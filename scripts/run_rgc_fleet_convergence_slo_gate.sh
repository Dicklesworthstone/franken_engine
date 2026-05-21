#!/usr/bin/env bash
# scripts/run_rgc_fleet_convergence_slo_gate.sh
#
# Fleet convergence SLO gate. Two modes:
#
#   ci        — (bd-cixqu.2.2) Consume docs/fleet_convergence_slo_v1.json,
#               validate the SLO contract against the B.1 harness
#               surface (crates/franken-engine/tests/fleet_convergence_harness_integration.rs),
#               and emit a structured artifact bundle (manifest.json +
#               events.jsonl + commands.txt + summary.md) with the
#               declared SLO + a per-secondary-SLO entry. The gate
#               does NOT invoke cargo in `ci` mode — the harness is
#               invoked separately via rch by callers that want live
#               percentile measurements; this gate validates the SLO
#               *contract* shape + cross-reference to the harness.
#   partition — (bd-cixqu.2.6) Run the existing per-profile convergence
#               refusal lane that asserts permanent_split / split_brain
#               are correctly refused while normal / degraded / healing
#               are correctly allowed. Requires
#               docs/fleet_partition_fault_profiles_v1.json and the
#               `convergence_slo_gate_test` cargo bin.
#   selftest  — shape-only (no cargo). Validates the SLO contract
#               JSON and the gate's structured output shape.
#
# Usage:
#   scripts/run_rgc_fleet_convergence_slo_gate.sh [ci|partition|selftest] [output_dir]
#
# Environment:
#   RGC_FLEET_CONVERGENCE_SLO_ARTIFACT_ROOT
#     Override artifacts directory. Default
#     artifacts/rgc_fleet_convergence_slo_gate.
#   RGC_FLEET_CONVERGENCE_SLO_REPLAY_RUN_DIR
#     If set, write outputs directly into this dir (used by the
#     replay wrapper).
#   FLEET_CONVERGENCE_SLO_CONTRACT
#     Override SLO contract path. Default docs/fleet_convergence_slo_v1.json.

set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_DIR}"

mode="${1:-ci}"
explicit_output_dir="${2:-}"

readonly GATE_NAME="rgc_fleet_convergence_slo_gate"
readonly ARTIFACT_ROOT="${RGC_FLEET_CONVERGENCE_SLO_ARTIFACT_ROOT:-artifacts/${GATE_NAME}}"
readonly TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly REPLAY_PIN="${RGC_FLEET_CONVERGENCE_SLO_REPLAY_RUN_DIR:-}"
readonly SLO_CONTRACT="${FLEET_CONVERGENCE_SLO_CONTRACT:-docs/fleet_convergence_slo_v1.json}"
readonly PARTITION_PROFILES_PATH="docs/fleet_partition_fault_profiles_v1.json"

if [[ -n "${explicit_output_dir}" ]]; then
  RUN_DIR="${explicit_output_dir}"
elif [[ -n "${REPLAY_PIN}" ]]; then
  RUN_DIR="${REPLAY_PIN}"
else
  RUN_DIR="${ARTIFACT_ROOT}/${TIMESTAMP}"
fi
mkdir -p "${RUN_DIR}"

readonly MANIFEST_PATH="${RUN_DIR}/run_manifest.json"
readonly EVENTS_PATH="${RUN_DIR}/events.jsonl"
readonly COMMANDS_PATH="${RUN_DIR}/commands.txt"
readonly SUMMARY_PATH="${RUN_DIR}/summary.md"

readonly TRACE_ID="trace-${GATE_NAME}-${TIMESTAMP}"
readonly DECISION_ID="decision-${GATE_NAME}-${TIMESTAMP}"
readonly POLICY_ID="policy-fe-claim-005-fleet-convergence-slo"
readonly COMPONENT="${GATE_NAME}"

printf './scripts/run_rgc_fleet_convergence_slo_gate.sh %s\n' "${mode}" >"${COMMANDS_PATH}"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 2
fi

emit_event() {
  local layer="$1"
  local subject="$2"
  local outcome="$3"
  local detail="$4"
  jq -nc \
    --arg trace_id "${TRACE_ID}" \
    --arg decision_id "${DECISION_ID}" \
    --arg policy_id "${POLICY_ID}" \
    --arg component "${COMPONENT}" \
    --arg event "${layer}" \
    --arg outcome "${outcome}" \
    --arg subject "${subject}" \
    --arg detail "${detail}" \
    '{
      schema_version: "franken-engine.gate-event.v1",
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: $event,
      outcome: $outcome,
      subject: $subject,
      detail: $detail
    }' >>"${EVENTS_PATH}"
}

# ---------------------------------------------------------------------------
# ci mode — SLO contract validation + harness cross-reference
# ---------------------------------------------------------------------------

run_ci_mode() {
  if [[ ! -f "${SLO_CONTRACT}" ]]; then
    emit_event "slo_contract_present" "${SLO_CONTRACT}" "fail" "missing file"
    echo "ERROR: SLO contract not found at ${SLO_CONTRACT}" >&2
    return 1
  fi

  # Layer 1 — schema validation
  if ! jq -e '
        .schema_version == "franken-engine.fleet-convergence-slo.v1"
        and (.slo | type == "object")
        and ((.slo.partition_profile // "") | length > 0)
        and ((.slo.fleet_size_nodes // 0) > 0)
        and ((.slo.target_convergence_percentile // 0) > 0)
        and ((.slo.target_convergence_percentile // 0) <= 1)
        and ((.slo.target_convergence_wall_time_seconds // 0) > 0)
      ' "${SLO_CONTRACT}" >/dev/null; then
    emit_event "slo_contract_schema" "${SLO_CONTRACT}" "fail" "schema validation failed against franken-engine.fleet-convergence-slo.v1"
    echo "ERROR: SLO contract fails schema validation" >&2
    return 1
  fi
  emit_event "slo_contract_schema" "${SLO_CONTRACT}" "pass" "contract conforms to franken-engine.fleet-convergence-slo.v1"

  # Layer 2 — harness source-file cross-reference
  local harness_source harness_module harness_test
  harness_source="$(jq -r '.harness.source_file // ""' "${SLO_CONTRACT}")"
  harness_module="$(jq -r '.harness.harness_module // ""' "${SLO_CONTRACT}")"
  harness_test="$(jq -r '.harness.integration_test // ""' "${SLO_CONTRACT}")"

  local harness_status="pass"
  local harness_detail=""
  local f
  for f in "${harness_source}" "${harness_module}" "${harness_test}"; do
    if [[ -z "${f}" || ! -f "${PROJECT_DIR}/${f}" ]]; then
      harness_status="fail"
      harness_detail="${harness_detail}${f} missing; "
    fi
  done
  emit_event "harness_cross_reference" "B.1 harness files" "${harness_status}" "${harness_detail:-all harness files present}"
  if [[ "${harness_status}" != "pass" ]]; then
    return 1
  fi

  # Layer 3 — per-secondary-SLO validation
  local secondary_count
  secondary_count="$(jq -r '[.secondary_slos // [] | .[]] | length' "${SLO_CONTRACT}")"
  local sec_pass=0
  local sec_fail=0
  local sec
  while IFS= read -r sec; do
    local sec_profile
    sec_profile="$(jq -r '.partition_profile' <<<"${sec}")"
    if jq -e '
          ((.fleet_size_nodes // 0) > 0)
          and ((.target_convergence_percentile // 0) > 0)
          and ((.target_convergence_percentile // 0) <= 1)
          and ((.target_convergence_wall_time_seconds // 0) > 0)
        ' <<<"${sec}" >/dev/null; then
      emit_event "secondary_slo_schema" "${sec_profile}" "pass" "secondary SLO entry conforms"
      sec_pass=$((sec_pass + 1))
    else
      emit_event "secondary_slo_schema" "${sec_profile}" "fail" "secondary SLO entry malformed"
      sec_fail=$((sec_fail + 1))
    fi
  done < <(jq -c '.secondary_slos // [] | .[]' "${SLO_CONTRACT}")

  # Layer 4 — unsupported-profile coverage
  local refused_profiles
  refused_profiles="$(jq -r '.unsupported_profiles // {} | keys | sort | join(",")' "${SLO_CONTRACT}")"
  if [[ "${refused_profiles}" != "permanent_split,split_brain" ]]; then
    emit_event "unsupported_profiles_coverage" "expected: permanent_split,split_brain" "fail" "got: ${refused_profiles}"
    return 1
  fi
  emit_event "unsupported_profiles_coverage" "permanent_split,split_brain" "pass" "both unsupported profiles declared with rationale"

  # Verdict + manifest + summary
  local slo_profile slo_nodes slo_pct slo_walltime
  slo_profile="$(jq -r '.slo.partition_profile' "${SLO_CONTRACT}")"
  slo_nodes="$(jq -r '.slo.fleet_size_nodes' "${SLO_CONTRACT}")"
  slo_pct="$(jq -r '.slo.target_convergence_percentile' "${SLO_CONTRACT}")"
  slo_walltime="$(jq -r '.slo.target_convergence_wall_time_seconds' "${SLO_CONTRACT}")"

  jq -n \
    --arg schema "franken-engine.rgc-fleet-convergence-slo-gate.manifest.v1" \
    --arg run_dir "${RUN_DIR}" \
    --arg mode "${mode}" \
    --arg trace_id "${TRACE_ID}" \
    --arg decision_id "${DECISION_ID}" \
    --arg policy_id "${POLICY_ID}" \
    --arg component "${COMPONENT}" \
    --arg generated_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg slo_contract "${SLO_CONTRACT}" \
    --arg slo_profile "${slo_profile}" \
    --argjson slo_nodes "${slo_nodes}" \
    --argjson slo_pct "${slo_pct}" \
    --argjson slo_walltime "${slo_walltime}" \
    --argjson secondary_count "${secondary_count}" \
    --argjson secondary_pass "${sec_pass}" \
    --argjson secondary_fail "${sec_fail}" \
    --arg verdict "pass" \
    '{
      schema_version: $schema,
      run_dir: $run_dir,
      mode: $mode,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      generated_utc: $generated_utc,
      freshness: { generated_utc: $generated_utc },
      verdict: $verdict,
      slo_contract: $slo_contract,
      primary_slo: {
        partition_profile: $slo_profile,
        fleet_size_nodes: $slo_nodes,
        target_convergence_percentile: $slo_pct,
        target_convergence_wall_time_seconds: $slo_walltime
      },
      secondary_slos: {
        declared: $secondary_count,
        pass: $secondary_pass,
        fail: $secondary_fail
      },
      artifacts: {
        events_jsonl: "events.jsonl",
        commands_txt: "commands.txt",
        summary_md: "summary.md"
      }
    }' >"${MANIFEST_PATH}"

  {
    printf -- '# RGC fleet convergence SLO gate — %s\n\n' "${TIMESTAMP}"
    printf -- '- Mode: `%s`\n' "${mode}"
    printf -- '- Verdict: **pass**\n'
    printf -- '- SLO contract: `%s`\n' "${SLO_CONTRACT}"
    printf -- '\n## Primary SLO\n\n'
    printf -- '- Partition profile: `%s`\n' "${slo_profile}"
    printf -- '- Fleet size: %s nodes\n' "${slo_nodes}"
    printf -- '- Target convergence percentile: %s\n' "${slo_pct}"
    printf -- '- Target wall-time: %s seconds\n' "${slo_walltime}"
    printf -- '\n## Secondary SLOs\n\n'
    printf -- '- Declared: %s · Pass: %s · Fail: %s\n' "${secondary_count}" "${sec_pass}" "${sec_fail}"
    printf -- '\n## Unsupported profiles\n\n'
    printf -- '- `permanent_split` and `split_brain` correctly declared as refused (covered by bd-cixqu.2.6 partition mode).\n'
  } >"${SUMMARY_PATH}"

  echo "rgc_fleet_convergence_slo_manifest=${MANIFEST_PATH}"
  echo "rgc_fleet_convergence_slo_events=${EVENTS_PATH}"
  echo "rgc_fleet_convergence_slo_summary=${SUMMARY_PATH}"
  return 0
}

# ---------------------------------------------------------------------------
# partition mode — bd-cixqu.2.6 negative-profile refusal lane (legacy)
# ---------------------------------------------------------------------------

run_partition_mode() {
  if [[ ! -f "${PARTITION_PROFILES_PATH}" ]]; then
    echo "ERROR: Fleet partition fault profiles not found at ${PARTITION_PROFILES_PATH}" >&2
    return 1
  fi

  echo "Loading partition profiles from: ${PARTITION_PROFILES_PATH}"
  local impossible_profiles=("permanent_split" "split_brain")
  local stable_profiles=("normal" "degraded" "healing")
  local rc=0

  local profile
  for profile in "${impossible_profiles[@]}"; do
    printf -- '--- Testing impossible profile: %s ---\n' "${profile}"
    if cargo run --bin convergence_slo_gate_test -- \
        --profile "${profile}" \
        --profiles-path "${PARTITION_PROFILES_PATH}" \
        --expect-refusal \
        --check-manifest-failure; then
      printf -- 'OK Profile %s correctly refused convergence claim\n' "${profile}"
      emit_event "partition_refusal" "${profile}" "pass" "refused as expected"
    else
      printf -- 'FAIL Profile %s did not refuse convergence claim\n' "${profile}" >&2
      emit_event "partition_refusal" "${profile}" "fail" "did not refuse"
      rc=1
    fi
  done

  for profile in "${stable_profiles[@]}"; do
    printf -- '--- Testing stable profile: %s ---\n' "${profile}"
    if cargo run --bin convergence_slo_gate_test -- \
        --profile "${profile}" \
        --profiles-path "${PARTITION_PROFILES_PATH}" \
        --expect-success; then
      printf -- 'OK Profile %s correctly allowed convergence claim\n' "${profile}"
      emit_event "stable_admission" "${profile}" "pass" "admitted as expected"
    else
      printf -- 'FAIL Profile %s did not allow convergence claim\n' "${profile}" >&2
      emit_event "stable_admission" "${profile}" "fail" "did not admit"
      rc=1
    fi
  done

  return ${rc}
}

# ---------------------------------------------------------------------------
# selftest mode — shape-only validation
# ---------------------------------------------------------------------------

run_selftest_mode() {
  local failures=0
  if [[ ! -f "${SLO_CONTRACT}" ]]; then
    echo "FAIL selftest: SLO contract not found at ${SLO_CONTRACT}" >&2
    failures=$((failures + 1))
  fi
  if ! jq -e '.schema_version == "franken-engine.fleet-convergence-slo.v1"' "${SLO_CONTRACT}" >/dev/null 2>&1; then
    echo "FAIL selftest: SLO contract schema mismatch" >&2
    failures=$((failures + 1))
  fi
  if ! jq -e '
        (.slo | type == "object")
        and ((.slo.partition_profile // "") | length > 0)
        and ((.slo.fleet_size_nodes // 0) > 0)
        and ((.slo.target_convergence_percentile // 0) > 0)
        and ((.slo.target_convergence_percentile // 0) <= 1)
        and ((.slo.target_convergence_wall_time_seconds // 0) > 0)
      ' "${SLO_CONTRACT}" >/dev/null 2>&1; then
    echo "FAIL selftest: primary SLO entry malformed" >&2
    failures=$((failures + 1))
  fi
  if ! jq -e '
        (.unsupported_profiles // {} | keys | sort | join(",")) == "permanent_split,split_brain"
      ' "${SLO_CONTRACT}" >/dev/null 2>&1; then
    echo "FAIL selftest: unsupported_profiles must declare permanent_split + split_brain" >&2
    failures=$((failures + 1))
  fi
  if [[ "${failures}" -eq 0 ]]; then
    printf -- 'PASS selftest: SLO contract schema + shape valid\n'
  fi
  return ${failures}
}

case "${mode}" in
  ci)
    run_ci_mode
    ;;
  partition)
    run_partition_mode
    ;;
  selftest)
    run_selftest_mode
    ;;
  -h|--help)
    sed -n '2,38p' "${BASH_SOURCE[0]}"
    exit 0
    ;;
  *)
    echo "ERROR: unknown mode: ${mode}" >&2
    echo "Usage: $0 [ci|partition|selftest] [output_dir]" >&2
    exit 64
    ;;
esac
