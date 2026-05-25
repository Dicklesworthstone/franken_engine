#!/usr/bin/env bash
# scripts/run_rgc_fleet_counterfactual_replay.sh
#
# Track S fleet-counterfactual-replay gate (bd-cixqu.19.3, bd-cixqu.19.4).
# Validates the counterfactual fleet-replay proof surface — the S.1
# fleet-counterfactual API (replay N captured traces under one substituted
# policy in a single operation), the S.2 signed N-counterfactual report schema
# (franken-engine.fleet-counterfactual-report.v1), the S.3 in-tree companion
# test + replay wrapper, and the S.4 metamorphic substitution test
# (counterfactual(trace, policy_original) === original_outcome) — and emits a
# replayable proof bundle.
#
# Modes:
#   ci        — Cross-reference every Track-S sub-claim (S.1/S.2/S.3/S.4) to its
#               in-tree source + test surface, content-address each file
#               (sha256), and emit a structured artifact bundle:
#                 run_manifest.json + events.jsonl + commands.txt +
#                 trace_ids.json + step_logs/.
#               Fails closed if any required artifact is missing. Like the
#               other RGC reality-check gates, `ci` does NOT invoke cargo —
#               the in-tree test
#               (crates/franken-engine/tests/rgc_fleet_counterfactual_replay.rs)
#               is run separately via rch by callers wanting live verification.
#   selftest  — Shape-only validation (no filesystem mutation beyond the run
#               dir): asserts the required-surface manifest is internally
#               consistent and that jq is available.
#
# Usage:
#   scripts/run_rgc_fleet_counterfactual_replay.sh [ci|selftest] [output_dir]
#
# Environment:
#   RGC_FLEET_COUNTERFACTUAL_REPLAY_ARTIFACT_ROOT
#     Override artifacts directory. Default
#     artifacts/fleet_counterfactual_replay.
#   RGC_FLEET_COUNTERFACTUAL_REPLAY_RUN_DIR
#     If set, write outputs directly into this dir (used by the replay
#     wrapper for deterministic re-runs).

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

readonly GATE_NAME="rgc_fleet_counterfactual_replay"
readonly ARTIFACT_ROOT="${RGC_FLEET_COUNTERFACTUAL_REPLAY_ARTIFACT_ROOT:-artifacts/fleet_counterfactual_replay}"
readonly TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly REPLAY_PIN="${RGC_FLEET_COUNTERFACTUAL_REPLAY_RUN_DIR:-}"

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
readonly TRACE_IDS_PATH="${RUN_DIR}/trace_ids.json"
readonly STEP_LOGS_DIR="${RUN_DIR}/step_logs"
mkdir -p "${STEP_LOGS_DIR}"

readonly TRACE_ID="trace-${GATE_NAME}-${TIMESTAMP}"
readonly DECISION_ID="decision-${GATE_NAME}-${TIMESTAMP}"
readonly POLICY_ID="policy-track-s-fleet-counterfactual-replay"
readonly COMPONENT="${GATE_NAME}"

# Reset events so replay-into-pinned-dir does not accumulate stale lines.
: >"${EVENTS_PATH}"
printf './scripts/run_rgc_fleet_counterfactual_replay.sh %s\n' "${mode}" >"${COMMANDS_PATH}"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 2
fi

sha256_of() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    printf ''
    return 0
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${path}" | awk '{print $1}'
  else
    shasum -a 256 "${path}" | awk '{print $1}'
  fi
}

emit_event() {
  local sub_claim="$1"
  local subject="$2"
  local outcome="$3"
  local detail="$4"
  jq -nc \
    --arg trace_id "${TRACE_ID}" \
    --arg decision_id "${DECISION_ID}" \
    --arg policy_id "${POLICY_ID}" \
    --arg component "${COMPONENT}" \
    --arg event "${sub_claim}" \
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

# Track-S required proof surface. Each row is "sub_claim|path".
# S.1 = fleet-counterfactual API (replay N traces under one substituted policy),
# S.2 = signed N-counterfactual report schema,
# S.3 = in-tree companion test + deterministic replay wrapper,
# S.4 = metamorphic substitution test (counterfactual(trace, policy_original)
#       === original_outcome).
readonly REQUIRED_SURFACE=(
  "S.1|crates/franken-engine/src/counterfactual_replay_engine.rs"
  "S.1|crates/franken-engine/tests/counterfactual_replay_engine_integration.rs"
  "S.2|crates/franken-engine/src/fleet_counterfactual_report.rs"
  "S.3|crates/franken-engine/tests/rgc_fleet_counterfactual_replay.rs"
  "S.3|scripts/e2e/rgc_fleet_counterfactual_replay_e2e.sh"
  "S.4|crates/franken-engine/tests/rgc_fleet_counterfactual_metamorphic.rs"
)

# ---------------------------------------------------------------------------
# ci mode — cross-reference + content-address the Track-S surface
# ---------------------------------------------------------------------------

run_ci_mode() {
  local verdict="pass"
  local present=0
  local missing=0
  local step_trace_ids=()
  local surface_json="[]"

  local idx=0
  local row sub_claim path step_trace step_log file_sha file_status
  for row in "${REQUIRED_SURFACE[@]}"; do
    sub_claim="${row%%|*}"
    path="${row#*|}"
    step_trace="${TRACE_ID}-step-$(printf '%02d' "${idx}")"
    step_trace_ids+=("${step_trace}")
    step_log="${STEP_LOGS_DIR}/$(printf '%02d' "${idx}")_$(basename "${path}").log"

    if [[ -f "${PROJECT_DIR}/${path}" ]]; then
      file_sha="$(sha256_of "${PROJECT_DIR}/${path}")"
      file_status="present"
      present=$((present + 1))
      emit_event "${sub_claim}" "${path}" "pass" "present sha256=${file_sha}"
    else
      file_sha=""
      file_status="missing"
      missing=$((missing + 1))
      verdict="fail"
      emit_event "${sub_claim}" "${path}" "fail" "required Track-S surface artifact missing"
    fi

    {
      printf 'step=%s\n' "${idx}"
      printf 'step_trace_id=%s\n' "${step_trace}"
      printf 'sub_claim=%s\n' "${sub_claim}"
      printf 'path=%s\n' "${path}"
      printf 'status=%s\n' "${file_status}"
      printf 'sha256=%s\n' "${file_sha}"
    } >"${step_log}"

    surface_json="$(jq -c \
      --arg sub_claim "${sub_claim}" \
      --arg path "${path}" \
      --arg status "${file_status}" \
      --arg sha256 "${file_sha}" \
      --arg step_trace "${step_trace}" \
      '. + [{
        sub_claim: $sub_claim,
        path: $path,
        status: $status,
        sha256: (if $sha256 == "" then null else $sha256 end),
        step_trace_id: $step_trace
      }]' <<<"${surface_json}")"

    idx=$((idx + 1))
  done

  # Each sub-claim must contribute at least one present artifact.
  local sub
  for sub in S.1 S.2 S.3 S.4; do
    local count
    count="$(jq -r --arg s "${sub}" '[.[] | select(.sub_claim == $s and .status == "present")] | length' <<<"${surface_json}")"
    if [[ "${count}" -eq 0 ]]; then
      verdict="fail"
      emit_event "${sub}" "sub_claim_coverage" "fail" "no present artifact for Track-S sub-claim ${sub}"
    else
      emit_event "${sub}" "sub_claim_coverage" "pass" "${count} present artifact(s)"
    fi
  done

  emit_event "gate" "track-s-surface" "${verdict}" "present=${present} missing=${missing}"

  # trace_ids.json — the canonical decision trace + per-step trace ids.
  local step_trace_json
  step_trace_json="$(printf '%s\n' "${step_trace_ids[@]}" | jq -R . | jq -s .)"
  jq -n \
    --arg schema "franken-engine.rgc-fleet-counterfactual-replay-gate.trace-ids.v1" \
    --arg trace_id "${TRACE_ID}" \
    --arg decision_id "${DECISION_ID}" \
    --arg policy_id "${POLICY_ID}" \
    --arg component "${COMPONENT}" \
    --argjson step_trace_ids "${step_trace_json}" \
    '{
      schema_version: $schema,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      step_trace_ids: $step_trace_ids
    }' >"${TRACE_IDS_PATH}"

  jq -n \
    --arg schema "franken-engine.rgc-fleet-counterfactual-replay-gate.manifest.v1" \
    --arg run_dir "${RUN_DIR}" \
    --arg mode "${mode}" \
    --arg trace_id "${TRACE_ID}" \
    --arg decision_id "${DECISION_ID}" \
    --arg policy_id "${POLICY_ID}" \
    --arg component "${COMPONENT}" \
    --arg generated_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg source_revision "$(git rev-parse HEAD 2>/dev/null || echo unknown)" \
    --arg verdict "${verdict}" \
    --argjson present "${present}" \
    --argjson missing "${missing}" \
    --argjson surface "${surface_json}" \
    '{
      schema_version: $schema,
      run_dir: $run_dir,
      mode: $mode,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      generated_utc: $generated_utc,
      source_revision: $source_revision,
      freshness: { generated_utc: $generated_utc },
      claim_id: "FE-TRACK-S",
      report_schema: "franken-engine.fleet-counterfactual-report.v1",
      verdict: $verdict,
      surface_summary: { present: $present, missing: $missing },
      required_surface: $surface,
      in_tree_test: "crates/franken-engine/tests/rgc_fleet_counterfactual_replay.rs",
      artifacts: {
        events_jsonl: "events.jsonl",
        commands_txt: "commands.txt",
        trace_ids_json: "trace_ids.json",
        step_logs_dir: "step_logs"
      }
    }' >"${MANIFEST_PATH}"

  echo "rgc_fleet_counterfactual_replay_manifest=${MANIFEST_PATH}"
  echo "rgc_fleet_counterfactual_replay_events=${EVENTS_PATH}"
  echo "rgc_fleet_counterfactual_replay_trace_ids=${TRACE_IDS_PATH}"
  echo "rgc_fleet_counterfactual_replay_verdict=${verdict}"

  [[ "${verdict}" == "pass" ]]
}

# ---------------------------------------------------------------------------
# selftest mode — shape-only validation
# ---------------------------------------------------------------------------

run_selftest_mode() {
  local failures=0
  if [[ "${#REQUIRED_SURFACE[@]}" -eq 0 ]]; then
    echo "FAIL selftest: required surface list is empty" >&2
    failures=$((failures + 1))
  fi
  local row sub_claim path
  local saw_s1=0 saw_s2=0 saw_s3=0 saw_s4=0
  for row in "${REQUIRED_SURFACE[@]}"; do
    sub_claim="${row%%|*}"
    path="${row#*|}"
    if [[ -z "${sub_claim}" || -z "${path}" || "${sub_claim}" == "${path}" ]]; then
      echo "FAIL selftest: malformed surface row: ${row}" >&2
      failures=$((failures + 1))
    fi
    case "${sub_claim}" in
      S.1) saw_s1=1 ;;
      S.2) saw_s2=1 ;;
      S.3) saw_s3=1 ;;
      S.4) saw_s4=1 ;;
    esac
  done
  if [[ "${saw_s1}" -eq 0 || "${saw_s2}" -eq 0 || "${saw_s3}" -eq 0 || "${saw_s4}" -eq 0 ]]; then
    echo "FAIL selftest: surface must cover S.1, S.2, S.3 and S.4" >&2
    failures=$((failures + 1))
  fi
  if [[ "${failures}" -eq 0 ]]; then
    printf 'PASS selftest: Track-S fleet-counterfactual-replay surface manifest shape valid\n'
  fi
  return ${failures}
}

case "${mode}" in
  ci)
    run_ci_mode
    ;;
  selftest)
    run_selftest_mode
    ;;
  -h|--help)
    sed -n '2,40p' "${BASH_SOURCE[0]}"
    exit 0
    ;;
  *)
    echo "ERROR: unknown mode: ${mode}" >&2
    echo "Usage: $0 [ci|selftest] [output_dir]" >&2
    exit 64
    ;;
esac
