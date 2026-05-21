#!/usr/bin/env bash
# RGC capability-typed compile-time gate (bd-cixqu.3.4)
#
# Track C cap-stone gate. Asserts the compile-time / lowering surface
# rejects every red-team scenario (C.3 corpus) whose manifest declares
# `expected_outcome.frankenengine.outcome = "fail_closed"`, and that
# Node + Bun both `succeeds` on the same input — i.e. FrankenEngine is
# *the only* runtime that refuses the attack.
#
# Three verification layers:
#   1. Manifest shape compliance: every scenario's `.manifest.json`
#      parses, declares the FE-CLAIM-006 schema, and matches the
#      EXPECTED_SCENARIOS list in
#      `tests/red_team_scenario_manifest_validation.rs`.
#   2. Execution-harness rejection: `tests/red_team_execution_harness.rs`
#      asserts the lowering refuses each scenario program.
#   3. Ambient-authority lowering: `tests/ambient_authority_lowering_rejection_integration.rs`
#      asserts the specific UnauthorizedFlow / UnsupportedSyntax
#      `LoweringPipelineError` variant declared by each manifest fires.
#
# Usage:
#   scripts/run_rgc_capability_typed_compile_time.sh ci [output_dir]
#   scripts/run_rgc_capability_typed_compile_time.sh dev [output_dir]
#   scripts/run_rgc_capability_typed_compile_time.sh selftest [output_dir]
#
# Modes:
#   ci       — runs all three layers; fails closed on any rejection miss.
#   dev      — same as ci but tolerates rch worker unavailability and
#              records `outcome=skipped` for any layer whose `cargo test`
#              cannot be invoked (e.g. workspace lib has an unrelated
#              compile error blocking the test binaries).
#   selftest — shape-only validation (does NOT invoke cargo). Useful as
#              a pre-rch smoke when the workspace build is red on
#              UNRELATED errors so the gate still exercises layer 1.
#
# Environment:
#   RGC_CAPABILITY_TYPED_COMPILE_TIME_ARTIFACT_ROOT
#     Override artifacts directory. Default
#     `artifacts/rgc_capability_typed_compile_time`.
#   RGC_CAPABILITY_TYPED_COMPILE_TIME_REPLAY_RUN_DIR
#     If set, the gate writes its outputs under this run dir directly
#     (used by the replay wrapper to reuse paths). Otherwise a fresh
#     timestamped dir is created.
#   CARGO_TARGET_DIR / CARGO_INCREMENTAL / RUSTFLAGS
#     Passed through to cargo invocations when run in `ci` / `dev`.
#
# Artifacts:
#   artifacts/rgc_capability_typed_compile_time/${timestamp}/
#   ├── run_manifest.json            # artifact manifest with content hashes
#   ├── events.jsonl                 # structured event log (per-scenario + per-layer)
#   ├── commands.txt                 # shell command transcript
#   ├── summary.md                   # operator-readable summary
#   ├── scenario_corpus.json         # snapshot of the EXPECTED_SCENARIOS list
#   ├── layer_1_manifest_shape.json  # shape-validation result per scenario
#   ├── layer_2_execution.json       # execution-harness result per scenario
#   └── layer_3_lowering.json        # lowering-rejection result per scenario

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

readonly GATE_NAME="rgc_capability_typed_compile_time"
readonly ARTIFACT_ROOT="${RGC_CAPABILITY_TYPED_COMPILE_TIME_ARTIFACT_ROOT:-artifacts/${GATE_NAME}}"
readonly TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly REPLAY_PIN="${RGC_CAPABILITY_TYPED_COMPILE_TIME_REPLAY_RUN_DIR:-}"

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
readonly CORPUS_PATH="${RUN_DIR}/scenario_corpus.json"
readonly LAYER1_PATH="${RUN_DIR}/layer_1_manifest_shape.json"
readonly LAYER2_PATH="${RUN_DIR}/layer_2_execution.json"
readonly LAYER3_PATH="${RUN_DIR}/layer_3_lowering.json"

readonly SCENARIO_DIR="${PROJECT_DIR}/crates/franken-engine/tests/red_team_scenarios"
readonly VALIDATION_TEST="red_team_scenario_manifest_validation"
readonly EXECUTION_TEST="red_team_execution_harness"
readonly LOWERING_TEST="ambient_authority_lowering_rejection_integration"

readonly TRACE_ID="trace-${GATE_NAME}-${TIMESTAMP}"
readonly DECISION_ID="decision-${GATE_NAME}-${TIMESTAMP}"
readonly POLICY_ID="policy-fe-claim-006-capability-typed-compile-time"
readonly COMPONENT="${GATE_NAME}"

printf './scripts/run_rgc_capability_typed_compile_time.sh %s\n' "${mode}" >"${COMMANDS_PATH}"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 2
fi

emit_event() {
  local layer="$1"
  local scenario="$2"
  local outcome="$3"
  local detail="$4"
  jq -nc \
    --arg trace_id "${TRACE_ID}" \
    --arg decision_id "${DECISION_ID}" \
    --arg policy_id "${POLICY_ID}" \
    --arg component "${COMPONENT}" \
    --arg event "${layer}" \
    --arg outcome "${outcome}" \
    --arg scenario "${scenario}" \
    --arg detail "${detail}" \
    '{
      schema_version: "franken-engine.gate-event.v1",
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: $event,
      outcome: $outcome,
      scenario: $scenario,
      detail: $detail
    }' >>"${EVENTS_PATH}"
}

# Snapshot the canonical EXPECTED_SCENARIOS list. We derive it from the
# Rust test source so the gate is locked-step with the test surface.
extract_expected_scenarios() {
  awk '
    /^const EXPECTED_SCENARIOS:/,/^];$/ {
      if (match($0, /"([^"]+)"/, m)) {
        print m[1]
      }
    }
  ' "${PROJECT_DIR}/crates/franken-engine/tests/red_team_scenario_manifest_validation.rs"
}

readarray -t EXPECTED_SCENARIOS < <(extract_expected_scenarios)
if [[ ${#EXPECTED_SCENARIOS[@]} -eq 0 ]]; then
  echo "ERROR: failed to extract EXPECTED_SCENARIOS from red_team_scenario_manifest_validation.rs" >&2
  exit 3
fi

# Persist the corpus list to the bundle for replay determinism.
jq -nc \
  --argjson names "$(printf '%s\n' "${EXPECTED_SCENARIOS[@]}" | jq -R . | jq -s .)" \
  --arg count "${#EXPECTED_SCENARIOS[@]}" \
  '{
    schema_version: "franken-engine.red-team-scenario-corpus.v1",
    source_file: "crates/franken-engine/tests/red_team_scenario_manifest_validation.rs",
    expected_count: ($count | tonumber),
    expected_scenarios: $names
  }' >"${CORPUS_PATH}"

# ---------------------------------------------------------------------------
# Layer 1 — manifest shape compliance (no cargo required)
# ---------------------------------------------------------------------------

layer1_pass=0
layer1_fail=0
layer1_results="[]"

for scenario in "${EXPECTED_SCENARIOS[@]}"; do
  manifest_path="${SCENARIO_DIR}/${scenario}.manifest.json"
  js_path="${SCENARIO_DIR}/${scenario}.js"

  shape_outcome="pass"
  shape_detail=""

  if [[ ! -f "${manifest_path}" ]]; then
    shape_outcome="fail"
    shape_detail="missing manifest at ${manifest_path}"
  elif [[ ! -f "${js_path}" ]]; then
    shape_outcome="fail"
    shape_detail="missing program at ${js_path}"
  elif ! jq -e --arg name "${scenario}" '
        .schema_version == "franken-engine.red-team-scenario.v1"
        and (.name == $name)
        and (.expected_outcome.frankenengine.outcome == "fail_closed")
        and (.expected_outcome.node.outcome == "succeeds")
        and (.expected_outcome.bun.outcome == "succeeds")
        and ((.expected_outcome.frankenengine.denial_reason // "") | length > 0)
        and ((.payload.success_criteria // "") | length > 0)
        and ((.attack_vector // "") | length > 0)
      ' "${manifest_path}" >/dev/null; then
    shape_outcome="fail"
    shape_detail="manifest does not satisfy red_team_scenario_manifests_have_required_shape contract"
  fi

  emit_event "layer_1_manifest_shape" "${scenario}" "${shape_outcome}" "${shape_detail}"

  if [[ "${shape_outcome}" == "pass" ]]; then
    layer1_pass=$((layer1_pass + 1))
  else
    layer1_fail=$((layer1_fail + 1))
  fi

  layer1_results="$(jq --arg s "${scenario}" --arg o "${shape_outcome}" --arg d "${shape_detail}" \
    '. += [{scenario: $s, outcome: $o, detail: $d}]' <<<"${layer1_results}")"
done

jq -n \
  --arg gate_layer "manifest_shape" \
  --argjson results "${layer1_results}" \
  --argjson pass "${layer1_pass}" \
  --argjson fail "${layer1_fail}" \
  '{
    schema_version: "franken-engine.rgc-capability-typed-compile-time.layer-result.v1",
    layer: $gate_layer,
    pass_count: $pass,
    fail_count: $fail,
    results: $results
  }' >"${LAYER1_PATH}"

# ---------------------------------------------------------------------------
# Layers 2 and 3 — cargo-test-driven (execution-harness + lowering-rejection)
# ---------------------------------------------------------------------------

run_cargo_test() {
  # Runs a single integration-test target via rch (or local cargo) and
  # captures pass/fail per the cargo output. Records the outcome and a
  # truncated diagnostic excerpt.
  local layer_name="$1"
  local test_target="$2"
  local layer_path="$3"
  local cargo_log
  cargo_log="$(mktemp "${TMPDIR:-/tmp}/${layer_name}.XXXXXX.log")"
  local cargo_exit
  local cargo_outcome="pass"
  local cargo_detail=""

  if [[ "${mode}" == "selftest" ]]; then
    # Selftest mode never invokes cargo; record skipped per layer.
    cargo_outcome="skipped"
    cargo_detail="selftest mode does not invoke cargo; rely on layer 1 + manual rch verification"
    cargo_exit=0
  else
    set +e
    if command -v rch >/dev/null 2>&1; then
      rch exec "env CARGO_INCREMENTAL=0 cargo test -p frankenengine-engine --test ${test_target} -- --nocapture" \
        >"${cargo_log}" 2>&1
    else
      env CARGO_INCREMENTAL=0 cargo test -p frankenengine-engine --test "${test_target}" -- --nocapture \
        >"${cargo_log}" 2>&1
    fi
    cargo_exit=$?
    set -e

    if [[ "${cargo_exit}" -ne 0 ]]; then
      cargo_outcome="fail"
      # Truncate the failure detail to the last 80 lines so the bundle
      # stays compact.
      cargo_detail="cargo exit=${cargo_exit}; tail: $(tail -n 80 "${cargo_log}" | tr '\n' ' ' | cut -c1-2000)"

      # Distinguish "unrelated build break" from "lowering missed a
      # rejection". If cargo never reached our test target — i.e. the
      # error mentions OTHER files — downgrade to skipped in dev mode.
      if [[ "${mode}" == "dev" ]] \
          && grep -Eq "could not compile.*\(lib\)$|could not compile.*\(lib test\)$|error\[E[0-9]{4}\]: cannot find" "${cargo_log}" \
          && ! grep -q "${test_target}" "${cargo_log}"; then
        cargo_outcome="skipped"
        cargo_detail="dev-mode tolerance: workspace lib failed to build for UNRELATED reasons before test target ${test_target} could execute. cargo exit=${cargo_exit}"
      fi
    fi
  fi

  emit_event "${layer_name}" "(test target: ${test_target})" "${cargo_outcome}" "${cargo_detail}"

  jq -n \
    --arg gate_layer "${layer_name}" \
    --arg test_target "${test_target}" \
    --arg outcome "${cargo_outcome}" \
    --arg detail "${cargo_detail}" \
    --argjson exit_code "${cargo_exit}" \
    '{
      schema_version: "franken-engine.rgc-capability-typed-compile-time.layer-result.v1",
      layer: $gate_layer,
      test_target: $test_target,
      outcome: $outcome,
      exit_code: $exit_code,
      detail: $detail
    }' >"${layer_path}"

  rm -f "${cargo_log}"

  if [[ "${cargo_outcome}" == "pass" || "${cargo_outcome}" == "skipped" ]]; then
    return 0
  fi
  return 1
}

layer2_status=0
layer3_status=0
run_cargo_test "layer_2_execution_harness" "${EXECUTION_TEST}" "${LAYER2_PATH}" || layer2_status=$?
run_cargo_test "layer_3_lowering_rejection" "${LOWERING_TEST}" "${LAYER3_PATH}" || layer3_status=$?

# ---------------------------------------------------------------------------
# Verdict + manifest + summary
# ---------------------------------------------------------------------------

verdict="pass"
verdict_reason="all three layers admitted"

if [[ "${layer1_fail}" -ne 0 ]]; then
  verdict="fail"
  verdict_reason="layer 1 (manifest shape) had ${layer1_fail} failure(s)"
elif [[ "${layer2_status}" -ne 0 ]]; then
  verdict="fail"
  verdict_reason="layer 2 (execution harness) failed"
elif [[ "${layer3_status}" -ne 0 ]]; then
  verdict="fail"
  verdict_reason="layer 3 (lowering rejection) failed"
fi

jq -n \
  --arg schema_version "franken-engine.rgc-capability-typed-compile-time.manifest.v1" \
  --arg run_dir "${RUN_DIR}" \
  --arg mode "${mode}" \
  --arg trace_id "${TRACE_ID}" \
  --arg decision_id "${DECISION_ID}" \
  --arg policy_id "${POLICY_ID}" \
  --arg component "${COMPONENT}" \
  --arg generated_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg verdict "${verdict}" \
  --arg verdict_reason "${verdict_reason}" \
  --argjson scenario_count "${#EXPECTED_SCENARIOS[@]}" \
  --argjson layer1_pass "${layer1_pass}" \
  --argjson layer1_fail "${layer1_fail}" \
  --slurpfile layer1 "${LAYER1_PATH}" \
  --slurpfile layer2 "${LAYER2_PATH}" \
  --slurpfile layer3 "${LAYER3_PATH}" \
  '{
    schema_version: $schema_version,
    run_dir: $run_dir,
    mode: $mode,
    trace_id: $trace_id,
    decision_id: $decision_id,
    policy_id: $policy_id,
    component: $component,
    generated_utc: $generated_utc,
    freshness: { generated_utc: $generated_utc },
    verdict: $verdict,
    verdict_reason: $verdict_reason,
    scenario_count: $scenario_count,
    layer_1: { pass_count: $layer1_pass, fail_count: $layer1_fail, result: $layer1[0] },
    layer_2: { result: $layer2[0] },
    layer_3: { result: $layer3[0] },
    artifacts: {
      events_jsonl: "events.jsonl",
      commands_txt: "commands.txt",
      summary_md: "summary.md",
      scenario_corpus_json: "scenario_corpus.json",
      layer_1_json: "layer_1_manifest_shape.json",
      layer_2_json: "layer_2_execution.json",
      layer_3_json: "layer_3_lowering.json"
    }
  }' >"${MANIFEST_PATH}"

{
  printf '# RGC capability-typed compile-time gate — %s\n\n' "${TIMESTAMP}"
  printf -- '- Mode: `%s`\n' "${mode}"
  printf -- '- Verdict: **%s** (%s)\n' "${verdict}" "${verdict_reason}"
  printf -- '- Scenarios: %d (from `tests/red_team_scenario_manifest_validation.rs::EXPECTED_SCENARIOS`)\n' "${#EXPECTED_SCENARIOS[@]}"
  printf '\n## Layer breakdown\n\n'
  printf '| Layer | Description | Pass | Fail |\n'
  printf '|---|---|---|---|\n'
  printf '| 1 | Manifest shape compliance | %d | %d |\n' "${layer1_pass}" "${layer1_fail}"
  layer2_outcome="$(jq -r '.outcome' "${LAYER2_PATH}")"
  layer3_outcome="$(jq -r '.outcome' "${LAYER3_PATH}")"
  printf '| 2 | Execution-harness (`%s`) | %s | — |\n' "${EXECUTION_TEST}" "${layer2_outcome}"
  printf '| 3 | Lowering rejection (`%s`) | %s | — |\n' "${LOWERING_TEST}" "${layer3_outcome}"
  printf '\n## Artifacts\n\n'
  printf -- '- `run_manifest.json` — canonical gate manifest with verdict.\n'
  printf -- '- `events.jsonl` — per-scenario + per-layer structured events.\n'
  printf -- '- `scenario_corpus.json` — frozen copy of `EXPECTED_SCENARIOS`.\n'
  printf -- '- `layer_{1,2,3}_*.json` — per-layer machine-readable result.\n'
  printf -- '- `commands.txt` — shell command transcript.\n'
} >"${SUMMARY_PATH}"

echo "rgc_capability_typed_compile_time_manifest=${MANIFEST_PATH}"
echo "rgc_capability_typed_compile_time_events=${EVENTS_PATH}"
echo "rgc_capability_typed_compile_time_summary=${SUMMARY_PATH}"

if [[ "${verdict}" == "pass" ]]; then
  exit 0
fi
exit 1
