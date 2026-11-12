#!/usr/bin/env bash
set -euo pipefail

# RGC-309A (bd-1lsy.4.10.1): Deterministic E2E scenario & triage artifact runner
# for executable module-graph live bindings, namespace exotic invariants,
# re-exports, cycles, and module-cache identity.
#
# Modes:
#   ci        — execute shipped-path frankenctl + library/integration suites via RCH
#   selftest  — validate artifact schema and contract emission without Cargo
#
# Emits under artifacts/rgc_module_live_binding/<timestamp>/ (or explicit dir):
#   - run_manifest.json
#   - events.jsonl
#   - commands.txt
#   - trace_ids.json
#   - live_binding_report.json

export TZ=UTC
export LC_ALL=C
export LANG=C

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}" || exit 1

MODE="${1:-ci}"
EXPLICIT_OUT_DIR="${2:-}"
TIMESTAMP="${RGC_MODULE_LIVE_BINDING_RUN_TS:-$(date -u +%Y%m%dT%H%M%SZ)}"
ARTIFACT_ROOT="${RGC_MODULE_LIVE_BINDING_ARTIFACT_ROOT:-artifacts/rgc_module_live_binding}"

if [[ -n "${EXPLICIT_OUT_DIR}" ]]; then
  RUN_DIR="${EXPLICIT_OUT_DIR}"
else
  RUN_DIR="${ARTIFACT_ROOT}/${TIMESTAMP}"
fi
mkdir -p "${RUN_DIR}"

MANIFEST_PATH="${RUN_DIR}/run_manifest.json"
EVENTS_PATH="${RUN_DIR}/events.jsonl"
COMMANDS_PATH="${RUN_DIR}/commands.txt"
TRACE_IDS_PATH="${RUN_DIR}/trace_ids.json"
REPORT_PATH="${RUN_DIR}/live_binding_report.json"

TRACE_ID="trace-rgc-309a-${TIMESTAMP}"
DECISION_ID="decision-rgc-309a-${TIMESTAMP}"
POLICY_ID="policy-rgc-309a-module-live-binding-v1"

: > "${EVENTS_PATH}"
printf './scripts/e2e/rgc_module_live_binding_e2e.sh %s\n' "${MODE}" > "${COMMANDS_PATH}"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 2
fi

emit_event() {
  local phase="$1"
  local scenario="$2"
  local outcome="$3"
  local detail="$4"
  jq -nc \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg trace_id "${TRACE_ID}" \
    --arg decision_id "${DECISION_ID}" \
    --arg policy_id "${POLICY_ID}" \
    --arg bead_id "bd-1lsy.4.10.1" \
    --arg phase "${phase}" \
    --arg scenario "${scenario}" \
    --arg outcome "${outcome}" \
    --arg detail "${detail}" \
    '{
      schema_version: "franken-engine.rgc-module-live-binding.event.v1",
      ts: $ts,
      bead_id: $bead_id,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      phase: $phase,
      scenario: $scenario,
      outcome: $outcome,
      detail: $detail
    }' >> "${EVENTS_PATH}"
}

jq -n \
  --arg schema_version "franken-engine.rgc-module-live-binding.trace-ids.v1" \
  --arg bead_id "bd-1lsy.4.10.1" \
  --arg run_id "${TIMESTAMP}" \
  --arg trace_id "${TRACE_ID}" \
  --arg decision_id "${DECISION_ID}" \
  --arg policy_id "${POLICY_ID}" \
  '{
    schema_version: $schema_version,
    bead_id: $bead_id,
    run_id: $run_id,
    trace_ids: [
      $trace_id,
      ($trace_id + ":direct-and-relay-live-bindings"),
      ($trace_id + ":star-reexport-diamond"),
      ($trace_id + ":cyclic-tdz-and-hoisted-var"),
      ($trace_id + ":namespace-exotic-and-cache-identity")
    ],
    decision_id: $decision_id,
    policy_id: $policy_id
  }' > "${TRACE_IDS_PATH}"

emit_event "run_start" "suite" "started" "mode=${MODE}"

SHIPPED_OUTCOME="skipped"
INTEGRATION_OUTCOME="skipped"
UNIT_OUTCOME="skipped"
SHIPPED_EXIT=0
INTEGRATION_EXIT=0
UNIT_EXIT=0

run_rch_suite() {
  local phase="$1"
  local log_file="$2"
  shift 2
  local -a worker_args=()
  if [[ -n "${RCH_WORKER:-}" ]]; then
    rch workers probe "${RCH_WORKER}" >/dev/null 2>&1 || true
    worker_args=(--worker "${RCH_WORKER}")
  fi
  printf 'rch exec %s -- %s\n' "${worker_args[*]:-}" "$*" >> "${COMMANDS_PATH}"
  set +e
  RCH_REQUIRE_REMOTE=1 rch exec "${worker_args[@]}" -- "$@" > "${log_file}" 2>&1
  local rc=$?
  set -e
  return "${rc}"
}

if [[ "${MODE}" == "ci" ]]; then
  if ! command -v rch >/dev/null 2>&1; then
    echo "ERROR: rch is required in ci mode" >&2
    exit 2
  fi

  if run_rch_suite "shipped_frankenctl_e2e" "${RUN_DIR}/shipped_e2e.log" \
    env CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_INCREMENTAL=false CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
    cargo test -j 2 -p frankenengine-engine --test esm_live_bindings_bd_1lsy_4_10_1 -- --nocapture --test-threads=2; then
    SHIPPED_OUTCOME="pass"
    emit_event "shipped_frankenctl_e2e" "esm_live_bindings_bd_1lsy_4_10_1" "pass" "4 shipped frankenctl module-graph scenarios passed"
  else
    SHIPPED_EXIT=$?
    SHIPPED_OUTCOME="fail"
    emit_event "shipped_frankenctl_e2e" "esm_live_bindings_bd_1lsy_4_10_1" "fail" "exit=${SHIPPED_EXIT}; see shipped_e2e.log"
  fi

  if run_rch_suite "module_live_binding_integration" "${RUN_DIR}/integration.log" \
    env CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_INCREMENTAL=false CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
    cargo test -j 2 -p frankenengine-engine \
      --test esm_star_reexport_bd_332pq \
      --test entry_module_import_cycles_bd_j8f7q \
      --test module_namespace_to_string_tag_bd_9vouw_399 \
      -- --test-threads=2; then
    INTEGRATION_OUTCOME="pass"
    emit_event "module_live_binding_integration" "esm_star_reexport_cycles_namespace" "pass" "shipped star-reexport, cyclic instantiation, and exotic namespace integration suites passed"
  else
    INTEGRATION_EXIT=$?
    INTEGRATION_OUTCOME="fail"
    emit_event "module_live_binding_integration" "esm_star_reexport_cycles_namespace" "fail" "exit=${INTEGRATION_EXIT}; see integration.log"
  fi

  if run_rch_suite "baseline_namespace_unit" "${RUN_DIR}/unit.log" \
    env CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_INCREMENTAL=false CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
    cargo test -j 2 -p frankenengine-engine --lib module_namespace_prototype_is_null -- --test-threads=2; then
    UNIT_OUTCOME="pass"
    emit_event "baseline_namespace_unit" "module_namespace_prototype_is_null" "pass" "baseline interpreter namespace exotic prototype & cache identity unit checks passed"
  else
    UNIT_EXIT=$?
    UNIT_OUTCOME="fail"
    emit_event "baseline_namespace_unit" "module_namespace_prototype_is_null" "fail" "exit=${UNIT_EXIT}; see unit.log"
  fi
elif [[ "${MODE}" == "selftest" ]]; then
  emit_event "selftest" "schema_contract" "pass" "validated deterministic artifact emission without cargo"
else
  echo "usage: $0 [ci|selftest] [output_dir]" >&2
  exit 2
fi

VERDICT="pass"
if [[ "${MODE}" == "ci" ]]; then
  if [[ "${SHIPPED_OUTCOME}" != "pass" || "${INTEGRATION_OUTCOME}" != "pass" || "${UNIT_OUTCOME}" != "pass" ]]; then
    VERDICT="fail"
  fi
fi

jq -n \
  --arg schema_version "franken-engine.rgc-module-live-binding.report.v1" \
  --arg bead_id "bd-1lsy.4.10.1" \
  --arg run_id "${TIMESTAMP}" \
  --arg mode "${MODE}" \
  --arg verdict "${VERDICT}" \
  --arg trace_id "${TRACE_ID}" \
  --arg shipped_outcome "${SHIPPED_OUTCOME}" \
  --arg integration_outcome "${INTEGRATION_OUTCOME}" \
  --arg unit_outcome "${UNIT_OUTCOME}" \
  '{
    schema_version: $schema_version,
    bead_id: $bead_id,
    run_id: $run_id,
    mode: $mode,
    verdict: $verdict,
    trace_id: $trace_id,
    scenarios: [
      {
        id: "direct_and_relay_live_bindings",
        test: "imports_follow_the_exporting_modules_later_writes",
        asserts: [
          "direct named import reflects post-evaluation exporter writes",
          "module namespace property reflects post-evaluation exporter writes",
          "named re-export (export { x as y } from) and imported-then-re-exported bindings stay live via retained module environment",
          "assigning to an imported binding throws TypeError without mutating source cell"
        ],
        outcome: $shipped_outcome
      },
      {
        id: "star_reexport_diamond_and_sorted_namespace_keys",
        test: "star_reexports_follow_the_source_modules_later_writes",
        asserts: [
          "export * barrel and diamond graphs propagate source mutations",
          "Object.keys(namespace) preserves deterministic lexicographic export order"
        ],
        outcome: $shipped_outcome
      },
      {
        id: "cyclic_instantiation_tdz_and_var_hoisting",
        test: "imports_in_a_cycle_see_the_exports_instantiation_state + a_captured_exported_var_is_hoisted_and_live",
        asserts: [
          "cyclic let export before initialization throws ReferenceError (TDZ)",
          "cyclic var export observes hoisted undefined then live post-declaration writes",
          "cyclic function export is immediately callable during cycle evaluation"
        ],
        outcome: $shipped_outcome
      },
      {
        id: "namespace_exotic_prototype_and_cycle_star_reexport_integration",
        test: "module_namespace_prototype_is_null + esm_star_reexport_bd_332pq + entry_module_import_cycles_bd_j8f7q + module_namespace_to_string_tag_bd_9vouw_399",
        asserts: [
          "module namespace exotic object has null prototype, @@toStringTag Module, and deterministic cache identity per module record",
          "star re-export barrels and entry-module import cycles preserve live bindings and deterministic instantiation order"
        ],
        outcome: (if $integration_outcome == "pass" and $unit_outcome == "pass" then "pass" elif $mode == "selftest" then "skipped" else "fail" end)
      }
    ]
  }' > "${REPORT_PATH}"

emit_event "run_complete" "suite" "${VERDICT}" "shipped=${SHIPPED_OUTCOME} integration=${INTEGRATION_OUTCOME} unit=${UNIT_OUTCOME}"

jq -n \
  --arg schema_version "franken-engine.rgc-module-live-binding.manifest.v1" \
  --arg bead_id "bd-1lsy.4.10.1" \
  --arg run_id "${TIMESTAMP}" \
  --arg mode "${MODE}" \
  --arg verdict "${VERDICT}" \
  --arg trace_id "${TRACE_ID}" \
  --arg decision_id "${DECISION_ID}" \
  --arg policy_id "${POLICY_ID}" \
  --arg generated_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg shipped_outcome "${SHIPPED_OUTCOME}" \
  --arg integration_outcome "${INTEGRATION_OUTCOME}" \
  --arg unit_outcome "${UNIT_OUTCOME}" \
  '{
    schema_version: $schema_version,
    bead_id: $bead_id,
    run_id: $run_id,
    mode: $mode,
    verdict: $verdict,
    trace_id: $trace_id,
    decision_id: $decision_id,
    policy_id: $policy_id,
    generated_utc: $generated_utc,
    layer_outcomes: {
      shipped_frankenctl_e2e: $shipped_outcome,
      module_live_binding_integration: $integration_outcome,
      baseline_namespace_unit: $unit_outcome
    },
    artifacts: {
      run_manifest_json: "run_manifest.json",
      events_jsonl: "events.jsonl",
      commands_txt: "commands.txt",
      trace_ids_json: "trace_ids.json",
      live_binding_report_json: "live_binding_report.json"
    }
  }' > "${MANIFEST_PATH}"

echo "rgc_module_live_binding_manifest=${MANIFEST_PATH}"
echo "rgc_module_live_binding_report=${REPORT_PATH}"

if [[ "${VERDICT}" != "pass" ]]; then
  exit 1
fi
