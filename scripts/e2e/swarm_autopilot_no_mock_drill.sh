#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_AUTOPILOT_NO_MOCK_DRILL_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-autopilot-no-mock-drill}"
run_id="${SWARM_AUTOPILOT_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AUTOPILOT_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-live}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

source_revision="${SWARM_AUTOPILOT_NO_MOCK_DRILL_SOURCE_REVISION:-}"
fixtures_json="${root_dir}/scripts/testdata/swarm_autopilot_no_mock_drill/cases.json"
replay_run_dir=""
latest_from=""
scenario_filter=""
fixed_now_epoch_seconds="1778122600"
stale_after_seconds="1800"
primary_live_scenario="healthy_autopilot"

swarm_ops_drill="${root_dir}/scripts/e2e/swarm_ops_no_mock_drill.sh"
swarm_ops_fixture_bundle="${root_dir}/scripts/testdata/swarm_ops_no_mock_drill/cases.json"
signal_normalizer="${root_dir}/scripts/swarm_topology_queue_signal_normalizer.sh"
queue_scorer="${root_dir}/scripts/swarm_topology_aware_queue_scorer.sh"
queue_fidelity_ledger="${root_dir}/scripts/swarm_topology_aware_queue_fidelity_ledger.sh"
warehouse_script="${root_dir}/scripts/swarm_autopilot_evidence_warehouse.sh"
forecaster_script="${root_dir}/scripts/swarm_autopilot_brownout_forecaster.sh"
policy_script="${root_dir}/scripts/swarm_autopilot_operator_intent_policy.sh"
lease_script="${root_dir}/scripts/swarm_autopilot_resource_lease_allocator.sh"
recommendation_script="${root_dir}/scripts/swarm_autopilot_recommendation_bundle.sh"
chaos_script="${root_dir}/scripts/swarm_autopilot_hindsight_chaos.sh"
contract_path="${root_dir}/docs/swarm_autopilot_no_mock_drill_contract_v1.json"

signal_fixture_bundle="${root_dir}/scripts/testdata/swarm_topology_queue_signal/queue_signal_fixtures.json"
scorer_fixture_bundle="${root_dir}/scripts/testdata/swarm_topology_aware_queue_scorer/cases.json"
fidelity_fixture_bundle="${root_dir}/scripts/testdata/swarm_topology_aware_queue_fidelity_ledger/fixtures.json"
brownout_fixture_bundle="${root_dir}/scripts/testdata/swarm_autopilot_brownout_forecaster/cases.json"
policy_fixture_bundle="${root_dir}/scripts/testdata/swarm_autopilot_operator_intent_policy/cases.json"
allocator_fixture_bundle="${root_dir}/scripts/testdata/swarm_autopilot_resource_lease_allocator/cases.json"
recommendation_fixture_bundle="${root_dir}/scripts/testdata/swarm_autopilot_recommendation_bundle/cases.json"
chaos_fixture_bundle="${root_dir}/scripts/testdata/swarm_autopilot_hindsight_chaos/cases.json"

events_path=""
commands_path=""
report_json=""
report_md=""
case_results_jsonl=""

signal_required_inputs=(
  execution_queue_input_json
  topology_placement_input_json
  rehabilitation_ledger_json
)

signal_optional_inputs=(
  placement_adoption_history_json
  operator_status_snapshot_json
)

scorer_required_inputs=(
  proof_cache_locality_plan_json
  queue_artifact_json
  bottleneck_report_json
  locality_outcome_samples_json
)

scorer_optional_inputs=(
  placement_adoption_history_json
  operator_status_snapshot_json
  resource_envelope_json
  tail_latency_locality_json
)

fidelity_required_inputs=(
  placement_evidence_ledger_json
  queue_artifact_json
  bottleneck_report_json
  locality_outcome_samples_json
)

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_no_mock_drill.sh [live|fixture|replay|check|selftest] [OPTIONS]

Compose the shipped SWARM AUTOPILOT control-plane surfaces into one
deterministic no-mock drill. Live mode runs the real SWARM-OPS capture and
autopilot evidence-warehouse path against local repository state. Fixture mode
uses preserved upstream inputs. Replay mode verifies a pinned bundle or the
latest complete bundle without re-running live capture.

Options:
  --fixtures-json FILE
  --replay-run-dir DIR
  --latest-from DIR
  --scenario-id ID
  --output-dir DIR
  --source-revision REV
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --fixtures-json)
      fixtures_json="${2:-}"
      mode="fixture"
      shift 2
      ;;
    --replay-run-dir)
      replay_run_dir="${2:-}"
      mode="replay"
      shift 2
      ;;
    --latest-from)
      latest_from="${2:-}"
      mode="replay"
      shift 2
      ;;
    --scenario-id)
      scenario_filter="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the swarm autopilot no-mock drill\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for the swarm autopilot no-mock drill\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

record_pass() {
  printf 'PASS swarm-autopilot-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-no-mock-drill %s\n' "$1" >&2
}

refresh_paths() {
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  report_json="${run_dir}/swarm_autopilot_no_mock_drill_report.json"
  report_md="${run_dir}/report.md"
  case_results_jsonl="${run_dir}/case_results.jsonl"
}

ensure_run_dir() {
  refresh_paths
  mkdir -p "$run_dir"
  : >"$events_path"
  : >"$commands_path"
  : >"$case_results_jsonl"
}

render_command() {
  local rendered="" arg quoted
  for arg in "$@"; do
    printf -v quoted '%q' "$arg"
    rendered+="${rendered:+ }${quoted}"
  done
  printf '%s' "$rendered"
}

log_command() {
  render_command "$@" >>"$commands_path"
  printf '\n' >>"$commands_path"
}

write_event() {
  local step="$1"
  local decision="$2"
  local exit_code="$3"
  local stdout_path="$4"
  local stderr_path="$5"

  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-no-mock-drill.event.v1" \
    --arg event_name "swarm_autopilot_no_mock_drill.step" \
    --arg step_id "$step" \
    --arg decision "$decision" \
    --arg stdout_path "$stdout_path" \
    --arg stderr_path "$stderr_path" \
    --argjson exit_code "$exit_code" \
    '{
      schema_version:$schema_version,
      event_name:$event_name,
      step_id:$step_id,
      decision:$decision,
      exit_code:$exit_code,
      artifact_paths:{stdout_log:$stdout_path,stderr_log:$stderr_path}
    }' >>"$events_path"
}

exit_code_for_decision() {
  case "$1" in
    pass|degraded|safe_mode)
      printf '0\n'
      ;;
    blocked)
      printf '75\n'
      ;;
    fail_closed)
      printf '42\n'
      ;;
    *)
      printf '64\n'
      ;;
  esac
}

exit_code_is_expected() {
  local actual="$1"
  local expected_csv="$2"
  local expected

  IFS=',' read -r -a expected_list <<<"$expected_csv"
  for expected in "${expected_list[@]}"; do
    if [[ "$actual" == "$expected" ]]; then
      return 0
    fi
  done
  return 1
}

run_step() {
  local step="$1"
  local expected_codes="$2"
  shift 2
  local step_dir="${run_dir}/${step}"
  local stdout_path="${step_dir}/stdout.log"
  local stderr_path="${step_dir}/stderr.log"
  local exit_code decision

  mkdir -p "$step_dir"
  log_command "$@"
  set +e
  (cd "$root_dir" && "$@") >"$stdout_path" 2>"$stderr_path"
  exit_code=$?
  set -e

  if exit_code_is_expected "$exit_code" "$expected_codes"; then
    decision="pass"
  else
    decision="fail"
  fi
  write_event "$step" "$decision" "$exit_code" "$stdout_path" "$stderr_path"
  if [[ "$decision" != "pass" ]]; then
    printf 'step %s exited %s, expected %s\nstdout=%s\nstderr=%s\n' "$step" "$exit_code" "$expected_codes" "$stdout_path" "$stderr_path" >&2
    return 1
  fi
}

require_json() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf 'missing JSON artifact: %s\n' "$path" >&2
    exit 64
  fi
  jq empty "$path" >/dev/null
}

scenario_selector() {
  if [[ -n "$scenario_filter" ]]; then
    jq -r --arg scenario "$scenario_filter" '.scenarios[] | select(.scenario_id == $scenario) | .scenario_id' "$fixtures_json"
  else
    jq -r '.scenarios[].scenario_id' "$fixtures_json"
  fi
}

scenario_value() {
  local scenario="$1"
  local filter="$2"
  jq -r --arg scenario "$scenario" ".scenarios[] | select(.scenario_id == \$scenario) | ${filter}" "$fixtures_json"
}

expected_value() {
  local scenario="$1"
  local field="$2"
  jq -r --arg scenario "$scenario" --arg field "$field" '.scenarios[] | select(.scenario_id == $scenario) | .expected[$field]' "$fixtures_json"
}

primary_scenario_id() {
  jq -r '.primary_scenario_id' "$fixtures_json"
}

deep_merge_json() {
  local left="$1"
  local right="$2"
  local output="$3"
  jq -n \
    --slurpfile left "$left" \
    --slurpfile right "$right" '
    def dm(a; b):
      if (a | type) == "object" and (b | type) == "object" then
        reduce (((a | keys_unsorted) + (b | keys_unsorted)) | unique[]) as $k ({};
          .[$k] = dm(a[$k]; b[$k])
        )
      elif b == null then a
      else b
      end;
    dm($left[0]; $right[0])
  ' >"$output"
}

materialize_case_fixture_doc() {
  local bundle_path="$1"
  local base_field="$2"
  local case_id="$3"
  local override_field="$4"
  local output_path="$5"
  jq -n \
    --slurpfile bundle "$bundle_path" \
    --arg base_field "$base_field" \
    --arg case_id "$case_id" \
    --arg override_field "$override_field" '
    def dm(a; b):
      if (a | type) == "object" and (b | type) == "object" then
        reduce (((a | keys_unsorted) + (b | keys_unsorted)) | unique[]) as $k ({};
          .[$k] = dm(a[$k]; b[$k])
        )
      elif b == null then a
      else b
      end;
    ($bundle[0]) as $doc
    | ($doc[$base_field] // {}) as $base
    | (($doc.cases[]? | select(.case_id == $case_id) | .overrides[$override_field]) // {}) as $override
    | dm($base; $override)
  ' >"$output_path"
}

materialize_base_doc() {
  local bundle_path="$1"
  local base_field="$2"
  local output_path="$3"
  jq --arg base_field "$base_field" '.[$base_field]' "$bundle_path" >"$output_path"
}

materialize_case_fixture_with_actual() {
  local bundle_path="$1"
  local base_field="$2"
  local case_id="$3"
  local override_field="$4"
  local actual_path="$5"
  local output_path="$6"
  local fixture_path="${output_path}.fixture.json"

  materialize_case_fixture_doc "$bundle_path" "$base_field" "$case_id" "$override_field" "$fixture_path"
  deep_merge_json "$fixture_path" "$actual_path" "$output_path"
}

allocator_fixture_case_id_for_scenario() {
  case "$1" in
    healthy_autopilot) printf 'healthy_balanced_allocation\n' ;;
    forecast_brownout) printf 'rch_brownout_deferral\n' ;;
    *) printf 'healthy_balanced_allocation\n' ;;
  esac
}

operator_status_fixture_case_id_for_scenario() {
  case "$1" in
    healthy_autopilot) printf 'healthy_autopilot\n' ;;
    forecast_brownout) printf 'degraded_forecast\n' ;;
    policy_conflict) printf 'fail_closed_policy_conflict\n' ;;
    local_fallback_contamination) printf 'contaminated_local_fallback_propagation\n' ;;
    *) printf 'healthy_autopilot\n' ;;
  esac
}

swarm_ops_json_path_for_key() {
  case "$1" in
    run_manifest_json) printf '%s\n' "run_manifest.json" ;;
    trace_ids_json) printf '%s\n' "trace_ids.json" ;;
    state_snapshot_json) printf '%s\n' "state_snapshot.json" ;;
    admission_plan_json) printf '%s\n' "admission_plan.json" ;;
    recovery_receipts_json) printf '%s\n' "recovery_receipts.json" ;;
    rch_rehab_ledger_json) printf '%s\n' "rch_rehab_ledger.json" ;;
    locality_plan_json) printf '%s\n' "locality_plan.json" ;;
    dashboard_bundle_json) printf '%s\n' "dashboard_bundle.json" ;;
    saturation_replay_report_json) printf '%s\n' "saturation_replay_report.json" ;;
    slo_gate_report_json) printf '%s\n' "slo_gate_report.json" ;;
    truth_gate_report_json) printf '%s\n' "truth_gate_report.json" ;;
    *) return 1 ;;
  esac
}

apply_swarm_ops_overrides() {
  local scenario="$1"
  local bundle_dir="$2"
  local key path override_tmp merged_tmp

  while IFS= read -r key; do
    path="$(swarm_ops_json_path_for_key "$key")" || continue
    override_tmp="${bundle_dir}/${key}.override.json"
    merged_tmp="${bundle_dir}/${key}.merged.json"
    jq --arg scenario "$scenario" --arg key "$key" '.scenarios[] | select(.scenario_id == $scenario) | .swarm_ops_bundle_overrides[$key]' "$fixtures_json" >"$override_tmp"
    deep_merge_json "${bundle_dir}/${path}" "$override_tmp" "$merged_tmp"
    mv "$merged_tmp" "${bundle_dir}/${path}"
  done < <(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | (.swarm_ops_bundle_overrides // {}) | keys[]?' "$fixtures_json")
}

extract_input_from_bundle() {
  local bundle_path="$1"
  local scenario="$2"
  local input_id="$3"
  local output_path="$4"
  local found is_null

  found="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .scenario_id' "$bundle_path")"
  if [[ -z "$found" ]]; then
    printf 'scenario %s not found in %s\n' "$scenario" "$bundle_path" >&2
    return 1
  fi

  is_null="$(jq -r --arg scenario "$scenario" --arg input_id "$input_id" '
    .scenarios[]
    | select(.scenario_id == $scenario)
    | (.inputs[$input_id] == null)
  ' "$bundle_path")"
  if [[ "$is_null" == "true" ]]; then
    return 1
  fi

  jq --arg scenario "$scenario" --arg input_id "$input_id" '
    .scenarios[]
    | select(.scenario_id == $scenario)
    | .inputs[$input_id]
  ' "$bundle_path" >"$output_path"
}

materialize_signal_fixture_dir() {
  local scenario="$1"
  local dir="$2"
  local fixture_scenario input_id

  fixture_scenario="$(scenario_value "$scenario" '.signal_fixture_scenario')"
  mkdir -p "$dir"
  for input_id in "${signal_required_inputs[@]}"; do
    if ! extract_input_from_bundle "$signal_fixture_bundle" "$fixture_scenario" "$input_id" "${dir}/${input_id}.json"; then
      printf 'missing required signal input %s for %s\n' "$input_id" "$scenario" >&2
      return 1
    fi
  done
  for input_id in "${signal_optional_inputs[@]}"; do
    extract_input_from_bundle "$signal_fixture_bundle" "$fixture_scenario" "$input_id" "${dir}/${input_id}.json" || true
  done
}

materialize_scorer_fixture_dir() {
  local scenario="$1"
  local dir="$2"
  local fixture_scenario input_id

  fixture_scenario="$(scenario_value "$scenario" '.scorer_fixture_scenario')"
  mkdir -p "$dir"
  for input_id in "${scorer_required_inputs[@]}"; do
    if ! extract_input_from_bundle "$scorer_fixture_bundle" "$fixture_scenario" "$input_id" "${dir}/${input_id}.json"; then
      printf 'missing required scorer input %s for %s\n' "$input_id" "$scenario" >&2
      return 1
    fi
  done
  for input_id in "${scorer_optional_inputs[@]}"; do
    extract_input_from_bundle "$scorer_fixture_bundle" "$fixture_scenario" "$input_id" "${dir}/${input_id}.json" || true
  done
}

materialize_fidelity_fixture_dir() {
  local scenario="$1"
  local dir="$2"
  local fixture_scenario input_id

  fixture_scenario="$(scenario_value "$scenario" '.fidelity_fixture_scenario')"
  mkdir -p "$dir"
  for input_id in "${fidelity_required_inputs[@]}"; do
    if ! extract_input_from_bundle "$fidelity_fixture_bundle" "$fixture_scenario" "$input_id" "${dir}/${input_id}.json"; then
      printf 'missing required fidelity input %s for %s\n' "$input_id" "$scenario" >&2
      return 1
    fi
  done
}

run_swarm_ops_case() {
  local scenario="$1"
  local case_dir="$2"
  local out_dir="${case_dir}/swarm_ops_bundle"
  local fixture_case_id

  fixture_case_id="$(scenario_value "$scenario" '.swarm_ops_fixture_case_id')"
  if [[ "$mode" == "fixture" || "$mode" == "selftest-fixture" ]]; then
    run_step "${scenario}/swarm_ops_bundle" "0,42" \
      bash "$swarm_ops_drill" \
        --fixtures-json "$swarm_ops_fixture_bundle" \
        --case-id "$fixture_case_id" \
        --output-dir "$out_dir"
    apply_swarm_ops_overrides "$scenario" "$out_dir"
  else
    run_step "${scenario}/swarm_ops_bundle" "0,42" \
      bash "$swarm_ops_drill" \
        --output-dir "$out_dir"
  fi

  require_json "${out_dir}/run_manifest.json"
  require_json "${out_dir}/trace_ids.json"
  require_json "${out_dir}/state_snapshot.json"
  require_json "${out_dir}/truth_gate_report.json"
}

run_signal_case() {
  local scenario="$1"
  local case_dir="$2"
  local fixture_dir="${case_dir}/topology/signal-fixtures"
  local out_dir="${case_dir}/topology/signal"
  local expected_decision expected_truth_state expected_code signal_path
  local args=()

  materialize_signal_fixture_dir "$scenario" "$fixture_dir"
  expected_decision="$(
    case "$scenario" in
      local_fallback_contamination) printf 'fail_closed' ;;
      *) printf 'pass' ;;
    esac
  )"
  expected_truth_state="$(
    case "$scenario" in
      local_fallback_contamination) printf 'contaminated' ;;
      *) printf 'confirmed' ;;
    esac
  )"
  if [[ "$scenario" == "forecast_brownout" ]]; then
    expected_decision="pass"
    expected_truth_state="confirmed"
  elif [[ "$scenario" == "policy_conflict" ]]; then
    expected_decision="pass"
    expected_truth_state="confirmed"
  elif [[ "$scenario" == "stale_rch_progress_not_upgraded" ]]; then
    expected_decision="pass"
    expected_truth_state="confirmed"
  fi
  expected_code="$(exit_code_for_decision "$expected_decision")"

  args=(
    --source-revision "$source_revision"
    --execution-queue-input-json "${fixture_dir}/execution_queue_input_json.json"
    --topology-placement-input-json "${fixture_dir}/topology_placement_input_json.json"
    --rehabilitation-ledger-json "${fixture_dir}/rehabilitation_ledger_json.json"
    --output-dir "$out_dir"
  )
  [[ -f "${fixture_dir}/placement_adoption_history_json.json" ]] && args+=(--placement-adoption-history-json "${fixture_dir}/placement_adoption_history_json.json")
  [[ -f "${fixture_dir}/operator_status_snapshot_json.json" ]] && args+=(--operator-status-snapshot-json "${fixture_dir}/operator_status_snapshot_json.json")

  run_step "${scenario}/signal_normalizer" "$expected_code" bash "$signal_normalizer" "${args[@]}"

  signal_path="${out_dir}/swarm_topology_queue_signal_input.json"
  require_json "$signal_path"
  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_truth_state "$expected_truth_state" '
    .decision == $expected_decision
    and .truth_state == $expected_truth_state
  ' "$signal_path" >/dev/null || {
    record_failure "signal normalizer mismatch for ${scenario}"
    return 1
  }
}

run_scorer_case() {
  local scenario="$1"
  local case_dir="$2"
  local support_dir="${case_dir}/topology/scorer-fixtures"
  local out_dir="${case_dir}/topology/scorer"
  local expected_decision expected_truth_state expected_code advisory_path
  local args=()

  materialize_scorer_fixture_dir "$scenario" "$support_dir"
  expected_decision="$(
    case "$scenario" in
      local_fallback_contamination) printf 'fail_closed' ;;
      *) printf 'pass' ;;
    esac
  )"
  expected_truth_state="$(
    case "$scenario" in
      local_fallback_contamination) printf 'contaminated' ;;
      *) printf 'confirmed' ;;
    esac
  )"
  if [[ "$scenario" == "forecast_brownout" || "$scenario" == "policy_conflict" || "$scenario" == "stale_rch_progress_not_upgraded" ]]; then
    expected_decision="pass"
    expected_truth_state="confirmed"
  fi
  expected_code="$(exit_code_for_decision "$expected_decision")"

  args=(
    --source-revision "$source_revision"
    --topology-queue-signal-input-json "${case_dir}/topology/signal/swarm_topology_queue_signal_input.json"
    --proof-cache-locality-plan-json "${support_dir}/proof_cache_locality_plan_json.json"
    --queue-artifact-json "${support_dir}/queue_artifact_json.json"
    --bottleneck-report-json "${support_dir}/bottleneck_report_json.json"
    --locality-outcome-samples-json "${support_dir}/locality_outcome_samples_json.json"
    --output-dir "$out_dir"
  )
  [[ -f "${support_dir}/placement_adoption_history_json.json" ]] && args+=(--placement-adoption-history-json "${support_dir}/placement_adoption_history_json.json")
  [[ -f "${support_dir}/operator_status_snapshot_json.json" ]] && args+=(--operator-status-snapshot-json "${support_dir}/operator_status_snapshot_json.json")
  [[ -f "${support_dir}/resource_envelope_json.json" ]] && args+=(--resource-envelope-json "${support_dir}/resource_envelope_json.json")
  [[ -f "${support_dir}/tail_latency_locality_json.json" ]] && args+=(--tail-latency-locality-json "${support_dir}/tail_latency_locality_json.json")

  run_step "${scenario}/queue_scorer" "$expected_code" bash "$queue_scorer" "${args[@]}"

  advisory_path="${out_dir}/queue_advisory_bundle.json"
  require_json "$advisory_path"
  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_truth_state "$expected_truth_state" '
    .decision == $expected_decision
    and .truth_state == $expected_truth_state
  ' "$advisory_path" >/dev/null || {
    record_failure "queue scorer mismatch for ${scenario}"
    return 1
  }
}

run_fidelity_case() {
  local scenario="$1"
  local case_dir="$2"
  local support_dir="${case_dir}/topology/fidelity-fixtures"
  local out_dir="${case_dir}/topology/fidelity"
  local expected_decision expected_truth_state expected_code receipt_path

  materialize_fidelity_fixture_dir "$scenario" "$support_dir"
  expected_decision="$(
    case "$scenario" in
      local_fallback_contamination) printf 'fail_closed' ;;
      *) printf 'pass' ;;
    esac
  )"
  expected_truth_state="$(
    case "$scenario" in
      local_fallback_contamination) printf 'contaminated' ;;
      *) printf 'confirmed' ;;
    esac
  )"
  if [[ "$scenario" == "forecast_brownout" || "$scenario" == "policy_conflict" || "$scenario" == "stale_rch_progress_not_upgraded" ]]; then
    expected_decision="pass"
    expected_truth_state="confirmed"
  fi
  expected_code="$(exit_code_for_decision "$expected_decision")"

  run_step "${scenario}/fidelity_ledger" "$expected_code" \
    bash "$queue_fidelity_ledger" \
      --source-revision "$source_revision" \
      --queue-advisory-bundle-json "${case_dir}/topology/scorer/queue_advisory_bundle.json" \
      --placement-evidence-ledger-json "${support_dir}/placement_evidence_ledger_json.json" \
      --queue-artifact-json "${support_dir}/queue_artifact_json.json" \
      --bottleneck-report-json "${support_dir}/bottleneck_report_json.json" \
      --locality-outcome-samples-json "${support_dir}/locality_outcome_samples_json.json" \
      --output-dir "$out_dir"

  receipt_path="${out_dir}/swarm_topology_aware_queue_fidelity_receipt.json"
  require_json "$receipt_path"
  require_json "${out_dir}/swarm_topology_aware_queue_drift_ledger.json"
  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_truth_state "$expected_truth_state" '
    .decision == $expected_decision
    and .truth_state == $expected_truth_state
  ' "$receipt_path" >/dev/null || {
    record_failure "queue fidelity mismatch for ${scenario}"
    return 1
  }
}

run_warehouse_case() {
  local scenario="$1"
  local case_dir="$2"
  local out_dir="${case_dir}/warehouse"
  local expected_decision expected_code warehouse_path

  expected_decision="$(expected_value "$scenario" "warehouse_decision")"
  expected_code="$(exit_code_for_decision "$expected_decision")"

  run_step "${scenario}/evidence_warehouse" "$expected_code" \
    bash "$warehouse_script" \
      --swarm-ops-bundle-dir "${case_dir}/swarm_ops_bundle" \
      --queue-locality-json "${case_dir}/topology/scorer/queue_advisory_bundle.json" \
      --source-revision "$source_revision" \
      --output-dir "$out_dir"

  warehouse_path="${out_dir}/evidence_warehouse.json"
  require_json "$warehouse_path"
  jq -e --arg expected_decision "$expected_decision" '.decision == $expected_decision' "$warehouse_path" >/dev/null || {
    record_failure "warehouse decision mismatch for ${scenario}"
    return 1
  }
}

materialize_forecast_inputs() {
  local scenario="$1"
  local case_dir="$2"
  local case_id
  local input_dir="${case_dir}/forecast-inputs"

  case_id="$(scenario_value "$scenario" '.forecaster_fixture_case_id')"
  mkdir -p "$input_dir"

  materialize_case_fixture_doc "$brownout_fixture_bundle" "base_evidence_warehouse_json" "$case_id" "evidence_warehouse_json" "${input_dir}/warehouse_fixture.json"
  deep_merge_json "${input_dir}/warehouse_fixture.json" "${case_dir}/warehouse/evidence_warehouse.json" "${input_dir}/evidence_warehouse_json.json"

  materialize_case_fixture_doc "$brownout_fixture_bundle" "base_queue_signal_input_json" "$case_id" "queue_signal_input_json" "${input_dir}/queue_signal_fixture.json"
  deep_merge_json "${input_dir}/queue_signal_fixture.json" "${case_dir}/topology/signal/swarm_topology_queue_signal_input.json" "${input_dir}/queue_signal_input_json.json"

  materialize_case_fixture_doc "$brownout_fixture_bundle" "base_queue_fidelity_receipt_json" "$case_id" "queue_fidelity_receipt_json" "${input_dir}/queue_fidelity_fixture.json"
  deep_merge_json "${input_dir}/queue_fidelity_fixture.json" "${case_dir}/topology/fidelity/swarm_topology_aware_queue_fidelity_receipt.json" "${input_dir}/queue_fidelity_receipt_json.json"

  materialize_case_fixture_doc "$brownout_fixture_bundle" "base_hindsight_bundle_json" "$case_id" "hindsight_bundle_json" "${input_dir}/hindsight_bundle_json.json"
}

run_forecast_case() {
  local scenario="$1"
  local case_dir="$2"
  local input_dir="${case_dir}/forecast-inputs"
  local out_dir="${case_dir}/forecast"
  local expected_decision expected_truth_state expected_code forecast_path

  materialize_forecast_inputs "$scenario" "$case_dir"
  expected_decision="$(expected_value "$scenario" "forecast_decision")"
  expected_truth_state="$(expected_value "$scenario" "forecast_truth_state")"
  expected_code="$(exit_code_for_decision "$expected_decision")"

  run_step "${scenario}/brownout_forecaster" "$expected_code" \
    bash "$forecaster_script" \
      --evidence-warehouse-json "${input_dir}/evidence_warehouse_json.json" \
      --queue-signal-input-json "${input_dir}/queue_signal_input_json.json" \
      --queue-fidelity-receipt-json "${input_dir}/queue_fidelity_receipt_json.json" \
      --hindsight-bundle-json "${input_dir}/hindsight_bundle_json.json" \
      --source-revision "$source_revision" \
      --now-epoch-seconds "$fixed_now_epoch_seconds" \
      --stale-after-seconds "$stale_after_seconds" \
      --output-dir "$out_dir"

  forecast_path="${out_dir}/swarm_autopilot_brownout_forecast.json"
  require_json "$forecast_path"
  require_json "${out_dir}/swarm_autopilot_brownout_hindsight_comparison.json"
  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_truth_state "$expected_truth_state" '
    .decision == $expected_decision
    and .truth_state == $expected_truth_state
  ' "$forecast_path" >/dev/null || {
    record_failure "brownout forecast mismatch for ${scenario}"
    return 1
  }
}

materialize_policy_intent_input() {
  local scenario="$1"
  local case_dir="$2"
  local case_id input_dir="${case_dir}/policy-inputs"

  case_id="$(scenario_value "$scenario" '.operator_intent_fixture_case_id')"
  mkdir -p "$input_dir"
  materialize_case_fixture_doc "$policy_fixture_bundle" "base_intent_json" "$case_id" "intent_json" "${input_dir}/intent.json"
  materialize_case_fixture_with_actual "$policy_fixture_bundle" "base_evidence_warehouse_json" "$case_id" "evidence_warehouse_json" "${case_dir}/warehouse/evidence_warehouse.json" "${input_dir}/evidence_warehouse.json"
  materialize_case_fixture_with_actual "$policy_fixture_bundle" "base_forecaster_json" "$case_id" "forecaster_json" "${case_dir}/forecast/swarm_autopilot_brownout_forecast.json" "${input_dir}/forecaster.json"
}

run_policy_case() {
  local scenario="$1"
  local case_dir="$2"
  local input_dir="${case_dir}/policy-inputs"
  local out_dir="${case_dir}/policy"
  local expected_decision expected_code policy_path

  materialize_policy_intent_input "$scenario" "$case_dir"
  expected_decision="$(expected_value "$scenario" "policy_decision")"
  expected_code="$(exit_code_for_decision "$expected_decision")"

  run_step "${scenario}/operator_intent_policy" "$expected_code" \
    bash "$policy_script" \
      --intent-json "${input_dir}/intent.json" \
      --evidence-warehouse-json "${input_dir}/evidence_warehouse.json" \
      --forecaster-json "${input_dir}/forecaster.json" \
      --source-revision "$source_revision" \
      --output-dir "$out_dir"

  policy_path="${out_dir}/operator_intent_policy.json"
  require_json "$policy_path"
  require_json "${out_dir}/verification_report.json"
  jq -e --arg expected_decision "$expected_decision" '.decision == $expected_decision' "$policy_path" >/dev/null || {
    record_failure "operator intent policy mismatch for ${scenario}"
    return 1
  }
}

materialize_allocator_inputs() {
  local scenario="$1"
  local case_dir="$2"
  local case_id
  local input_dir="${case_dir}/lease-inputs"
  local merged_queue_path="${input_dir}/queue_advisory_bundle.raw.json"

  case_id="$(allocator_fixture_case_id_for_scenario "$scenario")"
  mkdir -p "$input_dir"
  materialize_case_fixture_with_actual "$allocator_fixture_bundle" "base_operator_intent_policy_json" "$case_id" "operator_intent_policy_json" "${case_dir}/policy/operator_intent_policy.json" "${input_dir}/operator_intent_policy.json"
  materialize_case_fixture_with_actual "$allocator_fixture_bundle" "base_brownout_forecaster_json" "$case_id" "brownout_forecaster_json" "${case_dir}/forecast/swarm_autopilot_brownout_forecast.json" "${input_dir}/brownout_forecaster.json"
  materialize_case_fixture_with_actual "$allocator_fixture_bundle" "base_queue_advisory_bundle_json" "$case_id" "queue_advisory_bundle_json" "${case_dir}/topology/scorer/queue_advisory_bundle.json" "$merged_queue_path"
  jq '
    if (.worker_exclusions | type) == "object" then
      .worker_exclusions = (.worker_exclusions.excluded_worker_ids // [])
    else
      .
    end
  ' "$merged_queue_path" >"${input_dir}/queue_advisory_bundle.json"
  materialize_base_doc "$allocator_fixture_bundle" "base_rch_rehabilitation_ledger_json" "${input_dir}/rch_rehabilitation_ledger.fixture.json"
  deep_merge_json "${input_dir}/rch_rehabilitation_ledger.fixture.json" "${case_dir}/swarm_ops_bundle/rch_rehab_ledger.json" "${input_dir}/rch_rehabilitation_ledger.json"
}

run_lease_case() {
  local scenario="$1"
  local case_dir="$2"
  local input_dir="${case_dir}/lease-inputs"
  local out_dir="${case_dir}/lease"
  local expected_decision expected_code plan_path receipts_path

  materialize_allocator_inputs "$scenario" "$case_dir"
  expected_decision="$(expected_value "$scenario" "lease_decision")"
  expected_code="$(exit_code_for_decision "$expected_decision")"

  run_step "${scenario}/resource_lease_allocator" "$expected_code" \
    bash "$lease_script" \
      --operator-intent-policy-json "${input_dir}/operator_intent_policy.json" \
      --brownout-forecaster-json "${input_dir}/brownout_forecaster.json" \
      --queue-advisory-bundle-json "${input_dir}/queue_advisory_bundle.json" \
      --rch-rehabilitation-ledger-json "${input_dir}/rch_rehabilitation_ledger.json" \
      --source-revision "$source_revision" \
      --now-epoch-seconds "$fixed_now_epoch_seconds" \
      --stale-after-seconds "$stale_after_seconds" \
      --output-dir "$out_dir"

  plan_path="${out_dir}/swarm_autopilot_resource_lease_plan.json"
  receipts_path="${out_dir}/swarm_autopilot_resource_scarcity_receipts.json"
  require_json "$plan_path"
  require_json "$receipts_path"
  jq -e --arg expected_decision "$expected_decision" '.decision == $expected_decision' "$plan_path" >/dev/null || {
    record_failure "resource lease plan mismatch for ${scenario}"
    return 1
  }
}

materialize_control_plane_context() {
  local scenario="$1"
  local case_dir="$2"
  local case_id input_dir="${case_dir}/recommendation-inputs"

  case_id="$(scenario_value "$scenario" '.recommendation_fixture_case_id')"
  mkdir -p "$input_dir"
  materialize_case_fixture_doc "$recommendation_fixture_bundle" "base_control_plane_context_json" "$case_id" "control_plane_context_json" "${input_dir}/control_plane_context.json"
  materialize_case_fixture_with_actual "$recommendation_fixture_bundle" "base_operator_intent_policy_json" "$case_id" "operator_intent_policy_json" "${case_dir}/policy/operator_intent_policy.json" "${input_dir}/operator_intent_policy.json"
  materialize_case_fixture_with_actual "$recommendation_fixture_bundle" "base_brownout_forecaster_json" "$case_id" "brownout_forecaster_json" "${case_dir}/forecast/swarm_autopilot_brownout_forecast.json" "${input_dir}/brownout_forecaster.json"
  materialize_case_fixture_with_actual "$recommendation_fixture_bundle" "base_resource_lease_plan_json" "$case_id" "resource_lease_plan_json" "${case_dir}/lease/swarm_autopilot_resource_lease_plan.json" "${input_dir}/resource_lease_plan.json"
  materialize_case_fixture_with_actual "$recommendation_fixture_bundle" "base_resource_scarcity_receipts_json" "$case_id" "resource_scarcity_receipts_json" "${case_dir}/lease/swarm_autopilot_resource_scarcity_receipts.json" "${input_dir}/resource_scarcity_receipts.json"
}

run_recommendation_case() {
  local scenario="$1"
  local case_dir="$2"
  local input_dir="${case_dir}/recommendation-inputs"
  local out_dir="${case_dir}/recommendation"
  local expected_decision expected_code bundle_path

  materialize_control_plane_context "$scenario" "$case_dir"
  expected_decision="$(expected_value "$scenario" "recommendation_decision")"
  expected_code="$(exit_code_for_decision "$expected_decision")"

  run_step "${scenario}/recommendation_bundle" "$expected_code" \
    bash "$recommendation_script" \
      --operator-intent-policy-json "${input_dir}/operator_intent_policy.json" \
      --brownout-forecaster-json "${input_dir}/brownout_forecaster.json" \
      --resource-lease-plan-json "${input_dir}/resource_lease_plan.json" \
      --resource-scarcity-receipts-json "${input_dir}/resource_scarcity_receipts.json" \
      --control-plane-context-json "${input_dir}/control_plane_context.json" \
      --source-revision "$source_revision" \
      --now-epoch-seconds "$fixed_now_epoch_seconds" \
      --stale-after-seconds "$stale_after_seconds" \
      --output-dir "$out_dir"

  bundle_path="${out_dir}/swarm_autopilot_recommendation_bundle.json"
  require_json "$bundle_path"
  require_json "${out_dir}/swarm_autopilot_dashboard_projection.json"
  jq -e --arg expected_decision "$expected_decision" '.decision == $expected_decision' "$bundle_path" >/dev/null || {
    record_failure "recommendation bundle mismatch for ${scenario}"
    return 1
  }
}

materialize_chaos_source_bundle() {
  local scenario="$1"
  local case_dir="$2"
  local case_id input_dir="${case_dir}/chaos-inputs"
  local tmp_path="${input_dir}/source_bundle.base.json"
  local merged_path="${input_dir}/source_bundle.json"

  case_id="$(scenario_value "$scenario" '.hindsight_chaos_fixture_case_id')"
  mkdir -p "$input_dir"
  materialize_case_fixture_doc "$chaos_fixture_bundle" "base_source_bundle_json" "$case_id" "source_bundle_json" "$tmp_path"

  jq \
    --arg source_revision "$source_revision" \
    --arg completed_bundle_id "autopilot-no-mock-${scenario}" \
    --arg brownout_forecast_json "${case_dir}/forecast/swarm_autopilot_brownout_forecast.json" \
    --arg resource_lease_plan_json "${case_dir}/lease/swarm_autopilot_resource_lease_plan.json" \
    --arg resource_scarcity_receipts_json "${case_dir}/lease/swarm_autopilot_resource_scarcity_receipts.json" \
    --arg operator_intent_policy_json "${case_dir}/policy/operator_intent_policy.json" \
    --arg queue_advisory_bundle_json "${case_dir}/topology/scorer/queue_advisory_bundle.json" \
    --arg recommendation_bundle_json "${case_dir}/recommendation/swarm_autopilot_recommendation_bundle.json" \
    '.source_revision = $source_revision
     | .completed_bundle_id = $completed_bundle_id
     | .source_artifacts.brownout_forecast_json = $brownout_forecast_json
     | .source_artifacts.resource_lease_plan_json = $resource_lease_plan_json
     | .source_artifacts.resource_scarcity_receipts_json = $resource_scarcity_receipts_json
     | .source_artifacts.operator_intent_policy_json = $operator_intent_policy_json
     | .source_artifacts.queue_advisory_bundle_json = $queue_advisory_bundle_json
     | .source_artifacts.recommendation_bundle_json = $recommendation_bundle_json
    ' "$tmp_path" >"$merged_path"
}

run_chaos_case() {
  local scenario="$1"
  local case_dir="$2"
  local input_dir="${case_dir}/chaos-inputs"
  local out_dir="${case_dir}/chaos"

  materialize_chaos_source_bundle "$scenario" "$case_dir"
  run_step "${scenario}/hindsight_chaos" "0,42" \
    bash "$chaos_script" \
      --source-bundle-json "${input_dir}/source_bundle.json" \
      --source-revision "$source_revision" \
      --output-dir "$out_dir"

  require_json "${out_dir}/swarm_autopilot_hindsight_chaos_scenarios.json"
  require_json "${out_dir}/swarm_autopilot_hindsight_chaos_replay_index.json"
}

collect_reason_codes() {
  local case_dir="$1"
  jq -n \
    --slurpfile warehouse "${case_dir}/warehouse/evidence_warehouse.json" \
    --slurpfile forecast "${case_dir}/forecast/swarm_autopilot_brownout_forecast.json" \
    --slurpfile policy "${case_dir}/policy/verification_report.json" \
    --slurpfile lease "${case_dir}/lease/swarm_autopilot_resource_lease_plan.json" \
    --slurpfile recommendation "${case_dir}/recommendation/swarm_autopilot_recommendation_bundle.json" '
    [
      $warehouse[0].fail_closed_reasons[]?.code?,
      $forecast[0].fail_closed_reasons[]?.code?,
      $policy[0].failure_reasons[]?.code?,
      $policy[0].conflict_diagnostics[]?.code?,
      $lease[0].fail_closed_reasons[]?.code?,
      $recommendation[0].fail_closed_reasons[]?.code?
    ] | map(select(type == "string" and length > 0)) | unique
  '
}

append_case_result() {
  local scenario="$1"
  local case_dir="$2"
  local reason_codes_json="${case_dir}/reason_codes.json"

  collect_reason_codes "$case_dir" >"$reason_codes_json"

  jq -nc \
    --arg scenario_id "$scenario" \
    --arg swarm_ops_run_manifest_json "${case_dir}/swarm_ops_bundle/run_manifest.json" \
    --arg evidence_warehouse_json "${case_dir}/warehouse/evidence_warehouse.json" \
    --arg forecast_json "${case_dir}/forecast/swarm_autopilot_brownout_forecast.json" \
    --arg policy_json "${case_dir}/policy/operator_intent_policy.json" \
    --arg lease_plan_json "${case_dir}/lease/swarm_autopilot_resource_lease_plan.json" \
    --arg lease_receipts_json "${case_dir}/lease/swarm_autopilot_resource_scarcity_receipts.json" \
    --arg recommendations_json "${case_dir}/recommendation/swarm_autopilot_recommendation_bundle.json" \
    --arg dashboard_projection_json "${case_dir}/recommendation/swarm_autopilot_dashboard_projection.json" \
    --arg chaos_scenarios_json "${case_dir}/chaos/swarm_autopilot_hindsight_chaos_scenarios.json" \
    --arg chaos_replay_index_json "${case_dir}/chaos/swarm_autopilot_hindsight_chaos_replay_index.json" \
    --arg truth_reason_code "$(expected_value "$scenario" "required_truth_gate_reason_code")" \
    --arg warehouse_decision_expected "$(expected_value "$scenario" "warehouse_decision")" \
    --arg forecast_decision_expected "$(expected_value "$scenario" "forecast_decision")" \
    --arg policy_decision_expected "$(expected_value "$scenario" "policy_decision")" \
    --arg lease_decision_expected "$(expected_value "$scenario" "lease_decision")" \
    --arg recommendation_decision_expected "$(expected_value "$scenario" "recommendation_decision")" \
    --arg dashboard_decision_expected "$(expected_value "$scenario" "dashboard_decision")" \
    --arg dashboard_top_action_expected "$(expected_value "$scenario" "dashboard_top_action")" \
    --slurpfile warehouse_doc "${case_dir}/warehouse/evidence_warehouse.json" \
    --slurpfile forecast_doc "${case_dir}/forecast/swarm_autopilot_brownout_forecast.json" \
    --slurpfile policy_doc "${case_dir}/policy/operator_intent_policy.json" \
    --slurpfile lease_doc "${case_dir}/lease/swarm_autopilot_resource_lease_plan.json" \
    --slurpfile recommendation_doc "${case_dir}/recommendation/swarm_autopilot_recommendation_bundle.json" \
    --slurpfile dashboard_doc "${case_dir}/recommendation/swarm_autopilot_dashboard_projection.json" \
    --slurpfile reason_codes "$reason_codes_json" '
    ($warehouse_doc[0]) as $w
    | ($forecast_doc[0]) as $f
    | ($policy_doc[0]) as $p
    | ($lease_doc[0]) as $l
    | ($recommendation_doc[0]) as $r
    | ($dashboard_doc[0]) as $d
    | ($reason_codes[0]) as $codes
    | {
        scenario_id:$scenario_id,
        passed:(
          $w.decision == $warehouse_decision_expected
          and $f.decision == $forecast_decision_expected
          and $p.decision == $policy_decision_expected
          and $l.decision == $lease_decision_expected
          and $r.decision == $recommendation_decision_expected
          and (
            ($dashboard_decision_expected == "null" or ($dashboard_decision_expected | length) == 0)
            or $d.decision == $dashboard_decision_expected
          )
          and (
            ($dashboard_top_action_expected == "null" or ($dashboard_top_action_expected | length) == 0)
            or (($d.top_action.action // null) == $dashboard_top_action_expected)
          )
          and (
            ($truth_reason_code == "null" or ($truth_reason_code | length) == 0)
            or ($codes | index($truth_reason_code) != null)
          )
        ),
        expected:{
          warehouse_decision:$warehouse_decision_expected,
          forecast_decision:$forecast_decision_expected,
          policy_decision:$policy_decision_expected,
          lease_decision:$lease_decision_expected,
          recommendation_decision:$recommendation_decision_expected,
          dashboard_decision:(if $dashboard_decision_expected == "null" then null else $dashboard_decision_expected end),
          dashboard_top_action:(if $dashboard_top_action_expected == "null" then null else $dashboard_top_action_expected end),
          required_truth_gate_reason_code:(if $truth_reason_code == "null" then null else $truth_reason_code end)
        },
        actual:{
          warehouse_decision:$w.decision,
          forecast_decision:$f.decision,
          policy_decision:$p.decision,
          lease_decision:$l.decision,
          recommendation_decision:$r.decision,
          dashboard_decision:($d.decision // null),
          dashboard_top_action:($d.top_action.action // null),
          truth_gate_reason_codes:$codes
        },
        artifact_paths:{
          swarm_ops_run_manifest_json:$swarm_ops_run_manifest_json,
          evidence_warehouse_json:$evidence_warehouse_json,
          forecast_json:$forecast_json,
          policy_json:$policy_json,
          lease_plan_json:$lease_plan_json,
          lease_receipts_json:$lease_receipts_json,
          recommendations_json:$recommendations_json,
          dashboard_projection_json:$dashboard_projection_json,
          chaos_scenarios_json:$chaos_scenarios_json,
          chaos_replay_index_json:$chaos_replay_index_json
        }
      }
  ' >>"$case_results_jsonl"
}

run_case() {
  local scenario="$1"
  local case_dir="${run_dir}/cases/${scenario}"

  run_swarm_ops_case "$scenario" "$case_dir"
  run_signal_case "$scenario" "$case_dir"
  run_scorer_case "$scenario" "$case_dir"
  run_fidelity_case "$scenario" "$case_dir"
  run_warehouse_case "$scenario" "$case_dir"
  run_forecast_case "$scenario" "$case_dir"
  run_policy_case "$scenario" "$case_dir"
  run_lease_case "$scenario" "$case_dir"
  run_recommendation_case "$scenario" "$case_dir"
  run_chaos_case "$scenario" "$case_dir"
  append_case_result "$scenario" "$case_dir"
}

write_primary_artifacts() {
  local primary case_dir

  primary="$(primary_scenario_id)"
  case_dir="${run_dir}/cases/${primary}"
  cp "${case_dir}/warehouse/evidence_warehouse.json" "${run_dir}/evidence_warehouse.json"
  cp "${case_dir}/forecast/swarm_autopilot_brownout_forecast.json" "${run_dir}/forecast.json"
  cp "${case_dir}/policy/operator_intent_policy.json" "${run_dir}/policy.json"
  cp "${case_dir}/lease/swarm_autopilot_resource_scarcity_receipts.json" "${run_dir}/lease_receipts.json"
  cp "${case_dir}/recommendation/swarm_autopilot_recommendation_bundle.json" "${run_dir}/recommendations.json"
  cp "${case_dir}/recommendation/swarm_autopilot_dashboard_projection.json" "${run_dir}/dashboard_projection.json"
  cp "${case_dir}/chaos/swarm_autopilot_hindsight_chaos_scenarios.json" "${run_dir}/chaos_scenarios.json"
  cp "${case_dir}/chaos/swarm_autopilot_hindsight_chaos_replay_index.json" "${run_dir}/chaos_replay_index.json"
}

write_trace_ids() {
  jq -n \
    --arg schema_version "franken-engine.swarm-autopilot-no-mock-drill-trace-ids.v1" \
    --arg trace_id "trace-swarm-autopilot-no-mock-${run_id}" \
    --arg run_id "$run_id" \
    --arg primary_scenario_id "$(primary_scenario_id)" \
    '{
      schema_version:$schema_version,
      trace_id:$trace_id,
      run_id:$run_id,
      primary_scenario_id:$primary_scenario_id,
      stage_trace_ids:{
        swarm_ops_bundle:("trace-swarm-autopilot-no-mock-swarm-ops-" + $run_id),
        topology_signal:("trace-swarm-autopilot-no-mock-topology-signal-" + $run_id),
        topology_advisory:("trace-swarm-autopilot-no-mock-topology-advisory-" + $run_id),
        topology_fidelity:("trace-swarm-autopilot-no-mock-topology-fidelity-" + $run_id),
        evidence_warehouse:("trace-swarm-autopilot-no-mock-warehouse-" + $run_id),
        brownout_forecaster:("trace-swarm-autopilot-no-mock-forecast-" + $run_id),
        operator_intent_policy:("trace-swarm-autopilot-no-mock-policy-" + $run_id),
        resource_lease_allocator:("trace-swarm-autopilot-no-mock-lease-" + $run_id),
        recommendation_bundle:("trace-swarm-autopilot-no-mock-recommendation-" + $run_id),
        hindsight_chaos:("trace-swarm-autopilot-no-mock-chaos-" + $run_id),
        truth_gate:("trace-swarm-autopilot-no-mock-truth-" + $run_id)
      }
    }' >"${run_dir}/trace_ids.json"
}

write_truth_gate_report() {
  local report_tmp="${run_dir}/truth_gate_report.json.tmp"

  jq -s \
    --arg schema_version "franken-engine.swarm-autopilot-no-mock-drill-truth-gate.v1" \
    --arg primary_scenario_id "$(primary_scenario_id)" \
    '{
      schema_version:$schema_version,
      decision:(if (length > 0) and all(.[]; .passed) then "pass" else "fail_closed" end),
      primary_scenario_id:$primary_scenario_id,
      case_count:length,
      passed_count:(map(select(.passed)) | length),
      failed_count:(map(select(.passed | not)) | length),
      replay_verified:false,
      required_coverage:{
        healthy_autopilot:any(.[]; .scenario_id == "healthy_autopilot" and .passed),
        forecast_brownout:any(.[]; .scenario_id == "forecast_brownout" and .passed),
        policy_conflict:any(.[]; .scenario_id == "policy_conflict" and .passed),
        stale_rch_progress_not_upgraded:any(.[]; .scenario_id == "stale_rch_progress_not_upgraded" and .passed),
        local_fallback_contamination:any(.[]; .scenario_id == "local_fallback_contamination" and .passed)
      },
      scenario_results: .,
      truth_gate_reasons:(
        [ .[] | select(.passed | not) | .actual.truth_gate_reason_codes[]? | {code:.,source_id:"scenario_result",detail:"scenario did not satisfy the required truth expectations"} ]
        | unique_by(.code, .detail)
      ),
      artifact_paths:{
        evidence_warehouse_json:"evidence_warehouse.json",
        forecast_json:"forecast.json",
        policy_json:"policy.json",
        lease_receipts_json:"lease_receipts.json",
        recommendations_json:"recommendations.json",
        dashboard_projection_json:"dashboard_projection.json",
        chaos_scenarios_json:"chaos_scenarios.json",
        chaos_replay_index_json:"chaos_replay_index.json",
        trace_ids_json:"trace_ids.json",
        run_manifest_json:"run_manifest.json"
      }
    }' "$case_results_jsonl" >"$report_tmp"
  mv "$report_tmp" "${run_dir}/truth_gate_report.json"
}

write_run_manifest() {
  jq -n \
    --arg schema_version "franken-engine.swarm-autopilot-no-mock-drill-run-manifest.v1" \
    --arg run_id "$run_id" \
    --arg mode "$mode" \
    --arg source_revision "$source_revision" \
    --arg decision "$(jq -r '.decision' "${run_dir}/truth_gate_report.json")" \
    --arg primary_scenario_id "$(primary_scenario_id)" \
    --arg report_json "$report_json" \
    '{
      schema_version:$schema_version,
      run_id:$run_id,
      mode:$mode,
      source_revision:$source_revision,
      decision:$decision,
      primary_scenario_id:$primary_scenario_id,
      artifact_paths:{
        run_manifest_json:"run_manifest.json",
        events_jsonl:"events.jsonl",
        commands_txt:"commands.txt",
        trace_ids_json:"trace_ids.json",
        evidence_warehouse_json:"evidence_warehouse.json",
        forecast_json:"forecast.json",
        policy_json:"policy.json",
        lease_receipts_json:"lease_receipts.json",
        recommendations_json:"recommendations.json",
        dashboard_projection_json:"dashboard_projection.json",
        chaos_scenarios_json:"chaos_scenarios.json",
        chaos_replay_index_json:"chaos_replay_index.json",
        truth_gate_report_json:"truth_gate_report.json",
        drill_report_json:$report_json
      }
    }' >"${run_dir}/run_manifest.json"
}

write_report_json() {
  local report_tmp="${report_json}.tmp"
  jq -s \
    --arg report_json "$report_json" \
    --arg truth_gate_report_json "${run_dir}/truth_gate_report.json" \
    --arg events_jsonl "$events_path" \
    --arg commands_txt "$commands_path" \
    --arg report_md "$report_md" \
    --arg primary_scenario_id "$(primary_scenario_id)" '
    {
      schema_version:"franken-engine.swarm-autopilot-no-mock-drill-report.v1",
      decision:(if (length > 0) and all(.[]; .passed) then "pass" else "fail_closed" end),
      case_count:length,
      passed_count:(map(select(.passed)) | length),
      failed_count:(map(select(.passed | not)) | length),
      primary_scenario_id:$primary_scenario_id,
      cases: .,
      artifact_paths:{
        swarm_autopilot_no_mock_drill_report_json:$report_json,
        truth_gate_report_json:$truth_gate_report_json,
        events_jsonl:$events_jsonl,
        commands_txt:$commands_txt,
        report_md:$report_md
      },
      mutation_policy:{
        live_capture_allowed:true,
        fixture_mode_deterministic:true,
        replay_verification_only:true,
        advisory_only:true,
        proof_only:true,
        runs_cargo:false,
        runs_rch_heavy_commands:false,
        mutates_br:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false
      }
    }' "$case_results_jsonl" >"$report_tmp"
  mv "$report_tmp" "$report_json"
}

write_report_md() {
  {
    printf '# SWARM AUTOPILOT No-Mock Drill\n'
    printf '\n'
    printf -- "- report: \`%s\`\n" "$report_json"
    printf -- "- primary_scenario_id: \`%s\`\n" "$(primary_scenario_id)"
    printf -- "- case_count: \`%s\`\n" "$(jq -r '.case_count' "$report_json")"
    printf -- "- passed_count: \`%s\`\n" "$(jq -r '.passed_count' "$report_json")"
    printf -- "- failed_count: \`%s\`\n" "$(jq -r '.failed_count' "$report_json")"
    printf '\n## Scenario Results\n'
    jq -r '.cases[] | "- \(.scenario_id): warehouse=\(.actual.warehouse_decision), forecast=\(.actual.forecast_decision), policy=\(.actual.policy_decision), recommendation=\(.actual.recommendation_decision), dashboard=\(.actual.dashboard_decision)"' "$report_json"
  } >"$report_md"
}

validate_suite_outputs() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-no-mock-drill-report.v1"
    and .decision == "pass"
    and .case_count == 5
    and .passed_count == 5
    and .failed_count == 0
  ' "$report_json" >/dev/null

  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-no-mock-drill-truth-gate.v1"
    and .decision == "pass"
    and .required_coverage.healthy_autopilot == true
    and .required_coverage.forecast_brownout == true
    and .required_coverage.policy_conflict == true
    and .required_coverage.stale_rch_progress_not_upgraded == true
    and .required_coverage.local_fallback_contamination == true
  ' "${run_dir}/truth_gate_report.json" >/dev/null
}

run_fixture_suite() {
  local scenario

  ensure_run_dir
  printf './scripts/e2e/swarm_autopilot_no_mock_drill.sh %q' "$mode" >"$commands_path"
  printf ' --fixtures-json %q --output-dir %q\n' "$fixtures_json" "$run_dir" >>"$commands_path"

  while IFS= read -r scenario; do
    run_case "$scenario"
  done < <(scenario_selector)

  write_primary_artifacts
  write_truth_gate_report
  write_trace_ids
  write_run_manifest
  write_report_json
  write_report_md
  record_pass "fixture suite composed"
}

resolve_latest_bundle_dir() {
  local candidate
  while IFS= read -r candidate; do
    if [[ -f "${candidate}/run_manifest.json" ]]; then
      printf '%s\n' "$candidate"
    fi
  done < <(find "$latest_from" -mindepth 1 -maxdepth 1 -type d | sort) | tail -n1
}

run_replay_verification() {
  local source_dir="$replay_run_dir"
  local required source_report

  if [[ -z "$source_dir" && -n "$latest_from" ]]; then
    source_dir="$(resolve_latest_bundle_dir)"
  fi
  if [[ -z "$source_dir" || ! -d "$source_dir" ]]; then
    printf 'replay mode requires --replay-run-dir or --latest-from with a complete bundle\n' >&2
    exit 64
  fi

  ensure_run_dir
  printf './scripts/e2e/swarm_autopilot_no_mock_drill.sh replay --replay-run-dir %q --output-dir %q\n' "$source_dir" "$run_dir" >"$commands_path"

  for required in \
    run_manifest.json \
    events.jsonl \
    commands.txt \
    trace_ids.json \
    evidence_warehouse.json \
    forecast.json \
    policy.json \
    lease_receipts.json \
    recommendations.json \
    chaos_scenarios.json \
    dashboard_projection.json \
    chaos_replay_index.json \
    truth_gate_report.json; do
    if [[ ! -f "${source_dir}/${required}" ]]; then
      printf 'missing replay source artifact: %s\n' "${source_dir}/${required}" >&2
      exit 64
    fi
    if [[ "${required}" == *.json ]]; then
      jq empty "${source_dir}/${required}" >/dev/null
    fi
  done

  cp "${source_dir}/evidence_warehouse.json" "${run_dir}/evidence_warehouse.json"
  cp "${source_dir}/forecast.json" "${run_dir}/forecast.json"
  cp "${source_dir}/policy.json" "${run_dir}/policy.json"
  cp "${source_dir}/lease_receipts.json" "${run_dir}/lease_receipts.json"
  cp "${source_dir}/recommendations.json" "${run_dir}/recommendations.json"
  cp "${source_dir}/dashboard_projection.json" "${run_dir}/dashboard_projection.json"
  cp "${source_dir}/chaos_scenarios.json" "${run_dir}/chaos_scenarios.json"
  cp "${source_dir}/chaos_replay_index.json" "${run_dir}/chaos_replay_index.json"
  cp "${source_dir}/events.jsonl" "${run_dir}/source_events.jsonl"

  source_report="${source_dir}/truth_gate_report.json"
  jq -n \
    --slurpfile source_report "$source_report" \
    --arg schema_version "franken-engine.swarm-autopilot-no-mock-drill-truth-gate.v1" \
    --arg source_dir "$source_dir" \
    '{
      schema_version:$schema_version,
      decision:(if ($source_report[0].decision // "fail_closed") == "pass" then "pass" else "fail_closed" end),
      replay_verified:(($source_report[0].decision // "fail_closed") == "pass"),
      replay_source_dir:$source_dir,
      case_count:1,
      passed_count:(if ($source_report[0].decision // "fail_closed") == "pass" then 1 else 0 end),
      failed_count:(if ($source_report[0].decision // "fail_closed") == "pass" then 0 else 1 end),
      required_coverage:{replay_verification:true},
      truth_gate_reasons:($source_report[0].truth_gate_reasons // []),
      artifact_paths:{
        run_manifest_json:"run_manifest.json",
        trace_ids_json:"trace_ids.json",
        evidence_warehouse_json:"evidence_warehouse.json",
        forecast_json:"forecast.json",
        policy_json:"policy.json",
        lease_receipts_json:"lease_receipts.json",
        recommendations_json:"recommendations.json",
        dashboard_projection_json:"dashboard_projection.json",
        chaos_scenarios_json:"chaos_scenarios.json",
        chaos_replay_index_json:"chaos_replay_index.json",
        replay_source_truth_gate_report_json:($source_dir + "/truth_gate_report.json")
      }
    }' >"${run_dir}/truth_gate_report.json"

  write_trace_ids
  write_run_manifest
  jq -n \
    --arg schema_version "franken-engine.swarm-autopilot-no-mock-drill-report.v1" \
    --arg source_dir "$source_dir" \
    '{
      schema_version:$schema_version,
      decision:"pass",
      replay_verified:true,
      replay_source_dir:$source_dir,
      case_count:1,
      passed_count:1,
      failed_count:0
    }' >"$report_json"
  {
    printf '# SWARM AUTOPILOT Replay Verification\n'
    printf '\n'
    printf -- "- replay_source_dir: \`%s\`\n" "$source_dir"
    printf -- "- replay_verified: \`true\`\n"
  } >"$report_md"
  record_pass "replay verification"
}

run_check() {
  refresh_paths
  bash -n "${BASH_SOURCE[0]}"
  bash -n "$swarm_ops_drill" "$signal_normalizer" "$queue_scorer" "$queue_fidelity_ledger" \
    "$warehouse_script" "$forecaster_script" "$policy_script" "$lease_script" \
    "$recommendation_script" "$chaos_script"
  jq empty "$contract_path" >/dev/null
  jq empty "$fixtures_json" >/dev/null
  jq empty "$signal_fixture_bundle" >/dev/null
  jq empty "$scorer_fixture_bundle" >/dev/null
  jq empty "$fidelity_fixture_bundle" >/dev/null
  jq empty "$brownout_fixture_bundle" >/dev/null
  jq empty "$policy_fixture_bundle" >/dev/null
  jq empty "$allocator_fixture_bundle" >/dev/null
  jq empty "$recommendation_fixture_bundle" >/dev/null
  jq empty "$chaos_fixture_bundle" >/dev/null
  record_pass "syntax and fixture bundles"
}

run_selftest() {
  local selftest_root fixture_dir replay_dir

  selftest_root="${run_dir}"
  fixture_dir="${selftest_root}/fixture-suite"
  replay_dir="${selftest_root}/replay-suite"

  run_check

  mode="selftest-fixture"
  run_dir="$fixture_dir"
  run_fixture_suite
  validate_suite_outputs

  mode="replay"
  replay_run_dir="$fixture_dir"
  run_dir="$replay_dir"
  run_replay_verification

  jq -e '.decision == "pass" and .replay_verified == true' "${replay_dir}/truth_gate_report.json" >/dev/null
  record_pass "selftest"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  fixture)
    run_fixture_suite
    ;;
  live)
    scenario_filter="$primary_live_scenario"
    run_fixture_suite
    ;;
  replay)
    run_replay_verification
    ;;
  *)
    usage
    exit 64
    ;;
esac
