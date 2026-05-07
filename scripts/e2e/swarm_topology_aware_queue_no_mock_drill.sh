#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_TOPOLOGY_AWARE_QUEUE_NO_MOCK_DRILL_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-topology-aware-queue-no-mock-drill}"
run_id="${SWARM_TOPOLOGY_AWARE_QUEUE_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_TOPOLOGY_AWARE_QUEUE_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-run}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

normalizer="${root_dir}/scripts/swarm_topology_queue_signal_normalizer.sh"
scorer="${root_dir}/scripts/swarm_topology_aware_queue_scorer.sh"
fidelity_ledger="${root_dir}/scripts/swarm_topology_aware_queue_fidelity_ledger.sh"
operator_status="${root_dir}/scripts/swarm_operator_status_report.sh"
truth_gate="${root_dir}/scripts/e2e/swarm_topology_aware_queue_truth_gate.sh"
contract_path="${root_dir}/docs/swarm_topology_aware_queue_no_mock_drill_contract_v1.json"
case_bundle="${root_dir}/scripts/testdata/swarm_topology_aware_queue_no_mock_drill/cases.json"
signal_fixture_bundle="${root_dir}/scripts/testdata/swarm_topology_queue_signal/queue_signal_fixtures.json"
scorer_fixture_bundle="${root_dir}/scripts/testdata/swarm_topology_aware_queue_scorer/cases.json"
fidelity_fixture_bundle="${root_dir}/scripts/testdata/swarm_topology_aware_queue_fidelity_ledger/fixtures.json"

events_path=""
commands_path=""
report_json=""
report_md=""
case_results_jsonl=""
drill_source_revision="fixture-rev"

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
Usage: ./scripts/e2e/swarm_topology_aware_queue_no_mock_drill.sh [check|run|selftest] [OPTIONS]

Compose the SWARM-SCALE-III topology-aware queue surfaces into one
deterministic no-mock drill. The drill runs the real signal normalizer,
queue scorer, fidelity ledger, operator-status reporter, and truth gate
against checked-in fixtures. It does not run Cargo or RCH, mutate live workers,
pin workers, change queue policy, edit br, release reservations, or send Agent
Mail.

Options:
  --output-dir DIR
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      run_dir="${2:-}"
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

record_pass() {
  printf 'PASS swarm-topology-aware-queue-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-topology-aware-queue-no-mock-drill %s\n' "$1" >&2
}

refresh_paths() {
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  report_json="${run_dir}/swarm_topology_aware_queue_no_mock_drill_report.json"
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

quote_command() {
  printf '%q ' "$@"
}

write_command_log() {
  printf './scripts/e2e/swarm_topology_aware_queue_no_mock_drill.sh %q' "$mode" >"$commands_path"
  printf ' --output-dir %q\n' "$run_dir" >>"$commands_path"
}

exit_code_for_decision() {
  case "$1" in
    pass|degraded)
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

write_event() {
  local step="$1"
  local decision="$2"
  local exit_code="$3"
  local stdout_path="$4"
  local stderr_path="$5"

  jq -nc \
    --arg schema_version "franken-engine.swarm-topology-aware-queue-no-mock-drill.event.v1" \
    --arg event_name "swarm_topology_aware_queue_no_mock_drill.step" \
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

run_step() {
  local step="$1"
  local expected_codes="$2"
  shift 2

  local step_dir="${run_dir}/${step}"
  local stdout_path="${step_dir}/stdout.log"
  local stderr_path="${step_dir}/stderr.log"
  local exit_code decision

  mkdir -p "$step_dir"
  {
    printf '%s: ' "$step"
    quote_command "$@"
    printf '\n'
  } >>"$commands_path"

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

scenario_value() {
  local scenario="$1"
  local filter="$2"
  jq -r --arg scenario "$scenario" ".scenarios[] | select(.scenario_id == \$scenario) | ${filter}" "$case_bundle"
}

expected_value() {
  local scenario="$1"
  local field="$2"
  jq -r --arg scenario "$scenario" --arg field "$field" '.scenarios[] | select(.scenario_id == $scenario) | .expected[$field]' "$case_bundle"
}

primary_scenario_id() {
  jq -r '.primary_scenario_id' "$case_bundle"
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

run_signal_case() {
  local scenario="$1"
  local case_dir="$2"
  local fixture_dir="${case_dir}/signal-fixtures"
  local out_dir="${case_dir}/signal"
  local expected_decision expected_truth_state expected_code signal_path
  local args=()

  materialize_signal_fixture_dir "$scenario" "$fixture_dir"
  expected_decision="$(expected_value "$scenario" "signal_decision")"
  expected_truth_state="$(expected_value "$scenario" "signal_truth_state")"
  expected_code="$(exit_code_for_decision "$expected_decision")"

  args=(
    --source-revision "$drill_source_revision"
    --execution-queue-input-json "${fixture_dir}/execution_queue_input_json.json"
    --topology-placement-input-json "${fixture_dir}/topology_placement_input_json.json"
    --rehabilitation-ledger-json "${fixture_dir}/rehabilitation_ledger_json.json"
    --output-dir "$out_dir"
  )
  [[ -f "${fixture_dir}/placement_adoption_history_json.json" ]] && args+=(--placement-adoption-history-json "${fixture_dir}/placement_adoption_history_json.json")
  [[ -f "${fixture_dir}/operator_status_snapshot_json.json" ]] && args+=(--operator-status-snapshot-json "${fixture_dir}/operator_status_snapshot_json.json")

  run_step "${scenario}/signal_normalizer" "$expected_code" bash "$normalizer" "${args[@]}"

  signal_path="${out_dir}/swarm_topology_queue_signal_input.json"
  require_json "$signal_path"
  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_truth_state "$expected_truth_state" '
    .decision == $expected_decision
    and .truth_state == $expected_truth_state
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
  ' "$signal_path" >/dev/null || {
    record_failure "signal normalizer mismatch for ${scenario}"
    return 1
  }
}

run_scorer_case() {
  local scenario="$1"
  local case_dir="$2"
  local support_dir="${case_dir}/scorer-fixtures"
  local out_dir="${case_dir}/scorer"
  local expected_decision expected_truth_state expected_rank_bias expected_code required_reason advisory_path
  local args=()

  materialize_scorer_fixture_dir "$scenario" "$support_dir"
  expected_decision="$(expected_value "$scenario" "scorer_decision")"
  expected_truth_state="$(expected_value "$scenario" "scorer_truth_state")"
  expected_rank_bias="$(expected_value "$scenario" "operator_rank_bias_mode")"
  required_reason="$(expected_value "$scenario" "required_advisory_reason_code")"
  expected_code="$(exit_code_for_decision "$expected_decision")"

  args=(
    --source-revision "$drill_source_revision"
    --topology-queue-signal-input-json "${case_dir}/signal/swarm_topology_queue_signal_input.json"
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

  run_step "${scenario}/queue_scorer" "$expected_code" bash "$scorer" "${args[@]}"

  advisory_path="${out_dir}/queue_advisory_bundle.json"
  require_json "$advisory_path"
  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_truth_state "$expected_truth_state" \
    --arg expected_rank_bias "$expected_rank_bias" \
    --arg required_reason "$required_reason" '
    .decision == $expected_decision
    and .truth_state == $expected_truth_state
    and .locality_bias_summary.rank_bias_mode == $expected_rank_bias
    and (.reason_codes | index($required_reason) != null)
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.pins_workers_automatically == false
  ' "$advisory_path" >/dev/null || {
    record_failure "queue scorer mismatch for ${scenario}"
    return 1
  }
}

run_fidelity_case() {
  local scenario="$1"
  local case_dir="$2"
  local support_dir="${case_dir}/fidelity-fixtures"
  local out_dir="${case_dir}/fidelity"
  local expected_decision expected_truth_state expected_code required_reason receipt_path

  materialize_fidelity_fixture_dir "$scenario" "$support_dir"
  expected_decision="$(expected_value "$scenario" "fidelity_decision")"
  expected_truth_state="$(expected_value "$scenario" "fidelity_truth_state")"
  required_reason="$(expected_value "$scenario" "required_fidelity_reason_code")"
  expected_code="$(exit_code_for_decision "$expected_decision")"

  run_step "${scenario}/fidelity_ledger" "$expected_code" \
    bash "$fidelity_ledger" \
      --source-revision "$drill_source_revision" \
      --queue-advisory-bundle-json "${case_dir}/scorer/queue_advisory_bundle.json" \
      --placement-evidence-ledger-json "${support_dir}/placement_evidence_ledger_json.json" \
      --queue-artifact-json "${support_dir}/queue_artifact_json.json" \
      --bottleneck-report-json "${support_dir}/bottleneck_report_json.json" \
      --locality-outcome-samples-json "${support_dir}/locality_outcome_samples_json.json" \
      --output-dir "$out_dir"

  receipt_path="${out_dir}/swarm_topology_aware_queue_fidelity_receipt.json"
  require_json "$receipt_path"
  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_truth_state "$expected_truth_state" \
    --arg required_reason "$required_reason" '
    .decision == $expected_decision
    and .truth_state == $expected_truth_state
    and (.reason_codes | index($required_reason) != null)
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.pins_workers_automatically == false
  ' "$receipt_path" >/dev/null || {
    record_failure "fidelity receipt mismatch for ${scenario}"
    return 1
  }
  require_json "${out_dir}/swarm_topology_aware_queue_drift_ledger.json"
}

run_operator_case() {
  local scenario="$1"
  local case_dir="$2"
  local out_dir="${case_dir}/operator-status"
  local expected_readiness expected_decision expected_truth_state expected_rank_bias required_reason status_path

  expected_readiness="$(expected_value "$scenario" "operator_readiness")"
  expected_decision="$(expected_value "$scenario" "operator_advisory_decision")"
  expected_truth_state="$(expected_value "$scenario" "operator_truth_state")"
  expected_rank_bias="$(expected_value "$scenario" "operator_rank_bias_mode")"
  required_reason="$(expected_value "$scenario" "required_advisory_reason_code")"

  run_step "${scenario}/operator_status" "0" \
    bash "$operator_status" \
      --output-dir "$out_dir" \
      --bead-id bd-o9pr3 \
      --source-revision "$drill_source_revision" \
      --agent-mail-status ok \
      --rch-status ok \
      --proof-index-status ok \
      --swarm-topology-aware-queue-advisory-json "${case_dir}/scorer/queue_advisory_bundle.json"

  status_path="${out_dir}/status.json"
  require_json "$status_path"
  jq -e \
    --arg expected_readiness "$expected_readiness" \
    --arg expected_decision "$expected_decision" \
    --arg expected_truth_state "$expected_truth_state" \
    --arg expected_rank_bias "$expected_rank_bias" \
    --arg required_reason "$required_reason" '
    .predictive_dashboard.swarm_topology_aware_queue_advisory.readiness == $expected_readiness
    and .predictive_dashboard.swarm_topology_aware_queue_advisory.advisory_decision == $expected_decision
    and .predictive_dashboard.swarm_topology_aware_queue_advisory.truth_state == $expected_truth_state
    and .predictive_dashboard.swarm_topology_aware_queue_advisory.rank_bias_mode == $expected_rank_bias
    and (.predictive_dashboard.swarm_topology_aware_queue_advisory.reason_codes | index($required_reason) != null)
    and .predictive_dashboard.swarm_topology_aware_queue_advisory.mutation_policy.advisory_only == true
    and .predictive_dashboard.swarm_topology_aware_queue_advisory.mutation_policy.mutates_br == false
    and .predictive_dashboard.swarm_topology_aware_queue_advisory.mutation_policy.mutates_remote_workers == false
    and .predictive_dashboard.swarm_topology_aware_queue_advisory.mutation_policy.changes_live_queue_policy == false
    and .predictive_dashboard.swarm_topology_aware_queue_advisory.mutation_policy.pins_workers_automatically == false
  ' "$status_path" >/dev/null || {
    record_failure "operator-status topology queue mismatch for ${scenario}"
    return 1
  }
}

append_case_result() {
  local scenario="$1"
  local case_dir="$2"
  local signal_path="${case_dir}/signal/swarm_topology_queue_signal_input.json"
  local advisory_path="${case_dir}/scorer/queue_advisory_bundle.json"
  local fidelity_receipt_path="${case_dir}/fidelity/swarm_topology_aware_queue_fidelity_receipt.json"
  local drift_ledger_path="${case_dir}/fidelity/swarm_topology_aware_queue_drift_ledger.json"
  local status_path="${case_dir}/operator-status/status.json"
  local expected_excluded_worker_id

  expected_excluded_worker_id="$(expected_value "$scenario" "expected_excluded_worker_id")"
  jq -nc \
    --arg scenario_id "$scenario" \
    --arg signal_path "$signal_path" \
    --arg advisory_path "$advisory_path" \
    --arg fidelity_receipt_path "$fidelity_receipt_path" \
    --arg drift_ledger_path "$drift_ledger_path" \
    --arg status_path "$status_path" \
    --arg expected_signal_decision "$(expected_value "$scenario" "signal_decision")" \
    --arg expected_scorer_decision "$(expected_value "$scenario" "scorer_decision")" \
    --arg expected_fidelity_decision "$(expected_value "$scenario" "fidelity_decision")" \
    --arg expected_readiness "$(expected_value "$scenario" "operator_readiness")" \
    --arg expected_excluded_worker_id "$expected_excluded_worker_id" \
    --slurpfile signal_doc "$signal_path" \
    --slurpfile advisory_doc "$advisory_path" \
    --slurpfile fidelity_doc "$fidelity_receipt_path" \
    --slurpfile status_doc "$status_path" '
    ($signal_doc[0]) as $sig
    | ($advisory_doc[0]) as $adv
    | ($fidelity_doc[0]) as $fid
    | ($status_doc[0].predictive_dashboard.swarm_topology_aware_queue_advisory) as $status
    | {
        scenario_id:$scenario_id,
        passed:true,
        expected:{
          signal_decision:$expected_signal_decision,
          scorer_decision:$expected_scorer_decision,
          fidelity_decision:$expected_fidelity_decision,
          operator_readiness:$expected_readiness,
          expected_excluded_worker_id:(if $expected_excluded_worker_id == "null" then null else $expected_excluded_worker_id end)
        },
        actual:{
          signal_decision:$sig.decision,
          signal_truth_state:$sig.truth_state,
          scorer_decision:$adv.decision,
          scorer_truth_state:$adv.truth_state,
          scorer_rank_bias_mode:$adv.locality_bias_summary.rank_bias_mode,
          scorer_excluded_worker_ids:$adv.worker_exclusions.excluded_worker_ids,
          fidelity_decision:$fid.decision,
          fidelity_truth_state:$fid.truth_state,
          fidelity_reason_codes:$fid.reason_codes,
          operator_readiness:$status.readiness,
          operator_advisory_decision:$status.advisory_decision,
          operator_truth_state:$status.truth_state,
          operator_rank_bias_mode:$status.rank_bias_mode,
          operator_reason_codes:$status.reason_codes
        },
        artifact_paths:{
          swarm_topology_queue_signal_input_json:$signal_path,
          queue_advisory_bundle_json:$advisory_path,
          swarm_topology_aware_queue_fidelity_receipt_json:$fidelity_receipt_path,
          swarm_topology_aware_queue_drift_ledger_json:$drift_ledger_path,
          status_json:$status_path
        }
      }
  ' >>"$case_results_jsonl"
}

run_case() {
  local scenario="$1"
  local case_dir="${run_dir}/cases/${scenario}"

  run_signal_case "$scenario" "$case_dir"
  run_scorer_case "$scenario" "$case_dir"
  run_fidelity_case "$scenario" "$case_dir"
  run_operator_case "$scenario" "$case_dir"
  append_case_result "$scenario" "$case_dir"
}

write_primary_artifacts() {
  local primary case_dir

  primary="$(primary_scenario_id)"
  case_dir="${run_dir}/cases/${primary}"
  cp "${case_dir}/signal/swarm_topology_queue_signal_input.json" "${run_dir}/swarm_topology_queue_signal_input.json"
  cp "${case_dir}/signal/swarm_topology_queue_signal_sources.json" "${run_dir}/swarm_topology_queue_signal_sources.json"
  cp "${case_dir}/scorer/queue_advisory_bundle.json" "${run_dir}/queue_advisory_bundle.json"
  cp "${case_dir}/fidelity/swarm_topology_aware_queue_fidelity_receipt.json" "${run_dir}/swarm_topology_aware_queue_fidelity_receipt.json"
  cp "${case_dir}/fidelity/swarm_topology_aware_queue_drift_ledger.json" "${run_dir}/swarm_topology_aware_queue_drift_ledger.json"
  cp "${case_dir}/operator-status/status.json" "${run_dir}/status.json"
}

write_report() {
  local report_tmp

  report_tmp="${report_json}.tmp"
  jq -s \
    --arg report_json "$report_json" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg report_md "$report_md" \
    --arg primary_scenario_id "$(primary_scenario_id)" \
    --arg signal_path "${run_dir}/swarm_topology_queue_signal_input.json" \
    --arg signal_sources_path "${run_dir}/swarm_topology_queue_signal_sources.json" \
    --arg advisory_path "${run_dir}/queue_advisory_bundle.json" \
    --arg fidelity_receipt_path "${run_dir}/swarm_topology_aware_queue_fidelity_receipt.json" \
    --arg drift_ledger_path "${run_dir}/swarm_topology_aware_queue_drift_ledger.json" \
    --arg status_path "${run_dir}/status.json" '
    {
      schema_version:"franken-engine.swarm-topology-aware-queue-no-mock-drill-report.v1",
      decision:(if (length > 0) and all(.[]; .passed) then "pass" else "fail_closed" end),
      case_count:length,
      passed_count:(map(select(.passed)) | length),
      failed_count:(map(select(.passed | not)) | length),
      primary_scenario_id:$primary_scenario_id,
      required_coverage:{
        healthy_hot_cache_reuse:any(.[]; .scenario_id == "healthy_hot_cache_reuse" and .passed),
        degraded_missing_locality_adoption:any(.[]; .scenario_id == "degraded_missing_locality_adoption" and .passed),
        blocked_contradictory_locality:any(.[]; .scenario_id == "blocked_contradictory_locality" and .passed),
        drain_recommended_worker_exclusion:any(.[]; .scenario_id == "drain_recommended_worker_exclusion" and .passed),
        unstable_worker_downgrade:any(.[]; .scenario_id == "unstable_worker_downgrade" and .passed),
        contaminated_local_fallback:any(.[]; .scenario_id == "contaminated_local_fallback" and .passed)
      },
      cases:.,
      mutation_policy:{
        fixture_fed_only:true,
        proof_only:true,
        advisory_only:true,
        runs_cargo:false,
        runs_rch:false,
        mutates_live_workers:false,
        pins_workers_automatically:false,
        changes_live_queue_policy:false,
        reroutes_tasks_automatically:false,
        edits_br:false,
        releases_reservations:false,
        sends_agent_mail:false
      },
      producer_chain:[
        "scripts/swarm_topology_queue_signal_normalizer.sh",
        "scripts/swarm_topology_aware_queue_scorer.sh",
        "scripts/swarm_topology_aware_queue_fidelity_ledger.sh",
        "scripts/swarm_operator_status_report.sh"
      ],
      artifact_paths:{
        swarm_topology_aware_queue_no_mock_drill_report_json:$report_json,
        swarm_topology_queue_signal_input_json:$signal_path,
        swarm_topology_queue_signal_sources_json:$signal_sources_path,
        queue_advisory_bundle_json:$advisory_path,
        swarm_topology_aware_queue_fidelity_receipt_json:$fidelity_receipt_path,
        swarm_topology_aware_queue_drift_ledger_json:$drift_ledger_path,
        status_json:$status_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_md
      }
    }
  ' "$case_results_jsonl" >"$report_tmp"
  mv "$report_tmp" "$report_json"
}

write_report_md() {
  {
    printf '# Topology-Aware Queue No-Mock Drill\n'
    printf '\n'
    printf -- "- report: \`%s\`\n" "$report_json"
    printf -- "- primary_scenario_id: \`%s\`\n" "$(primary_scenario_id)"
    printf -- "- case_count: \`%s\`\n" "$(jq -r '.case_count' "$report_json")"
    printf -- "- passed_count: \`%s\`\n" "$(jq -r '.passed_count' "$report_json")"
    printf -- "- failed_count: \`%s\`\n" "$(jq -r '.failed_count' "$report_json")"
    printf '\n## Scenario Results\n'
    jq -r '.cases[] | "- \(.scenario_id): operator=\(.actual.operator_readiness) scorer=\(.actual.scorer_decision) fidelity=\(.actual.fidelity_decision)"' "$report_json"
  } >"$report_md"
}

validate_report() {
  jq -e '
    .schema_version == "franken-engine.swarm-topology-aware-queue-no-mock-drill-report.v1"
    and .decision == "pass"
    and .case_count == 6
    and .passed_count == 6
    and .failed_count == 0
    and .required_coverage.healthy_hot_cache_reuse == true
    and .required_coverage.degraded_missing_locality_adoption == true
    and .required_coverage.blocked_contradictory_locality == true
    and .required_coverage.drain_recommended_worker_exclusion == true
    and .required_coverage.unstable_worker_downgrade == true
    and .required_coverage.contaminated_local_fallback == true
    and any(.cases[]; .scenario_id == "healthy_hot_cache_reuse" and .actual.operator_readiness == "ready" and .actual.fidelity_decision == "pass")
    and any(.cases[]; .scenario_id == "degraded_missing_locality_adoption" and .actual.operator_readiness == "degraded")
    and any(.cases[]; .scenario_id == "blocked_contradictory_locality" and .actual.operator_readiness == "blocked" and .actual.fidelity_decision == "blocked")
    and any(.cases[]; .scenario_id == "drain_recommended_worker_exclusion" and (.actual.scorer_excluded_worker_ids | index("rch-e") != null))
    and any(.cases[]; .scenario_id == "unstable_worker_downgrade" and .actual.fidelity_decision == "blocked" and (.actual.scorer_excluded_worker_ids | index("rch-e") != null))
    and any(.cases[]; .scenario_id == "contaminated_local_fallback" and .actual.operator_readiness == "contaminated" and .actual.fidelity_decision == "fail_closed")
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_live_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.reroutes_tasks_automatically == false
  ' "$report_json" >/dev/null
}

run_check() {
  refresh_paths
  bash -n "${BASH_SOURCE[0]}"
  bash -n "$truth_gate"
  bash -n "$normalizer"
  bash -n "$scorer"
  bash -n "$fidelity_ledger"
  bash -n "$operator_status"
  jq empty "$contract_path" >/dev/null
  jq empty "$case_bundle" >/dev/null
  jq empty "$signal_fixture_bundle" >/dev/null
  jq empty "$scorer_fixture_bundle" >/dev/null
  jq empty "$fidelity_fixture_bundle" >/dev/null
  bash "$truth_gate" check >/dev/null
  record_pass "syntax fixtures contract and truth gate"
}

run_mode() {
  local scenario

  drill_source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf fixture-rev)"
  ensure_run_dir
  write_command_log

  while IFS= read -r scenario; do
    run_case "$scenario"
  done < <(jq -r '.scenarios[].scenario_id' "$case_bundle")

  write_primary_artifacts
  write_report
  write_report_md
  record_pass "composed drill report"
}

run_selftest() {
  run_check
  run_mode
  validate_report
  record_pass "selftest report validation"
}

case "${mode}" in
  check)
    run_check
    ;;
  run)
    run_mode
    ;;
  selftest)
    run_selftest
    ;;
  *)
    usage
    exit 64
    ;;
esac
