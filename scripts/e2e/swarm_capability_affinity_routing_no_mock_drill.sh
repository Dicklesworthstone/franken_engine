#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_CAPABILITY_AFFINITY_ROUTING_NO_MOCK_DRILL_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-capability-affinity-routing-no-mock-drill}"
run_id="${SWARM_CAPABILITY_AFFINITY_ROUTING_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_CAPABILITY_AFFINITY_ROUTING_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-run}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

normalizer="${root_dir}/scripts/swarm_worker_capability_toolchain_normalizer.sh"
planner="${root_dir}/scripts/swarm_capability_affinity_queue_routing_planner.sh"
ledger="${root_dir}/scripts/swarm_capability_affinity_routing_outcome_ledger.sh"
operator_status="${root_dir}/scripts/swarm_operator_status_report.sh"
truth_gate="${root_dir}/scripts/e2e/swarm_capability_affinity_routing_truth_gate.sh"
contract_path="${root_dir}/docs/swarm_capability_affinity_routing_no_mock_drill_contract_v1.json"
case_bundle="${root_dir}/scripts/testdata/swarm_capability_affinity_routing_no_mock_drill/cases.json"
normalizer_fixture_bundle="${root_dir}/scripts/testdata/swarm_worker_capability_toolchain/worker_capability_toolchain_fixtures.json"
planner_fixture_bundle="${root_dir}/scripts/testdata/swarm_capability_affinity_queue_routing_planner/fixtures.json"
ledger_fixture_bundle="${root_dir}/scripts/testdata/swarm_capability_affinity_routing_outcome_ledger/fixtures.json"

events_path=""
commands_path=""
report_json=""
report_md=""
case_results_jsonl=""
drill_source_revision="fixture-rev"

required_normalizer_inputs=(
  execution_queue_input_json
  topology_queue_signal_input_json
  rehabilitation_ledger_json
  rch_remote_compile_stall_bundle_json
  worker_capability_snapshot_json
  worker_toolchain_snapshot_json
)

optional_normalizer_inputs=(
  resource_envelope_json
  operator_status_snapshot_json
)

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_capability_affinity_routing_no_mock_drill.sh [check|run|selftest] [OPTIONS]

Compose the shipped capability-affinity routing surfaces into one deterministic
no-mock drill. The drill reuses checked-in upstream fixtures and runs the real
worker capability or toolchain normalizer, queue-routing planner, outcome
ledger, and operator-status reporter. It is fixture-fed, proof-only, and
advisory-only. It does not run Cargo or RCH, mutate live workers, change live
queue policy, reroute tasks automatically, repair workers automatically, edit
br, release reservations, or send Agent Mail.

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
  printf 'PASS swarm-capability-affinity-routing-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-capability-affinity-routing-no-mock-drill %s\n' "$1" >&2
}

refresh_paths() {
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  report_json="${run_dir}/swarm_capability_affinity_routing_no_mock_drill_report.json"
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
  printf './scripts/e2e/swarm_capability_affinity_routing_no_mock_drill.sh %q' "$mode" >"$commands_path"
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
    --arg schema_version "franken-engine.swarm-capability-affinity-routing-no-mock-drill.event.v1" \
    --arg event_name "swarm_capability_affinity_routing_no_mock_drill.step" \
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

materialize_normalizer_fixture_dir() {
  local scenario="$1"
  local dir="$2"
  local fixture_scenario input_id

  fixture_scenario="$(scenario_value "$scenario" '.normalizer_fixture_scenario')"
  mkdir -p "$dir"
  for input_id in "${required_normalizer_inputs[@]}"; do
    if ! extract_input_from_bundle "$normalizer_fixture_bundle" "$fixture_scenario" "$input_id" "${dir}/${input_id}.json"; then
      printf 'missing required normalizer input %s for %s\n' "$input_id" "$scenario" >&2
      return 1
    fi
  done
  for input_id in "${optional_normalizer_inputs[@]}"; do
    extract_input_from_bundle "$normalizer_fixture_bundle" "$fixture_scenario" "$input_id" "${dir}/${input_id}.json" || true
  done
}

materialize_planner_fixture_dir() {
  local scenario="$1"
  local dir="$2"
  local fixture_scenario

  fixture_scenario="$(scenario_value "$scenario" '.planner_fixture_scenario')"
  mkdir -p "$dir"
  extract_input_from_bundle "$planner_fixture_bundle" "$fixture_scenario" "routing_outcome_samples_json" "${dir}/routing_outcome_samples_json.json" || true
}

materialize_ledger_fixture_dir() {
  local scenario="$1"
  local dir="$2"
  local fixture_scenario

  fixture_scenario="$(scenario_value "$scenario" '.ledger_fixture_scenario')"
  mkdir -p "$dir"
  if ! extract_input_from_bundle "$ledger_fixture_bundle" "$fixture_scenario" "routing_outcome_samples_json" "${dir}/routing_outcome_samples_json.json"; then
    printf 'missing required ledger routing outcome samples for %s\n' "$scenario" >&2
    return 1
  fi
}

run_normalizer_case() {
  local scenario="$1"
  local case_dir="$2"
  local fixture_dir="${case_dir}/normalizer-fixtures"
  local out_dir="${case_dir}/normalizer"
  local expected_decision expected_truth_state expected_code input_path
  local args=()

  materialize_normalizer_fixture_dir "$scenario" "$fixture_dir"
  expected_decision="$(expected_value "$scenario" "normalizer_decision")"
  expected_truth_state="$(expected_value "$scenario" "normalizer_truth_state")"
  expected_code="$(exit_code_for_decision "$expected_decision")"

  args=(
    --execution-queue-input-json "${fixture_dir}/execution_queue_input_json.json"
    --topology-queue-signal-input-json "${fixture_dir}/topology_queue_signal_input_json.json"
    --rehabilitation-ledger-json "${fixture_dir}/rehabilitation_ledger_json.json"
    --rch-remote-compile-stall-bundle-json "${fixture_dir}/rch_remote_compile_stall_bundle_json.json"
    --worker-capability-snapshot-json "${fixture_dir}/worker_capability_snapshot_json.json"
    --worker-toolchain-snapshot-json "${fixture_dir}/worker_toolchain_snapshot_json.json"
    --source-revision "$drill_source_revision"
    --output-dir "$out_dir"
  )
  if [[ -f "${fixture_dir}/resource_envelope_json.json" ]]; then
    args+=(--resource-envelope-json "${fixture_dir}/resource_envelope_json.json")
  fi
  if [[ -f "${fixture_dir}/operator_status_snapshot_json.json" ]]; then
    args+=(--operator-status-snapshot-json "${fixture_dir}/operator_status_snapshot_json.json")
  fi

  run_step "${scenario}/normalizer" "$expected_code" bash "$normalizer" "${args[@]}"

  input_path="${out_dir}/swarm_worker_capability_toolchain_input.json"
  require_json "$input_path"
  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_truth_state "$expected_truth_state" '
    .decision == $expected_decision
    and .truth_state == $expected_truth_state
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.reroutes_tasks_automatically == false
  ' "$input_path" >/dev/null || {
    record_failure "normalizer output mismatch for ${scenario}"
    return 1
  }
}

run_planner_case() {
  local scenario="$1"
  local case_dir="$2"
  local support_dir="${case_dir}/planner-fixtures"
  local out_dir="${case_dir}/planner"
  local expected_decision expected_truth_state expected_routing_mode expected_code advisory_path
  local args=()

  materialize_planner_fixture_dir "$scenario" "$support_dir"
  expected_decision="$(expected_value "$scenario" "planner_decision")"
  expected_truth_state="$(expected_value "$scenario" "planner_truth_state")"
  expected_routing_mode="$(expected_value "$scenario" "planner_routing_mode")"
  expected_code="$(exit_code_for_decision "$expected_decision")"

  args=(
    --worker-capability-toolchain-input-json "${case_dir}/normalizer/swarm_worker_capability_toolchain_input.json"
    --source-revision "$drill_source_revision"
    --output-dir "$out_dir"
  )
  if [[ -f "${support_dir}/routing_outcome_samples_json.json" ]]; then
    args+=(--routing-outcome-samples-json "${support_dir}/routing_outcome_samples_json.json")
  fi

  run_step "${scenario}/planner" "$expected_code" bash "$planner" "${args[@]}"

  advisory_path="${out_dir}/capability_affinity_queue_routing_advisory.json"
  require_json "$advisory_path"
  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_truth_state "$expected_truth_state" \
    --arg expected_routing_mode "$expected_routing_mode" '
    .decision == $expected_decision
    and .truth_state == $expected_truth_state
    and .worker_affinity_summary.routing_mode == $expected_routing_mode
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.reroutes_tasks_automatically == false
  ' "$advisory_path" >/dev/null || {
    record_failure "planner advisory mismatch for ${scenario}"
    return 1
  }
}

run_ledger_case() {
  local scenario="$1"
  local case_dir="$2"
  local support_dir="${case_dir}/ledger-fixtures"
  local out_dir="${case_dir}/ledger"
  local expected_decision expected_truth_state expected_code ledger_path

  materialize_ledger_fixture_dir "$scenario" "$support_dir"
  expected_decision="$(expected_value "$scenario" "ledger_decision")"
  expected_truth_state="$(expected_value "$scenario" "ledger_truth_state")"
  expected_code="$(exit_code_for_decision "$expected_decision")"

  run_step "${scenario}/ledger" "$expected_code" \
    bash "$ledger" \
      --capability-affinity-routing-advisory-json "${case_dir}/planner/capability_affinity_queue_routing_advisory.json" \
      --routing-outcome-samples-json "${support_dir}/routing_outcome_samples_json.json" \
      --source-revision "$drill_source_revision" \
      --output-dir "$out_dir"

  ledger_path="${out_dir}/swarm_capability_affinity_routing_outcome_ledger.json"
  require_json "$ledger_path"
  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_truth_state "$expected_truth_state" '
    .decision == $expected_decision
    and .truth_state == $expected_truth_state
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.reroutes_tasks_automatically == false
  ' "$ledger_path" >/dev/null || {
    record_failure "outcome ledger mismatch for ${scenario}"
    return 1
  }
}

run_operator_case() {
  local scenario="$1"
  local case_dir="$2"
  local out_dir="${case_dir}/operator-status"
  local expected_readiness expected_advisory_decision expected_ledger_decision expected_routing_mode required_reason_code status_path

  expected_readiness="$(expected_value "$scenario" "operator_capability_affinity_readiness")"
  expected_advisory_decision="$(expected_value "$scenario" "operator_advisory_decision")"
  expected_ledger_decision="$(expected_value "$scenario" "operator_outcome_ledger_decision")"
  expected_routing_mode="$(expected_value "$scenario" "operator_routing_mode")"
  required_reason_code="$(expected_value "$scenario" "required_reason_code")"

  run_step "${scenario}/operator_status" "0" \
    bash "$operator_status" \
      --output-dir "$out_dir" \
      --bead-id bd-x0030 \
      --source-revision "$drill_source_revision" \
      --agent-mail-status ok \
      --rch-status ok \
      --proof-index-status ok \
      --swarm-capability-affinity-routing-advisory-json "${case_dir}/planner/capability_affinity_queue_routing_advisory.json" \
      --swarm-capability-affinity-routing-outcome-ledger-json "${case_dir}/ledger/swarm_capability_affinity_routing_outcome_ledger.json"

  status_path="${out_dir}/status.json"
  require_json "$status_path"
  jq -e \
    --arg expected_readiness "$expected_readiness" \
    --arg expected_advisory_decision "$expected_advisory_decision" \
    --arg expected_ledger_decision "$expected_ledger_decision" \
    --arg expected_routing_mode "$expected_routing_mode" \
    --arg required_reason_code "$required_reason_code" '
    .predictive_dashboard.swarm_capability_affinity_routing.readiness == $expected_readiness
    and .predictive_dashboard.swarm_capability_affinity_routing.advisory_decision == $expected_advisory_decision
    and .predictive_dashboard.swarm_capability_affinity_routing.outcome_ledger_decision == $expected_ledger_decision
    and .predictive_dashboard.swarm_capability_affinity_routing.routing_mode == $expected_routing_mode
    and (.predictive_dashboard.swarm_capability_affinity_routing.reason_codes | index($required_reason_code) != null)
    and .predictive_dashboard.swarm_capability_affinity_routing.mutation_policy.advisory_only == true
    and .predictive_dashboard.swarm_capability_affinity_routing.mutation_policy.mutates_br == false
    and .predictive_dashboard.swarm_capability_affinity_routing.mutation_policy.mutates_remote_workers == false
    and .predictive_dashboard.swarm_capability_affinity_routing.mutation_policy.changes_live_queue_policy == false
    and .predictive_dashboard.swarm_capability_affinity_routing.mutation_policy.reroutes_tasks_automatically == false
  ' "$status_path" >/dev/null || {
    record_failure "operator-status capability-affinity mismatch for ${scenario}"
    return 1
  }
}

append_case_result() {
  local scenario="$1"
  local case_dir="$2"
  local normalizer_input="${case_dir}/normalizer/swarm_worker_capability_toolchain_input.json"
  local advisory_path="${case_dir}/planner/capability_affinity_queue_routing_advisory.json"
  local ledger_path="${case_dir}/ledger/swarm_capability_affinity_routing_outcome_ledger.json"
  local status_path="${case_dir}/operator-status/status.json"

  jq -nc \
    --arg scenario_id "$scenario" \
    --arg normalizer_input "$normalizer_input" \
    --arg advisory_path "$advisory_path" \
    --arg ledger_path "$ledger_path" \
    --arg status_path "$status_path" \
    --arg expected_normalizer_decision "$(expected_value "$scenario" "normalizer_decision")" \
    --arg expected_planner_decision "$(expected_value "$scenario" "planner_decision")" \
    --arg expected_ledger_decision "$(expected_value "$scenario" "ledger_decision")" \
    --arg expected_readiness "$(expected_value "$scenario" "operator_capability_affinity_readiness")" \
    --arg required_reason_code "$(expected_value "$scenario" "required_reason_code")" \
    --slurpfile normalizer_doc "$normalizer_input" \
    --slurpfile advisory_doc "$advisory_path" \
    --slurpfile ledger_doc "$ledger_path" \
    --slurpfile status_doc "$status_path" '
    ($normalizer_doc[0]) as $n
    | ($advisory_doc[0]) as $a
    | ($ledger_doc[0]) as $l
    | ($status_doc[0].predictive_dashboard.swarm_capability_affinity_routing) as $s
    | {
        scenario_id:$scenario_id,
        passed:true,
        expected:{
          normalizer_decision:$expected_normalizer_decision,
          planner_decision:$expected_planner_decision,
          ledger_decision:$expected_ledger_decision,
          operator_capability_affinity_readiness:$expected_readiness,
          required_reason_code:$required_reason_code
        },
        actual:{
          normalizer_decision:$n.decision,
          normalizer_truth_state:$n.truth_state,
          planner_decision:$a.decision,
          planner_truth_state:$a.truth_state,
          planner_routing_mode:$a.worker_affinity_summary.routing_mode,
          ledger_decision:$l.decision,
          ledger_truth_state:$l.truth_state,
          operator_capability_affinity_readiness:$s.readiness,
          operator_advisory_decision:$s.advisory_decision,
          operator_outcome_ledger_decision:$s.outcome_ledger_decision,
          operator_routing_mode:$s.routing_mode,
          operator_reason_codes:$s.reason_codes
        },
        artifact_paths:{
          swarm_worker_capability_toolchain_input_json:$normalizer_input,
          capability_affinity_queue_routing_advisory_json:$advisory_path,
          swarm_capability_affinity_routing_outcome_ledger_json:$ledger_path,
          status_json:$status_path
        }
      }
  ' >>"$case_results_jsonl"
}

run_case() {
  local scenario="$1"
  local case_dir="${run_dir}/cases/${scenario}"

  run_normalizer_case "$scenario" "$case_dir"
  run_planner_case "$scenario" "$case_dir"
  run_ledger_case "$scenario" "$case_dir"
  run_operator_case "$scenario" "$case_dir"
  append_case_result "$scenario" "$case_dir"
}

write_primary_artifacts() {
  local primary case_dir

  primary="$(primary_scenario_id)"
  case_dir="${run_dir}/cases/${primary}"
  cp "${case_dir}/normalizer/swarm_worker_capability_toolchain_input.json" "${run_dir}/swarm_worker_capability_toolchain_input.json"
  cp "${case_dir}/normalizer/swarm_worker_capability_toolchain_sources.json" "${run_dir}/swarm_worker_capability_toolchain_sources.json"
  cp "${case_dir}/planner/capability_affinity_queue_routing_advisory.json" "${run_dir}/capability_affinity_queue_routing_advisory.json"
  cp "${case_dir}/ledger/swarm_capability_affinity_routing_outcome_ledger.json" "${run_dir}/swarm_capability_affinity_routing_outcome_ledger.json"
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
    --arg normalizer_input "${run_dir}/swarm_worker_capability_toolchain_input.json" \
    --arg normalizer_sources "${run_dir}/swarm_worker_capability_toolchain_sources.json" \
    --arg advisory_path "${run_dir}/capability_affinity_queue_routing_advisory.json" \
    --arg ledger_path "${run_dir}/swarm_capability_affinity_routing_outcome_ledger.json" \
    --arg status_path "${run_dir}/status.json" '
    {
      schema_version:"franken-engine.swarm-capability-affinity-routing-no-mock-drill-report.v1",
      decision:(if (length > 0) and all(.[]; .passed) then "pass" else "fail_closed" end),
      case_count:length,
      passed_count:(map(select(.passed)) | length),
      failed_count:(map(select(.passed | not)) | length),
      primary_scenario_id:$primary_scenario_id,
      required_coverage:{
        healthy_confirmed:any(.[]; .scenario_id == "healthy_confirmed" and .passed),
        degraded_missing_optional_support:any(.[]; .scenario_id == "degraded_missing_optional_support" and .passed),
        blocked_capability_gap:any(.[]; .scenario_id == "blocked_capability_gap" and .passed),
        blocked_unsupported_toolchain:any(.[]; .scenario_id == "blocked_unsupported_toolchain" and .passed),
        contaminated_local_fallback:any(.[]; .scenario_id == "contaminated_local_fallback" and .passed)
      },
      cases: .,
      mutation_policy:{
        fixture_fed_only:true,
        proof_only:true,
        advisory_only:true,
        runs_cargo:false,
        runs_rch:false,
        mutates_live_workers:false,
        changes_live_queue_policy:false,
        reroutes_tasks_automatically:false,
        repairs_workers_automatically:false
      },
      producer_chain:[
        "scripts/swarm_worker_capability_toolchain_normalizer.sh",
        "scripts/swarm_capability_affinity_queue_routing_planner.sh",
        "scripts/swarm_capability_affinity_routing_outcome_ledger.sh",
        "scripts/swarm_operator_status_report.sh"
      ],
      artifact_paths:{
        swarm_capability_affinity_routing_no_mock_drill_report_json:$report_json,
        swarm_worker_capability_toolchain_input_json:$normalizer_input,
        swarm_worker_capability_toolchain_sources_json:$normalizer_sources,
        capability_affinity_queue_routing_advisory_json:$advisory_path,
        swarm_capability_affinity_routing_outcome_ledger_json:$ledger_path,
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
    printf '# Capability Affinity Routing No-Mock Drill\n'
    printf '\n'
    printf -- "- report: \`%s\`\n" "$report_json"
    printf -- "- primary_scenario_id: \`%s\`\n" "$(primary_scenario_id)"
    printf -- "- case_count: \`%s\`\n" "$(jq -r '.case_count' "$report_json")"
    printf -- "- passed_count: \`%s\`\n" "$(jq -r '.passed_count' "$report_json")"
    printf -- "- failed_count: \`%s\`\n" "$(jq -r '.failed_count' "$report_json")"
    printf '\n## Scenario Results\n'
    jq -r '.cases[] | "- \(.scenario_id): \(.actual.operator_capability_affinity_readiness) / \(.actual.operator_advisory_decision) / \(.actual.operator_outcome_ledger_decision)"' "$report_json"
  } >"$report_md"
}

validate_report() {
  jq -e '
    .schema_version == "franken-engine.swarm-capability-affinity-routing-no-mock-drill-report.v1"
    and .decision == "pass"
    and .case_count == 5
    and .passed_count == 5
    and .failed_count == 0
    and .required_coverage.healthy_confirmed == true
    and .required_coverage.degraded_missing_optional_support == true
    and .required_coverage.blocked_capability_gap == true
    and .required_coverage.blocked_unsupported_toolchain == true
    and .required_coverage.contaminated_local_fallback == true
    and any(.cases[]; .scenario_id == "healthy_confirmed" and .actual.operator_capability_affinity_readiness == "ready")
    and any(.cases[]; .scenario_id == "degraded_missing_optional_support" and .actual.operator_capability_affinity_readiness == "degraded")
    and any(.cases[]; .scenario_id == "blocked_capability_gap" and .actual.operator_capability_affinity_readiness == "blocked")
    and any(.cases[]; .scenario_id == "blocked_unsupported_toolchain" and .actual.operator_capability_affinity_readiness == "blocked")
    and any(.cases[]; .scenario_id == "contaminated_local_fallback" and .actual.operator_capability_affinity_readiness == "contaminated")
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_live_workers == false
    and .mutation_policy.changes_live_queue_policy == false
  ' "$report_json" >/dev/null
}

run_check() {
  refresh_paths
  bash -n "${BASH_SOURCE[0]}"
  bash -n "$truth_gate"
  bash -n "$normalizer"
  bash -n "$planner"
  bash -n "$ledger"
  bash -n "$operator_status"
  jq empty "$contract_path" >/dev/null
  jq empty "$case_bundle" >/dev/null
  jq empty "$normalizer_fixture_bundle" >/dev/null
  jq empty "$planner_fixture_bundle" >/dev/null
  jq empty "$ledger_fixture_bundle" >/dev/null
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
