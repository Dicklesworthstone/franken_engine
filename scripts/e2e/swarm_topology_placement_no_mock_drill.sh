#!/usr/bin/env bash
# shellcheck disable=SC2094
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_TOPOLOGY_PLACEMENT_NO_MOCK_DRILL_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-topology-placement-no-mock-drill}"
run_id="${SWARM_TOPOLOGY_PLACEMENT_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_TOPOLOGY_PLACEMENT_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-run}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

normalizer="${root_dir}/scripts/swarm_topology_placement_normalizer.sh"
planner="${root_dir}/scripts/swarm_topology_placement_planner.sh"
ledger="${root_dir}/scripts/swarm_topology_placement_receipt_ledger.sh"
operator_status="${root_dir}/scripts/swarm_operator_status_report.sh"
truth_gate="${root_dir}/scripts/e2e/swarm_topology_placement_truth_gate.sh"
fixture_bundle="${root_dir}/scripts/testdata/swarm_topology_placement/topology_placement_fixtures.json"
contract_path="${root_dir}/docs/swarm_topology_placement_no_mock_drill_contract_v1.json"

events_path=""
commands_path=""
report_json=""
report_md=""
case_results_path=""
failures=0

required_input_ids=(
  host_topology_json
  numa_evidence_json
  worker_inventory_json
)

optional_input_ids=(
  cache_residency_json
  resource_envelope_json
  execution_queue_input_json
  tail_latency_evidence_json
)

drill_scenarios=(
  healthy_confirmed
  degraded_missing_cache_residency
  blocked_contradictory_locality
  contaminated_local_fallback
)

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_topology_placement_no_mock_drill.sh [check|run|selftest] [OPTIONS]

Compose the SWARM-SCALE-II topology placement surfaces into one deterministic
no-mock drill. The drill uses checked-in topology fixtures and runs the real
normalizer, placement planner, receipt ledger, operator-status reporter, and
truth gate. It does not run Cargo or RCH, mutate live workers, change queue
policy, pin workers, rebind hosts, edit br, or send Agent Mail.

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
  printf 'PASS swarm-topology-placement-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-topology-placement-no-mock-drill %s\n' "$1" >&2
  failures=$((failures + 1))
}

refresh_paths() {
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  report_json="${run_dir}/swarm_topology_placement_no_mock_drill_report.json"
  report_md="${run_dir}/report.md"
  case_results_path="${run_dir}/case_results.jsonl"
}

ensure_run_dir() {
  refresh_paths
  mkdir -p "$run_dir"
  : >"$events_path"
  : >"$commands_path"
  : >"$case_results_path"
}

quote_command() {
  printf '%q ' "$@"
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
    --arg schema_version "franken-engine.swarm-topology-placement-no-mock-drill.event.v1" \
    --arg step_id "$step" \
    --arg decision "$decision" \
    --arg stdout_path "$stdout_path" \
    --arg stderr_path "$stderr_path" \
    --argjson exit_code "$exit_code" \
    '{
      schema_version: $schema_version,
      event_name: "swarm_topology_placement_no_mock_drill.step",
      step_id: $step_id,
      decision: $decision,
      exit_code: $exit_code,
      artifact_paths: {
        stdout_log: $stdout_path,
        stderr_log: $stderr_path
      }
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

extract_fixture_input() {
  local scenario="$1"
  local input_id="$2"
  local output_path="$3"

  local is_null
  is_null="$(jq -r --arg scenario "$scenario" --arg input_id "$input_id" '
    .scenarios[]
    | select(.scenario_id == $scenario)
    | (.inputs[$input_id] == null)
  ' "$fixture_bundle")"
  if [[ "$is_null" == "true" ]]; then
    return 1
  fi

  jq --arg scenario "$scenario" --arg input_id "$input_id" '
    .scenarios[]
    | select(.scenario_id == $scenario)
    | .inputs[$input_id]
  ' "$fixture_bundle" >"$output_path"
}

materialize_fixture_dir() {
  local scenario="$1"
  local dir="$2"
  local input_id

  mkdir -p "$dir"
  for input_id in "${required_input_ids[@]}"; do
    if ! extract_fixture_input "$scenario" "$input_id" "${dir}/${input_id}.json"; then
      printf 'required fixture input %s missing for %s\n' "$input_id" "$scenario" >&2
      return 1
    fi
  done
  for input_id in "${optional_input_ids[@]}"; do
    extract_fixture_input "$scenario" "$input_id" "${dir}/${input_id}.json" || true
  done
}

expected_exit_for() {
  local scenario="$1"
  jq -r --arg scenario "$scenario" '
    .scenarios[]
    | select(.scenario_id == $scenario)
    | .expected_exit_code
  ' "$fixture_bundle"
}

expected_decision_for() {
  local scenario="$1"
  jq -r --arg scenario "$scenario" '
    .scenarios[]
    | select(.scenario_id == $scenario)
    | .expected_decision
  ' "$fixture_bundle"
}

expected_truth_state_for() {
  local scenario="$1"
  jq -r --arg scenario "$scenario" '
    .scenarios[]
    | select(.scenario_id == $scenario)
    | .expected_truth_state
  ' "$fixture_bundle"
}

operator_readiness_for() {
  local scenario="$1"
  case "$scenario" in
    healthy_confirmed)
      printf 'ready'
      ;;
    degraded_missing_cache_residency)
      printf 'degraded'
      ;;
    blocked_contradictory_locality)
      printf 'blocked'
      ;;
    contaminated_local_fallback)
      printf 'contaminated'
      ;;
    *)
      printf 'unknown'
      ;;
  esac
}

create_adoption_observation() {
  local plan_path="$1"
  local output_path="$2"
  local scenario="$3"
  local expected_worker expected_host cache_reuse_observed

  expected_worker="$(jq -r '.recommended_worker_targets[0].worker_id // empty' "$plan_path")"
  expected_host="$(jq -r '.context.host_identity.host_id // .context.host_identity.host // empty' "$plan_path")"
  if [[ -z "$expected_worker" || -z "$expected_host" ]]; then
    return 1
  fi

  cache_reuse_observed="false"
  if [[ "$scenario" == "healthy_confirmed" ]]; then
    cache_reuse_observed="true"
  fi

  jq -n \
    --arg worker_id "$expected_worker" \
    --arg host_id "$expected_host" \
    --arg scenario "$scenario" \
    --argjson cache_reuse_observed "$cache_reuse_observed" \
    '{
      schema_version: "franken-engine.swarm-topology-placement-adoption-observation.v1",
      observation_id: ("topology-placement-no-mock-" + $scenario),
      observed_at: "2026-05-06T20:25:00Z",
      host_id: $host_id,
      worker_ids: [$worker_id],
      cache_reuse_observed: $cache_reuse_observed,
      notes: ["deterministic no-mock drill observation; no worker pinning or rebinding was performed"]
    }' >"$output_path"
}

run_normalizer_case() {
  local scenario="$1"
  local case_dir="$2"
  local input_dir="${case_dir}/inputs"
  local out_dir="${case_dir}/normalizer"
  local expected_code expected_decision expected_truth_state input_path
  local args=()
  local input_id

  materialize_fixture_dir "$scenario" "$input_dir"
  expected_code="$(expected_exit_for "$scenario")"
  expected_decision="$(expected_decision_for "$scenario")"
  expected_truth_state="$(expected_truth_state_for "$scenario")"

  args+=(
    --bead-id bd-2r3eq
    --source-revision no-mock-drill-fixture
    --reference-time "$(jq -r '.reference_time' "$fixture_bundle")"
    --max-snapshot-age-seconds "$(jq -r '.max_snapshot_age_seconds' "$fixture_bundle")"
    --host-topology-json "${input_dir}/host_topology_json.json"
    --numa-evidence-json "${input_dir}/numa_evidence_json.json"
    --worker-inventory-json "${input_dir}/worker_inventory_json.json"
  )
  for input_id in "${optional_input_ids[@]}"; do
    if [[ -f "${input_dir}/${input_id}.json" ]]; then
      case "$input_id" in
        cache_residency_json)
          args+=(--cache-residency-json "${input_dir}/${input_id}.json")
          ;;
        resource_envelope_json)
          args+=(--resource-envelope-json "${input_dir}/${input_id}.json")
          ;;
        execution_queue_input_json)
          args+=(--execution-queue-input-json "${input_dir}/${input_id}.json")
          ;;
        tail_latency_evidence_json)
          args+=(--tail-latency-evidence-json "${input_dir}/${input_id}.json")
          ;;
      esac
    fi
  done
  args+=(--output-dir "$out_dir")

  run_step "${scenario}-normalizer" "$expected_code" bash "$normalizer" "${args[@]}"

  input_path="${out_dir}/swarm_topology_placement_input.json"
  test -f "$input_path"
  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_truth_state "$expected_truth_state" \
    '.decision == $expected_decision and .truth_state == $expected_truth_state' \
    "$input_path" >/dev/null
}

run_planner_case() {
  local scenario="$1"
  local case_dir="$2"
  local normalizer_input="${case_dir}/normalizer/swarm_topology_placement_input.json"
  local out_dir="${case_dir}/planner"
  local expected_decision expected_code

  expected_decision="$(expected_decision_for "$scenario")"
  expected_code="0"
  case "$expected_decision" in
    fail_closed)
      expected_code="42"
      ;;
    blocked)
      expected_code="75"
      ;;
  esac

  run_step "${scenario}-planner" "$expected_code" \
    bash "$planner" \
      --placement-input-json "$normalizer_input" \
      --bead-id bd-2r3eq \
      --source-revision no-mock-drill-fixture \
      --output-dir "$out_dir"

  test -f "${out_dir}/swarm_topology_placement_plan.json"
  jq -e --arg expected_decision "$expected_decision" '
    .decision == $expected_decision
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.pins_workers_automatically == false
    and .mutation_policy.rebinds_hosts_automatically == false
  ' "${out_dir}/swarm_topology_placement_plan.json" >/dev/null
}

run_ledger_case() {
  local scenario="$1"
  local case_dir="$2"
  local plan_path="${case_dir}/planner/swarm_topology_placement_plan.json"
  local observation_path="${case_dir}/adoption_observation.json"
  local out_dir="${case_dir}/ledger"
  local plan_decision expected_code args=()

  plan_decision="$(jq -r '.decision' "$plan_path")"
  expected_code="0"
  case "$plan_decision" in
    fail_closed)
      expected_code="42"
      ;;
    blocked)
      expected_code="75"
      ;;
  esac

  args+=(--placement-plan-json "$plan_path")
  if create_adoption_observation "$plan_path" "$observation_path" "$scenario"; then
    args+=(--adoption-observation-json "$observation_path")
  fi

  run_step "${scenario}-ledger" "$expected_code" \
    bash "$ledger" "${args[@]}" \
      --reference-time "2026-05-06T20:20:00Z" \
      --ttl-seconds 1800 \
      --bead-id bd-2r3eq \
      --source-revision no-mock-drill-fixture \
      --output-dir "$out_dir"

  test -f "${out_dir}/swarm_topology_placement_receipt.json"
  test -f "${out_dir}/swarm_topology_placement_evidence_ledger.json"
  jq -e '
    .mutation_policy.fixture_fed_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.pins_workers_automatically == false
    and .mutation_policy.rebinds_hosts_automatically == false
    and .mutation_policy.enforces_placement_automatically == false
  ' "${out_dir}/swarm_topology_placement_receipt.json" >/dev/null
}

run_operator_case() {
  local scenario="$1"
  local case_dir="$2"
  local out_dir="${case_dir}/operator-status"
  local expected_readiness

  expected_readiness="$(operator_readiness_for "$scenario")"

  run_step "${scenario}-operator-status" "0" \
    bash "$operator_status" \
      --output-dir "$out_dir" \
      --bead-id bd-2r3eq \
      --source-revision no-mock-drill-fixture \
      --agent-mail-status ok \
      --rch-status ok \
      --proof-index-status ok \
      --swarm-topology-placement-plan-json "${case_dir}/planner/swarm_topology_placement_plan.json" \
      --swarm-topology-placement-receipt-json "${case_dir}/ledger/swarm_topology_placement_receipt.json" \
      --swarm-topology-placement-evidence-ledger-json "${case_dir}/ledger/swarm_topology_placement_evidence_ledger.json"

  test -f "${out_dir}/status.json"
  jq -e --arg expected_readiness "$expected_readiness" '
    .predictive_dashboard.swarm_topology_placement.readiness == $expected_readiness
    and .predictive_dashboard.swarm_topology_placement.mutation_policy.advisory_only == true
    and .predictive_dashboard.swarm_topology_placement.mutation_policy.mutates_remote_workers == false
    and .predictive_dashboard.swarm_topology_placement.mutation_policy.changes_live_queue_policy == false
    and .predictive_dashboard.swarm_topology_placement.mutation_policy.pins_workers_automatically == false
  ' "${out_dir}/status.json" >/dev/null
}

record_case_result() {
  local scenario="$1"
  local case_dir="$2"
  local normalizer_input="${case_dir}/normalizer/swarm_topology_placement_input.json"
  local plan_path="${case_dir}/planner/swarm_topology_placement_plan.json"
  local receipt_path="${case_dir}/ledger/swarm_topology_placement_receipt.json"
  local ledger_path="${case_dir}/ledger/swarm_topology_placement_evidence_ledger.json"
  local status_path="${case_dir}/operator-status/status.json"

  jq -nc \
    --arg scenario_id "$scenario" \
    --arg normalizer_input "$normalizer_input" \
    --arg plan_path "$plan_path" \
    --arg receipt_path "$receipt_path" \
    --arg ledger_path "$ledger_path" \
    --arg status_path "$status_path" \
    --slurpfile input "$normalizer_input" \
    --slurpfile plan "$plan_path" \
    --slurpfile receipt "$receipt_path" \
    --slurpfile ledger "$ledger_path" \
    --slurpfile status "$status_path" '
    ($input[0]) as $i
    | ($plan[0]) as $p
    | ($receipt[0]) as $r
    | ($ledger[0]) as $l
    | ($status[0].predictive_dashboard.swarm_topology_placement) as $t
    | {
        scenario_id: $scenario_id,
        normalizer_decision: $i.decision,
        normalizer_truth_state: $i.truth_state,
        plan_decision: $p.decision,
        placement_readiness: $p.placement_readiness,
        receipt_decision: $r.decision,
        adoption_status: $r.adoption_status,
        ledger_decision: $l.decision,
        operator_topology_readiness: $t.readiness,
        operator_topology_severity: $t.severity,
        recommended_topology_class: $t.recommended_topology_class,
        warm_cache_residency_state: $t.warm_cache_residency_state,
        warm_cache_opportunity_count: $t.warm_cache_opportunity_count,
        adoption_drift_reason_codes: $t.adoption_drift_reason_codes,
        warnings: $t.warnings,
        artifact_paths: {
          topology_placement_input_json: $normalizer_input,
          topology_placement_plan_json: $plan_path,
          topology_placement_receipt_json: $receipt_path,
          topology_placement_evidence_ledger_json: $ledger_path,
          operator_status_json: $status_path
        },
        mutation_policy: {
          advisory_only: true,
          runs_cargo: false,
          runs_rch: false,
          mutates_remote_workers: false,
          changes_live_queue_policy: false,
          pins_workers_automatically: false,
          rebinds_hosts_automatically: false
        }
      }' >>"$case_results_path"
}

run_case() {
  local scenario="$1"
  local case_dir="${run_dir}/cases/${scenario}"

  mkdir -p "$case_dir"
  run_normalizer_case "$scenario" "$case_dir"
  run_planner_case "$scenario" "$case_dir"
  run_ledger_case "$scenario" "$case_dir"
  run_operator_case "$scenario" "$case_dir"
  record_case_result "$scenario" "$case_dir"
  record_pass "${scenario} composed placement drill"
}

write_final_report() {
  jq -n \
    --arg schema_version "franken-engine.swarm-topology-placement-no-mock-drill-report.v1" \
    --arg source_revision "no-mock-drill-fixture" \
    --arg run_id "$run_id" \
    --arg run_dir "$run_dir" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg report_json "$report_json" \
    --arg report_md "$report_md" \
    --slurpfile cases "$case_results_path" '
    {
      schema_version: $schema_version,
      drill_id: ("swarm-topology-placement-no-mock-" + $run_id),
      source_revision: $source_revision,
      run_dir: $run_dir,
      scenarios: $cases,
      summary: {
        scenario_count: ($cases | length),
        healthy_ready_count: ($cases | map(select(.operator_topology_readiness == "ready")) | length),
        degraded_count: ($cases | map(select(.operator_topology_readiness == "degraded")) | length),
        blocked_count: ($cases | map(select(.operator_topology_readiness == "blocked")) | length),
        contaminated_count: ($cases | map(select(.operator_topology_readiness == "contaminated")) | length)
      },
      proof_obligations: {
        healthy_topology_aware_placement_planning: any($cases[]; .scenario_id == "healthy_confirmed" and .plan_decision == "pass" and .operator_topology_readiness == "ready" and .warm_cache_opportunity_count >= 1),
        degraded_partial_topology_behavior: any($cases[]; .scenario_id == "degraded_missing_cache_residency" and .operator_topology_readiness == "degraded" and .warm_cache_residency_state == "missing_optional"),
        blocked_contradictory_locality_behavior: any($cases[]; .scenario_id == "blocked_contradictory_locality" and .operator_topology_readiness == "blocked" and (.adoption_drift_reason_codes | index("blocked_plan_not_adoptable") != null)),
        contaminated_local_fallback_behavior: any($cases[]; .scenario_id == "contaminated_local_fallback" and .operator_topology_readiness == "contaminated" and (.warnings | map(.code // "") | index("rch_local_fallback_contaminates_locality") != null))
      },
      artifact_paths: {
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_json: $report_json,
        report_md: $report_md
      },
      mutation_policy: {
        fixture_fed_only: true,
        proof_only: true,
        advisory_only: true,
        runs_cargo: false,
        runs_rch: false,
        mutates_live_workers: false,
        changes_live_queue_policy: false,
        pins_workers_automatically: false,
        rebinds_hosts_automatically: false,
        treats_missing_topology_as_healthy: false,
        treats_missing_cache_evidence_as_healthy: false
      }
    }' >"$report_json"

  {
    printf '# Swarm Topology Placement No-Mock Drill\n\n'
    printf -- "- Scenarios: \`%s\`\n" "$(jq '.summary.scenario_count' "$report_json")"
    printf -- "- Healthy ready: \`%s\`\n" "$(jq '.summary.healthy_ready_count' "$report_json")"
    printf -- "- Degraded: \`%s\`\n" "$(jq '.summary.degraded_count' "$report_json")"
    printf -- "- Blocked: \`%s\`\n" "$(jq '.summary.blocked_count' "$report_json")"
    printf -- "- Contaminated: \`%s\`\n\n" "$(jq '.summary.contaminated_count' "$report_json")"
    printf '## Scenario Proofs\n'
    jq -r '.scenarios[] | "- `" + .scenario_id + "` normalizer=`" + .normalizer_decision + "` plan=`" + .plan_decision + "` receipt=`" + .receipt_decision + "` operator=`" + .operator_topology_readiness + "` cache=`" + .warm_cache_residency_state + "`"' "$report_json"
    printf '\n## Artifacts\n'
    jq -r '.artifact_paths | to_entries[] | "- `" + .key + "`: `" + (.value // "null") + "`"' "$report_json"
  } >"$report_md"

  printf 'swarm_topology_placement_no_mock_drill_report_json=%s\n' "$report_json"
  printf 'swarm_topology_placement_no_mock_drill_report_md=%s\n' "$report_md"
}

check_no_heavy_or_live_claims() {
  local path="$1"
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      record_failure "${path#"$root_dir"/} has a heavy Cargo command claim: ${command}"
    fi
    if [[ "$command" =~ (^|[[:space:]])rch[[:space:]]+exec([[:space:]]|$) ]]; then
      record_failure "${path#"$root_dir"/} has an RCH execution claim: ${command}"
    fi
  done < <(jq -r '.verification_commands[]?' "$path" 2>/dev/null || true)
}

run_check() {
  bash -n "${BASH_SOURCE[0]}"
  bash -n "$normalizer"
  bash -n "$planner"
  bash -n "$ledger"
  bash -n "$operator_status"
  bash -n "$truth_gate"
  jq empty "$fixture_bundle" "$contract_path"
  check_no_heavy_or_live_claims "$contract_path"
  bash "$truth_gate" check

  if [[ "$failures" -eq 0 ]]; then
    record_pass "syntax, fixture, contract, and truth gate checks"
  fi
}

run_drill() {
  local scenario

  ensure_run_dir
  run_step "truth-gate-check" "0" bash "$truth_gate" check
  for scenario in "${drill_scenarios[@]}"; do
    run_case "$scenario"
  done
  write_final_report
}

run_selftest() {
  local tmp_root report_path

  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-topology-placement-no-mock-drill-selftest.XXXXXX")"
  bash "${BASH_SOURCE[0]}" run --output-dir "${tmp_root}/run" >/dev/null
  report_path="${tmp_root}/run/swarm_topology_placement_no_mock_drill_report.json"

  jq -e '
    .schema_version == "franken-engine.swarm-topology-placement-no-mock-drill-report.v1"
    and .summary.scenario_count == 4
    and .proof_obligations.healthy_topology_aware_placement_planning == true
    and .proof_obligations.degraded_partial_topology_behavior == true
    and .proof_obligations.blocked_contradictory_locality_behavior == true
    and .proof_obligations.contaminated_local_fallback_behavior == true
    and any(.scenarios[]; .scenario_id == "degraded_missing_cache_residency" and .operator_topology_readiness == "degraded")
    and any(.scenarios[]; .scenario_id == "blocked_contradictory_locality" and .operator_topology_readiness == "blocked")
    and any(.scenarios[]; .scenario_id == "contaminated_local_fallback" and .operator_topology_readiness == "contaminated")
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_live_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.pins_workers_automatically == false
    and .mutation_policy.rebinds_hosts_automatically == false
    and .mutation_policy.treats_missing_cache_evidence_as_healthy == false
  ' "$report_path" >/dev/null || {
    record_failure "composed drill report did not prove required obligations"
    return 1
  }
  record_pass "composed drill report obligations"

  bash "$truth_gate" selftest
  record_pass "truth gate selftest"
  printf 'swarm_topology_placement_no_mock_drill_selftest_artifacts=%s\n' "$tmp_root"
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_drill
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
