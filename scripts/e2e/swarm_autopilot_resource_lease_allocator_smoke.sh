#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
allocator="${root_dir}/scripts/swarm_autopilot_resource_lease_allocator.sh"
fixtures_path="${SWARM_AUTOPILOT_RESOURCE_LEASE_ALLOCATOR_FIXTURES:-${root_dir}/scripts/testdata/swarm_autopilot_resource_lease_allocator/cases.json}"
contract_path="${root_dir}/docs/swarm_autopilot_resource_lease_allocator_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_AUTOPILOT_RESOURCE_LEASE_ALLOCATOR.md"
mode="${1:-check}"
failures=0
fixed_now_epoch_seconds="1778122000"
stale_after_seconds="1800"
default_lease_duration_seconds="1800"

record_pass() {
  printf 'PASS swarm-autopilot-resource-lease-allocator %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-resource-lease-allocator %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_resource_lease_allocator_smoke.sh [check|selftest]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-resource-lease-allocator-fixtures.v1"
    and .base_operator_intent_policy_json.schema_version == "franken-engine.swarm-autopilot-operator-intent-policy.v1"
    and .base_brownout_forecaster_json.schema_version == "franken-engine.swarm-autopilot-brownout-forecaster.v1"
    and .base_queue_advisory_bundle_json.schema_version == "franken-engine.swarm-topology-aware-queue-advisory.v1"
    and .base_rch_rehabilitation_ledger_json.schema_version == "franken-engine.swarm-rch-stall-rehabilitation-ledger.v1"
    and (.cases | length) == 6
    and ([.cases[].case_id] | unique | length) == 6
    and any(.cases[]; .case_id == "healthy_balanced_allocation" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "urgent_lane_protection" and .expected.required_lane_id == "bd-urgent-a" and .expected.required_decision == "reserve")
    and any(.cases[]; .case_id == "fairness_recovery" and .expected.required_lane_id == "bd-fairness-d" and .expected.required_decision == "rebalance")
    and any(.cases[]; .case_id == "rch_brownout_deferral" and .expected.required_lane_id == "bd-background-b" and .expected.required_decision == "defer")
    and any(.cases[]; .case_id == "proof_cache_cooling" and .expected.required_lane_id == "bd-cache-c" and .expected.required_decision == "cool")
    and any(.cases[]; .case_id == "contradictory_locality_fail_closed" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-LEASE-CONTRADICTORY-QUEUE")
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-resource-lease-allocator-contract.v1"
    and .bead_id == "bd-knanr"
    and ((["bd-7dr9z","bd-g7bk2","bd-o9pr3"] - .depends_on) | length) == 0
    and .script == "scripts/swarm_autopilot_resource_lease_allocator.sh"
    and .smoke_script == "scripts/e2e/swarm_autopilot_resource_lease_allocator_smoke.sh"
    and .docs == "docs/SWARM_AUTOPILOT_RESOURCE_LEASE_ALLOCATOR.md"
    and .fixture_bundle == "scripts/testdata/swarm_autopilot_resource_lease_allocator/cases.json"
    and .plan_schema_version == "franken-engine.swarm-autopilot-resource-lease-plan.v1"
    and .receipt_schema_version == "franken-engine.swarm-autopilot-resource-scarcity-receipts.v1"
    and ((["cpu_memory","rch_slots","warm_target","proof_cache","fairness_recovery","all"] - .resource_classes) | length) == 0
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'The allocator is advisory only and proof only.' "$docs_path" \
    && grep -Fq 'Local fallback contamination fails closed.' "$docs_path" \
    && grep -Fq 'Contradictory queue or locality evidence fails closed.' "$docs_path" \
    && grep -Fq 'Urgent RCH slack protection outranks nonurgent heavy fanout.' "$docs_path" \
    && grep -Fq 'Every scarcity receipt includes reason codes, evidence paths, lease duration, and rollback or remediation guidance.' "$docs_path"
}

materialize_case() {
  local case_id="$1"
  local case_dir="$2"
  jq --arg case_id "$case_id" '
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | {
        operator_intent_policy_json: ($root.base_operator_intent_policy_json * ($case.overrides.operator_intent_policy_json // {})),
        brownout_forecaster_json: ($root.base_brownout_forecaster_json * ($case.overrides.brownout_forecaster_json // {})),
        queue_advisory_bundle_json: ($root.base_queue_advisory_bundle_json * ($case.overrides.queue_advisory_bundle_json // {})),
        rch_rehabilitation_ledger_json: ($root.base_rch_rehabilitation_ledger_json * ($case.overrides.rch_rehabilitation_ledger_json // {}))
      }
  ' "$fixtures_path" >"${case_dir}/materialized_inputs.json"

  jq '.operator_intent_policy_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/operator_intent_policy.json"
  jq '.brownout_forecaster_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/brownout_forecaster.json"
  jq '.queue_advisory_bundle_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/queue_advisory_bundle.json"
  jq '.rch_rehabilitation_ledger_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/rch_rehabilitation_ledger.json"
}

validate_required_artifacts() {
  local case_dir="$1"
  local artifact
  for artifact in \
    swarm_autopilot_resource_lease_plan.json \
    swarm_autopilot_resource_scarcity_receipts.json \
    events.jsonl \
    commands.txt \
    report.md; do
    if [[ ! -s "${case_dir}/${artifact}" ]]; then
      record_failure "${case_dir} missing ${artifact}"
    fi
  done
}

validate_outputs() {
  local output_case_dir="$1"
  local case_id="$2"
  local expected_json="$3"
  local plan_json="${output_case_dir}/swarm_autopilot_resource_lease_plan.json"
  local receipts_json="${output_case_dir}/swarm_autopilot_resource_scarcity_receipts.json"
  local required_error required_lane_id required_decision expected_overall_state

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-resource-lease-plan.v1"
    and .decision == $expected[0].decision
    and (.allocation_id | startswith("lease-plan-"))
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and (.artifact_paths.plan_json | length > 0)
    and (.artifact_paths.receipts_json | length > 0)
  ' "$plan_json" >/dev/null || record_failure "${case_id} plan shape mismatch"

  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-resource-scarcity-receipts.v1"
    and (.receipt_bundle_id | startswith("lease-receipts-"))
    and (.receipts | length) > 0
  ' "$receipts_json" >/dev/null || record_failure "${case_id} receipts shape mismatch"

  required_error="$(jq -r '.required_error_code // ""' "$expected_json")"
  if [[ -n "$required_error" ]]; then
    jq -e --arg required_error "$required_error" '.fail_closed_reasons | map(.code) | index($required_error) != null' "$plan_json" >/dev/null \
      || record_failure "${case_id} missing required error code ${required_error}"
    jq -e '.summary.overall_state == "fail_closed"' "$plan_json" >/dev/null \
      || record_failure "${case_id} expected fail_closed overall state"
  fi

  required_lane_id="$(jq -r '.required_lane_id // ""' "$expected_json")"
  required_decision="$(jq -r '.required_decision // ""' "$expected_json")"
  if [[ -n "$required_lane_id" && -n "$required_decision" ]]; then
    jq -e --arg required_lane_id "$required_lane_id" --arg required_decision "$required_decision" '.lease_allocations | any(.lane_id == $required_lane_id and .decision == $required_decision)' "$plan_json" >/dev/null \
      || record_failure "${case_id} missing required lane decision ${required_lane_id}/${required_decision}"
    jq -e --arg required_lane_id "$required_lane_id" --arg required_decision "$required_decision" '.receipts | any(.lane_id == $required_lane_id and .decision == $required_decision and (.reason_codes | length) > 0 and (.evidence_paths | length) > 0 and (.lease_duration_seconds | type) == "number" and (.rollback_command | length) > 0 and (.remediation_command | length) > 0)' "$receipts_json" >/dev/null \
      || record_failure "${case_id} missing required scarcity receipt detail ${required_lane_id}/${required_decision}"
  fi

  expected_overall_state="$(jq -r '.expected_overall_state // ""' "$expected_json")"
  if [[ -n "$expected_overall_state" ]]; then
    jq -e --arg expected_overall_state "$expected_overall_state" '.summary.overall_state == $expected_overall_state' "$plan_json" >/dev/null \
      || record_failure "${case_id} unexpected overall state"
  fi

  grep -Fq './scripts/swarm_autopilot_resource_lease_allocator.sh' "${output_case_dir}/commands.txt" \
    || record_failure "${case_id} commands.txt missing allocator command"
}

run_case() {
  local case_id="$1"
  local case_dir="$2"
  local expected_json="${case_dir}/expected.json"
  local output_case_dir="${case_dir}/output"
  local rc

  mkdir -p "$case_dir" "$output_case_dir"
  materialize_case "$case_id" "$case_dir"
  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected' "$fixtures_path" >"$expected_json"

  set +e
  bash "$allocator" \
    --operator-intent-policy-json "${case_dir}/operator_intent_policy.json" \
    --brownout-forecaster-json "${case_dir}/brownout_forecaster.json" \
    --queue-advisory-bundle-json "${case_dir}/queue_advisory_bundle.json" \
    --rch-rehabilitation-ledger-json "${case_dir}/rch_rehabilitation_ledger.json" \
    --source-revision "fixture-${case_id}" \
    --now-epoch-seconds "$fixed_now_epoch_seconds" \
    --stale-after-seconds "$stale_after_seconds" \
    --default-lease-duration-seconds "$default_lease_duration_seconds" \
    --output-dir "$output_case_dir"
  rc=$?
  set -e

  if [[ "$rc" -ne "$(jq -r '.expected_exit_code' "$expected_json")" ]]; then
    record_failure "${case_id} exit code ${rc} != expected $(jq -r '.expected_exit_code' "$expected_json")"
  fi

  validate_required_artifacts "$output_case_dir"
  validate_outputs "$output_case_dir" "$case_id" "$expected_json"
}

run_check() {
  fixtures_shape_ok || record_failure "fixtures shape mismatch"
  contract_shape_ok || record_failure "contract JSON shape mismatch"
  docs_shape_ok || record_failure "docs truth text mismatch"
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  local temp_dir
  temp_dir="$(mktemp -d)"
  trap 'rm -rf "$temp_dir"' RETURN

  while IFS= read -r case_id; do
    run_case "$case_id" "${temp_dir}/${case_id}"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")

  if [[ "$failures" -eq 0 ]]; then
    record_pass "selftest"
  else
    exit 1
  fi
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest
    else
      exit 1
    fi
    ;;
  *)
    usage
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
