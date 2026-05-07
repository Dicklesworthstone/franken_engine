#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/swarm_autopilot_warehouse_retention_planner.sh"
fixtures_path="${SWARM_AUTOPILOT_WAREHOUSE_RETENTION_FIXTURES:-${root_dir}/scripts/testdata/swarm_autopilot_warehouse_retention_planner/cases.json}"
contract_path="${root_dir}/docs/swarm_autopilot_warehouse_retention_planner_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_AUTOPILOT_WAREHOUSE_RETENTION_PLANNER.md"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-autopilot-warehouse-retention-planner %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-warehouse-retention-planner %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_warehouse_retention_planner_smoke.sh [check|run|selftest] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-warehouse-retention-planner-fixtures.v1"
    and .base_warehouse_json.schema_version == "franken-engine.swarm-autopilot-evidence-warehouse.v1"
    and (.base_warehouse_json.artifact_rows | type) == "array"
    and (.base_warehouse_json.artifact_rows | length) >= 4
    and (.cases | length) == 5
    and ([.cases[].case_id] | unique | length) == 5
    and any(.cases[]; .case_id == "healthy_bounded_retention" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "storage_pressure_degradation" and .expected.decision == "degraded")
    and any(.cases[]; .case_id == "replay_preserve_exemption" and .expected.replay_preserve_source == "state_snapshot_json")
    and any(.cases[]; .case_id == "stale_warehouse_fail_closed" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-WAREHOUSE-STALE")
    and any(.cases[]; .case_id == "contaminated_evidence_refusal" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-WAREHOUSE-CONTAMINATED")
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-warehouse-retention-planner-contract.v1"
    and .bead_id == "bd-gra1z.2"
    and .parent_bead_id == "bd-gra1z"
    and ((["bd-gra1z.1","bd-4t4oi"] - .depends_on) | length) == 0
    and .script == "scripts/swarm_autopilot_warehouse_retention_planner.sh"
    and .smoke_script == "scripts/e2e/swarm_autopilot_warehouse_retention_planner_smoke.sh"
    and .docs == "docs/SWARM_AUTOPILOT_WAREHOUSE_RETENTION_PLANNER.md"
    and .fixture_bundle == "scripts/testdata/swarm_autopilot_warehouse_retention_planner/cases.json"
    and .retention_plan_schema_version == "franken-engine.swarm-autopilot-warehouse-retention-plan.v1"
    and .storage_budget_ledger_schema_version == "franken-engine.swarm-autopilot-storage-budget-ledger.v1"
    and .event_schema_version == "franken-engine.swarm-autopilot-warehouse-retention.event.v1"
    and ((["short_lived_raw_capture","long_lived_replay_evidence","audit_log","policy_snapshot"] - .recognized_retention_classes) | length) == 0
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'The planner is advisory only and proof only.' "$docs_path" \
    && grep -Fq 'Storage pressure may degrade the plan without upgrading it to fail_closed.' "$docs_path" \
    && grep -Fq 'Replay-preserve exemptions must not be compacted.' "$docs_path" \
    && grep -Fq 'Stale warehouse evidence must fail closed.' "$docs_path" \
    && grep -Fq 'Local fallback contamination must fail closed.' "$docs_path"
}

materialize_case() {
  local case_id="$1"
  local case_dir="$2"
  jq --arg case_id "$case_id" '
    def merge_rows($base; $overrides):
      ($overrides // [] | map({key:.source_id, value:.}) | from_entries) as $override_map
      | ($base | map(. + ($override_map[.source_id] // {})) | sort_by(.source_id));
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | ($root.base_warehouse_json * (($case.overrides // {}) | del(.artifact_rows)))
    | .artifact_rows = merge_rows($root.base_warehouse_json.artifact_rows; ($case.overrides.artifact_rows // []))
  ' "$fixtures_path" >"${case_dir}/evidence_warehouse.json"
}

validate_required_artifacts() {
  local case_dir="$1"
  local artifact
  for artifact in swarm_autopilot_warehouse_retention_plan.json swarm_autopilot_storage_budget_ledger.json events.jsonl commands.txt report.md; do
    if [[ ! -s "${case_dir}/${artifact}" ]]; then
      record_failure "${case_dir} missing ${artifact}"
    fi
  done
}

validate_outputs() {
  local case_dir="$1"
  local case_id="$2"
  local expected_json="$3"
  local plan_json="${case_dir}/swarm_autopilot_warehouse_retention_plan.json"
  local ledger_json="${case_dir}/swarm_autopilot_storage_budget_ledger.json"
  local required_error replay_preserve_source minimum_candidates

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-warehouse-retention-plan.v1"
    and .decision == $expected[0].decision
    and .storage_pressure_state == $expected[0].storage_pressure_state
    and (.replay_preserve_sources | type) == "array"
    and (.compaction_candidates | type) == "array"
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
  ' "$plan_json" >/dev/null || record_failure "${case_id} plan mismatch"

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-storage-budget-ledger.v1"
    and .decision == $expected[0].decision
    and .storage_pressure_state == $expected[0].storage_pressure_state
    and .summary.artifact_row_count >= 4
    and .summary.total_estimated_bytes > 0
  ' "$ledger_json" >/dev/null || record_failure "${case_id} ledger mismatch"

  required_error="$(jq -r '.required_error_code // ""' "$expected_json")"
  if [[ -n "$required_error" ]]; then
    jq -e --arg required_error "$required_error" '.fail_closed_reasons | map(.code) | index($required_error) != null' "$plan_json" >/dev/null \
      || record_failure "${case_id} missing required error code ${required_error}"
  fi

  replay_preserve_source="$(jq -r '.replay_preserve_source // ""' "$expected_json")"
  if [[ -n "$replay_preserve_source" ]]; then
    jq -e --arg replay_preserve_source "$replay_preserve_source" '.replay_preserve_sources | index($replay_preserve_source) != null' "$plan_json" >/dev/null \
      || record_failure "${case_id} missing replay preserve source ${replay_preserve_source}"
  fi

  minimum_candidates="$(jq -r '.minimum_compaction_candidate_count // 0' "$expected_json")"
  jq -e --argjson minimum_candidates "$minimum_candidates" '.compaction_candidates | length >= $minimum_candidates' "$plan_json" >/dev/null \
    || record_failure "${case_id} compaction candidate count below expected minimum"

  grep -Fq './scripts/swarm_autopilot_warehouse_retention_planner.sh' "${case_dir}/commands.txt" \
    || record_failure "${case_id} commands.txt missing planner command"
}

run_case() {
  local case_id="$1"
  local case_dir="$2"
  local expected_json="${case_dir}/expected.json"
  local warehouse_json="${case_dir}/evidence_warehouse.json"
  local output_case_dir="${case_dir}/output"
  local rc

  mkdir -p "$output_case_dir"
  materialize_case "$case_id" "$case_dir"
  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected' "$fixtures_path" >"$expected_json"

  set +e
  bash "$planner" --evidence-warehouse-json "$warehouse_json" --source-revision "fixture-${case_id}" --output-dir "$output_case_dir"
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
  run|selftest)
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
