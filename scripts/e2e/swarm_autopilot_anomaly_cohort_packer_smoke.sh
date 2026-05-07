#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
packer="${root_dir}/scripts/swarm_autopilot_anomaly_cohort_packer.sh"
fixtures_path="${SWARM_AUTOPILOT_ANOMALY_COHORT_FIXTURES:-${root_dir}/scripts/testdata/swarm_autopilot_anomaly_cohort_packer/cases.json}"
contract_path="${root_dir}/docs/swarm_autopilot_anomaly_cohort_packer_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_AUTOPILOT_ANOMALY_COHORT_PACKER.md"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-autopilot-anomaly-cohort-packer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-anomaly-cohort-packer %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_anomaly_cohort_packer_smoke.sh [check|selftest]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-anomaly-cohort-packer-fixtures.v1"
    and .base_warehouse_json.schema_version == "franken-engine.swarm-autopilot-evidence-warehouse.v1"
    and (.base_warehouse_json.artifact_rows | type) == "array"
    and (.cases | length) == 5
    and ([.cases[].case_id] | unique | length) == 5
    and any(.cases[]; .case_id == "healthy_reference_cohort_creation" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "blocked_locality_contradiction" and .expected.decision == "degraded")
    and any(.cases[]; .case_id == "fallback_contaminated_isolation" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-COHORT-CONTAMINATED")
    and any(.cases[]; .case_id == "contradictory_cohort_rejection" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-COHORT-CONTRADICTORY-MEMBERSHIP")
    and any(.cases[]; .case_id == "stale_reference_fail_closed" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-COHORT-STALE-REFERENCE")
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-anomaly-cohort-packer-contract.v1"
    and .bead_id == "bd-gra1z.4"
    and .parent_bead_id == "bd-gra1z"
    and ((["bd-gra1z.1","bd-4t4oi"] - .depends_on) | length) == 0
    and .script == "scripts/swarm_autopilot_anomaly_cohort_packer.sh"
    and .smoke_script == "scripts/e2e/swarm_autopilot_anomaly_cohort_packer_smoke.sh"
    and .docs == "docs/SWARM_AUTOPILOT_ANOMALY_COHORT_PACKER.md"
    and .fixture_bundle == "scripts/testdata/swarm_autopilot_anomaly_cohort_packer/cases.json"
    and .cohort_bundle_schema_version == "franken-engine.swarm-autopilot-anomaly-cohorts.v1"
    and .replay_index_schema_version == "franken-engine.swarm-autopilot-replay-index.v1"
    and ((["reference","degraded","blocked","contaminated"] - .cohort_classifications) | length) == 0
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'The packer is advisory only and proof only.' "$docs_path" \
    && grep -Fq 'Healthy reference cohorts remain distinct from degraded, blocked, and contaminated cohorts.' "$docs_path" \
    && grep -Fq 'Fallback-contaminated cohorts remain isolated from healthy reference cohorts.' "$docs_path" \
    && grep -Fq 'Contradictory cohort membership fails closed.' "$docs_path" \
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
  for artifact in swarm_autopilot_anomaly_cohorts.json swarm_autopilot_replay_index.json events.jsonl commands.txt report.md; do
    if [[ ! -s "${case_dir}/${artifact}" ]]; then
      record_failure "${case_dir} missing ${artifact}"
    fi
  done
}

validate_outputs() {
  local case_dir="$1"
  local case_id="$2"
  local expected_json="$3"
  local cohorts_json="${case_dir}/swarm_autopilot_anomaly_cohorts.json"
  local replay_index_json="${case_dir}/swarm_autopilot_replay_index.json"
  local required_error required_classification expected_reference_count expected_blocked_count expected_contaminated_count

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-anomaly-cohorts.v1"
    and .decision == $expected[0].decision
    and (.cohorts | type) == "array"
    and (.cohort_summary.total_cohort_count == (.cohorts | length))
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
  ' "$cohorts_json" >/dev/null || record_failure "${case_id} cohorts bundle mismatch"

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-replay-index.v1"
    and .decision == $expected[0].decision
    and (.entries | type) == "array"
  ' "$replay_index_json" >/dev/null || record_failure "${case_id} replay index mismatch"

  required_error="$(jq -r '.required_error_code // ""' "$expected_json")"
  if [[ -n "$required_error" ]]; then
    jq -e --arg required_error "$required_error" '.fail_closed_reasons | map(.code) | index($required_error) != null' "$cohorts_json" >/dev/null \
      || record_failure "${case_id} missing required error code ${required_error}"
  fi

  required_classification="$(jq -r '.required_classification // ""' "$expected_json")"
  if [[ -n "$required_classification" ]]; then
    jq -e --arg required_classification "$required_classification" '.cohorts | any(.classification == $required_classification)' "$cohorts_json" >/dev/null \
      || record_failure "${case_id} missing required cohort classification ${required_classification}"
  fi

  expected_reference_count="$(jq -r '.expected_reference_count // -1' "$expected_json")"
  if [[ "$expected_reference_count" -ge 0 ]]; then
    jq -e --argjson expected_reference_count "$expected_reference_count" '.cohort_summary.reference_count == $expected_reference_count' "$cohorts_json" >/dev/null \
      || record_failure "${case_id} unexpected reference count"
  fi

  expected_blocked_count="$(jq -r '.expected_blocked_count // -1' "$expected_json")"
  if [[ "$expected_blocked_count" -ge 0 ]]; then
    jq -e --argjson expected_blocked_count "$expected_blocked_count" '.cohort_summary.blocked_count == $expected_blocked_count' "$cohorts_json" >/dev/null \
      || record_failure "${case_id} unexpected blocked count"
  fi

  expected_contaminated_count="$(jq -r '.expected_contaminated_count // -1' "$expected_json")"
  if [[ "$expected_contaminated_count" -ge 0 ]]; then
    jq -e --argjson expected_contaminated_count "$expected_contaminated_count" '.cohort_summary.contaminated_count == $expected_contaminated_count' "$cohorts_json" >/dev/null \
      || record_failure "${case_id} unexpected contaminated count"
  fi

  grep -Fq './scripts/swarm_autopilot_anomaly_cohort_packer.sh' "${case_dir}/commands.txt" \
    || record_failure "${case_id} commands.txt missing packer command"
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
  bash "$packer" --evidence-warehouse-json "$warehouse_json" --source-revision "fixture-${case_id}" --output-dir "$output_case_dir"
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
