#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
comparator="${root_dir}/scripts/swarm_autopilot_cohort_diff_comparator.sh"
fixtures_path="${SWARM_AUTOPILOT_COHORT_DIFF_FIXTURES:-${root_dir}/scripts/testdata/swarm_autopilot_cohort_diff_comparator/cases.json}"
contract_path="${root_dir}/docs/swarm_autopilot_cohort_diff_comparator_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_AUTOPILOT_COHORT_DIFF_COMPARATOR.md"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-autopilot-cohort-diff-comparator %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-cohort-diff-comparator %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_cohort_diff_comparator_smoke.sh [check|selftest]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-cohort-diff-comparator-fixtures.v1"
    and (.cases | length) == 4
    and ([.cases[].case_id] | unique | length) == 4
    and all(.cases[]; .reference_anomaly_cohorts_json.schema_version == "franken-engine.swarm-autopilot-anomaly-cohorts.v1")
    and all(.cases[]; .comparison_anomaly_cohorts_json.schema_version == "franken-engine.swarm-autopilot-anomaly-cohorts.v1")
    and all(.cases[]; .reference_replay_index_json.schema_version == "franken-engine.swarm-autopilot-replay-index.v1")
    and all(.cases[]; .comparison_replay_index_json.schema_version == "franken-engine.swarm-autopilot-replay-index.v1")
    and any(.cases[]; .case_id == "healthy_vs_blocked_locality_drift" and .expected.decision == "degraded")
    and any(.cases[]; .case_id == "healthy_vs_contaminated_fallback_separation" and .expected.required_transition == "reference_to_contaminated")
    and any(.cases[]; .case_id == "stale_reference_fail_closed" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-COHORT-DIFF-STALE-REFERENCE")
    and any(.cases[]; .case_id == "contradictory_cohort_identity_rejection" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-COHORT-DIFF-CONTRADICTORY-COHORT")
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-cohort-diff-comparator-contract.v1"
    and .bead_id == "bd-00ofm.2"
    and .parent_bead_id == "bd-00ofm"
    and ((["bd-00ofm.1","bd-gra1z.4"] - .depends_on) | length) == 0
    and .script == "scripts/swarm_autopilot_cohort_diff_comparator.sh"
    and .smoke_script == "scripts/e2e/swarm_autopilot_cohort_diff_comparator_smoke.sh"
    and .docs == "docs/SWARM_AUTOPILOT_COHORT_DIFF_COMPARATOR.md"
    and .fixture_bundle == "scripts/testdata/swarm_autopilot_cohort_diff_comparator/cases.json"
    and .receipt_schema_version == "franken-engine.swarm-autopilot-cohort-diff-receipts.v1"
    and .fingerprint_delta_plan_schema_version == "franken-engine.swarm-autopilot-fingerprint-delta-plan.v1"
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.approves_replay_automatically == false
    and .mutation_policy.promotes_evidence_automatically == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'The comparator is advisory only and proof only.' "$docs_path" \
    && grep -Fq 'Healthy reference cohorts remain distinct from blocked, degraded, and contaminated comparison cohorts.' "$docs_path" \
    && grep -Fq 'Blocked locality drift must preserve worker, toolchain, topology, raw artifact, and fingerprint deltas.' "$docs_path" \
    && grep -Fq 'Fallback-contaminated comparison cohorts remain isolated from healthy reference material and cannot become a reference baseline.' "$docs_path" \
    && grep -Fq 'Contradictory cohort identity fails closed.' "$docs_path"
}

materialize_case() {
  local case_id="$1"
  local case_dir="$2"
  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .reference_anomaly_cohorts_json' "$fixtures_path" >"${case_dir}/reference_anomaly_cohorts.json"
  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .comparison_anomaly_cohorts_json' "$fixtures_path" >"${case_dir}/comparison_anomaly_cohorts.json"
  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .reference_replay_index_json' "$fixtures_path" >"${case_dir}/reference_replay_index.json"
  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .comparison_replay_index_json' "$fixtures_path" >"${case_dir}/comparison_replay_index.json"
  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected' "$fixtures_path" >"${case_dir}/expected.json"
}

validate_required_artifacts() {
  local case_dir="$1"
  local artifact
  for artifact in swarm_autopilot_cohort_diff_receipts.json swarm_autopilot_fingerprint_delta_plan.json events.jsonl commands.txt report.md; do
    if [[ ! -s "${case_dir}/${artifact}" ]]; then
      record_failure "${case_dir} missing ${artifact}"
    fi
  done
}

validate_outputs() {
  local case_dir="$1"
  local case_id="$2"
  local expected_json="$3"
  local receipts_json="${case_dir}/swarm_autopilot_cohort_diff_receipts.json"
  local delta_plan_json="${case_dir}/swarm_autopilot_fingerprint_delta_plan.json"
  local required_error required_transition minimum_count requires_remote_truth_invalid

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-cohort-diff-receipts.v1"
    and .decision == $expected[0].decision
    and (.cohort_diff_receipts | type) == "array"
    and (.comparison_summary.diff_receipt_count == (.cohort_diff_receipts | length))
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.approves_replay_automatically == false
    and .mutation_policy.promotes_evidence_automatically == false
  ' "$receipts_json" >/dev/null || record_failure "${case_id} receipt bundle mismatch"

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-fingerprint-delta-plan.v1"
    and .decision == $expected[0].decision
    and (.fingerprint_deltas | type) == "array"
  ' "$delta_plan_json" >/dev/null || record_failure "${case_id} delta plan mismatch"

  required_error="$(jq -r '.required_error_code // ""' "$expected_json")"
  if [[ -n "$required_error" ]]; then
    jq -e --arg required_error "$required_error" '.fail_closed_reasons | map(.code) | index($required_error) != null' "$receipts_json" >/dev/null \
      || record_failure "${case_id} missing required error code ${required_error}"
  fi

  required_transition="$(jq -r '.required_transition // ""' "$expected_json")"
  if [[ -n "$required_transition" ]]; then
    jq -e --arg required_transition "$required_transition" '.cohort_diff_receipts | any(.classification_transition == $required_transition)' "$receipts_json" >/dev/null \
      || record_failure "${case_id} missing required transition ${required_transition}"
  fi

  minimum_count="$(jq -r '.minimum_changed_fingerprint_count // -1' "$expected_json")"
  if [[ "$minimum_count" -ge 0 ]]; then
    jq -e --argjson minimum_count "$minimum_count" '.comparison_summary.changed_fingerprint_count >= $minimum_count' "$receipts_json" >/dev/null \
      || record_failure "${case_id} changed fingerprint count below ${minimum_count}"
  fi

  minimum_count="$(jq -r '.minimum_worker_delta_count // -1' "$expected_json")"
  if [[ "$minimum_count" -ge 0 ]]; then
    jq -e --argjson minimum_count "$minimum_count" '([.cohort_diff_receipts[].worker_deltas[]?] | length) >= $minimum_count' "$receipts_json" >/dev/null \
      || record_failure "${case_id} worker delta count below ${minimum_count}"
  fi

  minimum_count="$(jq -r '.minimum_toolchain_delta_count // -1' "$expected_json")"
  if [[ "$minimum_count" -ge 0 ]]; then
    jq -e --argjson minimum_count "$minimum_count" '([.cohort_diff_receipts[].toolchain_deltas[]?] | length) >= $minimum_count' "$receipts_json" >/dev/null \
      || record_failure "${case_id} toolchain delta count below ${minimum_count}"
  fi

  minimum_count="$(jq -r '.minimum_topology_delta_count // -1' "$expected_json")"
  if [[ "$minimum_count" -ge 0 ]]; then
    jq -e --argjson minimum_count "$minimum_count" '([.cohort_diff_receipts[].topology_deltas[]?] | length) >= $minimum_count' "$receipts_json" >/dev/null \
      || record_failure "${case_id} topology delta count below ${minimum_count}"
  fi

  requires_remote_truth_invalid="$(jq -r '.requires_remote_truth_invalid // false' "$expected_json")"
  if [[ "$requires_remote_truth_invalid" == "true" ]]; then
    jq -e '.cohort_diff_receipts | any(.remote_truth_valid == false)' "$receipts_json" >/dev/null \
      || record_failure "${case_id} did not preserve remote_truth_valid=false"
  fi

  grep -Fq './scripts/swarm_autopilot_cohort_diff_comparator.sh' "${case_dir}/commands.txt" \
    || record_failure "${case_id} commands.txt missing comparator command"
}

run_case() {
  local case_id="$1"
  local case_dir="$2"
  local output_case_dir="${case_dir}/output"
  local expected_json="${case_dir}/expected.json"
  local rc

  mkdir -p "$output_case_dir"
  materialize_case "$case_id" "$case_dir"

  set +e
  bash "$comparator" \
    --reference-anomaly-cohorts-json "${case_dir}/reference_anomaly_cohorts.json" \
    --comparison-anomaly-cohorts-json "${case_dir}/comparison_anomaly_cohorts.json" \
    --reference-replay-index-json "${case_dir}/reference_replay_index.json" \
    --comparison-replay-index-json "${case_dir}/comparison_replay_index.json" \
    --source-revision "fixture-${case_id}" \
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
