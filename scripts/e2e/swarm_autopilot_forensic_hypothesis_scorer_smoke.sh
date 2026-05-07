#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scorer="${root_dir}/scripts/swarm_autopilot_forensic_hypothesis_scorer.sh"
fixtures_path="${SWARM_AUTOPILOT_HYPOTHESIS_SCORER_FIXTURES:-${root_dir}/scripts/testdata/swarm_autopilot_forensic_hypothesis_scorer/cases.json}"
contract_path="${root_dir}/docs/swarm_autopilot_forensic_hypothesis_scorer_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_AUTOPILOT_FORENSIC_HYPOTHESIS_SCORER.md"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-autopilot-forensic-hypothesis-scorer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-forensic-hypothesis-scorer %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_forensic_hypothesis_scorer_smoke.sh [check|selftest]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-forensic-hypothesis-scorer-fixtures.v1"
    and .base_cohort_diff_receipts_json.schema_version == "franken-engine.swarm-autopilot-cohort-diff-receipts.v1"
    and .base_evidence_warehouse_json.schema_version == "franken-engine.swarm-autopilot-evidence-warehouse.v1"
    and (.cases | length) == 4
    and ([.cases[].case_id] | unique | length) == 4
    and any(.cases[]; .case_id == "topology_drift_explanation" and .expected.required_pivot == "topology_drift")
    and any(.cases[]; .case_id == "contaminated_evidence_suppression" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-HYPOTHESIS-CONTAMINATED-EVIDENCE")
    and any(.cases[]; .case_id == "low_evidence_degradation" and .expected.required_pivot == "insufficient_evidence")
    and any(.cases[]; .case_id == "contradictory_hypothesis_fail_closed" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-HYPOTHESIS-CONTRADICTORY-EVIDENCE")
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-forensic-hypothesis-scorer-contract.v1"
    and .bead_id == "bd-00ofm.4"
    and .parent_bead_id == "bd-00ofm"
    and ((["bd-00ofm.1","bd-00ofm.2"] - .depends_on) | length) == 0
    and .script == "scripts/swarm_autopilot_forensic_hypothesis_scorer.sh"
    and .smoke_script == "scripts/e2e/swarm_autopilot_forensic_hypothesis_scorer_smoke.sh"
    and .docs == "docs/SWARM_AUTOPILOT_FORENSIC_HYPOTHESIS_SCORER.md"
    and .fixture_bundle == "scripts/testdata/swarm_autopilot_forensic_hypothesis_scorer/cases.json"
    and .summary_schema_version == "franken-engine.swarm-autopilot-forensic-hypothesis-summary.v1"
    and .evidence_schema_version == "franken-engine.swarm-autopilot-forensic-hypothesis-evidence.v1"
    and ((["topology_drift","toolchain_skew","worker_locality_shift","evidence_fingerprint_delta","insufficient_evidence"] - .hypothesis_pivots) | length) == 0
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.promotes_hypotheses_automatically == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'The forensic hypothesis scorer is advisory only and proof only.' "$docs_path" \
    && grep -Fq 'Topology drift is promoted only when topology deltas are present in coherent diff receipts.' "$docs_path" \
    && grep -Fq 'Each hypothesis preserves confidence band, counterevidence, supporting source ids, supporting receipts, and remediation suggestion.' "$docs_path" \
    && grep -Fq 'Low-evidence cases degrade instead of overclaiming certainty.' "$docs_path" \
    && grep -Fq 'Contaminated evidence is suppressed and cannot support promoted hypotheses.' "$docs_path"
}

materialize_case() {
  local case_id="$1"
  local case_dir="$2"
  jq --arg case_id "$case_id" '
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | {
        cohort_diff_receipts_json: ($root.base_cohort_diff_receipts_json * ($case.overrides.cohort_diff_receipts_json // {})),
        evidence_warehouse_json: ($root.base_evidence_warehouse_json * ($case.overrides.evidence_warehouse_json // {}))
      }
  ' "$fixtures_path" >"${case_dir}/materialized_inputs.json"
  jq '.cohort_diff_receipts_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/cohort_diff_receipts.json"
  jq '.evidence_warehouse_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/evidence_warehouse.json"
  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected' "$fixtures_path" >"${case_dir}/expected.json"
}

validate_required_artifacts() {
  local case_dir="$1"
  local artifact
  for artifact in swarm_autopilot_forensic_hypothesis_summary.json swarm_autopilot_forensic_hypothesis_evidence.json events.jsonl commands.txt report.md; do
    if [[ ! -s "${case_dir}/${artifact}" ]]; then
      record_failure "${case_dir} missing ${artifact}"
    fi
  done
}

validate_outputs() {
  local output_case_dir="$1"
  local case_id="$2"
  local expected_json="$3"
  local summary_json="${output_case_dir}/swarm_autopilot_forensic_hypothesis_summary.json"
  local evidence_json="${output_case_dir}/swarm_autopilot_forensic_hypothesis_evidence.json"
  local required_error required_pivot

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-forensic-hypothesis-summary.v1"
    and .decision == $expected[0].decision
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.promotes_hypotheses_automatically == false
  ' "$summary_json" >/dev/null || record_failure "${case_id} summary mismatch"

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-forensic-hypothesis-evidence.v1"
    and .decision == $expected[0].decision
    and (.warehouse_rows | length) > 0
  ' "$evidence_json" >/dev/null || record_failure "${case_id} evidence mismatch"

  required_error="$(jq -r '.required_error_code // ""' "$expected_json")"
  if [[ -n "$required_error" ]]; then
    jq -e --arg required_error "$required_error" '.fail_closed_reasons | map(.code) | index($required_error) != null' "$summary_json" >/dev/null \
      || record_failure "${case_id} missing required error code ${required_error}"
  fi

  required_pivot="$(jq -r '.required_pivot // ""' "$expected_json")"
  if [[ -n "$required_pivot" ]]; then
    jq -e --arg required_pivot "$required_pivot" '.hypotheses | any(.pivot == $required_pivot and (.confidence_band | length) > 0 and (.supporting_source_ids | type) == "array" and (.supporting_receipts | type) == "array" and (.remediation_suggestion | length) > 0)' "$summary_json" >/dev/null \
      || record_failure "${case_id} missing hypothesis pivot ${required_pivot}"
  fi

  grep -Fq './scripts/swarm_autopilot_forensic_hypothesis_scorer.sh' "${output_case_dir}/commands.txt" \
    || record_failure "${case_id} commands.txt missing hypothesis scorer command"
}

run_case() {
  local case_id="$1"
  local case_dir="$2"
  local output_case_dir="${case_dir}/output"
  local expected_json="${case_dir}/expected.json"
  local rc

  mkdir -p "$case_dir" "$output_case_dir"
  materialize_case "$case_id" "$case_dir"

  set +e
  bash "$scorer" \
    --cohort-diff-receipts-json "${case_dir}/cohort_diff_receipts.json" \
    --evidence-warehouse-json "${case_dir}/evidence_warehouse.json" \
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
