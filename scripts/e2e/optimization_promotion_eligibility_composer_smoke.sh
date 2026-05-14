#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
producer="${root_dir}/scripts/optimization_promotion_eligibility_composer.sh"
fixtures_path="${OPTIMIZATION_PROMOTION_ELIGIBILITY_FIXTURES:-${root_dir}/scripts/testdata/optimization_promotion_eligibility_composer/cases.json}"
contract_path="${root_dir}/docs/optimization_promotion_eligibility_composer_contract_v1.json"
docs_path="${root_dir}/docs/OPTIMIZATION_PROMOTION_ELIGIBILITY_COMPOSER.md"
mode="${1:-check}"
failures=0

usage() {
  cat >&2 <<'USAGE'
Usage: ./scripts/e2e/optimization_promotion_eligibility_composer_smoke.sh [check|selftest]
USAGE
}

record_pass() {
  printf 'PASS optimization-promotion-eligibility %s\n' "$1"
}

record_failure() {
  printf 'FAIL optimization-promotion-eligibility %s\n' "$1" >&2
  failures=$((failures + 1))
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.optimization-promotion-eligibility-composer-contract.v1"
    and .bead_id == "bd-4j2ck"
    and .parent_bead_id == "bd-xg3d6"
    and ((["bd-sisok"] - .depends_on) | length) == 0
    and .script == "scripts/optimization_promotion_eligibility_composer.sh"
    and .smoke_script == "scripts/e2e/optimization_promotion_eligibility_composer_smoke.sh"
    and .docs == "docs/OPTIMIZATION_PROMOTION_ELIGIBILITY_COMPOSER.md"
    and .fixture_bundle == "scripts/testdata/optimization_promotion_eligibility_composer/cases.json"
    and (([
      "optimization_promotion_control_contract",
      "real_hot_path_evidence",
      "proof_specialization_receipt",
      "semantic_parity",
      "rollback_health",
      "safe_mode_fallback",
      "performance_regression",
      "source_revision"
    ] - .required_inputs) | length) == 0
    and ((["observe","promote","pin","fail_closed"] - .recommended_states) | length) == 0
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_runtime_policy == false
    and (.selftest_cases | length) == 7
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.optimization-promotion-eligibility-composer-fixtures.v1"
    and .base_input.schema_version == "franken-engine.optimization-promotion-eligibility.input.v1"
    and .base_input.contract_report.decision == "pass"
    and .base_input.evidence.real_hot_path_evidence.real_runtime_execution == true
    and .base_input.evidence.semantic_parity.outcome == "match"
    and .base_input.evidence.rollback_health.ready == true
    and .base_input.evidence.safe_mode_fallback.ready == true
    and .base_input.evidence.performance_regression.tail_budget_ok == true
    and (.cases | length) == 7
    and ([.cases[].case_id] | unique | length) == 7
    and all(.cases[]; (.expected.expected_exit_code | type) == "number" and (.expected.decision | type) == "string")
  ' "$fixtures_path" >/dev/null
}

docs_shape_ok() {
  while IFS= read -r required; do
    grep -Fq "$required" "$docs_path" || return 1
  done < <(jq -r '.required_doc_text[]' "$contract_path")
}

materialize_case() {
  local case_id="$1"
  local out_path="$2"
  jq --arg case_id "$case_id" '
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | ($root.base_input * ($case.overrides // {}))
    | .case_id = $case.case_id
  ' "$fixtures_path" >"$out_path"
}

validate_outputs() {
  local case_id="$1"
  local run_dir="$2"
  local expected_json="$3"
  local plan_json="${run_dir}/optimization_promotion_plan.json"
  local required_error required_state

  for artifact in "$plan_json" "${run_dir}/events.jsonl" "${run_dir}/commands.txt" "${run_dir}/report.md"; do
    [[ -s "$artifact" ]] || record_failure "${case_id} missing $(basename "$artifact")"
  done

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.optimization-promotion-plan.v1"
    and .bead_id == "bd-4j2ck"
    and .parent_bead_id == "bd-xg3d6"
    and .decision == $expected[0].decision
    and ((.plan_hash // "") | length) == 64
    and ((.candidate.candidate_id // "") | length) > 0
    and ((.side_conditions // null) | type) == "object"
    and ((.reason_codes // null) | type) == "array"
    and ((.next_validation_commands // null) | type) == "array"
    and all(.next_validation_commands[]?; (.command | startswith("rch exec -- env ")))
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_runtime_policy == false
  ' "$plan_json" >/dev/null || record_failure "${case_id} plan mismatch"

  required_state="$(jq -r '.required_recommended_state // ""' "$expected_json")"
  if [[ -n "$required_state" ]]; then
    jq -e --arg required_state "$required_state" '.recommended_state == $required_state' "$plan_json" >/dev/null \
      || record_failure "${case_id} missing recommended state ${required_state}"
  fi

  required_error="$(jq -r '.required_error_code // ""' "$expected_json")"
  if [[ -n "$required_error" ]]; then
    jq -e --arg required_error "$required_error" '
      .fail_closed_reasons | map(.code) | index($required_error) != null
    ' "$plan_json" >/dev/null || record_failure "${case_id} missing error code ${required_error}"
  fi

  jq -e 'select(.schema_version == "franken-engine.optimization-promotion-eligibility.event.v1")' "${run_dir}/events.jsonl" >/dev/null \
    || record_failure "${case_id} event log missing schema"
  grep -Fq './scripts/optimization_promotion_eligibility_composer.sh' "${run_dir}/commands.txt" \
    || record_failure "${case_id} command transcript missing producer"
}

case "$mode" in
  check|selftest) ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage
    exit 64
    ;;
esac

if contract_shape_ok; then
  record_pass "contract shape"
else
  record_failure "contract shape"
fi
if fixtures_shape_ok; then
  record_pass "fixtures shape"
else
  record_failure "fixtures shape"
fi
if docs_shape_ok; then
  record_pass "docs required text"
else
  record_failure "docs required text"
fi

if [[ "$mode" == "selftest" ]]; then
  work_dir="$(mktemp -d "${TMPDIR:-/tmp}/optimization-promotion-eligibility-smoke.XXXXXX")"
  while IFS= read -r case_id; do
    case_dir="${work_dir}/${case_id}"
    mkdir -p "$case_dir"
    input_json="${case_dir}/input.json"
    expected_json="${case_dir}/expected.json"
    materialize_case "$case_id" "$input_json"
    jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected' "$fixtures_path" >"$expected_json"
    expected_exit="$(jq -r '.expected_exit_code' "$expected_json")"
    set +e
    "$producer" --input-json "$input_json" --source-revision "smoke-${case_id}" --output-dir "${case_dir}/out" >/dev/null 2>"${case_dir}/stderr.txt"
    actual_exit="$?"
    set -e
    if [[ "$actual_exit" != "$expected_exit" ]]; then
      record_failure "${case_id} expected exit ${expected_exit} got ${actual_exit}"
    fi
    validate_outputs "$case_id" "${case_dir}/out" "$expected_json"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")
fi

if [[ "$failures" -ne 0 ]]; then
  printf 'optimization promotion eligibility smoke failed with %s failure(s)\n' "$failures" >&2
  exit 1
fi

printf 'optimization promotion eligibility smoke %s passed\n' "$mode"
