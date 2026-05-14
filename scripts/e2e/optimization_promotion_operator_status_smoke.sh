#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
producer="${root_dir}/scripts/optimization_promotion_operator_status.sh"
fixtures_path="${OPTIMIZATION_PROMOTION_OPERATOR_STATUS_FIXTURES:-${root_dir}/scripts/testdata/optimization_promotion_operator_status/cases.json}"
contract_path="${root_dir}/docs/optimization_promotion_operator_status_contract_v1.json"
docs_path="${root_dir}/docs/OPTIMIZATION_PROMOTION_OPERATOR_STATUS.md"
mode="${1:-check}"
failures=0

usage() {
  cat >&2 <<'USAGE'
Usage: ./scripts/e2e/optimization_promotion_operator_status_smoke.sh [check|selftest]
USAGE
}

record_pass() {
  printf 'PASS optimization-promotion-operator-status %s\n' "$1"
}

record_failure() {
  printf 'FAIL optimization-promotion-operator-status %s\n' "$1" >&2
  failures=$((failures + 1))
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.optimization-promotion-operator-status-contract.v1"
    and .bead_id == "bd-yo0eh"
    and .parent_bead_id == "bd-xg3d6"
    and ((["bd-4j2ck","bd-or2e1","bd-jp4r0"] - .depends_on) | length) == 0
    and .script == "scripts/optimization_promotion_operator_status.sh"
    and .smoke_script == "scripts/e2e/optimization_promotion_operator_status_smoke.sh"
    and .docs == "docs/OPTIMIZATION_PROMOTION_OPERATOR_STATUS.md"
    and .fixture_bundle == "scripts/testdata/optimization_promotion_operator_status/cases.json"
    and (([
      "optimization_promotion_plan",
      "optimization_demotion_receipt",
      "optimization_transfer_guard",
      "source_revision"
    ] - .required_inputs) | length) == 0
    and ((["observe","promote","pin","demote","quarantine","fail_closed"] - .operator_states) | length) == 0
    and (([
      "FE-OPT-STATUS-LIVE-MUTATION-CLAIM",
      "FE-OPT-STATUS-AUTOMATIC-BENCHMARK-PUBLICATION",
      "FE-OPT-STATUS-BARE-CARGO-VALIDATION",
      "FE-OPT-STATUS-DENOMINATOR-WIN-OVERCLAIM"
    ] - .truth_gate_violation_codes) | length) == 0
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.mutates_runtime_policy == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.publishes_benchmark_claims == false
    and (.selftest_cases | length) == 7
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.optimization-promotion-operator-status-fixtures.v1"
    and .base_input.schema_version == "franken-engine.optimization-promotion-operator-status.input.v1"
    and .base_input.source_revision == .base_input.expected_source_revision
    and .base_input.optimization_promotion_plan.decision == "pass"
    and .base_input.optimization_demotion_receipt.decision == "pass"
    and .base_input.optimization_transfer_guard.decision == "pass"
    and (.cases | length) == 7
    and ([.cases[].case_id] | unique | length) == 7
    and all(.cases[]; (.expected.expected_exit_code | type) == "number" and (.expected.expected_operator_state | type) == "string")
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
  local status_json="${run_dir}/optimization_promotion_operator_status.json"
  local truth_report_json="${run_dir}/optimization_promotion_truth_gate_report.json"
  local required_violation

  for artifact in "$status_json" "$truth_report_json" "${run_dir}/operator_status.md" "${run_dir}/events.jsonl" "${run_dir}/commands.txt" "${run_dir}/report.md"; do
    [[ -s "$artifact" ]] || record_failure "${case_id} missing $(basename "$artifact")"
  done

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.optimization-promotion-operator-status.v1"
    and .bead_id == "bd-yo0eh"
    and .parent_bead_id == "bd-xg3d6"
    and .operator_state == $expected[0].expected_operator_state
    and .truth_gate.decision == $expected[0].expected_truth_gate_decision
    and ((.status_hash // "") | length) == 64
    and ((.saved_receipts // null) | type) == "object"
    and ((.next_validation_commands // null) | type) == "array"
    and all(.next_validation_commands[]?; (.command | startswith("rch exec -- env ")))
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_runtime_policy == false
    and .mutation_policy.publishes_benchmark_claims == false
  ' "$status_json" >/dev/null || record_failure "${case_id} status mismatch"

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.optimization-promotion-operator-truth-gate.v1"
    and .bead_id == "bd-yo0eh"
    and .decision == $expected[0].expected_truth_gate_decision
    and .operator_state == $expected[0].expected_operator_state
    and .mutation_policy.advisory_only == true
  ' "$truth_report_json" >/dev/null || record_failure "${case_id} truth report mismatch"

  required_violation="$(jq -r '.required_violation_code // ""' "$expected_json")"
  if [[ -n "$required_violation" ]]; then
    jq -e --arg required_violation "$required_violation" '
      .truth_gate.violations | map(.code) | index($required_violation) != null
    ' "$status_json" >/dev/null || record_failure "${case_id} missing violation code ${required_violation}"
  fi

  grep -Fq 'advisory only' "${run_dir}/operator_status.md" \
    || record_failure "${case_id} operator status missing advisory wording"
  grep -Fq './scripts/optimization_promotion_operator_status.sh' "${run_dir}/commands.txt" \
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
  work_dir="$(mktemp -d "${TMPDIR:-/tmp}/optimization-promotion-operator-status-smoke.XXXXXX")"
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
  printf 'optimization promotion operator status smoke failed with %s failure(s)\n' "$failures" >&2
  exit 1
fi

printf 'optimization promotion operator status smoke %s passed\n' "$mode"
