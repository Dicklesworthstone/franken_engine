#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
producer="${root_dir}/scripts/optimization_promotion_control_contract.sh"
fixtures_path="${OPTIMIZATION_PROMOTION_CONTROL_FIXTURES:-${root_dir}/scripts/testdata/optimization_promotion_control_contract/cases.json}"
contract_path="${root_dir}/docs/optimization_promotion_control_contract_v1.json"
docs_path="${root_dir}/docs/OPTIMIZATION_PROMOTION_CONTROL_CONTRACT.md"
mode="${1:-check}"
failures=0

usage() {
  cat >&2 <<'USAGE'
Usage: ./scripts/e2e/optimization_promotion_control_contract_smoke.sh [check|selftest]
USAGE
}

record_pass() {
  printf 'PASS optimization-promotion-control %s\n' "$1"
}

record_failure() {
  printf 'FAIL optimization-promotion-control %s\n' "$1" >&2
  failures=$((failures + 1))
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.optimization-promotion-control-contract.v1"
    and .bead_id == "bd-sisok"
    and .parent_bead_id == "bd-xg3d6"
    and .script == "scripts/optimization_promotion_control_contract.sh"
    and .smoke_script == "scripts/e2e/optimization_promotion_control_contract_smoke.sh"
    and .docs == "docs/OPTIMIZATION_PROMOTION_CONTROL_CONTRACT.md"
    and .fixture_bundle == "scripts/testdata/optimization_promotion_control_contract/cases.json"
    and (([
      "proof_specialization_receipt",
      "specialization_lane_gate",
      "specialization_rollback_gate",
      "performance_regression_gate",
      "safe_mode_fallback",
      "cross_workload_transfer",
      "real_hot_path_evidence"
    ] - .required_surfaces) | length) == 0
    and (([
      "real_hot_path_evidence",
      "proof_specialization_receipt",
      "semantic_parity",
      "rollback_health",
      "safe_mode_fallback",
      "cross_workload_transfer",
      "performance_regression"
    ] - .required_evidence_families) | length) == 0
    and ((["observe","promote","pin","demote","quarantine","fail_closed"] - .promotion_states) | length) == 0
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
    and (.selftest_cases | length) == 6
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.optimization-promotion-control-fixtures.v1"
    and .base_input.schema_version == "franken-engine.optimization-promotion-control.input.v1"
    and (.base_input.surfaces | length) == 7
    and (.base_input.evidence_families | length) == 7
    and (.base_input.promotion_states | length) == 6
    and .base_input.mutation_policy.advisory_only == true
    and .base_input.mutation_policy.runs_cargo == false
    and .base_input.mutation_policy.runs_rch == false
    and (.cases | length) == 6
    and ([.cases[].case_id] | unique | length) == 6
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
  local report_json="${run_dir}/optimization_promotion_control_contract.json"
  local inventory_json="${run_dir}/optimization_promotion_surface_inventory.json"
  local required_error

  for artifact in "$report_json" "$inventory_json" "${run_dir}/events.jsonl" "${run_dir}/commands.txt" "${run_dir}/report.md"; do
    [[ -s "$artifact" ]] || record_failure "${case_id} missing $(basename "$artifact")"
  done

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.optimization-promotion-control.report.v1"
    and .bead_id == "bd-sisok"
    and .parent_bead_id == "bd-xg3d6"
    and .decision == $expected[0].decision
    and (.promotion_states | length) == 6
    and (.required_evidence_families | length) == 7
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .artifact_paths.report_json
    and .artifact_paths.inventory_json
  ' "$report_json" >/dev/null || record_failure "${case_id} report mismatch"

  jq -e '
    .schema_version == "franken-engine.optimization-promotion-control.inventory.v1"
    and .bead_id == "bd-sisok"
    and (.surfaces | length) >= 6
    and (.evidence_families | type) == "array"
    and (.promotion_states | type) == "array"
  ' "$inventory_json" >/dev/null || record_failure "${case_id} inventory mismatch"

  required_error="$(jq -r '.required_error_code // ""' "$expected_json")"
  if [[ -n "$required_error" ]]; then
    jq -e --arg required_error "$required_error" '
      .fail_closed_reasons | map(.code) | index($required_error) != null
    ' "$report_json" >/dev/null || record_failure "${case_id} missing error code ${required_error}"
  fi

  jq -e 'select(.schema_version == "franken-engine.optimization-promotion-control.event.v1")' "${run_dir}/events.jsonl" >/dev/null \
    || record_failure "${case_id} event log missing schema"
  grep -Fq './scripts/optimization_promotion_control_contract.sh' "${run_dir}/commands.txt" \
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
  work_dir="$(mktemp -d "${TMPDIR:-/tmp}/optimization-promotion-control-smoke.XXXXXX")"
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
  printf 'optimization promotion-control smoke failed with %s failure(s)\n' "$failures" >&2
  exit 1
fi

printf 'optimization promotion-control smoke %s passed\n' "$mode"
