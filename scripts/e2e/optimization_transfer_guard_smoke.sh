#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
producer="${root_dir}/scripts/optimization_transfer_guard.sh"
fixtures_path="${OPTIMIZATION_TRANSFER_GUARD_FIXTURES:-${root_dir}/scripts/testdata/optimization_transfer_guard/cases.json}"
contract_path="${root_dir}/docs/optimization_transfer_guard_contract_v1.json"
docs_path="${root_dir}/docs/OPTIMIZATION_TRANSFER_GUARD.md"
mode="${1:-check}"
failures=0

usage() {
  cat >&2 <<'USAGE'
Usage: ./scripts/e2e/optimization_transfer_guard_smoke.sh [check|selftest]
USAGE
}

record_pass() {
  printf 'PASS optimization-transfer-guard %s\n' "$1"
}

record_failure() {
  printf 'FAIL optimization-transfer-guard %s\n' "$1" >&2
  failures=$((failures + 1))
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.optimization-transfer-guard-contract.v1"
    and .bead_id == "bd-jp4r0"
    and .parent_bead_id == "bd-xg3d6"
    and ((["bd-4j2ck","bd-or2e1"] - .depends_on) | length) == 0
    and .script == "scripts/optimization_transfer_guard.sh"
    and .smoke_script == "scripts/e2e/optimization_transfer_guard_smoke.sh"
    and .docs == "docs/OPTIMIZATION_TRANSFER_GUARD.md"
    and .fixture_bundle == "scripts/testdata/optimization_transfer_guard/cases.json"
    and (([
      "cross_workload_transfer",
      "workload_manifold",
      "performance_regression",
      "real_hot_path_evidence",
      "source_revision"
    ] - .required_inputs) | length) == 0
    and ((["allow_same_regime","allow_transfer","refuse_transfer","fail_closed"] - .recommended_states) | length) == 0
    and (([
      "OPT_TRANSFER_SAME_REGIME_SUPPORTED",
      "OPT_TRANSFER_CROSS_REGIME_SUPPORTED",
      "OPT_TRANSFER_UNSUPPORTED_REGIME",
      "OPT_TRANSFER_COLD_START_ONLY_WIN",
      "OPT_TRANSFER_WARMED_CACHE_ONLY_WIN"
    ] - .reason_codes) | length) == 0
    and (([
      "FE-OPT-TRANSFER-MISSING-EVIDENCE",
      "FE-OPT-TRANSFER-SOURCE-REVISION-MISMATCH",
      "FE-OPT-TRANSFER-AMBIGUOUS-WORKLOAD-IDENTITY",
      "FE-OPT-TRANSFER-CONTRADICTORY-REGIME-LABELS",
      "FE-OPT-TRANSFER-SYNTHETIC-CONTAMINATION"
    ] - .fail_closed_error_codes) | length) == 0
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
    .schema_version == "franken-engine.optimization-transfer-guard-fixtures.v1"
    and .base_input.schema_version == "franken-engine.optimization-transfer-guard.input.v1"
    and .base_input.source_revision == .base_input.expected_source_revision
    and .base_input.evidence.real_hot_path_evidence.real_runtime_execution == true
    and .base_input.evidence.cross_workload_transfer.available == true
    and .base_input.evidence.workload_manifold.identity_ambiguous == false
    and .base_input.evidence.performance_regression.tail_budget_ok == true
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
  local guard_json="${run_dir}/optimization_transfer_guard.json"
  local required_error required_reason required_state

  for artifact in "$guard_json" "${run_dir}/events.jsonl" "${run_dir}/commands.txt" "${run_dir}/report.md"; do
    [[ -s "$artifact" ]] || record_failure "${case_id} missing $(basename "$artifact")"
  done

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.optimization-transfer-guard.v1"
    and .bead_id == "bd-jp4r0"
    and .parent_bead_id == "bd-xg3d6"
    and .decision == $expected[0].decision
    and .recommended_state == $expected[0].required_recommended_state
    and ((.guard_hash // "") | length) == 64
    and ((.candidate.candidate_id // "") | length) > 0
    and ((.supported_regimes // null) | type) == "array"
    and ((.excluded_regimes // null) | type) == "array"
    and ((.counterevidence // null) | type) == "array"
    and ((.required_additional_proof // null) | type) == "array"
    and ((.promotion_side_conditions // null) | type) == "object"
    and ((.preserved_evidence_hashes // null) | type) == "array"
    and all(.preserved_evidence_hashes[]; ((.sha256 // "") | length) == 64)
    and ((.next_validation_commands // null) | type) == "array"
    and all(.next_validation_commands[]?; (.command | startswith("rch exec -- env ")))
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_runtime_policy == false
  ' "$guard_json" >/dev/null || record_failure "${case_id} guard mismatch"

  required_state="$(jq -r '.required_recommended_state // ""' "$expected_json")"
  if [[ -n "$required_state" ]]; then
    jq -e --arg required_state "$required_state" '.recommended_state == $required_state' "$guard_json" >/dev/null \
      || record_failure "${case_id} missing recommended state ${required_state}"
  fi

  required_reason="$(jq -r '.required_reason_code // ""' "$expected_json")"
  if [[ -n "$required_reason" ]]; then
    jq -e --arg required_reason "$required_reason" '
      .reason_codes | index($required_reason) != null
    ' "$guard_json" >/dev/null || record_failure "${case_id} missing reason code ${required_reason}"
  fi

  required_error="$(jq -r '.required_error_code // ""' "$expected_json")"
  if [[ -n "$required_error" ]]; then
    jq -e --arg required_error "$required_error" '
      .fail_closed_reasons | map(.code) | index($required_error) != null
    ' "$guard_json" >/dev/null || record_failure "${case_id} missing error code ${required_error}"
  fi

  if [[ "$(jq -r '.expected_additional_proof // false' "$expected_json")" == "true" ]]; then
    jq -e '(.required_additional_proof | length) > 0' "$guard_json" >/dev/null \
      || record_failure "${case_id} missing additional proof"
  fi

  jq -e 'select(.schema_version == "franken-engine.optimization-transfer-guard.event.v1")' "${run_dir}/events.jsonl" >/dev/null \
    || record_failure "${case_id} event log missing schema"
  grep -Fq './scripts/optimization_transfer_guard.sh' "${run_dir}/commands.txt" \
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
  work_dir="$(mktemp -d "${TMPDIR:-/tmp}/optimization-transfer-guard-smoke.XXXXXX")"
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
  printf 'optimization transfer guard smoke failed with %s failure(s)\n' "$failures" >&2
  exit 1
fi

printf 'optimization transfer guard smoke %s passed\n' "$mode"
