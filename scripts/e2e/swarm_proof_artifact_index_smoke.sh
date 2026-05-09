#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${root_dir}/scripts/swarm_proof_artifact_index.sh"
contract_path="${root_dir}/docs/swarm_proof_artifact_index_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_PROOF_ARTIFACT_INDEX.md"
cases_path="${root_dir}/scripts/testdata/swarm_proof_artifact_index/cases.json"
mode="${1:-check}"
output_root="${2:-${SWARM_PROOF_ARTIFACT_INDEX_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-proof-artifact-index-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS swarm-proof-artifact-index %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-proof-artifact-index %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_proof_artifact_index_smoke.sh [check|selftest] [output_root]
EOF
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-artifact-index-contract.v1"
    and .bead_id == "bd-ua5n2.4"
    and (.depends_on | index("bd-ua5n2.3") != null)
    and (.required_outputs | index("proof_artifact_index.json") != null)
    and (.required_outputs | index("reuse_refusal_receipts.jsonl") != null)
    and (.invalidation_reasons | index("expired_ttl") != null)
    and (.invalidation_reasons | index("changed_dependency_root") != null)
    and (.invalidation_reasons | index("incomplete_rch_artifact_retrieval") != null)
    and (.invalidation_reasons | index("failed_proof_reuse_refusal") != null)
    and (.invalidation_reasons | index("local_fallback_contamination") != null)
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'never runs Cargo or RCH' "$docs_path" \
    && grep -Fq 'TTL has not expired' "$docs_path" \
    && grep -Fq 'negative reuse refusal receipts' "$docs_path" \
    && grep -Fq 'local fallback contamination' "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-artifact-index-fixtures.v1"
    and (.cases | length) == 6
    and all(.cases[]; has("case_id") and has("proof") and has("expected"))
    and ([.cases[].expected.invalidation_reasons[]?] | unique | sort) == [
      "changed_dependency_root",
      "expired_ttl",
      "failed_proof_reuse_refusal",
      "incomplete_rch_artifact_retrieval",
      "local_fallback_contamination",
      "missing_artifact_members"
    ]
  ' "$cases_path" >/dev/null
}

script_static_ok() {
  bash -n "$script_path"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$script_path" "${BASH_SOURCE[0]}"
  fi
}

expand_case() {
  local case_json="$1"
  jq -n \
    --slurpfile fixtures "$cases_path" \
    --argjson case "$case_json" '
      {
        case_id: $case.case_id,
        proofs: [($fixtures[0].base_proof + $case.proof)],
        expected: $case.expected
      }
    '
}

assert_case_output() {
  local case_json="$1"
  local output_dir="$2"
  local index_path="${output_dir}/proof_artifact_index.json"
  local case_id

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  jq empty "$index_path" >/dev/null
  test -s "${output_dir}/proof_artifact_index.jsonl"
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"

  jq -e \
    --argjson expected "$(jq '.expected' <<<"$case_json")" \
    --arg case_id "$case_id" '
      .schema_version == "franken-engine.swarm-proof-artifact-index.v1"
      and .case_id == $case_id
      and .reusable_count == $expected.reusable_count
      and .refused_count == $expected.refused_count
      and .rows[0].invalidation_reasons == $expected.invalidation_reasons
      and (.index_hash | test("^[0-9a-f]{64}$"))
      and (.rows[0].remediation | length) >= 40
      and .non_mutation_attestation.runs_cargo == false
      and .non_mutation_attestation.runs_rch == false
    ' "$index_path" >/dev/null || record_failure "${case_id} index mismatch"

  if [[ "$(jq -r '.expected.reusable_count' <<<"$case_json")" == "1" ]]; then
    test -s "${output_dir}/reuse_receipts.jsonl" || record_failure "${case_id} missing positive reuse receipt"
    [[ ! -s "${output_dir}/reuse_refusal_receipts.jsonl" ]] || record_failure "${case_id} unexpected refusal receipt"
  else
    test -s "${output_dir}/reuse_refusal_receipts.jsonl" || record_failure "${case_id} missing refusal receipt"
  fi
}

run_case() {
  local raw_case_json="$1"
  local tmp_root="$2"
  local case_json case_id case_dir fixture_path

  case_json="$(expand_case "$raw_case_json")"
  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${tmp_root}/${case_id}"
  fixture_path="${case_dir}/fixture.json"
  mkdir -p "$case_dir"
  jq '.' <<<"$case_json" >"$fixture_path"

  "$script_path" --fixture-json "$fixture_path" --output-dir "${case_dir}/out" >/dev/null
  assert_case_output "$case_json" "${case_dir}/out"
  record_pass "$case_id"
}

run_check() {
  jq empty "$contract_path" "$cases_path" >/dev/null
  script_static_ok
  contract_shape_ok || record_failure "contract shape"
  docs_shape_ok || record_failure "docs shape"
  fixtures_shape_ok || record_failure "fixture shape"

  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  local tmp_root="$1"

  run_check
  if [[ "$failures" -ne 0 ]]; then
    return
  fi

  while IFS= read -r case_json; do
    run_case "$case_json" "$tmp_root"
  done < <(jq -c '.cases[]' "$cases_path")
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest "$output_root"
    ;;
  -h|--help|help)
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
