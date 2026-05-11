#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${root_dir}/scripts/swarm_proof_template_miner.sh"
contract_path="${root_dir}/docs/swarm_proof_template_miner_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_PROOF_TEMPLATE_MINER.md"
cases_path="${root_dir}/scripts/testdata/swarm_proof_template_miner/cases.json"
golden_dir="${SWARM_PROOF_TEMPLATE_MINER_GOLDEN_DIR:-${root_dir}/scripts/testdata/goldens}"
mode="${1:-check}"
output_root="${2:-${SWARM_PROOF_TEMPLATE_MINER_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-proof-template-miner-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS swarm-proof-template-miner %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-proof-template-miner %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_proof_template_miner_smoke.sh [check|selftest] [output_root]
EOF
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-template-miner-contract.v1"
    and .bead_id == "bd-ua5n2.10"
    and (.required_outputs | index("template_mining_report.json") != null)
    and (.required_outputs | index("promotion_candidates.jsonl") != null)
    and (.required_outputs | index("non_promotion_receipts.jsonl") != null)
    and (.decision_kinds | sort) == ["non_promotion", "promotion_candidate"]
    and (.non_promotion_reasons | sort) == [
      "contradictory_failure_history",
      "insufficient_evidence",
      "local_fallback_contamination",
      "stable_non_promotion",
      "stale_artifact_refusal"
    ]
    and .promotion_policy.min_success_count == 3
    and .promotion_policy.min_current_success_count == 2
    and .promotion_policy.min_refusal_count == 1
    and .promotion_policy.edits_agents_md == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.edits_scripts == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'deterministic' "$docs_path" \
    && grep -Fq 'source proof links' "$docs_path" \
    && grep -Fq 'never runs Cargo or RCH' "$docs_path" \
    && grep -Fq "never edits \`AGENTS.md\`" "$docs_path" \
    && grep -Fq 'stable non-promotion' "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-template-miner-fixtures.v1"
    and (.cases | length) == 6
    and ([.cases[].case_id] | sort) == [
      "contradictory_failure_history",
      "insufficient_evidence",
      "local_fallback_contamination",
      "promotable_repeated_proof_template",
      "stable_non_promotion",
      "stale_artifact_refusal"
    ]
    and ([.cases[].expected.reason_code] | unique | sort) == [
      "contradictory_failure_history",
      "insufficient_evidence",
      "local_fallback_contamination",
      "promote",
      "stable_non_promotion",
      "stale_artifact_refusal"
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
      ($fixtures[0].base_input * ($case | del(.expected)))
      + {expected: $case.expected}
    '
}

canonicalize_report() {
  local report_path="$1"
  local tmp_root="$2"
  jq --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "string" then
        gsub($tmp_root; "[SMOKE_ROOT]")
      elif type == "array" then
        map(scrub)
      elif type == "object" then
        with_entries(.value |= scrub)
      else
        .
      end;
    scrub
  ' "$report_path"
}

assert_case_golden() {
  local case_id="$1"
  local report_path="$2"
  local tmp_root="$3"
  local golden_path="${golden_dir}/swarm_proof_template_miner_${case_id}.golden"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    mkdir -p "$golden_dir"
    canonicalize_report "$report_path" "$tmp_root" >"$golden_path"
    return
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "${case_id} missing golden"
    return
  fi

  if ! diff -u "$golden_path" <(canonicalize_report "$report_path" "$tmp_root"); then
    record_failure "${case_id} golden drift"
  fi
}

assert_case_output() {
  local case_json="$1"
  local output_dir="$2"
  local report_path="${output_dir}/template_mining_report.json"
  local expected_json
  local case_id

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  expected_json="$(jq '.expected' <<<"$case_json")"
  jq empty "$report_path" >/dev/null
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"

  jq -e \
    --argjson expected "$expected_json" \
    --arg case_id "$case_id" '
      .schema_version == "franken-engine.swarm-proof-template-mining-report.v1"
      and .case_id == $case_id
      and .candidate_count == 1
      and .promotion_candidate_count == $expected.promotion_candidate_count
      and .non_promotion_count == $expected.non_promotion_count
      and (.report_hash | test("^[0-9a-f]{64}$"))
      and .candidates[0].candidate_id == $expected.candidate_id
      and .candidates[0].decision == $expected.decision
      and .candidates[0].reason_code == $expected.reason_code
      and .candidates[0].success_count == $expected.success_count
      and .candidates[0].refusal_count == $expected.refusal_count
      and (.candidates[0].source_proof_links | length) == ($expected.success_count + $expected.refusal_count)
      and (.candidates[0].remediation | length) >= 40
      and .candidates[0].automatic_edit_policy.edits_agents_md == false
      and .candidates[0].automatic_edit_policy.edits_scripts == false
      and .non_mutation_attestation.runs_cargo == false
      and .non_mutation_attestation.runs_rch == false
      and .non_mutation_attestation.edits_agents_md == false
    ' "$report_path" >/dev/null || record_failure "${case_id} mining report mismatch"

  if [[ "$(jq -r '.decision' <<<"$expected_json")" == "promotion_candidate" ]]; then
    test -s "${output_dir}/promotion_candidates.jsonl" || record_failure "${case_id} missing promotion candidate row"
    [[ ! -s "${output_dir}/non_promotion_receipts.jsonl" ]] || record_failure "${case_id} unexpected non-promotion row"
  else
    test -s "${output_dir}/non_promotion_receipts.jsonl" || record_failure "${case_id} missing non-promotion receipt row"
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
  jq 'del(.expected)' <<<"$case_json" >"$fixture_path"

  "$script_path" --fixture-json "$fixture_path" --output-dir "${case_dir}/out" >/dev/null
  assert_case_output "$case_json" "${case_dir}/out"
  assert_case_golden "$case_id" "${case_dir}/out/template_mining_report.json" "$tmp_root"
  record_pass "$case_id"
}

goldens_shape_ok() {
  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    return 0
  fi
  while IFS= read -r case_id; do
    local golden_path="${golden_dir}/swarm_proof_template_miner_${case_id}.golden"
    [[ -f "$golden_path" ]] || { record_failure "${case_id} missing checked-in golden"; continue; }
    jq empty "$golden_path" >/dev/null || record_failure "${case_id} invalid golden json"
  done < <(jq -r '.cases[].case_id' "$cases_path")
}

run_check() {
  jq empty "$contract_path" "$cases_path" >/dev/null
  script_static_ok
  contract_shape_ok || record_failure "contract shape"
  docs_shape_ok || record_failure "docs shape"
  fixtures_shape_ok || record_failure "fixture shape"
  goldens_shape_ok
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
