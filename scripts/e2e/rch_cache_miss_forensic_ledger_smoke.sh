#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ledger_script="${root_dir}/scripts/rch_cache_miss_forensic_ledger.sh"
docs_path="${root_dir}/docs/RCH_CACHE_MISS_FORENSIC_LEDGER.md"
contract_path="${root_dir}/docs/rch_cache_miss_forensic_ledger_contract_v1.json"
fixtures_path="${RCH_CACHE_MISS_FORENSIC_FIXTURES:-${root_dir}/scripts/testdata/rch_cache_miss_forensic_ledger/cases.json}"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS rch-cache-miss-forensic-ledger %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-cache-miss-forensic-ledger %s\n' "$1" >&2
  failures=$((failures + 1))
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.rch-cache-miss-forensic-ledger-contract.v1"
    and .bead_id == "bd-n4dfb"
    and (.required_fixture_cases | sort) == ["cache_hit","cache_miss_sync_root","local_fallback_fail_closed","missing_worker_fail_closed","truncated_log_fail_closed"]
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq "requires a preserved transcript" "$docs_path" \
    && grep -Fq "Local fallback markers fail closed" "$docs_path" \
    && grep -Fq "proof_freshness_diff.json" "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.rch-cache-miss-forensic-ledger-fixtures.v1"
    and ([.cases[].case_id] | sort) == ([
      "cache_hit",
      "cache_miss_sync_root",
      "local_fallback_fail_closed",
      "missing_worker_fail_closed",
      "truncated_log_fail_closed"
    ] | sort)
    and any(.cases[]; .case_id == "cache_hit" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "cache_miss_sync_root" and .expected.required_reason_code == "FE-IW3-RCH-PROOF-FRESHNESS-DRIFT")
    and any(.cases[]; .case_id == "local_fallback_fail_closed" and .expected.required_reason_code == "FE-IW3-RCH-LOCAL-FALLBACK")
    and any(.cases[]; .case_id == "missing_worker_fail_closed" and .expected.required_reason_code == "FE-IW3-RCH-MISSING-WORKER")
    and any(.cases[]; .case_id == "truncated_log_fail_closed" and .expected.required_reason_code == "FE-IW3-RCH-TRUNCATED-LOG")
  ' "$fixtures_path" >/dev/null
}

run_case() {
  local case_id="$1"
  local case_json tmpdir output_dir status expected_exit expected_decision expected_class expected_reason expected_diff_count
  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing case ${case_id}"
    return
  fi

  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  mkdir -p "$output_dir"
  jq -r '.summary_log' <<<"$case_json" >"${tmpdir}/summary.log"
  jq '.metadata_json' <<<"$case_json" >"${tmpdir}/metadata.json"

  expected_decision="$(jq -r '.expected.decision' <<<"$case_json")"
  expected_class="$(jq -r '.expected.miss_classification' <<<"$case_json")"
  expected_reason="$(jq -r '.expected.required_reason_code // ""' <<<"$case_json")"
  expected_diff_count="$(jq -r '.expected.diff_count' <<<"$case_json")"
  if [[ "$expected_decision" == "fail_closed" ]]; then
    expected_exit=42
  else
    expected_exit=0
  fi

  set +e
  "$ledger_script" \
    --summary-log "${tmpdir}/summary.log" \
    --metadata-json "${tmpdir}/metadata.json" \
    --case-id "$case_id" \
    --source-revision "smoke-${case_id}" \
    --output-dir "$output_dir" \
    >/dev/null 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    printf 'expected exit %s for %s, got %s\n' "$expected_exit" "$case_id" "$status" >&2
    cat "${tmpdir}/stderr.log" >&2
    record_failure "unexpected exit ${case_id}"
    return
  fi

  local ledger="${output_dir}/rch_cache_miss_forensic_ledger.json"
  [[ -f "$ledger" ]] || { record_failure "missing ledger ${case_id}"; return; }
  [[ -f "${output_dir}/proof_freshness_diff.json" ]] || { record_failure "missing freshness diff ${case_id}"; return; }
  [[ -f "${output_dir}/events.jsonl" ]] || { record_failure "missing events ${case_id}"; return; }
  [[ -f "${output_dir}/commands.txt" ]] || { record_failure "missing commands ${case_id}"; return; }
  [[ -f "${output_dir}/report.md" ]] || { record_failure "missing report ${case_id}"; return; }

  jq -e \
    --arg decision "$expected_decision" \
    --arg class "$expected_class" \
    --argjson diff_count "$expected_diff_count" '
      .schema_version == "franken-engine.rch-cache-miss-forensic-ledger.v1"
      and .decision == $decision
      and .miss_classification == $class
      and .proof_freshness_diff.diff_count == $diff_count
      and .mutation_policy.runs_cargo == false
      and .mutation_policy.runs_rch == false
      and .mutation_policy.mutates_br == false
      and .mutation_policy.sends_agent_mail == false
      and (.evidence_hashes.summary_excerpt_sha256 | test("^[0-9a-f]{64}$"))
    ' "$ledger" >/dev/null || record_failure "ledger mismatch ${case_id}"

  if [[ -n "$expected_reason" ]]; then
    jq -e --arg code "$expected_reason" 'any((.degraded_reasons + .fail_closed_reasons)[]?; .code == $code)' "$ledger" >/dev/null \
      || record_failure "missing reason ${expected_reason} ${case_id}"
  fi
  record_pass "$case_id"
}

run_check() {
  jq empty "$contract_path" "$fixtures_path"
  bash -n "$ledger_script" "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$ledger_script" "${BASH_SOURCE[0]}"
  fi
  contract_shape_ok || record_failure "contract shape"
  docs_shape_ok || record_failure "docs shape"
  fixtures_shape_ok || record_failure "fixture shape"
  if [[ "$failures" -ne 0 ]]; then
    exit 1
  fi
  record_pass "check"
}

run_selftest() {
  run_check
  while IFS= read -r case_id; do
    run_case "$case_id"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")
  if [[ "$failures" -ne 0 ]]; then
    exit 1
  fi
  record_pass "selftest"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help|help)
    printf 'Usage: ./scripts/e2e/rch_cache_miss_forensic_ledger_smoke.sh [check|selftest]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
