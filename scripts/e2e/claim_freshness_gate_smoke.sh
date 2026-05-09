#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate_script="${root_dir}/scripts/claim_freshness_gate.sh"
fixture_root="${CLAIM_FRESHNESS_FIXTURES:-${root_dir}/scripts/testdata/claim_freshness_gate}"
matrix_json="${fixture_root}/claim_to_proof_matrix_v1.json"
readme_file="${fixture_root}/docs/README.md"
runtime_charter_file="${fixture_root}/docs/runtime_charter.md"
failures=0

record_pass() {
  printf 'PASS claim-freshness-gate %s\n' "$1"
}

record_failure() {
  printf 'FAIL claim-freshness-gate %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/claim_freshness_gate_smoke.sh [check|selftest|run] [output_dir]
EOF
}

run_check() {
  bash -n "$gate_script"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$gate_script" "${BASH_SOURCE[0]}"
  fi
  jq empty "$matrix_json" "${fixture_root}/artifacts/fresh_observed/run_manifest.json" "${fixture_root}/artifacts/stale_observed/run_manifest.json" "${fixture_root}/artifacts/degraded_observed/run_manifest.json" >/dev/null
  jq -e '
    .schema_version == "franken-engine.claim-to-proof-matrix.v1"
    and ([.claims[].claim_id] | index("CLAIM-FRESH-OBSERVED") != null)
    and ([.claims[].claim_id] | index("CLAIM-STALE-OBSERVED") != null)
    and ([.claims[].claim_id] | index("CLAIM-MISSING-ARTIFACT") != null)
    and ([.claims[].claim_id] | index("CLAIM-DEGRADED-ARTIFACT") != null)
    and ([.claims[].claim_id] | index("CLAIM-TARGET-ALLOWED") != null)
    and ([.claims[].claim_id] | index("CLAIM-HYPOTHESIS-ALLOWED") != null)
  ' "$matrix_json" >/dev/null || record_failure "fixture matrix shape"

  grep -Fq 'claim_freshness_report.json' "$gate_script"
  grep -Fq 'rewrites_docs: false' "$gate_script"
  grep -Fq 'downgrade_suggestions.md' "$gate_script"
  record_pass "shell syntax and fixture shape"
}

run_selftest_case() {
  local output_dir="$1"
  local actual_exit

  set +e
  "$gate_script" \
    --claim-matrix-json "$matrix_json" \
    --readme-file "$readme_file" \
    --runtime-charter-file "$runtime_charter_file" \
    --source-revision fixture-revision \
    --now-ts 2026-05-09T13:30:00Z \
    --max-age-days 30 \
    --output-dir "$output_dir" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne 42 ]]; then
    record_failure "selftest exit ${actual_exit}, expected 42"
    return
  fi

  jq empty "${output_dir}/claim_freshness_report.json" >/dev/null
  test -s "${output_dir}/downgrade_suggestions.md"
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"

  jq -e '
    .schema_version == "franken-engine.claim-freshness-report.v1"
    and .decision == "downgrade_required"
    and .claim_count == 6
    and .alarm_counts.total == 3
    and .non_mutation_attestation.rewrites_docs == false
    and .non_mutation_attestation.runs_cargo == false
    and .non_mutation_attestation.runs_rch == false
    and .non_mutation_attestation.creates_beads == false
    and any(.claims[]; .claim_id == "CLAIM-FRESH-OBSERVED" and .decision == "allow" and .artifact_age_days == 0 and .runtime_charter_alignment == "pass")
    and any(.claims[]; .claim_id == "CLAIM-STALE-OBSERVED" and .decision == "downgrade_required" and .artifact_age_days == 69)
    and any(.claims[]; .claim_id == "CLAIM-MISSING-ARTIFACT" and .decision == "downgrade_required" and (.reason | contains("missing its backing artifact")))
    and any(.claims[]; .claim_id == "CLAIM-DEGRADED-ARTIFACT" and .decision == "downgrade_required" and (.reason | contains("not fresh pass")))
    and any(.claims[]; .claim_id == "CLAIM-TARGET-ALLOWED" and .decision == "allow" and .actual_wording_state == "target")
    and any(.claims[]; .claim_id == "CLAIM-HYPOTHESIS-ALLOWED" and .decision == "allow" and .actual_wording_state == "hypothesis")
  ' "${output_dir}/claim_freshness_report.json" >/dev/null || {
    record_failure "selftest report mismatch"
    return
  }

  grep -Fq 'CLAIM-STALE-OBSERVED' "${output_dir}/downgrade_suggestions.md"
  grep -Fq 'Use TARGET wording until a fresh live proof bundle is generated.' "${output_dir}/downgrade_suggestions.md"
  jq -s 'length == 6 and all(.[]; .event == "claim.checked")' "${output_dir}/events.jsonl" >/dev/null || {
    record_failure "event log mismatch"
    return
  }

  record_pass "selftest claim decisions"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest_case "$(mktemp -d "${TMPDIR:-/tmp}/claim-freshness-gate.XXXXXX")"
    fi
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      output_dir="${2:-$(mktemp -d "${TMPDIR:-/tmp}/claim-freshness-gate-run.XXXXXX")}"
      run_selftest_case "$output_dir"
      printf 'claim_freshness_gate_smoke_artifacts=%s\n' "$output_dir"
    fi
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
