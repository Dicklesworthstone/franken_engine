#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
schema_path="${root_dir}/docs/rch_validation_evidence_ledger_schema_v1.json"
sample_path="${root_dir}/docs/rch_validation_evidence_ledger_sample_v1.json"
runbook_path="${root_dir}/docs/RCH_VALIDATION_EVIDENCE_LEDGER_RUNBOOK.md"
verifier="${root_dir}/scripts/verify_rch_validation_evidence_ledger.sh"
mode="${1:-check}"
output_root="${2:-${RCH_VALIDATION_LEDGER_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-rch-validation-ledger-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS rch-validation-evidence-ledger %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-validation-evidence-ledger %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/rch_validation_evidence_ledger_smoke.sh [check|selftest] [output_root]
EOF
}

run_check() {
  jq empty "$schema_path" "$sample_path" >/dev/null || record_failure "json parse"
  bash -n "$verifier" || record_failure "verifier syntax"
  bash -n "${BASH_SOURCE[0]}" || record_failure "smoke syntax"
  "$verifier" "$sample_path" >/dev/null || record_failure "sample verification"
  grep -Fq 'RCH-E104' "$runbook_path" || record_failure "runbook timeout guidance"
  if grep -En '^[[:space:]]*cargo[[:space:]]' "$runbook_path" >/dev/null; then
    record_failure "runbook bare cargo command"
  fi
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

write_negative_fixture() {
  local path="$1"
  jq '.entries[0].bead_id = ""' "$sample_path" >"$path"
}

write_bare_cargo_fixture() {
  local path="$1"
  jq '.entries[0].command = "cargo check --all-targets"' "$sample_path" >"$path"
}

run_selftest() {
  local tmp_root="$1"
  local missing_bead="${tmp_root}/missing-bead.json"
  local bare_cargo="${tmp_root}/bare-cargo.json"
  mkdir -p "$tmp_root"

  run_check
  if [[ "$failures" -ne 0 ]]; then
    return
  fi

  write_negative_fixture "$missing_bead"
  if "$verifier" "$missing_bead" >/dev/null 2>&1; then
    record_failure "missing bead fixture should fail"
  else
    record_pass "missing_bead_rejected"
  fi

  write_bare_cargo_fixture "$bare_cargo"
  if "$verifier" "$bare_cargo" >/dev/null 2>&1; then
    record_failure "bare cargo fixture should fail"
  else
    record_pass "bare_cargo_rejected"
  fi
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
