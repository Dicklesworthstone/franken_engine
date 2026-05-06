#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
drill_path="${root_dir}/scripts/e2e/typed_persistence_no_mock_drill.sh"
truth_gate_path="${root_dir}/scripts/e2e/typed_persistence_truth_gate.sh"
suite_json="${root_dir}/scripts/testdata/typed_persistence_no_mock_drill/cases.json"
contract_path="${root_dir}/docs/typed_persistence_enforcement_contract_v1.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS typed-persistence-no-mock-smoke %s\n' "$1"
}

record_failure() {
  printf 'FAIL typed-persistence-no-mock-smoke %s\n' "$1" >&2
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/typed_persistence_no_mock_drill_smoke.sh [check|selftest]
EOF
}

run_check() {
  bash -n "$drill_path" "$truth_gate_path" "${BASH_SOURCE[0]}"
  shellcheck -x "$drill_path" "$truth_gate_path" "${BASH_SOURCE[0]}"
  jq empty "$contract_path" "$suite_json" >/dev/null
  bash "$drill_path" check >/dev/null
  bash "$truth_gate_path" check >/dev/null
  record_pass "syntax lint jq drill and truth gate"
}

run_selftest() {
  run_check
  bash "$drill_path" selftest >/dev/null
  bash "$truth_gate_path" selftest >/dev/null
  record_pass "selftest suite validates failure cases"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac
