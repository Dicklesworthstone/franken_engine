#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runbook_path="${SWARM_CTRL_IX_OPERATOR_RUNBOOK_PATH:-${root_dir}/docs/SWARM_CTRL_IX_OPERATOR_RUNBOOK.md}"
drill_path="${root_dir}/scripts/e2e/swarm_high_core_slo_calibration_no_mock_drill.sh"
contract_path="${SWARM_CTRL_IX_RUNBOOK_TRUTH_CONTRACT_PATH:-${root_dir}/docs/swarm_ctrl_ix_runbook_truth_contract_v1.json}"

record_pass() {
  printf 'PASS swarm-ctrl-ix-runbook-truth %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-ctrl-ix-runbook-truth %s\n' "$1" >&2
}

assert_truth_paths() {
  local path required_entry

  jq empty "$contract_path" >/dev/null
  while IFS= read -r path; do
    if [[ ! -e "${root_dir}/${path}" ]]; then
      record_failure "missing required path ${path}"
      return 1
    fi
  done < <(jq -r '.required_repo_paths[]' "$contract_path")

  while IFS= read -r required_entry; do
    if ! grep -qF "$required_entry" "$runbook_path"; then
      record_failure "missing required runbook entry ${required_entry}"
      return 1
    fi
  done < <(jq -r '.required_artifact_references[]' "$contract_path")

  while IFS= read -r required_entry; do
    if ! grep -qF "$required_entry" "$runbook_path"; then
      record_failure "missing required command ${required_entry}"
      return 1
    fi
  done < <(jq -r '.required_commands[]' "$contract_path")

  while IFS= read -r required_entry; do
    if ! grep -qF "$required_entry" "$runbook_path"; then
      record_failure "missing required workflow claim ${required_entry}"
      return 1
    fi
  done < <(jq -r '.required_workflow_claims[]' "$contract_path")

  if grep -En '(^|[[:space:]])cargo[[:space:]]+(check|test|clippy|run)' "$runbook_path" | grep -Fv 'rch exec -- env CARGO_TARGET_DIR=' >/dev/null; then
    record_failure "bare cargo command found in runbook"
    return 1
  fi

  if grep -Ein 'mutates live worker state|executes live high-core stress|kills running workers|changes worker state|live scheduler mutation' "$runbook_path" | grep -Eiv 'does not|no live|rejects|claims that' >/dev/null; then
    record_failure "runbook claims live worker mutation or live high-core stress"
    return 1
  fi

  if grep -Eiq 'traceability failures are acceptable|traceability failures still pass|claim-map traceability is already fully rch-backed' "$runbook_path"; then
    record_failure "runbook makes stale traceability claims"
    return 1
  fi
}

run_check() {
  bash -n "${BASH_SOURCE[0]}"
  bash -n "$drill_path"
  jq empty "$contract_path"
  assert_truth_paths
  record_pass "syntax contract and runbook truth"
}

run_selftest() {
  local tmp_root bare_runbook mutation_runbook

  run_check
  tmp_root="${SWARM_CTRL_IX_RUNBOOK_TRUTH_SELFTEST_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_root"

  bare_runbook="$(mktemp "${tmp_root%/}/swarm-ctrl-ix-runbook-bare.XXXXXX.md")"
  cp "$runbook_path" "$bare_runbook"
  cat >>"$bare_runbook" <<'EOF'

```bash
cargo test -p frankenengine-engine --test swarm_high_core_slo_calibration_no_mock_drill -- --nocapture
```
EOF
  if runbook_path="$bare_runbook" assert_truth_paths; then
    record_failure "bare cargo negative case should fail"
    return 1
  fi
  record_pass "bare cargo rejected"

  mutation_runbook="$(mktemp "${tmp_root%/}/swarm-ctrl-ix-runbook-mutation.XXXXXX.md")"
  cp "$runbook_path" "$mutation_runbook"
  printf '\nThis drill mutates live worker state to prove the IX flow end to end.\n' >>"$mutation_runbook"
  if runbook_path="$mutation_runbook" assert_truth_paths; then
    record_failure "live mutation negative case should fail"
    return 1
  fi
  record_pass "live mutation claims rejected"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    printf 'usage: %s [check|selftest]\n' "${BASH_SOURCE[0]}" >&2
    exit 64
    ;;
esac
