#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runbook_path="${SWARM_CTRL_XIV_OPERATOR_RUNBOOK_PATH:-${root_dir}/docs/SWARM_CTRL_XIV_OPERATOR_RUNBOOK.md}"
drill_path="${root_dir}/scripts/e2e/swarm_execution_queue_tuning_lifecycle_no_mock_drill.sh"
contract_path="${SWARM_CTRL_XIV_RUNBOOK_TRUTH_CONTRACT_PATH:-${root_dir}/docs/swarm_ctrl_xiv_runbook_truth_contract_v1.json}"

record_pass() {
  printf 'PASS swarm-ctrl-xiv-runbook-truth %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-ctrl-xiv-runbook-truth %s\n' "$1" >&2
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

  if grep -En '(^|[[:space:]])cargo[[:space:]]+(check|test|clippy|run)' "$runbook_path" \
    | grep -Fv 'rch exec -- env CARGO_TARGET_DIR=' >/dev/null; then
    record_failure "bare cargo command found in runbook"
    return 1
  fi

  if grep -Ei 'automatically promotes|applies retuning automatically|changes active queue|live queue mutation|reopens beads automatically|automatic ownership transfer|second predictive dashboard producer|manual approval may be skipped|fallback proof may be used' "$runbook_path" \
    | grep -Eiv 'does not|no automatic|not permission|must not|never|rejects|not as|not a|only predictive dashboard producer|truth gate rejects|claims that' >/dev/null; then
    record_failure "runbook makes automation, mutation, or duplicate producer claims"
    return 1
  fi
}

run_check() {
  local scope_file

  bash -n "${BASH_SOURCE[0]}"
  bash -n "$drill_path"
  shellcheck -x "$drill_path" "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  assert_truth_paths

  scope_file="$(mktemp "${TMPDIR:-/tmp}/swarm-ctrl-xiv-runbook-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/e2e/swarm_execution_queue_tuning_lifecycle_no_mock_drill.sh" \
    "scripts/e2e/swarm_ctrl_xiv_runbook_truth_gate.sh" \
    "docs/SWARM_CTRL_XIV_OPERATOR_RUNBOOK.md" \
    "docs/swarm_ctrl_xiv_runbook_truth_contract_v1.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/swarm-ctrl-xiv-runbook-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "syntax contract runbook truth and rch policy"
}

run_selftest() {
  local tmp_root bare_runbook missing_artifact_runbook mutation_runbook producer_runbook approval_runbook proof_runbook

  run_check
  tmp_root="${SWARM_CTRL_XIV_RUNBOOK_TRUTH_SELFTEST_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_root"

  bare_runbook="$(mktemp "${tmp_root%/}/swarm-ctrl-xiv-runbook-bare.XXXXXX.md")"
  cp "$runbook_path" "$bare_runbook"
  cat >>"$bare_runbook" <<'EOF'

```bash
# rch-policy-waive: bare_cargo reason=intentional_truth_gate_selftest_fixture
cargo test -p frankenengine-engine --test swarm_execution_queue_tuning_lifecycle -- --nocapture
```
EOF
  if runbook_path="$bare_runbook" assert_truth_paths; then
    record_failure "bare cargo negative case should fail"
    return 1
  fi
  record_pass "bare cargo rejected"

  missing_artifact_runbook="$(mktemp "${tmp_root%/}/swarm-ctrl-xiv-runbook-missing.XXXXXX.md")"
  grep -v 'canary_verdict_ledger.json' "$runbook_path" >"$missing_artifact_runbook"
  if runbook_path="$missing_artifact_runbook" assert_truth_paths; then
    record_failure "missing artifact reference should fail"
    return 1
  fi
  record_pass "missing artifact reference rejected"

  mutation_runbook="$(mktemp "${tmp_root%/}/swarm-ctrl-xiv-runbook-mutation.XXXXXX.md")"
  cp "$runbook_path" "$mutation_runbook"
  printf '\nThis drill applies retuning automatically and changes active queue policy.\n' >>"$mutation_runbook"
  if runbook_path="$mutation_runbook" assert_truth_paths; then
    record_failure "live mutation claim should fail"
    return 1
  fi
  record_pass "live mutation claim rejected"

  producer_runbook="$(mktemp "${tmp_root%/}/swarm-ctrl-xiv-runbook-producer.XXXXXX.md")"
  cp "$runbook_path" "$producer_runbook"
  printf '\nThis drill is a second predictive dashboard producer.\n' >>"$producer_runbook"
  if runbook_path="$producer_runbook" assert_truth_paths; then
    record_failure "duplicate dashboard producer claim should fail"
    return 1
  fi
  record_pass "duplicate dashboard producer claim rejected"

  approval_runbook="$(mktemp "${tmp_root%/}/swarm-ctrl-xiv-runbook-approval.XXXXXX.md")"
  cp "$runbook_path" "$approval_runbook"
  printf '\nFor this workflow, manual approval may be skipped after a clean canary.\n' >>"$approval_runbook"
  if runbook_path="$approval_runbook" assert_truth_paths; then
    record_failure "manual approval bypass claim should fail"
    return 1
  fi
  record_pass "manual approval bypass rejected"

  proof_runbook="$(mktemp "${tmp_root%/}/swarm-ctrl-xiv-runbook-proof.XXXXXX.md")"
  cp "$runbook_path" "$proof_runbook"
  printf '\nFallback proof may be used for promotion confidence.\n' >>"$proof_runbook"
  if runbook_path="$proof_runbook" assert_truth_paths; then
    record_failure "local proof fallback claim should fail"
    return 1
  fi
  record_pass "local proof fallback claim rejected"
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
