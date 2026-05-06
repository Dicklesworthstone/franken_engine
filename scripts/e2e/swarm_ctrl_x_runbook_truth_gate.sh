#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runbook_path="${SWARM_CTRL_X_OPERATOR_RUNBOOK_PATH:-${root_dir}/docs/SWARM_CTRL_X_OPERATOR_RUNBOOK.md}"
drill_path="${root_dir}/scripts/e2e/swarm_starvation_rescue_no_mock_drill.sh"
contract_path="${SWARM_CTRL_X_RUNBOOK_TRUTH_CONTRACT_PATH:-${root_dir}/docs/swarm_ctrl_x_runbook_truth_contract_v1.json}"

record_pass() {
  printf 'PASS swarm-ctrl-x-runbook-truth %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-ctrl-x-runbook-truth %s\n' "$1" >&2
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

  if grep -Ei 'mutates live worker state|reopens beads automatically|automatic ownership transfer|changes reservation state|second predictive dashboard producer' "$runbook_path" \
    | grep -Eiv 'does not|no live|rejects|must not|never|claims that' >/dev/null; then
    record_failure "runbook makes automation or duplicate producer claims"
    return 1
  fi

  if grep -Eiq 'safe to bypass conformance|ignore contradictory ownership|local fallback rejection is optional|planner mutates tracker state' "$runbook_path"; then
    record_failure "runbook makes stale rescue truth claims"
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

  scope_file="$(mktemp "${TMPDIR:-/tmp}/swarm-ctrl-x-runbook-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/e2e/swarm_starvation_rescue_no_mock_drill.sh" \
    "scripts/e2e/swarm_ctrl_x_runbook_truth_gate.sh" \
    "docs/SWARM_CTRL_X_OPERATOR_RUNBOOK.md" \
    "docs/swarm_ctrl_x_runbook_truth_contract_v1.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/swarm-ctrl-x-runbook-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "syntax contract runbook truth and rch policy"
}

run_selftest() {
  local tmp_root bare_runbook missing_artifact_runbook mutation_runbook producer_runbook

  run_check
  tmp_root="${SWARM_CTRL_X_RUNBOOK_TRUTH_SELFTEST_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_root"

  bare_runbook="$(mktemp "${tmp_root%/}/swarm-ctrl-x-runbook-bare.XXXXXX.md")"
  cp "$runbook_path" "$bare_runbook"
  cat >>"$bare_runbook" <<'EOF'

```bash
# rch-policy-waive: bare_cargo reason=intentional_truth_gate_selftest_fixture
cargo test -p frankenengine-engine --test swarm_starvation_rescue_no_mock_drill -- --nocapture
```
EOF
  if runbook_path="$bare_runbook" assert_truth_paths; then
    record_failure "bare cargo negative case should fail"
    return 1
  fi
  record_pass "bare cargo rejected"

  missing_artifact_runbook="$(mktemp "${tmp_root%/}/swarm-ctrl-x-runbook-missing.XXXXXX.md")"
  grep -v 'swarm_starvation_rescue_no_mock_drill_report.json' "$runbook_path" >"$missing_artifact_runbook"
  if runbook_path="$missing_artifact_runbook" assert_truth_paths; then
    record_failure "missing artifact reference should fail"
    return 1
  fi
  record_pass "missing artifact reference rejected"

  mutation_runbook="$(mktemp "${tmp_root%/}/swarm-ctrl-x-runbook-mutation.XXXXXX.md")"
  cp "$runbook_path" "$mutation_runbook"
  printf '\nThis drill mutates live worker state and reopens beads automatically.\n' >>"$mutation_runbook"
  if runbook_path="$mutation_runbook" assert_truth_paths; then
    record_failure "live mutation claim should fail"
    return 1
  fi
  record_pass "live mutation claim rejected"

  producer_runbook="$(mktemp "${tmp_root%/}/swarm-ctrl-x-runbook-producer.XXXXXX.md")"
  cp "$runbook_path" "$producer_runbook"
  printf '\nThis drill is a second predictive dashboard producer.\n' >>"$producer_runbook"
  if runbook_path="$producer_runbook" assert_truth_paths; then
    record_failure "duplicate dashboard producer claim should fail"
    return 1
  fi
  record_pass "duplicate dashboard producer claim rejected"
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
