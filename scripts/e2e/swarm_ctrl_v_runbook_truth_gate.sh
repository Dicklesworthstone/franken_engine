#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runbook_path="${SWARM_CTRL_V_OPERATOR_RUNBOOK_PATH:-${root_dir}/docs/SWARM_CTRL_V_OPERATOR_RUNBOOK.md}"
drill_path="${root_dir}/scripts/e2e/resident_remote_proof_no_mock_drill.sh"
contract_path="${SWARM_CTRL_V_RUNBOOK_TRUTH_CONTRACT_PATH:-${root_dir}/docs/swarm_ctrl_v_runbook_truth_contract_v1.json}"

record_pass() {
  printf 'PASS swarm-ctrl-v-runbook-truth %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-ctrl-v-runbook-truth %s\n' "$1" >&2
}

required_repo_paths=(
  "scripts/resident_remote_proof_bundle_executor.sh"
  "scripts/remote_proof_artifact_mirror_packer.sh"
  "scripts/warm_target_roi_eviction_ledger.sh"
  "scripts/remote_proof_salvage_receipt.sh"
  "scripts/locality_aware_remote_proof_batch_packer.sh"
  "scripts/e2e/resident_remote_proof_no_mock_drill.sh"
  "scripts/e2e/swarm_ctrl_v_runbook_truth_gate.sh"
  "docs/SWARM_CTRL_V_OPERATOR_RUNBOOK.md"
  "docs/swarm_ctrl_v_runbook_truth_contract_v1.json"
)

required_runbook_patterns=(
  "rch exec -- env CARGO_TARGET_DIR="
  "bundle_report.json"
  "retrieval_verification_report.json"
  "warm_target_roi_ledger.json"
  "salvage_receipt.json"
  "batch_manifest.json"
  "resident_remote_proof_no_mock_drill_report.json"
  "./scripts/e2e/resident_remote_proof_no_mock_drill.sh check"
  "./scripts/e2e/resident_remote_proof_no_mock_drill.sh selftest"
  "./scripts/e2e/swarm_ctrl_v_runbook_truth_gate.sh check"
  "./scripts/e2e/swarm_ctrl_v_runbook_truth_gate.sh selftest"
  "./scripts/resident_remote_proof_bundle_executor.sh"
  "./scripts/remote_proof_artifact_mirror_packer.sh"
  "./scripts/warm_target_roi_eviction_ledger.sh"
  "./scripts/remote_proof_salvage_receipt.sh"
  "./scripts/locality_aware_remote_proof_batch_packer.sh"
)

assert_runbook_truth() {
  local doc_path="$1"
  local line

  test -f "$doc_path"

  for line in "${required_runbook_patterns[@]}"; do
    grep -Fq -- "$line" "$doc_path"
  done

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    if [[ "$line" == *"cargo "* ]] && [[ "$line" != *"rch exec -- env CARGO_TARGET_DIR="* ]]; then
      printf 'bare heavy cargo example: %s\n' "$line" >&2
      return 1
    fi
  done < <(grep -E 'cargo (check|test|clippy)' "$doc_path" || true)
}

validate_contract() {
  jq empty "$contract_path" >/dev/null

  jq -e '
    .schema_version == "franken-engine.swarm-ctrl-v-runbook-truth-contract.v1"
    and (.required_repo_paths | index("scripts/e2e/resident_remote_proof_no_mock_drill.sh") != null)
    and (.required_repo_paths | index("docs/SWARM_CTRL_V_OPERATOR_RUNBOOK.md") != null)
    and (.required_artifact_references | index("bundle_report.json") != null)
    and (.required_artifact_references | index("retrieval_verification_report.json") != null)
    and (.required_artifact_references | index("warm_target_roi_ledger.json") != null)
    and (.required_artifact_references | index("salvage_receipt.json") != null)
    and (.required_artifact_references | index("batch_manifest.json") != null)
    and (.required_artifact_references | index("resident_remote_proof_no_mock_drill_report.json") != null)
    and (.verification_commands | index("bash -n scripts/e2e/swarm_ctrl_v_runbook_truth_gate.sh") != null)
    and (.verification_commands | index("./scripts/e2e/swarm_ctrl_v_runbook_truth_gate.sh check") != null)
    and (.verification_commands | index("./scripts/e2e/swarm_ctrl_v_runbook_truth_gate.sh selftest") != null)
  ' "$contract_path" >/dev/null
}

run_check() {
  local scope_file
  local path

  bash -n "${BASH_SOURCE[0]}"
  bash -n "$drill_path"
  assert_runbook_truth "$runbook_path"
  validate_contract
  record_pass "bash syntax, runbook truth, and contract shape"

  for path in "${required_repo_paths[@]}"; do
    test -e "${root_dir}/${path}"
  done
  record_pass "required repo paths exist"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/swarm-ctrl-v-runbook-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/e2e/resident_remote_proof_no_mock_drill.sh" \
    "scripts/e2e/swarm_ctrl_v_runbook_truth_gate.sh" \
    "docs/SWARM_CTRL_V_OPERATOR_RUNBOOK.md" \
    "docs/swarm_ctrl_v_runbook_truth_contract_v1.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/swarm-ctrl-v-runbook-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "rch policy compliance"
}

run_selftest() {
  local tmp_root bad_cargo_doc missing_artifact_doc missing_command_doc

  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-ctrl-v-runbook.XXXXXX")"

  bad_cargo_doc="${tmp_root}/bad-cargo.md"
  cp "$runbook_path" "$bad_cargo_doc"
  printf '\n```bash\ncargo test --all-targets\n```\n' >>"$bad_cargo_doc"
  if SWARM_CTRL_V_OPERATOR_RUNBOOK_PATH="$bad_cargo_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "bare heavy cargo example should fail truth gate"
    return 1
  fi
  record_pass "bare heavy cargo rejection"

  missing_artifact_doc="${tmp_root}/missing-artifact.md"
  grep -v 'salvage_receipt.json' "$runbook_path" >"$missing_artifact_doc"
  if SWARM_CTRL_V_OPERATOR_RUNBOOK_PATH="$missing_artifact_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "missing artifact reference should fail truth gate"
    return 1
  fi
  record_pass "missing artifact reference rejection"

  missing_command_doc="${tmp_root}/missing-command.md"
  grep -v 'resident_remote_proof_no_mock_drill.sh selftest' "$runbook_path" >"$missing_command_doc"
  if SWARM_CTRL_V_OPERATOR_RUNBOOK_PATH="$missing_command_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "missing drill selftest reference should fail truth gate"
    return 1
  fi
  record_pass "missing drill selftest rejection"

  printf 'swarm_ctrl_v_runbook_truth_gate_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
