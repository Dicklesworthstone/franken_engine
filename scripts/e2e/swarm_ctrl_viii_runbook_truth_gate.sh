#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runbook_path="${SWARM_CTRL_VIII_OPERATOR_RUNBOOK_PATH:-${root_dir}/docs/SWARM_CTRL_VIII_OPERATOR_RUNBOOK.md}"
drill_path="${root_dir}/scripts/e2e/swarm_predictive_admission_no_mock_drill.sh"
contract_path="${SWARM_CTRL_VIII_RUNBOOK_TRUTH_CONTRACT_PATH:-${root_dir}/docs/swarm_ctrl_viii_runbook_truth_contract_v1.json}"

record_pass() {
  printf 'PASS swarm-ctrl-viii-runbook-truth %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-ctrl-viii-runbook-truth %s\n' "$1" >&2
}

required_repo_paths=(
  "scripts/e2e/swarm_admission_drill.sh"
  "scripts/e2e/swarm_predictive_orchestration_e2e.sh"
  "scripts/e2e/remote_proof_archive_lifecycle_no_mock_drill.sh"
  "scripts/e2e/swarm_predictive_admission_no_mock_drill.sh"
  "scripts/e2e/swarm_ctrl_viii_runbook_truth_gate.sh"
  "scripts/swarm_operator_status_report.sh"
  "docs/SWARM_ADMISSION_DRILL.md"
  "docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md"
  "docs/SWARM_CTRL_VIII_OPERATOR_RUNBOOK.md"
  "docs/swarm_ctrl_viii_runbook_truth_contract_v1.json"
)

required_runbook_patterns=(
  "rch exec -- env CARGO_TARGET_DIR="
  "\`scripts/swarm_operator_status_report.sh\` remains the only predictive dashboard producer in \`franken_engine\`."
  "swarm_predictive_admission_no_mock_drill_report.json"
  "swarm_admission_drill_report.json"
  "predictive/wrapper/report.json"
  "predictive/operator-status/status.json"
  "predictive/operator-status/report.md"
  "swarm_capacity_forecast.json"
  "swarm_admission_budget_plan.json"
  "lease_exchange_salvage_simulation.json"
  "warm_target_prefetch_roi_advisory.json"
  "remote_proof_archive_lifecycle_no_mock_drill_report.json"
  "./scripts/e2e/swarm_predictive_admission_no_mock_drill.sh check"
  "./scripts/e2e/swarm_predictive_admission_no_mock_drill.sh selftest"
  "./scripts/e2e/swarm_ctrl_viii_runbook_truth_gate.sh check"
  "./scripts/e2e/swarm_ctrl_viii_runbook_truth_gate.sh selftest"
)

required_workflow_claims=(
  "Low-confidence or stale forecast evidence must keep the composed predictive admission drill fail-closed instead of upgrading to admit."
  "Lease exchange or salvage remains manual-confirmation only when stale locks, degraded rch, or archive pressure remain unresolved."
  "Archive pressure must keep warm-target prefetch advisory-only and negative until compaction or preserve-pinned evidence clears."
  "The drill does not mutate live worker state, leases, queue entries, or archive bundles."
)

assert_runbook_truth() {
  local doc_path="$1"
  local line

  test -f "$doc_path"

  for line in "${required_runbook_patterns[@]}"; do
    grep -Fq -- "$line" "$doc_path"
  done

  for line in "${required_workflow_claims[@]}"; do
    grep -Fq -- "$line" "$doc_path"
  done

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    if [[ "$line" == *"cargo "* ]] && [[ "$line" != *"rch exec -- env CARGO_TARGET_DIR="* ]]; then
      printf 'bare heavy cargo example: %s\n' "$line" >&2
      return 1
    fi
  done < <(grep -E 'cargo (check|test|clippy)' "$doc_path" || true)

  if grep -Eiq 'second predictive dashboard producer|another predictive dashboard producer|mutates live worker state during replay|automatic live worker mutation|live worker mutation is performed' "$doc_path"; then
    printf 'duplicate producer or live mutation claim detected\n' >&2
    return 1
  fi
}

validate_contract() {
  jq empty "$contract_path" >/dev/null

  jq -e '
    .schema_version == "franken-engine.swarm-ctrl-viii-runbook-truth-contract.v1"
    and (.required_repo_paths | index("scripts/e2e/swarm_predictive_admission_no_mock_drill.sh") != null)
    and (.required_repo_paths | index("docs/SWARM_CTRL_VIII_OPERATOR_RUNBOOK.md") != null)
    and (.required_artifact_references | index("swarm_predictive_admission_no_mock_drill_report.json") != null)
    and (.required_artifact_references | index("swarm_admission_drill_report.json") != null)
    and (.required_artifact_references | index("predictive/wrapper/report.json") != null)
    and (.required_artifact_references | index("predictive/operator-status/status.json") != null)
    and (.required_artifact_references | index("predictive/operator-status/report.md") != null)
    and (.required_artifact_references | index("swarm_capacity_forecast.json") != null)
    and (.required_artifact_references | index("swarm_admission_budget_plan.json") != null)
    and (.required_artifact_references | index("lease_exchange_salvage_simulation.json") != null)
    and (.required_artifact_references | index("warm_target_prefetch_roi_advisory.json") != null)
    and (.required_artifact_references | index("remote_proof_archive_lifecycle_no_mock_drill_report.json") != null)
    and (.verification_commands | index("bash -n scripts/e2e/swarm_ctrl_viii_runbook_truth_gate.sh") != null)
    and (.verification_commands | index("./scripts/e2e/swarm_ctrl_viii_runbook_truth_gate.sh check") != null)
    and (.verification_commands | index("./scripts/e2e/swarm_ctrl_viii_runbook_truth_gate.sh selftest") != null)
  ' "$contract_path" >/dev/null
}

run_check() {
  local scope_file
  local path

  bash -n "${BASH_SOURCE[0]}"
  bash -n "$drill_path"
  shellcheck -x "$drill_path" "${BASH_SOURCE[0]}"
  assert_runbook_truth "$runbook_path"
  validate_contract
  record_pass "bash syntax, runbook truth, and contract shape"

  for path in "${required_repo_paths[@]}"; do
    test -e "${root_dir}/${path}"
  done
  record_pass "required repo paths exist"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/swarm-ctrl-viii-runbook-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/e2e/swarm_predictive_admission_no_mock_drill.sh" \
    "scripts/e2e/swarm_ctrl_viii_runbook_truth_gate.sh" \
    "docs/SWARM_CTRL_VIII_OPERATOR_RUNBOOK.md" \
    "docs/swarm_ctrl_viii_runbook_truth_contract_v1.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/swarm-ctrl-viii-runbook-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "rch policy compliance"
}

run_selftest() {
  local tmp_root bad_cargo_doc missing_artifact_doc stale_workflow_doc bad_claim_doc

  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-ctrl-viii-runbook.XXXXXX")"

  bad_cargo_doc="${tmp_root}/bad-cargo.md"
  cp "$runbook_path" "$bad_cargo_doc"
  cat >>"$bad_cargo_doc" <<'EOF'

```bash
# rch-policy-waive: bare_cargo reason=intentional_truth_gate_selftest_fixture
cargo test --all-targets
```
EOF
  if SWARM_CTRL_VIII_OPERATOR_RUNBOOK_PATH="$bad_cargo_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "bare heavy cargo example should fail truth gate"
    return 1
  fi
  record_pass "bare heavy cargo rejection"

  missing_artifact_doc="${tmp_root}/missing-artifact.md"
  grep -v 'warm_target_prefetch_roi_advisory.json' "$runbook_path" >"$missing_artifact_doc"
  if SWARM_CTRL_VIII_OPERATOR_RUNBOOK_PATH="$missing_artifact_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "missing predictive artifact reference should fail truth gate"
    return 1
  fi
  record_pass "missing predictive artifact reference rejection"

  stale_workflow_doc="${tmp_root}/stale-workflow.md"
  grep -v 'Low-confidence or stale forecast evidence must keep the composed predictive admission drill fail-closed instead of upgrading to admit.' "$runbook_path" >"$stale_workflow_doc"
  if SWARM_CTRL_VIII_OPERATOR_RUNBOOK_PATH="$stale_workflow_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "stale forecast workflow claim should fail truth gate"
    return 1
  fi
  record_pass "stale forecast workflow claim rejection"

  bad_claim_doc="${tmp_root}/bad-claim.md"
  cp "$runbook_path" "$bad_claim_doc"
  cat >>"$bad_claim_doc" <<'EOF'

The composed drill is a second predictive dashboard producer and mutates live worker state during replay.
EOF
  if SWARM_CTRL_VIII_OPERATOR_RUNBOOK_PATH="$bad_claim_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "duplicate producer or live mutation claim should fail truth gate"
    return 1
  fi
  record_pass "duplicate producer and live mutation rejection"

  printf 'swarm_ctrl_viii_runbook_truth_gate_artifacts=%s\n' "$tmp_root"
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
