#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC2016

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runbook_path="${SWARM_CTRL_XI_OPERATOR_RUNBOOK_PATH:-${root_dir}/docs/SWARM_CTRL_XI_OPERATOR_RUNBOOK.md}"
drill_path="${root_dir}/scripts/e2e/swarm_checkpoint_lifecycle_no_mock_drill.sh"
contract_path="${SWARM_CTRL_XI_RUNBOOK_TRUTH_CONTRACT_PATH:-${root_dir}/docs/swarm_ctrl_xi_runbook_truth_contract_v1.json}"

record_pass() {
  printf 'PASS swarm-ctrl-xi-runbook-truth %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-ctrl-xi-runbook-truth %s\n' "$1" >&2
}

required_repo_paths=(
  "scripts/swarm_checkpoint_bundle_packer.sh"
  "scripts/swarm_checkpoint_restore_planner.sh"
  "scripts/swarm_checkpoint_restore_conformance_gate.sh"
  "scripts/swarm_operator_status_report.sh"
  "scripts/e2e/swarm_checkpoint_lifecycle_no_mock_drill.sh"
  "scripts/e2e/swarm_ctrl_xi_runbook_truth_gate.sh"
  "scripts/testdata/swarm_checkpoint_lifecycle_drill/healthy/swarm_capacity_snapshot.json"
  "docs/SWARM_CTRL_XI_OPERATOR_RUNBOOK.md"
  "docs/swarm_ctrl_xi_runbook_truth_contract_v1.json"
)

required_runbook_patterns=(
  'rch exec -- env CARGO_TARGET_DIR='
  "\`scripts/swarm_operator_status_report.sh\` remains the only predictive dashboard producer in \`franken_engine\`."
  'scripts/testdata/swarm_checkpoint_lifecycle_drill/healthy'
  'swarm_checkpoint_lifecycle_no_mock_drill_report.json'
  'capture/checkpoint_bundle.json'
  'capture/run_manifest.json'
  'simulated-disconnect-restart/checkpoint_bundle.json'
  'restore-plan/swarm_checkpoint_restore_plan.json'
  'conformance/swarm_checkpoint_restore_conformance_report.json'
  'operator-status/status.json'
  'operator-status/report.md'
  './scripts/e2e/swarm_checkpoint_lifecycle_no_mock_drill.sh check'
  './scripts/e2e/swarm_checkpoint_lifecycle_no_mock_drill.sh run'
  './scripts/e2e/swarm_checkpoint_lifecycle_no_mock_drill.sh selftest'
  './scripts/e2e/swarm_ctrl_xi_runbook_truth_gate.sh check'
  './scripts/e2e/swarm_ctrl_xi_runbook_truth_gate.sh selftest'
)

required_workflow_claims=(
  'The composed drill reuses the checked-in checkpoint lifecycle fixtures and the real control-plane scripts only; it does not mutate live bead, reservation, worker, or queue state.'
  "The simulated disconnect/restart step only replays the saved checkpoint bundle copy under \`simulated-disconnect-restart/checkpoint_bundle.json\`; there is no automatic reopen or silent ownership transfer."
  'Stale checkpoint age, local fallback truth, contradictory ownership/contact-first evidence, or salvage manual review must keep restore fail-closed or advisory; they never auto-promote resume.'
  "Because the no-mock drill omits unrelated resource-lease, proof-cache, QoS batch, and staged-contamination artifacts, \`operator-status/status.json\` may stay degraded; checkpoint restore truth lives in \`summary.checkpoint_restore_*\` and \`predictive_dashboard.checkpoint_restore.*\`."
  'The operator status report remains the only predictive dashboard producer in franken_engine.'
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

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    case "$line" in
      *automatic\ reopen*|*reopens\ beads\ automatically*|*silent\ ownership\ transfer*|*second\ predictive\ dashboard\ producer*|*mutates\ live\ worker\ state\ during\ replay*|*automatic\ ownership\ transfer*)
        case "$line" in
          *"there is no automatic reopen or silent ownership transfer."*|\
          *"cannot be reworded into an automatic reopen"*|\
          *"there is no silent ownership transfer"*|\
          *"claims that the drill performs automatic reopen, silent ownership transfer, or live worker mutation"*|\
          *"claims that the drill is a second predictive dashboard producer"*)
            continue
            ;;
        esac
        printf 'automatic reopen, silent ownership transfer, duplicate producer, or live mutation claim detected: %s\n' "$line" >&2
        return 1
        ;;
    esac
  done < "$doc_path"
}

validate_contract() {
  jq empty "$contract_path" >/dev/null

  jq -e '
    .schema_version == "franken-engine.swarm-ctrl-xi-runbook-truth-contract.v1"
    and (.required_repo_paths | index("scripts/e2e/swarm_checkpoint_lifecycle_no_mock_drill.sh") != null)
    and (.required_repo_paths | index("docs/SWARM_CTRL_XI_OPERATOR_RUNBOOK.md") != null)
    and (.required_artifact_references | index("swarm_checkpoint_lifecycle_no_mock_drill_report.json") != null)
    and (.required_artifact_references | index("simulated-disconnect-restart/checkpoint_bundle.json") != null)
    and (.required_artifact_references | index("restore-plan/swarm_checkpoint_restore_plan.json") != null)
    and (.required_artifact_references | index("conformance/swarm_checkpoint_restore_conformance_report.json") != null)
    and (.required_artifact_references | index("operator-status/status.json") != null)
    and (.required_artifact_references | index("operator-status/report.md") != null)
    and (.required_commands | index("./scripts/e2e/swarm_ctrl_xi_runbook_truth_gate.sh check") != null)
    and (.required_commands | index("./scripts/e2e/swarm_ctrl_xi_runbook_truth_gate.sh selftest") != null)
    and (.required_commands | index("./scripts/e2e/swarm_checkpoint_lifecycle_no_mock_drill.sh check") != null)
    and (.required_commands | index("./scripts/e2e/swarm_checkpoint_lifecycle_no_mock_drill.sh selftest") != null)
  ' "$contract_path" >/dev/null
}

run_check() {
  local path
  local scope_file
  local policy_output_dir

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

  scope_file="$(mktemp "${TMPDIR:-/tmp}/swarm-ctrl-xi-runbook-scope.XXXXXX")"
  policy_output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-ctrl-xi-runbook-rch-policy.XXXXXX")"
  printf '%s\n' \
    "scripts/e2e/swarm_checkpoint_lifecycle_no_mock_drill.sh" \
    "scripts/e2e/swarm_ctrl_xi_runbook_truth_gate.sh" \
    "docs/SWARM_CTRL_XI_OPERATOR_RUNBOOK.md" \
    "docs/swarm_ctrl_xi_runbook_truth_contract_v1.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "$policy_output_dir" \
    --scope-file "$scope_file" >/dev/null
  record_pass "rch policy compliance"
}

run_selftest() {
  local tmp_root bad_cargo_doc missing_artifact_doc stale_workflow_doc bad_claim_doc

  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-ctrl-xi-runbook.XXXXXX")"

  bad_cargo_doc="${tmp_root}/bad-cargo.md"
  cp "$runbook_path" "$bad_cargo_doc"
  cat >>"$bad_cargo_doc" <<'EOF'

```bash
# rch-policy-waive: bare_cargo reason=intentional_truth_gate_selftest_fixture
cargo test --all-targets
```
EOF
  if SWARM_CTRL_XI_OPERATOR_RUNBOOK_PATH="$bad_cargo_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "bare heavy cargo example should fail truth gate"
    return 1
  fi
  record_pass "bare heavy cargo rejection"

  missing_artifact_doc="${tmp_root}/missing-artifact.md"
  grep -v 'simulated-disconnect-restart/checkpoint_bundle.json' "$runbook_path" >"$missing_artifact_doc"
  if SWARM_CTRL_XI_OPERATOR_RUNBOOK_PATH="$missing_artifact_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "missing restart artifact reference should fail truth gate"
    return 1
  fi
  record_pass "missing restart artifact rejection"

  stale_workflow_doc="${tmp_root}/stale-workflow.md"
  grep -v 'Stale checkpoint age, local fallback truth, contradictory ownership/contact-first evidence, or salvage manual review must keep restore fail-closed or advisory; they never auto-promote resume.' "$runbook_path" >"$stale_workflow_doc"
  if SWARM_CTRL_XI_OPERATOR_RUNBOOK_PATH="$stale_workflow_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "stale checkpoint workflow claim should fail truth gate"
    return 1
  fi
  record_pass "stale checkpoint workflow claim rejection"

  bad_claim_doc="${tmp_root}/bad-claim.md"
  cp "$runbook_path" "$bad_claim_doc"
  cat >>"$bad_claim_doc" <<'EOF'

The composed drill performs automatic reopen, silent ownership transfer, and is a second predictive dashboard producer.
EOF
  if SWARM_CTRL_XI_OPERATOR_RUNBOOK_PATH="$bad_claim_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "automatic reopen, ownership transfer, or duplicate producer claim should fail truth gate"
    return 1
  fi
  record_pass "automatic reopen, ownership transfer, and duplicate producer rejection"

  printf 'swarm_ctrl_xi_runbook_truth_gate_artifacts=%s\n' "$tmp_root"
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
