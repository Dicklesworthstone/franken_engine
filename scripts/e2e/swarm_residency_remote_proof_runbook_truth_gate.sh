#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runbook_path="${SWARM_RESIDENCY_REMOTE_PROOF_RUNBOOK_PATH:-${root_dir}/docs/SWARM_RESIDENCY_REMOTE_PROOF_ACCELERATION_RUNBOOK.md}"
drill_path="${root_dir}/scripts/e2e/swarm_residency_remote_proof_drill.sh"

record_pass() {
  printf 'PASS swarm-residency-runbook-truth %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-residency-runbook-truth %s\n' "$1" >&2
}

assert_runbook_truth() {
  local doc_path="$1"

  test -f "$doc_path"
  grep -q 'rch exec -- env CARGO_TARGET_DIR=' "$doc_path"
  grep -q 'sticky_worker_warm_target_plan.json' "$doc_path"
  grep -q 'sync_closure_hotspots.json' "$doc_path"
  grep -q 'artifact_retrieval_budget_verdict.json' "$doc_path"
  grep -q 'incident_packet.json' "$doc_path"
  grep -q 'residency_drill_report.json' "$doc_path"
}

run_check() {
  local scope_file

  bash -n "${BASH_SOURCE[0]}"
  bash -n "$drill_path"
  assert_runbook_truth "$runbook_path"
  record_pass "bash syntax and runbook artifact references"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/swarm-residency-runbook-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/e2e/swarm_residency_remote_proof_drill.sh" \
    "scripts/e2e/swarm_residency_remote_proof_runbook_truth_gate.sh" \
    "$runbook_path" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/swarm-residency-runbook-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "rch policy compliance"
}

run_selftest() {
  local tmp_root bad_cargo_doc missing_artifact_doc

  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-residency-runbook.XXXXXX")"

  bad_cargo_doc="${tmp_root}/bad-cargo.md"
  cp "$runbook_path" "$bad_cargo_doc"
  printf "\n\`\`\`bash\ncargo test --all-targets\n\`\`\`\n" >>"$bad_cargo_doc"
  if SWARM_RESIDENCY_REMOTE_PROOF_RUNBOOK_PATH="$bad_cargo_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "bare heavy cargo example should fail truth gate"
    return 1
  fi
  record_pass "bare heavy cargo rejection"

  missing_artifact_doc="${tmp_root}/missing-artifact.md"
  grep -v 'incident_packet.json' "$runbook_path" >"$missing_artifact_doc"
  if SWARM_RESIDENCY_REMOTE_PROOF_RUNBOOK_PATH="$missing_artifact_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "missing artifact reference should fail truth gate"
    return 1
  fi
  record_pass "missing artifact reference rejection"

  printf 'swarm_residency_remote_proof_runbook_truth_gate_artifacts=%s\n' "$tmp_root"
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
