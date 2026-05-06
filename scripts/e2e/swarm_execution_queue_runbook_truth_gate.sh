#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runbook="${root_dir}/docs/SWARM_EXECUTION_QUEUE_OPERATOR_RUNBOOK.md"
contract="${root_dir}/docs/swarm_execution_queue_runbook_truth_contract_v1.json"
drill="${root_dir}/scripts/e2e/swarm_execution_queue_no_mock_drill.sh"
gate="${root_dir}/scripts/e2e/swarm_execution_queue_runbook_truth_gate.sh"
failures=0

record_pass() {
  printf 'PASS swarm-execution-queue-runbook-truth %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-runbook-truth %s\n' "$1" >&2
  failures=$((failures + 1))
}

check_no_forbidden_claims() {
  local path="$1"
  local rch_pattern='local[[:space:]-]*(rch[[:space:]]+)?fallback[[:space:]]+(is[[:space:]]+healthy|accepted[[:space:]]+as[[:space:]]+healthy)'
  local forbidden_pattern="automatically reopens|automatic reopen is allowed|runs br update|will run br update|release_file_reservations|will release reservations|sends Agent Mail automatically|mutates remote workers|${rch_pattern}"
  if grep -Eiq "$forbidden_pattern" "$path"; then
    record_failure "${path#"$root_dir"/} contains unsafe mutation or local-fallback wording"
  else
    record_pass "${path#"$root_dir"/} avoids unsafe mutation wording"
  fi
}

check_no_bare_heavy_cargo() {
  local path="$1"
  local line
  while IFS= read -r line; do
    if [[ "$line" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$line" != *"rch exec --"* || "$line" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "${path#"$root_dir"/} has bare heavy Cargo command: ${line}"
      fi
    fi
  done <"$path"
}

run_check() {
  bash -n "$drill" "$gate"
  jq empty "$contract"

  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-runbook-truth-contract.v1"
    and .bead_id == "bd-w9sxz"
    and (.real_chain | index("scripts/swarm_execution_queue_input_normalizer.sh"))
    and (.real_chain | index("franken_swarm_execution_queue"))
    and (.real_chain | index("scripts/e2e/swarm_execution_queue_conformance_gate.sh"))
    and (.real_chain | index("scripts/swarm_operator_status_report.sh"))
    and (.required_artifacts | index("normalized_input.json"))
    and (.required_artifacts | index("execution_queue_artifact.json"))
    and (.required_artifacts | index("risk_budget_receipt.json"))
    and (.required_artifacts | index("bottleneck_report.json"))
    and (.required_artifacts | index("status.json"))
    and (.degraded_cases | index("stale_owner_recent_reservation"))
    and (.degraded_cases | index("proof_transport_brownout"))
    and (.degraded_cases | index("checkpoint_restore_manual_review"))
    and (.degraded_cases | index("cycle_rejection"))
    and (.degraded_cases | index("malformed_graph_rejection"))
  ' "$contract" >/dev/null
  record_pass "contract shape"

  for path in "$runbook" "$contract" "$drill" "$gate"; do
    [[ -f "$path" ]] || record_failure "missing ${path#"$root_dir"/}"
    if [[ "$path" != "$gate" ]]; then
      check_no_forbidden_claims "$path"
    fi
    check_no_bare_heavy_cargo "$path"
  done

  for token in \
    'normalized_input.json' \
    'execution_queue_artifact.json' \
    'risk_budget_receipt.json' \
    'bottleneck_report.json' \
    'run_manifest.json' \
    'status.json' \
    'report.md' \
    'scripts/swarm_execution_queue_input_normalizer.sh' \
    'scripts/e2e/swarm_execution_queue_conformance_gate.sh' \
    'scripts/swarm_operator_status_report.sh'
  do
    if grep -Fq "$token" "$runbook" "$contract"; then
      record_pass "artifact reference ${token}"
    else
      record_failure "missing artifact reference ${token}"
    fi
  done

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
}

run_selftest() {
  local tmp_root bad_doc
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-execution-queue-runbook-truth.XXXXXX")"
  run_check

  bad_doc="${tmp_root}/bad.md"
  printf 'This lane automatically reopens beads and local-%s is healthy.\n' 'rch fallback' >"$bad_doc"
  if grep -Eiq 'automatically reopens|local[[:space:]-]*rch[[:space:]]+fallback[[:space:]]+is[[:space:]]+healthy' "$bad_doc"; then
    record_pass "bad mutation/local-fallback wording fails"
  else
    record_failure "bad mutation/local-fallback wording should fail"
  fi
  printf 'swarm_execution_queue_runbook_truth_artifacts=%s\n' "$tmp_root"
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
