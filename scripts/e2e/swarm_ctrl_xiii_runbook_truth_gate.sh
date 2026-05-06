#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docs_path="${SWARM_CTRL_XIII_RUNBOOK_DOC:-${root_dir}/docs/SWARM_CTRL_XIII_OPERATOR_RUNBOOK.md}"
contract_path="${SWARM_CTRL_XIII_TRUTH_CONTRACT:-${root_dir}/docs/swarm_execution_queue_hindsight_runbook_truth_contract_v1.json}"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-ctrl-xiii-runbook-truth %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-ctrl-xiii-runbook-truth %s\n' "$1" >&2
  failures=$((failures + 1))
}

check_no_forbidden_claims() {
  local path="$1"
  if grep -Eiq 'automatic queue actuation is allowed|automatically retunes|applies retuning automatically|changes active queue automatically|runs br update|will run br update|sends Agent Mail automatically|releases reservations automatically|does not reject local fallback proof|local fallback proof is acceptable' "$path"; then
    record_failure "${path#"$root_dir"/} contains unsafe automation or local-fallback wording"
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
  if [[ ! -f "$docs_path" ]]; then
    record_failure "missing runbook ${docs_path}"
    return 1
  fi
  if [[ ! -f "$contract_path" ]]; then
    record_failure "missing truth contract ${contract_path}"
    return 1
  fi
  jq empty "$contract_path" >/dev/null

  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-hindsight-runbook-truth.v1"
    and .bead_id == "bd-nt8fa"
    and (.required_artifact_references | index("hindsight/hindsight_report.json") != null)
    and (.required_artifact_references | index("fidelity/fidelity_score_receipt.json") != null)
    and (.required_artifact_references | index("fidelity/drift_ledger.json") != null)
    and (.required_artifact_references | index("counterfactual/tuning_plan.json") != null)
    and (.required_artifact_references | index("operator-status/status.json") != null)
    and (.required_scripts | index("scripts/swarm_execution_queue_hindsight_normalizer.sh") != null)
    and (.required_scripts | index("scripts/swarm_execution_queue_fidelity_scorer.sh") != null)
    and (.required_scripts | index("scripts/swarm_execution_queue_counterfactual_planner.sh") != null)
    and (.required_scripts | index("scripts/swarm_operator_status_report.sh") != null)
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
    and .mutation_policy.mutates_br == false
  ' "$contract_path" >/dev/null || record_failure "truth contract shape mismatch"

  while IFS= read -r required_text; do
    grep -Fq "$required_text" "$docs_path" || record_failure "runbook missing required text: ${required_text}"
  done < <(jq -r '.required_runbook_text[]' "$contract_path")

  while IFS= read -r artifact_ref; do
    grep -Fq "$artifact_ref" "$docs_path" || record_failure "runbook missing artifact reference: ${artifact_ref}"
  done < <(jq -r '.required_artifact_references[]' "$contract_path")

  while IFS= read -r script_ref; do
    grep -Fq "$script_ref" "$docs_path" || record_failure "runbook missing script reference: ${script_ref}"
  done < <(jq -r '.required_scripts[]' "$contract_path")

  check_no_forbidden_claims "$docs_path"
  check_no_forbidden_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  record_pass "runbook truth validates"
}

run_selftest() {
  local tmp_root bad_doc bad_contract
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-ctrl-xiii-runbook-truth.XXXXXX")"

  run_check

  bad_doc="${tmp_root}/bad-runbook.md"
  cp "$docs_path" "$bad_doc"
  printf '\nThe drill applies retuning automatically and does not reject local fallback proof promotion.\n' >>"$bad_doc"
  if SWARM_CTRL_XIII_RUNBOOK_DOC="$bad_doc" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "selftest expected unsafe automation wording rejection"
  else
    record_pass "selftest rejects unsafe automation wording"
  fi

  bad_contract="${tmp_root}/bad-contract.json"
  jq 'del(.required_artifact_references[] | select(. == "operator-status/status.json"))' "$contract_path" >"$bad_contract"
  if SWARM_CTRL_XIII_TRUTH_CONTRACT="$bad_contract" bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    record_failure "selftest expected missing artifact reference rejection"
  else
    record_pass "selftest rejects missing artifact reference"
  fi

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac
