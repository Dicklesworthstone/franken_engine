#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docs_path="${root_dir}/docs/SWARM_EXECUTION_QUEUE_HINDSIGHT_CONTRACT.md"
contract_path="${root_dir}/docs/swarm_execution_queue_hindsight_contract_v1.json"
gate_path="${root_dir}/scripts/e2e/swarm_execution_queue_hindsight_contract_smoke.sh"
failures=0

record_pass() {
  printf 'PASS swarm-execution-queue-hindsight-contract %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-hindsight-contract %s\n' "$1" >&2
  failures=$((failures + 1))
}

relative_path() {
  local path="$1"
  printf '%s\n' "${path#"$root_dir"/}"
}

check_path_exists() {
  local relative="$1"
  if [[ -z "$relative" || "$relative" == "null" ]]; then
    record_failure "referenced path is empty"
  elif [[ ! -e "${root_dir}/${relative}" ]]; then
    record_failure "missing referenced path ${relative}"
  else
    record_pass "referenced path exists ${relative}"
  fi
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'automatic reopen is allowed|automatically reopens|runs br update|will run br update|br update .*--status|release_file_reservations|will release reservations|sends Agent Mail automatically|mutates remote workers|changes active queue automatically|automatic queue actuation is allowed' "$path"; then
    record_failure "$(relative_path "$path") contains live-mutation wording"
  else
    record_pass "$(relative_path "$path") has advisory-only wording"
  fi
}

check_no_bare_heavy_cargo() {
  local path="$1"
  local command
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$command" != *"rch exec --"* || "$command" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "$(relative_path "$path") has bare heavy Cargo command: ${command}"
      fi
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,240p' "$path")
  return 0
}

contract_shape_ok() {
  local path="$1"
  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-hindsight-contract.v1"
    and .bead_id == "bd-7s7ui"
    and .parent_bead_id == "bd-d5daf"
    and (.depends_on | index("bd-g347f") != null)
    and .docs == "docs/SWARM_EXECUTION_QUEUE_HINDSIGHT_CONTRACT.md"
    and .smoke_gate == "scripts/e2e/swarm_execution_queue_hindsight_contract_smoke.sh"
    and (.required_queue_inputs | index("queue_artifact_json") != null)
    and (.required_queue_inputs | index("queue_run_manifest_json") != null)
    and (.required_queue_inputs | index("normalized_queue_input_json") != null)
    and (.required_aftermath_inputs | index("bead_status_snapshot_json") != null)
    and (.required_aftermath_inputs | index("owner_contact_snapshot_json") != null)
    and (.required_aftermath_inputs | index("reservation_friction_snapshot_json") != null)
    and (.required_aftermath_inputs | index("proof_outcome_snapshot_json") != null)
    and (.required_aftermath_inputs | index("checkpoint_restore_state_json") != null)
    and (.required_input_metadata | index("content_hash_hex") != null)
    and (.timestamp_policy.required_fields | index("queue_issued_epoch_seconds") != null)
    and (.timestamp_policy.required_fields | index("observation_epoch_seconds") != null)
    and .timestamp_policy.ambiguity_decision == "fail_closed"
    and (.evidence_ledger_required_fields | index("freshness_state") != null)
    and (.required_output_artifacts | index("hindsight_report.json") != null)
    and (.required_output_artifacts | index("counterfactual_candidates.json") != null)
    and (.required_hindsight_row_fields | index("rank_delta") != null)
    and (.required_hindsight_row_fields | index("counterfactual_candidate") != null)
    and (.allowed_fidelity_classes | index("justified_override") != null)
    and (.allowed_drift_classes | index("restore_drift") != null)
    and (.allowed_confidence_bands | index("insufficient_evidence") != null)
    and (.counterfactual_candidate_fields | index("expected_fidelity_gain_millionths") != null)
    and (.fail_closed_rules | map(test("timestamps fail closed")) | any)
    and (.fail_closed_rules | map(test("unknown task references fail closed")) | any)
    and (.fail_closed_rules | map(test("local-rch fallback.*fail closed")) | any)
    and .mutation_policy.mutates_br == false
    and .mutation_policy.reassigns_beads == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_active_queue == false
  ' "$path" >/dev/null
}

validate_contract() {
  jq empty "$contract_path"
  if contract_shape_ok "$contract_path"; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi

  while IFS= read -r referenced_path; do
    check_path_exists "$referenced_path"
  done < <(jq -r '.docs, .smoke_gate, .upstream_contracts[]' "$contract_path")

  check_no_mutation_claims "$contract_path"
  check_no_bare_heavy_cargo "$contract_path"
}

validate_docs() {
  grep -Fq 'SWARM-CTRL-XIII' "$docs_path"
  grep -Fq 'advisory evidence only' "$docs_path"
  grep -Fq 'Evidence Ledger' "$docs_path"
  grep -Fq 'Counterfactual Tuning Inputs' "$docs_path"
  grep -Eiq 'checkpoint[- ]restore' "$docs_path"
  grep -Eq 'local[[:space:]-]*rch[[:space:]]+fallback.*fail[[:space:]]+closed' "$docs_path"
  check_no_mutation_claims "$docs_path"
  check_no_bare_heavy_cargo "$docs_path"
  record_pass "docs cover scope and truth policy"
}

run_check() {
  bash -n "$gate_path"
  validate_contract
  validate_docs

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
}

run_selftest() {
  local tmp_parent tmp_root bad_contract bad_doc bad_timestamp_contract
  tmp_parent="${SWARM_EXECUTION_QUEUE_HINDSIGHT_CONTRACT_SMOKE_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-execution-queue-hindsight-contract.XXXXXX")"

  run_check

  bad_contract="${tmp_root}/bad_contract.json"
  jq 'del(.required_aftermath_inputs[] | select(. == "checkpoint_restore_state_json"))' "$contract_path" >"$bad_contract"
  if contract_shape_ok "$bad_contract"; then
    record_failure "bad contract without checkpoint restore state should fail"
  else
    record_pass "bad contract without checkpoint restore state fails"
  fi

  bad_timestamp_contract="${tmp_root}/bad_timestamp_contract.json"
  jq '.timestamp_policy.ambiguity_decision = "guess"' "$contract_path" >"$bad_timestamp_contract"
  if contract_shape_ok "$bad_timestamp_contract"; then
    record_failure "bad timestamp ambiguity policy should fail"
  else
    record_pass "bad timestamp ambiguity policy fails"
  fi

  bad_doc="${tmp_root}/bad_doc.md"
  printf 'This hindsight lane automatically reopens beads and changes active queue automatically.\n' >"$bad_doc"
  if grep -Eiq 'automatically reopens|changes active queue automatically' "$bad_doc"; then
    record_pass "bad automatic mutation wording fails"
  else
    record_failure "bad automatic mutation wording should fail"
  fi

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  printf 'swarm_execution_queue_hindsight_contract_smoke_artifacts=%s\n' "$tmp_root"
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
