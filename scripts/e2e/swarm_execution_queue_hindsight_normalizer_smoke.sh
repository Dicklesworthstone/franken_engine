#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/swarm_execution_queue_hindsight_normalizer.sh"
docs_path="${root_dir}/docs/SWARM_EXECUTION_QUEUE_HINDSIGHT_NORMALIZER.md"
contract_path="${root_dir}/docs/swarm_execution_queue_hindsight_input_contract_v1.json"
parent_contract_path="${root_dir}/docs/swarm_execution_queue_hindsight_contract_v1.json"
fixture_bundle_path="${root_dir}/scripts/testdata/swarm_execution_queue/hindsight_normalizer_fixtures.json"
failures=0

input_ids=(
  queue_artifact_json
  queue_run_manifest_json
  normalized_queue_input_json
  risk_budget_receipt_json
  bottleneck_report_json
  bead_status_snapshot_json
  bead_timing_snapshot_json
  owner_contact_snapshot_json
  reservation_friction_snapshot_json
  proof_outcome_snapshot_json
  checkpoint_restore_state_json
)

record_pass() {
  printf 'PASS swarm-execution-queue-hindsight-normalizer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-hindsight-normalizer %s\n' "$1" >&2
  failures=$((failures + 1))
}

rewrite_json() {
  local path="$1"
  local filter="$2"
  local tmp_path="${path}.tmp"
  jq "$filter" "$path" >"$tmp_path"
  mv "$tmp_path" "$path"
}

extract_fixture_input() {
  local scenario="$1"
  local input_id="$2"
  local output_path="$3"

  jq -e \
    --arg scenario "$scenario" \
    --arg input_id "$input_id" \
    '.scenarios[] | select(.scenario_id == $scenario) | .inputs[$input_id]' \
    "$fixture_bundle_path" >"$output_path"
}

write_case_inputs() {
  local dir="$1"
  local scenario="$2"
  local input_id

  mkdir -p "$dir"
  for input_id in "${input_ids[@]}"; do
    extract_fixture_input healthy "$input_id" "${dir}/${input_id}.json"
  done

  case "$scenario" in
    healthy)
      ;;
    stale_owner)
      rewrite_json "${dir}/bead_status_snapshot_json.json" '.tasks[0].status = "in_progress" | .tasks[0].actual_outcome = "started"'
      rewrite_json "${dir}/bead_timing_snapshot_json.json" '.tasks[0].actual_started_epoch_seconds = 1800004200 | del(.tasks[0].actual_closed_epoch_seconds) | .tasks[0].actual_outcome = "started"'
      rewrite_json "${dir}/owner_contact_snapshot_json.json" '.contacts[0].owner_last_contact_epoch_seconds = 1799990000 | .contacts[0].owner_friction_outcome = "stale_owner_contact"'
      ;;
    proof_brownout)
      rewrite_json "${dir}/proof_outcome_snapshot_json.json" '.proofs[0].state = "brownout" | .proofs[0].proof_outcome = "brownout"'
      ;;
    contradictory_owner)
      rewrite_json "${dir}/owner_contact_snapshot_json.json" '.contacts[0].owner = "AgentB" | .contacts[0].owner_friction_outcome = "conflicting_owner_contact"'
      ;;
    missing_outcome)
      rewrite_json "${dir}/bead_status_snapshot_json.json" '.tasks[0].status = "open" | del(.tasks[0].actual_outcome)'
      rewrite_json "${dir}/bead_timing_snapshot_json.json" '.tasks[0] = {task_id:"bd-ready-a", actual_rank:1}'
      ;;
    local_fallback)
      rewrite_json "${dir}/proof_outcome_snapshot_json.json" '.proofs[0].state = "remote_only_ok" | .proofs[0].proof_outcome = "healthy" | .proofs[0].local_fallback_detected = true'
      ;;
    *)
      record_failure "unknown fixture scenario ${scenario}"
      return 1
      ;;
  esac
}

run_normalizer_case() {
  local input_dir="$1"
  local output_dir="$2"
  local expected_code="$3"
  local code

  mkdir -p "$output_dir"
  set +e
  bash "$normalizer" \
    --queue-artifact-json "${input_dir}/queue_artifact_json.json" \
    --queue-run-manifest-json "${input_dir}/queue_run_manifest_json.json" \
    --normalized-queue-input-json "${input_dir}/normalized_queue_input_json.json" \
    --risk-budget-receipt-json "${input_dir}/risk_budget_receipt_json.json" \
    --bottleneck-report-json "${input_dir}/bottleneck_report_json.json" \
    --bead-status-snapshot-json "${input_dir}/bead_status_snapshot_json.json" \
    --bead-timing-snapshot-json "${input_dir}/bead_timing_snapshot_json.json" \
    --owner-contact-snapshot-json "${input_dir}/owner_contact_snapshot_json.json" \
    --reservation-friction-snapshot-json "${input_dir}/reservation_friction_snapshot_json.json" \
    --proof-outcome-snapshot-json "${input_dir}/proof_outcome_snapshot_json.json" \
    --checkpoint-restore-state-json "${input_dir}/checkpoint_restore_state_json.json" \
    --source-revision fixture-rev \
    --observation-epoch-seconds 1800000300 \
    --output-dir "$output_dir" >/dev/null
  code=$?
  set -e

  if [[ "$code" -ne "$expected_code" ]]; then
    record_failure "expected normalizer exit ${expected_code}, got ${code}"
    return 1
  fi

  if [[ ! -f "${output_dir}/hindsight_report.json" ]]; then
    record_failure "normalizer did not emit hindsight_report.json"
    return 1
  fi
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'automatic reopen is allowed|automatically reopens|runs br update|will run br update|br update .*--status|release_file_reservations|will release reservations|sends Agent Mail automatically|mutates remote workers|changes active queue automatically|automatic queue actuation is allowed' "$path"; then
    record_failure "${path#"$root_dir"/} contains live-mutation wording"
  fi
}

check_no_bare_heavy_cargo() {
  local path="$1"
  local command
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$command" != *"rch exec --"* || "$command" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "${path#"$root_dir"/} has bare heavy Cargo command: ${command}"
      fi
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,240p' "$path")
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-hindsight-input-normalizer-contract.v1"
    and .bead_id == "bd-p5j9g"
    and .parent_bead_id == "bd-d5daf"
    and (.depends_on | index("bd-7s7ui") != null)
    and .script == "scripts/swarm_execution_queue_hindsight_normalizer.sh"
    and .smoke_script == "scripts/e2e/swarm_execution_queue_hindsight_normalizer_smoke.sh"
    and .docs == "docs/SWARM_EXECUTION_QUEUE_HINDSIGHT_NORMALIZER.md"
    and .parent_contract == "docs/swarm_execution_queue_hindsight_contract_v1.json"
    and .fixture_bundle == "scripts/testdata/swarm_execution_queue/hindsight_normalizer_fixtures.json"
    and .input_schema_version == "franken-engine.swarm-execution-queue-hindsight-input.v1"
    and .report_schema_version == "franken-engine.swarm-execution-queue-hindsight-report.v1"
    and (.required_input_metadata | index("content_hash_hex") != null)
    and (.artifact_paths.hindsight_report_json == "hindsight_report.json")
    and (.required_hindsight_row_fields | index("recommended_first_action") != null)
    and (.required_hindsight_row_fields | index("checkpoint_restore_outcome") != null)
    and (.fail_closed_rules | map(test("unknown task references fail closed")) | any)
    and (.fail_closed_rules | map(test("local-rch fallback fails")) | any)
    and (.degraded_rules | map(test("missing observed outcomes")) | any)
    and (.selftest_scenarios | index("healthy") != null)
    and (.selftest_scenarios | index("stale_owner") != null)
    and (.selftest_scenarios | index("proof_brownout") != null)
    and (.selftest_scenarios | index("contradictory_owner") != null)
    and (.selftest_scenarios | index("missing_outcome") != null)
    and .mutation_policy.mutates_br == false
    and .mutation_policy.reassigns_beads == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_active_queue == false
  ' "$contract_path" >/dev/null
}

fixture_bundle_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-hindsight-normalizer-fixtures.v1"
    and (.scenarios | length) >= 1
    and any(.scenarios[]; .scenario_id == "healthy" and .expected_decision == "pass")
    and all(.scenarios[]; (.inputs.queue_artifact_json.queue | length) > 0)
    and all(.scenarios[]; .inputs.queue_artifact_json.queue[0].first_action | length > 0)
    and all(.scenarios[]; .inputs.bead_status_snapshot_json.observation_epoch_seconds >= .inputs.queue_artifact_json.queue_issued_epoch_seconds)
    and all(.scenarios[]; .inputs.proof_outcome_snapshot_json.proofs[0].local_fallback_detected == false)
  ' "$fixture_bundle_path" >/dev/null
}

run_rch_policy_gate() {
  local scope_file output_dir
  scope_file="$(mktemp "${TMPDIR:-/tmp}/swarm-execution-queue-hindsight-normalizer-scope.XXXXXX")"
  output_dir="${SWARM_EXECUTION_QUEUE_HINDSIGHT_RCH_POLICY_ROOT:-${TMPDIR:-/tmp}/swarm-execution-queue-hindsight-rch-policy}"
  printf '%s\n' \
    "scripts/swarm_execution_queue_hindsight_normalizer.sh" \
    "scripts/e2e/swarm_execution_queue_hindsight_normalizer_smoke.sh" \
    "docs/SWARM_EXECUTION_QUEUE_HINDSIGHT_NORMALIZER.md" \
    "docs/swarm_execution_queue_hindsight_input_contract_v1.json" \
    "scripts/testdata/swarm_execution_queue/hindsight_normalizer_fixtures.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "$output_dir" \
    --scope-file "$scope_file" >/dev/null
}

run_check() {
  bash -n "$normalizer"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path" "$parent_contract_path" "$fixture_bundle_path"

  if contract_shape_ok; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi

  if fixture_bundle_shape_ok; then
    record_pass "checked-in fixture bundle shape"
  else
    record_failure "checked-in fixture bundle shape mismatch"
  fi

  while IFS= read -r referenced_path; do
    if [[ ! -e "${root_dir}/${referenced_path}" ]]; then
      record_failure "missing referenced path ${referenced_path}"
    fi
  done < <(jq -r '.script, .smoke_script, .docs, .parent_contract, .fixture_bundle' "$contract_path")

  grep -Fq 'advisory-only' "$docs_path" || record_failure "docs must say advisory-only"
  grep -Fq 'hindsight_report.json' "$docs_path" || record_failure "docs must mention hindsight report artifact"
  grep -Fq 'local-rch fallback fails' "$docs_path" || record_failure "docs must reject local-rch fallback promotion"

  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$contract_path"
  check_no_bare_heavy_cargo "$contract_path"
  run_rch_policy_gate || record_failure "rch policy scoped gate failed"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
}

run_selftest() {
  local tmp_parent tmp_root scenario input_dir output_dir
  tmp_parent="${SWARM_EXECUTION_QUEUE_HINDSIGHT_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-execution-queue-hindsight-normalizer.XXXXXX")"

  run_check

  scenario="healthy"
  input_dir="${tmp_root}/${scenario}/inputs"
  output_dir="${tmp_root}/${scenario}/out"
  write_case_inputs "$input_dir" "$scenario"
  run_normalizer_case "$input_dir" "$output_dir" 0
  jq -e '
    .decision == "pass"
    and .summary.queue_task_count == 1
    and .summary.matched_count == 1
    and .summary.fail_closed_reason_count == 0
    and .rows[0].task_id == "bd-ready-a"
    and .rows[0].fidelity_class == "matched"
    and .rows[0].drift_class == "none"
    and .rows[0].confidence_band == "high"
  ' "${output_dir}/hindsight_report.json" >/dev/null
  record_pass "healthy fixture produces high-confidence match"

  scenario="stale_owner"
  input_dir="${tmp_root}/${scenario}/inputs"
  output_dir="${tmp_root}/${scenario}/out"
  write_case_inputs "$input_dir" "$scenario"
  run_normalizer_case "$input_dir" "$output_dir" 0
  jq -e '
    .decision == "degraded"
    and .rows[0].fidelity_class == "delayed_match"
    and .rows[0].drift_class == "timing_drift"
    and any(.degraded_inputs[]?; .kind == "owner_friction")
  ' "${output_dir}/hindsight_report.json" >/dev/null
  record_pass "stale-owner fixture degrades with visible owner friction"

  scenario="proof_brownout"
  input_dir="${tmp_root}/${scenario}/inputs"
  output_dir="${tmp_root}/${scenario}/out"
  write_case_inputs "$input_dir" "$scenario"
  run_normalizer_case "$input_dir" "$output_dir" 0
  jq -e '
    .decision == "degraded"
    and .rows[0].proof_outcome == "brownout"
    and .rows[0].drift_class == "proof_drift"
    and any(.degraded_inputs[]?; .kind == "proof_brownout")
  ' "${output_dir}/hindsight_report.json" >/dev/null
  record_pass "proof-brownout fixture degrades proof confidence"

  scenario="contradictory_owner"
  input_dir="${tmp_root}/${scenario}/inputs"
  output_dir="${tmp_root}/${scenario}/out"
  write_case_inputs "$input_dir" "$scenario"
  run_normalizer_case "$input_dir" "$output_dir" 42
  jq -e '
    .decision == "fail_closed"
    and any(.fail_closed_reasons[]?; .kind == "inconsistent_owner_identity")
  ' "${output_dir}/hindsight_report.json" >/dev/null
  record_pass "contradictory-owner fixture fails closed"

  scenario="missing_outcome"
  input_dir="${tmp_root}/${scenario}/inputs"
  output_dir="${tmp_root}/${scenario}/out"
  write_case_inputs "$input_dir" "$scenario"
  run_normalizer_case "$input_dir" "$output_dir" 0
  jq -e '
    .decision == "degraded"
    and .rows[0].actual_outcome == "not_observed"
    and .rows[0].fidelity_class == "insufficient_evidence"
    and .rows[0].drift_class == "data_gap"
    and any(.degraded_inputs[]?; .kind == "missing_outcome")
  ' "${output_dir}/hindsight_report.json" >/dev/null
  record_pass "missing-outcome fixture degrades into insufficient evidence"

  scenario="local_fallback"
  input_dir="${tmp_root}/${scenario}/inputs"
  output_dir="${tmp_root}/${scenario}/out"
  write_case_inputs "$input_dir" "$scenario"
  run_normalizer_case "$input_dir" "$output_dir" 42
  jq -e '
    .decision == "fail_closed"
    and any(.fail_closed_reasons[]?; .kind == "local_rch_fallback_promoted")
  ' "${output_dir}/hindsight_report.json" >/dev/null
  record_pass "local-rch fallback fixture fails when promoted as healthy proof"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  printf 'swarm_execution_queue_hindsight_normalizer_smoke_artifacts=%s\n' "$tmp_root"
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
