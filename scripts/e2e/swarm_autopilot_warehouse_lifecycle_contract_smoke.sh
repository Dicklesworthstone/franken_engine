#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docs_path="${SWARM_AUTOPILOT_WAREHOUSE_LIFECYCLE_DOC:-${root_dir}/docs/SWARM_AUTOPILOT_WAREHOUSE_LIFECYCLE_CONTRACT.md}"
contract_path="${SWARM_AUTOPILOT_WAREHOUSE_LIFECYCLE_CONTRACT:-${root_dir}/docs/swarm_autopilot_warehouse_lifecycle_contract_v1.json}"
mode="${1:-check}"

record_pass() {
  printf 'PASS swarm-autopilot-warehouse-lifecycle-contract %s\n' "$1"
}

record_fail() {
  printf 'FAIL swarm-autopilot-warehouse-lifecycle-contract %s\n' "$1" >&2
  exit 1
}

write_json() {
  local path="$1"
  local content="$2"
  printf '%s\n' "$content" >"$path"
}

bundle_has_path() {
  local bundle="$1"
  local dotted_path="$2"
  jq -e --arg dotted_path "$dotted_path" '
    def dotted_get($path):
      reduce ($path | split("."))[] as $segment
        (.;
          if . == null then null else .[$segment] end
        );
    dotted_get($dotted_path) != null
  ' "$bundle" >/dev/null
}

validate_bundle_against_contract() {
  local bundle="$1"

  jq -e --slurpfile contract "$contract_path" '
    ($contract[0]) as $contract_doc
    | .schema_version == $contract_doc.lifecycle_bundle_schema_version
    and (.truth_state | IN("confirmed", "degraded", "blocked", "contaminated"))
    and (.retention_decision | IN("retain", "compact_degraded", "fail_closed"))
    and (.promotion_decision | IN("pending_review", "degraded_insufficient_evidence", "blocked_contradiction", "contaminated"))
    and (.cohort_decision | IN("ready", "degraded_missing_optional", "blocked_missing_references", "contaminated"))
    and (.storage_pressure_state | IN("normal", "elevated", "critical"))
  ' "$bundle" >/dev/null || return 1

  while IFS= read -r dotted_path; do
    [[ -n "$dotted_path" ]] || continue
    bundle_has_path "$bundle" "$dotted_path" || return 1
  done < <(jq -r '.required_bundle_fields[]' "$contract_path")

  jq -e '
    .optional_snapshot_health.optional_present_count + .optional_snapshot_health.optional_missing_count
      == .optional_snapshot_health.optional_snapshot_count
    and (.contradiction_count >= 0)
  ' "$bundle" >/dev/null || return 1

  jq -e '
    if .truth_state == "confirmed" then
      .required_input_status.warehouse_rows_present == true
      and .required_input_status.retention_classes_present == true
      and .local_fallback_contamination == false
      and .optional_snapshot_health.optional_missing_count == 0
      and .contradiction_count == 0
      and (.error_codes | length) == 0
    elif .truth_state == "degraded" then
      .required_input_status.warehouse_rows_present == true
      and .required_input_status.retention_classes_present == true
      and .local_fallback_contamination == false
      and .optional_snapshot_health.optional_missing_count > 0
      and .contradiction_count == 0
    elif .truth_state == "blocked" then
      .local_fallback_contamination == false
      and (
        .required_input_status.warehouse_rows_present == false
        or .required_input_status.retention_classes_present == false
        or .contradiction_count > 0
      )
      and (.error_codes | length) > 0
    elif .truth_state == "contaminated" then
      .local_fallback_contamination == true
      and (.error_codes | length) > 0
    else
      false
    end
  ' "$bundle" >/dev/null || return 1
}

assert_bundle_valid() {
  local bundle="$1"
  local label="$2"
  validate_bundle_against_contract "$bundle" \
    || record_fail "${label} failed bundle validation"
}

check_no_forbidden_claims() {
  local path="$1"
  if grep -Eiq 'automatic promotion is allowed|automatic replay approval is allowed|mutates beads|releases reservations|sends Agent Mail|mutates workers|runs Cargo|runs RCH' "$path"; then
    record_fail "${path#"$root_dir"/} contains unsafe truth or mutation wording"
  fi
}

write_bundle() {
  local path="$1"
  local scenario="$2"

  local truth_state="confirmed"
  local retention_decision="retain"
  local promotion_decision="pending_review"
  local cohort_decision="ready"
  local storage_pressure_state="normal"
  local local_fallback_contamination="false"
  local warehouse_rows_present="true"
  local retention_classes_present="true"
  local optional_snapshot_count="3"
  local optional_present_count="3"
  local optional_missing_count="0"
  local contradiction_count="0"
  local error_codes='[]'

  case "$scenario" in
    healthy_lifecycle)
      ;;
    degraded_missing_optional_snapshot)
      truth_state="degraded"
      retention_decision="compact_degraded"
      promotion_decision="degraded_insufficient_evidence"
      cohort_decision="degraded_missing_optional"
      storage_pressure_state="elevated"
      optional_present_count="1"
      optional_missing_count="2"
      ;;
    blocked_contradictory_hindsight)
      truth_state="blocked"
      retention_decision="fail_closed"
      promotion_decision="blocked_contradiction"
      cohort_decision="blocked_missing_references"
      storage_pressure_state="critical"
      contradiction_count="1"
      error_codes='["FE-SWARM-AUTOPILOT-WAREHOUSE-CONTRADICTORY-HINDSIGHT"]'
      ;;
    contaminated_local_fallback)
      truth_state="contaminated"
      retention_decision="fail_closed"
      promotion_decision="contaminated"
      cohort_decision="contaminated"
      storage_pressure_state="critical"
      local_fallback_contamination="true"
      error_codes='["FE-SWARM-AUTOPILOT-WAREHOUSE-LOCAL-FALLBACK"]'
      ;;
    *)
      record_fail "unknown bundle scenario ${scenario}"
      ;;
  esac

  write_json "$path" "$(jq -n \
    --arg truth_state "$truth_state" \
    --arg retention_decision "$retention_decision" \
    --arg promotion_decision "$promotion_decision" \
    --arg cohort_decision "$cohort_decision" \
    --arg storage_pressure_state "$storage_pressure_state" \
    --argjson local_fallback_contamination "$local_fallback_contamination" \
    --argjson warehouse_rows_present "$warehouse_rows_present" \
    --argjson retention_classes_present "$retention_classes_present" \
    --argjson optional_snapshot_count "$optional_snapshot_count" \
    --argjson optional_present_count "$optional_present_count" \
    --argjson optional_missing_count "$optional_missing_count" \
    --argjson contradiction_count "$contradiction_count" \
    --argjson error_codes "$error_codes" \
    '{
      schema_version: "franken-engine.swarm-autopilot-warehouse-lifecycle-summary.v1",
      warehouse_lifecycle_id: "swarm-autopilot-warehouse-lifecycle-smoke",
      truth_state: $truth_state,
      retention_decision: $retention_decision,
      promotion_decision: $promotion_decision,
      cohort_decision: $cohort_decision,
      storage_pressure_state: $storage_pressure_state,
      local_fallback_contamination: $local_fallback_contamination,
      required_input_status: {
        warehouse_rows_present: $warehouse_rows_present,
        retention_classes_present: $retention_classes_present
      },
      optional_snapshot_health: {
        optional_snapshot_count: $optional_snapshot_count,
        optional_present_count: $optional_present_count,
        optional_missing_count: $optional_missing_count
      },
      contradiction_count: $contradiction_count,
      error_codes: $error_codes,
      retention_classes: [
        "short_lived_raw_capture",
        "long_lived_replay_evidence",
        "audit_log",
        "policy_snapshot"
      ],
      artifact_paths: {
        retention_plan_json: "artifacts/swarm_autopilot_warehouse_retention_plan.json",
        storage_budget_ledger_json: "artifacts/swarm_autopilot_storage_budget_ledger.json",
        promotion_candidates_json: "artifacts/swarm_autopilot_promotion_candidates.json",
        anomaly_cohorts_json: "artifacts/swarm_autopilot_anomaly_cohorts.json",
        replay_index_json: "artifacts/swarm_autopilot_replay_index.json",
        operator_summary_json: "artifacts/swarm_autopilot_operator_summary.json"
      }
    }')"
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-warehouse-lifecycle-contract.v1"
    and .bead_id == "bd-gra1z.1"
    and .parent_bead_id == "bd-gra1z"
    and (.depends_on | index("bd-4t4oi") != null)
    and (.upstream_contracts | index("docs/swarm_autopilot_evidence_warehouse_contract_v1.json") != null)
    and .smoke_script == "scripts/e2e/swarm_autopilot_warehouse_lifecycle_contract_smoke.sh"
    and .operator_docs == "docs/SWARM_AUTOPILOT_WAREHOUSE_LIFECYCLE_CONTRACT.md"
    and .lifecycle_bundle_schema_version == "franken-engine.swarm-autopilot-warehouse-lifecycle-summary.v1"
    and ((["evidence_warehouse_json"] - .required_inputs) | length) == 0
    and ((["historical_budget_baseline_json","operator_snapshot_json","hindsight_bundle_json"] - .optional_inputs) | length) == 0
    and ((["short_lived_raw_capture","long_lived_replay_evidence","audit_log","policy_snapshot"] - .recognized_retention_classes) | length) == 0
    and ((["confirmed","degraded","blocked","contaminated"] - .truth_states) | length) == 0
    and ((["retain","compact_degraded","fail_closed"] - .retention_decisions) | length) == 0
    and ((["pending_review","degraded_insufficient_evidence","blocked_contradiction","contaminated"] - .promotion_decisions) | length) == 0
    and ((["ready","degraded_missing_optional","blocked_missing_references","contaminated"] - .cohort_decisions) | length) == 0
    and ((["normal","elevated","critical"] - .storage_pressure_states) | length) == 0
    and (([
      "FE-SWARM-AUTOPILOT-WAREHOUSE-MISSING-INPUT",
      "FE-SWARM-AUTOPILOT-WAREHOUSE-CONTRADICTORY-HINDSIGHT",
      "FE-SWARM-AUTOPILOT-WAREHOUSE-MISSING-REPLAY-PATH",
      "FE-SWARM-AUTOPILOT-WAREHOUSE-LOCAL-FALLBACK"
    ] - .required_error_codes) | length) == 0
    and any(.fixture_examples[]; .fixture_id == "healthy_lifecycle" and .expected_truth_state == "confirmed")
    and any(.fixture_examples[]; .fixture_id == "degraded_missing_optional_snapshot" and .expected_truth_state == "degraded")
    and any(.fixture_examples[]; .fixture_id == "blocked_contradictory_hindsight" and .required_error_code == "FE-SWARM-AUTOPILOT-WAREHOUSE-CONTRADICTORY-HINDSIGHT")
    and any(.fixture_examples[]; .fixture_id == "contaminated_local_fallback" and .required_error_code == "FE-SWARM-AUTOPILOT-WAREHOUSE-LOCAL-FALLBACK")
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.automatic_promotion == false
    and .mutation_policy.automatic_replay_approval == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'This contract is advisory only and proof only.' "$docs_path" \
    && grep -Fq 'Missing optional warehouse lifecycle snapshots degrade trust.' "$docs_path" \
    && grep -Fq 'Contradictory hindsight must fail closed.' "$docs_path" \
    && grep -Fq 'Local fallback contamination must fail closed.' "$docs_path" \
    && grep -Fq 'The lifecycle surfaces must not mutate beads, reservations, Agent Mail, workers, or live queue policy.' "$docs_path"
}

run_check() {
  contract_shape_ok || record_fail "contract JSON shape mismatch"
  docs_shape_ok || record_fail "docs truth text mismatch"
  check_no_forbidden_claims "$docs_path"
  check_no_forbidden_claims "$contract_path"
  record_pass "check"
}

run_selftest() {
  local temp_dir
  temp_dir="$(mktemp -d)"
  trap 'rm -rf "$temp_dir"' RETURN

  local fixture bundle expected_truth expected_retention expected_promotion expected_cohort required_error
  while IFS= read -r fixture; do
    bundle="${temp_dir}/${fixture}.json"
    write_bundle "$bundle" "$fixture"
    assert_bundle_valid "$bundle" "$fixture"

    expected_truth="$(jq -r --arg fixture "$fixture" '.fixture_examples[] | select(.fixture_id == $fixture) | .expected_truth_state' "$contract_path")"
    expected_retention="$(jq -r --arg fixture "$fixture" '.fixture_examples[] | select(.fixture_id == $fixture) | .expected_retention_decision' "$contract_path")"
    expected_promotion="$(jq -r --arg fixture "$fixture" '.fixture_examples[] | select(.fixture_id == $fixture) | .expected_promotion_decision' "$contract_path")"
    expected_cohort="$(jq -r --arg fixture "$fixture" '.fixture_examples[] | select(.fixture_id == $fixture) | .expected_cohort_decision' "$contract_path")"
    required_error="$(jq -r --arg fixture "$fixture" '.fixture_examples[] | select(.fixture_id == $fixture) | (.required_error_code // "")' "$contract_path")"

    jq -e \
      --arg expected_truth "$expected_truth" \
      --arg expected_retention "$expected_retention" \
      --arg expected_promotion "$expected_promotion" \
      --arg expected_cohort "$expected_cohort" \
      --arg required_error "$required_error" '
      .truth_state == $expected_truth
      and .retention_decision == $expected_retention
      and .promotion_decision == $expected_promotion
      and .cohort_decision == $expected_cohort
      and (
        ($required_error | length) == 0
        or (.error_codes | index($required_error) != null)
      )
    ' "$bundle" >/dev/null || record_fail "${fixture} expectations mismatch"
  done < <(jq -r '.fixture_examples[].fixture_id' "$contract_path")

  record_pass "selftest"
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_warehouse_lifecycle_contract_smoke.sh [check|selftest]
EOF
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_check
    run_selftest
    ;;
  *)
    usage
    record_fail "unknown mode $mode"
    ;;
esac
