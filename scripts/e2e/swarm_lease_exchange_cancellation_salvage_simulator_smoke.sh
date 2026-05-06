#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
simulator="${root_dir}/scripts/swarm_lease_exchange_cancellation_salvage_simulator.sh"
contract_json="${root_dir}/docs/swarm_lease_exchange_cancellation_salvage_simulator_contract_v1.json"

record_pass() {
  printf 'PASS swarm-lease-exchange-cancellation-salvage-simulator %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-lease-exchange-cancellation-salvage-simulator %s\n' "$1" >&2
}

write_stale_lock_fixture() {
  local output_path="$1"
  local scenario="$2"
  local recommendation="safe_to_reopen"
  local safe_to_reopen="true"
  local contact_first="false"
  local assignee="AgentStale"
  local degraded_reasons='[]'

  case "$scenario" in
    stale_reservation|degraded_rch|salvage_pinned)
      ;;
    active_owner)
      recommendation="owner_active"
      safe_to_reopen="false"
      contact_first="true"
      assignee="AgentOwner"
      ;;
    manual_confirmation)
      recommendation="manual_confirmation_required"
      safe_to_reopen="false"
      contact_first="true"
      assignee="AgentManual"
      degraded_reasons='["file_reservations_missing"]'
      ;;
    ownership_contradiction)
      recommendation="safe_to_reopen"
      safe_to_reopen="false"
      contact_first="true"
      assignee="AgentAlpha"
      ;;
    *)
      record_failure "unknown stale-lock scenario ${scenario}"
      return 1
      ;;
  esac

  # shellcheck disable=SC2094
  jq -n \
    --arg output_path "$output_path" \
    --arg recommendation "$recommendation" \
    --arg assignee "$assignee" \
    --argjson safe_to_reopen "$safe_to_reopen" \
    --argjson contact_first "$contact_first" \
    --argjson degraded_reasons "$degraded_reasons" \
    '{
      schema_version: "franken-engine.stale-lock-recommendations.v1",
      stale_lock_recommendations: [
        {
          bead_id: "bd-sim-1",
          title: "Simulated bead",
          priority: 2,
          assignee: $assignee,
          safe_to_reopen: $safe_to_reopen,
          contact_first: $contact_first,
          recommendation: $recommendation,
          evidence: {
            degraded_reasons: $degraded_reasons
          }
        }
      ],
      artifact_paths: {
        stale_lock_recommendations_json: $output_path,
        report_md: "stale_lock_report.md"
      }
    }' >"$output_path"
}

write_admission_fixture() {
  local output_path="$1"
  local scenario="$2"
  local reasons='["resource_lease_restricted"]'

  case "$scenario" in
    stale_reservation|active_owner|manual_confirmation|ownership_contradiction)
      ;;
    degraded_rch)
      reasons='["rch_degradation_requires_narrow_scope","resource_lease_restricted"]'
      ;;
    salvage_pinned)
      reasons='["rch_degradation_requires_narrow_scope","resource_lease_restricted"]'
      ;;
    *)
      record_failure "unknown admission scenario ${scenario}"
      return 1
      ;;
  esac

  # shellcheck disable=SC2094
  jq -n \
    --arg output_path "$output_path" \
    --argjson reasons "$reasons" \
    '{
      schema_version: "franken-engine.swarm-admission-budget-plan.v1",
      decision: "admit_narrow",
      budget_profile: "degraded",
      recommendations: [
        {
          request_id: "req-1",
          agent_id: "AgentRequester",
          bead_id: "bd-sim-1",
          bead_priority: 2,
          priority_class: "P2",
          decision: "admit_narrow",
          heavy_rust: true,
          proof_obligation: true,
          budget_class: "protected",
          requested_command: "rch exec -- env CARGO_TARGET_DIR=/tmp/sim cargo test -p frankenengine-engine --lib",
          reasons: $reasons
        }
      ],
      artifact_paths: {
        swarm_admission_budget_plan_json: $output_path,
        report_md: "admission_report.md"
      }
    }' >"$output_path"
}

write_lease_fixture() {
  local output_path="$1"
  local scenario="$2"
  local decision="defer"
  local reason="target dir already leased by another worker"

  case "$scenario" in
    stale_reservation|active_owner|manual_confirmation|ownership_contradiction|salvage_pinned)
      ;;
    degraded_rch)
      decision="admit_narrow"
      reason="focused retry is allowed but should remain narrow under degraded rch"
      ;;
    *)
      record_failure "unknown lease scenario ${scenario}"
      return 1
      ;;
  esac

  # shellcheck disable=SC2094
  jq -n \
    --arg output_path "$output_path" \
    --arg decision "$decision" \
    --arg reason "$reason" \
    '{
      schema_version: "franken-engine.swarm-resource-lease-plan.v1",
      lease_decision: $decision,
      reason: $reason,
      safe_alternatives: ["/tmp/alt-target"],
      findings: [],
      artifact_paths: {
        resource_lease_plan_json: $output_path,
        report_md: "lease_report.md"
      }
    }' >"$output_path"
}

write_gc_guard_fixture() {
  local output_path="$1"
  local scenario="$2"
  local workflow_state="clean_finished"
  local guard_decision="cool_only"
  local recommended_action="cool_without_gc"
  local reason="bundle can cool without deletion"
  local policy_findings='["cool_before_delete"]'

  case "$scenario" in
    stale_reservation|active_owner|manual_confirmation|ownership_contradiction|degraded_rch)
      ;;
    salvage_pinned)
      workflow_state="orphan_reconciliation_required"
      guard_decision="deny_gc"
      recommended_action="pin_until_salvage_clears"
      reason="orphan-salvage reconciliation is still active"
      policy_findings='["orphan_salvage_pinned"]'
      ;;
    *)
      record_failure "unknown gc-guard scenario ${scenario}"
      return 1
      ;;
  esac

  # shellcheck disable=SC2094
  jq -n \
    --arg output_path "$output_path" \
    --arg workflow_state "$workflow_state" \
    --arg guard_decision "$guard_decision" \
    --arg recommended_action "$recommended_action" \
    --arg reason "$reason" \
    --argjson policy_findings "$policy_findings" \
    '{
      schema_version: "franken-engine.remote-proof-gc-guard.v1",
      bundle_id: "bundle-1",
      guard_decision: $guard_decision,
      recommended_action: $recommended_action,
      reason: $reason,
      policy_findings: $policy_findings,
      salvage_summary: {
        workflow_state: $workflow_state,
        recovery_recommendation: "preserve",
        observed_process_truth: "fixture"
      },
      artifact_paths: {
        remote_proof_gc_guard_report_json: $output_path,
        report_md: "gc_guard_report.md"
      }
    }' >"$output_path"
}

write_pressure_fixture() {
  local output_path="$1"
  local scenario="$2"
  local advisory="compaction_first"
  local recommended_action="compact_before_eviction"
  local policy_findings='["compaction_first_remediation"]'

  case "$scenario" in
    stale_reservation|active_owner|manual_confirmation|ownership_contradiction|degraded_rch)
      ;;
    salvage_pinned)
      advisory="fail_closed"
      recommended_action="preserve_pinned_evidence"
      policy_findings='["salvage_pinned_blocks_eviction"]'
      ;;
    *)
      record_failure "unknown pressure scenario ${scenario}"
      return 1
      ;;
  esac

  # shellcheck disable=SC2094
  jq -n \
    --arg output_path "$output_path" \
    --arg advisory "$advisory" \
    --arg recommended_action "$recommended_action" \
    --argjson policy_findings "$policy_findings" \
    '{
      schema_version: "franken-engine.remote-proof-archive-pressure-scoreboard.v1",
      bundle_id: "bundle-1",
      pressure_level: "elevated",
      advisory: $advisory,
      recommended_action: $recommended_action,
      reason: "fixture scoreboard",
      class_counts: {
        hot_replay_critical: 0,
        warm_operator_inspectable: 1,
        salvage_pinned: (if $advisory == "fail_closed" then 1 else 0 end),
        cold_archival: 1
      },
      policy_findings: $policy_findings,
      artifact_paths: {
        remote_proof_archive_pressure_scoreboard_json: $output_path,
        report_md: "pressure_report.md"
      }
    }' >"$output_path"
}

write_reservations_fixture() {
  local output_path="$1"
  local scenario="$2"

  case "$scenario" in
    stale_reservation|degraded_rch|salvage_pinned)
      jq -n '{
        reservations: [
          {
            bead_id: "bd-sim-1",
            agent_id: "AgentStale",
            path_pattern: "target/sim",
            expires_ts: "2099-01-01T00:00:00Z"
          }
        ]
      }' >"$output_path"
      ;;
    active_owner)
      jq -n '{
        reservations: [
          {
            bead_id: "bd-sim-1",
            agent_id: "AgentOwner",
            path_pattern: "target/sim",
            expires_ts: "2099-01-01T00:00:00Z"
          }
        ]
      }' >"$output_path"
      ;;
    manual_confirmation)
      jq -n '{reservations: []}' >"$output_path"
      ;;
    ownership_contradiction)
      jq -n '{
        reservations: [
          {
            bead_id: "bd-sim-1",
            agent_id: "AgentBeta",
            path_pattern: "target/sim",
            expires_ts: "2099-01-01T00:00:00Z"
          }
        ]
      }' >"$output_path"
      ;;
    *)
      record_failure "unknown reservation scenario ${scenario}"
      return 1
      ;;
  esac
}

write_profiles_fixture() {
  local output_path="$1"
  local scenario="$2"

  case "$scenario" in
    stale_reservation|degraded_rch|salvage_pinned)
      jq -n '{agents:[{name:"AgentStale"},{name:"AgentRequester"}]}' >"$output_path"
      ;;
    active_owner)
      jq -n '{agents:[{name:"AgentOwner"},{name:"AgentRequester"}]}' >"$output_path"
      ;;
    manual_confirmation)
      jq -n '{agents:[{name:"AgentManual"},{name:"AgentRequester"}]}' >"$output_path"
      ;;
    ownership_contradiction)
      jq -n '{agents:[{name:"AgentAlpha"},{name:"AgentRequester"}]}' >"$output_path"
      ;;
    *)
      record_failure "unknown profiles scenario ${scenario}"
      return 1
      ;;
  esac
}

run_case() {
  local scenario="$1"
  local expected_action="$2"
  local expected_decision="$3"
  local expected_exit="$4"
  local work_dir
  work_dir="$(mktemp -d)"

  write_stale_lock_fixture "${work_dir}/stale.json" "$scenario"
  write_admission_fixture "${work_dir}/admission.json" "$scenario"
  write_lease_fixture "${work_dir}/lease.json" "$scenario"
  write_gc_guard_fixture "${work_dir}/gc_guard.json" "$scenario"
  write_pressure_fixture "${work_dir}/pressure.json" "$scenario"
  write_reservations_fixture "${work_dir}/reservations.json" "$scenario"
  write_profiles_fixture "${work_dir}/profiles.json" "$scenario"

  local rc=0
  "${simulator}" \
    --stale-lock-recommendations-json "${work_dir}/stale.json" \
    --admission-budget-plan-json "${work_dir}/admission.json" \
    --resource-lease-plan-json "${work_dir}/lease.json" \
    --gc-guard-report-json "${work_dir}/gc_guard.json" \
    --archive-pressure-scoreboard-json "${work_dir}/pressure.json" \
    --reservation-snapshot-json "${work_dir}/reservations.json" \
    --agent-profiles-json "${work_dir}/profiles.json" \
    --source-revision smoke \
    --output-dir "${work_dir}/out" >/dev/null 2>&1 || rc=$?
  if [[ "$rc" -ne "$expected_exit" ]]; then
    record_failure "${scenario}: exit ${rc} != ${expected_exit}"
    return 1
  fi

  local simulation_path="${work_dir}/out/lease_exchange_cancellation_salvage_simulation.json"
  jq -e --arg action "$expected_action" '.recommendations[0].simulated_action == $action' "$simulation_path" >/dev/null
  jq -e --arg decision "$expected_decision" '.decision == $decision' "$simulation_path" >/dev/null
  jq -e '.artifact_paths.commands_txt | type == "string"' "$simulation_path" >/dev/null
  if grep -E 'br update|release_file_reservations|pkill|kill ' "${work_dir}/out/commands.txt" >/dev/null 2>&1; then
    record_failure "${scenario}: commands.txt includes forbidden mutation hints"
    return 1
  fi
  record_pass "$scenario"
}

run_check() {
  jq -e '
    .schema_version == "franken-engine.swarm-lease-exchange-cancellation-salvage-simulator-contract.v1"
    and (.simulation_schema_version == "franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1")
  ' "$contract_json" >/dev/null

  run_case stale_reservation simulate_lease_exchange advisory 0
  run_case active_owner contact_owner_before_exchange manual_review_required 75
  run_case degraded_rch simulate_cancel_and_promote_salvage advisory 0
  run_case salvage_pinned preserve_pinned_evidence manual_review_required 75
  run_case manual_confirmation manual_confirmation_required manual_review_required 75
  run_case ownership_contradiction fail_closed_missing_ownership fail_closed 42
}

run_selftest() {
  local work_a work_b
  work_a="$(mktemp -d)"
  work_b="$(mktemp -d)"

  write_stale_lock_fixture "${work_a}/stale.json" stale_reservation
  write_admission_fixture "${work_a}/admission.json" stale_reservation
  write_lease_fixture "${work_a}/lease.json" stale_reservation
  write_gc_guard_fixture "${work_a}/gc_guard.json" stale_reservation
  write_pressure_fixture "${work_a}/pressure.json" stale_reservation
  write_reservations_fixture "${work_a}/reservations.json" stale_reservation
  write_profiles_fixture "${work_a}/profiles.json" stale_reservation

  cp "${work_a}/stale.json" "${work_b}/stale.json"
  cp "${work_a}/admission.json" "${work_b}/admission.json"
  cp "${work_a}/lease.json" "${work_b}/lease.json"
  cp "${work_a}/gc_guard.json" "${work_b}/gc_guard.json"
  cp "${work_a}/pressure.json" "${work_b}/pressure.json"
  cp "${work_a}/reservations.json" "${work_b}/reservations.json"
  cp "${work_a}/profiles.json" "${work_b}/profiles.json"

  "${simulator}" \
    --stale-lock-recommendations-json "${work_a}/stale.json" \
    --admission-budget-plan-json "${work_a}/admission.json" \
    --resource-lease-plan-json "${work_a}/lease.json" \
    --gc-guard-report-json "${work_a}/gc_guard.json" \
    --archive-pressure-scoreboard-json "${work_a}/pressure.json" \
    --reservation-snapshot-json "${work_a}/reservations.json" \
    --agent-profiles-json "${work_a}/profiles.json" \
    --source-revision selftest \
    --output-dir "${work_a}/out" >/dev/null

  "${simulator}" \
    --stale-lock-recommendations-json "${work_b}/stale.json" \
    --admission-budget-plan-json "${work_b}/admission.json" \
    --resource-lease-plan-json "${work_b}/lease.json" \
    --gc-guard-report-json "${work_b}/gc_guard.json" \
    --archive-pressure-scoreboard-json "${work_b}/pressure.json" \
    --reservation-snapshot-json "${work_b}/reservations.json" \
    --agent-profiles-json "${work_b}/profiles.json" \
    --source-revision selftest \
    --output-dir "${work_b}/out" >/dev/null

  local hash_a hash_b
  hash_a="$(jq -r '.hash_basis.simulation_hash' "${work_a}/out/lease_exchange_cancellation_salvage_simulation.json")"
  hash_b="$(jq -r '.hash_basis.simulation_hash' "${work_b}/out/lease_exchange_cancellation_salvage_simulation.json")"
  if [[ "$hash_a" != "$hash_b" ]]; then
    record_failure "selftest: simulation hash drift"
    return 1
  fi
  record_pass selftest
}

mode="${1:-check}"
case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode ${mode}"
    exit 64
    ;;
esac
