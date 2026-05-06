#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_OPERATOR_STATUS_REPORT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-operator-status}"
run_id="${SWARM_OPERATOR_STATUS_REPORT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_OPERATOR_STATUS_REPORT_RUN_DIR:-${artifact_root}/${run_id}}"
bead_id="${SWARM_OPERATOR_STATUS_REPORT_BEAD_ID:-bd-jw854}"
source_revision="${SWARM_OPERATOR_STATUS_REPORT_SOURCE_REVISION:-smoke-rev}"
agent_mail_status="unknown"
rch_status="unknown"
proof_index_status="unknown"

ready_json=""
in_progress_json=""
bv_plan_json=""
reservations_json=""
resource_decision_json=""
validation_plan_json=""
proof_index_json=""
proof_outcomes_json=""
stale_evidence_json=""
dirty_files_json=""
collision_receipt_json=""
proof_freshness_json=""
rch_incident_packet_json=""
resource_lease_plan_json=""
proof_cache_plan_json=""
qos_batch_plan_json=""
stale_lock_recommendations_json=""
staged_ownership_report_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_operator_status_report.sh [OPTIONS]

Builds a fixture-fed operator status report. Inputs are explicit JSON snapshots
from br/bv, Agent Mail, rch, validation plans, resource decisions, and proof
evidence. The script does not claim beads, edit tracker state, or query live
services by itself.

Options:
  --output-dir DIR
  --bead-id ID
  --source-revision REV
  --agent-mail-status ok|degraded|missing|unknown
  --rch-status ok|degraded|missing|unknown
  --proof-index-status ok|degraded|missing|unknown
  --ready-json FILE
  --in-progress-json FILE
  --bv-plan-json FILE
  --reservations-json FILE
  --resource-decision-json FILE
  --validation-plan-json FILE
  --proof-index-json FILE
  --proof-outcomes-json FILE
  --stale-evidence-json FILE
  --dirty-files-json FILE
  --collision-receipt-json FILE
  --proof-freshness-json FILE
  --rch-incident-packet-json FILE
  --resource-lease-plan-json FILE
  --proof-cache-plan-json FILE
  --qos-batch-plan-json FILE
  --stale-lock-recommendations-json FILE
  --staged-ownership-report-json FILE
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      run_dir="$2"
      shift 2
      ;;
    --bead-id)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      bead_id="$2"
      shift 2
      ;;
    --source-revision)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      source_revision="$2"
      shift 2
      ;;
    --agent-mail-status)
      agent_mail_status="$2"
      shift 2
      ;;
    --rch-status)
      rch_status="$2"
      shift 2
      ;;
    --proof-index-status)
      proof_index_status="$2"
      shift 2
      ;;
    --ready-json)
      ready_json="$2"
      shift 2
      ;;
    --in-progress-json)
      in_progress_json="$2"
      shift 2
      ;;
    --bv-plan-json)
      bv_plan_json="$2"
      shift 2
      ;;
    --reservations-json)
      reservations_json="$2"
      shift 2
      ;;
    --resource-decision-json)
      resource_decision_json="$2"
      shift 2
      ;;
    --validation-plan-json)
      validation_plan_json="$2"
      shift 2
      ;;
    --proof-index-json)
      proof_index_json="$2"
      shift 2
      ;;
    --proof-outcomes-json)
      proof_outcomes_json="$2"
      shift 2
      ;;
    --stale-evidence-json)
      stale_evidence_json="$2"
      shift 2
      ;;
    --dirty-files-json)
      dirty_files_json="$2"
      shift 2
      ;;
    --collision-receipt-json)
      collision_receipt_json="$2"
      shift 2
      ;;
    --proof-freshness-json)
      proof_freshness_json="$2"
      shift 2
      ;;
    --rch-incident-packet-json)
      rch_incident_packet_json="$2"
      shift 2
      ;;
    --resource-lease-plan-json)
      resource_lease_plan_json="$2"
      shift 2
      ;;
    --proof-cache-plan-json)
      proof_cache_plan_json="$2"
      shift 2
      ;;
    --qos-batch-plan-json)
      qos_batch_plan_json="$2"
      shift 2
      ;;
    --stale-lock-recommendations-json)
      stale_lock_recommendations_json="$2"
      shift 2
      ;;
    --staged-ownership-report-json)
      staged_ownership_report_json="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

mkdir -p "$run_dir"
status_path="${run_dir}/status.json"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

printf './scripts/swarm_operator_status_report.sh' >"$commands_path"
printf ' --output-dir %q' "$run_dir" >>"$commands_path"
printf '\n' >>"$commands_path"

json_or_default() {
  local path="$1"
  local default_json="$2"
  local label="$3"

  if [[ -z "$path" ]]; then
    printf '%s' "$default_json"
    return 0
  fi
  if [[ ! -f "$path" ]]; then
    printf 'swarm-operator-status missing %s file: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null; then
    printf 'swarm-operator-status invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -c . "$path"
}

ready_data="$(json_or_default "$ready_json" '[]' 'ready')"
in_progress_data="$(json_or_default "$in_progress_json" '[]' 'in-progress')"
bv_plan_data="$(json_or_default "$bv_plan_json" '{"plan":{"tracks":[]}}' 'bv-plan')"
reservations_data="$(json_or_default "$reservations_json" '[]' 'reservations')"
resource_decision_data="$(json_or_default "$resource_decision_json" '{"decision":"unknown","findings":[]}' 'resource-decision')"
validation_plan_data="$(json_or_default "$validation_plan_json" '{"decision":"unknown","commands":[],"omitted_commands":[]}' 'validation-plan')"
proof_index_data="$(json_or_default "$proof_index_json" '{"queries":[]}' 'proof-index')"
proof_outcomes_data="$(json_or_default "$proof_outcomes_json" '[]' 'proof-outcomes')"
stale_evidence_data="$(json_or_default "$stale_evidence_json" '[]' 'stale-evidence')"
dirty_files_data="$(json_or_default "$dirty_files_json" '[]' 'dirty-files')"
collision_receipt_data="$(json_or_default "$collision_receipt_json" '{"collision_risk":"none","conflicting_agents":[],"safe_alternatives":[],"reservation_recommendations":[],"conflicts":{"reservations":[],"dirty":[],"in_progress":[]}}' 'collision-receipt')"
proof_freshness_data="$(json_or_default "$proof_freshness_json" '{"freshness_state":"not_provided","reusable":null,"reason":"No proof freshness report was provided.","recommended_next_action":"Provide a proof freshness report before reusing prior proof artifacts."}' 'proof-freshness')"
rch_incident_packet_data="$(json_or_default "$rch_incident_packet_json" '{"status":"not_provided","failure_kind":"none","retry_safety":"not_required","recommended_next_action":"No rch incident packet was provided."}' 'rch-incident-packet')"
resource_lease_plan_status="missing"
proof_cache_plan_status="missing"
qos_batch_plan_status="missing"
stale_lock_recommendations_status="missing"
staged_ownership_report_status="missing"
if [[ -n "$resource_lease_plan_json" ]]; then resource_lease_plan_status="provided"; fi
if [[ -n "$proof_cache_plan_json" ]]; then proof_cache_plan_status="provided"; fi
if [[ -n "$qos_batch_plan_json" ]]; then qos_batch_plan_status="provided"; fi
if [[ -n "$stale_lock_recommendations_json" ]]; then stale_lock_recommendations_status="provided"; fi
if [[ -n "$staged_ownership_report_json" ]]; then staged_ownership_report_status="provided"; fi
resource_lease_plan_data="$(json_or_default "$resource_lease_plan_json" '{"schema_version":"franken-engine.swarm-resource-lease-plan.v1","lease_decision":"missing","reason":"No resource lease plan was provided.","findings":[],"safe_alternatives":[]}' 'resource-lease-plan')"
proof_cache_plan_data="$(json_or_default "$proof_cache_plan_json" '{"schema_version":"franken-engine.proof-reuse-cache-plan.v1","proof_cache_decision":"missing","reason":"No proof cache plan was provided.","cache_hit_artifacts":[],"required_refreshes":[],"invalid_artifacts":[],"invalidated_paths":[],"refresh_commands":[]}' 'proof-cache-plan')"
qos_batch_plan_data="$(json_or_default "$qos_batch_plan_json" '{"schema_version":"franken-engine.build-storm-batch-plan.v1","batch_decision":"missing","fairness_reason":"No build-storm QoS batch plan was provided.","admitted_commands":[],"deferred_commands":[],"retry_after_seconds":0}' 'qos-batch-plan')"
stale_lock_recommendations_data="$(json_or_default "$stale_lock_recommendations_json" '{"schema_version":"franken-engine.stale-lock-recommendations.v1","stale_lock_recommendations":[],"safe_to_reopen":[],"contact_first":[]}' 'stale-lock-recommendations')"
staged_ownership_report_data="$(json_or_default "$staged_ownership_report_json" '{"schema_version":"franken-engine.staged-ownership-report.v1","decision":"missing","offender_count":0,"offending_paths":[],"findings":[]}' 'staged-ownership-report')"

# shellcheck disable=SC2094
jq -n \
  --arg schema_version "franken-engine.swarm-operator-status-report.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg agent_mail_status "$agent_mail_status" \
  --arg rch_status "$rch_status" \
  --arg proof_index_status "$proof_index_status" \
  --arg resource_lease_plan_status "$resource_lease_plan_status" \
  --arg proof_cache_plan_status "$proof_cache_plan_status" \
  --arg qos_batch_plan_status "$qos_batch_plan_status" \
  --arg stale_lock_recommendations_status "$stale_lock_recommendations_status" \
  --arg staged_ownership_report_status "$staged_ownership_report_status" \
  --arg status_path "$status_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --argjson ready "$ready_data" \
  --argjson in_progress "$in_progress_data" \
  --argjson bv_plan "$bv_plan_data" \
  --argjson reservations "$reservations_data" \
  --argjson resource_decision "$resource_decision_data" \
  --argjson validation_plan "$validation_plan_data" \
  --argjson proof_index "$proof_index_data" \
  --argjson proof_outcomes "$proof_outcomes_data" \
  --argjson stale_evidence "$stale_evidence_data" \
  --argjson dirty_files "$dirty_files_data" \
  --argjson collision_receipt "$collision_receipt_data" \
  --argjson proof_freshness "$proof_freshness_data" \
  --argjson rch_incident_packet "$rch_incident_packet_data" \
  --argjson resource_lease_plan "$resource_lease_plan_data" \
  --argjson proof_cache_plan "$proof_cache_plan_data" \
  --argjson qos_batch_plan "$qos_batch_plan_data" \
  --argjson stale_lock_recommendations "$stale_lock_recommendations_data" \
  --argjson staged_ownership_report "$staged_ownership_report_data" \
  '
  def degraded($component; $status; $impact; $remediation):
    if ($status == "ok") then empty
    else {component: $component, status: $status, impact: $impact, remediation: $remediation}
    end;
  def bead_row:
    {
      id: .id,
      title: .title,
      priority: (.priority // null),
      status: (.status // null),
      assignee: (.assignee // null)
    };
  def recommendation($action; $bead; $reason):
    {action: $action, bead_id: $bead, reason: $reason};
  def nonempty_or($primary; $fallback):
    if (($primary // []) | length) > 0 then $primary else ($fallback // []) end;
  def bounded($items): (($items // [])[0:8]);
  def strings($items): bounded(($items // []) | map(tostring));

  ($ready | map(bead_row) | sort_by(.priority // 999, .id)) as $ready_rows
  | ($in_progress | map(bead_row) | sort_by(.id)) as $in_progress_rows
  | ($dirty_files | map(select(.reserved == true or .overlaps_ready == true))) as $dirty_reserved
  | ($stale_evidence | map(select((.stale // false) == true))) as $stale
  | ($proof_outcomes | map(select((.status // "") | test("fail|blocked|stale")))) as $bad_proofs
  | ([($bv_plan.plan.tracks // [])[]?.items[]? | select((.status // "") == "blocked")]) as $blocked_items
  | ($validation_plan.commands // []
      | map(select(.predicted_cost? != null)
        | {
            command_id: (.command_id // null),
            display: (.display // null),
            command_kind: (.command_kind // null),
            cost_class: (.predicted_cost.cost_class // "unknown"),
            cost_state: (.predicted_cost.state // "unknown"),
            sample_count: (.predicted_cost.sample_count // 0),
            elapsed_ms_p50: (.predicted_cost.elapsed_ms_p50 // 0),
            elapsed_ms_max: (.predicted_cost.elapsed_ms_max // 0),
            compiled_target_count_max: (.predicted_cost.compiled_target_count_max // 0),
            linked_target_count_max: (.predicted_cost.linked_target_count_max // 0),
            risk_flags: (.risk_flags // []),
            cost_evidence: (.cost_evidence // {})
          })) as $cost_rows
  | ($cost_rows
      | map(select(
          (.cost_class // "unknown") == "high"
          or (((.risk_flags // []) | map(select(test("high|failed|fallback|unknown|stale|mismatched|contradictory"))) | length) > 0)
          or (((.cost_evidence.status // "") | test("unknown|stale|mismatched|contradictory|failed")))
        ))) as $high_cost_rows
  | ($validation_plan.proof_cost_budgets // []) as $proof_cost_budgets
  | ($validation_plan.collision_risk // $collision_receipt.collision_risk // "none") as $collision_risk
  | ({
      risk: $collision_risk,
      conflicting_agents: nonempty_or($validation_plan.conflicting_agents; $collision_receipt.conflicting_agents),
      safe_alternatives: nonempty_or($validation_plan.safe_alternatives; $collision_receipt.safe_alternatives),
      reservation_recommendations: nonempty_or($validation_plan.reservation_recommendations; $collision_receipt.reservation_recommendations),
      conflicts: ($collision_receipt.conflicts // {reservations: [], dirty: [], in_progress: []})
    }) as $collision_summary
  | ({
      state: ($proof_freshness.freshness_state // "not_provided"),
      reusable: (if ($proof_freshness | has("reusable")) then $proof_freshness.reusable else null end),
      artifact_id: ($proof_freshness.proof_artifact_id // null),
      artifact_path: ($proof_freshness.artifact_path // null),
      reason: ($proof_freshness.reason // null),
      recommended_next_action: ($proof_freshness.recommended_next_action // null),
      covered_paths: ($proof_freshness.covered_paths // []),
      changed_paths: ($proof_freshness.changed_paths // [])
    }) as $proof_freshness_summary
  | (if (($rch_incident_packet.status // "not_provided") == "not_provided"
          and ($rch_incident_packet.failure_kind // "none") == "none") then
      []
    else
      [{
        incident_id: ($rch_incident_packet.incident_id // null),
        status: ($rch_incident_packet.status // "unknown"),
        failure_kind: ($rch_incident_packet.failure_kind // "unknown"),
        retry_safety: ($rch_incident_packet.retry_safety // "unknown"),
        classification_confidence: ($rch_incident_packet.classification_confidence // "unknown"),
        worker_id: ($rch_incident_packet.worker_id // null),
        command: ($rch_incident_packet.command // null),
        target_dir: ($rch_incident_packet.target_dir // null),
        recommended_next_action: ($rch_incident_packet.recommended_next_action // null)
      }]
    end) as $rch_incident_summaries
  | ({
      artifact_status: $resource_lease_plan_status,
      severity: (
        if $resource_lease_plan_status == "missing" then "warning"
        elif (($resource_lease_plan.lease_decision // "") | IN("admit")) then "ok"
        elif (($resource_lease_plan.lease_decision // "") | IN("admit_narrow", "defer")) then "warning"
        else "critical"
        end
      ),
      lease_decision: ($resource_lease_plan.lease_decision // "missing"),
      reason: ($resource_lease_plan.reason // null),
      agent_id: ($resource_lease_plan.agent_id // null),
      bead_id: ($resource_lease_plan.bead_id // null),
      requested_command: ($resource_lease_plan.requested_command // null),
      target_dir: ($resource_lease_plan.target_dir // null),
      assigned_worker: ($resource_lease_plan.assigned_worker // null),
      safe_alternatives: bounded($resource_lease_plan.safe_alternatives),
      findings: bounded($resource_lease_plan.findings),
      actionable_commands: (
        if $resource_lease_plan_status == "missing" then
          ["./scripts/swarm_resource_lease_planner.sh --agent-id <agent-id> --bead-id <bead-id> --requested-command <command> --target-dir <target-dir>"]
        elif (($resource_lease_plan.lease_decision // "") | IN("admit", "admit_narrow")) then
          []
        else
          strings($resource_lease_plan.safe_alternatives)
        end
      )
    }) as $resource_leases_summary
  | ({
      artifact_status: $proof_cache_plan_status,
      severity: (
        if $proof_cache_plan_status == "missing" then "warning"
        elif (($proof_cache_plan.proof_cache_decision // "") == "cache_hit") then "ok"
        elif (($proof_cache_plan.proof_cache_decision // "") | IN("partial_refresh", "refresh_required")) then "warning"
        else "critical"
        end
      ),
      proof_cache_decision: ($proof_cache_plan.proof_cache_decision // "missing"),
      reason: ($proof_cache_plan.reason // null),
      cache_hit_count: (($proof_cache_plan.cache_hit_artifacts // []) | length),
      refresh_count: (($proof_cache_plan.required_refreshes // []) | length),
      invalid_count: (($proof_cache_plan.invalid_artifacts // []) | length),
      cache_hit_artifacts: bounded($proof_cache_plan.cache_hit_artifacts),
      required_refreshes: bounded($proof_cache_plan.required_refreshes),
      invalid_artifacts: bounded($proof_cache_plan.invalid_artifacts),
      invalidated_paths: bounded($proof_cache_plan.invalidated_paths),
      refresh_commands: strings($proof_cache_plan.refresh_commands),
      actionable_commands: (
        if $proof_cache_plan_status == "missing" then
          ["./scripts/proof_reuse_cache_planner.sh --proof-index-json <proof-index.json> --freshness-report <freshness.json>"]
        else
          strings($proof_cache_plan.refresh_commands)
        end
      )
    }) as $proof_cache_summary
  | ({
      artifact_status: $qos_batch_plan_status,
      severity: (
        if $qos_batch_plan_status == "missing" then "warning"
        elif (($qos_batch_plan.batch_decision // "") == "planned" and (($qos_batch_plan.deferred_commands // []) | length) == 0) then "ok"
        elif (($qos_batch_plan.batch_decision // "") | IN("planned", "all_deferred")) then "warning"
        else "critical"
        end
      ),
      batch_id: ($qos_batch_plan.batch_id // null),
      batch_decision: ($qos_batch_plan.batch_decision // "missing"),
      fairness_reason: ($qos_batch_plan.fairness_reason // null),
      max_parallel_heavy: ($qos_batch_plan.max_parallel_heavy // null),
      retry_after_seconds: ($qos_batch_plan.retry_after_seconds // 0),
      admitted_count: (($qos_batch_plan.admitted_commands // []) | length),
      deferred_count: (($qos_batch_plan.deferred_commands // []) | length),
      admitted_commands: bounded($qos_batch_plan.admitted_commands),
      deferred_commands: bounded($qos_batch_plan.deferred_commands),
      actionable_commands: (
        if $qos_batch_plan_status == "missing" then
          ["./scripts/build_storm_qos_batch_planner.sh --pending-requests-json <pending.json> --resource-lease-plans-json <leases.json> --proof-cost-history-json <costs.json> --rch-workers-json <workers.json>"]
        else
          strings((($qos_batch_plan.admitted_commands // []) + ($qos_batch_plan.deferred_commands // [])) | map(.command // empty))
        end
      )
    }) as $qos_batches_summary
  | ({
      artifact_status: $stale_lock_recommendations_status,
      severity: (
        if $stale_lock_recommendations_status == "missing" then "warning"
        elif ((($stale_lock_recommendations.safe_to_reopen // []) | length) == 0 and (($stale_lock_recommendations.contact_first // []) | length) == 0) then "ok"
        else "warning"
        end
      ),
      recommendation_count: (($stale_lock_recommendations.stale_lock_recommendations // []) | length),
      safe_to_reopen_count: (($stale_lock_recommendations.safe_to_reopen // []) | length),
      contact_first_count: (($stale_lock_recommendations.contact_first // []) | length),
      safe_to_reopen: bounded($stale_lock_recommendations.safe_to_reopen),
      contact_first: bounded($stale_lock_recommendations.contact_first),
      recommendations: bounded($stale_lock_recommendations.stale_lock_recommendations),
      actionable_commands: (
        if $stale_lock_recommendations_status == "missing" then
          ["./scripts/stale_lock_stalled_bead_recommender.sh --in-progress-json <in-progress.json>"]
        else
          strings([
            ($stale_lock_recommendations.stale_lock_recommendations // [])[]?
            | (.suggested_br_commands // [])[]?,
              (.contact_commands // [])[]?
          ])
        end
      )
    }) as $stale_lock_summary
  | ({
      artifact_status: $staged_ownership_report_status,
      severity: (
        if $staged_ownership_report_status == "missing" then "warning"
        elif (($staged_ownership_report.decision // "") == "pass") then "ok"
        elif (($staged_ownership_report.decision // "") == "pass_degraded") then "warning"
        else "critical"
        end
      ),
      decision: ($staged_ownership_report.decision // "missing"),
      staged_path_count: ($staged_ownership_report.staged_path_count // 0),
      offender_count: ($staged_ownership_report.offender_count // 0),
      scoped_beads_issue_ids: bounded($staged_ownership_report.scoped_beads_issue_ids),
      offending_paths: bounded($staged_ownership_report.offending_paths),
      findings: bounded($staged_ownership_report.findings),
      actionable_commands: (
        if $staged_ownership_report_status == "missing" then
          ["./scripts/staged_ownership_contamination_guard.sh --agent-id <agent-id> --bead-id <bead-id> --allowed-path <path>"]
        else
          strings(($staged_ownership_report.offending_paths // []) | map(.remediation // empty))
        end
      )
    }) as $staged_contamination_summary
  | ([
      degraded("agent_mail"; $agent_mail_status; "reservation and inbox data may be incomplete"; "Use bead assignee and dirty paths as degraded fallback evidence."),
      degraded("rch"; $rch_status; "remote proof routing may be unavailable"; "Defer heavy validation until rch status is ok or use script-only proof."),
      degraded("proof_evidence_index"; $proof_index_status; "proof queries may be incomplete"; "Use explicit proof outcome snapshots until bd-p03vs lands.")
    ]
    + (if (($validation_plan.decision // "") == "fail_closed") then
        [{component: "validation_plan", status: "fail_closed", impact: "planned validation cannot run safely", remediation: "Fix unknown path mappings or ownership before running validation."}]
      else [] end)
    + (if (($resource_decision.decision // "") | IN("defer", "fail_closed")) then
        [{component: "resource_governor", status: ($resource_decision.decision // "unknown"), impact: "resource admission is not green", remediation: "Follow resource-governor remediation before starting heavy validation."}]
      else [] end)
    + ($dirty_reserved | map({component: "dirty_reserved_file", status: "degraded", impact: (.path + " is dirty or reserved"), remediation: "Avoid this file or coordinate with the holder."}))
    + ($stale | map({component: "stale_proof_artifact", status: "degraded", impact: (.artifact_id + " is stale"), remediation: "Refresh or mark the proof stale before relying on it."}))
    + ($bad_proofs | map({component: "proof_outcome", status: (.status // "degraded"), impact: (.bead_id + " proof is not passing"), remediation: "Inspect the proof outcome before recommending dependent work."}))
    + ($blocked_items | map({component: "blocked_bead_chain", status: "blocked", impact: (.id + " is blocked in the bv track"), remediation: "Inspect dependencies before recommending this bead."}))
    + ($high_cost_rows | map({component: "predictive_cost", status: (.cost_class // "unknown"), impact: ((.command_id // "unknown_command") + " has elevated predicted validation cost"), remediation: "Narrow the command, defer until resource pressure clears, or preserve the high-cost receipt."}))
    + (if $resource_lease_plan_status == "missing" then
        [{component: "resource_leases", status: "missing", impact: "resource lease admission artifact is missing", remediation: "Provide --resource-lease-plan-json before publishing the operator status feed."}]
      elif $resource_leases_summary.severity != "ok" then
        [{component: "resource_leases", status: $resource_leases_summary.lease_decision, impact: "resource lease admission is not fully green", remediation: ($resource_leases_summary.reason // "Inspect the resource lease plan before running validation.")}]
      else [] end)
    + (if $proof_cache_plan_status == "missing" then
        [{component: "proof_cache", status: "missing", impact: "proof reuse cache artifact is missing", remediation: "Provide --proof-cache-plan-json before reusing prior proof artifacts."}]
      elif $proof_cache_summary.severity != "ok" then
        [{component: "proof_cache", status: $proof_cache_summary.proof_cache_decision, impact: "proof cache does not report a clean cache hit", remediation: ($proof_cache_summary.reason // "Refresh proof artifacts before relying on them.")}]
      else [] end)
    + (if $qos_batch_plan_status == "missing" then
        [{component: "qos_batches", status: "missing", impact: "build-storm QoS batch artifact is missing", remediation: "Provide --qos-batch-plan-json before publishing admission state."}]
      elif $qos_batches_summary.severity != "ok" then
        [{component: "qos_batches", status: $qos_batches_summary.batch_decision, impact: "one or more validation requests are deferred or the batch is unavailable", remediation: ($qos_batches_summary.fairness_reason // "Inspect QoS batch plan before admitting more heavy proof work.")}]
      else [] end)
    + (if $stale_lock_recommendations_status == "missing" then
        [{component: "stale_lock_recommendations", status: "missing", impact: "stale-lock recommendation artifact is missing", remediation: "Provide --stale-lock-recommendations-json before reopening stalled beads."}]
      elif $stale_lock_summary.severity != "ok" then
        [{component: "stale_lock_recommendations", status: "attention", impact: "stalled beads require reopen or contact-first action", remediation: "Follow the stale-lock recommendation commands before changing assignees."}]
      else [] end)
    + (if $staged_ownership_report_status == "missing" then
        [{component: "staged_contamination", status: "missing", impact: "staged ownership guard artifact is missing", remediation: "Provide --staged-ownership-report-json before commit or closeout."}]
      elif $staged_contamination_summary.severity != "ok" then
        [{component: "staged_contamination", status: $staged_contamination_summary.decision, impact: "staged paths are contaminated or only degraded ownership evidence is available", remediation: "Run the staged ownership guard and unstage offending paths before commit."}]
      else [] end)
    + (if ($collision_summary.risk != "none") then
        [{component: "collision_risk", status: $collision_summary.risk, impact: "planned work may collide with another agent or dirty surface", remediation: "Coordinate with listed agents or use safe alternatives before editing."}]
      else [] end)
    + (if (($proof_freshness_summary.state | IN("fresh", "not_provided"))
            and ($proof_freshness_summary.reusable == true or $proof_freshness_summary.reusable == null)) then
        []
      else
        [{component: "proof_freshness", status: $proof_freshness_summary.state, impact: "prior proof evidence is not reusable", remediation: ($proof_freshness_summary.recommended_next_action // "Refresh the proof before relying on it.")}]
      end)
    + ($rch_incident_summaries | map(select((.status // "") != "pass") | {component: "rch_incident_packet", status: (.failure_kind // "unknown"), impact: "rch proof execution has an incident packet", remediation: (.recommended_next_action // "Inspect the packet before retrying.")}))
    ) as $degraded
  | {
      schema_version: $schema_version,
      bead_id: $bead_id,
      source_revision: $source_revision,
      status: (if ($degraded | length) == 0 then "healthy" else "degraded" end),
      tui_ready: true,
      dashboard_contract: {
        schema_version: "franken-engine.swarm-predictive-dashboard.v1",
        contract_doc: "docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md",
        contract_json: "docs/swarm_predictive_dashboard_contract_v1.json",
        renderer: {
          provider: "/dp/frankentui",
          shipped_in_franken_engine: false,
          local_renderer: false
        }
      },
      summary: {
        ready_count: ($ready_rows | length),
        in_progress_count: ($in_progress_rows | length),
        reservation_count: ($reservations | length),
        degraded_count: ($degraded | length),
        planned_command_count: (($validation_plan.commands // []) | length),
        predictive_cost_command_count: ($cost_rows | length),
        high_cost_command_count: ($high_cost_rows | length),
        proof_cost_budget_count: ($proof_cost_budgets | length),
        stale_evidence_count: ($stale | length),
        dirty_reserved_count: ($dirty_reserved | length),
        blocked_bead_count: ($blocked_items | length),
        collision_risk: $collision_summary.risk,
        rch_incident_count: ($rch_incident_summaries | length),
        resource_lease_decision: $resource_leases_summary.lease_decision,
        proof_cache_decision: $proof_cache_summary.proof_cache_decision,
        qos_batch_decision: $qos_batches_summary.batch_decision,
        qos_admitted_count: $qos_batches_summary.admitted_count,
        qos_deferred_count: $qos_batches_summary.deferred_count,
        stale_lock_safe_to_reopen_count: $stale_lock_summary.safe_to_reopen_count,
        stale_lock_contact_first_count: $stale_lock_summary.contact_first_count,
        staged_contamination_decision: $staged_contamination_summary.decision,
        staged_contamination_offender_count: $staged_contamination_summary.offender_count
      },
      services: {
        agent_mail: $agent_mail_status,
        rch: $rch_status,
        proof_evidence_index: $proof_index_status
      },
      ready_beads: $ready_rows,
      in_progress_beads: $in_progress_rows,
      bv_tracks: ($bv_plan.plan.tracks // []),
      active_reservations: ($reservations | sort_by(.path // .path_pattern // "")),
      resource_decision: $resource_decision,
      validation_plan: {
        decision: ($validation_plan.decision // "unknown"),
        collision_risk: ($validation_plan.collision_risk // null),
        risk_flags: ($validation_plan.risk_flags // []),
        commands: ($validation_plan.commands // []),
        omitted_commands: ($validation_plan.omitted_commands // []),
        proof_cost_budgets: $proof_cost_budgets,
        conflicting_agents: ($validation_plan.conflicting_agents // []),
        safe_alternatives: ($validation_plan.safe_alternatives // [])
      },
      proof_evidence_index: $proof_index,
      proof_outcomes: ($proof_outcomes | sort_by(.bead_id // "", .artifact_id // "")),
      stale_evidence: ($stale_evidence | sort_by(.artifact_id // "")),
      dirty_files: ($dirty_files | sort_by(.path)),
      predictive_dashboard: {
        schema_version: "franken-engine.swarm-predictive-dashboard.v1",
        renderer_contract: {
          provider: "/dp/frankentui",
          shipped_in_franken_engine: false,
          local_renderer: false
        },
        predictive_cost: {
          status: (if ($high_cost_rows | length) == 0 then "nominal" else "elevated" end),
          commands: ($cost_rows | sort_by(.command_id // "")),
          high_risk_commands: ($high_cost_rows | sort_by(.command_id // "")),
          proof_cost_budgets: $proof_cost_budgets
        },
        collision_risk: $collision_summary,
        proof_freshness: $proof_freshness_summary,
        rch_incidents: {
          status: (
            if ($rch_incident_summaries | length) == 0 then "none"
            elif any($rch_incident_summaries[]; (.status // "") != "pass") then "degraded"
            else "observed"
            end
          ),
          incidents: $rch_incident_summaries
        },
        resource_leases: $resource_leases_summary,
        proof_cache: $proof_cache_summary,
        qos_batches: $qos_batches_summary,
        stale_lock_recommendations: $stale_lock_summary,
        staged_contamination: $staged_contamination_summary,
        fixture_contract: {
          golden_cases: ["healthy", "degraded", "stale_proof", "high_cost", "collision_risk", "overloaded"],
          intended_renderer_repo: "/dp/frankentui",
          local_tui_renderer: false
        }
      },
      degraded: $degraded,
      recommendations: (
        if $staged_contamination_summary.severity == "critical" then
          [recommendation("reject_staged_contamination"; null; "staged ownership guard reports contamination")]
        elif $resource_leases_summary.severity == "critical" then
          [recommendation("fix_resource_lease"; null; "resource lease planner denied or failed closed")]
        elif $proof_cache_summary.severity == "critical" then
          [recommendation("fix_proof_cache"; null; "proof reuse cache planner failed closed")]
        elif ($dirty_reserved | length) != 0 then
          [recommendation("avoid_dirty_reserved_files"; null; "dirty or reserved files overlap active work")]
        elif ($stale_lock_summary.safe_to_reopen_count > 0) then
          [recommendation("reopen_stale_beads"; $stale_lock_summary.safe_to_reopen[0]; "stale-lock recommender reports a safe reopen candidate")]
        elif ($stale_lock_summary.contact_first_count > 0) then
          [recommendation("contact_stalled_owner"; $stale_lock_summary.contact_first[0]; "stale-lock recommender requires contact before reopening")]
        elif ($collision_summary.risk != "none") then
          [recommendation("coordinate_collision_risk"; null; "planned dashboard feed reports collision risk")]
        elif $proof_cache_summary.severity == "warning" then
          [recommendation("refresh_or_partition_proof_cache"; null; "proof cache requires refresh or partial refresh")]
        elif $qos_batches_summary.deferred_count > 0 then
          [recommendation("respect_qos_batch_defer"; null; "QoS batch deferred lower-ranked or over-budget validation work")]
        elif $resource_leases_summary.severity == "warning" then
          [recommendation("treat_resource_lease_as_degraded"; null; "resource lease planner admitted only in degraded or deferred mode")]
        elif $staged_contamination_summary.severity == "warning" then
          [recommendation("refresh_staged_ownership_evidence"; null; "staged ownership guard is degraded or missing")]
        elif ($high_cost_rows | length) != 0 then
          [recommendation("narrow_high_cost_validation"; null; "predicted validation cost is elevated")]
        elif ((($proof_freshness_summary.state | IN("fresh", "not_provided"))
                and ($proof_freshness_summary.reusable == true or $proof_freshness_summary.reusable == null)) | not) then
          [recommendation("refresh_stale_proof"; null; "proof freshness gate reports non-reusable evidence")]
        elif (($rch_incident_summaries | map(select((.status // "") != "pass")) | length) != 0) then
          [recommendation("inspect_rch_incident_packet"; null; "rch incident packet is degraded")]
        elif ($agent_mail_status != "ok") then
          [recommendation("use_degraded_coordination"; null; "Agent Mail is not healthy")]
        elif (($resource_decision.decision // "") == "admit" or ($resource_decision.decision // "") == "admit_narrow") and ($ready_rows | length) > 0 then
          [recommendation("pick_next_ready_bead"; $ready_rows[0].id; "resource governor admits validation and bead is ready")]
        elif (($resource_decision.decision // "") == "defer") then
          [recommendation("defer_heavy_validation"; null; "resource governor reports pressure")]
        else
          [recommendation("inspect_degraded_fields"; null; "one or more required status surfaces are degraded")]
        end
      ),
      artifact_paths: {
        status_json: $status_path,
        commands_txt: $commands_path,
        report_md: $report_path
      }
    }
  ' >"$status_path"

{
  printf '# Swarm Operator Status\n\n'
  printf -- "- Status: \`%s\`\n" "$(jq -r '.status' "$status_path")"
  printf -- "- Ready beads: \`%s\`\n" "$(jq '.summary.ready_count' "$status_path")"
  printf -- "- In progress: \`%s\`\n" "$(jq '.summary.in_progress_count' "$status_path")"
  printf -- "- Degraded fields: \`%s\`\n\n" "$(jq '.summary.degraded_count' "$status_path")"
  printf -- "- Dashboard contract: \`%s\` via \`%s\`\n" "$(jq -r '.dashboard_contract.schema_version' "$status_path")" "$(jq -r '.dashboard_contract.renderer.provider' "$status_path")"
  printf -- "- High-cost commands: \`%s\`\n" "$(jq '.summary.high_cost_command_count' "$status_path")"
  printf -- "- Collision risk: \`%s\`\n" "$(jq -r '.summary.collision_risk' "$status_path")"
  printf -- "- RCH incidents: \`%s\`\n\n" "$(jq '.summary.rch_incident_count' "$status_path")"
  jq -r '.recommendations[] | "- `" + .action + "`" + (if .bead_id == null then "" else " for `" + .bead_id + "`" end) + ": " + .reason' "$status_path"
  if [[ "$(jq '.degraded | length' "$status_path")" -ne 0 ]]; then
    printf '\n## Degraded\n\n'
    jq -r '.degraded[] | "- `" + .component + "` `" + .status + "`: " + .impact + ". " + .remediation' "$status_path"
  fi
} >"$report_path"

printf 'swarm_operator_status_report=%s\n' "$status_path"
printf 'swarm_operator_status_markdown=%s\n' "$report_path"
