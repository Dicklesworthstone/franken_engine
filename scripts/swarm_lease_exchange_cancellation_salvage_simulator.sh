#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_LEASE_EXCHANGE_CANCELLATION_SALVAGE_SIMULATOR_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-lease-exchange-cancellation-salvage-simulator}"
run_id="${SWARM_LEASE_EXCHANGE_CANCELLATION_SALVAGE_SIMULATOR_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_LEASE_EXCHANGE_CANCELLATION_SALVAGE_SIMULATOR_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

stale_lock_recommendations_json=""
admission_budget_plan_json=""
resource_lease_plan_json=""
gc_guard_report_json=""
archive_pressure_scoreboard_json=""
reservation_snapshot_json=""
agent_profiles_json=""
source_revision=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_lease_exchange_cancellation_salvage_simulator.sh --stale-lock-recommendations-json FILE --admission-budget-plan-json FILE --resource-lease-plan-json FILE --gc-guard-report-json FILE --archive-pressure-scoreboard-json FILE [OPTIONS]

Builds a deterministic counterfactual report for lease exchange and proof
cancellation salvage promotion. The simulator is report-only. It must not call
br, mutate reservations, kill processes, or change worker state.

Required:
  --stale-lock-recommendations-json FILE
  --admission-budget-plan-json FILE
  --resource-lease-plan-json FILE
  --gc-guard-report-json FILE
  --archive-pressure-scoreboard-json FILE

Optional Agent Mail compatibility inputs:
  --reservation-snapshot-json FILE
  --agent-profiles-json FILE
  --source-revision REV
  --output-dir DIR

Artifacts:
  lease_exchange_cancellation_salvage_simulation.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  advisory report generated without fail-closed ownership contradictions
  42 fail-closed due to missing or contradictory ownership evidence
  75 deterministic manual-review posture without ownership contradiction
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --stale-lock-recommendations-json)
      stale_lock_recommendations_json="${2:-}"
      shift 2
      ;;
    --admission-budget-plan-json)
      admission_budget_plan_json="${2:-}"
      shift 2
      ;;
    --resource-lease-plan-json)
      resource_lease_plan_json="${2:-}"
      shift 2
      ;;
    --gc-guard-report-json)
      gc_guard_report_json="${2:-}"
      shift 2
      ;;
    --archive-pressure-scoreboard-json)
      archive_pressure_scoreboard_json="${2:-}"
      shift 2
      ;;
    --reservation-snapshot-json)
      reservation_snapshot_json="${2:-}"
      shift 2
      ;;
    --agent-profiles-json)
      agent_profiles_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
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

if [[ -z "$stale_lock_recommendations_json" || -z "$admission_budget_plan_json" || -z "$resource_lease_plan_json" || -z "$gc_guard_report_json" || -z "$archive_pressure_scoreboard_json" ]]; then
  printf 'simulator requires all five primary JSON inputs\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm lease-exchange simulation\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm lease-exchange simulation\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
simulation_path="${run_dir}/lease_exchange_cancellation_salvage_simulation.json"
simulation_tmp="${simulation_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
stale_normalized="${run_dir}/stale_lock_recommendations.normalized.json"
admission_normalized="${run_dir}/swarm_admission_budget_plan.normalized.json"
lease_normalized="${run_dir}/resource_lease_plan.normalized.json"
gc_normalized="${run_dir}/remote_proof_gc_guard.normalized.json"
scoreboard_normalized="${run_dir}/archive_pressure_scoreboard.normalized.json"
reservations_normalized="${run_dir}/reservation_snapshot.normalized.json"
profiles_normalized="${run_dir}/agent_profiles.normalized.json"
: >"$events_path"

printf './scripts/swarm_lease_exchange_cancellation_salvage_simulator.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

json_input() {
  local path="$1"
  local default_json="$2"
  local output_path="$3"
  local label="$4"
  local required="$5"

  if [[ -z "$path" ]]; then
    if [[ "$required" == "true" ]]; then
      printf 'simulator missing required %s JSON\n' "$label" >&2
      exit 64
    fi
    printf '%s\n' "$default_json" >"$output_path"
    printf 'missing'
    return 0
  fi
  if [[ ! -f "$path" ]]; then
    printf 'simulator missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'simulator invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -c . "$path" >"$output_path"
  printf 'provided'
}

validate_shape() {
  local file="$1"
  local expr="$2"
  local label="$3"

  if ! jq -e "$expr" "$file" >/dev/null 2>&1; then
    printf 'simulator invalid %s shape\n' "$label" >&2
    exit 64
  fi
}

stale_status="$(json_input "$stale_lock_recommendations_json" '{}' "$stale_normalized" 'stale lock recommendations' true)"
admission_status="$(json_input "$admission_budget_plan_json" '{}' "$admission_normalized" 'admission budget plan' true)"
lease_status="$(json_input "$resource_lease_plan_json" '{}' "$lease_normalized" 'resource lease plan' true)"
gc_status="$(json_input "$gc_guard_report_json" '{}' "$gc_normalized" 'remote proof GC guard' true)"
scoreboard_status="$(json_input "$archive_pressure_scoreboard_json" '{}' "$scoreboard_normalized" 'archive pressure scoreboard' true)"
reservation_status="$(json_input "$reservation_snapshot_json" '{"reservations":[]}' "$reservations_normalized" 'reservation snapshot' false)"
profiles_status="$(json_input "$agent_profiles_json" '{"agents":[]}' "$profiles_normalized" 'agent profiles' false)"

validate_shape "$stale_normalized" '
  .schema_version == "franken-engine.stale-lock-recommendations.v1"
  and (.stale_lock_recommendations | type == "array")
' 'stale lock recommendations'
validate_shape "$admission_normalized" '
  .schema_version == "franken-engine.swarm-admission-budget-plan.v1"
  and (.budget_profile | type == "string")
  and (.recommendations | type == "array")
' 'admission budget plan'
validate_shape "$lease_normalized" '
  .schema_version == "franken-engine.swarm-resource-lease-plan.v1"
  and (.lease_decision | type == "string")
  and (.reason | type == "string")
' 'resource lease plan'
validate_shape "$gc_normalized" '
  .schema_version == "franken-engine.remote-proof-gc-guard.v1"
  and (.guard_decision | type == "string")
  and (.recommended_action | type == "string")
  and (.salvage_summary | type == "object")
' 'remote proof GC guard'
validate_shape "$scoreboard_normalized" '
  .schema_version == "franken-engine.remote-proof-archive-pressure-scoreboard.v1"
  and (.advisory | type == "string")
  and (.recommended_action | type == "string")
  and (.policy_findings | type == "array")
' 'archive pressure scoreboard'
if [[ "$reservation_status" == "provided" ]]; then
  validate_shape "$reservations_normalized" '
    ((.reservations? | type) == "array") or (type == "array")
  ' 'reservation snapshot'
fi
if [[ "$profiles_status" == "provided" ]]; then
  validate_shape "$profiles_normalized" '
    ((.agents? | type) == "array") or (type == "array")
  ' 'agent profiles'
fi

jq -n \
  --slurpfile stale "$stale_normalized" \
  --slurpfile admission "$admission_normalized" \
  --slurpfile lease "$lease_normalized" \
  --slurpfile gc "$gc_normalized" \
  --slurpfile scoreboard "$scoreboard_normalized" \
  --slurpfile reservations "$reservations_normalized" \
  --slurpfile profiles "$profiles_normalized" \
  --arg schema_version "franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1" \
  --arg source_revision "$source_revision" \
  --arg stale_status "$stale_status" \
  --arg admission_status "$admission_status" \
  --arg lease_status "$lease_status" \
  --arg gc_status "$gc_status" \
  --arg scoreboard_status "$scoreboard_status" \
  --arg reservation_status "$reservation_status" \
  --arg profiles_status "$profiles_status" \
  '
  def arr($x; $name):
    if ($x | type) == "array" then $x else ($x[$name] // []) end;
  def low($x): (($x // "unknown") | tostring | ascii_downcase);
  def has_reason($row; $reason): any(($row.reasons // [])[]?; . == $reason);
  def admission_rows: ($admission[0].recommendations // []);
  def stale_rows: ($stale[0].stale_lock_recommendations // []);
  def reservation_rows: arr($reservations[0]; "reservations");
  def profile_rows: arr($profiles[0]; "agents");
  def profile_names:
    [profile_rows[]? | (.name // .agent_name // "") | select(. != "")] | unique | sort;
  def stale_row($bead_id):
    first(stale_rows[]? | select((.bead_id // "") == $bead_id));
  def active_holders($bead_id):
    [
      reservation_rows[]?
      | select((.bead_id // "") == $bead_id)
      | (.agent_id // .agent_name // .holder // "")
      | select(. != "")
    ] | unique | sort;
  def owner_truth($bead_id; $stale_row):
    (active_holders($bead_id)) as $holders
    | (profile_names) as $known_profiles
    | (($stale_row.assignee // "")) as $assignee
    | (($stale_row.recommendation // "missing")) as $recommendation
    | (($stale_row.evidence.degraded_reasons // [])) as $degraded
    | if $stale_row == null then
        {
          status: "missing",
          assignee: null,
          holder_candidates: $holders,
          reason_codes: ["stale_lock_recommendation_missing"]
        }
      elif ($assignee == "" and ($holders | length) == 0) then
        {
          status: "missing",
          assignee: null,
          holder_candidates: $holders,
          reason_codes: ["assignee_and_reservation_holder_missing"]
        }
      elif (($holders | length) > 1) then
        {
          status: "contradictory",
          assignee: (if $assignee == "" then null else $assignee end),
          holder_candidates: $holders,
          reason_codes: ["multiple_reservation_holders"]
        }
      elif (($holders | length) == 1 and $assignee != "" and $assignee != $holders[0]) then
        {
          status: "contradictory",
          assignee: $assignee,
          holder_candidates: $holders,
          reason_codes: ["assignee_reservation_mismatch"]
        }
      elif ($profiles_status == "provided" and $assignee != "" and (($known_profiles | index($assignee)) == null)) then
        {
          status: "contradictory",
          assignee: $assignee,
          holder_candidates: $holders,
          reason_codes: ["assignee_not_in_agent_snapshot"]
        }
      elif (($degraded | length) > 0 or $recommendation == "manual_confirmation_required") then
        {
          status: "manual_confirmation_required",
          assignee: (if $assignee == "" then null else $assignee end),
          holder_candidates: $holders,
          reason_codes: ((["manual_confirmation_required"] + $degraded) | unique | sort)
        }
      elif $recommendation == "safe_to_reopen" then
        {
          status: "stale_reclaimable",
          assignee: (if $assignee == "" then null else $assignee end),
          holder_candidates: $holders,
          reason_codes: ["safe_to_reopen"]
        }
      elif $recommendation == "owner_active" then
        {
          status: "active_owner",
          assignee: (if $assignee == "" then null else $assignee end),
          holder_candidates: $holders,
          reason_codes: ["owner_active"]
        }
      elif ($recommendation | startswith("contact_first")) then
        {
          status: "contact_first",
          assignee: (if $assignee == "" then null else $assignee end),
          holder_candidates: $holders,
          reason_codes: [$recommendation]
        }
      else
        {
          status: "contact_first",
          assignee: (if $assignee == "" then null else $assignee end),
          holder_candidates: $holders,
          reason_codes: [$recommendation]
        }
      end;
  def candidate_action($row; $owner; $lease_plan; $gc_guard; $pressure):
    (low($lease_plan.lease_decision)) as $lease_decision
    | (low($gc_guard.guard_decision)) as $guard_decision
    | (low($pressure.advisory)) as $pressure_advisory
    | (
        (($gc_guard.salvage_summary.workflow_state // "unknown") != "clean_finished")
        or any((($gc_guard.policy_findings // []) + ($pressure.policy_findings // []))[]?;
          . == "salvage_pinned"
          or . == "orphan_salvage_pinned"
          or . == "salvage_pinned_blocks_eviction"
        )
      ) as $salvage_pinned
    | (has_reason($row; "resource_lease_restricted")) as $lease_restricted
    | (has_reason($row; "rch_degradation_requires_narrow_scope")) as $rch_degraded
    | (has_reason($row; "disk_or_memory_pressure_requires_narrow_scope") or has_reason($row; "disk_or_memory_pressure_defers_non_protected_heavy_work")) as $pressure_restricted
    | (has_reason($row; "active_owner_manual_confirmation_required") or has_reason($row; "stale_lock_contact_first")) as $explicit_manual
    | (($row.proof_obligation // false) or (($row.budget_class // "") == "protected")) as $protected
    | if ($owner.status == "missing" or $owner.status == "contradictory") then
        "fail_closed_missing_ownership"
      elif ($owner.status == "manual_confirmation_required" or $explicit_manual) then
        "manual_confirmation_required"
      elif ($guard_decision == "fail_closed" or $pressure_advisory == "fail_closed") and ($salvage_pinned | not) then
        "manual_review_required"
      elif $salvage_pinned and ($rch_degraded or $lease_restricted or ($row.heavy_rust // false) or $protected) then
        "preserve_pinned_evidence"
      elif (($lease_decision == "deny" or $lease_decision == "defer") and $owner.status == "stale_reclaimable") then
        "simulate_lease_exchange"
      elif (($lease_decision == "deny" or $lease_decision == "defer") and ($owner.status == "active_owner" or $owner.status == "contact_first")) then
        "contact_owner_before_exchange"
      elif (($rch_degraded or $pressure_restricted or $lease_restricted) and $protected) then
        "simulate_cancel_and_promote_salvage"
      else
        "retain_current_admission"
      end;
  def priority_score($row):
    if (($row.bead_priority // 3) | tonumber) <= 1 then 900000
    elif (($row.bead_priority // 3) | tonumber) == 2 then 700000
    else 400000
    end;
  def bottleneck_score($action; $row; $lease_plan):
    if $action == "simulate_lease_exchange" then
      (if low($lease_plan.lease_decision) == "defer" or low($lease_plan.lease_decision) == "deny" then 950000 else 700000 end)
    elif $action == "simulate_cancel_and_promote_salvage" then
      (if has_reason($row; "rch_degradation_requires_narrow_scope") then 900000 else 750000 end)
    elif $action == "preserve_pinned_evidence" then
      500000
    elif $action == "contact_owner_before_exchange" then
      400000
    elif $action == "manual_confirmation_required" or $action == "manual_review_required" or $action == "fail_closed_missing_ownership" then
      250000
    else
      200000
    end;
  def artifact_score($action):
    if $action == "preserve_pinned_evidence" then 1000000
    elif $action == "simulate_cancel_and_promote_salvage" then 900000
    elif $action == "manual_confirmation_required" or $action == "manual_review_required" or $action == "fail_closed_missing_ownership" then 875000
    elif $action == "contact_owner_before_exchange" then 800000
    elif $action == "simulate_lease_exchange" then 700000
    else 600000
    end;
  def coordination_risk($action):
    if $action == "fail_closed_missing_ownership" then 1000000
    elif $action == "manual_confirmation_required" then 850000
    elif $action == "manual_review_required" then 800000
    elif $action == "contact_owner_before_exchange" then 650000
    elif $action == "simulate_cancel_and_promote_salvage" then 500000
    elif $action == "simulate_lease_exchange" then 300000
    elif $action == "preserve_pinned_evidence" then 250000
    else 150000
    end;
  def counterfactual($action; $lease_plan; $gc_guard; $pressure):
    if $action == "simulate_lease_exchange" then
      {
        simulated_exchange: true,
        expected_residency: "focus_existing_worker_or_target_dir",
        expected_next_step: "prepare coordination packet and focused proof retry",
        salvage_outcome: "unchanged"
      }
    elif $action == "simulate_cancel_and_promote_salvage" then
      {
        simulated_exchange: false,
        expected_residency: "release blocked proof slot in model only",
        expected_next_step: "promote blocked proof into salvage review packet",
        salvage_outcome: (if (($gc_guard.salvage_summary.workflow_state // "unknown") == "clean_finished") then "would_open_salvage_candidate" else "would_extend_existing_salvage" end)
      }
    elif $action == "preserve_pinned_evidence" then
      {
        simulated_exchange: false,
        expected_residency: "keep artifact set pinned",
        expected_next_step: ($pressure.recommended_action // "preserve_pinned_evidence"),
        salvage_outcome: "preserve_pinned_evidence"
      }
    elif $action == "contact_owner_before_exchange" then
      {
        simulated_exchange: false,
        expected_residency: "no modeled change until owner coordination clears",
        expected_next_step: "send contact-first coordination packet",
        salvage_outcome: "unchanged"
      }
    elif $action == "manual_confirmation_required" or $action == "manual_review_required" or $action == "fail_closed_missing_ownership" then
      {
        simulated_exchange: false,
        expected_residency: "no modeled change",
        expected_next_step: "manual review required",
        salvage_outcome: "unchanged"
      }
    else
      {
        simulated_exchange: false,
        expected_residency: "retain current admission posture",
        expected_next_step: "none",
        salvage_outcome: "unchanged"
      }
    end;

  ($lease[0]) as $lease_plan
  | ($gc[0]) as $gc_guard
  | ($scoreboard[0]) as $pressure
  | [
      admission_rows[]
      | {
          request_id: (.request_id // ((.agent_id // "unknown-agent") + ":" + (.bead_id // "unknown-bead"))),
          agent_id: (.agent_id // "unknown-agent"),
          bead_id: (.bead_id // "unknown-bead"),
          bead_priority: ((.bead_priority // 3) | tonumber),
          priority_class: (.priority_class // ("P" + (((.bead_priority // 3) | tonumber) | tostring))),
          decision: (.decision // "defer"),
          heavy_rust: (.heavy_rust // false),
          proof_obligation: (.proof_obligation // false),
          budget_class: (.budget_class // "standard"),
          requested_command: (.requested_command // .command // ""),
          reasons: (.reasons // []),
          owner_truth: (owner_truth((.bead_id // "unknown-bead"); stale_row((.bead_id // "unknown-bead"))))
        } as $row
      | (candidate_action($row; $row.owner_truth; $lease_plan; $gc_guard; $pressure)) as $action
      | (bottleneck_score($action; $row; $lease_plan)) as $bottleneck
      | ((priority_score($row) + (if ($row.proof_obligation or $row.budget_class == "protected") then 100000 else 0 end)) | if . > 1000000 then 1000000 else . end) as $fairness
      | (artifact_score($action)) as $artifact
      | (coordination_risk($action)) as $risk
      | {
          request_id: $row.request_id,
          bead_id: $row.bead_id,
          agent_id: $row.agent_id,
          bead_priority: $row.bead_priority,
          priority_class: $row.priority_class,
          current_admission_decision: $row.decision,
          current_reasons: $row.reasons,
          ownership_status: $row.owner_truth.status,
          ownership_evidence: $row.owner_truth,
          simulated_action: $action,
          bottleneck_relief_score_millionths: $bottleneck,
          fairness_impact_score_millionths: $fairness,
          artifact_preservation_score_millionths: $artifact,
          coordination_risk_score_millionths: $risk,
          overall_score_millionths: (((($bottleneck * 45) + ($fairness * 20) + ($artifact * 20) + ((1000000 - $risk) * 15)) / 100) | floor),
          counterfactual: counterfactual($action; $lease_plan; $gc_guard; $pressure),
          simulated_effects: {
            lease_exchange_candidate: ($action == "simulate_lease_exchange"),
            salvage_promotion_candidate: ($action == "simulate_cancel_and_promote_salvage"),
            archive_salvage_pinned: (
              (($gc_guard.salvage_summary.workflow_state // "unknown") != "clean_finished")
              or any((($gc_guard.policy_findings // []) + ($pressure.policy_findings // []))[]?;
                . == "salvage_pinned"
                or . == "orphan_salvage_pinned"
                or . == "salvage_pinned_blocks_eviction"
              )
            )
          }
        }
    ] as $recommendations_unsorted
  | ($recommendations_unsorted | sort_by(-.overall_score_millionths, .coordination_risk_score_millionths, .bead_priority, .bead_id, .request_id)) as $recommendations
  | ($recommendations | map(select(.ownership_status == "missing" or .ownership_status == "contradictory")) | length) as $ownership_fail_closed_count
  | ($recommendations | map(select(.simulated_action == "manual_confirmation_required" or .simulated_action == "manual_review_required" or .simulated_action == "contact_owner_before_exchange" or .simulated_action == "preserve_pinned_evidence")) | length) as $manual_review_count
  | ($recommendations | map(select(.simulated_action == "simulate_lease_exchange")) | length) as $lease_exchange_count
  | ($recommendations | map(select(.simulated_action == "simulate_cancel_and_promote_salvage")) | length) as $salvage_promotion_count
  | ($recommendations[0] // null) as $top
  | {
      schema_version: $schema_version,
      source_revision: $source_revision,
      decision: (
        if $ownership_fail_closed_count > 0 then "fail_closed"
        elif $manual_review_count > 0 then "manual_review_required"
        else "advisory"
        end
      ),
      exit_code: (
        if $ownership_fail_closed_count > 0 then 42
        elif $manual_review_count > 0 then 75
        else 0
        end
      ),
      summary: {
        request_count: ($recommendations | length),
        lease_exchange_candidate_count: $lease_exchange_count,
        salvage_promotion_candidate_count: $salvage_promotion_count,
        manual_review_count: $manual_review_count,
        ownership_fail_closed_count: $ownership_fail_closed_count,
        top_recommendation_request_id: ($top.request_id // null),
        top_recommendation_action: ($top.simulated_action // null)
      },
      input_status: {
        stale_lock_recommendations_json: $stale_status,
        admission_budget_plan_json: $admission_status,
        resource_lease_plan_json: $lease_status,
        remote_proof_gc_guard_json: $gc_status,
        archive_pressure_scoreboard_json: $scoreboard_status,
        reservation_snapshot_json: $reservation_status,
        agent_profiles_json: $profiles_status
      },
      upstream_summary: {
        budget_profile: ($admission[0].budget_profile // "unknown"),
        lease_decision: ($lease_plan.lease_decision // "unknown"),
        lease_reason: ($lease_plan.reason // ""),
        gc_guard_decision: ($gc_guard.guard_decision // "unknown"),
        gc_guard_recommended_action: ($gc_guard.recommended_action // "unknown"),
        archive_pressure_advisory: ($pressure.advisory // "unknown"),
        archive_pressure_action: ($pressure.recommended_action // "unknown"),
        salvage_workflow_state: ($gc_guard.salvage_summary.workflow_state // "unknown")
      },
      recommendations: $recommendations
    }
  ' >"$simulation_tmp"

input_hash="$(
  jq -n \
    --slurpfile stale "$stale_normalized" \
    --slurpfile admission "$admission_normalized" \
    --slurpfile lease "$lease_normalized" \
    --slurpfile gc "$gc_normalized" \
    --slurpfile scoreboard "$scoreboard_normalized" \
    --slurpfile reservations "$reservations_normalized" \
    --slurpfile profiles "$profiles_normalized" \
    '{
      stale_lock_recommendations: ($stale[0]),
      admission_budget_plan: ($admission[0]),
      resource_lease_plan: ($lease[0]),
      remote_proof_gc_guard: ($gc[0]),
      archive_pressure_scoreboard: ($scoreboard[0]),
      reservation_snapshot: ($reservations[0]),
      agent_profiles: ($profiles[0])
    }' | jq -cS . | sha256sum | awk '{print $1}'
)"
simulation_hash="$(jq -cS . "$simulation_tmp" | sha256sum | awk '{print $1}')"

# shellcheck disable=SC2094
jq \
  --arg input_hash "$input_hash" \
  --arg simulation_hash "$simulation_hash" \
  --arg simulation_id "lease-salvage-${simulation_hash:0:16}" \
  --arg simulation_path "$simulation_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg stale_path "$stale_lock_recommendations_json" \
  --arg admission_path "$admission_budget_plan_json" \
  --arg lease_path "$resource_lease_plan_json" \
  --arg gc_path "$gc_guard_report_json" \
  --arg scoreboard_path "$archive_pressure_scoreboard_json" \
  --arg reservation_path "$reservation_snapshot_json" \
  --arg profiles_path "$agent_profiles_json" '
  . + {
    simulation_id: $simulation_id,
    hash_basis: {
      input_hash: $input_hash,
      simulation_hash: $simulation_hash
    },
    truth_constraints: [
      "report_only",
      "no_br_update",
      "no_reservation_release",
      "no_process_kill"
    ],
    upstream_artifact_paths: {
      stale_lock_recommendations_json: $stale_path,
      admission_budget_plan_json: $admission_path,
      resource_lease_plan_json: $lease_path,
      remote_proof_gc_guard_json: $gc_path,
      archive_pressure_scoreboard_json: $scoreboard_path,
      reservation_snapshot_json: (if $reservation_path == "" then null else $reservation_path end),
      agent_profiles_json: (if $profiles_path == "" then null else $profiles_path end)
    },
    artifact_paths: {
      lease_exchange_cancellation_salvage_simulation_json: $simulation_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path
    }
  }
' "$simulation_tmp" >"$simulation_path"
rm -f "$simulation_tmp"

jq -c '
  .recommendations[]
  | {
      schema_version: "franken-engine.swarm-lease-exchange-cancellation-salvage-simulation-event.v1",
      event_name: "swarm_lease_exchange_cancellation_salvage_simulator.recommendation",
      request_id,
      bead_id,
      simulated_action,
      ownership_status,
      overall_score_millionths
    }
' "$simulation_path" >>"$events_path"

{
  printf '# Swarm Lease Exchange And Cancellation Salvage Simulator\n\n'
  printf '%s\n' "- Decision: \`$(jq -r '.decision' "$simulation_path")\`"
  printf '%s\n' "- Top action: \`$(jq -r '.summary.top_recommendation_action' "$simulation_path")\`"
  printf '%s\n' "- Lease exchange candidates: \`$(jq -r '.summary.lease_exchange_candidate_count' "$simulation_path")\`"
  printf '%s\n' "- Salvage promotion candidates: \`$(jq -r '.summary.salvage_promotion_candidate_count' "$simulation_path")\`"
  printf '%s\n' "- Manual review count: \`$(jq -r '.summary.manual_review_count' "$simulation_path")\`"
  printf '%s\n' "- Ownership fail-closed count: \`$(jq -r '.summary.ownership_fail_closed_count' "$simulation_path")\`"
  printf '%s\n' "- Lease posture: \`$(jq -r '.upstream_summary.lease_decision' "$simulation_path")\` / $(jq -r '.upstream_summary.lease_reason' "$simulation_path")"
  printf '%s\n' "- Archive salvage posture: \`$(jq -r '.upstream_summary.archive_pressure_advisory' "$simulation_path")\` / \`$(jq -r '.upstream_summary.salvage_workflow_state' "$simulation_path")\`"
} >"$report_path"

exit "$(jq -r '.exit_code' "$simulation_path")"
