#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_EXECUTION_QUEUE_INPUT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-execution-queue-input}"
run_id="${SWARM_EXECUTION_QUEUE_INPUT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_EXECUTION_QUEUE_INPUT_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

br_ready_json=""
br_list_json=""
bv_actionable_plan_json=""
br_sync_status_json=""
agent_mail_activity_json=""
file_reservations_json=""
stale_lock_recommendations_json=""
proof_transport_health_json=""
source_revision=""
generated_epoch_seconds="$(date -u +%s)"
stale_after_seconds="3600"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_execution_queue_input_normalizer.sh \
  --br-ready-json FILE \
  --br-list-json FILE \
  --bv-actionable-plan-json FILE \
  [OPTIONS]

Normalizes fixture snapshots from br, bv, Agent Mail, reservation summaries,
stale-lock evidence, and proof-transport health into the SWARM-CTRL-XII
execution queue input contract. This script is advisory-only: it does not run
br update, mutate Agent Mail, release reservations, execute cargo, or change
remote worker state.

Required:
  --br-ready-json FILE
  --br-list-json FILE
  --bv-actionable-plan-json FILE

Optional:
  --br-sync-status-json FILE
  --agent-mail-activity-json FILE
  --file-reservations-json FILE
  --stale-lock-recommendations-json FILE
  --proof-transport-health-json FILE
  --source-revision REV
  --generated-epoch-seconds N
  --stale-after-seconds N
  --output-dir DIR

Artifacts:
  normalized_input.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  normalized input is replayable; decision may be pass or degraded
  42 fail-closed due to malformed required shapes, empty graph, unknown deps,
     cycles, missing first actions, local-rch fallback promoted as health, or
     supplied br sync freshness showing db/jsonl divergence
  64 invalid or missing input path / malformed JSON
EOF
}

is_int() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --br-ready-json)
      br_ready_json="${2:-}"
      shift 2
      ;;
    --br-list-json)
      br_list_json="${2:-}"
      shift 2
      ;;
    --bv-actionable-plan-json)
      bv_actionable_plan_json="${2:-}"
      shift 2
      ;;
    --br-sync-status-json)
      br_sync_status_json="${2:-}"
      shift 2
      ;;
    --agent-mail-activity-json)
      agent_mail_activity_json="${2:-}"
      shift 2
      ;;
    --file-reservations-json)
      file_reservations_json="${2:-}"
      shift 2
      ;;
    --stale-lock-recommendations-json)
      stale_lock_recommendations_json="${2:-}"
      shift 2
      ;;
    --proof-transport-health-json)
      proof_transport_health_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --generated-epoch-seconds)
      generated_epoch_seconds="${2:-}"
      shift 2
      ;;
    --now-epoch-seconds)
      generated_epoch_seconds="${2:-}"
      shift 2
      ;;
    --stale-after-seconds)
      stale_after_seconds="${2:-}"
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
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$br_ready_json" || -z "$br_list_json" || -z "$bv_actionable_plan_json" ]]; then
  printf 'swarm execution queue input normalizer requires br ready, br list, and bv actionable plan JSON inputs\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm execution queue input normalization\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm execution queue input normalization\n' >&2
  exit 2
fi
if ! is_int "$generated_epoch_seconds" || ! is_int "$stale_after_seconds"; then
  printf 'generated/stale thresholds must be non-negative integers\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
normalized_input_path="${run_dir}/normalized_input.json"
normalized_input_tmp="${normalized_input_path}.tmp"
core_path="${run_dir}/normalized_input.core.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

br_ready_normalized="${run_dir}/br_ready.normalized.json"
br_list_normalized="${run_dir}/br_list.normalized.json"
bv_plan_normalized="${run_dir}/bv_actionable_plan.normalized.json"
br_sync_status_normalized="${run_dir}/br_sync_status.normalized.json"
agent_mail_normalized="${run_dir}/agent_mail_activity.normalized.json"
reservations_normalized="${run_dir}/file_reservations.normalized.json"
stale_lock_normalized="${run_dir}/stale_lock_recommendations.normalized.json"
proof_transport_normalized="${run_dir}/proof_transport_health.normalized.json"

printf './scripts/swarm_execution_queue_input_normalizer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$fail_closed_reasons_jsonl"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-execution-queue-input.event.v1" \
    --arg event_name "$1" \
    --arg detail "$2" \
    --arg source_revision "$source_revision" \
    '{
      schema_version: $schema_version,
      event_name: $event_name,
      detail: $detail,
      source_revision: $source_revision
    }' >>"$events_path"
}

append_failure() {
  jq -nc \
    --arg kind "$1" \
    --arg source "$2" \
    --arg label "$3" \
    --arg detail "$4" \
    '{kind:$kind,source:$source,label:$label,detail:$detail}' >>"$fail_closed_reasons_jsonl"
}

json_input() {
  local path="$1"
  local default_json="$2"
  local output_path="$3"
  local label="$4"
  local required="$5"

  if [[ -z "$path" ]]; then
    if [[ "$required" == "true" ]]; then
      printf 'missing required %s JSON\n' "$label" >&2
      exit 64
    fi
    printf '%s\n' "$default_json" >"$output_path"
    printf 'missing'
    return
  fi
  if [[ ! -f "$path" ]]; then
    printf 'missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
  printf 'provided'
}

check_shape() {
  local file="$1"
  local expr="$2"
  local source="$3"
  local label="$4"
  if ! jq -e "$expr" "$file" >/dev/null 2>&1; then
    append_failure "malformed_required_shape" "$source" "$label" "required shape is missing or invalid"
  fi
}

br_ready_status="$(json_input "$br_ready_json" '[]' "$br_ready_normalized" 'br ready' true)"
br_list_status="$(json_input "$br_list_json" '{"issues":[]}' "$br_list_normalized" 'br list' true)"
bv_plan_status="$(json_input "$bv_actionable_plan_json" '{"plan":{"tracks":[]}}' "$bv_plan_normalized" 'bv actionable plan' true)"
br_sync_status_status="$(json_input "$br_sync_status_json" '{"state":"unknown_missing_optional","db_newer":false,"jsonl_newer":false,"dirty_count":0}' "$br_sync_status_normalized" 'br sync status' false)"
agent_mail_status="$(json_input "$agent_mail_activity_json" '{"agents":[],"messages":[]}' "$agent_mail_normalized" 'Agent Mail activity' false)"
reservations_status="$(json_input "$file_reservations_json" '{"reservations":[]}' "$reservations_normalized" 'file reservations' false)"
stale_lock_status="$(json_input "$stale_lock_recommendations_json" '{"stale_lock_recommendations":[],"safe_to_reopen":[],"contact_first":[]}' "$stale_lock_normalized" 'stale lock recommendations' false)"
proof_transport_status="$(json_input "$proof_transport_health_json" '{"state":"unknown_missing_optional","local_fallback_detected":false}' "$proof_transport_normalized" 'proof transport health' false)"

check_shape "$br_ready_normalized" '((type == "array") or (type == "object" and ((.issues // null) | type == "array")))' "br_ready_json" "array_or_issues_array"
check_shape "$br_list_normalized" '((type == "array") or (type == "object" and ((.issues // null) | type == "array")))' "br_list_json" "array_or_issues_array"
check_shape "$bv_plan_normalized" '(type == "object" and ((.plan.tracks // null) | type == "array"))' "bv_actionable_plan_json" "plan_tracks_array"

write_event "inputs_loaded" "loaded required and optional execution queue snapshots"

jq -n \
  --arg schema_version "franken-engine.swarm-execution-queue-input.v1" \
  --arg source_revision "$source_revision" \
  --argjson generated_epoch_seconds "$generated_epoch_seconds" \
  --argjson stale_after_seconds "$stale_after_seconds" \
  --arg br_ready_status "$br_ready_status" \
  --arg br_list_status "$br_list_status" \
  --arg bv_plan_status "$bv_plan_status" \
  --arg br_sync_status_status "$br_sync_status_status" \
  --arg agent_mail_status "$agent_mail_status" \
  --arg reservations_status "$reservations_status" \
  --arg stale_lock_status "$stale_lock_status" \
  --arg proof_transport_status "$proof_transport_status" \
  --arg normalized_input_path "$normalized_input_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --slurpfile br_ready "$br_ready_normalized" \
  --slurpfile br_list "$br_list_normalized" \
  --slurpfile bv_plan "$bv_plan_normalized" \
  --slurpfile br_sync_status "$br_sync_status_normalized" \
  --slurpfile agent_mail "$agent_mail_normalized" \
  --slurpfile reservations "$reservations_normalized" \
  --slurpfile stale_lock "$stale_lock_normalized" \
  --slurpfile proof_transport "$proof_transport_normalized" \
  --slurpfile shape_failures "$fail_closed_reasons_jsonl" '
    def rows($doc):
      if ($doc | type) == "array" then
        $doc
      elif ($doc | type) == "object" and (($doc.issues // null) | type) == "array" then
        $doc.issues
      else
        []
      end;

    def id_from($value):
      if ($value | type) == "object" then
        ($value.id // $value.issue_id // $value.depends_on_id // $value.bead_id // $value.task_id // empty)
      else
        ($value | tostring)
      end;

    def id_list($issue; $field):
      [($issue[$field] // [])[]? | id_from(.) | select(length > 0)] | unique | sort;

    def priority_impact($priority):
      if $priority == 0 then 1000000
      elif $priority == 1 then 900000
      elif $priority == 2 then 700000
      elif $priority == 3 then 450000
      else 250000
      end;

    def bounded_score($value):
      if $value < 0 then 0
      elif $value > 1000000 then 1000000
      else $value
      end;

    def plan_items($doc):
      [($doc.plan.tracks // [])[]? | (.items // [])[]?];

    def agent_rows($doc):
      if (($doc.agents // null) | type) == "array" then $doc.agents
      elif (($doc.profiles // null) | type) == "array" then $doc.profiles
      elif (($doc.result // null) | type) == "array" then $doc.result
      else []
      end;

    def message_rows($doc):
      if (($doc.messages // null) | type) == "array" then $doc.messages else [] end;

    def reservation_rows($doc):
      if (($doc.reservations // null) | type) == "array" then $doc.reservations
      elif (($doc.granted // null) | type) == "array" then $doc.granted
      else []
      end;

    def stale_rows($doc):
      if (($doc.stale_lock_recommendations // null) | type) == "array" then
        $doc.stale_lock_recommendations
      else
        []
      end;

    def proof_task_rows($doc):
      if (($doc.tasks // null) | type) == "array" then $doc.tasks
      elif (($doc.proof_transport_health // null) | type) == "array" then $doc.proof_transport_health
      else []
      end;

    def has_cycle($edges):
      def outs($id): [$edges[]? | select(.from == $id) | .to];
      def visit($id; $stack):
        if ($stack | index($id)) then
          true
        else
          any(outs($id)[]?; visit(.; $stack + [$id]))
        end;
      any(([$edges[]?.from] | unique)[]?; visit(.; []));

    def contains_task_ref($row; $task_id):
      [
        ($row.bead_id // ""),
        ($row.issue_id // ""),
        ($row.task_id // ""),
        ($row.id // ""),
        ($row.reason // ""),
        ($row.label // "")
      ] | map(tostring) | any(. == $task_id or contains($task_id));

    def action_for($trigger; $task_id; $depends_on):
      if $trigger == "local_rch_fallback_detected" then
        "reject local fallback proof and rerun proof remotely before queueing"
      elif $trigger == "contact_or_reopen_required" then
        "contact owner or reopen only after stale-lock evidence says safe_to_reopen"
      elif $trigger == "proof_brownout_conservative_mode" then
        "defer broad proof and select a narrower no-cargo task"
      elif $trigger == "blocked_parent" then
        "work dependency " + (($depends_on[0] // "unknown-dependency") | tostring) + " before parent closeout"
      elif $trigger == "coordinate_reservation_holder" then
        "coordinate reservation holder before editing shared files"
      else
        "claim bead and reserve the focused file set"
      end;

    ($br_ready[0]) as $ready_doc
    | ($br_list[0]) as $list_doc
    | ($bv_plan[0]) as $bv_doc
    | ($br_sync_status[0]) as $sync_doc
    | ($agent_mail[0]) as $agent_doc
    | ($reservations[0]) as $reservations_doc
    | ($stale_lock[0]) as $stale_doc
    | ($proof_transport[0]) as $proof_doc
    | rows($ready_doc) as $ready_rows
    | rows($list_doc) as $all_issue_rows
    | plan_items($bv_doc) as $bv_items
    | agent_rows($agent_doc) as $agent_rows
    | message_rows($agent_doc) as $message_rows
    | reservation_rows($reservations_doc) as $reservation_rows
    | stale_rows($stale_doc) as $stale_rows
    | proof_task_rows($proof_doc) as $proof_task_rows
    | ([$all_issue_rows[]? | (.id // empty)] | unique | sort) as $known_issue_ids
    | ([($all_issue_rows[]?, $ready_rows[]?, $bv_items[]?)
        | select((.id // "") != "")
        | select((.status // "open") != "closed")
       ] | unique_by(.id) | sort_by(.id)) as $task_base
    | ([$ready_rows[]? | .id // empty] | unique) as $ready_ids
    | ([$bv_items[]? | .id // empty] | unique) as $bv_ids
    | (($sync_doc.db_newer // false) == true) as $tracker_db_newer
    | (($sync_doc.jsonl_newer // false) == true) as $tracker_jsonl_newer
    | (($sync_doc.dirty_count // 0) | tonumber? // 0) as $tracker_dirty_count
    | ($proof_doc.state // $proof_doc.proof_transport.state // $proof_doc.summary.state // "unknown_missing_optional") as $global_proof_state
    | (($proof_doc.local_fallback_detected // $proof_doc.proof_transport.local_fallback_detected // false) == true) as $global_local_fallback
    | {
        task_base: $task_base,
        known_issue_ids: $known_issue_ids,
        ready_ids: $ready_ids,
        bv_ids: $bv_ids,
        tracker_db_newer: $tracker_db_newer,
        tracker_jsonl_newer: $tracker_jsonl_newer,
        tracker_dirty_count: $tracker_dirty_count,
        tracker_consistency_state: (
          if $br_sync_status_status == "missing" then "unknown_missing_optional"
          elif $tracker_db_newer or $tracker_jsonl_newer then "divergent"
          else "synced"
          end
        ),
        edge_rows: [
          $task_base[]? as $issue
          | id_list($issue; "dependencies")[]? as $dep
          | {from: ($issue.id // ""), to: $dep}
        ],
        unknown_dependency_rows: [
          $task_base[]? as $issue
          | id_list($issue; "dependencies")[]? as $dep
          | select(($known_issue_ids | index($dep)) == null)
          | {
              kind: "unknown_dependency",
              source: "br_list_json",
              label: ($issue.id // ""),
              detail: ("dependency " + $dep + " is not present in br list snapshot")
            }
        ],
        source_rows: {
          ready: $ready_rows,
          all_issues: $all_issue_rows,
          bv_items: $bv_items,
          agents: $agent_rows,
          messages: $message_rows,
          reservations: $reservation_rows,
          stale_locks: $stale_rows,
          proof_tasks: $proof_task_rows
        },
        global_proof_state: $global_proof_state,
        global_local_fallback: $global_local_fallback,
        optional_missing: [
          {input:"agent_mail_activity_json", status:$agent_mail_status, degraded_reason:"owner freshness uses conservative unknowns"},
          {input:"file_reservations_json", status:$reservations_status, degraded_reason:"reservation pressure uses conservative unknowns"},
          {input:"stale_lock_recommendations_json", status:$stale_lock_status, degraded_reason:"stale owners require contact-first action"},
          {input:"proof_transport_health_json", status:$proof_transport_status, degraded_reason:"proof transport uses remote-only unknown state"}
        ] | map(select(.status == "missing")),
        input_rows: [
          {input:"br_ready_json", status:$br_ready_status, schema_version:"beads.ready-json"},
          {input:"br_list_json", status:$br_list_status, schema_version:"beads.list-json"},
          {input:"bv_actionable_plan_json", status:$bv_plan_status, schema_version:"bv.actionable-plan"},
          {input:"br_sync_status_json", status:$br_sync_status_status, schema_version:($sync_doc.schema_version // "beads.sync-status-json")},
          {input:"agent_mail_activity_json", status:$agent_mail_status, schema_version:($agent_doc.schema_version // "agent-mail.activity-fixture")},
          {input:"file_reservations_json", status:$reservations_status, schema_version:($reservations_doc.schema_version // "agent-mail.reservation-fixture")},
          {input:"stale_lock_recommendations_json", status:$stale_lock_status, schema_version:($stale_doc.schema_version // "franken-engine.stale-lock-recommendations.v1")},
          {input:"proof_transport_health_json", status:$proof_transport_status, schema_version:($proof_doc.schema_version // "franken-engine.proof-transport-health.v1")}
        ]
      } as $ctx
    | ($ctx.edge_rows | has_cycle(.)) as $cycle_detected
    | ([
        $ctx.task_base[]? as $issue
        | ($issue.id // "") as $task_id
        | (id_list($issue; "dependencies")) as $depends_on
        | ((id_list($issue; "dependents")
            + ([$ctx.source_rows.bv_items[]? | select((.id // "") == $task_id) | (.unblocks // [])[]? | tostring])
           ) | unique | sort) as $dependents
        | (($issue.assignee // "") | tostring) as $assignee
        | ($issue.priority // 4) as $priority
        | ([($ctx.source_rows.agents[]? | select((.name // .agent_name // .agent // "") == $assignee)
              | (.last_active_age_seconds // .age_seconds // .inactive_seconds // 0)
            )] | first // 0) as $agent_age
        | ([($ctx.source_rows.messages[]? | select((.from // .sender // "") == $assignee)
              | (.age_seconds // .last_message_age_seconds // empty)
            )] | first // null) as $message_age
        | ([($ctx.source_rows.stale_locks[]? | select(contains_task_ref(.; $task_id)))] | first // {}) as $stale_evidence
        | ([($ctx.source_rows.reservations[]? | select(contains_task_ref(.; $task_id)))] | length) as $reservation_count
        | ([($ctx.source_rows.reservations[]? | select(contains_task_ref(.; $task_id))
              | (.agent_name // .agent // .holder // "")
              | select(. != "" and . != $assignee)
            )] | unique) as $reservation_holders
        | ([($ctx.source_rows.proof_tasks[]? | select(contains_task_ref(.; $task_id)))] | first // {}) as $task_proof
        | (($task_proof.state // $task_proof.proof_transport.state // $ctx.global_proof_state) | tostring) as $proof_state
        | ((($task_proof.local_fallback_detected // $task_proof.proof_transport.local_fallback_detected // false) == true)
            or $ctx.global_local_fallback) as $local_fallback
        | (if $assignee == "" then "unassigned"
           elif (($stale_evidence.safe_to_reopen // false) == true)
             or (($stale_evidence.recommendation // "") | test("stale|safe_to_reopen"))
             or (($agent_age | tonumber) > $stale_after_seconds)
             or (($message_age // 0 | tonumber) > $stale_after_seconds)
           then "stale"
           else "fresh"
           end) as $owner_state
        | (if $reservation_count == 0 then
             (if (($issue.status // "open") == "in_progress") then "no_active_reservations" else "clear" end)
           elif ($reservation_holders | length) > 0 then "contended"
           else "owned_by_assignee"
           end) as $reservation_state
        | ([ $depends_on[]? | select(($known_issue_ids | index(.)) != null) ] | length) as $known_dep_count
        | ([ $depends_on[]? | select(($known_issue_ids | index(.)) == null) ] | length) as $unknown_dep_count
        | (([$ctx.source_rows.all_issues[]? | select((.id // "") as $id | $depends_on | index($id)) | select((.status // "open") != "closed")] | length)
            + $unknown_dep_count) as $open_blocker_count
        | (if $local_fallback then "local_rch_fallback_detected"
           elif $owner_state == "stale" then "contact_or_reopen_required"
           elif ($proof_state | test("brownout|degraded|unavailable|failed")) then "proof_brownout_conservative_mode"
           elif $open_blocker_count > 0 then "blocked_parent"
           elif $reservation_state == "contended" then "coordinate_reservation_holder"
           else "none"
           end) as $fallback_trigger
        | (priority_impact($priority)) as $impact
        | (if ($ctx.bv_ids | index($task_id)) != null then 880000 else 680000 end) as $base_confidence
        | (if ($ctx.ready_ids | index($task_id)) != null then 760000 else 620000 end) as $base_reuse
        | (bounded_score(180000 + (($priority | tonumber) * 60000) + ($known_dep_count * 70000))) as $effort
        | (bounded_score(
            (if $owner_state == "stale" then 320000 elif $owner_state == "fresh" then 120000 else 20000 end)
            + (if $reservation_state == "contended" then 260000 elif $reservation_state == "no_active_reservations" then 120000 else 0 end)
            + (if ($proof_state | test("brownout|degraded|unavailable|failed")) then 260000 else 0 end)
            + ($open_blocker_count * 90000)
          )) as $friction
        | {
            task_id: $task_id,
            title: (($issue.title // "(untitled)") | tostring),
            status: (($issue.status // "open") | tostring),
            priority: $priority,
            assignee: $assignee,
            depends_on: $depends_on,
            dependents: $dependents,
            completed: (($issue.status // "open") == "closed"),
            open_blocker_count: $open_blocker_count,
            owner_freshness: {
              state: $owner_state,
              last_active_age_seconds: (if $assignee == "" then 0 else ($agent_age | tonumber) end)
            },
            reservation_pressure: {
              state: $reservation_state,
              active_reservation_count: $reservation_count,
              holders: $reservation_holders
            },
            proof_transport: {
              state: $proof_state,
              local_fallback_detected: $local_fallback
            },
            scores: {
              impact_millionths: $impact,
              confidence_millionths: (if $agent_mail_status == "missing" or $proof_transport_status == "missing" then ($base_confidence - 120000) else $base_confidence end | bounded_score(.)),
              reuse_millionths: $base_reuse,
              effort_millionths: $effort,
              friction_millionths: $friction
            },
            fallback_trigger: $fallback_trigger,
            first_action: action_for($fallback_trigger; $task_id; $depends_on)
          }
      ] | sort_by(.open_blocker_count, .scores.friction_millionths, (0 - .scores.impact_millionths), .task_id)) as $tasks
    | (
        $shape_failures
        + (if ($tasks | length) == 0 then [{kind:"empty_task_graph",source:"br_list_json",label:"tasks",detail:"no open or in-progress tasks available for execution queue"}] else [] end)
        + $ctx.unknown_dependency_rows
        + (if $cycle_detected then [{kind:"dependency_cycle",source:"br_list_json",label:"dependencies",detail:"dependency cycle detected in normalized task graph"}] else [] end)
        + ([$tasks[]? | select(.proof_transport.local_fallback_detected == true) | {kind:"local_rch_fallback_detected",source:"proof_transport_health_json",label:.task_id,detail:"local fallback cannot be promoted as successful proof health"}])
        + ([$tasks[]? | select((.first_action // "") == "") | {kind:"missing_first_action",source:"normalizer",label:.task_id,detail:"normalized task lacks operator first_action"}])
        + (if $br_sync_status_status == "provided" and ($ctx.tracker_db_newer or $ctx.tracker_jsonl_newer) then
             [{
               kind:"tracker_freshness_divergence",
               source:"br_sync_status_json",
               label:"tracker_sync_state",
               detail:"br sync status reported db_newer/jsonl_newer divergence; br and bv snapshots may refer to different tracker states"
             }]
           else
             []
           end)
        + ([$tasks[]?
            | .task_id as $task_id
            | select(($ctx.bv_ids | index($task_id)) != null)
            | select(($ctx.ready_ids | index($task_id)) == null)
            | select(.status == "open")
            | select(.open_blocker_count > 0)
            | {
                kind:"bv_ready_snapshot_divergence",
                source:"bv_actionable_plan_json",
                label:$task_id,
                detail:"bv actionable plan listed a blocked open task that is absent from br ready snapshot"
              }])
      ) as $fail_closed_reasons
    | (
        $ctx.optional_missing
        + ([$tasks[]? | select(.owner_freshness.state == "stale") | {kind:"stale_owner",source:"stale_lock_recommendations_json",label:.task_id,detail:.first_action}])
        + ([$tasks[]? | select(.reservation_pressure.state == "contended") | {kind:"reservation_contention",source:"file_reservations_json",label:.task_id,detail:.first_action}])
        + ([$tasks[]? | select(.proof_transport.state | test("brownout|degraded|unavailable|failed")) | {kind:"proof_transport_degraded",source:"proof_transport_health_json",label:.task_id,detail:.first_action}])
      ) as $degraded_inputs
    | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
       elif ($degraded_inputs | length) > 0 then "degraded"
       else "pass"
       end) as $decision
    | {
        schema_version: $schema_version,
        normalizer_schema_version: "franken-engine.swarm-execution-queue-input-normalizer.v1",
        source_revision: $source_revision,
        generated_epoch_seconds: $generated_epoch_seconds,
        stale_after_seconds: $stale_after_seconds,
        decision: $decision,
        source_snapshots: {
          br_ready_json: $br_ready_status,
          br_list_json: $br_list_status,
          bv_actionable_plan_json: $bv_plan_status,
          br_sync_status_json: $br_sync_status_status,
          agent_mail_activity_json: $agent_mail_status,
          file_reservations_json: $reservations_status,
          stale_lock_recommendations_json: $stale_lock_status,
          proof_transport_health_json: $proof_transport_status
        },
        tracker_freshness: {
          source_snapshot_status: $br_sync_status_status,
          consistency_state: $ctx.tracker_consistency_state,
          db_newer: $ctx.tracker_db_newer,
          jsonl_newer: $ctx.tracker_jsonl_newer,
          dirty_count: $ctx.tracker_dirty_count
        },
        summary: {
          task_count: ($tasks | length),
          ready_task_count: ([$tasks[]? | .task_id as $task_id | select(($ctx.ready_ids | index($task_id)) != null)] | length),
          in_progress_task_count: ([$tasks[]? | select(.status == "in_progress")] | length),
          stale_owner_count: ([$tasks[]? | select(.owner_freshness.state == "stale")] | length),
          contended_reservation_count: ([$tasks[]? | select(.reservation_pressure.state == "contended")] | length),
          proof_brownout_task_count: ([$tasks[]? | select(.proof_transport.state | test("brownout|degraded|unavailable|failed"))] | length),
          fail_closed_reason_count: ($fail_closed_reasons | length),
          degraded_input_count: ($degraded_inputs | length)
        },
        cross_cutting_signals: {
          observability_quality_millionths: (if $agent_mail_status == "missing" then 640000 else 860000 end),
          catastrophic_tail_score_millionths: (if any($tasks[]?; .proof_transport.state | test("brownout|degraded|unavailable|failed")) then 420000 else 60000 end),
          bifurcation_distance_millionths: (if $decision == "fail_closed" then 300000 elif $decision == "degraded" then 680000 else 880000 end),
          unit_depth_score_millionths: (if any($tasks[]?; .open_blocker_count > 0) then 780000 else 900000 end),
          e2e_stability_score_millionths: (if $proof_transport_status == "missing" then 700000 else 840000 end),
          logging_integrity_score_millionths: (if $agent_mail_status == "missing" then 720000 else 900000 end)
        },
        risk_budget: {
          remaining_millionths: ($proof_doc.risk_budget.remaining_millionths // (if any($tasks[]?; .proof_transport.state | test("brownout|degraded|unavailable|failed")) then 180000 else 720000 end)),
          consumed_millionths: ($proof_doc.risk_budget.consumed_millionths // (if any($tasks[]?; .proof_transport.state | test("brownout|degraded|unavailable|failed")) then 820000 else 280000 end)),
          conservative_threshold_millionths: ($proof_doc.risk_budget.conservative_threshold_millionths // 200000),
          conservative_mode: (($proof_doc.risk_budget.remaining_millionths // (if any($tasks[]?; .proof_transport.state | test("brownout|degraded|unavailable|failed")) then 180000 else 720000 end)) <= ($proof_doc.risk_budget.conservative_threshold_millionths // 200000))
        },
        accepted_inputs: ($ctx.input_rows | map(select(.status == "provided"))),
        degraded_inputs: $degraded_inputs,
        fail_closed_reasons: $fail_closed_reasons,
        graph_checks: {
          known_issue_count: ($ctx.known_issue_ids | length),
          edge_count: ($ctx.edge_rows | length),
          unknown_dependency_count: ($ctx.unknown_dependency_rows | length),
          cycle_detected: $cycle_detected
        },
        tasks: $tasks,
        artifact_paths: {
          normalized_input_json: $normalized_input_path,
          events_jsonl: $events_path,
          commands_txt: $commands_path,
          report_md: $report_path
        }
      }
  ' >"$core_path"

normalization_id="swarm-execution-queue-input-$(jq -cS 'del(.artifact_paths)' "$core_path" | sha256sum | awk '{print $1}' | cut -c1-16)"
jq --arg normalization_id "$normalization_id" '. + {normalization_id:$normalization_id}' "$core_path" >"$normalized_input_tmp"
mv "$normalized_input_tmp" "$normalized_input_path"

write_event "normalized_input.written" "$(jq -r '.decision + " / tasks=" + (.summary.task_count | tostring)' "$normalized_input_path")"

{
  printf '# Swarm Execution Queue Input Normalization\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$normalized_input_path")"
  printf -- "- Tracker freshness: \`%s\`\n" "$(jq -r '.tracker_freshness.consistency_state' "$normalized_input_path")"
  printf -- "- Tasks: \`%s\`\n" "$(jq '.summary.task_count' "$normalized_input_path")"
  printf -- "- Ready tasks: \`%s\`\n" "$(jq '.summary.ready_task_count' "$normalized_input_path")"
  printf -- "- Stale owners: \`%s\`\n" "$(jq '.summary.stale_owner_count' "$normalized_input_path")"
  printf -- "- Contended reservations: \`%s\`\n" "$(jq '.summary.contended_reservation_count' "$normalized_input_path")"
  printf -- "- Proof brownout tasks: \`%s\`\n" "$(jq '.summary.proof_brownout_task_count' "$normalized_input_path")"
  printf -- "- Fail-closed reasons: \`%s\`\n" "$(jq '.summary.fail_closed_reason_count' "$normalized_input_path")"
  printf -- "- Degraded inputs: \`%s\`\n\n" "$(jq '.summary.degraded_input_count' "$normalized_input_path")"

  if [[ "$(jq '.fail_closed_reasons | length' "$normalized_input_path")" -ne 0 ]]; then
    printf '## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `" + .kind + "` `" + .label + "`: " + .detail' "$normalized_input_path"
    printf '\n'
  fi

  if [[ "$(jq '.degraded_inputs | length' "$normalized_input_path")" -ne 0 ]]; then
    printf '## Degraded Inputs\n'
    jq -r '.degraded_inputs[] | "- `" + (.kind // .input) + "` `" + (.label // .source // "") + "`: " + (.detail // .degraded_reason)' "$normalized_input_path"
    printf '\n'
  fi

  printf '## First Actions\n'
  jq -r '.tasks[] | "- `" + .task_id + "`: " + .first_action' "$normalized_input_path"
} >"$report_path"

printf 'normalized_input_json=%s\n' "$normalized_input_path"
printf 'normalized_input_report=%s\n' "$report_path"

if [[ "$(jq -r '.decision' "$normalized_input_path")" == "fail_closed" ]]; then
  exit 42
fi
exit 0
