#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_FAIR_SHARE_BATCH_PLANNER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-fair-share-batch-planner}"
run_id="${SWARM_FAIR_SHARE_BATCH_PLANNER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_FAIR_SHARE_BATCH_PLANNER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

resource_envelope_json=""
bv_actionable_plan_json=""
validation_cost_hints_json=""
proof_cache_plan_json=""
active_reservations_json=""
causal_trace_summary_json=""
source_revision="${SWARM_FAIR_SHARE_BATCH_PLANNER_SOURCE_REVISION:-unknown}"
reference_time="${SWARM_FAIR_SHARE_BATCH_PLANNER_REFERENCE_TIME:-}"
max_envelope_age_seconds="${SWARM_FAIR_SHARE_BATCH_PLANNER_MAX_ENVELOPE_AGE_SECONDS:-3600}"
max_lanes_per_agent="${SWARM_FAIR_SHARE_BATCH_PLANNER_MAX_LANES_PER_AGENT:-2}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_fair_share_batch_planner.sh --resource-envelope-json FILE --bv-actionable-plan-json FILE [OPTIONS]

Turns a fixture-fed SWARM-SCALE-I resource envelope and bv plan snapshot into
advisory fair-share work admission guidance. It never queries live br, Agent
Mail, rch, cargo, ps, df, or workers, and it never starts validation commands.

Required:
  --resource-envelope-json FILE
  --bv-actionable-plan-json FILE

Optional:
  --validation-cost-hints-json FILE
  --proof-cache-plan-json FILE
  --active-reservations-json FILE
  --causal-trace-summary-json FILE
  --source-revision REV
  --reference-time RFC3339
  --max-envelope-age-seconds N
  --max-lanes-per-agent N
  --output-dir DIR

Artifacts:
  swarm_fair_share_batch_plan.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  at least one lane is admitted or admitted-narrow
  42 fail-closed input truth
  64 invalid required input or threshold
  75 all lanes are safely deferred
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --resource-envelope-json)
      resource_envelope_json="${2:-}"
      shift 2
      ;;
    --bv-actionable-plan-json)
      bv_actionable_plan_json="${2:-}"
      shift 2
      ;;
    --validation-cost-hints-json)
      validation_cost_hints_json="${2:-}"
      shift 2
      ;;
    --proof-cache-plan-json)
      proof_cache_plan_json="${2:-}"
      shift 2
      ;;
    --active-reservations-json)
      active_reservations_json="${2:-}"
      shift 2
      ;;
    --causal-trace-summary-json)
      causal_trace_summary_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --reference-time)
      reference_time="${2:-}"
      shift 2
      ;;
    --max-envelope-age-seconds)
      max_envelope_age_seconds="${2:-}"
      shift 2
      ;;
    --max-lanes-per-agent)
      max_lanes_per_agent="${2:-}"
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

is_int() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

if [[ -z "$resource_envelope_json" || -z "$bv_actionable_plan_json" ]]; then
  printf 'swarm fair-share batch planner requires --resource-envelope-json and --bv-actionable-plan-json\n' >&2
  usage
  exit 64
fi
if ! is_int "$max_envelope_age_seconds" || ! is_int "$max_lanes_per_agent"; then
  printf 'max-envelope-age-seconds and max-lanes-per-agent must be non-negative integers\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm fair-share batch planning\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm fair-share batch planning\n' >&2
  exit 2
fi
if [[ -n "$reference_time" ]] && ! date -u -d "$reference_time" +%s >/dev/null 2>&1; then
  printf 'reference time must be parseable by date -u -d: %s\n' "$reference_time" >&2
  exit 64
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/swarm_fair_share_batch_plan.json"
plan_tmp="${plan_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
fail_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"
envelope_normalized="${run_dir}/resource_envelope.normalized.json"
bv_plan_normalized="${run_dir}/bv_actionable_plan.normalized.json"
validation_normalized="${run_dir}/validation_cost_hints.normalized.json"
proof_cache_normalized="${run_dir}/proof_cache.normalized.json"
reservations_normalized="${run_dir}/active_reservations.normalized.json"
causal_normalized="${run_dir}/causal_trace_summary.normalized.json"

printf './scripts/swarm_fair_share_batch_planner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$fail_reasons_jsonl"

write_event() {
  local event_name="$1"
  local detail="$2"
  jq -nc \
    --arg schema_version "franken-engine.swarm-fair-share-batch-planner.event.v1" \
    --arg event_name "$event_name" \
    --arg detail "$detail" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event_name:$event_name,detail:$detail,source_revision:$source_revision}' >>"$events_path"
}

append_failure() {
  local code="$1"
  local detail="$2"
  jq -nc --arg code "$code" --arg detail "$detail" '{code:$code,detail:$detail}' >>"$fail_reasons_jsonl"
  write_event "fail_closed_reason" "$code"
}

normalize_required_json() {
  local input="$1"
  local output="$2"
  local label="$3"

  if [[ ! -f "$input" ]]; then
    printf 'missing required %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  if ! jq -e . "$input" >/dev/null 2>&1; then
    printf 'invalid required %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  jq -cS . "$input" >"$output"
}

normalize_optional_json() {
  local input="$1"
  local output="$2"
  local default_json="$3"
  local label="$4"

  if [[ -z "$input" ]]; then
    printf '%s\n' "$default_json" | jq -cS . >"$output"
    write_event "optional_source_missing" "$label"
    return
  fi
  if [[ ! -f "$input" ]]; then
    printf '%s\n' "$default_json" | jq -cS . >"$output"
    write_event "optional_source_missing" "$label"
    return
  fi
  if ! jq -e . "$input" >/dev/null 2>&1; then
    printf '%s\n' "$default_json" | jq -cS . >"$output"
    append_failure "malformed_optional_source" "${label} was malformed JSON"
    return
  fi
  jq -cS . "$input" >"$output"
  write_event "optional_source_loaded" "$label"
}

epoch_seconds() {
  date -u -d "$1" +%s 2>/dev/null
}

normalize_required_json "$resource_envelope_json" "$envelope_normalized" "resource envelope"
normalize_required_json "$bv_actionable_plan_json" "$bv_plan_normalized" "bv actionable plan"
normalize_optional_json "$validation_cost_hints_json" "$validation_normalized" '{"commands":[]}' "validation cost hints"
normalize_optional_json "$proof_cache_plan_json" "$proof_cache_normalized" '{"proof_cache_decision":"missing"}' "proof cache plan"
normalize_optional_json "$active_reservations_json" "$reservations_normalized" '{"reservations":[]}' "active reservations"
normalize_optional_json "$causal_trace_summary_json" "$causal_normalized" '{"decision":"missing","anomalies":[]}' "causal trace summary"

if ! jq -e '
  .schema_version == "franken-engine.swarm-resource-envelope.v1"
  and (.decision | type == "string")
  and (.capacity_budget | type == "object")
  and (.capacity_budget.script_lane_limit | type == "number")
  and (.capacity_budget.build_lane_limit | type == "number")
  and (.capacity_budget.remote_rch_slot_limit | type == "number")
  and (.capacity_budget.memory_bytes_budget | type == "number")
  and (.capacity_budget.target_dir_bytes_budget | type == "number")
  and (.mutation_policy.runs_cargo == false)
  and (.mutation_policy.runs_rch == false)
' "$envelope_normalized" >/dev/null; then
  append_failure "invalid_resource_envelope_shape" "resource envelope lacks required budget fields or mutation policy"
fi

envelope_observed_at="$(jq -r '.observed_at // ""' "$envelope_normalized")"
if [[ -z "$envelope_observed_at" ]]; then
  append_failure "stale_resource_snapshot" "resource envelope lacks observed_at evidence"
elif ! observed_epoch="$(epoch_seconds "$envelope_observed_at")"; then
  append_failure "stale_resource_snapshot" "resource envelope observed_at is not parseable"
elif [[ -n "$reference_time" ]]; then
  reference_epoch="$(epoch_seconds "$reference_time")"
  age_seconds=$((reference_epoch - observed_epoch))
  if (( age_seconds < -300 || age_seconds > max_envelope_age_seconds )); then
    append_failure "stale_resource_snapshot" "resource envelope age ${age_seconds}s exceeds accepted bounds"
  fi
fi

if jq -e '
  ((.decision // "") == "fail_closed")
  or any((.fail_closed_reasons // [])[]?; (.code // "") | IN("rch_local_fallback_contaminates_capacity","causal_trace_contamination_blocks_admission","heavy_command_missing_budget","unsafe_live_mutation_claim"))
' "$envelope_normalized" >/dev/null; then
  append_failure "contaminated_resource_envelope" "resource envelope contains fail-closed or contaminated evidence"
fi

# rch-policy-waive: local_fallback_not_rejected reason=Planner rejects preserved fallback markers in fixture evidence
fallback_pattern='local fallback|\[RCH\] local|running locally'
if jq -s -e '
  any(.[]; ([.. | objects | select(.local_fallback_detected? == true)] | length > 0)
    or ([.. | scalars | tostring | select(test($fallback_pattern; "i"))] | length > 0))
' --arg fallback_pattern "$fallback_pattern" "$envelope_normalized" "$causal_normalized" "$validation_normalized" >/dev/null; then
  append_failure "local_rch_fallback_contamination" "planner input contains a local fallback marker"
fi

if jq -e '
  ((.decision // "") | test("fail_closed|contaminated"; "i"))
  or ([.. | objects | select(((.severity // .decision // "") | test("fail_closed|contaminated"; "i")))] | length > 0)
' "$causal_normalized" >/dev/null; then
  append_failure "causal_trace_contamination" "causal trace summary blocks admission"
fi

if jq -e '
  def command_rows:
    if type == "array" then .
    elif type == "object" and has("commands") then .commands
    elif type == "object" and has("validations") then .validations
    else [] end;
  [command_rows[]
    | select((.cost_class // .command_kind // .kind // "") | test("heavy|cargo|rch|build|clippy|test"; "i"))
    | select((.budget_class // .budget_id // .cost_budget // "") == "")
  ] | length > 0
' "$validation_normalized" >/dev/null; then
  append_failure "heavy_command_missing_budget" "heavy command cost hint lacks budget classification"
fi

if jq -s -e '
  any(.[]; ([.. | objects | select((.auto_run? == true) or (.runs_cargo? == true) or (.runs_rch? == true))] | length > 0)
    or ([.. | scalars | tostring | select(test("auto-run cargo|auto-run rch|automatically run cargo|automatically run rch"; "i"))] | length > 0))
' "$envelope_normalized" "$bv_plan_normalized" "$validation_normalized" "$proof_cache_normalized" "$reservations_normalized" "$causal_normalized" >/dev/null; then
  append_failure "unsafe_auto_run_claim" "planner input attempts to authorize automatic Cargo or RCH execution"
fi

jq -s . "$fail_reasons_jsonl" >"${run_dir}/fail_closed_reasons.json"
input_hash="sha256:$(jq -cS . "$envelope_normalized" "$bv_plan_normalized" "$validation_normalized" "$proof_cache_normalized" "$reservations_normalized" "$causal_normalized" | sha256sum | awk '{print $1}')"

# shellcheck disable=SC2094
jq -n \
  --slurpfile envelope "$envelope_normalized" \
  --slurpfile bv "$bv_plan_normalized" \
  --slurpfile validation "$validation_normalized" \
  --slurpfile proof "$proof_cache_normalized" \
  --slurpfile reservations "$reservations_normalized" \
  --slurpfile causal "$causal_normalized" \
  --slurpfile fail_closed "${run_dir}/fail_closed_reasons.json" \
  --arg schema_version "franken-engine.swarm-fair-share-batch-plan.v1" \
  --arg source_revision "$source_revision" \
  --arg input_hash "$input_hash" \
  --arg plan_path "$plan_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg resource_envelope_json "$resource_envelope_json" \
  --arg bv_actionable_plan_json "$bv_actionable_plan_json" \
  --arg validation_cost_hints_json "$validation_cost_hints_json" \
  --arg proof_cache_plan_json "$proof_cache_plan_json" \
  --arg active_reservations_json "$active_reservations_json" \
  --arg causal_trace_summary_json "$causal_trace_summary_json" \
  --argjson max_lanes_per_agent "$max_lanes_per_agent" \
  '
  def low($x): (($x // "") | tostring | ascii_downcase);
  def rows($x; $field):
    if ($x | type) == "array" then $x
    elif ($x | type) == "object" and ($x | has($field)) then $x[$field]
    elif ($x | type) == "object" and ($x | has("issues")) then $x.issues
    else [] end;
  def plan_items($p):
    if ($p | type) == "array" then $p
    elif ($p | type) == "object" and ($p | has("items")) then $p.items
    elif ($p | type) == "object" and ($p.plan.tracks? | type) == "array" then [$p.plan.tracks[]?.items[]?]
    elif ($p | type) == "object" and ($p.tracks? | type) == "array" then [$p.tracks[]?.items[]?]
    else [] end;
  def heavy($r):
    ((($r.command_kind // $r.kind // $r.validation_kind // "") | test("heavy|cargo|rch|build|clippy|test"; "i"))
      or (($r.requested_command // $r.command // "") | test("(^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$)"))
      or (($r.requested_command // $r.command // "") | test("rch[[:space:]]+exec"; "i")));
  def lane_id($r): ($r.lane_id // $r.request_id // $r.id // $r.bead_id // "unknown-lane");
  def agent_id($r): ($r.agent_id // $r.assignee // $r.owner // "unassigned");
  def priority($r): (($r.priority // $r.bead_priority // 3) | tonumber);
  def write_paths($r):
    if ($r.planned_write_paths // null) != null then $r.planned_write_paths
    elif ($r.write_paths // null) != null then $r.write_paths
    elif ($r.paths // null) != null then $r.paths
    else [] end;
  def reservation_rows: rows($reservations[0]; "reservations") + rows($reservations[0]; "granted");
  def reservation_conflict($r):
    (write_paths($r)) as $paths
    | [reservation_rows[]
       | (.path_pattern // .path // "") as $reserved
       | (.agent_name // .holder // "") as $holder
       | select(($reserved | length) > 0 and ($paths | index($reserved)) != null and $holder != "" and $holder != agent_id($r))
      ] | length > 0;
  def classify($r; $state):
    ($envelope[0]) as $env
    | ($env.capacity_budget // {}) as $budget
    | heavy($r) as $is_heavy
    | agent_id($r) as $agent
    | (($state.agent_counts[$agent] // 0) | tonumber) as $agent_count
    | {
        lane_id: lane_id($r),
        bead_id: ($r.bead_id // $r.id // null),
        title: ($r.title // null),
        agent_id: $agent,
        priority: priority($r),
        heavy_lane: $is_heavy,
        requested_command: ($r.requested_command // $r.command // null),
        planned_write_paths: write_paths($r),
        requested_cpu_slots: (($r.requested_cpu_slots // (if $is_heavy then 1 else 0 end)) | tonumber),
        requested_memory_bytes: (($r.requested_memory_bytes // 0) | tonumber),
        requested_rch_slots: (($r.requested_rch_slots // (if $is_heavy then 1 else 0 end)) | tonumber),
        proof_cache_hint: ($proof[0].proof_cache_decision // $env.proof_cache.decision // "missing"),
        fairness_rationale: [],
        reasons: []
      }
    | if ($fail_closed[0] | length) > 0 then
        .decision = "defer" | .reasons += ["fail_closed_input_truth"] | .fairness_rationale += ["input truth must be repaired before admission"]
      elif low($env.decision) == "blocked" then
        .decision = "defer" | .reasons += ["resource_envelope_blocked"] | .fairness_rationale += ["capacity evidence is trustworthy but saturated"]
      elif reservation_conflict($r) then
        .decision = "defer" | .reasons += ["conflicting_reservation"] | .fairness_rationale += ["reservation holder keeps write ownership"]
      elif $agent_count >= $max_lanes_per_agent then
        .decision = "defer" | .reasons += ["per_agent_fair_share_limit"] | .fairness_rationale += ["per-agent admission cap preserves swarm fairness"]
      elif $is_heavy and (($state.heavy_used + 1) > (($budget.build_lane_limit // 0) | tonumber)) then
        .decision = "defer" | .reasons += ["build_lane_budget_exhausted"] | .fairness_rationale += ["heavy lanes cannot exceed envelope build lane limit"]
      elif $is_heavy and (($state.rch_used + (.requested_rch_slots // 1)) > (($budget.remote_rch_slot_limit // 0) | tonumber)) then
        .decision = "defer" | .reasons += ["rch_slot_budget_exhausted"] | .fairness_rationale += ["RCH lane use cannot exceed envelope remote slot limit"]
      elif ((.requested_memory_bytes // 0) > (($budget.memory_bytes_budget // 0) | tonumber)) then
        .decision = "defer" | .reasons += ["memory_budget_exhausted"] | .fairness_rationale += ["lane memory request exceeds envelope memory headroom"]
      elif (($budget.target_dir_bytes_budget // 0) | tonumber) <= 0 and $is_heavy then
        .decision = "defer" | .reasons += ["target_dir_budget_exhausted"] | .fairness_rationale += ["heavy lanes require target-dir headroom"]
      else
        .decision = (if $is_heavy then "admit_narrow" else "admit" end)
        | .fairness_rationale += [if $is_heavy then "heavy lane admitted within build/RCH budgets" else "script lane admitted within per-agent cap" end]
      end;
  ($envelope[0]) as $env
  | (plan_items($bv[0]) | sort_by(priority(.), agent_id(.), lane_id(.))) as $items
  | reduce $items[] as $item (
      {rows:[], heavy_used:0, rch_used:0, agent_counts:{}};
      classify($item; .) as $row
      | .rows += [$row]
      | if ($row.decision | IN("admit","admit_narrow")) then
          .agent_counts[$row.agent_id] = ((.agent_counts[$row.agent_id] // 0) + 1)
          | if $row.heavy_lane then
              .heavy_used += 1
              | .rch_used += ($row.requested_rch_slots // 1)
            else . end
        else . end
    ) as $state
  | ($state.rows | map(select(.decision | IN("admit","admit_narrow")))) as $admitted
  | ($state.rows | map(select(.decision == "defer"))) as $deferred
  | {
      schema_version:$schema_version,
      source_revision:$source_revision,
      plan_id: ("swarm-fair-share-" + ($input_hash | gsub("[^A-Fa-f0-9]"; "")[0:16])),
      input_hash:$input_hash,
      decision: (
        if (($fail_closed[0] | length) > 0) then "fail_closed"
        elif ($admitted | length) > 0 and ($deferred | length) == 0 then "admit"
        elif ($admitted | length) > 0 then "admit_narrow"
        else "defer" end
      ),
      summary:{
        requested_count:($state.rows | length),
        admitted_count:($admitted | length),
        deferred_count:($deferred | length),
        heavy_admitted_count:($admitted | map(select(.heavy_lane)) | length),
        heavy_lane_limit:(($env.capacity_budget.build_lane_limit // 0) | tonumber),
        remote_rch_slot_limit:(($env.capacity_budget.remote_rch_slot_limit // 0) | tonumber),
        rch_slots_used:$state.rch_used,
        max_lanes_per_agent:$max_lanes_per_agent,
        contaminated_input:(($fail_closed[0] | length) > 0)
      },
      capacity_budget:($env.capacity_budget // {}),
      fairness_rationale:($state.rows | map(.fairness_rationale[]) | unique | sort),
      admitted_lanes:$admitted,
      deferred_lanes:$deferred,
      proof_cache_reuse_hints:{
        decision:($proof[0].proof_cache_decision // $env.proof_cache.decision // "missing"),
        cache_hit_artifacts:($proof[0].cache_hit_artifacts // [])
      },
      source_decisions:{
        resource_envelope_decision:($env.decision // "unknown"),
        causal_trace_decision:($causal[0].decision // "missing")
      },
      fail_closed_reasons:$fail_closed[0],
      resolved_inputs:[
        {input:"resource_envelope_json", path:$resource_envelope_json},
        {input:"bv_actionable_plan_json", path:$bv_actionable_plan_json},
        {input:"validation_cost_hints_json", path:$validation_cost_hints_json},
        {input:"proof_cache_plan_json", path:$proof_cache_plan_json},
        {input:"active_reservations_json", path:$active_reservations_json},
        {input:"causal_trace_summary_json", path:$causal_trace_summary_json}
      ],
      mutation_policy:{
        fixture_fed_only:true,
        proof_only:true,
        advisory_only:true,
        mutates_br:false,
        reassigns_beads:false,
        releases_reservations:false,
        sends_agent_mail:false,
        queries_live_agent_mail:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        deletes_target_dirs:false,
        repairs_stalled_builds:false,
        changes_live_queue_policy:false
      },
      artifact_paths:{
        swarm_fair_share_batch_plan_json:$plan_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_path
      }
    }
  ' >"$plan_tmp"
mv "$plan_tmp" "$plan_path"

write_event "planner_completed" "$(jq -r '.decision' "$plan_path")"

{
  printf '# Swarm Fair-Share Batch Plan\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$plan_path")"
  printf -- "- Requested: \`%s\`\n" "$(jq -r '.summary.requested_count' "$plan_path")"
  printf -- "- Admitted: \`%s\`\n" "$(jq -r '.summary.admitted_count' "$plan_path")"
  printf -- "- Deferred: \`%s\`\n" "$(jq -r '.summary.deferred_count' "$plan_path")"
  printf -- "- Heavy admitted: \`%s\`\n" "$(jq -r '.summary.heavy_admitted_count' "$plan_path")"
} >"$report_path"

printf 'swarm_fair_share_batch_plan=%s\n' "$plan_path"

case "$(jq -r '.decision' "$plan_path")" in
  admit|admit_narrow)
    exit 0
    ;;
  defer)
    exit 75
    ;;
  *)
    exit 42
    ;;
esac
