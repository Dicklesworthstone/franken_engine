#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_SATURATION_REPLAY_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-saturation-replay-drill}"
run_id="${SWARM_SATURATION_REPLAY_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_SATURATION_REPLAY_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

scenario_json=""
source_revision="${SWARM_SATURATION_REPLAY_DRILL_SOURCE_REVISION:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_saturation_replay_drill.sh --scenario-json FILE [OPTIONS]

Replays a deterministic many-agent SWARM-OPS saturation scenario from fixtures.
This drill is artifact-driven only. It does not execute build commands, query
live workers, mutate beads, release reservations, send Agent Mail, or repair
target directories.

Required:
  --scenario-json FILE

Options:
  --source-revision REV
  --output-dir DIR

Artifacts:
  run_manifest.json
  events.jsonl
  commands.txt
  saturation_replay_report.json
  trace_ids.json

Exit codes:
  0   replay succeeded; decision may be pass or degraded
  42  fail-closed evidence prevents saturation planning
  64  invalid option or malformed input
  75  trustworthy constraints block every lane
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --scenario-json)
      scenario_json="${2:-}"
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
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$scenario_json" ]]; then
  printf 'saturation replay drill requires --scenario-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for saturation replay drill\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for saturation replay drill\n' >&2
  exit 2
fi
if [[ ! -f "$scenario_json" ]]; then
  printf 'missing scenario JSON: %s\n' "$scenario_json" >&2
  exit 64
fi
if ! jq empty "$scenario_json" >/dev/null 2>&1; then
  printf 'invalid scenario JSON: %s\n' "$scenario_json" >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/saturation_replay_report.json"
report_core_path="${run_dir}/saturation_replay_report.core.json"
report_tmp="${report_path}.tmp"
trace_ids_path="${run_dir}/trace_ids.json"
scenario_normalized="${run_dir}/scenario.normalized.json"
: >"$events_path"

printf './scripts/swarm_saturation_replay_drill.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -cS . "$scenario_json" >"$scenario_normalized"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-saturation-replay-drill.event.v1" \
    --arg component "swarm_saturation_replay_drill" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    --arg evidence_path "$4" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail,evidence_path:$evidence_path}' \
    >>"$events_path"
}

write_event "input.loaded" "ok" "scenario fixture" "$scenario_json"

jq -n \
  --slurpfile scenario "$scenario_normalized" \
  --arg schema_version "franken-engine.swarm-saturation-replay-report.v1" \
  --arg source_revision "$source_revision" \
  --arg scenario_json "$scenario_json" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg trace_ids_path "$trace_ids_path" '
  def low($value): (($value // "") | tostring | ascii_downcase);
  def arr($value): if ($value | type) == "array" then $value else [] end;
  def reason($code; $source; $detail): {code:$code,source_id:$source,detail:$detail};
  def heavy($class): low($class) | IN("cargo_check", "cargo_clippy", "cargo_test", "rust_validation");
  def light($class): low($class) | IN("script_gate", "docs_only", "shell_gate", "json_gate");
  def owner_blocked($state): low($state) | IN("blocked", "active_owner_blocked", "manual_review");
  def owner_stale($state): low($state) | IN("stale", "needs_contact");
  def lane($request; $decision; $reason_codes; $transport):
    {
      request_id:($request.request_id // ""),
      agent_id:($request.agent_id // ""),
      bead_id:($request.bead_id // ""),
      priority:(($request.priority // 3) | tonumber),
      urgent:(($request.urgent // false) == true),
      command_class:($request.command_class // "unknown"),
      owner_state:($request.owner_state // "healthy"),
      before_decision:($request.before_decision // "requested"),
      after_decision:$decision,
      reason_codes:$reason_codes,
      transport:$transport
    };

  ($scenario[0]) as $s
  | ($s.host // {}) as $host
  | ($s.constraints // {}) as $constraints
  | (arr($s.requests)
      | sort_by((.priority // 3 | tonumber), (if (.urgent // false) == true then 0 else 1 end), (.agent_id // ""), (.request_id // ""))) as $requests
  | (($host.remote_rch_slots // 0) | tonumber) as $remote_slots
  | (($constraints.heavy_fanout_cap // $remote_slots // 0) | tonumber) as $heavy_fanout_cap
  | (($constraints.urgent_slack_slots // 0) | tonumber) as $urgent_slack_slots
  | (($constraints.max_heavy_per_agent // 1) | tonumber) as $max_heavy_per_agent
  | (($s.evidence.local_fallback_observed // false) == true) as $local_fallback
  | ([
      if (($s.schema_version // "") != "franken-engine.swarm-saturation-replay-scenario.v1") then reason("bad_schema"; "scenario_json"; "scenario schema is unexpected") else empty end,
      if (($requests | length) == 0) then reason("missing_requests"; "scenario_json"; "scenario must contain at least one request") else empty end,
      if $remote_slots < 0 or $heavy_fanout_cap < 0 or $urgent_slack_slots < 0 or $max_heavy_per_agent < 0 then reason("invalid_capacity_constraint"; "scenario_json"; "capacity constraints must be non-negative") else empty end,
      if $local_fallback then reason("local_fallback_contamination"; "scenario_json"; "local fallback evidence invalidates remote saturation planning") else empty end,
      if (($s.mutation_policy.runs_cargo // false) == true) or (($s.mutation_policy.runs_rch // false) == true) or (($s.mutation_policy.mutates_remote_workers // false) == true) or (($s.mutation_policy.mutates_br // false) == true) then reason("unsafe_mutation_policy"; "scenario_json"; "scenario claims live mutation or execution authority") else empty end
    ] | unique_by([.code, .source_id, .detail])) as $fail_closed_reasons
  | (reduce $requests[] as $r (
      {
        lanes:[],
        nonurgent_heavy_count:0,
        urgent_heavy_count:0,
        remote_heavy_count:0,
        per_agent_heavy:{},
        fairness_deferrals:0
      };
      ($r.command_class // "unknown") as $class
      | ($r.agent_id // "unknown") as $agent
      | (($r.urgent // false) == true) as $urgent
      | (($r.owner_state // "healthy")) as $owner_state
      | (if ($fail_closed_reasons | length) > 0 then
          .lanes += [lane($r; "fail_closed"; ($fail_closed_reasons | map(.code) | unique | sort); "none")]
        elif owner_blocked($owner_state) then
          .lanes += [lane($r; "defer"; ["blocked_ownership"]; "none")]
        elif owner_stale($owner_state) then
          .lanes += [lane($r; "defer"; ["stale_ownership_requires_contact"]; "none")]
        elif heavy($class) then
          (if $urgent then
             if .remote_heavy_count < $remote_slots then
               .lanes += [lane($r; "admit"; ["urgent_lane_admitted"]; "rch_required")]
               | .urgent_heavy_count += 1
               | .remote_heavy_count += 1
             else
               .lanes += [lane($r; "defer"; ["remote_slot_limit"]; "none")]
             end
           elif .nonurgent_heavy_count >= $heavy_fanout_cap then
             .lanes += [lane($r; "defer"; ["heavy_fanout_cap"]; "none")]
           elif .nonurgent_heavy_count >= ([($remote_slots - $urgent_slack_slots), 0] | max) then
             .lanes += [lane($r; "defer"; ["urgent_slack_reserved"]; "none")]
           elif ((.per_agent_heavy[$agent] // 0) >= $max_heavy_per_agent) then
             .lanes += [lane($r; "defer"; ["fairness_agent_cap"]; "none")]
             | .fairness_deferrals += 1
           else
             .lanes += [lane($r; "admit"; ["rch_heavy_lane_admitted"]; "rch_required")]
             | .nonurgent_heavy_count += 1
             | .remote_heavy_count += 1
             | .per_agent_heavy[$agent] = ((.per_agent_heavy[$agent] // 0) + 1)
           end)
        elif light($class) then
          .lanes += [lane($r; "admit"; ["fixture_safe_light_lane"]; "fixture_only")]
        else
          .lanes += [lane($r; "defer"; ["unknown_command_class"]; "none")]
        end
    ))) as $replay
  | ($replay.lanes) as $lanes
  | ($lanes | map(select(.after_decision == "admit"))) as $admitted
  | ($lanes | map(select(.after_decision != "admit"))) as $deferred
  | ($admitted | map(select(heavy(.command_class) and (.urgent | not)))) as $admitted_nonurgent_heavy
  | ($admitted | map(select(heavy(.command_class) and .urgent))) as $admitted_urgent_heavy
  | ($deferred | map(.reason_codes[]) | unique | sort) as $deferred_reason_codes
  | ($admitted_nonurgent_heavy | group_by(.agent_id) | map({agent_id:.[0].agent_id,count:length})) as $admitted_heavy_by_agent
  | ([
      if (($admitted_nonurgent_heavy | length) > $heavy_fanout_cap) then reason("heavy_fanout_exceeded"; "replay"; "non-urgent heavy admissions exceed fanout cap") else empty end,
      if (($admitted_nonurgent_heavy | length) > ([($remote_slots - $urgent_slack_slots), 0] | max)) then reason("urgent_slack_not_reserved"; "replay"; "non-urgent heavy admissions consume urgent slack") else empty end,
      if any($admitted_heavy_by_agent[]?; .count > $max_heavy_per_agent) then reason("fairness_agent_cap_exceeded"; "replay"; "one agent received more heavy lanes than the fairness cap") else empty end,
      if $local_fallback and (($admitted | length) > 0) then reason("local_fallback_admitted_lane"; "replay"; "local fallback scenario admitted work") else empty end
    ] | unique_by([.code, .source_id, .detail])) as $invariant_failures
  | (if ($fail_closed_reasons | length) > 0 or ($invariant_failures | length) > 0 then "fail_closed"
     elif (($admitted | length) == 0) then "blocked"
     elif (($deferred | length) > 0) then "degraded"
     else "pass" end) as $decision
  | {
      schema_version:$schema_version,
      bead_id:"bd-2zn02",
      source_revision:$source_revision,
      scenario_id:($s.scenario_id // "unknown"),
      host_profile:($host.profile // "unknown"),
      decision:$decision,
      before_lane_decisions:($requests | map({
        request_id:(.request_id // ""),
        agent_id:(.agent_id // ""),
        bead_id:(.bead_id // ""),
        priority:(.priority // 3),
        urgent:(.urgent // false),
        command_class:(.command_class // "unknown"),
        owner_state:(.owner_state // "healthy"),
        before_decision:(.before_decision // "requested")
      })),
      after_lane_decisions:$lanes,
      fairness_report:{
        max_heavy_per_agent:$max_heavy_per_agent,
        admitted_heavy_by_agent:$admitted_heavy_by_agent,
        fairness_deferral_count:$replay.fairness_deferrals,
        fairness_preserved:(all($admitted_heavy_by_agent[]?; .count <= $max_heavy_per_agent))
      },
      fanout_report:{
        remote_rch_slots:$remote_slots,
        heavy_fanout_cap:$heavy_fanout_cap,
        urgent_slack_slots:$urgent_slack_slots,
        admitted_nonurgent_heavy_count:($admitted_nonurgent_heavy | length),
        admitted_urgent_heavy_count:($admitted_urgent_heavy | length),
        heavy_fanout_capped:(($admitted_nonurgent_heavy | length) <= $heavy_fanout_cap),
        urgent_slack_preserved:(($admitted_nonurgent_heavy | length) <= ([($remote_slots - $urgent_slack_slots), 0] | max))
      },
      contamination_report:{
        local_fallback_observed:$local_fallback,
        admitted_lane_count_when_contaminated:(if $local_fallback then ($admitted | length) else 0 end),
        local_fallback_contamination_avoided:(if $local_fallback then (($admitted | length) == 0) else true end)
      },
      summary:{
        total_requests:($requests | length),
        admitted_count:($admitted | length),
        deferred_count:($deferred | length),
        heavy_admitted_count:($admitted | map(select(heavy(.command_class))) | length),
        light_admitted_count:($admitted | map(select(light(.command_class))) | length),
        stale_or_blocked_lane_count:($lanes | map(select((.reason_codes | index("blocked_ownership") != null) or (.reason_codes | index("stale_ownership_requires_contact") != null))) | length),
        deferred_reason_codes:$deferred_reason_codes
      },
      fail_closed_reasons:($fail_closed_reasons + $invariant_failures | unique_by([.code, .source_id, .detail])),
      mutation_policy:{
        fixture_fed_only:true,
        replay_only:true,
        advisory_only:true,
        mutates_br:false,
        releases_reservations:false,
        sends_agent_mail:false,
        queries_live_agent_mail:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false,
        writes_outside_output_dir:false
      },
      source_artifacts:{
        scenario_json:$scenario_json
      },
      artifact_paths:{
        run_manifest_json:$manifest_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        saturation_replay_report_json:$report_path,
        trace_ids_json:$trace_ids_path
      }
    }' >"$report_core_path"

replay_hash="$(jq -cS 'del(.artifact_paths)' "$report_core_path" | sha256sum | awk '{print $1}')"
replay_id="swarm-saturation-replay-${replay_hash:0:16}"
jq --arg replay_id "$replay_id" --arg replay_hash "$replay_hash" \
  '. + {replay_id:$replay_id, hash_basis:{replay_hash:$replay_hash}}' \
  "$report_core_path" >"$report_tmp"
mv "$report_tmp" "$report_path"

decision="$(jq -r '.decision' "$report_path")"
write_event "saturation_replay.emitted" "$decision" "emitted saturation replay report" "$report_path"

jq -n \
  --arg schema_version "franken-engine.swarm-saturation-replay-run-manifest.v1" \
  --arg replay_id "$replay_id" \
  --arg source_revision "$source_revision" \
  --arg scenario_json "$scenario_json" \
  --arg report_path "$report_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg trace_ids_path "$trace_ids_path" \
  '{
    schema_version:$schema_version,
    replay_id:$replay_id,
    source_revision:$source_revision,
    scenario_json:$scenario_json,
    artifact_paths:{
      saturation_replay_report_json:$report_path,
      events_jsonl:$events_path,
      commands_txt:$commands_path,
      trace_ids_json:$trace_ids_path
    },
    mutation_policy:{
      fixture_fed_only:true,
      replay_only:true,
      runs_cargo:false,
      runs_rch:false,
      mutates_remote_workers:false,
      mutates_br:false
    }
  }' >"$manifest_path"

jq -n \
  --arg schema_version "franken-engine.swarm-saturation-replay-trace-ids.v1" \
  --arg replay_id "$replay_id" \
  --arg scenario_id "$(jq -r '.scenario_id // "unknown"' "$report_path")" \
  --arg replay_hash "$replay_hash" \
  '{
    schema_version:$schema_version,
    replay_id:$replay_id,
    trace_ids:[
      ("trace-saturation-" + $scenario_id),
      ("trace-saturation-hash-" + ($replay_hash[0:16]))
    ]
  }' >"$trace_ids_path"

printf 'saturation_replay_report_json=%s\n' "$report_path"
printf 'run_manifest_json=%s\n' "$manifest_path"
printf 'trace_ids_json=%s\n' "$trace_ids_path"

case "$decision" in
  fail_closed)
    exit 42
    ;;
  blocked)
    exit 75
    ;;
  *)
    exit 0
    ;;
esac
