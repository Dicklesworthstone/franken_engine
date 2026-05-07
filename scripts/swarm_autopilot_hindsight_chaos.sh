#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_AUTOPILOT_HINDSIGHT_CHAOS_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-autopilot-hindsight-chaos}"
run_id="${SWARM_AUTOPILOT_HINDSIGHT_CHAOS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AUTOPILOT_HINDSIGHT_CHAOS_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_AUTOPILOT_HINDSIGHT_CHAOS_SOURCE_REVISION:-unknown}"
source_bundle_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_autopilot_hindsight_chaos.sh [OPTIONS]

Generate deterministic hindsight and chaos scenarios from a completed swarm
autopilot source bundle. The generator is advisory only and proof only. It does
not mutate beads, reservations, Agent Mail, workers, live queue policy, Cargo,
or RCH.

Required inputs:
  --source-bundle-json FILE

Optional inputs:
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_autopilot_hindsight_chaos_scenarios.json
  swarm_autopilot_hindsight_chaos_replay_index.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   scenarios emitted and replay invariants are complete
  42  stale, contaminated, missing, or under-specified scenario material failed closed
  64  invalid command-line arguments
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --source-bundle-json)
      source_bundle_json="${2:-}"
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

if [[ -z "$source_bundle_json" ]]; then
  printf 'source bundle JSON is required\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the hindsight chaos generator\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for the hindsight chaos generator\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
scenarios_path="${run_dir}/swarm_autopilot_hindsight_chaos_scenarios.json"
scenarios_tmp="${scenarios_path}.tmp"
replay_index_path="${run_dir}/swarm_autopilot_hindsight_chaos_replay_index.json"
replay_index_tmp="${replay_index_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
source_normalized="${run_dir}/source_bundle.normalized.json"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"
scenario_records_jsonl="${run_dir}/scenario_records.jsonl"

printf './scripts/swarm_autopilot_hindsight_chaos.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$fail_closed_reasons_jsonl"
: >"$scenario_records_jsonl"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-hindsight-chaos.event.v1" \
    --arg trace_id "trace-swarm-autopilot-hindsight-chaos-${run_id}" \
    --arg component "$1" \
    --arg event "$2" \
    --arg outcome "$3" \
    --arg error_code "$4" \
    --arg evidence_path "$5" \
    '{
      schema_version:$schema_version,
      trace_id:$trace_id,
      component:$component,
      event:$event,
      outcome:$outcome,
      error_code:(if $error_code == "" then null else $error_code end),
      evidence_path:$evidence_path
    }' >>"$events_path"
}

append_failure() {
  jq -nc \
    --arg code "$1" \
    --arg source_id "$2" \
    --arg detail "$3" \
    --arg remediation_command "$4" \
    '{
      code:$code,
      source_id:$source_id,
      detail:$detail,
      remediation_command:$remediation_command
    }' >>"$fail_closed_reasons_jsonl"
  write_event "hindsight_chaos_generator" "fail_closed_reason_recorded" "fail_closed" "$1" "$2"
}

if [[ ! -f "$source_bundle_json" ]]; then
  printf 'missing required source bundle JSON: %s\n' "$source_bundle_json" >&2
  exit 64
fi
if ! jq empty "$source_bundle_json" >/dev/null 2>&1; then
  printf 'invalid required source bundle JSON: %s\n' "$source_bundle_json" >&2
  exit 64
fi
jq -cS . "$source_bundle_json" >"$source_normalized"
write_event "source_bundle" "input_loaded" "captured" "" "$source_normalized"

check_shape() {
  local expr="$1"
  local code="$2"
  local source_id="$3"
  local detail="$4"
  local remediation="$5"
  if ! jq -e "$expr" "$source_normalized" >/dev/null 2>&1; then
    append_failure "$code" "$source_id" "$detail" "$remediation"
  fi
}

check_shape '
  .schema_version == "franken-engine.swarm-autopilot-hindsight-source-bundle.v1"
  and ((.completed_bundle_id // "") | (type == "string" and length > 0))
  and ((.source_artifacts.brownout_forecast_json // "") | (type == "string" and length > 0))
  and ((.source_artifacts.resource_lease_plan_json // "") | (type == "string" and length > 0))
  and ((.source_artifacts.resource_scarcity_receipts_json // "") | (type == "string" and length > 0))
  and ((.source_artifacts.operator_intent_policy_json // "") | (type == "string" and length > 0))
  and ((.source_artifacts.queue_advisory_bundle_json // "") | (type == "string" and length > 0))
  and ((.base_state.rch_slots_available // null) | type == "number")
  and ((.base_state.worker_stale_progress_count // null) | type == "number")
  and ((.base_state.target_dir_pressure_millionths // null) | type == "number")
  and ((.base_state.proof_cache_pressure_millionths // null) | type == "number")
  and ((.base_state.fairness_skew_millionths // null) | type == "number")
  and (.base_state | has("local_fallback_contaminated"))
  and ((.base_state.local_fallback_contaminated | type) == "boolean")
  and ((.requested_perturbations // null) | type == "array")
  and ((.requested_perturbations | length) > 0)
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-HINDSIGHT-CHAOS-SCHEMA-DRIFT" "source_bundle_json" \
  "source bundle lacks required artifact paths, base state, perturbations, or safety markers" \
  "Regenerate the completed autopilot source bundle before creating hindsight chaos scenarios."

check_shape '
  all(.requested_perturbations[]?;
    ((.perturbation_id // "") | (type == "string" and length > 0))
    and ((.perturbation_type // "") | (type == "string" and length > 0))
    and ((.delta // null) | type == "object")
    and ((.stress_targets // null) | type == "array")
  )
' "FE-SWARM-AUTOPILOT-HINDSIGHT-CHAOS-SCHEMA-DRIFT" "requested_perturbations" \
  "one or more perturbations lack ids, types, deltas, or stress targets" \
  "Provide explicit perturbation ids, types, deltas, and stress targets before generating scenarios."

if jq -e '
  (.base_state.local_fallback_contaminated == true)
  or any(.requested_perturbations[]?; (.perturbation_type // "") == "local_fallback_contamination" or (.delta.local_fallback_contaminated == true))
' "$source_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-HINDSIGHT-CHAOS-LOCAL-FALLBACK" "local_fallback_state" \
    "local fallback contamination cannot produce replayable remote-only chaos scenarios" \
    "Discard contaminated local-fallback material or keep it quarantined as non-replayable evidence."
fi

if jq -e '
  any(.requested_perturbations[]?;
    ((.expected_invariant // "") | length) == 0
    or ((.replay_command // "") | length) == 0
  )
' "$source_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-HINDSIGHT-CHAOS-UNDER-SPECIFIED" "requested_perturbations" \
    "one or more generated scenarios lack a replay command or clear expected invariant" \
    "Attach exact replay commands and expected invariants to every requested perturbation."
fi

if jq -e '
  any([
    .source_freshness?,
    .base_state.freshness?,
    .requested_perturbations[]?.freshness?
  ] | map(tostring)[]; test("stale"; "i"))
' "$source_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-HINDSIGHT-CHAOS-STALE-SOURCE" "source_bundle_json" \
    "source bundle or requested perturbations contain stale freshness markers" \
    "Refresh the source bundle before generating hindsight chaos scenarios."
fi

source_sha="$(sha256sum "$source_normalized" | awk '{print $1}')"
if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(jq -r '.source_revision // "unknown"' "$source_normalized")"
fi

while IFS= read -r perturbation_json; do
  perturbation_id="$(jq -r '.perturbation_id // "unknown"' <<<"$perturbation_json")"
  scenario_hash="$(printf '%s\n%s\n' "$source_sha" "$perturbation_json" | sha256sum | awk '{print $1}')"
  jq -nc \
    --slurpfile source "$source_normalized" \
    --argjson perturbation "$perturbation_json" \
    --arg scenario_hash "$scenario_hash" \
    --arg source_sha "$source_sha" \
    '
    def stable_id($prefix; $value): ($prefix + "-" + (($value // "unknown") | gsub("[^A-Za-z0-9]+"; "-") | ascii_downcase));
    ($source[0]) as $src
    | ($perturbation.expected_invariant // "") as $expected_invariant
    | ($perturbation.replay_command // "") as $replay_command
    | (($expected_invariant | length) > 0 and ($replay_command | length) > 0 and (($perturbation.delta.local_fallback_contaminated // false) == false)) as $replay_ready
    | {
        scenario_id: stable_id("hindsight-chaos"; $perturbation.perturbation_id),
        scenario_hash: $scenario_hash,
        scenario_hash_basis: {
          source_bundle_sha256: $source_sha,
          perturbation_id: $perturbation.perturbation_id,
          perturbation_type: $perturbation.perturbation_type,
          delta: ($perturbation.delta // {})
        },
        source_bundle_id: $src.completed_bundle_id,
        source_revision: ($src.source_revision // "unknown"),
        perturbation_type: $perturbation.perturbation_type,
        stress_targets: ($perturbation.stress_targets // []),
        source_artifacts: $src.source_artifacts,
        base_state: $src.base_state,
        delta: ($perturbation.delta // {}),
        expected_invariant: (if $expected_invariant == "" then null else $expected_invariant end),
        replay_command: (if $replay_command == "" then null else $replay_command end),
        replay_ready: $replay_ready,
        reason_codes: (
          if (($perturbation.delta.local_fallback_contaminated // false) == true) then
            ["local_fallback_contamination", "quarantine_only"]
          elif ($expected_invariant == "" or $replay_command == "") then
            ["under_specified_replay"]
          else
            ($perturbation.reason_codes // ["deterministic_hindsight_chaos"])
          end
        )
      }
    ' >>"$scenario_records_jsonl"
  write_event "hindsight_chaos_generator" "scenario_materialized" "captured" "" "$perturbation_id"
done < <(jq -c '.requested_perturbations[]?' "$source_normalized")

decision="pass"
truth_state="confirmed"
exit_code=0
if [[ -s "$fail_closed_reasons_jsonl" ]]; then
  decision="fail_closed"
  truth_state="unknown"
  exit_code=42
fi

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-hindsight-chaos-scenarios.v1" \
  --arg bead_id "bd-09g6k" \
  --arg source_revision "$source_revision" \
  --arg source_bundle_json "$source_bundle_json" \
  --arg scenarios_path "$scenarios_path" \
  --arg replay_index_path "$replay_index_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg decision "$decision" \
  --arg truth_state "$truth_state" \
  --slurpfile source "$source_normalized" \
  --slurpfile scenarios "$scenario_records_jsonl" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" '
  ($source[0]) as $src
  | ($scenarios | sort_by(.scenario_id)) as $scenario_list
  | {
      schema_version:$schema_version,
      bead_id:$bead_id,
      source_revision:$source_revision,
      decision:$decision,
      truth_state:$truth_state,
      completed_bundle_id:$src.completed_bundle_id,
      source_artifacts:$src.source_artifacts,
      scenario_summary:{
        scenario_count:($scenario_list | length),
        replay_ready_count:($scenario_list | map(select(.replay_ready == true)) | length),
        brownout_count:($scenario_list | map(select(.perturbation_type | test("brownout"; "i"))) | length),
        stale_ownership_count:($scenario_list | map(select(.perturbation_type | test("stale_ownership"; "i"))) | length),
        local_fallback_count:($scenario_list | map(select(.perturbation_type | test("local_fallback"; "i"))) | length),
        recommendation_bundle_stress_count:($scenario_list | map(select((.stress_targets // []) | index("recommendation_bundle") != null)) | length)
      },
      scenarios:$scenario_list,
      fail_closed_reasons:($fail_closed_reasons | unique_by([.code, .source_id, .detail])),
      artifact_paths:{
        scenarios_json:$scenarios_path,
        replay_index_json:$replay_index_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_path,
        source_bundle_json:$source_bundle_json
      },
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        fixture_fed_only:true,
        mutates_br:false,
        reassigns_beads:false,
        releases_reservations:false,
        sends_agent_mail:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false,
        approves_replay_automatically:false,
        promotes_recommendations_automatically:false
      }
    }' >"$scenarios_tmp"
mv "$scenarios_tmp" "$scenarios_path"

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-hindsight-chaos-replay-index.v1" \
  --arg bead_id "bd-09g6k" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg scenarios_path "$scenarios_path" \
  --arg replay_index_path "$replay_index_path" \
  --slurpfile scenarios_doc "$scenarios_path" '
  ($scenarios_doc[0]) as $doc
  | {
      schema_version:$schema_version,
      bead_id:$bead_id,
      source_revision:$source_revision,
      decision:$decision,
      completed_bundle_id:$doc.completed_bundle_id,
      entries:($doc.scenarios | map({
        scenario_id,
        scenario_hash,
        perturbation_type,
        stress_targets,
        replay_ready,
        replay_command,
        expected_invariant,
        source_artifacts,
        reason_codes
      })),
      fail_closed_reasons:$doc.fail_closed_reasons,
      artifact_paths:{
        replay_index_json:$replay_index_path,
        scenarios_json:$scenarios_path
      },
      mutation_policy:$doc.mutation_policy
    }' >"$replay_index_tmp"
mv "$replay_index_tmp" "$replay_index_path"

{
  printf '# SWARM_AUTOPILOT_HINDSIGHT_CHAOS\n\n'
  printf -- "- decision: \`%s\`\n" "$(jq -r '.decision' "$scenarios_path")"
  printf -- "- scenario_count: \`%s\`\n" "$(jq -r '.scenario_summary.scenario_count' "$scenarios_path")"
  printf -- "- replay_ready_count: \`%s\`\n" "$(jq -r '.scenario_summary.replay_ready_count' "$scenarios_path")"
  printf '\n## Scenarios\n'
  jq -r '.scenarios[] | "- `\(.scenario_id)` type=`\(.perturbation_type)` replay_ready=`\(.replay_ready)` hash=`\(.scenario_hash)`"' "$scenarios_path"
  if jq -e '.fail_closed_reasons | length > 0' "$scenarios_path" >/dev/null; then
    printf '\n## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `\(.code)` from `\(.source_id)`: \(.detail)"' "$scenarios_path"
  fi
} >"$report_path"

write_event "hindsight_chaos_generator" "scenarios_emitted" "$decision" "" "$scenarios_path"
write_event "hindsight_chaos_generator" "replay_index_emitted" "$decision" "" "$replay_index_path"

exit "$exit_code"
