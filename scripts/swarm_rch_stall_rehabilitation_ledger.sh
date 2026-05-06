#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_RCH_STALL_REHABILITATION_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-rch-stall-rehabilitation}"
run_id="${SWARM_RCH_STALL_REHABILITATION_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_RCH_STALL_REHABILITATION_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_RCH_STALL_REHABILITATION_SOURCE_REVISION:-unknown}"
swarm_ops_state_snapshot_json=""
worker_status_json=""
stall_observations_json=""
worker_capabilities_json=""
operator_actions_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_rch_stall_rehabilitation_ledger.sh [OPTIONS]

Build an advisory-only RCH stall quarantine and rehabilitation ledger from
preserved SWARM-OPS state, worker/job status, and remote stall observations.
This script never mutates workers, beads, reservations, or Agent Mail.

Required inputs:
  --swarm-ops-state-snapshot-json FILE
  --worker-status-json FILE
  --stall-observations-json FILE

Optional inputs:
  --worker-capabilities-json FILE
  --operator-actions-json FILE
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_rch_stall_rehabilitation_ledger.json
  swarm_rch_stall_rehabilitation_receipts.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  ledger is replayable; decision may be pass or degraded
  42 malformed or untrusted required evidence prevented truthful classification
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --swarm-ops-state-snapshot-json)
      swarm_ops_state_snapshot_json="${2:-}"
      shift 2
      ;;
    --worker-status-json)
      worker_status_json="${2:-}"
      shift 2
      ;;
    --stall-observations-json)
      stall_observations_json="${2:-}"
      shift 2
      ;;
    --worker-capabilities-json)
      worker_capabilities_json="${2:-}"
      shift 2
      ;;
    --operator-actions-json)
      operator_actions_json="${2:-}"
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

if [[ -z "$swarm_ops_state_snapshot_json" || -z "$worker_status_json" || -z "$stall_observations_json" ]]; then
  printf 'swarm ops state, worker status, and stall observations are required\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the rehabilitation ledger\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for the rehabilitation ledger\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
ledger_path="${run_dir}/swarm_rch_stall_rehabilitation_ledger.json"
ledger_tmp="${ledger_path}.tmp"
receipts_path="${run_dir}/swarm_rch_stall_rehabilitation_receipts.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

swarm_ops_state_normalized="${run_dir}/swarm_ops_state_snapshot.normalized.json"
worker_status_normalized="${run_dir}/worker_status.normalized.json"
stall_observations_normalized="${run_dir}/stall_observations.normalized.json"
worker_capabilities_normalized="${run_dir}/worker_capabilities.normalized.json"
operator_actions_normalized="${run_dir}/operator_actions.normalized.json"
worker_receipts_jsonl="${run_dir}/worker_receipts.jsonl"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

printf './scripts/swarm_rch_stall_rehabilitation_ledger.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$worker_receipts_jsonl"
: >"$fail_closed_reasons_jsonl"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-rch-stall-rehabilitation.event.v1" \
    --arg trace_id "trace-swarm-rch-stall-rehabilitation-${run_id}" \
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
    '{code:$code,source_id:$source_id,detail:$detail}' >>"$fail_closed_reasons_jsonl"
}

normalize_required_json() {
  local input_path="$1"
  local output_path="$2"
  local label="$3"
  if [[ ! -f "$input_path" ]]; then
    printf 'missing required %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'invalid required %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  jq -cS . "$input_path" >"$output_path"
  write_event "$label" "input_loaded" "captured" "" "$output_path"
}

normalize_optional_json() {
  local input_path="$1"
  local output_path="$2"
  local label="$3"
  local default_json="$4"
  if [[ -z "$input_path" ]]; then
    printf '%s\n' "$default_json" >"$output_path"
    write_event "$label" "input_loaded" "missing_optional" "" "$output_path"
    printf 'missing'
    return
  fi
  if [[ ! -f "$input_path" ]]; then
    printf 'missing optional %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'invalid optional %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  jq -cS . "$input_path" >"$output_path"
  write_event "$label" "input_loaded" "captured" "" "$output_path"
  printf 'provided'
}

check_shape() {
  local path="$1"
  local expr="$2"
  local source_id="$3"
  local detail="$4"
  if ! jq -e "$expr" "$path" >/dev/null 2>&1; then
    append_failure "malformed_required_shape" "$source_id" "$detail"
  fi
}

normalize_required_json "$swarm_ops_state_snapshot_json" "$swarm_ops_state_normalized" "swarm_ops_state_snapshot"
normalize_required_json "$worker_status_json" "$worker_status_normalized" "worker_status"
normalize_required_json "$stall_observations_json" "$stall_observations_normalized" "stall_observations"
worker_capabilities_status="$(normalize_optional_json "$worker_capabilities_json" "$worker_capabilities_normalized" "worker_capabilities" '{"workers":[]}')"
operator_actions_status="$(normalize_optional_json "$operator_actions_json" "$operator_actions_normalized" "operator_actions" '{"actions":[]}')"

check_shape "$swarm_ops_state_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.components.rch.state // "") | (type == "string" and length > 0))
  and ((.components.rch.active_stall_count // null) | type == "number")
' "swarm_ops_state_snapshot_json" "swarm ops state snapshot lacks decision or RCH state fields"

check_shape "$worker_status_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.captured_at_epoch_seconds // null) | type == "number")
  and ((.queue_depth // null) | type == "number")
  and ((.slot_utilization_millionths // null) | type == "number")
  and ((.workers // null) | type == "array")
  and all(.workers[]?;
    ((.worker_id // "") | (type == "string" and length > 0))
    and ((.state // "") | (type == "string" and length > 0))
  )
' "worker_status_json" "worker status snapshot lacks required worker or pressure fields"

check_shape "$stall_observations_normalized" '
  type == "object"
  and ((.schema_version // "") | (type == "string" and length > 0))
  and ((.observations // null) | type == "array")
  and all(.observations[]?;
    ((.worker_id // "") | (type == "string" and length > 0))
    and ((.build_id // "") | (type == "string" and length > 0))
    and ((.command // "") | (type == "string" and length > 0))
    and ((.final_verdict // "") | (type == "string" and length > 0))
    and ((.reason_code // "") | (type == "string" and length > 0))
    and ((.source_evidence // "") | (type == "string" and length > 0))
    and ((.local_fallback_observed | type) == "boolean")
    and ((.cancellation_outcome // "") | (type == "string"))
    and ((.queue_depth // null) | type == "number")
    and ((.slot_utilization_millionths // null) | type == "number")
    and ((.observed_at_epoch_seconds // null) | type == "number")
  )
' "stall_observations_json" "stall observations are missing required worker/build/command fields"

if [[ "$worker_capabilities_status" == "provided" ]]; then
  check_shape "$worker_capabilities_normalized" '
    type == "object"
    and ((.workers // null) | type == "array")
    and all(.workers[]?;
      ((.worker_id // "") | (type == "string" and length > 0))
      and ((.capabilities_state // "") | (type == "string" and length > 0))
    )
  ' "worker_capabilities_json" "worker capabilities snapshot is malformed"
fi
if [[ "$operator_actions_status" == "provided" ]]; then
  check_shape "$operator_actions_normalized" '
    type == "object"
    and ((.actions // null) | type == "array")
    and all(.actions[]?;
      ((.worker_id // "") | (type == "string" and length > 0))
      and ((.action // "") | (type == "string" and length > 0))
      and ((.outcome // "") | (type == "string" and length > 0))
      and ((.observed_at_epoch_seconds // null) | type == "number")
    )
  ' "operator_actions_json" "operator actions snapshot is malformed"
fi

ops_decision="$(jq -r '.decision // ""' "$swarm_ops_state_normalized")"
if [[ "$ops_decision" == "fail_closed" ]]; then
  append_failure "untrusted_swarm_ops_state" "swarm_ops_state_snapshot_json" "upstream swarm ops state is already fail_closed"
fi

worker_ids="$( {
  jq -r '.workers[]?.worker_id' "$worker_status_normalized"
  jq -r '.observations[]?.worker_id' "$stall_observations_normalized"
  jq -r '.actions[]?.worker_id' "$operator_actions_normalized"
} | awk 'NF' | sort -u )"

if [[ -z "$worker_ids" ]]; then
  append_failure "missing_worker_identity" "worker_status_json" "no worker ids were present across status, observations, or actions"
fi

if [[ -s "$fail_closed_reasons_jsonl" ]]; then
  :
else
  while IFS= read -r worker_id; do
    [[ -n "$worker_id" ]] || continue

    state="$(jq -r --arg worker_id "$worker_id" '([.workers[]? | select(.worker_id == $worker_id)] | .[0].state) // "UNKNOWN"' "$worker_status_normalized")"
    active_builds="$(jq -r --arg worker_id "$worker_id" '([.workers[]? | select(.worker_id == $worker_id)] | .[0].active_builds) // 0' "$worker_status_normalized")"
    latest_build_id="$(jq -r --arg worker_id "$worker_id" '[.observations[]? | select(.worker_id == $worker_id)] | sort_by(.observed_at_epoch_seconds // 0) | last.build_id // ""' "$stall_observations_normalized")"
    latest_command="$(jq -r --arg worker_id "$worker_id" '[.observations[]? | select(.worker_id == $worker_id)] | sort_by(.observed_at_epoch_seconds // 0) | last.command // ""' "$stall_observations_normalized")"
    latest_heartbeat_age_seconds="$(jq -r --arg worker_id "$worker_id" '[.observations[]? | select(.worker_id == $worker_id)] | sort_by(.observed_at_epoch_seconds // 0) | last.heartbeat_age_seconds // null' "$stall_observations_normalized")"
    latest_progress_age_seconds="$(jq -r --arg worker_id "$worker_id" '[.observations[]? | select(.worker_id == $worker_id)] | sort_by(.observed_at_epoch_seconds // 0) | last.progress_age_seconds // null' "$stall_observations_normalized")"
    latest_cancellation_outcome="$(jq -r --arg worker_id "$worker_id" '[.observations[]? | select(.worker_id == $worker_id)] | sort_by(.observed_at_epoch_seconds // 0) | last.cancellation_outcome // "none"' "$stall_observations_normalized")"
    max_queue_depth="$(jq -r --arg worker_id "$worker_id" '[.observations[]? | select(.worker_id == $worker_id) | .queue_depth] | max // 0' "$stall_observations_normalized")"
    max_slot_utilization_millionths="$(jq -r --arg worker_id "$worker_id" '[.observations[]? | select(.worker_id == $worker_id) | .slot_utilization_millionths] | max // 0' "$stall_observations_normalized")"
    stall_count="$(jq -r --arg worker_id "$worker_id" '
      [.observations[]?
        | select(.worker_id == $worker_id)
        | (.final_verdict // "") as $verdict
        | select((.local_fallback_observed // false) == false)
        | select((["transport_timeout", "fresh_heartbeat_frozen_progress_stall"] | index($verdict)) != null)
      ] | length
    ' "$stall_observations_normalized")"
    source_failure_count="$(jq -r --arg worker_id "$worker_id" '
      [.observations[]?
        | select(.worker_id == $worker_id)
        | select((.final_verdict // "") == "source_failure")
      ] | length
    ' "$stall_observations_normalized")"
    local_fallback_count="$(jq -r --arg worker_id "$worker_id" '
      [.observations[]?
        | select(.worker_id == $worker_id)
        | select((.local_fallback_observed // false) == true or (.final_verdict // "") == "contaminated_local_fallback")
      ] | length
    ' "$stall_observations_normalized")"
    telemetry_gap_count="$(jq -r --arg worker_id "$worker_id" '
      [.observations[]?
        | select(.worker_id == $worker_id)
        | select((.reason_code // "") == "telemetry_gap" or .heartbeat_age_seconds == null or .progress_age_seconds == null)
      ] | length
    ' "$stall_observations_normalized")"
    rehab_success_count="$(jq -r --arg worker_id "$worker_id" '
      [.observations[]?
        | select(.worker_id == $worker_id)
        | (.final_verdict // "") as $verdict
        | select((["healthy_remote_completion", "confirmed_remote_completion"] | index($verdict)) != null)
      ] | length
    ' "$stall_observations_normalized")"
    clean_cancellation_count="$(jq -r --arg worker_id "$worker_id" '
      [.observations[]?
        | select(.worker_id == $worker_id)
        | (.cancellation_outcome // "") as $outcome
        | select((["cancelled_clean", "cancelled_successfully"] | index($outcome)) != null)
      ] | length
    ' "$stall_observations_normalized")"
    capabilities_state="$(jq -r --arg worker_id "$worker_id" '([.workers[]? | select(.worker_id == $worker_id)] | .[0].capabilities_state) // "missing_optional"' "$worker_capabilities_normalized")"
    latest_action="$(jq -r --arg worker_id "$worker_id" '[.actions[]? | select(.worker_id == $worker_id)] | sort_by(.observed_at_epoch_seconds // 0) | last.action // ""' "$operator_actions_normalized")"

    classification="healthy"
    if [[ "$state" == "DRAINING" || "$state" == "DRAINED" ]] && [[ "$rehab_success_count" -eq 0 ]]; then
      classification="drained"
    elif [[ "$rehab_success_count" -gt 0 ]] && [[ "$state" == "DRAINING" || "$state" == "DRAINED" || "$state" == "DISABLED" || "$latest_action" == "drain" ]]; then
      classification="rehab_candidate"
    elif [[ "$local_fallback_count" -gt 0 || "$telemetry_gap_count" -gt 0 || "$capabilities_state" == "stale" ]]; then
      classification="probe_required"
    elif [[ "$stall_count" -ge 2 ]]; then
      classification="drain_recommended"
    elif [[ "$stall_count" -eq 1 ]]; then
      classification="watch"
    fi

    operator_commands_json='[]'
    case "$classification" in
      healthy)
        operator_commands_json='[]'
        ;;
      watch)
        operator_commands_json="$(jq -nc --arg worker_id "$worker_id" '[ "rch workers probe " + $worker_id + " --json" ]')"
        ;;
      probe_required)
        operator_commands_json="$(jq -nc --arg worker_id "$worker_id" '[
          "rch workers probe " + $worker_id + " --json",
          "rch workers capabilities --refresh --json"
        ]')"
        ;;
      drain_recommended)
        operator_commands_json="$(jq -nc --arg worker_id "$worker_id" '[
          "rch workers drain -y " + $worker_id,
          "rch workers probe " + $worker_id + " --json"
        ]')"
        ;;
      drained)
        operator_commands_json="$(jq -nc --arg worker_id "$worker_id" '[ "rch workers probe " + $worker_id + " --json" ]')"
        ;;
      rehab_candidate)
        operator_commands_json="$(jq -nc --arg worker_id "$worker_id" '[
          "rch workers enable " + $worker_id,
          "rch workers capabilities --refresh --json"
        ]')"
        ;;
    esac

    reason_codes_json="$(jq -nc \
      --arg classification "$classification" \
      --arg capabilities_state "$capabilities_state" \
      --arg state "$state" \
      --arg latest_action "$latest_action" \
      --argjson stall_count "$stall_count" \
      --argjson source_failure_count "$source_failure_count" \
      --argjson local_fallback_count "$local_fallback_count" \
      --argjson telemetry_gap_count "$telemetry_gap_count" \
      --argjson rehab_success_count "$rehab_success_count" \
      --argjson clean_cancellation_count "$clean_cancellation_count" '
        [
          (if $stall_count >= 2 then "repeated_remote_stall" else empty end),
          (if $stall_count == 1 then "single_remote_stall" else empty end),
          (if $source_failure_count > 0 then "source_failure_observed" else empty end),
          (if $local_fallback_count > 0 then "local_fallback_contaminated" else empty end),
          (if $telemetry_gap_count > 0 then "telemetry_gap" else empty end),
          (if $clean_cancellation_count > 0 then "clean_cancellation_observed" else empty end),
          (if $rehab_success_count > 0 then "successful_rehab_observed" else empty end),
          (if ($state == "DRAINING" or $state == "DRAINED") then "worker_drained_state" else empty end),
          (if $capabilities_state == "stale" then "capabilities_refresh_required" else empty end),
          (if $latest_action == "drain" then "prior_drain_action" else empty end),
          ("classification:" + $classification)
        ] | unique
      ')"

    jq -nc \
      --arg worker_id "$worker_id" \
      --arg state "$state" \
      --arg latest_build_id "$latest_build_id" \
      --arg latest_command "$latest_command" \
      --arg latest_cancellation_outcome "$latest_cancellation_outcome" \
      --arg capabilities_state "$capabilities_state" \
      --arg latest_action "$latest_action" \
      --arg classification "$classification" \
      --argjson active_builds "$active_builds" \
      --argjson latest_heartbeat_age_seconds "$latest_heartbeat_age_seconds" \
      --argjson latest_progress_age_seconds "$latest_progress_age_seconds" \
      --argjson max_queue_depth "$max_queue_depth" \
      --argjson max_slot_utilization_millionths "$max_slot_utilization_millionths" \
      --argjson stall_count "$stall_count" \
      --argjson source_failure_count "$source_failure_count" \
      --argjson local_fallback_count "$local_fallback_count" \
      --argjson telemetry_gap_count "$telemetry_gap_count" \
      --argjson rehab_success_count "$rehab_success_count" \
      --argjson clean_cancellation_count "$clean_cancellation_count" \
      --argjson operator_commands "$operator_commands_json" \
      --argjson reason_codes "$reason_codes_json" \
      '{
        worker_id:$worker_id,
        current_state:$state,
        classification:$classification,
        latest_build_id:$latest_build_id,
        latest_command:$latest_command,
        latest_heartbeat_age_seconds:$latest_heartbeat_age_seconds,
        latest_progress_age_seconds:$latest_progress_age_seconds,
        latest_cancellation_outcome:$latest_cancellation_outcome,
        active_builds:$active_builds,
        pressure_telemetry:{
          max_queue_depth:$max_queue_depth,
          max_slot_utilization_millionths:$max_slot_utilization_millionths
        },
        evidence_summary:{
          remote_stall_count:$stall_count,
          source_failure_count:$source_failure_count,
          local_fallback_count:$local_fallback_count,
          telemetry_gap_count:$telemetry_gap_count,
          successful_rehab_count:$rehab_success_count,
          clean_cancellation_count:$clean_cancellation_count,
          capabilities_state:$capabilities_state,
          latest_action:$latest_action
        },
        reason_codes:$reason_codes,
        operator_commands:$operator_commands
      }' >>"$worker_receipts_jsonl"

    write_event "swarm_rch_stall_rehabilitation_ledger" "worker_classified" "$classification" "" "$worker_id"
  done <<<"$worker_ids"
fi

jq -n \
  --arg schema_version "franken-engine.swarm-rch-stall-rehabilitation-ledger.v1" \
  --arg receipts_schema_version "franken-engine.swarm-rch-stall-rehabilitation-receipts.v1" \
  --arg source_revision "$source_revision" \
  --arg ledger_path "$ledger_path" \
  --arg receipts_path "$receipts_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg ops_decision "$ops_decision" \
  --slurpfile swarm_ops "$swarm_ops_state_normalized" \
  --slurpfile worker_status "$worker_status_normalized" \
  --slurpfile observations "$stall_observations_normalized" \
  --slurpfile receipts "$worker_receipts_jsonl" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" \
  '{
    schema_version:$schema_version,
    source_revision:$source_revision,
    upstream_swarm_ops_decision:$ops_decision,
    decision: (
      if ($fail_closed_reasons | length) > 0 then "fail_closed"
      elif ([ $receipts[]? | select(.classification != "healthy") ] | length) > 0 or ($ops_decision != "pass") then "degraded"
      else "pass"
      end
    ),
    summary:{
      total_workers: ($receipts | length),
      healthy_count: ([$receipts[]? | select(.classification == "healthy")] | length),
      watch_count: ([$receipts[]? | select(.classification == "watch")] | length),
      probe_required_count: ([$receipts[]? | select(.classification == "probe_required")] | length),
      drain_recommended_count: ([$receipts[]? | select(.classification == "drain_recommended")] | length),
      drained_count: ([$receipts[]? | select(.classification == "drained")] | length),
      rehab_candidate_count: ([$receipts[]? | select(.classification == "rehab_candidate")] | length),
      observation_count: (($observations[0].observations // []) | length)
    },
    fail_closed_reasons:$fail_closed_reasons,
    workers:$receipts,
    artifact_paths:{
      ledger_json:$ledger_path,
      receipts_json:$receipts_path,
      events_jsonl:$events_path,
      commands_txt:$commands_path,
      report_md:$report_path
    },
    mutation_policy:{
      advisory_only:true,
      proof_only:true,
      fixture_fed_only:true,
      mutates_br:false,
      releases_reservations:false,
      sends_agent_mail:false,
      runs_cargo:false,
      runs_rch:false,
      mutates_remote_workers:false
    }
  }' >"$ledger_tmp"

ledger_id="swarm-rch-stall-rehabilitation-$(jq -cS 'del(.artifact_paths,.workers)' "$ledger_tmp" | sha256sum | awk '{print $1}' | cut -c1-16)"
jq --arg ledger_id "$ledger_id" '. + {ledger_id:$ledger_id}' "$ledger_tmp" >"$ledger_path"
mv "$ledger_path" "$ledger_tmp" 2>/dev/null || true
mv "$ledger_tmp" "$ledger_path"
jq -n \
  --arg schema_version "franken-engine.swarm-rch-stall-rehabilitation-receipts.v1" \
  --arg ledger_id "$ledger_id" \
  --slurpfile receipts "$worker_receipts_jsonl" \
  '{schema_version:$schema_version,ledger_id:$ledger_id,receipts:$receipts}' >"$receipts_path"

decision="$(jq -r '.decision' "$ledger_path")"
error_code=""
if [[ "$decision" == "fail_closed" ]]; then
  error_code="FE-SWARM-RCH-REHAB-INPUT"
elif jq -e '.summary.drain_recommended_count > 0' "$ledger_path" >/dev/null; then
  error_code="FE-SWARM-RCH-DRAIN-RECOMMENDED"
elif jq -e '.summary.probe_required_count > 0' "$ledger_path" >/dev/null; then
  error_code="FE-SWARM-RCH-PROBE-REQUIRED"
fi
write_event "swarm_rch_stall_rehabilitation_ledger" "summary_normalized" "$decision" "$error_code" "$ledger_path"

{
  printf '# SWARM RCH STALL REHABILITATION LEDGER\n\n'
  printf '%s\n' "- Decision: \`${decision}\`"
  printf '%s\n' "- Workers: \`$(jq '.summary.total_workers' "$ledger_path")\`"
  printf '%s\n' "- Healthy: \`$(jq '.summary.healthy_count' "$ledger_path")\`"
  printf '%s\n' "- Watch: \`$(jq '.summary.watch_count' "$ledger_path")\`"
  printf '%s\n' "- Probe required: \`$(jq '.summary.probe_required_count' "$ledger_path")\`"
  printf '%s\n' "- Drain recommended: \`$(jq '.summary.drain_recommended_count' "$ledger_path")\`"
  printf '%s\n' "- Drained: \`$(jq '.summary.drained_count' "$ledger_path")\`"
  printf '%s\n\n' "- Rehab candidate: \`$(jq '.summary.rehab_candidate_count' "$ledger_path")\`"

  jq -r '.workers[] | "- `" + .worker_id + "` `" + .classification + "` build=`" + (.latest_build_id // "") + "` command=`" + (.latest_command // "") + "`"' "$ledger_path"
} >"$report_path"

printf 'swarm_rch_stall_rehabilitation_ledger_json=%s\n' "$ledger_path"
printf 'swarm_rch_stall_rehabilitation_receipts_json=%s\n' "$receipts_path"
printf 'swarm_rch_stall_rehabilitation_report_md=%s\n' "$report_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
exit 0
