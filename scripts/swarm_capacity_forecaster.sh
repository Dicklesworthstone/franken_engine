#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_CAPACITY_FORECASTER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-capacity-forecast}"
run_id="${SWARM_CAPACITY_FORECASTER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_CAPACITY_FORECASTER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

telemetry_snapshot_json=""
source_revision=""
now_epoch_seconds="$(date -u +%s)"
stale_after_seconds="1800"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_capacity_forecaster.sh --telemetry-snapshot-json FILE [OPTIONS]

Builds a deterministic capacity forecast over the SWARM-CTRL-VIII telemetry
snapshot and its normalized child artifacts. The script stays fixture-fed only:
it does not query live services, mutate tracker state, execute cargo, or call
rch.

Required:
  --telemetry-snapshot-json FILE

Optional:
  --source-revision REV
  --now-epoch-seconds N
  --stale-after-seconds N
  --output-dir DIR

Artifacts:
  swarm_capacity_forecast.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  forecast emitted successfully
  42 fail-closed due to stale telemetry, contradictions, or low-confidence
     forecast categories
  64 invalid or missing top-level input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --telemetry-snapshot-json)
      telemetry_snapshot_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --now-epoch-seconds)
      now_epoch_seconds="${2:-}"
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
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

is_int() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

if [[ -z "$telemetry_snapshot_json" ]]; then
  printf 'swarm capacity forecaster requires --telemetry-snapshot-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm capacity forecasting\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm capacity forecasting\n' >&2
  exit 2
fi
if [[ ! -f "$telemetry_snapshot_json" ]]; then
  printf 'swarm capacity forecaster missing telemetry snapshot JSON: %s\n' "$telemetry_snapshot_json" >&2
  exit 64
fi
if ! jq empty "$telemetry_snapshot_json" >/dev/null 2>&1; then
  printf 'swarm capacity forecaster invalid telemetry snapshot JSON: %s\n' "$telemetry_snapshot_json" >&2
  exit 64
fi
if ! jq -e '.schema_version == "franken-engine.swarm-capacity-snapshot.v1"' "$telemetry_snapshot_json" >/dev/null 2>&1; then
  printf 'swarm capacity forecaster expected franken-engine.swarm-capacity-snapshot.v1: %s\n' "$telemetry_snapshot_json" >&2
  exit 64
fi
if ! is_int "$now_epoch_seconds" || ! is_int "$stale_after_seconds"; then
  printf 'now/stale thresholds must be non-negative integers\n' >&2
  exit 64
fi

snapshot_dir="$(cd "$(dirname "$telemetry_snapshot_json")" && pwd)"
if [[ -z "$source_revision" ]]; then
  source_revision="$(jq -r '.source_revision // empty' "$telemetry_snapshot_json")"
fi
if [[ -z "$source_revision" || "$source_revision" == "null" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
forecast_path="${run_dir}/swarm_capacity_forecast.json"
forecast_tmp="${forecast_path}.tmp"
core_path="${run_dir}/swarm_capacity_forecast.core.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
fail_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

snapshot_normalized="${run_dir}/telemetry_snapshot.normalized.json"
validation_plan_normalized="${run_dir}/validation_plan.normalized.json"
resource_decision_normalized="${run_dir}/resource_decision.normalized.json"
stale_lock_normalized="${run_dir}/stale_lock_recommendations.normalized.json"
proof_freshness_normalized="${run_dir}/proof_freshness.normalized.json"
admission_drill_normalized="${run_dir}/admission_drill_report.normalized.json"
predictive_wrapper_normalized="${run_dir}/predictive_wrapper_report.normalized.json"
archive_lifecycle_normalized="${run_dir}/archive_lifecycle_report.normalized.json"
proof_economy_drill_normalized="${run_dir}/proof_economy_drill_report.normalized.json"
operator_status_normalized="${run_dir}/operator_status.normalized.json"
rch_incident_normalized="${run_dir}/rch_incident_packet.normalized.json"
resource_lease_normalized="${run_dir}/resource_lease_plan.normalized.json"
proof_cache_normalized="${run_dir}/proof_cache_plan.normalized.json"
qos_batch_normalized="${run_dir}/build_storm_batch_plan.normalized.json"

: >"$events_path"
: >"$fail_reasons_jsonl"

printf './scripts/swarm_capacity_forecaster.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-capacity-forecast.event.v1" \
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
    '{kind:$kind,source:$source,label:$label,detail:$detail}' >>"$fail_reasons_jsonl"
}

snapshot_epoch_for() {
  local file="$1"
  jq -r '
    if (.generated_epoch_seconds? | type) == "number" then
      .generated_epoch_seconds
    elif (.snapshot_epoch_seconds? | type) == "number" then
      .snapshot_epoch_seconds
    elif (.captured_epoch_seconds? | type) == "number" then
      .captured_epoch_seconds
    elif (.generated_timestamp_ms? | type) == "number" then
      (.generated_timestamp_ms / 1000 | floor)
    elif (.timestamp_ms? | type) == "number" then
      (.timestamp_ms / 1000 | floor)
    elif (.summary.generated_timestamp_ms? | type) == "number" then
      (.summary.generated_timestamp_ms / 1000 | floor)
    else
      0
    end
  ' "$file"
}

check_staleness() {
  local file="$1"
  local status="$2"
  local source="$3"
  local label="$4"
  local epoch age

  if [[ "$status" != "provided" ]]; then
    return 0
  fi
  epoch="$(snapshot_epoch_for "$file")"
  if is_int "$epoch" && (( epoch > 0 )); then
    age=$((now_epoch_seconds - epoch))
    if (( age > stale_after_seconds )); then
      append_failure "stale_required_telemetry" "$source" "$label" "snapshot age ${age}s exceeds ${stale_after_seconds}s"
    fi
  fi
}

resolve_relative_path() {
  local base_dir="$1"
  local rel_path="$2"

  if [[ -z "$rel_path" ]]; then
    printf ''
    return 0
  fi
  if [[ "$rel_path" == /* ]]; then
    printf '%s' "$rel_path"
    return 0
  fi
  realpath -m "${base_dir}/${rel_path}"
}

json_input() {
  local path="$1"
  local default_json="$2"
  local output_path="$3"
  local source="$4"
  local label="$5"
  local kind="$6"

  if [[ -z "$path" || ! -f "$path" ]]; then
    printf '%s\n' "$default_json" >"$output_path"
    append_failure "$kind" "$source" "$label" "missing ${label}"
    printf 'missing'
    return 0
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf '%s\n' "$default_json" >"$output_path"
    append_failure "invalid_required_telemetry" "$source" "$label" "invalid JSON at ${path}"
    printf 'invalid'
    return 0
  fi
  jq -c . "$path" >"$output_path"
  printf 'provided'
}

accepted_input_path() {
  local input_name="$1"
  jq -r --arg input_name "$input_name" '
    (.accepted_inputs // [])
    | map(select(.input == $input_name))
    | .[0].path // empty
  ' "$snapshot_normalized"
}

artifact_path_for_key() {
  local doc_path="$1"
  local key="$2"
  jq -r --arg key "$key" '(.artifact_paths[$key] // .child_artifacts[$key] // empty)' "$doc_path"
}

accepted_input_to_file() {
  local input_name="$1"
  local default_json="$2"
  local output_path="$3"
  local label="$4"
  local kind="$5"
  local rel_path resolved_path

  rel_path="$(accepted_input_path "$input_name")"
  resolved_path="$(resolve_relative_path "$snapshot_dir" "$rel_path")"
  json_input "$resolved_path" "$default_json" "$output_path" "$input_name" "$label" "$kind"
}

doc_artifact_to_file() {
  local doc_path="$1"
  local default_json="$2"
  local output_path="$3"
  local artifact_key="$4"
  local source="$5"
  local label="$6"
  local kind="$7"
  local rel_path doc_dir resolved_path

  doc_dir="$(cd "$(dirname "$doc_path")" && pwd)"
  rel_path="$(artifact_path_for_key "$doc_path" "$artifact_key")"
  resolved_path="$(resolve_relative_path "$doc_dir" "$rel_path")"
  json_input "$resolved_path" "$default_json" "$output_path" "$source" "$label" "$kind"
}

check_required_fields() {
  local file="$1"
  local expr="$2"
  local source="$3"
  local label="$4"

  if ! jq -e "$expr" "$file" >/dev/null 2>&1; then
    append_failure "invalid_required_field" "$source" "$label" "required field or shape missing"
  fi
}

jq -c . "$telemetry_snapshot_json" >"$snapshot_normalized"
write_event "telemetry_snapshot.loaded" "loaded swarm telemetry snapshot"

validation_plan_status="$(accepted_input_to_file "validation_plan_json" '{}' "$validation_plan_normalized" 'validation plan' 'missing_required_telemetry')"
resource_decision_status="$(accepted_input_to_file "resource_decision_json" '{}' "$resource_decision_normalized" 'resource decision' 'missing_required_telemetry')"
stale_lock_status="$(accepted_input_to_file "stale_lock_recommendations_json" '{"stale_lock_recommendations":[],"safe_to_reopen":[],"contact_first":[]}' "$stale_lock_normalized" 'stale lock recommendations' 'missing_required_telemetry')"
proof_freshness_status="$(accepted_input_to_file "proof_freshness_json" '{}' "$proof_freshness_normalized" 'proof freshness report' 'missing_required_telemetry')"
admission_drill_status="$(accepted_input_to_file "admission_drill_report_json" '{}' "$admission_drill_normalized" 'admission drill report' 'missing_required_telemetry')"
predictive_wrapper_status="$(accepted_input_to_file "predictive_wrapper_report_json" '{}' "$predictive_wrapper_normalized" 'predictive wrapper report' 'missing_required_telemetry')"
archive_lifecycle_status="$(accepted_input_to_file "archive_lifecycle_report_json" '{}' "$archive_lifecycle_normalized" 'archive lifecycle report' 'missing_required_telemetry')"
proof_economy_status="$(accepted_input_to_file "proof_economy_drill_report_json" '{}' "$proof_economy_drill_normalized" 'proof economy drill report' 'missing_required_telemetry')"

check_required_fields "$validation_plan_normalized" 'has("schema_version") and has("decision") and has("commands")' "validation_plan_json" "schema_version_decision_commands"
check_required_fields "$resource_decision_normalized" 'has("schema_version") and has("decision") and has("findings")' "resource_decision_json" "schema_version_decision_findings"
check_required_fields "$stale_lock_normalized" 'has("stale_lock_recommendations") and has("safe_to_reopen") and has("contact_first")' "stale_lock_recommendations_json" "stale_lock_fields"
check_required_fields "$proof_freshness_normalized" 'has("freshness_state") and has("reusable")' "proof_freshness_json" "freshness_state_reusable"
check_required_fields "$admission_drill_normalized" 'has("schema_version") and has("child_artifacts")' "admission_drill_report_json" "schema_version_child_artifacts"
check_required_fields "$predictive_wrapper_normalized" 'has("schema_version") and has("artifact_paths")' "predictive_wrapper_report_json" "schema_version_artifact_paths"
check_required_fields "$archive_lifecycle_normalized" 'has("schema_version") and has("drill_decision") and has("scenarios")' "archive_lifecycle_report_json" "schema_version_drill_scenarios"
check_required_fields "$proof_economy_drill_normalized" 'has("schema_version") and (has("summary") or has("dashboard_fields"))' "proof_economy_drill_report_json" "schema_version_summary_or_dashboard"

check_staleness "$snapshot_normalized" "provided" "telemetry_snapshot_json" "generated_epoch_seconds"
check_staleness "$predictive_wrapper_normalized" "$predictive_wrapper_status" "predictive_wrapper_report_json" "captured_epoch_seconds"
check_staleness "$archive_lifecycle_normalized" "$archive_lifecycle_status" "archive_lifecycle_report_json" "captured_epoch_seconds"
check_staleness "$proof_economy_drill_normalized" "$proof_economy_status" "proof_economy_drill_report_json" "captured_epoch_seconds"

operator_status_status="$(doc_artifact_to_file "$predictive_wrapper_normalized" '{}' "$operator_status_normalized" "operator_status_json" "predictive_wrapper_report_json" "operator status report" "missing_required_artifact")"
rch_incident_status="$(doc_artifact_to_file "$predictive_wrapper_normalized" '{"status":"unknown","failure_kind":"unknown","retry_safety":"unknown"}' "$rch_incident_normalized" "rch_incident_packet_json" "predictive_wrapper_report_json" "rch incident packet" "missing_required_artifact")"
resource_lease_status="$(doc_artifact_to_file "$admission_drill_normalized" '{}' "$resource_lease_normalized" "resource_lease_plan_json" "admission_drill_report_json" "resource lease plan" "missing_required_artifact")"
proof_cache_status="$(doc_artifact_to_file "$admission_drill_normalized" '{}' "$proof_cache_normalized" "proof_cache_plan_json" "admission_drill_report_json" "proof cache plan" "missing_required_artifact")"
qos_batch_status="$(doc_artifact_to_file "$admission_drill_normalized" '{}' "$qos_batch_normalized" "build_storm_batch_plan_json" "admission_drill_report_json" "build storm batch plan" "missing_required_artifact")"

check_required_fields "$operator_status_normalized" 'has("predictive_dashboard") or has("status")' "operator_status_json" "predictive_dashboard_or_status"
check_required_fields "$rch_incident_normalized" 'has("status") and has("failure_kind") and has("retry_safety")' "rch_incident_packet_json" "status_failure_kind_retry_safety"
check_required_fields "$resource_lease_normalized" 'has("schema_version") and has("lease_decision") and has("target_dir") and has("findings")' "resource_lease_plan_json" "schema_version_lease_decision_target_dir_findings"
check_required_fields "$proof_cache_normalized" 'has("schema_version") and has("proof_cache_decision") and has("refresh_commands")' "proof_cache_plan_json" "schema_version_proof_cache_decision_refresh_commands"
check_required_fields "$qos_batch_normalized" 'has("schema_version") and has("batch_decision") and has("admitted_commands") and has("deferred_commands")' "build_storm_batch_plan_json" "schema_version_batch_decision_admitted_deferred"

snapshot_age_seconds="$(snapshot_epoch_for "$snapshot_normalized")"
if ! is_int "$snapshot_age_seconds"; then
  snapshot_age_seconds=0
fi
if (( snapshot_age_seconds > 0 )); then
  snapshot_age_seconds=$((now_epoch_seconds - snapshot_age_seconds))
else
  snapshot_age_seconds=0
fi

jq -n \
  --arg schema_version "franken-engine.swarm-capacity-forecast.v1" \
  --arg contract_json "docs/swarm_capacity_forecaster_contract_v1.json" \
  --arg dashboard_contract_json "docs/swarm_predictive_dashboard_contract_v1.json" \
  --arg source_revision "$source_revision" \
  --arg telemetry_snapshot_path "$telemetry_snapshot_json" \
  --arg validation_plan_path "$(accepted_input_path "validation_plan_json")" \
  --arg resource_decision_path "$(accepted_input_path "resource_decision_json")" \
  --arg stale_lock_path "$(accepted_input_path "stale_lock_recommendations_json")" \
  --arg proof_freshness_path "$(accepted_input_path "proof_freshness_json")" \
  --arg admission_drill_path "$(accepted_input_path "admission_drill_report_json")" \
  --arg predictive_wrapper_path "$(accepted_input_path "predictive_wrapper_report_json")" \
  --arg archive_lifecycle_path "$(accepted_input_path "archive_lifecycle_report_json")" \
  --arg proof_economy_path "$(accepted_input_path "proof_economy_drill_report_json")" \
  --arg operator_status_path "$(artifact_path_for_key "$predictive_wrapper_normalized" "operator_status_json")" \
  --arg rch_incident_path "$(artifact_path_for_key "$predictive_wrapper_normalized" "rch_incident_packet_json")" \
  --arg resource_lease_path "$(artifact_path_for_key "$admission_drill_normalized" "resource_lease_plan_json")" \
  --arg proof_cache_path "$(artifact_path_for_key "$admission_drill_normalized" "proof_cache_plan_json")" \
  --arg qos_batch_path "$(artifact_path_for_key "$admission_drill_normalized" "build_storm_batch_plan_json")" \
  --arg validation_plan_status "$validation_plan_status" \
  --arg resource_decision_status "$resource_decision_status" \
  --arg stale_lock_status "$stale_lock_status" \
  --arg proof_freshness_status "$proof_freshness_status" \
  --arg admission_drill_status "$admission_drill_status" \
  --arg predictive_wrapper_status "$predictive_wrapper_status" \
  --arg archive_lifecycle_status "$archive_lifecycle_status" \
  --arg proof_economy_status "$proof_economy_status" \
  --arg operator_status_status "$operator_status_status" \
  --arg rch_incident_status "$rch_incident_status" \
  --arg resource_lease_status "$resource_lease_status" \
  --arg proof_cache_status "$proof_cache_status" \
  --arg qos_batch_status "$qos_batch_status" \
  --arg forecast_path "$forecast_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --argjson now_epoch_seconds "$now_epoch_seconds" \
  --argjson stale_after_seconds "$stale_after_seconds" \
  --argjson snapshot_age_seconds "$snapshot_age_seconds" \
  --slurpfile snapshot "$snapshot_normalized" \
  --slurpfile validation_plan "$validation_plan_normalized" \
  --slurpfile resource_decision "$resource_decision_normalized" \
  --slurpfile stale_lock "$stale_lock_normalized" \
  --slurpfile proof_freshness "$proof_freshness_normalized" \
  --slurpfile admission_drill "$admission_drill_normalized" \
  --slurpfile predictive_wrapper "$predictive_wrapper_normalized" \
  --slurpfile archive_lifecycle "$archive_lifecycle_normalized" \
  --slurpfile proof_economy "$proof_economy_drill_normalized" \
  --slurpfile operator_status "$operator_status_normalized" \
  --slurpfile rch_incident "$rch_incident_normalized" \
  --slurpfile resource_lease "$resource_lease_normalized" \
  --slurpfile proof_cache "$proof_cache_normalized" \
  --slurpfile qos_batch "$qos_batch_normalized" \
  --slurpfile fail_reasons "$fail_reasons_jsonl" \
  '
  def low($value): ($value // "" | tostring | ascii_downcase);
  def conf($signal_count):
    if $signal_count >= 3 then {score_millionths: 900000, band: "high"}
    elif $signal_count == 2 then {score_millionths: 700000, band: "medium"}
    else {score_millionths: 300000, band: "low"}
    end;
  def risk_level($state):
    if $state == "blocked" then "critical"
    elif $state == "brownout" then "high"
    elif $state == "degraded" then "medium"
    else "low"
    end;
  def overall_state($forecasts):
    if any($forecasts[]?; .state == "blocked") then "blocked"
    elif any($forecasts[]?; .state == "brownout") then "brownout"
    elif any($forecasts[]?; .state == "degraded") then "degraded"
    else "normal"
    end;
  def text_blob($rows):
    ($rows // [])
    | map([(.signal // ""), (.code // ""), (.reason // ""), (.message // ""), (.recommended_next_action // ""), (.detail // "")] | join(" "))
    | join(" ")
    | ascii_downcase;
  def any_text($rows; $pattern):
    (text_blob($rows) | test($pattern));
  def incidents_from_operator($operator):
    ($operator.predictive_dashboard.rch_incidents.incidents // []);
  def first_incident($operator; $incident):
    if ((incidents_from_operator($operator)) | length) > 0 then
      (incidents_from_operator($operator))[0]
    else
      $incident
    end;
  def archive_advisories($archive):
    [
      ($archive.scenarios.resident_bundle_export_restore.pressure_summary.advisory // empty),
      ($archive.scenarios.duplicate_compaction_before_export.pressure_summary.advisory // empty),
      ($archive.scenarios.salvage_pinned_gc_block.pressure_summary.advisory // empty)
    ] | map(select(. != ""));

  ($snapshot[0]) as $snapshot
  | ($validation_plan[0]) as $validation
  | ($resource_decision[0]) as $resource
  | ($stale_lock[0]) as $stale_lock
  | ($proof_freshness[0]) as $proof_freshness
  | ($admission_drill[0]) as $admission
  | ($predictive_wrapper[0]) as $predictive
  | ($archive_lifecycle[0]) as $archive
  | ($proof_economy[0]) as $proof_economy
  | ($operator_status[0]) as $operator_status
  | ($rch_incident[0]) as $rch_incident
  | ($resource_lease[0]) as $resource_lease
  | ($proof_cache[0]) as $proof_cache
  | ($qos_batch[0]) as $qos_batch
  | ($fail_reasons // []) as $external_failures
  | (first_incident($operator_status; $rch_incident)) as $incident
  | (archive_advisories($archive)) as $archive_advisories
  | (low($proof_economy.summary.brownout_state // $proof_economy.dashboard_fields.brownout_state // "normal")) as $brownout_state
  | (($snapshot.summary.high_cost_command_count // 0)) as $high_cost_command_count
  | (($qos_batch.deferred_commands // []) | length) as $deferred_command_count
  | (($stale_lock.contact_first // []) | length) as $contact_first_count
  | (($snapshot.contradictory_inputs // []) | length) as $contradiction_count
  | (($resource.findings // []) + ($resource_lease.findings // [])) as $resource_findings
  | (conf(
      (if $validation_plan_status == "provided" then 1 else 0 end) +
      (if $qos_batch_status == "provided" then 1 else 0 end) +
      (if $proof_economy_status == "provided" then 1 else 0 end)
    )) as $compile_conf
  | (conf(
      (if $resource_decision_status == "provided" then 1 else 0 end) +
      (if $resource_lease_status == "provided" then 1 else 0 end) +
      (if $proof_economy_status == "provided" then 1 else 0 end)
    )) as $resource_conf
  | (conf(
      (if $predictive_wrapper_status == "provided" then 1 else 0 end) +
      (if $operator_status_status == "provided" then 1 else 0 end) +
      (if $rch_incident_status == "provided" then 1 else 0 end)
    )) as $rch_conf
  | (conf(
      (if $resource_lease_status == "provided" then 1 else 0 end) +
      (if $proof_cache_status == "provided" then 1 else 0 end) +
      (if $qos_batch_status == "provided" then 1 else 0 end)
    )) as $target_dir_conf
  | (conf(
      (if $proof_freshness_status == "provided" then 1 else 0 end) +
      (if $proof_cache_status == "provided" then 1 else 0 end) +
      (if $archive_lifecycle_status == "provided" then 1 else 0 end)
    )) as $proof_conf
  | (conf(
      (if $stale_lock_status == "provided" then 1 else 0 end) +
      (if ($snapshot.accepted_inputs // [] | length) > 0 then 1 else 0 end) +
      (if $predictive_wrapper_status == "provided" then 1 else 0 end)
    )) as $coordination_conf
  | (if $snapshot.decision != "pass" then "blocked"
     elif ($brownout_state | test("brownout|shed|throttle")) then "brownout"
     elif ($high_cost_command_count > 0 or $deferred_command_count > 0 or (low($resource_lease.lease_decision // "admit") != "admit")) then "degraded"
     else "normal"
     end) as $compile_state
  | (if $snapshot.decision != "pass" then "blocked"
     elif ((any_text($resource_findings; "disk|memory")) and (low($resource.decision // "unknown") != "admit" or low($resource_lease.lease_decision // "admit") != "admit")) then "degraded"
     elif any_text($resource_findings; "worker_capacity|active_compile|capacity") then "degraded"
     else "normal"
     end) as $resource_state
  | (if $snapshot.decision != "pass" then "blocked"
     elif (low($incident.failure_kind // "none") | test("local_fallback")) then "blocked"
     elif (low($incident.status // "pass") | test("fail|degraded")) or ((low($incident.failure_kind // "none") != "none") and (low($incident.failure_kind // "none") != "unknown")) then "degraded"
     else "normal"
     end) as $rch_state
  | (if $snapshot.decision != "pass" then "blocked"
     elif (low($resource_lease.lease_decision // "admit") | test("busy|defer|deny|fail")) then "degraded"
     elif (low($proof_cache.proof_cache_decision // "unknown") | test("refresh_required|partial_refresh|fail_closed")) then "degraded"
     elif ((($proof_cache.invalidated_paths // []) | length) > 0) or (($proof_cache.refresh_commands // []) | length) > 0 then "degraded"
     elif any_text($resource_findings; "target.?dir|cache") then "degraded"
     else "normal"
     end) as $target_dir_state
  | (if $snapshot.decision != "pass" then "blocked"
     elif low($archive.drill_decision // "pass") != "pass" then "blocked"
     elif low($proof_cache.proof_cache_decision // "unknown") == "fail_closed" then "blocked"
     elif ($proof_freshness.reusable == false) or (low($proof_cache.proof_cache_decision // "unknown") | test("refresh_required|partial_refresh")) or any($archive_advisories[]?; test("fail_closed|compaction_first|evict_cold_archive|cool_archive")) then "degraded"
     else "normal"
     end) as $proof_state
  | (if $snapshot.decision != "pass" then "blocked"
     elif ($contradiction_count > 0) then "blocked"
     elif ($contact_first_count > 0) then "blocked"
     elif any(($stale_lock.stale_lock_recommendations // [])[]?; ((.contact_first // false) == true) or (low(.reason // .classification // .recommended_next_action // "") | test("manual_confirmation_required|contact_first"))) then "blocked"
     elif (low($snapshot.swarm_capacity_snapshot.predictive_cost.collision_risk // "none") != "none") or ((($snapshot.swarm_capacity_snapshot.predictive_cost.conflicting_agents // []) | length) > 0) then "degraded"
     else "normal"
     end) as $coordination_state
  | ({
      compile_pressure: {
        state: $compile_state,
        risk_level: risk_level($compile_state),
        confidence_band: $compile_conf.band,
        confidence_score_millionths: $compile_conf.score_millionths,
        assumptions: [
          "The normalized validation plan remains the authoritative command set for the next forecast window.",
          (if $qos_batch_status == "provided" then "QoS batch deferrals are treated as the strongest heavy-validation contention signal." else "No QoS batch plan was provided; compile-pressure confidence is reduced." end),
          (if $proof_economy_status == "provided" then "Proof-economy brownout state is treated as the strongest saturation override." else "No proof-economy drill report was provided; compile-pressure confidence is reduced." end)
        ],
        evidence: {
          high_cost_command_count: $high_cost_command_count,
          deferred_command_count: $deferred_command_count,
          brownout_state: ($proof_economy.summary.brownout_state // $proof_economy.dashboard_fields.brownout_state // "unknown"),
          lease_decision: ($resource_lease.lease_decision // null)
        },
        recommended_action: (
          if $compile_state == "brownout" then
            "Throttle or defer heavy validation and prefer narrow shell/docs proofs until brownout clears."
          elif $compile_state == "degraded" then
            "Batch heavy commands, prefer warm targets, and keep the validation plan narrow."
          else
            "Proceed with the focused validation plan."
          end
        )
      },
      disk_memory_pressure: {
        state: $resource_state,
        risk_level: risk_level($resource_state),
        confidence_band: $resource_conf.band,
        confidence_score_millionths: $resource_conf.score_millionths,
        assumptions: [
          "Resource-governor findings are authoritative for disk and memory pressure whenever present.",
          (if $resource_lease_status == "provided" then "The resource lease planner target-dir and worker findings are treated as the current execution envelope." else "No resource lease plan was provided; disk/memory confidence is reduced." end)
        ],
        evidence: {
          resource_decision: ($resource.decision // "unknown"),
          lease_decision: ($resource_lease.lease_decision // "unknown"),
          finding_signals: (($resource_findings // []) | map(.signal // .code // .message // .reason // empty) | map(select(. != "")) | unique | sort)
        },
        recommended_action: (
          if $resource_state == "degraded" then
            "Reduce concurrent heavy proofs or move to a lower-pressure target-dir before retrying."
          else
            "Current disk and memory signals are within the planned envelope."
          end
        )
      },
      rch_degradation: {
        state: $rch_state,
        risk_level: risk_level($rch_state),
        confidence_band: $rch_conf.band,
        confidence_score_millionths: $rch_conf.score_millionths,
        assumptions: [
          "The predictive wrapper incident packet remains authoritative for remote execution health.",
          (if $operator_status_status == "provided" then "Operator-status degraded components are treated as corroborating evidence for rch risk." else "No operator status report was provided; rch confidence is reduced." end)
        ],
        evidence: {
          incident_status: ($incident.status // "unknown"),
          failure_kind: ($incident.failure_kind // "unknown"),
          retry_safety: ($incident.retry_safety // "unknown"),
          classification_confidence: ($incident.classification_confidence // "unknown")
        },
        recommended_action: (
          if $rch_state == "blocked" or $rch_state == "degraded" then
            ($incident.recommended_next_action // "Keep the proof remote-only and narrow the command before retrying.")
          else
            "Remote execution signals are healthy enough for focused proof work."
          end
        )
      },
      target_dir_heat: {
        state: $target_dir_state,
        risk_level: risk_level($target_dir_state),
        confidence_band: $target_dir_conf.band,
        confidence_score_millionths: $target_dir_conf.score_millionths,
        assumptions: [
          "The resource lease target-dir and proof-cache plan together define target-dir contention.",
          "Refresh-required proof-cache decisions imply higher warm-target churn."
        ],
        evidence: {
          target_dir: ($resource_lease.target_dir // null),
          lease_decision: ($resource_lease.lease_decision // "unknown"),
          proof_cache_decision: ($proof_cache.proof_cache_decision // "unknown"),
          refresh_command_count: (($proof_cache.refresh_commands // []) | length),
          invalidated_path_count: (($proof_cache.invalidated_paths // []) | length)
        },
        recommended_action: (
          if $target_dir_state == "degraded" then
            "Prefetch or switch target dirs before reusing the current warm cache."
          else
            "Current target-dir and cache signals do not indicate acute contention."
          end
        )
      },
      proof_availability: {
        state: $proof_state,
        risk_level: risk_level($proof_state),
        confidence_band: $proof_conf.band,
        confidence_score_millionths: $proof_conf.score_millionths,
        assumptions: [
          "Proof freshness, proof-cache reuse, and archive lifecycle evidence must all agree before the forecast can treat proof assets as reusable.",
          "Archive lifecycle pressure advisories override optimistic cache-hit claims when they disagree."
        ],
        evidence: {
          proof_freshness_state: ($proof_freshness.freshness_state // "unknown"),
          proof_reusable: ($proof_freshness.reusable // null),
          proof_cache_decision: ($proof_cache.proof_cache_decision // "unknown"),
          archive_drill_decision: ($archive.drill_decision // "unknown"),
          archive_advisories: $archive_advisories
        },
        recommended_action: (
          if $proof_state == "blocked" then
            ($proof_freshness.recommended_next_action // "Refresh proof artifacts before attempting reuse.")
          elif $proof_state == "degraded" then
            "Refresh stale proofs or compact/archive bundles before relying on cached proof assets."
          else
            "Proof-cache and archive evidence support reuse within the current source revision."
          end
        )
      },
      coordination_pressure: {
        state: $coordination_state,
        risk_level: risk_level($coordination_state),
        confidence_band: $coordination_conf.band,
        confidence_score_millionths: $coordination_conf.score_millionths,
        assumptions: [
          "Stale-lock recommendations are authoritative for auto-reopen and lease-exchange safety.",
          "Active-owner and contradictory-ownership signals block automatic coordination actions."
        ],
        evidence: {
          contradiction_count: $contradiction_count,
          reservation_count: ($snapshot.summary.reservation_count // 0),
          contact_first_count: $contact_first_count,
          safe_to_reopen_count: (($stale_lock.safe_to_reopen // []) | length)
        },
        auto_reopen_allowed: ($coordination_state == "normal"),
        lease_exchange_allowed: ($coordination_state == "normal"),
        recommended_action: (
          if $coordination_state == "blocked" then
            "Do not auto-reopen or exchange leases; contact the active owner and wait for manual confirmation."
          elif $coordination_state == "degraded" then
            "Coordinate reservation ownership before widening the planned write set."
          else
            "Current coordination signals allow automatic reopen and lease exchange."
          end
        )
      }
    }) as $forecasts
  | ($forecasts | to_entries | map(select(.value.confidence_band == "low") | {
      kind: "low_confidence",
      source: .key,
      label: "confidence_band",
      detail: "required telemetry missing or incomplete for forecast category"
    })) as $low_confidence_rows
  | ($external_failures + $low_confidence_rows) as $all_failures
  | {
      schema_version: $schema_version,
      source_revision: $source_revision,
      generated_epoch_seconds: $now_epoch_seconds,
      stale_after_seconds: $stale_after_seconds,
      decision: (
        if ($snapshot.decision != "pass") or (($all_failures | length) > 0) then
          "fail_closed"
        else
          "pass"
        end
      ),
      confidence_band: (
        if (($low_confidence_rows | length) > 0) then "low"
        elif any(($forecasts | to_entries)[]?; .value.confidence_band == "medium") then "medium"
        else "high"
        end
      ),
      summary: {
        overall_state: overall_state(($forecasts | [.[]])),
        brownout_state: ($proof_economy.summary.brownout_state // $proof_economy.dashboard_fields.brownout_state // "unknown"),
        snapshot_age_seconds: $snapshot_age_seconds,
        high_cost_command_count: $high_cost_command_count,
        deferred_command_count: $deferred_command_count,
        contact_first_count: $contact_first_count,
        blocked_categories: ($forecasts | to_entries | map(select(.value.state == "blocked") | .key)),
        degraded_categories: ($forecasts | to_entries | map(select((.value.state == "degraded") or (.value.state == "brownout")) | .key))
      },
      assumptions: [
        "The telemetry snapshot and normalized child artifacts are the only evidence sources used by this forecast.",
        "The heuristics are deterministic and replayable; no live rch, cargo, or Agent Mail queries are executed here.",
        "Confidence bands are completeness-based: missing required telemetry forces fail-closed rather than speculative inference."
      ],
      inherited_snapshot_failures: {
        snapshot_decision: ($snapshot.decision // "unknown"),
        missing_required_fields: ($snapshot.missing_required_fields // []),
        stale_inputs: ($snapshot.stale_inputs // []),
        contradictory_inputs: ($snapshot.contradictory_inputs // []),
        non_replayable_artifact_refs: ($snapshot.non_replayable_artifact_refs // [])
      },
      fail_closed_reasons: $all_failures,
      resolved_inputs: [
        {input:"telemetry_snapshot_json", status:"provided", path:$telemetry_snapshot_path, schema_version:($snapshot.schema_version // null)},
        {input:"validation_plan_json", status:$validation_plan_status, path:$validation_plan_path, schema_version:($validation.schema_version // null)},
        {input:"resource_decision_json", status:$resource_decision_status, path:$resource_decision_path, schema_version:($resource.schema_version // null)},
        {input:"stale_lock_recommendations_json", status:$stale_lock_status, path:$stale_lock_path, schema_version:($stale_lock.schema_version // null)},
        {input:"proof_freshness_json", status:$proof_freshness_status, path:$proof_freshness_path, schema_version:($proof_freshness.schema_version // null)},
        {input:"admission_drill_report_json", status:$admission_drill_status, path:$admission_drill_path, schema_version:($admission.schema_version // null)},
        {input:"predictive_wrapper_report_json", status:$predictive_wrapper_status, path:$predictive_wrapper_path, schema_version:($predictive.schema_version // null)},
        {input:"archive_lifecycle_report_json", status:$archive_lifecycle_status, path:$archive_lifecycle_path, schema_version:($archive.schema_version // null)},
        {input:"proof_economy_drill_report_json", status:$proof_economy_status, path:$proof_economy_path, schema_version:($proof_economy.schema_version // null)},
        {input:"operator_status_json", status:$operator_status_status, path:$operator_status_path, schema_version:($operator_status.schema_version // null)},
        {input:"rch_incident_packet_json", status:$rch_incident_status, path:$rch_incident_path, schema_version:($rch_incident.schema_version // null)},
        {input:"resource_lease_plan_json", status:$resource_lease_status, path:$resource_lease_path, schema_version:($resource_lease.schema_version // null)},
        {input:"proof_cache_plan_json", status:$proof_cache_status, path:$proof_cache_path, schema_version:($proof_cache.schema_version // null)},
        {input:"build_storm_batch_plan_json", status:$qos_batch_status, path:$qos_batch_path, schema_version:($qos_batch.schema_version // null)}
      ],
      forecasts: $forecasts,
      artifact_paths: {
        swarm_capacity_forecast_json: $forecast_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      },
      contract_paths: {
        forecast_contract_json: $contract_json,
        dashboard_contract_json: $dashboard_contract_json
      }
    }
  ' >"$core_path"

forecast_id="swarm-capacity-forecast-$(jq -cS 'del(.artifact_paths)' "$core_path" | sha256sum | awk '{print $1}' | cut -c1-16)"
jq --arg forecast_id "$forecast_id" '. + {forecast_id: $forecast_id}' "$core_path" >"$forecast_tmp"
mv "$forecast_tmp" "$forecast_path"

write_event "swarm_capacity_forecast.computed" "$(jq -r '.decision + " / overall_state=" + .summary.overall_state' "$forecast_path")"

{
  printf '# Swarm Capacity Forecast\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$forecast_path")"
  printf -- "- Overall state: \`%s\`\n" "$(jq -r '.summary.overall_state' "$forecast_path")"
  printf -- "- Confidence: \`%s\`\n" "$(jq -r '.confidence_band' "$forecast_path")"
  printf -- "- Snapshot age (s): \`%s\`\n" "$(jq -r '.summary.snapshot_age_seconds' "$forecast_path")"
  printf -- "- Fail-closed reasons: \`%s\`\n\n" "$(jq '.fail_closed_reasons | length' "$forecast_path")"

  printf '## Forecast Categories\n'
  jq -r '
    .forecasts
    | to_entries[]
    | "- `" + .key + "` state=`" + .value.state + "` risk=`" + .value.risk_level + "` confidence=`" + .value.confidence_band + "`"
  ' "$forecast_path"
  printf '\n'

  if [[ "$(jq '.fail_closed_reasons | length' "$forecast_path")" -ne 0 ]]; then
    printf '## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `" + .source + "` `" + .label + "`: " + .detail' "$forecast_path"
    printf '\n'
  fi
} >"$report_path"

printf 'swarm_capacity_forecast_json=%s\n' "$forecast_path"
printf 'swarm_capacity_forecast_report=%s\n' "$report_path"

if [[ "$(jq -r '.decision' "$forecast_path")" == "fail_closed" ]]; then
  exit 42
fi
exit 0
