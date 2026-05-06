#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_CHECKPOINT_RESTORE_PLANNER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-checkpoint-restore-plan}"
run_id="${SWARM_CHECKPOINT_RESTORE_PLANNER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_CHECKPOINT_RESTORE_PLANNER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

checkpoint_bundle_json=""
current_swarm_capacity_snapshot_json=""
current_swarm_capacity_forecast_json=""
current_remote_proof_archive_pressure_scoreboard_json=""
current_stale_lock_recommendations_json=""
current_swarm_lease_exchange_cancellation_salvage_simulation_json=""
current_swarm_operator_status_report_json=""

source_revision=""
now_epoch_seconds="$(date -u +%s)"
max_restore_age_seconds=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_checkpoint_restore_planner.sh --checkpoint-bundle-json FILE [OPTIONS]

Build a deterministic checkpoint restore plan for SWARM-CTRL-XI.
The planner is fixture-fed only. It does not query live br, Agent Mail, rch,
or execute Cargo.

Required:
  --checkpoint-bundle-json FILE

Optional current-state comparison inputs:
  --current-swarm-capacity-snapshot-json FILE
  --current-swarm-capacity-forecast-json FILE
  --current-remote-proof-archive-pressure-scoreboard-json FILE
  --current-stale-lock-recommendations-json FILE
  --current-swarm-lease-exchange-cancellation-salvage-simulation-json FILE
  --current-swarm-operator-status-report-json FILE
  --now-epoch-seconds N
  --max-restore-age-seconds N
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_checkpoint_restore_plan.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  bounded resume plan emitted
  75 advisory manual review required before restore
  42 fail-closed restore decision
  64 invalid or missing required input path / malformed JSON / bad CLI usage
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --checkpoint-bundle-json)
      checkpoint_bundle_json="${2:-}"
      shift 2
      ;;
    --current-swarm-capacity-snapshot-json)
      current_swarm_capacity_snapshot_json="${2:-}"
      shift 2
      ;;
    --current-swarm-capacity-forecast-json)
      current_swarm_capacity_forecast_json="${2:-}"
      shift 2
      ;;
    --current-remote-proof-archive-pressure-scoreboard-json)
      current_remote_proof_archive_pressure_scoreboard_json="${2:-}"
      shift 2
      ;;
    --current-stale-lock-recommendations-json)
      current_stale_lock_recommendations_json="${2:-}"
      shift 2
      ;;
    --current-swarm-lease-exchange-cancellation-salvage-simulation-json)
      current_swarm_lease_exchange_cancellation_salvage_simulation_json="${2:-}"
      shift 2
      ;;
    --current-swarm-operator-status-report-json)
      current_swarm_operator_status_report_json="${2:-}"
      shift 2
      ;;
    --now-epoch-seconds)
      now_epoch_seconds="${2:-}"
      shift 2
      ;;
    --max-restore-age-seconds)
      max_restore_age_seconds="${2:-}"
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

is_int() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

json_scalar_contains() {
  local path="$1"
  local pattern="$2"

  jq -e --arg pattern "$pattern" '
    [.. | scalars | tostring | ascii_downcase | select(test($pattern))]
    | length > 0
  ' "$path" >/dev/null 2>&1
}

if [[ -z "$checkpoint_bundle_json" ]]; then
  printf 'swarm checkpoint restore planner requires --checkpoint-bundle-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm checkpoint restore planning\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm checkpoint restore planning\n' >&2
  exit 2
fi
if ! is_int "$now_epoch_seconds"; then
  printf 'now epoch seconds must be a non-negative integer\n' >&2
  exit 64
fi
if [[ -n "$max_restore_age_seconds" ]] && ! is_int "$max_restore_age_seconds"; then
  printf 'max restore age seconds must be a non-negative integer\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/swarm_checkpoint_restore_plan.json"
plan_tmp="${plan_path}.tmp"
core_path="${run_dir}/swarm_checkpoint_restore_plan.core.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
report_tmp="${report_path}.tmp"
fail_reasons_jsonl="${run_dir}/fail_reasons.jsonl"
drift_findings_jsonl="${run_dir}/drift_findings.jsonl"
checkpoint_normalized="${run_dir}/checkpoint_bundle.normalized.json"
current_capacity_snapshot_normalized="${run_dir}/current_swarm_capacity_snapshot.normalized.json"
current_capacity_forecast_normalized="${run_dir}/current_swarm_capacity_forecast.normalized.json"
current_archive_scoreboard_normalized="${run_dir}/current_remote_proof_archive_pressure_scoreboard.normalized.json"
current_stale_lock_normalized="${run_dir}/current_stale_lock_recommendations.normalized.json"
current_salvage_normalized="${run_dir}/current_swarm_lease_exchange_cancellation_salvage_simulation.normalized.json"
current_operator_status_normalized="${run_dir}/current_swarm_operator_status_report.normalized.json"

: >"$events_path"
: >"$fail_reasons_jsonl"
: >"$drift_findings_jsonl"

printf './scripts/swarm_checkpoint_restore_planner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-checkpoint-restore-planner.event.v1" \
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

fail_reason_count=0
drift_finding_count=0
advisory_reason_count=0
provided_current_comparison_count=0
missing_current_comparison_count=0

append_fail_reason() {
  local kind="$1"
  local detail="$2"

  jq -nc \
    --arg kind "$kind" \
    --arg detail "$detail" \
    '{kind: $kind, detail: $detail}' >>"$fail_reasons_jsonl"
  fail_reason_count=$((fail_reason_count + 1))
}

append_drift_finding() {
  local kind="$1"
  local severity="$2"
  local checkpoint_value="$3"
  local current_value="$4"
  local detail="$5"

  jq -nc \
    --arg kind "$kind" \
    --arg severity "$severity" \
    --arg checkpoint_value "$checkpoint_value" \
    --arg current_value "$current_value" \
    --arg detail "$detail" \
    '{
      kind: $kind,
      severity: $severity,
      checkpoint_value: (if $checkpoint_value == "" then null else $checkpoint_value end),
      current_value: (if $current_value == "" then null else $current_value end),
      detail: $detail
    }' >>"$drift_findings_jsonl"
  drift_finding_count=$((drift_finding_count + 1))
  if [[ "$severity" == "advisory" ]]; then
    advisory_reason_count=$((advisory_reason_count + 1))
  fi
}

normalize_required_json() {
  local path="$1"
  local label="$2"
  local schema_version="$3"
  local output_path="$4"

  if [[ ! -f "$path" ]]; then
    printf 'swarm checkpoint restore planner missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'swarm checkpoint restore planner invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq -e --arg schema_version "$schema_version" '.schema_version == $schema_version' "$path" >/dev/null 2>&1; then
    printf 'swarm checkpoint restore planner expected %s for %s\n' "$schema_version" "$label" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
}

normalize_optional_json() {
  local path="$1"
  local label="$2"
  local schema_version="$3"
  local output_path="$4"

  if [[ -z "$path" ]]; then
    printf 'missing'
    return 0
  fi
  if [[ ! -f "$path" ]]; then
    printf 'swarm checkpoint restore planner missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'swarm checkpoint restore planner invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq -e --arg schema_version "$schema_version" '.schema_version == $schema_version' "$path" >/dev/null 2>&1; then
    printf 'swarm checkpoint restore planner expected %s for %s\n' "$schema_version" "$label" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
  printf 'provided'
}

checkpoint_input_path() {
  local key="$1"
  jq -r --arg key "$key" '.normalized_inputs[$key] // ""' "$checkpoint_normalized"
}

ensure_checkpoint_baseline() {
  local path="$1"
  local label="$2"

  if [[ -z "$path" ]]; then
    append_fail_reason "checkpoint_missing_normalized_input" "checkpoint bundle is missing normalized input path for ${label}"
    return 1
  fi
  if [[ ! -f "$path" ]]; then
    append_fail_reason "checkpoint_missing_baseline_artifact" "checkpoint bundle baseline artifact is missing for ${label}: ${path}"
    return 1
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    append_fail_reason "checkpoint_invalid_baseline_artifact" "checkpoint bundle baseline artifact is malformed for ${label}: ${path}"
    return 1
  fi
  return 0
}

record_missing_current_input() {
  local key="$1"
  local detail="$2"

  missing_current_comparison_count=$((missing_current_comparison_count + 1))
  append_drift_finding "$key" "advisory" "" "" "$detail"
}

normalize_required_json "$checkpoint_bundle_json" "checkpoint bundle" "franken-engine.swarm-checkpoint-bundle.v1" "$checkpoint_normalized"

if ! jq -e '
  has("checkpoint_id")
  and has("capture_decision")
  and has("restore_readiness_hint")
  and has("captured_epoch_seconds")
  and has("stale_after_seconds")
  and (.artifact_ledger | type == "object")
  and (.normalized_inputs | type == "object")
  and (.artifact_paths.checkpoint_bundle_json | type == "string")
' "$checkpoint_normalized" >/dev/null 2>&1; then
  printf 'swarm checkpoint restore planner checkpoint bundle is missing required fields\n' >&2
  exit 64
fi

capacity_snapshot_status="$(normalize_optional_json "$current_swarm_capacity_snapshot_json" "current swarm capacity snapshot" "franken-engine.swarm-capacity-snapshot.v1" "$current_capacity_snapshot_normalized")"
capacity_forecast_status="$(normalize_optional_json "$current_swarm_capacity_forecast_json" "current swarm capacity forecast" "franken-engine.swarm-capacity-forecast.v1" "$current_capacity_forecast_normalized")"
archive_scoreboard_status="$(normalize_optional_json "$current_remote_proof_archive_pressure_scoreboard_json" "current remote proof archive pressure scoreboard" "franken-engine.remote-proof-archive-pressure-scoreboard.v1" "$current_archive_scoreboard_normalized")"
stale_lock_status="$(normalize_optional_json "$current_stale_lock_recommendations_json" "current stale lock recommendations" "franken-engine.stale-lock-recommendations.v1" "$current_stale_lock_normalized")"
salvage_status="$(normalize_optional_json "$current_swarm_lease_exchange_cancellation_salvage_simulation_json" "current swarm lease exchange cancellation salvage simulation" "franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1" "$current_salvage_normalized")"
operator_status_status="$(normalize_optional_json "$current_swarm_operator_status_report_json" "current swarm operator status report" "franken-engine.swarm-operator-status-report.v1" "$current_operator_status_normalized")"

write_event "checkpoint_restore_planner.inputs_loaded" "loaded checkpoint bundle and optional current-state comparison inputs"

checkpoint_id="$(jq -r '.checkpoint_id' "$checkpoint_normalized")"
checkpoint_capture_decision="$(jq -r '.capture_decision' "$checkpoint_normalized")"
checkpoint_restore_hint="$(jq -r '.restore_readiness_hint' "$checkpoint_normalized")"
checkpoint_captured_epoch="$(jq -r '.captured_epoch_seconds' "$checkpoint_normalized")"
checkpoint_stale_after="$(jq -r '.stale_after_seconds' "$checkpoint_normalized")"

if ! is_int "$checkpoint_captured_epoch" || ! is_int "$checkpoint_stale_after"; then
  append_fail_reason "checkpoint_invalid_freshness" "checkpoint bundle freshness fields must be numeric"
fi

restore_age_limit="$checkpoint_stale_after"
if [[ -n "$max_restore_age_seconds" ]]; then
  restore_age_limit="$max_restore_age_seconds"
fi

checkpoint_age_seconds=0
checkpoint_freshness_state="fresh"
if is_int "$checkpoint_captured_epoch"; then
  checkpoint_age_seconds=$((now_epoch_seconds - checkpoint_captured_epoch))
  if (( checkpoint_age_seconds < 0 )); then
    checkpoint_age_seconds=0
  fi
  if (( checkpoint_age_seconds > restore_age_limit )); then
    checkpoint_freshness_state="stale"
    append_fail_reason "stale_checkpoint_age" "checkpoint age ${checkpoint_age_seconds}s exceeds allowed restore age ${restore_age_limit}s"
  fi
else
  checkpoint_freshness_state="invalid"
fi

if [[ "$checkpoint_capture_decision" == "fail_closed" || "$checkpoint_restore_hint" == "blocked" ]]; then
  append_fail_reason "checkpoint_not_replayable" "checkpoint bundle was captured as fail_closed or blocked and cannot be restored"
elif [[ "$checkpoint_capture_decision" == "captured_degraded" || "$checkpoint_restore_hint" == "manual_review" ]]; then
  append_drift_finding "checkpoint_requires_manual_review" "advisory" "$checkpoint_capture_decision/$checkpoint_restore_hint" "$checkpoint_capture_decision/$checkpoint_restore_hint" "checkpoint bundle already carried degraded or manual-review restore truth"
fi

checkpoint_blocker_count="$(jq -r '.upstream_evidence.blocker_count // 0' "$checkpoint_normalized")"
if [[ "$checkpoint_blocker_count" != "0" ]]; then
  append_fail_reason "checkpoint_upstream_blockers" "checkpoint bundle still reports upstream blocker_count=${checkpoint_blocker_count}"
fi

if json_scalar_contains "$checkpoint_normalized" 'local_fallback|fallback_to_local|running locally|rch-e326'; then
  append_fail_reason "checkpoint_local_fallback_truth" "checkpoint bundle still contains local-fallback heavy-proof truth"
fi

compare_capacity_snapshot() {
  local current_status="$1"
  local checkpoint_path checkpoint_ready current_ready checkpoint_in_progress current_in_progress

  if [[ "$current_status" == "missing" ]]; then
    record_missing_current_input "missing_current_capacity_snapshot" "current capacity snapshot is required before automatic resume is allowed"
    return 0
  fi

  provided_current_comparison_count=$((provided_current_comparison_count + 1))
  checkpoint_path="$(checkpoint_input_path "swarm_capacity_snapshot_json")"
  ensure_checkpoint_baseline "$checkpoint_path" "swarm capacity snapshot" || return 0

  checkpoint_ready="$(jq -r '.summary.ready_count // 0' "$checkpoint_path")"
  current_ready="$(jq -r '.summary.ready_count // 0' "$current_capacity_snapshot_normalized")"
  checkpoint_in_progress="$(jq -r '.summary.in_progress_count // 0' "$checkpoint_path")"
  current_in_progress="$(jq -r '.summary.in_progress_count // 0' "$current_capacity_snapshot_normalized")"

  if [[ "$current_ready" == "0" ]]; then
    append_fail_reason "worker_pool_exhausted" "current capacity snapshot reports zero ready workers"
  elif [[ "$current_ready" != "$checkpoint_ready" || "$current_in_progress" != "$checkpoint_in_progress" ]]; then
    append_drift_finding "worker_pool_drift" "advisory" "ready=${checkpoint_ready},in_progress=${checkpoint_in_progress}" "ready=${current_ready},in_progress=${current_in_progress}" "current worker counts differ from the captured checkpoint snapshot"
  fi
}

compare_capacity_forecast() {
  local current_status="$1"
  local checkpoint_path checkpoint_state current_state checkpoint_confidence current_confidence checkpoint_decision current_decision

  if [[ "$current_status" == "missing" ]]; then
    record_missing_current_input "missing_current_capacity_forecast" "current capacity forecast is required before automatic resume is allowed"
    return 0
  fi

  provided_current_comparison_count=$((provided_current_comparison_count + 1))
  checkpoint_path="$(checkpoint_input_path "swarm_capacity_forecast_json")"
  ensure_checkpoint_baseline "$checkpoint_path" "swarm capacity forecast" || return 0

  checkpoint_state="$(lower "$(jq -r '.summary.overall_state // "unknown"' "$checkpoint_path")")"
  current_state="$(lower "$(jq -r '.summary.overall_state // "unknown"' "$current_capacity_forecast_normalized")")"
  checkpoint_confidence="$(lower "$(jq -r '.confidence_band // "unknown"' "$checkpoint_path")")"
  current_confidence="$(lower "$(jq -r '.confidence_band // "unknown"' "$current_capacity_forecast_normalized")")"
  checkpoint_decision="$(lower "$(jq -r '.decision // "unknown"' "$checkpoint_path")")"
  current_decision="$(lower "$(jq -r '.decision // "unknown"' "$current_capacity_forecast_normalized")")"

  if [[ "$current_decision" == "fail_closed" || "$current_state" == "blocked" || "$current_state" == "brownout" ]]; then
    append_fail_reason "worker_pool_drift_blocked" "current capacity forecast is no longer green enough to resume from checkpoint"
  elif [[ "$current_state" == "degraded" || "$current_confidence" != "high" || "$current_decision" != "pass" ]]; then
    append_drift_finding "worker_pool_drift" "advisory" "${checkpoint_state}/${checkpoint_confidence}/${checkpoint_decision}" "${current_state}/${current_confidence}/${current_decision}" "current capacity forecast degraded from the captured checkpoint posture"
  elif [[ "$checkpoint_state" != "$current_state" || "$checkpoint_confidence" != "$current_confidence" || "$checkpoint_decision" != "$current_decision" ]]; then
    append_drift_finding "capacity_forecast_drift" "advisory" "${checkpoint_state}/${checkpoint_confidence}/${checkpoint_decision}" "${current_state}/${current_confidence}/${current_decision}" "current capacity forecast changed since checkpoint capture"
  fi
}

compare_archive_pressure() {
  local current_status="$1"
  local checkpoint_path checkpoint_band current_band checkpoint_decision current_decision

  if [[ "$current_status" == "missing" ]]; then
    record_missing_current_input "missing_current_archive_pressure" "current archive pressure scoreboard is required before automatic resume is allowed"
    return 0
  fi

  provided_current_comparison_count=$((provided_current_comparison_count + 1))
  checkpoint_path="$(checkpoint_input_path "remote_proof_archive_pressure_scoreboard_json")"
  ensure_checkpoint_baseline "$checkpoint_path" "remote proof archive pressure scoreboard" || return 0

  checkpoint_band="$(lower "$(jq -r '.summary.pressure_band // "unknown"' "$checkpoint_path")")"
  current_band="$(lower "$(jq -r '.summary.pressure_band // "unknown"' "$current_archive_scoreboard_normalized")")"
  checkpoint_decision="$(lower "$(jq -r '.decision // "unknown"' "$checkpoint_path")")"
  current_decision="$(lower "$(jq -r '.decision // "unknown"' "$current_archive_scoreboard_normalized")")"

  if [[ "$current_decision" == "fail_closed" || "$current_band" == "critical" ]]; then
    append_fail_reason "archive_pressure_blocked" "current archive pressure requires fail-closed preservation before restore"
  elif [[ "$current_band" == "high" || "$current_decision" == "advisory" ]]; then
    append_drift_finding "archive_pressure_drift" "advisory" "${checkpoint_band}/${checkpoint_decision}" "${current_band}/${current_decision}" "current archive pressure is no longer at the captured low-pressure posture"
  elif [[ "$checkpoint_band" != "$current_band" || "$checkpoint_decision" != "$current_decision" ]]; then
    append_drift_finding "archive_pressure_drift" "advisory" "${checkpoint_band}/${checkpoint_decision}" "${current_band}/${current_decision}" "current archive pressure changed since checkpoint capture"
  fi
}

compare_stale_lock_recommendations() {
  local current_status="$1"
  local checkpoint_path checkpoint_safe current_safe checkpoint_contact current_contact

  if [[ "$current_status" == "missing" ]]; then
    record_missing_current_input "missing_current_stale_lock_truth" "current stale-lock recommendations are required before automatic resume is allowed"
    return 0
  fi

  provided_current_comparison_count=$((provided_current_comparison_count + 1))
  checkpoint_path="$(checkpoint_input_path "stale_lock_recommendations_json")"
  ensure_checkpoint_baseline "$checkpoint_path" "stale lock recommendations" || return 0

  if json_scalar_contains "$current_stale_lock_normalized" 'contradictory'; then
    append_fail_reason "contradictory_ownership" "current stale-lock recommendations contain contradictory ownership evidence"
    return 0
  fi

  checkpoint_safe="$(jq -c '(.safe_to_reopen // []) | sort' "$checkpoint_path")"
  current_safe="$(jq -c '(.safe_to_reopen // []) | sort' "$current_stale_lock_normalized")"
  checkpoint_contact="$(jq -c '(.contact_first // []) | sort' "$checkpoint_path")"
  current_contact="$(jq -c '(.contact_first // []) | sort' "$current_stale_lock_normalized")"

  if [[ "$current_contact" != "[]" ]]; then
    append_fail_reason "ownership_contact_first" "current stale-lock truth requires owner contact before restore"
  elif [[ "$checkpoint_safe" != "$current_safe" || "$checkpoint_contact" != "$current_contact" ]]; then
    append_fail_reason "ownership_drift" "current stale-lock reopen/contact truth drifted from the captured checkpoint evidence"
  fi
}

compare_salvage_simulation() {
  local current_status="$1"
  local checkpoint_path checkpoint_decision current_decision current_manual_review_count current_ownership_fail_closed_count

  if [[ "$current_status" == "missing" ]]; then
    record_missing_current_input "missing_current_salvage_truth" "current salvage simulation is required before automatic resume is allowed"
    return 0
  fi

  provided_current_comparison_count=$((provided_current_comparison_count + 1))
  checkpoint_path="$(checkpoint_input_path "swarm_lease_exchange_cancellation_salvage_simulation_json")"
  ensure_checkpoint_baseline "$checkpoint_path" "swarm lease exchange cancellation salvage simulation" || return 0

  checkpoint_decision="$(lower "$(jq -r '.decision // "unknown"' "$checkpoint_path")")"
  current_decision="$(lower "$(jq -r '.decision // "unknown"' "$current_salvage_normalized")")"
  current_manual_review_count="$(jq -r '.summary.manual_review_count // 0' "$current_salvage_normalized")"
  current_ownership_fail_closed_count="$(jq -r '.summary.ownership_fail_closed_count // 0' "$current_salvage_normalized")"

  if [[ "$current_decision" == "fail_closed" || "$current_ownership_fail_closed_count" != "0" ]] || json_scalar_contains "$current_salvage_normalized" 'contradictory'; then
    append_fail_reason "salvage_contradiction" "current salvage truth is fail-closed or contradictory"
  elif [[ "$current_decision" == *manual_review* || "$current_manual_review_count" != "0" ]]; then
    append_drift_finding "salvage_manual_review" "advisory" "$checkpoint_decision" "$current_decision" "current salvage truth requires manual review before restore"
  elif [[ "$checkpoint_decision" != "$current_decision" ]]; then
    append_drift_finding "salvage_drift" "advisory" "$checkpoint_decision" "$current_decision" "current salvage decision changed since checkpoint capture"
  fi
}

compare_operator_status() {
  local current_status="$1"
  local checkpoint_path checkpoint_state current_state checkpoint_action current_action current_unresolved_count

  if [[ "$current_status" == "missing" ]]; then
    record_missing_current_input "missing_current_operator_status" "current operator status report is required before automatic resume is allowed"
    return 0
  fi

  provided_current_comparison_count=$((provided_current_comparison_count + 1))
  checkpoint_path="$(checkpoint_input_path "swarm_operator_status_report_json")"
  ensure_checkpoint_baseline "$checkpoint_path" "swarm operator status report" || return 0

  checkpoint_state="$(lower "$(jq -r '.predictive_dashboard.capacity_forecast.summary.overall_state // "unknown"' "$checkpoint_path")")"
  current_state="$(lower "$(jq -r '.predictive_dashboard.capacity_forecast.summary.overall_state // "unknown"' "$current_operator_status_normalized")")"
  checkpoint_action="$(lower "$(jq -r '.predictive_dashboard.starvation_rescue.top_recommendation_action // "unknown"' "$checkpoint_path")")"
  current_action="$(lower "$(jq -r '.predictive_dashboard.starvation_rescue.top_recommendation_action // "unknown"' "$current_operator_status_normalized")")"
  current_unresolved_count="$(jq -r '.predictive_dashboard.starvation_rescue.unresolved_risks | if type == "array" then length else 0 end' "$current_operator_status_normalized")"

  if [[ "$current_action" == "do_not_resume" || "$current_state" == "blocked" || "$current_state" == "brownout" ]]; then
    append_fail_reason "operator_status_blocked" "current operator status report no longer allows restore from checkpoint"
  elif [[ "$current_state" == "degraded" || "$current_action" == "review_checkpoint_before_resume" || "$current_unresolved_count" != "0" ]]; then
    append_drift_finding "operator_status_drift" "advisory" "${checkpoint_state}/${checkpoint_action}" "${current_state}/${current_action}" "current operator status still requires review before resume"
  elif [[ "$checkpoint_state" != "$current_state" || "$checkpoint_action" != "$current_action" ]]; then
    append_drift_finding "operator_status_drift" "advisory" "${checkpoint_state}/${checkpoint_action}" "${current_state}/${current_action}" "current operator status changed since checkpoint capture"
  fi
}

compare_capacity_snapshot "$capacity_snapshot_status"
compare_capacity_forecast "$capacity_forecast_status"
compare_archive_pressure "$archive_scoreboard_status"
compare_stale_lock_recommendations "$stale_lock_status"
compare_salvage_simulation "$salvage_status"
compare_operator_status "$operator_status_status"

all_current_inputs_provided=false
if [[ "$capacity_snapshot_status" == "provided" && "$capacity_forecast_status" == "provided" && "$archive_scoreboard_status" == "provided" && "$stale_lock_status" == "provided" && "$salvage_status" == "provided" && "$operator_status_status" == "provided" ]]; then
  all_current_inputs_provided=true
fi

decision="resume"
exit_code=0
drift_class="none"
top_restore_action="resume_from_checkpoint"

if [[ "$fail_reason_count" -gt 0 ]]; then
  decision="fail_closed"
  exit_code=42
  drift_class="blocked"
  if jq -s -e 'map(select(.kind == "stale_checkpoint_age")) | length > 0' "$fail_reasons_jsonl" >/dev/null 2>&1; then
    top_restore_action="capture_fresh_checkpoint_bundle"
  elif jq -s -e 'map(select(.kind == "ownership_drift" or .kind == "ownership_contact_first" or .kind == "contradictory_ownership")) | length > 0' "$fail_reasons_jsonl" >/dev/null 2>&1; then
    top_restore_action="manual_ownership_review"
  elif jq -s -e 'map(select(.kind == "archive_pressure_blocked")) | length > 0' "$fail_reasons_jsonl" >/dev/null 2>&1; then
    top_restore_action="clear_archive_blockers_before_restore"
  else
    top_restore_action="refresh_checkpoint_inputs_before_restore"
  fi
elif [[ "$advisory_reason_count" -gt 0 || "$missing_current_comparison_count" -gt 0 || "$all_current_inputs_provided" != "true" ]]; then
  decision="advisory_manual_review"
  exit_code=75
  drift_class="soft"
  if jq -s -e 'map(select(.kind == "salvage_manual_review")) | length > 0' "$drift_findings_jsonl" >/dev/null 2>&1; then
    top_restore_action="review_salvage_pressure_before_resume"
  elif [[ "$missing_current_comparison_count" -gt 0 ]]; then
    top_restore_action="gather_current_comparison_inputs"
  elif jq -s -e 'map(select(.kind == "worker_pool_drift" or .kind == "capacity_forecast_drift" or .kind == "operator_status_drift")) | length > 0' "$drift_findings_jsonl" >/dev/null 2>&1; then
    top_restore_action="refresh_capacity_and_status_before_resume"
  else
    top_restore_action="review_checkpoint_before_resume"
  fi
fi

write_event "checkpoint_restore_planner.drift_evaluated" "decision=${decision} top_action=${top_restore_action}"

fail_reasons_json="$(jq -s '.' "$fail_reasons_jsonl")"
drift_findings_json="$(jq -s '.' "$drift_findings_jsonl")"

jq -n \
  --arg source_revision "$source_revision" \
  --arg checkpoint_id "$checkpoint_id" \
  --arg checkpoint_capture_decision "$checkpoint_capture_decision" \
  --arg checkpoint_restore_hint "$checkpoint_restore_hint" \
  --arg checkpoint_freshness_state "$checkpoint_freshness_state" \
  --arg decision "$decision" \
  --arg drift_class "$drift_class" \
  --arg top_restore_action "$top_restore_action" \
  --argjson exit_code "$exit_code" \
  --argjson checkpoint_age_seconds "$checkpoint_age_seconds" \
  --argjson captured_epoch_seconds "$checkpoint_captured_epoch" \
  --argjson restore_age_limit "$restore_age_limit" \
  --argjson blocker_count "$fail_reason_count" \
  --argjson drift_count "$drift_finding_count" \
  --argjson advisory_count "$advisory_reason_count" \
  --argjson provided_current_comparison_count "$provided_current_comparison_count" \
  --argjson missing_current_comparison_count "$missing_current_comparison_count" \
  --arg capacity_snapshot_status "$capacity_snapshot_status" \
  --arg capacity_forecast_status "$capacity_forecast_status" \
  --arg archive_scoreboard_status "$archive_scoreboard_status" \
  --arg stale_lock_status "$stale_lock_status" \
  --arg salvage_status "$salvage_status" \
  --arg operator_status_status "$operator_status_status" \
  --argjson fail_reasons "$fail_reasons_json" \
  --argjson drift_findings "$drift_findings_json" \
  '{
    source_revision: $source_revision,
    checkpoint_id: $checkpoint_id,
    checkpoint_snapshot: {
      capture_decision: $checkpoint_capture_decision,
      restore_readiness_hint: $checkpoint_restore_hint,
      captured_epoch_seconds: $captured_epoch_seconds,
      checkpoint_freshness_state: $checkpoint_freshness_state,
      allowed_restore_age_seconds: $restore_age_limit
    },
    decision: $decision,
    exit_code: $exit_code,
    drift_class: $drift_class,
    summary: {
      top_restore_action: $top_restore_action,
      blocker_count: $blocker_count,
      drift_count: $drift_count,
      advisory_count: $advisory_count,
      provided_current_comparison_count: $provided_current_comparison_count,
      missing_current_comparison_count: $missing_current_comparison_count
    },
    assumptions: [
      "The checkpoint bundle remains advisory evidence only until current-state comparisons confirm it is still safe.",
      "This planner never reopens beads, transfers ownership, releases reservations, or mutates worker state.",
      "Automatic resume is allowed only when every current comparison input stays within explicit safe bounds."
    ],
    drift_receipt: {
      checkpoint_age_seconds: $checkpoint_age_seconds,
      required_current_comparison_count: 6,
      provided_current_comparison_count: $provided_current_comparison_count,
      missing_current_comparison_count: $missing_current_comparison_count,
      findings: $drift_findings,
      fail_closed_reasons: $fail_reasons
    },
    resolved_inputs: [
      {input: "checkpoint_bundle_json", status: "provided", path: $checkpoint_id, schema_version: "franken-engine.swarm-checkpoint-bundle.v1"},
      {input: "current_swarm_capacity_snapshot_json", status: $capacity_snapshot_status, path: (if $capacity_snapshot_status == "provided" then "provided" else null end), schema_version: "franken-engine.swarm-capacity-snapshot.v1"},
      {input: "current_swarm_capacity_forecast_json", status: $capacity_forecast_status, path: (if $capacity_forecast_status == "provided" then "provided" else null end), schema_version: "franken-engine.swarm-capacity-forecast.v1"},
      {input: "current_remote_proof_archive_pressure_scoreboard_json", status: $archive_scoreboard_status, path: (if $archive_scoreboard_status == "provided" then "provided" else null end), schema_version: "franken-engine.remote-proof-archive-pressure-scoreboard.v1"},
      {input: "current_stale_lock_recommendations_json", status: $stale_lock_status, path: (if $stale_lock_status == "provided" then "provided" else null end), schema_version: "franken-engine.stale-lock-recommendations.v1"},
      {input: "current_swarm_lease_exchange_cancellation_salvage_simulation_json", status: $salvage_status, path: (if $salvage_status == "provided" then "provided" else null end), schema_version: "franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1"},
      {input: "current_swarm_operator_status_report_json", status: $operator_status_status, path: (if $operator_status_status == "provided" then "provided" else null end), schema_version: "franken-engine.swarm-operator-status-report.v1"}
    ]
  }' >"$core_path"

plan_hash="$(jq -cS . "$core_path" | sha256sum | awk '{print $1}')"
plan_id="swarm-checkpoint-restore-plan-${plan_hash:0:16}"

jq \
  --arg schema_version "franken-engine.swarm-checkpoint-restore-plan.v1" \
  --arg plan_id "$plan_id" \
  --arg plan_hash "$plan_hash" \
  --arg plan_path "$plan_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg planner_contract_json "docs/swarm_checkpoint_restore_planner_contract_v1.json" \
  --arg checkpoint_contract_json "docs/swarm_checkpoint_bundle_contract_v1.json" \
  '
  . + {
    schema_version: $schema_version,
    plan_id: $plan_id,
    hash_basis: {
      plan_hash: $plan_hash
    },
    artifact_paths: {
      swarm_checkpoint_restore_plan_json: $plan_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path
    },
    contract_paths: {
      checkpoint_restore_planner_contract_json: $planner_contract_json,
      checkpoint_bundle_contract_json: $checkpoint_contract_json
    }
  }' "$core_path" >"$plan_tmp"
mv "$plan_tmp" "$plan_path"

write_event "checkpoint_restore_planner.completed" "$(jq -r '.decision + " / top_action=" + (.summary.top_restore_action // "none")' "$plan_path")"

{
  printf '# Swarm Checkpoint Restore Plan\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$plan_path")"
  printf -- "- Drift class: \`%s\`\n" "$(jq -r '.drift_class' "$plan_path")"
  printf -- "- Top restore action: \`%s\`\n" "$(jq -r '.summary.top_restore_action' "$plan_path")"
  printf -- "- Checkpoint age seconds: \`%s\`\n" "$(jq -r '.drift_receipt.checkpoint_age_seconds' "$plan_path")"
  printf -- "- Provided current comparisons: \`%s\`\n" "$(jq -r '.summary.provided_current_comparison_count' "$plan_path")"
  printf -- "- Missing current comparisons: \`%s\`\n" "$(jq -r '.summary.missing_current_comparison_count' "$plan_path")"
  if [[ "$(jq '.drift_receipt.fail_closed_reasons | length' "$plan_path")" -ne 0 ]]; then
    printf '\n## Fail-closed reasons\n'
    jq -r '.drift_receipt.fail_closed_reasons[] | "- [" + .kind + "] " + .detail' "$plan_path"
  fi
  if [[ "$(jq '.drift_receipt.findings | length' "$plan_path")" -ne 0 ]]; then
    printf '\n## Drift findings\n'
    jq -r '.drift_receipt.findings[] | "- [" + .kind + "] " + .detail' "$plan_path"
  fi
} >"$report_tmp"
mv "$report_tmp" "$report_path"

printf 'swarm_checkpoint_restore_plan=%s\n' "$plan_path"
case "$decision" in
  resume)
    exit 0
    ;;
  advisory_manual_review)
    exit 75
    ;;
  *)
    exit 42
    ;;
esac
