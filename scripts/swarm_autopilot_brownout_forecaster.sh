#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_AUTOPILOT_BROWNOUT_FORECASTER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-autopilot-brownout-forecast}"
run_id="${SWARM_AUTOPILOT_BROWNOUT_FORECASTER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AUTOPILOT_BROWNOUT_FORECASTER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_AUTOPILOT_BROWNOUT_FORECASTER_SOURCE_REVISION:-unknown}"
evidence_warehouse_json=""
queue_signal_input_json=""
queue_fidelity_receipt_json=""
hindsight_bundle_json=""
operator_intent_policy_json=""
now_epoch_seconds="$(date -u +%s)"
stale_after_seconds="1800"
validated_horizon_seconds="1800"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_autopilot_brownout_forecaster.sh [OPTIONS]

Build an advisory-only brownout and saturation forecast from preserved autopilot
warehouse, queue/locality, fidelity, and hindsight evidence. The script is
fixture-fed only: it does not mutate beads, reservations, Agent Mail, Cargo,
RCH, workers, or live queue policy.

Required inputs:
  --evidence-warehouse-json FILE
  --queue-signal-input-json FILE
  --queue-fidelity-receipt-json FILE
  --hindsight-bundle-json FILE

Optional inputs:
  --operator-intent-policy-json FILE
  --source-revision REV
  --now-epoch-seconds N
  --stale-after-seconds N
  --validated-horizon-seconds N
  --output-dir DIR

Artifacts:
  swarm_autopilot_brownout_forecast.json
  swarm_autopilot_brownout_hindsight_comparison.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  forecast emitted successfully
  42 evidence is stale, contradictory, contaminated, or outside the validated horizon
  64 invalid or missing required inputs
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --evidence-warehouse-json)
      evidence_warehouse_json="${2:-}"
      shift 2
      ;;
    --queue-signal-input-json)
      queue_signal_input_json="${2:-}"
      shift 2
      ;;
    --queue-fidelity-receipt-json)
      queue_fidelity_receipt_json="${2:-}"
      shift 2
      ;;
    --hindsight-bundle-json)
      hindsight_bundle_json="${2:-}"
      shift 2
      ;;
    --operator-intent-policy-json)
      operator_intent_policy_json="${2:-}"
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
    --validated-horizon-seconds)
      validated_horizon_seconds="${2:-}"
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

for required_path in \
  "$evidence_warehouse_json" \
  "$queue_signal_input_json" \
  "$queue_fidelity_receipt_json" \
  "$hindsight_bundle_json"; do
  if [[ -z "$required_path" ]]; then
    printf 'all required brownout forecaster inputs must be provided\n' >&2
    usage
    exit 64
  fi
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the swarm autopilot brownout forecaster\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for the swarm autopilot brownout forecaster\n' >&2
  exit 2
fi
if ! is_int "$now_epoch_seconds" || ! is_int "$stale_after_seconds" || ! is_int "$validated_horizon_seconds"; then
  printf 'time and horizon arguments must be non-negative integers\n' >&2
  exit 64
fi

mkdir -p "$run_dir"
forecast_path="${run_dir}/swarm_autopilot_brownout_forecast.json"
forecast_tmp="${forecast_path}.tmp"
forecast_core="${run_dir}/swarm_autopilot_brownout_forecast.core.json"
comparison_path="${run_dir}/swarm_autopilot_brownout_hindsight_comparison.json"
comparison_tmp="${comparison_path}.tmp"
comparison_core="${run_dir}/swarm_autopilot_brownout_hindsight_comparison.core.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

warehouse_normalized="${run_dir}/evidence_warehouse.normalized.json"
queue_signal_normalized="${run_dir}/queue_signal_input.normalized.json"
queue_fidelity_normalized="${run_dir}/queue_fidelity_receipt.normalized.json"
hindsight_normalized="${run_dir}/hindsight_bundle.normalized.json"
operator_intent_normalized="${run_dir}/operator_intent_policy.normalized.json"

printf './scripts/swarm_autopilot_brownout_forecaster.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

: >"$events_path"
: >"$fail_closed_reasons_jsonl"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-brownout-forecaster.event.v1" \
    --arg trace_id "trace-swarm-autopilot-brownout-forecaster-${run_id}" \
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
  local code="$1"
  local source_id="$2"
  local detail="$3"
  local remediation_command="$4"
  jq -nc \
    --arg code "$code" \
    --arg source_id "$source_id" \
    --arg detail "$detail" \
    --arg remediation_command "$remediation_command" \
    '{
      code:$code,
      source_id:$source_id,
      detail:$detail,
      remediation_command:$remediation_command
    }' >>"$fail_closed_reasons_jsonl"
  write_event "$source_id" "fail_closed_reason" "captured" "$code" "$source_id"
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
  if [[ -z "$input_path" ]]; then
    printf 'null\n' >"$output_path"
    write_event "$label" "input_loaded" "missing_optional" "" "$output_path"
    printf 'missing'
    return 0
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
  local code="$3"
  local source_id="$4"
  local detail="$5"
  local remediation="$6"
  if ! jq -e "$expr" "$path" >/dev/null 2>&1; then
    append_failure "$code" "$source_id" "$detail" "$remediation"
  fi
}

snapshot_epoch_for() {
  local file="$1"
  jq -r '
    if (.generated_epoch_seconds? | type) == "number" then
      .generated_epoch_seconds
    elif (.captured_epoch_seconds? | type) == "number" then
      .captured_epoch_seconds
    elif (.actual_epoch_seconds? | type) == "number" then
      .actual_epoch_seconds
    else
      0
    end
  ' "$file"
}

check_staleness() {
  local file="$1"
  local status="$2"
  local source_id="$3"
  local label="$4"
  local remediation="$5"
  local epoch age

  if [[ "$status" != "provided" ]]; then
    return 0
  fi
  epoch="$(snapshot_epoch_for "$file")"
  if is_int "$epoch" && (( epoch > 0 )); then
    age=$((now_epoch_seconds - epoch))
    if (( age > stale_after_seconds )); then
      append_failure "FE-SWARM-AUTOPILOT-BROWNOUT-STALE-EVIDENCE" "$source_id" "${label} age ${age}s exceeds ${stale_after_seconds}s" "$remediation"
    fi
  fi
}

abs_diff() {
  local a="$1"
  local b="$2"
  local delta=$((a - b))
  if (( delta < 0 )); then
    delta=$((-delta))
  fi
  printf '%s' "$delta"
}

normalize_required_json "$evidence_warehouse_json" "$warehouse_normalized" "evidence_warehouse"
normalize_required_json "$queue_signal_input_json" "$queue_signal_normalized" "queue_signal_input"
normalize_required_json "$queue_fidelity_receipt_json" "$queue_fidelity_normalized" "queue_fidelity_receipt"
normalize_required_json "$hindsight_bundle_json" "$hindsight_normalized" "hindsight_bundle"
operator_intent_status="$(normalize_optional_json "$operator_intent_policy_json" "$operator_intent_normalized" "operator_intent_policy")"

if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(jq -r '.source_revision // empty' "$warehouse_normalized")"
fi
if [[ -z "$source_revision" || "$source_revision" == "null" || "$source_revision" == "unknown" ]]; then
  source_revision="$(jq -r '.source_revision // empty' "$queue_signal_normalized")"
fi
if [[ -z "$source_revision" || "$source_revision" == "null" || "$source_revision" == "unknown" ]]; then
  source_revision="unknown"
fi

check_shape "$warehouse_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-evidence-warehouse.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.summary // null) | type == "object")
  and ((.summary.observed_heavy_lane_pressure_millionths // null) | type == "number")
  and ((.summary.heavy_lane_count // null) | type == "number")
  and ((.summary.free_rch_slots // null) | type == "number")
  and ((.summary.target_dir_pressure_millionths // null) | type == "number")
  and ((.summary.proof_cache_pressure_millionths // null) | type == "number")
  and ((.summary.fairness_starvation_millionths // null) | type == "number")
  and ((.summary.stale_progress_risk_millionths // null) | type == "number")
  and ((.artifact_rows // null) | type == "array")
  and ((.hash_basis.warehouse_hash // "") | (type == "string" and length == 64))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-BROWNOUT-SCHEMA-DRIFT" "evidence_warehouse_json" \
  "evidence warehouse is missing required summary, hash, artifact, or safety fields" \
  "Refresh the warehouse bundle from the shipped contract before forecasting."

check_shape "$queue_signal_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-topology-queue-signal-input.v1"
  and ((.truth_state // "") | (type == "string" and length > 0))
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.queue_context.ready_heavy_lane_count // null) | type == "number")
  and ((.queue_context.heavy_lane_pressure_millionths // null) | type == "number")
  and ((.queue_context.starved_ready_count // null) | type == "number")
  and ((.locality_context.target_dir_pressure_millionths // null) | type == "number")
  and ((.rehabilitation_context.available_slot_count // null) | type == "number")
  and ((.rehabilitation_context.active_stall_count // null) | type == "number")
  and ((.rehabilitation_context.stale_progress_worker_count // null) | type == "number")
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-BROWNOUT-SCHEMA-DRIFT" "queue_signal_input_json" \
  "queue signal input is missing required queue, locality, rehab, or safety fields" \
  "Regenerate the topology queue signal input before forecasting."

check_shape "$queue_fidelity_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-topology-aware-queue-fidelity-receipt.v1"
  and ((.truth_state // "") | (type == "string" and length > 0))
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.aggregate_metrics.cache_reuse_confirmation_rate_millionths // null) | type == "number")
  and ((.aggregate_metrics.contradiction_rate_millionths // null) | type == "number")
  and ((.aggregate_metrics.evidence_completeness_rate_millionths // null) | type == "number")
  and ((.aggregate_metrics.confidence_band // "") | (type == "string" and length > 0))
  and ((.reason_codes // null) | type == "array")
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-BROWNOUT-SCHEMA-DRIFT" "queue_fidelity_receipt_json" \
  "queue fidelity receipt is missing required cache, contradiction, completeness, or safety fields" \
  "Regenerate the queue fidelity receipt before forecasting."

check_shape "$hindsight_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-brownout-hindsight-bundle.v1"
  and ((.validated_horizon_seconds // null) | type == "number")
  and ((.actuals // null) | type == "object")
  and ((.actuals.admitted_heavy_lane_pressure.state // "") | (type == "string" and length > 0))
  and ((.actuals.rch_slot_exhaustion.state // "") | (type == "string" and length > 0))
  and ((.actuals.target_dir_pressure.state // "") | (type == "string" and length > 0))
  and ((.actuals.stale_progress_risk.state // "") | (type == "string" and length > 0))
  and ((.actuals.proof_cache_pressure.state // "") | (type == "string" and length > 0))
  and ((.actuals.fairness_starvation_window.state // "") | (type == "string" and length > 0))
  and ((.actual_summary.overall_state // "") | (type == "string" and length > 0))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-BROWNOUT-SCHEMA-DRIFT" "hindsight_bundle_json" \
  "hindsight bundle is missing validated horizon, actual category states, or safety fields" \
  "Refresh the hindsight bundle before forecasting."

if [[ "$operator_intent_status" == "provided" ]]; then
  check_shape "$operator_intent_normalized" '
    type == "object"
    and ((.schema_version // "") | (type == "string" and length > 0))
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
  ' "FE-SWARM-AUTOPILOT-BROWNOUT-SCHEMA-DRIFT" "operator_intent_policy_json" \
    "operator intent policy is missing schema or advisory-only safety markers" \
    "Refresh the operator intent policy before using it as optional context."
fi

check_staleness "$warehouse_normalized" "provided" "evidence_warehouse_json" "warehouse evidence" \
  "Refresh the autopilot evidence warehouse before forecasting."
check_staleness "$queue_signal_normalized" "provided" "queue_signal_input_json" "queue signal evidence" \
  "Refresh the topology queue signal input before forecasting."
check_staleness "$queue_fidelity_normalized" "provided" "queue_fidelity_receipt_json" "queue fidelity evidence" \
  "Refresh the queue fidelity receipt before forecasting."
check_staleness "$hindsight_normalized" "provided" "hindsight_bundle_json" "hindsight evidence" \
  "Refresh the hindsight bundle before forecasting."
if [[ "$operator_intent_status" == "provided" ]]; then
  check_staleness "$operator_intent_normalized" "provided" "operator_intent_policy_json" "operator intent evidence" \
    "Refresh the optional operator intent policy before forecasting."
fi

hindsight_supported_horizon="$(jq -r '.validated_horizon_seconds // 0' "$hindsight_normalized")"
if is_int "$hindsight_supported_horizon" && (( validated_horizon_seconds > hindsight_supported_horizon )); then
  append_failure "FE-SWARM-AUTOPILOT-BROWNOUT-OUTSIDE-VALIDATED-HORIZON" "hindsight_bundle_json" \
    "requested forecast horizon ${validated_horizon_seconds}s exceeds hindsight support window ${hindsight_supported_horizon}s" \
    "Reduce the requested horizon or regenerate a hindsight bundle with a wider validated window."
fi

if jq -e '.decision == "fail_closed"' "$warehouse_normalized" >/dev/null 2>&1; then
  if jq -e '(.fail_closed_reasons // []) | length > 0' "$warehouse_normalized" >/dev/null 2>&1; then
    while IFS= read -r reason; do
      append_failure \
        "$(jq -r '.code // "FE-SWARM-AUTOPILOT-BROWNOUT-UPSTREAM-FAIL-CLOSED"' <<<"$reason")" \
        "$(jq -r '.source_id // "evidence_warehouse_json"' <<<"$reason")" \
        "$(jq -r '.detail // "evidence warehouse is already fail_closed and cannot be promoted into a forecast"' <<<"$reason")" \
        "$(jq -r '.remediation_command // "Refresh the autopilot evidence warehouse before forecasting."' <<<"$reason")"
    done < <(jq -c '.fail_closed_reasons[]' "$warehouse_normalized")
  else
    append_failure "FE-SWARM-AUTOPILOT-BROWNOUT-UPSTREAM-FAIL-CLOSED" "evidence_warehouse_json" \
      "evidence warehouse is already fail_closed and cannot be promoted into a forecast" \
      "Refresh the autopilot evidence warehouse before forecasting."
  fi
fi

if jq -e '
  (.decision == "fail_closed" and ([.fail_closed_reasons[]?.code?, .fail_closed_reasons[]?.detail?] | map(tostring) | any(test("LOCAL-FALLBACK|local fallback|contaminated"; "i"))))
' "$warehouse_normalized" >/dev/null 2>&1 \
  || jq -e '.truth_state == "contaminated"' "$queue_signal_normalized" >/dev/null 2>&1 \
  || jq -e '.truth_state == "contaminated"' "$queue_fidelity_normalized" >/dev/null 2>&1 \
  || jq -e '.local_fallback_contaminated == true' "$hindsight_normalized" >/dev/null 2>&1; then
  append_failure "FE-SWARM-AUTOPILOT-BROWNOUT-LOCAL-FALLBACK" "local_fallback_state" \
    "local fallback contamination is present in required remote-only forecast evidence" \
    "Discard contaminated captures and rerun the forecast with remote-only evidence."
fi

if jq -e '.decision == "blocked" or .truth_state == "blocked"' "$queue_signal_normalized" >/dev/null 2>&1; then
  append_failure "FE-SWARM-AUTOPILOT-BROWNOUT-CONTRADICTORY-EVIDENCE" "queue_signal_input_json" \
    "blocked upstream queue signal evidence cannot be promoted into a brownout forecast" \
    "Resolve the contradictory locality or queue signal evidence before forecasting."
fi

warehouse_heavy_count="$(jq -r '.summary.heavy_lane_count // 0' "$warehouse_normalized")"
queue_heavy_count="$(jq -r '.queue_context.ready_heavy_lane_count // 0' "$queue_signal_normalized")"
warehouse_free_slots="$(jq -r '.summary.free_rch_slots // 0' "$warehouse_normalized")"
queue_free_slots="$(jq -r '.rehabilitation_context.available_slot_count // 0' "$queue_signal_normalized")"
warehouse_pressure="$(jq -r '.summary.observed_heavy_lane_pressure_millionths // 0' "$warehouse_normalized")"
queue_pressure="$(jq -r '.queue_context.heavy_lane_pressure_millionths // 0' "$queue_signal_normalized")"
fidelity_contradiction_rate="$(jq -r '.aggregate_metrics.contradiction_rate_millionths // 0' "$queue_fidelity_normalized")"

if (( $(abs_diff "$warehouse_heavy_count" "$queue_heavy_count") > 2 )); then
  append_failure "FE-SWARM-AUTOPILOT-BROWNOUT-CONTRADICTORY-EVIDENCE" "heavy_lane_pressure" \
    "warehouse heavy-lane count ${warehouse_heavy_count} contradicts queue signal count ${queue_heavy_count}" \
    "Refresh the warehouse and queue-signal captures until heavy-lane counts agree."
fi
if (( $(abs_diff "$warehouse_free_slots" "$queue_free_slots") > 1 )); then
  append_failure "FE-SWARM-AUTOPILOT-BROWNOUT-CONTRADICTORY-EVIDENCE" "free_rch_slots" \
    "warehouse free-slot count ${warehouse_free_slots} contradicts queue signal slot count ${queue_free_slots}" \
    "Refresh the warehouse and queue-signal captures until free-slot evidence agrees."
fi
if (( warehouse_pressure >= 850000 && queue_heavy_count == 0 )); then
  append_failure "FE-SWARM-AUTOPILOT-BROWNOUT-CONTRADICTORY-EVIDENCE" "heavy_lane_pressure" \
    "warehouse claims brownout heavy-lane pressure while queue signal reports zero ready heavy lanes" \
    "Refresh the heavy-lane pressure evidence before forecasting."
fi
if (( queue_pressure >= 850000 && warehouse_free_slots >= 4 )); then
  append_failure "FE-SWARM-AUTOPILOT-BROWNOUT-CONTRADICTORY-EVIDENCE" "free_rch_slots" \
    "queue signal claims brownout pressure while warehouse still reports abundant free RCH slots" \
    "Refresh the queue pressure and RCH slot evidence before forecasting."
fi
if (( fidelity_contradiction_rate > 250000 )); then
  append_failure "FE-SWARM-AUTOPILOT-BROWNOUT-CONTRADICTORY-EVIDENCE" "queue_fidelity_receipt_json" \
    "queue fidelity contradiction rate exceeds the trusted bound for deterministic forecasting" \
    "Resolve queue fidelity contradictions before treating the forecast as trusted."
fi

warehouse_sha="$(sha256sum "$warehouse_normalized" | awk '{print $1}')"
queue_signal_sha="$(sha256sum "$queue_signal_normalized" | awk '{print $1}')"
queue_fidelity_sha="$(sha256sum "$queue_fidelity_normalized" | awk '{print $1}')"
hindsight_sha="$(sha256sum "$hindsight_normalized" | awk '{print $1}')"
if [[ "$operator_intent_status" == "provided" ]]; then
  operator_intent_sha="$(sha256sum "$operator_intent_normalized" | awk '{print $1}')"
else
  operator_intent_sha=""
fi

decision="pass"
truth_state="confirmed"
exit_code=0
if [[ -s "$fail_closed_reasons_jsonl" ]]; then
  decision="fail_closed"
  truth_state="unknown"
  exit_code=42
elif jq -e '.decision != "pass" or .truth_state != "confirmed"' "$queue_signal_normalized" >/dev/null 2>&1 \
  || jq -e '.decision != "pass" or .truth_state != "confirmed"' "$queue_fidelity_normalized" >/dev/null 2>&1; then
  truth_state="degraded"
fi

jq -n \
  --slurpfile warehouse "$warehouse_normalized" \
  --slurpfile queue "$queue_signal_normalized" \
  --slurpfile fidelity "$queue_fidelity_normalized" \
  --slurpfile hindsight "$hindsight_normalized" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg truth_state "$truth_state" \
  --argjson now_epoch_seconds "$now_epoch_seconds" \
  --argjson validated_horizon_seconds "$validated_horizon_seconds" \
  --arg operator_intent_status "$operator_intent_status" \
  --arg warehouse_sha "$warehouse_sha" \
  --arg queue_signal_sha "$queue_signal_sha" \
  --arg queue_fidelity_sha "$queue_fidelity_sha" \
  --arg hindsight_sha "$hindsight_sha" \
  --arg operator_intent_sha "$operator_intent_sha" \
  '
  def clamp($n):
    if $n < 0 then 0
    elif $n > 1000000 then 1000000
    else $n
    end;
  def sev($state):
    if $state == "brownout" then 2
    elif $state == "watch" then 1
    elif $state == "green" then 0
    else -1
    end;
  def band($score):
    if $score >= 850000 then "high"
    elif $score >= 650000 then "medium"
    else "low"
    end;
  def state_from_score($score):
    if $score >= 850000 then "brownout"
    elif $score >= 600000 then "watch"
    else "green"
    end;
  def level_from_state($state):
    if $state == "brownout" then "critical"
    elif $state == "watch" then "high"
    elif $state == "green" then "low"
    else "unknown"
    end;
  def uncertainty($band):
    if $band == "high" then
      "bounded by coherent warehouse, queue, fidelity, and hindsight evidence"
    elif $band == "medium" then
      "bounded by partial upstream degradation but still within the validated horizon"
    else
      "bounded by degraded corroboration and should not be promoted past advisory-only use"
    end;
  ($warehouse[0]) as $w |
  ($queue[0]) as $q |
  ($fidelity[0]) as $f |
  ($hindsight[0]) as $h |
  (clamp(
    900000
    - (if (($q.decision // "pass") != "pass") then 150000 else 0 end)
    - (if (($f.decision // "pass") != "pass") then 150000 else 0 end)
    - (if (($f.aggregate_metrics.evidence_completeness_rate_millionths // 1000000) < 850000) then 100000 else 0 end)
    - (if (($f.aggregate_metrics.contradiction_rate_millionths // 0) > 0) then 100000 else 0 end)
  )) as $base_confidence |
  (if $decision == "fail_closed" then
    {
      admitted_heavy_lane_pressure: {
        state: "unknown",
        risk_level: "unknown",
        confidence_band: "low",
        confidence_score_millionths: 0,
        horizon_seconds: $validated_horizon_seconds,
        source_evidence: [
          ($w.artifact_paths.evidence_warehouse_json // ""),
          ($q.artifact_paths.input_json // ""),
          ($h.artifact_paths.hindsight_bundle_json // "")
        ] | map(select(length > 0)) | unique,
        bounded_uncertainty: "fail_closed evidence cannot be promoted into a forecast"
      },
      rch_slot_exhaustion: {
        state: "unknown",
        risk_level: "unknown",
        confidence_band: "low",
        confidence_score_millionths: 0,
        horizon_seconds: $validated_horizon_seconds,
        source_evidence: [
          ($w.artifact_paths.evidence_warehouse_json // ""),
          ($q.artifact_paths.input_json // ""),
          ($h.artifact_paths.hindsight_bundle_json // "")
        ] | map(select(length > 0)) | unique,
        bounded_uncertainty: "fail_closed evidence cannot be promoted into a forecast"
      },
      target_dir_pressure: {
        state: "unknown",
        risk_level: "unknown",
        confidence_band: "low",
        confidence_score_millionths: 0,
        horizon_seconds: $validated_horizon_seconds,
        source_evidence: [
          ($w.artifact_paths.evidence_warehouse_json // ""),
          ($q.artifact_paths.input_json // ""),
          ($f.artifact_paths.fidelity_receipt_json // ""),
          ($h.artifact_paths.hindsight_bundle_json // "")
        ] | map(select(length > 0)) | unique,
        bounded_uncertainty: "fail_closed evidence cannot be promoted into a forecast"
      },
      stale_progress_risk: {
        state: "unknown",
        risk_level: "unknown",
        confidence_band: "low",
        confidence_score_millionths: 0,
        horizon_seconds: $validated_horizon_seconds,
        source_evidence: [
          ($w.artifact_paths.evidence_warehouse_json // ""),
          ($q.artifact_paths.input_json // ""),
          ($h.artifact_paths.hindsight_bundle_json // "")
        ] | map(select(length > 0)) | unique,
        bounded_uncertainty: "fail_closed evidence cannot be promoted into a forecast"
      },
      proof_cache_pressure: {
        state: "unknown",
        risk_level: "unknown",
        confidence_band: "low",
        confidence_score_millionths: 0,
        horizon_seconds: $validated_horizon_seconds,
        source_evidence: [
          ($w.artifact_paths.evidence_warehouse_json // ""),
          ($f.artifact_paths.fidelity_receipt_json // ""),
          ($h.artifact_paths.hindsight_bundle_json // "")
        ] | map(select(length > 0)) | unique,
        bounded_uncertainty: "fail_closed evidence cannot be promoted into a forecast"
      },
      fairness_starvation_window: {
        state: "unknown",
        risk_level: "unknown",
        confidence_band: "low",
        confidence_score_millionths: 0,
        horizon_seconds: $validated_horizon_seconds,
        source_evidence: [
          ($w.artifact_paths.evidence_warehouse_json // ""),
          ($q.artifact_paths.input_json // ""),
          ($h.artifact_paths.hindsight_bundle_json // "")
        ] | map(select(length > 0)) | unique,
        bounded_uncertainty: "fail_closed evidence cannot be promoted into a forecast"
      }
    }
  else
    {
      admitted_heavy_lane_pressure: (
        ([
          ($w.summary.observed_heavy_lane_pressure_millionths // 0),
          ($q.queue_context.heavy_lane_pressure_millionths // 0)
        ] | max) as $score |
        {
          state: state_from_score($score),
          risk_level: level_from_state(state_from_score($score)),
          confidence_score_millionths: $base_confidence,
          confidence_band: band($base_confidence),
          horizon_seconds: $validated_horizon_seconds,
          source_evidence: [
            ($w.artifact_paths.evidence_warehouse_json // ""),
            ($q.artifact_paths.input_json // ""),
            ($h.artifact_paths.hindsight_bundle_json // "")
          ] | map(select(length > 0)) | unique,
          bounded_uncertainty: uncertainty(band($base_confidence))
        }
      ),
      rch_slot_exhaustion: (
        (if (([$w.summary.free_rch_slots // 0, $q.rehabilitation_context.available_slot_count // 0] | min) <= 1)
           or (($q.rehabilitation_context.active_stall_count // 0) >= 2)
         then 920000
         elif (([$w.summary.free_rch_slots // 0, $q.rehabilitation_context.available_slot_count // 0] | min) <= 2)
           or (($q.rehabilitation_context.active_stall_count // 0) > 0)
         then 680000
         else 220000
         end) as $score |
        {
          state: state_from_score($score),
          risk_level: level_from_state(state_from_score($score)),
          confidence_score_millionths: $base_confidence,
          confidence_band: band($base_confidence),
          horizon_seconds: $validated_horizon_seconds,
          source_evidence: [
            ($w.artifact_paths.evidence_warehouse_json // ""),
            ($q.artifact_paths.input_json // ""),
            ($h.artifact_paths.hindsight_bundle_json // "")
          ] | map(select(length > 0)) | unique,
          bounded_uncertainty: uncertainty(band($base_confidence))
        }
      ),
      target_dir_pressure: (
        ([
          ($w.summary.target_dir_pressure_millionths // 0),
          ($q.locality_context.target_dir_pressure_millionths // 0)
        ] | max) as $score |
        {
          state: state_from_score($score),
          risk_level: level_from_state(state_from_score($score)),
          confidence_score_millionths: $base_confidence,
          confidence_band: band($base_confidence),
          horizon_seconds: $validated_horizon_seconds,
          source_evidence: [
            ($w.artifact_paths.evidence_warehouse_json // ""),
            ($q.artifact_paths.input_json // ""),
            ($f.artifact_paths.fidelity_receipt_json // ""),
            ($h.artifact_paths.hindsight_bundle_json // "")
          ] | map(select(length > 0)) | unique,
          bounded_uncertainty: uncertainty(band($base_confidence))
        }
      ),
      stale_progress_risk: (
        ([
          ($w.summary.stale_progress_risk_millionths // 0),
          (if (($q.rehabilitation_context.stale_progress_worker_count // 0) >= 2) then 900000
           elif (($q.rehabilitation_context.stale_progress_worker_count // 0) == 1) then 700000
           else 120000
           end)
        ] | max) as $score |
        {
          state: state_from_score($score),
          risk_level: level_from_state(state_from_score($score)),
          confidence_score_millionths: $base_confidence,
          confidence_band: band($base_confidence),
          horizon_seconds: $validated_horizon_seconds,
          source_evidence: [
            ($w.artifact_paths.evidence_warehouse_json // ""),
            ($q.artifact_paths.input_json // ""),
            ($h.artifact_paths.hindsight_bundle_json // "")
          ] | map(select(length > 0)) | unique,
          bounded_uncertainty: uncertainty(band($base_confidence))
        }
      ),
      proof_cache_pressure: (
        ([
          ($w.summary.proof_cache_pressure_millionths // 0),
          (if (($f.aggregate_metrics.cache_reuse_confirmation_rate_millionths // 1000000) < 400000) then 910000
           elif (($f.aggregate_metrics.cache_reuse_confirmation_rate_millionths // 1000000) < 700000) then 680000
           else 180000
           end)
        ] | max) as $score |
        {
          state: state_from_score($score),
          risk_level: level_from_state(state_from_score($score)),
          confidence_score_millionths: $base_confidence,
          confidence_band: band($base_confidence),
          horizon_seconds: $validated_horizon_seconds,
          source_evidence: [
            ($w.artifact_paths.evidence_warehouse_json // ""),
            ($f.artifact_paths.fidelity_receipt_json // ""),
            ($h.artifact_paths.hindsight_bundle_json // "")
          ] | map(select(length > 0)) | unique,
          bounded_uncertainty: uncertainty(band($base_confidence))
        }
      ),
      fairness_starvation_window: (
        ([
          ($w.summary.fairness_starvation_millionths // 0),
          (if (($q.queue_context.starved_ready_count // 0) >= 2) then 900000
           elif (($q.queue_context.starved_ready_count // 0) == 1) then 680000
           else 120000
           end)
        ] | max) as $score |
        {
          state: state_from_score($score),
          risk_level: level_from_state(state_from_score($score)),
          confidence_score_millionths: $base_confidence,
          confidence_band: band($base_confidence),
          horizon_seconds: $validated_horizon_seconds,
          source_evidence: [
            ($w.artifact_paths.evidence_warehouse_json // ""),
            ($q.artifact_paths.input_json // ""),
            ($h.artifact_paths.hindsight_bundle_json // "")
          ] | map(select(length > 0)) | unique,
          bounded_uncertainty: uncertainty(band($base_confidence))
        }
      )
    }
  end) as $forecasts |
  ($forecasts | [.[] | sev(.state)] | max) as $max_severity |
  {
    schema_version: "franken-engine.swarm-autopilot-brownout-forecaster.v1",
    source_revision: $source_revision,
    generated_epoch_seconds: $now_epoch_seconds,
    validated_horizon_seconds: $validated_horizon_seconds,
    decision: $decision,
    truth_state: $truth_state,
    summary: {
      overall_state: (
        if $decision == "fail_closed" then "fail_closed"
        elif $max_severity == 2 then "brownout"
        elif $max_severity == 1 then "watch"
        else "green"
        end
      ),
      brownout_state: (
        if $decision == "fail_closed" then "fail_closed"
        elif $max_severity == 2 then "brownout"
        elif $max_severity == 1 then "watch"
        else "green"
        end
      ),
      deterministic_replay_hash_basis: {
        warehouse_sha256: $warehouse_sha,
        queue_signal_sha256: $queue_signal_sha,
        queue_fidelity_sha256: $queue_fidelity_sha,
        hindsight_sha256: $hindsight_sha,
        operator_intent_sha256: (if $operator_intent_sha == "" then null else $operator_intent_sha end)
      },
      compared_category_count: 6
    },
    resolved_inputs: {
      evidence_warehouse_json: "provided",
      queue_signal_input_json: "provided",
      queue_fidelity_receipt_json: "provided",
      hindsight_bundle_json: "provided",
      operator_intent_policy_json: $operator_intent_status
    },
    fail_closed_reasons: $fail_closed_reasons,
    forecasts: $forecasts,
    mutation_policy: {
      advisory_only: true,
      proof_only: true,
      fixture_fed_only: true,
      mutates_br: false,
      reassigns_beads: false,
      releases_reservations: false,
      sends_agent_mail: false,
      runs_cargo: false,
      runs_rch: false,
      mutates_remote_workers: false,
      changes_live_queue_policy: false
    }
  }
' >"$forecast_core"

forecast_hash="$(jq -cS . "$forecast_core" | sha256sum | awk '{print $1}')"
forecast_id="brownout-forecast-${forecast_hash:0:16}"

jq \
  --arg forecast_id "$forecast_id" \
  --arg forecast_path "$forecast_path" \
  --arg comparison_path "$comparison_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  '. + {
    forecast_id: $forecast_id,
    artifact_paths: {
      swarm_autopilot_brownout_forecast_json: $forecast_path,
      swarm_autopilot_brownout_hindsight_comparison_json: $comparison_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path
    }
  }' "$forecast_core" >"$forecast_tmp"
mv "$forecast_tmp" "$forecast_path"

jq -n \
  --slurpfile forecast "$forecast_path" \
  --slurpfile hindsight "$hindsight_normalized" \
  '
  def sev($state):
    if $state == "brownout" then 2
    elif $state == "watch" then 1
    elif $state == "green" then 0
    else -1
    end;
  def comparison_state($predicted; $actual):
    if $predicted == "unknown" then "skipped_due_to_fail_closed"
    elif $predicted == $actual then "exact_match"
    elif sev($predicted) > sev($actual) then "over_warn"
    else "under_warn"
    end;
  ($forecast[0]) as $f |
  ($hindsight[0]) as $h |
  [
    "admitted_heavy_lane_pressure",
    "rch_slot_exhaustion",
    "target_dir_pressure",
    "stale_progress_risk",
    "proof_cache_pressure",
    "fairness_starvation_window"
  ] as $categories |
  ($categories | map({
      category: .,
      predicted_state: ($f.forecasts[.].state // "unknown"),
      predicted_risk_level: ($f.forecasts[.].risk_level // "unknown"),
      actual_state: ($h.actuals[.].state // "unknown"),
      comparison_state: comparison_state(($f.forecasts[.].state // "unknown"); ($h.actuals[.].state // "unknown"))
    })) as $comparisons |
  {
    schema_version: "franken-engine.swarm-autopilot-brownout-hindsight-comparison.v1",
    source_revision: $f.source_revision,
    generated_epoch_seconds: $f.generated_epoch_seconds,
    validated_horizon_seconds: $f.validated_horizon_seconds,
    forecast_id: $f.forecast_id,
    actual_summary: $h.actual_summary,
    comparisons: $comparisons,
    summary: {
      match_count: ($comparisons | map(select(.comparison_state == "exact_match")) | length),
      over_warn_count: ($comparisons | map(select(.comparison_state == "over_warn")) | length),
      under_warn_count: ($comparisons | map(select(.comparison_state == "under_warn")) | length),
      skipped_count: ($comparisons | map(select(.comparison_state == "skipped_due_to_fail_closed")) | length),
      compared_category_count: ($comparisons | length)
    }
  }
' >"$comparison_core"

comparison_hash="$(jq -cS . "$comparison_core" | sha256sum | awk '{print $1}')"
comparison_id="brownout-compare-${comparison_hash:0:16}"

jq \
  --arg comparison_id "$comparison_id" \
  --arg comparison_path "$comparison_path" \
  '. + {comparison_id: $comparison_id, artifact_path: $comparison_path}' \
  "$comparison_core" >"$comparison_tmp"
mv "$comparison_tmp" "$comparison_path"

jq -r '
  [
    "# Swarm Autopilot Brownout Forecast",
    "",
    "- Decision: " + .decision,
    "- Truth state: " + .truth_state,
    "- Overall state: " + .summary.overall_state,
    "- Brownout state: " + .summary.brownout_state,
    "- Forecast ID: " + .forecast_id,
    "- Validated horizon seconds: " + (.validated_horizon_seconds | tostring),
    "- Warehouse hash: " + .summary.deterministic_replay_hash_basis.warehouse_sha256,
    ""
  ]
  + (if (.fail_closed_reasons | length) > 0 then
      ["## Fail-Closed Reasons", ""] +
      (.fail_closed_reasons | map("- `" + .code + "` " + .detail))
    else
      ["## Forecast Categories", ""] +
      (
        .forecasts
        | to_entries
        | map("- `" + .key + "` " + .value.state + " (" + .value.risk_level + ", " + .value.confidence_band + ")")
      )
    end)
  | join("\n")
' "$forecast_path" >"$report_path"

write_event "brownout_forecaster" "forecast_emitted" "$decision" "" "$forecast_path"
write_event "brownout_forecaster" "comparison_emitted" "captured" "" "$comparison_path"

exit "$exit_code"
