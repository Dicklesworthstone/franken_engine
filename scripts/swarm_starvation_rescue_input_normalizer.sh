#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_STARVATION_RESCUE_INPUT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-starvation-rescue-input}"
run_id="${SWARM_STARVATION_RESCUE_INPUT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_STARVATION_RESCUE_INPUT_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

brownout_report_json=""
stale_lock_recommendations_json=""
lease_exchange_salvage_simulation_json=""
admission_budget_plan_json=""
capacity_forecast_json=""
slo_threshold_receipt_json=""
source_revision=""
now_epoch_seconds="$(date -u +%s)"
stale_after_seconds="1800"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_starvation_rescue_input_normalizer.sh \
  --brownout-report-json FILE \
  --stale-lock-recommendations-json FILE \
  --lease-exchange-salvage-simulation-json FILE \
  --admission-budget-plan-json FILE \
  --capacity-forecast-json FILE \
  --slo-threshold-receipt-json FILE \
  [OPTIONS]

Normalizes the existing starvation, stale-lock, salvage, admission, forecast,
and SLO evidence into one deterministic rescue-input surface. This script is
artifact-only: it does not mutate tracker state, call Agent Mail, run cargo, or
change worker state.

Required:
  --brownout-report-json FILE
  --stale-lock-recommendations-json FILE
  --lease-exchange-salvage-simulation-json FILE
  --admission-budget-plan-json FILE
  --capacity-forecast-json FILE
  --slo-threshold-receipt-json FILE

Optional:
  --source-revision REV
  --now-epoch-seconds N
  --stale-after-seconds N
  --output-dir DIR

Artifacts:
  swarm_starvation_rescue_input.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  normalized input surface is publishable
  42 fail-closed due to stale, contradictory, or fallback-admitting evidence
  64 invalid or missing input
EOF
}

is_int() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --brownout-report-json)
      brownout_report_json="${2:-}"
      shift 2
      ;;
    --stale-lock-recommendations-json)
      stale_lock_recommendations_json="${2:-}"
      shift 2
      ;;
    --lease-exchange-salvage-simulation-json)
      lease_exchange_salvage_simulation_json="${2:-}"
      shift 2
      ;;
    --admission-budget-plan-json)
      admission_budget_plan_json="${2:-}"
      shift 2
      ;;
    --capacity-forecast-json)
      capacity_forecast_json="${2:-}"
      shift 2
      ;;
    --slo-threshold-receipt-json)
      slo_threshold_receipt_json="${2:-}"
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
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

for required_path in \
  "$brownout_report_json" \
  "$stale_lock_recommendations_json" \
  "$lease_exchange_salvage_simulation_json" \
  "$admission_budget_plan_json" \
  "$capacity_forecast_json" \
  "$slo_threshold_receipt_json"; do
  if [[ -z "$required_path" ]]; then
    printf 'swarm starvation rescue input normalizer requires all six primary JSON inputs\n' >&2
    exit 64
  fi
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm starvation rescue input normalization\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm starvation rescue input normalization\n' >&2
  exit 2
fi
if ! is_int "$now_epoch_seconds" || ! is_int "$stale_after_seconds"; then
  printf 'now/stale thresholds must be non-negative integers\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
report_path="${run_dir}/swarm_starvation_rescue_input.json"
report_tmp="${report_path}.tmp"
core_path="${run_dir}/swarm_starvation_rescue_input.core.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md_path="${run_dir}/report.md"
fail_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

brownout_normalized="${run_dir}/proof_queue_brownout_report.normalized.json"
stale_lock_normalized="${run_dir}/stale_lock_recommendations.normalized.json"
lease_simulation_normalized="${run_dir}/lease_exchange_salvage_simulation.normalized.json"
admission_plan_normalized="${run_dir}/swarm_admission_budget_plan.normalized.json"
capacity_forecast_normalized="${run_dir}/swarm_capacity_forecast.normalized.json"
slo_receipt_normalized="${run_dir}/swarm_slo_threshold_receipt.normalized.json"

printf './scripts/swarm_starvation_rescue_input_normalizer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$fail_reasons_jsonl"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-starvation-rescue-input.event.v1" \
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
    --arg detail "$3" \
    '{kind:$kind,source:$source,detail:$detail}' >>"$fail_reasons_jsonl"
}

normalize_required_json() {
  local path="$1"
  local output_path="$2"
  local label="$3"
  if [[ ! -f "$path" ]]; then
    printf 'missing required %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
}

snapshot_epoch_for() {
  jq -r '
    if (.generated_epoch_seconds? | type) == "number" then
      .generated_epoch_seconds
    elif (.captured_epoch_seconds? | type) == "number" then
      .captured_epoch_seconds
    elif (.snapshot_epoch_seconds? | type) == "number" then
      .snapshot_epoch_seconds
    elif (.generated_timestamp_ms? | type) == "number" then
      (.generated_timestamp_ms / 1000 | floor)
    elif (.summary.generated_timestamp_ms? | type) == "number" then
      (.summary.generated_timestamp_ms / 1000 | floor)
    else
      0
    end
  ' "$1"
}

check_schema() {
  local file="$1"
  local expr="$2"
  local source="$3"
  local label="$4"
  if ! jq -e "$expr" "$file" >/dev/null 2>&1; then
    append_failure "invalid_required_field" "$source" "required field or shape missing for ${label}"
  fi
}

check_staleness() {
  local file="$1"
  local source="$2"
  local label="$3"
  local epoch
  epoch="$(snapshot_epoch_for "$file")"
  if is_int "$epoch" && (( epoch > 0 )); then
    local age=$((now_epoch_seconds - epoch))
    if (( age > stale_after_seconds )); then
      append_failure "stale_required_input" "$source" "${label} age ${age}s exceeds ${stale_after_seconds}s"
    fi
  fi
}

normalize_required_json "$brownout_report_json" "$brownout_normalized" "brownout report"
normalize_required_json "$stale_lock_recommendations_json" "$stale_lock_normalized" "stale lock recommendations"
normalize_required_json "$lease_exchange_salvage_simulation_json" "$lease_simulation_normalized" "lease exchange salvage simulation"
normalize_required_json "$admission_budget_plan_json" "$admission_plan_normalized" "admission budget plan"
normalize_required_json "$capacity_forecast_json" "$capacity_forecast_normalized" "capacity forecast"
normalize_required_json "$slo_threshold_receipt_json" "$slo_receipt_normalized" "SLO threshold receipt"

check_schema "$brownout_normalized" \
  '.schema_version == "franken-engine.proof-queue-brownout-report.v1" and has("policy_decision") and has("summary")' \
  "brownout_report_json" "brownout report"
check_schema "$stale_lock_normalized" \
  '.schema_version == "franken-engine.stale-lock-recommendations.v1" and (.stale_lock_recommendations | type == "array") and (.safe_to_reopen | type == "array") and (.contact_first | type == "array")' \
  "stale_lock_recommendations_json" "stale lock recommendations"
check_schema "$lease_simulation_normalized" \
  '.schema_version == "franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1" and has("decision") and has("summary") and (.recommendations | type == "array")' \
  "lease_exchange_salvage_simulation_json" "lease exchange salvage simulation"
check_schema "$admission_plan_normalized" \
  '.schema_version == "franken-engine.swarm-admission-budget-plan.v1" and has("decision") and has("summary") and (.recommendations | type == "array")' \
  "admission_budget_plan_json" "admission budget plan"
check_schema "$capacity_forecast_normalized" \
  '.schema_version == "franken-engine.swarm-capacity-forecast.v1" and has("decision") and has("summary") and has("forecasts")' \
  "capacity_forecast_json" "capacity forecast"
check_schema "$slo_receipt_normalized" \
  '.schema_version == "franken-engine.swarm-slo-threshold-receipt.v1" and has("decision") and has("summary") and has("thresholds")' \
  "slo_threshold_receipt_json" "SLO threshold receipt"

check_staleness "$stale_lock_normalized" "stale_lock_recommendations_json" "stale lock recommendations"
check_staleness "$capacity_forecast_normalized" "capacity_forecast_json" "capacity forecast"
check_staleness "$slo_receipt_normalized" "slo_threshold_receipt_json" "SLO threshold receipt"

capacity_decision="$(jq -r '.decision // "unknown"' "$capacity_forecast_normalized")"
slo_decision="$(jq -r '.decision // "unknown"' "$slo_receipt_normalized")"
lease_decision="$(jq -r '.decision // "unknown"' "$lease_simulation_normalized")"
ownership_fail_closed_count="$(jq -r '.summary.ownership_fail_closed_count // 0' "$lease_simulation_normalized")"
if ! is_int "$ownership_fail_closed_count"; then
  ownership_fail_closed_count=0
fi

if [[ "$capacity_decision" != "pass" ]]; then
  append_failure "capacity_forecast_not_pass" "capacity_forecast_json" "capacity forecast decision=${capacity_decision}"
fi
if [[ "$slo_decision" != "pass" ]]; then
  append_failure "slo_receipt_not_pass" "slo_threshold_receipt_json" "SLO threshold receipt decision=${slo_decision}"
fi
if (( ownership_fail_closed_count > 0 )) || [[ "$lease_decision" == "fail_closed" ]]; then
  append_failure "contradictory_ownership" "lease_exchange_salvage_simulation_json" "lease simulation reports ownership fail-closed state"
fi

local_fallback_text="$(jq -r '
  [
    (.fail_closed_reasons[]?.detail // empty),
    (.fail_closed_reasons[]?.reason // empty),
    (.forecasts.rch_transport.supporting_signals.failure_kind // empty),
    (.forecasts.rch_transport.supporting_signals.message // empty),
    (.forecasts.rch_transport.supporting_signals.recommended_action // empty),
    (.forecasts.rch_transport.supporting_signals.recommended_next_action // empty)
  ] | join(" ")
' "$capacity_forecast_normalized" | tr '[:upper:]' '[:lower:]')"
local_fallback_detected=false
if [[ "$local_fallback_text" =~ local[[:space:]_-]*fallback ]]; then
  local_fallback_detected=true
fi
if [[ "$capacity_decision" == "pass" && "$local_fallback_detected" == "true" ]]; then
  append_failure "local_rch_fallback_admitted" "capacity_forecast_json" "capacity forecast passed while rch transport signals still mention local fallback"
fi

write_event "swarm_starvation_rescue_input_normalizer.inputs_loaded" "normalized six upstream rescue inputs"

jq -n \
  --slurpfile brownout "$brownout_normalized" \
  --slurpfile stale "$stale_lock_normalized" \
  --slurpfile lease "$lease_simulation_normalized" \
  --slurpfile admission "$admission_plan_normalized" \
  --slurpfile capacity "$capacity_forecast_normalized" \
  --slurpfile slo "$slo_receipt_normalized" \
  --slurpfile fail_rows "$fail_reasons_jsonl" \
  --arg schema_version "franken-engine.swarm-starvation-rescue-input.v1" \
  --arg source_revision "$source_revision" \
  --arg brownout_path "$brownout_report_json" \
  --arg stale_path "$stale_lock_recommendations_json" \
  --arg lease_path "$lease_exchange_salvage_simulation_json" \
  --arg admission_path "$admission_budget_plan_json" \
  --arg capacity_path "$capacity_forecast_json" \
  --arg slo_path "$slo_threshold_receipt_json" \
  --argjson now_epoch_seconds "$now_epoch_seconds" \
  --argjson stale_after_seconds "$stale_after_seconds" \
  --argjson local_fallback_detected "$local_fallback_detected" \
  '
  def low($value): (($value // "") | tostring | ascii_downcase);
  def count_codes($rows; $pattern):
    [ $rows[]? | select(low(.code // "") | test($pattern)) ] | length;
  def input_epoch($doc):
    if ($doc.generated_epoch_seconds? | type) == "number" then
      $doc.generated_epoch_seconds
    elif ($doc.captured_epoch_seconds? | type) == "number" then
      $doc.captured_epoch_seconds
    elif ($doc.snapshot_epoch_seconds? | type) == "number" then
      $doc.snapshot_epoch_seconds
    elif ($doc.generated_timestamp_ms? | type) == "number" then
      ($doc.generated_timestamp_ms / 1000 | floor)
    elif ($doc.summary.generated_timestamp_ms? | type) == "number" then
      ($doc.summary.generated_timestamp_ms / 1000 | floor)
    else
      0
    end;
  ($brownout[0]) as $brownout_doc |
  ($stale[0]) as $stale_doc |
  ($lease[0]) as $lease_doc |
  ($admission[0]) as $admission_doc |
  ($capacity[0]) as $capacity_doc |
  ($slo[0]) as $slo_doc |
  ($fail_rows // []) as $failures |
  ($brownout_doc.findings // []) as $brownout_findings |
  ($stale_doc.stale_lock_recommendations // []) as $stale_rows |
  ($lease_doc.recommendations // []) as $lease_rows |
  ($failures | length) as $failure_count |
  (if $failure_count > 0 then "fail_closed" else "pass" end) as $decision |
  (if $decision == "fail_closed" then
      "fail_closed"
    elif (
      low($capacity_doc.summary.overall_state // "unknown") != "normal"
      or low($brownout_doc.policy_decision // "unknown") != "pass"
      or low($admission_doc.decision // "unknown") != "admit"
      or low($lease_doc.decision // "unknown") != "advisory"
      or low($slo_doc.confidence_class // "unknown") != "high"
    ) then
      "degraded"
    else
      "ready"
    end) as $readiness |
  {
    schema_version: $schema_version,
    source_revision: $source_revision,
    generated_epoch_seconds: $now_epoch_seconds,
    stale_after_seconds: $stale_after_seconds,
    decision: $decision,
    summary: {
      readiness: $readiness,
      brownout_finding_count: ($brownout_findings | length),
      starvation_finding_count: count_codes($brownout_findings; "starvation"),
      queue_brownout_finding_count: count_codes($brownout_findings; "brownout"),
      safe_to_reopen_count: (($stale_doc.safe_to_reopen // []) | length),
      contact_first_count: (($stale_doc.contact_first // []) | length),
      lease_exchange_candidate_count: ($lease_doc.summary.lease_exchange_candidate_count // 0),
      salvage_promotion_candidate_count: ($lease_doc.summary.salvage_promotion_candidate_count // 0),
      manual_review_count: ($lease_doc.summary.manual_review_count // 0),
      ownership_fail_closed_count: ($lease_doc.summary.ownership_fail_closed_count // 0),
      capacity_overall_state: ($capacity_doc.summary.overall_state // "unknown"),
      capacity_confidence_band: ($capacity_doc.confidence_band // "unknown"),
      admission_decision: ($admission_doc.decision // "unknown"),
      budget_profile: ($admission_doc.budget_profile // "unknown"),
      slo_confidence_class: ($slo_doc.confidence_class // "unknown"),
      brownout_policy_decision: ($brownout_doc.policy_decision // "unknown")
    },
    assumptions: [
      "This normalizer is replay-only and does not mutate beads, reservations, or worker state.",
      "Brownout and admission-plan decisions are preserved as rescue signals rather than treated as automatic blockers by themselves.",
      "Inputs without replayable timestamps are normalized but cannot be age-validated until their upstream surfaces publish epochs."
    ],
    derived_truth: {
      local_rch_fallback_detected: $local_fallback_detected,
      contradictory_ownership_detected: (($lease_doc.summary.ownership_fail_closed_count // 0) > 0),
      lease_decision: ($lease_doc.decision // "unknown"),
      capacity_decision: ($capacity_doc.decision // "unknown"),
      slo_decision: ($slo_doc.decision // "unknown"),
      timestampless_inputs: [
        (if input_epoch($brownout_doc) == 0 then "brownout_report_json" else empty end),
        (if input_epoch($lease_doc) == 0 then "lease_exchange_salvage_simulation_json" else empty end),
        (if input_epoch($admission_doc) == 0 then "admission_budget_plan_json" else empty end)
      ]
    },
    fail_closed_reasons: $failures,
    resolved_inputs: [
      {input:"brownout_report_json", path:$brownout_path, schema_version:($brownout_doc.schema_version // null), generated_epoch_seconds:(input_epoch($brownout_doc) | if . == 0 then null else . end)},
      {input:"stale_lock_recommendations_json", path:$stale_path, schema_version:($stale_doc.schema_version // null), generated_epoch_seconds:(input_epoch($stale_doc) | if . == 0 then null else . end)},
      {input:"lease_exchange_salvage_simulation_json", path:$lease_path, schema_version:($lease_doc.schema_version // null), generated_epoch_seconds:(input_epoch($lease_doc) | if . == 0 then null else . end)},
      {input:"admission_budget_plan_json", path:$admission_path, schema_version:($admission_doc.schema_version // null), generated_epoch_seconds:(input_epoch($admission_doc) | if . == 0 then null else . end)},
      {input:"capacity_forecast_json", path:$capacity_path, schema_version:($capacity_doc.schema_version // null), generated_epoch_seconds:(input_epoch($capacity_doc) | if . == 0 then null else . end)},
      {input:"slo_threshold_receipt_json", path:$slo_path, schema_version:($slo_doc.schema_version // null), generated_epoch_seconds:(input_epoch($slo_doc) | if . == 0 then null else . end)}
    ],
    normalized_inputs: {
      brownout_report: $brownout_doc,
      stale_lock_recommendations: $stale_doc,
      lease_exchange_salvage_simulation: $lease_doc,
      admission_budget_plan: $admission_doc,
      capacity_forecast: $capacity_doc,
      slo_threshold_receipt: $slo_doc
    }
  }
  ' >"$core_path"

input_hash="$(
  jq -n \
    --slurpfile brownout "$brownout_normalized" \
    --slurpfile stale "$stale_lock_normalized" \
    --slurpfile lease "$lease_simulation_normalized" \
    --slurpfile admission "$admission_plan_normalized" \
    --slurpfile capacity "$capacity_forecast_normalized" \
    --slurpfile slo "$slo_receipt_normalized" \
    '{
      brownout_report: ($brownout[0]),
      stale_lock_recommendations: ($stale[0]),
      lease_exchange_salvage_simulation: ($lease[0]),
      admission_budget_plan: ($admission[0]),
      capacity_forecast: ($capacity[0]),
      slo_threshold_receipt: ($slo[0])
    }' | jq -cS . | sha256sum | awk '{print $1}'
)"
report_hash="$(jq -cS . "$core_path" | sha256sum | awk '{print $1}')"
report_id="swarm-starvation-rescue-input-${report_hash:0:16}"

jq \
  --arg report_id "$report_id" \
  --arg input_hash "$input_hash" \
  --arg report_hash "$report_hash" \
  --arg report_path "$report_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md_path "$report_md_path" \
  --arg contract_json "docs/swarm_starvation_rescue_input_contract_v1.json" \
  '
  . + {
    report_id: $report_id,
    hash_basis: {
      input_hash: $input_hash,
      report_hash: $report_hash
    },
    artifact_paths: {
      swarm_starvation_rescue_input_json: $report_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_md_path
    },
    contract_paths: {
      normalizer_contract_json: $contract_json
    }
  }
  ' "$core_path" >"$report_tmp"
mv "$report_tmp" "$report_path"

write_event "swarm_starvation_rescue_input_normalizer.completed" \
  "$(jq -r '.decision + \" / readiness=\" + .summary.readiness' "$report_path")"

{
  printf '# Swarm Starvation Rescue Input\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$report_path")"
  printf -- "- Readiness: \`%s\`\n" "$(jq -r '.summary.readiness' "$report_path")"
  printf -- "- Brownout findings: \`%s\`\n" "$(jq -r '.summary.brownout_finding_count' "$report_path")"
  printf -- "- Safe to reopen: \`%s\`\n" "$(jq -r '.summary.safe_to_reopen_count' "$report_path")"
  printf -- "- Contact first: \`%s\`\n" "$(jq -r '.summary.contact_first_count' "$report_path")"
  printf -- "- Lease exchange candidates: \`%s\`\n" "$(jq -r '.summary.lease_exchange_candidate_count' "$report_path")"
  printf -- "- Manual review count: \`%s\`\n" "$(jq -r '.summary.manual_review_count' "$report_path")"
  printf -- "- Ownership fail-closed count: \`%s\`\n" "$(jq -r '.summary.ownership_fail_closed_count' "$report_path")"
  if [[ "$(jq '.fail_closed_reasons | length' "$report_path")" -ne 0 ]]; then
    printf '\n## Fail-closed reasons\n'
    jq -r '.fail_closed_reasons[] | "- [" + .kind + "] " + .source + ": " + .detail' "$report_path"
  fi
} >"$report_md_path"

printf 'swarm_starvation_rescue_input=%s\n' "$report_path"
if [[ "$(jq -r '.decision' "$report_path")" == "fail_closed" ]]; then
  exit 42
fi
