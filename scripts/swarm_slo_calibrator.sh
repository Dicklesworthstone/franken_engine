#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_SLO_CALIBRATOR_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-slo-calibrator}"
run_id="${SWARM_SLO_CALIBRATOR_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_SLO_CALIBRATOR_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

telemetry_snapshot_json=""
scenario_matrix_report_json=""
archive_pressure_scoreboard_json=""
warm_target_prefetch_roi_advisory_json=""
source_revision=""
now_epoch_seconds="$(date -u +%s)"
stale_after_seconds="1800"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_slo_calibrator.sh --telemetry-snapshot-json FILE --scenario-matrix-report-json FILE --archive-pressure-scoreboard-json FILE --warm-target-prefetch-roi-advisory-json FILE [OPTIONS]

Derives deterministic SWARM-CTRL-IX advisory threshold receipts from the
standalone telemetry snapshot, high-core scenario matrix, and archive / warm
target advisory artifacts. The script is report-only and fixture-fed; it does
not query live services, mutate scheduler state, execute cargo, or call rch.

Required:
  --telemetry-snapshot-json FILE
  --scenario-matrix-report-json FILE
  --archive-pressure-scoreboard-json FILE
  --warm-target-prefetch-roi-advisory-json FILE

Optional:
  --source-revision REV
  --now-epoch-seconds N
  --stale-after-seconds N
  --output-dir DIR

Artifacts:
  swarm_slo_threshold_receipt.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  threshold receipt emitted successfully
  42 fail-closed due to insufficient evidence or contradictory signals
  64 invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --telemetry-snapshot-json)
      telemetry_snapshot_json="${2:-}"
      shift 2
      ;;
    --scenario-matrix-report-json)
      scenario_matrix_report_json="${2:-}"
      shift 2
      ;;
    --archive-pressure-scoreboard-json)
      archive_pressure_scoreboard_json="${2:-}"
      shift 2
      ;;
    --warm-target-prefetch-roi-advisory-json)
      warm_target_prefetch_roi_advisory_json="${2:-}"
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

json_copy() {
  local input_path="$1"
  local output_path="$2"
  local label="$3"

  if [[ -z "$input_path" ]]; then
    printf 'swarm SLO calibrator missing %s\n' "$label" >&2
    exit 64
  fi
  if [[ ! -f "$input_path" ]]; then
    printf 'swarm SLO calibrator missing %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'swarm SLO calibrator invalid %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  jq -c . "$input_path" >"$output_path"
}

if [[ -z "$telemetry_snapshot_json" || -z "$scenario_matrix_report_json" || -z "$archive_pressure_scoreboard_json" || -z "$warm_target_prefetch_roi_advisory_json" ]]; then
  printf 'swarm SLO calibrator requires all four input JSON files\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm SLO calibration\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm SLO calibration\n' >&2
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
receipt_path="${run_dir}/swarm_slo_threshold_receipt.json"
receipt_tmp="${receipt_path}.tmp"
core_path="${run_dir}/swarm_slo_threshold_receipt.core.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

telemetry_normalized="${run_dir}/telemetry_snapshot.normalized.json"
matrix_normalized="${run_dir}/scenario_matrix_report.normalized.json"
archive_normalized="${run_dir}/archive_pressure_scoreboard.normalized.json"
roi_normalized="${run_dir}/warm_target_prefetch_roi_advisory.normalized.json"

: >"$events_path"

printf './scripts/swarm_slo_calibrator.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

json_copy "$telemetry_snapshot_json" "$telemetry_normalized" "telemetry snapshot"
json_copy "$scenario_matrix_report_json" "$matrix_normalized" "scenario matrix report"
json_copy "$archive_pressure_scoreboard_json" "$archive_normalized" "archive pressure scoreboard"
json_copy "$warm_target_prefetch_roi_advisory_json" "$roi_normalized" "warm-target prefetch ROI advisory"

if ! jq -e '.schema_version == "franken-engine.swarm-capacity-snapshot.v1"' "$telemetry_normalized" >/dev/null 2>&1; then
  printf 'swarm SLO calibrator expected franken-engine.swarm-capacity-snapshot.v1\n' >&2
  exit 64
fi
if ! jq -e '.schema_version == "franken-engine.swarm-high-core-scenario-matrix-report.v1"' "$matrix_normalized" >/dev/null 2>&1; then
  printf 'swarm SLO calibrator expected franken-engine.swarm-high-core-scenario-matrix-report.v1\n' >&2
  exit 64
fi
if ! jq -e '
  .schema_version == "franken-engine.remote-proof-archive-pressure-scoreboard.v1"
  and (.pressure_level | type == "string")
  and (.advisory | type == "string")
  and (.recommended_action | type == "string")
' "$archive_normalized" >/dev/null 2>&1; then
  printf 'swarm SLO calibrator archive pressure scoreboard shape mismatch\n' >&2
  exit 64
fi
if ! jq -e '
  .schema_version == "franken-engine.swarm-warm-target-prefetch-roi-advisory.v1"
  and (.advisory | type == "string")
  and (.recommended_action | type == "string")
  and (.proof_cache_summary.proof_cache_decision | type == "string")
  and (.warm_target_summary.roi.expected_reuse_score | type == "number")
  and (.warm_target_summary.roi.realized_reuse_score | type == "number")
  and (.archive_pressure_summary.advisory | type == "string")
  and (.validation_cost_summary.estimated_cpu_slots_total | type == "number")
' "$roi_normalized" >/dev/null 2>&1; then
  printf 'swarm SLO calibrator warm-target ROI advisory shape mismatch\n' >&2
  exit 64
fi

telemetry_hash="$(jq -cS . "$telemetry_normalized" | sha256sum | awk '{print $1}')"
matrix_hash="$(jq -cS . "$matrix_normalized" | sha256sum | awk '{print $1}')"
archive_hash="$(jq -cS . "$archive_normalized" | sha256sum | awk '{print $1}')"
roi_hash="$(jq -cS . "$roi_normalized" | sha256sum | awk '{print $1}')"

jq -n \
  --arg schema_version "franken-engine.swarm-slo-threshold-receipt.v1" \
  --arg source_revision "$source_revision" \
  --argjson generated_epoch_seconds "$now_epoch_seconds" \
  --argjson stale_after_seconds "$stale_after_seconds" \
  --arg telemetry_hash "$telemetry_hash" \
  --arg matrix_hash "$matrix_hash" \
  --arg archive_hash "$archive_hash" \
  --arg roi_hash "$roi_hash" \
  --slurpfile telemetry "$telemetry_normalized" \
  --slurpfile matrix "$matrix_normalized" \
  --slurpfile archive "$archive_normalized" \
  --slurpfile roi "$roi_normalized" \
  '
  def max0(arr): (arr | max // 0);
  def min0(arr): (arr | min // 0);
  def non_rch_count($snapshot):
    [
      $snapshot.swarm_capacity_snapshot.swarm_slo_inputs.stress_concurrency.traceability,
      $snapshot.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.traceability,
      $snapshot.swarm_capacity_snapshot.swarm_slo_inputs.chaos_verification.traceability,
      $snapshot.swarm_capacity_snapshot.swarm_slo_inputs.responsiveness_claim_map.traceability
    ] | map(select(. != "rch_backed")) | length;
  def current_band($value; $green; $near):
    if $value <= $green then "healthy"
    elif $value <= $near then "near_limit"
    else "saturated"
    end;
  def expected_cases:
    [
      "healthy_64plus_admission",
      "disk_pressure_memory_headroom",
      "degraded_worker_pool_local_fallback",
      "manual_confirmation_lock_pressure",
      "proof_cache_hit",
      "proof_cache_stale_miss",
      "chaos_recovery_saturated_queue"
    ];
  ($telemetry[0]) as $snapshot |
  ($matrix[0]) as $matrix_report |
  ($archive[0]) as $archive_scoreboard |
  ($roi[0]) as $roi_advisory |
  ($matrix_report.cases // []) as $cases |
  ([ $cases[] | select(.matched_expected == true and .actual.capacity_decision == "pass") ]) as $pass_cases |
  ([ $pass_cases[] | select(.capacity_snapshot.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.guardrail_state == "healthy") ]) as $healthy_cases |
  ([ $cases[] | .case_id ]) as $present_cases |
  ((expected_cases - $present_cases) | unique) as $missing_cases |
  (max0([ $healthy_cases[] | .capacity_snapshot.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.queue_adjusted_p99_ns ])) as $queue_green_upper_bound_ns |
  (max0([ $pass_cases[] | .capacity_snapshot.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.queue_adjusted_p99_ns ])) as $queue_near_limit_upper_bound_ns |
  (max0([ $healthy_cases[] | .capacity_snapshot.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.observed_p95_ns ])) as $p95_green_upper_bound_ns |
  (max0([ $healthy_cases[] | .capacity_snapshot.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.observed_p99_ns ])) as $p99_green_upper_bound_ns |
  (max0([ $pass_cases[] | .capacity_snapshot.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.observed_p99_ns ])) as $p99_near_limit_upper_bound_ns |
  (max0([ $pass_cases[] | .capacity_snapshot.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.queue_adjusted_p99_ns ])) as $brownout_warning_queue_p99_ns |
  (max0([ $cases[] | .capacity_snapshot.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.queue_adjusted_p99_ns ])) as $brownout_hard_stop_queue_p99_ns |
  (min0([ $pass_cases[] | .capacity_snapshot.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.observed_p95_ns ])) as $p95_floor_ns |
  (min0([ $pass_cases[] | .capacity_snapshot.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.observed_p99_ns ])) as $p99_floor_ns |
  (non_rch_count($snapshot)) as $observed_local_or_unknown_surfaces |
  ($snapshot.decision // "fail_closed") as $snapshot_decision |
  ($snapshot.swarm_capacity_snapshot.swarm_slo_inputs.decision // "fail_closed") as $high_core_decision |
  ($snapshot.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.queue_adjusted_p99_ns // 0) as $current_queue_p99_ns |
  ($snapshot.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.observed_p95_ns // 0) as $current_p95_ns |
  ($snapshot.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.observed_p99_ns // 0) as $current_p99_ns |
  ($snapshot.swarm_capacity_snapshot.predictive_cost.collision_risk // "unknown") as $collision_risk |
  ($snapshot.swarm_capacity_snapshot.proof_freshness.freshness_state // "unknown") as $proof_freshness_state |
  ($roi_advisory.advisory // "fail_closed") as $roi_mode |
  ($archive_scoreboard.advisory // "fail_closed") as $archive_mode |
  ($snapshot_decision != "pass" or $high_core_decision != "pass") as $telemetry_rejected |
  (($matrix_report.failure_count // 0) > 0 or (($matrix_report.summary.mismatch_case_ids // []) | length) > 0 or (($missing_cases | length) > 0)) as $matrix_rejected |
  ($observed_local_or_unknown_surfaces > 0) as $traceability_rejected |
  ($archive_mode == "fail_closed") as $archive_rejected |
  ($roi_mode == "fail_closed") as $roi_rejected |
  ({
    queue_wait_budget_band: (
      if $telemetry_rejected or $matrix_rejected then
        {
          status: "rejected",
          reason: "telemetry snapshot or scenario matrix is not calibration-safe",
          confidence_class: "low",
          unit: "ns",
          green_upper_bound_ns: $queue_green_upper_bound_ns,
          near_limit_upper_bound_ns: $queue_near_limit_upper_bound_ns,
          current_value_ns: $current_queue_p99_ns,
          current_band: "fail_closed",
          accepted_case_ids: ($healthy_cases | map(.case_id))
        }
      elif $current_queue_p99_ns <= $queue_green_upper_bound_ns then
        {
          status: "accepted",
          reason: "current queue-adjusted p99 stays inside the healthy reviewed band",
          confidence_class: "high",
          unit: "ns",
          green_upper_bound_ns: $queue_green_upper_bound_ns,
          near_limit_upper_bound_ns: $queue_near_limit_upper_bound_ns,
          current_value_ns: $current_queue_p99_ns,
          current_band: "healthy",
          accepted_case_ids: ($healthy_cases | map(.case_id))
        }
      elif $current_queue_p99_ns <= $queue_near_limit_upper_bound_ns then
        {
          status: "downgraded",
          reason: "current queue-adjusted p99 only clears the reviewed near-limit band",
          confidence_class: "medium",
          unit: "ns",
          green_upper_bound_ns: $queue_green_upper_bound_ns,
          near_limit_upper_bound_ns: $queue_near_limit_upper_bound_ns,
          current_value_ns: $current_queue_p99_ns,
          current_band: "near_limit",
          accepted_case_ids: ($pass_cases | map(.case_id))
        }
      else
        {
          status: "downgraded",
          reason: "current queue-adjusted p99 exceeds the reviewed healthy band and must stay in a saturated advisory posture",
          confidence_class: "medium",
          unit: "ns",
          green_upper_bound_ns: $queue_green_upper_bound_ns,
          near_limit_upper_bound_ns: $queue_near_limit_upper_bound_ns,
          current_value_ns: $current_queue_p99_ns,
          current_band: "saturated",
          accepted_case_ids: ($pass_cases | map(.case_id))
        }
      end
    ),
    validation_latency_band: (
      if $telemetry_rejected or $matrix_rejected then
        {
          status: "rejected",
          reason: "latency thresholds are not trustworthy while the telemetry snapshot or scenario matrix is fail-closed",
          confidence_class: "low",
          p95_floor_ns: $p95_floor_ns,
          p95_green_upper_bound_ns: $p95_green_upper_bound_ns,
          p99_floor_ns: $p99_floor_ns,
          p99_green_upper_bound_ns: $p99_green_upper_bound_ns,
          p99_near_limit_upper_bound_ns: $p99_near_limit_upper_bound_ns,
          current_p95_ns: $current_p95_ns,
          current_p99_ns: $current_p99_ns,
          current_band: "fail_closed"
        }
      elif ($current_p95_ns <= $p95_green_upper_bound_ns and $current_p99_ns <= $p99_green_upper_bound_ns) then
        {
          status: "accepted",
          reason: "current p95 and p99 stay inside the reviewed healthy latency envelope",
          confidence_class: "high",
          p95_floor_ns: $p95_floor_ns,
          p95_green_upper_bound_ns: $p95_green_upper_bound_ns,
          p99_floor_ns: $p99_floor_ns,
          p99_green_upper_bound_ns: $p99_green_upper_bound_ns,
          p99_near_limit_upper_bound_ns: $p99_near_limit_upper_bound_ns,
          current_p95_ns: $current_p95_ns,
          current_p99_ns: $current_p99_ns,
          current_band: "healthy"
        }
      elif $current_p99_ns <= $p99_near_limit_upper_bound_ns then
        {
          status: "downgraded",
          reason: "current p99 exceeds the healthy band but remains inside the reviewed near-limit envelope",
          confidence_class: "medium",
          p95_floor_ns: $p95_floor_ns,
          p95_green_upper_bound_ns: $p95_green_upper_bound_ns,
          p99_floor_ns: $p99_floor_ns,
          p99_green_upper_bound_ns: $p99_green_upper_bound_ns,
          p99_near_limit_upper_bound_ns: $p99_near_limit_upper_bound_ns,
          current_p95_ns: $current_p95_ns,
          current_p99_ns: $current_p99_ns,
          current_band: "near_limit"
        }
      else
        {
          status: "downgraded",
          reason: "current p99 is above the reviewed healthy band and requires saturated-lane advisory handling",
          confidence_class: "medium",
          p95_floor_ns: $p95_floor_ns,
          p95_green_upper_bound_ns: $p95_green_upper_bound_ns,
          p99_floor_ns: $p99_floor_ns,
          p99_green_upper_bound_ns: $p99_green_upper_bound_ns,
          p99_near_limit_upper_bound_ns: $p99_near_limit_upper_bound_ns,
          current_p95_ns: $current_p95_ns,
          current_p99_ns: $current_p99_ns,
          current_band: "saturated"
        }
      end
    ),
    rch_fallback_rate_tolerance: (
      if $telemetry_rejected or $matrix_rejected or $traceability_rejected then
        {
          status: "rejected",
          reason: "one or more high-core surfaces are local or otherwise non-rch-traceable",
          confidence_class: "low",
          required_rch_backed_surfaces: 4,
          max_local_or_unknown_high_core_surfaces: 0,
          observed_local_or_unknown_high_core_surfaces: $observed_local_or_unknown_surfaces,
          current_band: "fail_closed"
        }
      else
        {
          status: "accepted",
          reason: "all four high-core surfaces remain rch-backed, so fallback tolerance stays strict",
          confidence_class: "high",
          required_rch_backed_surfaces: 4,
          max_local_or_unknown_high_core_surfaces: 0,
          observed_local_or_unknown_high_core_surfaces: 0,
          current_band: "rch_backed_only"
        }
      end
    ),
    starvation_brownout_guardrails: (
      if $telemetry_rejected or $matrix_rejected then
        {
          status: "rejected",
          reason: "brownout guardrails cannot be calibrated from fail-closed telemetry or drifting matrix evidence",
          confidence_class: "low",
          warning_queue_p99_ns: $brownout_warning_queue_p99_ns,
          hard_stop_queue_p99_ns: $brownout_hard_stop_queue_p99_ns,
          degraded_worker_pool_requires_fail_closed: true,
          manual_confirmation_risk: "manual_confirmation",
          saturated_queue_risk: "saturated_queue",
          current_collision_risk: $collision_risk,
          current_band: "fail_closed"
        }
      elif $collision_risk == "manual_confirmation" then
        {
          status: "downgraded",
          reason: "manual confirmation pressure requires the reviewed narrow/manual guardrail posture",
          confidence_class: "medium",
          warning_queue_p99_ns: $brownout_warning_queue_p99_ns,
          hard_stop_queue_p99_ns: $brownout_hard_stop_queue_p99_ns,
          degraded_worker_pool_requires_fail_closed: true,
          manual_confirmation_risk: "manual_confirmation",
          saturated_queue_risk: "saturated_queue",
          current_collision_risk: $collision_risk,
          current_band: "manual_review"
        }
      elif $collision_risk == "saturated_queue" or $current_queue_p99_ns > $queue_green_upper_bound_ns then
        {
          status: "downgraded",
          reason: "queue saturation is present in the reviewed chaos case, so the guardrail stays near-limit instead of widening automatically",
          confidence_class: "medium",
          warning_queue_p99_ns: $brownout_warning_queue_p99_ns,
          hard_stop_queue_p99_ns: $brownout_hard_stop_queue_p99_ns,
          degraded_worker_pool_requires_fail_closed: true,
          manual_confirmation_risk: "manual_confirmation",
          saturated_queue_risk: "saturated_queue",
          current_collision_risk: $collision_risk,
          current_band: "near_limit"
        }
      else
        {
          status: "accepted",
          reason: "current queue and collision signals remain inside the reviewed healthy guardrail posture",
          confidence_class: "high",
          warning_queue_p99_ns: $brownout_warning_queue_p99_ns,
          hard_stop_queue_p99_ns: $brownout_hard_stop_queue_p99_ns,
          degraded_worker_pool_requires_fail_closed: true,
          manual_confirmation_risk: "manual_confirmation",
          saturated_queue_risk: "saturated_queue",
          current_collision_risk: $collision_risk,
          current_band: "healthy"
        }
      end
    ),
    proof_cache_freshness_and_warm_target_roi: (
      if $telemetry_rejected or $matrix_rejected or $roi_rejected then
        {
          status: "rejected",
          reason: "proof-cache freshness or warm-target ROI evidence is fail-closed",
          confidence_class: "low",
          proof_freshness_state: $proof_freshness_state,
          roi_advisory: $roi_mode,
          proof_cache_decision: ($roi_advisory.proof_cache_summary.proof_cache_decision // "unknown"),
          expected_reuse_score: ($roi_advisory.warm_target_summary.roi.expected_reuse_score // 0),
          realized_reuse_score: ($roi_advisory.warm_target_summary.roi.realized_reuse_score // 0),
          recommended_action: ($roi_advisory.recommended_action // "unknown"),
          current_band: "fail_closed"
        }
      elif $roi_mode == "reuse_hot_cache" and $proof_freshness_state == "fresh" then
        {
          status: "accepted",
          reason: "fresh proof-cache evidence and strong warm-target ROI both support hot-cache reuse",
          confidence_class: "high",
          proof_freshness_state: $proof_freshness_state,
          roi_advisory: $roi_mode,
          proof_cache_decision: ($roi_advisory.proof_cache_summary.proof_cache_decision // "unknown"),
          expected_reuse_score: ($roi_advisory.warm_target_summary.roi.expected_reuse_score // 0),
          realized_reuse_score: ($roi_advisory.warm_target_summary.roi.realized_reuse_score // 0),
          recommended_action: ($roi_advisory.recommended_action // "unknown"),
          current_band: "reuse_hot_cache"
        }
      elif $roi_mode == "prefetch_archive" then
        {
          status: "downgraded",
          reason: "ROI stays good enough to refresh from archive, but the calibrator must keep prefetch bounded and advisory-only",
          confidence_class: "medium",
          proof_freshness_state: $proof_freshness_state,
          roi_advisory: $roi_mode,
          proof_cache_decision: ($roi_advisory.proof_cache_summary.proof_cache_decision // "unknown"),
          expected_reuse_score: ($roi_advisory.warm_target_summary.roi.expected_reuse_score // 0),
          realized_reuse_score: ($roi_advisory.warm_target_summary.roi.realized_reuse_score // 0),
          recommended_action: ($roi_advisory.recommended_action // "unknown"),
          current_band: "refresh_from_archive"
        }
      else
        {
          status: "downgraded",
          reason: "warm-target evidence says reuse should stay deferred instead of being promoted into an automatic hot-path threshold",
          confidence_class: "medium",
          proof_freshness_state: $proof_freshness_state,
          roi_advisory: $roi_mode,
          proof_cache_decision: ($roi_advisory.proof_cache_summary.proof_cache_decision // "unknown"),
          expected_reuse_score: ($roi_advisory.warm_target_summary.roi.expected_reuse_score // 0),
          realized_reuse_score: ($roi_advisory.warm_target_summary.roi.realized_reuse_score // 0),
          recommended_action: ($roi_advisory.recommended_action // "unknown"),
          current_band: "defer"
        }
      end
    ),
    archive_salvage_pressure_thresholds: (
      if $telemetry_rejected or $matrix_rejected or $archive_rejected then
        {
          status: "rejected",
          reason: "archive or salvage pressure evidence is fail-closed and cannot support a trustworthy threshold receipt",
          confidence_class: "low",
          pressure_level: ($archive_scoreboard.pressure_level // "unknown"),
          advisory: $archive_mode,
          recommended_action: ($archive_scoreboard.recommended_action // "unknown"),
          current_band: "fail_closed"
        }
      elif $archive_mode == "retain" then
        {
          status: "accepted",
          reason: "archive pressure remains low enough to preserve current residency without salvage escalation",
          confidence_class: "high",
          pressure_level: ($archive_scoreboard.pressure_level // "unknown"),
          advisory: $archive_mode,
          recommended_action: ($archive_scoreboard.recommended_action // "unknown"),
          current_band: "retain"
        }
      elif $archive_mode == "compaction_first" or $archive_mode == "cool_archive" then
        {
          status: "downgraded",
          reason: "archive pressure is elevated enough that compaction or cooling must precede any stronger pressure action",
          confidence_class: "medium",
          pressure_level: ($archive_scoreboard.pressure_level // "unknown"),
          advisory: $archive_mode,
          recommended_action: ($archive_scoreboard.recommended_action // "unknown"),
          current_band: $archive_mode
        }
      else
        {
          status: "downgraded",
          reason: "archive pressure is critical enough that only bounded eviction-ready advice can be published",
          confidence_class: "medium",
          pressure_level: ($archive_scoreboard.pressure_level // "unknown"),
          advisory: $archive_mode,
          recommended_action: ($archive_scoreboard.recommended_action // "unknown"),
          current_band: "critical"
        }
      end
    )
  }) as $thresholds |
  ([ $thresholds[] | select(.status == "accepted") ] | length) as $accepted_count |
  ([ $thresholds[] | select(.status == "downgraded") ] | length) as $downgraded_count |
  ([ $thresholds[] | select(.status == "rejected") ] | length) as $rejected_count |
  (if $rejected_count > 0 then "fail_closed" else "pass" end) as $decision |
  (if $rejected_count > 0 then "low" elif $downgraded_count > 0 then "medium" else "high" end) as $confidence_class |
  {
    schema_version: $schema_version,
    source_revision: $source_revision,
    generated_epoch_seconds: $generated_epoch_seconds,
    stale_after_seconds: $stale_after_seconds,
    decision: $decision,
    exit_code: (if $decision == "fail_closed" then 42 else 0 end),
    confidence_class: $confidence_class,
    assumptions: [
      "The scenario matrix remains the reviewed source of truth for healthy, degraded-worker, manual-confirmation, proof-cache, and chaos high-core cases.",
      "All threshold outputs are advisory only and must not mutate scheduler, archive, or resource-governor defaults automatically.",
      "High-core threshold calibration requires four rch-backed evidence surfaces: stress, tail latency, chaos verification, and responsiveness claim map.",
      "Warm-target ROI thresholds are bounded by the standalone ROI advisory and must not claim live prefetch execution."
    ],
    evidence_hashes: {
      telemetry_snapshot_sha256: $telemetry_hash,
      scenario_matrix_report_sha256: $matrix_hash,
      archive_pressure_scoreboard_sha256: $archive_hash,
      warm_target_prefetch_roi_advisory_sha256: $roi_hash
    },
    summary: {
      accepted_threshold_count: $accepted_count,
      downgraded_threshold_count: $downgraded_count,
      rejected_threshold_count: $rejected_count,
      missing_scenario_classes: $missing_cases,
      reviewed_scenario_count: ($cases | length)
    },
    thresholds: $thresholds
  }
  ' >"$core_path"

receipt_hash="$(jq -cS . "$core_path" | sha256sum | awk '{print $1}')"
receipt_id="swarm-slo-threshold-${receipt_hash:0:16}"

jq \
  --arg receipt_id "$receipt_id" \
  --arg receipt_hash "$receipt_hash" \
  --arg receipt_path "$receipt_path" \
  --arg report_path "$report_path" \
  --arg commands_path "$commands_path" \
  --arg events_path "$events_path" \
  '
  . + {
    receipt_id: $receipt_id,
    hash_basis: {
      receipt_hash: $receipt_hash
    },
    artifact_paths: {
      swarm_slo_threshold_receipt_json: $receipt_path,
      report_md: $report_path,
      commands_txt: $commands_path,
      events_jsonl: $events_path
    }
  }
  ' "$core_path" >"$receipt_tmp"
mv "$receipt_tmp" "$receipt_path"

jq -c --arg source_revision "$source_revision" '
  .thresholds
  | to_entries[]
  | {
      schema_version: "franken-engine.swarm-slo-calibrator.event.v1",
      event_name: "threshold_evaluated",
      threshold_id: .key,
      status: .value.status,
      reason: .value.reason,
      confidence_class: .value.confidence_class,
      source_revision: $source_revision
    }
' "$receipt_path" >>"$events_path"

jq -c --arg source_revision "$source_revision" '
  {
    schema_version: "franken-engine.swarm-slo-calibrator.event.v1",
    event_name: "threshold_receipt_generated",
    threshold_id: "summary",
    status: .decision,
    reason: (
      if .decision == "fail_closed" then
        "one or more threshold families were rejected due to insufficient evidence or contradictory signals"
      elif .summary.downgraded_threshold_count > 0 then
        "threshold families were calibrated successfully but one or more stayed downgraded under current pressure"
      else
        "all threshold families were accepted in the reviewed healthy band"
      end
    ),
    confidence_class: .confidence_class,
    source_revision: $source_revision
  }
' "$receipt_path" >>"$events_path"

{
  printf '# Swarm SLO Threshold Receipt\n\n'
  printf -- "- Receipt ID: \`%s\`\n" "$(jq -r '.receipt_id' "$receipt_path")"
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$receipt_path")"
  printf -- "- Confidence class: \`%s\`\n" "$(jq -r '.confidence_class' "$receipt_path")"
  printf -- "- Accepted thresholds: \`%s\`\n" "$(jq -r '.summary.accepted_threshold_count' "$receipt_path")"
  printf -- "- Downgraded thresholds: \`%s\`\n" "$(jq -r '.summary.downgraded_threshold_count' "$receipt_path")"
  printf -- "- Rejected thresholds: \`%s\`\n\n" "$(jq -r '.summary.rejected_threshold_count' "$receipt_path")"
  jq -r '
    .thresholds
    | to_entries[]
    | "- \(.key): \(.value.status) [\(.value.current_band // "n/a")] - \(.value.reason)"
  ' "$receipt_path"
} >"$report_path"

printf 'swarm_slo_threshold_receipt=%s\n' "$receipt_path"
printf 'swarm_slo_threshold_report=%s\n' "$report_path"
exit "$(jq -r '.exit_code' "$receipt_path")"
