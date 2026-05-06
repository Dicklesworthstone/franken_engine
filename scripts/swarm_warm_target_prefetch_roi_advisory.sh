#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_WARM_TARGET_PREFETCH_ROI_ADVISORY_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-warm-target-prefetch-roi-advisory}"
run_id="${SWARM_WARM_TARGET_PREFETCH_ROI_ADVISORY_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_WARM_TARGET_PREFETCH_ROI_ADVISORY_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

capacity_forecast_json=""
admission_budget_plan_json=""
proof_cache_plan_json=""
warm_target_roi_ledger_json=""
archive_pressure_scoreboard_json=""
replay_trace_json=""
source_revision=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_warm_target_prefetch_roi_advisory.sh --capacity-forecast-json FILE --admission-budget-plan-json FILE --proof-cache-plan-json FILE --warm-target-roi-ledger-json FILE --archive-pressure-scoreboard-json FILE --replay-trace-json FILE [OPTIONS]

Compose predictive capacity, warm-target ROI, proof-cache reuse, archive
pressure, and replay-cost evidence into a bounded dry-run prefetch advisory.
The advisory is report-only. It does not execute cargo, prefetch artifacts, or
mutate warm target directories.

Required:
  --capacity-forecast-json FILE
  --admission-budget-plan-json FILE
  --proof-cache-plan-json FILE
  --warm-target-roi-ledger-json FILE
  --archive-pressure-scoreboard-json FILE
  --replay-trace-json FILE

Optional:
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_warm_target_prefetch_roi_advisory.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   safe warm-target reuse or archive prefetch is recommended
  42  fail-closed due to cache or archive truth constraints
  75  no safe prefetch should occur under current ROI or pressure
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --capacity-forecast-json)
      capacity_forecast_json="${2:-}"
      shift 2
      ;;
    --admission-budget-plan-json)
      admission_budget_plan_json="${2:-}"
      shift 2
      ;;
    --proof-cache-plan-json)
      proof_cache_plan_json="${2:-}"
      shift 2
      ;;
    --warm-target-roi-ledger-json)
      warm_target_roi_ledger_json="${2:-}"
      shift 2
      ;;
    --archive-pressure-scoreboard-json)
      archive_pressure_scoreboard_json="${2:-}"
      shift 2
      ;;
    --replay-trace-json)
      replay_trace_json="${2:-}"
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

if [[ -z "$capacity_forecast_json" || -z "$admission_budget_plan_json" || -z "$proof_cache_plan_json" || -z "$warm_target_roi_ledger_json" || -z "$archive_pressure_scoreboard_json" || -z "$replay_trace_json" ]]; then
  printf 'warm-target prefetch ROI advisory requires all six input JSON files\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm warm-target prefetch ROI advisory\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm warm-target prefetch ROI advisory\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
advisory_path="${run_dir}/swarm_warm_target_prefetch_roi_advisory.json"
advisory_tmp="${advisory_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
forecast_normalized="${run_dir}/capacity_forecast.normalized.json"
admission_normalized="${run_dir}/admission_budget_plan.normalized.json"
proof_cache_normalized="${run_dir}/proof_cache_plan.normalized.json"
roi_normalized="${run_dir}/warm_target_roi_ledger.normalized.json"
archive_normalized="${run_dir}/archive_pressure_scoreboard.normalized.json"
replay_trace_normalized="${run_dir}/replay_trace.normalized.json"
: >"$events_path"

printf './scripts/swarm_warm_target_prefetch_roi_advisory.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

normalize_required_json() {
  local path="$1"
  local output_path="$2"
  local label="$3"

  if [[ ! -f "$path" ]]; then
    printf 'warm-target prefetch ROI advisory missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'warm-target prefetch ROI advisory invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
}

validate_shape() {
  local file="$1"
  local expr="$2"
  local label="$3"

  if ! jq -e "$expr" "$file" >/dev/null 2>&1; then
    printf 'warm-target prefetch ROI advisory invalid %s shape\n' "$label" >&2
    exit 64
  fi
}

normalize_required_json "$capacity_forecast_json" "$forecast_normalized" "capacity forecast"
normalize_required_json "$admission_budget_plan_json" "$admission_normalized" "admission budget plan"
normalize_required_json "$proof_cache_plan_json" "$proof_cache_normalized" "proof cache plan"
normalize_required_json "$warm_target_roi_ledger_json" "$roi_normalized" "warm target ROI ledger"
normalize_required_json "$archive_pressure_scoreboard_json" "$archive_normalized" "archive pressure scoreboard"
normalize_required_json "$replay_trace_json" "$replay_trace_normalized" "replay trace"

validate_shape "$forecast_normalized" '
  .schema_version == "franken-engine.swarm-capacity-forecast.v1"
  and (.decision | type == "string")
  and (.forecasts | type == "object")
  and (.forecasts.disk_memory_pressure.state | type == "string")
  and (.forecasts.proof_availability.state | type == "string")
' 'capacity forecast'
validate_shape "$admission_normalized" '
  .schema_version == "franken-engine.swarm-admission-budget-plan.v1"
  and (.budget_profile | type == "string")
  and (.recommendations | type == "array")
' 'admission budget plan'
validate_shape "$proof_cache_normalized" '
  .schema_version == "franken-engine.proof-reuse-cache-plan.v1"
  and (.proof_cache_decision | type == "string")
  and (.cache_hit_artifacts | type == "array")
  and (.required_refreshes | type == "array")
  and (.refresh_commands | type == "array")
' 'proof cache plan'
validate_shape "$roi_normalized" '
  .schema_version == "franken-engine.warm-target-roi-eviction-ledger.v1"
  and (.decision | type == "string")
  and (.recommended_action | type == "string")
  and (.roi.expected_reuse_score | type == "number")
  and (.roi.realized_reuse_score | type == "number")
' 'warm target ROI ledger'
validate_shape "$archive_normalized" '
  .schema_version == "franken-engine.remote-proof-archive-pressure-scoreboard.v1"
  and (.advisory | type == "string")
  and (.recommended_action | type == "string")
  and (.policy_findings | type == "array")
' 'archive pressure scoreboard'
validate_shape "$replay_trace_normalized" '
  .schema_version == "franken-engine.proof-economy-replay-trace.v1"
  and (.command_rows | type == "array")
' 'replay trace'

jq -n \
  --slurpfile forecast "$forecast_normalized" \
  --slurpfile admission "$admission_normalized" \
  --slurpfile cache "$proof_cache_normalized" \
  --slurpfile roi "$roi_normalized" \
  --slurpfile archive "$archive_normalized" \
  --slurpfile trace "$replay_trace_normalized" \
  --arg schema_version "franken-engine.swarm-warm-target-prefetch-roi-advisory.v1" \
  --arg source_revision "$source_revision" \
  '
  def low($x): (($x // "unknown") | tostring | ascii_downcase);
  def high_cost_command($row):
    (($row.estimated_cpu_slots // 0) >= 4)
    or (($row.memory_class // "") == "large")
    or (($row.memory_class // "") == "xlarge");
  def bounded($rows):
    if ($rows | type) != "array" then []
    else $rows | map(select(type == "object")) end;

  ($forecast[0]) as $forecast
  | ($admission[0]) as $admission
  | ($cache[0]) as $cache
  | ($roi[0]) as $roi
  | ($archive[0]) as $archive
  | ($trace[0]) as $trace
  | (bounded($trace.command_rows)) as $commands
  | (($commands | map(.estimated_cpu_slots // 1) | add) // 0) as $estimated_cpu_slots_total
  | (($commands | map(select(high_cost_command(.))) | length)) as $high_cost_command_count
  | (($commands | length)) as $command_count
  | (($admission.recommendations // []) | map(select((.decision // "") != "defer"))) as $active_requests
  | (($active_requests | map(select((.proof_obligation // false) or (.budget_class // "") == "protected")) | length)) as $protected_request_count
  | (($cache.summary.cache_hit_count // (($cache.cache_hit_artifacts // []) | length))) as $cache_hit_count
  | (($cache.summary.refresh_count // (($cache.required_refreshes // []) | length))) as $refresh_count
  | (($cache.summary.invalid_count // (($cache.invalid_artifacts // []) | length))) as $invalid_count
  | (($roi.roi.expected_reuse_score // 0) | tonumber) as $expected_reuse_score
  | (($roi.roi.realized_reuse_score // 0) | tonumber) as $realized_reuse_score
  | (($roi.roi.reuse_delta // ($realized_reuse_score - $expected_reuse_score)) | tonumber) as $reuse_delta
  | (low($forecast.forecasts.disk_memory_pressure.state)) as $disk_state
  | (low($forecast.forecasts.proof_availability.state)) as $proof_state
  | (low($forecast.summary.overall_state)) as $overall_state
  | (low($roi.decision)) as $roi_decision
  | (low($cache.proof_cache_decision)) as $cache_decision
  | (low($archive.advisory)) as $archive_advisory
  | (($archive.recommended_action // "unknown")) as $archive_action
  | (($archive.policy_findings // []) + ($roi.policy_findings // [])) as $policy_findings
  | (any($policy_findings[]?; . == "salvage_pinned_blocks_eviction" or . == "orphan_salvage_pinned")) as $salvage_pinned
  | ($archive_advisory == "fail_closed" and $archive_action == "manual_review_required") as $archive_missing_or_untrustworthy
  | ($archive_advisory == "compaction_first") as $archive_compaction_first
  | (
      $roi_decision == "retain"
      and $realized_reuse_score >= $expected_reuse_score
      and $reuse_delta >= 0
      and $estimated_cpu_slots_total >= 4
    ) as $high_roi
  | (
      $roi_decision == "evict"
      or $reuse_delta < 0
      or ($estimated_cpu_slots_total < 4 and $high_cost_command_count == 0)
    ) as $low_roi
  | (
      $disk_state == "degraded"
      or $disk_state == "blocked"
      or $disk_state == "brownout"
      or $overall_state == "brownout"
      or any(($roi.policy_findings // [])[]?; . == "critical_pressure_forced_eviction")
      or ($archive.pressure_level // "") == "critical"
    ) as $disk_or_pressure_blocked
  | (
      if $cache_decision == "fail_closed" then
        {
          advisory: "fail_closed",
          recommended_action: "manual_review_required",
          reason: ($cache.reason // "proof cache planner failed closed"),
          exit_code: 42,
          policy_findings: ["proof_cache_fail_closed"],
          recommended_prefetches: []
        }
      elif $salvage_pinned then
        {
          advisory: "fail_closed",
          recommended_action: "preserve_pinned_evidence",
          reason: "salvage-pinned or orphaned archive evidence blocks safe prefetch planning",
          exit_code: 42,
          policy_findings: ["salvage_pinned_evidence_blocks_prefetch"],
          recommended_prefetches: []
        }
      elif $archive_missing_or_untrustworthy then
        {
          advisory: "fail_closed",
          recommended_action: "defer_until_archive_materialized",
          reason: ($archive.reason // "archive evidence is missing or untrustworthy"),
          exit_code: 42,
          policy_findings: ["archive_prefetch_truth_missing"],
          recommended_prefetches: []
        }
      elif $disk_or_pressure_blocked then
        {
          advisory: "defer",
          recommended_action: "defer_prefetch_pressure",
          reason: "disk, memory, or brownout pressure makes new warm-target or archive prefetch unsafe",
          exit_code: 75,
          policy_findings: ["pressure_blocks_prefetch"],
          recommended_prefetches: []
        }
      elif $low_roi then
        {
          advisory: "defer",
          recommended_action: "defer_prefetch_low_roi",
          reason: "recent validation cost and realized reuse do not justify more warm-target or archive residency",
          exit_code: 75,
          policy_findings: ["low_roi_prefetch_rejected"],
          recommended_prefetches: []
        }
      elif $archive_compaction_first and ($refresh_count > 0) then
        {
          advisory: "defer",
          recommended_action: "defer_until_archive_compaction",
          reason: "archive compaction must happen before a refresh-driven prefetch can be justified",
          exit_code: 75,
          policy_findings: ["archive_compaction_precedes_prefetch"],
          recommended_prefetches: []
        }
      elif (($cache_decision == "partial_refresh" or $cache_decision == "refresh_required") and $refresh_count > 0 and $high_roi) then
        {
          advisory: "prefetch_archive",
          recommended_action: "prefetch_archive_and_retain_target",
          reason: "high ROI and stale proof cache justify bounded archive prefetch plus warm-target retention",
          exit_code: 0,
          policy_findings: ["high_roi_refresh_prefetch"],
          recommended_prefetches: (
            ($cache.required_refreshes // [])
            | map({
                kind: "archive_prefetch",
                artifact_id: (.artifact_id // ""),
                artifact_path: (.artifact_path // ""),
                refresh_command: (.refresh_command // "")
              })
            | sort_by(.artifact_id, .artifact_path, .refresh_command)
          )
        }
      elif ($cache_decision == "cache_hit" and $cache_hit_count > 0 and $high_roi) then
        {
          advisory: "reuse_hot_cache",
          recommended_action: "retain_target_and_reuse_cache",
          reason: "high ROI and safe cache hits justify keeping the existing warm target hot without archive fetch",
          exit_code: 0,
          policy_findings: ["high_roi_hot_cache_reuse"],
          recommended_prefetches: (
            ($cache.cache_hit_artifacts // [])
            | map({
                kind: "reuse_hot_cache",
                artifact_id: (.artifact_id // ""),
                artifact_path: (.artifact_path // "")
              })
            | sort_by(.artifact_id, .artifact_path)
          )
        }
      elif $roi_decision == "cool" then
        {
          advisory: "defer",
          recommended_action: "cool_target_before_prefetch",
          reason: "recent incident history requires cooling the target before any new prefetch can be recommended",
          exit_code: 75,
          policy_findings: ["cool_target_before_prefetch"],
          recommended_prefetches: []
        }
      else
        {
          advisory: "defer",
          recommended_action: "no_safe_prefetch",
          reason: "available cache and warm-target evidence do not support a bounded prefetch recommendation",
          exit_code: 75,
          policy_findings: ["insufficient_prefetch_roi_truth"],
          recommended_prefetches: []
        }
      end
    ) as $decision
  | {
      schema_version: $schema_version,
      source_revision: $source_revision,
      advisory: $decision.advisory,
      recommended_action: $decision.recommended_action,
      reason: $decision.reason,
      exit_code: $decision.exit_code,
      forecast_summary: {
        decision: ($forecast.decision // "unknown"),
        overall_state: ($forecast.summary.overall_state // "unknown"),
        disk_memory_pressure_state: ($forecast.forecasts.disk_memory_pressure.state // "unknown"),
        proof_availability_state: ($forecast.forecasts.proof_availability.state // "unknown")
      },
      budget_summary: {
        budget_profile: ($admission.budget_profile // "unknown"),
        active_request_count: ($active_requests | length),
        protected_request_count: $protected_request_count
      },
      proof_cache_summary: {
        proof_cache_decision: ($cache.proof_cache_decision // "unknown"),
        reason: ($cache.reason // ""),
        cache_hit_count: $cache_hit_count,
        refresh_count: $refresh_count,
        invalid_count: $invalid_count,
        refresh_commands: ($cache.refresh_commands // [])
      },
      warm_target_summary: {
        bundle_id: ($roi.bundle_id // "unknown"),
        worker_id: ($roi.worker_id // null),
        target_dir: ($roi.target_dir // null),
        decision: ($roi.decision // "unknown"),
        recommended_action: ($roi.recommended_action // "unknown"),
        roi: {
          expected_reuse_score: $expected_reuse_score,
          realized_reuse_score: $realized_reuse_score,
          reuse_delta: $reuse_delta
        }
      },
      archive_pressure_summary: {
        advisory: ($archive.advisory // "unknown"),
        recommended_action: ($archive.recommended_action // "unknown"),
        pressure_level: ($archive.pressure_level // "unknown"),
        policy_findings: ($archive.policy_findings // [])
      },
      validation_cost_summary: {
        command_count: $command_count,
        estimated_cpu_slots_total: $estimated_cpu_slots_total,
        high_cost_command_count: $high_cost_command_count
      },
      recommended_prefetches: $decision.recommended_prefetches,
      policy_findings: (($decision.policy_findings + ($roi.policy_findings // [])) | unique | sort)
    }
  ' >"$advisory_tmp"

input_hash="$(
  jq -n \
    --slurpfile forecast "$forecast_normalized" \
    --slurpfile admission "$admission_normalized" \
    --slurpfile cache "$proof_cache_normalized" \
    --slurpfile roi "$roi_normalized" \
    --slurpfile archive "$archive_normalized" \
    --slurpfile trace "$replay_trace_normalized" \
    '{
      capacity_forecast: ($forecast[0]),
      admission_budget_plan: ($admission[0]),
      proof_cache_plan: ($cache[0]),
      warm_target_roi_ledger: ($roi[0]),
      archive_pressure_scoreboard: ($archive[0]),
      replay_trace: ($trace[0])
    }' | jq -cS . | sha256sum | awk '{print $1}'
)"
advisory_hash="$(jq -cS . "$advisory_tmp" | sha256sum | awk '{print $1}')"

# shellcheck disable=SC2094
jq \
  --arg input_hash "$input_hash" \
  --arg advisory_hash "$advisory_hash" \
  --arg advisory_id "prefetch-roi-${advisory_hash:0:16}" \
  --arg advisory_path "$advisory_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg forecast_path "$capacity_forecast_json" \
  --arg admission_path "$admission_budget_plan_json" \
  --arg cache_path "$proof_cache_plan_json" \
  --arg roi_path "$warm_target_roi_ledger_json" \
  --arg archive_path "$archive_pressure_scoreboard_json" \
  --arg trace_path "$replay_trace_json" '
  . + {
    advisory_id: $advisory_id,
    hash_basis: {
      input_hash: $input_hash,
      advisory_hash: $advisory_hash
    },
    upstream_artifact_paths: {
      capacity_forecast_json: $forecast_path,
      admission_budget_plan_json: $admission_path,
      proof_cache_plan_json: $cache_path,
      warm_target_roi_ledger_json: $roi_path,
      archive_pressure_scoreboard_json: $archive_path,
      replay_trace_json: $trace_path
    },
    artifact_paths: {
      swarm_warm_target_prefetch_roi_advisory_json: $advisory_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path
    }
  }
' "$advisory_tmp" >"$advisory_path"
rm -f "$advisory_tmp"

jq -c '
  {
    schema_version: "franken-engine.swarm-warm-target-prefetch-roi-advisory-event.v1",
    event_name: "swarm_warm_target_prefetch_roi_advisory.generated",
    advisory: .advisory,
    recommended_action: .recommended_action,
    exit_code: .exit_code
  }
' "$advisory_path" >>"$events_path"

{
  printf '# Swarm Warm Target Prefetch ROI Advisory\n\n'
  printf '%s\n' "- Advisory: \`$(jq -r '.advisory' "$advisory_path")\`"
  printf '%s\n' "- Recommended action: \`$(jq -r '.recommended_action' "$advisory_path")\`"
  printf '%s\n' "- Reason: $(jq -r '.reason' "$advisory_path")"
  printf '%s\n' "- Budget profile: \`$(jq -r '.budget_summary.budget_profile' "$advisory_path")\`"
  printf '%s\n' "- Warm target: \`$(jq -r '.warm_target_summary.target_dir // "unknown"' "$advisory_path")\`"
  printf '%s\n' "- Proof cache decision: \`$(jq -r '.proof_cache_summary.proof_cache_decision' "$advisory_path")\`"
  printf '%s\n' "- Archive pressure: \`$(jq -r '.archive_pressure_summary.advisory' "$advisory_path")\`"
  printf '%s\n' "- Estimated CPU slots: \`$(jq -r '.validation_cost_summary.estimated_cpu_slots_total' "$advisory_path")\`"
} >"$report_path"

exit "$(jq -r '.exit_code' "$advisory_path")"
