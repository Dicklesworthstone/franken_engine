#!/usr/bin/env bash
set -euo pipefail

artifact_root="${WARM_TARGET_ROI_EVICTION_LEDGER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-warm-target-roi-eviction-ledger}"
run_id="${WARM_TARGET_ROI_EVICTION_LEDGER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${WARM_TARGET_ROI_EVICTION_LEDGER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

bundle_report_json=""
sticky_plan_json=""
hotspot_ledger_json=""
pressure_snapshot_json=""
incident_history_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/warm_target_roi_eviction_ledger.sh --bundle-report-json FILE --sticky-plan-json FILE --hotspot-ledger-json FILE --pressure-snapshot-json FILE --incident-history-json FILE [OPTIONS]

Build a deterministic retain/cool/evict policy ledger for warm target
directories used by resident remote proof bundles.

Required:
  --bundle-report-json FILE
  --sticky-plan-json FILE
  --hotspot-ledger-json FILE
  --pressure-snapshot-json FILE
  --incident-history-json FILE

Optional:
  --output-dir DIR

Artifacts:
  warm_target_roi_ledger.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   retain the warm target
  42  evict the warm target
  75  cool the warm target due to recent incident history
  64  invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bundle-report-json)
      bundle_report_json="${2:-}"
      shift 2
      ;;
    --sticky-plan-json)
      sticky_plan_json="${2:-}"
      shift 2
      ;;
    --hotspot-ledger-json)
      hotspot_ledger_json="${2:-}"
      shift 2
      ;;
    --pressure-snapshot-json)
      pressure_snapshot_json="${2:-}"
      shift 2
      ;;
    --incident-history-json)
      incident_history_json="${2:-}"
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

if [[ -z "$bundle_report_json" || -z "$sticky_plan_json" || -z "$hotspot_ledger_json" || -z "$pressure_snapshot_json" || -z "$incident_history_json" ]]; then
  printf 'warm target ROI eviction ledger requires all five input JSON files\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for warm target ROI eviction ledger\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for warm target ROI eviction ledger\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
ledger_path="${run_dir}/warm_target_roi_ledger.json"
ledger_tmp="${ledger_path}.tmp"
summary_path="${run_dir}/report.md"
summary_tmp="${summary_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
bundle_normalized="${run_dir}/bundle_report.normalized.json"
sticky_normalized="${run_dir}/sticky_plan.normalized.json"
hotspot_normalized="${run_dir}/hotspot_ledger.normalized.json"
pressure_normalized="${run_dir}/pressure_snapshot.normalized.json"
incident_history_normalized="${run_dir}/incident_history.normalized.json"
ledger_core="${run_dir}/ledger_core.json"
: >"$events_path"

printf './scripts/warm_target_roi_eviction_ledger.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg event "$1" \
    --arg detail "$2" \
    '{event: $event, detail: $detail}' >>"$events_path"
}

normalize_required_json() {
  local path="$1"
  local output_path="$2"
  local label="$3"

  if [[ ! -f "$path" ]]; then
    printf 'warm target ROI eviction ledger missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'warm target ROI eviction ledger invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
}

normalize_required_json "$bundle_report_json" "$bundle_normalized" "bundle report"
normalize_required_json "$sticky_plan_json" "$sticky_normalized" "sticky plan"
normalize_required_json "$hotspot_ledger_json" "$hotspot_normalized" "hotspot ledger"
normalize_required_json "$pressure_snapshot_json" "$pressure_normalized" "pressure snapshot"
normalize_required_json "$incident_history_json" "$incident_history_normalized" "incident history"

jq -cS '
  {
    bundle_id: (.bundle_id // "unknown"),
    bundle_decision: (.bundle_decision // "unknown"),
    expected_worker_id: (.expected_worker_id // ""),
    expected_target_dir: (.expected_target_dir // ""),
    phase_count: (
      if (.phase_count | type) == "number" then .phase_count
      elif (.phase_results | type) == "array" then (.phase_results | length)
      else 0
      end
    ),
    source_revision: (.source_revision // "unknown")
  }
' "$bundle_normalized" >"${bundle_normalized}.tmp"
mv "${bundle_normalized}.tmp" "$bundle_normalized"
write_event "bundle_report_loaded" "normalized resident bundle report"

jq -cS '
  {
    plan_decision: (.plan_decision // "unknown"),
    assigned_worker_id: (.assigned_worker_id // ""),
    assigned_target_dir: (.assigned_target_dir // ""),
    manifest_phase_count: (.manifest_phase_count // 0)
  }
' "$sticky_normalized" >"${sticky_normalized}.tmp"
mv "${sticky_normalized}.tmp" "$sticky_normalized"
write_event "sticky_plan_loaded" "normalized sticky warm-target plan"

jq -cS '
  {
    analysis_status: (.analysis_status // "unknown"),
    repeated_hotspot_count: (.repeated_hotspot_count // 0),
    total_full_sync_commands: (.total_full_sync_commands // 0),
    total_narrow_sync_commands: (.total_narrow_sync_commands // 0)
  }
' "$hotspot_normalized" >"${hotspot_normalized}.tmp"
mv "${hotspot_normalized}.tmp" "$hotspot_normalized"
write_event "hotspot_ledger_loaded" "normalized sync closure hotspot ledger"

jq -cS '
  def valid_level:
    if . == "low" or . == "medium" or . == "high" or . == "critical" then .
    else "low"
    end;
  {
    disk_pressure: ((.disk_pressure // .disk // "low") | valid_level),
    memory_pressure: ((.memory_pressure // .memory // "low") | valid_level)
  }
' "$pressure_normalized" >"${pressure_normalized}.tmp"
mv "${pressure_normalized}.tmp" "$pressure_normalized"
write_event "pressure_snapshot_loaded" "normalized pressure snapshot"

jq -cS '
  {
    incidents: (
      if type == "array" then .
      else (.incidents // [])
      end
      | if type == "array" then . else [] end
      | map({
          failure_kind: (.failure_kind // "unknown"),
          worker_id: (.worker_id // "")
        })
      | sort_by(.failure_kind, .worker_id)
    )
  }
' "$incident_history_normalized" >"${incident_history_normalized}.tmp"
mv "${incident_history_normalized}.tmp" "$incident_history_normalized"
write_event "incident_history_loaded" "normalized preserved incident history"

bundle_error="$(
  jq -r '
    if (.bundle_id | length) == 0 or .bundle_id == "unknown" then
      "bundle report must declare bundle_id"
    elif (.expected_target_dir | length) == 0 then
      "bundle report must declare expected_target_dir"
    else
      ""
    end
  ' "$bundle_normalized"
)"
if [[ -n "$bundle_error" ]]; then
  printf 'warm target ROI eviction ledger invalid bundle report: %s\n' "$bundle_error" >&2
  exit 64
fi

jq -n \
  --slurpfile bundle "$bundle_normalized" \
  --slurpfile sticky "$sticky_normalized" \
  --slurpfile hotspot "$hotspot_normalized" \
  --slurpfile pressure "$pressure_normalized" \
  --slurpfile incidents "$incident_history_normalized" '
  def pressure_rank($value):
    if $value == "critical" then 4
    elif $value == "high" then 3
    elif $value == "medium" then 2
    else 1
    end;
  ($bundle[0]) as $bundle
  | ($sticky[0]) as $sticky
  | ($hotspot[0]) as $hotspot
  | ($pressure[0]) as $pressure
  | ($incidents[0].incidents // []) as $incidents
  | (
      ($hotspot.repeated_hotspot_count * 3)
      + ($hotspot.total_full_sync_commands * 2)
      + ($bundle.phase_count // 0)
      + (if ($sticky.plan_decision // "") == "admit_sticky" then 3
         elif ($sticky.plan_decision // "") == "admit_fallback_worker" then 1
         else 0
         end)
    ) as $expected_reuse_score
  | (
      (if ($bundle.bundle_decision // "") == "pass" then (($bundle.phase_count // 0) * 2) else ($bundle.phase_count // 0) end)
      + (if ($sticky.assigned_target_dir // "") == ($bundle.expected_target_dir // "") then 3 else 0 end)
      + ($hotspot.repeated_hotspot_count // 0)
    ) as $realized_reuse_score
  | (($realized_reuse_score - $expected_reuse_score)) as $reuse_delta
  | (
      [
        $incidents[]
        | select(
            (.failure_kind == "remote_sigkill")
            or (.failure_kind == "worker_unreachable_degraded")
            or (.failure_kind == "timed_out_transport_live_remote_compile")
            or (.failure_kind == "canceled_build_live_orphaned_rustc")
          )
      ]
      | length
    ) as $cooling_incident_count
  | (
      if (pressure_rank($pressure.disk_pressure) >= 4 or pressure_rank($pressure.memory_pressure) >= 4) then
        {
          decision: "evict",
          recommended_action: "evict_warm_target",
          reason: "critical disk or memory pressure overrides warm-target reuse value",
          exit_code: 42,
          policy_findings: ["critical_pressure_forced_eviction"]
        }
      elif ($cooling_incident_count >= 2) then
        {
          decision: "cool",
          recommended_action: "cool_warm_target",
          reason: "recent incident history is too noisy to keep the target in a hot reusable state",
          exit_code: 75,
          policy_findings: ["incident_history_cooling"]
        }
      elif ($realized_reuse_score >= $expected_reuse_score and pressure_rank($pressure.disk_pressure) <= 2 and pressure_rank($pressure.memory_pressure) <= 2) then
        {
          decision: "retain",
          recommended_action: "retain_warm_target",
          reason: "realized reuse value meets or exceeds expectation under bounded pressure",
          exit_code: 0,
          policy_findings: ["high_realized_reuse_value"]
        }
      else
        {
          decision: "evict",
          recommended_action: "evict_warm_target",
          reason: "warm target reuse value does not justify continued residency under current conditions",
          exit_code: 42,
          policy_findings: ["low_realized_reuse_value"]
        }
      end
    ) as $policy
  | {
      schema_version: "franken-engine.warm-target-roi-eviction-ledger.v1",
      bundle_id: $bundle.bundle_id,
      worker_id: (($sticky.assigned_worker_id // "") | if . == "" then null else . end),
      target_dir: $bundle.expected_target_dir,
      decision: $policy.decision,
      recommended_action: $policy.recommended_action,
      reason: $policy.reason,
      policy_findings: $policy.policy_findings,
      roi: {
        expected_reuse_score: $expected_reuse_score,
        realized_reuse_score: $realized_reuse_score,
        reuse_delta: $reuse_delta
      },
      pressure_snapshot: $pressure,
      incident_summary: {
        recent_incident_count: ($incidents | length),
        cooling_incident_count: $cooling_incident_count
      },
      upstream_summaries: {
        bundle_decision: $bundle.bundle_decision,
        sticky_plan_decision: $sticky.plan_decision,
        hotspot_analysis_status: $hotspot.analysis_status
      },
      exit_code: $policy.exit_code
    }
' >"$ledger_core"

input_hash="$(
  jq -n \
    --slurpfile bundle "$bundle_normalized" \
    --slurpfile sticky "$sticky_normalized" \
    --slurpfile hotspot "$hotspot_normalized" \
    --slurpfile pressure "$pressure_normalized" \
    --slurpfile incidents "$incident_history_normalized" \
    '{
      bundle_report: ($bundle[0]),
      sticky_plan: ($sticky[0]),
      hotspot_ledger: ($hotspot[0]),
      pressure_snapshot: ($pressure[0]),
      incident_history: ($incidents[0])
    }' | jq -cS . | sha256sum | awk '{print $1}'
)"
ledger_hash="$(jq -cS . "$ledger_core" | sha256sum | awk '{print $1}')"

jq \
  --arg input_hash "$input_hash" \
  --arg ledger_hash "$ledger_hash" \
  --arg ledger_path "$ledger_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg summary_path "$summary_path" \
  --arg bundle_report_path "$bundle_report_json" \
  --arg sticky_plan_path "$sticky_plan_json" \
  --arg hotspot_ledger_path "$hotspot_ledger_json" \
  --arg pressure_snapshot_path "$pressure_snapshot_json" \
  --arg incident_history_path "$incident_history_json" '
  . + {
    hash_basis: {
      input_hash: $input_hash,
      ledger_hash: $ledger_hash
    },
    upstream_artifact_paths: {
      bundle_report_json: $bundle_report_path,
      sticky_plan_json: $sticky_plan_path,
      hotspot_ledger_json: $hotspot_ledger_path,
      pressure_snapshot_json: $pressure_snapshot_path,
      incident_history_json: $incident_history_path
    },
    artifact_paths: {
      warm_target_roi_ledger_json: $ledger_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $summary_path
    }
  }
' "$ledger_core" >"$ledger_tmp"
mv "$ledger_tmp" "$ledger_path"

write_event "roi_ledger_written" "$(jq -r '.decision + " / " + .recommended_action' "$ledger_path")"

{
  printf '# Warm Target ROI Eviction Ledger\n\n'
  printf '%s\n' "- Decision: \`$(jq -r '.decision' "$ledger_path")\`"
  printf '%s\n' "- Recommended action: \`$(jq -r '.recommended_action' "$ledger_path")\`"
  printf '%s\n' "- Reason: $(jq -r '.reason' "$ledger_path")"
  printf '%s\n' "- Expected reuse score: \`$(jq -r '.roi.expected_reuse_score' "$ledger_path")\`"
  printf '%s\n' "- Realized reuse score: \`$(jq -r '.roi.realized_reuse_score' "$ledger_path")\`"
  printf '%s\n' "- Reuse delta: \`$(jq -r '.roi.reuse_delta' "$ledger_path")\`"
  printf '%s\n' "- Disk pressure: \`$(jq -r '.pressure_snapshot.disk_pressure' "$ledger_path")\`"
  printf '%s\n' "- Memory pressure: \`$(jq -r '.pressure_snapshot.memory_pressure' "$ledger_path")\`"
  printf '\n## Policy Findings\n\n'
  jq -r '.policy_findings[] | "- " + .' "$ledger_path"
} >"$summary_tmp"
mv "$summary_tmp" "$summary_path"

printf 'warm_target_roi_ledger=%s\n' "$ledger_path"
printf 'warm_target_roi_summary=%s\n' "$summary_path"

exit "$(jq -r '.exit_code' "$ledger_path")"
