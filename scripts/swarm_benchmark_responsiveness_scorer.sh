#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_BENCHMARK_RESPONSIVENESS_SCORER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-benchmark-responsiveness-scorer}"
run_id="${SWARM_BENCHMARK_RESPONSIVENESS_SCORER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_BENCHMARK_RESPONSIVENESS_SCORER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_BENCHMARK_RESPONSIVENESS_SCORER_SOURCE_REVISION:-}"
normalized_workload_catalog_json=""
normalized_benchmark_bundle_json=""
resource_envelope_json=""
topology_locality_json=""
proof_cache_locality_plan_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_benchmark_responsiveness_scorer.sh [OPTIONS]

Build a deterministic responsiveness and utilization advisory from the
normalized benchmark workload catalog and normalized benchmark bundle.

Required:
  --normalized-workload-catalog-json FILE
  --normalized-benchmark-bundle-json FILE

Optional:
  --resource-envelope-json FILE
  --topology-locality-json FILE
  --proof-cache-locality-plan-json FILE
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_benchmark_responsiveness_advisory.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  advisory emitted with decision pass or degraded
  42 fail-closed benchmark evidence or recommendation policy violation
  64 invalid argument or malformed required JSON
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --normalized-workload-catalog-json)
      normalized_workload_catalog_json="${2:-}"
      shift 2
      ;;
    --normalized-benchmark-bundle-json)
      normalized_benchmark_bundle_json="${2:-}"
      shift 2
      ;;
    --resource-envelope-json)
      resource_envelope_json="${2:-}"
      shift 2
      ;;
    --topology-locality-json)
      topology_locality_json="${2:-}"
      shift 2
      ;;
    --proof-cache-locality-plan-json)
      proof_cache_locality_plan_json="${2:-}"
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

if [[ -z "$normalized_workload_catalog_json" || -z "$normalized_benchmark_bundle_json" ]]; then
  printf 'normalized workload catalog and normalized benchmark bundle are required\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for benchmark responsiveness scoring\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for benchmark responsiveness scoring\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
advisory_path="${run_dir}/swarm_benchmark_responsiveness_advisory.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
bottlenecks_jsonl="${run_dir}/bottlenecks.jsonl"
advisory_commands_jsonl="${run_dir}/advisory_commands.jsonl"
degraded_reasons_jsonl="${run_dir}/degraded_reasons.jsonl"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"
catalog_normalized="${run_dir}/normalized_workload_catalog.normalized.json"
bundle_normalized="${run_dir}/normalized_benchmark_bundle.normalized.json"
resource_envelope_normalized="${run_dir}/resource_envelope.normalized.json"
topology_locality_normalized="${run_dir}/topology_locality.normalized.json"
proof_cache_plan_normalized="${run_dir}/proof_cache_locality_plan.normalized.json"

: >"$events_path"
: >"$bottlenecks_jsonl"
: >"$advisory_commands_jsonl"
: >"$degraded_reasons_jsonl"
: >"$fail_closed_reasons_jsonl"

printf './scripts/swarm_benchmark_responsiveness_scorer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-benchmark-responsiveness-scorer.event.v1" \
    --arg component "swarm_benchmark_responsiveness_scorer" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail}' >>"$events_path"
}

append_reason() {
  local target="$1"
  local code="$2"
  local source_id="$3"
  local detail="$4"
  jq -nc --arg code "$code" --arg source_id "$source_id" --arg detail "$detail" \
    '{code:$code,source_id:$source_id,detail:$detail}' >>"$target"
}

normalize_required_json() {
  local input="$1"
  local output="$2"
  local label="$3"
  if [[ ! -f "$input" ]]; then
    printf 'missing required %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  if ! jq empty "$input" >/dev/null 2>&1; then
    printf 'invalid required %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  jq -cS . "$input" >"$output"
  write_event "input.loaded" "provided" "$label"
}

normalize_optional_json() {
  local input="$1"
  local output="$2"
  local label="$3"
  if [[ -z "$input" ]]; then
    printf '{}\n' >"$output"
    write_event "input.loaded" "missing_optional" "$label"
    printf 'missing'
    return
  fi
  if [[ ! -f "$input" ]]; then
    printf 'missing optional %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  if ! jq empty "$input" >/dev/null 2>&1; then
    printf 'invalid optional %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  jq -cS . "$input" >"$output"
  write_event "input.loaded" "provided" "$label"
  printf 'provided'
}

is_bare_heavy_cargo() {
  local command_text="$1"
  if [[ "$command_text" =~ (^|[[:space:]])cargo[[:space:]]+(check|test|clippy|run|bench) ]] && [[ ! "$command_text" =~ ^rch\ exec\ --\ env\ CARGO_TARGET_DIR= ]]; then
    return 0
  fi
  return 1
}

command_from_catalog() {
  local workload_id="$1"
  local candidate
  candidate="$(jq -r --arg workload_id "$workload_id" '
    .workloads[]
    | select(.workload_id == $workload_id)
    | (.validation_commands[0] // .benchmark_entrypoint // empty)
  ' "$catalog_normalized" | head -n 1)"
  if [[ -z "$candidate" ]]; then
    return 1
  fi
  if [[ "$candidate" == /* || "$candidate" == ./* || "$candidate" == *" "* ]]; then
    printf '%s\n' "$candidate"
  else
    printf './%s\n' "$candidate"
  fi
}

add_command() {
  local command_text="$1"
  jq -nc --arg command "$command_text" '{command:$command}' >>"$advisory_commands_jsonl"
}

add_bottleneck() {
  local bottleneck_class="$1"
  local severity="$2"
  local reason_code="$3"
  local detail="$4"
  jq -nc \
    --arg bottleneck_class "$bottleneck_class" \
    --arg severity "$severity" \
    --arg reason_code "$reason_code" \
    --arg detail "$detail" \
    '{bottleneck_class:$bottleneck_class,severity:$severity,reason_code:$reason_code,detail:$detail}' >>"$bottlenecks_jsonl"
}

normalize_required_json "$normalized_workload_catalog_json" "$catalog_normalized" "normalized workload catalog"
normalize_required_json "$normalized_benchmark_bundle_json" "$bundle_normalized" "normalized benchmark bundle"
resource_status="$(normalize_optional_json "$resource_envelope_json" "$resource_envelope_normalized" "resource envelope")"
topology_status="$(normalize_optional_json "$topology_locality_json" "$topology_locality_normalized" "topology locality")"
proof_cache_status="$(normalize_optional_json "$proof_cache_locality_plan_json" "$proof_cache_plan_normalized" "proof cache locality plan")"

if ! jq -e '(.workloads | type == "array") and (.decision | type == "string")' "$catalog_normalized" >/dev/null 2>&1; then
  append_reason "$fail_closed_reasons_jsonl" "missing_required_benchmark_evidence" "normalized_workload_catalog_json" "catalog JSON lacks workloads array or decision"
fi
if ! jq -e '(.rows | type == "array") and (.decision | type == "string")' "$bundle_normalized" >/dev/null 2>&1; then
  append_reason "$fail_closed_reasons_jsonl" "missing_required_benchmark_evidence" "normalized_benchmark_bundle_json" "bundle JSON lacks rows array or decision"
fi
if jq -e '.workloads | type == "array" and length == 0' "$catalog_normalized" >/dev/null 2>&1; then
  append_reason "$fail_closed_reasons_jsonl" "missing_required_benchmark_evidence" "normalized_workload_catalog_json" "catalog workloads array is empty"
fi
if jq -e '.rows | type == "array" and length == 0' "$bundle_normalized" >/dev/null 2>&1; then
  append_reason "$fail_closed_reasons_jsonl" "missing_required_benchmark_evidence" "normalized_benchmark_bundle_json" "bundle rows array is empty"
fi

catalog_decision="$(jq -r '.decision // "unknown"' "$catalog_normalized")"
bundle_decision="$(jq -r '.decision // "unknown"' "$bundle_normalized")"
if [[ "$catalog_decision" == "fail_closed" ]]; then
  append_reason "$fail_closed_reasons_jsonl" "upstream_catalog_fail_closed" "normalized_workload_catalog_json" "catalog decision is fail_closed"
fi
if [[ "$bundle_decision" == "fail_closed" ]]; then
  append_reason "$fail_closed_reasons_jsonl" "upstream_bundle_fail_closed" "normalized_benchmark_bundle_json" "bundle decision is fail_closed"
fi

if jq -e 'any(.rows[]?; .row_state == "fail_closed")' "$bundle_normalized" >/dev/null; then
  append_reason "$fail_closed_reasons_jsonl" "upstream_bundle_fail_closed" "normalized_benchmark_bundle_json" "bundle rows contain fail_closed evidence"
fi
if jq -e 'any(.findings[]?; .code == "FE-SWARM-BUNDLE-LOCAL-FALLBACK-CONTAMINATION")' "$bundle_normalized" >/dev/null; then
  append_reason "$fail_closed_reasons_jsonl" "local_fallback_contamination" "normalized_benchmark_bundle_json" "benchmark bundle preserves local fallback contamination"
  add_bottleneck "remote_validation_contamination" "fail_closed" "local_fallback_contamination" "remote benchmark proof is contaminated by local fallback"
  add_command "./scripts/e2e/rch_remote_compile_stall_bundle_capture_smoke.sh check"
fi

blocked_measurement=false
if jq -e 'any(.rows[]?; .workload_id == "frankenengine_throughput_baseline_status" and (.row_state == "blocked" or .row_state == "blocked_remote_validation" or .row_state == "recovered_remote_stall"))' "$bundle_normalized" >/dev/null; then
  blocked_measurement=true
  add_bottleneck "blocked_runtime_measurement" "degraded" "blocked_runtime_measurement" "FrankenEngine throughput measurement remains blocked or stall-recovered without an observed runtime baseline"
  append_reason "$degraded_reasons_jsonl" "blocked_runtime_measurement" "normalized_benchmark_bundle_json" "throughput baseline evidence is blocked or remote-stall recovered"
  if command_text="$(command_from_catalog "frankenengine_throughput_baseline_status")"; then
    add_command "$command_text"
  fi
fi

proof_cache_pressure=false
proof_decision="$(jq -r '.decision // "missing"' "$proof_cache_plan_normalized")"
proof_cache_subdecision="$(jq -r '.proof_cache_summary.proof_cache_decision // ""' "$proof_cache_plan_normalized")"
proof_warm_state="$(jq -r '.topology_summary.warm_cache_residency_state // .warm_cache_residency_state // ""' "$proof_cache_plan_normalized")"
if [[ "$proof_cache_status" == "provided" ]] && {
  [[ "$proof_decision" != "pass" ]] ||
  [[ "$proof_cache_subdecision" == "cache_miss" || "$proof_cache_subdecision" == "partial_refresh" || "$proof_cache_subdecision" == "refresh_required" ]] ||
  [[ "$proof_warm_state" == "cold" ]];
}; then
  proof_cache_pressure=true
  add_bottleneck "proof_cache_rebuild_pressure" "degraded" "proof_cache_rebuild_pressure" "proof cache or warm-target evidence indicates cold rebuild pressure"
  append_reason "$degraded_reasons_jsonl" "proof_cache_rebuild_pressure" "proof_cache_locality_plan_json" "proof cache locality plan indicates cache miss, refresh pressure, or cold residency"
  add_command "./scripts/e2e/swarm_proof_cache_locality_optimizer_smoke.sh check"
fi

topology_mismatch=false
topology_decision="$(jq -r '.decision // .truth_state // "missing"' "$topology_locality_normalized")"
topology_class="$(jq -r '.locality_context.recommended_topology_class // .recommended_topology_class // .topology_summary.recommended_topology_class // ""' "$topology_locality_normalized")"
if [[ "$topology_status" == "provided" ]] && {
  [[ "$topology_decision" == "blocked" || "$topology_decision" == "degraded" ]] ||
  [[ "$topology_class" == *contradictory* || "$topology_class" == *mismatch* || "$topology_class" == *drift* ]];
}; then
  topology_mismatch=true
  add_bottleneck "topology_locality_mismatch" "degraded" "topology_locality_mismatch" "topology or locality evidence indicates contradictory or degraded placement guidance"
  append_reason "$degraded_reasons_jsonl" "topology_locality_mismatch" "topology_locality_json" "topology/locality evidence is degraded, blocked, or contradictory"
  add_command "./scripts/e2e/swarm_topology_aware_queue_scorer_smoke.sh check"
fi

resource_saturation=false
resource_decision="$(jq -r '.decision // "missing"' "$resource_envelope_normalized")"
resource_readiness="$(jq -r '.readiness // "unknown"' "$resource_envelope_normalized")"
resource_slots_available="$(jq -r '.rch_slots.available // .rch_slots.available_slots // 0' "$resource_envelope_normalized")"
resource_memory_available="$(jq -r '.memory_pressure.available_bytes // 0' "$resource_envelope_normalized")"
if [[ "$resource_status" == "provided" ]] && {
  [[ "$resource_decision" == "blocked" ]] ||
  [[ "$resource_readiness" == "blocked" || "$resource_readiness" == "saturated" ]] ||
  [[ "$resource_slots_available" -le 0 ]] ||
  { [[ "$resource_memory_available" =~ ^[0-9]+$ ]] && [[ "$resource_memory_available" -gt 0 && "$resource_memory_available" -lt 68719476736 ]]; };
}; then
  resource_saturation=true
  add_bottleneck "resource_saturation" "degraded" "resource_saturation" "resource envelope indicates slot, memory, or readiness saturation"
  append_reason "$degraded_reasons_jsonl" "resource_saturation" "resource_envelope_json" "resource envelope is blocked, saturated, or below safe memory/slot thresholds"
  add_command "./scripts/e2e/swarm_resource_envelope_normalizer_smoke.sh check"
fi

while IFS= read -r command_text; do
  [[ -z "$command_text" ]] && continue
  if is_bare_heavy_cargo "$command_text"; then
    append_reason "$fail_closed_reasons_jsonl" "bare_heavy_cargo_recommendation" "advisory_commands" "generated recommendation requires bare heavy Cargo: ${command_text}"
  fi
done < <(jq -r '.command' "$advisory_commands_jsonl" 2>/dev/null || true)

fail_closed_count="$(jq -s 'length' "$fail_closed_reasons_jsonl")"
if [[ "$fail_closed_count" -gt 0 ]]; then
  decision="fail_closed"
  exit_code=42
elif [[ "$blocked_measurement" == "true" || "$proof_cache_pressure" == "true" || "$topology_mismatch" == "true" || "$resource_saturation" == "true" || "$catalog_decision" == "degraded" || "$bundle_decision" == "degraded" ]]; then
  decision="degraded"
  exit_code=0
else
  decision="pass"
  exit_code=0
fi

if [[ "$fail_closed_count" -gt 0 ]]; then
  truth_state="contaminated"
  throughput_gap_band="contaminated"
  remote_proof_confidence_state="contaminated"
elif [[ "$blocked_measurement" == "true" ]]; then
  truth_state="degraded"
  throughput_gap_band="blocked_measurement"
  remote_proof_confidence_state="degraded"
elif [[ "$proof_cache_pressure" == "true" || "$topology_mismatch" == "true" || "$resource_saturation" == "true" || "$catalog_decision" == "degraded" || "$bundle_decision" == "degraded" ]]; then
  truth_state="degraded"
  throughput_gap_band="moderate"
  remote_proof_confidence_state="degraded"
else
  truth_state="confirmed"
  throughput_gap_band="narrow"
  remote_proof_confidence_state="confirmed"
fi

if [[ "$resource_status" != "provided" ]]; then
  utilization_pressure_band="unknown"
elif [[ "$resource_saturation" == "true" ]]; then
  utilization_pressure_band="saturated"
elif [[ "$resource_memory_available" =~ ^[0-9]+$ ]] && [[ "$resource_memory_available" -gt 0 && "$resource_memory_available" -lt 137438953472 ]]; then
  utilization_pressure_band="elevated"
else
  utilization_pressure_band="relaxed"
fi

if [[ "$proof_cache_pressure" == "true" ]]; then
  cold_warm_cache_recommendation="refresh_cold_target"
elif [[ "$topology_mismatch" == "true" ]]; then
  cold_warm_cache_recommendation="investigate_topology_locality"
elif [[ "$proof_cache_status" == "provided" ]] && [[ "$proof_warm_state" == "hot" || "$proof_warm_state" == "warm" ]]; then
  cold_warm_cache_recommendation="prefer_warm_reuse"
else
  cold_warm_cache_recommendation="insufficient_cache_evidence"
fi

advisory_commands_json="${run_dir}/advisory_commands.json"
bottlenecks_json="${run_dir}/bottlenecks.json"
jq -s 'unique_by(.command)' "$advisory_commands_jsonl" >"$advisory_commands_json"
jq -s 'to_entries | map(.value + {rank:(.key + 1)})' "$bottlenecks_jsonl" >"$bottlenecks_json"

# shellcheck disable=SC2094
jq -n \
  --arg schema_version "franken-engine.swarm-benchmark-responsiveness-advisory.v1" \
  --arg source_revision "$source_revision" \
  --arg catalog_path "$normalized_workload_catalog_json" \
  --arg bundle_path "$normalized_benchmark_bundle_json" \
  --arg resource_path "$resource_envelope_json" \
  --arg topology_path "$topology_locality_json" \
  --arg proof_cache_path "$proof_cache_locality_plan_json" \
  --arg decision "$decision" \
  --arg truth_state "$truth_state" \
  --arg throughput_gap_band "$throughput_gap_band" \
  --arg utilization_pressure_band "$utilization_pressure_band" \
  --arg cold_warm_cache_recommendation "$cold_warm_cache_recommendation" \
  --arg remote_proof_confidence_state "$remote_proof_confidence_state" \
  --arg advisory_json "$advisory_path" \
  --arg events_jsonl "$events_path" \
  --arg commands_txt "$commands_path" \
  --arg report_md "$report_path" \
  --slurpfile catalog "$catalog_normalized" \
  --slurpfile bundle "$bundle_normalized" \
  --slurpfile resource "$resource_envelope_normalized" \
  --slurpfile topology "$topology_locality_normalized" \
  --slurpfile proof "$proof_cache_plan_normalized" \
  --slurpfile bottlenecks "$bottlenecks_json" \
  --slurpfile advisory_commands "$advisory_commands_json" \
  --slurpfile degraded_reasons "$degraded_reasons_jsonl" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    decision: $decision,
    truth_state: $truth_state,
    catalog_decision: ($catalog[0].decision // "unknown"),
    bundle_decision: ($bundle[0].decision // "unknown"),
    throughput_gap_band: $throughput_gap_band,
    utilization_pressure_band: $utilization_pressure_band,
    cold_warm_cache_recommendation: $cold_warm_cache_recommendation,
    remote_proof_confidence_state: $remote_proof_confidence_state,
    bottleneck_classes: $bottlenecks[0],
    advisory_commands: $advisory_commands[0],
    input_status: {
      resource_envelope: (if ($resource_path | length) == 0 then "missing_optional" else "provided" end),
      topology_locality: (if ($topology_path | length) == 0 then "missing_optional" else "provided" end),
      proof_cache_locality_plan: (if ($proof_cache_path | length) == 0 then "missing_optional" else "provided" end)
    },
    degraded_reasons: $degraded_reasons,
    fail_closed_reasons: $fail_closed_reasons,
    artifact_paths: {
      swarm_benchmark_responsiveness_advisory_json: $advisory_json,
      events_jsonl: $events_jsonl,
      commands_txt: $commands_txt,
      report_md: $report_md
    },
    source_artifacts: {
      normalized_workload_catalog_json: $catalog_path,
      normalized_benchmark_bundle_json: $bundle_path,
      resource_envelope_json: (if ($resource_path | length) == 0 then null else $resource_path end),
      topology_locality_json: (if ($topology_path | length) == 0 then null else $topology_path end),
      proof_cache_locality_plan_json: (if ($proof_cache_path | length) == 0 then null else $proof_cache_path end)
    },
    mutation_policy: {
      advisory_only: true,
      proof_only: true,
      fixture_fed_only: true,
      mutates_br: false,
      sends_agent_mail: false,
      runs_cargo: false,
      runs_rch: false,
      changes_live_queue_policy: false
    }
  }' >"$advisory_path"

{
  printf '# Swarm Benchmark Responsiveness Advisory\n\n'
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- truth state: \`%s\`\n" "$truth_state"
  printf -- "- throughput gap band: \`%s\`\n" "$throughput_gap_band"
  printf -- "- utilization pressure band: \`%s\`\n" "$utilization_pressure_band"
  printf -- "- remote proof confidence: \`%s\`\n" "$remote_proof_confidence_state"
  printf -- "- cold/warm recommendation: \`%s\`\n" "$cold_warm_cache_recommendation"
  printf '\n## Bottlenecks\n'
  jq -r '.bottleneck_classes[]? | "- `rank " + (.rank | tostring) + "` `" + .bottleneck_class + "` `" + .reason_code + "`: " + .detail' "$advisory_path"
  printf '\n## Advisory Commands\n'
  jq -r '.advisory_commands[]? | "- `" + .command + "`"' "$advisory_path"
} >"$report_path"

write_event "advisory_emitted" "$decision" "benchmark responsiveness advisory emitted"
exit "$exit_code"
