#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${IDEA_WIZARD_IV_RESOURCE_PROOF_HEATMAP_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-iw4-resource-proof-heatmap}"
run_id="${IDEA_WIZARD_IV_RESOURCE_PROOF_HEATMAP_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${IDEA_WIZARD_IV_RESOURCE_PROOF_HEATMAP_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${IDEA_WIZARD_IV_RESOURCE_PROOF_HEATMAP_SOURCE_REVISION:-}"
generated_at_utc="${IDEA_WIZARD_IV_RESOURCE_PROOF_HEATMAP_GENERATED_AT_UTC:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
bead_id="${IDEA_WIZARD_IV_RESOURCE_PROOF_HEATMAP_BEAD_ID:-bd-my2jw}"
original_args=("$@")

rch_status_json=""
queue_depth_json=""
target_dir_heatmap_json=""
proof_cache_locality_json=""
pressure_metrics_json=""
validation_impact_plan_json=""
archive_pressure_json=""
resource_envelope_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/idea_wizard_iv_resource_proof_heatmap.sh --rch-status-json FILE [OPTIONS]

Emit resource_proof_heatmap.json from preserved resource and proof-cache
evidence. This surface is advisory only and never runs Cargo or RCH.

Required:
  --rch-status-json FILE

Optional:
  --queue-depth-json FILE
  --target-dir-heatmap-json FILE
  --proof-cache-locality-json FILE
  --pressure-metrics-json FILE
  --validation-impact-plan-json FILE
  --archive-pressure-json FILE
  --resource-envelope-json FILE
  --source-revision REV
  --generated-at-utc TIMESTAMP
  --output-dir DIR
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --rch-status-json)
      rch_status_json="${2:-}"
      shift 2
      ;;
    --queue-depth-json)
      queue_depth_json="${2:-}"
      shift 2
      ;;
    --target-dir-heatmap-json)
      target_dir_heatmap_json="${2:-}"
      shift 2
      ;;
    --proof-cache-locality-json)
      proof_cache_locality_json="${2:-}"
      shift 2
      ;;
    --pressure-metrics-json)
      pressure_metrics_json="${2:-}"
      shift 2
      ;;
    --validation-impact-plan-json)
      validation_impact_plan_json="${2:-}"
      shift 2
      ;;
    --archive-pressure-json)
      archive_pressure_json="${2:-}"
      shift 2
      ;;
    --resource-envelope-json)
      resource_envelope_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --generated-at-utc)
      generated_at_utc="${2:-}"
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

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for resource proof heatmap integration\n' >&2
  exit 2
fi
if [[ -z "$rch_status_json" ]]; then
  printf 'resource proof heatmap requires --rch-status-json\n' >&2
  usage
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

validate_json() {
  local path="$1"
  local label="$2"
  if [[ ! -f "$path" ]]; then
    printf '%s JSON not found: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf '%s JSON is malformed: %s\n' "$label" "$path" >&2
    exit 64
  fi
}

validate_json_if_supplied() {
  local path="$1"
  local label="$2"
  if [[ -z "$path" ]]; then
    return 0
  fi
  validate_json "$path" "$label"
}

validate_json "$rch_status_json" "rch-status"
validate_json_if_supplied "$queue_depth_json" "queue-depth"
validate_json_if_supplied "$target_dir_heatmap_json" "target-dir-heatmap"
validate_json_if_supplied "$proof_cache_locality_json" "proof-cache-locality"
validate_json_if_supplied "$pressure_metrics_json" "pressure-metrics"
validate_json_if_supplied "$validation_impact_plan_json" "validation-impact-plan"
validate_json_if_supplied "$archive_pressure_json" "archive-pressure"
validate_json_if_supplied "$resource_envelope_json" "resource-envelope"

mkdir -p "$run_dir"
heatmap_path="${run_dir}/resource_proof_heatmap.json"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
trace_ids_path="${run_dir}/trace_ids.json"

rch_normalized="${run_dir}/rch_status.normalized.json"
queue_normalized="${run_dir}/queue_depth.normalized.json"
target_normalized="${run_dir}/target_dir_heatmap.normalized.json"
cache_normalized="${run_dir}/proof_cache_locality.normalized.json"
pressure_normalized="${run_dir}/pressure_metrics.normalized.json"
validation_normalized="${run_dir}/validation_impact_plan.normalized.json"
archive_normalized="${run_dir}/archive_pressure.normalized.json"
resource_normalized="${run_dir}/resource_envelope.normalized.json"

for artifact_path in \
  "$heatmap_path" \
  "$manifest_path" \
  "$events_path" \
  "$commands_path" \
  "$report_path" \
  "$trace_ids_path" \
  "$rch_normalized" \
  "$queue_normalized" \
  "$target_normalized" \
  "$cache_normalized" \
  "$pressure_normalized" \
  "$validation_normalized" \
  "$archive_normalized" \
  "$resource_normalized"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

normalize_json_or_empty() {
  local input_path="$1"
  local output_path="$2"
  if [[ -n "$input_path" ]]; then
    jq -cS . "$input_path" >"$output_path"
  else
    printf '{}\n' >"$output_path"
  fi
}

normalize_json_or_empty "$rch_status_json" "$rch_normalized"
normalize_json_or_empty "$queue_depth_json" "$queue_normalized"
normalize_json_or_empty "$target_dir_heatmap_json" "$target_normalized"
normalize_json_or_empty "$proof_cache_locality_json" "$cache_normalized"
normalize_json_or_empty "$pressure_metrics_json" "$pressure_normalized"
normalize_json_or_empty "$validation_impact_plan_json" "$validation_normalized"
normalize_json_or_empty "$archive_pressure_json" "$archive_normalized"
normalize_json_or_empty "$resource_envelope_json" "$resource_normalized"

: >"$events_path"
printf './scripts/idea_wizard_iv_resource_proof_heatmap.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n\n# advisory validation commands\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.idea-wizard-iv-resource-proof-heatmap.event.v1" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event:$event,outcome:$outcome,detail:$detail,source_revision:$source_revision}' >>"$events_path"
}

write_event "heatmap_start" "started" "integrating resource and proof-cache evidence"

jq -n \
  --slurpfile rch "$rch_normalized" \
  --slurpfile queue "$queue_normalized" \
  --slurpfile target "$target_normalized" \
  --slurpfile cache "$cache_normalized" \
  --slurpfile pressure "$pressure_normalized" \
  --slurpfile validation "$validation_normalized" \
  --slurpfile archive "$archive_normalized" \
  --slurpfile resource "$resource_normalized" \
  --arg schema_version "franken-engine.idea-wizard-iv-resource-proof-heatmap.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg generated_at_utc "$generated_at_utc" \
  --arg rch_status_json "$rch_status_json" \
  --arg queue_depth_json "$queue_depth_json" \
  --arg target_dir_heatmap_json "$target_dir_heatmap_json" \
  --arg proof_cache_locality_json "$proof_cache_locality_json" \
  --arg pressure_metrics_json "$pressure_metrics_json" \
  --arg validation_impact_plan_json "$validation_impact_plan_json" \
  --arg archive_pressure_json "$archive_pressure_json" \
  --arg resource_envelope_json "$resource_envelope_json" \
  --arg heatmap_path "$heatmap_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg trace_ids_path "$trace_ids_path" '
    def arr($v): if ($v | type) == "array" then $v else [] end;
    def num($v): if ($v | type) == "number" then $v elif ($v | type) == "string" then ($v | tonumber? // 0) else 0 end;
    def low($v): ($v // "" | tostring | ascii_downcase);
    def reason($code; $severity; $detail; $action):
      {code:$code,severity:$severity,detail:$detail,recommended_action:$action};
    ($rch[0] // {}) as $r
    | ($queue[0] // {}) as $q
    | ($target[0] // {}) as $t
    | ($cache[0] // {}) as $c
    | ($pressure[0] // {}) as $p
    | ($validation[0] // {}) as $v
    | ($archive[0] // {}) as $a
    | ($resource[0] // {}) as $e
    | (if ($r.workers | type) == "array" then $r.workers
       elif ($r.rch_snapshot.workers | type) == "array" then $r.rch_snapshot.workers
       elif ($r.result.workers | type) == "array" then $r.result.workers
       else []
       end) as $workers
    | (num($q.queue_depth // $q.queued_jobs // $r.queue_depth // $r.queued_jobs // 0)) as $queue_depth
    | ([$workers[]? | num(.slots_available // .available_slots // .idle_slots // .free_slots // 0)] | add // 0) as $available_slots
    | ([$workers[]? | num(.active_compiles // .active_jobs // .running_jobs // .busy_slots // 0)] | add // 0) as $active_compiles
    | ([$workers[]? | num(.total_slots // .slots_total // .slots // (.slots_available // 0))] | add // 0) as $total_slots
    | (
        (($r.local_fallback_detected // false) == true)
        or ((low($r.decision) | contains("local_fallback")))
        or any($workers[]?; ((.local_fallback_detected // false) == true) or (low(.state // .status) | contains("local")))
        or ((low($t.decision) | contains("fail_closed")) and (low($t | tostring) | contains("local fallback")))
      ) as $local_fallback
    | (low($a.pressure_class // $a.archive_pressure // $a.decision // $a.recommended_action // "")) as $archive_pressure
    | (num($p.memory_available_bytes // $p.mem_available_bytes // $e.memory.available_bytes // 0)) as $memory_available_bytes
    | (low($p.memory_pressure // $p.psi.memory.class // $e.memory_pressure // $e.worker_pressure // "")) as $memory_pressure_label
    | (if $memory_available_bytes >= 137438953472 then "high"
       elif $memory_available_bytes >= 34359738368 then "moderate"
       elif $memory_available_bytes > 0 then "low"
       elif ($memory_pressure_label | IN("low","healthy","idle")) then "high"
       elif ($memory_pressure_label | IN("moderate","medium")) then "moderate"
       elif ($memory_pressure_label | IN("high","critical","saturated")) then "low"
       else "unknown"
       end) as $memory_headroom_class
    | (low($c.cache_heat // $c.summary.cache_heat // $c.decision // $t.cache_heat // $t.summary.cache_heat // "")) as $cache_label
    | (if ($cache_label | IN("warm","hot","reuse","pass","green")) then "warm"
       elif ($cache_label | IN("mixed","degraded","partial")) then "mixed"
       elif ($cache_label | IN("cold","miss","low")) then "cold"
       elif (low($t | tostring) | test("warm_reusable|reuse_warm_target")) then "warm"
       elif (low($t | tostring) | test("cold|fresh_target")) then "cold"
       else "unknown"
       end) as $cache_heat
    | (if $local_fallback then "contaminated"
       elif (($available_slots <= 0 and ($queue_depth > 0 or ($workers | length) > 0)) or $active_compiles >= 32) then "saturated"
       elif ($active_compiles >= 16 or $queue_depth > ($available_slots + 4)) then "high"
       elif ($active_compiles > 0 or $queue_depth > 0) then "moderate"
       else "idle"
       end) as $worker_pressure
    | ([
        if $local_fallback then reason("FE-IW4-LOCAL-FALLBACK-CONTAMINATION"; "blocked"; "RCH or target-dir evidence contains local fallback contamination."; "Discard contaminated evidence and recapture remote-only resource status.") else empty end
      ]) as $fail_closed_reasons
    | ([
        if $target_dir_heatmap_json == "" then reason("missing_target_dir_heatmap"; "degraded"; "target-dir heatmap evidence was not supplied."; "Run or attach the existing swarm_rch_target_dir_heatmap output before green scheduling.") else empty end,
        if $proof_cache_locality_json == "" then reason("missing_proof_cache_locality"; "degraded"; "proof-cache locality plan was not supplied."; "Attach swarm_proof_cache_locality_optimizer output before green cache advice.") else empty end,
        if $pressure_metrics_json == "" then reason("missing_pressure_metrics"; "degraded"; "Linux pressure or memory metrics were not supplied."; "Capture pressure metrics before treating the host as saturated or idle.") else empty end,
        if $validation_impact_plan_json == "" then reason("missing_validation_impact_plan"; "degraded"; "validation-impact plan was not supplied."; "Attach the IW4 validation impact plan before recommending proof windows.") else empty end,
        if $archive_pressure_json == "" then reason("missing_archive_pressure"; "degraded"; "remote proof archive pressure was not supplied."; "Attach remote_proof_archive_pressure_scoreboard output before archive-sensitive scheduling.") else empty end,
        if $resource_envelope_json == "" then reason("missing_resource_envelope"; "degraded"; "resource envelope output was not supplied."; "Attach swarm_resource_envelope_normalizer output before green status.") else empty end,
        if ($worker_pressure | IN("high","saturated")) then reason("worker_pressure_" + $worker_pressure; "degraded"; "RCH worker pressure is " + $worker_pressure + "."; "Defer broad proof or shard work into lower-cost windows.") else empty end,
        if ($cache_heat | IN("cold","unknown")) then reason("cache_heat_" + $cache_heat; "degraded"; "Proof-cache heat is " + $cache_heat + "."; "Prefer warm target reuse only after locality evidence is fresh.") else empty end,
        if ($memory_headroom_class | IN("low","unknown")) then reason("memory_headroom_" + $memory_headroom_class; "degraded"; "Memory headroom is " + $memory_headroom_class + "."; "Defer high-core proof until pressure metrics show adequate memory.") else empty end,
        if ($archive_pressure | test("high|critical|compact|evict|pressure")) then reason("archive_pressure"; "degraded"; "Remote proof archive pressure is elevated."; "Prefer compaction/defer guidance before creating more proof artifacts.") else empty end,
        if (($v.decision // "") == "fail_closed") then reason("validation_impact_fail_closed"; "degraded"; "Validation impact planner failed closed."; "Do not schedule proof until a safe command plan exists.") else empty end
      ]) as $degraded_reasons
    | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
       elif ($degraded_reasons | length) > 0 then "degraded"
       else "green"
       end) as $decision
    | (if $decision == "fail_closed" then "resource_pressure_blocked"
       elif ($worker_pressure | IN("high","saturated")) then "resource_pressure_blocked"
       elif ($cache_heat | IN("cold","unknown")) then "resource_pressure_blocked"
       elif ($memory_headroom_class | IN("low","unknown")) then "resource_pressure_blocked"
       elif ($degraded_reasons | length) > 0 then "resource_pressure_blocked"
       else "true_saturation"
       end) as $classification
    | {
        schema_version:$schema_version,
        bead_id:$bead_id,
        source_revision:$source_revision,
        generated_at_utc:$generated_at_utc,
        decision:$decision,
        classification:$classification,
        worker_pressure:{
          class:$worker_pressure,
          worker_count:($workers | length),
          total_slots:$total_slots,
          available_slots:$available_slots,
          active_compiles:$active_compiles,
          queue_depth:$queue_depth
        },
        cache_heat:{
          class:$cache_heat,
          target_dir_heatmap_present:($target_dir_heatmap_json != ""),
          proof_cache_locality_present:($proof_cache_locality_json != "")
        },
        memory_headroom_class:$memory_headroom_class,
        archive_pressure:{
          class:(if $archive_pressure == "" then "unknown" else $archive_pressure end),
          archive_pressure_present:($archive_pressure_json != "")
        },
        scheduling_advice:(
          if $decision == "fail_closed" then [
            "Do not schedule proof from contaminated local-fallback evidence.",
            "Rollback any queued broad validation based on this packet and recapture remote-only evidence."
          ]
          elif ($worker_pressure | IN("high","saturated")) then [
            "Defer broad Cargo proof until worker pressure drops.",
            "Use validation-impact output to shard into lower-cost RCH windows.",
            "Keep rollback/defer reason attached to the active bead."
          ]
          elif ($archive_pressure | test("high|critical|compact|evict|pressure")) then [
            "Prefer archive compaction or retention guidance before generating more remote proof artifacts.",
            "Schedule only focused validation until archive pressure cools."
          ]
          elif ($cache_heat | IN("cold","unknown")) then [
            "Avoid claiming warm-cache speedup without proof-cache locality evidence.",
            "Prefer fresh target directories or explicit warm-target ROI receipts."
          ]
          elif $memory_headroom_class == "low" then [
            "Defer high-core proof until memory headroom improves.",
            "Run only narrow proof shards with explicit CARGO_TARGET_DIR if necessary."
          ]
          else [
            "Resource evidence is green for focused RCH-wrapped validation.",
            "Preserve target-dir and proof-cache receipts with the validation transcript."
          ]
          end
        ),
        degraded_reasons:$degraded_reasons,
        fail_closed_reasons:$fail_closed_reasons,
        source_surface_refs:[
          {surface_id:"rch_status", path:$rch_status_json, present:true},
          {surface_id:"queue_depth", path:$queue_depth_json, present:($queue_depth_json != "")},
          {surface_id:"swarm_rch_target_dir_heatmap", path:$target_dir_heatmap_json, present:($target_dir_heatmap_json != ""), schema_version:($t.schema_version // null)},
          {surface_id:"swarm_proof_cache_locality_optimizer", path:$proof_cache_locality_json, present:($proof_cache_locality_json != ""), schema_version:($c.schema_version // null)},
          {surface_id:"pressure_metrics", path:$pressure_metrics_json, present:($pressure_metrics_json != "")},
          {surface_id:"idea_wizard_iv_validation_impact_planner", path:$validation_impact_plan_json, present:($validation_impact_plan_json != ""), schema_version:($v.schema_version // null)},
          {surface_id:"remote_proof_archive_pressure_scoreboard", path:$archive_pressure_json, present:($archive_pressure_json != ""), schema_version:($a.schema_version // null)},
          {surface_id:"swarm_resource_envelope_normalizer", path:$resource_envelope_json, present:($resource_envelope_json != ""), schema_version:($e.schema_version // null)}
        ],
        validation_guidance:{
          recommended_commands:($v.recommended_commands // []),
          cost_class:($v.cost_class // "unknown")
        },
        mutation_policy:{
          advisory_only:true,
          proof_only:true,
          mutates_br:false,
          mutates_remote_workers:false,
          deletes_or_overwrites_target_dirs:false,
          changes_queue_policy:false,
          runs_cargo:false,
          runs_rch:false,
          mutates_git:false
        },
        rch_policy:{
          runs_rch:false,
          emits_commands_only:true,
          required_heavy_cargo_prefix:"rch exec -- env CARGO_TARGET_DIR="
        },
        artifact_paths:{
          resource_proof_heatmap_json:$heatmap_path,
          run_manifest_json:$manifest_path,
          events_jsonl:$events_path,
          commands_txt:$commands_path,
          trace_ids_json:$trace_ids_path,
          report_md:$report_path
        }
      }
  ' >"$heatmap_path"

jq -r '.validation_guidance.recommended_commands[]?.display // empty' "$heatmap_path" >>"$commands_path"
if ! grep -Fq 'rch exec -- env CARGO_TARGET_DIR=' "$commands_path"; then
  printf 'rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_iw4_resource_heatmap CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check --all-targets\n' >>"$commands_path"
fi

jq -c '.degraded_reasons[]? | {schema_version:"franken-engine.idea-wizard-iv-resource-proof-heatmap.event.v1",event:"degraded_reason",outcome:.severity,code:.code,detail:.detail}' "$heatmap_path" >>"$events_path"
jq -c '.fail_closed_reasons[]? | {schema_version:"franken-engine.idea-wizard-iv-resource-proof-heatmap.event.v1",event:"fail_closed_reason",outcome:.severity,code:.code,detail:.detail}' "$heatmap_path" >>"$events_path"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-iv-resource-proof-heatmap.run-manifest.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg decision "$(jq -r '.decision' "$heatmap_path")" \
  --arg heatmap_path "$heatmap_path" \
  '{schema_version:$schema_version,bead_id:$bead_id,source_revision:$source_revision,decision:$decision,artifacts:{resource_proof_heatmap_json:$heatmap_path}}' >"$manifest_path"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-iv-resource-proof-heatmap.trace-ids.v1" \
  --arg trace_id "iw4-resource-proof-heatmap-${run_id}" \
  --arg bead_id "$bead_id" \
  '{schema_version:$schema_version,trace_id:$trace_id,bead_id:$bead_id}' >"$trace_ids_path"

{
  printf '# IDEA-WIZARD-IV Resource Proof Heatmap\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$heatmap_path")"
  printf -- "- Classification: \`%s\`\n" "$(jq -r '.classification' "$heatmap_path")"
  printf -- "- Worker pressure: \`%s\`\n" "$(jq -r '.worker_pressure.class' "$heatmap_path")"
  printf -- "- Cache heat: \`%s\`\n" "$(jq -r '.cache_heat.class' "$heatmap_path")"
  printf -- "- Memory headroom: \`%s\`\n\n" "$(jq -r '.memory_headroom_class' "$heatmap_path")"
  printf '## Scheduling Advice\n\n'
  jq -r '.scheduling_advice[]? | "- " + .' "$heatmap_path"
  if [[ "$(jq '.degraded_reasons | length' "$heatmap_path")" -ne 0 ]]; then
    printf '\n## Degraded Reasons\n\n'
    jq -r '.degraded_reasons[] | "- `" + .code + "`: " + .detail' "$heatmap_path"
  fi
  if [[ "$(jq '.fail_closed_reasons | length' "$heatmap_path")" -ne 0 ]]; then
    printf '\n## Fail-Closed Reasons\n\n'
    jq -r '.fail_closed_reasons[] | "- `" + .code + "`: " + .detail' "$heatmap_path"
  fi
} >"$report_path"

write_event "heatmap_complete" "$(jq -r '.decision' "$heatmap_path")" "resource proof heatmap emitted"
printf 'resource_proof_heatmap=%s\n' "$heatmap_path"
if [[ "$(jq -r '.decision' "$heatmap_path")" == "fail_closed" ]]; then
  exit 42
fi
