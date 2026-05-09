#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_RCH_TARGET_DIR_HEATMAP_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-rch-target-dir-heatmap}"
run_id="${SWARM_RCH_TARGET_DIR_HEATMAP_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_RCH_TARGET_DIR_HEATMAP_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${SWARM_RCH_TARGET_DIR_HEATMAP_SOURCE_REVISION:-unknown}"
input_json=""
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_rch_target_dir_heatmap.sh --input-json FILE [OPTIONS]

Builds a read-only target-dir heat map from saved rch/resource/proof-cache
snapshots. The command is advisory-only and never probes workers, deletes
caches, runs Cargo/rch, mutates rch config, or schedules work.

Required:
  --input-json FILE

Options:
  --source-revision REV
  --output-dir DIR

Artifacts:
  target_dir_heatmap.json
  target_dir_advice.md
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   heat map emitted with pass or degraded decision
  42  local fallback or unsafe evidence forced fail_closed
  64  invalid input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --input-json)
      input_json="${2:-}"
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

if [[ -z "$input_json" ]]; then
  printf 'missing required --input-json\n' >&2
  usage
  exit 64
fi
if [[ ! -f "$input_json" ]]; then
  printf 'input JSON not found: %s\n' "$input_json" >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm rch target-dir heatmap\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm rch target-dir heatmap\n' >&2
  exit 2
fi
if ! jq empty "$input_json" >/dev/null 2>&1; then
  printf 'invalid input JSON: %s\n' "$input_json" >&2
  exit 64
fi
if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(git rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
heatmap_path="${run_dir}/target_dir_heatmap.json"
advice_path="${run_dir}/target_dir_advice.md"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
normalized_input="${run_dir}/input.normalized.json"
heatmap_tmp="${heatmap_path}.tmp"

for artifact_path in \
  "$heatmap_path" \
  "$advice_path" \
  "$events_path" \
  "$commands_path" \
  "$report_path" \
  "$normalized_input" \
  "$heatmap_tmp"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

jq -cS . "$input_json" >"$normalized_input"
input_hash="$(sha256sum "$normalized_input" | awk '{print $1}')"

printf './scripts/swarm_rch_target_dir_heatmap.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -n \
  --slurpfile input "$normalized_input" \
  --arg source_revision "$source_revision" \
  --arg input_json "$input_json" \
  --arg normalized_input "$normalized_input" \
  --arg input_hash "$input_hash" \
  --arg heatmap_path "$heatmap_path" \
  --arg advice_path "$advice_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def src: $input[0];
  def pressure_rank($value):
    if $value == "critical" then 4
    elif $value == "high" then 3
    elif $value == "medium" then 2
    else 1 end;
  def max_pressure($items):
    reduce $items[] as $item ("low"; if pressure_rank($item) > pressure_rank(.) then $item else . end);
  def reason($code; $source_id; $detail; $remediation):
    {code:$code, source_id:$source_id, detail:$detail, remediation:$remediation};
  def workers: (src.rch_snapshot.workers // []);
  def snapshot_present: ((src.rch_snapshot.present // false) == true);
  def snapshot_fresh: ((src.rch_snapshot.freshness // "fresh") == "fresh");
  def target_rows:
    [workers[] as $worker
      | ($worker.target_dirs // [])[]?
      | {
          worker_id: ($worker.worker_id // "unknown_worker"),
          daemon_status: ($worker.daemon_status // "unknown"),
          slots_available: (($worker.slots_available // 0) | tonumber),
          target_dir: (.target_dir // ""),
          target_dir_class: (.target_dir_class // "unknown"),
          pressure_level: max_pressure([
            ($worker.disk_pressure // "low"),
            (src.resource_pressure.disk_pressure // "low"),
            (src.resource_pressure.memory_pressure // "low")
          ]),
          cache_reuse_score: ((.cache_reuse_score // 0) | tonumber),
          evidence_freshness: (.evidence_freshness // src.rch_snapshot.freshness // "unknown"),
          safe_alternative: (.safe_alternative // "defer proof and refresh worker evidence")
        }];

  ([]
    + (if ((src.contract_profile.decision // "") == "pass") then [] else [
        reason("missing_contract_profile"; "bd-gvhsx.6";
          "target-dir heat map lacks passing shared contract/profile evidence";
          "Run bd-gvhsx.6 and provide a passing profile artifact.")
      ] end)
    + (if ((src.rch_snapshot.local_fallback_detected // false) == true) then [
        reason("local_rch_fallback_contamination"; "rch_snapshot";
          "rch snapshot contains local fallback contamination";
          "Discard the contaminated snapshot and capture remote-only rch evidence.")
      ] else [] end)
  ) as $fail_closed_reasons
  | (target_rows) as $rows
  | ([]
    + (if snapshot_present then [] else [
        reason("missing_rch_snapshot"; "rch_snapshot";
          "required rch worker snapshot is missing";
          "Provide a saved rch status or queue snapshot before acting.")
      ] end)
    + (if snapshot_present and (snapshot_fresh | not) then [
        reason("stale_worker_evidence"; "rch_snapshot";
          "worker evidence is stale";
          "Refresh the saved rch snapshot before trusting cache heat.")
      ] else [] end)
    + (if any($rows[]?; (.evidence_freshness // "") != "fresh") then [
        reason("stale_target_evidence"; "target_dirs";
          "one or more target-dir rows use stale evidence";
          "Refresh target-dir evidence or downgrade the recommendation.")
      ] else [] end)
    + (if any($rows[]?; (.pressure_level | IN("high", "critical"))) then [
        reason("disk_or_memory_pressure"; "resource_pressure";
          "disk or memory pressure requires conservative target-dir advice";
          "Prefer deferral or a fresh target until pressure drops.")
      ] else [] end)
    + (if snapshot_present and (($rows | map(.slots_available) | max // 0) <= 0) then [
        reason("worker_saturated"; "rch_snapshot";
          "all observed workers have zero available proof slots";
          "Defer proof scheduling or wait for an operator-selected slot.")
      ] else [] end)
    + (if snapshot_present and (($rows | length) == 0) then [
        reason("missing_target_dir_rows"; "rch_snapshot";
          "rch snapshot has no target-dir rows";
          "Provide target-dir class and cache reuse evidence.")
      ] else [] end)
  ) as $degraded_reasons
  | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
     elif ($degraded_reasons | length) > 0 then "degraded"
     else "pass" end) as $decision
  | ([$rows[]
      | . + {
          recommendation: (
            if $decision == "fail_closed" then "manual_review"
            elif (.pressure_level | IN("high", "critical")) then "defer_due_to_pressure"
            elif .slots_available <= 0 then "defer_no_slot"
            elif .target_dir_class == "warm_reusable" and .cache_reuse_score >= 70 then "reuse_warm_target"
            elif .target_dir_class == "cold" then "allocate_fresh_target"
            else "manual_review" end
          ),
          confidence: (
            if $decision == "fail_closed" then "none"
            elif (.pressure_level | IN("high", "critical")) or .slots_available <= 0 then "bounded"
            elif .target_dir_class == "warm_reusable" and .cache_reuse_score >= 70 then "high"
            elif .target_dir_class == "cold" then "bounded"
            else "partial" end
          )
        }]
    | sort_by(.worker_id, .target_dir)) as $recommendations
  | {
      schema_version: "franken-engine.swarm-rch-target-dir-heatmap.v1",
      component: "swarm_rch_target_dir_heatmap",
      source_revision: $source_revision,
      input: {
        path: $input_json,
        normalized_path: $normalized_input,
        sha256: $input_hash,
        schema_version: (src.schema_version // null),
        case_id: (src.case_id // null)
      },
      decision: $decision,
      fail_closed_reasons: $fail_closed_reasons,
      degraded_reasons: $degraded_reasons,
      evidence_freshness: (src.rch_snapshot.freshness // "missing"),
      resource_pressure: (src.resource_pressure // {}),
      target_dir_rows: $recommendations,
      summary: {
        worker_count: (workers | length),
        target_dir_count: ($recommendations | length),
        warm_reusable_count: ($recommendations | map(select(.target_dir_class == "warm_reusable")) | length),
        cold_target_count: ($recommendations | map(select(.target_dir_class == "cold")) | length),
        saturated_worker_count: ([workers[]? | select(((.slots_available // 0) | tonumber) <= 0)] | length),
        highest_pressure: (if ($recommendations | length) == 0 then "unknown" else max_pressure($recommendations | map(.pressure_level)) end)
      },
      artifact_paths: {
        target_dir_heatmap_json: $heatmap_path,
        target_dir_advice_md: $advice_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      },
      non_mutation_attestation: {
        reads_saved_files_only: true,
        probes_live_workers: false,
        deletes_caches: false,
        mutates_rch_config: false,
        runs_cargo: false,
        runs_rch: false,
        schedules_work: false
      }
    }
' >"$heatmap_tmp"
mv "$heatmap_tmp" "$heatmap_path"

jq -c '
  if (.decision == "fail_closed") then
    [.fail_closed_reasons[]
      | {
          schema_version: "franken-engine.swarm-rch-target-dir-heatmap.event.v1",
          component: "swarm_rch_target_dir_heatmap",
          event: "fail_closed_reason",
          outcome: "fail_closed",
          error_code: .code,
          source_id: .source_id,
          detail: .detail
        }]
  elif (.decision == "degraded") then
    [.degraded_reasons[]
      | {
          schema_version: "franken-engine.swarm-rch-target-dir-heatmap.event.v1",
          component: "swarm_rch_target_dir_heatmap",
          event: "degraded_reason",
          outcome: "degraded",
          error_code: .code,
          source_id: .source_id,
          detail: .detail
        }]
  else
    [{
      schema_version: "franken-engine.swarm-rch-target-dir-heatmap.event.v1",
      component: "swarm_rch_target_dir_heatmap",
      event: "heatmap_passed",
      outcome: "pass",
      error_code: null,
      source_id: null,
      detail: "target-dir heat map passed"
    }]
  end
  | .[]
' "$heatmap_path" >"$events_path"

jq -r '
  "# Target-Dir Heat Map Advice",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Evidence freshness: `" + .evidence_freshness + "`"),
  ("- Highest pressure: `" + .summary.highest_pressure + "`"),
  "",
  "## Recommendations",
  "",
  (if (.target_dir_rows | length) == 0 then
    "none"
  else
    (.target_dir_rows[]
      | "- `" + .worker_id + "` `" + .target_dir + "` class `" + .target_dir_class + "` pressure `" + .pressure_level + "` cache `" + (.cache_reuse_score | tostring) + "` -> `" + .recommendation + "`; safe alternative: " + .safe_alternative)
  end)
' "$heatmap_path" >"$advice_path"

jq -r '
  "# Swarm RCH Target-Dir Heat Map",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Workers: `" + (.summary.worker_count | tostring) + "`"),
  ("- Target dirs: `" + (.summary.target_dir_count | tostring) + "`"),
  ("- Warm reusable: `" + (.summary.warm_reusable_count | tostring) + "`"),
  ("- Cold: `" + (.summary.cold_target_count | tostring) + "`"),
  "",
  "## Fail-Closed Reasons",
  "",
  (if (.fail_closed_reasons | length) == 0 then "none" else (.fail_closed_reasons[] | "- `" + .code + "` `" + .source_id + "`: " + .detail) end),
  "",
  "## Degraded Reasons",
  "",
  (if (.degraded_reasons | length) == 0 then "none" else (.degraded_reasons[] | "- `" + .code + "` `" + .source_id + "`: " + .detail) end)
' "$heatmap_path" >"$report_path"

printf 'target_dir_heatmap=%s\n' "$heatmap_path"
printf 'target_dir_advice=%s\n' "$advice_path"

if jq -e '.decision == "fail_closed"' "$heatmap_path" >/dev/null; then
  exit 42
fi
exit 0
