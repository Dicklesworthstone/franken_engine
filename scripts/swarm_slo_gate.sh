#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_SLO_GATE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-slo-gate}"
run_id="${SWARM_SLO_GATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_SLO_GATE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_SLO_GATE_SOURCE_REVISION:-}"
slo_input_json=""
admission_budget_plan_json=""
rch_rehabilitation_ledger_json=""
proof_cache_locality_plan_json=""
saturation_replay_report_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_slo_gate.sh [OPTIONS]

Evaluates the SWARM-OPS brownout/proof-fanout SLO gate from preserved fixture
artifacts. The gate is advisory-only and fail-closed: it does not execute build
commands, query live services, mutate beads, change workers, or release
reservations.

Required inputs:
  --slo-input-json FILE
  --admission-budget-plan-json FILE
  --rch-rehabilitation-ledger-json FILE
  --proof-cache-locality-plan-json FILE
  --saturation-replay-report-json FILE

Options:
  --source-revision REV
  --output-dir DIR

Artifacts:
  slo_gate_report.json
  run_manifest.json
  events.jsonl
  commands.txt

Exit codes:
  0   SLO gate emitted; overall verdict is pass or warn
  42  fail-closed SLO violation or contaminated upstream evidence
  64  invalid option or malformed input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --slo-input-json)
      slo_input_json="${2:-}"
      shift 2
      ;;
    --admission-budget-plan-json)
      admission_budget_plan_json="${2:-}"
      shift 2
      ;;
    --rch-rehabilitation-ledger-json)
      rch_rehabilitation_ledger_json="${2:-}"
      shift 2
      ;;
    --proof-cache-locality-plan-json)
      proof_cache_locality_plan_json="${2:-}"
      shift 2
      ;;
    --saturation-replay-report-json)
      saturation_replay_report_json="${2:-}"
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

if [[ -z "$slo_input_json" || -z "$admission_budget_plan_json" || -z "$rch_rehabilitation_ledger_json" || -z "$proof_cache_locality_plan_json" || -z "$saturation_replay_report_json" ]]; then
  printf 'swarm SLO gate requires all input JSON files\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm SLO gate\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm SLO gate\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
report_path="${run_dir}/slo_gate_report.json"
report_core_path="${run_dir}/slo_gate_report.core.json"
report_tmp="${report_path}.tmp"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

slo_input_normalized="${run_dir}/slo_input.normalized.json"
admission_normalized="${run_dir}/admission_budget_plan.normalized.json"
rehab_normalized="${run_dir}/rch_rehabilitation_ledger.normalized.json"
locality_normalized="${run_dir}/proof_cache_locality_plan.normalized.json"
saturation_normalized="${run_dir}/saturation_replay_report.normalized.json"
: >"$events_path"

printf './scripts/swarm_slo_gate.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-slo-gate.event.v1" \
    --arg component "swarm_slo_gate" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    --arg evidence_path "$4" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail,evidence_path:$evidence_path}' \
    >>"$events_path"
}

normalize_required_json() {
  local input_path="$1"
  local output_path="$2"
  local label="$3"
  if [[ ! -f "$input_path" ]]; then
    printf 'swarm SLO gate missing %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'swarm SLO gate invalid %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  jq -cS . "$input_path" >"$output_path"
  write_event "input.loaded" "ok" "$label" "$input_path"
}

normalize_required_json "$slo_input_json" "$slo_input_normalized" "SLO input"
normalize_required_json "$admission_budget_plan_json" "$admission_normalized" "admission budget plan"
normalize_required_json "$rch_rehabilitation_ledger_json" "$rehab_normalized" "RCH rehabilitation ledger"
normalize_required_json "$proof_cache_locality_plan_json" "$locality_normalized" "proof-cache locality plan"
normalize_required_json "$saturation_replay_report_json" "$saturation_normalized" "saturation replay report"

jq -n \
  --slurpfile slo "$slo_input_normalized" \
  --slurpfile admission "$admission_normalized" \
  --slurpfile rehab "$rehab_normalized" \
  --slurpfile locality "$locality_normalized" \
  --slurpfile saturation "$saturation_normalized" \
  --arg schema_version "franken-engine.swarm-slo-gate-report.v1" \
  --arg source_revision "$source_revision" \
  --arg slo_input_json "$slo_input_json" \
  --arg admission_budget_plan_json "$admission_budget_plan_json" \
  --arg rch_rehabilitation_ledger_json "$rch_rehabilitation_ledger_json" \
  --arg proof_cache_locality_plan_json "$proof_cache_locality_plan_json" \
  --arg saturation_replay_report_json "$saturation_replay_report_json" \
  --arg report_path "$report_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" '
  def low($value): (($value // "") | tostring | ascii_downcase);
  def arr($value): if ($value | type) == "array" then $value else [] end;
  def rank_pressure($value):
    (low($value)) as $p
    | if $p == "none" or $p == "low" then 1
      elif $p == "moderate" or $p == "medium" then 2
      elif $p == "high" then 3
      elif $p == "critical" then 4
      else 5 end;
  def reason($code; $source; $detail): {code:$code,source_id:$source,detail:$detail};
  def verdict($id; $observed; $threshold; $verdict; $error_code; $remediation; $evidence_path):
    {
      slo_id:$id,
      observed:$observed,
      threshold:$threshold,
      verdict:$verdict,
      error_code:(if $error_code == "" then null else $error_code end),
      remediation_command:$remediation,
      evidence_path:$evidence_path
    };
  def warn_ratio($observed; $limit): ($limit > 0 and $observed >= (($limit * 8) / 10));

  ($slo[0]) as $slo_doc
  | ($admission[0]) as $admission_doc
  | ($rehab[0]) as $rehab_doc
  | ($locality[0]) as $locality_doc
  | ($saturation[0]) as $saturation_doc
  | ($slo_doc.thresholds // {}) as $t
  | (($t.max_admitted_heavy_lanes // 4) | tonumber) as $max_heavy
  | (($t.min_free_rch_slots // 1) | tonumber) as $min_free_slots
  | (($t.max_stale_progress_seconds // 900) | tonumber) as $max_stale_progress
  | (($t.max_stale_tracker_age_seconds // 900) | tonumber) as $max_tracker_age
  | (($t.max_unknown_dirty_files // 0) | tonumber) as $max_unknown_dirty
  | (($t.max_proof_cache_pressure_rank // 3) | tonumber) as $max_pressure_rank
  | (($saturation_doc.summary.heavy_admitted_count // 0) | tonumber) as $heavy_admitted
  | (($saturation_doc.fanout_report.remote_rch_slots // 0) | tonumber) as $remote_slots
  | ([$remote_slots - $heavy_admitted, 0] | max) as $free_slots
  | ((arr($rehab_doc.workers) | map((.latest_progress_age_seconds // 0) | tonumber) | max) // 0) as $max_progress_age
  | (($slo_doc.tracker_age_seconds // 0) | tonumber) as $tracker_age
  | (($slo_doc.unknown_dirty_file_count // 0) | tonumber) as $unknown_dirty
  | ($locality_doc.archive_summary.pressure_level // $slo_doc.proof_cache_pressure_level // "low") as $pressure_level
  | (rank_pressure($pressure_level)) as $pressure_rank
  | (($saturation_doc.contamination_report.local_fallback_observed // false) == true) as $local_fallback
  | ([
      if (($slo_doc.schema_version // "") != "franken-engine.swarm-slo-gate-input.v1") then reason("bad_schema"; "slo_input_json"; "SLO input schema is unexpected") else empty end,
      if (($admission_doc.schema_version // "") != "franken-engine.swarm-admission-budget-plan.v1") then reason("missing_or_bad_upstream_bundle"; "admission_budget_plan_json"; "admission budget bundle is missing or malformed") else empty end,
      if (($rehab_doc.schema_version // "") != "franken-engine.swarm-rch-stall-rehabilitation-ledger.v1") then reason("missing_or_bad_upstream_bundle"; "rch_rehabilitation_ledger_json"; "RCH rehabilitation bundle is missing or malformed") else empty end,
      if (($locality_doc.schema_version // "") != "franken-engine.swarm-proof-cache-locality-plan.v1") then reason("missing_or_bad_upstream_bundle"; "proof_cache_locality_plan_json"; "proof-cache locality bundle is missing or malformed") else empty end,
      if (($saturation_doc.schema_version // "") != "franken-engine.swarm-saturation-replay-report.v1") then reason("missing_or_bad_upstream_bundle"; "saturation_replay_report_json"; "saturation replay bundle is missing or malformed") else empty end,
      if (($rehab_doc.summary.total_workers // null) == null) then reason("incomplete_worker_pressure_telemetry"; "rch_rehabilitation_ledger_json"; "RCH rehab ledger lacks worker pressure summary") else empty end,
      if $local_fallback then reason("local_fallback_contamination"; "saturation_replay_report_json"; "local fallback evidence invalidates brownout SLO gate") else empty end,
      if (($admission_doc.decision // "") == "fail_closed") then reason("upstream_fail_closed"; "admission_budget_plan_json"; "admission planner failed closed") else empty end,
      if (($rehab_doc.decision // "") == "fail_closed") then reason("upstream_fail_closed"; "rch_rehabilitation_ledger_json"; "RCH rehabilitation ledger failed closed") else empty end,
      if (($locality_doc.decision // "") == "fail_closed") then reason("upstream_fail_closed"; "proof_cache_locality_plan_json"; "proof-cache locality plan failed closed") else empty end,
      if (($saturation_doc.decision // "") == "fail_closed") then reason("upstream_fail_closed"; "saturation_replay_report_json"; "saturation replay failed closed") else empty end
    ] | unique_by([.code, .source_id, .detail])) as $fail_closed_reasons
  | ([
      verdict(
        "max_admitted_heavy_lanes";
        $heavy_admitted;
        $max_heavy;
        (if $heavy_admitted > $max_heavy then "fail" elif $heavy_admitted == $max_heavy then "warn" else "pass" end);
        (if $heavy_admitted > $max_heavy then "FE-SWARM-SLO-HEAVY-FANOUT" elif $heavy_admitted == $max_heavy then "FE-SWARM-SLO-HEAVY-FANOUT-WARN" else "" end);
        "# operator: defer_nonurgent_heavy_lanes";
        "saturation_replay_report.json#summary.heavy_admitted_count"
      ),
      verdict(
        "minimum_free_rch_slots";
        $free_slots;
        $min_free_slots;
        (if $free_slots < $min_free_slots then "fail" elif $free_slots == $min_free_slots then "warn" else "pass" end);
        (if $free_slots < $min_free_slots then "FE-SWARM-SLO-RCH-SLOTS" elif $free_slots == $min_free_slots then "FE-SWARM-SLO-RCH-SLOTS-WARN" else "" end);
        "# operator: preserve_urgent_rch_slack";
        "saturation_replay_report.json#fanout_report"
      ),
      verdict(
        "maximum_stale_progress_seconds";
        $max_progress_age;
        $max_stale_progress;
        (if $max_progress_age > $max_stale_progress then "fail" elif warn_ratio($max_progress_age; $max_stale_progress) then "warn" else "pass" end);
        (if $max_progress_age > $max_stale_progress then "FE-SWARM-SLO-STALE-PROGRESS" elif warn_ratio($max_progress_age; $max_stale_progress) then "FE-SWARM-SLO-STALE-PROGRESS-WARN" else "" end);
        "# operator: refresh_rch_rehabilitation_ledger";
        "rch_rehabilitation_ledger.json#workers"
      ),
      verdict(
        "maximum_stale_tracker_age_seconds";
        $tracker_age;
        $max_tracker_age;
        (if $tracker_age > $max_tracker_age then "fail" elif warn_ratio($tracker_age; $max_tracker_age) then "warn" else "pass" end);
        (if $tracker_age > $max_tracker_age then "FE-SWARM-SLO-STALE-TRACKER" elif warn_ratio($tracker_age; $max_tracker_age) then "FE-SWARM-SLO-STALE-TRACKER-WARN" else "" end);
        "# operator: refresh_bead_tracker_snapshot";
        "slo_input.json#tracker_age_seconds"
      ),
      verdict(
        "maximum_unknown_dirty_files";
        $unknown_dirty;
        $max_unknown_dirty;
        (if $unknown_dirty > $max_unknown_dirty then "fail" elif $unknown_dirty == $max_unknown_dirty and $max_unknown_dirty > 0 then "warn" else "pass" end);
        (if $unknown_dirty > $max_unknown_dirty then "FE-SWARM-SLO-UNKNOWN-DIRTY" elif $unknown_dirty == $max_unknown_dirty and $max_unknown_dirty > 0 then "FE-SWARM-SLO-UNKNOWN-DIRTY-WARN" else "" end);
        "# operator: classify_or_reserve_dirty_paths";
        "slo_input.json#unknown_dirty_file_count"
      ),
      verdict(
        "maximum_proof_cache_pressure";
        {level:$pressure_level, rank:$pressure_rank};
        {max_rank:$max_pressure_rank};
        (if $pressure_rank > $max_pressure_rank then "fail" elif $pressure_rank == $max_pressure_rank then "warn" else "pass" end);
        (if $pressure_rank > $max_pressure_rank then "FE-SWARM-SLO-PROOF-CACHE-PRESSURE" elif $pressure_rank == $max_pressure_rank then "FE-SWARM-SLO-PROOF-CACHE-PRESSURE-WARN" else "" end);
        "# operator: refresh_or_cool_proof_cache";
        "proof_cache_locality_plan.json#archive_summary.pressure_level"
      )
    ]) as $slo_verdicts
  | ($slo_verdicts | map(select(.verdict == "fail"))) as $fail_verdicts
  | ($slo_verdicts | map(select(.verdict == "warn"))) as $warn_verdicts
  | (if ($fail_closed_reasons | length) > 0 or ($fail_verdicts | length) > 0 then "fail_closed"
     elif ($warn_verdicts | length) > 0 then "warn"
     else "pass" end) as $decision
  | {
      schema_version:$schema_version,
      bead_id:"bd-u0mau",
      source_revision:$source_revision,
      decision:$decision,
      overall_verdict:(if $decision == "fail_closed" then "fail" else $decision end),
      thresholds:$t,
      observed:{
        admitted_heavy_lanes:$heavy_admitted,
        free_rch_slots:$free_slots,
        max_stale_progress_seconds:$max_progress_age,
        tracker_age_seconds:$tracker_age,
        unknown_dirty_file_count:$unknown_dirty,
        proof_cache_pressure_level:$pressure_level,
        proof_cache_pressure_rank:$pressure_rank,
        local_fallback_observed:$local_fallback
      },
      slo_verdicts:$slo_verdicts,
      fail_closed_reasons:$fail_closed_reasons,
      summary:{
        pass_count:($slo_verdicts | map(select(.verdict == "pass")) | length),
        warn_count:($warn_verdicts | length),
        fail_count:($fail_verdicts | length),
        fail_closed_reason_count:($fail_closed_reasons | length),
        every_fail_has_error_code_and_remediation:(all($fail_verdicts[]?; ((.error_code // "") | length) > 0 and ((.remediation_command // "") | length) > 0 and ((.evidence_path // "") | length) > 0))
      },
      mutation_policy:{
        fixture_fed_only:true,
        gate_only:true,
        advisory_only:true,
        mutates_br:false,
        releases_reservations:false,
        sends_agent_mail:false,
        queries_live_agent_mail:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false,
        writes_outside_output_dir:false
      },
      source_artifacts:{
        slo_input_json:$slo_input_json,
        admission_budget_plan_json:$admission_budget_plan_json,
        rch_rehabilitation_ledger_json:$rch_rehabilitation_ledger_json,
        proof_cache_locality_plan_json:$proof_cache_locality_plan_json,
        saturation_replay_report_json:$saturation_replay_report_json
      },
      artifact_paths:{
        slo_gate_report_json:$report_path,
        run_manifest_json:$manifest_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path
      }
    }' >"$report_core_path"

report_hash="$(jq -cS 'del(.artifact_paths, .source_artifacts)' "$report_core_path" | sha256sum | awk '{print $1}')"
gate_id="swarm-slo-gate-${report_hash:0:16}"
jq --arg gate_id "$gate_id" --arg report_hash "$report_hash" \
  '. + {gate_id:$gate_id, hash_basis:{report_hash:$report_hash}}' \
  "$report_core_path" >"$report_tmp"
mv "$report_tmp" "$report_path"

decision="$(jq -r '.decision' "$report_path")"
write_event "slo_gate.emitted" "$decision" "emitted SLO gate report" "$report_path"

jq -n \
  --arg schema_version "franken-engine.swarm-slo-gate-run-manifest.v1" \
  --arg gate_id "$gate_id" \
  --arg source_revision "$source_revision" \
  --arg report_path "$report_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  '{
    schema_version:$schema_version,
    gate_id:$gate_id,
    source_revision:$source_revision,
    artifact_paths:{
      slo_gate_report_json:$report_path,
      events_jsonl:$events_path,
      commands_txt:$commands_path
    },
    mutation_policy:{
      fixture_fed_only:true,
      gate_only:true,
      runs_cargo:false,
      runs_rch:false,
      mutates_remote_workers:false,
      mutates_br:false
    }
  }' >"$manifest_path"

printf 'slo_gate_report_json=%s\n' "$report_path"
printf 'run_manifest_json=%s\n' "$manifest_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
