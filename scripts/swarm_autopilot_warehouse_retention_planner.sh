#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_AUTOPILOT_WAREHOUSE_RETENTION_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-autopilot-warehouse-retention}"
run_id="${SWARM_AUTOPILOT_WAREHOUSE_RETENTION_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AUTOPILOT_WAREHOUSE_RETENTION_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_AUTOPILOT_WAREHOUSE_RETENTION_SOURCE_REVISION:-unknown}"
evidence_warehouse_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_autopilot_warehouse_retention_planner.sh [OPTIONS]

Build a proof-only retention compaction plan and storage budget ledger from the
autopilot evidence warehouse. This script never deletes evidence, mutates the
warehouse, mutates beads, releases reservations, sends Agent Mail, runs Cargo,
runs RCH, or changes live queue policy.

Required inputs:
  --evidence-warehouse-json FILE

Optional inputs:
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_autopilot_warehouse_retention_plan.json
  swarm_autopilot_storage_budget_ledger.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  plan is replayable; decision may be pass or degraded
  42 malformed or untrusted warehouse evidence prevented truthful planning
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --evidence-warehouse-json)
      evidence_warehouse_json="${2:-}"
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

if [[ -z "$evidence_warehouse_json" ]]; then
  printf 'evidence warehouse JSON is required\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the warehouse retention planner\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/swarm_autopilot_warehouse_retention_plan.json"
plan_tmp="${plan_path}.tmp"
ledger_path="${run_dir}/swarm_autopilot_storage_budget_ledger.json"
ledger_tmp="${ledger_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
warehouse_normalized="${run_dir}/evidence_warehouse.normalized.json"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

printf './scripts/swarm_autopilot_warehouse_retention_planner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$fail_closed_reasons_jsonl"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-warehouse-retention.event.v1" \
    --arg trace_id "trace-swarm-autopilot-warehouse-retention-${run_id}" \
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
  jq -nc \
    --arg code "$1" \
    --arg source_id "$2" \
    --arg detail "$3" \
    --arg remediation_command "$4" \
    '{
      code:$code,
      source_id:$source_id,
      detail:$detail,
      remediation_command:$remediation_command
    }' >>"$fail_closed_reasons_jsonl"
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

check_shape() {
  local path="$1"
  local expr="$2"
  local source_id="$3"
  local detail="$4"
  if ! jq -e "$expr" "$path" >/dev/null 2>&1; then
    append_failure "FE-SWARM-AUTOPILOT-WAREHOUSE-MISSING-INPUT" "$source_id" "$detail" \
      "Refresh the warehouse with scripts/swarm_autopilot_evidence_warehouse.sh before planning retention."
  fi
}

normalize_required_json "$evidence_warehouse_json" "$warehouse_normalized" "evidence_warehouse"

check_shape "$warehouse_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-evidence-warehouse.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.artifact_rows // null) | type == "array")
  and ((.artifact_rows | length) > 0)
  and ((.retention_classes // null) | type == "object")
  and (((.hash_basis.warehouse_hash // "") | type) == "string")
  and ((.hash_basis.warehouse_hash // "") | length == 64)
  and .mutation_policy.advisory_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "evidence_warehouse_json" "warehouse snapshot lacks required schema, artifact rows, or safety markers"

required_rows=(run_manifest_json trace_ids_json queue_locality_json truth_gate_report_json)
for source_id in "${required_rows[@]}"; do
  if ! jq -e --arg source_id "$source_id" '.artifact_rows | any(.source_id == $source_id)' "$warehouse_normalized" >/dev/null; then
    append_failure "FE-SWARM-AUTOPILOT-WAREHOUSE-MISSING-ARTIFACT-ROW" "$source_id" \
      "required warehouse row ${source_id} is missing" \
      "Regenerate the warehouse bundle and ensure ${source_id} is preserved in artifact_rows."
  fi
done

if ! jq -e '
  .artifact_rows
  | all(.[]; .retention_class == "short_lived_raw_capture"
      or .retention_class == "long_lived_replay_evidence"
      or .retention_class == "audit_log"
      or .retention_class == "policy_snapshot")
' "$warehouse_normalized" >/dev/null 2>&1; then
  append_failure "FE-SWARM-AUTOPILOT-WAREHOUSE-UNKNOWN-RETENTION-CLASS" "artifact_rows" \
    "artifact_rows contains an unsupported retention_class" \
    "Normalize warehouse rows to one of short_lived_raw_capture, long_lived_replay_evidence, audit_log, or policy_snapshot."
fi

if ! jq -e '
  (.retention_classes | keys_unsorted | sort)
  == ["audit_log","long_lived_replay_evidence","policy_snapshot","short_lived_raw_capture"]
' "$warehouse_normalized" >/dev/null 2>&1; then
  append_failure "FE-SWARM-AUTOPILOT-WAREHOUSE-UNKNOWN-RETENTION-CLASS" "retention_classes" \
    "warehouse retention_classes map does not match the recognized contract" \
    "Refresh the warehouse contract and keep only the recognized retention class keys."
fi

if jq -e '.decision == "fail_closed"' "$warehouse_normalized" >/dev/null; then
  if jq -e '[.fail_closed_reasons[]?.code?] | any(test("STALE"; "i"))' "$warehouse_normalized" >/dev/null; then
    append_failure "FE-SWARM-AUTOPILOT-WAREHOUSE-STALE" "evidence_warehouse_json" \
      "warehouse is already marked fail_closed due to stale evidence" \
      "Refresh the warehouse from current SWARM-OPS and queue-locality artifacts before planning retention."
  fi
  if jq -e '[.fail_closed_reasons[]?.code?, .fail_closed_reasons[]?.detail?] | map(tostring) | any(test("local_fallback|contaminated"; "i"))' "$warehouse_normalized" >/dev/null; then
    append_failure "FE-SWARM-AUTOPILOT-WAREHOUSE-CONTAMINATED" "evidence_warehouse_json" \
      "warehouse is contaminated by local fallback evidence" \
      "Discard contaminated warehouse captures and regenerate from remote-only evidence."
  fi
  if ! jq -e '[.fail_closed_reasons[]?.code?] | any(test("STALE|LOCAL-FALLBACK|CONTAMINATED"; "i"))' "$warehouse_normalized" >/dev/null; then
    append_failure "FE-SWARM-AUTOPILOT-WAREHOUSE-MISSING-INPUT" "evidence_warehouse_json" \
      "warehouse is fail_closed for an unsupported reason" \
      "Review the upstream warehouse fail_closed reasons before planning retention."
  fi
fi

decision="pass"
storage_pressure_state="normal"
exit_code=0
normal_max=150000
elevated_max=250000

total_estimated_bytes="$(
  jq -r '
    def default_estimate($class):
      if $class == "short_lived_raw_capture" then 16000
      elif $class == "long_lived_replay_evidence" then 32000
      elif $class == "audit_log" then 8000
      elif $class == "policy_snapshot" then 6000
      else 0
      end;
    [.artifact_rows[] | (.estimated_bytes // default_estimate(.retention_class))] | add // 0
  ' "$warehouse_normalized"
)"

if [[ -s "$fail_closed_reasons_jsonl" ]]; then
  decision="fail_closed"
  exit_code=42
else
  if (( total_estimated_bytes > elevated_max )); then
    decision="degraded"
    storage_pressure_state="critical"
  elif (( total_estimated_bytes > normal_max )); then
    decision="degraded"
    storage_pressure_state="elevated"
  fi
fi

if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(jq -r '.source_revision // .run_identity.source_revision // "unknown"' "$warehouse_normalized")"
fi

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-warehouse-retention-plan.v1" \
  --arg bead_id "bd-gra1z.2" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg storage_pressure_state "$storage_pressure_state" \
  --arg evidence_warehouse_json "$evidence_warehouse_json" \
  --arg plan_path "$plan_path" \
  --arg ledger_path "$ledger_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --slurpfile warehouse "$warehouse_normalized" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" '
  def default_estimate($class):
    if $class == "short_lived_raw_capture" then 16000
    elif $class == "long_lived_replay_evidence" then 32000
    elif $class == "audit_log" then 8000
    elif $class == "policy_snapshot" then 6000
    else 0
    end;
  def replay_preserve:
    (.replay_preserve // false)
    or (.retention_class == "long_lived_replay_evidence" and ((.decision // "pass") != "pass" or (.freshness // "fresh") != "fresh"));
  def compaction_action($pressure):
    if replay_preserve then "preserve_replay_exempt"
    elif .retention_class == "short_lived_raw_capture" then "compact_to_summary"
    elif .retention_class == "audit_log" and $pressure != "normal" then "archive_log_excerpt"
    elif .retention_class == "policy_snapshot" and $pressure == "critical" then "archive_snapshot"
    elif .retention_class == "long_lived_replay_evidence" and $pressure == "critical" then "retain_replay_only"
    else "retain"
    end;
  ($warehouse[0]) as $warehouse_doc
  | ($warehouse_doc.artifact_rows | map(. + {
      estimated_bytes:(.estimated_bytes // default_estimate(.retention_class)),
      replay_preserve: replay_preserve,
      compaction_action: compaction_action($storage_pressure_state)
    })) as $rows
  | {
      schema_version:$schema_version,
      bead_id:$bead_id,
      plan_id:("retention-plan-" + ($warehouse_doc.hash_basis.warehouse_hash[0:12])),
      source_revision:$source_revision,
      warehouse_hash:$warehouse_doc.hash_basis.warehouse_hash,
      decision:$decision,
      storage_pressure_state:$storage_pressure_state,
      total_estimated_bytes:($rows | map(.estimated_bytes) | add // 0),
      retention_window_policy:{
        short_lived_raw_capture_days:7,
        long_lived_replay_evidence_days:120,
        audit_log_days:30,
        policy_snapshot_days:45
      },
      replay_preserve_sources:($rows | map(select(.replay_preserve == true) | .source_id) | unique | sort),
      compaction_candidates:($rows | map(select(.compaction_action != "retain" and .compaction_action != "preserve_replay_exempt") | {
        source_id,
        retention_class,
        estimated_bytes,
        freshness,
        decision,
        action:.compaction_action,
        reason_code:(if .retention_class == "short_lived_raw_capture" then "compact_short_lived_raw_capture"
          elif .retention_class == "audit_log" then "archive_audit_log_pressure"
          elif .retention_class == "policy_snapshot" then "archive_policy_snapshot_pressure"
          else "retain_replay_only_pressure"
          end)
      })),
      fail_closed_reasons:($fail_closed_reasons | unique_by([.code, .source_id, .detail])),
      remediation_commands:(
        if $decision == "fail_closed" then
          ($fail_closed_reasons | map(.remediation_command) | unique)
        elif $storage_pressure_state == "critical" then
          ["Review compaction candidates and archive short-lived raw captures or audit logs before the next warehouse refresh."]
        elif $storage_pressure_state == "elevated" then
          ["Review compaction candidates and schedule a bounded archive window before storage pressure becomes critical."]
        else
          ["Retention is within budget; preserve replay-exempt evidence and monitor future warehouse growth."]
        end
      ),
      artifact_paths:{
        retention_plan_json:$plan_path,
        storage_budget_ledger_json:$ledger_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_path,
        evidence_warehouse_json:$evidence_warehouse_json
      },
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        fixture_fed_only:true,
        mutates_br:false,
        reassigns_beads:false,
        releases_reservations:false,
        sends_agent_mail:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false
      }
    }' >"$plan_tmp"
mv "$plan_tmp" "$plan_path"

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-storage-budget-ledger.v1" \
  --arg bead_id "bd-gra1z.2" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg storage_pressure_state "$storage_pressure_state" \
  --arg evidence_warehouse_json "$evidence_warehouse_json" \
  --arg plan_path "$plan_path" \
  --arg ledger_path "$ledger_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --slurpfile warehouse "$warehouse_normalized" '
  def default_estimate($class):
    if $class == "short_lived_raw_capture" then 16000
    elif $class == "long_lived_replay_evidence" then 32000
    elif $class == "audit_log" then 8000
    elif $class == "policy_snapshot" then 6000
    else 0
    end;
  def replay_preserve:
    (.replay_preserve // false)
    or (.retention_class == "long_lived_replay_evidence" and ((.decision // "pass") != "pass" or (.freshness // "fresh") != "fresh"));
  def compaction_action($pressure):
    if replay_preserve then "preserve_replay_exempt"
    elif .retention_class == "short_lived_raw_capture" then "compact_to_summary"
    elif .retention_class == "audit_log" and $pressure != "normal" then "archive_log_excerpt"
    elif .retention_class == "policy_snapshot" and $pressure == "critical" then "archive_snapshot"
    elif .retention_class == "long_lived_replay_evidence" and $pressure == "critical" then "retain_replay_only"
    else "retain"
    end;
  ($warehouse[0]) as $warehouse_doc
  | ($warehouse_doc.artifact_rows | map(. + {
      estimated_bytes:(.estimated_bytes // default_estimate(.retention_class)),
      replay_preserve: replay_preserve,
      compaction_action: compaction_action($storage_pressure_state)
    })) as $rows
  | {
      schema_version:$schema_version,
      bead_id:$bead_id,
      source_revision:$source_revision,
      warehouse_hash:$warehouse_doc.hash_basis.warehouse_hash,
      decision:$decision,
      storage_pressure_state:$storage_pressure_state,
      summary:{
        artifact_row_count:($rows | length),
        total_estimated_bytes:($rows | map(.estimated_bytes) | add // 0),
        replay_preserve_count:($rows | map(select(.replay_preserve == true)) | length),
        compaction_candidate_count:($rows | map(select(.compaction_action != "retain" and .compaction_action != "preserve_replay_exempt")) | length)
      },
      class_totals:($rows
        | group_by(.retention_class)
        | map({
            retention_class:.[0].retention_class,
            source_count:length,
            total_estimated_bytes:(map(.estimated_bytes) | add // 0)
          })
        | sort_by(.retention_class)),
      action_totals:($rows
        | group_by(.compaction_action)
        | map({
            action:.[0].compaction_action,
            source_count:length,
            total_estimated_bytes:(map(.estimated_bytes) | add // 0)
          })
        | sort_by(.action)),
      replay_preserve_sources:($rows | map(select(.replay_preserve == true) | .source_id) | unique | sort),
      artifact_paths:{
        storage_budget_ledger_json:$ledger_path,
        retention_plan_json:$plan_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_path,
        evidence_warehouse_json:$evidence_warehouse_json
      }
    }' >"$ledger_tmp"
mv "$ledger_tmp" "$ledger_path"

{
  printf '# SWARM_AUTOPILOT_WAREHOUSE_RETENTION_PLANNER\n\n'
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- storage_pressure_state: \`%s\`\n" "$storage_pressure_state"
  printf -- "- total_estimated_bytes: \`%s\`\n" "$total_estimated_bytes"
  printf -- "- warehouse_hash: \`%s\`\n" "$(jq -r '.warehouse_hash' "$plan_path")"
  printf '\n## Replay Preserve Sources\n'
  jq -r '.replay_preserve_sources[]? | "- `\(. )`"' "$plan_path"
  printf '\n## Compaction Candidates\n'
  jq -r '.compaction_candidates[]? | "- `\(.source_id)` -> `\(.action)` (\(.estimated_bytes) bytes)"' "$plan_path"
  if jq -e '.fail_closed_reasons | length > 0' "$plan_path" >/dev/null; then
    printf '\n## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `\(.code)` from `\(.source_id)`: \(.detail)"' "$plan_path"
  fi
  printf '\n## Remediation Commands\n'
  jq -r '.remediation_commands[] | "- \(. )"' "$plan_path"
} >"$report_path"

write_event "warehouse_retention_planner" "retention_plan_emitted" "$decision" "" "$plan_path"
write_event "warehouse_retention_planner" "storage_budget_ledger_emitted" "$decision" "" "$ledger_path"

exit "$exit_code"
