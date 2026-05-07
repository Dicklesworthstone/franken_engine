#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_AUTOPILOT_EVIDENCE_WAREHOUSE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-autopilot-evidence-warehouse}"
run_id="${SWARM_AUTOPILOT_EVIDENCE_WAREHOUSE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AUTOPILOT_EVIDENCE_WAREHOUSE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_AUTOPILOT_EVIDENCE_WAREHOUSE_SOURCE_REVISION:-}"
swarm_ops_bundle_dir=""
queue_locality_json=""
operator_intent_policy_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_autopilot_evidence_warehouse.sh [OPTIONS]

Normalizes SWARM-OPS bundles, topology-aware queue advice, RCH rehabilitation
evidence, SLO gate reports, and optional operator-intent policies into one
append-only evidence warehouse. The warehouse is advisory and proof-only: it
does not mutate beads, send Agent Mail, run Cargo or RCH, release reservations,
or change live queue policy.

Inputs:
  --swarm-ops-bundle-dir DIR
  --queue-locality-json FILE
  --operator-intent-policy-json FILE
  --source-revision REV
  --output-dir DIR

Artifacts:
  evidence_warehouse.json
  run_manifest.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   warehouse emitted with pass decision
  42  warehouse emitted with fail-closed decision
  64  invalid option
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --swarm-ops-bundle-dir)
      swarm_ops_bundle_dir="${2:-}"
      shift 2
      ;;
    --queue-locality-json)
      queue_locality_json="${2:-}"
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

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm autopilot evidence warehouse\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm autopilot evidence warehouse\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
warehouse_path="${run_dir}/evidence_warehouse.json"
warehouse_tmp="${warehouse_path}.tmp"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
artifact_rows_jsonl="${run_dir}/artifact_rows.jsonl"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"
remediations_jsonl="${run_dir}/remediation_commands.jsonl"
hash_basis_path="${run_dir}/warehouse_hash_basis.json"

normalized_dir="${run_dir}/normalized"
mkdir -p "$normalized_dir"
: >"$events_path"
: >"$artifact_rows_jsonl"
: >"$fail_closed_reasons_jsonl"
: >"$remediations_jsonl"

printf './scripts/swarm_autopilot_evidence_warehouse.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-evidence-warehouse.event.v1" \
    --arg component "swarm_autopilot_evidence_warehouse" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    --arg evidence_path "$4" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail,evidence_path:$evidence_path}' \
    >>"$events_path"
}

append_remediation() {
  local code="$1"
  local command="$2"
  jq -nc --arg code "$code" --arg command "$command" \
    '{code:$code,command:$command}' >>"$remediations_jsonl"
}

append_reason() {
  local reason_type="$1"
  local code="$2"
  local source_id="$3"
  local detail="$4"
  local remediation="$5"
  jq -nc \
    --arg reason_type "$reason_type" \
    --arg code "$code" \
    --arg source_id "$source_id" \
    --arg detail "$detail" \
    --arg remediation_command "$remediation" \
    '{reason_type:$reason_type,code:$code,source_id:$source_id,detail:$detail,remediation_command:$remediation_command}' \
    >>"$fail_closed_reasons_jsonl"
  append_remediation "$code" "$remediation"
  write_event "warehouse.fail_closed_reason" "$code" "$detail" "$source_id"
}

sha_file() {
  local path="$1"
  sha256sum "$path" | awk '{print $1}'
}

append_artifact_row() {
  local source_id="$1"
  local source_path="$2"
  local normalized_path="$3"
  local schema_version="$4"
  local retention_class="$5"
  local decision="$6"
  local freshness="$7"
  local sha256="$8"
  local provided="$9"
  jq -nc \
    --arg source_id "$source_id" \
    --arg source_path "$source_path" \
    --arg normalized_path "$normalized_path" \
    --arg schema_version "$schema_version" \
    --arg retention_class "$retention_class" \
    --arg decision "$decision" \
    --arg freshness "$freshness" \
    --arg sha256 "$sha256" \
    --argjson provided "$provided" \
    '{
      source_id:$source_id,
      source_path:$source_path,
      normalized_path:$normalized_path,
      schema_version:$schema_version,
      retention_class:$retention_class,
      decision:$decision,
      freshness:$freshness,
      sha256:$sha256,
      provided:$provided
    }' >>"$artifact_rows_jsonl"
}

normalize_json_artifact() {
  local source_id="$1"
  local source_path="$2"
  local normalized_path="$3"
  local expected_schema="$4"
  local retention_class="$5"
  local remediation="$6"
  local schema_version decision freshness sha256

  if [[ ! -f "$source_path" ]]; then
    append_reason "missing_bundle_member" "FE-SWARM-AUTOPILOT-MISSING-BUNDLE-MEMBER" "$source_id" "required bundle member is missing: $source_path" "$remediation"
    append_artifact_row "$source_id" "$source_path" "$normalized_path" "missing" "$retention_class" "missing" "missing" "" false
    return
  fi
  if ! jq empty "$source_path" >/dev/null 2>&1; then
    append_reason "bad_schema" "FE-SWARM-AUTOPILOT-SCHEMA-DRIFT" "$source_id" "required bundle member is not valid JSON: $source_path" "$remediation"
    append_artifact_row "$source_id" "$source_path" "$normalized_path" "invalid_json" "$retention_class" "invalid" "invalid" "" true
    return
  fi

  jq -cS . "$source_path" >"$normalized_path"
  schema_version="$(jq -r '.schema_version // "missing_schema"' "$normalized_path")"
  decision="$(jq -r '.decision // .truth_state // .verdict // "provided"' "$normalized_path")"
  freshness="$(jq -r '.freshness // .captured_at // .captured_at_epoch_seconds // .created_at // .run_id // "unknown"' "$normalized_path")"
  sha256="$(sha_file "$normalized_path")"
  append_artifact_row "$source_id" "$source_path" "$normalized_path" "$schema_version" "$retention_class" "$decision" "$freshness" "$sha256" true
  write_event "artifact.normalized" "ok" "$source_id" "$source_path"

  if [[ "$schema_version" != "$expected_schema" ]]; then
    append_reason "bad_schema" "FE-SWARM-AUTOPILOT-SCHEMA-DRIFT" "$source_id" "expected schema $expected_schema, got $schema_version" "$remediation"
  fi
}

normalize_text_artifact() {
  local source_id="$1"
  local source_path="$2"
  local retention_class="$3"
  local remediation="$4"
  local sha256

  if [[ ! -f "$source_path" ]]; then
    append_reason "missing_bundle_member" "FE-SWARM-AUTOPILOT-MISSING-BUNDLE-MEMBER" "$source_id" "required bundle member is missing: $source_path" "$remediation"
    append_artifact_row "$source_id" "$source_path" "" "missing" "$retention_class" "missing" "missing" "" false
    return
  fi
  sha256="$(sha_file "$source_path")"
  append_artifact_row "$source_id" "$source_path" "" "text/plain" "$retention_class" "provided" "unknown" "$sha256" true
  write_event "artifact.normalized" "ok" "$source_id" "$source_path"
}

bundle_path_for() {
  local name="$1"
  if [[ -z "$swarm_ops_bundle_dir" ]]; then
    printf '%s' ""
  else
    printf '%s/%s' "$swarm_ops_bundle_dir" "$name"
  fi
}

missing_bundle_remediation="# operator: rerun bash scripts/e2e/swarm_ops_no_mock_drill.sh --output-dir <fresh-bundle>"
schema_remediation="# operator: rerun bash scripts/e2e/swarm_ops_no_mock_drill_smoke.sh selftest and refresh the stale schema producer"
queue_remediation="# operator: rerun bash scripts/e2e/swarm_topology_aware_queue_scorer_smoke.sh selftest and pass queue_advisory_bundle.json"

if [[ -z "$swarm_ops_bundle_dir" || ! -d "$swarm_ops_bundle_dir" ]]; then
  append_reason "missing_bundle_member" "FE-SWARM-AUTOPILOT-MISSING-BUNDLE-MEMBER" "swarm_ops_bundle_dir" "SWARM-OPS bundle directory is missing or not a directory" "$missing_bundle_remediation"
fi

normalize_json_artifact "run_manifest_json" "$(bundle_path_for run_manifest.json)" "${normalized_dir}/run_manifest.normalized.json" "franken-engine.swarm-ops-no-mock-drill-run-manifest.v1" "long_lived_replay_evidence" "$missing_bundle_remediation"
normalize_text_artifact "events_jsonl" "$(bundle_path_for events.jsonl)" "audit_log" "$missing_bundle_remediation"
normalize_text_artifact "commands_txt" "$(bundle_path_for commands.txt)" "audit_log" "$missing_bundle_remediation"
normalize_json_artifact "trace_ids_json" "$(bundle_path_for trace_ids.json)" "${normalized_dir}/trace_ids.normalized.json" "franken-engine.swarm-ops-no-mock-drill-trace-ids.v1" "long_lived_replay_evidence" "$missing_bundle_remediation"
normalize_json_artifact "state_snapshot_json" "$(bundle_path_for state_snapshot.json)" "${normalized_dir}/state_snapshot.normalized.json" "franken-engine.swarm-ops-state-snapshot.v1" "short_lived_raw_capture" "$schema_remediation"
normalize_json_artifact "admission_plan_json" "$(bundle_path_for admission_plan.json)" "${normalized_dir}/admission_plan.normalized.json" "franken-engine.swarm-admission-budget-plan.v1" "long_lived_replay_evidence" "$schema_remediation"
normalize_json_artifact "recovery_receipts_json" "$(bundle_path_for recovery_receipts.json)" "${normalized_dir}/recovery_receipts.normalized.json" "franken-engine.swarm-stale-recovery-receipts.v1" "long_lived_replay_evidence" "$schema_remediation"
normalize_json_artifact "rch_rehab_ledger_json" "$(bundle_path_for rch_rehab_ledger.json)" "${normalized_dir}/rch_rehab_ledger.normalized.json" "franken-engine.swarm-rch-stall-rehabilitation-ledger.v1" "long_lived_replay_evidence" "$schema_remediation"
normalize_json_artifact "locality_plan_json" "$(bundle_path_for locality_plan.json)" "${normalized_dir}/locality_plan.normalized.json" "franken-engine.swarm-proof-cache-locality-plan.v1" "long_lived_replay_evidence" "$schema_remediation"
normalize_json_artifact "dashboard_bundle_json" "$(bundle_path_for dashboard_bundle.json)" "${normalized_dir}/dashboard_bundle.normalized.json" "franken-engine.swarm-frankentui-dashboard-bundle.v1" "short_lived_raw_capture" "$schema_remediation"
normalize_json_artifact "saturation_replay_report_json" "$(bundle_path_for saturation_replay_report.json)" "${normalized_dir}/saturation_replay_report.normalized.json" "franken-engine.swarm-saturation-replay-report.v1" "long_lived_replay_evidence" "$schema_remediation"
normalize_json_artifact "slo_gate_report_json" "$(bundle_path_for slo_gate_report.json)" "${normalized_dir}/slo_gate_report.normalized.json" "franken-engine.swarm-slo-gate-report.v1" "long_lived_replay_evidence" "$schema_remediation"
normalize_json_artifact "truth_gate_report_json" "$(bundle_path_for truth_gate_report.json)" "${normalized_dir}/truth_gate_report.normalized.json" "franken-engine.swarm-ops-no-mock-drill-truth-gate.v1" "long_lived_replay_evidence" "$schema_remediation"

queue_normalized="${normalized_dir}/queue_locality.normalized.json"
if [[ -z "$queue_locality_json" || ! -f "$queue_locality_json" ]]; then
  append_reason "missing_queue_locality_evidence" "FE-SWARM-AUTOPILOT-MISSING-QUEUE-LOCALITY" "queue_locality_json" "topology-aware queue locality evidence is missing" "$queue_remediation"
  append_artifact_row "queue_locality_json" "${queue_locality_json:-missing}" "$queue_normalized" "missing" "long_lived_replay_evidence" "missing" "missing" "" false
elif ! jq empty "$queue_locality_json" >/dev/null 2>&1; then
  append_reason "queue_locality_schema_drift" "FE-SWARM-AUTOPILOT-SCHEMA-DRIFT" "queue_locality_json" "topology-aware queue locality evidence is not valid JSON" "$queue_remediation"
  append_artifact_row "queue_locality_json" "$queue_locality_json" "$queue_normalized" "invalid_json" "long_lived_replay_evidence" "invalid" "invalid" "" true
else
  jq -cS . "$queue_locality_json" >"$queue_normalized"
  queue_schema_version="$(jq -r '.schema_version // "missing_schema"' "$queue_normalized")"
  queue_decision="$(jq -r '.decision // "unknown"' "$queue_normalized")"
  queue_freshness="$(jq -r '.source_revision // .queue_advisory_id // "unknown"' "$queue_normalized")"
  append_artifact_row "queue_locality_json" "$queue_locality_json" "$queue_normalized" "$queue_schema_version" "long_lived_replay_evidence" "$queue_decision" "$queue_freshness" "$(sha_file "$queue_normalized")" true
  write_event "artifact.normalized" "ok" "queue_locality_json" "$queue_locality_json"
  if [[ "$queue_schema_version" != "franken-engine.swarm-topology-aware-queue-advisory.v1" ]]; then
    append_reason "queue_locality_schema_drift" "FE-SWARM-AUTOPILOT-SCHEMA-DRIFT" "queue_locality_json" "expected topology-aware queue advisory schema, got $queue_schema_version" "$queue_remediation"
  fi
fi

operator_policy_normalized="${normalized_dir}/operator_intent_policy.normalized.json"
if [[ -z "$operator_intent_policy_json" ]]; then
  jq -cS '{
    schema_version:"franken-engine.swarm-autopilot-operator-intent-policy.v1",
    decision:"not_provided",
    intents:[],
    mutation_policy:{advisory_only:true, mutates_br:false, runs_cargo:false, runs_rch:false}
  }' <<<"{}" >"$operator_policy_normalized"
  append_artifact_row "operator_intent_policy_json" "not_provided" "$operator_policy_normalized" "franken-engine.swarm-autopilot-operator-intent-policy.v1" "policy_snapshot" "not_provided" "defaulted" "$(sha_file "$operator_policy_normalized")" false
elif ! jq empty "$operator_intent_policy_json" >/dev/null 2>&1; then
  append_reason "bad_schema" "FE-SWARM-AUTOPILOT-SCHEMA-DRIFT" "operator_intent_policy_json" "operator intent policy is not valid JSON" "# operator: regenerate operator-intent policy with the compiler before warehouse ingestion"
  append_artifact_row "operator_intent_policy_json" "$operator_intent_policy_json" "$operator_policy_normalized" "invalid_json" "policy_snapshot" "invalid" "invalid" "" true
else
  jq -cS . "$operator_intent_policy_json" >"$operator_policy_normalized"
  operator_schema_version="$(jq -r '.schema_version // "missing_schema"' "$operator_policy_normalized")"
  operator_decision="$(jq -r '.decision // "provided"' "$operator_policy_normalized")"
  append_artifact_row "operator_intent_policy_json" "$operator_intent_policy_json" "$operator_policy_normalized" "$operator_schema_version" "policy_snapshot" "$operator_decision" "provided" "$(sha_file "$operator_policy_normalized")" true
  if [[ "$operator_schema_version" != "franken-engine.swarm-autopilot-operator-intent-policy.v1" ]]; then
    append_reason "bad_schema" "FE-SWARM-AUTOPILOT-SCHEMA-DRIFT" "operator_intent_policy_json" "expected operator intent policy schema, got $operator_schema_version" "# operator: regenerate operator-intent policy with the compiler before warehouse ingestion"
  fi
fi

state_snapshot_normalized="${normalized_dir}/state_snapshot.normalized.json"
truth_gate_normalized="${normalized_dir}/truth_gate_report.normalized.json"
saturation_normalized="${normalized_dir}/saturation_replay_report.normalized.json"
slo_gate_normalized="${normalized_dir}/slo_gate_report.normalized.json"

if [[ -s "$state_snapshot_normalized" ]] && jq -e '
  (.br_sync_status_json.db_newer // false) == true
  or (.br_sync_status_json.jsonl_newer // false) == true
  or ([.reason_codes[]?, .fail_closed_reasons[]?.code?, .state_reasons[]?.code?] | any(. == "FE-SWARM-OPS-STALE-BV" or . == "stale_bv_due_to_br_sync"))
' "$state_snapshot_normalized" >/dev/null; then
  append_reason "stale_swarm_ops_state" "FE-SWARM-AUTOPILOT-STALE-SWARM-OPS" "state_snapshot_json" "state snapshot records stale br/bv sync state" "# operator: br sync --flush-only && bv --recipe actionable --robot-plan"
fi

if [[ -s "$truth_gate_normalized" ]] && jq -e '
  [.truth_gate_reasons[]?.code?, .reason_codes[]?, .fail_closed_reasons[]?.code?] | any(. == "FE-SWARM-OPS-STALE-BV" or . == "stale_bv_due_to_br_sync")
' "$truth_gate_normalized" >/dev/null; then
  append_reason "stale_swarm_ops_state" "FE-SWARM-AUTOPILOT-STALE-SWARM-OPS" "truth_gate_report_json" "truth gate records stale br/bv sync state" "# operator: br sync --flush-only && bv --recipe actionable --robot-plan"
fi

if { [[ -s "$saturation_normalized" ]] && jq -e '(.contamination_report.local_fallback_observed // false) == true' "$saturation_normalized" >/dev/null; } \
  || { [[ -s "$slo_gate_normalized" ]] && jq -e '[.. | scalars | tostring] | any(test("local_fallback|LOCAL-FALLBACK|local fallback"; "i"))' "$slo_gate_normalized" >/dev/null; } \
  || { [[ -s "$queue_normalized" ]] && jq -e '[.reason_codes[]?, .fail_closed_reasons[]?.code?, .truth_state?] | map(tostring) | any(test("local_fallback|contaminated"; "i"))' "$queue_normalized" >/dev/null; }; then
  append_reason "local_fallback_contamination" "FE-SWARM-AUTOPILOT-LOCAL-FALLBACK" "swarm_ops_bundle" "local fallback contamination is present in upstream evidence" "# operator: rerun through rch exec only, then regenerate SWARM-OPS and queue scorer bundles"
fi

if [[ -s "$truth_gate_normalized" ]] && jq -e '
  (.decision // "") as $truth
  | ([.stage_decisions[]? | (.decision // .verdict // "")] | map(select(. == "fail_closed" or . == "fail"))) as $failed
  | (($truth == "pass" and ($failed | length) > 0) or ($truth == "fail_closed" and ($failed | length) == 0 and ((.stage_decisions // []) | length) > 0))
' "$truth_gate_normalized" >/dev/null; then
  append_reason "contradictory_stage_decision" "FE-SWARM-AUTOPILOT-CONTRADICTORY-STAGE" "truth_gate_report_json" "truth-gate decision contradicts stage decisions" "# operator: rerun scripts/e2e/swarm_ops_no_mock_drill_smoke.sh selftest and inspect stage_decisions"
fi

decision="pass"
if [[ -s "$fail_closed_reasons_jsonl" ]]; then
  decision="fail_closed"
fi

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-evidence-warehouse-hash-basis.v1" \
  --arg bead_id "bd-4t4oi" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --slurpfile artifact_rows "$artifact_rows_jsonl" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" '
  {
    schema_version:$schema_version,
    bead_id:$bead_id,
    source_revision:$source_revision,
    decision:$decision,
    artifact_rows:($artifact_rows | map({
      source_id,
      schema_version,
      retention_class,
      decision,
      freshness,
      sha256,
      provided
    }) | sort_by(.source_id)),
    fail_closed_reasons:($fail_closed_reasons | sort_by(.code, .source_id, .detail))
  }' | jq -cS . >"$hash_basis_path"
warehouse_hash="$(sha_file "$hash_basis_path")"

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-evidence-warehouse.v1" \
  --arg bead_id "bd-4t4oi" \
  --arg source_revision "$source_revision" \
  --arg run_id "$run_id" \
  --arg decision "$decision" \
  --arg warehouse_hash "$warehouse_hash" \
  --arg warehouse_path "$warehouse_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg hash_basis_path "$hash_basis_path" \
  --arg swarm_ops_bundle_dir "${swarm_ops_bundle_dir:-missing}" \
  --arg queue_locality_json "${queue_locality_json:-missing}" \
  --slurpfile artifact_rows "$artifact_rows_jsonl" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" \
  --slurpfile remediation_commands "$remediations_jsonl" '
  {
    schema_version:$schema_version,
    bead_id:$bead_id,
    source_revision:$source_revision,
    run_identity:{
      run_id:$run_id,
      clock:"wall-clock-recorded-in-manifest",
      source_revision:$source_revision
    },
    decision:$decision,
    fail_closed_reasons:($fail_closed_reasons | unique_by([.code, .source_id, .detail])),
    remediation_commands:($remediation_commands | unique_by([.code, .command])),
    artifact_rows:($artifact_rows | sort_by(.source_id)),
    retention_classes:{
      short_lived_raw_capture:["state_snapshot_json","dashboard_bundle_json"],
      long_lived_replay_evidence:["run_manifest_json","trace_ids_json","admission_plan_json","recovery_receipts_json","rch_rehab_ledger_json","locality_plan_json","saturation_replay_report_json","slo_gate_report_json","truth_gate_report_json","queue_locality_json"],
      audit_log:["events_jsonl","commands_txt"],
      policy_snapshot:["operator_intent_policy_json"]
    },
    hash_basis:{
      schema_version:"franken-engine.swarm-autopilot-evidence-warehouse-hash-basis.v1",
      algorithm:"sha256",
      warehouse_hash:$warehouse_hash,
      basis_path:$hash_basis_path,
      excludes:["artifact_paths","source_path","normalized_path","run_id","wall_clock"]
    },
    artifact_paths:{
      evidence_warehouse_json:$warehouse_path,
      run_manifest_json:$manifest_path,
      events_jsonl:$events_path,
      commands_txt:$commands_path,
      report_md:$report_path,
      hash_basis_json:$hash_basis_path,
      swarm_ops_bundle_dir:$swarm_ops_bundle_dir,
      queue_locality_json:$queue_locality_json
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
      changes_live_queue_policy:false,
      pins_workers_automatically:false,
      writes_outside_output_dir:false
    }
  }' >"$warehouse_tmp"
mv "$warehouse_tmp" "$warehouse_path"

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-evidence-warehouse-run-manifest.v1" \
  --arg bead_id "bd-4t4oi" \
  --arg source_revision "$source_revision" \
  --arg run_id "$run_id" \
  --arg decision "$decision" \
  --arg warehouse_hash "$warehouse_hash" \
  --arg warehouse_path "$warehouse_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  '{
    schema_version:$schema_version,
    bead_id:$bead_id,
    run_id:$run_id,
    source_revision:$source_revision,
    decision:$decision,
    warehouse_hash:$warehouse_hash,
    artifact_paths:{
      evidence_warehouse_json:$warehouse_path,
      events_jsonl:$events_path,
      commands_txt:$commands_path
    }
  }' >"$manifest_path"

{
  printf '# Swarm Autopilot Evidence Warehouse\n'
  printf '\n'
  printf -- "- bead_id: \`bd-4t4oi\`\n"
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- warehouse_hash: \`%s\`\n" "$warehouse_hash"
  printf -- "- fail_closed_reason_count: \`%s\`\n" "$(jq -s 'length' "$fail_closed_reasons_jsonl")"
  if [[ -s "$fail_closed_reasons_jsonl" ]]; then
    printf '\n## Remediation\n\n'
    jq -r '.remediation_command' "$fail_closed_reasons_jsonl" | sort -u | sed 's/^/- /'
  fi
} >"$report_path"

write_event "warehouse.emitted" "$decision" "$warehouse_hash" "$warehouse_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
exit 0
