#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_OPS_NO_MOCK_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-ops-no-mock-drill}"
run_id="${SWARM_OPS_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_OPS_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${SWARM_OPS_NO_MOCK_DRILL_SOURCE_REVISION:-}"
fixtures_json=""
case_id=""
replay_run_dir=""
latest_from=""
mode="live"
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_ops_no_mock_drill.sh [OPTIONS]

Runs the closed-loop SWARM-OPS no-mock drill. Live mode captures local br, bv,
Agent Mail, RCH, and git state through the shipped capture surface. Fixture mode
uses deterministic preserved inputs. Replay mode verifies a pinned or latest
complete bundle without re-running capture.

Options:
  --fixtures-json FILE
  --case-id ID
  --replay-run-dir DIR
  --latest-from DIR
  --output-dir DIR
  --source-revision REV
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --fixtures-json)
      fixtures_json="${2:-}"
      mode="fixture"
      shift 2
      ;;
    --case-id)
      case_id="${2:-}"
      shift 2
      ;;
    --replay-run-dir)
      replay_run_dir="${2:-}"
      mode="replay"
      shift 2
      ;;
    --latest-from)
      latest_from="${2:-}"
      mode="replay"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
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
  printf 'jq is required for swarm ops no-mock drill\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm ops no-mock drill\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi
if [[ "$mode" == "fixture" && ( -z "$fixtures_json" || -z "$case_id" ) ]]; then
  printf 'fixture mode requires --fixtures-json and --case-id\n' >&2
  exit 64
fi

mkdir -p "$run_dir"
inputs_dir="${run_dir}/inputs"
stages_dir="${run_dir}/stages"
truth_inputs_dir="${run_dir}/truth_inputs"
mkdir -p "$inputs_dir" "$stages_dir" "$truth_inputs_dir"

events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
stage_status_path="${run_dir}/stage_status.jsonl"
truth_failures_path="${run_dir}/truth_failures.jsonl"
command_evidence_path="${run_dir}/command_evidence.txt"
truth_report_path="${run_dir}/truth_gate_report.json"
manifest_path="${run_dir}/run_manifest.json"
trace_ids_path="${run_dir}/trace_ids.json"
case_json="${inputs_dir}/case.json"
: >"$events_path"
: >"$commands_path"
: >"$stage_status_path"
: >"$truth_failures_path"

render_command() {
  local rendered="" arg quoted
  for arg in "$@"; do
    printf -v quoted '%q' "$arg"
    rendered+="${rendered:+ }${quoted}"
  done
  printf '%s' "$rendered"
}

log_command() {
  render_command "$@" >>"$commands_path"
  printf '\n' >>"$commands_path"
}

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-ops-no-mock-drill.event.v1" \
    --arg trace_id "trace-swarm-ops-no-mock-${run_id}" \
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

append_truth_failure() {
  jq -nc \
    --arg code "$1" \
    --arg source_id "$2" \
    --arg detail "$3" \
    --arg remediation_command "$4" \
    --arg evidence_path "$5" \
    '{
      code:$code,
      source_id:$source_id,
      detail:$detail,
      remediation_command:$remediation_command,
      evidence_path:$evidence_path
    }' >>"$truth_failures_path"
}

run_stage() {
  local stage="$1"
  shift
  local stage_dir="${stages_dir}/${stage}"
  local stdout_path="${stage_dir}/stdout.txt"
  local stderr_path="${stage_dir}/stderr.txt"
  local rendered exit_code
  mkdir -p "$stage_dir"
  rendered="$(render_command "$@")"
  printf '%s\n' "$rendered" >>"$commands_path"
  write_event "$stage" "stage_started" "running" "" "$stage_dir"
  set +e
  "$@" >"$stdout_path" 2>"$stderr_path"
  exit_code=$?
  set -e
  jq -nc \
    --arg stage "$stage" \
    --arg command "$rendered" \
    --arg stdout_path "$stdout_path" \
    --arg stderr_path "$stderr_path" \
    --argjson exit_code "$exit_code" \
    '{stage:$stage,exit_code:$exit_code,command:$command,stdout_path:$stdout_path,stderr_path:$stderr_path}' \
    >>"$stage_status_path"
  if [[ "$exit_code" -eq 0 ]]; then
    write_event "$stage" "stage_finished" "pass" "" "$stdout_path"
  else
    write_event "$stage" "stage_finished" "nonzero" "FE-SWARM-OPS-STAGE-NONZERO" "$stderr_path"
  fi
}

write_case_file() {
  if [[ "$mode" == "fixture" ]]; then
    jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_json" >"$case_json"
    if ! jq -e '(.case_id // "") | length > 0' "$case_json" >/dev/null; then
      printf 'fixture case not found: %s\n' "$case_id" >&2
      exit 64
    fi
  else
    printf '{}\n' >"$case_json"
  fi
}

write_fixture_json_field() {
  local field="$1"
  local output="$2"
  jq --arg field "$field" '.state_capture[$field]' "$case_json" >"$output"
}

write_fixture_text_field() {
  local field="$1"
  local output="$2"
  jq -r --arg field "$field" '.state_capture[$field] // ""' "$case_json" >"$output"
}

required_artifacts=(
  "run_manifest.json"
  "events.jsonl"
  "commands.txt"
  "trace_ids.json"
  "state_snapshot.json"
  "admission_plan.json"
  "recovery_receipts.json"
  "rch_rehab_ledger.json"
  "locality_plan.json"
  "dashboard_bundle.json"
  "saturation_replay_report.json"
  "slo_gate_report.json"
)

ensure_truth_json() {
  local source_path="$1"
  local output_path="$2"
  local source_id="$3"
  if [[ -s "$source_path" ]] && jq empty "$source_path" >/dev/null 2>&1; then
    cp "$source_path" "$output_path"
  else
    append_truth_failure \
      "FE-SWARM-OPS-MISSING-BUNDLE-ARTIFACT" \
      "$source_id" \
      "required bundle artifact is missing or malformed" \
      "# operator: rerun swarm_ops_no_mock_drill with a complete output directory" \
      "$source_path"
    printf '{}\n' >"$output_path"
  fi
}

scan_command_evidence() {
  local command_scan_path="${command_evidence_path}.scan"
  : >"$command_evidence_path"
  while IFS= read -r path; do
    printf '# %s\n' "$path" >>"$command_evidence_path"
    sed -n '1,260p' "$path" >>"$command_evidence_path"
  done < <(find "$1" -type f -name commands.txt | sort)
  if [[ -f "$1/stages/state_capture/out/raw/bv_actionable_plan.txt" ]]; then
    printf '# %s\n' "$1/stages/state_capture/out/raw/bv_actionable_plan.txt" >>"$command_evidence_path"
    sed -n '1,260p' "$1/stages/state_capture/out/raw/bv_actionable_plan.txt" >>"$command_evidence_path"
  fi

  cp "$command_evidence_path" "$command_scan_path"
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) && "$command" != *"rch exec --"* ]]; then
      append_truth_failure \
        "FE-SWARM-OPS-BARE-CARGO" \
        "command_evidence" \
        "heavy Cargo command appears without rch exec wrapper" \
        "# operator: rerun heavy validation through rch exec --" \
        "$command_evidence_path"
    fi
  done <"$command_scan_path"
}

write_truth_report() {
  local bundle_dir="$1"
  local output_dir="$2"
  local state_json="${output_dir}/truth_inputs/state_snapshot.json"
  local admission_json="${output_dir}/truth_inputs/admission_plan.json"
  local recovery_json="${output_dir}/truth_inputs/recovery_receipts.json"
  local rehab_json="${output_dir}/truth_inputs/rch_rehab_ledger.json"
  local locality_json="${output_dir}/truth_inputs/locality_plan.json"
  local dashboard_json="${output_dir}/truth_inputs/dashboard_bundle.json"
  local saturation_json="${output_dir}/truth_inputs/saturation_replay_report.json"
  local slo_json="${output_dir}/truth_inputs/slo_gate_report.json"
  local truth_path="${output_dir}/truth_gate_report.json"
  local manifest_out="${output_dir}/run_manifest.json"
  local trace_out="${output_dir}/trace_ids.json"
  mkdir -p "${output_dir}/truth_inputs"

  ensure_truth_json "${bundle_dir}/state_snapshot.json" "$state_json" "state_snapshot_json"
  ensure_truth_json "${bundle_dir}/admission_plan.json" "$admission_json" "admission_plan_json"
  ensure_truth_json "${bundle_dir}/recovery_receipts.json" "$recovery_json" "recovery_receipts_json"
  ensure_truth_json "${bundle_dir}/rch_rehab_ledger.json" "$rehab_json" "rch_rehab_ledger_json"
  ensure_truth_json "${bundle_dir}/locality_plan.json" "$locality_json" "locality_plan_json"
  ensure_truth_json "${bundle_dir}/dashboard_bundle.json" "$dashboard_json" "dashboard_bundle_json"
  ensure_truth_json "${bundle_dir}/saturation_replay_report.json" "$saturation_json" "saturation_replay_report_json"
  ensure_truth_json "${bundle_dir}/slo_gate_report.json" "$slo_json" "slo_gate_report_json"

  local artifact
  for artifact in "${required_artifacts[@]}"; do
    if [[ "$bundle_dir" == "$output_dir" && ( "$artifact" == "run_manifest.json" || "$artifact" == "trace_ids.json" ) ]]; then
      continue
    fi
    if [[ ! -s "${bundle_dir}/${artifact}" ]]; then
      append_truth_failure \
        "FE-SWARM-OPS-INCOMPLETE-BUNDLE" \
        "$artifact" \
        "complete bundle is missing a required artifact" \
        "# operator: rerun or pin a complete swarm ops no-mock drill bundle" \
        "${bundle_dir}/${artifact}"
    fi
  done

  scan_command_evidence "$bundle_dir"

  if jq -e '(.fail_closed_reasons // [] | index("stale_bv_due_to_br_sync") != null)' "$state_json" >/dev/null \
    && ! jq -e '(.fail_closed_reasons // [] | index("stale_br_bv_state") != null)' "$admission_json" >/dev/null; then
    append_truth_failure \
      "FE-SWARM-OPS-STALE-BV-NOT-DETECTED" \
      "admission_plan_json" \
      "stale br/bv export state was not propagated into admission fail-closed reasons" \
      "# operator: refresh br sync state before admission planning" \
      "${bundle_dir}/admission_plan.json"
  fi

  if jq -e 'any(.workers[]?; .classification != "healthy") and .decision == "pass"' "$rehab_json" >/dev/null; then
    append_truth_failure \
      "FE-SWARM-OPS-RCH-STALL-UPGRADED" \
      "rch_rehab_ledger_json" \
      "RCH stale-progress or rehab evidence was upgraded to pass" \
      "# operator: probe or drain the affected worker before admitting heavy lanes" \
      "${bundle_dir}/rch_rehab_ledger.json"
  fi

  if jq -e '(.components.rch.local_fallback_observed // false) == true' "$state_json" >/dev/null \
    && ! jq -e '(.fail_closed_reasons // [] | map(.code) | index("local_fallback_contamination") != null)' "$slo_json" >/dev/null; then
    append_truth_failure \
      "FE-SWARM-OPS-LOCAL-FALLBACK-NOT-CLOSED" \
      "slo_gate_report_json" \
      "local fallback evidence did not force the SLO gate closed" \
      "# operator: discard contaminated local fallback bundle and rerun through remote evidence" \
      "${bundle_dir}/slo_gate_report.json"
  fi

  jq -n \
    --slurpfile state "$state_json" \
    --slurpfile admission "$admission_json" \
    --slurpfile recovery "$recovery_json" \
    --slurpfile rehab "$rehab_json" \
    --slurpfile locality "$locality_json" \
    --slurpfile dashboard "$dashboard_json" \
    --slurpfile saturation "$saturation_json" \
    --slurpfile slo "$slo_json" \
    --slurpfile truth_failures "$truth_failures_path" \
    --slurpfile stages "$stage_status_path" \
    --arg schema_version "franken-engine.swarm-ops-no-mock-drill-truth-gate.v1" \
    --arg source_revision "$source_revision" \
    --arg run_id "$run_id" \
    --arg bundle_dir "$bundle_dir" \
    --arg output_dir "$output_dir" \
    --arg command_evidence_path "$command_evidence_path" '
      def arr($x): if ($x | type) == "array" then $x else [] end;
      def reason($code; $source; $detail; $remediation; $evidence):
        {code:$code,source_id:$source,detail:$detail,remediation_command:$remediation,evidence_path:$evidence};
      def decision_rank($d):
        if $d == "fail_closed" then 4
        elif $d == "blocked" then 3
        elif $d == "degraded" or $d == "warn" then 2
        elif $d == "pass" then 1
        else 0 end;
      def max_decision($decisions):
        ($decisions | map(decision_rank(.)) | max // 0) as $rank
        | if $rank >= 4 then "fail_closed"
          elif $rank == 3 then "blocked"
          elif $rank == 2 then "degraded"
          elif $rank == 1 then "pass"
          else "fail_closed" end;

      ($state[0]) as $state_doc
      | ($admission[0]) as $admission_doc
      | ($recovery[0]) as $recovery_doc
      | ($rehab[0]) as $rehab_doc
      | ($locality[0]) as $locality_doc
      | ($dashboard[0]) as $dashboard_doc
      | ($saturation[0]) as $saturation_doc
      | ($slo[0]) as $slo_doc
      | ([
          {stage:"state_snapshot", decision:($state_doc.decision // "fail_closed")},
          {stage:"admission_plan", decision:($admission_doc.decision // "fail_closed")},
          {stage:"recovery_receipts", decision:($recovery_doc.decision // "fail_closed")},
          {stage:"rch_rehab_ledger", decision:($rehab_doc.decision // "fail_closed")},
          {stage:"locality_plan", decision:($locality_doc.decision // "fail_closed")},
          {stage:"dashboard_bundle", decision:($dashboard_doc.decision // "fail_closed")},
          {stage:"saturation_replay", decision:($saturation_doc.decision // "fail_closed")},
          {stage:"slo_gate", decision:($slo_doc.decision // "fail_closed")}
        ]) as $stage_decisions
      | ([
          if (($state_doc.fail_closed_reasons // []) | index("stale_bv_due_to_br_sync") != null) then
            reason("FE-SWARM-OPS-STALE-BV"; "state_snapshot_json"; "stale br/bv sync state was detected"; "# operator: br sync --status --json, then refresh bv plan"; "state_snapshot.json")
          else empty end,
          if (($state_doc.blocked_reasons // []) | index("dirty_unowned_files") != null) then
            reason("FE-SWARM-OPS-DIRTY-UNOWNED"; "state_snapshot_json"; "unclassified dirty files block no-mock admission"; "# operator: classify, reserve, or wait for unrelated dirty files to clear"; "state_snapshot.json")
          else empty end,
          if (($rehab_doc.summary.probe_required_count // 0) > 0 or ($rehab_doc.summary.drain_recommended_count // 0) > 0 or (($state_doc.degraded_reasons // []) | index("active_rch_stall") != null)) then
            reason("FE-SWARM-OPS-RCH-STALL-NOT-UPGRADED"; "rch_rehab_ledger_json"; "RCH stale-progress evidence remains degraded and was not upgraded"; "# operator: probe or drain the affected worker before heavy fanout"; "rch_rehab_ledger.json")
          else empty end,
          if (($slo_doc.fail_closed_reasons // [] | map(.code) | index("local_fallback_contamination")) != null) then
            reason("FE-SWARM-OPS-RCH-LOCAL-FALLBACK"; "slo_gate_report_json"; "local fallback contamination failed closed"; "# operator: discard local fallback evidence and rerun remotely"; "slo_gate_report.json")
          else empty end
        ]) as $derived_reasons
      | ($truth_failures + $derived_reasons | unique_by([.code, .source_id, .detail])) as $truth_reasons
      | (max_decision($stage_decisions | map(.decision))) as $stage_decision
      | (if ($truth_failures | length) > 0 then "fail_closed" else $stage_decision end) as $decision
      | {
          schema_version:$schema_version,
          bead_id:"bd-r1abw",
          run_id:$run_id,
          source_revision:$source_revision,
          verified_bundle_dir:$bundle_dir,
          decision:$decision,
          stage_decisions:$stage_decisions,
          stage_exit_codes:$stages,
          truth_gate_reasons:$truth_reasons,
          summary:{
            required_artifact_count:12,
            truth_failure_count:($truth_failures | length),
            derived_reason_count:($derived_reasons | length),
            stage_fail_closed_count:($stage_decisions | map(select(.decision == "fail_closed")) | length),
            stage_degraded_count:($stage_decisions | map(select(.decision == "degraded" or .decision == "warn")) | length),
            no_heavy_cargo_outside_rch:(all($truth_reasons[]?; .code != "FE-SWARM-OPS-BARE-CARGO")),
            rch_stale_progress_not_upgraded:(all($truth_reasons[]?; .code != "FE-SWARM-OPS-RCH-STALL-UPGRADED"))
          },
          artifact_paths:{
            run_manifest_json:($bundle_dir + "/run_manifest.json"),
            events_jsonl:($bundle_dir + "/events.jsonl"),
            commands_txt:($bundle_dir + "/commands.txt"),
            trace_ids_json:($bundle_dir + "/trace_ids.json"),
            state_snapshot_json:($bundle_dir + "/state_snapshot.json"),
            admission_plan_json:($bundle_dir + "/admission_plan.json"),
            recovery_receipts_json:($bundle_dir + "/recovery_receipts.json"),
            rch_rehab_ledger_json:($bundle_dir + "/rch_rehab_ledger.json"),
            locality_plan_json:($bundle_dir + "/locality_plan.json"),
            dashboard_bundle_json:($bundle_dir + "/dashboard_bundle.json"),
            saturation_replay_report_json:($bundle_dir + "/saturation_replay_report.json"),
            slo_gate_report_json:($bundle_dir + "/slo_gate_report.json"),
            command_evidence_txt:$command_evidence_path
          },
          mutation_policy:{
            live_capture_allowed:true,
            replay_verification_only:($bundle_dir != $output_dir),
            mutates_br:false,
            releases_reservations:false,
            sends_agent_mail:false,
            runs_cargo:false,
            runs_rch_heavy_commands:false,
            mutates_remote_workers:false,
            changes_live_queue_policy:false,
            writes_outside_output_dir:false
          }
        }' >"$truth_path"

  local truth_hash
  truth_hash="$(jq -cS 'del(.artifact_paths)' "$truth_path" | sha256sum | awk '{print $1}')"
  jq -n \
    --arg schema_version "franken-engine.swarm-ops-no-mock-drill-trace-ids.v1" \
    --arg run_id "$run_id" \
    --arg truth_hash "$truth_hash" \
    --slurpfile admission_trace "${bundle_dir}/stages/admission_plan/out/trace_ids.json" \
    --slurpfile saturation_trace "${bundle_dir}/stages/saturation_replay/out/trace_ids.json" \
    '{
      schema_version:$schema_version,
      run_id:$run_id,
      trace_ids:(
        ["trace-swarm-ops-no-mock-" + $run_id, "trace-swarm-ops-no-mock-hash-" + ($truth_hash[0:16])]
        + (($admission_trace[0].trace_ids // []) | map(.trace_id))
        + ($saturation_trace[0].trace_ids // [])
      )
    }' >"$trace_out" 2>/dev/null || jq -n \
      --arg schema_version "franken-engine.swarm-ops-no-mock-drill-trace-ids.v1" \
      --arg run_id "$run_id" \
      --arg truth_hash "$truth_hash" \
      '{schema_version:$schema_version,run_id:$run_id,trace_ids:["trace-swarm-ops-no-mock-" + $run_id, "trace-swarm-ops-no-mock-hash-" + ($truth_hash[0:16])]}' >"$trace_out"

  jq -n \
    --arg schema_version "franken-engine.swarm-ops-no-mock-drill-run-manifest.v1" \
    --arg run_id "$run_id" \
    --arg mode "$mode" \
    --arg source_revision "$source_revision" \
    --arg bundle_dir "$bundle_dir" \
    --arg truth_report_json "$truth_path" \
    --arg trace_ids_json "$trace_out" \
    '{
      schema_version:$schema_version,
      bead_id:"bd-r1abw",
      run_id:$run_id,
      mode:$mode,
      source_revision:$source_revision,
      verified_bundle_dir:$bundle_dir,
      artifact_paths:{
        truth_gate_report_json:$truth_report_json,
        trace_ids_json:$trace_ids_json
      },
      mutation_policy:{
        mutates_br:false,
        releases_reservations:false,
        sends_agent_mail:false,
        runs_cargo:false,
        runs_rch_heavy_commands:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false
      }
    }' >"$manifest_out"
}

if [[ "$mode" == "replay" ]]; then
  if [[ -n "$latest_from" ]]; then
    replay_run_dir="$(find "$latest_from" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
  fi
  if [[ -z "$replay_run_dir" || ! -d "$replay_run_dir" ]]; then
    printf 'replay mode requires a valid --replay-run-dir or --latest-from\n' >&2
    exit 64
  fi
  log_command "${original_args[@]}"
  write_event "swarm_ops_no_mock_drill" "replay_started" "running" "" "$replay_run_dir"
  write_truth_report "$replay_run_dir" "$run_dir"
  decision="$(jq -r '.decision' "$truth_report_path")"
  write_event "swarm_ops_no_mock_drill" "replay_finished" "$decision" "" "$truth_report_path"
  printf 'truth_gate_report_json=%s\n' "$truth_report_path"
  case "$decision" in
    fail_closed) exit 42 ;;
    blocked) exit 75 ;;
    *) exit 0 ;;
  esac
fi

write_case_file
log_command "${original_args[@]}"

state_out="${stages_dir}/state_capture/out"
mkdir -p "${stages_dir}/state_capture/fixtures"
state_fixture_args=()
if [[ "$mode" == "fixture" ]]; then
  for field in br_ready_json br_in_progress_json br_sync_status_json agent_mail_agents_json agent_mail_inbox_json rch_status_json rch_queue_json; do
    write_fixture_json_field "$field" "${stages_dir}/state_capture/fixtures/${field}.json"
  done
  for field in bv_plan_txt agent_mail_reservations_txt git_status_txt; do
    write_fixture_text_field "$field" "${stages_dir}/state_capture/fixtures/${field}.txt"
  done
  state_fixture_args=(
    --br-ready-json "${stages_dir}/state_capture/fixtures/br_ready_json.json"
    --br-in-progress-json "${stages_dir}/state_capture/fixtures/br_in_progress_json.json"
    --br-sync-status-json "${stages_dir}/state_capture/fixtures/br_sync_status_json.json"
    --bv-plan-txt "${stages_dir}/state_capture/fixtures/bv_plan_txt.txt"
    --agent-mail-agents-json "${stages_dir}/state_capture/fixtures/agent_mail_agents_json.json"
    --agent-mail-inbox-json "${stages_dir}/state_capture/fixtures/agent_mail_inbox_json.json"
    --agent-mail-reservations-txt "${stages_dir}/state_capture/fixtures/agent_mail_reservations_txt.txt"
    --rch-status-json "${stages_dir}/state_capture/fixtures/rch_status_json.json"
    --rch-queue-json "${stages_dir}/state_capture/fixtures/rch_queue_json.json"
    --git-status-txt "${stages_dir}/state_capture/fixtures/git_status_txt.txt"
  )
fi

run_stage "state_capture" bash "${root_dir}/scripts/swarm_ops_state_snapshot_capture.sh" \
  --output-dir "$state_out" \
  --project-key "$root_dir" \
  --agent-name "${AGENT_NAME:-BrownCreek}" \
  --source-revision "$source_revision" \
  "${state_fixture_args[@]}"

host_cpu_slots="$(nproc 2>/dev/null || printf 4)"
jq -n \
  --slurpfile captured "${state_out}/swarm_ops_state_snapshot.json" \
  --slurpfile case "$case_json" \
  --slurpfile br_ready "${state_out}/raw/br_ready.json" \
  --argjson host_cpu_slots "$host_cpu_slots" '
    def issues($x): if ($x | type) == "array" then $x else ($x.issues // []) end;
    def lane($issue; $idx):
      ($issue.priority // 2 | tonumber) as $priority
      | {
          lane_id:($issue.id // ("ready-" + ($idx | tostring))),
          bead_id:($issue.id // null),
          title:($issue.title // "unknown"),
          priority:$priority,
          lane_class:(if $priority <= 1 then "heavy" else "light" end),
          cpu_slots:(if $priority <= 1 then 8 else 1 end),
          memory_bytes:(if $priority <= 1 then 17179869184 else 1073741824 end),
          rch_slots:(if $priority <= 1 then 1 else 0 end),
          target_dir_bytes:(if $priority <= 1 then 10737418240 else 0 end),
          write_paths:[("docs/" + ($issue.id // ("ready-" + ($idx | tostring))) + ".md")]
        };
    ($captured[0]) as $captured_doc
    | ($case[0].capacity_envelope // {
        total_cpu_slots:($host_cpu_slots | tonumber),
        total_memory_bytes:68719476736,
        total_rch_slots:(if ($captured_doc.components.rch.state // "") == "captured" then 8 else 0 end),
        target_dir_available_bytes:107374182400,
        min_target_dir_available_bytes:10737418240,
        max_parallel_heavy_lanes:4
      }) as $capacity
    | ($case[0].candidate_lanes // (issues($br_ready[0]) | .[0:8] | to_entries | map(lane(.value; .key)))) as $lanes
    | $captured_doc + {
        capacity_envelope:$capacity,
        candidate_lanes:$lanes,
        reservation_conflicts:($case[0].reservation_conflicts // [])
      }' >"${run_dir}/state_snapshot.json"

admission_out="${stages_dir}/admission_plan/out"
run_stage "admission_plan" bash "${root_dir}/scripts/swarm_ops_admission_planner.sh" \
  --state-snapshot-json "${run_dir}/state_snapshot.json" \
  --source-revision "$source_revision" \
  --output-dir "$admission_out"
jq '
  .schema_version = "franken-engine.swarm-admission-budget-plan.v1"
  | .recommendations = ((.admitted_lanes + .deferred_lanes + .blocked_lanes)
      | map({
          lane_id,
          bead_id,
          priority,
          lane_class,
          decision,
          reason,
          advisory_command
        }))
' "${admission_out}/plan.json" >"${run_dir}/admission_plan.json"

jq -n --slurpfile state "${run_dir}/state_snapshot.json" --argjson now "$(date -u +%s)" '
  {git_activity:[($state[0].components.git.dirty_files // [])[] | {path, touched_epoch_seconds:$now}]}
' >"${inputs_dir}/git_activity.json"
jq -n --slurpfile state "${run_dir}/state_snapshot.json" '
  {reservations:[($state[0].reservation_conflicts // [])[] | {path_pattern, holder, expires_epoch_seconds:0}]}
' >"${inputs_dir}/file_reservations.json"

stale_out="${stages_dir}/recovery_receipts/out"
run_stage "recovery_receipts" bash "${root_dir}/scripts/swarm_ops_stale_recovery_policy.sh" \
  --in-progress-json "${state_out}/raw/br_in_progress.json" \
  --agent-profiles-json "${state_out}/raw/agent_mail_agents.json" \
  --mail-activity-json "${state_out}/raw/agent_mail_inbox.json" \
  --file-reservations-json "${inputs_dir}/file_reservations.json" \
  --git-activity-json "${inputs_dir}/git_activity.json" \
  --output-dir "$stale_out"
cp "${stale_out}/recovery_receipts.json" "${run_dir}/recovery_receipts.json"

if jq -e 'has("worker_status_json")' "$case_json" >/dev/null; then
  jq '.worker_status_json' "$case_json" >"${inputs_dir}/worker_status.json"
else
  jq -n \
    --slurpfile status "${state_out}/raw/rch_status.json" \
    --slurpfile queue "${state_out}/raw/rch_queue.json" \
    --argjson now "$(date -u +%s)" '
      def arr($x): if ($x | type) == "array" then $x else [] end;
      ($status[0]) as $s
      | ($queue[0]) as $q
      | {
          schema_version:"franken-engine.swarm-rch-worker-status.v1",
          captured_at_epoch_seconds:$now,
          queue_depth:((arr($q.jobs) + arr($q.running)) | length),
          slot_utilization_millionths:0,
          workers:((arr($s.workers) + arr($s.worker_rows))
            | map({worker_id:(.worker_id // .id // .name), state:((.state // .status // "UNKNOWN") | tostring | ascii_upcase), active_builds:(.active_builds // 0)})
            | map(select((.worker_id // "") | length > 0)))
        }' >"${inputs_dir}/worker_status.json"
fi
if jq -e 'has("stall_observations_json")' "$case_json" >/dev/null; then
  jq '.stall_observations_json' "$case_json" >"${inputs_dir}/stall_observations.json"
else
  jq -n '{schema_version:"franken-engine.swarm-rch-stall-observations.v1",observations:[]}' >"${inputs_dir}/stall_observations.json"
fi
if jq -e 'has("worker_capabilities_json")' "$case_json" >/dev/null; then
  jq '.worker_capabilities_json' "$case_json" >"${inputs_dir}/worker_capabilities.json"
else
  jq '{workers:[.workers[]? | {worker_id, capabilities_state:"fresh"}]}' "${inputs_dir}/worker_status.json" >"${inputs_dir}/worker_capabilities.json"
fi
if jq -e 'has("operator_actions_json")' "$case_json" >/dev/null; then
  jq '.operator_actions_json' "$case_json" >"${inputs_dir}/operator_actions.json"
else
  jq -n '{actions:[]}' >"${inputs_dir}/operator_actions.json"
fi

rehab_out="${stages_dir}/rch_rehab_ledger/out"
run_stage "rch_rehab_ledger" bash "${root_dir}/scripts/swarm_rch_stall_rehabilitation_ledger.sh" \
  --swarm-ops-state-snapshot-json "${run_dir}/state_snapshot.json" \
  --worker-status-json "${inputs_dir}/worker_status.json" \
  --stall-observations-json "${inputs_dir}/stall_observations.json" \
  --worker-capabilities-json "${inputs_dir}/worker_capabilities.json" \
  --operator-actions-json "${inputs_dir}/operator_actions.json" \
  --source-revision "$source_revision" \
  --output-dir "$rehab_out"
cp "${rehab_out}/swarm_rch_stall_rehabilitation_ledger.json" "${run_dir}/rch_rehab_ledger.json"

jq -n \
  --slurpfile state "${run_dir}/state_snapshot.json" \
  --slurpfile admission "${run_dir}/admission_plan.json" \
  --slurpfile rehab "${run_dir}/rch_rehab_ledger.json" \
  --slurpfile case "$case_json" '
    ($rehab[0].workers[0].worker_id // "rch-a") as $worker_id
    | ($state[0].capacity_envelope.total_rch_slots // 8) as $slots
    | ($case[0].proof_cache_pressure_level // "low") as $pressure
    | {
        warm_target_prefetch_roi_advisory_json:{
          schema_version:"franken-engine.swarm-warm-target-prefetch-roi-advisory.v1",
          decision:"pass",
          advisory:"reuse_hot_cache",
          recommended_action:"reuse_warm_target",
          warm_target_summary:{target_dir:"/tmp/franken-engine-rch-target",worker_id:$worker_id},
          mutation_policy:{runs_cargo:false,runs_rch:false,mutates_remote_workers:false,changes_live_queue_policy:false,pins_workers_automatically:false,rebinds_hosts_automatically:false,deletes_or_overwrites_target_dirs:false}
        },
        proof_cache_plan_json:{
          schema_version:"franken-engine.proof-reuse-cache-plan.v1",
          proof_cache_decision:(if $pressure == "high" or $pressure == "critical" then "refresh_required" else "cache_hit" end),
          cache_hit_artifacts:[{artifact_id:"fixture-proof-cache-hit",artifact_path:"proof/cache/hit.json"}],
          required_refreshes:[]
        },
        archive_pressure_scoreboard_json:{
          schema_version:"franken-engine.remote-proof-archive-pressure-scoreboard.v1",
          advisory:(if $pressure == "high" or $pressure == "critical" then "refresh_required" else "reuse" end),
          pressure_level:$pressure,
          recommended_action:(if $pressure == "high" or $pressure == "critical" then "refresh_archive_evidence" else "reuse_warm_target" end)
        },
        worker_truth_report_json:{
          schema_version:"franken-engine.rch-worker-truth-parity-report.v1",
          decision:"pass",
          findings:[],
          worker_rows:[{worker_id:$worker_id,daemon_status:"idle",probe_schedulable:true}]
        },
        swarm_resource_envelope_json:{
          schema_version:"franken-engine.swarm-resource-envelope.v1",
          decision:"pass",
          readiness:"ready",
          host_profile:"64c_256g",
          capacity_budget:{remote_rch_slot_limit:$slots},
          memory_pressure:{total_bytes:274877906944},
          active_target_locks:[],
          mutation_policy:{runs_cargo:false,runs_rch:false,mutates_remote_workers:false,changes_live_queue_policy:false}
        },
        swarm_topology_placement_plan_json:{
          schema_version:"franken-engine.swarm-topology-placement-plan.v1",
          decision:"pass",
          recommended_topology_class:"warm-cache",
          warm_cache_residency_state:"warm",
          recommended_worker_targets:[{worker_id:$worker_id,target_dir:"/tmp/franken-engine-rch-target"}],
          fail_closed_reasons:[],
          mutation_policy:{runs_cargo:false,runs_rch:false,mutates_remote_workers:false,changes_live_queue_policy:false,pins_workers_automatically:false,rebinds_hosts_automatically:false,deletes_or_overwrites_target_dirs:false}
        },
        swarm_topology_placement_receipt_json:{
          schema_version:"franken-engine.swarm-topology-placement-receipt.v1",
          decision:"pass",
          adoption_status:"adopted",
          receipt_id:"fixture-topology-receipt",
          recommended_worker_ids:[$worker_id],
          fail_closed_reasons:[],
          mutation_policy:{runs_cargo:false,runs_rch:false,mutates_remote_workers:false,changes_live_queue_policy:false,pins_workers_automatically:false,rebinds_hosts_automatically:false,deletes_or_overwrites_target_dirs:false}
        },
        swarm_topology_placement_evidence_ledger_json:{
          schema_version:"franken-engine.swarm-topology-placement-evidence-ledger.v1",
          decision:"pass",
          entries:[]
        }
      }' >"${inputs_dir}/locality_adapter_inputs.json"
for field in warm_target_prefetch_roi_advisory_json proof_cache_plan_json archive_pressure_scoreboard_json worker_truth_report_json swarm_resource_envelope_json swarm_topology_placement_plan_json swarm_topology_placement_receipt_json swarm_topology_placement_evidence_ledger_json; do
  jq --arg field "$field" '.[$field]' "${inputs_dir}/locality_adapter_inputs.json" >"${inputs_dir}/${field}.json"
done

locality_out="${stages_dir}/locality_plan/out"
run_stage "locality_plan" bash "${root_dir}/scripts/swarm_proof_cache_locality_optimizer.sh" \
  --admission-budget-plan-json "${run_dir}/admission_plan.json" \
  --warm-target-prefetch-roi-advisory-json "${inputs_dir}/warm_target_prefetch_roi_advisory_json.json" \
  --proof-cache-plan-json "${inputs_dir}/proof_cache_plan_json.json" \
  --archive-pressure-scoreboard-json "${inputs_dir}/archive_pressure_scoreboard_json.json" \
  --worker-truth-report-json "${inputs_dir}/worker_truth_report_json.json" \
  --swarm-resource-envelope-json "${inputs_dir}/swarm_resource_envelope_json.json" \
  --swarm-topology-placement-plan-json "${inputs_dir}/swarm_topology_placement_plan_json.json" \
  --swarm-topology-placement-receipt-json "${inputs_dir}/swarm_topology_placement_receipt_json.json" \
  --swarm-topology-placement-evidence-ledger-json "${inputs_dir}/swarm_topology_placement_evidence_ledger_json.json" \
  --source-revision "$source_revision" \
  --output-dir "$locality_out"
cp "${locality_out}/locality_plan.json" "${run_dir}/locality_plan.json"

dashboard_out="${stages_dir}/dashboard_bundle/out"
run_stage "dashboard_bundle" bash "${root_dir}/scripts/swarm_frankentui_dashboard_bundle.sh" \
  --resource-envelope-json "${inputs_dir}/swarm_resource_envelope_json.json" \
  --admission-budget-plan-json "${run_dir}/admission_plan.json" \
  --stale-recovery-receipts-json "${run_dir}/recovery_receipts.json" \
  --worker-truth-report-json "${inputs_dir}/worker_truth_report_json.json" \
  --proof-cache-locality-plan-json "${run_dir}/locality_plan.json" \
  --rch-rehabilitation-ledger-json "${run_dir}/rch_rehab_ledger.json" \
  --source-revision "$source_revision" \
  --output-dir "$dashboard_out"
cp "${dashboard_out}/dashboard_bundle.json" "${run_dir}/dashboard_bundle.json"

jq -n \
  --slurpfile state "${run_dir}/state_snapshot.json" \
  --slurpfile admission "${run_dir}/admission_plan.json" \
  --slurpfile case "$case_json" '
    def heavy($lane): ($lane.lane_class // "") == "heavy";
    (($admission[0].admitted_lanes // []) + ($admission[0].deferred_lanes // []) + ($admission[0].blocked_lanes // [])) as $lanes
    | {
        schema_version:"franken-engine.swarm-saturation-replay-scenario.v1",
        scenario_id:($case[0].case_id // "live"),
        host:{profile:"64c_256gb",remote_rch_slots:($state[0].capacity_envelope.total_rch_slots // 0)},
        constraints:{
          heavy_fanout_cap:($state[0].capacity_envelope.max_parallel_heavy_lanes // 4),
          urgent_slack_slots:1,
          max_heavy_per_agent:1
        },
        evidence:{local_fallback_observed:($state[0].components.rch.local_fallback_observed // false)},
        requests:($lanes | map({
          request_id:(.lane_id // .bead_id // "lane"),
          agent_id:(.agent_id // "BrownCreek"),
          bead_id:(.bead_id // .lane_id // "unknown"),
          priority:(.priority // 2),
          urgent:((.priority // 2) <= 1),
          command_class:(if heavy(.) then "cargo_check" else "script_gate" end),
          owner_state:(if (.reason // "") == "reservation_conflict" then "blocked" else "healthy" end),
          before_decision:"requested"
        })),
        mutation_policy:{fixture_fed_only:true,runs_cargo:false,runs_rch:false,mutates_remote_workers:false,mutates_br:false}
      }' >"${inputs_dir}/saturation_scenario.json"

saturation_out="${stages_dir}/saturation_replay/out"
run_stage "saturation_replay" bash "${root_dir}/scripts/swarm_saturation_replay_drill.sh" \
  --scenario-json "${inputs_dir}/saturation_scenario.json" \
  --source-revision "$source_revision" \
  --output-dir "$saturation_out"
cp "${saturation_out}/saturation_replay_report.json" "${run_dir}/saturation_replay_report.json"

jq -n \
  --slurpfile state "${run_dir}/state_snapshot.json" \
  --slurpfile locality "${run_dir}/locality_plan.json" '
    {
      schema_version:"franken-engine.swarm-slo-gate-input.v1",
      tracker_age_seconds:(if (($state[0].fail_closed_reasons // []) | index("stale_bv_due_to_br_sync") != null) then 9999 else 120 end),
      unknown_dirty_file_count:($state[0].components.git.unowned_dirty_count // 0),
      proof_cache_pressure_level:($locality[0].archive_summary.pressure_level // "low"),
      thresholds:{
        max_admitted_heavy_lanes:($state[0].capacity_envelope.max_parallel_heavy_lanes // 4),
        min_free_rch_slots:1,
        max_stale_progress_seconds:900,
        max_stale_tracker_age_seconds:600,
        max_unknown_dirty_files:0,
        max_proof_cache_pressure_rank:3
      }
    }' >"${inputs_dir}/slo_input.json"

slo_out="${stages_dir}/slo_gate/out"
run_stage "slo_gate" bash "${root_dir}/scripts/swarm_slo_gate.sh" \
  --slo-input-json "${inputs_dir}/slo_input.json" \
  --admission-budget-plan-json "${run_dir}/admission_plan.json" \
  --rch-rehabilitation-ledger-json "${run_dir}/rch_rehab_ledger.json" \
  --proof-cache-locality-plan-json "${run_dir}/locality_plan.json" \
  --saturation-replay-report-json "${run_dir}/saturation_replay_report.json" \
  --source-revision "$source_revision" \
  --output-dir "$slo_out"
cp "${slo_out}/slo_gate_report.json" "${run_dir}/slo_gate_report.json"

write_truth_report "$run_dir" "$run_dir"
decision="$(jq -r '.decision' "$truth_report_path")"
write_event "swarm_ops_no_mock_drill" "truth_gate_emitted" "$decision" "" "$truth_report_path"

printf 'run_manifest_json=%s\n' "$manifest_path"
printf 'truth_gate_report_json=%s\n' "$truth_report_path"
printf 'trace_ids_json=%s\n' "$trace_ids_path"

case "$decision" in
  fail_closed) exit 42 ;;
  blocked) exit 75 ;;
  *) exit 0 ;;
esac
