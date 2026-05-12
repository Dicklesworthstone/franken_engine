#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${PROOF_ECONOMY_CONTROL_TOWER_DRILL_ROOT:-${TMPDIR:-/tmp}/franken-engine-proof-economy-control-tower-drill}"
run_id="${PROOF_ECONOMY_CONTROL_TOWER_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${PROOF_ECONOMY_CONTROL_TOWER_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-run}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

fixtures_json="${root_dir}/scripts/testdata/proof_economy_control_tower_no_mock_drill/cases.json"
contract_path="${root_dir}/docs/proof_economy_control_tower_no_mock_drill_contract_v1.json"
docs_path="${root_dir}/docs/PROOF_ECONOMY_CONTROL_TOWER_NO_MOCK_DRILL.md"
replay_run_dir=""
scenario_filter=""
source_revision="${PROOF_ECONOMY_CONTROL_TOWER_DRILL_SOURCE_REVISION:-}"
failures=0

proof_reuse_script="${root_dir}/scripts/proof_reuse_admission_bundle.sh"
tail_rescue_script="${root_dir}/scripts/proof_queue_tail_latency_rescue_gate.sh"
agent_index_script="${root_dir}/scripts/agent_run_evidence_index.sh"
control_tower_script="${root_dir}/scripts/proof_economy_control_tower.sh"

run_manifest_path=""
events_path=""
commands_path=""
trace_ids_path=""
operator_report_path=""
case_results_path=""
report_md_path=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/proof_economy_control_tower_no_mock_drill.sh [check|run|replay|selftest] [OPTIONS]

Options:
  --fixtures-json FILE
  --scenario-id ID
  --replay-run-dir DIR
  --output-dir DIR
  --source-revision REV

The drill is fixture-fed and read-only. It invokes the real proof reuse
admission, tail-latency rescue, agent-run evidence index, and proof-economy
control tower scripts on preserved br/git/mail/rch/artifact snapshots.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --fixtures-json)
      fixtures_json="${2:-}"
      shift 2
      ;;
    --scenario-id)
      scenario_filter="${2:-}"
      shift 2
      ;;
    --replay-run-dir)
      replay_run_dir="${2:-}"
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
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for proof-economy control tower drill\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for proof-economy control tower drill\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

refresh_paths() {
  run_manifest_path="${run_dir}/run_manifest.json"
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  trace_ids_path="${run_dir}/trace_ids.json"
  operator_report_path="${run_dir}/operator_report.json"
  case_results_path="${run_dir}/case_results.jsonl"
  report_md_path="${run_dir}/report.md"
}

record_pass() {
  printf 'PASS proof-economy-control-tower-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL proof-economy-control-tower-no-mock-drill %s\n' "$1" >&2
  failures=$((failures + 1))
}

render_command() {
  local rendered="" arg quoted
  for arg in "$@"; do
    printf -v quoted '%q' "$arg"
    rendered+="${rendered:+ }${quoted}"
  done
  printf '%s' "$rendered"
}

ensure_run_dir() {
  mkdir -p "$run_dir"
  run_dir="$(cd "$run_dir" && pwd)"
  refresh_paths

  local artifact
  for artifact in "$run_manifest_path" "$events_path" "$commands_path" "$trace_ids_path" "$operator_report_path" "$case_results_path" "$report_md_path"; do
    if [[ -e "$artifact" ]]; then
      printf 'refusing to overwrite existing drill artifact: %s\n' "$artifact" >&2
      exit 73
    fi
  done

  : >"$events_path"
  : >"$commands_path"
  : >"$case_results_path"
}

log_command() {
  render_command "$@" >>"$commands_path"
  printf '\n' >>"$commands_path"
}

write_event() {
  local scenario_id="$1"
  local component="$2"
  local event_name="$3"
  local outcome="$4"
  local exit_code="$5"
  local artifact_path="$6"
  local detail="$7"

  jq -nc \
    --arg schema_version "franken-engine.proof-economy-control-tower-no-mock-drill.event.v1" \
    --arg scenario_id "$scenario_id" \
    --arg component "$component" \
    --arg event_name "$event_name" \
    --arg outcome "$outcome" \
    --arg artifact_path "$artifact_path" \
    --arg detail "$detail" \
    --arg source_revision "$source_revision" \
    --argjson exit_code "$exit_code" \
    '{
      schema_version:$schema_version,
      scenario_id:$scenario_id,
      component:$component,
      event_name:$event_name,
      outcome:$outcome,
      exit_code:$exit_code,
      artifact_path:(if $artifact_path == "" then null else $artifact_path end),
      detail:$detail,
      source_revision:$source_revision
    }' >>"$events_path"
}

exit_code_is_expected() {
  local actual="$1"
  local expected_csv="$2"
  local expected
  IFS=',' read -r -a expected_list <<<"$expected_csv"
  for expected in "${expected_list[@]}"; do
    if [[ "$actual" == "$expected" ]]; then
      return 0
    fi
  done
  return 1
}

run_step() {
  local scenario_id="$1"
  local component="$2"
  local expected_codes="$3"
  shift 3
  local step_dir="${run_dir}/cases/${scenario_id}/steps/${component}"
  local stdout_path="${step_dir}/stdout.log"
  local stderr_path="${step_dir}/stderr.log"
  local exit_code

  mkdir -p "$step_dir"
  log_command "$@"
  write_event "$scenario_id" "$component" "started" "running" -1 "$step_dir" "command started"

  set +e
  (cd "$root_dir" && "$@") >"$stdout_path" 2>"$stderr_path"
  exit_code=$?
  set -e

  if exit_code_is_expected "$exit_code" "$expected_codes"; then
    write_event "$scenario_id" "$component" "finished" "pass" "$exit_code" "$step_dir" "command exit matched expected set"
    return 0
  fi

  write_event "$scenario_id" "$component" "finished" "fail" "$exit_code" "$stderr_path" "unexpected command exit"
  printf 'scenario %s component %s expected exit %s, got %s\n' "$scenario_id" "$component" "$expected_codes" "$exit_code" >&2
  sed -n '1,120p' "$stderr_path" >&2
  return 1
}

write_run_manifest() {
  # shellcheck disable=SC2094
  # shellcheck disable=SC2094
  jq -n \
    --arg schema_version "franken-engine.proof-economy-control-tower-no-mock-drill.run-manifest.v1" \
    --arg run_id "$run_id" \
    --arg mode "$mode" \
    --arg source_revision "$source_revision" \
    --arg fixtures_json "$fixtures_json" \
    --arg replay_command "./scripts/e2e/proof_economy_control_tower_no_mock_drill.sh replay --replay-run-dir ${run_dir}" \
    '{
      schema_version:$schema_version,
      run_id:$run_id,
      mode:$mode,
      source_revision:$source_revision,
      fixtures_json:$fixtures_json,
      replay_command:$replay_command,
      required_artifacts:[
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "trace_ids.json",
        "operator_report.json",
        "report.md"
      ],
      component_scripts:[
        "scripts/proof_reuse_admission_bundle.sh",
        "scripts/proof_queue_tail_latency_rescue_gate.sh",
        "scripts/agent_run_evidence_index.sh",
        "scripts/proof_economy_control_tower.sh"
      ],
      mutation_policy:{
        fixture_fed_only:true,
        proof_only:true,
        advisory_only:true,
        queries_live_agent_mail:false,
        mutates_br:false,
        releases_reservations:false,
        sends_agent_mail:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false
      }
    }' >"$run_manifest_path"
}

case_json() {
  local scenario_id="$1"
  jq -c --arg scenario_id "$scenario_id" '.cases[] | select(.case_id == $scenario_id)' "$fixtures_json"
}

case_source() {
  local scenario_id="$1"
  local source_name="$2"
  local output_path="$3"

  jq --arg scenario_id "$scenario_id" --arg source_name "$source_name" '
    . as $root
    | ($root.cases[] | select(.case_id == $scenario_id)) as $case
    | if (($case.sources // {}) | has($source_name)) then
        $case.sources[$source_name]
      else
        $root.base_sources[$source_name]
      end
  ' "$fixtures_json" >"$output_path"
}

case_expected_value() {
  local scenario_id="$1"
  local path="$2"
  jq -r --arg scenario_id "$scenario_id" --arg path "$path" '
    ($path | split(".")) as $parts
    | (.cases[] | select(.case_id == $scenario_id)) as $case
    | reduce $parts[] as $part ($case; .[$part])
  ' "$fixtures_json"
}

write_component_sources() {
  local scenario_id="$1"
  local snapshots_dir="$2"
  local artifact_snapshot="${snapshots_dir}/artifact_snapshot.json"
  local i freshness_count

  mkdir -p "$snapshots_dir"
  case_source "$scenario_id" br_snapshot_json "${snapshots_dir}/br_snapshot.json"
  case_source "$scenario_id" git_snapshot_json "${snapshots_dir}/git_snapshot.json"
  case_source "$scenario_id" mail_health_json "${snapshots_dir}/mail_health.json"
  case_source "$scenario_id" rch_log_json "${snapshots_dir}/rch_log.json"
  case_source "$scenario_id" artifact_snapshot_json "$artifact_snapshot"
  case_source "$scenario_id" replay_trace_json "${snapshots_dir}/replay_trace.json"
  case_source "$scenario_id" counterfactual_report_json "${snapshots_dir}/counterfactual_report.json"
  case_source "$scenario_id" tail_latency_report_json "${snapshots_dir}/tail_latency_report.json"
  case_source "$scenario_id" advisory_mutation_snapshot_json "${snapshots_dir}/advisory_mutation_snapshot.json"

  jq '.proof_index_json' "$artifact_snapshot" >"${snapshots_dir}/proof_index.json"
  freshness_count="$(jq '.freshness_reports | length' "$artifact_snapshot")"
  for ((i = 0; i < freshness_count; i++)); do
    jq --argjson i "$i" '.freshness_reports[$i]' "$artifact_snapshot" >"${snapshots_dir}/freshness-${i}.json"
  done
}

write_agent_run_snapshot() {
  local scenario_id="$1"
  local snapshots_dir="$2"
  local complete_expected
  local output_path="${snapshots_dir}/agent_run_snapshot.json"
  complete_expected="$(case_expected_value "$scenario_id" "complete_run_expected")"

  jq -n \
    --slurpfile br "${snapshots_dir}/br_snapshot.json" \
    --slurpfile git "${snapshots_dir}/git_snapshot.json" \
    --slurpfile mail "${snapshots_dir}/mail_health.json" \
    --slurpfile rch "${snapshots_dir}/rch_log.json" \
    --arg scenario_id "$scenario_id" \
    --arg source_revision "$source_revision" \
    --argjson complete_run_expected "$complete_expected" \
    '
    ($br[0]) as $brs
    | ($git[0]) as $gits
    | ($mail[0]) as $mail
    | ($rch[0]) as $rch
    | (($mail.state // $mail.status // "unknown") == "healthy") as $mail_ok
    | {
        schema_version:"franken-engine.agent-run-evidence-index.snapshot.v1",
        case_id:$scenario_id,
        bead_id:"bd-operator",
        agent_name:"CreamRobin",
        source_revision:$source_revision,
        complete_run_expected:$complete_run_expected,
        sources:{
          br_issue_json:($brs.issues // []),
          br_ready_json:{issues:($brs.ready_issues // [])},
          br_sync_status_json:($brs.sync_status // {dirty_count:0, db_newer:false, jsonl_newer:false}),
          bv_actionable_plan_json:($brs.bv_plan // {plan:{tracks:[{track_id:"proof-economy-control-tower",items:[{id:"bd-operator",status:"closed"}]}]}}),
          agent_mail_profiles_json:(if $mail_ok then {agents:[{name:"CreamRobin",last_active_ts:"2026-05-12T00:00:00Z",task_description:"proof-economy control tower drill"}]} else null end),
          agent_mail_messages_json:(if $mail_ok then {messages:[{id:1,thread_id:"bd-operator",from:"CreamRobin",ack_required:true,ack_ts:"2026-05-12T00:01:00Z",subject:"Claimed bd-operator proof economy drill"}]} else null end),
          file_reservations_json:{reservations:($brs.file_reservations // [])},
          declared_write_set_json:{paths:($gits.write_set_paths // [])},
          git_status_json:{paths:($gits.dirty_paths // [])},
          git_closeout_commits_json:{commits:($gits.commits // [])},
          rch_validation_artifacts_json:{artifacts:($rch.validation_artifacts // $rch.artifacts // [])},
          validation_commands_json:{commands:($rch.validation_commands // [{display:"jq empty docs/proof_economy_control_tower_no_mock_drill_contract_v1.json",exit_code:0}])},
          operator_status_json:{schema_version:"franken-engine.swarm-predictive-dashboard.v1",status:"ok",summary:{proof_economy_control_tower:"fixture-fed"}}
        }
      }
    ' >"$output_path"
}

run_proof_reuse() {
  local scenario_id="$1"
  local snapshots_dir="$2"
  local output_dir="$3"
  local case_data freshness_count i changed_count changed_path
  local expected_source_revision

  case_data="$(case_json "$scenario_id")"
  expected_source_revision="$(jq -r '.expected_source_revision' <<<"$case_data")"
  freshness_count="$(jq '.sources.artifact_snapshot_json.freshness_reports // empty | length' <<<"$case_data" 2>/dev/null || jq '.base_sources.artifact_snapshot_json.freshness_reports | length' "$fixtures_json")"
  if ! [[ "$freshness_count" =~ ^[0-9]+$ ]]; then
    freshness_count="$(jq '.freshness_reports | length' "${snapshots_dir}/artifact_snapshot.json")"
  fi

  local args=(
    bash "$proof_reuse_script"
    --proof-index-json "${snapshots_dir}/proof_index.json"
    --expected-source-revision "$expected_source_revision"
    --source-revision "$source_revision"
    --output-dir "$output_dir"
  )

  for ((i = 0; i < freshness_count; i++)); do
    args+=(--freshness-report "${snapshots_dir}/freshness-${i}.json")
  done

  changed_count="$(jq '.changed_paths | length' <<<"$case_data")"
  for ((i = 0; i < changed_count; i++)); do
    changed_path="$(jq -r --argjson i "$i" '.changed_paths[$i]' <<<"$case_data")"
    args+=(--changed-path "$changed_path")
  done

  run_step "$scenario_id" "proof-reuse-admission" "0,42" "${args[@]}"
}

run_tail_rescue() {
  local scenario_id="$1"
  local snapshots_dir="$2"
  local output_dir="$3"
  local case_data max_share

  case_data="$(case_json "$scenario_id")"
  max_share="$(jq -r '.max_agent_share_millionths' <<<"$case_data")"
  run_step "$scenario_id" "tail-latency-rescue" "0,42" \
    bash "$tail_rescue_script" \
      --replay-trace-json "${snapshots_dir}/replay_trace.json" \
      --counterfactual-report-json "${snapshots_dir}/counterfactual_report.json" \
      --tail-latency-report-json "${snapshots_dir}/tail_latency_report.json" \
      --max-agent-share-millionths "$max_share" \
      --source-revision "$source_revision" \
      --generated-epoch-seconds 1800000000 \
      --output-dir "$output_dir"
}

run_agent_index() {
  local scenario_id="$1"
  local snapshots_dir="$2"
  local output_dir="$3"

  write_agent_run_snapshot "$scenario_id" "$snapshots_dir"
  run_step "$scenario_id" "agent-run-evidence-index" "0,42" \
    bash "$agent_index_script" \
      --run-snapshot-json "${snapshots_dir}/agent_run_snapshot.json" \
      --source-revision "$source_revision" \
      --output-dir "$output_dir"
}

run_control_tower() {
  local scenario_id="$1"
  local components_dir="$2"
  local output_dir="$3"

  run_step "$scenario_id" "proof-economy-control-tower" "0,42" \
    bash "$control_tower_script" \
      --proof-reuse-admission-json "${components_dir}/proof_reuse_admission/proof_reuse_admission_bundle.json" \
      --tail-latency-rescue-json "${components_dir}/tail_latency_rescue/tail_latency_rescue_receipt.json" \
      --agent-run-evidence-index-json "${components_dir}/agent_run_evidence_index/agent_run_evidence_index.json" \
      --source-revision "$source_revision" \
      --output-dir "$output_dir"
}

require_file() {
  local path="$1"
  local label="$2"
  if [[ ! -s "$path" ]]; then
    record_failure "missing ${label}: ${path}"
    return 1
  fi
  return 0
}

assert_json_schema() {
  local path="$1"
  local schema="$2"
  local label="$3"
  require_file "$path" "$label" || return 1
  jq -e --arg schema "$schema" '.schema_version == $schema' "$path" >/dev/null \
    || record_failure "${label} schema mismatch"
}

write_case_report() {
  local scenario_id="$1"
  local case_dir="$2"
  local snapshots_dir="${case_dir}/snapshots"
  local components_dir="${case_dir}/components"
  local case_report="${case_dir}/operator_case_report.json"
  local expected_decision
  expected_decision="$(case_expected_value "$scenario_id" "expected.decision")"

  assert_json_schema "${components_dir}/proof_reuse_admission/proof_reuse_admission_bundle.json" "franken-engine.proof-reuse-admission-bundle.v1" "${scenario_id} proof reuse report"
  assert_json_schema "${components_dir}/tail_latency_rescue/tail_latency_rescue_receipt.json" "franken-engine.proof-queue-tail-latency-rescue-receipt.v1" "${scenario_id} tail-latency report"
  assert_json_schema "${components_dir}/agent_run_evidence_index/agent_run_evidence_index.json" "franken-engine.agent-run-evidence-index.v1" "${scenario_id} agent evidence index"
  assert_json_schema "${components_dir}/control_tower/proof_economy_control_tower_report.json" "franken-engine.proof-economy-control-tower-report.v1" "${scenario_id} control tower report"

  # shellcheck disable=SC2094
  jq -n \
    --slurpfile reuse "${components_dir}/proof_reuse_admission/proof_reuse_admission_bundle.json" \
    --slurpfile tail "${components_dir}/tail_latency_rescue/tail_latency_rescue_receipt.json" \
    --slurpfile agent "${components_dir}/agent_run_evidence_index/agent_run_evidence_index.json" \
    --slurpfile tower "${components_dir}/control_tower/proof_economy_control_tower_report.json" \
    --slurpfile anomalies "${components_dir}/agent_run_evidence_index/causal_trace_graph/swarm_agent_causal_trace_anomalies.json" \
    --slurpfile mail "${snapshots_dir}/mail_health.json" \
    --slurpfile rch "${snapshots_dir}/rch_log.json" \
    --slurpfile mutation "${snapshots_dir}/advisory_mutation_snapshot.json" \
    --arg schema_version "franken-engine.proof-economy-control-tower-no-mock-drill.case-report.v1" \
    --arg scenario_id "$scenario_id" \
    --arg expected_decision "$expected_decision" \
    --arg case_report "$case_report" \
    --arg proof_reuse_json "${components_dir}/proof_reuse_admission/proof_reuse_admission_bundle.json" \
    --arg tail_json "${components_dir}/tail_latency_rescue/tail_latency_rescue_receipt.json" \
    --arg agent_index_json "${components_dir}/agent_run_evidence_index/agent_run_evidence_index.json" \
    --arg control_tower_json "${components_dir}/control_tower/proof_economy_control_tower_report.json" \
    '
    def arr($v): if ($v | type) == "array" then $v else [] end;
    def duplicate_reuse_without_hash($rows):
      ([arr($rows)[] | {
        key:((.artifact_id // "") + "|" + (.command_fingerprint // "")),
        source_hash_ok:(.compatibility.source_hash_ok // false)
      }]
      | sort_by(.key)
      | group_by(.key)
      | any(. as $g | ($g | length) > 1 and any($g[]; .source_hash_ok != true)));
    def timeout_jobs: [arr($rch[0].jobs)[] | select((.status // "") == "timeout" or (.timed_out // false) == true)];
    def local_fallback:
      (any(arr($rch[0].validation_artifacts)[]?; (.local_fallback_detected // false) == true)
       or any(arr($anomalies[0].anomalies)[]?; (.anomaly_class // "") | test("local_.*fallback")));
    def mutation_attempts: arr($mutation[0].attempted_mutations);
    def degraded_mail:
      (($mail[0].state // $mail[0].status // "unknown") != "healthy");
    def finding($code; $severity; $message; $remediation):
      {code:$code,severity:$severity,message:$message,remediation:$remediation};
    ([
      if duplicate_reuse_without_hash($reuse[0].admission_rows) then
        finding("duplicate_proof_reuse_without_source_hash"; "error"; "duplicate proof reuse row lacks a matching source hash"; "Refresh the proof through rch with a source-hash-matched manifest before admitting reuse.")
      else empty end,
      if local_fallback then
        finding("local_cargo_fallback_detected"; "error"; "rch evidence shows local fallback contamination"; "Discard the local fallback proof and rerun the command through rch with an isolated CARGO_TARGET_DIR.")
      else empty end,
      if (mutation_attempts | length) > 0 then
        finding("advisory_mutation_attempt"; "error"; "snapshot contains mutation attempts while the drill is advisory-only"; "Stop the drill and require explicit operator approval before any br, reservation, Agent Mail, queue, or worker mutation.")
      else empty end,
      if any(arr($agent[0].fail_closed_reasons)[]?; (.code // "") == "complete_run_missing_artifact_manifest") then
        finding("missing_rch_manifest"; "error"; "complete run snapshot is missing an RCH artifact manifest"; "Require run_manifest.json or a hashed artifact manifest before closing the proof lane.")
      else empty end
    ]) as $fail_findings
    | ([
      if degraded_mail then
        finding("agent_mail_degraded"; "warning"; ($mail[0].message // "Agent Mail snapshot is degraded or unavailable"); ($mail[0].remediation // "Use br ownership as the soft lock and keep mail evidence degraded until health recovers."))
      else empty end,
      if ((timeout_jobs | length) > 0) then
        finding("rch_timeout"; "warning"; (timeout_jobs[0].message // "rch proof command timed out"); (timeout_jobs[0].remediation // "Split or rerun the timed-out proof through rch before admitting reuse."))
      else empty end
    ]) as $degraded_findings
    | ($tower[0].decision // "unknown") as $tower_decision
    | (if (($fail_findings | length) > 0) or $tower_decision == "fail_closed" then "fail_closed"
       elif (($degraded_findings | length) > 0) or $tower_decision == "degraded" then "degraded"
       else "pass" end) as $decision
    | {
        schema_version:$schema_version,
        scenario_id:$scenario_id,
        expected_decision:$expected_decision,
        decision:$decision,
        matches_expected:($decision == $expected_decision),
        control_tower_decision:$tower_decision,
        component_decisions:{
          proof_reuse_admission:($reuse[0].admission_decision // "unknown"),
          tail_latency_rescue:($tail[0].decision // "unknown"),
          agent_run_evidence_index:($agent[0].decision // "unknown")
        },
        fail_closed_findings:$fail_findings,
        degraded_findings:$degraded_findings,
        mutation_policy:{
          fixture_fed_only:true,
          proof_only:true,
          advisory_only:true,
          queries_live_agent_mail:false,
          mutates_br:false,
          releases_reservations:false,
          sends_agent_mail:false,
          runs_cargo:false,
          runs_rch:false,
          mutates_remote_workers:false,
          changes_live_queue_policy:false
        },
        subordinate_reports:{
          proof_reuse_admission_json:$proof_reuse_json,
          tail_latency_rescue_json:$tail_json,
          agent_run_evidence_index_json:$agent_index_json,
          proof_economy_control_tower_json:$control_tower_json
        },
        artifact_paths:{
          operator_case_report_json:$case_report,
          snapshots_dir:"snapshots",
          steps_dir:"steps"
        }
      }
    ' >"$case_report"

  jq -e '.matches_expected == true' "$case_report" >/dev/null \
    || record_failure "${scenario_id} did not match expected drill decision"

  jq -c . "$case_report" >>"$case_results_path"
}

run_case() {
  local scenario_id="$1"
  local case_dir="${run_dir}/cases/${scenario_id}"
  local snapshots_dir="${case_dir}/snapshots"
  local components_dir="${case_dir}/components"

  write_event "$scenario_id" "case" "started" "running" -1 "$case_dir" "case started"
  write_component_sources "$scenario_id" "$snapshots_dir"
  run_proof_reuse "$scenario_id" "$snapshots_dir" "${components_dir}/proof_reuse_admission"
  run_tail_rescue "$scenario_id" "$snapshots_dir" "${components_dir}/tail_latency_rescue"
  run_agent_index "$scenario_id" "$snapshots_dir" "${components_dir}/agent_run_evidence_index"
  run_control_tower "$scenario_id" "$components_dir" "${components_dir}/control_tower"
  write_case_report "$scenario_id" "$case_dir"
  write_event "$scenario_id" "case" "finished" "pass" 0 "${case_dir}/operator_case_report.json" "case artifacts emitted"
}

write_trace_ids() {
  # shellcheck disable=SC2094
  jq -s \
    --arg schema_version "franken-engine.proof-economy-control-tower-no-mock-drill.trace-ids.v1" \
    --arg run_id "$run_id" \
    '{
      schema_version:$schema_version,
      run_id:$run_id,
      cases:map({
        scenario_id:.scenario_id,
        decision:.decision,
        control_tower_decision:.control_tower_decision,
        component_decisions:.component_decisions,
        subordinate_reports:.subordinate_reports
      })
    }' "$case_results_path" >"$trace_ids_path"
}

write_operator_report() {
  # shellcheck disable=SC2094
  jq -s \
    --arg schema_version "franken-engine.proof-economy-control-tower-no-mock-drill.operator-report.v1" \
    --arg run_id "$run_id" \
    --arg source_revision "$source_revision" \
    --arg run_manifest_json "$run_manifest_path" \
    --arg events_jsonl "$events_path" \
    --arg commands_txt "$commands_path" \
    --arg trace_ids_json "$trace_ids_path" \
    --arg operator_report_json "$operator_report_path" \
    --arg report_md "$report_md_path" \
    '{
      schema_version:$schema_version,
      run_id:$run_id,
      source_revision:$source_revision,
      decision:(if all(.[]; .matches_expected == true) then "pass" else "fail_closed" end),
      case_count:length,
      cases:.,
      coverage:{
        has_pass_case:any(.[]; .decision == "pass"),
        has_degraded_mail_and_rch_timeout:any(.[]; any(.degraded_findings[]?; .code == "agent_mail_degraded") and any(.degraded_findings[]?; .code == "rch_timeout")),
        fails_closed_missing_manifest:any(.[]; any(.fail_closed_findings[]?; .code == "missing_rch_manifest")),
        fails_closed_local_cargo_fallback:any(.[]; any(.fail_closed_findings[]?; .code == "local_cargo_fallback_detected")),
        fails_closed_duplicate_without_source_hash:any(.[]; any(.fail_closed_findings[]?; .code == "duplicate_proof_reuse_without_source_hash")),
        fails_closed_advisory_mutation:any(.[]; any(.fail_closed_findings[]?; .code == "advisory_mutation_attempt"))
      },
      mutation_policy:{
        fixture_fed_only:true,
        proof_only:true,
        advisory_only:true,
        queries_live_agent_mail:false,
        mutates_br:false,
        releases_reservations:false,
        sends_agent_mail:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false
      },
      artifact_paths:{
        run_manifest_json:$run_manifest_json,
        events_jsonl:$events_jsonl,
        commands_txt:$commands_txt,
        trace_ids_json:$trace_ids_json,
        operator_report_json:$operator_report_json,
        report_md:$report_md
      }
    }' "$case_results_path" >"$operator_report_path"

  jq -e '
    .decision == "pass"
    and .coverage.has_pass_case == true
    and .coverage.has_degraded_mail_and_rch_timeout == true
    and .coverage.fails_closed_missing_manifest == true
    and .coverage.fails_closed_local_cargo_fallback == true
    and .coverage.fails_closed_duplicate_without_source_hash == true
    and .coverage.fails_closed_advisory_mutation == true
  ' "$operator_report_path" >/dev/null || record_failure "operator report coverage"
}

write_markdown_report() {
  {
    printf '# Proof Economy Control Tower No-Mock Drill\n\n'
    printf -- "- Run ID: \`%s\`\n" "$run_id"
    printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$operator_report_path")"
    printf -- "- Cases: \`%s\`\n\n" "$(jq -r '.case_count' "$operator_report_path")"
    jq -r '.cases[] | "- `" + .scenario_id + "`: decision=`" + .decision + "` expected=`" + .expected_decision + "`"' "$operator_report_path"
  } >"$report_md_path"
}

run_drill() {
  ensure_run_dir
  write_run_manifest

  local scenario_id
  while IFS= read -r scenario_id; do
    if [[ -n "$scenario_filter" && "$scenario_id" != "$scenario_filter" ]]; then
      continue
    fi
    run_case "$scenario_id"
  done < <(jq -r '.cases[].case_id' "$fixtures_json")

  write_trace_ids
  write_operator_report
  write_markdown_report

  if [[ "$failures" -ne 0 ]]; then
    exit 1
  fi
  record_pass "run"
  printf 'proof_economy_control_tower_no_mock_drill=%s\n' "$operator_report_path"
}

check_no_forbidden_mutation_words() {
  local path="$1"
  if grep -Eiq 'automatically mutates|automatically closes|automatically claims|repairs Agent Mail automatically|sends Agent Mail automatically|runs Cargo automatically|runs rch automatically|changes live queue policy' "$path"; then
    record_failure "${path#"$root_dir"/} contains forbidden mutation wording"
  fi
}

check_no_bare_heavy_cargo() {
  local path="$1"
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$command" != *"rch exec --"* || "$command" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "${path#"$root_dir"/} has bare heavy Cargo command: ${command}"
      fi
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,260p' "$path")
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.proof-economy-control-tower-no-mock-drill-contract.v1"
    and .bead_id == "bd-ksuqm"
    and .drill_script == "scripts/e2e/proof_economy_control_tower_no_mock_drill.sh"
    and (.component_scripts | index("scripts/proof_reuse_admission_bundle.sh") != null)
    and (.component_scripts | index("scripts/proof_queue_tail_latency_rescue_gate.sh") != null)
    and (.component_scripts | index("scripts/agent_run_evidence_index.sh") != null)
    and (.component_scripts | index("scripts/proof_economy_control_tower.sh") != null)
    and ([.required_fixture_cases[]] | sort) == ([
      "advisory_mutation_attempt_fail_closed",
      "duplicate_reuse_without_source_hash_fail_closed",
      "healthy_control_tower",
      "local_cargo_fallback_fail_closed",
      "mail_degraded_rch_timeout",
      "missing_manifest_fail_closed"
    ] | sort)
    and (.required_artifacts | index("run_manifest.json") != null)
    and (.required_artifacts | index("events.jsonl") != null)
    and (.required_artifacts | index("commands.txt") != null)
    and (.required_artifacts | index("trace_ids.json") != null)
    and (.required_artifacts | index("operator_report.json") != null)
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_br == false
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.proof-economy-control-tower-no-mock-drill-fixtures.v1"
    and ([.cases[].case_id] | sort) == ([
      "advisory_mutation_attempt_fail_closed",
      "duplicate_reuse_without_source_hash_fail_closed",
      "healthy_control_tower",
      "local_cargo_fallback_fail_closed",
      "mail_degraded_rch_timeout",
      "missing_manifest_fail_closed"
    ] | sort)
    and all(.cases[]; (.expected.decision | IN("pass","degraded","fail_closed")))
    and any(.cases[]; .expected.decision == "pass")
    and any(.cases[]; .case_id == "mail_degraded_rch_timeout" and .expected.decision == "degraded")
    and any(.cases[]; .expected.required_reason_code == "missing_rch_manifest")
    and any(.cases[]; .expected.required_reason_code == "local_cargo_fallback_detected")
    and any(.cases[]; .expected.required_reason_code == "duplicate_proof_reuse_without_source_hash")
    and any(.cases[]; .expected.required_reason_code == "advisory_mutation_attempt")
  ' "$fixtures_json" >/dev/null
}

docs_shape_ok() {
  grep -Fq "proof_reuse_admission_bundle.sh" "$docs_path" \
    && grep -Fq "proof_queue_tail_latency_rescue_gate.sh" "$docs_path" \
    && grep -Fq "agent_run_evidence_index.sh" "$docs_path" \
    && grep -Fq "proof_economy_control_tower.sh" "$docs_path" \
    && grep -Fq "run_manifest.json" "$docs_path" \
    && grep -Fq "replay" "$docs_path"
}

run_check() {
  jq empty "$contract_path" "$fixtures_json"
  bash -n "${BASH_SOURCE[0]}" "$proof_reuse_script" "$tail_rescue_script" "$agent_index_script" "$control_tower_script"
  contract_shape_ok || record_failure "contract shape"
  fixtures_shape_ok || record_failure "fixture shape"
  docs_shape_ok || record_failure "docs shape"
  check_no_forbidden_mutation_words "$docs_path"
  check_no_forbidden_mutation_words "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$contract_path"
  check_no_bare_heavy_cargo "${BASH_SOURCE[0]}"

  if [[ "$failures" -ne 0 ]]; then
    exit 1
  fi
  record_pass "check"
}

run_replay() {
  if [[ -z "$replay_run_dir" ]]; then
    printf 'replay mode requires --replay-run-dir\n' >&2
    exit 64
  fi
  mkdir -p "$run_dir"
  run_dir="$(cd "$run_dir" && pwd)"
  local replay_report="${run_dir}/replay_report.json"
  local required

  for required in run_manifest.json events.jsonl commands.txt trace_ids.json operator_report.json report.md; do
    if [[ ! -s "${replay_run_dir}/${required}" ]]; then
      printf 'replay source missing %s\n' "$required" >&2
      exit 42
    fi
  done

  jq empty "${replay_run_dir}/run_manifest.json" "${replay_run_dir}/trace_ids.json" "${replay_run_dir}/operator_report.json"

  while IFS= read -r required; do
    if [[ ! -s "$required" ]]; then
      printf 'replay source missing subordinate report %s\n' "$required" >&2
      exit 42
    fi
    jq empty "$required" >/dev/null
  done < <(jq -r '.cases[] | .subordinate_reports[]' "${replay_run_dir}/operator_report.json")

  # shellcheck disable=SC2094
  jq -n \
    --slurpfile report "${replay_run_dir}/operator_report.json" \
    --arg schema_version "franken-engine.proof-economy-control-tower-no-mock-drill.replay-report.v1" \
    --arg replay_run_dir "$replay_run_dir" \
    --arg replay_report "$replay_report" \
    '{
      schema_version:$schema_version,
      replay_run_dir:$replay_run_dir,
      replay_report_json:$replay_report,
      decision:(if $report[0].decision == "pass" then "pass" else "fail_closed" end),
      replay_verified:($report[0].decision == "pass"),
      coverage:$report[0].coverage,
      case_count:$report[0].case_count
    }' >"$replay_report"

  jq -e '.decision == "pass" and .replay_verified == true' "$replay_report" >/dev/null || exit 42
  record_pass "replay"
  printf 'proof_economy_control_tower_no_mock_drill_replay=%s\n' "$replay_report"
}

run_selftest() {
  local tmp_root run_out replay_out
  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/proof-economy-control-tower-drill.XXXXXX")"
  run_out="${tmp_root}/run"
  replay_out="${tmp_root}/replay"

  bash "${BASH_SOURCE[0]}" run --output-dir "$run_out" >/dev/null
  jq -e '
    .decision == "pass"
    and .case_count == 6
    and .coverage.has_degraded_mail_and_rch_timeout == true
    and .coverage.fails_closed_missing_manifest == true
    and .coverage.fails_closed_local_cargo_fallback == true
    and .coverage.fails_closed_duplicate_without_source_hash == true
    and .coverage.fails_closed_advisory_mutation == true
  ' "${run_out}/operator_report.json" >/dev/null

  bash "${BASH_SOURCE[0]}" replay --replay-run-dir "$run_out" --output-dir "$replay_out" >/dev/null
  jq -e '.decision == "pass" and .replay_verified == true' "${replay_out}/replay_report.json" >/dev/null
  record_pass "selftest"
  printf 'proof_economy_control_tower_no_mock_drill_artifacts=%s\n' "$tmp_root"
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_drill
    ;;
  replay)
    run_replay
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac
