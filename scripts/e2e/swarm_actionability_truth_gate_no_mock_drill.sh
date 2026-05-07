#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_ACTIONABILITY_NO_MOCK_DRILL_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-actionability-no-mock-drill}"
run_id="${SWARM_ACTIONABILITY_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_ACTIONABILITY_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-live}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

gate_script="${root_dir}/scripts/swarm_actionability_truth_gate.sh"
fixtures_json="${root_dir}/scripts/testdata/swarm_actionability_truth_gate/cases.json"
contract_path="${root_dir}/docs/swarm_actionability_truth_gate_no_mock_drill_contract_v1.json"
source_revision="${SWARM_ACTIONABILITY_NO_MOCK_DRILL_SOURCE_REVISION:-}"
scenario_filter=""
replay_run_dir=""
latest_from=""

run_manifest_path=""
source_snapshots_path=""
report_path=""
events_path=""
commands_path=""
truth_gate_report_path=""
case_results_path=""
report_md_path=""
trace_ids_path=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_actionability_truth_gate_no_mock_drill.sh [live|fixture|replay|check|selftest] [OPTIONS]

Options:
  --fixtures-json FILE
  --replay-run-dir DIR
  --latest-from DIR
  --scenario-id ID
  --output-dir DIR
  --source-revision REV
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --fixtures-json)
      fixtures_json="${2:-}"
      shift 2
      ;;
    --replay-run-dir)
      replay_run_dir="${2:-}"
      shift 2
      ;;
    --latest-from)
      latest_from="${2:-}"
      shift 2
      ;;
    --scenario-id)
      scenario_filter="${2:-}"
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
  printf 'jq is required for the swarm actionability no-mock drill\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

refresh_paths() {
  run_manifest_path="${run_dir}/run_manifest.json"
  source_snapshots_path="${run_dir}/source_snapshots.json"
  report_path="${run_dir}/actionability_report.json"
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  truth_gate_report_path="${run_dir}/truth_gate_report.json"
  case_results_path="${run_dir}/case_results.jsonl"
  report_md_path="${run_dir}/report.md"
  trace_ids_path="${run_dir}/trace_ids.json"
}

ensure_run_dir() {
  mkdir -p "$run_dir"
  run_dir="$(cd "$run_dir" && pwd)"
  refresh_paths
  : >"$events_path"
  : >"$commands_path"
  : >"$case_results_path"
}

record_pass() {
  printf 'PASS swarm-actionability-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-actionability-no-mock-drill %s\n' "$1" >&2
}

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
  local trace_id="$1"
  local component="$2"
  local event_name="$3"
  local outcome="$4"
  local error_code="$5"
  local evidence_path="$6"
  jq -nc \
    --arg schema_version "franken-engine.swarm-actionability-no-mock-drill.event.v1" \
    --arg trace_id "$trace_id" \
    --arg component "$component" \
    --arg event "$event_name" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    --arg evidence_path "$evidence_path" \
    '{
      schema_version:$schema_version,
      trace_id:$trace_id,
      component:$component,
      event:$event,
      outcome:$outcome,
      error_code:$error_code,
      evidence_path:$evidence_path
    }' >>"$events_path"
}

latest_bundle_dir() {
  local parent="$1"
  find "$parent" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' \
    | sort -n \
    | awk 'END {print $2}'
}

write_json_field() {
  local case_json="$1"
  local jq_expr="$2"
  local path="$3"
  jq "$jq_expr" <<<"$case_json" >"$path"
}

prepare_case_sources() {
  local case_json="$1"
  local scenario_dir="$2"
  local sources_dir="${scenario_dir}/sources"

  mkdir -p "$sources_dir"
  write_json_field "$case_json" '.sources.br_ready_json' "${sources_dir}/br_ready.json"
  write_json_field "$case_json" '.sources.br_open_json' "${sources_dir}/br_open.json"
  write_json_field "$case_json" '.sources.br_in_progress_json' "${sources_dir}/br_in_progress.json"
  write_json_field "$case_json" '.sources.br_blocked_json' "${sources_dir}/br_blocked.json"
  write_json_field "$case_json" '.sources.bv_robot_plan_json' "${sources_dir}/bv_plan.json"
  write_json_field "$case_json" '.sources.git_status_snapshot_json' "${sources_dir}/git_status.json"
  write_json_field "$case_json" '.sources.source_freshness_json' "${sources_dir}/source_freshness.json"
  if jq -e '.sources.agent_mail_snapshot_json != null' <<<"$case_json" >/dev/null; then
    write_json_field "$case_json" '.sources.agent_mail_snapshot_json' "${sources_dir}/agent_mail.json"
  fi
}

source_snapshot_manifest() {
  local scenario_dir="$1"
  local source_manifest_path="$2"
  local sources_dir="${scenario_dir}/sources"

  jq -n \
    --arg schema_version "franken-engine.swarm-actionability-no-mock-drill.source-snapshots.v1" \
    --arg br_ready "${sources_dir}/br_ready.json" \
    --arg br_open "${sources_dir}/br_open.json" \
    --arg br_in_progress "${sources_dir}/br_in_progress.json" \
    --arg br_blocked "${sources_dir}/br_blocked.json" \
    --arg bv_plan "${sources_dir}/bv_plan.json" \
    --arg git_status "${sources_dir}/git_status.json" \
    --arg source_freshness "${sources_dir}/source_freshness.json" \
    --arg agent_mail "${sources_dir}/agent_mail.json" \
    '{
      schema_version:$schema_version,
      sources:{
        br_ready_json:$br_ready,
        br_open_json:$br_open,
        br_in_progress_json:$br_in_progress,
        br_blocked_json:$br_blocked,
        bv_robot_plan_json:$bv_plan,
        git_status_snapshot_json:$git_status,
        source_freshness_json:$source_freshness,
        agent_mail_snapshot_json:$agent_mail
      }
    }' >"$source_manifest_path"
  if [[ ! -f "${sources_dir}/agent_mail.json" ]]; then
    jq 'del(.sources.agent_mail_snapshot_json)' "$source_manifest_path" >"${source_manifest_path}.tmp"
    mv "${source_manifest_path}.tmp" "$source_manifest_path"
  fi
}

run_gate_with_sources() {
  local scenario_id="$1"
  local trace_id="$2"
  local sources_manifest="$3"
  local scenario_dir="$4"

  local gate_dir="${scenario_dir}/gate"
  local stdout_path="${scenario_dir}/gate.stdout.log"
  local stderr_path="${scenario_dir}/gate.stderr.log"
  local rc decision candidate expected_decision expected_candidate expected_reason expected_exit expected_match
  mkdir -p "$gate_dir"

  local br_ready_path br_open_path br_in_progress_path br_blocked_path bv_plan_path git_status_path source_freshness_path agent_mail_path
  br_ready_path="$(jq -r '.sources.br_ready_json' "$sources_manifest")"
  br_open_path="$(jq -r '.sources.br_open_json' "$sources_manifest")"
  br_in_progress_path="$(jq -r '.sources.br_in_progress_json' "$sources_manifest")"
  br_blocked_path="$(jq -r '.sources.br_blocked_json' "$sources_manifest")"
  bv_plan_path="$(jq -r '.sources.bv_robot_plan_json' "$sources_manifest")"
  git_status_path="$(jq -r '.sources.git_status_snapshot_json' "$sources_manifest")"
  source_freshness_path="$(jq -r '.sources.source_freshness_json' "$sources_manifest")"
  agent_mail_path="$(jq -r '.sources.agent_mail_snapshot_json // ""' "$sources_manifest")"

  gate_cmd=(
    "$gate_script"
    --br-ready-json "$br_ready_path"
    --br-open-json "$br_open_path"
    --br-in-progress-json "$br_in_progress_path"
    --br-blocked-json "$br_blocked_path"
    --bv-robot-plan-json "$bv_plan_path"
    --git-status-snapshot-json "$git_status_path"
    --source-freshness-json "$source_freshness_path"
    --source-revision "$source_revision"
    --output-dir "$gate_dir"
  )
  if [[ -n "$agent_mail_path" ]]; then
    gate_cmd+=(--agent-mail-snapshot-json "$agent_mail_path")
  fi

  log_command "${gate_cmd[@]}"
  set +e
  "${gate_cmd[@]}" >"$stdout_path" 2>"$stderr_path"
  rc=$?
  set -e

  decision="$(jq -r '.decision' "${gate_dir}/actionability_report.json")"
  candidate="$(jq -r '.primary_candidate_id // ""' "${gate_dir}/actionability_report.json")"
  write_event "$trace_id" "swarm_actionability_truth_gate" "scenario_run" "$decision" "$(jq -r '.fail_closed_reasons[0].code // ""' "${gate_dir}/actionability_report.json")" "${gate_dir}/actionability_report.json"

  expected_match=true
  if [[ -f "${scenario_dir}/case.json" ]]; then
    expected_decision="$(jq -r '.expected.decision' "${scenario_dir}/case.json")"
    expected_candidate="$(jq -r '.expected.candidate_id // ""' "${scenario_dir}/case.json")"
    expected_reason="$(jq -r '.expected.required_reason_code // ""' "${scenario_dir}/case.json")"
    if [[ "$expected_decision" == "fail_closed" ]]; then
      expected_exit=42
    else
      expected_exit=0
    fi
    if [[ "$rc" -ne "$expected_exit" ]]; then
      expected_match=false
    fi
    if [[ "$decision" != "$expected_decision" ]]; then
      expected_match=false
    fi
    if [[ -n "$expected_candidate" && "$candidate" != "$expected_candidate" ]]; then
      expected_match=false
    fi
    if [[ -n "$expected_reason" ]] && ! jq -e --arg code "$expected_reason" 'any(.fail_closed_reasons[]?; .code == $code)' "${gate_dir}/actionability_report.json" >/dev/null; then
      expected_match=false
    fi
  fi

  jq -nc \
    --arg schema_version "franken-engine.swarm-actionability-no-mock-drill.case-result.v1" \
    --arg trace_id "$trace_id" \
    --arg scenario_id "$scenario_id" \
    --arg decision "$decision" \
    --arg candidate_id "$candidate" \
    --argjson exit_code "$rc" \
    --argjson expected_match "$expected_match" \
    --arg report_path "${gate_dir}/actionability_report.json" \
    --arg stdout_path "$stdout_path" \
    --arg stderr_path "$stderr_path" \
    '{
      schema_version:$schema_version,
      trace_id:$trace_id,
      scenario_id:$scenario_id,
      decision:$decision,
      candidate_id:(if $candidate_id == "" then null else $candidate_id end),
      exit_code:$exit_code,
      expected_match:$expected_match,
      artifact_paths:{
        actionability_report_json:$report_path,
        stdout_log:$stdout_path,
        stderr_log:$stderr_path
      }
    }' >>"$case_results_path"
}

copy_primary_outputs() {
  local scenario_dir="$1"
  local source_manifest="$2"
  cp "${scenario_dir}/gate/actionability_report.json" "$report_path"
  cp "$source_manifest" "$source_snapshots_path"
}

write_truth_gate_report() {
  local decision="$1"
  local replay_verified="$2"
  jq -n \
    --arg schema_version "franken-engine.swarm-actionability-no-mock-drill.truth-gate-report.v1" \
    --arg decision "$decision" \
    --argjson replay_verified "$replay_verified" \
    --arg case_results_jsonl "$case_results_path" \
    --arg actionability_report_json "$report_path" \
    '{
      schema_version:$schema_version,
      decision:$decision,
      replay_verified:$replay_verified,
      artifact_paths:{
        case_results_jsonl:$case_results_jsonl,
        actionability_report_json:$actionability_report_json
      }
    }' >"$truth_gate_report_path"
}

write_run_manifest() {
  local primary_scenario_id="$1"
  local mode_used="$2"
  local replay_verified="$3"
  local run_manifest_tmp="${run_manifest_path}.tmp"
  jq -n \
    --arg schema_version "franken-engine.swarm-actionability-no-mock-drill.manifest.v1" \
    --arg run_id "$run_id" \
    --arg mode "$mode_used" \
    --arg source_revision "$source_revision" \
    --arg primary_scenario_id "$primary_scenario_id" \
    --arg trace_ids_path "$trace_ids_path" \
    --arg source_snapshots_path "$source_snapshots_path" \
    --arg actionability_report_json "$report_path" \
    --arg events_jsonl "$events_path" \
    --arg commands_txt "$commands_path" \
    --arg truth_gate_report_json "$truth_gate_report_path" \
    --argjson replay_verified "$replay_verified" \
    '{
      schema_version:$schema_version,
      run_id:$run_id,
      mode:$mode,
      source_revision:$source_revision,
      primary_scenario_id:$primary_scenario_id,
      replay_verified:$replay_verified,
      artifact_paths:{
        trace_ids_json:$trace_ids_path,
        run_manifest_json:$run_manifest_path,
        source_snapshots_json:$source_snapshots_path,
        actionability_report_json:$actionability_report_json,
        events_jsonl:$events_jsonl,
        commands_txt:$commands_txt,
        truth_gate_report_json:$truth_gate_report_json
      }
    }' \
    --arg run_manifest_path "$run_manifest_path" >"$run_manifest_tmp"
  mv "$run_manifest_tmp" "$run_manifest_path"
}

write_report_md() {
  jq -r '
    [
      "# SWARM_ACTIONABILITY_NO_MOCK_DRILL",
      "",
      "- decision: `\(.decision)`",
      "- primary candidate: `\(.primary_candidate_id // "none")`",
      "- fail-closed reasons: " + (
        if (.fail_closed_reasons | length) == 0 then "`none`"
        else (.fail_closed_reasons | map("`\(.code)`") | join(", "))
        end
      )
    ] | join("\n")
  ' "$report_path" >"$report_md_path"
}

run_fixture_mode() {
  local selected_case_ids primary_scenario_id="" trace_ids_json="[]" overall_decision="pass"

  [[ -f "$fixtures_json" ]] || { printf 'missing fixture bundle: %s\n' "$fixtures_json" >&2; exit 64; }
  jq empty "$fixtures_json" >/dev/null
  mapfile -t selected_case_ids < <(
    if [[ -n "$scenario_filter" ]]; then
      jq -r --arg scenario "$scenario_filter" '.cases[] | select(.case_id == $scenario) | .case_id' "$fixtures_json"
    else
      jq -r '.cases[].case_id' "$fixtures_json"
    fi
  )
  if [[ "${#selected_case_ids[@]}" -eq 0 ]]; then
    printf 'no fixture scenarios selected\n' >&2
    exit 64
  fi

  for scenario_id in "${selected_case_ids[@]}"; do
    local case_json scenario_dir trace_id source_manifest
    case_json="$(jq -c --arg scenario "$scenario_id" '.cases[] | select(.case_id == $scenario)' "$fixtures_json")"
    scenario_dir="${run_dir}/scenarios/${scenario_id}"
    trace_id="trace-${scenario_id}"
    source_manifest="${scenario_dir}/source_snapshots.json"
    mkdir -p "$scenario_dir"
    printf '%s\n' "$case_json" >"${scenario_dir}/case.json"
    prepare_case_sources "$case_json" "$scenario_dir"
    source_snapshot_manifest "$scenario_dir" "$source_manifest"
    run_gate_with_sources "$scenario_id" "$trace_id" "$source_manifest" "$scenario_dir"
    trace_ids_json="$(jq -c --arg trace_id "$trace_id" '. + [$trace_id]' <<<"$trace_ids_json")"
    if [[ -z "$primary_scenario_id" ]]; then
      primary_scenario_id="$scenario_id"
      copy_primary_outputs "$scenario_dir" "$source_manifest"
    fi
    if ! jq -e 'last.expected_match == true' <(jq -s . "$case_results_path") >/dev/null; then
      overall_decision="fail_closed"
    fi
  done

  printf '%s\n' "$trace_ids_json" >"$trace_ids_path"
  write_truth_gate_report "$overall_decision" false
  write_run_manifest "$primary_scenario_id" "fixture" false
  write_report_md

  if [[ "$overall_decision" != "pass" ]]; then
    return 1
  fi
  return 0
}

run_live_mode() {
  local scenario_id trace_id scenario_dir source_manifest rc
  scenario_id="${scenario_filter:-live_repo_state}"
  trace_id="trace-${scenario_id}"
  scenario_dir="${run_dir}/scenarios/${scenario_id}"
  mkdir -p "$scenario_dir"

  gate_cmd=("$gate_script" --collect-live --source-revision "$source_revision" --output-dir "${scenario_dir}/gate")
  log_command "${gate_cmd[@]}"
  set +e
  "${gate_cmd[@]}" >"${scenario_dir}/gate.stdout.log" 2>"${scenario_dir}/gate.stderr.log"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 && "$rc" -ne 42 ]]; then
    return "$rc"
  fi

  source_manifest="${scenario_dir}/source_snapshots.json"
  jq -n \
    --arg schema_version "franken-engine.swarm-actionability-no-mock-drill.source-snapshots.v1" \
    --arg br_ready "${scenario_dir}/gate/br_ready.normalized.json" \
    --arg br_open "${scenario_dir}/gate/br_open.normalized.json" \
    --arg br_in_progress "${scenario_dir}/gate/br_in_progress.normalized.json" \
    --arg br_blocked "${scenario_dir}/gate/br_blocked.normalized.json" \
    --arg bv_plan "${scenario_dir}/gate/bv_robot_plan.normalized.json" \
    --arg git_status "${scenario_dir}/gate/git_status_snapshot.normalized.json" \
    --arg source_freshness "${scenario_dir}/gate/source_freshness.normalized.json" \
    --arg agent_mail "${scenario_dir}/gate/agent_mail_snapshot.normalized.json" \
    '{
      schema_version:$schema_version,
      sources:{
        br_ready_json:$br_ready,
        br_open_json:$br_open,
        br_in_progress_json:$br_in_progress,
        br_blocked_json:$br_blocked,
        bv_robot_plan_json:$bv_plan,
        git_status_snapshot_json:$git_status,
        source_freshness_json:$source_freshness,
        agent_mail_snapshot_json:$agent_mail
      }
    }' >"$source_manifest"
  if [[ ! -f "${scenario_dir}/gate/agent_mail_snapshot.normalized.json" ]]; then
    jq 'del(.sources.agent_mail_snapshot_json)' "$source_manifest" >"${source_manifest}.tmp"
    mv "${source_manifest}.tmp" "$source_manifest"
  fi
  copy_primary_outputs "$scenario_dir" "$source_manifest"
  printf '[%s]\n' "\"${trace_id}\"" >"$trace_ids_path"
  jq -nc \
    --arg schema_version "franken-engine.swarm-actionability-no-mock-drill.case-result.v1" \
    --arg trace_id "$trace_id" \
    --arg scenario_id "$scenario_id" \
    --arg report_path "${scenario_dir}/gate/actionability_report.json" \
    --arg stdout_path "${scenario_dir}/gate.stdout.log" \
    --arg stderr_path "${scenario_dir}/gate.stderr.log" \
    --arg decision "$(jq -r '.decision' "${scenario_dir}/gate/actionability_report.json")" \
    --arg candidate_id "$(jq -r '.primary_candidate_id // ""' "${scenario_dir}/gate/actionability_report.json")" \
    --argjson exit_code "$rc" \
    '{
      schema_version:$schema_version,
      trace_id:$trace_id,
      scenario_id:$scenario_id,
      decision:$decision,
      candidate_id:(if $candidate_id == "" then null else $candidate_id end),
      exit_code:$exit_code,
      expected_match:true,
      artifact_paths:{
        actionability_report_json:$report_path,
        stdout_log:$stdout_path,
        stderr_log:$stderr_path
      }
    }' >>"$case_results_path"
  write_event "$trace_id" "swarm_actionability_truth_gate" "live_capture" "$(jq -r '.decision' "${scenario_dir}/gate/actionability_report.json")" "$(jq -r '.fail_closed_reasons[0].code // ""' "${scenario_dir}/gate/actionability_report.json")" "${scenario_dir}/gate/actionability_report.json"
  write_truth_gate_report "pass" false
  write_run_manifest "$scenario_id" "live" false
  write_report_md
}

run_replay_mode() {
  local source_bundle source_manifest scenario_id previous_report trace_id scenario_dir
  if [[ -z "$replay_run_dir" && -n "$latest_from" ]]; then
    replay_run_dir="$(latest_bundle_dir "$latest_from")"
  fi
  if [[ -z "$replay_run_dir" ]]; then
    printf 'replay mode requires --replay-run-dir or --latest-from\n' >&2
    exit 64
  fi
  source_bundle="$(cd "$replay_run_dir" && pwd)"
  source_manifest="${source_bundle}/source_snapshots.json"
  previous_report="${source_bundle}/actionability_report.json"
  [[ -f "$source_manifest" ]] || { printf 'missing replay source snapshot manifest: %s\n' "$source_manifest" >&2; exit 64; }
  [[ -f "$previous_report" ]] || { printf 'missing replay actionability report: %s\n' "$previous_report" >&2; exit 64; }

  scenario_id="${scenario_filter:-replay_verification}"
  trace_id="trace-${scenario_id}"
  scenario_dir="${run_dir}/scenarios/${scenario_id}"
  mkdir -p "$scenario_dir"

  run_gate_with_sources "$scenario_id" "$trace_id" "$source_manifest" "$scenario_dir"
  cp "${scenario_dir}/gate/actionability_report.json" "$report_path"
  cp "$source_manifest" "$source_snapshots_path"
  printf '[%s]\n' "\"${trace_id}\"" >"$trace_ids_path"

  if ! jq -e --slurpfile previous "$previous_report" '
      .decision == $previous[0].decision
      and (.primary_candidate_id // null) == ($previous[0].primary_candidate_id // null)
    ' "$report_path" >/dev/null; then
    printf 'replay verification did not reproduce the pinned actionability decision\n' >&2
    exit 1
  fi

  write_truth_gate_report "pass" true
  write_run_manifest "$scenario_id" "replay" true
  write_report_md
}

run_check_mode() {
  [[ -f "$contract_path" ]] || { printf 'missing no-mock drill contract: %s\n' "$contract_path" >&2; exit 64; }
  jq empty "$contract_path" >/dev/null
  run_fixture_mode
  jq -e '.decision == "pass"' "$truth_gate_report_path" >/dev/null
  jq -e '.schema_version == "franken-engine.swarm-actionability-no-mock-drill.manifest.v1"' "$run_manifest_path" >/dev/null
  jq -e '.schema_version == "franken-engine.swarm-actionability-truth-gate.v1"' "$report_path" >/dev/null
  record_pass "check"
}

run_selftest_mode() {
  local selftest_root baseline_dir replay_dir
  selftest_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-actionability-no-mock-drill.XXXXXX")"
  baseline_dir="${selftest_root}/baseline"
  replay_dir="${selftest_root}/replay"

  bash "$0" check --output-dir "$baseline_dir" --fixtures-json "$fixtures_json" >/dev/null
  bash "$0" replay --output-dir "$replay_dir" --replay-run-dir "$baseline_dir" >/dev/null

  jq -e '.replay_verified == true' "${replay_dir}/truth_gate_report.json" >/dev/null
  record_pass "selftest"
}

ensure_run_dir

case "$mode" in
  live)
    run_live_mode
    ;;
  fixture)
    run_fixture_mode
    ;;
  replay)
    run_replay_mode
    ;;
  check)
    run_check_mode
    ;;
  selftest)
    run_selftest_mode
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
