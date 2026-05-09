#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
adapter="${root_dir}/scripts/swarm_live_readonly_capture_adapter.sh"
bundle_script="${root_dir}/scripts/swarm_live_readonly_snapshot_bundle.sh"
docs_path="${root_dir}/docs/SWARM_LIVE_READONLY_CAPTURE_ADAPTER.md"
fixtures_path="${SWARM_LIVE_READONLY_CAPTURE_ADAPTER_FIXTURES:-${root_dir}/scripts/testdata/swarm_live_readonly_capture_adapter/cases.json}"
mode="${1:-check}"
output_dir="${2:-${SWARM_LIVE_READONLY_CAPTURE_ADAPTER_OUTPUT_DIR:-}}"
failures=0

record_pass() {
  printf 'PASS swarm-live-readonly-capture-adapter %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-live-readonly-capture-adapter %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_live_readonly_capture_adapter_smoke.sh [check|run|selftest] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-live-readonly-capture-adapter-fixtures.v1"
    and (.cases | length >= 3)
    and (.cases | map(.case_id) | index("healthy_round_trip") != null)
    and (.cases | map(.case_id) | index("missing_agent_mail_degraded") != null)
    and (.cases | map(.case_id) | index("local_fallback_round_trip") != null)
    and all(.cases[]; has("inputs") and has("expected"))
  ' "$fixtures_path" >/dev/null
}

write_json_input() {
  local case_json="$1"
  local jq_path="$2"
  local output_path="$3"
  if jq -e "${jq_path} != null" <<<"$case_json" >/dev/null; then
    jq "$jq_path" <<<"$case_json" >"$output_path"
    printf '%s' "$output_path"
  fi
}

add_arg_if_present() {
  local -n args_ref="$1"
  local flag="$2"
  local path="$3"
  if [[ -n "$path" ]]; then
    args_ref+=("$flag" "$path")
  fi
}

run_case() {
  local case_json="$1"
  local root="$2"
  local case_id case_dir out_dir
  local swarm_ops br_ready br_in_progress br_sync bv_plan agent_mail rch_status rch_queue git_status git_diff resource_pressure proof_transcript
  local args=()

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${root}/${case_id}"
  out_dir="${case_dir}/out"
  mkdir -p "$case_dir"

  swarm_ops="$(write_json_input "$case_json" '.inputs.swarm_ops_state' "${case_dir}/swarm_ops_state.json")"
  br_ready="$(write_json_input "$case_json" '.inputs.br_ready' "${case_dir}/br_ready.json")"
  br_in_progress="$(write_json_input "$case_json" '.inputs.br_in_progress' "${case_dir}/br_in_progress.json")"
  br_sync="$(write_json_input "$case_json" '.inputs.br_sync_status' "${case_dir}/br_sync_status.json")"
  bv_plan="$(write_json_input "$case_json" '.inputs.bv_plan' "${case_dir}/bv_plan.json")"
  agent_mail="$(write_json_input "$case_json" '.inputs.agent_mail_snapshot' "${case_dir}/agent_mail_snapshot.json")"
  rch_status="$(write_json_input "$case_json" '.inputs.rch_status' "${case_dir}/rch_status.json")"
  rch_queue="$(write_json_input "$case_json" '.inputs.rch_queue' "${case_dir}/rch_queue.json")"
  git_status="$(write_json_input "$case_json" '.inputs.git_status' "${case_dir}/git_status.json")"
  git_diff="$(write_json_input "$case_json" '.inputs.git_diff_check' "${case_dir}/git_diff_check.json")"
  resource_pressure="$(write_json_input "$case_json" '.inputs.resource_pressure' "${case_dir}/resource_pressure.json")"
  proof_transcript="$(write_json_input "$case_json" '.inputs.proof_transcript' "${case_dir}/proof_transcript.json")"

  args=(--output-dir "$out_dir" --source-revision fixture-revision --now-ts "2026-05-09T12:00:00Z" --swarm-ops-state-json "$swarm_ops")
  add_arg_if_present args --br-ready-json "$br_ready"
  add_arg_if_present args --br-in-progress-json "$br_in_progress"
  add_arg_if_present args --br-sync-status-json "$br_sync"
  add_arg_if_present args --bv-plan-json "$bv_plan"
  add_arg_if_present args --agent-mail-json "$agent_mail"
  add_arg_if_present args --rch-status-json "$rch_status"
  add_arg_if_present args --rch-queue-json "$rch_queue"
  add_arg_if_present args --git-status-json "$git_status"
  add_arg_if_present args --git-diff-check-json "$git_diff"
  add_arg_if_present args --resource-pressure-json "$resource_pressure"
  add_arg_if_present args --proof-transcript-json "$proof_transcript"

  "$adapter" "${args[@]}" >/dev/null

  jq empty "${out_dir}/capture_adapter.json" >/dev/null
  jq empty "${out_dir}/bundle/snapshot.json" >/dev/null
  test -s "${out_dir}/commands.txt"
  test -s "${out_dir}/events.jsonl"
  test -s "${out_dir}/report.md"

  jq -e --argjson expected "$(jq '.expected' <<<"$case_json")" '
    .decision == $expected.decision
    and .fail_closed_reasons == $expected.fail_closed_reasons
    and .blocked_reasons == $expected.blocked_reasons
    and .degraded_reasons == $expected.degraded_reasons
  ' "${out_dir}/bundle/snapshot.json" >/dev/null || {
    record_failure "${case_id} bundle snapshot mismatch"
    return
  }

  if grep -Eiq 'mutation_class=(read_only|read_only_status|input_file_only|generated)' "${out_dir}/commands.txt"; then
    record_pass "${case_id} round trip"
  else
    record_failure "${case_id} commands missing mutation classes"
  fi
}

run_check() {
  bash -n "$adapter"
  bash -n "$bundle_script"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$fixtures_path" >/dev/null
  test -f "$docs_path"
  if fixtures_shape_ok; then
    record_pass "fixture shape"
  else
    record_failure "fixture shape mismatch"
  fi
  grep -Fq 'br ready --json' "$adapter"
  grep -Fq 'br list --status=in_progress --json' "$adapter"
  grep -Fq 'br sync --status --json' "$adapter"
  grep -Fq 'bv --recipe actionable --robot-plan' "$adapter"
  grep -Fq 'rch status --workers --jobs --json' "$adapter"
  grep -Fq 'rch queue --json' "$adapter"
  grep -Fq 'git status --short' "$adapter"
  grep -Fq 'Agent Mail evidence is accepted only from an operator-supplied JSON file' "$docs_path"
}

run_all_cases() {
  local root="$1"
  mkdir -p "$root"
  while IFS= read -r case_json; do
    run_case "$case_json" "$root"
  done < <(jq -c '.cases[]' "$fixtures_path")
}

run_forbidden_command_case() {
  local root="$1"
  local output exit_code
  set +e
  output="$("$adapter" --output-dir "${root}/forbidden" --validate-command "br close bd-x --reason done" 2>&1)"
  exit_code=$?
  set -e
  if [[ "$exit_code" -eq 42 ]] && grep -Fq 'refusing mutating capture command' <<<"$output"; then
    record_pass "forbidden command rejected"
  else
    record_failure "forbidden command was not rejected"
    printf '%s\n' "$output" >&2
  fi
}

run_selftest() {
  local tmp_root
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-live-readonly-capture-adapter.XXXXXX")"
  run_all_cases "$tmp_root"
  run_forbidden_command_case "$tmp_root"
  if jq -e '.mutation_boundary.queries_live_agent_mail == false and .mutation_boundary.runs_rch_exec == false' "${tmp_root}/healthy_round_trip/out/capture_adapter.json" >/dev/null; then
    record_pass "adapter mutation boundary"
  else
    record_failure "adapter mutation boundary mismatch"
  fi
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      if [[ -z "$output_dir" ]]; then
        output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-live-readonly-capture-adapter-run.XXXXXX")"
      fi
      run_all_cases "$output_dir"
    fi
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest
    fi
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
