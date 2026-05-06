#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
capture_script="${root_dir}/scripts/swarm_ops_state_snapshot_capture.sh"
fixtures_path="${SWARM_OPS_STATE_SNAPSHOT_FIXTURES:-${root_dir}/scripts/testdata/swarm_ops_state_snapshot/cases.json}"
mode="${1:-check}"
output_dir="${2:-${SWARM_OPS_STATE_SNAPSHOT_OUTPUT_DIR:-}}"
failures=0

record_pass() {
  printf 'PASS swarm-ops-state-snapshot %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-ops-state-snapshot %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_ops_state_snapshot_capture_smoke.sh [check|run|selftest] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-ops-state-snapshot-fixtures.v1"
    and (.cases | length == 4)
    and (.cases | map(.case_id) | index("healthy") != null)
    and (.cases | map(.case_id) | index("stale_bv") != null)
    and (.cases | map(.case_id) | index("active_rch_stall") != null)
    and (.cases | map(.case_id) | index("dirty_unowned_file") != null)
    and all(.cases[]; has("inputs") and has("expected"))
  ' "$fixtures_path" >/dev/null
}

write_case_inputs() {
  local case_json="$1"
  local case_dir="$2"
  mkdir -p "$case_dir"

  jq '.inputs.br_ready' <<<"$case_json" >"${case_dir}/br_ready.json"
  jq '.inputs.br_in_progress' <<<"$case_json" >"${case_dir}/br_in_progress.json"
  jq '.inputs.br_sync_status' <<<"$case_json" >"${case_dir}/br_sync_status.json"
  jq -r '.inputs.bv_plan' <<<"$case_json" >"${case_dir}/bv_actionable_plan.txt"
  jq '.inputs.agent_mail_agents' <<<"$case_json" >"${case_dir}/agent_mail_agents.json"
  jq '.inputs.agent_mail_inbox' <<<"$case_json" >"${case_dir}/agent_mail_inbox.json"
  jq -r '.inputs.agent_mail_reservations' <<<"$case_json" >"${case_dir}/agent_mail_reservations.txt"
  jq '.inputs.rch_status' <<<"$case_json" >"${case_dir}/rch_status.json"
  jq '.inputs.rch_queue' <<<"$case_json" >"${case_dir}/rch_queue.json"
  jq -r '.inputs.git_status' <<<"$case_json" >"${case_dir}/git_status.txt"
  jq '.expected' <<<"$case_json" >"${case_dir}/expected.json"
}

assert_case_output() {
  local case_id="$1"
  local case_dir="$2"
  local snapshot="${case_dir}/out/swarm_ops_state_snapshot.json"
  local events="${case_dir}/out/events.jsonl"
  local expected="${case_dir}/expected.json"

  jq empty "$snapshot" >/dev/null
  jq -e --slurpfile expected "$expected" '
    .schema_version == "franken-engine.swarm-ops-state-snapshot.v1"
    and .decision == $expected[0].decision
    and .fail_closed_reasons == $expected[0].fail_closed_reasons
    and .blocked_reasons == $expected[0].blocked_reasons
    and .degraded_reasons == $expected[0].degraded_reasons
    and .components.br.bv_plan_state == $expected[0].bv_plan_state
    and .components.git.unowned_dirty_count == $expected[0].unowned_dirty_count
    and .components.rch.active_stall_count == $expected[0].active_stall_count
  ' "$snapshot" >/dev/null || {
    record_failure "${case_id} snapshot did not match expected decision/reasons"
    return
  }

  jq -s '
    length >= 11
    and all(.[]; has("trace_id") and has("component") and has("event") and has("outcome") and has("error_code") and has("evidence_path"))
    and any(.[]; .component == "swarm_ops_state_snapshot" and .event == "summary_normalized")
  ' "$events" >/dev/null || {
    record_failure "${case_id} events missing stable keys or summary event"
    return
  }

  record_pass "${case_id} snapshot"
}

run_case() {
  local case_json="$1"
  local root="$2"
  local case_id case_dir

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${root}/${case_id}"
  write_case_inputs "$case_json" "$case_dir"

  "$capture_script" \
    --output-dir "${case_dir}/out" \
    --source-revision fixture-revision \
    --agent-name BrownCreek \
    --project-key "$root_dir" \
    --br-ready-json "${case_dir}/br_ready.json" \
    --br-in-progress-json "${case_dir}/br_in_progress.json" \
    --br-sync-status-json "${case_dir}/br_sync_status.json" \
    --bv-plan-txt "${case_dir}/bv_actionable_plan.txt" \
    --agent-mail-agents-json "${case_dir}/agent_mail_agents.json" \
    --agent-mail-inbox-json "${case_dir}/agent_mail_inbox.json" \
    --agent-mail-reservations-txt "${case_dir}/agent_mail_reservations.txt" \
    --rch-status-json "${case_dir}/rch_status.json" \
    --rch-queue-json "${case_dir}/rch_queue.json" \
    --git-status-txt "${case_dir}/git_status.txt" >/dev/null

  assert_case_output "$case_id" "$case_dir"
}

run_check() {
  bash -n "$capture_script"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$fixtures_path" >/dev/null
  if fixtures_shape_ok; then
    record_pass "fixture shape"
  else
    record_failure "fixture shape mismatch"
  fi
  grep -Fq 'br sync --status --json' "$capture_script"
  grep -Fq 'bv --recipe actionable --robot-plan' "$capture_script"
  grep -Fq 'am agents list' "$capture_script"
  grep -Fq 'rch status --workers --jobs --json' "$capture_script"
  grep -Fq 'status --short' "$capture_script"
}

run_all_cases() {
  local root="$1"
  mkdir -p "$root"
  while IFS= read -r case_json; do
    run_case "$case_json" "$root"
  done < <(jq -c '.cases[]' "$fixtures_path")
}

run_selftest() {
  local tmp_root stale_snapshot
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-ops-state-snapshot-selftest.XXXXXX")"
  run_all_cases "$tmp_root"

  stale_snapshot="${tmp_root}/stale_bv/out/swarm_ops_state_snapshot.json"
  if jq -e '.decision != "pass" and (.fail_closed_reasons | index("stale_bv_due_to_br_sync") != null)' "$stale_snapshot" >/dev/null; then
    record_pass "selftest stale bv never upgrades to pass"
  else
    record_failure "selftest stale bv was upgraded to pass"
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
        output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-ops-state-snapshot-run.XXXXXX")"
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
