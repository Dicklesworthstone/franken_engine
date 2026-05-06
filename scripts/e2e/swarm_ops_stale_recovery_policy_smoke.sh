#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
policy_script="${root_dir}/scripts/swarm_ops_stale_recovery_policy.sh"
fixtures_path="${SWARM_OPS_STALE_RECOVERY_FIXTURES:-${root_dir}/scripts/testdata/swarm_ops_stale_recovery/cases.json}"
mode="${1:-check}"
output_dir="${2:-${SWARM_OPS_STALE_RECOVERY_OUTPUT_DIR:-}}"
failures=0

record_pass() {
  printf 'PASS swarm-ops-stale-recovery-policy %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-ops-stale-recovery-policy %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_ops_stale_recovery_policy_smoke.sh [check|run|selftest] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-ops-stale-recovery-fixtures.v1"
    and (.cases | length == 6)
    and (.cases | map(.case_id) | index("active_owner") != null)
    and (.cases | map(.case_id) | index("blocked_by_active_agent") != null)
    and (.cases | map(.case_id) | index("dead_owner") != null)
    and (.cases | map(.case_id) | index("stale_but_recent_git") != null)
    and (.cases | map(.case_id) | index("expired_reservation") != null)
    and (.cases | map(.case_id) | index("contradictory_mail_state") != null)
    and all(.cases[]; has("inputs") and has("expected"))
  ' "$fixtures_path" >/dev/null
}

write_case_inputs() {
  local case_json="$1"
  local case_dir="$2"
  mkdir -p "$case_dir"
  jq '.inputs.in_progress' <<<"$case_json" >"${case_dir}/in_progress.json"
  jq '.inputs.agent_profiles' <<<"$case_json" >"${case_dir}/agent_profiles.json"
  jq '.inputs.mail_activity' <<<"$case_json" >"${case_dir}/mail_activity.json"
  jq '.inputs.file_reservations' <<<"$case_json" >"${case_dir}/file_reservations.json"
  jq '.inputs.git_activity' <<<"$case_json" >"${case_dir}/git_activity.json"
  jq '.expected' <<<"$case_json" >"${case_dir}/expected.json"
}

assert_case_output() {
  local case_id="$1"
  local case_dir="$2"
  local receipts="${case_dir}/out/recovery_receipts.json"
  local events="${case_dir}/out/events.jsonl"
  local expected="${case_dir}/expected.json"

  jq empty "$receipts" >/dev/null
  jq -e --slurpfile expected "$expected" '
    .schema_version == "franken-engine.swarm-ops-stale-recovery-receipts.v1"
    and .decision == $expected[0].decision
    and (.recovery_receipts | length == 1)
    and .recovery_receipts[0].classification == $expected[0].classification
    and .recovery_receipts[0].reason_code == $expected[0].reason_code
    and .recovery_receipts[0].mutation_policy.mutates_br == false
    and .recovery_receipts[0].mutation_policy.reopens_beads == false
    and .recovery_receipts[0].mutation_policy.force_releases_reservations == false
    and .recovery_receipts[0].mutation_policy.sends_agent_mail == false
    and (
      if .recovery_receipts[0].classification == "healthy" then
        .recovery_receipts[0].agent_mail_notification_template == null
      else
        .recovery_receipts[0].agent_mail_notification_template.ack_required == true
      end
    )
  ' "$receipts" >/dev/null || {
    record_failure "${case_id} receipt mismatch"
    return
  }

  jq -s '
    length >= 1
    and all(.[]; has("trace_id") and has("component") and has("event") and has("outcome") and has("error_code") and has("evidence_path"))
  ' "$events" >/dev/null || {
    record_failure "${case_id} events missing stable keys"
    return
  }

  test -s "${case_dir}/out/report.md"
  test -s "${case_dir}/out/commands.txt"
  record_pass "${case_id} receipt"
}

run_case() {
  local case_json="$1"
  local root="$2"
  local case_id case_dir
  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${root}/${case_id}"
  write_case_inputs "$case_json" "$case_dir"

  "$policy_script" \
    --in-progress-json "${case_dir}/in_progress.json" \
    --agent-profiles-json "${case_dir}/agent_profiles.json" \
    --mail-activity-json "${case_dir}/mail_activity.json" \
    --file-reservations-json "${case_dir}/file_reservations.json" \
    --git-activity-json "${case_dir}/git_activity.json" \
    --now-epoch-seconds 2000 \
    --stale-owner-seconds 1000 \
    --recent-activity-seconds 300 \
    --output-dir "${case_dir}/out" >/dev/null

  assert_case_output "$case_id" "$case_dir"
}

run_check() {
  bash -n "$policy_script"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$fixtures_path" >/dev/null
  if fixtures_shape_ok; then
    record_pass "fixture shape"
  else
    record_failure "fixture shape mismatch"
  fi
  grep -Fq 'advisory-only' "$policy_script"
  grep -Fq 'ack_required: true' "$policy_script"
  if grep -En '(^|[[:space:]])br[[:space:]]+update[[:space:]]' "$policy_script" | grep -Fv 'suggested_operator_commands' >/dev/null; then
    record_failure "policy script must not execute br update"
  fi
  if grep -En 'file_reservations release' "$policy_script" | grep -Fv 'force_release_commands' | grep -Fv 'map("am file_reservations release' >/dev/null; then
    record_failure "policy script must not execute reservation release"
  fi
}

run_all_cases() {
  local root="$1"
  mkdir -p "$root"
  while IFS= read -r case_json; do
    run_case "$case_json" "$root"
  done < <(jq -c '.cases[]' "$fixtures_path")
}

run_selftest() {
  local tmp_root incomplete_dir incomplete_receipts
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-ops-stale-recovery-selftest.XXXXXX")"
  run_all_cases "$tmp_root"

  incomplete_dir="${tmp_root}/incomplete_evidence"
  mkdir -p "$incomplete_dir"
  jq '.cases[] | select(.case_id == "dead_owner") | .inputs.in_progress' "$fixtures_path" >"${incomplete_dir}/in_progress.json"
  "$policy_script" \
    --in-progress-json "${incomplete_dir}/in_progress.json" \
    --now-epoch-seconds 2000 \
    --stale-owner-seconds 1000 \
    --recent-activity-seconds 300 \
    --output-dir "${incomplete_dir}/out" >/dev/null
  incomplete_receipts="${incomplete_dir}/out/recovery_receipts.json"
  if jq -e '.decision == "fail_closed" and .recovery_receipts[0].classification == "manual-review" and .recovery_receipts[0].reason_code == "incomplete_activity_evidence"' "$incomplete_receipts" >/dev/null; then
    record_pass "selftest incomplete evidence fails closed"
  else
    record_failure "selftest incomplete evidence did not fail closed"
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
        output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-ops-stale-recovery-run.XXXXXX")"
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
