#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
sla_script="${root_dir}/scripts/swarm_agent_mail_sla_panel.sh"
fixtures_path="${SWARM_AGENT_MAIL_SLA_PANEL_FIXTURES:-${root_dir}/scripts/testdata/swarm_agent_mail_sla_panel/cases.json}"
mode="${1:-check}"
output_dir="${2:-${SWARM_AGENT_MAIL_SLA_PANEL_OUTPUT_DIR:-}}"
failures=0

case_ids=(
  healthy_response_times
  stale_ack_required_thread
  expired_reservation
  inactive_assignee_active_reservation
  missing_mail_snapshot
  schema_corrupt_mail_snapshot
  contact_policy_blocked_recipient
  contradictory_ownership_reservation
)

record_pass() {
  printf 'PASS swarm-agent-mail-sla-panel %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-agent-mail-sla-panel %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_agent_mail_sla_panel_smoke.sh [check|selftest|run] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-agent-mail-sla-panel.fixtures.v1"
    and ([.cases[].case_id] | sort) == ([
      "contact_policy_blocked_recipient",
      "contradictory_ownership_reservation",
      "expired_reservation",
      "healthy_response_times",
      "inactive_assignee_active_reservation",
      "missing_mail_snapshot",
      "schema_corrupt_mail_snapshot",
      "stale_ack_required_thread"
    ] | sort)
    and any(.cases[]; .case_id == "healthy_response_times" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "stale_ack_required_thread" and (.expected.diagnostic_codes | index("stale_ack_required_thread") != null))
    and any(.cases[]; .case_id == "expired_reservation" and (.expected.diagnostic_codes | index("expired_reservation") != null))
    and any(.cases[]; .case_id == "inactive_assignee_active_reservation" and (.expected.diagnostic_codes | index("inactive_assignee_active_reservation") != null))
    and any(.cases[]; .case_id == "missing_mail_snapshot" and (.expected.diagnostic_codes | index("missing_mail_snapshot") != null))
    and any(.cases[]; .case_id == "schema_corrupt_mail_snapshot" and (.expected.diagnostic_codes | index("schema_corrupt_mail_snapshot") != null))
    and any(.cases[]; .case_id == "contact_policy_blocked_recipient" and (.expected.diagnostic_codes | index("contact_policy_blocked_recipient") != null))
    and any(.cases[]; .case_id == "contradictory_ownership_reservation" and (.expected.diagnostic_codes | index("contradictory_ownership_reservation") != null))
  ' "$fixtures_path" >/dev/null
}

run_check() {
  bash -n "$sla_script"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$sla_script" "${BASH_SOURCE[0]}"
  fi
  jq empty "$fixtures_path" >/dev/null
  fixtures_shape_ok
  grep -Fq 'queries_live_mcp:false' "$sla_script"
  grep -Fq 'sends_agent_mail:false' "$sla_script"
  grep -Fq 'releases_reservations:false' "$sla_script"
  grep -Fq 'mutates_br:false' "$sla_script"
  grep -Fq 'runs_cargo:false' "$sla_script"
  grep -Fq 'runs_rch:false' "$sla_script"
  grep -Fq 'contradictory_ownership_reservation' "$sla_script"
  record_pass "shell syntax and fixture shape"
}

write_optional_json() {
  local case_json="$1"
  local key="$2"
  local path="$3"
  if jq -e --arg key "$key" '.[$key] != null' "$case_json" >/dev/null; then
    jq --arg key "$key" '.[$key]' "$case_json" >"$path"
    printf '%s\n' "$path"
  fi
}

run_case() {
  local tmp_root="$1"
  local case_id="$2"
  local case_dir="${tmp_root}/${case_id}"
  local case_json="${case_dir}/case.json"
  local mail_path br_path reservations_path
  local actual_exit expected_decision expected_codes now_ts
  mkdir -p "$case_dir"

  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' \
    "$fixtures_path" >"$case_json"
  now_ts="$(jq -r '.now_ts // "2026-05-09T15:00:00Z"' "$case_json")"
  expected_decision="$(jq -r '.expected.decision' "$case_json")"
  expected_codes="$(jq -r '(.expected.diagnostic_codes // []) | join(",")' "$case_json")"
  mail_path="$(write_optional_json "$case_json" "mail_snapshot" "${case_dir}/mail_snapshot.json")"
  br_path="$(write_optional_json "$case_json" "br_in_progress" "${case_dir}/br_in_progress.json")"
  reservations_path="$(write_optional_json "$case_json" "file_reservations" "${case_dir}/file_reservations.json")"

  args=(
    --now-ts "$now_ts"
    --source-revision fixture-revision
    --output-dir "${case_dir}/out"
  )
  if [[ -n "$mail_path" ]]; then
    args+=(--mail-snapshot-json "$mail_path")
  fi
  if [[ -n "$br_path" ]]; then
    args+=(--br-in-progress-json "$br_path")
  fi
  if [[ -n "$reservations_path" ]]; then
    args+=(--file-reservations-json "$reservations_path")
  fi

  set +e
  "$sla_script" "${args[@]}" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$expected_decision" == "blocked" && "$actual_exit" -ne 42 ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected 42"
    return
  fi
  if [[ "$expected_decision" != "blocked" && "$actual_exit" -ne 0 ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected 0"
    return
  fi

  jq -e --arg expected_decision "$expected_decision" '
    .schema_version == "franken-engine.agent-mail-sla-report.v1"
    and .decision == $expected_decision
    and .non_mutation_attestation.fixture_fed_only == true
    and .non_mutation_attestation.sends_agent_mail == false
    and .non_mutation_attestation.acknowledges_messages == false
    and .non_mutation_attestation.releases_reservations == false
    and .non_mutation_attestation.changes_contact_policy == false
    and .non_mutation_attestation.queries_live_mcp == false
    and .non_mutation_attestation.mutates_br == false
    and .non_mutation_attestation.runs_cargo == false
    and .non_mutation_attestation.runs_rch == false
  ' "${case_dir}/out/agent_mail_sla_report.json" >/dev/null || {
    record_failure "${case_id} report shape mismatch"
    return
  }

  if [[ -n "$expected_codes" ]]; then
    IFS=',' read -r -a reason_codes <<<"$expected_codes"
    for reason_code in "${reason_codes[@]}"; do
      jq -e --arg reason_code "$reason_code" \
        'any(.diagnostics[]?; .code == $reason_code)' \
        "${case_dir}/out/agent_mail_sla_report.json" >/dev/null || {
        record_failure "${case_id} missing diagnostic ${reason_code}"
        return
      }
    done
  fi

  if [[ "$case_id" == "stale_ack_required_thread" ]]; then
    jq -e 'any(.diagnostics[]?; .code == "stale_ack_required_thread" and (.message_age_seconds // 0) > 900)' \
      "${case_dir}/out/agent_mail_sla_report.json" >/dev/null || {
      record_failure "${case_id} missing message age evidence"
      return
    }
  fi
  if [[ "$case_id" == "expired_reservation" ]]; then
    jq -e 'any(.diagnostics[]?; .code == "expired_reservation" and (.reservation_expired_seconds // 0) > 0 and (.reservation_path // "") != "")' \
      "${case_dir}/out/agent_mail_sla_report.json" >/dev/null || {
      record_failure "${case_id} missing reservation expiry evidence"
      return
    }
  fi
  if [[ "$case_id" == "schema_corrupt_mail_snapshot" ]]; then
    jq -e '
      .decision == "degraded"
      and any(.diagnostics[]?;
        .code == "schema_corrupt_mail_snapshot"
        and .severity == "warning"
        and (.mail_health_status // "") == "red"
        and ((.mail_diagnostic_codes // []) | index("schema_corrupt") != null)
      )
    ' "${case_dir}/out/agent_mail_sla_report.json" >/dev/null || {
      record_failure "${case_id} missing schema-corrupt health evidence"
      return
    }
  fi

  jq -s 'length >= 1' "${case_dir}/out/events.jsonl" >/dev/null
  grep -Fq './scripts/swarm_agent_mail_sla_panel.sh' "${case_dir}/out/commands.txt"
  grep -Fq 'Agent Mail SLA Panel' "${case_dir}/out/agent_mail_sla_panel.md"
  grep -Fq 'Agent Mail SLA Report' "${case_dir}/out/report.md"
  record_pass "$case_id"
}

run_selftest() {
  local tmp_root="$1"
  for case_id in "${case_ids[@]}"; do
    run_case "$tmp_root" "$case_id"
  done
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest "$(mktemp -d "${TMPDIR:-/tmp}/swarm-agent-mail-sla-panel.XXXXXX")"
    fi
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      if [[ -z "$output_dir" ]]; then
        output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-agent-mail-sla-panel-run.XXXXXX")"
      fi
      mkdir -p "$output_dir"
      run_selftest "$output_dir"
      printf 'swarm_agent_mail_sla_panel_smoke_artifacts=%s\n' "$output_dir"
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
