#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
bridge_script="${root_dir}/scripts/swarm_agent_mail_outage_continuity_bridge.sh"
docs_path="${root_dir}/docs/SWARM_AGENT_MAIL_OUTAGE_CONTINUITY_BRIDGE.md"
contract_path="${root_dir}/docs/agent_mail_outage_continuity_bridge_contract_v1.json"
fixtures_path="${SWARM_AGENT_MAIL_OUTAGE_BRIDGE_FIXTURES:-${root_dir}/scripts/testdata/swarm_agent_mail_outage_continuity_bridge/cases.json}"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-agent-mail-outage-continuity-bridge %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-agent-mail-outage-continuity-bridge %s\n' "$1" >&2
  failures=$((failures + 1))
}

write_optional_source() {
  local case_json="$1"
  local jq_expr="$2"
  local path="$3"
  if jq -e "${jq_expr} != null" <<<"$case_json" >/dev/null; then
    jq "$jq_expr" <<<"$case_json" >"$path"
    return 0
  fi
  return 1
}

run_case() {
  local case_id="$1"
  local case_json tmpdir output_dir status expected_exit expected_decision expected_reason expected_soft_locks
  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing fixture case ${case_id}"
    return
  fi

  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  mkdir -p "$output_dir"

  jq '.sources.br_in_progress_json' <<<"$case_json" >"${tmpdir}/br_in_progress.json"
  cmd=(
    "$bridge_script"
    --br-in-progress-json "${tmpdir}/br_in_progress.json"
    --source-revision "smoke-${case_id}"
    --generated-epoch-seconds 1800000000
    --output-dir "$output_dir"
  )
  if write_optional_source "$case_json" '.sources.mail_health_json' "${tmpdir}/mail_health.json"; then
    cmd+=(--mail-health-json "${tmpdir}/mail_health.json")
  fi
  if write_optional_source "$case_json" '.sources.mail_bootstrap_json' "${tmpdir}/mail_bootstrap.json"; then
    cmd+=(--mail-bootstrap-json "${tmpdir}/mail_bootstrap.json")
  fi
  if write_optional_source "$case_json" '.sources.agent_profiles_json' "${tmpdir}/agent_profiles.json"; then
    cmd+=(--agent-profiles-json "${tmpdir}/agent_profiles.json")
  fi
  if write_optional_source "$case_json" '.sources.git_status_json' "${tmpdir}/git_status.json"; then
    cmd+=(--git-status-json "${tmpdir}/git_status.json")
  fi
  if write_optional_source "$case_json" '.sources.file_reservations_json' "${tmpdir}/file_reservations.json"; then
    cmd+=(--file-reservations-json "${tmpdir}/file_reservations.json")
  fi

  expected_decision="$(jq -r '.expected.decision' <<<"$case_json")"
  expected_reason="$(jq -r '.expected.required_reason_code // ""' <<<"$case_json")"
  expected_soft_locks="$(jq -r '.expected.soft_lock_count' <<<"$case_json")"
  if [[ "$expected_decision" == "blocked" ]]; then
    expected_exit=42
  else
    expected_exit=0
  fi

  set +e
  "${cmd[@]}" >/dev/null 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    printf 'expected exit %s for %s, got %s\n' "$expected_exit" "$case_id" "$status" >&2
    cat "${tmpdir}/stderr.log" >&2
    record_failure "unexpected exit ${case_id}"
    return
  fi

  local report_json="${output_dir}/mail_outage_continuity_bridge.json"
  [[ -f "$report_json" ]] || { record_failure "missing report ${case_id}"; return; }
  [[ -f "${output_dir}/soft_lock_receipts.jsonl" ]] || { record_failure "missing soft locks ${case_id}"; return; }
  [[ -f "${output_dir}/events.jsonl" ]] || { record_failure "missing events ${case_id}"; return; }
  [[ -f "${output_dir}/commands.txt" ]] || { record_failure "missing commands ${case_id}"; return; }
  [[ -f "${output_dir}/report.md" ]] || { record_failure "missing markdown ${case_id}"; return; }

  jq -e --arg decision "$expected_decision" '.decision == $decision' "$report_json" >/dev/null \
    || record_failure "decision mismatch ${case_id}"
  jq -e --argjson soft_locks "$expected_soft_locks" '.summary.soft_lock_count == $soft_locks' "$report_json" >/dev/null \
    || record_failure "soft-lock count mismatch ${case_id}"
  if [[ -n "$expected_reason" ]]; then
    jq -e --arg code "$expected_reason" 'any((.degraded_reasons + .blocked_reasons)[]?; .code == $code)' "$report_json" >/dev/null \
      || record_failure "missing reason ${expected_reason} ${case_id}"
  fi
  jq -e '.mutation_policy.sends_agent_mail == false and .mutation_policy.repairs_agent_mail_db == false and .mutation_policy.mutates_br == false and .mutation_policy.runs_cargo == false and .mutation_policy.runs_rch == false' "$report_json" >/dev/null \
    || record_failure "unsafe mutation policy ${case_id}"
  grep -Fq "./scripts/swarm_agent_mail_outage_continuity_bridge.sh" "${output_dir}/commands.txt" \
    || record_failure "commands missing invocation ${case_id}"

  record_pass "$case_id"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.agent-mail-outage-continuity-bridge-fixtures.v1"
    and ([.cases[].case_id] | sort) == ([
      "br_only_soft_lock_fallback",
      "healthy_mail_snapshot",
      "missing_table_health_json",
      "transient_macro_start_failure"
    ] | sort)
    and any(.cases[]; .case_id == "missing_table_health_json" and .expected.required_reason_code == "FE-IW3-MAIL-DB-CORRUPT")
    and any(.cases[]; .case_id == "transient_macro_start_failure" and .expected.required_reason_code == "FE-IW3-MAIL-BOOTSTRAP-FAILED")
    and any(.cases[]; .case_id == "healthy_mail_snapshot" and .expected.decision == "healthy")
    and any(.cases[]; .case_id == "br_only_soft_lock_fallback" and .expected.required_reason_code == "FE-IW3-MAIL-SNAPSHOT-MISSING")
  ' "$fixtures_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq "The bridge is advisory-only and proof-only." "$docs_path" \
    && grep -Fq "It never sends Agent Mail" "$docs_path" \
    && grep -Fq "repairs the Agent Mail database" "$docs_path" \
    && grep -Fq "soft-lock evidence" "$docs_path"
}

run_check() {
  jq empty "$contract_path" "$fixtures_path"
  bash -n "$bridge_script" "${BASH_SOURCE[0]}"
  docs_shape_ok || record_failure "docs shape"
  fixtures_shape_ok || record_failure "fixture shape"

  local case_id
  while IFS= read -r case_id; do
    run_case "$case_id"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")

  if [[ "$failures" -ne 0 ]]; then
    exit 1
  fi
  record_pass "check"
}

run_selftest() {
  run_check
  jq -e '
    ([.cases[].expected.decision] | unique | sort) == ["degraded","healthy"]
    and ([.cases[].expected.required_reason_code // empty] | unique | sort) == [
      "FE-IW3-MAIL-BOOTSTRAP-FAILED",
      "FE-IW3-MAIL-DB-CORRUPT",
      "FE-IW3-MAIL-SNAPSHOT-MISSING"
    ]
  ' "$fixtures_path" >/dev/null || {
    record_failure "decision/reason coverage"
    exit 1
  }
  record_pass "selftest"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help|help)
    printf 'Usage: ./scripts/e2e/swarm_agent_mail_outage_continuity_bridge_smoke.sh [check|selftest]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
