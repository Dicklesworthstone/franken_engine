#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
packet_script="${root_dir}/scripts/idea_wizard_iv_coordination_health_packet.sh"
mode="${1:-check}"

record_pass() {
  printf 'PASS idea-wizard-iv-coordination-health %s\n' "$1"
}

record_failure() {
  printf 'FAIL idea-wizard-iv-coordination-health %s\n' "$1" >&2
  exit 1
}

write_in_progress() {
  local path="$1"
  cat >"$path" <<'JSON'
[
  {
    "id": "bd-o9wbd",
    "title": "coordination health packet",
    "status": "in_progress",
    "assignee": "RainyBadger",
    "updated_at": "2026-05-11T02:00:00Z"
  }
]
JSON
}

write_health() {
  local case_id="$1"
  local path="$2"
  case "$case_id" in
    healthy)
      printf '{"status":"ok","health_level":"green"}\n' >"$path"
      ;;
    degraded)
      printf '{"status":"degraded_read_only","health_level":"yellow"}\n' >"$path"
      ;;
    red-schema)
      printf '{"status":"error","health_level":"red","semantic_readiness":{"status":"fail","detail":"sqlite schema missing required health_check tables: projects, agents, messages, message_recipients"},"recovery":{"mode":"corrupt","next_action":"Run am doctor repair --yes"}}\n' >"$path"
      ;;
    malformed)
      printf '{"status":' >"$path"
      ;;
  esac
}

run_case() {
  local case_id="$1"
  local expected_decision="$2"
  local include_health="$3"
  local tmpdir output_dir status expected_exit br_json health_json

  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  br_json="${tmpdir}/br_in_progress.json"
  health_json="${tmpdir}/mail_health.json"
  write_in_progress "$br_json"

  if [[ "$include_health" == "true" ]]; then
    write_health "$case_id" "$health_json"
  fi

  if [[ "$expected_decision" == "fail_closed" ]]; then
    expected_exit=42
  else
    expected_exit=0
  fi

  cmd=(
    "$packet_script"
    --br-in-progress-json "$br_json"
    --source-revision "smoke-${case_id}"
    --generated-epoch-seconds 1800000000
    --output-dir "$output_dir"
  )
  if [[ "$include_health" == "true" ]]; then
    cmd+=(--mail-health-json "$health_json")
  fi

  set +e
  "${cmd[@]}" >"${tmpdir}/stdout.log" 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    cat "${tmpdir}/stderr.log" >&2
    record_failure "unexpected exit for ${case_id}: got ${status}, expected ${expected_exit}"
  fi

  [[ -f "${output_dir}/coordination_health_packet.json" ]] || record_failure "missing packet for ${case_id}"
  [[ -f "${output_dir}/run_manifest.json" ]] || record_failure "missing manifest for ${case_id}"
  [[ -f "${output_dir}/events.jsonl" ]] || record_failure "missing events for ${case_id}"
  [[ -f "${output_dir}/commands.txt" ]] || record_failure "missing commands for ${case_id}"
  [[ -f "${output_dir}/report.md" ]] || record_failure "missing report for ${case_id}"

  jq -e --arg decision "$expected_decision" '.decision == $decision' "${output_dir}/coordination_health_packet.json" >/dev/null \
    || record_failure "decision mismatch for ${case_id}"
  jq -e '.mutation_policy.repairs_agent_mail_db == false and .mutation_policy.sends_agent_mail == false and .mutation_policy.mutates_br == false' "${output_dir}/coordination_health_packet.json" >/dev/null \
    || record_failure "unsafe mutation policy for ${case_id}"
  grep -Fq "./scripts/idea_wizard_iv_coordination_health_packet.sh" "${output_dir}/commands.txt" \
    || record_failure "commands transcript missing invocation for ${case_id}"

  record_pass "$case_id"
}

run_check() {
  bash -n "$packet_script" "${BASH_SOURCE[0]}"
  run_case "healthy" "healthy" "true"
  run_case "degraded" "degraded" "true"
  run_case "red-schema" "degraded" "true"
  run_case "missing-health" "degraded" "false"
  run_case "malformed" "fail_closed" "true"
  git -C "$root_dir" diff --check -- \
    docs/IDEA_WIZARD_IV_COORDINATION_HEALTH_PACKET.md \
    scripts/idea_wizard_iv_coordination_health_packet.sh \
    scripts/e2e/idea_wizard_iv_coordination_health_packet_smoke.sh \
    docs/idea_wizard_iv_saturation_convergence_v1.json
  record_pass "check"
}

case "$mode" in
  check)
    run_check
    ;;
  -h|--help|help)
    printf 'Usage: ./scripts/e2e/idea_wizard_iv_coordination_health_packet_smoke.sh [check]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
