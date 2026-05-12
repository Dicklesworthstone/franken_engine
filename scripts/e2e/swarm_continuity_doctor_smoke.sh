#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
doctor_script="${root_dir}/scripts/swarm_continuity_doctor.sh"
docs_path="${root_dir}/docs/SWARM_CONTINUITY_DOCTOR.md"
contract_path="${root_dir}/docs/swarm_continuity_doctor_contract_v1.json"
fixtures_path="${SWARM_CONTINUITY_DOCTOR_FIXTURES:-${root_dir}/scripts/testdata/swarm_continuity_doctor/cases.json}"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-continuity-doctor %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-continuity-doctor %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_continuity_doctor_smoke.sh [check|selftest]
EOF
}

write_source() {
  local case_json="$1"
  local source_key="$2"
  local path="$3"
  if jq -e --arg source_key "$source_key" '.sources[$source_key] != null' <<<"$case_json" >/dev/null; then
    jq --arg source_key "$source_key" '.sources[$source_key]' <<<"$case_json" >"$path"
    return 0
  fi
  return 1
}

check_no_forbidden_words() {
  local path="$1"
  if grep -Eiq 'repairs Agent Mail automatically|automatically repairs|automatically sends Agent Mail|automatically closes beads|automatically releases reservations|runs Cargo locally|invokes rch automatically|mutates remote workers|changes live queue policy' "$path"; then
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
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,240p' "$path")
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-continuity-doctor-contract.v1"
    and .bead_id == "bd-bahyn"
    and .implementation_script == "scripts/swarm_continuity_doctor.sh"
    and .smoke_script == "scripts/e2e/swarm_continuity_doctor_smoke.sh"
    and (.required_artifacts | index("run_manifest.json") != null)
    and (.required_artifacts | index("swarm_continuity_doctor_report.json") != null)
    and (.required_artifacts | index("mail_outage_bridge/mail_outage_continuity_bridge.json") != null)
    and (.required_fixture_cases | sort) == (["corrupt_mail_partial_read","degraded_read_only","healthy"] | sort)
    and .mutation_policy.repairs_agent_mail_db == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-continuity-doctor-fixtures.v1"
    and (.cases | length == 3)
    and ([.cases[].case_id] | sort) == (["corrupt_mail_partial_read","degraded_read_only","healthy"] | sort)
    and any(.cases[]; .case_id == "healthy" and .expected.decision == "healthy")
    and any(.cases[]; .case_id == "degraded_read_only" and .expected.required_reason_code == "FE-SWARM-CONTINUITY-MAIL-DEGRADED")
    and any(.cases[]; .case_id == "corrupt_mail_partial_read" and .expected.required_reason_code == "FE-SWARM-CONTINUITY-MAIL-CORRUPT" and .expected.also_requires_reason_code == "FE-SWARM-CONTINUITY-PARTIAL-MAIL-READ")
  ' "$fixtures_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq "fixture-fed continuity evidence" "$docs_path" \
    && grep -Fq "never repairs the Agent Mail database" "$docs_path" \
    && grep -Fq "Red or corrupt Agent Mail is always represented as degraded evidence" "$docs_path" \
    && grep -Fq "run_manifest.json" "$docs_path"
}

run_case() {
  local case_id="$1"
  local case_json tmpdir output_dir status expected_decision expected_reason expected_also_reason expected_mail expected_rch
  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing fixture ${case_id}"
    return
  fi

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-continuity-doctor-smoke.XXXXXX")"
  output_dir="${tmpdir}/out"
  mkdir -p "$output_dir"

  write_source "$case_json" br_ready_json "${tmpdir}/br_ready.json" >/dev/null \
    || { record_failure "case ${case_id} missing br_ready_json"; return; }
  write_source "$case_json" br_in_progress_json "${tmpdir}/br_in_progress.json" >/dev/null \
    || { record_failure "case ${case_id} missing br_in_progress_json"; return; }

  cmd=(
    "$doctor_script"
    --br-ready-json "${tmpdir}/br_ready.json"
    --br-in-progress-json "${tmpdir}/br_in_progress.json"
    --source-revision "smoke-${case_id}"
    --generated-epoch-seconds 1800000000
    --output-dir "$output_dir"
  )

  if write_source "$case_json" mail_health_json "${tmpdir}/mail_health.json"; then
    cmd+=(--mail-health-json "${tmpdir}/mail_health.json")
  fi
  if write_source "$case_json" mail_bootstrap_json "${tmpdir}/mail_bootstrap.json"; then
    cmd+=(--mail-bootstrap-json "${tmpdir}/mail_bootstrap.json")
  fi
  if write_source "$case_json" agent_profiles_json "${tmpdir}/agent_profiles.json"; then
    cmd+=(--agent-profiles-json "${tmpdir}/agent_profiles.json")
  fi
  if write_source "$case_json" git_status_json "${tmpdir}/git_status.json"; then
    cmd+=(--git-status-json "${tmpdir}/git_status.json")
  fi
  if write_source "$case_json" file_reservations_json "${tmpdir}/file_reservations.json"; then
    cmd+=(--file-reservations-json "${tmpdir}/file_reservations.json")
  fi
  if write_source "$case_json" rch_status_json "${tmpdir}/rch_status.json"; then
    cmd+=(--rch-status-json "${tmpdir}/rch_status.json")
  fi
  if write_source "$case_json" rch_queue_json "${tmpdir}/rch_queue.json"; then
    cmd+=(--rch-queue-json "${tmpdir}/rch_queue.json")
  fi

  expected_decision="$(jq -r '.expected.decision' <<<"$case_json")"
  expected_reason="$(jq -r '.expected.required_reason_code // ""' <<<"$case_json")"
  expected_also_reason="$(jq -r '.expected.also_requires_reason_code // ""' <<<"$case_json")"
  expected_mail="$(jq -r '.expected.mail_health' <<<"$case_json")"
  expected_rch="$(jq -r '.expected.rch_state' <<<"$case_json")"

  set +e
  "${cmd[@]}" >"${tmpdir}/stdout.log" 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$expected_decision" == "blocked" ]]; then
    [[ "$status" -eq 42 ]] || record_failure "case ${case_id} expected exit 42 got ${status}"
  else
    [[ "$status" -eq 0 ]] || {
      cat "${tmpdir}/stderr.log" >&2
      record_failure "case ${case_id} expected exit 0 got ${status}"
    }
  fi

  for artifact in run_manifest.json swarm_continuity_doctor_report.json events.jsonl commands.txt report.md mail_outage_bridge/mail_outage_continuity_bridge.json; do
    [[ -f "${output_dir}/${artifact}" ]] || record_failure "case ${case_id} missing ${artifact}"
  done

  local report_json="${output_dir}/swarm_continuity_doctor_report.json"
  jq -e --arg decision "$expected_decision" '.decision == $decision' "$report_json" >/dev/null \
    || record_failure "case ${case_id} decision mismatch"
  jq -e --arg state "$expected_mail" '.states.mail_health == $state' "$report_json" >/dev/null \
    || record_failure "case ${case_id} mail state mismatch"
  jq -e --arg state "$expected_rch" '.states.rch == $state' "$report_json" >/dev/null \
    || record_failure "case ${case_id} rch state mismatch"
  jq -e '.mutation_policy.repairs_agent_mail_db == false and .mutation_policy.sends_agent_mail == false and .mutation_policy.mutates_br == false and .mutation_policy.releases_reservations == false and .mutation_policy.runs_cargo == false and .mutation_policy.runs_rch == false' "$report_json" >/dev/null \
    || record_failure "case ${case_id} unsafe mutation policy"
  if [[ -n "$expected_reason" ]]; then
    jq -e --arg code "$expected_reason" 'any(.findings[]?; .code == $code)' "$report_json" >/dev/null \
      || record_failure "case ${case_id} missing reason ${expected_reason}"
  fi
  if [[ -n "$expected_also_reason" ]]; then
    jq -e --arg code "$expected_also_reason" 'any(.findings[]?; .code == $code)' "$report_json" >/dev/null \
      || record_failure "case ${case_id} missing secondary reason ${expected_also_reason}"
  fi
  grep -Fq "./scripts/swarm_agent_mail_outage_continuity_bridge.sh" "${output_dir}/commands.txt" \
    || record_failure "case ${case_id} commands did not record bridge invocation"

  record_pass "$case_id"
}

run_check() {
  jq empty "$contract_path" "$fixtures_path"
  bash -n "$doctor_script" "${BASH_SOURCE[0]}"
  contract_shape_ok || record_failure "contract shape"
  fixtures_shape_ok || record_failure "fixtures shape"
  docs_shape_ok || record_failure "docs shape"
  check_no_forbidden_words "$docs_path"
  check_no_forbidden_words "$contract_path"
  check_no_forbidden_words "$fixtures_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$contract_path"
  check_no_bare_heavy_cargo "$fixtures_path"
  check_no_bare_heavy_cargo "$doctor_script"
  check_no_bare_heavy_cargo "${BASH_SOURCE[0]}"

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
    and any(.cases[]; .expected.mail_health == "corrupt")
    and any(.cases[]; .expected.mail_health == "degraded_read_only")
  ' "$fixtures_path" >/dev/null || {
    record_failure "selftest coverage"
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
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac
