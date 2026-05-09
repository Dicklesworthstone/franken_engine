#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
recommender_script="${root_dir}/scripts/swarm_stalled_ownership_reopen_recommender.sh"
fixtures_path="${SWARM_STALLED_OWNERSHIP_REOPEN_FIXTURES:-${root_dir}/scripts/testdata/swarm_stalled_ownership_reopen_recommender/cases.json}"
mode="${1:-check}"
output_dir="${2:-${SWARM_STALLED_OWNERSHIP_REOPEN_OUTPUT_DIR:-}}"
failures=0

case_ids=(
  active_owner
  stale_owner_safe_to_reopen
  stale_owner_dirty_overlap
  expired_reservation
  mail_unavailable
  recently_active_old_bead
  missing_br_snapshot
  contradictory_ownership
)

record_pass() {
  printf 'PASS swarm-stalled-ownership-reopen %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-stalled-ownership-reopen %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_stalled_ownership_reopen_recommender_smoke.sh [check|selftest|run] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.stalled-ownership-reopen.fixtures.v1"
    and ([.cases[].case_id] | sort) == ([
      "active_owner",
      "contradictory_ownership",
      "expired_reservation",
      "mail_unavailable",
      "missing_br_snapshot",
      "recently_active_old_bead",
      "stale_owner_dirty_overlap",
      "stale_owner_safe_to_reopen"
    ] | sort)
    and any(.cases[]; .case_id == "active_owner" and .expected.recommendation == "keep_assigned")
    and any(.cases[]; .case_id == "stale_owner_safe_to_reopen" and .expected.recommendation == "recommend_reopen")
    and any(.cases[]; .case_id == "stale_owner_dirty_overlap" and .expected.reason_code == "dirty_overlap")
    and any(.cases[]; .case_id == "expired_reservation" and .expected.reason_code == "expired_reservation")
    and any(.cases[]; .case_id == "mail_unavailable" and .expected.reason_code == "mail_unavailable")
    and any(.cases[]; .case_id == "recently_active_old_bead" and .expected.recommendation == "keep_assigned")
    and any(.cases[]; .case_id == "missing_br_snapshot" and .expected.fail_closed_reason == "missing_br_snapshot")
    and any(.cases[]; .case_id == "contradictory_ownership" and .expected.fail_closed_reason == "contradictory_ownership_evidence")
  ' "$fixtures_path" >/dev/null
}

run_check() {
  bash -n "$recommender_script"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$recommender_script" "${BASH_SOURCE[0]}"
  fi
  jq empty "$fixtures_path" >/dev/null
  fixtures_shape_ok
  grep -Fq 'runs_br_reopen:false' "$recommender_script"
  grep -Fq 'mutates_br:false' "$recommender_script"
  grep -Fq 'releases_reservations:false' "$recommender_script"
  grep -Fq 'sends_agent_mail:false' "$recommender_script"
  grep -Fq 'runs_cargo:false' "$recommender_script"
  grep -Fq 'runs_rch:false' "$recommender_script"
  record_pass "shell syntax and fixture shape"
}

run_case() {
  local tmp_root="$1"
  local case_id="$2"
  local case_dir="${tmp_root}/${case_id}"
  local input_path="${case_dir}/input.json"
  local actual_exit expected_decision expected_recommendation expected_reason expected_fail
  mkdir -p "$case_dir"

  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .input' \
    "$fixtures_path" >"$input_path"
  expected_decision="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected.decision' "$fixtures_path")"
  expected_recommendation="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected.recommendation // ""' "$fixtures_path")"
  expected_reason="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected.reason_code // ""' "$fixtures_path")"
  expected_fail="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected.fail_closed_reason // ""' "$fixtures_path")"

  set +e
  "$recommender_script" \
    --input-json "$input_path" \
    --source-revision fixture-revision \
    --output-dir "${case_dir}/out" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$expected_decision" == "fail_closed" && "$actual_exit" -ne 42 ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected 42"
    return
  fi
  if [[ "$expected_decision" != "fail_closed" && "$actual_exit" -ne 0 ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected 0"
    return
  fi

  jq -e --arg expected_decision "$expected_decision" '
    .schema_version == "franken-engine.stalled-ownership-reopen-recommendations.v1"
    and .decision == $expected_decision
    and .non_mutation_attestation.advisory_only == true
    and .non_mutation_attestation.runs_br_reopen == false
    and .non_mutation_attestation.mutates_br == false
    and .non_mutation_attestation.reassigns_beads == false
    and .non_mutation_attestation.releases_reservations == false
    and .non_mutation_attestation.sends_agent_mail == false
    and .non_mutation_attestation.edits_files == false
    and .non_mutation_attestation.runs_cargo == false
    and .non_mutation_attestation.runs_rch == false
  ' "${case_dir}/out/stalled_ownership_reopen_recommendations.json" >/dev/null || {
    record_failure "${case_id} report shape mismatch"
    return
  }

  if [[ -n "$expected_recommendation" ]]; then
    jq -e --arg recommendation "$expected_recommendation" \
      'any(.recommendations[]?; .recommendation == $recommendation)' \
      "${case_dir}/out/stalled_ownership_reopen_recommendations.json" >/dev/null || {
      record_failure "${case_id} missing recommendation ${expected_recommendation}"
      return
    }
  fi
  if [[ -n "$expected_reason" ]]; then
    jq -e --arg reason_code "$expected_reason" \
      'any(.recommendations[]?; .reason_code == $reason_code)' \
      "${case_dir}/out/stalled_ownership_reopen_recommendations.json" >/dev/null || {
      record_failure "${case_id} missing reason ${expected_reason}"
      return
    }
  fi
  if [[ -n "$expected_fail" ]]; then
    jq -e --arg reason_code "$expected_fail" \
      'any(.fail_closed_reasons[]?; .code == $reason_code)' \
      "${case_dir}/out/stalled_ownership_reopen_recommendations.json" >/dev/null || {
      record_failure "${case_id} missing fail-closed reason ${expected_fail}"
      return
    }
  fi
  if [[ "$case_id" == "stale_owner_safe_to_reopen" ]]; then
    jq -e 'any(.recommendations[]?; .manual_br_command | startswith("br reopen bd-stale-safe "))' \
      "${case_dir}/out/stalled_ownership_reopen_recommendations.json" >/dev/null || {
      record_failure "${case_id} missing manual br reopen command"
      return
    }
  fi

  jq -s 'length >= 1' "${case_dir}/out/events.jsonl" >/dev/null
  grep -Fq './scripts/swarm_stalled_ownership_reopen_recommender.sh' "${case_dir}/out/commands.txt"
  grep -Fq 'Stalled Ownership Reopen Receipts' "${case_dir}/out/reopen_receipts.md"
  grep -Fq 'Stalled Ownership Reopen Report' "${case_dir}/out/report.md"
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
      run_selftest "$(mktemp -d "${TMPDIR:-/tmp}/swarm-stalled-ownership-reopen.XXXXXX")"
    fi
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      if [[ -z "$output_dir" ]]; then
        output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-stalled-ownership-reopen-run.XXXXXX")"
      fi
      mkdir -p "$output_dir"
      run_selftest "$output_dir"
      printf 'swarm_stalled_ownership_reopen_smoke_artifacts=%s\n' "$output_dir"
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
