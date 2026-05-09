#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract_script="${root_dir}/scripts/swarm_feedback_contract_profile.sh"
fixtures_path="${SWARM_FEEDBACK_CONTRACT_PROFILE_FIXTURES:-${root_dir}/scripts/testdata/swarm_feedback_contract_profile/cases.json}"
mode="${1:-check}"
output_dir="${2:-${SWARM_FEEDBACK_CONTRACT_PROFILE_OUTPUT_DIR:-}}"
failures=0

case_ids=(
  complete_profile
  missing_upstream_live_state
  missing_resource_authority
  stale_proof_state
  contradictory_advisory_inputs
)

record_pass() {
  printf 'PASS swarm-feedback-contract-profile %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-feedback-contract-profile %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_feedback_contract_profile_smoke.sh [check|selftest|run] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-feedback-contract-profile.fixtures.v1"
    and ([.cases[].case_id] | sort) == ([
      "complete_profile",
      "contradictory_advisory_inputs",
      "missing_resource_authority",
      "missing_upstream_live_state",
      "stale_proof_state"
    ] | sort)
    and any(.cases[]; .case_id == "complete_profile" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "missing_upstream_live_state" and (.expected.fail_closed_reasons | index("missing_upstream_live_state") != null))
    and any(.cases[]; .case_id == "missing_resource_authority" and (.expected.fail_closed_reasons | index("missing_resource_authority") != null))
    and any(.cases[]; .case_id == "stale_proof_state" and (.expected.fail_closed_reasons | index("stale_proof_state_evidence") != null))
    and any(.cases[]; .case_id == "contradictory_advisory_inputs" and (.expected.fail_closed_reasons | index("contradictory_advisory_input") != null))
  ' "$fixtures_path" >/dev/null
}

run_check() {
  bash -n "$contract_script"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$contract_script" "${BASH_SOURCE[0]}"
  fi
  jq empty "$fixtures_path" >/dev/null
  fixtures_shape_ok
  grep -Fq 'runs_cargo: false' "$contract_script"
  grep -Fq 'runs_rch: false' "$contract_script"
  grep -Fq 'mutates_beads: false' "$contract_script"
  record_pass "shell syntax and fixture shape"
}

run_case() {
  local tmp_root="$1"
  local case_id="$2"
  local case_dir="${tmp_root}/${case_id}"
  local input_path="${case_dir}/input.json"
  local actual_exit expected_decision expected_reasons
  mkdir -p "$case_dir"

  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .input' \
    "$fixtures_path" >"$input_path"
  expected_decision="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected.decision' "$fixtures_path")"
  expected_reasons="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | (.expected.fail_closed_reasons // []) | join(",")' "$fixtures_path")"

  set +e
  "$contract_script" \
    --input-json "$input_path" \
    --source-revision fixture-revision \
    --output-dir "${case_dir}/out" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$expected_decision" == "pass" && "$actual_exit" -ne 0 ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected 0"
    return
  fi
  if [[ "$expected_decision" != "pass" && "$actual_exit" -ne 42 ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected 42"
    return
  fi

  jq -e --arg expected_decision "$expected_decision" '
    .schema_version == "franken-engine.swarm-feedback-contract-profile.report.v1"
    and .decision == $expected_decision
    and .non_mutation_attestation.mutates_beads == false
    and .non_mutation_attestation.runs_cargo == false
    and .non_mutation_attestation.runs_rch == false
    and (.profiles | length) >= 5
    and (.field_inventory | length) >= 5
  ' "${case_dir}/out/swarm_feedback_contract_profile.json" >/dev/null || {
    record_failure "${case_id} report shape mismatch"
    return
  }

  if [[ -n "$expected_reasons" ]]; then
    IFS=',' read -r -a reason_codes <<<"$expected_reasons"
    for reason_code in "${reason_codes[@]}"; do
      jq -e --arg reason_code "$reason_code" \
        'any(.fail_closed_reasons[]?; .code == $reason_code)' \
        "${case_dir}/out/swarm_feedback_contract_profile.json" >/dev/null || {
        record_failure "${case_id} missing reason ${reason_code}"
        return
      }
    done
  fi

  jq empty "${case_dir}/out/profile_field_inventory.json" >/dev/null
  jq -s 'length >= 1' "${case_dir}/out/events.jsonl" >/dev/null
  grep -Fq './scripts/swarm_feedback_contract_profile.sh' "${case_dir}/out/commands.txt"
  grep -Fq 'Swarm Feedback Contract Profile' "${case_dir}/out/report.md"
  record_pass "${case_id}"
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
      run_selftest "$(mktemp -d "${TMPDIR:-/tmp}/swarm-feedback-contract-profile.XXXXXX")"
    fi
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      if [[ -z "$output_dir" ]]; then
        output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-feedback-contract-profile-run.XXXXXX")"
      fi
      mkdir -p "$output_dir"
      run_selftest "$output_dir"
      printf 'swarm_feedback_contract_profile_smoke_artifacts=%s\n' "$output_dir"
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
