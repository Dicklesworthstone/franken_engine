#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate_script="${root_dir}/scripts/swarm_feedback_family_conformance_gate.sh"
fixtures_path="${SWARM_FEEDBACK_FAMILY_CONFORMANCE_FIXTURES:-${root_dir}/scripts/testdata/swarm_feedback_family_conformance_gate/cases.json}"
mode="${1:-check}"
output_dir="${2:-${SWARM_FEEDBACK_FAMILY_CONFORMANCE_OUTPUT_DIR:-}}"
failures=0

case_ids=(
  healthy_family_output
  missing_profile_contract
  stale_upstream_evidence
  local_fallback_contamination
  mutation_wording
  claim_proof_downgrade_required
)

record_pass() {
  printf 'PASS swarm-feedback-family-conformance %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-feedback-family-conformance %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_feedback_family_conformance_gate_smoke.sh [check|selftest|run] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-feedback-family-conformance.fixtures.v1"
    and ([.cases[].case_id] | sort) == ([
      "claim_proof_downgrade_required",
      "healthy_family_output",
      "local_fallback_contamination",
      "missing_profile_contract",
      "mutation_wording",
      "stale_upstream_evidence"
    ] | sort)
    and any(.cases[]; .case_id == "healthy_family_output" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "missing_profile_contract" and .expected.reason_code == "missing_profile_contract")
    and any(.cases[]; .case_id == "stale_upstream_evidence" and .expected.reason_code == "stale_upstream_evidence")
    and any(.cases[]; .case_id == "local_fallback_contamination" and .expected.reason_code == "local_fallback_contamination")
    and any(.cases[]; .case_id == "mutation_wording" and .expected.reason_code == "mutation_wording")
    and any(.cases[]; .case_id == "claim_proof_downgrade_required" and .expected.reason_code == "claim_proof_state_downgrade_required")
  ' "$fixtures_path" >/dev/null
}

run_check() {
  bash -n "$gate_script"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$gate_script" "${BASH_SOURCE[0]}"
  fi
  jq empty "$fixtures_path" >/dev/null
  fixtures_shape_ok
  grep -Fq 'runs_cargo:false' "$gate_script"
  grep -Fq 'runs_rch:false' "$gate_script"
  grep -Fq 'mutates_live_workers:false' "$gate_script"
  grep -Fq 'sends_agent_mail:false' "$gate_script"
  grep -Fq 'releases_reservations:false' "$gate_script"
  grep -Fq 'reopens_beads:false' "$gate_script"
  record_pass "shell syntax and fixture shape"
}

run_case() {
  local tmp_root="$1"
  local case_id="$2"
  local case_dir="${tmp_root}/${case_id}"
  local input_path="${case_dir}/input.json"
  local actual_exit expected_decision expected_reason
  mkdir -p "$case_dir"

  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .input' \
    "$fixtures_path" >"$input_path"
  expected_decision="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected.decision' "$fixtures_path")"
  expected_reason="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected.reason_code // ""' "$fixtures_path")"

  set +e
  "$gate_script" \
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
    .schema_version == "franken-engine.swarm-feedback-family-conformance.v1"
    and .decision == $expected_decision
    and .non_mutation_attestation.advisory_only == true
    and .non_mutation_attestation.runs_cargo == false
    and .non_mutation_attestation.runs_rch == false
    and .non_mutation_attestation.mutates_live_workers == false
    and .non_mutation_attestation.sends_agent_mail == false
    and .non_mutation_attestation.releases_reservations == false
    and .non_mutation_attestation.reopens_beads == false
    and .non_mutation_attestation.promotes_documentation_claims == false
    and (.artifact_summary | length) >= 5
  ' "${case_dir}/out/family_conformance.json" >/dev/null || {
    record_failure "${case_id} report shape mismatch"
    return
  }

  if [[ -n "$expected_reason" ]]; then
    jq -e --arg reason_code "$expected_reason" \
      'any((.fail_closed_reasons + .degraded_reasons)[]?; .code == $reason_code)' \
      "${case_dir}/out/family_conformance.json" >/dev/null || {
      record_failure "${case_id} missing reason ${expected_reason}"
      return
    }
  fi

  jq -s 'length >= 1' "${case_dir}/out/events.jsonl" >/dev/null
  grep -Fq './scripts/swarm_feedback_family_conformance_gate.sh' "${case_dir}/out/commands.txt"
  grep -Fq 'Feedback Family Golden Comparison' "${case_dir}/out/golden_comparison.md"
  grep -Fq 'Feedback Family Conformance Report' "${case_dir}/out/report.md"
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
      run_selftest "$(mktemp -d "${TMPDIR:-/tmp}/swarm-feedback-family-conformance.XXXXXX")"
    fi
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      if [[ -z "$output_dir" ]]; then
        output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-feedback-family-conformance-run.XXXXXX")"
      fi
      mkdir -p "$output_dir"
      run_selftest "$output_dir"
      printf 'swarm_feedback_family_conformance_smoke_artifacts=%s\n' "$output_dir"
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
