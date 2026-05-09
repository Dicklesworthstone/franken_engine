#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
portfolio_script="${root_dir}/scripts/swarm_proof_portfolio_optimizer.sh"
fixtures_path="${SWARM_PROOF_PORTFOLIO_FIXTURES:-${root_dir}/scripts/testdata/swarm_proof_portfolio_optimizer/cases.json}"
mode="${1:-check}"
output_dir="${2:-${SWARM_PROOF_PORTFOLIO_OUTPUT_DIR:-}}"
failures=0

case_ids=(
  clean_focused_proof
  compile_drift
  stale_artifact_evidence
  all_workers_busy
  local_rch_fallback_contamination
)

record_pass() {
  printf 'PASS swarm-proof-portfolio %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-proof-portfolio %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_proof_portfolio_optimizer_smoke.sh [check|selftest|run] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-portfolio.fixtures.v1"
    and (.default_input.schema_version == "franken-engine.swarm-proof-portfolio.input.v1")
    and ([.cases[].case_id] | sort) == ([
      "all_workers_busy",
      "clean_focused_proof",
      "compile_drift",
      "local_rch_fallback_contamination",
      "stale_artifact_evidence"
    ] | sort)
    and any(.cases[]; .case_id == "clean_focused_proof" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "compile_drift" and .expected.portfolio_state == "compile_blocker")
    and any(.cases[]; .case_id == "all_workers_busy" and .expected.portfolio_state == "no_worker_slot")
    and any(.cases[]; .case_id == "stale_artifact_evidence" and (.expected.fail_closed_reasons | index("stale_artifact_evidence") != null))
    and any(.cases[]; .case_id == "local_rch_fallback_contamination" and (.expected.fail_closed_reasons | index("local_rch_fallback_contamination") != null))
  ' "$fixtures_path" >/dev/null
}

run_check() {
  bash -n "$portfolio_script"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$portfolio_script" "${BASH_SOURCE[0]}"
  fi
  jq empty "$fixtures_path" >/dev/null
  fixtures_shape_ok
  grep -Fq 'runs_cargo: false' "$portfolio_script"
  grep -Fq 'claims_command_success: false' "$portfolio_script"
  grep -Fq 'bare_cargo_candidate' "$portfolio_script"
  record_pass "shell syntax and fixture shape"
}

write_case_input() {
  local case_id="$1"
  local input_path="$2"
  jq --arg case_id "$case_id" '
    (.cases[] | select(.case_id == $case_id)) as $case
    | (.default_input * ($case.input_patch // {}))
    | .case_id = $case.case_id
  ' "$fixtures_path" >"$input_path"
}

run_case() {
  local tmp_root="$1"
  local case_id="$2"
  local case_dir="${tmp_root}/${case_id}"
  local input_path="${case_dir}/input.json"
  local actual_exit expected_decision expected_state expected_reasons
  mkdir -p "$case_dir"
  write_case_input "$case_id" "$input_path"

  expected_decision="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected.decision' "$fixtures_path")"
  expected_state="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected.portfolio_state' "$fixtures_path")"
  expected_reasons="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | (.expected.fail_closed_reasons // []) | join(",")' "$fixtures_path")"

  set +e
  "$portfolio_script" \
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

  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_state "$expected_state" '
    .schema_version == "franken-engine.swarm-proof-portfolio-plan.v1"
    and .decision == $expected_decision
    and .portfolio_state == $expected_state
    and .non_mutation_attestation.runs_cargo == false
    and .non_mutation_attestation.runs_rch == false
    and .non_mutation_attestation.claims_command_success == false
    and all(.portfolio_items[]; ((.command | contains("cargo ")) == false) or (.command | contains("rch exec --")))
  ' "${case_dir}/out/proof_portfolio_plan.json" >/dev/null || {
    record_failure "${case_id} report shape mismatch"
    return
  }

  if [[ -n "$expected_reasons" ]]; then
    IFS=',' read -r -a reason_codes <<<"$expected_reasons"
    for reason_code in "${reason_codes[@]}"; do
      jq -e --arg reason_code "$reason_code" \
        'any(.fail_closed_reasons[]?; .code == $reason_code)' \
        "${case_dir}/out/proof_portfolio_plan.json" >/dev/null || {
        record_failure "${case_id} missing reason ${reason_code}"
        return
      }
    done
  fi

  jq -s 'length >= 1' "${case_dir}/out/events.jsonl" >/dev/null
  grep -Fq './scripts/swarm_proof_portfolio_optimizer.sh' "${case_dir}/out/commands.txt"
  grep -Fq 'Swarm Proof Portfolio Plan' "${case_dir}/out/report.md"
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
      run_selftest "$(mktemp -d "${TMPDIR:-/tmp}/swarm-proof-portfolio.XXXXXX")"
    fi
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      if [[ -z "$output_dir" ]]; then
        output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-proof-portfolio-run.XXXXXX")"
      fi
      mkdir -p "$output_dir"
      run_selftest "$output_dir"
      printf 'swarm_proof_portfolio_smoke_artifacts=%s\n' "$output_dir"
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
