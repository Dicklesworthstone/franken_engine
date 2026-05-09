#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
diff_script="${root_dir}/scripts/swarm_since_green_slo_diff.sh"
fixtures_path="${SWARM_SINCE_GREEN_SLO_DIFF_FIXTURES:-${root_dir}/scripts/testdata/swarm_since_green_slo_diff/cases.json}"
mode="${1:-check}"
output_dir="${2:-${SWARM_SINCE_GREEN_SLO_DIFF_OUTPUT_DIR:-}}"
failures=0

case_ids=(
  clean_no_diff
  stale_current_bundle
  missing_green_baseline
  local_fallback_current
  schema_drift
  claim_downgrade_required
)

record_pass() {
  printf 'PASS swarm-since-green-slo-diff %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-since-green-slo-diff %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_since_green_slo_diff_smoke.sh [check|selftest|run] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-since-green-slo-diff.fixtures.v1"
    and (.default_input.schema_version == "franken-engine.swarm-since-green-slo-diff.input.v1")
    and ([.cases[].case_id] | sort) == ([
      "claim_downgrade_required",
      "clean_no_diff",
      "local_fallback_current",
      "missing_green_baseline",
      "schema_drift",
      "stale_current_bundle"
    ] | sort)
    and any(.cases[]; .case_id == "clean_no_diff" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "stale_current_bundle" and (.expected.degraded_reasons | index("stale_current_bundle") != null))
    and any(.cases[]; .case_id == "missing_green_baseline" and (.expected.fail_closed_reasons | index("missing_green_baseline") != null))
    and any(.cases[]; .case_id == "local_fallback_current" and (.expected.fail_closed_reasons | index("local_fallback_in_current") != null))
    and any(.cases[]; .case_id == "schema_drift" and (.expected.degraded_reasons | index("schema_drift") != null))
    and any(.cases[]; .case_id == "claim_downgrade_required" and (.expected.degraded_reasons | index("claim_downgrade_required") != null))
  ' "$fixtures_path" >/dev/null
}

run_check() {
  bash -n "$diff_script"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$diff_script" "${BASH_SOURCE[0]}"
  fi
  jq empty "$fixtures_path" >/dev/null
  fixtures_shape_ok
  grep -Fq 'reruns_proofs: false' "$diff_script"
  grep -Fq 'mutates_claims: false' "$diff_script"
  grep -Fq 'missing_green_baseline' "$diff_script"
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
  local actual_exit expected_decision expected_fail expected_degraded
  mkdir -p "$case_dir"
  write_case_input "$case_id" "$input_path"

  expected_decision="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected.decision' "$fixtures_path")"
  expected_fail="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | (.expected.fail_closed_reasons // []) | join(",")' "$fixtures_path")"
  expected_degraded="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | (.expected.degraded_reasons // []) | join(",")' "$fixtures_path")"

  set +e
  "$diff_script" \
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
    .schema_version == "franken-engine.swarm-since-green-slo-diff.v1"
    and .decision == $expected_decision
    and .non_mutation_attestation.reruns_proofs == false
    and .non_mutation_attestation.mutates_claims == false
    and .non_mutation_attestation.runs_rch == false
    and (.next_inspection_commands | length) >= 3
  ' "${case_dir}/out/since_green_diff.json" >/dev/null || {
    record_failure "${case_id} diff shape mismatch"
    return
  }

  if [[ -n "$expected_fail" ]]; then
    IFS=',' read -r -a reason_codes <<<"$expected_fail"
    for reason_code in "${reason_codes[@]}"; do
      jq -e --arg reason_code "$reason_code" \
        'any(.fail_closed_reasons[]?; .code == $reason_code)' \
        "${case_dir}/out/since_green_diff.json" >/dev/null || {
        record_failure "${case_id} missing fail-closed reason ${reason_code}"
        return
      }
    done
  fi

  if [[ -n "$expected_degraded" ]]; then
    IFS=',' read -r -a reason_codes <<<"$expected_degraded"
    for reason_code in "${reason_codes[@]}"; do
      jq -e --arg reason_code "$reason_code" \
        'any(.degraded_reasons[]?; .code == $reason_code)' \
        "${case_dir}/out/since_green_diff.json" >/dev/null || {
        record_failure "${case_id} missing degraded reason ${reason_code}"
        return
      }
    done
  fi

  jq -s 'length >= 1' "${case_dir}/out/events.jsonl" >/dev/null
  grep -Fq './scripts/swarm_since_green_slo_diff.sh' "${case_dir}/out/commands.txt"
  grep -Fq 'Since-Green Downgrade Summary' "${case_dir}/out/downgrade_summary.md"
  grep -Fq 'Swarm Since-Green SLO Diff' "${case_dir}/out/report.md"
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
      run_selftest "$(mktemp -d "${TMPDIR:-/tmp}/swarm-since-green-slo-diff.XXXXXX")"
    fi
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      if [[ -z "$output_dir" ]]; then
        output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-since-green-slo-diff-run.XXXXXX")"
      fi
      mkdir -p "$output_dir"
      run_selftest "$output_dir"
      printf 'swarm_since_green_slo_diff_smoke_artifacts=%s\n' "$output_dir"
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
