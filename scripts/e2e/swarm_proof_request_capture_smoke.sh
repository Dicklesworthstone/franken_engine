#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${root_dir}/scripts/swarm_proof_request_capture.sh"
docs_path="${root_dir}/docs/SWARM_PROOF_REQUEST_CAPTURE.md"
cases_path="${root_dir}/scripts/testdata/swarm_proof_request_capture/cases.json"
mode="${1:-check}"
output_root="${2:-${SWARM_PROOF_REQUEST_CAPTURE_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-proof-request-capture-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS swarm-proof-request-capture %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-proof-request-capture %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_proof_request_capture_smoke.sh [check|selftest] [output_root]
EOF
}

docs_shape_ok() {
  grep -Fq 'never runs Cargo or RCH' "$docs_path" \
    && grep -Fq 'missing Agent Mail' "$docs_path" \
    && grep -Fq 'stale br/bv snapshot' "$docs_path" \
    && grep -Fq 'dirty git paths outside the claimed lane' "$docs_path" \
    && grep -Fq 'RCH local fallback contamination' "$docs_path" \
    && grep -Fq 'trace_id' "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-request-capture-fixtures.v1"
    and (.cases | length) == 6
    and all(.cases[]; has("case_id") and has("sources") and has("expected"))
    and ([.cases[].expected.decision] | unique | sort) == ["fail_closed", "pass"]
    and ([.cases[].expected.fail_closed_reasons[]?] | unique | sort) == [
      "ambiguous_command_text",
      "dirty_outside_claimed_lane",
      "local_fallback_contamination",
      "missing_agent_mail_context",
      "stale_br_snapshot"
    ]
  ' "$cases_path" >/dev/null
}

script_static_ok() {
  bash -n "$script_path"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$script_path" "${BASH_SOURCE[0]}"
  fi
}

assert_case_output() {
  local case_json="$1"
  local output_dir="$2"
  local capture_path="${output_dir}/proof_request_capture.json"
  local case_id

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  jq empty "$capture_path" "${output_dir}/run_manifest.json" >/dev/null
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"

  jq -e \
    --argjson expected "$(jq '.expected' <<<"$case_json")" \
    --arg case_id "$case_id" '
      .schema_version == "franken-engine.swarm-proof-request-capture.v1"
      and .case_id == $case_id
      and .decision == $expected.decision
      and .fail_closed_reasons == $expected.fail_closed_reasons
      and .proof_request_count == $expected.proof_request_count
      and .non_mutation_attestation.runs_cargo == false
      and .non_mutation_attestation.runs_rch == false
      and .non_mutation_attestation.mutates_br == false
    ' "$capture_path" >/dev/null || record_failure "${case_id} capture report mismatch"

  if [[ "$(jq -r '.expected.decision' <<<"$case_json")" == "pass" ]]; then
    jq -e --arg expected_command "$(jq -r '.expected.command' <<<"$case_json")" '
      .proof_requests | length == 1
      and .[0].trace_id != ""
      and .[0].command == $expected_command
      and (.[0].source_evidence | length) == 4
      and all(.[0].source_evidence[]; (.evidence_path // "") != "" and (.id // "") != "")
    ' "$capture_path" >/dev/null || record_failure "${case_id} proof request row mismatch"
    test -s "${output_dir}/proof_requests.jsonl" || record_failure "${case_id} missing proof_requests.jsonl row"
  else
    if [[ -s "${output_dir}/proof_requests.jsonl" ]]; then
      record_failure "${case_id} emitted proof request rows for fail-closed case"
    fi
  fi
}

run_case() {
  local case_json="$1"
  local tmp_root="$2"
  local case_id case_dir input_path expected_exit actual_exit

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${tmp_root}/${case_id}"
  input_path="${case_dir}/fixture.json"
  mkdir -p "$case_dir"
  jq '.' <<<"$case_json" >"$input_path"

  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"
  set +e
  "$script_path" --fixture-json "$input_path" --output-dir "${case_dir}/out" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected ${expected_exit}"
    return
  fi

  assert_case_output "$case_json" "${case_dir}/out"
  record_pass "$case_id"
}

run_check() {
  jq empty "$cases_path" >/dev/null
  script_static_ok
  docs_shape_ok || record_failure "docs shape"
  fixtures_shape_ok || record_failure "fixture shape"

  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  local tmp_root="$1"

  run_check
  if [[ "$failures" -ne 0 ]]; then
    return
  fi

  while IFS= read -r case_json; do
    run_case "$case_json" "$tmp_root"
  done < <(jq -c '.cases[]' "$cases_path")
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest "$output_root"
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

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
