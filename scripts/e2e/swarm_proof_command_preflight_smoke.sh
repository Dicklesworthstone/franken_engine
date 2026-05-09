#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${root_dir}/scripts/swarm_proof_command_preflight.sh"
contract_path="${root_dir}/docs/swarm_proof_command_preflight_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_PROOF_COMMAND_PREFLIGHT.md"
cases_path="${root_dir}/scripts/testdata/swarm_proof_command_preflight/cases.json"
mode="${1:-check}"
output_root="${2:-${SWARM_PROOF_COMMAND_PREFLIGHT_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-proof-command-preflight-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS swarm-proof-command-preflight %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-proof-command-preflight %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_proof_command_preflight_smoke.sh [check|selftest] [output_root]
EOF
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-command-preflight-contract.v1"
    and .bead_id == "bd-ua5n2.9"
    and (.depends_on | index("bd-ua5n2.1") != null)
    and .heavy_command_policy.cargo_requires_rch_exec == true
    and .heavy_command_policy.accepted_heavy_prefix == "rch exec -- env"
    and .heavy_command_policy.target_dir_required == true
    and .heavy_command_policy.shell_wrappers_allowed == false
    and .heavy_command_policy.bare_cargo_allowed == false
    and (.accepted_env_allowlist | index("CARGO_TARGET_DIR") != null)
    and (.accepted_env_allowlist | index("RCH_VISIBILITY") != null)
    and (.valid_decisions | sort) == ["needs_human_review", "non_heavy_read_only", "proof_safe", "proof_unsafe"]
    and (.fixture_cases | length) == 8
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_br == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'never executes the command under inspection' "$docs_path" \
    && grep -Fq 'shell-wrapped Cargo or RCH commands' "$docs_path" \
    && grep -Fq 'bare local Cargo' "$docs_path" \
    && grep -Fq 'unsupported env leakage' "$docs_path" \
    && grep -Fq 'RCH_VISIBILITY' "$docs_path" \
    && grep -Fq '/tmp/rch_target_franken_engine_<safe_bead_id>' "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-command-preflight-fixtures.v1"
    and .contract_schema_version == "franken-engine.swarm-proof-command-preflight-contract.v1"
    and (.cases | length) == 8
    and all(.cases[]; has("case_id") and has("command") and has("context") and has("expected"))
    and ([.cases[].expected.decision] | unique | sort) == ["needs_human_review", "non_heavy_read_only", "proof_safe", "proof_unsafe"]
    and ([.cases[].expected.reason_code] | unique | sort) == [
      "bare_cargo_not_allowed",
      "direct_rch_cargo_proof",
      "missing_rch_visibility",
      "missing_target_dir_policy",
      "non_heavy_read_only",
      "shell_wrapper_fallback_risk",
      "unknown_command_shape",
      "unsupported_env_leakage"
    ]
    and all(.cases[]; (.expected.remediation | length) >= 40)
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
  local preflight_path="${output_dir}/preflight_report.json"
  local manifest_path="${output_dir}/run_manifest.json"
  local case_id

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  jq empty "$preflight_path" "$manifest_path" >/dev/null
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"

  jq -e \
    --argjson expected "$(jq '.expected' <<<"$case_json")" \
    --arg case_id "$case_id" '
      .schema_version == "franken-engine.swarm-proof-command-preflight.v1"
      and .case_id == $case_id
      and .decision == $expected.decision
      and .reason_code == $expected.reason_code
      and .command.command_kind == $expected.command_kind
      and .command.transport == $expected.transport
      and .remediation == $expected.remediation
      and .pasteable_command == $expected.pasteable_command
      and .non_mutation_attestation.runs_cargo == false
      and .non_mutation_attestation.runs_rch == false
      and .non_mutation_attestation.mutates_br == false
    ' "$preflight_path" >/dev/null || record_failure "${case_id} preflight output mismatch"
}

run_case() {
  local case_json="$1"
  local tmp_root="$2"
  local case_id case_dir input_path expected_exit actual_exit

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${tmp_root}/${case_id}"
  input_path="${case_dir}/input.json"
  mkdir -p "$case_dir"
  jq '.' <<<"$case_json" >"$input_path"

  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"
  set +e
  "$script_path" --command-json "$input_path" --output-dir "${case_dir}/out" >/dev/null 2>&1
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
  jq empty "$contract_path" "$cases_path" >/dev/null
  script_static_ok
  contract_shape_ok || record_failure "contract shape"
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
