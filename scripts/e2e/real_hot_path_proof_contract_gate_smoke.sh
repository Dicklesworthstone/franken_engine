#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="${root_dir}/scripts/real_hot_path_proof_contract_gate.sh"
fixture_dir="${root_dir}/scripts/testdata/real_hot_path_proof_contract"
golden_dir="${root_dir}/scripts/testdata/goldens"
expected_source_revision="golden-revision-20260514"

record_pass() {
  printf 'PASS real-hot-path-proof-contract %s\n' "$1"
}

record_failure() {
  printf 'FAIL real-hot-path-proof-contract %s\n' "$1" >&2
}

canonicalize_json() {
  local path="$1"
  local tmp_root="$2"

  jq --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "object" then
        with_entries(.value |= scrub)
      elif type == "array" then
        map(scrub)
      elif type == "string" then
        split($tmp_root) | join("[SMOKE_ROOT]")
      else
        .
      end;
    scrub
  ' "$path"
}

canonicalize_report() {
  local path="$1"
  local tmp_root="$2"

  jq -R -s -r -j --arg tmp_root "$tmp_root" '
    split($tmp_root) | join("[SMOKE_ROOT]")
  ' "$path"
}

write_case_golden() {
  local tmp_root="$1"
  local output_dir="$2"
  local actual_path="$3"

  {
    printf '=== DIAGNOSTICS ===\n'
    canonicalize_json "${output_dir}/diagnostics.json" "$tmp_root"
    printf '=== REPORT ===\n'
    canonicalize_report "${output_dir}/report.md" "$tmp_root"
  } >"$actual_path"
}

compare_case_golden() {
  local case_name="$1"
  local actual_path="$2"
  local golden_path="$3"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    mkdir -p "$golden_dir"
    cp "$actual_path" "$golden_path"
    record_pass "updated golden ${case_name}"
    return 0
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "missing golden ${golden_path}"
    return 1
  fi

  if ! diff -u "$golden_path" "$actual_path"; then
    record_failure "golden drift for ${case_name}; set UPDATE_GOLDENS=1 only after reviewing the diff"
    return 1
  fi

  record_pass "golden matches ${case_name}"
}

assert_case_golden() {
  local case_name="$1"
  local tmp_root="$2"
  local output_dir="$3"
  local golden_path="$4"
  local actual_path="${tmp_root}/${case_name}.actual.golden"

  write_case_golden "$tmp_root" "$output_dir" "$actual_path"
  compare_case_golden "$case_name" "$actual_path" "$golden_path"
}

run_gate_expect_pass() {
  local case_name="$1"
  local output_dir="$2"

  "$gate" \
    --bundle-dir "${fixture_dir}/${case_name}" \
    --output-dir "$output_dir" \
    --source-revision "$expected_source_revision" >/dev/null

  jq -e '
    .schema_version == "franken-engine.real-hot-path-proof-contract-gate.v1"
    and .status == "pass"
    and .failure_count == 0
    and .contract.workload_id == "real_runtime_hot_paths"
    and .contract.source_revision == "golden-revision-20260514"
    and .contract.target_dir_policy == "off_repo_tmp_required"
    and .contract.proof_state.remote_execution_verified == true
    and (.contract.correctness_digest | type == "string" and length == 64)
  ' "${output_dir}/diagnostics.json" >/dev/null

  record_pass "gate passed ${case_name}"
}

run_gate_expect_fail() {
  local case_name="$1"
  local output_dir="$2"
  local expected_code="$3"
  local output exit_code

  set +e
  output="$("$gate" \
    --bundle-dir "${fixture_dir}/${case_name}" \
    --output-dir "$output_dir" \
    --source-revision "$expected_source_revision" 2>&1)"
  exit_code=$?
  set -e

  if [[ "$exit_code" -eq 0 ]]; then
    record_failure "gate unexpectedly passed for ${case_name}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  jq -e --arg expected_code "$expected_code" '
    .status == "fail"
    and .failure_count >= 1
    and (.failures | map(.code) | index($expected_code) != null)
  ' "${output_dir}/diagnostics.json" >/dev/null
  grep -Fq "$expected_code" "${output_dir}/report.md"
  record_pass "gate failed ${case_name} on ${expected_code}"
}

run_selftest() {
  local tmp_parent tmp_root

  tmp_parent="${REAL_HOT_PATH_PROOF_CONTRACT_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/real-hot-path-proof-contract.XXXXXX")"

  run_gate_expect_pass "valid" "${tmp_root}/valid-output"
  assert_case_golden \
    "valid" \
    "$tmp_root" \
    "${tmp_root}/valid-output" \
    "${golden_dir}/real_hot_path_proof_contract_valid.golden"

  run_gate_expect_fail "malformed_manifest" "${tmp_root}/malformed-output" "FE-REAL-HOT-PATH-CONTRACT-MALFORMED-MANIFEST"
  assert_case_golden \
    "malformed-manifest" \
    "$tmp_root" \
    "${tmp_root}/malformed-output" \
    "${golden_dir}/real_hot_path_proof_contract_malformed_manifest.golden"

  run_gate_expect_fail "missing_artifact" "${tmp_root}/missing-output" "FE-REAL-HOT-PATH-CONTRACT-MISSING-ARTIFACT"
  assert_case_golden \
    "missing-artifact" \
    "$tmp_root" \
    "${tmp_root}/missing-output" \
    "${golden_dir}/real_hot_path_proof_contract_missing_artifact.golden"

  run_gate_expect_fail "stale_source" "${tmp_root}/stale-output" "FE-REAL-HOT-PATH-CONTRACT-STALE-SOURCE-REVISION"
  assert_case_golden \
    "stale-source" \
    "$tmp_root" \
    "${tmp_root}/stale-output" \
    "${golden_dir}/real_hot_path_proof_contract_stale_source.golden"

  printf 'real_hot_path_proof_contract_gate_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check|selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
