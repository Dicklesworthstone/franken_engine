#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="${root_dir}/scripts/rch_policy_compliance_gate.sh"
golden_dir="${root_dir}/scripts/testdata/goldens"

record_pass() {
  printf 'PASS rch-policy-compliance %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-policy-compliance %s\n' "$1" >&2
}

write_fixture() {
  local path="$1"
  local content="$2"

  mkdir -p "$(dirname "$path")"
  printf '%s\n' "$content" >"$path"
}

canonicalize_diagnostics() {
  local diagnostics_path="$1"
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
    | del(.artifact_paths)
  ' "$diagnostics_path"
}

write_case_golden() {
  local tmp_root="$1"
  local output_dir="$2"
  local actual_path="$3"

  canonicalize_diagnostics "${output_dir}/diagnostics.json" "$tmp_root" >"$actual_path"
}

compare_case_golden() {
  local case_name="$1"
  local actual_path="$2"
  local golden_path="$3"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
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
  local output_dir="$1"
  shift

  "$gate" --output-dir "$output_dir" "$@" >/dev/null
  jq -e '.status == "pass" and .violation_count == 0' "${output_dir}/diagnostics.json" >/dev/null
  record_pass "gate passed"
}

run_gate_expect_fail() {
  local output_dir="$1"
  local expected_kind="$2"
  shift 2
  local output exit_code

  set +e
  output="$("$gate" --output-dir "$output_dir" "$@" 2>&1)"
  exit_code=$?
  set -e

  if [[ "$exit_code" -eq 0 ]]; then
    record_failure "gate unexpectedly passed for ${expected_kind}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  jq -e --arg expected_kind "$expected_kind" '
    .status == "fail"
    and .violation_count >= 1
    and (.violations | map(.kind) | index($expected_kind) != null)
  ' "${output_dir}/diagnostics.json" >/dev/null
  grep -Fq "$expected_kind" "${output_dir}/report.md"
  record_pass "gate failed on ${expected_kind}"
}

run_selftest() {
  local tmp_parent tmp_root pass_file wrapper_file no_fallback_doc bare_file missing_target_file fallback_file waiver_file

  tmp_parent="${RCH_POLICY_COMPLIANCE_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/rch-policy-compliance.XXXXXX")"

  pass_file="${tmp_root}/fixtures/pass.sh"
  wrapper_file="${tmp_root}/fixtures/wrapper.sh"
  no_fallback_doc="${tmp_root}/fixtures/no-fallback.md"
  bare_file="${tmp_root}/fixtures/bare.sh"
  missing_target_file="${tmp_root}/fixtures/missing-target.sh"
  fallback_file="${tmp_root}/fixtures/local-fallback.sh"
  waiver_file="${tmp_root}/fixtures/waiver.md"

  # shellcheck disable=SC2016
  write_fixture "$pass_file" '#!/usr/bin/env bash
set -euo pipefail
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_example cargo test -p frankenengine-engine --lib
if grep -q "falling back to local" "$log_path"; then # reject local fallback
  echo "refusing local fallback"
  exit 1
fi'

  # shellcheck disable=SC2016
  write_fixture "$wrapper_file" '#!/usr/bin/env bash
set -euo pipefail

toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_wrapper_fixture}"

run_rch() {
  rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
}

run_step() {
  local command_text="$1"
  shift
  printf "==> %s\n" "$command_text"
  run_rch "$@"
}

run_step "cargo check -p frankenengine-engine --all-targets" \
  cargo check -p frankenengine-engine --all-targets
run_step "cargo test -p frankenengine-engine --test storage_adapter" \
  cargo test -p frankenengine-engine --test storage_adapter'

  write_fixture "$no_fallback_doc" '# Operator policy

Validation operations are rch only, no local fallback.'

  write_fixture "$bare_file" '#!/usr/bin/env bash
set -euo pipefail
cargo test -p frankenengine-engine --lib'

  write_fixture "$missing_target_file" '#!/usr/bin/env bash
set -euo pipefail
rch exec -- env RUSTUP_TOOLCHAIN=nightly cargo test -p frankenengine-engine --lib'

  # shellcheck disable=SC2016
  write_fixture "$fallback_file" '#!/usr/bin/env bash
set -euo pipefail
if grep -q "falling back to local" "$log_path"; then
  echo "warning: local fallback accepted"
fi'

  write_fixture "$waiver_file" '# Lightweight docs example.
# rch-policy-waive: bare_cargo reason=lightweight-doc-example-only
cargo test --help'

  run_gate_expect_pass "${tmp_root}/pass-output" "$no_fallback_doc" "$pass_file" "$waiver_file" "$wrapper_file"
  assert_case_golden \
    "pass" \
    "$tmp_root" \
    "${tmp_root}/pass-output" \
    "${golden_dir}/rch_policy_compliance_gate_pass.golden"

  run_gate_expect_fail "${tmp_root}/bare-output" "bare_cargo" "$bare_file"
  assert_case_golden \
    "bare-cargo" \
    "$tmp_root" \
    "${tmp_root}/bare-output" \
    "${golden_dir}/rch_policy_compliance_gate_bare_cargo.golden"

  run_gate_expect_fail "${tmp_root}/missing-target-output" "missing_target_dir" "$missing_target_file"
  assert_case_golden \
    "missing-target-dir" \
    "$tmp_root" \
    "${tmp_root}/missing-target-output" \
    "${golden_dir}/rch_policy_compliance_gate_missing_target_dir.golden"

  run_gate_expect_fail "${tmp_root}/local-fallback-output" "local_fallback_not_rejected" "$fallback_file"
  assert_case_golden \
    "local-fallback" \
    "$tmp_root" \
    "${tmp_root}/local-fallback-output" \
    "${golden_dir}/rch_policy_compliance_gate_local_fallback.golden"

  printf 'rch_policy_compliance_gate_smoke_artifacts=%s\n' "$tmp_root"
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
