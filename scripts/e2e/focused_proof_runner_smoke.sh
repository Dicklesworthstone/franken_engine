#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runner="${root_dir}/scripts/focused_proof_runner.sh"
# shellcheck source=scripts/lib/proof_artifact_contract.sh
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

record_pass() {
  printf 'PASS focused-proof-runner %s\n' "$1"
}

record_failure() {
  printf 'FAIL focused-proof-runner %s\n' "$1" >&2
}

run_pass_case() {
  local case_root="$1"
  local run_id="$2"

  FOCUSED_PROOF_ARTIFACT_ROOT="${case_root}" \
  FOCUSED_PROOF_RUN_ID="${run_id}" \
  FOCUSED_PROOF_BEAD_ID="bd-fk5cb" \
  FOCUSED_PROOF_SUITE="focused_proof_runner_smoke" \
  FOCUSED_PROOF_COMMAND="printf focused-proof-ok" \
  FOCUSED_PROOF_CARGO_PACKAGE="frankenengine-engine" \
  FOCUSED_PROOF_EXPECTED_TARGETS="focused_proof_runner_smoke,frankenengine-engine" \
  FOCUSED_PROOF_OBSERVED_TARGETS=$'frankenengine-engine|test|focused_proof_runner_smoke|test|true|true|explicit smoke\nfrankenengine-engine|lib|frankenengine-engine|test|true|false|test harness dependency' \
  FOCUSED_PROOF_WORKER="smoke-worker" \
  FOCUSED_PROOF_SYNC_ROOTS="/data/projects/franken_engine,/data/projects/frankensqlite" \
  FOCUSED_PROOF_DURATION_MS_OVERRIDE=0 \
  "${runner}" >/dev/null
}

validate_pass_bundle() {
  local run_dir="$1"
  local manifest_path="${run_dir}/manifest.json"
  local report_path="${run_dir}/report.json"
  local source_report_path="${run_dir}/source_report.json"
  local proof_cost_path="${run_dir}/proof_cost_manifest.json"

  jq -e '
    .schema_version == "franken-engine.proof-artifact-manifest.v1"
    and .status == "pass"
    and .artifact_paths.proof_cost_manifest_json != null
    and any(.generated_artifacts[]; .role == "proof_cost_manifest")
  ' "${manifest_path}" >/dev/null
  record_pass "standard bundle includes proof cost manifest"

  jq -e '
    .schema_version == "franken-engine.proof-artifact-report.v1"
    and .status == "pass"
    and .failure_count == 0
  ' "${report_path}" >/dev/null
  record_pass "standard report passes"

  jq -e '
    .schema_version == "franken-engine.focused-proof-runner-report.v1"
    and .status == "pass"
    and .target_cardinality == 2
    and (.sync_roots | length) == 2
    and (.unexpected_targets | length) == 0
  ' "${source_report_path}" >/dev/null
  record_pass "source report captures worker, sync roots, and target cardinality"

  jq -e '
    .schema_version == "franken-engine.proof-cost-manifest.v1"
    and .bead_id == "bd-fk5cb"
    and .focused_suite == "focused_proof_runner_smoke"
    and .target_counts.test == 1
    and .target_counts.lib == 1
    and .total_compiled_targets == 2
    and .total_linked_targets == 1
    and (.unexpected_targets | length) == 0
  ' "${proof_cost_path}" >/dev/null
  record_pass "proof cost manifest is well formed"
}

run_broadening_case() {
  local case_root="$1"
  local run_id="$2"
  local output

  set +e
  output="$(
    FOCUSED_PROOF_ARTIFACT_ROOT="${case_root}" \
    FOCUSED_PROOF_RUN_ID="${run_id}" \
    FOCUSED_PROOF_BEAD_ID="bd-fk5cb" \
    FOCUSED_PROOF_SUITE="focused_proof_runner_smoke_broadening" \
    FOCUSED_PROOF_COMMAND="printf focused-proof-ok" \
    FOCUSED_PROOF_CARGO_PACKAGE="frankenengine-engine" \
    FOCUSED_PROOF_EXPECTED_TARGETS="focused_proof_runner_smoke" \
    FOCUSED_PROOF_OBSERVED_TARGETS=$'frankenengine-engine|test|focused_proof_runner_smoke|test|true|true|explicit smoke\nfrankenengine-engine|test|unexpected_broad_target|test|true|true|hidden fanout' \
    FOCUSED_PROOF_WORKER="smoke-worker" \
    FOCUSED_PROOF_DURATION_MS_OVERRIDE=0 \
    "${runner}" 2>&1
  )"
  local exit_code=$?
  set -e

  if [[ "${exit_code}" -eq 0 ]]; then
    record_failure "broadening case unexpectedly passed"
    printf '%s\n' "${output}" >&2
    return 1
  fi
  record_pass "broadening case fails closed"

  jq -e '
    .status == "fail"
    and .failure_reason == "unexpected_target_fanout"
    and (.unexpected_targets | index("frankenengine-engine:test:unexpected_broad_target") != null)
  ' "${case_root}/${run_id}/source_report.json" >/dev/null
  record_pass "broadening failure is recorded in source report"

  jq -e '
    .status == "fail"
    and any(.generated_artifacts[]; .role == "proof_cost_manifest")
  ' "${case_root}/${run_id}/manifest.json" >/dev/null
  record_pass "broadening failure still emits artifact bundle"
}

run_command_failure_case() {
  local case_root="$1"
  local run_id="$2"
  local output

  set +e
  output="$(
    FOCUSED_PROOF_ARTIFACT_ROOT="${case_root}" \
    FOCUSED_PROOF_RUN_ID="${run_id}" \
    FOCUSED_PROOF_BEAD_ID="bd-fk5cb" \
    FOCUSED_PROOF_SUITE="focused_proof_runner_smoke_command_failure" \
    FOCUSED_PROOF_COMMAND="exit 7" \
    FOCUSED_PROOF_CARGO_PACKAGE="frankenengine-engine" \
    FOCUSED_PROOF_EXPECTED_TARGETS="focused_proof_runner_smoke" \
    FOCUSED_PROOF_OBSERVED_TARGETS=$'frankenengine-engine|test|focused_proof_runner_smoke|test|true|true|explicit smoke' \
    FOCUSED_PROOF_WORKER="smoke-worker" \
    FOCUSED_PROOF_DURATION_MS_OVERRIDE=0 \
    "${runner}" 2>&1
  )"
  local exit_code=$?
  set -e

  if [[ "${exit_code}" -ne 7 ]]; then
    record_failure "command failure case returned ${exit_code}, expected 7"
    printf '%s\n' "${output}" >&2
    return 1
  fi
  record_pass "command failure case preserves wrapped exit code"

  jq -e '
    .status == "fail"
    and .failure_reason == "command_exit_7"
    and (.unexpected_targets | length) == 0
  ' "${case_root}/${run_id}/source_report.json" >/dev/null
  record_pass "command failure is recorded in source report"

  jq -e '
    .status == "fail"
    and .failure_count == 1
  ' "${case_root}/${run_id}/report.json" >/dev/null
  record_pass "command failure increments standard bundle failure count"
}

run_selftest() {
  local tmp_parent tmp_root pass_a pass_b fail_root command_fail_root

  tmp_parent="${FOCUSED_PROOF_RUNNER_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "${tmp_parent}"
  tmp_root="$(mktemp -d "${tmp_parent%/}/focused-proof-runner-smoke.XXXXXX")"
  pass_a="${tmp_root}/pass-a"
  pass_b="${tmp_root}/pass-b"
  fail_root="${tmp_root}/fail"
  command_fail_root="${tmp_root}/command-fail"

  run_pass_case "${pass_a}" "stable"
  validate_pass_bundle "${pass_a}/stable"

  run_pass_case "${pass_b}" "stable"
  if [[ "$(proof_contract_sha256_file "${pass_a}/stable/proof_cost_manifest.json")" != "$(proof_contract_sha256_file "${pass_b}/stable/proof_cost_manifest.json")" ]]; then
    record_failure "proof cost manifests differ for identical inputs"
    return 1
  fi
  record_pass "proof cost manifest is deterministic for identical inputs"

  run_broadening_case "${fail_root}" "broadening"
  run_command_failure_case "${command_fail_root}" "command-failure"
  printf 'focused_proof_runner_smoke_artifacts=%s\n' "${tmp_root}"
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
