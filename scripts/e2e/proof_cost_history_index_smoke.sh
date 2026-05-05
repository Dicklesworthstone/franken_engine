#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
run_id="${PROOF_COST_HISTORY_INDEX_SMOKE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
artifact_root="${PROOF_COST_HISTORY_INDEX_SMOKE_ARTIFACT_ROOT:-${root_dir}/artifacts/proof_cost_history_index_smoke/${run_id}}"
commands_path="${artifact_root}/commands.txt"
report_path="${artifact_root}/report.json"
stdout_path="${artifact_root}/selftest.stdout.log"
stderr_path="${artifact_root}/selftest.stderr.log"

record_pass() {
  printf 'PASS proof-cost-history-index %s\n' "$1"
}

record_failure() {
  printf 'FAIL proof-cost-history-index %s\n' "$1" >&2
}

ensure_artifact_root() {
  mkdir -p "${artifact_root}"
  : >"${commands_path}"
}

detect_rch_local_fallback() {
  rg -q '(\[RCH\] local|falling back to local|fallback to local|local fallback|running locally|Remote execution failed: .*running locally|Dependency preflight blocked remote execution|RCH-E326)' "$@"
}

run_check() {
  local scope_file

  ensure_artifact_root
  bash -n "${BASH_SOURCE[0]}"
  record_pass "bash syntax"

  scope_file="${artifact_root}/rch-policy-scope.txt"
  printf '%s\n' \
    "scripts/e2e/proof_cost_history_index_smoke.sh" \
    "crates/franken-engine/src/proof_evidence_index.rs" \
    "crates/franken-engine/tests/proof_evidence_index_integration.rs" \
    >"${scope_file}"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${artifact_root}/rch-policy-check" \
    --scope-file "${scope_file}" >/dev/null
  record_pass "rch policy compliance"
}

run_selftest() {
  local target_dir
  local source_revision
  local exit_code

  run_check
  target_dir="${PROOF_COST_HISTORY_INDEX_SMOKE_TARGET_DIR:-/tmp/rch_target_franken_engine_bd_tgc6r}"
  source_revision="$(git -C "${root_dir}" rev-parse HEAD 2>/dev/null || printf unknown)"

  printf '%q ' rch exec -- env "CARGO_TARGET_DIR=${target_dir}" cargo test -p frankenengine-engine --test proof_evidence_index_integration proof_cost_history -- --nocapture >"${commands_path}"
  printf '\n' >>"${commands_path}"

  set +e
  rch exec -- env "CARGO_TARGET_DIR=${target_dir}" cargo test -p frankenengine-engine --test proof_evidence_index_integration proof_cost_history -- --nocapture >"${stdout_path}" 2>"${stderr_path}"
  exit_code=$?
  set -e

  if detect_rch_local_fallback "${stdout_path}" "${stderr_path}"; then
    record_failure "detected rch local fallback marker"
    jq -n \
      --arg schema_version "franken-engine.proof-cost-history-index-smoke.v1" \
      --arg source_revision "${source_revision}" \
      --arg commands_path "${commands_path}" \
      --arg stdout_path "${stdout_path}" \
      --arg stderr_path "${stderr_path}" \
      '{
        schema_version: $schema_version,
        status: "fail",
        failure_reason: "rch_local_fallback_detected",
        source_revision: $source_revision,
        artifact_paths: {
          commands_txt: $commands_path,
          stdout_log: $stdout_path,
          stderr_log: $stderr_path
        }
      }' >"${report_path}"
    exit 42
  fi

  if [[ "${exit_code}" -ne 0 ]]; then
    record_failure "rust proof-cost history tests exited ${exit_code}"
    printf 'stdout=%s\nstderr=%s\n' "${stdout_path}" "${stderr_path}" >&2
    exit "${exit_code}"
  fi

  jq -n \
    --arg schema_version "franken-engine.proof-cost-history-index-smoke.v1" \
    --arg source_revision "${source_revision}" \
    --arg artifact_root "${artifact_root}" \
    --arg commands_path "${commands_path}" \
    --arg stdout_path "${stdout_path}" \
    --arg stderr_path "${stderr_path}" \
    '{
      schema_version: $schema_version,
      status: "pass",
      source_revision: $source_revision,
      artifact_root: $artifact_root,
      artifact_paths: {
        commands_txt: $commands_path,
        stdout_log: $stdout_path,
        stderr_log: $stderr_path
      }
    }' >"${report_path}"

  record_pass "selftest"
  printf 'proof_cost_history_index_smoke_artifacts=%s\n' "${artifact_root}"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
