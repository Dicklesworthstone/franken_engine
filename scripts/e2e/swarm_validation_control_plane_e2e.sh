#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
run_id="${SWARM_VALIDATION_CONTROL_PLANE_E2E_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
artifact_root="${SWARM_VALIDATION_CONTROL_PLANE_E2E_ARTIFACT_ROOT:-${root_dir}/artifacts/swarm_validation_control_plane_e2e/${run_id}}"
wrapper_dir="${artifact_root}/wrapper"
commands_path="${wrapper_dir}/commands.txt"
events_path="${wrapper_dir}/events.jsonl"
report_path="${wrapper_dir}/report.json"
stdout_path="${wrapper_dir}/selftest.stdout.log"
stderr_path="${wrapper_dir}/selftest.stderr.log"

record_pass() {
  printf 'PASS swarm-validation-control-plane-e2e %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-validation-control-plane-e2e %s\n' "$1" >&2
}

write_event() {
  local step="$1"
  local decision="$2"
  local exit_code="$3"

  jq -nc \
    --arg schema_version "franken-engine.proof-artifact-event.v1" \
    --arg event_name "swarm_validation_control_plane_e2e.wrapper_step" \
    --arg step_id "${step}" \
    --arg command_id "${step}" \
    --arg decision "${decision}" \
    --argjson exit_code "${exit_code}" \
    '{
      schema_version: $schema_version,
      event_name: $event_name,
      severity: (if $decision == "pass" then "info" else "error" end),
      step_id: $step_id,
      command_id: $command_id,
      decision: $decision,
      exit_code: $exit_code,
      duration_ms: 0
    }' >>"${events_path}"
}

ensure_wrapper_dir() {
  mkdir -p "${wrapper_dir}"
  : >"${commands_path}"
  : >"${events_path}"
}

run_check() {
  local scope_file

  ensure_wrapper_dir
  bash -n "${BASH_SOURCE[0]}"
  record_pass "bash syntax"

  jq empty "${root_dir}/docs/swarm_validation_control_plane_contract_v1.json"
  record_pass "contract json parses"

  scope_file="${wrapper_dir}/rch-policy-scope.txt"
  printf '%s\n' \
    "scripts/e2e/swarm_validation_control_plane_e2e.sh" \
    "docs/swarm_validation_control_plane_contract_v1.json" \
    >"${scope_file}"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${wrapper_dir}/rch-policy-check" \
    --scope-file "${scope_file}" >/dev/null
  record_pass "rch policy compliance"
}

run_selftest() {
  local target_dir
  local exit_code

  run_check
  target_dir="${SWARM_VALIDATION_CONTROL_PLANE_E2E_TARGET_DIR:-/tmp/rch_target_franken_engine_bd_3snv2_e2e}"

  printf '%q ' rch exec -- env "CARGO_TARGET_DIR=${target_dir}" "SWARM_VALIDATION_CONTROL_PLANE_E2E_ARTIFACT_ROOT=${artifact_root}" cargo test -p frankenengine-engine --test swarm_validation_control_plane_e2e -- --nocapture >"${commands_path}"
  printf '\n' >>"${commands_path}"

  set +e
  rch exec -- env "CARGO_TARGET_DIR=${target_dir}" "SWARM_VALIDATION_CONTROL_PLANE_E2E_ARTIFACT_ROOT=${artifact_root}" cargo test -p frankenengine-engine --test swarm_validation_control_plane_e2e -- --nocapture >"${stdout_path}" 2>"${stderr_path}"
  exit_code=$?
  set -e

  if rg -q '(\[RCH\] local|falling back to local|local fallback|running locally)' "${stdout_path}" "${stderr_path}"; then # detect local fallback marker
    write_event "rch-local-fallback-detected" "fail" 42
    record_failure "detected rch local fallback marker"
    exit 42
  fi

  if [[ "${exit_code}" -ne 0 ]]; then
    write_event "rust-e2e" "fail" "${exit_code}"
    record_failure "rust e2e exited ${exit_code}"
    printf 'stdout=%s\nstderr=%s\n' "${stdout_path}" "${stderr_path}" >&2
    exit "${exit_code}"
  fi

  write_event "rust-e2e" "pass" 0
  jq -n \
    --arg schema_version "franken-engine.swarm-validation-control-plane-e2e-wrapper.v1" \
    --arg artifact_root "${artifact_root}" \
    --arg commands_path "${commands_path}" \
    --arg events_path "${events_path}" \
    --arg stdout_path "${stdout_path}" \
    --arg stderr_path "${stderr_path}" \
    '{
      schema_version: $schema_version,
      status: "pass",
      artifact_root: $artifact_root,
      artifact_paths: {
        commands_txt: $commands_path,
        events_jsonl: $events_path,
        stdout_log: $stdout_path,
        stderr_log: $stderr_path
      }
    }' >"${report_path}"

  record_pass "selftest"
  printf 'swarm_validation_control_plane_e2e_artifacts=%s\n' "${artifact_root}"
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
