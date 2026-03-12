#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
rch_exec_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-1800}"
rch_build_timeout_sec="${RCH_BUILD_TIMEOUT_SEC:-${RCH_BUILD_TIMEOUT_SECONDS:-300}}"
artifact_root="${ORCHESTRATOR_CONTEXT_REFACTOR_ARTIFACT_ROOT:-artifacts/orchestrator_context_refactor}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_target_dir="/var/tmp/rch_target_franken_engine_orchestrator_context_refactor"
target_dir="${CARGO_TARGET_DIR:-${default_target_dir}}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-4}"
run_dir="${artifact_root}/${timestamp}"
rch_step_logs_dir="${run_dir}/rch_step_logs"
local_binary_path="${target_dir}/debug/franken_orchestrator_context_refactor"
rch_ready_attempts="${RCH_READY_ATTEMPTS:-12}"
rch_ready_sleep_seconds="${RCH_READY_SLEEP_SECONDS:-2}"

mkdir -p "$run_dir" "$rch_step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for orchestrator context refactor heavy commands" >&2
  exit 2
fi

if ! command -v timeout >/dev/null 2>&1; then
  echo "timeout is required to fail closed on orchestrator context refactor rch steps" >&2
  exit 2
fi

run_rch() {
  RCH_EXEC_TIMEOUT_SECONDS="${rch_exec_timeout_seconds}" \
  RCH_BUILD_TIMEOUT_SEC="${rch_build_timeout_sec}" \
    RCH_BUILD_TIMEOUT_SECONDS="${rch_build_timeout_sec}" \
    timeout --kill-after=30 "${rch_exec_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "$@"
}

run_rch_strict_logged() {
  local log_path="$1"
  shift

  local fifo_path fallback_flag_path reader_pid rch_pid rch_status=0
  local local_command_pattern="$*"
  local line

  fifo_path="$(mktemp -u "${TMPDIR:-/tmp}/rch-orchestrator-context-refactor-stream.XXXXXX")"
  fallback_flag_path="$(mktemp "${run_dir}/rch-fallback.XXXXXX")"
  rm -f "$fallback_flag_path"
  mkfifo "$fifo_path"
  : >"$log_path"

  {
    while IFS= read -r line || [[ -n "$line" ]]; do
      printf '%s\n' "$line" | tee -a "$log_path"
      if [[ "$line" == *"Remote execution failed: "*"running locally"* ||
        "$line" == *"Remote toolchain failure, falling back to local"* ||
        "$line" == *"falling back to local"* ||
        "$line" == *"fallback to local"* ||
        "$line" == *"local fallback"* ||
        "$line" == *"running locally"* ||
        "$line" == *"[RCH] local ("* ||
        "$line" == *"Failed to query daemon:"*"running locally"* ||
        "$line" == *"Dependency preflight blocked remote execution"* ||
        "$line" == *"RCH-E326"* ]]; then
        : >"$fallback_flag_path"
        if [[ -n "${rch_pid:-}" ]]; then
          kill "$rch_pid" 2>/dev/null || true
          pkill -P "$rch_pid" 2>/dev/null || true
        fi
        if [[ -n "$local_command_pattern" ]]; then
          pkill -f "$local_command_pattern" 2>/dev/null || true
        fi
        pkill -f "CARGO_TARGET_DIR=${target_dir}" 2>/dev/null || true
        pkill -f "${target_dir}" 2>/dev/null || true
      fi
    done <"$fifo_path"
  } &
  reader_pid=$!

  run_rch "$@" >"$fifo_path" 2>&1 &
  rch_pid=$!
  wait "$rch_pid" || rch_status=$?
  wait "$reader_pid" || true
  rm -f "$fifo_path"

  if [[ -f "$fallback_flag_path" ]]; then
    rm -f "$fallback_flag_path"
    if [[ -n "$local_command_pattern" ]]; then
      pkill -f "$local_command_pattern" 2>/dev/null || true
    fi
    pkill -f "CARGO_TARGET_DIR=${target_dir}" 2>/dev/null || true
    pkill -f "${target_dir}" 2>/dev/null || true
    return 125
  fi

  rm -f "$fallback_flag_path"
  return "$rch_status"
}

rch_strip_ansi() {
  sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' "$1"
}

rch_remote_exit_code() {
  local log_path="$1"
  local exit_line
  exit_line="$(rch_strip_ansi "$log_path" | grep -Eo 'Remote command finished: exit=[0-9]+' | tail -n 1 || true)"
  if [[ -z "$exit_line" ]]; then
    return 1
  fi
  printf '%s\n' "${exit_line##*=}"
}

rch_reported_timeout_seconds() {
  local log_path="$1"
  rch_strip_ansi "$log_path" | sed -nE 's/.*timeout_secs: ([0-9]+).*/\1/p' | tail -n 1
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote execution failed: .*running locally|Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

remote_code_allowed() {
  local code="$1"
  shift
  local allowed
  for allowed in "$@"; do
    if [[ "$code" == "$allowed" ]]; then
      return 0
    fi
  done
  return 1
}

ensure_rch_ready() {
  local attempts="${1:-5}"
  local sleep_seconds="${2:-2}"
  local attempt

  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if rch check >/dev/null 2>&1; then
      return 0
    fi
    sleep "${sleep_seconds}"
  done

  return 1
}

declare -a commands_run=()
step_index=0

run_step() {
  local command_text="$1"
  shift
  local allowed_codes=()
  while [[ "$#" -gt 0 && "$1" != "--" ]]; do
    allowed_codes+=("$1")
    shift
  done
  shift

  local log_path="${rch_step_logs_dir}/step_$(printf '%03d' "${step_index}").log"
  step_index=$((step_index + 1))
  commands_run+=("${command_text}")

  echo "==> ${command_text}"

  local status=0
  local fallback_detected=false

  if ! ensure_rch_ready "${rch_ready_attempts}" "${rch_ready_sleep_seconds}"; then
    echo "rch check not ready after ${rch_ready_attempts} attempts; refusing to risk local fallback" >&2
    return 1
  fi

  set +e
  run_rch_strict_logged "$log_path" "$@"
  status=$?
  set -e

  if [[ "$status" -eq 125 ]]; then
    fallback_detected=true
  fi

  if "$fallback_detected"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    return 1
  fi

  if [[ "$status" -eq 124 ]]; then
    echo "rch command timed out after ${rch_exec_timeout_seconds}s" >&2
    return 1
  fi

  local reported_timeout
  reported_timeout="$(rch_reported_timeout_seconds "$log_path" || true)"
  if [[ "$rch_build_timeout_sec" =~ ^[0-9]+$ && "$reported_timeout" =~ ^[0-9]+$ ]] &&
    (( reported_timeout < rch_build_timeout_sec )); then
    echo "rch reported timeout_secs=${reported_timeout} but requested build timeout is ${rch_build_timeout_sec}" >&2
    return 1
  fi

  local remote_exit_code
  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -z "$remote_exit_code" ]]; then
    if [[ "$status" -eq 0 ]]; then
      remote_exit_code="0"
    else
      echo "rch output missing remote exit marker" >&2
      return 1
    fi
  fi
  if ! remote_code_allowed "$remote_exit_code" "${allowed_codes[@]}"; then
    echo "unexpected remote exit code ${remote_exit_code} for: ${command_text}" >&2
    return 1
  fi
}

run_local_step() {
  local command_text="$1"
  shift
  commands_run+=("${command_text}")

  echo "==> ${command_text}"

  if ! "$@"; then
    return 1
  fi
}

run_check() {
  run_step \
    "cargo check -p frankenengine-engine --lib --bin franken_orchestrator_context_refactor" \
    0 -- \
    cargo check -p frankenengine-engine --lib --bin franken_orchestrator_context_refactor
}

run_tests() {
  run_step \
    "cargo test -p frankenengine-engine --lib orchestrator_context_refactor_passes_corrected_fixture -- --exact" \
    0 -- \
    cargo test -p frankenengine-engine --lib orchestrator_context_refactor_passes_corrected_fixture -- --exact
  run_step \
    "cargo test -p frankenengine-engine --lib orchestrator_context_refactor_fails_when_mock_context_returns -- --exact" \
    0 -- \
    cargo test -p frankenengine-engine --lib orchestrator_context_refactor_fails_when_mock_context_returns -- --exact
  run_step \
    "cargo test -p frankenengine-engine --lib write_orchestrator_context_refactor_bundle_emits_expected_artifacts -- --exact" \
    0 -- \
    cargo test -p frankenengine-engine --lib write_orchestrator_context_refactor_bundle_emits_expected_artifacts -- --exact
  run_step \
    "cargo test -p frankenengine-engine --test execution_orchestrator_integration orchestrator_context_refactor_bundle_emits_expected_artifacts -- --exact" \
    0 -- \
    cargo test -p frankenengine-engine --test execution_orchestrator_integration orchestrator_context_refactor_bundle_emits_expected_artifacts -- --exact
}

run_clippy() {
  run_step \
    "cargo clippy -p frankenengine-engine --lib --bin franken_orchestrator_context_refactor --test execution_orchestrator_integration -- -D warnings" \
    0 -- \
    cargo clippy -p frankenengine-engine --lib --bin franken_orchestrator_context_refactor --test execution_orchestrator_integration -- -D warnings
}

run_bundle() {
  run_step \
    "cargo build -p frankenengine-engine --bin franken_orchestrator_context_refactor" \
    0 -- \
    cargo build -p frankenengine-engine --bin franken_orchestrator_context_refactor

  [[ -x "${local_binary_path}" ]] || {
    echo "missing local binary: ${local_binary_path}" >&2
    return 1
  }

  run_local_step \
    "${local_binary_path} --out-dir ${run_dir} --workspace-root ${root_dir}" \
    "${local_binary_path}" --out-dir "${run_dir}" --workspace-root "${root_dir}"
}

case "$mode" in
  check)
    run_check
    run_bundle
    ;;
  test)
    run_tests
    run_bundle
    ;;
  clippy)
    run_clippy
    run_bundle
    ;;
  ci)
    run_check
    run_tests
    run_bundle
    run_clippy
    ;;
  *)
    echo "usage: $0 [check|test|clippy|ci]" >&2
    exit 2
    ;;
esac

for artifact in \
  production_context_path_contract.json \
  orchestrator_context_refactor_report.json \
  trace_ids.json \
  run_manifest.json \
  events.jsonl \
  commands.txt \
  env.json \
  repro.lock \
  summary.md; do
  [[ -f "${run_dir}/${artifact}" ]] || {
    echo "missing required artifact: ${run_dir}/${artifact}" >&2
    exit 1
  }
done

[[ -d "${run_dir}/step_logs" ]] || {
  echo "missing required artifact directory: ${run_dir}/step_logs" >&2
  exit 1
}

printf '%s\n' "${commands_run[@]}" > "${run_dir}/suite_commands.txt"
printf '%s\n' "${mode}" > "${run_dir}/suite_mode.txt"
printf '%s\n' "${rch_step_logs_dir}" > "${run_dir}/rch_step_logs_dir.txt"

echo "orchestrator context refactor artifacts: ${run_dir}"
