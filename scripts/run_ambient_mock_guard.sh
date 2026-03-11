#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
rch_build_timeout_sec="${RCH_BUILD_TIMEOUT_SEC:-${RCH_BUILD_TIMEOUT_SECONDS:-1800}}"
artifact_root="${AMBIENT_MOCK_GUARD_ARTIFACT_ROOT:-artifacts/ambient_mock_guard}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_dir="${CARGO_TARGET_DIR:-/var/tmp/rch_target_franken_engine_ambient_mock_guard}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-2}"
run_dir="${artifact_root}/${timestamp}"
rch_step_logs_dir="${run_dir}/rch_step_logs"

mkdir -p "$run_dir" "$rch_step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for ambient mock guard heavy commands" >&2
  exit 2
fi

if ! command -v timeout >/dev/null 2>&1; then
  echo "timeout is required to fail closed on ambient mock guard rch steps" >&2
  exit 2
fi

run_rch() {
  RCH_BUILD_TIMEOUT_SEC="${rch_build_timeout_sec}" \
    RCH_BUILD_TIMEOUT_SECONDS="${rch_build_timeout_sec}" \
    timeout --kill-after=30 "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "$@"
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
  set +e
  run_rch "$@" > >(tee "$log_path") 2>&1
  status=$?
  set -e

  if ! rch_reject_local_fallback "$log_path"; then
    return 1
  fi

  if [[ "$status" -eq 124 ]]; then
    echo "rch command timed out after ${rch_timeout_seconds}s" >&2
    return 1
  fi

  local remote_exit_code
  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -z "$remote_exit_code" ]]; then
    echo "rch output missing remote exit marker" >&2
    return 1
  fi
  if ! remote_code_allowed "$remote_exit_code" "${allowed_codes[@]}"; then
    echo "unexpected remote exit code ${remote_exit_code} for: ${command_text}" >&2
    return 1
  fi
}

run_step \
  "cargo test -p frankenengine-engine --test ambient_mock_guard" \
  0 -- \
  cargo test -p frankenengine-engine --test ambient_mock_guard

run_step \
  "cargo run -p frankenengine-engine --bin franken_ambient_mock_guard -- --out-dir ${run_dir}" \
  0 2 -- \
  cargo run -p frankenengine-engine --bin franken_ambient_mock_guard -- --out-dir "${run_dir}"

for artifact in \
  ambient_mock_guard_report.json \
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

echo "ambient mock guard artifacts: ${run_dir}"
