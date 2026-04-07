#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/data/projects/franken_engine/target_rch_rgc_json_compound_placeholder_closure}"
artifact_root_input="${RGC_JSON_COMPOUND_PLACEHOLDER_CLOSURE_ARTIFACT_ROOT:-artifacts/rgc_json_compound_placeholder_closure}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ "${artifact_root_input}" = /* ]]; then
  artifact_root="${artifact_root_input}"
else
  artifact_root="${root_dir}/${artifact_root_input}"
fi
run_dir="${artifact_root}/${timestamp}"

export RGC_JSON_COMPOUND_PLACEHOLDER_CLOSURE_ARTIFACT_DIR="${run_dir}"

inline_artifact_begin="__RGC_JSON_COMPOUND_PLACEHOLDER_CLOSURE_ARTIFACT_BEGIN__:"
inline_artifact_end="__RGC_JSON_COMPOUND_PLACEHOLDER_CLOSURE_ARTIFACT_END__:"

mkdir -p "${run_dir}"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for JSON compound placeholder closure heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "RGC_JSON_COMPOUND_PLACEHOLDER_CLOSURE_ARTIFACT_DIR=${run_dir}" \
    "RGC_JSON_COMPOUND_PLACEHOLDER_CLOSURE_INLINE_ARTIFACTS=1" \
    "$@"
}

rch_strip_ansi() {
  sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g' "$1"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line

  remote_exit_line="$(rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n1 || true)"
  [[ -n "${remote_exit_line}" ]] || return 1
  printf '%s\n' "${remote_exit_line##*=}"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_recovered_success() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | rg -q 'Remote command finished: exit=0|Finished.*profile|test result: ok\.' \
    && ! rch_strip_ansi "$log_path" | rg -qi 'error(\[[[:alnum:]]+\])?:'; then
    return 0
  fi
  return 1
}

run_step() {
  local command_text="$1"
  local log_path status remote_exit_code
  shift

  echo "==> ${command_text}"
  log_path="$(mktemp)"

  set +e
  run_rch "$@" >"${log_path}" 2>&1
  status=$?
  set -e

  cat "${log_path}"

  if ! rch_reject_local_fallback "${log_path}"; then
    rm -f "${log_path}"
    return 1
  fi

  if [[ "${status}" -ne 0 ]]; then
    if rch_recovered_success "${log_path}"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out"
    else
      remote_exit_code="$(rch_remote_exit_code "${log_path}" || true)"
      rm -f "${log_path}"
      if [[ -n "${remote_exit_code}" ]]; then
        echo "rch command failed: ${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})" >&2
      else
        echo "rch command failed: ${command_text} (rch-exit=${status}; missing-remote-exit-marker)" >&2
      fi
      return 1
    fi
  fi

  remote_exit_code="$(rch_remote_exit_code "${log_path}" || true)"
  rm -f "${log_path}"
  if [[ -z "${remote_exit_code}" || "${remote_exit_code}" != "0" ]]; then
    echo "rch remote exit marker missing or non-zero for: ${command_text}" >&2
    return 1
  fi
}

print_log_without_inline_artifacts() {
  local log_path="$1"
  awk \
    -v begin="${inline_artifact_begin}" \
    -v end="${inline_artifact_end}" \
    'index($0, begin) { skip = 1; next } index($0, end) { skip = 0; next } !skip { print }' \
    "${log_path}"
}

extract_inline_artifacts_to_run_dir() {
  local log_path="$1"
  local line current_path found_any

  found_any=0
  current_path=""
  mkdir -p "${run_dir}"

  while IFS= read -r line || [[ -n "${line}" ]]; do
    if [[ "${line}" == "${inline_artifact_begin}"* ]]; then
      current_path="${line#${inline_artifact_begin}}"
      mkdir -p "$(dirname "${run_dir}/${current_path}")"
      : >"${run_dir}/${current_path}"
      found_any=1
      continue
    fi

    if [[ "${line}" == "${inline_artifact_end}"* ]]; then
      current_path=""
      continue
    fi

    if [[ -n "${current_path}" ]]; then
      printf '%s\n' "${line}" >>"${run_dir}/${current_path}"
    fi
  done <"${log_path}"

  if [[ "${found_any}" -eq 0 ]]; then
    echo "missing inline artifact capture for ${run_dir}" >&2
    return 1
  fi
}

run_test_step_with_artifacts() {
  local command_text="$1"
  local log_path status remote_exit_code

  echo "==> ${command_text}"
  log_path="$(mktemp)"

  set +e
  run_rch \
    cargo test -p frankenengine-engine --test stdlib_integration \
    json_compound_placeholder_closure_scenario_emits_artifact_bundle -- --exact --nocapture \
    >"${log_path}" 2>&1
  status=$?
  set -e

  print_log_without_inline_artifacts "${log_path}"

  if ! rch_reject_local_fallback "${log_path}"; then
    rm -f "${log_path}"
    return 1
  fi

  if [[ "${status}" -ne 0 ]]; then
    if rch_recovered_success "${log_path}"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out"
    else
      remote_exit_code="$(rch_remote_exit_code "${log_path}" || true)"
      rm -f "${log_path}"
      if [[ -n "${remote_exit_code}" ]]; then
        echo "rch command failed: ${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})" >&2
      else
        echo "rch command failed: ${command_text} (rch-exit=${status}; missing-remote-exit-marker)" >&2
      fi
      return 1
    fi
  fi

  remote_exit_code="$(rch_remote_exit_code "${log_path}" || true)"
  if [[ -z "${remote_exit_code}" || "${remote_exit_code}" != "0" ]]; then
    rm -f "${log_path}"
    echo "rch remote exit marker missing or non-zero for: ${command_text}" >&2
    return 1
  fi

  extract_inline_artifacts_to_run_dir "${log_path}"
  rm -f "${log_path}"
}

run_mode() {
  case "${mode}" in
    check)
      run_step \
        "cargo check -p frankenengine-engine --test stdlib_integration" \
        cargo check -p frankenengine-engine --test stdlib_integration
      ;;
    test)
      run_test_step_with_artifacts \
        "cargo test -p frankenengine-engine --test stdlib_integration json_compound_placeholder_closure_scenario_emits_artifact_bundle -- --exact --nocapture"
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --test stdlib_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test stdlib_integration -- -D warnings
      ;;
    replay)
      run_test_step_with_artifacts \
        "cargo test -p frankenengine-engine --test stdlib_integration json_compound_placeholder_closure_scenario_emits_artifact_bundle -- --exact --nocapture"
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-engine --test stdlib_integration" \
        cargo check -p frankenengine-engine --test stdlib_integration
      run_test_step_with_artifacts \
        "cargo test -p frankenengine-engine --test stdlib_integration json_compound_placeholder_closure_scenario_emits_artifact_bundle -- --exact --nocapture"
      run_step \
        "cargo clippy -p frankenengine-engine --test stdlib_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test stdlib_integration -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|replay|ci]" >&2
      exit 2
      ;;
  esac
}

run_mode

if [[ "${mode}" == "test" || "${mode}" == "replay" || "${mode}" == "ci" ]]; then
  for required in \
    run_manifest.json \
    events.jsonl \
    commands.txt \
    trace_ids.json \
    json_compound_placeholder_closure_report.json \
    step_logs/step_000.log; do
    if [[ ! -f "${run_dir}/${required}" ]]; then
      echo "missing artifact after successful run: ${run_dir}/${required}" >&2
      exit 1
    fi
  done

  printf 'json compound placeholder closure artifacts: %s\n' "${run_dir}"
else
  printf 'json compound placeholder closure %s completed via rch\n' "${mode}"
fi
