#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_react_package_cohort}"
artifact_root_setting="${REACT_PACKAGE_COHORT_ARTIFACT_ROOT:-artifacts/react_package_cohort}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="${REACT_PACKAGE_COHORT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"

case "$artifact_root_setting" in
  /*) artifact_root="$artifact_root_setting" ;;
  *) artifact_root="${root_dir}/${artifact_root_setting}" ;;
esac

run_dir="${artifact_root}/${timestamp}"
mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for react package cohort heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" rch exec --color never -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|Remote execution failed.*running locally|running locally|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

verify_rch_log() {
  local command_text="$1"
  local log_path="$2"

  if grep -Eq 'Remote command finished: exit=[1-9][0-9]*' "$log_path"; then
    echo "rch reported non-zero remote exit for step: ${command_text}" >&2
    return 1
  fi

  if ! grep -Eq 'Remote command finished: exit=0' "$log_path"; then
    echo "rch did not emit a remote success marker for step: ${command_text}" >&2
    return 1
  fi

  rch_reject_local_fallback "$log_path"
}

run_step() {
  local command_text="$1"
  local log_path
  shift

  echo "==> ${command_text}"
  log_path="$(mktemp)"

  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    if grep -Eq 'Remote command finished: exit=0' "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      rm -f "$log_path"
      return 1
    fi
  fi

  if ! verify_rch_log "$command_text" "$log_path"; then
    rm -f "$log_path"
    return 1
  fi

  rm -f "$log_path"
}

generate_bundle() {
  local command_text="cargo run -p frankenengine-engine --bin franken_react_package_cohort -- --out-dir ${run_dir}"
  local log_path
  local worker

  echo "==> ${command_text}"
  log_path="$(mktemp)"

  if ! run_rch cargo run -p frankenengine-engine --bin franken_react_package_cohort -- --out-dir "${run_dir}" \
    > >(tee "$log_path") 2>&1; then
    if grep -Eq 'Remote command finished: exit=0' "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      rm -f "$log_path"
      return 1
    fi
  fi

  if ! verify_rch_log "$command_text" "$log_path"; then
    rm -f "$log_path"
    return 1
  fi

  worker="$(
    sed -n 's/.*Selected worker: \([^ ]*\) at .*/\1/p' "$log_path" | tail -n 1
  )"
  if [[ -z "$worker" ]]; then
    echo "failed to determine rch worker for artifact sync" >&2
    rm -f "$log_path"
    return 1
  fi

  scp -q -r "${worker}:${run_dir}/." "$run_dir/"
  rm -f "$log_path"
}

run_mode() {
  case "$mode" in
    check)
      run_step \
        "cargo check -p frankenengine-engine --test react_package_cohort_integration --bin franken_react_package_cohort" \
        cargo check -p frankenengine-engine --test react_package_cohort_integration --bin franken_react_package_cohort
      ;;
    test)
      run_step \
        "cargo test -p frankenengine-engine --test react_package_cohort_integration -- --nocapture" \
        cargo test -p frankenengine-engine --test react_package_cohort_integration -- --nocapture
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --test react_package_cohort_integration --bin franken_react_package_cohort -- -D warnings" \
        cargo clippy -p frankenengine-engine --test react_package_cohort_integration --bin franken_react_package_cohort -- -D warnings
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-engine --test react_package_cohort_integration --bin franken_react_package_cohort" \
        cargo check -p frankenengine-engine --test react_package_cohort_integration --bin franken_react_package_cohort
      run_step \
        "cargo test -p frankenengine-engine --test react_package_cohort_integration -- --nocapture" \
        cargo test -p frankenengine-engine --test react_package_cohort_integration -- --nocapture
      run_step \
        "cargo clippy -p frankenengine-engine --test react_package_cohort_integration --bin franken_react_package_cohort -- -D warnings" \
        cargo clippy -p frankenengine-engine --test react_package_cohort_integration --bin franken_react_package_cohort -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

generate_bundle

test -f "$run_dir/react_package_cohort_matrix.json"
test -f "$run_dir/run_manifest.json"
test -f "$run_dir/events.jsonl"
test -f "$run_dir/commands.txt"
test -f "$run_dir/trace_ids.json"

run_mode

printf 'react package cohort artifacts: %s\n' "$run_dir"
