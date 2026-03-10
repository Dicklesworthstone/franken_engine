#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
rch_exec_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
rch_build_timeout_sec="${RCH_BUILD_TIMEOUT_SEC:-${RCH_BUILD_TIMEOUT_SECONDS:-300}}"
artifact_root="${ARBITRARY_JS_TS_WORKLOAD_CORPUS_ARTIFACT_ROOT:-artifacts/rgc_arbitrary_js_ts_workload_corpus}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_dir="${CARGO_TARGET_DIR:-/var/tmp/rch_target_franken_engine_arbitrary_js_ts_workload_corpus}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-2}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
step_logs_dir="${run_dir}/step_logs"
component="rgc_arbitrary_js_ts_workload_corpus_contract"
bead_id="bd-1lsy.8.4.1"

mkdir -p "$run_dir" "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for arbitrary JS/TS workload corpus heavy commands" >&2
  exit 2
fi

if ! command -v timeout >/dev/null 2>&1; then
  echo "timeout is required for arbitrary JS/TS workload corpus heavy commands" >&2
  exit 2
fi

run_rch() {
  RCH_BUILD_TIMEOUT_SEC="${rch_build_timeout_sec}" \
    RCH_BUILD_TIMEOUT_SECONDS="${rch_build_timeout_sec}" \
    timeout --kill-after=30 "${rch_exec_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "$@"
}

rch_strip_ansi() {
  sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' "$1"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote execution failed: .*running locally|Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_last_remote_exit_code() {
  local log_path="$1"
  local exit_line
  exit_line="$(rch_strip_ansi "$log_path" | grep -Eo 'Remote command finished: exit=[0-9]+' | tail -n 1 || true)"
  if [[ -z "$exit_line" ]]; then
    echo ""
    return
  fi
  echo "${exit_line##*=}"
}

rch_reported_timeout_seconds() {
  local log_path="$1"
  local timeout_value
  timeout_value="$(
    rch_strip_ansi "$log_path" | sed -nE 's/.*timeout_secs: ([0-9]+).*/\1/p' | tail -n 1
  )"
  if [[ -z "$timeout_value" ]]; then
    echo ""
    return
  fi
  echo "$timeout_value"
}

rch_has_artifact_retrieval_failure() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Artifact retrieval failed|Failed to retrieve artifacts:|rsync artifact retrieval failed|rsync error: .*code 23'; then
    return 0
  fi
  return 1
}

kill_descendants() {
  local parent_pid="$1"
  local child_pid
  while IFS= read -r child_pid; do
    child_pid="${child_pid//[[:space:]]/}"
    if [[ -z "$child_pid" ]]; then
      continue
    fi
    kill_descendants "$child_pid"
    kill "$child_pid" 2>/dev/null || true
  done < <(ps -o pid= --ppid "$parent_pid" 2>/dev/null || true)
}

declare -a commands_run=()
failed_command=""
failed_step_log_path=""
step_counter=0
manifest_written=false

run_step() {
  local command_text="$1"
  local fallback_flag log_path monitor_pid rch_pid remote_exit_code reported_timeout run_rc status
  local stream_path
  shift

  step_counter=$((step_counter + 1))
  log_path="${step_logs_dir}/step_${step_counter}.log"
  commands_run+=("$command_text")
  echo "==> $command_text"
  : >"$log_path"

  fallback_flag="$(mktemp)"
  stream_path="$(mktemp -u)"
  mkfifo "$stream_path"

  run_rch "$@" >"$stream_path" 2>&1 &
  rch_pid=$!
  {
    while IFS= read -r line; do
      printf '%s\n' "$line"
      printf '%s\n' "$line" >>"$log_path"
      if grep -Eiq 'Remote execution failed: .*running locally|Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326' <<<"$line"; then
        printf 'fallback-detected\n' >"$fallback_flag"
        kill_descendants "$rch_pid"
        kill "$rch_pid" 2>/dev/null || true
      fi
    done <"$stream_path"
  } &
  monitor_pid=$!

  if wait "$rch_pid"; then
    status=0
  else
    status=$?
  fi
  wait "$monitor_pid" || true
  rm -f "$stream_path"

  if [[ -s "$fallback_flag" ]]; then
    kill_descendants "$rch_pid"
    rm -f "$fallback_flag"
    failed_command="${command_text} (rch-local-fallback-detected)"
    failed_step_log_path="$log_path"
    return 1
  fi
  rm -f "$fallback_flag"

  if [[ "$status" -ne 0 ]]; then
    run_rc=$status
    remote_exit_code="$(rch_last_remote_exit_code "$log_path")"
    reported_timeout="$(rch_reported_timeout_seconds "$log_path")"
    if [[ "$rch_build_timeout_sec" =~ ^[0-9]+$ && "$reported_timeout" =~ ^[0-9]+$ ]] &&
      (( reported_timeout < rch_build_timeout_sec )); then
      echo "rch reported timeout_secs=${reported_timeout} but requested build timeout is ${rch_build_timeout_sec}" | tee -a "$log_path"
      failed_command="${command_text} (rch-timeout-mismatch-${reported_timeout}-lt-${rch_build_timeout_sec})"
      failed_step_log_path="$log_path"
      return 1
    fi
    if [[ "$run_rc" -eq 124 ]]; then
      failed_command="${command_text} (timeout-${rch_exec_timeout_seconds}s)"
    elif [[ -n "$remote_exit_code" ]]; then
      failed_command="${command_text} (remote-exit-${remote_exit_code})"
    else
      failed_command="${command_text} (rch-exit-${run_rc})"
    fi
    failed_step_log_path="$log_path"
    return 1
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    failed_step_log_path="$log_path"
    return 1
  fi

  reported_timeout="$(rch_reported_timeout_seconds "$log_path")"
  if [[ "$rch_build_timeout_sec" =~ ^[0-9]+$ && "$reported_timeout" =~ ^[0-9]+$ ]] &&
    (( reported_timeout < rch_build_timeout_sec )); then
    echo "rch reported timeout_secs=${reported_timeout} but requested build timeout is ${rch_build_timeout_sec}" | tee -a "$log_path"
    failed_command="${command_text} (rch-timeout-mismatch-${reported_timeout}-lt-${rch_build_timeout_sec})"
    failed_step_log_path="$log_path"
    return 1
  fi

  remote_exit_code="$(rch_last_remote_exit_code "$log_path")"
  if [[ -z "$remote_exit_code" ]]; then
    echo "rch output missing remote exit marker; failing closed" | tee -a "$log_path"
    failed_command="${command_text} (missing-remote-exit-marker)"
    failed_step_log_path="$log_path"
    return 1
  fi
  if rch_has_artifact_retrieval_failure "$log_path"; then
    if [[ "$remote_exit_code" == "0" ]]; then
      echo "rch artifact retrieval failed after successful remote execution; accepting step because remote exit marker is zero" | tee -a "$log_path"
    else
      echo "rch artifact retrieval failed; refusing to mark heavy command as successful" | tee -a "$log_path"
      failed_command="${command_text} (rch-artifact-retrieval-failed)"
      failed_step_log_path="$log_path"
      return 1
    fi
  fi
  if [[ "$remote_exit_code" != "0" ]]; then
    failed_command="${command_text} (remote-exit-${remote_exit_code})"
    failed_step_log_path="$log_path"
    return 1
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test arbitrary_js_ts_workload_corpus" \
        cargo check -p frankenengine-engine --test arbitrary_js_ts_workload_corpus
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test arbitrary_js_ts_workload_corpus" \
        cargo test -p frankenengine-engine --test arbitrary_js_ts_workload_corpus
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test arbitrary_js_ts_workload_corpus -- -D warnings" \
        cargo clippy -p frankenengine-engine --test arbitrary_js_ts_workload_corpus -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test arbitrary_js_ts_workload_corpus" \
        cargo check -p frankenengine-engine --test arbitrary_js_ts_workload_corpus
      run_step "cargo test -p frankenengine-engine --test arbitrary_js_ts_workload_corpus" \
        cargo test -p frankenengine-engine --test arbitrary_js_ts_workload_corpus
      run_step "cargo clippy -p frankenengine-engine --test arbitrary_js_ts_workload_corpus -- -D warnings" \
        cargo clippy -p frankenengine-engine --test arbitrary_js_ts_workload_corpus -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json dirty_worktree idx comma
  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-704A-CORPUS-0001"'
  fi

  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"${commands_path}"

  {
    echo "{\"schema_version\":\"franken-engine.rgc-arbitrary-js-ts-workload-corpus.event.v1\",\"component\":\"${component}\",\"bead_id\":\"${bead_id}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"${events_path}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-arbitrary-js-ts-workload-corpus.run-manifest.v1",'
    echo "  \"component\": \"${component}\","
    echo "  \"bead_id\": \"${bead_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"cargo_build_jobs\": ${cargo_build_jobs},"
    echo "  \"rch_exec_timeout_seconds\": ${rch_exec_timeout_seconds},"
    echo "  \"rch_build_timeout_sec\": ${rch_build_timeout_sec},"
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"error_code\": ${error_code_json},"
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    if [[ -n "${failed_command}" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    if [[ -n "${failed_step_log_path}" ]]; then
      echo "  \"failed_step_log\": \"${failed_step_log_path}\","
    fi
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"step_logs_dir\": \"${step_logs_dir}\","
    echo '    "normative_doc": "docs/RGC_ARBITRARY_JS_TS_WORKLOAD_CORPUS_V1.md",'
    echo '    "corpus_manifest": "docs/rgc_arbitrary_js_ts_workload_corpus_v1.json",'
    echo '    "test_target": "crates/franken-engine/tests/arbitrary_js_ts_workload_corpus.rs"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"ls -1 ${step_logs_dir}\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"${manifest_path}"
}

trap 'write_manifest $?' EXIT
run_mode
