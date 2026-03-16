#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
seed="${CONTROL_PLANE_BENCHMARK_SPLIT_SEED:-control-plane-benchmark-split-seed-v1}"
artifact_root="${CONTROL_PLANE_BENCHMARK_SPLIT_ARTIFACT_ROOT:-artifacts/control_plane_benchmark_split_gate}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_control_plane_benchmark_split_gate_${target_namespace}}"
run_dir="$artifact_root/$timestamp"
manifest_path="$run_dir/run_manifest.json"
commands_path="$run_dir/commands.txt"
events_path="$run_dir/events.jsonl"
env_path="$run_dir/env.json"
summary_path="$run_dir/summary.md"
repro_lock_path="$run_dir/repro.lock"
trace_ids_path="$run_dir/trace_ids"
step_logs_dir="$run_dir/step_logs"

trace_id="trace-cp-benchmark-split-${timestamp}"
decision_id="decision-cp-benchmark-split-${timestamp}"
policy_id="policy-cp-benchmark-split-v1"
component="control_plane_benchmark_split_gate_suite"
replay_command="./scripts/e2e/control_plane_benchmark_split_gate_replay.sh ${mode}"

mkdir -p "$run_dir" "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for control-plane benchmark split heavy commands" >&2
  exit 2
fi

run_rch() {
  RCH_EXEC_TIMEOUT_SECONDS="${rch_timeout_seconds}" \
  timeout "${rch_timeout_seconds}" \
    rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|Remote execution failed.*running locally|running locally|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_last_remote_exit_code() {
  local log_path="$1"
  local exit_line
  exit_line="$(grep -Eo 'Remote command finished: exit=[0-9]+' "$log_path" | tail -n 1 || true)"
  if [[ -z "$exit_line" ]]; then
    echo ""
    return
  fi
  echo "${exit_line##*=}"
}

rch_has_recoverable_artifact_timeout() {
  local log_path="$1"
  grep -Eiq 'artifact retrieval timed out|artifact transfer timed out|timed out waiting for artifacts|failed to retrieve artifacts|failed to download artifacts' "$log_path"
}

rch_reject_artifact_retrieval_failure() {
  local log_path="$1"
  if grep -Eiq 'Artifact retrieval failed|Failed to retrieve artifacts:|rsync artifact retrieval failed|rsync error: .*code 23' "$log_path"; then
    echo "rch artifact retrieval failed; refusing to mark heavy command as successful" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false
step_log_index=0

run_step() {
  local command_text="$1"
  local log_path
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  step_log_index=$((step_log_index + 1))

  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    local remote_exit_code
    remote_exit_code="$(rch_last_remote_exit_code "$log_path")"
    if [[ "$remote_exit_code" == "0" ]] && rch_has_recoverable_artifact_timeout "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      failed_command="$command_text"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  if ! rch_reject_artifact_retrieval_failure "$log_path"; then
    failed_command="${command_text} (rch-artifact-retrieval-failed)"
    return 1
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --lib" \
        cargo check -p frankenengine-engine --lib
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test control_plane_benchmark_split_gate" \
        cargo test -p frankenengine-engine --test control_plane_benchmark_split_gate
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test control_plane_benchmark_split_gate -- -D warnings" \
        cargo clippy -p frankenengine-engine --test control_plane_benchmark_split_gate -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --lib" \
        cargo check -p frankenengine-engine --lib
      run_step "cargo test -p frankenengine-engine --test control_plane_benchmark_split_gate" \
        cargo test -p frankenengine-engine --test control_plane_benchmark_split_gate
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome git_commit dirty_worktree idx comma error_code_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-CP-BENCH-SPLIT-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  printf '%s\n' "${trace_id}" >"$trace_ids_path"

  cat >"$env_path" <<EOF
{
  "schema_version": "franken-engine.control-plane-benchmark-split.env.v1",
  "mode": "${mode}",
  "seed": "${seed}",
  "toolchain": "${toolchain}",
  "cargo_target_dir": "${target_dir}",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "policy_id": "${policy_id}"
}
EOF

  cat >"$summary_path" <<EOF
# Control-Plane Benchmark Split Gate Summary

- outcome: ${outcome}
- mode: ${mode}
- trace_id: ${trace_id}
- decision_id: ${decision_id}
- replay_command: ${replay_command}
EOF

  cat >"$repro_lock_path" <<EOF
schema_version=franken-engine.control-plane-benchmark-split.repro-lock.v1
mode=${mode}
seed=${seed}
toolchain=${toolchain}
cargo_target_dir=${target_dir}
trace_id=${trace_id}
decision_id=${decision_id}
policy_id=${policy_id}
replay_command=${replay_command}
EOF

  {
    echo "{\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.control-plane-benchmark-split.run-manifest.v1",'
    echo '  "component": "'"${component}"'",'
    echo '  "mode": "'"${mode}"'",'
    echo '  "seed": "'"${seed}"'",'
    echo '  "toolchain": "'"${toolchain}"'",'
    echo '  "cargo_target_dir": "'"${target_dir}"'",'
    echo '  "trace_id": "'"${trace_id}"'",'
    echo '  "decision_id": "'"${decision_id}"'",'
    echo '  "policy_id": "'"${policy_id}"'",'
    echo '  "git_commit": "'"${git_commit}"'",'
    echo '  "dirty_worktree": '"${dirty_worktree}"','
    echo '  "generated_at_utc": "'"${timestamp}"'",'
    echo '  "outcome": "'"${outcome}"'",'
    if [[ -n "$failed_command" ]]; then
      echo '  "failed_command": "'"${failed_command}"'",'
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
    echo '    "command_log": "'"${commands_path}"'",'
    echo '    "events": "'"${events_path}"'",'
    echo '    "manifest": "'"${manifest_path}"'",'
    echo '    "step_logs": "'"${step_logs_dir}"'",'
    echo '    "env": "'"${env_path}"'",'
    echo '    "summary": "'"${summary_path}"'",'
    echo '    "repro_lock": "'"${repro_lock_path}"'",'
    echo '    "trace_ids": "'"${trace_ids_path}"'",'
    echo '    "contract_doc": "docs/CONTROL_PLANE_BENCHMARK_SPLIT_GATE.md",'
    echo '    "replay_wrapper": "scripts/e2e/control_plane_benchmark_split_gate_replay.sh"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${step_logs_dir}/step_000.log\","
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "control-plane benchmark split manifest: $manifest_path"
  echo "control-plane benchmark split events: $events_path"
}

trap 'write_manifest $?' EXIT
run_mode
