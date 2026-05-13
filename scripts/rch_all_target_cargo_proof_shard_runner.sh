#!/usr/bin/env bash
set -euo pipefail

if [[ "${RCH_SHARD_RUSTC_KEEPALIVE_WRAPPER:-0}" == "1" ]]; then
  rustc_keepalive_seconds="${RCH_SHARD_RUSTC_KEEPALIVE_SECONDS:-60}"
  [[ "$rustc_keepalive_seconds" =~ ^[0-9]+$ ]] || {
    printf 'RCH_SHARD_RUSTC_KEEPALIVE_SECONDS must be an integer\n' >&2
    exit 64
  }
  [[ "$#" -ge 1 ]] || {
    printf 'rustc keepalive wrapper requires the rustc executable argument\n' >&2
    exit 64
  }
  rustc_executable="$1"
  shift
  if [[ "$rustc_keepalive_seconds" -eq 0 ]]; then
    exec "$rustc_executable" "$@"
  fi

  "$rustc_executable" "$@" &
  rustc_pid=$!
  elapsed=0
  while kill -0 "$rustc_pid" 2>/dev/null; do
    sleep "$rustc_keepalive_seconds" &
    sleep_pid=$!
    wait "$sleep_pid" 2>/dev/null || true
    elapsed=$((elapsed + rustc_keepalive_seconds))
    if kill -0 "$rustc_pid" 2>/dev/null; then
      printf '[rch-shard-runner] rustc_keepalive elapsed_seconds=%s\n' "$elapsed" >&2
    fi
  done
  set +e
  wait "$rustc_pid"
  rustc_status=$?
  set -e
  exit "$rustc_status"
fi

script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
manifest_path=""
shard_id=""
output_dir=""
execute=false
timeout_seconds="${RCH_SHARD_TIMEOUT_SECONDS:-3600}"
remote_keepalive_seconds="${RCH_SHARD_REMOTE_KEEPALIVE_SECONDS:-0}"

usage() {
  cat >&2 <<'EOF'
Usage: scripts/rch_all_target_cargo_proof_shard_runner.sh --manifest FILE --shard-id ID --output-dir DIR [--execute]

Runs the fail-closed admission preflight for one shard emitted by
all_target_cargo_proof_shard_planner.sh. With --execute it then runs the shard's
RCH command and rejects worker drift, local fallback, and missing test execution.

Required:
  --manifest FILE       shard_manifest.json
  --shard-id ID         shard_id from the manifest
  --output-dir DIR      artifact directory for this shard attempt

Optional:
  --execute             run the shard after preflight passes
  --timeout-seconds N   execution timeout for --execute (default: 3600)
  --remote-keepalive-seconds N
                        opt into RUSTC_WRAPPER progress while rustc is silent
                        (default: 0, disabled)
EOF
}

log() {
  printf '[rch-shard-runner] %s\n' "$*"
}

fail_usage() {
  printf '%s\n' "$1" >&2
  usage
  exit 64
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --manifest)
      manifest_path="${2:-}"
      shift 2
      ;;
    --shard-id)
      shard_id="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    --execute)
      execute=true
      shift
      ;;
    --timeout-seconds)
      timeout_seconds="${2:-}"
      shift 2
      ;;
    --remote-keepalive-seconds)
      remote_keepalive_seconds="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail_usage "unknown option: $1"
      ;;
  esac
done

[[ -n "$manifest_path" ]] || fail_usage "--manifest is required"
[[ -n "$shard_id" ]] || fail_usage "--shard-id is required"
[[ -n "$output_dir" ]] || fail_usage "--output-dir is required"
[[ "$timeout_seconds" =~ ^[0-9]+$ ]] || fail_usage "--timeout-seconds must be an integer"
[[ "$remote_keepalive_seconds" =~ ^[0-9]+$ ]] || fail_usage "--remote-keepalive-seconds must be an integer"
[[ -f "$manifest_path" ]] || fail_usage "manifest not found: $manifest_path"
command -v jq >/dev/null 2>&1 || { printf 'jq is required\n' >&2; exit 2; }
jq empty "$manifest_path" >/dev/null

mkdir -p "$output_dir"
shard_json="${output_dir}/shard.json"
commands_path="${output_dir}/commands.txt"
events_path="${output_dir}/events.jsonl"
result_path="${output_dir}/result.json"
diagnose_path="${output_dir}/worker-diagnose.json"
diagnose_stderr_path="${output_dir}/worker-diagnose.stderr"
worker_status_path="${output_dir}/worker-pressure-status.json"
worker_status_stderr_path="${output_dir}/worker-pressure-status.stderr"
selected_worker_status_path="${output_dir}/selected-worker-status.json"
cargo_log_path="${output_dir}/cargo-output.log"

for artifact_path in \
  "$shard_json" \
  "$commands_path" \
  "$events_path" \
  "$result_path" \
  "$diagnose_path" \
  "$diagnose_stderr_path" \
  "$worker_status_path" \
  "$worker_status_stderr_path" \
  "$selected_worker_status_path" \
  "$cargo_log_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

jq -e --arg shard_id "$shard_id" '.shards[] | select(.shard_id == $shard_id)' \
  "$manifest_path" >"$shard_json" || {
  printf 'shard not found in manifest: %s\n' "$shard_id" >&2
  exit 64
}

diagnose_command="$(jq -r '.preflight.diagnose_command // ""' "$shard_json")"
worker_status_command="$(jq -r '.preflight.worker_status_command // ""' "$shard_json")"
exec_command="$(jq -r '.command // ""' "$shard_json")"
lane="$(jq -r '.lane // ""' "$shard_json")"
target_kind="$(jq -r '.target_kind // ""' "$shard_json")"

[[ -n "$diagnose_command" ]] || fail_usage "shard missing preflight.diagnose_command"
[[ -n "$worker_status_command" ]] || fail_usage "shard missing preflight.worker_status_command"
[[ -n "$exec_command" ]] || fail_usage "shard missing command"

{
  printf 'manifest=%q\n' "$manifest_path"
  printf 'shard_id=%q\n' "$shard_id"
  printf 'diagnose_command=%s\n' "$diagnose_command"
  printf 'worker_status_command=%s\n' "$worker_status_command"
  printf 'execute_command=%s\n' "$exec_command"
  printf 'remote_keepalive_seconds=%q\n' "$remote_keepalive_seconds"
} >"$commands_path"

: >"$events_path"

emit_event() {
  local event="$1"
  shift
  jq -cn --arg event "$event" --arg shard_id "$shard_id" --arg detail "$*" \
    '{schema_version:"franken-engine.rch-shard-runner.event.v1", event:$event, shard_id:$shard_id, detail:$detail}' \
    >>"$events_path"
}

emit_result() {
  local decision="$1"
  local reason="$2"
  local exit_code="$3"
  local selected_worker="${4:-}"
  local execution_worker="${5:-}"
  local pressure_state="${6:-}"
  local pressure_reason="${7:-}"
  local rch_build_id=""
  if [[ -f "$cargo_log_path" ]]; then
    rch_build_id="$(extract_rch_build_id_from_log "$cargo_log_path")"
  fi
  jq -n \
    --arg schema_version "franken-engine.rch-shard-runner.result.v1" \
    --arg shard_id "$shard_id" \
    --arg lane "$lane" \
    --arg target_kind "$target_kind" \
    --arg decision "$decision" \
    --arg reason "$reason" \
    --argjson exit_code "$exit_code" \
    --arg selected_worker "$selected_worker" \
    --arg execution_worker "$execution_worker" \
    --arg rch_build_id "$rch_build_id" \
    --arg pressure_state "$pressure_state" \
    --arg pressure_reason "$pressure_reason" \
    --arg output_dir "$output_dir" \
    --arg shard_json "$shard_json" \
    --arg commands_txt "$commands_path" \
    --arg events_jsonl "$events_path" \
    --arg worker_diagnose_json "$diagnose_path" \
    --arg worker_status_json "$worker_status_path" \
    --arg selected_worker_status_json "$selected_worker_status_path" \
    --arg cargo_output_log "$cargo_log_path" \
    '{
      schema_version:$schema_version,
      shard_id:$shard_id,
      lane:$lane,
      target_kind:$target_kind,
      decision:$decision,
      reason:$reason,
      exit_code:$exit_code,
      selected_worker:$selected_worker,
      execution_worker:$execution_worker,
      rch_build_id:(if $rch_build_id == "" then null else $rch_build_id end),
      pressure_state:$pressure_state,
      pressure_reason:$pressure_reason,
      output_dir:$output_dir,
      artifacts:{
        shard_json:$shard_json,
        commands_txt:$commands_txt,
        events_jsonl:$events_jsonl,
        worker_diagnose_json:$worker_diagnose_json,
        worker_pressure_status_json:$worker_status_json,
        selected_worker_status_json:$selected_worker_status_json,
        cargo_output_log:$cargo_output_log
      }
    }' >"$result_path"
}

run_text_command() {
  local command_text="$1"
  local stdout_path="$2"
  local stderr_path="$3"

  set +e
  bash -c "$command_text" >"$stdout_path" 2>"$stderr_path"
  local status=$?
  set -e
  return "$status"
}

run_exec_command_with_keepalive() {
  local command_text="$1"
  local log_path="$2"
  local -a command_parts=()
  local -a instrumented_command=()
  local -a payload=()
  local -a instrumented_payload=()
  local cargo_index=-1

  if [[ "$remote_keepalive_seconds" -eq 0 ]]; then
    timeout "$timeout_seconds" bash -c "$command_text" >"$log_path" 2>&1
    return "$?"
  fi

  eval "command_parts=(${command_text})"
  if [[ "${#command_parts[@]}" -lt 4 || "${command_parts[0]}" != "rch" || "${command_parts[1]}" != "exec" || "${command_parts[2]}" != "--" ]]; then
    timeout "$timeout_seconds" bash -c "$command_text" >"$log_path" 2>&1
    return "$?"
  fi

  payload=("${command_parts[@]:3}")
  if [[ "${payload[0]:-}" != "env" ]]; then
    timeout "$timeout_seconds" bash -c "$command_text" >"$log_path" 2>&1
    return "$?"
  fi
  for i in "${!payload[@]}"; do
    if [[ "${payload[$i]}" == "cargo" ]]; then
      cargo_index="$i"
      break
    fi
  done
  if [[ "$cargo_index" -lt 0 ]]; then
    timeout "$timeout_seconds" bash -c "$command_text" >"$log_path" 2>&1
    return "$?"
  fi

  instrumented_payload=("${payload[@]:0:cargo_index}")
  instrumented_payload+=(
    "RCH_SHARD_RUSTC_KEEPALIVE_WRAPPER=1"
    "RCH_SHARD_RUSTC_KEEPALIVE_SECONDS=${remote_keepalive_seconds}"
    "RUSTC_WRAPPER=${script_path}"
  )
  instrumented_payload+=("${payload[@]:cargo_index}")
  instrumented_command=(rch exec -- "${instrumented_payload[@]}")
  {
    printf 'executed_command='
    printf '%q ' "${instrumented_command[@]}"
    printf '\n'
  } >>"$commands_path"
  timeout "$timeout_seconds" "${instrumented_command[@]}" >"$log_path" 2>&1
}

strip_ansi() {
  perl -pe 's/\e\[[0-9;?]*[ -\/]*[@-~]//g' "$1"
}

local_fallback_detected() {
  local path="$1"
  [[ -f "$path" ]] || return 1
  strip_ansi "$path" | grep -Eiq 'Remote execution failed: .*running locally|Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'
}

extract_selected_worker_from_log() {
  local path="$1"
  strip_ansi "$path" | sed -n 's/.*Selected worker: \([^ ]*\).*/\1/p' | tail -n1 || true
}

extract_rch_build_id_from_log() {
  local path="$1"
  strip_ansi "$path" | sed -En '
    s/.*[Bb]uild[[:space:]#:=]+([0-9]{6,}).*/\1/p
    s/.*job-([0-9]{6,}).*/\1/p
  ' | tail -n1 || true
}

remote_toolchain_failure_detected() {
  local path="$1"
  [[ -f "$path" ]] || return 1
  strip_ansi "$path" | grep -Eiq "the 'cargo' binary, normally provided by the 'cargo' component, is not applicable|toolchain.*cargo.*component|cargo component.*toolchain"
}

test_lane_requires_execution() {
  [[ "$lane" == "lib_test" || "$lane" == "bin_test" || "$lane" == "integration_test" || "$lane" == "doctest" ]]
}

test_execution_observed() {
  local path="$1"
  strip_ansi "$path" | grep -Eq '(^|[[:space:]])running[[:space:]]+[0-9]+[[:space:]]+tests?($|[[:space:]])' \
    && strip_ansi "$path" | grep -Eq '(^|[[:space:]])test[[:space:]]+result:[[:space:]]+ok\.'
}

emit_event "preflight_start" "$diagnose_command"
set +e
run_text_command "$diagnose_command" "$diagnose_path" "$diagnose_stderr_path"
status=$?
set -e
if [[ "$status" -ne 0 ]]; then
  emit_result "fail_closed" "worker_selection_preflight_diagnose_failed" "$status"
  emit_event "fail_closed" "worker_selection_preflight_diagnose_failed"
  exit "$status"
fi
jq empty "$diagnose_path" >/dev/null || {
  emit_result "fail_closed" "worker_selection_preflight_invalid_json" 65
  exit 65
}

selected_worker="$(jq -r '.data.worker_selection.worker.id // ""' "$diagnose_path")"
if [[ -z "$selected_worker" ]]; then
  emit_result "fail_closed" "worker_selection_preflight_not_observed" 66
  emit_event "fail_closed" "worker_selection_preflight_not_observed"
  exit 66
fi

set +e
run_text_command "$worker_status_command" "$worker_status_path" "$worker_status_stderr_path"
status=$?
set -e
if [[ "$status" -ne 0 ]]; then
  emit_result "fail_closed" "worker_pressure_preflight_status_failed" "$status" "$selected_worker"
  emit_event "fail_closed" "worker_pressure_preflight_status_failed"
  exit "$status"
fi
jq empty "$worker_status_path" >/dev/null || {
  emit_result "fail_closed" "worker_pressure_preflight_status_invalid_json" 65 "$selected_worker"
  exit 65
}

if ! jq -e --arg selected "$selected_worker" '.data.daemon.workers[]? | select(.id == $selected)' \
  "$worker_status_path" >"$selected_worker_status_path"; then
  emit_result "fail_closed" "worker_pressure_preflight_worker_missing" 66 "$selected_worker"
  emit_event "fail_closed" "worker_pressure_preflight_worker_missing"
  exit 66
fi

pressure_state="$(jq -r '.pressure_state // "unknown"' "$selected_worker_status_path")"
pressure_reason="$(jq -r '.pressure_reason_code // "unknown"' "$selected_worker_status_path")"
pressure_policy="$(jq -r '.pressure_policy_rule // "unknown"' "$selected_worker_status_path")"
critical_pressure="$(jq -r '
  [
    (.pressure_state // ""),
    (.pressure_reason_code // ""),
    (.pressure_policy_rule // "")
  ]
  | map(ascii_downcase)
  | any(. == "critical" or contains("critical"))
' "$selected_worker_status_path")"

if [[ "$critical_pressure" == "true" ]]; then
  emit_result "fail_closed" "worker_pressure_preflight_critical" 42 "$selected_worker" "" "$pressure_state" "$pressure_reason"
  emit_event "fail_closed" "worker_pressure_preflight_critical ${pressure_policy}"
  exit 42
fi

emit_event "preflight_pass" "selected_worker=${selected_worker} pressure_state=${pressure_state} pressure_reason=${pressure_reason}"
if [[ "$execute" == false ]]; then
  emit_result "pass" "preflight_only" 0 "$selected_worker" "" "$pressure_state" "$pressure_reason"
  log "result=pass mode=preflight selected_worker=${selected_worker} pressure_state=${pressure_state} artifact_root=${output_dir}"
  exit 0
fi

emit_event "execute_start" "$exec_command"
set +e
run_exec_command_with_keepalive "$exec_command" "$cargo_log_path"
exec_status=$?
set -e

if local_fallback_detected "$cargo_log_path"; then
  emit_result "fail_closed" "rch_local_fallback_detected" 67 "$selected_worker" "" "$pressure_state" "$pressure_reason"
  emit_event "fail_closed" "rch_local_fallback_detected"
  exit 67
fi

execution_worker="$(extract_selected_worker_from_log "$cargo_log_path")"
if [[ -z "$execution_worker" ]]; then
  emit_result "fail_closed" "execution_worker_not_observed" 66 "$selected_worker" "" "$pressure_state" "$pressure_reason"
  emit_event "fail_closed" "execution_worker_not_observed"
  exit 66
fi
if [[ "$execution_worker" != "$selected_worker" ]]; then
  emit_result "fail_closed" "execution_worker_drift" 68 "$selected_worker" "$execution_worker" "$pressure_state" "$pressure_reason"
  emit_event "fail_closed" "execution_worker_drift selected=${selected_worker} execution=${execution_worker}"
  exit 68
fi

if [[ "$exec_status" -eq 0 ]]; then
  if test_lane_requires_execution && ! test_execution_observed "$cargo_log_path"; then
    emit_result "fail_closed" "test_execution_not_observed" 69 "$selected_worker" "$execution_worker" "$pressure_state" "$pressure_reason"
    emit_event "fail_closed" "test_execution_not_observed"
    exit 69
  fi
  emit_result "pass" "remote_execution_passed" 0 "$selected_worker" "$execution_worker" "$pressure_state" "$pressure_reason"
  emit_event "pass" "remote_execution_passed"
  log "result=pass mode=execute selected_worker=${selected_worker} artifact_root=${output_dir}"
  exit 0
fi

remote_failure_reason="remote_command_failed"
if [[ "$exec_status" -eq 124 ]]; then
  remote_failure_reason="remote_command_timeout"
elif [[ "$exec_status" -eq 15 || "$exec_status" -eq 143 ]]; then
  remote_failure_reason="remote_command_terminated"
elif remote_toolchain_failure_detected "$cargo_log_path"; then
  remote_failure_reason="remote_worker_toolchain_unavailable"
fi

emit_result "remote_failure" "$remote_failure_reason" "$exec_status" "$selected_worker" "$execution_worker" "$pressure_state" "$pressure_reason"
emit_event "remote_failure" "reason=${remote_failure_reason} exit_code=${exec_status}"
log "result=remote_failure reason=${remote_failure_reason} exit_code=${exec_status} selected_worker=${selected_worker} artifact_root=${output_dir}"
exit "$exec_status"
