#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-smoke}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_root="${REAL_HOT_PATH_PROOF_ARTIFACT_ROOT:-artifacts/real_hot_path_proof}"
if [[ "$artifact_root" = /* ]]; then
  run_dir="${artifact_root}/${timestamp}"
else
  run_dir="${root_dir}/${artifact_root}/${timestamp}"
fi

manifest_path="${run_dir}/run_manifest.json"
trace_ids_path="${run_dir}/trace_ids.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
step_logs_dir="${run_dir}/step_logs"
step_log_path="${step_logs_dir}/step_000_real_hot_path_proof.log"
rch_log_path="${run_dir}/rch-log.step_000.log"

trace_id="trace-real-hot-path-proof-${timestamp}"
decision_id="decision-real-hot-path-proof-${timestamp}"
policy_id="policy-real-hot-path-proof-v1"
component="real_hot_path_proof"
bead_id="bd-t5k40.3"

toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_real_hot_path_proof_${timestamp}_$$}"
cargo_incremental="${CARGO_INCREMENTAL:-0}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-4}"
rustflags="${RUSTFLAGS:--Cdebuginfo=0}"
rch_exec_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-3900}"
rch_test_timeout_seconds="${RCH_TEST_TIMEOUT_SEC:-1800}"
rch_wait_timeout_seconds="${RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS:-3600}"
rch_priority="${RCH_PRIORITY:-normal}"
rch_visibility="${RCH_VISIBILITY:-verbose}"

mkdir -p "$run_dir" "$step_logs_dir"
: >"$commands_path"

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "${tool} is required for real hot-path proof wrapper" >&2
    exit 2
  fi
}

require_tool jq
require_tool rch
require_tool sed
require_tool timeout

strip_ansi() {
  sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g' "$1"
}

detect_local_fallback() {
  local log_path="$1"
  strip_ansi "$log_path" | grep -Eiq \
    'Remote execution failed: .*running locally|Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326|selection error: queue_timeout'
}

remote_exit_code() {
  local log_path="$1"
  local exit_line
  exit_line="$(strip_ansi "$log_path" | grep -Eo 'Remote command finished: exit=[0-9]+' | tail -n 1 || true)"
  if [[ -z "$exit_line" ]]; then
    return 1
  fi
  printf '%s\n' "${exit_line##*=}"
}

selected_worker() {
  local log_path="$1"
  strip_ansi "$log_path" | sed -n 's/.*Selected worker: \([^ ]*\) at \([^ ]*\) (.*/\1|\2/p' | tail -n 1
}

git_commit() {
  git rev-parse HEAD 2>/dev/null || printf 'unknown'
}

dirty_worktree_json() {
  if [[ -n "$(git status --short 2>/dev/null)" ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

command_text_for() {
  local cargo_text="$1"
  printf 'RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=%s RCH_QUEUE_WHEN_BUSY=1 RCH_PRIORITY=%s RCH_VISIBILITY=%s RCH_TEST_TIMEOUT_SEC=%s rch exec -- env RUSTUP_TOOLCHAIN=%s CARGO_TARGET_DIR=%s CARGO_INCREMENTAL=%s CARGO_BUILD_JOBS=%s RUSTFLAGS=%q %s\n' \
    "$rch_wait_timeout_seconds" \
    "$rch_priority" \
    "$rch_visibility" \
    "$rch_test_timeout_seconds" \
    "$toolchain" \
    "$target_dir" \
    "$cargo_incremental" \
    "$cargo_build_jobs" \
    "$rustflags" \
    "$cargo_text"
}

write_trace_ids() {
  jq -n \
    --arg schema "franken-engine.real-hot-path-proof.trace-ids.v1" \
    --arg bead_id "$bead_id" \
    --arg component "$component" \
    --arg policy_id "$policy_id" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    '{
      schema_version: $schema,
      bead_id: $bead_id,
      component: $component,
      policy_id: $policy_id,
      trace_ids: [$trace_id],
      decision_ids: [$decision_id]
    }' >"$trace_ids_path"
}

write_event() {
  local outcome="$1"
  local error_code="$2"
  local failure_reason="$3"

  jq -nc \
    --arg schema "franken-engine.real-hot-path-proof.event.v1" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg event "real_hot_path_proof_completed" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    --arg failure_reason "$failure_reason" \
    --arg owner_bead "$bead_id" \
    --arg runtime_lane "real_runtime_hot_paths" \
    --arg generated_at_utc "$timestamp" \
    '{
      schema_version: $schema,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: $event,
      outcome: $outcome,
      error_code: (if $error_code == "" then null else $error_code end),
      failure_reason: (if $failure_reason == "" then null else $failure_reason end),
      owner_bead: $owner_bead,
      runtime_lane: $runtime_lane,
      generated_at_utc: $generated_at_utc
    }' >"$events_path"
}

write_manifest() {
  local outcome="$1"
  local error_code="$2"
  local failure_reason="$3"
  local remote_exit="$4"
  local selected_worker_pair="$5"
  local local_fallback_detected="$6"

  local commands_json manifest_tmp worker_id worker_spec worker_user worker_host
  commands_json="$(jq -R . "$commands_path" | jq -s .)"
  manifest_tmp="${manifest_path}.tmp"
  worker_id=""
  worker_spec=""
  worker_user=""
  worker_host=""
  if [[ -n "$selected_worker_pair" ]]; then
    worker_id="${selected_worker_pair%%|*}"
    worker_spec="${selected_worker_pair#*|}"
    worker_user="${worker_spec%@*}"
    worker_host="${worker_spec#*@}"
  fi

  jq -n \
    --arg schema "franken-engine.real-hot-path-proof.run-manifest.v1" \
    --arg bead_id "$bead_id" \
    --arg component "$component" \
    --arg mode "$mode" \
    --arg generated_at_utc "$timestamp" \
    --arg git_commit "$(git_commit)" \
    --argjson dirty_worktree "$(dirty_worktree_json)" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg toolchain "$toolchain" \
    --arg target_dir "$target_dir" \
    --arg cargo_incremental "$cargo_incremental" \
    --arg cargo_build_jobs "$cargo_build_jobs" \
    --arg rustflags "$rustflags" \
    --arg rch_exec_timeout_seconds "$rch_exec_timeout_seconds" \
    --arg rch_test_timeout_seconds "$rch_test_timeout_seconds" \
    --arg rch_wait_timeout_seconds "$rch_wait_timeout_seconds" \
    --arg rch_priority "$rch_priority" \
    --arg rch_visibility "$rch_visibility" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    --arg failure_reason "$failure_reason" \
    --arg remote_exit "$remote_exit" \
    --arg worker_id "$worker_id" \
    --arg worker_user "$worker_user" \
    --arg worker_host "$worker_host" \
    --argjson local_fallback_detected "$local_fallback_detected" \
    --arg manifest "$manifest_path" \
    --arg trace_ids "$trace_ids_path" \
    --arg events "$events_path" \
    --arg commands "$commands_path" \
    --arg step_logs_dir "$step_logs_dir" \
    --arg first_step_log "$step_log_path" \
    --arg rch_log "$rch_log_path" \
    --argjson commands_array "$commands_json" \
    '{
      schema_version: $schema,
      bead_id: $bead_id,
      component: $component,
      mode: $mode,
      generated_at_utc: $generated_at_utc,
      git_commit: $git_commit,
      dirty_worktree: $dirty_worktree,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      toolchain: $toolchain,
      cargo_target_dir: $target_dir,
      cargo_incremental: $cargo_incremental,
      cargo_build_jobs: $cargo_build_jobs,
      rustflags: $rustflags,
      rch: {
        exec_timeout_seconds: ($rch_exec_timeout_seconds | tonumber),
        test_timeout_seconds: ($rch_test_timeout_seconds | tonumber),
        wait_response_timeout_seconds: ($rch_wait_timeout_seconds | tonumber),
        queue_when_busy: true,
        priority: $rch_priority,
        visibility: $rch_visibility,
        local_fallback_detected: $local_fallback_detected,
        remote_exit_code: (if $remote_exit == "" then null else ($remote_exit | tonumber) end),
        selected_worker: {
          id: (if $worker_id == "" then null else $worker_id end),
          user: (if $worker_user == "" then null else $worker_user end),
          host: (if $worker_host == "" then null else $worker_host end)
        }
      },
      outcome: $outcome,
      error_code: (if $error_code == "" then null else $error_code end),
      failure_reason: (if $failure_reason == "" then null else $failure_reason end),
      commands: $commands_array,
      artifacts: {
        manifest: $manifest,
        trace_ids: $trace_ids,
        events: $events,
        commands: $commands,
        step_logs_dir: $step_logs_dir,
        first_step_log: $first_step_log,
        rch_log: $rch_log
      },
      operator_verification: [
        ("cat " + $manifest),
        ("cat " + $trace_ids),
        ("cat " + $events),
        ("cat " + $commands),
        ("cat " + $first_step_log),
        ("cat " + $rch_log)
      ]
    }' >"$manifest_tmp"
  mv "$manifest_tmp" "$manifest_path"
}

write_artifacts() {
  local outcome="$1"
  local error_code="$2"
  local failure_reason="$3"
  local remote_exit="${4:-}"
  local selected_worker_pair="${5:-}"
  local local_fallback_detected="${6:-false}"

  write_trace_ids
  write_event "$outcome" "$error_code" "$failure_reason"
  write_manifest "$outcome" "$error_code" "$failure_reason" "$remote_exit" "$selected_worker_pair" "$local_fallback_detected"
}

case "$mode" in
  dry-run)
    cargo_text="cargo bench -p frankenengine-engine --no-default-features --bench hot_paths -- --test"
    printf '%s' "$(command_text_for "$cargo_text")" >"$commands_path"
    printf 'dry-run: %s\n' "$(cat "$commands_path")" >"$step_log_path"
    cp "$step_log_path" "$rch_log_path"
    write_artifacts "dry_run" "" "" "" "" false
    echo "real hot-path proof dry-run manifest: ${manifest_path}"
    exit 0
    ;;
  check)
    cargo_text="cargo check -p frankenengine-engine --no-default-features --bench hot_paths"
    cargo_cmd=(cargo check -p frankenengine-engine --no-default-features --bench hot_paths)
    ;;
  smoke|ci)
    cargo_text="cargo bench -p frankenengine-engine --no-default-features --bench hot_paths -- --test"
    cargo_cmd=(cargo bench -p frankenengine-engine --no-default-features --bench hot_paths -- --test)
    ;;
  *)
    echo "usage: $0 [dry-run|check|smoke|ci]" >&2
    exit 2
    ;;
esac

printf '%s' "$(command_text_for "$cargo_text")" >"$commands_path"

set +e
env \
  "RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=${rch_wait_timeout_seconds}" \
  "RCH_QUEUE_WHEN_BUSY=1" \
  "RCH_PRIORITY=${rch_priority}" \
  "RCH_VISIBILITY=${rch_visibility}" \
  "RCH_TEST_TIMEOUT_SEC=${rch_test_timeout_seconds}" \
  timeout --kill-after=30 "${rch_exec_timeout_seconds}" \
  rch exec -- env \
  "RUSTUP_TOOLCHAIN=${toolchain}" \
  "CARGO_TARGET_DIR=${target_dir}" \
  "CARGO_INCREMENTAL=${cargo_incremental}" \
  "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
  "RUSTFLAGS=${rustflags}" \
  "${cargo_cmd[@]}" 2>&1 | tee "$step_log_path"
step_status="${PIPESTATUS[0]}"
set -e

cp "$step_log_path" "$rch_log_path"

fallback_detected=false
if detect_local_fallback "$step_log_path"; then
  fallback_detected=true
fi

worker_pair="$(selected_worker "$step_log_path" || true)"
remote_exit="$(remote_exit_code "$step_log_path" || true)"
outcome="pass"
error_code=""
failure_reason=""

if [[ "$fallback_detected" == true ]]; then
  outcome="fail"
  error_code="FE-REAL-HOT-PATH-PROOF-RCH-LOCAL-FALLBACK"
  failure_reason="rch reported local fallback or queue-timeout local execution"
elif [[ -z "$remote_exit" ]]; then
  outcome="fail"
  error_code="FE-REAL-HOT-PATH-PROOF-MISSING-REMOTE-EXIT"
  failure_reason="rch output did not include a remote command exit marker"
elif [[ "$remote_exit" != "0" ]]; then
  outcome="fail"
  error_code="FE-REAL-HOT-PATH-PROOF-REMOTE-FAIL"
  failure_reason="remote command exited ${remote_exit}"
elif [[ "$step_status" -ne 0 ]]; then
  outcome="fail"
  error_code="FE-REAL-HOT-PATH-PROOF-RCH-FAIL"
  failure_reason="rch wrapper exited ${step_status} despite remote exit ${remote_exit}"
fi

write_artifacts "$outcome" "$error_code" "$failure_reason" "$remote_exit" "$worker_pair" "$fallback_detected"

echo "real hot-path proof manifest: ${manifest_path}"
echo "real hot-path proof events: ${events_path}"

if [[ "$outcome" != "pass" ]]; then
  echo "real hot-path proof failed: ${error_code} ${failure_reason}" >&2
  exit 1
fi

exit 0
