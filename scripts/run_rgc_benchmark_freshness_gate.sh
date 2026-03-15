#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_benchmark_freshness_gate}"
artifact_root="${RGC_BENCHMARK_FRESHNESS_GATE_ARTIFACT_ROOT:-artifacts/benchmark_freshness_gate}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
rch_build_timeout_sec="${RCH_BUILD_TIMEOUT_SEC:-${RCH_BUILD_TIMEOUT_SECONDS:-0}}"
# Quiet cold-worker compiles can legitimately go silent for minutes, so keep
# stall killing opt-in and rely on the outer timeout by default.
rch_progress_stall_seconds="${RCH_PROGRESS_STALL_SECONDS:-0}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
summary_path="${run_dir}/summary.md"
env_path="${run_dir}/env.json"
repro_lock_path="${run_dir}/repro.lock"
step_logs_dir="${run_dir}/step_logs"
freshness_state_path="${run_dir}/benchmark_freshness_state.json"
downgrade_reasons_path="${run_dir}/freshness_downgrade_reasons.jsonl"
remediation_plan_path="${run_dir}/freshness_remediation_plan.json"

trace_id="trace-rgc-benchmark-freshness-gate-${timestamp}"
decision_id="decision-rgc-benchmark-freshness-gate-${timestamp}"
policy_id="policy-rgc-benchmark-freshness-gate-v1"
component="rgc_benchmark_freshness_gate"
scenario_id="rgc-706c"
replay_command="./scripts/e2e/rgc_benchmark_freshness_gate_replay.sh ${mode}"

mkdir -p "$run_dir" "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for benchmark freshness gate heavy commands" >&2
  exit 2
fi

run_rch() {
  if [[ "$rch_build_timeout_sec" -gt 0 ]]; then
    RCH_BUILD_TIMEOUT_SEC="${rch_build_timeout_sec}" \
      RCH_BUILD_TIMEOUT_SECONDS="${rch_build_timeout_sec}" \
      timeout --kill-after=30 "${rch_timeout_seconds}" \
      rch exec -- env \
      "RUSTUP_TOOLCHAIN=${toolchain}" \
      "CARGO_TARGET_DIR=${target_dir}" \
      "$@"
  else
    timeout --kill-after=30 "${rch_timeout_seconds}" \
      rch exec -- env \
      "RUSTUP_TOOLCHAIN=${toolchain}" \
      "CARGO_TARGET_DIR=${target_dir}" \
      "$@"
  fi
}

rch_strip_ansi() {
  sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g' "$1"
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

kill_process_tree() {
  local root_pid="$1"
  local child_pid

  while read -r child_pid; do
    [[ -n "$child_pid" ]] || continue
    kill_process_tree "$child_pid"
  done < <(ps -o pid= --ppid "$root_pid" 2>/dev/null || true)

  kill "$root_pid" 2>/dev/null || true
}

watch_rch_progress() {
  local log_path="$1"
  local step_pid="$2"
  local stall_seconds="$3"
  local expected_timeout="$4"
  local remote_started=false
  local last_size="-1"
  local last_progress_ts
  local current_size now_ts reported_timeout

  last_progress_ts="$(date +%s)"

  while kill -0 "$step_pid" 2>/dev/null; do
    sleep 5

    if [[ ! -f "$log_path" ]]; then
      continue
    fi

    current_size="$(wc -c <"$log_path")"
    if [[ "$current_size" != "$last_size" ]]; then
      last_size="$current_size"
      last_progress_ts="$(date +%s)"
    fi

    reported_timeout="$(rch_reported_timeout_seconds "$log_path")"
    if [[ "$expected_timeout" =~ ^[0-9]+$ && "$reported_timeout" =~ ^[0-9]+$ ]] \
      && (( reported_timeout < expected_timeout )); then
      echo "rch reported timeout_secs=${reported_timeout} but requested build timeout is ${expected_timeout}" \
        | tee -a "$log_path"
      kill_process_tree "$step_pid"
      return 4
    fi

    if [[ "$remote_started" == false ]] \
      && rch_strip_ansi "$log_path" | rg -q 'Executing command remotely:'; then
      remote_started=true
      last_progress_ts="$(date +%s)"
      continue
    fi

    if [[ "$remote_started" != true || "$stall_seconds" -le 0 ]]; then
      continue
    fi

    now_ts="$(date +%s)"
    if (( now_ts - last_progress_ts < stall_seconds )); then
      continue
    fi

    echo "==> failure: no remote progress for ${stall_seconds}s after remote execution started" \
      | tee -a "$log_path"
    kill_process_tree "$step_pid"
    return 3
  done

  return 0
}

declare -a commands_run=()
declare -a step_logs=()
failed_command=""
manifest_written=false
step_log_index=0

run_step() {
  local command_text="$1"
  local status step_pid progress_watch_pid progress_watch_status reported_timeout
  local step_log_path="${step_logs_dir}/step_$(printf '%03d' "$step_log_index").log"
  step_log_index=$((step_log_index + 1))
  shift

  commands_run+=("$command_text")
  step_logs+=("$step_log_path")
  echo "==> $command_text"

  set +e
  : >"$step_log_path"
  run_rch "$@" > >(tee "$step_log_path") 2>&1 &
  step_pid=$!
  progress_watch_pid=""
  progress_watch_status=0
  if [[ "$rch_progress_stall_seconds" -gt 0 || "$rch_build_timeout_sec" -gt 0 ]]; then
    watch_rch_progress \
      "$step_log_path" \
      "$step_pid" \
      "$rch_progress_stall_seconds" \
      "$rch_build_timeout_sec" &
    progress_watch_pid=$!
  fi

  wait "$step_pid"
  status=$?
  if [[ -n "$progress_watch_pid" ]]; then
    wait "$progress_watch_pid"
    progress_watch_status=$?
  fi
  set -e

  if [[ "$progress_watch_status" -eq 3 ]]; then
    failed_command="${command_text} (rch-stalled-no-progress-${rch_progress_stall_seconds}s)"
    return 1
  fi
  if [[ "$progress_watch_status" -eq 4 ]]; then
    reported_timeout="$(rch_reported_timeout_seconds "$step_log_path")"
    failed_command="${command_text} (rch-timeout-mismatch-${reported_timeout}-lt-${rch_build_timeout_sec})"
    return 1
  fi

  if [[ "$status" -ne 0 ]]; then
    if [[ "$status" -eq 124 ]]; then
      echo "==> failure: rch command timed out after ${rch_timeout_seconds}s" | tee -a "$step_log_path"
      failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      return 1
    fi

    if rch_recovered_success "$step_log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$step_log_path"
    else
      failed_command="$command_text"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$step_log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  reported_timeout="$(rch_reported_timeout_seconds "$step_log_path")"
  if [[ "$rch_build_timeout_sec" =~ ^[0-9]+$ && "$reported_timeout" =~ ^[0-9]+$ ]] \
    && (( reported_timeout < rch_build_timeout_sec )); then
    echo "rch reported timeout_secs=${reported_timeout} but requested build timeout is ${rch_build_timeout_sec}" \
      | tee -a "$step_log_path"
    failed_command="${command_text} (rch-timeout-mismatch-${reported_timeout}-lt-${rch_build_timeout_sec})"
    return 1
  fi
}

run_mode() {
  case "$mode" in
  check)
    run_step "cargo check -p frankenengine-engine --test benchmark_freshness_gate_integration --test benchmark_freshness_gate_enrichment_integration" \
      cargo check -p frankenengine-engine \
      --test benchmark_freshness_gate_integration \
      --test benchmark_freshness_gate_enrichment_integration
    ;;
  test)
    run_step "cargo test -p frankenengine-engine --test benchmark_freshness_gate_integration --test benchmark_freshness_gate_enrichment_integration" \
      cargo test -p frankenengine-engine \
      --test benchmark_freshness_gate_integration \
      --test benchmark_freshness_gate_enrichment_integration
    ;;
  clippy)
    run_step "cargo clippy -p frankenengine-engine --test benchmark_freshness_gate_integration --test benchmark_freshness_gate_enrichment_integration -- -D warnings" \
      cargo clippy -p frankenengine-engine \
      --test benchmark_freshness_gate_integration \
      --test benchmark_freshness_gate_enrichment_integration \
      -- -D warnings
    ;;
  ci)
    run_step "cargo check -p frankenengine-engine --test benchmark_freshness_gate_integration --test benchmark_freshness_gate_enrichment_integration" \
      cargo check -p frankenengine-engine \
      --test benchmark_freshness_gate_integration \
      --test benchmark_freshness_gate_enrichment_integration
    run_step "cargo test -p frankenengine-engine --test benchmark_freshness_gate_integration --test benchmark_freshness_gate_enrichment_integration" \
      cargo test -p frankenengine-engine \
      --test benchmark_freshness_gate_integration \
      --test benchmark_freshness_gate_enrichment_integration
    run_step "cargo clippy -p frankenengine-engine --test benchmark_freshness_gate_integration --test benchmark_freshness_gate_enrichment_integration -- -D warnings" \
      cargo clippy -p frankenengine-engine \
      --test benchmark_freshness_gate_integration \
      --test benchmark_freshness_gate_enrichment_integration \
      -- -D warnings
    ;;
  *)
    echo "usage: $0 [check|test|clippy|ci]" >&2
    exit 2
    ;;
  esac
}

write_trace_ids() {
  cat >"${trace_ids_path}" <<EOF_TRACE
{"schema_version":"franken-engine.rgc-benchmark-freshness-gate.trace-ids.v1","trace_ids":["${trace_id}"],"decision_ids":["${decision_id}"],"policy_ids":["${policy_id}"],"scenario_id":"${scenario_id}"}
EOF_TRACE
}

write_env_bundle() {
  cat >"${env_path}" <<EOF_ENV
{"schema_version":"franken-engine.rgc-benchmark-freshness-gate.env.v1","bead_id":"bd-1lsy.8.6.3","mode":"${mode}","toolchain":"${toolchain}","cargo_target_dir":"${target_dir}","artifact_root":"${artifact_root}","root_dir":"${root_dir}","pwd":"${PWD}","rch_exec_timeout_seconds":${rch_timeout_seconds},"runner":"scripts/run_rgc_benchmark_freshness_gate.sh","replay_wrapper":"scripts/e2e/rgc_benchmark_freshness_gate_replay.sh","generated_at_utc":"${timestamp}"}
EOF_ENV
}

write_repro_lock() {
  local git_commit="$1"

  cat >"${repro_lock_path}" <<EOF_LOCK
schema_version=franken-engine.rgc-benchmark-freshness-gate.repro-lock.v1
bead_id=bd-1lsy.8.6.3
mode=${mode}
toolchain=${toolchain}
cargo_target_dir=${target_dir}
git_commit=${git_commit}
runner=scripts/run_rgc_benchmark_freshness_gate.sh
replay_wrapper=scripts/e2e/rgc_benchmark_freshness_gate_replay.sh
trace_id=${trace_id}
decision_id=${decision_id}
policy_id=${policy_id}
generated_at_utc=${timestamp}
EOF_LOCK
}

write_summary() {
  local outcome="$1"

  cat >"${summary_path}" <<EOF_SUMMARY
# RGC Benchmark Freshness Gate

- bead: \`bd-1lsy.8.6.3\`
- scenario: \`${scenario_id}\`
- outcome: \`${outcome}\`
- trace_id: \`${trace_id}\`
- decision_id: \`${decision_id}\`
- policy_id: \`${policy_id}\`
- cargo_target_dir: \`${target_dir}\`
- freshness_state: \`${freshness_state_path}\`
- downgrade_reasons: \`${downgrade_reasons_path}\`
- remediation_plan: \`${remediation_plan_path}\`
- replay: \`${replay_command}\`
- failed_command: \`${failed_command:-none}\`
EOF_SUMMARY
}

write_contract_artifacts() {
  local outcome="$1"

  cat >"${freshness_state_path}" <<EOF_STATE
{
  "schema_version": "franken-engine.rgc-benchmark-freshness-gate.state.v1",
  "bead_id": "bd-1lsy.8.6.3",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "policy_id": "${policy_id}",
  "component": "${component}",
  "mode": "${mode}",
  "outcome": "${outcome}",
  "scenarios": [
    {
      "scenario_id": "fresh_clean_board",
      "freshness": "fresh",
      "rollout_trust": "full",
      "supporting_tests": [
        "test_gate_fresh_when_no_alarms",
        "enrichment_gate_fresh_no_alarms"
      ]
    },
    {
      "scenario_id": "scoped_shift_with_healthy_acquisition",
      "freshness": "aging",
      "rollout_trust": "limited",
      "supporting_tests": [
        "test_gate_info_alarm_gives_aging",
        "test_gate_warning_with_healthy_acquisition_gives_aging",
        "test_multi_domain_worst_freshness_wins"
      ]
    },
    {
      "scenario_id": "stale_board_or_signal_silence",
      "freshness": "stale",
      "rollout_trust": "support_only",
      "supporting_tests": [
        "test_gate_warning_without_acquisition_gives_stale",
        "test_silence_degrades_freshness",
        "test_cumulative_severity_threshold_triggers_stale"
      ]
    },
    {
      "scenario_id": "acquisition_backlog_or_invalid_state",
      "freshness": "invalid",
      "rollout_trust": "blocked",
      "supporting_tests": [
        "test_gate_critical_without_acquisition_gives_invalid",
        "test_gate_emergency_alarm_always_invalid",
        "test_batch_overall_freshness_is_worst"
      ]
    }
  ]
}
EOF_STATE

  cat >"${downgrade_reasons_path}" <<EOF_REASONS
{"schema_version":"franken-engine.rgc-benchmark-freshness-gate.reason.v1","trace_id":"${trace_id}","reason_id":"live_shift_alarm","freshness":"aging","supporting_tests":["test_gate_info_alarm_gives_aging","test_multi_domain_mixed_severities"]}
{"schema_version":"franken-engine.rgc-benchmark-freshness-gate.reason.v1","trace_id":"${trace_id}","reason_id":"missing_or_unhealthy_acquisition","freshness":"stale","supporting_tests":["test_gate_warning_without_acquisition_gives_stale","test_gate_critical_without_acquisition_gives_invalid"]}
{"schema_version":"franken-engine.rgc-benchmark-freshness-gate.reason.v1","trace_id":"${trace_id}","reason_id":"signal_silence","freshness":"stale","supporting_tests":["test_silence_degrades_freshness","test_silence_reset_by_alarm_and_acquisition"]}
{"schema_version":"franken-engine.rgc-benchmark-freshness-gate.reason.v1","trace_id":"${trace_id}","reason_id":"emergency_shift","freshness":"invalid","supporting_tests":["test_gate_emergency_alarm_always_invalid","enrichment_gate_verdict_downgraded_by_alarm"]}
EOF_REASONS

  cat >"${remediation_plan_path}" <<EOF_PLAN
{
  "schema_version": "franken-engine.rgc-benchmark-freshness-gate.remediation-plan.v1",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "policy_id": "${policy_id}",
  "component": "${component}",
  "outcome": "${outcome}",
  "actions": [
    {
      "action_id": "acknowledge_or_resolve_active_shift_alarm",
      "priority": "high",
      "replay_command": "${replay_command}",
      "evidence_anchor": "test_resolve_alarm_restores_freshness"
    },
    {
      "action_id": "restore_healthy_acquisition_burndown",
      "priority": "high",
      "replay_command": "${replay_command}",
      "evidence_anchor": "test_acquisition_progression_through_stages"
    },
    {
      "action_id": "re-establish_live_signal_before_rollout",
      "priority": "medium",
      "replay_command": "${replay_command}",
      "evidence_anchor": "test_silence_reset_by_alarm_and_acquisition"
    }
  ]
}
EOF_PLAN
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree
  local idx comma

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-706C-GATE-0001"'
  fi

  write_trace_ids
  write_env_bundle
  write_contract_artifacts "$outcome"

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi
  write_repro_lock "$git_commit"
  write_summary "$outcome"

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.rgc-benchmark-freshness-gate.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-benchmark-freshness-gate.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.8.6.3",'
    echo "  \"component\": \"${component}\","
    echo "  \"scenario_id\": \"${scenario_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"failed_command\": $(if [[ -n "$failed_command" ]]; then printf '"%s"' "$(parser_frontier_json_escape "$failed_command")"; else printf 'null'; fi),"
    echo '  "test_targets": ["benchmark_freshness_gate_integration", "benchmark_freshness_gate_enrichment_integration"],'
    echo '  "artifacts": {'
    echo "    \"run_manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"trace_ids\": \"${trace_ids_path}\","
    echo "    \"summary\": \"${summary_path}\","
    echo "    \"env\": \"${env_path}\","
    echo "    \"repro_lock\": \"${repro_lock_path}\","
    echo "    \"benchmark_freshness_state\": \"${freshness_state_path}\","
    echo "    \"freshness_downgrade_reasons\": \"${downgrade_reasons_path}\","
    echo "    \"freshness_remediation_plan\": \"${remediation_plan_path}\","
    echo '    "step_logs": ['
    for idx in "${!step_logs[@]}"; do
      comma=","
      if [[ "$idx" -eq $((${#step_logs[@]} - 1)) ]]; then
        comma=""
      fi
      echo "      \"${step_logs[$idx]}\"${comma}"
    done
    echo '    ]'
    echo '  },'
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo '  },'
    echo "  \"replay_command\": \"${replay_command}\""
    echo "}"
  } >"$manifest_path"
}

trap 'write_manifest "$?"' EXIT
trap 'write_manifest 130; exit 130' INT TERM

run_mode

echo "benchmark freshness gate manifest: ${manifest_path}"
echo "benchmark freshness gate summary: ${summary_path}"
