#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
if [[ $# -gt 0 ]]; then
  shift
fi
extra_runner_args=("$@")

toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/var/tmp/rch_target_franken_engine_security_conformance}"
artifact_root="${SECURITY_CONFORMANCE_ARTIFACT_ROOT:-artifacts/security_conformance_runner}"
labels_root="${SECURITY_CONFORMANCE_LABELS_ROOT:-crates/franken-engine/tests/security_conformance}"
observations_jsonl="${SECURITY_CONFORMANCE_OBSERVATIONS_JSONL:-}"
policy_snapshot_hash="${SECURITY_CONFORMANCE_POLICY_SNAPSHOT_HASH:-}"
allow_small_corpus="${SECURITY_CONFORMANCE_ALLOW_SMALL_CORPUS:-1}"
fail_on_gate_failure="${SECURITY_CONFORMANCE_FAIL_ON_GATE_FAILURE:-1}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
rch_ready_attempts="${RCH_READY_ATTEMPTS:-12}"
rch_ready_sleep_seconds="${RCH_READY_SLEEP_SECONDS:-2}"
rch_step_retry_attempts="${RCH_STEP_RETRY_ATTEMPTS:-3}"
rch_step_retry_sleep_seconds="${RCH_STEP_RETRY_SLEEP_SECONDS:-2}"
rch_retry_on_transient="${RCH_RETRY_ON_TRANSIENT:-1}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
command_logs_dir="${run_dir}/command_logs"
runner_stdout_path="${run_dir}/runner.stdout.log"
runner_output_root="${run_dir}/runner_output"

trace_id="trace-security-conformance-${timestamp}"
decision_id="decision-security-conformance-${timestamp}"
policy_id="policy-security-conformance-v1"
component="security_conformance_runner_suite"
scenario_id="bd-2rk"
replay_command="${0} ${mode}"

mkdir -p "$run_dir" "$command_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for security conformance heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_strip_ansi() {
  perl -pe 's/\e\[[0-9;?]*[ -\/]*[@-~]//g' "$1"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n1 || true)"
  if [[ -z "$remote_exit_line" ]]; then
    return 1
  fi

  remote_exit_code="${remote_exit_line##*=}"
  if [[ -z "$remote_exit_code" ]]; then
    return 1
  fi

  printf '%s\n' "$remote_exit_code"
}

rch_selected_worker_id() {
  local log_path="$1"
  rch_strip_ansi "$log_path" | sed -n 's/.*Selected worker: \([^ ]*\).*/\1/p' | tail -n1
}

rch_transient_infra_failure() {
  local log_path="$1"
  local run_status="${2:-0}"
  local remote_exit_code="${3:-}"

  if [[ "$run_status" -eq 15 && -z "$remote_exit_code" ]]; then
    return 0
  fi

  if rch_strip_ansi "$log_path" | grep -Eiq \
    'No space left on device|StorageFull|SSH command timed out|transport failure|repo_updater .* failed|connection reset by peer|connection timed out|broken pipe|network is unreachable'; then
    return 0
  fi

  return 1
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \('; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

run_rch_strict_logged() {
  local log_path="$1"
  shift

  local fifo_path fallback_flag_path reader_pid rch_pid rch_status=0
  local line

  fifo_path="$(mktemp -u "${TMPDIR:-/tmp}/rch-security-conformance-stream.XXXXXX")"
  fallback_flag_path="$(mktemp "${run_dir}/rch-fallback.XXXXXX")"
  rm -f "$fallback_flag_path"
  mkfifo "$fifo_path"
  : >"$log_path"

  {
    while IFS= read -r line || [[ -n "$line" ]]; do
      printf '%s\n' "$line" | tee -a "$log_path"
      if [[ "$line" == *"Remote toolchain failure, falling back to local"* ||
        "$line" == *"falling back to local"* ||
        "$line" == *"fallback to local"* ||
        "$line" == *"local fallback"* ||
        "$line" == *"running locally"* ||
        "$line" == *"[RCH] local ("* ]]; then
        : >"$fallback_flag_path"
        if [[ -n "${rch_pid:-}" ]]; then
          kill "$rch_pid" 2>/dev/null || true
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
    pkill -f "CARGO_TARGET_DIR=${target_dir}" 2>/dev/null || true
    return 125
  fi

  rm -f "$fallback_flag_path"
  return "$rch_status"
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
declare -a step_logs=()
failed_command=""
manifest_written=false
evidence_path=""
gate_outcome=""
gate_failure_reasons_json="[]"

command_log_name() {
  local command_text="$1"
  local index="$2"
  local sanitized

  sanitized="$(printf '%s' "$command_text" | tr ' /:|()' '_' | tr -cd '[:alnum:]_.-' | cut -c1-120)"
  printf '%03d_%s.log\n' "$index" "$sanitized"
}

run_step_core() {
  local command_text="$1"
  local expected_exit="$2"
  local capture_path="${3:-}"
  local log_path remote_exit_code run_status attempt selected_worker_id
  local fallback_detected command_index command_log_path
  shift 3

  commands_run+=("$command_text")
  command_index=$(( ${#commands_run[@]} - 1 ))
  command_log_path="${command_logs_dir}/$(command_log_name "$command_text" "$command_index")"
  echo "==> $command_text"

  for ((attempt = 1; attempt <= rch_step_retry_attempts; attempt++)); do
    log_path="$(mktemp "${run_dir}/rch-log.XXXXXX")"
    step_logs+=("$log_path")

    if ! ensure_rch_ready "${rch_ready_attempts}" "${rch_ready_sleep_seconds}"; then
      echo "==> warning: rch check not ready after ${rch_ready_attempts} attempts; attempting remote execution anyway" | tee -a "$log_path"
    fi

    run_rch_strict_logged "$log_path" "$@"
    run_status=$?
    fallback_detected=false
    if [[ "$run_status" -eq 125 ]]; then
      fallback_detected=true
    fi

    if ! rch_reject_local_fallback "$log_path"; then
      fallback_detected=true
    fi

    selected_worker_id="$(rch_selected_worker_id "$log_path" || true)"

    if [[ "$fallback_detected" == true ]]; then
      cp "$log_path" "$command_log_path"
      if [[ -n "$capture_path" ]]; then
        cp "$log_path" "$capture_path"
      fi
      if [[ "$attempt" -lt "$rch_step_retry_attempts" ]]; then
        echo "==> warning: detected rch local fallback signature (attempt ${attempt}/${rch_step_retry_attempts}); retrying step after daemon nudge" | tee -a "$log_path"
        rch daemon start >/dev/null 2>&1 || true
        sleep "${rch_step_retry_sleep_seconds}"
        rm -f "$log_path"
        continue
      fi
      rm -f "$log_path"
      failed_command="${command_text} (rch-local-fallback-detected)"
      return 1
    fi

    remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
    if [[ -n "$remote_exit_code" ]]; then
      if [[ "$remote_exit_code" != "$expected_exit" ]]; then
        if [[ "$rch_retry_on_transient" == "1" ]] && rch_transient_infra_failure "$log_path" "$run_status" "$remote_exit_code"; then
          cp "$log_path" "$command_log_path"
          if [[ -n "$capture_path" ]]; then
            cp "$log_path" "$capture_path"
          fi
          if [[ "$attempt" -lt "$rch_step_retry_attempts" ]]; then
            echo "==> warning: transient rch infrastructure failure detected (attempt ${attempt}/${rch_step_retry_attempts}, worker=${selected_worker_id:-unknown}, remote-exit=${remote_exit_code}); retrying step" | tee -a "$log_path"
            rch daemon restart -y >/dev/null 2>&1 || rch daemon start >/dev/null 2>&1 || true
            sleep "${rch_step_retry_sleep_seconds}"
            rm -f "$log_path"
            continue
          fi
        fi
        cp "$log_path" "$command_log_path"
        if [[ -n "$capture_path" ]]; then
          cp "$log_path" "$capture_path"
        fi
        rm -f "$log_path"
        failed_command="${command_text} (remote-exit=${remote_exit_code}, expected=${expected_exit}, worker=${selected_worker_id:-unknown})"
        return 1
      fi
    elif [[ "$run_status" != "$expected_exit" ]]; then
      if [[ "$rch_retry_on_transient" == "1" ]] && rch_transient_infra_failure "$log_path" "$run_status" ""; then
        cp "$log_path" "$command_log_path"
        if [[ -n "$capture_path" ]]; then
          cp "$log_path" "$capture_path"
        fi
        if [[ "$attempt" -lt "$rch_step_retry_attempts" ]]; then
          echo "==> warning: transient rch process interruption detected (attempt ${attempt}/${rch_step_retry_attempts}, worker=${selected_worker_id:-unknown}, process-exit=${run_status}); retrying step" | tee -a "$log_path"
          rch daemon restart -y >/dev/null 2>&1 || rch daemon start >/dev/null 2>&1 || true
          sleep "${rch_step_retry_sleep_seconds}"
          rm -f "$log_path"
          continue
        fi
      fi
      cp "$log_path" "$command_log_path"
      if [[ -n "$capture_path" ]]; then
        cp "$log_path" "$capture_path"
      fi
      rm -f "$log_path"
      failed_command="${command_text} (remote-exit=missing, expected=${expected_exit}, process-exit=${run_status}, worker=${selected_worker_id:-unknown})"
      return 1
    fi

    cp "$log_path" "$command_log_path"
    if [[ -n "$capture_path" ]]; then
      cp "$log_path" "$capture_path"
    fi
    rm -f "$log_path"
    return 0
  done

  failed_command="$command_text"
  return 1
}

run_step() {
  local command_text="$1"
  shift
  run_step_core "$command_text" 0 "" "$@"
}

run_step_capture() {
  local command_text="$1"
  local capture_path="$2"
  shift 2
  run_step_core "$command_text" 0 "$capture_path" "$@"
}

declare -a runner_args=()
build_runner_args() {
  runner_args=(
    --labels-root "$labels_root"
    --output-root "$runner_output_root"
  )

  if [[ -n "$observations_jsonl" ]]; then
    runner_args+=(--observations-jsonl "$observations_jsonl")
  fi
  if [[ -n "$policy_snapshot_hash" ]]; then
    runner_args+=(--policy-snapshot-hash "$policy_snapshot_hash")
  fi
  if [[ "$allow_small_corpus" == "1" ]]; then
    runner_args+=(--allow-small-corpus)
  fi
  if [[ "$fail_on_gate_failure" == "1" ]]; then
    runner_args+=(--fail-on-gate-failure)
  fi
  if [[ "${#extra_runner_args[@]}" -gt 0 ]]; then
    runner_args+=("${extra_runner_args[@]}")
  fi
}

render_runner_args() {
  local rendered=""
  local arg
  for arg in "${runner_args[@]}"; do
    rendered+="${arg} "
  done
  printf '%s' "${rendered%" "}"
}

resolve_evidence_path() {
  local parsed

  parsed="$(rch_strip_ansi "$runner_stdout_path" | sed -n 's/^security evidence=//p' | tail -n1 || true)"
  if [[ -z "$parsed" ]]; then
    return 1
  fi

  evidence_path="$parsed"

  if [[ -f "$parsed" ]]; then
    return 0
  fi

  if [[ -f "${root_dir}/${parsed}" ]]; then
    return 0
  fi

  return 2
}

security_summary_outcome() {
  local summary_path="$1"
  jq -r 'select(.event == "summary") | .outcome' "$summary_path" | tail -n1
}

security_summary_failure_reasons_json() {
  local summary_path="$1"
  jq -c 'select(.event == "summary") | (.gate_failure_reasons // [])' "$summary_path" | tail -n1
}

security_stdout_outcome() {
  local parsed

  parsed="$(rch_strip_ansi "$runner_stdout_path" | sed -n 's/^security gate_pass=//p' | tail -n1 || true)"
  case "$parsed" in
    true)
      printf 'pass\n'
      return 0
      ;;
    false)
      printf 'fail\n'
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

security_stdout_failure_reasons_json() {
  rch_strip_ansi "$runner_stdout_path" \
    | sed -n 's/^security gate_failure_reason=//p' \
    | jq -R -s 'split("\n") | map(select(length > 0))'
}

run_mode() {
  local selected_mode="${1:-$mode}"
  local runner_command runner_remote_exit_code run_status gate_failure_reasons_pretty
  local evidence_resolution_status

  case "$selected_mode" in
    check)
      # Use test compilation without execution so rch applies the longer
      # cargo-test timeout envelope instead of the shorter cargo-check cap.
      run_step "cargo test -p frankenengine-engine --bin franken_security_conformance_runner --test security_conformance_integration --no-run" \
        cargo test -p frankenengine-engine --bin franken_security_conformance_runner --test security_conformance_integration --no-run
      run_step "cargo test -p frankenengine-engine --bin franken_security_conformance_runner --test security_conformance_runner_cli --no-run" \
        cargo test -p frankenengine-engine --bin franken_security_conformance_runner --test security_conformance_runner_cli --no-run
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --bin franken_security_conformance_runner --test security_conformance_integration" \
        cargo test -p frankenengine-engine --bin franken_security_conformance_runner --test security_conformance_integration
      run_step "cargo test -p frankenengine-engine --bin franken_security_conformance_runner --test security_conformance_runner_cli" \
        cargo test -p frankenengine-engine --bin franken_security_conformance_runner --test security_conformance_runner_cli
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --bin franken_security_conformance_runner --test security_conformance_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin franken_security_conformance_runner --test security_conformance_integration -- -D warnings
      run_step "cargo clippy -p frankenengine-engine --bin franken_security_conformance_runner --test security_conformance_runner_cli -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin franken_security_conformance_runner --test security_conformance_runner_cli -- -D warnings
      ;;
    run)
      mkdir -p "$runner_output_root"
      : >"$runner_stdout_path"
      build_runner_args
      runner_command="cargo run -p frankenengine-engine --bin franken_security_conformance_runner -- $(render_runner_args)"
      run_status=0
      evidence_resolution_status=0
      run_step_core "$runner_command" 0 "$runner_stdout_path" \
        cargo run -p frankenengine-engine --bin franken_security_conformance_runner -- "${runner_args[@]}" || run_status=$?
      # Defensively re-check remote exit from captured log so timeout exits are
      # reported deterministically even if earlier step parsing misses it.
      runner_remote_exit_code="$(rch_remote_exit_code "$runner_stdout_path" || true)"
      resolve_evidence_path || evidence_resolution_status=$?
      if [[ "$evidence_resolution_status" -eq 1 ]]; then
        if [[ "$run_status" -ne 0 || ( -n "$runner_remote_exit_code" && "$runner_remote_exit_code" != "0" ) ]]; then
          if [[ -z "$failed_command" ]]; then
            failed_command="${runner_command} (missing-or-unresolvable-evidence-path)"
          fi
          return 1
        fi
        failed_command="${runner_command} (missing-or-unresolvable-evidence-path)"
        return 1
      fi
      if [[ -f "$evidence_path" || -f "${root_dir}/${evidence_path}" ]]; then
        gate_outcome="$(security_summary_outcome "$evidence_path" || true)"
        gate_failure_reasons_json="$(security_summary_failure_reasons_json "$evidence_path" || echo '[]')"
      else
        gate_outcome="$(security_stdout_outcome || true)"
        gate_failure_reasons_json="$(security_stdout_failure_reasons_json || echo '[]')"
      fi
      if [[ -z "$gate_outcome" ]]; then
        failed_command="${runner_command} (missing-summary-outcome)"
        return 1
      fi
      if [[ "$gate_outcome" != "pass" ]]; then
        gate_failure_reasons_pretty="$(printf '%s' "$gate_failure_reasons_json" | jq -r 'join("; ")')"
        failed_command="${runner_command} (gate-outcome=${gate_outcome}${gate_failure_reasons_pretty:+, reasons=${gate_failure_reasons_pretty}}${evidence_resolution_status:+, evidence-not-retrieved})"
        return 1
      fi
      if [[ "$evidence_resolution_status" -eq 2 ]]; then
        failed_command="${runner_command} (gate-outcome=pass, evidence-not-retrieved)"
        return 1
      fi
      if [[ -n "$runner_remote_exit_code" && "$runner_remote_exit_code" != "0" ]]; then
        failed_command="${runner_command} (remote-exit=${runner_remote_exit_code}, expected=0)"
        return 1
      fi
      if [[ "$run_status" -ne 0 ]]; then
        return "$run_status"
      fi
      ;;
    ci)
      run_mode check || return $?
      run_mode test || return $?
      run_mode clippy || return $?
      run_mode run || return $?
      ;;
    *)
      echo "usage: $0 [check|test|clippy|run|ci] [-- extra runner args]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code git_commit dirty_worktree commands_json operator_json artifacts_json
  local failed_command_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code=""
  else
    outcome="fail"
    error_code="FE-SECURITY-CONFORMANCE-SUITE-0001"
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  if [[ ! -f "$runner_stdout_path" ]]; then
    : >"$runner_stdout_path"
  fi
  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  jq -nc \
    --arg schema_version "franken-engine.security-conformance-suite.event.v1" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg event "suite_completed" \
    --arg scenario_id "$scenario_id" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    '{
      schema_version: $schema_version,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: $event,
      scenario_id: $scenario_id,
      outcome: $outcome,
      error_code: (if $error_code == "" then null else $error_code end)
    }' >"$events_path"

  commands_json="$(printf '%s\n' "${commands_run[@]}" | jq -R -s 'split("\n") | map(select(length > 0))')"
  operator_json="$(jq -nc \
    --arg manifest "$manifest_path" \
    --arg events "$events_path" \
    --arg commands "$commands_path" \
    --arg stdout "$runner_stdout_path" \
    --arg output_root "$runner_output_root" \
    --arg replay "$replay_command" \
    '[
      "cat " + $manifest,
      "cat " + $events,
      "cat " + $commands,
      "cat " + $stdout,
      "ls -R " + $output_root,
      $replay
    ]')"
  artifacts_json="$(jq -nc \
    --arg manifest "$manifest_path" \
    --arg events "$events_path" \
    --arg commands "$commands_path" \
    --arg runner_stdout "$runner_stdout_path" \
    --arg runner_output_root "$runner_output_root" \
    '{
      run_manifest: $manifest,
      events: $events,
      commands: $commands,
      runner_stdout: $runner_stdout,
      runner_output_root: $runner_output_root
    }')"
  failed_command_json="$(if [[ -n "$failed_command" ]]; then printf '%s' "$failed_command" | jq -R .; else echo "null"; fi)"

  jq -n \
    --arg schema_version "franken-engine.security-conformance-suite.run-manifest.v1" \
    --arg bead_id "bd-2rk" \
    --arg component "$component" \
    --arg mode "$mode" \
    --arg toolchain "$toolchain" \
    --arg cargo_target_dir "$target_dir" \
    --arg labels_root "$labels_root" \
    --arg observations_jsonl "$observations_jsonl" \
    --arg policy_snapshot_hash "$policy_snapshot_hash" \
    --argjson allow_small_corpus "$allow_small_corpus" \
    --arg runner_output_root "$runner_output_root" \
    --arg evidence_path "$evidence_path" \
    --arg gate_outcome "$gate_outcome" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg generated_at_utc "$timestamp" \
    --arg git_commit "$git_commit" \
    --arg outcome "$outcome" \
    --arg replay_command "$replay_command" \
    --argjson dirty_worktree "$dirty_worktree" \
    --argjson commands "$commands_json" \
    --argjson artifacts "$artifacts_json" \
    --argjson gate_failure_reasons "$gate_failure_reasons_json" \
    --argjson operator_verification "$operator_json" \
    --argjson failed_command "$failed_command_json" \
    --arg error_code "$error_code" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      component: $component,
      mode: $mode,
      toolchain: $toolchain,
      cargo_target_dir: $cargo_target_dir,
      labels_root: $labels_root,
      observations_jsonl: $observations_jsonl,
      policy_snapshot_hash: $policy_snapshot_hash,
      allow_small_corpus: $allow_small_corpus,
      runner_output_root: $runner_output_root,
      evidence_path: $evidence_path,
      gate_outcome: (if $gate_outcome == "" then null else $gate_outcome end),
      gate_failure_reasons: $gate_failure_reasons,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      generated_at_utc: $generated_at_utc,
      git_commit: $git_commit,
      dirty_worktree: $dirty_worktree,
      outcome: $outcome,
      commands: $commands,
      artifacts: $artifacts,
      operator_verification: $operator_verification
    }
    + (if $failed_command == null then {} else {failed_command: $failed_command} end)
    + (if $error_code == "" then {} else {error_code: $error_code} end)' >"$manifest_path"

  echo "security conformance manifest: ${manifest_path}"
  echo "security conformance events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"
exit "$main_exit"
