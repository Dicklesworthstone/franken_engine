#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_lockstep_runner_suite}"
artifact_root="${LOCKSTEP_RUNNER_ARTIFACT_ROOT:-artifacts/lockstep_runner}"
rch_exec_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-0}"
fixture_catalog="${LOCKSTEP_RUNNER_FIXTURE_CATALOG:-crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json}"
fixture_limit="${LOCKSTEP_RUNNER_FIXTURE_LIMIT:-8}"
fixture_id="${LOCKSTEP_RUNNER_FIXTURE_ID:-}"
runtime_specs="${LOCKSTEP_RUNNER_RUNTIME_SPECS:-}"
canon_rules="${LOCKSTEP_RUNNER_CANON_RULES:-crates/franken-engine/tests/fixtures/lockstep_canon_rules.toml}"
seed="${LOCKSTEP_RUNNER_SEED:-7}"
fail_on_divergence="${LOCKSTEP_RUNNER_FAIL_ON_DIVERGENCE:-0}"
allow_critical_drift="${LOCKSTEP_RUNNER_ALLOW_CRITICAL_DRIFT:-0}"
max_retries="${LOCKSTEP_RUNNER_MAX_RETRIES:-0}"
quarantine_flaky="${LOCKSTEP_RUNNER_QUARANTINE_FLAKY:-0}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.json"
evidence_path="${run_dir}/lockstep_evidence.jsonl"
governance_actions_path="${run_dir}/governance_actions.json"
repro_packs_dir="${run_dir}/repro_packs"
step_logs_dir="${run_dir}/step_logs"

trace_id="trace-lockstep-runner-${timestamp}"
decision_id="decision-lockstep-runner-${timestamp}"
policy_id="policy-lockstep-runner-v1"
component="lockstep_runner_suite"

mkdir -p "$run_dir" "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "error: rch is required for lockstep runner suite commands" >&2
  exit 1
fi

run_rch() {
  if [[ "${rch_exec_timeout_seconds}" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
    timeout "${rch_exec_timeout_seconds}" \
      rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
  else
    rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
  fi
}

run_rch_strict_logged() {
  local log_path="$1"
  shift

  local fifo_path fallback_flag_path reader_pid rch_pid rch_status=0
  local line

  fifo_path="$(mktemp -u "${run_dir}/rch-stream.XXXXXX")"
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
        "$line" == *"[RCH] local ("* ||
        "$line" == *"Failed to query daemon:"*"running locally"* ||
        "$line" == *"Dependency preflight blocked remote execution"* ||
        "$line" == *"RCH-E326"* ]]; then
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

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
    echo "error: rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

strip_ansi() {
  sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g' "$1"
}

extract_remote_exit_marker() {
  local log_path="$1"
  strip_ansi "$log_path" | sed -nE 's/.*Remote command finished: exit=([0-9]+).*/\1/p' | tail -n 1
}

annotate_failed_command() {
  local command_text="$1"
  local process_exit="$2"
  local log_path="$3"
  local remote_exit

  remote_exit="$(extract_remote_exit_marker "$log_path")"
  if [[ "$process_exit" -eq 124 ]]; then
    if [[ "${rch_exec_timeout_seconds}" -gt 0 ]]; then
      failed_command="${command_text} (timeout=${rch_exec_timeout_seconds}s/process-exit=${process_exit})"
    else
      failed_command="${command_text} (timeout/process-exit=${process_exit})"
    fi
  elif [[ -n "$remote_exit" ]]; then
    failed_command="${command_text} (remote-exit=${remote_exit}/process-exit=${process_exit})"
  else
    failed_command="${command_text} (remote-exit=missing/process-exit=${process_exit})"
  fi
}

extract_json_object_from_stream() {
  local input_path="$1"
  local output_path="$2"

  if jq -e '.' "$input_path" >/dev/null 2>&1; then
    cp "$input_path" "$output_path"
    return 0
  fi

  awk '
    BEGIN { capture=0 }
    /^\{/ { capture=1 }
    capture { print }
  ' "$input_path" >"$output_path"

  if [[ -s "$output_path" ]] && jq -e '.' "$output_path" >/dev/null 2>&1; then
    return 0
  fi

  rm -f "$output_path"
  return 1
}

declare -a commands_run=()
failed_command=""
manifest_written=false
divergent_fixtures=0
nondeterministic_fixtures=0
repro_pack_fixtures=0
step_log_index=0
preflight_state="not_run"
preflight_error_code=""
preflight_report_path="${run_dir}/report.preflight.json"

run_step() {
  local command_text="$1"
  shift
  local step_log_path
  step_log_path="${step_logs_dir}/step_$(printf '%03d' "$step_log_index").log"
  step_log_index=$((step_log_index + 1))
  commands_run+=("$command_text")
  echo "==> $command_text"
  set +e
  run_rch_strict_logged "$step_log_path" "$@"
  local rc=$?
  set -e
  if [[ "$rc" -eq 125 ]]; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 86
  fi
  if [[ "$rc" -ne 0 ]]; then
    annotate_failed_command "$command_text" "$rc" "$step_log_path"
    return "$rc"
  fi
  if ! rch_reject_local_fallback "$step_log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 86
  fi
  if [[ -z "$(extract_remote_exit_marker "$step_log_path")" ]]; then
    annotate_failed_command "$command_text" 0 "$step_log_path"
    return 87
  fi
}

run_report_step() {
  local preflight_stdout_path="${run_dir}/report.preflight.stdout"
  local -a preflight_command=(
    cargo run -p frankenengine-engine --bin franken_lockstep_runner -- \
      --fixture-catalog "$fixture_catalog" \
      --fixture-limit "$fixture_limit" \
      --seed "$seed" \
      --trace-id "$trace_id" \
      --decision-id "$decision_id" \
      --policy-id "$policy_id" \
      --locale C \
      --timezone UTC \
      --canon-rules "$canon_rules" \
      --preflight-only
  )

  if [[ -n "$fixture_id" ]]; then
    preflight_command+=(--fixture-id "$fixture_id")
  fi
  if [[ -n "$runtime_specs" ]]; then
    preflight_command+=(--runtime-specs "$runtime_specs")
  fi

  local preflight_command_text
  preflight_command_text="$(printf '%q ' "${preflight_command[@]}")"
  preflight_command_text="${preflight_command_text% }"
  commands_run+=("$preflight_command_text")
  echo "==> $preflight_command_text"
  set +e
  run_rch_strict_logged "$preflight_stdout_path" "${preflight_command[@]}"
  local preflight_rc=$?
  set -e
  if [[ "$preflight_rc" -eq 125 ]]; then
    preflight_state="failed"
    preflight_error_code="FE-LOCKSTEP-PREFLIGHT-LOCAL-FALLBACK"
    failed_command="${preflight_command_text} (rch-local-fallback-detected)"
    return 86
  fi
  if ! rch_reject_local_fallback "$preflight_stdout_path"; then
    preflight_state="failed"
    preflight_error_code="FE-LOCKSTEP-PREFLIGHT-LOCAL-FALLBACK"
    failed_command="${preflight_command_text} (rch-local-fallback-detected)"
    return 86
  fi
  if [[ "$preflight_rc" -eq 0 && -z "$(extract_remote_exit_marker "$preflight_stdout_path")" ]]; then
    preflight_state="failed"
    preflight_error_code="FE-LOCKSTEP-PREFLIGHT-REMOTE-EXIT-MISSING"
    annotate_failed_command "$preflight_command_text" 0 "$preflight_stdout_path"
    return 87
  fi

  if extract_json_object_from_stream "$preflight_stdout_path" "$preflight_report_path"; then
    if [[ "$(jq -r '.preflight_passed // false' "$preflight_report_path")" == "true" ]]; then
      preflight_state="passed"
      preflight_error_code=""
    else
      preflight_state="failed"
      preflight_error_code="$(jq -r '.error_code // empty' "$preflight_report_path")"
    fi
  else
    preflight_state="unknown"
    preflight_error_code=""
  fi

  if [[ "$preflight_rc" -ne 0 ]]; then
    preflight_state="failed"
    if [[ -z "$preflight_error_code" ]]; then
      preflight_error_code="FE-LOCKSTEP-PREFLIGHT-COMMAND-FAILED"
    fi
    annotate_failed_command "$preflight_command_text" "$preflight_rc" "$preflight_stdout_path"
    return "$preflight_rc"
  fi

  local report_stdout_path="${run_dir}/report.stdout"
  local -a command=(
    cargo run -p frankenengine-engine --bin franken_lockstep_runner -- \
      --fixture-catalog "$fixture_catalog" \
      --fixture-limit "$fixture_limit" \
      --seed "$seed" \
      --trace-id "$trace_id" \
      --decision-id "$decision_id" \
      --policy-id "$policy_id" \
      --locale C \
      --timezone UTC \
      --canon-rules "$canon_rules" \
      --out "$report_path" \
      --evidence-jsonl "$evidence_path" \
      --governance-actions-out "$governance_actions_path" \
      --max-retries "$max_retries"
  )

  if [[ -n "$fixture_id" ]]; then
    command+=(--fixture-id "$fixture_id")
  fi
  if [[ -n "$runtime_specs" ]]; then
    command+=(--runtime-specs "$runtime_specs")
  fi
  if [[ "$fail_on_divergence" == "1" ]]; then
    command+=(--fail-on-divergence)
  fi
  if [[ "$allow_critical_drift" == "1" ]]; then
    command+=(--allow-critical-drift)
  fi
  if [[ "$quarantine_flaky" == "1" ]]; then
    command+=(--quarantine-flaky)
  fi

  local command_text
  command_text="$(printf '%q ' "${command[@]}")"
  command_text="${command_text% }"
  commands_run+=("$command_text")
  echo "==> $command_text"

  set +e
  run_rch_strict_logged "$report_stdout_path" "${command[@]}"
  local rc=$?
  set -e
  if [[ "$rc" -eq 125 ]]; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 86
  fi

  if ! rch_reject_local_fallback "$report_stdout_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 86
  fi
  if [[ "$rc" -eq 0 && -z "$(extract_remote_exit_marker "$report_stdout_path")" ]]; then
    annotate_failed_command "$command_text" 0 "$report_stdout_path"
    return 87
  fi

  if [[ ! -f "$report_path" && -s "$report_stdout_path" ]]; then
    if jq -e '.' "$report_stdout_path" >/dev/null 2>&1; then
      cp "$report_stdout_path" "$report_path"
    else
      local extracted_json_path="${run_dir}/report.stdout.extracted.json"
      awk '
        BEGIN { capture=0 }
        /^\{/ { capture=1 }
        capture { print }
      ' "$report_stdout_path" >"$extracted_json_path"
      if [[ -s "$extracted_json_path" ]] && jq -e '.' "$extracted_json_path" >/dev/null 2>&1; then
        cp "$extracted_json_path" "$report_path"
      fi
    fi
  fi

  if [[ -f "$report_path" ]]; then
    divergent_fixtures="$(jq -r '.summary.divergent_fixtures // 0' "$report_path")"
    nondeterministic_fixtures="$(jq -r '.summary.fixtures_with_nondeterminism // 0' "$report_path")"
    repro_pack_fixtures="$(jq -r '[.fixture_results[] | select(.repro_pack != null)] | length' "$report_path")"
    mkdir -p "$repro_packs_dir"
    jq -c '.fixture_results[] | select(.repro_pack != null) | .repro_pack' "$report_path" \
      | while IFS= read -r repro_json; do
          fixture_key="$(jq -r '.fixture_id' <<<"$repro_json")"
          jq '.' <<<"$repro_json" >"${repro_packs_dir}/${fixture_key}.json"
        done
  fi

  if [[ "$rc" -ne 0 ]]; then
    annotate_failed_command "$command_text" "$rc" "$report_stdout_path"
    return "$rc"
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --bin franken_lockstep_runner --test franken_lockstep_runner_cli" \
        cargo check -p frankenengine-engine --bin franken_lockstep_runner --test franken_lockstep_runner_cli \
        || return $?
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test franken_lockstep_runner_cli" \
        cargo test -p frankenengine-engine --test franken_lockstep_runner_cli \
        || return $?
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --bin franken_lockstep_runner --test franken_lockstep_runner_cli -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin franken_lockstep_runner --test franken_lockstep_runner_cli -- -D warnings \
        || return $?
      ;;
    report)
      run_report_step || return $?
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --bin franken_lockstep_runner --test franken_lockstep_runner_cli" \
        cargo check -p frankenengine-engine --bin franken_lockstep_runner --test franken_lockstep_runner_cli \
        || return $?
      run_step "cargo test -p frankenengine-engine --test franken_lockstep_runner_cli" \
        cargo test -p frankenengine-engine --test franken_lockstep_runner_cli \
        || return $?
      run_step "cargo clippy -p frankenengine-engine --bin franken_lockstep_runner --test franken_lockstep_runner_cli -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin franken_lockstep_runner --test franken_lockstep_runner_cli -- -D warnings \
        || return $?
      run_report_step || return $?
      ;;
    *)
      echo "usage: $0 [check|test|clippy|report|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-LOCKSTEP-RUNNER-SUITE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  {
    echo "{\"schema_version\":\"franken-engine.parser-log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json},\"divergent_fixtures\":${divergent_fixtures},\"nondeterministic_fixtures\":${nondeterministic_fixtures}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.lockstep-runner-suite.run-manifest.v1",'
    echo '  "bead_id": "bd-2vu",'
    echo "  \"component\": \"${component}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"rch_timeout_seconds\": ${rch_exec_timeout_seconds},"
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"fixture_catalog\": \"${fixture_catalog}\","
    echo "  \"fixture_limit\": \"${fixture_limit}\","
    echo "  \"fixture_id\": \"${fixture_id}\","
    echo "  \"runtime_specs\": \"${runtime_specs}\","
    echo "  \"canon_rules\": \"${canon_rules}\","
    echo "  \"seed\": ${seed},"
    echo "  \"fail_on_divergence\": ${fail_on_divergence},"
    echo "  \"allow_critical_drift\": ${allow_critical_drift},"
    echo "  \"max_retries\": ${max_retries},"
    echo "  \"quarantine_flaky\": ${quarantine_flaky},"
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"preflight_state\": \"${preflight_state}\","
    if [[ -n "$preflight_error_code" ]]; then
      echo "  \"preflight_error_code\": \"${preflight_error_code}\","
    fi
    echo "  \"divergent_fixtures\": ${divergent_fixtures},"
    echo "  \"nondeterministic_fixtures\": ${nondeterministic_fixtures},"
    echo "  \"repro_pack_fixtures\": ${repro_pack_fixtures},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo "  ],"
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"preflight_report\": \"${preflight_report_path}\","
    echo "    \"report\": \"${report_path}\","
    echo "    \"evidence\": \"${evidence_path}\","
    echo "    \"governance_actions\": \"${governance_actions_path}\","
    echo "    \"repro_packs_dir\": \"${repro_packs_dir}\","
    echo "    \"step_logs_dir\": \"${step_logs_dir}\""
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${preflight_report_path}\","
    echo "    \"cat ${report_path}\","
    echo "    \"cat ${evidence_path}\","
    echo "    \"cat ${governance_actions_path}\","
    echo "    \"ls ${step_logs_dir}\","
    echo "    \"ls ${repro_packs_dir}\","
    echo "    \"./scripts/e2e/lockstep_runner_replay.sh report\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "lockstep runner suite manifest: $manifest_path"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "$events_path"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
