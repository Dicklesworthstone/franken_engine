#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
artifact_root="${PARSER_PERFORMANCE_PROMOTION_GATE_ARTIFACT_ROOT:-artifacts/parser_performance_promotion_gate}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
fixture_path="crates/franken-engine/tests/fixtures/parser_performance_promotion_gate_v1.json"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_parser_performance_promotion_gate_${target_namespace}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
step_logs_dir="${run_dir}/step_logs"

trace_id="trace-parser-performance-promotion-gate-${timestamp}"
decision_id="decision-parser-performance-promotion-gate-${timestamp}"
policy_id="policy-parser-performance-promotion-gate-v1"
component="parser_performance_promotion_gate"
replay_command="./scripts/e2e/parser_performance_promotion_gate_replay.sh ${mode}"

mkdir -p "$run_dir" "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for parser performance promotion gate heavy commands" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to emit parser performance gate structured inventories" >&2
  exit 2
fi

run_rch() {
  RCH_EXEC_TIMEOUT_SECONDS="${rch_timeout_seconds}" \
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "$@"
}

rch_strip_ansi() {
  local input="$1"
  sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' "$input"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|Remote execution failed.*running locally|running locally|Dependency preflight blocked remote execution|RCH-E326'; then
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

rch_has_recoverable_artifact_timeout() {
  local log_path="$1"
  rch_strip_ansi "$log_path" | grep -Eiq 'artifact retrieval timed out|artifact transfer timed out|timed out waiting for artifacts|failed to retrieve artifacts|failed to download artifacts'
}

rch_reject_artifact_retrieval_failure() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Artifact retrieval failed|Failed to retrieve artifacts:|rsync artifact retrieval failed|rsync error: .*code 23'; then
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
  local log_path run_rc remote_exit_code
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  step_log_index=$((step_log_index + 1))

  if run_rch "$@" > >(tee "$log_path") 2>&1; then
    run_rc=0
  else
    run_rc=$?
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  if ! rch_reject_artifact_retrieval_failure "$log_path"; then
    failed_command="${command_text} (rch-artifact-retrieval-failed)"
    return 1
  fi

  remote_exit_code="$(rch_last_remote_exit_code "$log_path")"

  if [[ "$run_rc" -ne 0 ]]; then
    if [[ "$remote_exit_code" == "0" ]] && rch_has_recoverable_artifact_timeout "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    elif [[ "$run_rc" -eq 124 ]]; then
      failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      return 1
    elif [[ -n "$remote_exit_code" ]]; then
      failed_command="${command_text} (remote-exit=${remote_exit_code})"
      return 1
    else
      failed_command="${command_text} (rch-exit=${run_rc})"
      return 1
    fi
  fi

  if [[ -z "$remote_exit_code" ]]; then
    failed_command="${command_text} (missing-remote-exit-marker)"
    return 1
  fi

  if [[ "$remote_exit_code" != "0" ]]; then
    failed_command="${command_text} (remote-exit=${remote_exit_code})"
    return 1
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step \
        "cargo check -p frankenengine-engine --test parser_performance_promotion_gate" \
        cargo check -p frankenengine-engine --test parser_performance_promotion_gate || return $?
      ;;
    test)
      run_step \
        "cargo test -p frankenengine-engine --test parser_performance_promotion_gate" \
        cargo test -p frankenengine-engine --test parser_performance_promotion_gate || return $?
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --test parser_performance_promotion_gate -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_performance_promotion_gate -- -D warnings || return $?
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-engine --test parser_performance_promotion_gate" \
        cargo check -p frankenengine-engine --test parser_performance_promotion_gate || return $?
      run_step \
        "cargo test -p frankenengine-engine --test parser_performance_promotion_gate" \
        cargo test -p frankenengine-engine --test parser_performance_promotion_gate || return $?
      run_step \
        "cargo clippy -p frankenengine-engine --test parser_performance_promotion_gate -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_performance_promotion_gate -- -D warnings || return $?
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

json_array_or_empty() {
  local jq_expr="$1"
  if [[ -f "$fixture_path" ]]; then
    jq -c "$jq_expr" "$fixture_path"
  else
    echo "[]"
  fi
}

json_string_or_default() {
  local jq_expr="$1"
  local default_value="$2"
  if [[ -f "$fixture_path" ]]; then
    jq -r "$jq_expr // \"${default_value}\"" "$fixture_path"
  else
    echo "$default_value"
  fi
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma
  local blocked_pairs failing_workload_ids quantile_inventory corpus_inventory replay_pointers
  local protocol_version protocol_hash

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-PARSER-PERF-GATE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  blocked_pairs="$(json_array_or_empty '.expected_gate.expected_blocked_pairs')"
  failing_workload_ids="$(json_array_or_empty '.expected_gate.expected_failing_workload_ids')"
  quantile_inventory="$(json_array_or_empty '.required_quantiles')"
  corpus_inventory="$(json_array_or_empty '[.benchmark_rows[].corpus_id] | unique')"
  replay_pointers="$(json_array_or_empty '([.evidence_vectors[].replay_command] + [.telemetry_artifacts[].replay_command] + [.replay_scenarios[].replay_command]) | unique')"
  protocol_version="$(json_string_or_default '.protocol_version' 'unknown-protocol')"
  protocol_hash="$(json_string_or_default '.protocol_hash' 'unknown-hash')"

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.parser-log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"performance_gate_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json},\"blocked_pairs\":${blocked_pairs},\"failing_workload_ids\":${failing_workload_ids},\"corpus_inventory\":${corpus_inventory},\"quantile_inventory\":${quantile_inventory},\"replay_pointers\":${replay_pointers},\"protocol_version\":\"${protocol_version}\",\"protocol_hash\":\"${protocol_hash}\",\"replay_command\":\"${replay_command}\"}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-performance-promotion-gate.run-manifest.v1",'
    echo '  "bead_id": "bd-2mds.1.8.3",'
    echo "  \"component\": \"${component}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"deterministic_env_schema_version\": \"${PARSER_FRONTIER_ENV_SCHEMA_VERSION}\","
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo "  },"
    echo "  \"outcome\": \"${outcome}\","
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\","
    fi
    echo "  \"protocol_version\": \"$(parser_frontier_json_escape "${protocol_version}")\","
    echo "  \"protocol_hash\": \"$(parser_frontier_json_escape "${protocol_hash}")\","
    echo "  \"blocked_pairs\": ${blocked_pairs},"
    echo "  \"failing_workload_ids\": ${failing_workload_ids},"
    echo "  \"corpus_inventory\": ${corpus_inventory},"
    echo "  \"quantile_inventory\": ${quantile_inventory},"
    echo "  \"replay_pointers\": ${replay_pointers},"
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\","
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo "  ],"
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo '    "step_logs": "'"${step_logs_dir}"'",'
    echo '    "contract_doc": "docs/PARSER_PERFORMANCE_PROMOTION_GATE.md",'
    echo '    "gate_fixture": "crates/franken-engine/tests/fixtures/parser_performance_promotion_gate_v1.json",'
    echo '    "gate_tests": "crates/franken-engine/tests/parser_performance_promotion_gate.rs",'
    echo '    "replay_wrapper": "scripts/e2e/parser_performance_promotion_gate_replay.sh"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${step_logs_dir}/step_000.log\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "parser performance promotion gate manifest: ${manifest_path}"
  echo "parser performance promotion gate events: ${events_path}"
}

main_exit=0
if run_mode; then
  main_exit=0
else
  main_exit=$?
fi
write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "$events_path"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
