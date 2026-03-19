#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root="${PARSER_PARALLEL_INTERFERENCE_ARTIFACT_ROOT:-artifacts/parser_parallel_interference}"
scenario_id="${PARSER_PARALLEL_INTERFERENCE_SCENARIO:-psrp-05-4-2}"
arch_profile="${PARSER_PARALLEL_INTERFERENCE_ARCH_PROFILE:-${PARSER_FRONTIER_RUST_HOST}}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
rch_build_timeout_sec="${RCH_BUILD_TIMEOUT_SEC:-${RCH_BUILD_TIMEOUT_SECONDS:-${rch_timeout_seconds}}}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_target_dir_root="${PARSER_PARALLEL_INTERFERENCE_TARGET_DIR_ROOT:-/var/tmp/rch_target_franken_engine_parser_parallel_interference}"
if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  target_dir="${CARGO_TARGET_DIR}"
  target_dir_strategy="explicit-env"
else
  target_dir="${default_target_dir_root}/${timestamp}-pid$$"
  target_dir_strategy="run-scoped-default"
fi
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

trace_id="trace-parser-parallel-interference-${timestamp}"
decision_id="decision-parser-parallel-interference-${timestamp}"
policy_id="policy-parser-parallel-interference-v1"
component="parser_parallel_interference_gate"
replay_command="${0} ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "error: rch is required for parser parallel interference gate runs" >&2
  exit 2
fi

run_rch() {
  RCH_BUILD_TIMEOUT_SEC="${rch_build_timeout_sec}" \
    RCH_BUILD_TIMEOUT_SECONDS="${rch_build_timeout_sec}" \
    timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_strip_ansi() {
  local input="$1"
  sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' "$input"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Remote execution failed: .*running locally|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_last_remote_exit_code() {
  local log_path="$1"
  local exit_line
  exit_line="$(
    rch_strip_ansi "$log_path" | grep -Eo 'Remote command finished: exit=[0-9]+' | tail -n 1 || true
  )"
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

rch_has_recoverable_artifact_timeout() {
  local log_path="$1"
  rch_strip_ansi "$log_path" \
    | grep -Eiq 'artifact retrieval timed out|artifact transfer timed out|timed out waiting for artifacts|failed to retrieve artifacts|failed to download artifacts'
}

rch_has_remote_compile_failure() {
  local log_path="$1"
  rch_strip_ansi "$log_path" \
    | grep -Eiq '(^|[^[:alnum:]_])error(\[[A-Z0-9]+\])?([^[:alnum:]_]|$)|could not compile `|aborting due to [0-9]+ previous errors?'
}

rch_reject_artifact_retrieval_failure() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" \
    | grep -Eiq 'Artifact retrieval failed|Failed to retrieve artifacts:|rsync artifact retrieval failed|rsync error: .*code 23'; then
    echo "rch artifact retrieval failed; refusing to mark heavy command as successful" >&2
    return 1
  fi
}

rch_exact_filter_ran_zero_tests() {
  local log_path="$1"
  rch_strip_ansi "$log_path" \
    | grep -Eiq '^running 0 tests$|test result: ok\. 0 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out;'
}

declare -a commands_run=()
declare -a command_log_paths=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path
  local run_rch_status=0
  local remote_exit_code=""
  local reported_timeout=""
  local step_index
  shift

  step_index="$(( ${#commands_run[@]} + 1 ))"
  log_path="${run_dir}/step-$(printf '%03d' "${step_index}").log"

  commands_run+=("$command_text")
  command_log_paths+=("$log_path")
  echo "==> $command_text"

  run_rch "$@" > >(tee "$log_path") 2>&1 || run_rch_status=$?
  remote_exit_code="$(rch_last_remote_exit_code "$log_path")"
  reported_timeout="$(rch_reported_timeout_seconds "$log_path")"

  if [[ "$run_rch_status" -ne 0 ]]; then
    if [[ "$rch_build_timeout_sec" =~ ^[0-9]+$ && "$reported_timeout" =~ ^[0-9]+$ ]] &&
      (( reported_timeout < rch_build_timeout_sec )); then
      echo "rch reported timeout_secs=${reported_timeout} but requested build timeout is ${rch_build_timeout_sec}" | tee -a "$log_path"
      failed_command="${command_text} (rch-timeout-mismatch-${reported_timeout}-lt-${rch_build_timeout_sec})"
      return 1
    fi
    if [[ "$remote_exit_code" == "0" ]] && rch_has_recoverable_artifact_timeout "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    elif [[ "$run_rch_status" -eq 124 ]]; then
      if rch_has_remote_compile_failure "$log_path"; then
        failed_command="${command_text} (rch-timeout-after-remote-compile-failure)"
      else
        failed_command="${command_text} (rch-timeout)"
      fi
      return 1
    elif [[ -n "$remote_exit_code" ]]; then
      failed_command="${command_text} (remote-exit-${remote_exit_code})"
      return 1
    else
      failed_command="$command_text"
      return 1
    fi
  fi

  if [[ "$rch_build_timeout_sec" =~ ^[0-9]+$ && "$reported_timeout" =~ ^[0-9]+$ ]] &&
    (( reported_timeout < rch_build_timeout_sec )); then
    echo "rch reported timeout_secs=${reported_timeout} but requested build timeout is ${rch_build_timeout_sec}" | tee -a "$log_path"
    failed_command="${command_text} (rch-timeout-mismatch-${reported_timeout}-lt-${rch_build_timeout_sec})"
    return 1
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  if ! rch_reject_artifact_retrieval_failure "$log_path"; then
    failed_command="${command_text} (rch-artifact-retrieval-failed)"
    return 1
  fi

  if [[ -z "$remote_exit_code" ]]; then
    echo "rch output missing remote exit marker; failing closed" | tee -a "$log_path"
    failed_command="${command_text} (missing-remote-exit-marker)"
    return 1
  fi

  if [[ "$remote_exit_code" != "0" ]]; then
    failed_command="${command_text} (remote-exit-${remote_exit_code})"
    return 1
  fi

  if [[ "$command_text" == *"--exact"* ]] && rch_exact_filter_ran_zero_tests "$log_path"; then
    echo "rch exact-filter step matched zero tests; failing closed" | tee -a "$log_path"
    failed_command="${command_text} (zero-tests-matched-exact-filter)"
    return 1
  fi
}

run_test_lane() {
  run_step \
    "cargo test -p frankenengine-engine --lib -- --exact parallel_parser::tests::chunk_plan_worker_count_capped_to_input_bytes" \
    cargo test -p frankenengine-engine --lib -- --exact parallel_parser::tests::chunk_plan_worker_count_capped_to_input_bytes
  run_step \
    "cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact evaluate_gate_correct_run_count" \
    cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact evaluate_gate_correct_run_count
  run_step \
    "cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact evaluate_gate_many_worker_variations" \
    cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact evaluate_gate_many_worker_variations
  run_step \
    "cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact evaluate_gate_deterministic_repeated" \
    cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact evaluate_gate_deterministic_repeated
  run_step \
    "cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact evaluate_gate_operators_and_strings" \
    cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact evaluate_gate_operators_and_strings
  run_step \
    "cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact compare_witnesses_all_fields_differ" \
    cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact compare_witnesses_all_fields_differ
  run_step \
    "cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact build_replay_bundle_deduplicates_seeds_and_workers" \
    cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact build_replay_bundle_deduplicates_seeds_and_workers
  run_step \
    "cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact flake_rate_excess_mismatches_clamp_to_full_rate" \
    cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact flake_rate_excess_mismatches_clamp_to_full_rate
  run_step \
    "cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact operator_summary_multiple_classes_sorted_by_count" \
    cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact operator_summary_multiple_classes_sorted_by_count
  run_step \
    "cargo test -p frankenengine-engine --test parallel_parser_integration -- --exact parse_parallel_merge_witness_present" \
    cargo test -p frankenengine-engine --test parallel_parser_integration -- --exact parse_parallel_merge_witness_present
}

run_mode() {
  case "$mode" in
    check)
      run_step \
        "cargo test -p frankenengine-engine --lib --test parallel_interference_gate_integration --test parallel_parser_integration --no-run" \
        cargo test -p frankenengine-engine --lib --test parallel_interference_gate_integration --test parallel_parser_integration --no-run
      ;;
    test)
      run_test_lane
      ;;
    clippy)
      run_step \
        "env RUSTC_WORKSPACE_WRAPPER=clippy-driver RUSTFLAGS=-Dwarnings cargo test -p frankenengine-engine --lib --test parallel_interference_gate_integration --test parallel_parser_integration --no-run" \
        env RUSTC_WORKSPACE_WRAPPER=clippy-driver RUSTFLAGS=-Dwarnings cargo test -p frankenengine-engine --lib --test parallel_interference_gate_integration --test parallel_parser_integration --no-run
      ;;
    ci)
      run_step \
        "cargo test -p frankenengine-engine --lib --test parallel_interference_gate_integration --test parallel_parser_integration --no-run" \
        cargo test -p frankenengine-engine --lib --test parallel_interference_gate_integration --test parallel_parser_integration --no-run
      run_test_lane
      run_step \
        "env RUSTC_WORKSPACE_WRAPPER=clippy-driver RUSTFLAGS=-Dwarnings cargo test -p frankenengine-engine --lib --test parallel_interference_gate_integration --test parallel_parser_integration --no-run" \
        env RUSTC_WORKSPACE_WRAPPER=clippy-driver RUSTFLAGS=-Dwarnings cargo test -p frankenengine-engine --lib --test parallel_interference_gate_integration --test parallel_parser_integration --no-run
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx log_idx comma

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-PARSER-PARALLEL-INTERFERENCE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  {
    echo "{\"schema_version\":\"franken-engine.parser-parallel-interference.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-parallel-interference.run-manifest.v1",'
    echo '  "bead_id": "bd-2mds.1.5.4.2",'
    echo "  \"deterministic_env_schema_version\": \"${PARSER_FRONTIER_ENV_SCHEMA_VERSION}\"," 
    echo "  \"component\": \"${component}\"," 
    echo "  \"scenario_id\": \"${scenario_id}\"," 
    echo "  \"arch_profile\": \"$(parser_frontier_json_escape "${arch_profile}")\"," 
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"toolchain\": \"${toolchain}\"," 
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"rch_build_timeout_seconds\": ${rch_build_timeout_sec},"
    echo "  \"cargo_target_dir_strategy\": \"${target_dir_strategy}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\"," 
    echo "  \"trace_id\": \"${trace_id}\"," 
    echo "  \"decision_id\": \"${decision_id}\"," 
    echo "  \"policy_id\": \"${policy_id}\"," 
    echo "  \"generated_at_utc\": \"${timestamp}\"," 
    echo "  \"git_commit\": \"${git_commit}\"," 
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\"," 
    echo "  \"error_code\": ${error_code_json},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\"," 
    fi
    echo '  "matrix_profile": {'
    echo '    "worker_counts": [2, 4, 8],'
    echo '    "seed_count": 3,'
    echo '    "repeats_per_seed": 2,'
    echo '    "adversarial_profiles": ["operators-and-strings", "witness-diff-synthetic"]'
    echo '  },'
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo "  },"
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
    echo '    "step_logs": ['
    for log_idx in "${!command_log_paths[@]}"; do
      comma=","
      if [[ "$log_idx" == "$(( ${#command_log_paths[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "      \"$(parser_frontier_json_escape "${command_log_paths[$log_idx]}")\"${comma}"
    done
    echo '    ],'
    echo '    "contract_doc": "docs/PARSER_PARALLEL_INTERFERENCE_GATE.md",'
    echo '    "integration_tests": "crates/franken-engine/tests/parallel_interference_gate_integration.rs",'
    echo '    "parallel_parser_tests": "crates/franken-engine/tests/parallel_parser_integration.rs",'
    echo '    "source_modules": ["crates/franken-engine/src/parallel_interference_gate.rs", "crates/franken-engine/src/parallel_parser.rs"]'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "parser parallel interference manifest: ${manifest_path}"
  echo "parser parallel interference events: ${events_path}"
}

main_exit=0
set +e
run_mode
main_exit=$?
set -e
write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "$events_path"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
