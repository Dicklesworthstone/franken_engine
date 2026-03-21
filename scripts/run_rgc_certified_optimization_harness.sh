#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root="${RGC_CERTIFIED_OPTIMIZATION_HARNESS_ARTIFACT_ROOT:-artifacts/rgc_certified_optimization_harness}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_target_dir="/data/projects/franken_engine/target_rch_rgc_certified_optimization_harness"
target_dir="${CARGO_TARGET_DIR:-${default_target_dir}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
proof_index_path="${run_dir}/rewrite_proof_index.json"
trace_ids_path="${run_dir}/trace_ids.json"

trace_id="trace-rgc-certified-optimization-harness-${timestamp}"
decision_id="decision-rgc-certified-optimization-harness-${timestamp}"
policy_id="policy-rgc-certified-optimization-harness-v1"
component="rgc_certified_optimization_harness"
scenario_id="rgc-607"
replay_command="./scripts/e2e/rgc_certified_optimization_harness_replay.sh ${mode}"
artifact_env_var="RGC_CERTIFIED_OPTIMIZATION_HARNESS_ARTIFACT_DIR"
bead_id="bd-1lsy.7.7"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC certified optimization harness heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rg -o 'Remote command finished: exit=[0-9]+' "$log_path" | tail -n 1 || true)"
  if [[ -z "$remote_exit_line" ]]; then
    return 1
  fi

  remote_exit_code="${remote_exit_line##*=}"
  if [[ -z "$remote_exit_code" ]]; then
    return 1
  fi

  printf '%s\n' "$remote_exit_code"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
declare -a rch_logs=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path remote_exit_code run_rch_status
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="$(mktemp "${run_dir}/rch-log.XXXXXX")"
  rch_logs+=("$log_path")

  if run_rch "$@" > >(tee "$log_path") 2>&1; then
    :
  else
    run_rch_status="$?"
    if rg -q "Remote command finished: exit=0" "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" \
        | tee -a "$log_path"
    else
      if [[ "$run_rch_status" == "124" ]]; then
        failed_command="${command_text} (outer-timeout=${rch_timeout_seconds}s)"
      else
        failed_command="${command_text} (run_rch-exit=${run_rch_status})"
      fi
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -n "$remote_exit_code" && "$remote_exit_code" != "0" ]]; then
    failed_command="${command_text} (remote-exit=${remote_exit_code})"
    return 1
  fi
}

assert_test_artifacts_present() {
  local missing=0
  for required_path in "$proof_index_path" "$trace_ids_path"; do
    if [[ ! -f "$required_path" ]]; then
      echo "missing required artifact: ${required_path}" >&2
      missing=1
    fi
  done

  if [[ "$missing" -ne 0 ]]; then
    failed_command="artifact validation (missing certified optimization harness outputs)"
    return 1
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test rgc_certified_optimization_harness --test translation_validation_integration --test translation_validation_receipt_integration --test certified_optimization_governance_integration" \
        cargo check -p frankenengine-engine --test rgc_certified_optimization_harness --test translation_validation_integration --test translation_validation_receipt_integration --test certified_optimization_governance_integration
      ;;
    test)
      run_step "env ${artifact_env_var}=${run_dir} cargo test -p frankenengine-engine --test rgc_certified_optimization_harness --test translation_validation_integration --test translation_validation_receipt_integration --test certified_optimization_governance_integration" \
        "${artifact_env_var}=${run_dir}" \
        cargo test -p frankenengine-engine --test rgc_certified_optimization_harness --test translation_validation_integration --test translation_validation_receipt_integration --test certified_optimization_governance_integration
      assert_test_artifacts_present
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test rgc_certified_optimization_harness --test translation_validation_integration --test translation_validation_receipt_integration --test certified_optimization_governance_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_certified_optimization_harness --test translation_validation_integration --test translation_validation_receipt_integration --test certified_optimization_governance_integration -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test rgc_certified_optimization_harness --test translation_validation_integration --test translation_validation_receipt_integration --test certified_optimization_governance_integration" \
        cargo check -p frankenengine-engine --test rgc_certified_optimization_harness --test translation_validation_integration --test translation_validation_receipt_integration --test certified_optimization_governance_integration
      run_step "env ${artifact_env_var}=${run_dir} cargo test -p frankenengine-engine --test rgc_certified_optimization_harness --test translation_validation_integration --test translation_validation_receipt_integration --test certified_optimization_governance_integration" \
        "${artifact_env_var}=${run_dir}" \
        cargo test -p frankenengine-engine --test rgc_certified_optimization_harness --test translation_validation_integration --test translation_validation_receipt_integration --test certified_optimization_governance_integration
      assert_test_artifacts_present
      run_step "cargo clippy -p frankenengine-engine --test rgc_certified_optimization_harness --test translation_validation_integration --test translation_validation_receipt_integration --test certified_optimization_governance_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_certified_optimization_harness --test translation_validation_integration --test translation_validation_receipt_integration --test certified_optimization_governance_integration -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma include_bundle_artifacts

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-607-CERTIFIED-OPT-HARNESS-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  include_bundle_artifacts=false
  if [[ "$mode" == "test" || "$mode" == "ci" ]]; then
    include_bundle_artifacts=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.rgc-certified-optimization-harness.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo "  \"schema_version\": \"franken-engine.rgc-certified-optimization-harness.run-manifest.v1\","
    echo "  \"bead_id\": \"${bead_id}\","
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
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"error_code\": ${error_code_json},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\","
    fi
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
    if [[ "$include_bundle_artifacts" == true ]]; then
      echo "    \"rewrite_proof_index\": \"${proof_index_path}\","
      echo "    \"trace_ids\": \"${trace_ids_path}\","
    fi
    echo '    "integration_tests": "crates/franken-engine/tests/rgc_certified_optimization_harness.rs",'
    echo '    "replay_wrapper": "scripts/e2e/rgc_certified_optimization_harness_replay.sh"'
    echo "  },"
    echo '  "rch_logs": ['
    for idx in "${!rch_logs[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#rch_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${rch_logs[$idx]}")\"${comma}"
    done
    echo "  ],"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    if [[ "$include_bundle_artifacts" == true ]]; then
      echo "    \"cat ${proof_index_path}\","
      echo "    \"cat ${trace_ids_path}\","
    fi
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "rgc certified optimization harness manifest: ${manifest_path}"
  echo "rgc certified optimization harness events: ${events_path}"
}

main_exit=0

emit_manifest_on_exit() {
  local trap_exit="$?"
  local exit_code

  set +e
  exit_code="${main_exit}"
  if [[ "$exit_code" -eq 0 && "$trap_exit" -ne 0 ]]; then
    exit_code="$trap_exit"
  fi
  write_manifest "$exit_code" || true
}

trap emit_manifest_on_exit EXIT

run_mode || main_exit=$?
exit "$main_exit"
