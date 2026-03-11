#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root="${RGC_MODULE_INTEROP_MATRIX_ARTIFACT_ROOT:-artifacts/rgc_module_interop_verification_matrix}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_target_dir="/tmp/rch_target_franken_engine_rgc_module_interop_matrix_${timestamp}_$$"
target_dir="${CARGO_TARGET_DIR:-${default_target_dir}}"
cargo_home="${CARGO_HOME:-}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
module_resolution_trace_path="${run_dir}/module_resolution_trace.jsonl"

trace_id="trace-rgc-module-interop-matrix-${timestamp}"
decision_id="decision-rgc-module-interop-matrix-${timestamp}"
policy_id="policy-rgc-module-interop-matrix-v1"
component="rgc_module_interop_verification_matrix"
scenario_id="rgc-058"
replay_command="./scripts/e2e/rgc_module_interop_verification_matrix_replay.sh ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC module interop verification matrix heavy commands" >&2
  exit 2
fi

run_rch() {
  local -a env_args
  env_args=(
    "RUSTUP_TOOLCHAIN=${toolchain}"
    "CARGO_TARGET_DIR=${target_dir}"
  )
  if [[ -n "$cargo_home" ]]; then
    env_args+=("CARGO_HOME=${cargo_home}")
  fi

  timeout "${rch_timeout_seconds}" \
    rch exec -q -- env \
    "${env_args[@]}" \
    "$@"
}

rch_strip_ansi() {
  local input="$1"
  sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' "$input"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n 1 || true)"
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
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote execution failed: .*running locally|Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path remote_exit_code
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="$(mktemp)"

  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    if rch_strip_ansi "$log_path" | rg -q "Remote command finished: exit=0"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" \
        | tee -a "$log_path"
    else
      rm -f "$log_path"
      failed_command="$command_text"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    rm -f "$log_path"
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -n "$remote_exit_code" && "$remote_exit_code" != "0" ]]; then
    rm -f "$log_path"
    failed_command="${command_text} (remote-exit=${remote_exit_code})"
    return 1
  fi
  if [[ -z "$remote_exit_code" ]]; then
    echo "==> warning: missing remote exit marker; relying on rch process exit status" \
      | tee -a "$log_path"
  fi

  rm -f "$log_path"
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test module_compatibility_matrix --test module_compatibility_matrix_integration --test module_resolver_integration" \
        cargo check -p frankenengine-engine --test module_compatibility_matrix --test module_compatibility_matrix_integration --test module_resolver_integration \
        || return $?
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test module_compatibility_matrix --test module_compatibility_matrix_integration --test module_resolver_integration" \
        cargo test -p frankenengine-engine --test module_compatibility_matrix --test module_compatibility_matrix_integration --test module_resolver_integration \
        || return $?
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test module_compatibility_matrix --test module_compatibility_matrix_integration --test module_resolver_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test module_compatibility_matrix --test module_compatibility_matrix_integration --test module_resolver_integration -- -D warnings \
        || return $?
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test module_compatibility_matrix --test module_compatibility_matrix_integration --test module_resolver_integration" \
        cargo check -p frankenengine-engine --test module_compatibility_matrix --test module_compatibility_matrix_integration --test module_resolver_integration \
        || return $?
      run_step "cargo test -p frankenengine-engine --test module_compatibility_matrix --test module_compatibility_matrix_integration --test module_resolver_integration" \
        cargo test -p frankenengine-engine --test module_compatibility_matrix --test module_compatibility_matrix_integration --test module_resolver_integration \
        || return $?
      run_step "cargo clippy -p frankenengine-engine --test module_compatibility_matrix --test module_compatibility_matrix_integration --test module_resolver_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test module_compatibility_matrix --test module_compatibility_matrix_integration --test module_resolver_integration -- -D warnings \
        || return $?
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

run_local_step() {
  local command_text="$1"
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"
  if ! "$@"; then
    failed_command="$command_text"
    return 1
  fi
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
    error_code_json='"FE-RGC-058-MOD-INTEROP-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"rgc.module-interop.verification-matrix.gate.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "rgc.module-interop.verification-matrix.gate.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.11.8",'
    echo "  \"component\": \"${component}\"," 
    echo "  \"scenario_id\": \"${scenario_id}\"," 
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"toolchain\": \"${toolchain}\"," 
    echo "  \"cargo_target_dir\": \"${target_dir}\"," 
    if [[ -n "$cargo_home" ]]; then
      echo "  \"cargo_home\": \"${cargo_home}\"," 
    else
      echo '  "cargo_home": null,'
    fi
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
    echo "    \"module_resolution_trace\": \"${module_resolution_trace_path}\"," 
    echo '    "matrix_doc": "docs/module_compatibility_matrix_v1.json",'
    echo '    "matrix_impl": "crates/franken-engine/src/module_compatibility_matrix.rs",'
    echo '    "interop_parity_impl": "crates/franken-engine/src/esm_cjs_interop_parity.rs",'
    echo '    "unit_tests": "crates/franken-engine/tests/module_compatibility_matrix.rs",'
    echo '    "integration_tests": "crates/franken-engine/tests/module_compatibility_matrix_integration.rs",'
    echo '    "resolver_integration_tests": "crates/franken-engine/tests/module_resolver_integration.rs",'
    echo '    "replay_wrapper": "scripts/e2e/rgc_module_interop_verification_matrix_replay.sh"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo "    \"cat ${module_resolution_trace_path}\"," 
    echo "    \"./scripts/e2e/rgc_module_resolution_trace_contract_smoke.sh ${module_resolution_trace_path}\"," 
    echo '    "rg -n '\''compatibility_disposition|remediation_guidance'\'' crates/franken-engine/src/esm_cjs_interop_parity.rs",' 
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "rgc module interop verification matrix manifest: ${manifest_path}"
  echo "rgc module interop verification matrix events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?
run_local_step \
  "./scripts/e2e/rgc_module_resolution_trace_contract_smoke.sh ${module_resolution_trace_path}" \
  "${root_dir}/scripts/e2e/rgc_module_resolution_trace_contract_smoke.sh" \
  "${module_resolution_trace_path}" \
  || main_exit=$?
write_manifest "$main_exit"
exit "$main_exit"
