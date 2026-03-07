#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/data/projects/franken_engine/target_rch_rgc_react_capability_contract}"
artifact_root="${RGC_REACT_CAPABILITY_CONTRACT_ARTIFACT_ROOT:-artifacts/rgc_react_capability_contract}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
contract_artifact_path="${run_dir}/react_capability_contract.json"

trace_id="trace-rgc-react-capability-contract-${timestamp}"
decision_id="decision-rgc-react-capability-contract-${timestamp}"
policy_id="policy-rgc-react-capability-contract-v1"
component="rgc_react_capability_contract_gate"
scenario_id="rgc-016a"
replay_command="./scripts/e2e/rgc_react_capability_contract_replay.sh ${mode}"

contract_doc="docs/RGC_REACT_CAPABILITY_CONTRACT_V1.md"
contract_json="docs/rgc_react_capability_contract_v1.json"
matrix_doc="docs/RGC_EXECUTABLE_COMPATIBILITY_TARGET_MATRIX_V1.md"
matrix_json="docs/rgc_executable_compatibility_target_matrix_v1.json"

mkdir -p "$run_dir"

if [[ ! -f "$contract_doc" || ! -f "$contract_json" ]]; then
  echo "FE-RGC-016A-CONTRACT-0001: missing React capability contract inputs" >&2
  exit 1
fi

if [[ ! -f "$matrix_doc" || ! -f "$matrix_json" ]]; then
  echo "FE-RGC-016A-CONTRACT-0002: missing executable matrix linkage inputs" >&2
  exit 1
fi

if ! jq -e '.' "$contract_json" >/dev/null 2>&1; then
  echo "FE-RGC-016A-CONTRACT-0003: failed to parse ${contract_json}" >&2
  exit 1
fi

if ! jq -e '.' "$matrix_json" >/dev/null 2>&1; then
  echo "FE-RGC-016A-CONTRACT-0004: failed to parse ${matrix_json}" >&2
  exit 1
fi

cp "$contract_json" "$contract_artifact_path"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC React capability contract heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" rch exec -q -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"

  log_path="$(mktemp)"
  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    if rg -q "Remote command finished: exit=0" "$log_path"; then
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

  rm -f "$log_path"
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test rgc_react_capability_contract --test rgc_executable_compatibility_target_matrix" \
        cargo check -p frankenengine-engine --test rgc_react_capability_contract --test rgc_executable_compatibility_target_matrix
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test rgc_react_capability_contract --test rgc_executable_compatibility_target_matrix" \
        cargo test -p frankenengine-engine --test rgc_react_capability_contract --test rgc_executable_compatibility_target_matrix
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test rgc_react_capability_contract --test rgc_executable_compatibility_target_matrix -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_react_capability_contract --test rgc_executable_compatibility_target_matrix -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test rgc_react_capability_contract --test rgc_executable_compatibility_target_matrix" \
        cargo check -p frankenengine-engine --test rgc_react_capability_contract --test rgc_executable_compatibility_target_matrix
      run_step "cargo test -p frankenengine-engine --test rgc_react_capability_contract --test rgc_executable_compatibility_target_matrix" \
        cargo test -p frankenengine-engine --test rgc_react_capability_contract --test rgc_executable_compatibility_target_matrix
      run_step "cargo clippy -p frankenengine-engine --test rgc_react_capability_contract --test rgc_executable_compatibility_target_matrix -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_react_capability_contract --test rgc_executable_compatibility_target_matrix -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
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
    error_code_json='"FE-RGC-016A-GATE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"rgc.react-capability-contract.gate.event.v1\",\"scenario_id\":\"${scenario_id}\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"runtime_lane\":\"planning_contract\",\"seed\":\"fixed-contract-seed-v1\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "rgc.react-capability-contract.gate.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.1.6.1",'
    echo "  \"component\": \"${component}\","
    echo "  \"scenario_id\": \"${scenario_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
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
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\","
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    "
    echo '  },'
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"react_capability_contract\": \"${contract_artifact_path}\","
    echo '    "contract_doc": "docs/RGC_REACT_CAPABILITY_CONTRACT_V1.md",'
    echo '    "contract_json": "docs/rgc_react_capability_contract_v1.json",'
    echo '    "matrix_doc": "docs/RGC_EXECUTABLE_COMPATIBILITY_TARGET_MATRIX_V1.md",'
    echo '    "matrix_json": "docs/rgc_executable_compatibility_target_matrix_v1.json",'
    echo '    "integration_tests": ['
    echo '      "crates/franken-engine/tests/rgc_react_capability_contract.rs",'
    echo '      "crates/franken-engine/tests/rgc_executable_compatibility_target_matrix.rs"'
    echo '    ]'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${contract_artifact_path}\","
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "rgc react capability contract manifest: ${manifest_path}"
  echo "rgc react capability contract events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"
exit "$main_exit"
