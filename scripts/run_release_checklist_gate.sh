#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-}"
toolchain_display="${toolchain:-default}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_release_checklist_gate}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
cargo_incremental="${CARGO_INCREMENTAL:-0}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
component="release_checklist_gate"
bead_id="bd-ag4"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="artifacts/release_checklist_gate/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/release_checklist_gate_events.jsonl"
commands_path="${run_dir}/commands.txt"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for release checklist gate heavy commands" >&2
  exit 2
fi

run_rch() {
  local -a env_args=(
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "CARGO_INCREMENTAL=${cargo_incremental}" \
  )
  if [[ -n "$toolchain" ]]; then
    env_args+=("RUSTUP_TOOLCHAIN=${toolchain}")
  fi
  rch exec -- env "${env_args[@]}" "$@"
}

reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|running locally' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path step_index run_status
  shift
  step_index="${#commands_run[@]}"
  commands_run+=("$command_text")
  echo "==> $command_text"

  log_path="${run_dir}/rch-log-${step_index}.log"
  if ! timeout "${rch_timeout_seconds}" run_rch "$@" > >(tee "$log_path") 2>&1; then
    run_status="$?"
    if [[ "$run_status" == "124" ]]; then
      failed_command="${command_text} (outer-timeout=${rch_timeout_seconds}s)"
    else
      failed_command="${command_text} (rch-exit=${run_status})"
    fi
    return 1
  fi

  if ! reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi
}

run_check() {
  run_step "cargo check -p frankenengine-engine --test release_checklist_gate" \
    cargo check -p frankenengine-engine --test release_checklist_gate
}

run_test() {
  run_step "cargo test -p frankenengine-engine --test release_checklist_gate" \
    cargo test -p frankenengine-engine --test release_checklist_gate
}

run_clippy() {
  run_step "cargo clippy -p frankenengine-engine --test release_checklist_gate -- -D warnings" \
    cargo clippy -p frankenengine-engine --test release_checklist_gate -- -D warnings
}

run_zero_placeholder_gate() {
  run_step "zero-placeholder gate security validation" \
    ./scripts/run_rgc_zero_placeholder_gate.sh ci
}

run_mode() {
  case "$mode" in
    check)
      run_check
      ;;
    test)
      run_test
      ;;
    clippy)
      run_clippy
      ;;
    zero-placeholder)
      run_zero_placeholder_gate
      ;;
    ci)
      run_check
      run_test
      run_clippy
      run_zero_placeholder_gate
      ;;
    *)
      echo "usage: $0 [check|test|clippy|zero-placeholder|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome git_commit dirty_worktree idx comma error_code_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
  else
    outcome="fail"
  fi

  if [[ -n "$failed_command" ]]; then
    error_code_json='"FE-RCHK-1005"'
  else
    error_code_json='null'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"${commands_path}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.release-checklist-gate.run-manifest.v1",'
    echo "  \"component\": \"${component}\","
    echo "  \"bead_id\": \"${bead_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"toolchain\": \"${toolchain_display}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"cargo_build_jobs\": ${cargo_build_jobs},"
    echo "  \"cargo_incremental\": ${cargo_incremental},"
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
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
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"command_log\": \"${commands_path}\","
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo '    "module": "crates/franken-engine/src/release_checklist_gate.rs",'
    echo '    "tests": "crates/franken-engine/tests/release_checklist_gate.rs",'
    echo '    "suite_script": "scripts/run_release_checklist_gate.sh",'
    echo '    "zero_placeholder_gate": "scripts/run_rgc_zero_placeholder_gate.sh",'
    echo '    "zero_placeholder_module": "crates/franken-engine/src/zero_placeholder_gate.rs"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"${manifest_path}"

  {
    echo "{\"trace_id\":\"trace-release-checklist-gate-${timestamp}\",\"decision_id\":\"decision-release-checklist-gate-${timestamp}\",\"policy_id\":\"policy-release-checklist-v1\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"${events_path}"

  echo "release checklist gate run manifest: ${manifest_path}"
  echo "release checklist gate events: ${events_path}"
}

trap 'write_manifest $?' EXIT
run_mode
