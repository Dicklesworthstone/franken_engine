#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
uid="$(id -u)"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_supremacy_cell_matrix_uid${uid}}"
artifact_root="${SUPREMACY_CELL_MATRIX_ARTIFACT_ROOT:-artifacts/supremacy_cell_matrix}"
contract_version="0.1.0"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
matrix_path="${run_dir}/supremacy_cell_matrix.json"
fixture_path="crates/franken-engine/tests/fixtures/supremacy_cell_matrix_v1.json"

run_id="supremacy-cell-matrix-${timestamp}"
trace_id="trace-supremacy-cell-matrix-${timestamp}"
decision_id="decision-supremacy-cell-matrix-${timestamp}"
policy_id="policy-supremacy-cell-matrix-v1"
component="supremacy_cell_matrix"
artifact_bundle_id="supremacy_cell_matrix_v1"
replay_command="${0} ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for supremacy cell matrix heavy commands" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to materialize supremacy cell matrix artifacts" >&2
  exit 2
fi

run_rch() {
  rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "$@"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'falling back to local|fallback to local|local fallback' "$log_path"; then
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
    rm -f "$log_path"
    failed_command="$command_text"
    return 1
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
      run_step "cargo check -p frankenengine-engine --test supremacy_cell_matrix" \
        cargo check -p frankenengine-engine --test supremacy_cell_matrix || return 1
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test supremacy_cell_matrix" \
        cargo test -p frankenengine-engine --test supremacy_cell_matrix || return 1
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test supremacy_cell_matrix -- -D warnings" \
        cargo clippy -p frankenengine-engine --test supremacy_cell_matrix -- -D warnings || return 1
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test supremacy_cell_matrix" \
        cargo check -p frankenengine-engine --test supremacy_cell_matrix || return 1
      run_step "cargo test -p frankenengine-engine --test supremacy_cell_matrix" \
        cargo test -p frankenengine-engine --test supremacy_cell_matrix || return 1
      run_step "cargo clippy -p frankenengine-engine --test supremacy_cell_matrix -- -D warnings" \
        cargo clippy -p frankenengine-engine --test supremacy_cell_matrix -- -D warnings || return 1
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_matrix_artifact() {
  jq '.' "$fixture_path" >"$matrix_path"
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
    error_code_json='"FE-SUPREMACY-CELL-MATRIX-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  write_matrix_artifact

  {
    echo "{\"schema_version\":\"franken-engine.supremacy-cell-matrix.log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json},\"run_id\":\"${run_id}\",\"contract_version\":\"${contract_version}\",\"artifact_bundle_id\":\"${artifact_bundle_id}\",\"replay_command\":\"${replay_command}\"}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.supremacy-cell-matrix.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.8.5.1",'
    echo "  \"contract_version\": \"${contract_version}\","
    echo "  \"component\": \"${component}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"run_id\": \"${run_id}\","
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"${timestamp}\","
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
    echo "  ],"
    echo '  "artifacts": {'
    echo "    \"supremacy_cell_matrix\": \"${matrix_path}\","
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo '    "contract_doc": "docs/RGC_SUPREMACY_CELL_MATRIX_V1.md",'
    echo '    "fixture": "crates/franken-engine/tests/fixtures/supremacy_cell_matrix_v1.json",'
    echo '    "tests": "crates/franken-engine/tests/supremacy_cell_matrix.rs"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${matrix_path}\","
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "supremacy cell matrix artifact: ${matrix_path}"
  echo "supremacy cell matrix manifest: ${manifest_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"

exit "$main_exit"
