#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target/rch/frx_local_semantic_atlas}"
artifact_root="${FRX_LOCAL_SEMANTIC_ATLAS_ARTIFACT_ROOT:-artifacts/frx_local_semantic_atlas}"
rch_timeout_seconds="${RCH_TIMEOUT_SECONDS:-1800}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

trace_id="trace-frx-local-semantic-atlas-${timestamp}"
decision_id="decision-frx-local-semantic-atlas-${timestamp}"
policy_id="policy-frx-local-semantic-atlas-v1"
component="frx_local_semantic_atlas_gate"
scenario_id="frx-14.1"
replay_command="${0} ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for FRX local semantic atlas suite commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    env -u CARGO_ENCODED_RUSTFLAGS \
    rch exec -q -- env -u CARGO_ENCODED_RUSTFLAGS \
    "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  shift
  commands_run+=("$command_text")
  echo "==> $command_text"
  if ! run_rch "$@"; then
    if [[ -z "$failed_command" ]]; then
      failed_command="$command_text"
    fi
    return 1
  fi
}

run_mode() {
  local mode_exit=0
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test local_semantic_atlas_integration" \
        cargo check -p frankenengine-engine --test local_semantic_atlas_integration || mode_exit=1
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --lib local_semantic_atlas" \
        cargo test -p frankenengine-engine --lib local_semantic_atlas || mode_exit=1
      run_step "cargo test -p frankenengine-engine --test local_semantic_atlas_integration" \
        cargo test -p frankenengine-engine --test local_semantic_atlas_integration || mode_exit=1
      ;;
    clippy)
      run_step "env -u CARGO_ENCODED_RUSTFLAGS RUSTC_WORKSPACE_WRAPPER=clippy-driver RUSTFLAGS='-Dwarnings -Clinker-features=-lld' cargo test -p frankenengine-engine --test local_semantic_atlas_integration --no-run" \
        env -u CARGO_ENCODED_RUSTFLAGS RUSTC_WORKSPACE_WRAPPER=clippy-driver RUSTFLAGS='-Dwarnings -Clinker-features=-lld' \
        cargo test -p frankenengine-engine --test local_semantic_atlas_integration --no-run || mode_exit=1
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test local_semantic_atlas_integration" \
        cargo check -p frankenengine-engine --test local_semantic_atlas_integration || mode_exit=1
      run_step "cargo test -p frankenengine-engine --lib local_semantic_atlas" \
        cargo test -p frankenengine-engine --lib local_semantic_atlas || mode_exit=1
      run_step "cargo test -p frankenengine-engine --test local_semantic_atlas_integration" \
        cargo test -p frankenengine-engine --test local_semantic_atlas_integration || mode_exit=1
      run_step "env -u CARGO_ENCODED_RUSTFLAGS RUSTC_WORKSPACE_WRAPPER=clippy-driver RUSTFLAGS='-Dwarnings -Clinker-features=-lld' cargo test -p frankenengine-engine --test local_semantic_atlas_integration --no-run" \
        env -u CARGO_ENCODED_RUSTFLAGS RUSTC_WORKSPACE_WRAPPER=clippy-driver RUSTFLAGS='-Dwarnings -Clinker-features=-lld' \
        cargo test -p frankenengine-engine --test local_semantic_atlas_integration --no-run || mode_exit=1
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
  return "$mode_exit"
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
    error_code_json='"FE-FRX-14-1-GATE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"frx.local-semantic-atlas.gate.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "frx.local-semantic-atlas.gate.run-manifest.v1",'
    echo '  "bead_id": "bd-mjh3.14.1",'
    echo "  \"component\": \"${component}\"," 
    echo "  \"scenario_id\": \"${scenario_id}\"," 
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"toolchain\": \"${toolchain}\"," 
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
      echo "  \"failed_command\": \"${failed_command}\"," 
    fi
    echo "  \"replay_command\": \"${replay_command}\"," 
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
    echo '    "contract_doc": "docs/FRX_LOCAL_SEMANTIC_ATLAS_V1.md",'
    echo '    "contract_json": "docs/frx_local_semantic_atlas_v1.json",'
    echo '    "gate_test": "crates/franken-engine/tests/local_semantic_atlas_integration.rs"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "frx local semantic atlas manifest: ${manifest_path}"
  echo "frx local semantic atlas events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"
exit "$main_exit"
