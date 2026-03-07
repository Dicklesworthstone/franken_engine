#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

mode="ci"
mode_explicit=false
scenario_filter=""
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
artifact_root="${RGC_V8_SUPREMACY_CLAIM_ARTIFACT_ROOT:-artifacts/rgc_v8_supremacy_claim_contract}"
contract_version="0.1.0"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
supremacy_contract_path="${run_dir}/supremacy_claim_contract.json"
language_contract_path="${run_dir}/published_language_contract.json"
fixture_path="crates/franken-engine/tests/fixtures/rgc_v8_supremacy_claim_contract_v1.json"

run_id="rgc-v8-supremacy-claim-contract-${timestamp}"
trace_id="trace-rgc-v8-supremacy-claim-${timestamp}"
decision_id="decision-rgc-v8-supremacy-claim-${timestamp}"
policy_id="policy-rgc-v8-supremacy-claim-v1"
component="rgc_v8_supremacy_claim_contract"
artifact_bundle_id="rgc_v8_supremacy_claim_contract_v1"

usage() {
  echo "usage: $0 [check|test|clippy|ci] [--scenario <scenario_id>]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    check|test|clippy|ci)
      if [[ "$mode_explicit" == true ]]; then
        echo "mode already set to '${mode}'" >&2
        usage
        exit 2
      fi
      mode="$1"
      mode_explicit=true
      shift
      ;;
    --scenario)
      if [[ $# -lt 2 || -z "${2}" ]]; then
        echo "--scenario requires a non-empty scenario id" >&2
        usage
        exit 2
      fi
      scenario_filter="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -n "$scenario_filter" ]]; then
  case "$scenario_filter" in
    *[!a-zA-Z0-9_]*)
      echo "scenario id must be alphanumeric/underscore only: ${scenario_filter}" >&2
      exit 2
      ;;
  esac
  if ! jq -e --arg scenario_id "$scenario_filter" \
    '.publication_scenarios[] | select(.scenario_id == $scenario_id)' \
    "$fixture_path" >/dev/null; then
    echo "unknown scenario id: ${scenario_filter}" >&2
    exit 2
  fi
fi

replay_command="${0} ${mode}"
if [[ -n "$scenario_filter" ]]; then
  replay_command+=" --scenario ${scenario_filter}"
fi

target_namespace="${mode}_${scenario_filter:-suite}_$$"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_rgc_v8_supremacy_claim_contract_${target_namespace}}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for V8 supremacy claim contract heavy commands" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to materialize contract artifacts" >&2
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
  local fallback_flag log_path stream_path monitor_pid rch_pid status
  shift
  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="$(mktemp)"
  fallback_flag="$(mktemp)"
  stream_path="$(mktemp -u)"
  mkfifo "$stream_path"

  run_rch "$@" >"$stream_path" 2>&1 &
  rch_pid=$!
  {
    while IFS= read -r line; do
      printf '%s\n' "$line"
      printf '%s\n' "$line" >>"$log_path"
      if grep -Eiq 'falling back to local|fallback to local|local fallback' <<<"$line"; then
        printf 'fallback-detected\n' >"$fallback_flag"
        kill "$rch_pid" 2>/dev/null || true
      fi
    done <"$stream_path"
  } &
  monitor_pid=$!

  wait "$rch_pid"
  status=$?
  wait "$monitor_pid" || true

  rm -f "$stream_path"
  if [[ "$status" -ne 0 ]]; then
    rm -f "$log_path"
    rm -f "$fallback_flag"
    failed_command="$command_text"
    return 1
  fi
  if [[ -s "$fallback_flag" ]] || ! rch_reject_local_fallback "$log_path"; then
    rm -f "$fallback_flag"
    rm -f "$log_path"
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi
  rm -f "$fallback_flag"
  rm -f "$log_path"
}

run_mode() {
  local scenario_test_name=""
  if [[ -n "$scenario_filter" ]]; then
    scenario_test_name="publication_scenario_${scenario_filter}"
  fi

  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test rgc_v8_supremacy_claim_contract" \
        cargo check -p frankenengine-engine --test rgc_v8_supremacy_claim_contract
      ;;
    test)
      if [[ -n "$scenario_test_name" ]]; then
        run_step "cargo test -p frankenengine-engine --test rgc_v8_supremacy_claim_contract ${scenario_test_name} -- --exact" \
          cargo test -p frankenengine-engine --test rgc_v8_supremacy_claim_contract "${scenario_test_name}" -- --exact
      else
        run_step "cargo test -p frankenengine-engine --test rgc_v8_supremacy_claim_contract" \
          cargo test -p frankenengine-engine --test rgc_v8_supremacy_claim_contract
      fi
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test rgc_v8_supremacy_claim_contract -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_v8_supremacy_claim_contract -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test rgc_v8_supremacy_claim_contract" \
        cargo check -p frankenengine-engine --test rgc_v8_supremacy_claim_contract
      if [[ -n "$scenario_test_name" ]]; then
        run_step "cargo test -p frankenengine-engine --test rgc_v8_supremacy_claim_contract ${scenario_test_name} -- --exact" \
          cargo test -p frankenengine-engine --test rgc_v8_supremacy_claim_contract "${scenario_test_name}" -- --exact
      else
        run_step "cargo test -p frankenengine-engine --test rgc_v8_supremacy_claim_contract" \
          cargo test -p frankenengine-engine --test rgc_v8_supremacy_claim_contract
      fi
      run_step "cargo clippy -p frankenengine-engine --test rgc_v8_supremacy_claim_contract -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_v8_supremacy_claim_contract -- -D warnings
      ;;
    *)
      usage
      exit 2
      ;;
  esac
}

write_contract_artifacts() {
  jq '.supremacy_claim_contract' "$fixture_path" >"$supremacy_contract_path"
  jq '.published_language_contract' "$fixture_path" >"$language_contract_path"
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
    error_code_json='"FE-RGC-V8-SUPREMACY-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if [[ -z "$(git status --short --untracked-files=normal 2>/dev/null)" ]]; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  write_contract_artifacts

  {
    echo "{\"schema_version\":\"franken-engine.rgc-v8-supremacy-claim.log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json},\"run_id\":\"${run_id}\",\"contract_version\":\"${contract_version}\",\"artifact_bundle_id\":\"${artifact_bundle_id}\",\"replay_command\":\"${replay_command}\"}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-v8-supremacy-claim.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.1.6.2",'
    echo "  \"contract_version\": \"${contract_version}\","
    echo "  \"component\": \"${component}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"cargo_build_jobs\": \"${cargo_build_jobs}\","
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
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"supremacy_claim_contract\": \"${supremacy_contract_path}\","
    echo "    \"published_language_contract\": \"${language_contract_path}\","
    echo '    "contract_doc": "docs/RGC_V8_SUPREMACY_CLAIM_CONTRACT_V1.md",'
    echo '    "contract_fixture": "crates/franken-engine/tests/fixtures/rgc_v8_supremacy_claim_contract_v1.json",'
    echo '    "contract_tests": "crates/franken-engine/tests/rgc_v8_supremacy_claim_contract.rs"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${supremacy_contract_path}\","
    echo "    \"cat ${language_contract_path}\","
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "RGC V8 supremacy contract manifest: ${manifest_path}"
  echo "RGC V8 supremacy contract events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"

exit "$main_exit"
