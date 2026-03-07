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
artifact_root="${RGC_CLAIM_ENVELOPE_CONTRACT_ARTIFACT_ROOT:-artifacts/rgc_claim_envelope_contract}"
contract_version="0.1.0"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
contract_path="${run_dir}/claim_envelope_contract.json"
fixture_path="crates/franken-engine/tests/fixtures/rgc_claim_envelope_contract_v1.json"

run_id="rgc-claim-envelope-contract-${timestamp}"
trace_id="trace-rgc-claim-envelope-${timestamp}"
decision_id="decision-rgc-claim-envelope-${timestamp}"
policy_id="policy-rgc-claim-envelope-contract-v1"
component="rgc_claim_envelope_contract"
artifact_bundle_id="rgc_claim_envelope_contract_v1"

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

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for claim-envelope heavy commands" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to materialize claim-envelope artifacts" >&2
  exit 2
fi

if ! command -v setsid >/dev/null 2>&1; then
  echo "setsid is required to fail closed on rch local fallback" >&2
  exit 2
fi

replay_command="${0} ${mode}"
if [[ -n "$scenario_filter" ]]; then
  replay_command+=" --scenario ${scenario_filter}"
fi

target_namespace="${mode}_${scenario_filter:-suite}_$$"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_rgc_claim_envelope_contract_${target_namespace}}"

mkdir -p "$run_dir"

reject_local_fallback() {
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

  setsid rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "$@" >"$stream_path" 2>&1 &
  rch_pid=$!
  {
    while IFS= read -r line; do
      printf '%s\n' "$line"
      printf '%s\n' "$line" >>"$log_path"
      if grep -Eiq 'falling back to local|fallback to local|local fallback' <<<"$line"; then
        printf 'fallback-detected\n' >"$fallback_flag"
        kill -TERM -- "-$rch_pid" 2>/dev/null || true
        sleep 1
        kill -KILL -- "-$rch_pid" 2>/dev/null || true
      fi
    done <"$stream_path"
  } &
  monitor_pid=$!

  wait "$rch_pid"
  status=$?
  wait "$monitor_pid" || true

  rm -f "$stream_path"
  if [[ "$status" -ne 0 ]]; then
    rm -f "$log_path" "$fallback_flag"
    failed_command="$command_text"
    return 1
  fi
  if [[ -s "$fallback_flag" ]] || ! reject_local_fallback "$log_path"; then
    rm -f "$log_path" "$fallback_flag"
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi
  rm -f "$log_path" "$fallback_flag"
}

run_mode() {
  local scenario_test_name=""
  if [[ -n "$scenario_filter" ]]; then
    scenario_test_name="publication_scenario_${scenario_filter}"
  fi

  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test rgc_claim_envelope_contract" \
        cargo check -p frankenengine-engine --test rgc_claim_envelope_contract || return 1
      ;;
    test)
      if [[ -n "$scenario_test_name" ]]; then
        run_step "cargo test -p frankenengine-engine --test rgc_claim_envelope_contract ${scenario_test_name} -- --exact" \
          cargo test -p frankenengine-engine --test rgc_claim_envelope_contract "${scenario_test_name}" -- --exact || return 1
      else
        run_step "cargo test -p frankenengine-engine --test rgc_claim_envelope_contract" \
          cargo test -p frankenengine-engine --test rgc_claim_envelope_contract || return 1
      fi
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test rgc_claim_envelope_contract -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_claim_envelope_contract -- -D warnings || return 1
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test rgc_claim_envelope_contract" \
        cargo check -p frankenengine-engine --test rgc_claim_envelope_contract || return 1
      if [[ -n "$scenario_test_name" ]]; then
        run_step "cargo test -p frankenengine-engine --test rgc_claim_envelope_contract ${scenario_test_name} -- --exact" \
          cargo test -p frankenengine-engine --test rgc_claim_envelope_contract "${scenario_test_name}" -- --exact || return 1
      else
        run_step "cargo test -p frankenengine-engine --test rgc_claim_envelope_contract" \
          cargo test -p frankenengine-engine --test rgc_claim_envelope_contract || return 1
      fi
      run_step "cargo clippy -p frankenengine-engine --test rgc_claim_envelope_contract -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_claim_envelope_contract -- -D warnings || return 1
      ;;
    *)
      usage
      exit 2
      ;;
  esac
}

write_contract_artifacts() {
  jq '.claim_envelope_contract' "$fixture_path" >"$contract_path"
  cat >"$trace_ids_path" <<JSON
{"run_id":"${run_id}","trace_id":"${trace_id}","decision_id":"${decision_id}","policy_id":"${policy_id}"}
JSON
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
    error_code_json='"FE-RGC-016C-0001"'
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
    echo "{\"schema_version\":\"franken-engine.rgc-claim-envelope-contract.log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json},\"run_id\":\"${run_id}\",\"requested_class\":\"${scenario_filter:-suite}\",\"verdict\":\"${outcome}\",\"replay_command\":\"${replay_command}\"}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-claim-envelope-contract.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.1.6.3",'
    echo "  \"contract_version\": \"${contract_version}\","
    echo "  \"component\": \"${component}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"run_id\": \"${run_id}\","
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"replay_command\": \"${replay_command}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"failed_command\": $(if [[ -n "$failed_command" ]]; then printf '"%s"' "$failed_command"; else echo null; fi),"
    echo "  \"requested_scenario\": $(if [[ -n "$scenario_filter" ]]; then printf '"%s"' "$scenario_filter"; else echo null; fi),"
    echo '  "artifacts": {'
    echo "    \"claim_envelope_contract\": \"${contract_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"trace_ids\": \"${trace_ids_path}\""
    echo "  },"
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" -eq $((${#commands_run[@]} - 1)) ]]; then
        comma=""
      fi
      printf '    "%s"%s\n' "${commands_run[$idx]}" "$comma"
    done
    echo '  ]'
    echo "}"
  } >"$manifest_path"
}

finish() {
  local exit_code="$1"
  write_manifest "$exit_code"
  exit "$exit_code"
}

trap 'finish $?' EXIT

run_mode
