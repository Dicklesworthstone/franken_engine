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
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_rgc_v8_supremacy_claim_contract}"
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
replay_command="${0} ${mode}"

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
  rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
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
      run_step "cargo check -p frankenengine-engine --test rgc_v8_supremacy_claim_contract" \
        cargo check -p frankenengine-engine --test rgc_v8_supremacy_claim_contract
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test rgc_v8_supremacy_claim_contract" \
        cargo test -p frankenengine-engine --test rgc_v8_supremacy_claim_contract
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test rgc_v8_supremacy_claim_contract -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_v8_supremacy_claim_contract -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test rgc_v8_supremacy_claim_contract" \
        cargo check -p frankenengine-engine --test rgc_v8_supremacy_claim_contract
      run_step "cargo test -p frankenengine-engine --test rgc_v8_supremacy_claim_contract" \
        cargo test -p frankenengine-engine --test rgc_v8_supremacy_claim_contract
      run_step "cargo clippy -p frankenengine-engine --test rgc_v8_supremacy_claim_contract -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_v8_supremacy_claim_contract -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
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
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
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
