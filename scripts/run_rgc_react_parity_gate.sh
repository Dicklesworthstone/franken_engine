#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
artifact_root="${RGC_REACT_PARITY_GATE_ARTIFACT_ROOT:-artifacts/rgc_react_parity_gate}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_rgc_react_parity_gate_${target_namespace}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
index_path="${run_dir}/react_parity_gate_index.json"
compile_report_path="${run_dir}/react_compile_parity_report.json"
ssr_report_path="${run_dir}/react_ssr_client_parity_report.json"
mismatch_catalog_path="${run_dir}/react_mismatch_catalog.json"
copied_contract_path="${run_dir}/rgc_react_parity_gate_v1.json"
step_logs_dir="${run_dir}/step_logs"

contract_doc="docs/RGC_REACT_PARITY_GATE_V1.md"
contract_json="docs/rgc_react_parity_gate_v1.json"

trace_id="trace-rgc-react-parity-gate-${timestamp}"
decision_id="decision-rgc-react-parity-gate-${timestamp}"
policy_id="RGC-807"
component="rgc_react_parity_gate"
scenario_id="rgc-807"
replay_command="./scripts/e2e/rgc_react_parity_gate_replay.sh ${mode}"

mkdir -p "$run_dir" "$step_logs_dir"

if [[ ! -f "$contract_doc" ]]; then
  echo "FE-RGC-807-CONTRACT-0001: missing contract doc (${contract_doc})" >&2
  exit 1
fi

if [[ ! -f "$contract_json" ]]; then
  echo "FE-RGC-807-CONTRACT-0002: missing contract JSON (${contract_json})" >&2
  exit 1
fi

if ! jq -e '.' "$contract_json" >/dev/null 2>&1; then
  echo "FE-RGC-807-CONTRACT-0003: failed to parse contract JSON (${contract_json})" >&2
  exit 1
fi

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC React parity gate heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "$@"
}

rch_strip_ansi() {
  sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g' "$1"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n1 || true)"
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
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_recovered_success() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | rg -q 'Remote command finished: exit=0|Finished.*profile|test result: ok\.' \
    && ! rch_strip_ansi "$log_path" | rg -qi 'error(\[[[:alnum:]]+\])?:'; then
    return 0
  fi
  return 1
}

declare -a commands_run=()
declare -a validation_errors=()
failed_command=""
manifest_written=false
step_log_index=0

run_step() {
  local command_text="$1"
  local log_path status remote_exit_code
  shift

  commands_run+=("${command_text}")
  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  step_log_index=$((step_log_index + 1))

  echo "==> ${command_text}"

  set +e
  run_rch "$@" > >(tee "$log_path") 2>&1
  status=$?
  set -e

  if [[ "${status}" -ne 0 ]]; then
    if [[ "${status}" -eq 124 ]]; then
      echo "==> failure: rch command timed out after ${rch_timeout_seconds}s" | tee -a "$log_path"
      failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      return 1
    fi

    if rch_recovered_success "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
      if [[ -n "$remote_exit_code" ]]; then
        failed_command="${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})"
      else
        failed_command="${command_text} (rch-exit=${status}; missing-remote-exit-marker)"
      fi
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -z "$remote_exit_code" ]]; then
    failed_command="${command_text} (rch-exit=${status}; missing-remote-exit-marker)"
    return 1
  fi
  if [[ "$remote_exit_code" != "0" ]]; then
    failed_command="${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})"
    return 1
  fi
}

copy_contract_artifacts() {
  commands_run+=("cp ${contract_json} ${copied_contract_path}")
  cp "$contract_json" "$copied_contract_path"
}

validate_contract_inputs() {
  commands_run+=("jq empty ${contract_json}")
  validation_errors=()

  if ! jq -e '.schema_version == "franken-engine.rgc-react-parity-gate.v1"' "$contract_json" >/dev/null; then
    validation_errors+=("unexpected schema_version in ${contract_json}")
  fi

  if ! jq -e '.bead_id == "bd-1lsy.9.7"' "$contract_json" >/dev/null; then
    validation_errors+=("unexpected bead_id in ${contract_json}")
  fi

  if ! jq -e '.gate_runner.script == "scripts/run_rgc_react_parity_gate.sh"' "$contract_json" >/dev/null; then
    validation_errors+=("gate_runner.script drift in ${contract_json}")
  fi

  if ! jq -e '.gate_runner.replay_wrapper == "scripts/e2e/rgc_react_parity_gate_replay.sh"' "$contract_json" >/dev/null; then
    validation_errors+=("gate_runner.replay_wrapper drift in ${contract_json}")
  fi

  if ! jq -e '.child_beads | length == 3' "$contract_json" >/dev/null; then
    validation_errors+=("expected three child_beads in ${contract_json}")
  fi

  if (( ${#validation_errors[@]} != 0 )); then
    printf 'FE-RGC-807-CONTRACT-0099: %s\n' "${validation_errors[@]}" >&2
    return 1
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step \
        "cargo check -p frankenengine-engine --test react_compile_verification_integration --test react_ssr_verification_integration --test react_mismatch_catalog_integration --test rgc_react_parity_gate" \
        cargo check -p frankenengine-engine --test react_compile_verification_integration --test react_ssr_verification_integration --test react_mismatch_catalog_integration --test rgc_react_parity_gate \
        || return 1
      ;;
    test)
      run_step \
        "cargo test -p frankenengine-engine --test react_compile_verification_integration --test react_ssr_verification_integration --test react_mismatch_catalog_integration --test rgc_react_parity_gate" \
        cargo test -p frankenengine-engine --test react_compile_verification_integration --test react_ssr_verification_integration --test react_mismatch_catalog_integration --test rgc_react_parity_gate \
        || return 1
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --test react_compile_verification_integration --test react_ssr_verification_integration --test react_mismatch_catalog_integration --test rgc_react_parity_gate -- -D warnings" \
        cargo clippy -p frankenengine-engine --test react_compile_verification_integration --test react_ssr_verification_integration --test react_mismatch_catalog_integration --test rgc_react_parity_gate -- -D warnings \
        || return 1
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-engine --test react_compile_verification_integration --test react_ssr_verification_integration --test react_mismatch_catalog_integration --test rgc_react_parity_gate" \
        cargo check -p frankenengine-engine --test react_compile_verification_integration --test react_ssr_verification_integration --test react_mismatch_catalog_integration --test rgc_react_parity_gate \
        || return 1
      run_step \
        "cargo test -p frankenengine-engine --test react_compile_verification_integration --test react_ssr_verification_integration --test react_mismatch_catalog_integration --test rgc_react_parity_gate" \
        cargo test -p frankenengine-engine --test react_compile_verification_integration --test react_ssr_verification_integration --test react_mismatch_catalog_integration --test rgc_react_parity_gate \
        || return 1
      run_step \
        "cargo clippy -p frankenengine-engine --test react_compile_verification_integration --test react_ssr_verification_integration --test react_mismatch_catalog_integration --test rgc_react_parity_gate -- -D warnings" \
        cargo clippy -p frankenengine-engine --test react_compile_verification_integration --test react_ssr_verification_integration --test react_mismatch_catalog_integration --test rgc_react_parity_gate -- -D warnings \
        || return 1
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_trace_ids() {
  cat >"${trace_ids_path}" <<EOF_TRACE
{
  "schema_version": "franken-engine.rgc-react-parity-gate.trace-ids.v1",
  "bead_id": "bd-1lsy.9.7",
  "component": "${component}",
  "policy_id": "${policy_id}",
  "trace_ids": ["${trace_id}"],
  "decision_ids": ["${decision_id}"]
}
EOF_TRACE
}

write_report_artifacts() {
  local outcome="$1"

  cat >"${compile_report_path}" <<EOF_COMPILE
{
  "schema_version": "franken-engine.react-compile-parity-report.v1",
  "bead_id": "bd-1lsy.9.7.1",
  "policy_id": "RGC-807A",
  "component": "react_compile_verification",
  "gate_bead_id": "bd-1lsy.9.7",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "owner_route_bead": "bd-1lsy.9.7.1",
  "supporting_tests": [
    "react_compile_verification_integration",
    "rgc_react_parity_gate"
  ],
  "artifact_expectations": [
    "compiled_output",
    "source_map",
    "diagnostics",
    "bundle_manifest"
  ],
  "outcome": "${outcome}"
}
EOF_COMPILE

  cat >"${ssr_report_path}" <<EOF_SSR
{
  "schema_version": "franken-engine.react-ssr-client-parity-report.v1",
  "bead_id": "bd-1lsy.9.7.2",
  "policy_id": "RGC-807B",
  "component": "react_ssr_verification",
  "gate_bead_id": "bd-1lsy.9.7",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "owner_route_bead": "bd-1lsy.9.7.2",
  "supporting_tests": [
    "react_ssr_verification_integration",
    "rgc_react_parity_gate"
  ],
  "execution_kinds": [
    "ssr",
    "client_entry",
    "hydration",
    "static_generation",
    "streaming_ssr"
  ],
  "outcome": "${outcome}"
}
EOF_SSR

  cat >"${mismatch_catalog_path}" <<EOF_MISMATCH
{
  "schema_version": "franken-engine.react-mismatch-catalog-report.v1",
  "bead_id": "bd-1lsy.9.7.3",
  "policy_id": "RGC-807C",
  "component": "react_mismatch_catalog",
  "gate_bead_id": "bd-1lsy.9.7",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "owner_route_bead": "bd-1lsy.9.7.3",
  "supporting_tests": [
    "react_mismatch_catalog_integration",
    "rgc_react_parity_gate"
  ],
  "downstream_consumers": [
    "docs",
    "advisories",
    "benchmarks"
  ],
  "outcome": "${outcome}"
}
EOF_MISMATCH

  cat >"${index_path}" <<EOF_INDEX
{
  "schema_version": "franken-engine.react-parity-gate.index.v1",
  "bead_id": "bd-1lsy.9.7",
  "policy_id": "${policy_id}",
  "component": "${component}",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "contract_path": "${copied_contract_path}",
  "reports": [
    {
      "report_id": "react_compile_parity",
      "artifact_path": "${compile_report_path}",
      "bead_id": "bd-1lsy.9.7.1",
      "policy_id": "RGC-807A",
      "owner_route_bead": "bd-1lsy.9.7.1"
    },
    {
      "report_id": "react_ssr_client_parity",
      "artifact_path": "${ssr_report_path}",
      "bead_id": "bd-1lsy.9.7.2",
      "policy_id": "RGC-807B",
      "owner_route_bead": "bd-1lsy.9.7.2"
    },
    {
      "report_id": "react_mismatch_catalog",
      "artifact_path": "${mismatch_catalog_path}",
      "bead_id": "bd-1lsy.9.7.3",
      "policy_id": "RGC-807C",
      "owner_route_bead": "bd-1lsy.9.7.3"
    }
  ],
  "supporting_tests": [
    "react_compile_verification_integration",
    "react_ssr_verification_integration",
    "react_mismatch_catalog_integration",
    "rgc_react_parity_gate"
  ],
  "outcome": "${outcome}"
}
EOF_INDEX
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma
  local contract_operator_verification_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-807-GATE-0001"'
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  write_trace_ids
  write_report_artifacts "$outcome"
  contract_operator_verification_json="$(jq '.operator_verification' "$contract_json")"

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if [[ -z "$(git status --short --untracked-files=normal 2>/dev/null)" ]]; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  {
    echo "{\"schema_version\":\"franken-engine.rgc-react-parity-gate.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"runtime_lane\":\"react_parity_gate\",\"seed\":\"fixed-react-parity-gate-seed-v1\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json},\"replay_command\":\"${replay_command}\"}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-react-parity-gate.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.9.7",'
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
    echo '  "operator_verification": '"${contract_operator_verification_json}"','
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"trace_ids\": \"${trace_ids_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"react_parity_gate_index\": \"${index_path}\","
    echo "    \"react_compile_parity_report\": \"${compile_report_path}\","
    echo "    \"react_ssr_client_parity_report\": \"${ssr_report_path}\","
    echo "    \"react_mismatch_catalog\": \"${mismatch_catalog_path}\","
    echo "    \"contract_json\": \"${copied_contract_path}\","
    echo "    \"first_step_log\": \"${step_logs_dir}/step_000.log\""
    echo '  }'
    echo "}"
  } >"$manifest_path"

  echo "rgc react parity gate manifest: ${manifest_path}"
  echo "rgc react parity gate index: ${index_path}"
}

main_exit=0
copy_contract_artifacts || main_exit=$?
if [[ "$main_exit" -eq 0 ]]; then
  validate_contract_inputs || main_exit=$?
fi
if [[ "$main_exit" -eq 0 ]]; then
  run_mode || main_exit=$?
fi
write_manifest "$main_exit"
exit "$main_exit"
