#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root="${RGC_REACT_DOCTOR_PREFLIGHT_ARTIFACT_ROOT:-artifacts/rgc_react_doctor_preflight}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-/data/projects/franken_engine/target_rch_rgc_react_doctor_preflight_${target_namespace}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
trace_ids_path="${run_dir}/trace_ids.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
support_contract_path="${run_dir}/react_doctor_support_contract.json"
support_repro_index_path="${run_dir}/react_support_repro_index.json"
contract_copy_path="${run_dir}/rgc_react_doctor_preflight_v1.json"
step_logs_dir="${run_dir}/step_logs"
first_step_log_path="${run_dir}/step_logs/step_000.log"

trace_id="trace-rgc-react-doctor-preflight-${timestamp}"
decision_id="decision-rgc-react-doctor-preflight-${timestamp}"
policy_id="policy-rgc-react-doctor-preflight-v1"
component="rgc_react_doctor_preflight_gate"
scenario_id="rgc-912b"
replay_command="./scripts/e2e/rgc_react_doctor_preflight_replay.sh ${mode}"

contract_doc="docs/RGC_REACT_DOCTOR_PREFLIGHT_V1.md"
contract_json="docs/rgc_react_doctor_preflight_v1.json"

mkdir -p "$run_dir" "$step_logs_dir"

if [[ ! -f "$contract_doc" || ! -f "$contract_json" ]]; then
  echo "FE-RGC-912B-CONTRACT-0001: missing react doctor/preflight contract inputs" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for react doctor/preflight contract validation" >&2
  exit 2
fi

if ! jq -e '.' "$contract_json" >/dev/null 2>&1; then
  echo "FE-RGC-912B-CONTRACT-0002: failed to parse ${contract_json}" >&2
  exit 1
fi

contract_policy_id="$(jq -r '.policy_id // empty' "$contract_json" 2>/dev/null)"
if [[ -z "$contract_policy_id" ]]; then
  echo "FE-RGC-912B-CONTRACT-0003: missing policy_id in ${contract_json}" >&2
  exit 1
fi

if [[ "$contract_policy_id" != "$policy_id" ]]; then
  echo "FE-RGC-912B-CONTRACT-0004: ${contract_json} policy_id '${contract_policy_id}' does not match runner policy_id '${policy_id}'" >&2
  exit 1
fi

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC React doctor/preflight heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_TERM_COLOR=never" \
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
  if rch_strip_ansi "$log_path" | rg -q 'Remote command finished: exit=[0-9]+'; then
    return 0
  fi
  return 1
}

declare -a commands_run=()
failed_command=""
manifest_written=false
step_log_index=0

run_step() {
  local command_text="$1"
  local expected_remote_exit="$2"
  local log_path status remote_exit_code
  shift 2

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
      failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      return 1
    fi

    if ! rch_recovered_success "$log_path"; then
      remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
      if [[ -n "${remote_exit_code}" ]]; then
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
  if [[ -z "${remote_exit_code}" ]]; then
    failed_command="${command_text} (missing-remote-exit-marker)"
    return 1
  fi
  if [[ "${remote_exit_code}" != "${expected_remote_exit}" ]]; then
    failed_command="${command_text} (expected-remote-exit=${expected_remote_exit}; remote-exit=${remote_exit_code})"
    return 1
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step \
        "cargo check -p frankenengine-engine --test rgc_react_doctor_preflight --test react_doctor_preflight_integration --test react_doctor_preflight_enrichment_integration" \
        0 \
        cargo check -p frankenengine-engine --test rgc_react_doctor_preflight --test react_doctor_preflight_integration --test react_doctor_preflight_enrichment_integration
      ;;
    test)
      run_step \
        "cargo test -p frankenengine-engine --test rgc_react_doctor_preflight --test react_doctor_preflight_integration --test react_doctor_preflight_enrichment_integration" \
        0 \
        cargo test -p frankenengine-engine --test rgc_react_doctor_preflight --test react_doctor_preflight_integration --test react_doctor_preflight_enrichment_integration
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --test rgc_react_doctor_preflight --test react_doctor_preflight_integration --test react_doctor_preflight_enrichment_integration -- -D warnings" \
        0 \
        cargo clippy -p frankenengine-engine --test rgc_react_doctor_preflight --test react_doctor_preflight_integration --test react_doctor_preflight_enrichment_integration -- -D warnings
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-engine --test rgc_react_doctor_preflight --test react_doctor_preflight_integration --test react_doctor_preflight_enrichment_integration" \
        0 \
        cargo check -p frankenengine-engine --test rgc_react_doctor_preflight --test react_doctor_preflight_integration --test react_doctor_preflight_enrichment_integration
      run_step \
        "cargo test -p frankenengine-engine --test rgc_react_doctor_preflight --test react_doctor_preflight_integration --test react_doctor_preflight_enrichment_integration" \
        0 \
        cargo test -p frankenengine-engine --test rgc_react_doctor_preflight --test react_doctor_preflight_integration --test react_doctor_preflight_enrichment_integration
      run_step \
        "cargo clippy -p frankenengine-engine --test rgc_react_doctor_preflight --test react_doctor_preflight_integration --test react_doctor_preflight_enrichment_integration -- -D warnings" \
        0 \
        cargo clippy -p frankenengine-engine --test rgc_react_doctor_preflight --test react_doctor_preflight_integration --test react_doctor_preflight_enrichment_integration -- -D warnings
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
  "schema_version": "franken-engine.rgc-react-doctor-preflight.trace-ids.v1",
  "bead_id": "bd-1lsy.10.12.2",
  "component": "${component}",
  "policy_id": "${policy_id}",
  "trace_ids": ["${trace_id}"],
  "decision_ids": ["${decision_id}"]
}
EOF_TRACE
}

write_support_contract_artifact() {
  cat >"${support_contract_path}" <<EOF_CONTRACT
{
  "schema_version": "franken-engine.react-doctor-support-contract.v1",
  "bead_id": "bd-1lsy.10.12.2",
  "policy_id": "RGC-912B",
  "component": "react_doctor_preflight",
  "generated_at_utc": "${timestamp}",
  "passed": false,
  "entries_analyzed": 3,
  "blocker_count": 2,
  "advisory_count": 1,
  "guidance_count": 3,
  "support_bundle_categories": [
    "category_breakdown",
    "doctor_checks",
    "guidance",
    "severity_breakdown"
  ],
  "dependency_routes": [
    {
      "bead_id": "bd-1lsy.9.7.3",
      "policy_id": "RGC-807C",
      "component": "react_mismatch_catalog"
    },
    {
      "bead_id": "bd-1lsy.5.7.3",
      "policy_id": "RGC-405C",
      "component": "minimized_repro_extraction"
    }
  ],
  "operator_surfaces": [
    "react_doctor_support_contract.json",
    "react_support_repro_index.json"
  ]
}
EOF_CONTRACT
}

write_support_repro_index_artifact() {
  cat >"${support_repro_index_path}" <<EOF_REPRO
{
  "schema_version": "franken-engine.react-support-repro-index.v1",
  "bead_id": "bd-1lsy.10.12.2",
  "policy_id": "RGC-912B",
  "component": "react_doctor_preflight",
  "generated_at_utc": "${timestamp}",
  "upstream_catalog_bead_id": "bd-1lsy.9.7.3",
  "upstream_repro_bead_id": "bd-1lsy.5.7.3",
  "entries": [
    {
      "mismatch_entry_id": "ssr-config-error",
      "domain": "server_side_render",
      "severity": "error",
      "target": "nodejs",
      "owner_route": "react_integration",
      "owner_route_bead": "bd-1lsy.5.7.3",
      "triage_severity": "error",
      "repro_input_id": "react-hydration-repro",
      "repro_hash": "repro-react-hydration-repro",
      "repro_command": "frankenctl react doctor --input fixtures/react_hydration_mismatch.json --json",
      "recommended_action": "Route to the React integration lane and preserve the minimized fixture",
      "source_reproduction": "fixtures/ssr-config-error.json"
    }
  ]
}
EOF_REPRO
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
    error_code_json='"FE-RGC-912B-GATE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if [[ -n "$(git status --short 2>/dev/null)" ]]; then
    dirty_worktree=true
  else
    dirty_worktree=false
  fi

  printf '%s\n' "${commands_run[@]}" >"${commands_path}"

  {
    echo "{\"schema_version\":\"franken-engine.rgc-react-doctor-preflight.event.v1\",\"scenario_id\":\"${scenario_id}\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"runtime_lane\":\"support_preflight\",\"seed\":\"fixed-react-doctor-preflight-seed-v1\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"${events_path}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-react-doctor-preflight.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.10.12.2",'
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
    echo "    \"trace_ids\": \"${trace_ids_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"react_doctor_support_contract\": \"${support_contract_path}\","
    echo "    \"react_support_repro_index\": \"${support_repro_index_path}\","
    echo "    \"contract_json\": \"${contract_copy_path}\","
    echo "    \"step_logs_dir\": \"${step_logs_dir}\","
    echo "    \"first_step_log\": \"${first_step_log_path}\","
    echo '    "doc_path": "docs/RGC_REACT_DOCTOR_PREFLIGHT_V1.md",'
    echo '    "test_path": "crates/franken-engine/tests/rgc_react_doctor_preflight.rs"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${trace_ids_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${support_contract_path}\","
    echo "    \"cat ${support_repro_index_path}\","
    echo "    \"cat ${contract_copy_path}\","
    echo "    \"cat ${first_step_log_path}\""
    echo '  ]'
    echo "}"
  } >"${manifest_path}"
}

write_trace_ids
cp "${contract_json}" "${contract_copy_path}"
write_support_contract_artifact
write_support_repro_index_artifact

set +e
run_mode
exit_code=$?
set -e

write_manifest "${exit_code}"

echo "rgc react doctor preflight manifest: ${manifest_path}"
echo "rgc react doctor preflight support contract: ${support_contract_path}"
echo "rgc react doctor preflight repro index: ${support_repro_index_path}"

exit "${exit_code}"
