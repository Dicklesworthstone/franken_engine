#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_extension_host_root_contract}"
artifact_root="${EXTENSION_HOST_ROOT_CONTRACT_ARTIFACT_ROOT:-artifacts/rgc_extension_host_root_contract}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
step_logs_dir="${run_dir}/step_logs"
manifest_path="${run_dir}/run_manifest.json"
trace_ids_path="${run_dir}/trace_ids.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
contract_artifact_path="${run_dir}/extension_host_root_contract.json"
validation_report_path="${run_dir}/extension_host_root_contract_validation_report.json"
surface_report_path="${run_dir}/extension_host_root_surface_report.json"
contract_source_json="docs/extension_host_root_contract_v1.json"

trace_id="trace-rgc-extension-host-root-contract-${timestamp}"
decision_id="decision-rgc-extension-host-root-contract-${timestamp}"
policy_id="policy-rgc-920b-extension-host-root-contract-v1"
component="rgc_extension_host_root_contract_gate"
scenario_id="rgc-920b"
replay_command="./scripts/e2e/rgc_extension_host_root_contract_replay.sh ${mode}"

if [[ "${run_dir}" = /* ]]; then
  run_dir_abs="${run_dir}"
else
  run_dir_abs="${root_dir}/${run_dir}"
fi

mkdir -p "${run_dir}" "${step_logs_dir}"

commands_run=()
failed_command=""
exit_code=0
step_index=0

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for extension-host root contract heavy commands" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for extension-host root contract artifact validation" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "EXTENSION_HOST_ROOT_CONTRACT_ARTIFACT_DIR=${run_dir_abs}" \
    "$@"
}

rch_strip_ansi() {
  sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g' "$1"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line

  remote_exit_line="$(rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n1 || true)"
  [[ -n "${remote_exit_line}" ]] || return 1
  printf '%s\n' "${remote_exit_line##*=}"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

run_step() {
  local command_text="$1"
  local log_path remote_exit_code status
  shift

  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_index}").log"
  step_index=$((step_index + 1))
  commands_run+=("${command_text}")
  echo "==> ${command_text}"

  set +e
  run_rch "$@" > >(tee "${log_path}") 2>&1
  status=$?
  set -e

  if ! rch_reject_local_fallback "${log_path}"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "${log_path}" || true)"
  if [[ "${status}" -ne 0 ]]; then
    if [[ -n "${remote_exit_code}" && "${remote_exit_code}" == "0" ]]; then
      echo "==> recovered: remote execution succeeded; artifact retrieval reported a non-fatal warning" \
        | tee -a "${log_path}"
      return 0
    fi
    failed_command="${command_text}"
    return 1
  fi

  if [[ -z "${remote_exit_code}" || "${remote_exit_code}" != "0" ]]; then
    failed_command="${command_text}"
    return 1
  fi
}

root_inventory_as_json_array() {
  local source_path inventory_path
  source_path="${root_dir}/crates/franken-extension-host/src/lib.rs"
  inventory_path="$(mktemp)"

  awk '
    function identifier_prefix(token, out, i, ch) {
      out = ""
      for (i = 1; i <= length(token); i++) {
        ch = substr(token, i, 1)
        if (ch ~ /[[:alnum:]_]/) {
          out = out ch
        } else {
          break
        }
      }
      return out
    }
    {
      line = $0
      sub(/^[[:space:]]+/, "", line)
      if (line !~ /^pub /) {
        next
      }

      count = split(line, fields, /[[:space:]]+/)
      name = ""
      if (count >= 4 && fields[1] == "pub" && fields[2] == "const" && fields[3] == "fn") {
        name = identifier_prefix(fields[4])
      } else if (count >= 3 && fields[1] == "pub" &&
        (fields[2] == "struct" ||
         fields[2] == "enum" ||
         fields[2] == "trait" ||
         fields[2] == "fn" ||
         fields[2] == "const")) {
        name = identifier_prefix(fields[3])
      }

      if (name != "") {
        print name
      }
    }
  ' "${source_path}" | sort -u >"${inventory_path}"

  jq -Rn '[inputs]' <"${inventory_path}"
  rm -f "${inventory_path}"
}

materialize_contract_artifacts() {
  local inventory_json required_items_checked placeholder_present outcome error_code_json
  local contract_variant required_constants_json required_functions_json required_types_json

  inventory_json="$(root_inventory_as_json_array)"
  required_constants_json="$(jq '.root_contract.required_public_constants' "${contract_source_json}")"
  required_functions_json="$(jq '.root_contract.required_public_functions' "${contract_source_json}")"
  required_types_json="$(jq '.root_contract.required_public_types' "${contract_source_json}")"
  contract_variant="$(jq -r '.root_contract.variant' "${contract_source_json}")"

  required_items_checked="$(
    jq -n \
      --argjson inventory "${inventory_json}" \
      --argjson constants "${required_constants_json}" \
      --argjson functions "${required_functions_json}" \
      --argjson types "${required_types_json}" \
      '
      reduce ($constants + $functions + $types)[] as $name
        ({}; .[$name] = ($inventory | index($name) != null))
      '
  )"

  placeholder_present="$(
    jq -n --argjson inventory "${inventory_json}" \
      '($inventory | index("placeholder_extension_host_symbol")) != null'
  )"

  outcome="$(
    jq -nr \
      --argjson required "${required_items_checked}" \
      --argjson placeholder_present "${placeholder_present}" \
      'if ($placeholder_present or ($required | to_entries | any(.value == false))) then "fail" else "pass" end'
  )"

  if [[ "${outcome}" == "pass" ]]; then
    error_code_json="null"
  else
    error_code_json='"FE-RGC-920B-GATE-0001"'
  fi

  jq '.' "${contract_source_json}" >"${contract_artifact_path}"

  jq -n \
    --arg schema_version "franken-engine.extension-host.root-contract.validation-report.v1" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg component "${component}" \
    --arg event "contract_validated" \
    --arg outcome "${outcome}" \
    --argjson error_code "${error_code_json}" \
    --arg contract_variant "${contract_variant}" \
    --argjson placeholder_symbol_present "${placeholder_present}" \
    --argjson required_items_checked "${required_items_checked}" \
    '{
      schema_version: $schema_version,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: $event,
      outcome: $outcome,
      error_code: $error_code,
      contract_variant: $contract_variant,
      placeholder_symbol_present: $placeholder_symbol_present,
      required_items_checked: $required_items_checked
    }' >"${validation_report_path}"

  jq -n \
    --arg schema_version "franken-engine.extension-host.root-contract.surface-report.v1" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg component "${component}" \
    --arg event "root_surface_inventory" \
    --arg outcome "${outcome}" \
    --argjson error_code "${error_code_json}" \
    --arg contract_variant "${contract_variant}" \
    --argjson inventory "${inventory_json}" \
    --argjson required_constants "${required_constants_json}" \
    --argjson required_functions "${required_functions_json}" \
    --argjson required_types "${required_types_json}" \
    '{
      schema_version: $schema_version,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: $event,
      outcome: $outcome,
      error_code: $error_code,
      contract_variant: $contract_variant,
      total_public_items: ($inventory | length),
      public_item_inventory: $inventory,
      required_public_constants: $required_constants,
      required_public_functions: $required_functions,
      required_public_types: $required_types
    }' >"${surface_report_path}"
}

write_trace_ids() {
  cat >"${trace_ids_path}" <<EOF_TRACE
{
  "schema_version": "franken-engine.extension-host.root-contract.trace-ids.v1",
  "bead_id": "bd-2muur.2",
  "component": "${component}",
  "policy_id": "${policy_id}",
  "trace_ids": ["${trace_id}"],
  "decision_ids": ["${decision_id}"]
}
EOF_TRACE
}

write_commands() {
  printf '%s\n' "${commands_run[@]}" >"${commands_path}"
}

write_events() {
  local outcome error_code_json
  if [[ "${exit_code}" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-920B-GATE-0001"'
  fi

  cat >"${events_path}" <<EOF_EVENT
{"schema_version":"franken-engine.extension-host.root-contract.event.v1","scenario_id":"${scenario_id}","trace_id":"${trace_id}","decision_id":"${decision_id}","policy_id":"${policy_id}","component":"${component}","event":"gate_completed","outcome":"${outcome}","error_code":${error_code_json}}
EOF_EVENT
}

write_manifest() {
  local outcome error_code_json git_commit idx comma
  if [[ "${exit_code}" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-920B-GATE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.extension-host.root-contract.run-manifest.v1",'
    echo '  "bead_id": "bd-2muur.2",'
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
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"error_code\": ${error_code_json},"
    if [[ -n "${failed_command}" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\","
    fi
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\","
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    "
    echo '  },'
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "${idx}" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"run_manifest\": \"${manifest_path}\","
    echo "    \"trace_ids\": \"${trace_ids_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"contract_source\": \"${contract_source_json}\","
    echo "    \"extension_host_root_contract\": \"${contract_artifact_path}\","
    echo "    \"extension_host_root_contract_validation_report\": \"${validation_report_path}\","
    echo "    \"extension_host_root_surface_report\": \"${surface_report_path}\","
    echo "    \"step_logs_dir\": \"${step_logs_dir}\""
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${trace_ids_path}\","
    echo "    \"cat ${contract_artifact_path}\","
    echo "    \"cat ${validation_report_path}\","
    echo "    \"cat ${surface_report_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${step_logs_dir}/step_000.log\""
    echo '  ]'
    echo "}"
  } >"${manifest_path}"
}

finalize() {
  local status=$?
  if [[ "${exit_code}" -eq 0 && "${status}" -ne 0 ]]; then
    exit_code="${status}"
  fi
  write_trace_ids
  write_commands
  write_events
  write_manifest
  exit "${exit_code}"
}

trap finalize EXIT

if [[ ! -f "${contract_source_json}" ]]; then
  failed_command="preflight: missing ${contract_source_json}"
  exit_code=1
  exit 1
fi

if ! jq -e '.' "${contract_source_json}" >/dev/null 2>&1; then
  failed_command="preflight: parse ${contract_source_json}"
  exit_code=1
  exit 1
fi

run_mode() {
  case "${mode}" in
    check)
      run_step \
        "cargo check -p frankenengine-extension-host --test root_contract" \
        cargo check -p frankenengine-extension-host --test root_contract
      ;;
    test)
      run_step \
        "cargo test -p frankenengine-extension-host --test root_contract -- --nocapture" \
        cargo test -p frankenengine-extension-host --test root_contract -- --nocapture
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-extension-host --test root_contract -- -D warnings" \
        cargo clippy -p frankenengine-extension-host --test root_contract -- -D warnings
      ;;
    replay)
      run_step \
        "cargo test -p frankenengine-extension-host --test root_contract extension_host_root_contract_scenario_emits_artifact_bundle -- --exact --nocapture" \
        cargo test -p frankenengine-extension-host --test root_contract extension_host_root_contract_scenario_emits_artifact_bundle -- --exact --nocapture
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-extension-host --test root_contract" \
        cargo check -p frankenengine-extension-host --test root_contract
      run_step \
        "cargo test -p frankenengine-extension-host --test root_contract -- --nocapture" \
        cargo test -p frankenengine-extension-host --test root_contract -- --nocapture
      run_step \
        "cargo clippy -p frankenengine-extension-host --test root_contract -- -D warnings" \
        cargo clippy -p frankenengine-extension-host --test root_contract -- -D warnings
      ;;
    *)
      failed_command="usage"
      exit_code=2
      echo "usage: $0 [check|test|clippy|replay|ci]" >&2
      exit 2
      ;;
  esac
}

if ! run_mode; then
  exit_code=1
  exit 1
fi

if ! materialize_contract_artifacts; then
  failed_command="artifact materialization"
  exit_code=1
  exit 1
fi

for artifact in \
  extension_host_root_contract.json \
  extension_host_root_contract_validation_report.json \
  extension_host_root_surface_report.json \
  step_logs/step_000.log; do
  if [[ ! -f "${run_dir}/${artifact}" ]]; then
    failed_command="artifact validation: missing ${artifact}"
    exit_code=1
    exit 1
  fi
done

echo "extension-host root contract artifacts: ${run_dir}"
