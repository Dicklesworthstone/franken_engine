#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root="${FRANKENCTL_REACT_EXAMPLE_APP_ARTIFACT_ROOT:-artifacts/frankenctl_react_example_app_workflow}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-/data/projects/franken_engine/target_rch_frankenctl_react_example_app_workflow_${target_namespace}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
contract_path="${run_dir}/react_cli_contract.json"
compile_report_path="${run_dir}/react_compile_report.json"
ssr_report_path="${run_dir}/react_build_ssr_report.json"
client_report_path="${run_dir}/react_build_client_report.json"
hydration_report_path="${run_dir}/react_build_hydration_report.json"
doctor_input_path="${run_dir}/doctor_input.json"
doctor_report_path="${run_dir}/doctor_report.json"
example_report_path="${run_dir}/react_example_app_e2e_report.json"
help_output_path="${run_dir}/react_help.txt"
step_logs_dir="${run_dir}/step_logs"
fixtures_dir="${run_dir}/fixtures"
compile_source_path="${fixtures_dir}/example_app.tsx"
build_entry_path="${fixtures_dir}/example_entry.jsx"
support_bundle_dir="${run_dir}/support_bundle"
support_preflight_path="${support_bundle_dir}/preflight_report.json"
support_scorecard_path="${support_bundle_dir}/onboarding_scorecard.json"
support_rollout_path="${support_bundle_dir}/rollout_decision_artifact.json"
support_doctor_report_path="${support_bundle_dir}/frankenctl_doctor_report.json"

workflow_trace_id="trace-frankenctl-react-example-app-workflow-${timestamp}"
workflow_decision_id="decision-frankenctl-react-example-app-workflow-${timestamp}"
workflow_policy_id="policy-frankenctl-react-example-app-workflow-v1"
contract_trace_id="trace-frankenctl-react-example-contract-${timestamp}"
contract_decision_id="decision-frankenctl-react-example-contract-${timestamp}"
contract_policy_id="policy-frankenctl-react-example-contract-v1"
compile_trace_id="trace-frankenctl-react-example-compile-${timestamp}"
compile_decision_id="decision-frankenctl-react-example-compile-${timestamp}"
compile_policy_id="policy-frankenctl-react-example-compile-v1"
ssr_trace_id="trace-frankenctl-react-example-ssr-${timestamp}"
ssr_decision_id="decision-frankenctl-react-example-ssr-${timestamp}"
ssr_policy_id="policy-frankenctl-react-example-ssr-v1"
client_trace_id="trace-frankenctl-react-example-client-${timestamp}"
client_decision_id="decision-frankenctl-react-example-client-${timestamp}"
client_policy_id="policy-frankenctl-react-example-client-v1"
hydration_trace_id="trace-frankenctl-react-example-hydration-${timestamp}"
hydration_decision_id="decision-frankenctl-react-example-hydration-${timestamp}"
hydration_policy_id="policy-frankenctl-react-example-hydration-v1"
doctor_trace_id="trace-frankenctl-react-example-doctor-${timestamp}"
doctor_decision_id="decision-frankenctl-react-example-doctor-${timestamp}"
doctor_policy_id="policy-frankenctl-react-example-doctor-v1"
component="frankenctl_react_example_app_workflow_gate"
scenario_id="bd-1lsy.10.12.3"
replay_command="./scripts/e2e/frankenctl_react_example_app_workflow.sh ${mode}"

mkdir -p "$run_dir" "$step_logs_dir" "$fixtures_dir" "$support_bundle_dir"

cat >"$compile_source_path" <<'EOF'
export const ExampleApp = () => (
  <section data-example="react-example-app">
    <h1>FrankenEngine React example-app workflow</h1>
  </section>
);
EOF

cat >"$build_entry_path" <<'EOF'
export default function ExampleEntry() {
  return <main data-surface="react-build-entry">Example entry</main>;
}
EOF

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for frankenctl React example-app workflow heavy commands" >&2
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for frankenctl React example-app workflow report assembly" >&2
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

extract_json_from_log() {
  local log_path="$1"
  local output_path="$2"

  rch_strip_ansi "$log_path" | awk '
    BEGIN {
      capture = 0
      depth = 0
    }
    {
      line = $0
      if (!capture && line ~ /^[[:space:]]*\{[[:space:]]*$/) {
        capture = 1
      }
      if (!capture) {
        next
      }
      print line
      tmp = line
      opens = gsub(/\{/, "{", tmp)
      closes = gsub(/\}/, "}", tmp)
      depth += opens - closes
      if (depth == 0) {
        exit
      }
    }
  ' >"$output_path"

  if [[ ! -s "$output_path" ]]; then
    echo "failed to extract JSON artifact from ${log_path}" >&2
    return 1
  fi

  jq -e '.' "$output_path" >/dev/null
}

append_event() {
  local event="$1"
  local path_type="$2"
  local outcome="$3"
  local trace_id="$4"
  local decision_id="$5"
  local policy_id="$6"
  local error_code="${7:-null}"
  local artifact_path="${8:-null}"

  cat >>"$events_path" <<EOF
{"schema_version":"franken-engine.frankenctl.react-example-app-workflow.event.v1","scenario_id":"${scenario_id}","trace_id":"${trace_id}","decision_id":"${decision_id}","policy_id":"${policy_id}","component":"${component}","event":"${event}","path_type":"${path_type}","outcome":"${outcome}","error_code":${error_code},"artifact_path":${artifact_path}}
EOF
}

json_quote() {
  jq -Rn --arg value "$1" '$value'
}

declare -a commands_run=()
failed_command=""
manifest_written=false
step_log_index=0
last_step_log_path=""

run_step() {
  local command_text="$1"
  local expected_remote_exit="$2"
  local artifact_path="${3:-}"
  local log_path status remote_exit_code
  shift 3

  commands_run+=("${command_text}")
  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  step_log_index=$((step_log_index + 1))
  last_step_log_path="${log_path}"

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

  if [[ -n "${artifact_path}" ]]; then
    extract_json_from_log "$log_path" "$artifact_path"
  fi
}

write_doctor_input() {
  cat >"$doctor_input_path" <<EOF
{
  "trace_id": "${doctor_trace_id}",
  "decision_id": "${doctor_decision_id}",
  "policy_id": "${doctor_policy_id}",
  "runtime_state": {
    "snapshot_timestamp_ns": 42000,
    "loaded_extensions": [
      {
        "extension_id": "react-example-app-surface",
        "containment_state": "running"
      }
    ],
    "active_policies": [
      "${doctor_policy_id}",
      "${workflow_policy_id}"
    ],
    "security_epoch": 7,
    "gc_pressure": [
      {
        "extension_id": "react-example-app-surface",
        "used_bytes": 128,
        "budget_bytes": 1024
      }
    ],
    "scheduler_lanes": [
      {
        "lane": "react_example_app",
        "queue_depth": 1,
        "max_depth": 8,
        "tasks_submitted": 4,
        "tasks_scheduled": 4,
        "tasks_completed": 4,
        "tasks_timed_out": 0
      }
    ]
  },
  "evidence_entries": [],
  "hostcall_records": [],
  "containment_receipts": [],
  "replay_artifacts": [
    {
      "trace_id": "${contract_trace_id}",
      "extension_id": "react-example-app-surface",
      "timestamp_ns": 42001,
      "artifact_id": "react_cli_contract",
      "replay_pointer": "${contract_path}"
    },
    {
      "trace_id": "${compile_trace_id}",
      "extension_id": "react-example-app-surface",
      "timestamp_ns": 42002,
      "artifact_id": "react_compile_report",
      "replay_pointer": "${compile_report_path}"
    },
    {
      "trace_id": "${ssr_trace_id}",
      "extension_id": "react-example-app-surface",
      "timestamp_ns": 42003,
      "artifact_id": "react_build_ssr_report",
      "replay_pointer": "${ssr_report_path}"
    },
    {
      "trace_id": "${client_trace_id}",
      "extension_id": "react-example-app-surface",
      "timestamp_ns": 42004,
      "artifact_id": "react_build_client_report",
      "replay_pointer": "${client_report_path}"
    },
    {
      "trace_id": "${hydration_trace_id}",
      "extension_id": "react-example-app-surface",
      "timestamp_ns": 42005,
      "artifact_id": "react_build_hydration_report",
      "replay_pointer": "${hydration_report_path}"
    }
  ]
}
EOF
}

build_example_report() {
  jq -n \
    --arg schema_version "franken-engine.frankenctl.react-example-app-e2e-report.v1" \
    --arg bead_id "${scenario_id}" \
    --arg component "${component}" \
    --arg generated_at "${timestamp}" \
    --arg trace_id "${workflow_trace_id}" \
    --arg decision_id "${workflow_decision_id}" \
    --arg policy_id "${workflow_policy_id}" \
    --arg help_output_path "${help_output_path}" \
    --arg contract_path "${contract_path}" \
    --arg compile_path "${compile_report_path}" \
    --arg ssr_path "${ssr_report_path}" \
    --arg client_path "${client_report_path}" \
    --arg hydration_path "${hydration_report_path}" \
    --arg doctor_input_path "${doctor_input_path}" \
    --arg doctor_path "${doctor_report_path}" \
    --arg support_preflight_path "${support_preflight_path}" \
    --arg support_scorecard_path "${support_scorecard_path}" \
    --arg support_rollout_path "${support_rollout_path}" \
    --arg support_doctor_report_path "${support_doctor_report_path}" \
    --arg contract_command "frankenctl react contract --trace-id <id> --decision-id <id> --policy-id <id>" \
    --arg compile_command "frankenctl react compile --input <example_app.tsx> --source-form tsx --runtime automatic --trace-id <id> --decision-id <id> --policy-id <id>" \
    --arg ssr_command "frankenctl react build --entry <example_entry.jsx> --target ssr --trace-id <id> --decision-id <id> --policy-id <id>" \
    --arg client_command "frankenctl react build --entry <example_entry.jsx> --target client --trace-id <id> --decision-id <id> --policy-id <id>" \
    --arg hydration_command "frankenctl react build --entry <example_entry.jsx> --target hydration --trace-id <id> --decision-id <id> --policy-id <id>" \
    --arg doctor_command "frankenctl doctor --input <doctor_input.json> --out-dir <path>" \
    --slurpfile contract "${contract_path}" \
    --slurpfile compile "${compile_report_path}" \
    --slurpfile ssr "${ssr_report_path}" \
    --slurpfile client "${client_report_path}" \
    --slurpfile hydration "${hydration_report_path}" \
    --slurpfile doctor "${doctor_report_path}" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      component: $component,
      generated_at_utc: $generated_at,
      workflow: {
        trace_id: $trace_id,
        decision_id: $decision_id,
        policy_id: $policy_id
      },
      supported_journeys: [
        {
          journey_id: "react_help",
          outcome: "pass",
          artifact_path: $help_output_path
        },
        {
          journey_id: "react_contract",
          outcome: "pass",
          command: $contract_command,
          schema_version: $contract[0].schema_version,
          artifact_path: $contract_path
        },
        {
          journey_id: "doctor_support_bundle",
          outcome: "pass",
          command: $doctor_command,
          preflight_verdict: $doctor[0].preflight_verdict,
          readiness: $doctor[0].readiness,
          rollout_recommendation: $doctor[0].rollout_recommendation,
          blocked: $doctor[0].blocked,
          support_bundle_paths: [
            $support_preflight_path,
            $support_scorecard_path,
            $support_rollout_path,
            $support_doctor_report_path
          ],
          doctor_input_path: $doctor_input_path,
          artifact_path: $doctor_path
        }
      ],
      fail_closed_journeys: [
        {
          journey_id: "compile_only_tsx",
          outcome: "expected_fail_closed",
          command: $compile_command,
          capability_id: $compile[0].capability_id,
          support_status: $compile[0].support_status,
          error_code: $compile[0].diagnostic.error_code,
          product_surface_bead: $compile[0].diagnostic.product_surface_bead,
          artifact_path: $compile_path
        },
        {
          journey_id: "ssr_entrypoint",
          outcome: "expected_fail_closed",
          command: $ssr_command,
          capability_id: $ssr[0].capability_id,
          support_status: $ssr[0].support_status,
          error_code: $ssr[0].diagnostic.error_code,
          product_surface_bead: $ssr[0].diagnostic.product_surface_bead,
          artifact_path: $ssr_path
        },
        {
          journey_id: "client_entry_preparation",
          outcome: "expected_fail_closed",
          command: $client_command,
          capability_id: $client[0].capability_id,
          support_status: $client[0].support_status,
          error_code: $client[0].diagnostic.error_code,
          product_surface_bead: $client[0].diagnostic.product_surface_bead,
          artifact_path: $client_path
        },
        {
          journey_id: "hydration_handoff",
          outcome: "expected_fail_closed",
          command: $hydration_command,
          capability_id: $hydration[0].capability_id,
          support_status: $hydration[0].support_status,
          error_code: $hydration[0].diagnostic.error_code,
          product_surface_bead: $hydration[0].diagnostic.product_surface_bead,
          artifact_path: $hydration_path
        }
      ],
      artifact_paths: {
        react_cli_contract: $contract_path,
        react_compile_report: $compile_path,
        react_build_ssr_report: $ssr_path,
        react_build_client_report: $client_path,
        react_build_hydration_report: $hydration_path,
        doctor_input: $doctor_input_path,
        doctor_report: $doctor_path,
        support_bundle: [
          $support_preflight_path,
          $support_scorecard_path,
          $support_rollout_path,
          $support_doctor_report_path
        ]
      }
    }' >"${example_report_path}"

  jq -e '.' "${example_report_path}" >/dev/null
}

emit_trace_ids() {
  cat >"$trace_ids_path" <<EOF
{
  "schema_version": "franken-engine.frankenctl.react-example-app-workflow.trace-ids.v1",
  "bead_id": "bd-1lsy.10.12.3",
  "workflow_trace_id": "${workflow_trace_id}",
  "trace_ids": [
    "${contract_trace_id}",
    "${compile_trace_id}",
    "${ssr_trace_id}",
    "${client_trace_id}",
    "${hydration_trace_id}",
    "${doctor_trace_id}"
  ],
  "decision_ids": [
    "${contract_decision_id}",
    "${compile_decision_id}",
    "${ssr_decision_id}",
    "${client_decision_id}",
    "${hydration_decision_id}",
    "${doctor_decision_id}"
  ],
  "policy_ids": [
    "${contract_policy_id}",
    "${compile_policy_id}",
    "${ssr_policy_id}",
    "${client_policy_id}",
    "${hydration_policy_id}",
    "${doctor_policy_id}"
  ],
  "artifact_paths": {
    "react_cli_contract": "${contract_path}",
    "react_compile_report": "${compile_report_path}",
    "react_build_ssr_report": "${ssr_report_path}",
    "react_build_client_report": "${client_report_path}",
    "react_build_hydration_report": "${hydration_report_path}",
    "doctor_input": "${doctor_input_path}",
    "doctor_report": "${doctor_report_path}",
    "react_example_app_e2e_report": "${example_report_path}",
    "run_manifest": "${manifest_path}",
    "events": "${events_path}",
    "commands": "${commands_path}"
  }
}
EOF
}

run_artifact_flow() {
  : >"$events_path"

  run_step \
    "cargo run -q -p frankenengine-engine --bin frankenctl -- react --help" \
    "0" \
    "" \
    cargo run -q -p frankenengine-engine --bin frankenctl -- react --help || return $?
  rch_strip_ansi "${last_step_log_path}" | awk '/^react usage:$/,/^$/' >"$help_output_path"
  append_event "react_help_captured" "control" "pass" "${workflow_trace_id}" "${workflow_decision_id}" "${workflow_policy_id}" "null" "$(json_quote "${help_output_path}")"

  run_step \
    "cargo run -q -p frankenengine-engine --bin frankenctl -- react contract --trace-id ${contract_trace_id} --decision-id ${contract_decision_id} --policy-id ${contract_policy_id}" \
    "0" \
    "${contract_path}" \
    cargo run -q -p frankenengine-engine --bin frankenctl -- react contract \
      --trace-id "${contract_trace_id}" \
      --decision-id "${contract_decision_id}" \
      --policy-id "${contract_policy_id}" \
      --out "${contract_path}" || return $?
  append_event "react_contract_emitted" "contract" "pass" "${contract_trace_id}" "${contract_decision_id}" "${contract_policy_id}" "null" "$(json_quote "${contract_path}")"

  run_step \
    "cargo run -q -p frankenengine-engine --bin frankenctl -- react compile --input ${compile_source_path} --source-form tsx --runtime automatic --trace-id ${compile_trace_id} --decision-id ${compile_decision_id} --policy-id ${compile_policy_id}" \
    "25" \
    "${compile_report_path}" \
    cargo run -q -p frankenengine-engine --bin frankenctl -- react compile \
      --input "${compile_source_path}" \
      --source-form tsx \
      --runtime automatic \
      --trace-id "${compile_trace_id}" \
      --decision-id "${compile_decision_id}" \
      --policy-id "${compile_policy_id}" \
      --out "${compile_report_path}" || return $?
  append_event "react_compile_report_emitted" "deferred" "expected_fail_closed" "${compile_trace_id}" "${compile_decision_id}" "${compile_policy_id}" "$(json_quote "FE-RGC-016A-CAP-0005")" "$(json_quote "${compile_report_path}")"

  run_step \
    "cargo run -q -p frankenengine-engine --bin frankenctl -- react build --entry ${build_entry_path} --target ssr --trace-id ${ssr_trace_id} --decision-id ${ssr_decision_id} --policy-id ${ssr_policy_id}" \
    "25" \
    "${ssr_report_path}" \
    cargo run -q -p frankenengine-engine --bin frankenctl -- react build \
      --entry "${build_entry_path}" \
      --target ssr \
      --trace-id "${ssr_trace_id}" \
      --decision-id "${ssr_decision_id}" \
      --policy-id "${ssr_policy_id}" \
      --out "${ssr_report_path}" || return $?
  append_event "react_build_ssr_report_emitted" "unsupported" "expected_fail_closed" "${ssr_trace_id}" "${ssr_decision_id}" "${ssr_policy_id}" "$(json_quote "FE-RGC-016A-CAP-0007")" "$(json_quote "${ssr_report_path}")"

  run_step \
    "cargo run -q -p frankenengine-engine --bin frankenctl -- react build --entry ${build_entry_path} --target client --trace-id ${client_trace_id} --decision-id ${client_decision_id} --policy-id ${client_policy_id}" \
    "25" \
    "${client_report_path}" \
    cargo run -q -p frankenengine-engine --bin frankenctl -- react build \
      --entry "${build_entry_path}" \
      --target client \
      --trace-id "${client_trace_id}" \
      --decision-id "${client_decision_id}" \
      --policy-id "${client_policy_id}" \
      --out "${client_report_path}" || return $?
  append_event "react_build_client_report_emitted" "unsupported" "expected_fail_closed" "${client_trace_id}" "${client_decision_id}" "${client_policy_id}" "$(json_quote "FE-RGC-016A-CAP-0008")" "$(json_quote "${client_report_path}")"

  run_step \
    "cargo run -q -p frankenengine-engine --bin frankenctl -- react build --entry ${build_entry_path} --target hydration --trace-id ${hydration_trace_id} --decision-id ${hydration_decision_id} --policy-id ${hydration_policy_id}" \
    "25" \
    "${hydration_report_path}" \
    cargo run -q -p frankenengine-engine --bin frankenctl -- react build \
      --entry "${build_entry_path}" \
      --target hydration \
      --trace-id "${hydration_trace_id}" \
      --decision-id "${hydration_decision_id}" \
      --policy-id "${hydration_policy_id}" \
      --out "${hydration_report_path}" || return $?
  append_event "react_build_hydration_report_emitted" "unsupported" "expected_fail_closed" "${hydration_trace_id}" "${hydration_decision_id}" "${hydration_policy_id}" "$(json_quote "FE-RGC-016A-CAP-0009")" "$(json_quote "${hydration_report_path}")"

  write_doctor_input
  append_event "doctor_input_emitted" "doctor_input" "pass" "${doctor_trace_id}" "${doctor_decision_id}" "${doctor_policy_id}" "null" "$(json_quote "${doctor_input_path}")"

  run_step \
    "cargo run -q -p frankenengine-engine --bin frankenctl -- doctor --input ${doctor_input_path} --out-dir ${run_dir}" \
    "0" \
    "${doctor_report_path}" \
    cargo run -q -p frankenengine-engine --bin frankenctl -- doctor \
      --input "${doctor_input_path}" \
      --out-dir "${run_dir}" || return $?
  append_event "doctor_support_bundle_emitted" "support_bundle" "pass" "${doctor_trace_id}" "${doctor_decision_id}" "${doctor_policy_id}" "null" "$(json_quote "${doctor_report_path}")"

  build_example_report
  append_event "react_example_app_e2e_report_emitted" "workflow_report" "pass" "${workflow_trace_id}" "${workflow_decision_id}" "${workflow_policy_id}" "null" "$(json_quote "${example_report_path}")"

  emit_trace_ids
  append_event "trace_ids_emitted" "trace_index" "pass" "${workflow_trace_id}" "${workflow_decision_id}" "${workflow_policy_id}" "null" "$(json_quote "${trace_ids_path}")"

  for required_path in \
    "${contract_path}" \
    "${compile_report_path}" \
    "${ssr_report_path}" \
    "${client_report_path}" \
    "${hydration_report_path}" \
    "${doctor_input_path}" \
    "${doctor_report_path}" \
    "${example_report_path}" \
    "${trace_ids_path}" \
    "${help_output_path}" \
    "${support_preflight_path}" \
    "${support_scorecard_path}" \
    "${support_rollout_path}" \
    "${support_doctor_report_path}"; do
    if [[ ! -f "${required_path}" ]]; then
      echo "required artifact missing: ${required_path}" >&2
      failed_command="artifact_presence_check (${required_path})"
      return 1
    fi
  done
}

run_mode() {
  case "$mode" in
    artifacts)
      run_artifact_flow || return $?
      ;;
    check)
      run_step \
        "cargo check -p frankenengine-engine --bin frankenctl --test frankenctl_cli" \
        "0" \
        "" \
        cargo check -p frankenengine-engine --bin frankenctl --test frankenctl_cli || return $?
      run_artifact_flow || return $?
      ;;
    test)
      run_step \
        "cargo test -p frankenengine-engine --test frankenctl_cli frankenctl_react_" \
        "0" \
        "" \
        cargo test -p frankenengine-engine --test frankenctl_cli frankenctl_react_ || return $?
      run_artifact_flow || return $?
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --bin frankenctl --test frankenctl_cli -- -D warnings" \
        "0" \
        "" \
        cargo clippy -p frankenengine-engine --bin frankenctl --test frankenctl_cli -- -D warnings || return $?
      run_artifact_flow || return $?
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-engine --bin frankenctl --test frankenctl_cli" \
        "0" \
        "" \
        cargo check -p frankenengine-engine --bin frankenctl --test frankenctl_cli || return $?
      run_step \
        "cargo test -p frankenengine-engine --test frankenctl_cli frankenctl_react_" \
        "0" \
        "" \
        cargo test -p frankenengine-engine --test frankenctl_cli frankenctl_react_ || return $?
      run_step \
        "cargo clippy -p frankenengine-engine --bin frankenctl --test frankenctl_cli -- -D warnings" \
        "0" \
        "" \
        cargo clippy -p frankenengine-engine --bin frankenctl --test frankenctl_cli -- -D warnings || return $?
      run_artifact_flow || return $?
      ;;
    *)
      echo "usage: $0 [artifacts|check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma

  if [[ "${manifest_written}" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "${exit_code}" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-912C-WORKFLOW-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  append_event "workflow_completed" "gate" "${outcome}" "${workflow_trace_id}" "${workflow_decision_id}" "${workflow_policy_id}" "${error_code_json}" "null"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.frankenctl.react-example-app-workflow.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.10.12.3",'
    echo "  \"component\": \"${component}\","
    echo "  \"scenario_id\": \"${scenario_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"trace_id\": \"${workflow_trace_id}\","
    echo "  \"decision_id\": \"${workflow_decision_id}\","
    echo "  \"policy_id\": \"${workflow_policy_id}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
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
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"trace_ids\": \"${trace_ids_path}\","
    echo "    \"react_cli_contract\": \"${contract_path}\","
    echo "    \"react_compile_report\": \"${compile_report_path}\","
    echo "    \"react_build_ssr_report\": \"${ssr_report_path}\","
    echo "    \"react_build_client_report\": \"${client_report_path}\","
    echo "    \"react_build_hydration_report\": \"${hydration_report_path}\","
    echo "    \"doctor_input\": \"${doctor_input_path}\","
    echo "    \"doctor_report\": \"${doctor_report_path}\","
    echo "    \"react_example_app_e2e_report\": \"${example_report_path}\","
    echo "    \"react_help\": \"${help_output_path}\","
    echo "    \"step_logs_dir\": \"${step_logs_dir}\","
    echo '    "support_bundle": ['
    echo '      "support_bundle/preflight_report.json",'
    echo '      "support_bundle/onboarding_scorecard.json",'
    echo '      "support_bundle/rollout_decision_artifact.json",'
    echo '      "support_bundle/frankenctl_doctor_report.json"'
    echo '    ]'
    echo '  },'
    echo '  "consumer_routes": ['
    echo '    {"consumer":"docs_smoke","artifact":"react_example_app_e2e_report.json","command":"./scripts/e2e/frankenctl_react_example_app_workflow.sh artifacts"},'
    echo '    {"consumer":"rollout","artifact":"react_example_app_e2e_report.json","command":"./scripts/e2e/frankenctl_react_example_app_workflow.sh ci"},'
    echo '    {"consumer":"doctor","artifact":"support_bundle/preflight_report.json","command":"frankenctl doctor --input <doctor_input.json> --out-dir <path>"}'
    echo '  ],'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${trace_ids_path}\","
    echo "    \"cat ${contract_path}\","
    echo "    \"cat ${compile_report_path}\","
    echo "    \"cat ${ssr_report_path}\","
    echo "    \"cat ${client_report_path}\","
    echo "    \"cat ${hydration_report_path}\","
    echo "    \"cat ${doctor_report_path}\","
    echo "    \"cat ${example_report_path}\","
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "frankenctl React example-app workflow manifest: ${manifest_path}"
  echo "frankenctl React example-app workflow events: ${events_path}"
  echo "frankenctl React example-app workflow commands: ${commands_path}"
  echo "frankenctl React example-app workflow trace ids: ${trace_ids_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"
exit "$main_exit"
