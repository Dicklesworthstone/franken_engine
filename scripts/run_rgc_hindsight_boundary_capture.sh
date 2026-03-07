#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/data/projects/franken_engine/target_rch_rgc_hindsight_boundary_capture}"
artifact_root="${RGC_HINDSIGHT_BOUNDARY_CAPTURE_ARTIFACT_ROOT:-artifacts/rgc_hindsight_boundary_capture}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
catalog_path="${run_dir}/hindsight_boundary_catalog.json"
schema_path="${run_dir}/minimal_replay_input_schema.json"
redaction_path="${run_dir}/boundary_redaction_map.json"
capture_log_path="${run_dir}/boundary_capture_log.jsonl"
step_logs_dir="${run_dir}/step_logs"

contract_doc="docs/RGC_HINDSIGHT_BOUNDARY_CAPTURE_V1.md"
contract_json="docs/rgc_hindsight_boundary_capture_v1.json"

trace_id="trace-rgc-hindsight-boundary-capture-${timestamp}"
decision_id="decision-rgc-hindsight-boundary-capture-${timestamp}"
policy_id="policy-rgc-hindsight-boundary-capture-v1"
component="rgc_hindsight_boundary_capture_gate"
scenario_id="rgc-811a"
replay_command="./scripts/e2e/rgc_hindsight_boundary_capture_replay.sh ${mode}"

mkdir -p "$run_dir" "$step_logs_dir"

if [[ ! -f "$contract_doc" ]]; then
  echo "FE-RGC-811A-CONTRACT-0001: missing contract doc (${contract_doc})" >&2
  exit 1
fi

if [[ ! -f "$contract_json" ]]; then
  echo "FE-RGC-811A-CONTRACT-0002: missing contract JSON (${contract_json})" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for hindsight boundary capture artifacts" >&2
  exit 2
fi

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for hindsight boundary capture heavy commands" >&2
  exit 2
fi

declare -a commands_run=()
failed_command=""
step_log_index=0
run_status="failed"

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
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
      failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      return 1
    fi
    remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
    if [[ -n "${remote_exit_code}" ]]; then
      failed_command="${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})"
    else
      failed_command="${command_text} (rch-exit=${status}; missing-remote-exit-marker)"
    fi
    return 1
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -z "$remote_exit_code" || "$remote_exit_code" != "0" ]]; then
    failed_command="${command_text} (missing-or-nonzero-remote-exit)"
    return 1
  fi
}

run_mode_steps() {
  case "$mode" in
    check)
      run_step \
        "cargo check -p frankenengine-engine --test rgc_hindsight_boundary_capture" \
        cargo check -p frankenengine-engine --test rgc_hindsight_boundary_capture
      ;;
    test)
      run_step \
        "cargo test -p frankenengine-engine --test rgc_hindsight_boundary_capture" \
        cargo test -p frankenengine-engine --test rgc_hindsight_boundary_capture
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --test rgc_hindsight_boundary_capture -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_hindsight_boundary_capture -- -D warnings
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-engine --test rgc_hindsight_boundary_capture" \
        cargo check -p frankenengine-engine --test rgc_hindsight_boundary_capture
      run_step \
        "cargo test -p frankenengine-engine --test rgc_hindsight_boundary_capture" \
        cargo test -p frankenengine-engine --test rgc_hindsight_boundary_capture
      run_step \
        "cargo clippy -p frankenengine-engine --test rgc_hindsight_boundary_capture -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_hindsight_boundary_capture -- -D warnings
      ;;
    *)
      echo "unsupported mode: ${mode} (expected check|test|clippy|ci)" >&2
      exit 2
      ;;
  esac
}

emit_artifacts() {
  jq '.boundary_catalog' "$contract_json" >"$catalog_path"
  jq '.minimal_replay_input_schema' "$contract_json" >"$schema_path"
  jq '.boundary_redaction_map' "$contract_json" >"$redaction_path"

  jq -nc \
    --arg schema_version "franken-engine.rgc-boundary-capture-event.v1" \
    --arg trace_id "$trace_id" \
    --arg policy_id "$policy_id" \
    '
    [
      {
        schema_version: $schema_version,
        trace_id: $trace_id,
        decision_id: "decision-rgc-811a-module",
        policy_id: $policy_id,
        component: "module_loader",
        sequence: 0,
        boundary_class: "module_resolution",
        nondeterminism_tag: "module_resolution",
        correlation_key: "bcorr_sample_module_resolution",
        virtual_ts: 20,
        minimal_fields: {
          specifier: "pkg:demo/widget",
          referrer_digest: "digest-referrer",
          resolved_path_digest: "digest-resolved"
        },
        redaction: {
          specifier: { privacy_class: "public_metadata", treatment: "plaintext" },
          referrer_digest: { privacy_class: "path_digest", treatment: "digest_only" },
          resolved_path_digest: { privacy_class: "path_digest", treatment: "digest_only" }
        },
        sufficiency: "sufficient",
        escalation_reason: null
      },
      {
        schema_version: $schema_version,
        trace_id: $trace_id,
        decision_id: "decision-rgc-811a-scheduler",
        policy_id: $policy_id,
        component: "scheduler",
        sequence: 1,
        boundary_class: "scheduling_decision",
        nondeterminism_tag: "scheduling_decision",
        correlation_key: "bcorr_sample_scheduling_decision",
        virtual_ts: 40,
        minimal_fields: {
          queue_id: "ready",
          task_id: "task-41",
          ordering_digest: "digest-ordering"
        },
        redaction: {
          queue_id: { privacy_class: "public_metadata", treatment: "plaintext" },
          task_id: { privacy_class: "public_metadata", treatment: "plaintext" },
          ordering_digest: { privacy_class: "secret_digest", treatment: "digest_only" }
        },
        sufficiency: "sufficient",
        escalation_reason: null
      },
      {
        schema_version: $schema_version,
        trace_id: $trace_id,
        decision_id: "decision-rgc-811a-controller",
        policy_id: $policy_id,
        component: "controller",
        sequence: 2,
        boundary_class: "controller_override",
        nondeterminism_tag: "controller_override",
        correlation_key: "bcorr_sample_controller_override",
        virtual_ts: 60,
        minimal_fields: {
          controller_id: "router",
          override_kind: "force_safe_mode",
          value_digest: "digest-value"
        },
        redaction: {
          controller_id: { privacy_class: "public_metadata", treatment: "plaintext" },
          override_kind: { privacy_class: "public_metadata", treatment: "plaintext" },
          value_digest: { privacy_class: "secret_digest", treatment: "digest_only" }
        },
        sufficiency: "needs_escalation",
        escalation_reason: "interactive-controller-input"
      }
    ][]' >"$capture_log_path"
}

write_commands() {
  {
    printf '%s\n' "${commands_run[@]}"
    echo "jq '.boundary_catalog' ${contract_json} > ${catalog_path}"
    echo "jq '.minimal_replay_input_schema' ${contract_json} > ${schema_path}"
    echo "jq '.boundary_redaction_map' ${contract_json} > ${redaction_path}"
    echo "jq -nc '<sample boundary capture log>' > ${capture_log_path}"
    echo "${replay_command}"
  } >"$commands_path"
}

write_events() {
  {
    printf '{"schema_version":"franken-engine.rgc-hindsight-boundary-capture.event.v1","trace_id":"%s","decision_id":"%s","policy_id":"%s","component":"%s","event":"gate_started","scenario_id":"%s","outcome":"pass","error_code":null}\n' \
      "$trace_id" "$decision_id" "$policy_id" "$component" "$scenario_id"
    printf '{"schema_version":"franken-engine.rgc-hindsight-boundary-capture.event.v1","trace_id":"%s","decision_id":"%s","policy_id":"%s","component":"%s","event":"artifacts_emitted","scenario_id":"%s","outcome":"pass","error_code":null}\n' \
      "$trace_id" "$decision_id" "$policy_id" "$component" "$scenario_id"
    printf '{"schema_version":"franken-engine.rgc-hindsight-boundary-capture.event.v1","trace_id":"%s","decision_id":"%s","policy_id":"%s","component":"%s","event":"gate_completed","scenario_id":"%s","outcome":"pass","error_code":null}\n' \
      "$trace_id" "$decision_id" "$policy_id" "$component" "$scenario_id"
  } >"$events_path"
}

write_manifest() {
  cat >"$manifest_path" <<EOF
{
  "schema_version": "franken-engine.rgc-hindsight-boundary-capture.run-manifest.v1",
  "bead_id": "bd-1lsy.9.11.1",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "policy_id": "${policy_id}",
  "component": "${component}",
  "scenario_id": "${scenario_id}",
  "mode": "${mode}",
  "status": "${run_status}",
  "contract_doc": "${contract_doc}",
  "contract_json": "${contract_json}",
  "replay_command": "${replay_command}",
  "artifacts": {
    "hindsight_boundary_catalog": "${catalog_path}",
    "minimal_replay_input_schema": "${schema_path}",
    "boundary_redaction_map": "${redaction_path}",
    "boundary_capture_log": "${capture_log_path}",
    "events_jsonl": "${events_path}",
    "commands_txt": "${commands_path}"
  },
  "step_logs_dir": "${step_logs_dir}",
  "deterministic_environment": {
$(parser_frontier_emit_manifest_environment_fields "    " "null")
  }
}
EOF
}

run_mode_steps
emit_artifacts
write_commands
run_status="pass"
write_events
write_manifest

echo "hindsight boundary capture manifest: ${manifest_path}"
echo "hindsight boundary capture catalog: ${catalog_path}"
echo "hindsight boundary capture schema: ${schema_path}"
echo "hindsight boundary capture log: ${capture_log_path}"
