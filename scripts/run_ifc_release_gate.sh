#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_franken_engine_ifc_release_gate}"
artifact_root="${IFC_RELEASE_GATE_ARTIFACT_ROOT:-artifacts/ifc_release_gate}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
component="ifc_release_gate"
bead_id="bd-eke"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/ifc_release_gate_events.jsonl"
commands_path="${run_dir}/commands.txt"
logs_dir="${run_dir}/logs"
ifc_output_root="${run_dir}/ifc_conformance"
replay_command="./scripts/e2e/ifc_release_gate_replay.sh ${mode}"

trace_id="trace-ifc-release-gate-${timestamp}"
decision_id="decision-ifc-release-gate-${timestamp}"
policy_id="policy-ifc-release-gate-v1"

mkdir -p "$logs_dir"
mkdir -p "$ifc_output_root"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for IFC release gate heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -q -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a runtime_guard_test_commands=(
  "cargo test -p frankenengine-engine --test lowering_pipeline dynamic_hostcall_flow_proof_artifact_emits_runtime_checkpoint -- --exact"
  "cargo test -p frankenengine-engine --test lowering_pipeline declassification_flow_inserts_runtime_ifc_guard_before_hostcall -- --exact"
  "cargo test -p frankenengine-engine --test execution_orchestrator execute_blocks_unresolved_ifc_runtime_checkpoint_before_interpreter -- --exact"
)

run_runtime_guard_tests() {
  local command_text
  for command_text in "${runtime_guard_test_commands[@]}"; do
    case "$command_text" in
      *"dynamic_hostcall_flow_proof_artifact_emits_runtime_checkpoint"*)
        run_step "$command_text" \
          run_rch cargo test -p frankenengine-engine --test lowering_pipeline dynamic_hostcall_flow_proof_artifact_emits_runtime_checkpoint -- --exact
        ;;
      *"declassification_flow_inserts_runtime_ifc_guard_before_hostcall"*)
        run_step "$command_text" \
          run_rch cargo test -p frankenengine-engine --test lowering_pipeline declassification_flow_inserts_runtime_ifc_guard_before_hostcall -- --exact
        ;;
      *"execute_blocks_unresolved_ifc_runtime_checkpoint_before_interpreter"*)
        run_step "$command_text" \
          run_rch cargo test -p frankenengine-engine --test execution_orchestrator execute_blocks_unresolved_ifc_runtime_checkpoint_before_interpreter -- --exact
        ;;
    esac
  done
}

json_escape() {
  local input="$1"
  input="${input//\\/\\\\}"
  input="${input//\"/\\\"}"
  input="${input//$'\n'/\\n}"
  printf '%s' "$input"
}

declare -a commands_run=()
declare -a command_logs=()
failed_command=""
failed_log_path=""
manifest_written=false

summary_path=""
ci_blocking_failures=-1
false_positive_count=-1
false_negative_count=-1
false_negative_direct_indirect_count=-1
benign_total=0
exfil_total=0
declassify_total=0

run_step() {
  local command_text="$1"
  shift
  local step_index="${#commands_run[@]}"
  local log_path="${logs_dir}/step_$(printf '%02d' "$step_index").log"

  commands_run+=("$command_text")
  command_logs+=("$log_path")
  echo "==> $command_text"

  if ! "$@" > >(tee "$log_path") 2>&1; then
    if rg -q "Remote command finished: exit=0" "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      failed_command="$command_text"
      failed_log_path="$log_path"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    failed_log_path="$log_path"
    return 1
  fi

  return 0
}

run_check() {
  run_step "cargo check -p frankenengine-engine --test lowering_pipeline" \
    run_rch cargo check -p frankenengine-engine --test lowering_pipeline
  run_step "cargo check -p frankenengine-engine --test execution_orchestrator" \
    run_rch cargo check -p frankenengine-engine --test execution_orchestrator
  run_step "cargo check -p frankenengine-engine --test ifc_release_gate" \
    run_rch cargo check -p frankenengine-engine --test ifc_release_gate
  run_step "cargo check -p frankenengine-engine --bin franken_ifc_conformance_runner" \
    run_rch cargo check -p frankenengine-engine --bin franken_ifc_conformance_runner
}

run_test() {
  run_step "cargo test -p frankenengine-engine --test ifc_release_gate" \
    run_rch cargo test -p frankenengine-engine --test ifc_release_gate
  run_runtime_guard_tests
}

run_clippy() {
  run_step "cargo clippy -p frankenengine-engine --test lowering_pipeline --test execution_orchestrator --test ifc_release_gate --bin franken_ifc_conformance_runner -- -D warnings" \
    run_rch cargo clippy -p frankenengine-engine --test lowering_pipeline --test execution_orchestrator --test ifc_release_gate --bin franken_ifc_conformance_runner -- -D warnings
}

extract_metric_from_log() {
  local key="$1"
  local gate_log="$2"
  grep -E "^ifc metric\.${key}=" "$gate_log" | tail -n 1 | awk -F= '{print $2}'
}

collect_gate_metrics() {
  local gate_log
  gate_log="${command_logs[$(( ${#command_logs[@]} - 1 ))]}"

  if [[ ! -f "$gate_log" ]]; then
    failed_command="ifc_release_gate_summary_parse"
    return 1
  fi

  summary_path="$(grep -E '^ifc ifc_conformance_evidence=' "$gate_log" | tail -n 1 | awk -F= '{print $2}')"

  ci_blocking_failures="$(extract_metric_from_log 'ci_blocking_failures' "$gate_log")"
  false_positive_count="$(extract_metric_from_log 'false_positive_count' "$gate_log")"
  false_negative_count="$(extract_metric_from_log 'false_negative_count' "$gate_log")"
  false_negative_direct_indirect_count="$(extract_metric_from_log 'false_negative_direct_indirect_count' "$gate_log")"
  benign_total="$(extract_metric_from_log 'benign_total' "$gate_log")"
  exfil_total="$(extract_metric_from_log 'exfil_total' "$gate_log")"
  declassify_total="$(extract_metric_from_log 'declassify_total' "$gate_log")"

  if [[ -z "$ci_blocking_failures" || -z "$false_positive_count" || -z "$false_negative_count" || -z "$false_negative_direct_indirect_count" || -z "$benign_total" || -z "$exfil_total" || -z "$declassify_total" ]]; then
    failed_command="ifc_release_gate_summary_parse"
    return 1
  fi

  return 0
}

validate_thresholds() {
  local threshold_failure=0

  if [[ "$ci_blocking_failures" -ne 0 ]]; then
    echo "IFC gate failure: ci_blocking_failures=${ci_blocking_failures} (expected 0)" >&2
    threshold_failure=1
  fi
  if [[ "$false_positive_count" -ne 0 ]]; then
    echo "IFC gate failure: false_positive_count=${false_positive_count} (expected 0)" >&2
    threshold_failure=1
  fi
  if [[ "$false_negative_count" -ne 0 ]]; then
    echo "IFC gate failure: false_negative_count=${false_negative_count} (expected 0)" >&2
    threshold_failure=1
  fi
  if [[ "$false_negative_direct_indirect_count" -ne 0 ]]; then
    echo "IFC gate failure: false_negative_direct_indirect_count=${false_negative_direct_indirect_count} (expected 0)" >&2
    threshold_failure=1
  fi
  if [[ "$benign_total" -lt 100 ]]; then
    echo "IFC gate failure: benign_total=${benign_total} (expected >= 100)" >&2
    threshold_failure=1
  fi
  if [[ "$exfil_total" -lt 80 ]]; then
    echo "IFC gate failure: exfil_total=${exfil_total} (expected >= 80)" >&2
    threshold_failure=1
  fi
  if [[ "$declassify_total" -lt 30 ]]; then
    echo "IFC gate failure: declassify_total=${declassify_total} (expected >= 30)" >&2
    threshold_failure=1
  fi

  if [[ "$threshold_failure" -ne 0 ]]; then
    failed_command="ifc_release_gate_threshold_validation"
    return 1
  fi

  return 0
}

run_gate() {
  run_step "cargo run -p frankenengine-engine --bin franken_ifc_conformance_runner -- --manifest crates/franken-engine/tests/conformance/ifc_corpus/ifc_conformance_assets.json --output-root ${ifc_output_root}" \
    run_rch cargo run -p frankenengine-engine --bin franken_ifc_conformance_runner -- \
      --manifest crates/franken-engine/tests/conformance/ifc_corpus/ifc_conformance_assets.json \
      --output-root "$ifc_output_root"

  collect_gate_metrics
  validate_thresholds
}

handle_signal() {
  local signal="$1"
  failed_command="${failed_command:-./scripts/run_ifc_release_gate.sh ${mode} (signal:${signal})}"
  write_manifest 130
  exit 130
}

run_mode() {
  case "$mode" in
    check)
      run_check
      ;;
    test)
      run_test
      ;;
    clippy)
      run_clippy
      ;;
    gate)
      run_gate
      ;;
    ci)
      run_check
      run_test
      run_gate
      run_clippy
      ;;
    *)
      failed_command="./scripts/run_ifc_release_gate.sh ${mode}"
      echo "usage: $0 [check|test|clippy|gate|ci]" >&2
      return 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json idx comma failed_log_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    if [[ -z "$failed_command" ]]; then
      failed_command="./scripts/run_ifc_release_gate.sh ${mode}"
    fi
    case "$failed_command" in
      ifc_release_gate_threshold_validation)
        error_code_json='"FE-IFCR-1001"'
        ;;
      ifc_release_gate_summary_parse)
        error_code_json='"FE-IFCR-1002"'
        ;;
      *)
        error_code_json='"FE-IFCR-1003"'
        ;;
    esac
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  if [[ -n "$failed_log_path" ]]; then
    failed_log_json="\"$(json_escape "$failed_log_path")\""
  else
    failed_log_json="null"
  fi

  cat >"$events_path" <<JSONL
{"trace_id":"${trace_id}","decision_id":"${decision_id}","policy_id":"${policy_id}","component":"${component}","event":"suite_completed","outcome":"${outcome}","error_code":${error_code_json},"ci_blocking_failures":${ci_blocking_failures},"false_positive_count":${false_positive_count},"false_negative_direct_indirect_count":${false_negative_direct_indirect_count}}
JSONL

  {
    echo "{"
    echo '  "schema_version": "franken-engine.ifc-release-gate.run-manifest.v1",'
    echo "  \"component\": \"${component}\","
    echo "  \"bead_id\": \"${bead_id}\","
    echo "  \"mode\": \"$(json_escape "$mode")\","
    echo "  \"generated_at_utc\": \"$(json_escape "$timestamp")\","
    echo "  \"toolchain\": \"$(json_escape "$toolchain")\","
    echo "  \"cargo_target_dir\": \"$(json_escape "$target_dir")\","
    echo "  \"trace_id\": \"$(json_escape "$trace_id")\","
    echo "  \"decision_id\": \"$(json_escape "$decision_id")\","
    echo "  \"policy_id\": \"$(json_escape "$policy_id")\","
    echo "  \"outcome\": \"$(json_escape "$outcome")\","
    echo "  \"failed_command\": \"$(json_escape "$failed_command")\","
    echo "  \"failed_log\": ${failed_log_json},"
    echo '  "thresholds": {'
    echo '    "ci_blocking_failures": 0,'
    echo '    "false_positive_count": 0,'
    echo '    "false_negative_count": 0,'
    echo '    "false_negative_direct_indirect_count": 0,'
    echo '    "benign_total_min": 100,'
    echo '    "exfil_total_min": 80,'
    echo '    "declassify_total_min": 30'
    echo '  },'
    echo '  "observed_metrics": {'
    echo "    \"ci_blocking_failures\": ${ci_blocking_failures},"
    echo "    \"false_positive_count\": ${false_positive_count},"
    echo "    \"false_negative_count\": ${false_negative_count},"
    echo "    \"false_negative_direct_indirect_count\": ${false_negative_direct_indirect_count},"
    echo "    \"benign_total\": ${benign_total},"
    echo "    \"exfil_total\": ${exfil_total},"
    echo "    \"declassify_total\": ${declassify_total}"
    echo '  },'
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "command_logs": ['
    for idx in "${!command_logs[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#command_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${command_logs[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"$(json_escape "$manifest_path")\","
    echo "    \"events\": \"$(json_escape "$events_path")\","
    echo "    \"commands\": \"$(json_escape "$commands_path")\","
    echo "    \"ifc_summary\": \"$(json_escape "$summary_path")\","
    echo '    "suite_script": "scripts/run_ifc_release_gate.sh",'
    echo "    \"suite_replay\": \"$(json_escape "$replay_command")\","
    echo '    "gate_test": "crates/franken-engine/tests/ifc_release_gate.rs",'
    echo '    "runtime_guard_source": "crates/franken-engine/src/execution_orchestrator.rs",'
    echo '    "runner_bin": "crates/franken-engine/src/bin/franken_ifc_conformance_runner.rs",'
    echo '    "runbook": "artifacts/ifc_release_gate/README.md"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat $(json_escape "$manifest_path")\","
    echo "    \"cat $(json_escape "$events_path")\","
    echo "    \"cat $(json_escape "$commands_path")\","
    echo '    "./scripts/run_ifc_release_gate.sh test",'
    echo "    \"$(json_escape "$replay_command")\","
    echo "    \"${0} gate\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "ifc release gate run manifest: ${manifest_path}"
  echo "ifc release gate events: ${events_path}"
}

trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM
trap 'write_manifest $?' EXIT
run_mode
