#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_test262_gate}"
artifact_root="${TEST262_GATE_ARTIFACT_ROOT:-artifacts/test262_es2020_gate}"
timestamp="$(date -u +"%Y%m%dT%H%M%SZ")"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/test262_gate_events.jsonl"
commands_path="${run_dir}/commands.txt"
logs_dir="${run_dir}/logs"

trace_id="trace-test262-gate-${timestamp}"
decision_id="decision-test262-gate-${timestamp}"
policy_id="policy-test262-es2020"
component="test262_es2020_gate_runner"
bead_id="${TEST262_GATE_BEAD_ID:-bd-11p}"
run_date="$(date -u +%Y-%m-%d)"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
pins_path="crates/franken-engine/tests/test262_conformance_pins.toml"
profile_path="crates/franken-engine/tests/test262_es2020_profile.toml"
waivers_path="crates/franken-engine/tests/test262_conformance_waivers.toml"
case_vectors_path="crates/franken-engine/tests/test262_case_vectors.jsonl"
runner_output_root="${run_dir}/test262_runner"
canonical_hwm_path="${run_dir}/test262_hwm.json"

mkdir -p "$logs_dir"

run_rch() {
  timeout "${rch_timeout_seconds}" rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
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
runner_manifest_path=""
runner_evidence_path=""
runner_hwm_path=""
runner_canonical_hwm_path=""
runner_case_execution_path=""

run_step() {
  local command_text="$1"
  shift
  local step_index="${#commands_run[@]}"
  local log_path="${logs_dir}/step_$(printf '%02d' "$step_index").log"
  commands_run+=("$command_text")
  command_logs+=("$log_path")
  echo "==> $command_text"
  if "$@" > >(tee "$log_path") 2>&1; then
    return 0
  fi

  if rg -q "Remote command finished: exit=0" "$log_path"; then
    echo "==> recovered: remote execution succeeded; artifact retrieval timed out" \
      | tee -a "$log_path"
    return 0
  fi

  failed_command="$command_text"
  failed_log_path="$log_path"
  return 1
}

run_check() {
  run_step "cargo check -p frankenengine-engine --test test262_release_gate" \
    run_rch cargo check -p frankenengine-engine --test test262_release_gate
  run_step "cargo check -p frankenengine-engine --bin franken_test262_runner" \
    run_rch cargo check -p frankenengine-engine --bin franken_test262_runner
}

run_test() {
  run_step "cargo test -p frankenengine-engine --test test262_release_gate" \
    run_rch cargo test -p frankenengine-engine --test test262_release_gate
  run_step "cargo test -p frankenengine-engine --bin franken_test262_runner" \
    run_rch cargo test -p frankenengine-engine --bin franken_test262_runner
  run_step "cargo run -p frankenengine-engine --bin franken_test262_runner -- --pins ${pins_path} --profile ${profile_path} --waivers ${waivers_path} --case-vectors ${case_vectors_path} --output-root ${runner_output_root} --high-water-mark ${canonical_hwm_path} --run-date ${run_date}" \
    run_rch cargo run -p frankenengine-engine --bin franken_test262_runner -- \
      --pins "${pins_path}" \
      --profile "${profile_path}" \
      --waivers "${waivers_path}" \
      --case-vectors "${case_vectors_path}" \
      --output-root "${runner_output_root}" \
      --high-water-mark "${canonical_hwm_path}" \
      --run-date "${run_date}"

  local runner_log_path="${command_logs[$(( ${#command_logs[@]} - 1 ))]}"
  runner_manifest_path="$(rg -o 'test262 run_manifest=.*' "$runner_log_path" | tail -n 1 | sed 's/.*test262 run_manifest=//')"
  runner_evidence_path="$(rg -o 'test262 evidence=.*' "$runner_log_path" | tail -n 1 | sed 's/.*test262 evidence=//')"
  runner_hwm_path="$(rg -o 'test262 high_water_mark=.*' "$runner_log_path" | tail -n 1 | sed 's/.*test262 high_water_mark=//')"
  runner_canonical_hwm_path="$(rg -o 'test262 canonical_high_water_mark=.*' "$runner_log_path" | tail -n 1 | sed 's/.*test262 canonical_high_water_mark=//')"
  runner_case_execution_path="$(rg -o 'test262 case_execution=.*' "$runner_log_path" | tail -n 1 | sed 's/.*test262 case_execution=//')"
  if [[ -n "$runner_canonical_hwm_path" ]]; then
    canonical_hwm_path="$runner_canonical_hwm_path"
  fi

  # Check gate result for release blocking
  local gate_blocked="$(rg -o 'test262 blocked=.*' "$runner_log_path" | tail -n 1 | sed 's/.*test262 blocked=//')"
  if [[ "$gate_blocked" == "true" ]]; then
    echo "==> RELEASE BLOCKED: test262 ES2020 conformance gate failed" >&2
    echo "==> See gate output in: ${runner_log_path}" >&2
    return 1
  fi

  if [[ -z "$runner_manifest_path" || -z "$runner_evidence_path" || -z "$runner_hwm_path" ]]; then
    echo "runner artifact discovery failed from ${runner_log_path}" >&2
    return 1
  fi
}

run_clippy() {
  run_step "cargo clippy -p frankenengine-engine --test test262_release_gate -- -D warnings" \
    run_rch cargo clippy -p frankenengine-engine --test test262_release_gate -- -D warnings
  run_step "cargo clippy -p frankenengine-engine --bin franken_test262_runner -- -D warnings" \
    run_rch cargo clippy -p frankenengine-engine --bin franken_test262_runner -- -D warnings
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
    ci)
      run_check
      run_test
      run_clippy
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      return 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code failed_log_json runner_manifest_json runner_evidence_json
  local runner_hwm_json canonical_hwm_json runner_case_execution_json idx comma

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code="null"
  elif [[ -n "$failed_log_path" ]] && rg -q "test262 blocked=true" "$failed_log_path"; then
    outcome="blocked"
    error_code='"FE-T262-1005"'
  else
    outcome="fail"
    error_code='"FE-T262-1008"'
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  if [[ -n "$failed_log_path" ]]; then
    failed_log_json="\"$(json_escape "$failed_log_path")\""
  else
    failed_log_json="null"
  fi

  if [[ -n "$runner_manifest_path" ]]; then
    runner_manifest_json="\"$(json_escape "$runner_manifest_path")\""
  else
    runner_manifest_json="null"
  fi

  if [[ -n "$runner_evidence_path" ]]; then
    runner_evidence_json="\"$(json_escape "$runner_evidence_path")\""
  else
    runner_evidence_json="null"
  fi

  if [[ -n "$runner_hwm_path" ]]; then
    runner_hwm_json="\"$(json_escape "$runner_hwm_path")\""
  else
    runner_hwm_json="null"
  fi

  if [[ -n "$runner_canonical_hwm_path" ]]; then
    canonical_hwm_json="\"$(json_escape "$runner_canonical_hwm_path")\""
  else
    canonical_hwm_json="null"
  fi

  if [[ -n "$runner_case_execution_path" ]]; then
    runner_case_execution_json="\"$(json_escape "$runner_case_execution_path")\""
  else
    runner_case_execution_json="null"
  fi

  cat >"$events_path" <<JSONL
{"trace_id":"${trace_id}","decision_id":"${decision_id}","policy_id":"${policy_id}","component":"${component}","event":"suite_completed","outcome":"${outcome}","error_code":${error_code}}
JSONL

  {
    echo "{";
    echo '  "schema_version": "franken-engine.test262-gate.run-manifest.v2",';
    echo "  \"bead_id\": \"${bead_id}\",";
    echo "  \"timestamp_utc\": \"$(json_escape "$timestamp")\",";
    echo "  \"mode\": \"$(json_escape "$mode")\",";
    echo "  \"toolchain\": \"$(json_escape "$toolchain")\",";
    echo "  \"cargo_target_dir\": \"$(json_escape "$target_dir")\",";
    echo "  \"run_date\": \"$(json_escape "$run_date")\",";
    echo "  \"trace_id\": \"$(json_escape "$trace_id")\",";
    echo "  \"decision_id\": \"$(json_escape "$decision_id")\",";
    echo "  \"policy_id\": \"$(json_escape "$policy_id")\",";
    echo "  \"outcome\": \"$(json_escape "$outcome")\",";
    echo "  \"failed_command\": \"$(json_escape "$failed_command")\",";
    echo "  \"failed_log\": ${failed_log_json},";
    echo '  "fixture_inputs": {';
    echo "    \"pins\": \"$(json_escape "$pins_path")\",";
    echo "    \"profile\": \"$(json_escape "$profile_path")\",";
    echo "    \"waivers\": \"$(json_escape "$waivers_path")\",";
    echo "    \"case_vectors\": \"$(json_escape "$case_vectors_path")\"";
    echo '  },';
    echo '  "runner_artifacts": {';
    echo "    \"runner_manifest\": ${runner_manifest_json},";
    echo "    \"runner_evidence\": ${runner_evidence_json},";
    echo "    \"runner_high_water_mark\": ${runner_hwm_json},";
    echo "    \"canonical_high_water_mark\": ${canonical_hwm_json},";
    echo "    \"runner_case_execution\": ${runner_case_execution_json}";
    echo '  },';
    echo '  "commands": [';
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],';
    echo '  "command_logs": [';
    for idx in "${!command_logs[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#command_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${command_logs[$idx]}")\"${comma}"
    done
    echo '  ],';
    echo '  "targets": [';
    echo '    "test262_release_gate",';
    echo '    "franken_test262_runner"';
    echo '  ],';
    echo '  "operator_verification": [';
    echo "    \"cat $(json_escape "$manifest_path")\",";
    echo "    \"cat $(json_escape "$events_path")\",";
    echo "    \"cat $(json_escape "$commands_path")\",";
    echo "    \"find $(json_escape "$runner_output_root") -maxdepth 2 -type f | sort\",";
    echo "    \"cat $(json_escape "$runner_output_root")/*/test262_case_execution.jsonl\",";
    echo "    \"cat $(json_escape "$canonical_hwm_path")\",";
    echo "    \"${0} ci\"";
    echo '  ]';
    echo "}";
  } >"$manifest_path"
}

set +e
run_mode
exit_code=$?
set -e

write_manifest "$exit_code"

echo "test262 gate run manifest: ${manifest_path}"
echo "test262 gate events: ${events_path}"

exit "$exit_code"
