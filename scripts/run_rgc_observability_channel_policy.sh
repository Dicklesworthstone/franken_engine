#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/data/projects/franken_engine/target_rch_rgc_observability_channel_policy}"
artifact_root="${RGC_OBSERVABILITY_CHANNEL_POLICY_ARTIFACT_ROOT:-artifacts/rgc_observability_channel_policy}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids"
step_logs_dir="${run_dir}/step_logs"

contract_json="docs/rgc_observability_channel_policy_v1.json"
contract_doc="docs/RGC_OBSERVABILITY_CHANNEL_POLICY_V1.md"
engine_policy_path="${run_dir}/engine_observability_channel_policy.json"
operator_mode_path="${run_dir}/operator_mode_contract.json"
site_policy_path="${run_dir}/telemetry_site_policy_matrix.json"
sampling_contract_path="${run_dir}/telemetry_sampling_contract.json"
sketch_report_path="${run_dir}/sketch_error_envelope_report.json"
fixture_matrix_path="${run_dir}/sampling_seed_replay_fixture_matrix.json"

trace_id="trace-rgc-observability-channel-policy-${timestamp}"
decision_id="decision-rgc-observability-channel-policy-${timestamp}"
policy_id="policy-rgc-observability-channel-policy-v1"
component="rgc_observability_channel_policy_gate"
scenario_id="rgc-066a"
replay_command="./scripts/e2e/rgc_observability_channel_policy_replay.sh ${mode}"

mkdir -p "$run_dir" "$step_logs_dir"

if [[ ! -f "$contract_doc" || ! -f "$contract_json" ]]; then
  echo "FE-RGC-066A-CONTRACT-0001: missing observability contract inputs" >&2
  exit 1
fi

if ! jq -e '.' "$contract_json" >/dev/null 2>&1; then
  echo "FE-RGC-066A-CONTRACT-0002: failed to parse ${contract_json}" >&2
  exit 1
fi

jq '.engine_observability_channel_policy' "$contract_json" >"$engine_policy_path"
jq '.operator_mode_contract' "$contract_json" >"$operator_mode_path"
jq '.telemetry_site_policy_matrix' "$contract_json" >"$site_policy_path"
jq '.telemetry_sampling_contract' "$contract_json" >"$sampling_contract_path"
jq '.sketch_error_envelope_report' "$contract_json" >"$sketch_report_path"
jq '.sampling_seed_replay_fixture_matrix' "$contract_json" >"$fixture_matrix_path"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC observability channel policy heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" rch exec -q -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path step_index
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"

  step_index="${#commands_run[@]}"
  log_path="${step_logs_dir}/step-$(printf '%02d' "${step_index}").log"
  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    if rg -q "Remote command finished: exit=0" "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" \
        | tee -a "$log_path"
    else
      failed_command="$command_text"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test rgc_observability_channel_policy --test observability_channel_model --test observability_channel_model_integration" \
        cargo check -p frankenengine-engine --test rgc_observability_channel_policy --test observability_channel_model --test observability_channel_model_integration
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test rgc_observability_channel_policy --test observability_channel_model --test observability_channel_model_integration" \
        cargo test -p frankenengine-engine --test rgc_observability_channel_policy --test observability_channel_model --test observability_channel_model_integration
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test rgc_observability_channel_policy --test observability_channel_model --test observability_channel_model_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_observability_channel_policy --test observability_channel_model --test observability_channel_model_integration -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test rgc_observability_channel_policy --test observability_channel_model --test observability_channel_model_integration" \
        cargo check -p frankenengine-engine --test rgc_observability_channel_policy --test observability_channel_model --test observability_channel_model_integration
      run_step "cargo test -p frankenengine-engine --test rgc_observability_channel_policy --test observability_channel_model --test observability_channel_model_integration" \
        cargo test -p frankenengine-engine --test rgc_observability_channel_policy --test observability_channel_model --test observability_channel_model_integration
      run_step "cargo clippy -p frankenengine-engine --test rgc_observability_channel_policy --test observability_channel_model --test observability_channel_model_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_observability_channel_policy --test observability_channel_model --test observability_channel_model_integration -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
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
    error_code_json='"FE-RGC-066A-GATE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  cat >"$trace_ids_path" <<EOF
trace_id=${trace_id}
decision_id=${decision_id}
policy_id=${policy_id}
scenario_id=${scenario_id}
EOF

  {
    echo "{\"schema_version\":\"rgc.observability-channel-policy.gate.event.v1\",\"scenario_id\":\"${scenario_id}\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"runtime_lane\":\"observability_contract\",\"seed\":\"fixed-observability-contract-seed-v1\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "rgc.observability-channel-policy.gate.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.11.20.1",'
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
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"trace_ids\": \"${trace_ids_path}\","
    echo "    \"step_logs\": \"${step_logs_dir}\","
    echo "    \"engine_observability_channel_policy\": \"${engine_policy_path}\","
    echo "    \"operator_mode_contract\": \"${operator_mode_path}\","
    echo "    \"telemetry_site_policy_matrix\": \"${site_policy_path}\","
    echo "    \"telemetry_sampling_contract\": \"${sampling_contract_path}\","
    echo "    \"sketch_error_envelope_report\": \"${sketch_report_path}\","
    echo "    \"sampling_seed_replay_fixture_matrix\": \"${fixture_matrix_path}\","
    echo '    "contract_doc": "docs/RGC_OBSERVABILITY_CHANNEL_POLICY_V1.md",'
    echo '    "contract_json": "docs/rgc_observability_channel_policy_v1.json",'
    echo '    "integration_tests": ['
    echo '      "crates/franken-engine/tests/rgc_observability_channel_policy.rs",'
    echo '      "crates/franken-engine/tests/observability_channel_model.rs",'
    echo '      "crates/franken-engine/tests/observability_channel_model_integration.rs"'
    echo '    ]'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${trace_ids_path}\","
    echo "    \"ls ${step_logs_dir}\","
    echo "    \"cat ${engine_policy_path}\","
    echo "    \"cat ${operator_mode_path}\","
    echo "    \"cat ${site_policy_path}\","
    echo "    \"cat ${sampling_contract_path}\","
    echo "    \"cat ${sketch_report_path}\","
    echo "    \"cat ${fixture_matrix_path}\","
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "rgc observability channel policy manifest: ${manifest_path}"
  echo "rgc observability channel policy events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"
exit "$main_exit"
