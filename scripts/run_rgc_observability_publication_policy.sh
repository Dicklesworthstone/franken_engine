#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/data/projects/franken_engine/target_rch_rgc_observability_publication_policy}"
artifact_root="${RGC_OBSERVABILITY_PUBLICATION_POLICY_ARTIFACT_ROOT:-artifacts/rgc_observability_publication_policy}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids"
step_logs_dir="${run_dir}/step_logs"

budget_report_path="${run_dir}/observability_budget_sentinel_report.json"
supremacy_matrix_path="${run_dir}/observability_on_supremacy_matrix.json"
claim_delta_path="${run_dir}/observability_claim_delta_report.json"
demotion_receipts_path="${run_dir}/telemetry_demotion_receipts.json"
publication_policy_path="${run_dir}/observability_publication_policy.json"
attestation_path="${run_dir}/support_bundle_observability_attestation.json"

trace_id="trace-rgc-observability-publication-policy-${timestamp}"
decision_id="decision-rgc-observability-publication-policy-${timestamp}"
policy_id="policy-rgc-observability-publication-v1"
component="rgc_observability_publication_policy_gate"
scenario_id="rgc-066c"
replay_command="RGC_OBSERVABILITY_PUBLICATION_POLICY_REPLAY_RUN_DIR=\"${run_dir}\" ./scripts/e2e/rgc_observability_publication_policy_replay.sh ${mode}"
first_step_log_path="${step_logs_dir}/step-01.log"

if [[ "$run_dir" = /* ]]; then
  run_dir_abs="${run_dir}"
else
  run_dir_abs="${root_dir}/${run_dir}"
fi

mkdir -p "$run_dir" "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC observability publication policy heavy commands" >&2
  exit 2
fi

join_command() {
  local rendered=""
  local arg

  for arg in "$@"; do
    if [[ -n "$rendered" ]]; then
      rendered+=" "
    fi
    printf -v rendered '%s%q' "$rendered" "$arg"
  done

  printf '%s' "$rendered"
}

run_rch_command() {
  # Keep the cargo command direct so rch classifies and offloads it instead of
  # treating a shell wrapper as an unclassified local command.
  timeout "${rch_timeout_seconds}" \
    rch exec -q -- env RUSTUP_TOOLCHAIN="${toolchain}" CARGO_TARGET_DIR="${target_dir}" "$@"
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

emit_operator_verification_entry() {
  local command_text="$1"
  local suffix="${2:-}"
  echo "    \"$(parser_frontier_json_escape "${command_text}")\"${suffix}"
}

run_step() {
  local command_text log_path step_index

  command_text="$(join_command "$@")"

  commands_run+=("$command_text")
  echo "==> $command_text"

  step_index="${#commands_run[@]}"
  log_path="${step_logs_dir}/step-$(printf '%02d' "${step_index}").log"
  if ! run_rch_command "$@" > >(tee "$log_path") 2>&1; then
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
  local -a bundle_cmd=(
    cargo run
    --manifest-path "${root_dir}/Cargo.toml"
    -p frankenengine-engine
    --bin franken_observability_publication_bundle
    --
    --out-dir "${run_dir_abs}"
  )
  local -a check_cmd=(
    cargo check
    --manifest-path "${root_dir}/Cargo.toml"
    -p frankenengine-engine
    --bin franken_observability_publication_bundle
    --test observability_publication_bundle_integration
  )
  local -a test_cmd=(
    cargo test
    --manifest-path "${root_dir}/Cargo.toml"
    -p frankenengine-engine
    --test observability_publication_bundle_integration
  )
  local -a clippy_cmd=(
    cargo clippy
    --manifest-path "${root_dir}/Cargo.toml"
    -p frankenengine-engine
    --bin franken_observability_publication_bundle
    --test observability_publication_bundle_integration
    --
    -D warnings
  )

  case "$mode" in
    bundle)
      run_step "${bundle_cmd[@]}"
      ;;
    check)
      run_step "${bundle_cmd[@]}"
      run_step "${check_cmd[@]}"
      ;;
    test)
      run_step "${bundle_cmd[@]}"
      run_step "${test_cmd[@]}"
      ;;
    clippy)
      run_step "${bundle_cmd[@]}"
      run_step "${clippy_cmd[@]}"
      ;;
    ci)
      run_step "${bundle_cmd[@]}"
      run_step "${check_cmd[@]}"
      run_step "${test_cmd[@]}"
      run_step "${clippy_cmd[@]}"
      ;;
    *)
      echo "usage: $0 [bundle|check|test|clippy|ci]" >&2
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
    error_code_json='"FE-RGC-066C-GATE-0001"'
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
    echo "{\"schema_version\":\"rgc.observability-publication-policy.gate.event.v1\",\"scenario_id\":\"${scenario_id}\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"runtime_lane\":\"observability_publication\",\"seed\":\"fixed-observability-publication-seed-v1\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "rgc.observability-publication-policy.gate.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.11.20.3",'
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
    echo "    \"first_step_log\": \"${first_step_log_path}\","
    echo "    \"observability_budget_sentinel_report\": \"${budget_report_path}\","
    echo "    \"observability_on_supremacy_matrix\": \"${supremacy_matrix_path}\","
    echo "    \"observability_claim_delta_report\": \"${claim_delta_path}\","
    echo "    \"telemetry_demotion_receipts\": \"${demotion_receipts_path}\","
    echo "    \"observability_publication_policy\": \"${publication_policy_path}\","
    echo "    \"support_bundle_observability_attestation\": \"${attestation_path}\""
    echo '  },'
    echo '  "operator_verification": ['
    emit_operator_verification_entry "cat \"${manifest_path}\"" ","
    emit_operator_verification_entry "cat \"${events_path}\"" ","
    emit_operator_verification_entry "cat \"${commands_path}\"" ","
    emit_operator_verification_entry "cat \"${trace_ids_path}\"" ","
    emit_operator_verification_entry "ls \"${step_logs_dir}\"" ","
    emit_operator_verification_entry "cat \"${first_step_log_path}\"" ","
    emit_operator_verification_entry "cat \"${budget_report_path}\"" ","
    emit_operator_verification_entry "cat \"${supremacy_matrix_path}\"" ","
    emit_operator_verification_entry "cat \"${claim_delta_path}\"" ","
    emit_operator_verification_entry "cat \"${demotion_receipts_path}\"" ","
    emit_operator_verification_entry "cat \"${publication_policy_path}\"" ","
    emit_operator_verification_entry "cat \"${attestation_path}\"" ","
    emit_operator_verification_entry "${replay_command}"
    echo '  ]'
    echo "}"
  } >"$manifest_path"
}

on_exit() {
  local exit_code="$1"
  write_manifest "$exit_code"
}

trap 'on_exit $?' EXIT

run_mode
