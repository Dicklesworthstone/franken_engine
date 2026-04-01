#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_cross_repo_integration}"
artifact_root="${CROSS_REPO_INTEGRATION_ARTIFACT_ROOT:-artifacts/cross_repo_integration_suite}"
asupersync_root="${ASUPERSYNC_ROOT:-/dp/asupersync}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

trace_id="trace-cross-repo-integration-suite-${timestamp}"
decision_id="decision-cross-repo-integration-suite-${timestamp}"
policy_id="policy-cross-repo-integration-suite-v1"
component="cross_repo_integration_suite"
bead_id="bd-1mgd"
failure_code="FE-XREPO-INT-0001"

mkdir -p "$run_dir"

run_rch() {
  if ! command -v rch >/dev/null 2>&1; then
    echo "error: rch is required for this suite" >&2
    exit 3
  fi
  rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
}

declare -a commands_run=()
failed_step=""
failed_boundary=""
failed_command=""
manifest_written=false
mode_completed=false

append_event() {
  local event_name="$1"
  local outcome="$2"
  local error_code_json="$3"
  local boundary="$4"
  local step_name="$5"
  printf '%s\n' \
    "{\"schema_version\":\"franken-engine.cross-repo-integration-suite.log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"${event_name}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json},\"boundary\":\"${boundary}\",\"step\":\"${step_name}\"}" \
    >>"$events_path"
}

run_step() {
  local step_name="$1"
  local boundary="$2"
  local command_text="$3"
  shift 3

  commands_run+=("$command_text")
  echo "==> $command_text"
  if ! run_rch "$@"; then
    failed_step="$step_name"
    failed_boundary="$boundary"
    failed_command="$command_text"
    append_event "step_failed" "fail" "\"${failure_code}\"" "$boundary" "$step_name"
    return 1
  fi

  append_event "step_completed" "pass" "null" "$boundary" "$step_name"
}

run_host_step() {
  local step_name="$1"
  local boundary="$2"
  local command_text="$3"
  shift 3

  commands_run+=("$command_text")
  echo "==> $command_text"
  if ! "$@"; then
    failed_step="$step_name"
    failed_boundary="$boundary"
    failed_command="$command_text"
    append_event "step_failed" "fail" "\"${failure_code}\"" "$boundary" "$step_name"
    return 1
  fi

  append_event "step_completed" "pass" "null" "$boundary" "$step_name"
}

run_check_mode() {
  run_step \
    "targeted_check" \
    "suite" \
    "cargo check -p frankenengine-engine --test cross_repo_integration_suite --test cross_repo_contract_integration --test cross_repo_contract_enrichment_integration --test cross_repo_contract_edge_cases --test asupersync_contract_matrix_integration --test asupersync_contract_matrix_enrichment_integration --test frankentui_adapter_integration --test frankentui_adapter_enrichment_integration --test storage_adapter_integration --test storage_adapter_enrichment_integration --test service_endpoint_template_integration --test sibling_integration_benchmark_gate_integration --test sqlmodel_rust_boundary" \
    cargo check -p frankenengine-engine \
      --test cross_repo_integration_suite \
      --test cross_repo_contract_integration \
      --test cross_repo_contract_enrichment_integration \
      --test cross_repo_contract_edge_cases \
      --test asupersync_contract_matrix_integration \
      --test asupersync_contract_matrix_enrichment_integration \
      --test frankentui_adapter_integration \
      --test frankentui_adapter_enrichment_integration \
      --test storage_adapter_integration \
      --test storage_adapter_enrichment_integration \
      --test service_endpoint_template_integration \
      --test sibling_integration_benchmark_gate_integration \
      --test sqlmodel_rust_boundary
}

run_test_mode() {
  run_step "suite_contract" "suite" \
    "cargo test -p frankenengine-engine --test cross_repo_integration_suite" \
    cargo test -p frankenengine-engine --test cross_repo_integration_suite
  run_step "shared_contracts_primary" "shared_contracts" \
    "cargo test -p frankenengine-engine --test cross_repo_contract_integration" \
    cargo test -p frankenengine-engine --test cross_repo_contract_integration
  run_step "shared_contracts_enrichment" "shared_contracts" \
    "cargo test -p frankenengine-engine --test cross_repo_contract_enrichment_integration" \
    cargo test -p frankenengine-engine --test cross_repo_contract_enrichment_integration
  run_step "shared_contracts_edge_cases" "shared_contracts" \
    "cargo test -p frankenengine-engine --test cross_repo_contract_edge_cases" \
    cargo test -p frankenengine-engine --test cross_repo_contract_edge_cases
  run_step "asupersync_primary" "asupersync" \
    "cargo test -p frankenengine-engine --test asupersync_contract_matrix_integration" \
    cargo test -p frankenengine-engine --test asupersync_contract_matrix_integration
  run_step "asupersync_enrichment" "asupersync" \
    "cargo test -p frankenengine-engine --test asupersync_contract_matrix_enrichment_integration" \
    cargo test -p frankenengine-engine --test asupersync_contract_matrix_enrichment_integration
  run_host_step "asupersync_bundle" "asupersync" \
    "env CARGO_TARGET_DIR=${target_dir}_asupersync_matrix ./scripts/e2e/run_asupersync_contract_matrix.sh ${run_dir}/asupersync_contract_matrix ${asupersync_root}" \
    env "CARGO_TARGET_DIR=${target_dir}_asupersync_matrix" \
      ./scripts/e2e/run_asupersync_contract_matrix.sh \
      "${run_dir}/asupersync_contract_matrix" \
      "${asupersync_root}"
  run_step "frankentui_primary" "frankentui" \
    "cargo test -p frankenengine-engine --test frankentui_adapter_integration" \
    cargo test -p frankenengine-engine --test frankentui_adapter_integration
  run_step "frankentui_enrichment" "frankentui" \
    "cargo test -p frankenengine-engine --test frankentui_adapter_enrichment_integration" \
    cargo test -p frankenengine-engine --test frankentui_adapter_enrichment_integration
  run_step "frankensqlite_primary" "frankensqlite" \
    "cargo test -p frankenengine-engine --test storage_adapter_integration" \
    cargo test -p frankenengine-engine --test storage_adapter_integration
  run_step "frankensqlite_enrichment" "frankensqlite" \
    "cargo test -p frankenengine-engine --test storage_adapter_enrichment_integration" \
    cargo test -p frankenengine-engine --test storage_adapter_enrichment_integration
  run_step "fastapi_service_endpoints" "fastapi_rust" \
    "cargo test -p frankenengine-engine --test service_endpoint_template_integration" \
    cargo test -p frankenengine-engine --test service_endpoint_template_integration
  run_step "sqlmodel_boundary" "sqlmodel_rust" \
    "cargo test -p frankenengine-engine --test sqlmodel_rust_boundary" \
    cargo test -p frankenengine-engine --test sqlmodel_rust_boundary
  run_step "sibling_benchmark_guard" "shared_contracts" \
    "cargo test -p frankenengine-engine --test sibling_integration_benchmark_gate_integration" \
    cargo test -p frankenengine-engine --test sibling_integration_benchmark_gate_integration
}

run_clippy_mode() {
  run_step \
    "targeted_clippy" \
    "suite" \
    "cargo clippy -p frankenengine-engine --test cross_repo_integration_suite --test cross_repo_contract_integration --test cross_repo_contract_enrichment_integration --test cross_repo_contract_edge_cases --test asupersync_contract_matrix_integration --test asupersync_contract_matrix_enrichment_integration --test frankentui_adapter_integration --test frankentui_adapter_enrichment_integration --test storage_adapter_integration --test storage_adapter_enrichment_integration --test service_endpoint_template_integration --test sibling_integration_benchmark_gate_integration --test sqlmodel_rust_boundary -- -D warnings" \
    cargo clippy -p frankenengine-engine \
      --test cross_repo_integration_suite \
      --test cross_repo_contract_integration \
      --test cross_repo_contract_enrichment_integration \
      --test cross_repo_contract_edge_cases \
      --test asupersync_contract_matrix_integration \
      --test asupersync_contract_matrix_enrichment_integration \
      --test frankentui_adapter_integration \
      --test frankentui_adapter_enrichment_integration \
      --test storage_adapter_integration \
      --test storage_adapter_enrichment_integration \
      --test service_endpoint_template_integration \
      --test sibling_integration_benchmark_gate_integration \
      --test sqlmodel_rust_boundary \
      -- -D warnings
}

run_mode() {
  case "$mode" in
    check)
      run_check_mode
      ;;
    test)
      run_test_mode
      ;;
    clippy)
      run_clippy_mode
      ;;
    ci)
      run_check_mode
      run_test_mode
      run_clippy_mode
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac

  mode_completed=true
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 && "$mode_completed" == true ]]; then
    outcome="pass"
    error_code_json='null'
  else
    outcome="fail"
    error_code_json="\"${failure_code}\""
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  append_event "suite_completed" "$outcome" "$error_code_json" "suite" "$mode"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.cross-repo-integration-suite.run-manifest.v1",'
    echo "  \"component\": \"${component}\","
    echo "  \"bead_id\": \"${bead_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"asupersync_root\": \"${asupersync_root}\","
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"mode_completed\": ${mode_completed},"
    echo "  \"commands_executed\": ${#commands_run[@]},"
    if [[ -n "$failed_step" ]]; then
      echo "  \"failed_step\": \"${failed_step}\","
      echo "  \"failed_boundary\": \"${failed_boundary}\","
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    echo '  "boundaries": ['
    echo '    "asupersync",'
    echo '    "frankentui",'
    echo '    "frankensqlite",'
    echo '    "fastapi_rust",'
    echo '    "sqlmodel_rust"'
    echo '  ],'
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"asupersync_contract_matrix\": \"${run_dir}/asupersync_contract_matrix\""
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"./scripts/e2e/cross_repo_integration_suite_replay.sh ${mode}\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "cross-repo integration manifest: $manifest_path"
  echo "cross-repo integration events: $events_path"
}

append_event "suite_started" "start" "null" "suite" "$mode"
trap 'write_manifest $?' EXIT
run_mode
