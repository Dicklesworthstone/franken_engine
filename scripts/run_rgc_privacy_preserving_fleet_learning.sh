#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root="${RGC_PRIVACY_PRESERVING_FLEET_LEARNING_ARTIFACT_ROOT:-artifacts/rgc_privacy_preserving_fleet_learning}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-1200}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
# Use a stable gate target dir by default so rch workers can reuse incremental
# artifacts across runs instead of recompiling from a cold directory each time.
default_target_dir="/data/projects/franken_engine/target_rch_rgc_privacy_preserving_fleet_learning"
target_dir="${CARGO_TARGET_DIR:-${default_target_dir}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

trace_id="trace-rgc-privacy-preserving-fleet-learning-${timestamp}"
decision_id="decision-rgc-privacy-preserving-fleet-learning-${timestamp}"
policy_id="policy-rgc-privacy-preserving-fleet-learning-v1"
component="rgc_privacy_preserving_fleet_learning_gate"
scenario_id="rgc-privacy-t4"
replay_command="./scripts/e2e/rgc_privacy_preserving_fleet_learning_replay.sh ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC privacy-preserving fleet learning heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rg -o 'Remote command finished: exit=[0-9]+' "$log_path" | tail -n 1 || true)"
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
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path remote_exit_code
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="$(mktemp "${run_dir}/rch-log.XXXXXX")"

  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    if rg -q "Remote command finished: exit=0" "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" \
        | tee -a "$log_path"
    else
      rm -f "$log_path"
      failed_command="$command_text"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    rm -f "$log_path"
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -n "$remote_exit_code" && "$remote_exit_code" != "0" ]]; then
    rm -f "$log_path"
    failed_command="${command_text} (remote-exit=${remote_exit_code})"
    return 1
  fi

  rm -f "$log_path"
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --lib --test privacy_preserving_fleet_learning_integration" \
        cargo check -p frankenengine-engine --lib --test privacy_preserving_fleet_learning_integration
      run_step "cargo check -p dp" \
        cargo check -p dp
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test privacy_preserving_fleet_learning_integration" \
        cargo test -p frankenengine-engine --test privacy_preserving_fleet_learning_integration
      run_step "cargo test -p frankenengine-engine --lib federated_posterior_aggregation::tests::" \
        cargo test -p frankenengine-engine --lib federated_posterior_aggregation::tests::
      run_step "cargo test -p frankenengine-engine --lib differential_privacy_posterior::tests::" \
        cargo test -p frankenengine-engine --lib differential_privacy_posterior::tests::
      run_step "cargo test -p dp --lib" \
        cargo test -p dp --lib
      run_step "cargo test -p dp --test secure_aggregation_integration" \
        cargo test -p dp --test secure_aggregation_integration
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test privacy_preserving_fleet_learning_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test privacy_preserving_fleet_learning_integration -- -D warnings
      run_step "cargo clippy -p dp -- -D warnings" \
        cargo clippy -p dp -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --lib --test privacy_preserving_fleet_learning_integration" \
        cargo check -p frankenengine-engine --lib --test privacy_preserving_fleet_learning_integration
      run_step "cargo check -p dp" \
        cargo check -p dp
      run_step "cargo test -p frankenengine-engine --test privacy_preserving_fleet_learning_integration" \
        cargo test -p frankenengine-engine --test privacy_preserving_fleet_learning_integration
      run_step "cargo test -p frankenengine-engine --lib federated_posterior_aggregation::tests::" \
        cargo test -p frankenengine-engine --lib federated_posterior_aggregation::tests::
      run_step "cargo test -p frankenengine-engine --lib differential_privacy_posterior::tests::" \
        cargo test -p frankenengine-engine --lib differential_privacy_posterior::tests::
      run_step "cargo test -p dp --lib" \
        cargo test -p dp --lib
      run_step "cargo test -p dp --test secure_aggregation_integration" \
        cargo test -p dp --test secure_aggregation_integration
      run_step "cargo clippy -p frankenengine-engine --test privacy_preserving_fleet_learning_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test privacy_preserving_fleet_learning_integration -- -D warnings
      run_step "cargo clippy -p dp -- -D warnings" \
        cargo clippy -p dp -- -D warnings
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
    error_code_json='"FE-RGC-PRIVACY-T4-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  # Privacy-specific event logging: NO individual peer contribution contents
  {
    echo "{\"schema_version\":\"franken-engine.rgc-privacy-preserving-fleet-learning.gate.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json},\"privacy_invariant\":\"no_individual_peer_data_logged\"}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-privacy-preserving-fleet-learning.gate.run-manifest.v1",'
    echo '  "bead_id": "bd-cixqu.20.4",'
    echo "  \"component\": \"${component}\","
    echo "  \"scenario_id\": \"${scenario_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"error_code\": ${error_code_json},"
    echo "  \"privacy_guarantees\": {"
    echo "    \"federated_posterior_aggregation\": \"individual_contributions_hidden\","
    echo "    \"differential_privacy\": \"epsilon_delta_noise_injection\","
    echo "    \"secure_aggregation\": \"cryptographic_individual_masking\","
    echo "    \"logging_discipline\": \"no_peer_content_logged\""
    echo "  },"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\","
    fi
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo "  },"
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\","
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo "  ],"
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo '    "federated_aggregation_module": "crates/franken-engine/src/federated_posterior_aggregation.rs",'
    echo '    "differential_privacy_module": "crates/franken-engine/src/differential_privacy_posterior.rs",'
    echo '    "secure_aggregation_crate": "crates/dp/",'
    echo '    "integration_tests": "crates/franken-engine/tests/privacy_preserving_fleet_learning_integration.rs",'
    echo '    "dp_integration_tests": "crates/franken-engine/tests/differential_privacy_posterior_integration.rs",'
    echo '    "federated_integration_tests": "crates/franken-engine/tests/federated_posterior_aggregation_integration.rs",'
    echo '    "secure_aggregation_tests": "crates/dp/tests/secure_aggregation_integration.rs",'
    echo '    "replay_wrapper": "scripts/e2e/rgc_privacy_preserving_fleet_learning_replay.sh"'
    echo "  },"
    echo '  "privacy_audit": {'
    echo '    "epsilon_delta_parameters": "configurable_per_aggregation_round",'
    echo '    "privacy_budget_tracking": "enforced_with_budget_exhaustion_protection",'
    echo '    "secure_aggregation_primitive": "bonawitz_2017_cryptographic_masking",'
    echo '    "individual_data_isolation": "three_layer_protection",'
    echo '    "logging_compliance": "no_peer_contributions_in_logs"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "rgc privacy-preserving fleet learning manifest: ${manifest_path}"
  echo "rgc privacy-preserving fleet learning events: ${events_path}"
  echo "Privacy invariant: no individual peer contribution contents logged"
}

main_exit=0

emit_manifest_on_exit() {
  local trap_exit="$?"
  local exit_code

  # Keep the original script exit code while still emitting triage artifacts.
  set +e
  exit_code="${main_exit}"
  if [[ "$exit_code" -eq 0 && "$trap_exit" -ne 0 ]]; then
    exit_code="$trap_exit"
  fi
  write_manifest "$exit_code" || true
}

trap emit_manifest_on_exit EXIT

run_mode || main_exit=$?
exit "$main_exit"