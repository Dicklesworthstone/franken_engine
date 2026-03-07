#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
artifact_root="${RGC_CONTINUATION_CLIFF_ATLAS_ARTIFACT_ROOT:-artifacts/rgc_continuation_cliff_atlas}"
rch_timeout_seconds="${RCH_TIMEOUT_SECONDS:-1800}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_rgc_continuation_cliff_atlas_${target_namespace}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

trace_id="trace-rgc-continuation-cliff-atlas-${timestamp}"
decision_id="decision-rgc-continuation-cliff-atlas-${timestamp}"
policy_id="policy-rgc-continuation-cliff-atlas-v1"
component="rgc_continuation_cliff_atlas_gate"
scenario_id="rgc-619"
replay_command="./scripts/run_rgc_continuation_cliff_atlas_suite.sh ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC continuation cliff atlas commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "$@"
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  shift
  commands_run+=("${command_text}")
  echo "==> ${command_text}"
  if ! run_rch "$@"; then
    if [[ -z "$failed_command" ]]; then
      failed_command="${command_text}"
    fi
    return 1
  fi
}

run_mode() {
  local mode_exit=0
  case "$mode" in
    check)
      run_step "cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::evaluate_missing_neighborhoods_are_inconclusive --no-run -- --exact" \
        cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::evaluate_missing_neighborhoods_are_inconclusive --no-run -- --exact || mode_exit=1
      run_step "cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::continuation_cliff_atlas_hash_uses_escape_action_display_contract --no-run -- --exact" \
        cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::continuation_cliff_atlas_hash_uses_escape_action_display_contract --no-run -- --exact || mode_exit=1
      run_step "cargo test -p frankenengine-engine --test catastrophic_tail_tournament_gate_integration evaluate_missing_neighborhood_is_inconclusive_and_emits_witness --no-run -- --exact" \
        cargo test -p frankenengine-engine --test catastrophic_tail_tournament_gate_integration evaluate_missing_neighborhood_is_inconclusive_and_emits_witness --no-run -- --exact || mode_exit=1
      ;;
    test)
      run_step "cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::evaluate_missing_neighborhoods_are_inconclusive -- --exact" \
        cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::evaluate_missing_neighborhoods_are_inconclusive -- --exact || mode_exit=1
      run_step "cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::continuation_cliff_atlas_hash_uses_escape_action_display_contract -- --exact" \
        cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::continuation_cliff_atlas_hash_uses_escape_action_display_contract -- --exact || mode_exit=1
      run_step "cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::near_cliff_margin_emits_warning_witness -- --exact" \
        cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::near_cliff_margin_emits_warning_witness -- --exact || mode_exit=1
      run_step "cargo test -p frankenengine-engine --test catastrophic_tail_tournament_gate_integration evaluate_missing_neighborhood_is_inconclusive_and_emits_witness -- --exact" \
        cargo test -p frankenengine-engine --test catastrophic_tail_tournament_gate_integration evaluate_missing_neighborhood_is_inconclusive_and_emits_witness -- --exact || mode_exit=1
      run_step "cargo test -p frankenengine-engine --test catastrophic_tail_tournament_gate_integration evaluate_near_cliff_band_warns_without_failing -- --exact" \
        cargo test -p frankenengine-engine --test catastrophic_tail_tournament_gate_integration evaluate_near_cliff_band_warns_without_failing -- --exact || mode_exit=1
      ;;
    clippy)
      run_step "env RUSTC_WORKSPACE_WRAPPER=clippy-driver RUSTFLAGS=-Dwarnings cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::evaluate_missing_neighborhoods_are_inconclusive --no-run -- --exact" \
        env RUSTC_WORKSPACE_WRAPPER=clippy-driver RUSTFLAGS=-Dwarnings cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::evaluate_missing_neighborhoods_are_inconclusive --no-run -- --exact || mode_exit=1
      run_step "env RUSTC_WORKSPACE_WRAPPER=clippy-driver RUSTFLAGS=-Dwarnings cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::continuation_cliff_atlas_hash_uses_escape_action_display_contract --no-run -- --exact" \
        env RUSTC_WORKSPACE_WRAPPER=clippy-driver RUSTFLAGS=-Dwarnings cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::continuation_cliff_atlas_hash_uses_escape_action_display_contract --no-run -- --exact || mode_exit=1
      run_step "env RUSTC_WORKSPACE_WRAPPER=clippy-driver RUSTFLAGS=-Dwarnings cargo test -p frankenengine-engine --test catastrophic_tail_tournament_gate_integration --no-run" \
        env RUSTC_WORKSPACE_WRAPPER=clippy-driver RUSTFLAGS=-Dwarnings cargo test -p frankenengine-engine --test catastrophic_tail_tournament_gate_integration --no-run || mode_exit=1
      ;;
    ci)
      run_step "cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::evaluate_missing_neighborhoods_are_inconclusive --no-run -- --exact" \
        cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::evaluate_missing_neighborhoods_are_inconclusive --no-run -- --exact || mode_exit=1
      run_step "cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::continuation_cliff_atlas_hash_uses_escape_action_display_contract --no-run -- --exact" \
        cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::continuation_cliff_atlas_hash_uses_escape_action_display_contract --no-run -- --exact || mode_exit=1
      run_step "cargo test -p frankenengine-engine --test catastrophic_tail_tournament_gate_integration evaluate_missing_neighborhood_is_inconclusive_and_emits_witness --no-run -- --exact" \
        cargo test -p frankenengine-engine --test catastrophic_tail_tournament_gate_integration evaluate_missing_neighborhood_is_inconclusive_and_emits_witness --no-run -- --exact || mode_exit=1
      run_step "cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::evaluate_missing_neighborhoods_are_inconclusive -- --exact" \
        cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::evaluate_missing_neighborhoods_are_inconclusive -- --exact || mode_exit=1
      run_step "cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::continuation_cliff_atlas_hash_uses_escape_action_display_contract -- --exact" \
        cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::continuation_cliff_atlas_hash_uses_escape_action_display_contract -- --exact || mode_exit=1
      run_step "cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::near_cliff_margin_emits_warning_witness -- --exact" \
        cargo test -p frankenengine-engine catastrophic_tail_tournament_gate::tests::near_cliff_margin_emits_warning_witness -- --exact || mode_exit=1
      run_step "cargo test -p frankenengine-engine --test catastrophic_tail_tournament_gate_integration evaluate_missing_neighborhood_is_inconclusive_and_emits_witness -- --exact" \
        cargo test -p frankenengine-engine --test catastrophic_tail_tournament_gate_integration evaluate_missing_neighborhood_is_inconclusive_and_emits_witness -- --exact || mode_exit=1
      run_step "cargo test -p frankenengine-engine --test catastrophic_tail_tournament_gate_integration evaluate_near_cliff_band_warns_without_failing -- --exact" \
        cargo test -p frankenengine-engine --test catastrophic_tail_tournament_gate_integration evaluate_near_cliff_band_warns_without_failing -- --exact || mode_exit=1
      run_step "env RUSTC_WORKSPACE_WRAPPER=clippy-driver RUSTFLAGS=-Dwarnings cargo test -p frankenengine-engine --test catastrophic_tail_tournament_gate_integration --no-run" \
        env RUSTC_WORKSPACE_WRAPPER=clippy-driver RUSTFLAGS=-Dwarnings cargo test -p frankenengine-engine --test catastrophic_tail_tournament_gate_integration --no-run || mode_exit=1
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
  return "$mode_exit"
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json dirty_worktree git_commit idx comma

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-619-GATE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if [[ -z "$(git status --short --untracked-files=normal 2>/dev/null)" ]]; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  printf '%s\n' \
    "{\"schema_version\":\"franken-engine.continuation-cliff-atlas.gate.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}" \
    >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.continuation-cliff-atlas.gate.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.7.19",'
    echo "  \"component\": \"${component}\","
    echo "  \"scenario_id\": \"${scenario_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"error_code\": ${error_code_json},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    echo "  \"replay_command\": \"${replay_command}\","
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo "  ],"
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo '    "contract_doc": "docs/RGC_CONTINUATION_CLIFF_ATLAS_V1.md",'
    echo '    "contract_json": "docs/rgc_continuation_cliff_atlas_v1.json",'
    echo '    "integration_test": "crates/franken-engine/tests/catastrophic_tail_tournament_gate_integration.rs",'
    echo '    "library_module": "crates/franken-engine/src/catastrophic_tail_tournament_gate.rs"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "rgc continuation cliff atlas manifest: ${manifest_path}"
  echo "rgc continuation cliff atlas events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"
exit "$main_exit"
