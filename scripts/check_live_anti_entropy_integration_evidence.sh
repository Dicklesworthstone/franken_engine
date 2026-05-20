#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
target_dir="${CARGO_TARGET_DIR:-target_rch_reality_check}"
rustflags="${RUSTFLAGS:--C linker=cc}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
component="live_anti_entropy_integration_evidence_gate"
bead_id="bd-fmyrx"
test_name="live_anti_entropy_integration_evidence_gate"
run_dir="artifacts/live_anti_entropy_integration_evidence/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
commands_path="${run_dir}/commands.txt"

mkdir -p "$run_dir"

declare -a commands_run=()
failed_command=""
manifest_written=false

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for live anti-entropy integration evidence manifest generation" >&2
  exit 2
fi

reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|running locally' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

run_rch_cargo() {
  local command_text="$1"
  shift
  local step_index log_path

  if ! command -v rch >/dev/null 2>&1; then
    echo "rch is required for live anti-entropy integration evidence cargo gates" >&2
    failed_command="$command_text (missing-rch)"
    return 1
  fi

  step_index="${#commands_run[@]}"
  commands_run+=("$command_text")
  log_path="${run_dir}/rch-log-${step_index}.log"

  echo "==> $command_text"
  if ! rch exec -- env \
    "RUSTFLAGS=${rustflags}" \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=1 \
    "$@" > >(tee "$log_path") 2>&1; then
    failed_command="$command_text"
    return 1
  fi

  if ! reject_local_fallback "$log_path"; then
    failed_command="$command_text (rch-local-fallback-detected)"
    return 1
  fi
}

run_check() {
  run_rch_cargo \
    "cargo check -p frankenengine-engine --target-dir ${target_dir} --test ${test_name}" \
    cargo check -p frankenengine-engine --target-dir "$target_dir" --test "$test_name"
}

run_test() {
  run_rch_cargo \
    "cargo test -p frankenengine-engine --target-dir ${target_dir} --test ${test_name} -- --nocapture" \
    cargo test -p frankenengine-engine --target-dir "$target_dir" --test "$test_name" -- --nocapture
}

run_fixture_verifier() {
  local command_text="./examples/09_anti_entropy_trust_reconciliation/verify.sh"
  local log_path step_index
  step_index="${#commands_run[@]}"
  commands_run+=("$command_text")
  log_path="${run_dir}/fixture-verifier-${step_index}.log"

  echo "==> $command_text"
  if ! "$root_dir/examples/09_anti_entropy_trust_reconciliation/verify.sh" > >(tee "$log_path") 2>&1; then
    failed_command="$command_text"
    return 1
  fi
}

run_static_linkage_check() {
  local command_text="static linkage check for ${bead_id}, ${test_name}, and PLAN 10.11"
  commands_run+=("$command_text")
  echo "==> $command_text"

  rg -q "$bead_id" "crates/franken-engine/tests/${test_name}.rs"
  rg -q "$bead_id" "$0"
  rg -q "scripts/check_live_anti_entropy_integration_evidence.sh" \
    docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md
  rg -q "crates/franken-engine/tests/${test_name}.rs" \
    docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome git_commit dirty_worktree commands_json failed_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
  else
    outcome="fail"
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  commands_json="$(printf '%s\n' "${commands_run[@]}" | jq -R . | jq -s .)"
  if [[ -n "$failed_command" ]]; then
    failed_json="$(jq -n --arg value "$failed_command" '$value')"
  else
    failed_json="null"
  fi

  jq -n \
    --arg schema_version "franken-engine.live-anti-entropy-integration-evidence.run-manifest.v1" \
    --arg component "$component" \
    --arg bead_id "$bead_id" \
    --arg mode "$mode" \
    --arg generated_at_utc "$timestamp" \
    --arg cargo_target_dir "$target_dir" \
    --arg rustflags "$rustflags" \
    --arg git_commit "$git_commit" \
    --arg outcome "$outcome" \
    --arg command_log "$commands_path" \
    --arg manifest "$manifest_path" \
    --arg test_path "crates/franken-engine/tests/${test_name}.rs" \
    --arg script_path "scripts/check_live_anti_entropy_integration_evidence.sh" \
    --arg fixture_verifier "examples/09_anti_entropy_trust_reconciliation/verify.sh" \
    --argjson dirty_worktree "$dirty_worktree" \
    --argjson commands "$commands_json" \
    --argjson failed_command "$failed_json" \
    '{
      schema_version: $schema_version,
      component: $component,
      bead_id: $bead_id,
      mode: $mode,
      generated_at_utc: $generated_at_utc,
      cargo_target_dir: $cargo_target_dir,
      rustflags: $rustflags,
      git_commit: $git_commit,
      dirty_worktree: $dirty_worktree,
      outcome: $outcome,
      failed_command: $failed_command,
      commands: $commands,
      artifacts: {
        command_log: $command_log,
        manifest: $manifest,
        test: $test_path,
        gate_script: $script_path,
        fixture_verifier: $fixture_verifier
      },
      operator_verification: [
        ("cat " + $manifest),
        ("cat " + $command_log),
        ("CARGO_TARGET_DIR=" + $cargo_target_dir + " " + $script_path + " ci")
      ]
    }' >"$manifest_path"

  echo "live anti-entropy integration evidence manifest: ${manifest_path}"
}

trap 'write_manifest $?' EXIT

case "$mode" in
  check)
    run_check
    run_static_linkage_check
    ;;
  test)
    run_test
    run_fixture_verifier
    run_static_linkage_check
    ;;
  fixture)
    run_fixture_verifier
    ;;
  ci)
    run_check
    run_test
    run_fixture_verifier
    run_static_linkage_check
    ;;
  *)
    echo "usage: $0 [check|test|fixture|ci]" >&2
    exit 2
    ;;
esac
