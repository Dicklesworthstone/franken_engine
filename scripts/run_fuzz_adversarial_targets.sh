#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_fuzz_adversarial}"
fuzz_time_seconds="${FUZZ_TIME_SECONDS:-60}"
rss_limit_mb="${FUZZ_RSS_LIMIT_MB:-2048}"
artifact_root="${FUZZ_ADVERSARIAL_ARTIFACT_ROOT:-artifacts/fuzz_adversarial}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="$artifact_root/$timestamp"
manifest_path="$run_dir/run_manifest.json"
events_path="$run_dir/events.jsonl"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "error: rch is required for fuzz adversarial target commands" >&2
  exit 1
fi

run_rch() {
  rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
    echo "error: rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false
step_log_index=0

run_step() {
  local command_text="$1"
  shift
  local step_log_path="${run_dir}/step_$(printf '%03d' "$step_log_index").log"
  step_log_index=$((step_log_index + 1))
  commands_run+=("$command_text")
  echo "==> $command_text"
  if ! run_rch "$@" > >(tee "$step_log_path") 2>&1; then
    failed_command="$command_text"
    return 1
  fi
  if ! rch_reject_local_fallback "$step_log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 86
  fi
}

build_targets() {
  run_step "cargo fuzz build decode_dos" cargo fuzz build decode_dos
  run_step "cargo fuzz build handshake_replay" cargo fuzz build handshake_replay
  run_step "cargo fuzz build token_verification" cargo fuzz build token_verification
  run_step "cargo fuzz build parser_boundary" cargo fuzz build parser_boundary
  run_step "cargo fuzz build ir_lowering_fuzz" cargo fuzz build ir_lowering_fuzz
  run_step "cargo fuzz build ir3_instruction_fuzz" cargo fuzz build ir3_instruction_fuzz
  run_step "cargo fuzz build module_loader_fuzz" cargo fuzz build module_loader_fuzz
  run_step "cargo fuzz build governance_verdict_fuzz" cargo fuzz build governance_verdict_fuzz
}

run_fuzz_targets() {
  run_step "cargo fuzz run decode_dos -- -max_total_time=$fuzz_time_seconds -rss_limit_mb=$rss_limit_mb -runs=0" \
    cargo fuzz run decode_dos -- "-max_total_time=$fuzz_time_seconds" "-rss_limit_mb=$rss_limit_mb" -runs=0
  run_step "cargo fuzz run handshake_replay -- -max_total_time=$fuzz_time_seconds -rss_limit_mb=$rss_limit_mb -runs=0" \
    cargo fuzz run handshake_replay -- "-max_total_time=$fuzz_time_seconds" "-rss_limit_mb=$rss_limit_mb" -runs=0
  run_step "cargo fuzz run token_verification -- -max_total_time=$fuzz_time_seconds -rss_limit_mb=$rss_limit_mb -runs=0" \
    cargo fuzz run token_verification -- "-max_total_time=$fuzz_time_seconds" "-rss_limit_mb=$rss_limit_mb" -runs=0
  run_step "cargo fuzz run parser_boundary -- -max_total_time=$fuzz_time_seconds -rss_limit_mb=$rss_limit_mb -runs=0" \
    cargo fuzz run parser_boundary -- "-max_total_time=$fuzz_time_seconds" "-rss_limit_mb=$rss_limit_mb" -runs=0
  run_step "cargo fuzz run ir_lowering_fuzz -- -max_total_time=$fuzz_time_seconds -rss_limit_mb=$rss_limit_mb -runs=0" \
    cargo fuzz run ir_lowering_fuzz -- "-max_total_time=$fuzz_time_seconds" "-rss_limit_mb=$rss_limit_mb" -runs=0
  run_step "cargo fuzz run ir3_instruction_fuzz -- -max_total_time=$fuzz_time_seconds -rss_limit_mb=$rss_limit_mb -runs=0" \
    cargo fuzz run ir3_instruction_fuzz -- "-max_total_time=$fuzz_time_seconds" "-rss_limit_mb=$rss_limit_mb" -runs=0
  run_step "cargo fuzz run module_loader_fuzz -- -max_total_time=$fuzz_time_seconds -rss_limit_mb=$rss_limit_mb -runs=0" \
    cargo fuzz run module_loader_fuzz -- "-max_total_time=$fuzz_time_seconds" "-rss_limit_mb=$rss_limit_mb" -runs=0
  run_step "cargo fuzz run governance_verdict_fuzz -- -max_total_time=$fuzz_time_seconds -rss_limit_mb=$rss_limit_mb -runs=0" \
    cargo fuzz run governance_verdict_fuzz -- "-max_total_time=$fuzz_time_seconds" "-rss_limit_mb=$rss_limit_mb" -runs=0
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test fuzz_adversarial" \
        cargo check -p frankenengine-engine --test fuzz_adversarial
      build_targets
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test fuzz_adversarial" \
        cargo test -p frankenengine-engine --test fuzz_adversarial
      ;;
    fuzz)
      run_fuzz_targets
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test fuzz_adversarial" \
        cargo check -p frankenengine-engine --test fuzz_adversarial
      run_step "cargo test -p frankenengine-engine --test fuzz_adversarial" \
        cargo test -p frankenengine-engine --test fuzz_adversarial
      build_targets
      run_fuzz_targets
      ;;
    *)
      echo "usage: $0 [check|test|fuzz|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local git_commit dirty_worktree idx comma outcome error_code_json
  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json='null'
  else
    outcome="fail"
    error_code_json='"FE-FUZZ-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$run_dir/commands.txt"

  {
    echo "{"
    echo '  "component": "fuzz_adversarial_targets",'
    echo '  "bead_id": "bd-3mu",'
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"fuzz_time_seconds\": ${fuzz_time_seconds},"
    echo "  \"rss_limit_mb\": ${rss_limit_mb},"
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "targets": ["decode_dos","handshake_replay","token_verification","parser_boundary","ir_lowering_fuzz","ir3_instruction_fuzz","module_loader_fuzz","governance_verdict_fuzz"],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"command_log\": \"${run_dir}/commands.txt\""
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${run_dir}/commands.txt\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  {
    echo "{\"trace_id\":\"trace-fuzz-adversarial-${timestamp}\",\"decision_id\":\"decision-fuzz-adversarial-${timestamp}\",\"policy_id\":\"policy-fuzz-adversarial-v1\",\"component\":\"fuzz_adversarial_targets\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  echo "fuzz adversarial manifest: $manifest_path"
  echo "fuzz adversarial events: $events_path"
}

trap 'write_manifest $?' EXIT
run_mode
