#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
uid="$(id -u)"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_category_shift_report_uid${uid}}"
artifact_root="${CATEGORY_SHIFT_REPORT_ARTIFACT_ROOT:-artifacts/category_shift_report}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
summary_path="${run_dir}/summary.md"
env_path="${run_dir}/env.json"
repro_lock_path="${run_dir}/repro.lock"
step_logs_dir="${run_dir}/step_logs"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
bead_id="${CATEGORY_SHIFT_REPORT_BEAD_ID:-bd-f7n}"
trace_id="trace-category-shift-report-${timestamp}"
decision_id="decision-category-shift-report-${timestamp}"
policy_id="section-10.9-category-shift"

mkdir -p "$run_dir" "$step_logs_dir"

run_rch() {
  timeout "${rch_timeout_seconds}" rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

declare -a commands_run=()
declare -a step_logs=()
failed_command=""
failed_log_path=""
manifest_written=false
mode_completed=false

json_or_null() {
  local value="$1"
  if [[ -n "$value" ]]; then
    printf '"%s"' "$value"
  else
    printf 'null'
  fi
}

write_static_artifacts() {
  cat >"$env_path" <<EOF
{
  "toolchain": "${toolchain}",
  "cargo_target_dir": "${target_dir}",
  "bead_id": "${bead_id}",
  "mode": "${mode}",
  "component": "category_shift_report_suite"
}
EOF

  cat >"$repro_lock_path" <<EOF
mode=${mode}
toolchain=${toolchain}
cargo_target_dir=${target_dir}
rch_exec_timeout_seconds=${rch_timeout_seconds}
bead_id=${bead_id}
EOF
}

run_step() {
  local command_text="$1"
  shift
  local step_index
  local log_path
  step_index="${#commands_run[@]}"
  log_path="${step_logs_dir}/step_$(printf '%02d' "$((step_index + 1))").log"
  commands_run+=("${command_text}")
  step_logs+=("${log_path}")

  echo "==> ${command_text}"
  if run_rch "$@" > >(tee "$log_path") 2>&1; then
    return 0
  fi

  if rg -q "Remote command finished: exit=0" "$log_path"; then
    echo "==> recovered: remote execution succeeded; artifact retrieval timed out or stalled" \
      | tee -a "$log_path"
    return 0
  fi

  failed_command="${command_text}"
  failed_log_path="${log_path}"
  return 1
}

run_mode() {
  case "$mode" in
    check)
      run_step \
        "cargo check -p frankenengine-engine --test category_shift_report_integration" \
        cargo check -p frankenengine-engine --test category_shift_report_integration
      ;;
    test)
      run_step \
        "cargo test -p frankenengine-engine --test category_shift_report_integration" \
        cargo test -p frankenengine-engine --test category_shift_report_integration
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --test category_shift_report_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test category_shift_report_integration -- -D warnings
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-engine --test category_shift_report_integration" \
        cargo check -p frankenengine-engine --test category_shift_report_integration
      run_step \
        "cargo test -p frankenengine-engine --test category_shift_report_integration" \
        cargo test -p frankenengine-engine --test category_shift_report_integration
      run_step \
        "cargo clippy -p frankenengine-engine --test category_shift_report_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test category_shift_report_integration -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac

  mode_completed=true
}

write_summary() {
  local outcome="$1"
  cat >"$summary_path" <<EOF
# Category Shift Report Suite

- bead_id: \`${bead_id}\`
- mode: \`${mode}\`
- outcome: \`${outcome}\`
- generated_at_utc: \`${timestamp}\`
- toolchain: \`${toolchain}\`
- cargo_target_dir: \`${target_dir}\`

## Commands
$(printf '%s\n' "${commands_run[@]}" | sed 's/^/- `/; s/$/`/')
EOF
}

write_manifest() {
  local exit_code="${1:-0}"
  local dirty_worktree git_commit outcome error_code_json failed_log_json idx comma

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  write_static_artifacts
  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  if [[ "$exit_code" -eq 0 && "$mode_completed" == true ]]; then
    outcome="pass"
    error_code_json='null'
  else
    outcome="fail"
    error_code_json='"FE-CATEGORY-SHIFT-0001"'
  fi
  write_summary "$outcome"

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi
  failed_log_json="$(json_or_null "$failed_log_path")"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.category-shift-report.run-manifest.v1",'
    echo '  "component": "category_shift_report_suite",'
    echo "  \"bead_id\": \"${bead_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"mode_completed\": ${mode_completed},"
    echo "  \"commands_executed\": ${#commands_run[@]},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    echo "  \"failed_log\": ${failed_log_json},"
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "step_logs": ['
    for idx in "${!step_logs[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#step_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${step_logs[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"summary\": \"${summary_path}\","
    echo "    \"env\": \"${env_path}\","
    echo "    \"repro_lock\": \"${repro_lock_path}\","
    echo "    \"step_logs_dir\": \"${step_logs_dir}\","
    echo '    "source_module": "crates/franken-engine/src/category_shift_report.rs",'
    echo '    "integration_test": "crates/franken-engine/tests/category_shift_report_integration.rs"'
    echo '  }'
    echo "}"
  } >"$manifest_path"

  {
    echo "{\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"category_shift_report_suite\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  echo "Category-shift report manifest: $manifest_path"
  echo "Category-shift report events: $events_path"
}

trap 'write_manifest $?' EXIT
run_mode
