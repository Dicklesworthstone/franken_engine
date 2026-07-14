#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
component="typed_persistence_sqlmodel"
bead_id="${TYPED_PERSISTENCE_BEAD_ID:-bd-3lurx}"
artifact_root="${TYPED_PERSISTENCE_ARTIFACT_ROOT:-artifacts/typed_persistence_sqlmodel}"
run_id="${TYPED_PERSISTENCE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${TYPED_PERSISTENCE_RUN_DIR:-${artifact_root}/${run_id}}"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
manifest_path="${run_dir}/manifest.json"
step_logs_dir="${run_dir}/step_logs"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target/typed_persistence_sqlmodel_replay}"
trace_id="${TYPED_PERSISTENCE_TRACE_ID:-trace-typed-persistence-${run_id}}"
decision_id="${TYPED_PERSISTENCE_DECISION_ID:-decision-typed-persistence-${run_id}}"
policy_id="${TYPED_PERSISTENCE_POLICY_ID:-policy-sqlmodel-typed-boundaries-v1}"
required_linker_rustflag="-Clinker-features=-lld"

linker_policy_is_effective() {
  local rustflags_value="${1-}"
  local -a tokens=()
  local index
  local effective_state="unset"

  read -r -a tokens <<<"$rustflags_value"
  for index in "${!tokens[@]}"; do
    case "${tokens[$index]}" in
      "$required_linker_rustflag") effective_state="disabled" ;;
      -Clinker-features=*) effective_state="other" ;;
      -C)
        case "${tokens[$((index + 1))]:-}" in
          linker-features=-lld) effective_state="disabled" ;;
          linker-features=*) effective_state="other" ;;
        esac
        ;;
    esac
  done
  [[ "$effective_state" == "disabled" ]]
}

rustflags="${RUSTFLAGS:--C linker=cc -Clinker-features=-lld}"
if ! linker_policy_is_effective "$rustflags"; then
  rustflags="${rustflags:+${rustflags} }${required_linker_rustflag}"
fi

mkdir -p "$step_logs_dir"
: >"$events_path"
: >"$commands_path"

declare -a commands_run=()
failed_command=""
mode_completed=false
manifest_written=false

render_shell_command() {
  local rendered=""
  local argument quoted

  for argument in "$@"; do
    printf -v quoted '%q' "$argument"
    rendered="${rendered}${rendered:+ }${quoted}"
  done
  printf '%s' "$rendered"
}

assert_shell_command_round_trip() {
  local rendered="$1"
  shift
  local -a expected=("$@")
  local -a decoded=()
  local index

  # `rendered` is generated exclusively by render_shell_command using Bash's
  # %q format, so evaluating it as an array cannot execute caller input.
  # shellcheck disable=SC2294
  eval "decoded=( ${rendered} )"
  if [[ "${#decoded[@]}" -ne "$#" ]]; then
    printf 'rendered command changed argv length: expected=%s actual=%s\n' "$#" "${#decoded[@]}" >&2
    return 1
  fi
  for index in "${!decoded[@]}"; do
    if [[ "${decoded[$index]}" != "${expected[$index]}" ]]; then
      printf 'rendered command changed argv element %s\n' "$index" >&2
      return 1
    fi
  done
}

json_event() {
  local event="$1"
  local outcome="$2"
  local error_code="$3"
  local step_id="$4"
  local command_text="$5"
  local log_path="$6"
  local duration_ms="$7"
  jq -nc \
    --arg schema_version "franken-engine.typed-persistence-sqlmodel.event.v1" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    --arg step_id "$step_id" \
    --arg command "$command_text" \
    --arg log_path "$log_path" \
    --argjson duration_ms "$duration_ms" \
    '{
      schema_version: $schema_version,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: $event,
      outcome: $outcome,
      error_code: (if $error_code == "" then null else $error_code end),
      step_id: $step_id,
      command: $command,
      log_path: $log_path,
      duration_ms: $duration_ms
    }' >>"$events_path"
}

run_step() {
  local step_id="$1"
  shift
  local log_path="${step_logs_dir}/${step_id}.log"
  local -a command=(
    env -u CARGO_ENCODED_RUSTFLAGS
    rch exec -- env -u CARGO_ENCODED_RUSTFLAGS
    "RUSTC_WRAPPER=${RUSTC_WRAPPER:-}"
    "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-1}"
    "CARGO_INCREMENTAL=${CARGO_INCREMENTAL:-0}"
    "CARGO_TARGET_DIR=${target_dir}"
    "RUSTFLAGS=${rustflags}"
    "$@"
  )
  local command_text
  local started_ms ended_ms duration_ms

  command_text="$(render_shell_command "${command[@]}")"
  assert_shell_command_round_trip "$command_text" "${command[@]}"

  commands_run+=("$command_text")
  printf '%s\n' "$command_text" >>"$commands_path"
  json_event "${step_id}.started" "running" "" "$step_id" "$command_text" "$log_path" 0

  started_ms="$(date -u +%s%3N)"
  if "${command[@]}" >"$log_path" 2>&1; then
    ended_ms="$(date -u +%s%3N)"
    duration_ms="$((ended_ms - started_ms))"
    json_event "${step_id}.completed" "pass" "" "$step_id" "$command_text" "$log_path" "$duration_ms"
  else
    local exit_code="$?"
    ended_ms="$(date -u +%s%3N)"
    duration_ms="$((ended_ms - started_ms))"
    failed_command="$command_text"
    json_event "${step_id}.completed" "fail" "FE-TYPED-PERSISTENCE-E2E-${exit_code}" "$step_id" "$command_text" "$log_path" "$duration_ms"
    return "$exit_code"
  fi
}

run_mode() {
  case "$mode" in
    fmt)
      run_step "fmt-check" cargo fmt --check
      ;;
    test)
      run_step "focused-typed-tests" cargo test -p frankenengine-engine --lib typed_persistence_models -- --nocapture
      ;;
    check)
      run_step "engine-lib-check" cargo check -p frankenengine-engine --lib
      ;;
    clippy)
      run_step "engine-lib-clippy" cargo clippy -p frankenengine-engine --lib -- -D warnings
      ;;
    ci)
      run_step "fmt-check" cargo fmt --check
      run_step "focused-typed-tests" cargo test -p frankenengine-engine --lib typed_persistence_models -- --nocapture
      run_step "engine-lib-check" cargo check -p frankenengine-engine --lib
      run_step "engine-lib-clippy" cargo clippy -p frankenengine-engine --lib -- -D warnings
      ;;
    *)
      echo "usage: $0 [fmt|test|check|clippy|ci]" >&2
      exit 2
      ;;
  esac
  mode_completed=true
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome="fail"
  local error_code="FE-TYPED-PERSISTENCE-E2E-${exit_code}"
  local git_commit dirty_worktree

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 && "$mode_completed" == true ]]; then
    outcome="pass"
    error_code=""
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  # manifest_path is passed as data, not read by jq.
  # shellcheck disable=SC2094
  jq -n \
    --arg schema_version "franken-engine.typed-persistence-sqlmodel.manifest.v1" \
    --arg bead_id "$bead_id" \
    --arg component "$component" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg mode "$mode" \
    --arg generated_at_utc "$run_id" \
    --arg git_commit "$git_commit" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    --arg target_dir "$target_dir" \
    --arg manifest_path "$manifest_path" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg step_logs_dir "$step_logs_dir" \
    --arg source_module "crates/franken-engine/src/typed_persistence_models.rs" \
    --arg failed_command "$failed_command" \
    --argjson dirty_worktree "$dirty_worktree" \
    --argjson mode_completed "$mode_completed" \
    --argjson exit_code "$exit_code" \
    --argjson command_count "${#commands_run[@]}" \
    --slurpfile commands <(jq -R . "$commands_path" | jq -s .) \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      component: $component,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      mode: $mode,
      generated_at_utc: $generated_at_utc,
      git_commit: $git_commit,
      dirty_worktree: $dirty_worktree,
      outcome: $outcome,
      error_code: (if $error_code == "" then null else $error_code end),
      exit_code: $exit_code,
      mode_completed: $mode_completed,
      command_count: $command_count,
      failed_command: (if $failed_command == "" then null else $failed_command end),
      cargo_target_dir: $target_dir,
      validation_scope: [
        "sqlmodel table metadata",
        "typed StoreRecord serialization/deserialization",
        "fail-closed validation",
        "legacy mapper classification",
        "FrankenSQLite in-memory schema initialization"
      ],
      commands: $commands[0],
      artifacts: {
        manifest: $manifest_path,
        structured_events: $events_path,
        command_transcript: $commands_path,
        step_logs_dir: $step_logs_dir,
        source_module: $source_module
      },
      operator_verification: [
        ("cat " + $manifest_path),
        ("cat " + $events_path),
        ("cat " + $commands_path),
        ("find " + $step_logs_dir + " -maxdepth 1 -type f -print"),
        ("scripts/e2e/typed_persistence_sqlmodel_replay.sh " + $mode)
      ]
    }' >"$manifest_path"

  json_event "manifest.written" "$outcome" "$error_code" "manifest" "write typed persistence replay manifest" "$manifest_path" 0
  echo "typed_persistence_sqlmodel_manifest=${manifest_path}"
  echo "typed_persistence_sqlmodel_events=${events_path}"
}

trap 'write_manifest $?' EXIT
run_mode
