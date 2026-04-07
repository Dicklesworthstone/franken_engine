#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

print_usage() {
  cat <<'EOF'
usage: ./scripts/test_standalone_build.sh [standalone-check|standalone-test|full-check|ci]

Modes:
  standalone-check  rch-backed cargo check in standalone mode
  standalone-test   rch-backed cargo test in standalone mode
  full-check        rch-backed cargo check with all features when sibling deps exist
  ci                standalone-check + standalone-test + full-check manifest/report

Environment:
  STANDALONE_BUILD_GATE_ARTIFACT_ROOT  Output root (default: artifacts/standalone_build_gate)
  STANDALONE_BUILD_GATE_SKIP_REMOTE    Set to 1 to skip heavy rch-backed lanes and emit a manifest only
  RUSTUP_TOOLCHAIN                     Toolchain for rch-backed cargo lanes (default: nightly)
  CARGO_TARGET_DIR                     Remote cargo target dir (default: repo-local .rch-target/standalone_build_gate_...)
  CARGO_BUILD_JOBS                     Remote cargo build jobs for rch lanes (default: 1)
  CARGO_INCREMENTAL                    Remote cargo incremental mode for rch lanes (default: 0)
  RCH_EXEC_TIMEOUT_SECONDS             Timeout for each rch lane (default: 900)
EOF
}

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root="${STANDALONE_BUILD_GATE_ARTIFACT_ROOT:-artifacts/standalone_build_gate}"
skip_remote="${STANDALONE_BUILD_GATE_SKIP_REMOTE:-0}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
cargo_incremental="${CARGO_INCREMENTAL:-0}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_target_dir="${root_dir}/.rch-target/standalone_build_gate_${timestamp}_$$"
target_dir="${CARGO_TARGET_DIR:-${default_target_dir}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
step_logs_dir="${run_dir}/step_logs"

case "$mode" in
  standalone-check|standalone-test|full-check|ci)
    ;;
  -h|--help)
    print_usage
    exit 0
    ;;
  *)
    print_usage >&2
    exit 2
    ;;
esac

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required" >&2
  exit 3
fi

if [[ "$skip_remote" != "1" ]] && ! command -v rch >/dev/null 2>&1; then
  echo "error: rch is required unless STANDALONE_BUILD_GATE_SKIP_REMOTE=1" >&2
  exit 4
fi

mkdir -p "$run_dir" "$step_logs_dir"
mkdir -p "${root_dir}/.rch-target"
: >"$events_path"

declare -a commands_run=()
declare -a lane_results=()

json_array_from_args() {
  if [[ "$#" -eq 0 ]]; then
    printf '[]'
    return
  fi

  printf '%s\n' "$@" | jq -R . | jq -s .
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

rch_local_fallback_detected() {
  local log_path="$1"
  grep -Eiq \
    'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326' \
    "$log_path"
}

rch_recovered_success() {
  local log_path="$1"
  if rg -q 'Remote command finished: exit=0|Finished `dev` profile|Finished `test` profile|test result: ok\.' "$log_path" \
    && ! rg -qi 'error(\[[[:alnum:]]+\])?:' "$log_path"; then
    return 0
  fi
  return 1
}

discover_external_dependency_paths() {
  rg -No 'path[[:space:]]*=[[:space:]]*"(/dp/[^"]+)"' crates/franken-engine/Cargo.toml \
    | sed -E 's/.*"([^"]+)"/\1/' \
    | sort -u
}

record_event() {
  local lane="$1"
  local status="$2"
  local note="$3"
  jq -cn \
    --arg lane "$lane" \
    --arg status "$status" \
    --arg note "$note" \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
      schema_version: "franken-engine.standalone-build-gate.event.v1",
      generated_at_utc: $generated_at_utc,
      lane: $lane,
      status: $status,
      note: $note
    }' >>"$events_path"
}

lane_result_json() {
  local lane="$1"
  local status="$2"
  local command_text="$3"
  local log_path="$4"
  local note="$5"
  jq -cn \
    --arg lane "$lane" \
    --arg status "$status" \
    --arg command "$command_text" \
    --arg log_path "$log_path" \
    --arg note "$note" \
    '{
      lane: $lane,
      status: $status,
      command: $command,
      log_path: $log_path,
      note: $note
    }'
}

run_rch_lane() {
  local lane="$1"
  local command_text="$2"
  shift 2

  local log_path="${step_logs_dir}/${lane}.log"
  local run_status=0
  local lane_status=""
  local note=""
  local remote_exit_code=""

  commands_run+=("$command_text")

  if [[ "$skip_remote" == "1" ]]; then
    : >"$log_path"
    lane_status="skipped"
    note="skip_remote=1"
    record_event "$lane" "$lane_status" "$note"
    lane_results+=("$(lane_result_json "$lane" "$lane_status" "$command_text" "$log_path" "$note")")
    return 0
  fi

  set +e
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
      "RUSTUP_TOOLCHAIN=${toolchain}" \
      "CARGO_TARGET_DIR=${target_dir}" \
      "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
      "CARGO_INCREMENTAL=${cargo_incremental}" \
      "$@" > >(tee "$log_path") 2>&1
  run_status=$?
  set -e

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ "$run_status" -eq 0 ]]; then
    if rch_local_fallback_detected "$log_path"; then
      lane_status="failed"
      note="rch reported local fallback"
    else
      lane_status="passed"
      note="remote_exit=${remote_exit_code:-0}"
    fi
  elif [[ "$run_status" -eq 124 ]]; then
    lane_status="failed"
    note="rch timeout after ${rch_timeout_seconds}s"
  elif rch_recovered_success "$log_path"; then
    if rch_local_fallback_detected "$log_path"; then
      lane_status="failed"
      note="rch recovered success marker but reported local fallback"
    else
      lane_status="passed"
      note="remote success recovered after local artifact retrieval issue"
    fi
  elif rch_local_fallback_detected "$log_path"; then
    lane_status="failed"
    note="rch reported local fallback"
  else
    lane_status="failed"
    if [[ -n "$remote_exit_code" ]]; then
      note="rch_exit=${run_status}, remote_exit=${remote_exit_code}"
    else
      note="rch_exit=${run_status}, remote exit marker missing"
    fi
  fi

  record_event "$lane" "$lane_status" "$note"
  lane_results+=("$(lane_result_json "$lane" "$lane_status" "$command_text" "$log_path" "$note")")
  [[ "$lane_status" == "passed" ]]
}

mark_full_check_skipped() {
  local command_text="cargo check -p frankenengine-engine --all-features"
  local log_path="${step_logs_dir}/full-check.log"
  local note="$1"

  commands_run+=("$command_text")
  : >"$log_path"
  record_event "full-check" "skipped_missing_external_deps" "$note"
  lane_results+=("$(lane_result_json "full-check" "skipped_missing_external_deps" "$command_text" "$log_path" "$note")")
}

declare -a external_dependency_paths=()
declare -a missing_external_dependency_paths=()

mapfile -t external_dependency_paths < <(discover_external_dependency_paths)
for dep_path in "${external_dependency_paths[@]}"; do
  if [[ ! -f "${dep_path}/Cargo.toml" ]]; then
    missing_external_dependency_paths+=("$dep_path")
  fi
done

run_failures=0

run_mode() {
  case "$mode" in
    standalone-check)
      run_rch_lane \
        "standalone-check" \
        "cargo check -p frankenengine-engine --no-default-features" \
        cargo check -p frankenengine-engine --no-default-features || run_failures=$((run_failures + 1))
      ;;
    standalone-test)
      run_rch_lane \
        "standalone-test" \
        "cargo test -p frankenengine-engine --no-default-features" \
        cargo test -p frankenengine-engine --no-default-features || run_failures=$((run_failures + 1))
      ;;
    full-check)
      if [[ "${#missing_external_dependency_paths[@]}" -gt 0 ]]; then
        mark_full_check_skipped "missing sibling dependency Cargo.toml for: ${missing_external_dependency_paths[*]}"
      else
        run_rch_lane \
          "full-check" \
          "cargo check -p frankenengine-engine --all-features" \
          cargo check -p frankenengine-engine --all-features || run_failures=$((run_failures + 1))
      fi
      ;;
    ci)
      run_rch_lane \
        "standalone-check" \
        "cargo check -p frankenengine-engine --no-default-features" \
        cargo check -p frankenengine-engine --no-default-features || run_failures=$((run_failures + 1))
      run_rch_lane \
        "standalone-test" \
        "cargo test -p frankenengine-engine --no-default-features" \
        cargo test -p frankenengine-engine --no-default-features || run_failures=$((run_failures + 1))
      if [[ "${#missing_external_dependency_paths[@]}" -gt 0 ]]; then
        mark_full_check_skipped "missing sibling dependency Cargo.toml for: ${missing_external_dependency_paths[*]}"
      else
        run_rch_lane \
          "full-check" \
          "cargo check -p frankenengine-engine --all-features" \
          cargo check -p frankenengine-engine --all-features || run_failures=$((run_failures + 1))
      fi
      ;;
  esac
}

run_mode

printf '%s\n' "${commands_run[@]}" >"$commands_path"

if [[ "${#lane_results[@]}" -eq 0 ]]; then
  lane_results_json='[]'
else
  lane_results_json="$(printf '%s\n' "${lane_results[@]}" | jq -s '.')"
fi

external_dependency_paths_json="$(json_array_from_args "${external_dependency_paths[@]}")"
missing_external_dependency_paths_json="$(json_array_from_args "${missing_external_dependency_paths[@]}")"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

standalone_check_status="$(printf '%s\n' "$lane_results_json" | jq -r 'map(select(.lane == "standalone-check")) | .[0].status // "not_run"')"
standalone_test_status="$(printf '%s\n' "$lane_results_json" | jq -r 'map(select(.lane == "standalone-test")) | .[0].status // "not_run"')"
full_check_status="$(printf '%s\n' "$lane_results_json" | jq -r 'map(select(.lane == "full-check")) | .[0].status // "not_run"')"

if [[ "$standalone_check_status" == "passed" && "$standalone_test_status" == "passed" ]]; then
  standalone_status="ready"
  standalone_gate_passed=true
elif [[ "$standalone_check_status" == "failed" || "$standalone_test_status" == "failed" ]]; then
  standalone_status="blocked"
  standalone_gate_passed=false
else
  standalone_status="not_verified"
  standalone_gate_passed=false
fi

case "$full_check_status" in
  passed)
    full_integration_status="ready"
    ;;
  skipped_missing_external_deps)
    full_integration_status="skipped_missing_external_deps"
    ;;
  failed)
    full_integration_status="blocked"
    ;;
  skipped)
    full_integration_status="not_verified"
    ;;
  *)
    full_integration_status="not_run"
    ;;
esac

if [[ "$standalone_status" == "ready" && "$full_integration_status" == "ready" ]]; then
  overall_status="ready"
elif [[ "$standalone_status" == "ready" && "$full_integration_status" == "skipped_missing_external_deps" ]]; then
  overall_status="standalone_ready_full_integration_skipped"
elif [[ "$standalone_status" == "ready" && "$full_integration_status" == "blocked" ]]; then
  overall_status="standalone_ready_full_integration_blocked"
elif [[ "$standalone_status" == "blocked" ]]; then
  overall_status="blocked"
else
  overall_status="not_verified"
fi

jq -n \
  --arg schema_version "franken-engine.standalone-build-gate.v1" \
  --arg generated_at_utc "$generated_at_utc" \
  --arg repo_root "$root_dir" \
  --arg mode "$mode" \
  --arg toolchain "$toolchain" \
  --arg target_dir "$target_dir" \
  --arg manifest_path "$manifest_path" \
  --arg commands_path "$commands_path" \
  --arg events_path "$events_path" \
  --arg step_logs_dir "$step_logs_dir" \
  --argjson rch_exec_timeout_seconds "$rch_timeout_seconds" \
  --argjson skip_remote "$([[ "$skip_remote" == "1" ]] && printf 'true' || printf 'false')" \
  --argjson lanes "$lane_results_json" \
  --argjson external_dependency_paths "$external_dependency_paths_json" \
  --argjson missing_external_dependency_paths "$missing_external_dependency_paths_json" \
  --arg standalone_status "$standalone_status" \
  --arg full_integration_status "$full_integration_status" \
  --arg overall_status "$overall_status" \
  --argjson standalone_gate_passed "$standalone_gate_passed" \
  '{
    schema_version: $schema_version,
    generated_at_utc: $generated_at_utc,
    repo_root: $repo_root,
    mode: $mode,
    toolchain: $toolchain,
    cargo_target_dir: $target_dir,
    rch_exec_timeout_seconds: $rch_exec_timeout_seconds,
    skip_remote: $skip_remote,
    manifest_path: $manifest_path,
    commands_path: $commands_path,
    events_path: $events_path,
    step_logs_dir: $step_logs_dir,
    external_dependency_paths: $external_dependency_paths,
    missing_external_dependency_paths: $missing_external_dependency_paths,
    lanes: $lanes,
    build_modes: {
      standalone: {
        status: $standalone_status,
        gate_passed: $standalone_gate_passed,
        commands: [
          "cargo check -p frankenengine-engine --no-default-features",
          "cargo test -p frankenengine-engine --no-default-features"
        ]
      },
      full_integration: {
        status: $full_integration_status,
        commands: [
          "cargo check -p frankenengine-engine --all-features"
        ]
      }
    },
    summary: {
      lane_count: ($lanes | length),
      failed_lane_count: ($lanes | map(select(.status == "failed")) | length),
      standalone_gate_passed: $standalone_gate_passed,
      overall_status: $overall_status
    }
  }' >"$manifest_path"

echo "wrote ${manifest_path}"

exit_code=0
if [[ "$skip_remote" == "1" ]]; then
  exit 0
fi

case "$mode" in
  standalone-check)
    [[ "$standalone_check_status" == "passed" ]] || exit_code=1
    ;;
  standalone-test)
    [[ "$standalone_test_status" == "passed" ]] || exit_code=1
    ;;
  full-check)
    [[ "$full_integration_status" == "ready" || "$full_integration_status" == "skipped_missing_external_deps" ]] || exit_code=1
    ;;
  ci)
    [[ "$standalone_gate_passed" == "true" ]] || exit_code=1
    ;;
esac

exit "$exit_code"
