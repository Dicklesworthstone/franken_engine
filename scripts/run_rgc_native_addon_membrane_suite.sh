#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root_input="${RGC_NATIVE_ADDON_MEMBRANE_ARTIFACT_ROOT:-artifacts/rgc_native_addon_membrane}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_target_dir="${root_dir}/target_rch_native_addon_membrane"
target_dir_input="${CARGO_TARGET_DIR:-${default_target_dir}}"

case "${artifact_root_input}" in
  /*) artifact_root="${artifact_root_input}" ;;
  *) artifact_root="${root_dir}/${artifact_root_input}" ;;
esac

case "${target_dir_input}" in
  /*) target_dir="${target_dir_input}" ;;
  *) target_dir="${root_dir}/${target_dir_input}" ;;
esac

run_dir="${artifact_root}/${timestamp}"
step_logs_dir="${run_dir}/step_logs"

mkdir -p "$run_dir" "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for native-addon membrane heavy commands" >&2
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

declare -a required_artifacts=(
  addon_abi_fingerprint_index.json
  addon_compatibility_matrix.json
  addon_execution_disposition.json
  addon_fallback_receipts.json
  addon_handle_safety_report.json
  commands.txt
  events.jsonl
  native_addon_inventory.json
  native_addon_membrane_report.json
  native_addon_support_surface.json
  run_manifest.json
  trace_ids.json
)

rch_strip_ansi() {
  local input="$1"
  sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' "$input"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n 1 || true)"
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
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote execution failed: .*running locally|Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    echo "rch reported local fallback; refusing local execution" >&2
    return 1
  fi
}

declare -a commands_run=()
step_log_index=0
failed_command=""
last_step_log_path=""

run_step() {
  local command_text="$1"
  shift

  local log_path remote_exit_code
  step_log_index="$((step_log_index + 1))"
  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  last_step_log_path="$log_path"

  commands_run+=("$command_text")
  echo "==> $command_text" | tee "$log_path"

  if ! run_rch "$@" > >(tee -a "$log_path") 2>&1; then
    if rch_strip_ansi "$log_path" | rg -q "Remote command finished: exit=0"; then
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

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -z "$remote_exit_code" ]]; then
    failed_command="${command_text} (missing-remote-exit-marker)"
    return 1
  fi
  if [[ "$remote_exit_code" != "0" ]]; then
    failed_command="${command_text} (remote-exit=${remote_exit_code})"
    return 1
  fi
}

emit_bridge_artifacts() {
  local commands_json stripped_log marker_prefix
  commands_json="$(printf '%s\n' "${commands_run[@]}" | jq -R . | jq -c -s .)"
  marker_prefix="__RGC_NATIVE_ADDON_MEMBRANE_ARTIFACT__"

  run_step \
    "RGC_NATIVE_ADDON_MEMBRANE_ARTIFACT_DIR=${run_dir} cargo test -p frankenengine-engine --test native_addon_membrane_integration native_addon_membrane_artifact_bridge_emits_bundle_when_env_is_set -- --exact --nocapture && stream artifact bundle" \
    env \
    "RGC_NATIVE_ADDON_MEMBRANE_ARTIFACT_DIR=${run_dir}" \
    "RGC_NATIVE_ADDON_MEMBRANE_COMMANDS_JSON=${commands_json}" \
    sh -lc \
    'set -eu; cargo test -p frankenengine-engine --test native_addon_membrane_integration native_addon_membrane_artifact_bridge_emits_bundle_when_env_is_set -- --exact --nocapture; for artifact_name in "$@"; do printf "%s:BEGIN:%s\n" "__RGC_NATIVE_ADDON_MEMBRANE_ARTIFACT__" "$artifact_name"; cat "${RGC_NATIVE_ADDON_MEMBRANE_ARTIFACT_DIR}/${artifact_name}"; printf "\n%s:END:%s\n" "__RGC_NATIVE_ADDON_MEMBRANE_ARTIFACT__" "$artifact_name"; done' \
    sh \
    "${required_artifacts[@]}"

  stripped_log="$(mktemp)"
  rch_strip_ansi "${last_step_log_path}" >"$stripped_log"
  for required in "${required_artifacts[@]}"; do
    awk \
      -v begin="${marker_prefix}:BEGIN:${required}" \
      -v end="${marker_prefix}:END:${required}" \
      '
        $0 == begin { capture = 1; next }
        $0 == end { capture = 0; exit }
        capture { print }
      ' \
      "$stripped_log" >"${run_dir}/${required}"

    if [[ ! -s "${run_dir}/${required}" ]]; then
      rm -f "$stripped_log"
      failed_command="stream artifact bundle (missing ${required})"
      return 1
    fi
  done
  rm -f "$stripped_log"

  for required in "${required_artifacts[@]}"; do
    test -f "${run_dir}/${required}"
  done
  test -d "${step_logs_dir}"
}

run_mode() {
  local -a clippy_cmd=(
    cargo clippy -p frankenengine-engine --test native_addon_membrane_integration --no-deps -- -D warnings
  )

  case "$mode" in
    check)
      run_step \
        "cargo check -p frankenengine-engine --test native_addon_membrane_integration" \
        cargo check -p frankenengine-engine --test native_addon_membrane_integration
      ;;
    test)
      run_step \
        "cargo test -p frankenengine-engine --test native_addon_membrane_integration" \
        cargo test -p frankenengine-engine --test native_addon_membrane_integration
      emit_bridge_artifacts
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --test native_addon_membrane_integration --no-deps -- -D warnings" \
        "${clippy_cmd[@]}"
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-engine --test native_addon_membrane_integration" \
        cargo check -p frankenengine-engine --test native_addon_membrane_integration
      run_step \
        "cargo test -p frankenengine-engine --test native_addon_membrane_integration" \
        cargo test -p frankenengine-engine --test native_addon_membrane_integration
      run_step \
        "cargo clippy -p frankenengine-engine --test native_addon_membrane_integration --no-deps -- -D warnings" \
        "${clippy_cmd[@]}"
      emit_bridge_artifacts
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

run_mode

echo "rgc native-addon membrane artifacts: ${run_dir}"
