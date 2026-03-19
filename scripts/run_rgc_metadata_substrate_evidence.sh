#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
artifact_root="${RGC_METADATA_SUBSTRATE_EVIDENCE_ARTIFACT_ROOT:-artifacts/rgc_metadata_substrate_evidence}"
run_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_rgc_metadata_substrate_evidence_${target_namespace}}"
run_dir="${artifact_root}/${run_stamp}"
step_logs_dir="${run_dir}/step_logs"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-1200}"
failed_command=""
step_index=0

mkdir -p "${step_logs_dir}"

declare -a registered_temp_paths=()

register_temp_path() {
  local path="${1:-}"
  if [[ -n "${path}" ]]; then
    registered_temp_paths+=("${path}")
  fi
}

unregister_temp_path() {
  local path_to_remove="${1:-}"
  local kept=()
  local path=""

  for path in "${registered_temp_paths[@]}"; do
    if [[ "${path}" != "${path_to_remove}" ]]; then
      kept+=("${path}")
    fi
  done

  registered_temp_paths=("${kept[@]}")
}

cleanup_temp_path() {
  local path="${1:-}"
  if [[ -z "${path}" ]]; then
    return
  fi

  rm -f "${path}" 2>/dev/null || true
  unregister_temp_path "${path}"
}

cleanup_registered_temp_paths() {
  local path=""
  for path in "${registered_temp_paths[@]}"; do
    rm -f "${path}" 2>/dev/null || true
  done
  registered_temp_paths=()
}

trap cleanup_registered_temp_paths EXIT

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for metadata substrate evidence heavy commands" >&2
  exit 2
fi

run_rch() {
  RCH_EXEC_TIMEOUT_SECONDS="${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "$@"
}

run_rch_strict_logged() {
  local log_path="$1"
  shift

  local fifo_path fallback_flag_path rch_pid_path reader_pid rch_pid rch_status=0
  local line current_rch_pid

  fifo_path="$(mktemp -u "${run_dir}/rch-stream.XXXXXX")"
  fallback_flag_path="$(mktemp "${run_dir}/rch-fallback.XXXXXX")"
  rch_pid_path="$(mktemp "${run_dir}/rch-pid.XXXXXX")"
  register_temp_path "${fifo_path}"
  register_temp_path "${fallback_flag_path}"
  register_temp_path "${rch_pid_path}"
  rm -f "${fallback_flag_path}"
  mkfifo "${fifo_path}"
  : >"${log_path}"

  {
    while IFS= read -r line || [[ -n "${line}" ]]; do
      printf '%s\n' "${line}" | tee -a "${log_path}"
      if [[ "${line}" == *"Remote toolchain failure, falling back to local"* ||
        "${line}" == *"falling back to local"* ||
        "${line}" == *"fallback to local"* ||
        "${line}" == *"local fallback"* ||
        "${line}" == *"running locally"* ||
        "${line}" == *"[RCH] local ("* ]]; then
        : >"${fallback_flag_path}"
        current_rch_pid="$(tr -d '[:space:]' <"${rch_pid_path}" 2>/dev/null || true)"
        if [[ -n "${current_rch_pid}" ]]; then
          kill "${current_rch_pid}" 2>/dev/null || true
          pkill -P "${current_rch_pid}" 2>/dev/null || true
        fi
        pkill -f 'franken_metadata_substrate_evidence' 2>/dev/null || true
        pkill -f 'metadata_substrate_evidence_cli' 2>/dev/null || true
        pkill -f "CARGO_TARGET_DIR=${target_dir}" 2>/dev/null || true
        pkill -f "${target_dir}" 2>/dev/null || true
      fi
    done <"${fifo_path}"
  } &
  reader_pid=$!

  run_rch "$@" >"${fifo_path}" 2>&1 &
  rch_pid=$!
  printf '%s\n' "${rch_pid}" >"${rch_pid_path}"
  wait "${rch_pid}" || rch_status=$?
  wait "${reader_pid}" || true
  cleanup_temp_path "${fifo_path}"

  if [[ -f "${fallback_flag_path}" ]]; then
    cleanup_temp_path "${fallback_flag_path}"
    cleanup_temp_path "${rch_pid_path}"
    return 125
  fi

  cleanup_temp_path "${fallback_flag_path}"
  cleanup_temp_path "${rch_pid_path}"
  return "${rch_status}"
}

run_step() {
  local command_text="$1"
  shift

  local log_path run_rc=0
  printf -v log_path '%s/step_%03d.log' "${step_logs_dir}" "${step_index}"
  step_index=$((step_index + 1))

  echo "==> ${command_text}"
  if run_rch_strict_logged "${log_path}" "$@"; then
    run_rc=0
  else
    run_rc=$?
  fi

  if [[ "${run_rc}" -eq 125 ]]; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  if [[ "${run_rc}" -ne 0 ]]; then
    failed_command="${command_text} (exit=${run_rc})"
    return "${run_rc}"
  fi
}

emit_run_artifact_paths() {
  local artifact_dir="$1"
  local report_path="${artifact_dir}/runtime_metadata_substrate_report.json"
  local evidence_manifest_path="${artifact_dir}/runtime_metadata_substrate_evidence_manifest.json"
  local cache_miss_path="${artifact_dir}/cache_miss_profile.json"
  local fallback_receipts_path="${artifact_dir}/metadata_fallback_receipts.json"
  local override_receipts_path="${artifact_dir}/substrate_override_receipts.json"
  local run_manifest_path="${artifact_dir}/run_manifest.json"
  local events_path="${artifact_dir}/events.jsonl"
  local commands_path="${artifact_dir}/commands.txt"
  local trace_ids_path="${artifact_dir}/trace_ids.json"

  for path in \
    "${report_path}" \
    "${evidence_manifest_path}" \
    "${cache_miss_path}" \
    "${fallback_receipts_path}" \
    "${override_receipts_path}" \
    "${run_manifest_path}" \
    "${events_path}" \
    "${commands_path}" \
    "${trace_ids_path}"; do
    if [[ ! -f "${path}" ]]; then
      echo "metadata substrate evidence bundle is incomplete; missing ${path}" >&2
      return 1
    fi
  done

  echo "metadata substrate report: ${report_path}"
  echo "metadata substrate evidence manifest: ${evidence_manifest_path}"
  echo "metadata substrate cache-miss profile: ${cache_miss_path}"
  echo "metadata substrate fallback receipts: ${fallback_receipts_path}"
  echo "metadata substrate override receipts: ${override_receipts_path}"
  echo "metadata substrate run manifest: ${run_manifest_path}"
  echo "metadata substrate events: ${events_path}"
  echo "metadata substrate commands: ${commands_path}"
  echo "metadata substrate trace ids: ${trace_ids_path}"
}

case "${mode}" in
  check)
    run_step \
      "cargo check -p frankenengine-engine --bin franken_metadata_substrate_evidence --test metadata_substrate_evidence_cli" \
      cargo check -p frankenengine-engine --bin franken_metadata_substrate_evidence --test metadata_substrate_evidence_cli
    ;;
  test)
    run_step \
      "cargo test -p frankenengine-engine --test metadata_substrate_evidence_cli" \
      cargo test -p frankenengine-engine --test metadata_substrate_evidence_cli
    ;;
  clippy)
    run_step \
      "cargo clippy -p frankenengine-engine --bin franken_metadata_substrate_evidence --test metadata_substrate_evidence_cli -- -D warnings" \
      cargo clippy -p frankenengine-engine --bin franken_metadata_substrate_evidence --test metadata_substrate_evidence_cli -- -D warnings
    ;;
  run)
    run_step \
      "cargo run -p frankenengine-engine --bin franken_metadata_substrate_evidence -- --out-dir ${run_dir}" \
      cargo run -p frankenengine-engine --bin franken_metadata_substrate_evidence -- --out-dir "${run_dir}"
    emit_run_artifact_paths "${run_dir}"
    ;;
  ci)
    run_step \
      "cargo check -p frankenengine-engine --bin franken_metadata_substrate_evidence --test metadata_substrate_evidence_cli" \
      cargo check -p frankenengine-engine --bin franken_metadata_substrate_evidence --test metadata_substrate_evidence_cli
    run_step \
      "cargo test -p frankenengine-engine --test metadata_substrate_evidence_cli" \
      cargo test -p frankenengine-engine --test metadata_substrate_evidence_cli
    run_step \
      "cargo clippy -p frankenengine-engine --bin franken_metadata_substrate_evidence --test metadata_substrate_evidence_cli -- -D warnings" \
      cargo clippy -p frankenengine-engine --bin franken_metadata_substrate_evidence --test metadata_substrate_evidence_cli -- -D warnings
    run_step \
      "cargo run -p frankenengine-engine --bin franken_metadata_substrate_evidence -- --out-dir ${run_dir}" \
      cargo run -p frankenengine-engine --bin franken_metadata_substrate_evidence -- --out-dir "${run_dir}"
    emit_run_artifact_paths "${run_dir}"
    ;;
  *)
    echo "usage: ./scripts/run_rgc_metadata_substrate_evidence.sh [check|test|clippy|run|ci]" >&2
    exit 2
    ;;
esac
