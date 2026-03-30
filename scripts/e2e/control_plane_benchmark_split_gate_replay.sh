#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${CONTROL_PLANE_BENCHMARK_SPLIT_ARTIFACT_ROOT:-${root_dir}/artifacts/control_plane_benchmark_split_gate}"
explicit_run_dir="${CONTROL_PLANE_BENCHMARK_SPLIT_GATE_REPLAY_RUN_DIR:-}"
mode="${1:-test}"
main_exit=0
pre_run_latest_artifact_dir_path=""

run_dir_is_complete() {
  local candidate="${1:-}"
  [[ -n "${candidate}" ]] || return 1
  [[ -f "${candidate}/run_manifest.json" ]] || return 1
  [[ -f "${candidate}/events.jsonl" ]] || return 1
  [[ -f "${candidate}/commands.txt" ]] || return 1
  [[ -f "${candidate}/control_plane_real_context_overhead_report.json" ]] || return 1
  [[ -f "${candidate}/benchmark_split_delta_report.json" ]] || return 1
  [[ -f "${candidate}/summary.md" ]] || return 1
  [[ -f "${candidate}/env.json" ]] || return 1
  [[ -f "${candidate}/repro.lock" ]] || return 1
  [[ -f "${candidate}/trace_ids" ]] || return 1
  [[ -f "${candidate}/step_logs/step_000.log" ]] || return 1
}

latest_artifact_dir() {
  if [[ ! -d "${artifact_root}" ]]; then
    return 0
  fi

  find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1
}

latest_complete_run_dir() {
  if [[ ! -d "${artifact_root}" ]]; then
    return 0
  fi

  find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d | sort | while IFS= read -r candidate; do
    run_dir_is_complete "${candidate}" || continue
    printf '%s\n' "${candidate}"
  done | tail -n 1
}

missing_bundle_exit_code() {
  local prior_exit="${1:-1}"
  if [[ "${prior_exit}" -eq 0 ]]; then
    echo 1
    return
  fi

  echo "${prior_exit}"
}

warn_about_failed_gate_replay_source() {
  local prior_exit="${1:-0}"
  local prior_artifact_dir="${2:-}"
  if [[ "${prior_exit}" -eq 0 ]]; then
    return
  fi

  if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
    echo "[control-plane-benchmark-split] gate exited with status ${prior_exit}; replay output reflects latest complete run directory ${latest_run_dir}" >&2
    return
  fi

  if [[ -n "${prior_artifact_dir}" && "${latest_run_dir}" == "${prior_artifact_dir}" ]]; then
    echo "[control-plane-benchmark-split] gate exited with status ${prior_exit}; replay output reflects previous latest complete run directory ${latest_run_dir}" >&2
    return
  fi

  echo "[control-plane-benchmark-split] gate exited with status ${prior_exit}; replay output reflects current run directory ${latest_run_dir}" >&2
}

if [[ -z "${explicit_run_dir}" ]]; then
  pre_run_latest_artifact_dir_path="$(latest_artifact_dir)"
  "${root_dir}/scripts/run_control_plane_benchmark_split_gate_suite.sh" "${mode}" || main_exit=$?
fi

latest_artifact_dir_path="$(latest_artifact_dir)"
latest_run_dir="$(latest_complete_run_dir)"
if [[ -n "${explicit_run_dir}" ]]; then
  latest_artifact_dir_path="${explicit_run_dir}"
  latest_run_dir=""
  if run_dir_is_complete "${explicit_run_dir}"; then
    latest_run_dir="${explicit_run_dir}"
  fi
fi

if [[ -z "${latest_run_dir}" ]]; then
  if [[ -n "${explicit_run_dir}" ]]; then
    echo "control-plane benchmark split replay explicit run directory is incomplete: ${explicit_run_dir}" >&2
    exit 1
  fi
  if [[ -n "${latest_artifact_dir_path}" ]]; then
    echo "control-plane benchmark split replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "control-plane benchmark split replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[control-plane-benchmark-split] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

warn_about_failed_gate_replay_source "${main_exit}" "${pre_run_latest_artifact_dir_path}"

echo "[control-plane-benchmark-split] latest complete run directory: ${latest_run_dir}"
echo "[control-plane-benchmark-split] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[control-plane-benchmark-split] latest trace ids: ${latest_run_dir}/trace_ids"
cat "${latest_run_dir}/trace_ids"
echo "[control-plane-benchmark-split] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo "[control-plane-benchmark-split] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo "[control-plane-benchmark-split] latest summary: ${latest_run_dir}/summary.md"
cat "${latest_run_dir}/summary.md"
echo "[control-plane-benchmark-split] latest env: ${latest_run_dir}/env.json"
cat "${latest_run_dir}/env.json"
echo "[control-plane-benchmark-split] latest repro lock: ${latest_run_dir}/repro.lock"
cat "${latest_run_dir}/repro.lock"
echo "[control-plane-benchmark-split] latest real-context overhead report: ${latest_run_dir}/control_plane_real_context_overhead_report.json"
cat "${latest_run_dir}/control_plane_real_context_overhead_report.json"
echo "[control-plane-benchmark-split] latest split delta report: ${latest_run_dir}/benchmark_split_delta_report.json"
cat "${latest_run_dir}/benchmark_split_delta_report.json"
echo "[control-plane-benchmark-split] latest first step log: ${latest_run_dir}/step_logs/step_000.log"
cat "${latest_run_dir}/step_logs/step_000.log"

exit "${main_exit}"
