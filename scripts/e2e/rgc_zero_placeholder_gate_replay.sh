#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${RGC_ZERO_PLACEHOLDER_GATE_ARTIFACT_ROOT:-${root_dir}/artifacts/rgc_zero_placeholder_gate}"
mode="${1:-ci}"
main_exit=0

"${root_dir}/scripts/run_rgc_zero_placeholder_gate.sh" "${mode}" || main_exit=$?

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
    [[ -f "${candidate}/placeholder_gate_report.json" ]] || continue
    [[ -f "${candidate}/waiver_manifest.json" ]] || continue
    [[ -f "${candidate}/trace_ids.json" ]] || continue
    [[ -f "${candidate}/run_manifest.json" ]] || continue
    [[ -f "${candidate}/events.jsonl" ]] || continue
    [[ -f "${candidate}/commands.txt" ]] || continue
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
  if [[ "${prior_exit}" -eq 0 ]]; then
    return
  fi

  if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
    echo "[rgc-zero-placeholder-gate] gate exited with status ${prior_exit}; replay output reflects latest complete run directory ${latest_run_dir}" >&2
    return
  fi

  echo "[rgc-zero-placeholder-gate] gate exited with status ${prior_exit}; replay output reflects current run directory ${latest_run_dir}" >&2
}

latest_artifact_dir_path="$(latest_artifact_dir)"
latest_run_dir="$(latest_complete_run_dir)"
if [[ -z "${latest_run_dir}" ]]; then
  if [[ -n "${latest_artifact_dir_path}" ]]; then
    echo "rgc zero-placeholder gate replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "rgc zero-placeholder gate replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[rgc-zero-placeholder-gate] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

warn_about_failed_gate_replay_source "${main_exit}"

echo "[rgc-zero-placeholder-gate] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[rgc-zero-placeholder-gate] latest trace ids: ${latest_run_dir}/trace_ids.json"
cat "${latest_run_dir}/trace_ids.json"
echo "[rgc-zero-placeholder-gate] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo "[rgc-zero-placeholder-gate] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo "[rgc-zero-placeholder-gate] latest report: ${latest_run_dir}/placeholder_gate_report.json"
cat "${latest_run_dir}/placeholder_gate_report.json"
echo "[rgc-zero-placeholder-gate] latest waiver manifest: ${latest_run_dir}/waiver_manifest.json"
cat "${latest_run_dir}/waiver_manifest.json"

exit "$main_exit"
