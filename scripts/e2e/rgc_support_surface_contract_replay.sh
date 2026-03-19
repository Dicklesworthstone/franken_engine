#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${root_dir}"

artifact_root="${RGC_SUPPORT_SURFACE_CONTRACT_ARTIFACT_ROOT:-${root_dir}/artifacts/rgc_support_surface_contract}"
mode="${1:-ci}"
main_exit=0

"${root_dir}/scripts/run_rgc_support_surface_contract.sh" "${mode}" || main_exit=$?

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
    [[ -f "${candidate}/run_manifest.json" ]] || continue
    [[ -f "${candidate}/trace_ids.json" ]] || continue
    [[ -f "${candidate}/events.jsonl" ]] || continue
    [[ -f "${candidate}/commands.txt" ]] || continue
    [[ -f "${candidate}/support_surface_schema_report.json" ]] || continue
    [[ -f "${candidate}/support_surface_contract.json" ]] || continue
    [[ -f "${candidate}/support_surface_mode_matrix.json" ]] || continue
    [[ -f "${candidate}/step_logs/step_000.log" ]] || continue
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

latest_artifact_dir_path="$(latest_artifact_dir)"
latest_run_dir="$(latest_complete_run_dir)"
if [[ -z "${latest_run_dir}" ]]; then
  if [[ -n "${latest_artifact_dir_path}" ]]; then
    echo "rgc support-surface contract replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "rgc support-surface contract replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[rgc-support-surface-contract] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

echo "[rgc-support-surface-contract] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[rgc-support-surface-contract] latest trace ids: ${latest_run_dir}/trace_ids.json"
cat "${latest_run_dir}/trace_ids.json"
echo "[rgc-support-surface-contract] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo "[rgc-support-surface-contract] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo "[rgc-support-surface-contract] latest schema report: ${latest_run_dir}/support_surface_schema_report.json"
cat "${latest_run_dir}/support_surface_schema_report.json"
echo "[rgc-support-surface-contract] latest contract: ${latest_run_dir}/support_surface_contract.json"
cat "${latest_run_dir}/support_surface_contract.json"
echo "[rgc-support-surface-contract] latest mode matrix: ${latest_run_dir}/support_surface_mode_matrix.json"
cat "${latest_run_dir}/support_surface_mode_matrix.json"
echo "[rgc-support-surface-contract] latest first step log: ${latest_run_dir}/step_logs/step_000.log"
cat "${latest_run_dir}/step_logs/step_000.log"

exit "${main_exit}"
