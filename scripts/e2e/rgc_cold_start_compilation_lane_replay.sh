#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${root_dir}"

artifact_root="${RGC_COLD_START_COMPILATION_LANE_ARTIFACT_ROOT:-${root_dir}/artifacts/rgc_cold_start_compilation_lane}"
mode="${1:-ci}"
main_exit=0

"${root_dir}/scripts/run_rgc_cold_start_compilation_lane.sh" "${mode}" || main_exit=$?

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
    [[ -f "${candidate}/cold_start_compilation_report.json" ]] || continue
    [[ -f "${candidate}/cold_start_observability_delta.json" ]] || continue
    [[ -f "${candidate}/aot_bundle_compilation_report.json" ]] || continue
    [[ -f "${candidate}/runtime_image_manifest.json" ]] || continue
    [[ -f "${candidate}/summary.md" ]] || continue
    [[ -f "${candidate}/persistent_cache_contract/persistent_cache_contract.json" ]] || continue
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
    echo "rgc cold-start compilation lane replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "rgc cold-start compilation lane replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[rgc-cold-start-compilation-lane] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

echo "[rgc-cold-start-compilation-lane] latest complete run directory: ${latest_run_dir}"
echo "[rgc-cold-start-compilation-lane] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[rgc-cold-start-compilation-lane] latest trace ids: ${latest_run_dir}/trace_ids.json"
cat "${latest_run_dir}/trace_ids.json"
echo "[rgc-cold-start-compilation-lane] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo "[rgc-cold-start-compilation-lane] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo "[rgc-cold-start-compilation-lane] latest report: ${latest_run_dir}/cold_start_compilation_report.json"
cat "${latest_run_dir}/cold_start_compilation_report.json"
echo "[rgc-cold-start-compilation-lane] latest observability delta: ${latest_run_dir}/cold_start_observability_delta.json"
cat "${latest_run_dir}/cold_start_observability_delta.json"
echo "[rgc-cold-start-compilation-lane] latest AOT bundle: ${latest_run_dir}/aot_bundle_compilation_report.json"
cat "${latest_run_dir}/aot_bundle_compilation_report.json"
echo "[rgc-cold-start-compilation-lane] latest runtime image manifest: ${latest_run_dir}/runtime_image_manifest.json"
cat "${latest_run_dir}/runtime_image_manifest.json"
echo "[rgc-cold-start-compilation-lane] latest persistent cache contract: ${latest_run_dir}/persistent_cache_contract/persistent_cache_contract.json"
cat "${latest_run_dir}/persistent_cache_contract/persistent_cache_contract.json"
echo "[rgc-cold-start-compilation-lane] latest summary: ${latest_run_dir}/summary.md"
cat "${latest_run_dir}/summary.md"
echo "[rgc-cold-start-compilation-lane] latest first step log: ${latest_run_dir}/step_logs/step_000.log"
cat "${latest_run_dir}/step_logs/step_000.log"

exit "${main_exit}"
