#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${root_dir}"

artifact_root="${RGC_REACT_PARITY_GATE_ARTIFACT_ROOT:-${root_dir}/artifacts/rgc_react_parity_gate}"
mode="${1:-ci}"
main_exit=0

"${root_dir}/scripts/run_rgc_react_parity_gate.sh" "${mode}" || main_exit=$?

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
    [[ -f "${candidate}/react_parity_gate_index.json" ]] || continue
    [[ -f "${candidate}/react_compile_parity_report.json" ]] || continue
    [[ -f "${candidate}/react_ssr_client_parity_report.json" ]] || continue
    [[ -f "${candidate}/react_mismatch_catalog.json" ]] || continue
    [[ -f "${candidate}/rgc_react_parity_gate_v1.json" ]] || continue
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
    echo "rgc react parity gate replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "rgc react parity gate replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[rgc-react-parity-gate] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

echo "[rgc-react-parity-gate] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[rgc-react-parity-gate] latest trace ids: ${latest_run_dir}/trace_ids.json"
cat "${latest_run_dir}/trace_ids.json"
echo "[rgc-react-parity-gate] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo "[rgc-react-parity-gate] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo "[rgc-react-parity-gate] latest index: ${latest_run_dir}/react_parity_gate_index.json"
cat "${latest_run_dir}/react_parity_gate_index.json"
echo "[rgc-react-parity-gate] latest compile report: ${latest_run_dir}/react_compile_parity_report.json"
cat "${latest_run_dir}/react_compile_parity_report.json"
echo "[rgc-react-parity-gate] latest ssr report: ${latest_run_dir}/react_ssr_client_parity_report.json"
cat "${latest_run_dir}/react_ssr_client_parity_report.json"
echo "[rgc-react-parity-gate] latest mismatch catalog: ${latest_run_dir}/react_mismatch_catalog.json"
cat "${latest_run_dir}/react_mismatch_catalog.json"
echo "[rgc-react-parity-gate] latest contract: ${latest_run_dir}/rgc_react_parity_gate_v1.json"
cat "${latest_run_dir}/rgc_react_parity_gate_v1.json"
echo "[rgc-react-parity-gate] latest first step log: ${latest_run_dir}/step_logs/step_000.log"
cat "${latest_run_dir}/step_logs/step_000.log"

exit "${main_exit}"
