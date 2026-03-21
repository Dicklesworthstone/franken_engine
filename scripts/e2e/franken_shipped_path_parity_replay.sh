#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mode="${1:-run}"
artifact_root="${FRANKEN_SHIPPED_PATH_PARITY_ARTIFACT_ROOT:-artifacts/franken_shipped_path_parity}"
main_exit=0

cd "${root_dir}"
./scripts/run_franken_shipped_path_parity.sh "${mode}" || main_exit=$?

latest_artifact_dir() {
  if [[ ! -d "${artifact_root}" ]]; then
    return 0
  fi

  find "${artifact_root}" -mindepth 2 -maxdepth 2 -type d | sort | tail -n 1
}

latest_complete_run_dir() {
  if [[ ! -d "${artifact_root}" ]]; then
    return 0
  fi

  find "${artifact_root}" -mindepth 2 -maxdepth 2 -type d | sort | while IFS= read -r candidate; do
    [[ -f "${candidate}/run_manifest.json" ]] || continue
    [[ -f "${candidate}/events.jsonl" ]] || continue
    [[ -f "${candidate}/commands.txt" ]] || continue
    [[ -f "${candidate}/parity_report.json" ]] || continue
    [[ -f "${candidate}/shipped_path_mismatch_catalog.json" ]] || continue
    [[ -f "${candidate}/shipped_path_operator_summary.json" ]] || continue
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
    echo "[franken-shipped-path-parity] no complete artifact directory found; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "[franken-shipped-path-parity] no artifact directory found under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[franken-shipped-path-parity] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

echo "[franken-shipped-path-parity] latest run dir: ${latest_run_dir}"
cat "${latest_run_dir}/run_manifest.json"
echo "[franken-shipped-path-parity] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo "[franken-shipped-path-parity] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo "[franken-shipped-path-parity] latest parity report: ${latest_run_dir}/parity_report.json"
cat "${latest_run_dir}/parity_report.json"
echo "[franken-shipped-path-parity] latest mismatch catalog: ${latest_run_dir}/shipped_path_mismatch_catalog.json"
cat "${latest_run_dir}/shipped_path_mismatch_catalog.json"
echo "[franken-shipped-path-parity] latest operator summary: ${latest_run_dir}/shipped_path_operator_summary.json"
cat "${latest_run_dir}/shipped_path_operator_summary.json"

exit "$main_exit"
