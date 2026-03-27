#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${root_dir}"

artifact_root="${RGC_REACT_DOCTOR_PREFLIGHT_ARTIFACT_ROOT:-${root_dir}/artifacts/rgc_react_doctor_preflight}"
explicit_run_dir="${RGC_REACT_DOCTOR_PREFLIGHT_REPLAY_RUN_DIR:-}"
mode="${1:-ci}"
main_exit=0

run_dir_is_complete() {
  local candidate="${1:-}"
  [[ -n "${candidate}" ]] || return 1
  [[ -f "${candidate}/run_manifest.json" ]] || return 1
  [[ -f "${candidate}/trace_ids.json" ]] || return 1
  [[ -f "${candidate}/events.jsonl" ]] || return 1
  [[ -f "${candidate}/commands.txt" ]] || return 1
  [[ -f "${candidate}/react_doctor_support_contract.json" ]] || return 1
  [[ -f "${candidate}/react_support_repro_index.json" ]] || return 1
  [[ -f "${candidate}/rgc_react_doctor_preflight_v1.json" ]] || return 1
  [[ -f "${candidate}/step_logs/step_000.log" ]] || return 1
}

if [[ -z "${explicit_run_dir}" ]]; then
  "${root_dir}/scripts/run_rgc_react_doctor_preflight.sh" "${mode}" || main_exit=$?
fi

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
  if [[ "${prior_exit}" -eq 0 ]]; then
    return
  fi

  if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
    echo "[rgc-react-doctor-preflight] gate exited with status ${prior_exit}; replay output reflects latest complete run directory ${latest_run_dir}" >&2
    return
  fi

  echo "[rgc-react-doctor-preflight] gate exited with status ${prior_exit}; replay output reflects current run directory ${latest_run_dir}" >&2
}

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
    echo "rgc react doctor/preflight replay explicit run directory is incomplete: ${explicit_run_dir}" >&2
    exit 1
  fi
  if [[ -n "${latest_artifact_dir_path}" ]]; then
    echo "rgc react doctor/preflight replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "rgc react doctor/preflight replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[rgc-react-doctor-preflight] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

warn_about_failed_gate_replay_source "${main_exit}"

echo "[rgc-react-doctor-preflight] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[rgc-react-doctor-preflight] latest trace ids: ${latest_run_dir}/trace_ids.json"
cat "${latest_run_dir}/trace_ids.json"
echo "[rgc-react-doctor-preflight] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo "[rgc-react-doctor-preflight] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo "[rgc-react-doctor-preflight] latest support contract: ${latest_run_dir}/react_doctor_support_contract.json"
cat "${latest_run_dir}/react_doctor_support_contract.json"
echo "[rgc-react-doctor-preflight] latest repro index: ${latest_run_dir}/react_support_repro_index.json"
cat "${latest_run_dir}/react_support_repro_index.json"
echo "[rgc-react-doctor-preflight] latest contract json: ${latest_run_dir}/rgc_react_doctor_preflight_v1.json"
cat "${latest_run_dir}/rgc_react_doctor_preflight_v1.json"
echo "[rgc-react-doctor-preflight] latest first step log: ${latest_run_dir}/step_logs/step_000.log"
cat "${latest_run_dir}/step_logs/step_000.log"

exit "${main_exit}"
