#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mode="${1:-run}"
artifact_root="${FRANKEN_SHIPPED_PATH_PARITY_ARTIFACT_ROOT:-artifacts/franken_shipped_path_parity}"
explicit_run_dir="${FRANKEN_SHIPPED_PATH_PARITY_REPLAY_RUN_DIR:-}"
main_exit=0

run_dir_is_complete() {
  local candidate="${1:-}"
  [[ -n "${candidate}" ]] || return 1
  [[ -f "${candidate}/run_manifest.json" ]] || return 1
  [[ -f "${candidate}/trace_ids.json" ]] || return 1
  [[ -f "${candidate}/events.jsonl" ]] || return 1
  [[ -f "${candidate}/commands.txt" ]] || return 1
  [[ -f "${candidate}/parity_report.json" ]] || return 1
  [[ -f "${candidate}/shipped_path_mismatch_catalog.json" ]] || return 1
  [[ -f "${candidate}/shipped_path_operator_summary.json" ]] || return 1
}

cd "${root_dir}"
if [[ -z "${explicit_run_dir}" ]]; then
  ./scripts/run_franken_shipped_path_parity.sh "${mode}" || main_exit=$?
fi

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
    echo "[franken-shipped-path-parity] gate exited with status ${prior_exit}; replay output reflects latest complete run directory ${latest_run_dir}" >&2
    return
  fi

  echo "[franken-shipped-path-parity] gate exited with status ${prior_exit}; replay output reflects current run directory ${latest_run_dir}" >&2
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
    echo "franken shipped path parity replay explicit run directory is incomplete: ${explicit_run_dir}" >&2
    exit 1
  fi
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

warn_about_failed_gate_replay_source "${main_exit}"

echo "[franken-shipped-path-parity] latest run dir: ${latest_run_dir}"
cat "${latest_run_dir}/run_manifest.json"
echo "[franken-shipped-path-parity] latest trace ids: ${latest_run_dir}/trace_ids.json"
cat "${latest_run_dir}/trace_ids.json"
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
