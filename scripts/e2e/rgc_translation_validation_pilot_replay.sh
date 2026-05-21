#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

artifact_root="${TRANSLATION_VALIDATION_PILOT_ARTIFACT_ROOT:-${root_dir}/artifacts/translation_validation_pilot}"
explicit_run_dir="${TRANSLATION_VALIDATION_PILOT_REPLAY_RUN_DIR:-}"
mode="${1:-ci}"
main_exit=0
pre_run_latest_artifact_dir_path=""

run_dir_is_complete() {
  local candidate="${1:-}"
  [[ -n "${candidate}" ]] || return 1
  [[ -f "${candidate}/run_manifest.json" ]] || return 1
  [[ -f "${candidate}/pilot_log.log" ]] || return 1
  [[ -f "${candidate}/translation_validation_report.md" ]] || return 1
  [[ -f "${candidate}/test_cases.json" ]] || return 1
  [[ -f "${candidate}/lean_proofs_status.json" ]] || return 1
}

latest_artifact_dir() {
  if [[ ! -d "${artifact_root}" ]]; then
    return 0
  fi

  find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1
}

if [[ -z "${explicit_run_dir}" ]]; then
  pre_run_latest_artifact_dir_path="$(latest_artifact_dir)"
  "${root_dir}/scripts/run_rgc_translation_validation_pilot.sh" "${mode}" || main_exit=$?
fi

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
    echo "[translation-validation-pilot] gate exited with status ${prior_exit}; replay output reflects latest complete run directory ${latest_run_dir}" >&2
    return
  fi

  if [[ -n "${prior_artifact_dir}" && "${latest_run_dir}" == "${prior_artifact_dir}" ]]; then
    echo "[translation-validation-pilot] gate exited with status ${prior_exit}; replay output reflects previous latest complete run directory ${latest_run_dir}" >&2
    return
  fi

  echo "[translation-validation-pilot] gate exited with status ${prior_exit}; replay output reflects current run directory ${latest_run_dir}" >&2
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
    echo "translation validation pilot replay explicit run directory is incomplete: ${explicit_run_dir}" >&2
    exit 1
  fi
  if [[ -n "${latest_artifact_dir_path}" ]]; then
    echo "translation validation pilot replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "translation validation pilot replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[translation-validation-pilot] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

warn_about_failed_gate_replay_source "${main_exit}" "${pre_run_latest_artifact_dir_path}"

echo "[translation-validation-pilot] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[translation-validation-pilot] latest pilot log: ${latest_run_dir}/pilot_log.log"
cat "${latest_run_dir}/pilot_log.log"
echo "[translation-validation-pilot] latest report: ${latest_run_dir}/translation_validation_report.md"
cat "${latest_run_dir}/translation_validation_report.md"
echo "[translation-validation-pilot] latest test cases: ${latest_run_dir}/test_cases.json"
cat "${latest_run_dir}/test_cases.json"
echo "[translation-validation-pilot] latest lean proofs status: ${latest_run_dir}/lean_proofs_status.json"
cat "${latest_run_dir}/lean_proofs_status.json"

exit "${main_exit}"