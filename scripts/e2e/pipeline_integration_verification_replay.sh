#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${root_dir}"

artifact_root="${PIPELINE_INTEGRATION_VERIFICATION_ARTIFACT_ROOT:-artifacts/pipeline_integration_verification}"
explicit_run_dir="${PIPELINE_INTEGRATION_VERIFICATION_REPLAY_RUN_DIR:-}"
main_exit=0

run_dir_is_complete() {
  local candidate="${1:-}"
  [[ -n "${candidate}" ]] || return 1
  [[ -f "${candidate}/run_manifest.json" ]] || return 1
  [[ -f "${candidate}/events.jsonl" ]] || return 1
  [[ -f "${candidate}/commands.txt" ]] || return 1
  [[ -f "${candidate}/trace_ids.json" ]] || return 1
  [[ -f "${candidate}/pipeline_verification_report.json" ]] || return 1
  [[ -f "${candidate}/pipeline_verification.jsonl" ]] || return 1
  [[ -f "${candidate}/summary.md" ]] || return 1
  [[ -d "${candidate}/reports" ]] || return 1
  [[ -d "${candidate}/step_logs" ]] || return 1
  find "${candidate}/step_logs" -type f -name 'step_*.log' -print -quit | grep -q .
}

if [[ -z "${explicit_run_dir}" ]]; then
  "${root_dir}/scripts/test_pipeline_integration_verification.sh" || main_exit=$?
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

latest_first_step_log() {
  local run_dir="${1:-}"
  if [[ -z "${run_dir}" ]]; then
    return 0
  fi

  find "${run_dir}/step_logs" -type f -name 'step_*.log' | sort | head -n 1
}

latest_artifact_dir_path="$(latest_artifact_dir)"
latest_run_dir="$(latest_complete_run_dir)"
if [[ -n "${explicit_run_dir}" ]]; then
  latest_run_dir=""
  if run_dir_is_complete "${explicit_run_dir}"; then
    latest_run_dir="${explicit_run_dir}"
  fi
fi

if [[ -z "${latest_run_dir}" ]]; then
  if [[ -n "${explicit_run_dir}" ]]; then
    echo "pipeline integration verification replay explicit run directory is incomplete: ${explicit_run_dir}" >&2
  elif [[ -n "${latest_artifact_dir_path}" ]]; then
    echo "pipeline integration verification replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "pipeline integration verification replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[pipeline-integration-verification] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

first_step_log_path="$(latest_first_step_log "${latest_run_dir}")"
if [[ -z "${first_step_log_path}" ]]; then
  echo "pipeline integration verification replay could not locate a step log under ${latest_run_dir}/step_logs" >&2
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

echo "[pipeline-integration-verification] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[pipeline-integration-verification] latest trace ids: ${latest_run_dir}/trace_ids.json"
cat "${latest_run_dir}/trace_ids.json"
echo "[pipeline-integration-verification] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo "[pipeline-integration-verification] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo "[pipeline-integration-verification] latest jsonl log: ${latest_run_dir}/pipeline_verification.jsonl"
cat "${latest_run_dir}/pipeline_verification.jsonl"
echo "[pipeline-integration-verification] latest report: ${latest_run_dir}/pipeline_verification_report.json"
cat "${latest_run_dir}/pipeline_verification_report.json"
echo "[pipeline-integration-verification] latest summary: ${latest_run_dir}/summary.md"
cat "${latest_run_dir}/summary.md"
echo "[pipeline-integration-verification] first step log: ${first_step_log_path}"
cat "${first_step_log_path}"

exit "${main_exit}"
