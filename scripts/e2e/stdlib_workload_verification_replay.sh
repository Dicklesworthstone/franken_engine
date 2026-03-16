#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${STDLIB_WORKLOAD_VERIFICATION_ARTIFACT_ROOT:-${root_dir}/artifacts/stdlib_workload_verification}"
mode="${1:-ci}"
main_exit=0

"${root_dir}/scripts/run_stdlib_workload_verification_suite.sh" "${mode}" || main_exit=$?

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
    [[ -f "${candidate}/events.jsonl" ]] || continue
    [[ -f "${candidate}/commands.txt" ]] || continue
    [[ -f "${candidate}/summary.md" ]] || continue
    [[ -f "${candidate}/env.json" ]] || continue
    [[ -f "${candidate}/repro.lock" ]] || continue
    [[ -f "${candidate}/trace_ids.json" ]] || continue
    [[ -f "${candidate}/stdlib_runtime_report.json" ]] || continue
    [[ -f "${candidate}/callback_trace.json" ]] || continue
    [[ -f "${candidate}/mutation_trace.json" ]] || continue
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
    echo "stdlib workload verification replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "stdlib workload verification replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[stdlib-workload-verification] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

echo "stdlib workload verification replay manifest: ${latest_run_dir}/run_manifest.json"
echo "stdlib workload verification replay summary: ${latest_run_dir}/summary.md"
echo "stdlib workload verification replay report: ${latest_run_dir}/stdlib_runtime_report.json"
echo "stdlib workload verification replay callback trace: ${latest_run_dir}/callback_trace.json"

exit "$main_exit"
