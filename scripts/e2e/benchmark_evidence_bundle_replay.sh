#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${BENCHMARK_EVIDENCE_BUNDLE_ARTIFACT_ROOT:-${root_dir}/artifacts/benchmark_evidence_bundle}"
mode="${1:-ci}"
main_exit=0

"${root_dir}/scripts/run_benchmark_evidence_bundle_suite.sh" "${mode}" || main_exit=$?

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
    [[ -f "${candidate}/benchmark_evidence_bundle.json" ]] || continue
    [[ -f "${candidate}/benchmark_evidence_report.json" ]] || continue
    [[ -f "${candidate}/workload_provenance_index.json" ]] || continue
    [[ -f "${candidate}/parity_verdict_matrix.json" ]] || continue
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
    echo "benchmark evidence bundle replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "benchmark evidence bundle replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[benchmark-evidence-bundle] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

echo "benchmark evidence bundle replay manifest: ${latest_run_dir}/run_manifest.json"
echo "benchmark evidence bundle replay summary: ${latest_run_dir}/summary.md"
echo "benchmark evidence bundle replay bundle: ${latest_run_dir}/benchmark_evidence_bundle.json"
echo "benchmark evidence bundle replay report: ${latest_run_dir}/benchmark_evidence_report.json"

exit "$main_exit"
