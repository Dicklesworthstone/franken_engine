#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

artifact_root="${SEQLOCK_ROLLOUT_GUARD_ARTIFACT_ROOT:-artifacts/seqlock_rollout_guard}"
mode="${1:-ci}"
main_exit=0

"${root_dir}/scripts/run_seqlock_rollout_guard_suite.sh" "${mode}" || main_exit=$?

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
    [[ -f "${candidate}/suite_run_manifest.json" ]] || continue
    [[ -f "${candidate}/run_manifest.json" ]] || continue
    [[ -f "${candidate}/events.jsonl" ]] || continue
    [[ -f "${candidate}/suite_commands.txt" ]] || continue
    [[ -f "${candidate}/commands.txt" ]] || continue
    [[ -f "${candidate}/seqlock_rollout_guard.json" ]] || continue
    [[ -f "${candidate}/seqlock_safety_case.json" ]] || continue
    [[ -f "${candidate}/starvation_microbench_report.json" ]] || continue
    [[ -f "${candidate}/loom_schedule_coverage_report.json" ]] || continue
    [[ -f "${candidate}/trace_ids.json" ]] || continue
    [[ -d "${candidate}/step_logs" ]] || continue
    find "${candidate}/step_logs" -type f -print -quit | grep -q . || continue
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
    echo "seqlock rollout guard replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "seqlock rollout guard replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[seqlock-rollout-guard] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

echo "[seqlock-rollout-guard] latest suite manifest: ${latest_run_dir}/suite_run_manifest.json"
cat "${latest_run_dir}/suite_run_manifest.json"
echo "[seqlock-rollout-guard] latest runner manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[seqlock-rollout-guard] latest rollout guard: ${latest_run_dir}/seqlock_rollout_guard.json"
cat "${latest_run_dir}/seqlock_rollout_guard.json"
echo "[seqlock-rollout-guard] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo "[seqlock-rollout-guard] latest suite commands: ${latest_run_dir}/suite_commands.txt"
cat "${latest_run_dir}/suite_commands.txt"
echo "[seqlock-rollout-guard] latest bundle commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo "[seqlock-rollout-guard] latest trace ids: ${latest_run_dir}/trace_ids.json"
cat "${latest_run_dir}/trace_ids.json"
echo "[seqlock-rollout-guard] latest step logs: ${latest_run_dir}/step_logs"
ls -1 "${latest_run_dir}/step_logs"

exit "${main_exit}"
