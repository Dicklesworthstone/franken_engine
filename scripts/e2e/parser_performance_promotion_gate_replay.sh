#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

artifact_root="${PARSER_PERFORMANCE_PROMOTION_GATE_ARTIFACT_ROOT:-artifacts/parser_performance_promotion_gate}"
mode="${1:-test}"
main_exit=0

"${root_dir}/scripts/run_parser_performance_promotion_gate.sh" "${mode}" || main_exit=$?

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
    find "${candidate}/step_logs" -mindepth 1 -maxdepth 1 -type f -name 'step_*.log' 2>/dev/null | grep -q . || continue
    printf '%s\n' "${candidate}"
  done | tail -n 1
}

first_step_log_path() {
  local run_dir="${1:-}"
  if [[ -z "${run_dir}" || ! -d "${run_dir}/step_logs" ]]; then
    return 0
  fi

  find "${run_dir}/step_logs" -mindepth 1 -maxdepth 1 -type f -name 'step_*.log' | sort | head -n 1
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
    echo "parser performance promotion gate replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "parser performance promotion gate replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[parser-performance-promotion-gate] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

first_step_log="$(first_step_log_path "${latest_run_dir}")"
if [[ -z "${first_step_log}" ]]; then
  echo "parser performance promotion gate replay could not locate a step log under ${latest_run_dir}/step_logs" >&2
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

echo "[parser-performance-promotion-gate] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[parser-performance-promotion-gate] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo "[parser-performance-promotion-gate] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo "[parser-performance-promotion-gate] latest first step log: ${first_step_log}"
cat "${first_step_log}"

exit "$main_exit"
