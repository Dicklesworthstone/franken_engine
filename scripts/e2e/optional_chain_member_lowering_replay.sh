#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${OPTIONAL_CHAIN_MEMBER_LOWERING_ARTIFACT_ROOT:-artifacts/optional_chain_member_lowering}"
mode="${1:-ci}"
main_exit=0

"${root_dir}/scripts/run_optional_chain_member_lowering_suite.sh" "${mode}" || main_exit=$?

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
    [[ -f "${candidate}/trace_ids.json" ]] || continue
    [[ -f "${candidate}/optional_chain_member_lowering_report.json" ]] || continue
    [[ -f "${candidate}/summary.md" ]] || continue
    [[ -f "${candidate}/member.compile.json" ]] || continue
    [[ -f "${candidate}/computed.compile.json" ]] || continue
    [[ -f "${candidate}/nullish.run.json" ]] || continue
    [[ -d "${candidate}/step_logs" ]] || continue
    find "${candidate}/step_logs" -type f -name 'step_*.log' -print -quit | grep -q . || continue
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
if [[ -z "${latest_run_dir}" ]]; then
  if [[ -n "${latest_artifact_dir_path}" ]]; then
    echo "optional-chain member lowering replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "optional-chain member lowering replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[optional-chain-member-lowering] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

first_step_log_path="$(latest_first_step_log "${latest_run_dir}")"
if [[ -z "${first_step_log_path}" ]]; then
  echo "optional-chain member lowering replay could not locate a step log under ${latest_run_dir}/step_logs" >&2
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

echo "[optional-chain-member-lowering] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[optional-chain-member-lowering] latest trace ids: ${latest_run_dir}/trace_ids.json"
cat "${latest_run_dir}/trace_ids.json"
echo "[optional-chain-member-lowering] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo "[optional-chain-member-lowering] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo "[optional-chain-member-lowering] latest report: ${latest_run_dir}/optional_chain_member_lowering_report.json"
cat "${latest_run_dir}/optional_chain_member_lowering_report.json"
echo "[optional-chain-member-lowering] latest summary: ${latest_run_dir}/summary.md"
cat "${latest_run_dir}/summary.md"
echo "[optional-chain-member-lowering] first step log: ${first_step_log_path}"
cat "${first_step_log_path}"

exit "${main_exit}"
