#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runner="${root_dir}/scripts/run_scientific_contribution_targets.sh"
artifact_root="${root_dir}/artifacts/scientific_contribution_targets"

mode="${1:-show}"

if [[ "$mode" != "show" ]]; then
  exec "$runner" "$mode"
fi

latest_artifact_dir() {
  if [[ ! -d "$artifact_root" ]]; then
    return 0
  fi

  find "$artifact_root" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1
}

latest_complete_run_dir() {
  if [[ ! -d "$artifact_root" ]]; then
    return 0
  fi

  find "$artifact_root" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | while IFS= read -r candidate; do
    [[ -f "${candidate}/run_manifest.json" ]] || continue
    [[ -f "${candidate}/events.jsonl" ]] || continue
    [[ -f "${candidate}/commands.txt" ]] || continue
    [[ -f "${candidate}/trace_ids.json" ]] || continue
    [[ -f "${candidate}/contribution_status_report.json" ]] || continue
    [[ -f "${candidate}/output_contract_status_report.json" ]] || continue
    [[ -f "${candidate}/dependency_status_report.json" ]] || continue
    [[ -f "${candidate}/scientific_contribution_summary.md" ]] || continue
    [[ -f "${candidate}/scientific_contribution_targets_v1.json" ]] || continue
    [[ -f "${candidate}/scientific_contribution_targets_v1.md" ]] || continue
    printf '%s\n' "${candidate}"
  done | tail -n 1
}

latest_artifact_dir_path="$(latest_artifact_dir)"
latest_run_dir="$(latest_complete_run_dir)"

if [[ -z "${latest_run_dir}" ]]; then
  if [[ -n "${latest_artifact_dir_path}" ]]; then
    echo "scientific contribution target replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "no scientific contribution target artifacts found under ${artifact_root}" >&2
  fi
  exit 1
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[scientific-contribution-targets] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

echo "[scientific-contribution-targets] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[scientific-contribution-targets] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo "[scientific-contribution-targets] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo "[scientific-contribution-targets] latest trace ids: ${latest_run_dir}/trace_ids.json"
cat "${latest_run_dir}/trace_ids.json"
echo "[scientific-contribution-targets] latest contribution report: ${latest_run_dir}/contribution_status_report.json"
cat "${latest_run_dir}/contribution_status_report.json"
echo "[scientific-contribution-targets] latest output-contract report: ${latest_run_dir}/output_contract_status_report.json"
cat "${latest_run_dir}/output_contract_status_report.json"
echo "[scientific-contribution-targets] latest dependency report: ${latest_run_dir}/dependency_status_report.json"
cat "${latest_run_dir}/dependency_status_report.json"
echo "[scientific-contribution-targets] latest summary: ${latest_run_dir}/scientific_contribution_summary.md"
cat "${latest_run_dir}/scientific_contribution_summary.md"
echo "[scientific-contribution-targets] latest contract: ${latest_run_dir}/scientific_contribution_targets_v1.json"
cat "${latest_run_dir}/scientific_contribution_targets_v1.json"
echo "[scientific-contribution-targets] latest doc: ${latest_run_dir}/scientific_contribution_targets_v1.md"
cat "${latest_run_dir}/scientific_contribution_targets_v1.md"
if [[ -f "${latest_run_dir}/step_logs/step_000.log" ]]; then
  echo "[scientific-contribution-targets] latest first step log: ${latest_run_dir}/step_logs/step_000.log"
  cat "${latest_run_dir}/step_logs/step_000.log"
else
  echo "[scientific-contribution-targets] latest first step log unavailable"
fi
