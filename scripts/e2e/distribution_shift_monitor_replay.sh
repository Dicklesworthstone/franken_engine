#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${DISTRIBUTION_SHIFT_MONITOR_ARTIFACT_ROOT:-artifacts/distribution_shift_monitor}"
mode="${1:-ci}"
main_exit=0

./scripts/run_distribution_shift_monitor_suite.sh "${mode}" || main_exit=$?

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
    [[ -f "${candidate}/summary.md" ]] || continue
    [[ -f "${candidate}/events.jsonl" ]] || continue
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
    echo "distribution-shift replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "distribution-shift replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[distribution-shift-monitor] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

echo "[distribution-shift-monitor] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[distribution-shift-monitor] latest summary: ${latest_run_dir}/summary.md"
cat "${latest_run_dir}/summary.md"
echo "[distribution-shift-monitor] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"

for artifact in \
  "live_shift_windows.json" \
  "kernel_shift_statistics.jsonl" \
  "shift_alarm_report.json" \
  "shift_negative_control_report.json"; do
  if [[ -f "${latest_run_dir}/${artifact}" ]]; then
    echo "[distribution-shift-monitor] ${artifact}: ${latest_run_dir}/${artifact}"
    cat "${latest_run_dir}/${artifact}"
  fi
done

exit "$main_exit"
