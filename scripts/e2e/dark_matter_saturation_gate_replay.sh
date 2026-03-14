#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${DARK_MATTER_SATURATION_ARTIFACT_ROOT:-artifacts/dark_matter_saturation_gate}"
mode="${1:-ci}"
main_exit=0

./scripts/run_dark_matter_saturation_gate_suite.sh "${mode}" || main_exit=$?

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
    echo "dark-matter saturation replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "dark-matter saturation replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[dark-matter-saturation] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

echo "[dark-matter-saturation] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[dark-matter-saturation] latest summary: ${latest_run_dir}/summary.md"
cat "${latest_run_dir}/summary.md"
echo "[dark-matter-saturation] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"

exit "$main_exit"
