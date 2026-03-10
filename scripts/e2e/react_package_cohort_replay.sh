#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mode="${1:-ci}"
artifact_root_setting="${REACT_PACKAGE_COHORT_ARTIFACT_ROOT:-artifacts/react_package_cohort}"

case "$artifact_root_setting" in
  /*) artifact_root="$artifact_root_setting" ;;
  *) artifact_root="${root_dir}/${artifact_root_setting}" ;;
esac

"${root_dir}/scripts/run_react_package_cohort_suite.sh" "${mode}"

latest_run_dir="$(
  find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1
)"
if [[ -z "${latest_run_dir}" ]]; then
  echo "react package cohort replay could not locate a run directory" >&2
  exit 1
fi

echo "[react-package-cohort] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[react-package-cohort] latest trace ids: ${latest_run_dir}/trace_ids.json"
cat "${latest_run_dir}/trace_ids.json"
echo "[react-package-cohort] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
