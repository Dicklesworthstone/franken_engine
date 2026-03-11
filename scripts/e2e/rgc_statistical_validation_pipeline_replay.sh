#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mode="${1:-ci}"
artifact_root="${RGC_STATISTICAL_VALIDATION_ARTIFACT_ROOT:-${root_dir}/artifacts/rgc_statistical_validation_pipeline}"

"${root_dir}/scripts/run_rgc_statistical_validation_pipeline.sh" "${mode}"

latest_run_dir="$(find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d | sort | tail -n1)"
if [[ -z "${latest_run_dir}" ]]; then
  echo "no statistical validation artifact directory found under ${artifact_root}" >&2
  exit 1
fi

test -f "${latest_run_dir}/run_manifest.json"
test -f "${latest_run_dir}/events.jsonl"
test -f "${latest_run_dir}/commands.txt"
test -f "${latest_run_dir}/trace_ids.json"
test -f "${latest_run_dir}/summary.md"
test -f "${latest_run_dir}/env.json"
test -f "${latest_run_dir}/repro.lock"
test -d "${latest_run_dir}/step_logs"
test -f "${latest_run_dir}/support_bundle/stats_verdict_report.json"

echo "rgc statistical validation replay manifest: ${latest_run_dir}/run_manifest.json"
echo "rgc statistical validation replay summary: ${latest_run_dir}/summary.md"
