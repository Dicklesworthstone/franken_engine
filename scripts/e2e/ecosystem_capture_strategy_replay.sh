#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runner="${root_dir}/scripts/run_ecosystem_capture_strategy.sh"
artifact_root="${root_dir}/artifacts/ecosystem_capture_strategy"

mode="${1:-show}"

if [[ "$mode" != "show" ]]; then
  exec "$runner" "$mode"
fi

latest_run_dir="$(
  find "$artifact_root" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1
)"

if [[ -z "${latest_run_dir}" ]]; then
  echo "no ecosystem capture strategy artifacts found under ${artifact_root}" >&2
  exit 1
fi

printf 'latest run: %s\n' "$latest_run_dir"
printf 'latest manifest: %s\n' "${latest_run_dir}/run_manifest.json"
printf 'latest events: %s\n' "${latest_run_dir}/events.jsonl"
printf 'latest summary: %s\n' "${latest_run_dir}/strategy_summary.md"
printf 'latest milestone report: %s\n' "${latest_run_dir}/milestone_status_report.json"
printf 'latest blocker report: %s\n' "${latest_run_dir}/blocker_status_report.json"
printf 'latest contract: %s\n' "${latest_run_dir}/ecosystem_capture_strategy_v1.json"
printf 'latest doc: %s\n' "${latest_run_dir}/ecosystem_capture_strategy_v1.md"
