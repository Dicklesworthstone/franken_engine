#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

artifact_root="${PARSER_RERUN_KIT_ARTIFACT_ROOT:-artifacts/parser_third_party_rerun_kit}"
mode="${1:-package}"
main_exit=0

./scripts/run_parser_third_party_rerun_kit.sh "$mode" || main_exit=$?

latest_run_dir="$(
  find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1
)"
if [[ -z "${latest_run_dir}" ]]; then
  echo "parser third-party rerun kit replay could not locate a run directory" >&2
  exit "${main_exit:-1}"
fi

echo "[parser-third-party-rerun-kit] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[parser-third-party-rerun-kit] latest rerun kit index: ${latest_run_dir}/rerun_kit_index.json"
cat "${latest_run_dir}/rerun_kit_index.json"
echo "[parser-third-party-rerun-kit] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"

exit "$main_exit"
