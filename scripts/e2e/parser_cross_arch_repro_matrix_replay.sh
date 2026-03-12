#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

artifact_root="${PARSER_CROSS_ARCH_REPRO_ARTIFACT_ROOT:-artifacts/parser_cross_arch_repro_matrix}"
mode="${1:-matrix}"
main_exit=0

./scripts/run_parser_cross_arch_repro_matrix.sh "${mode}" || main_exit=$?

latest_run_dir="$(
  find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1
)"
if [[ -z "${latest_run_dir}" ]]; then
  echo "parser cross-arch repro replay could not locate a run directory" >&2
  exit "${main_exit:-1}"
fi

echo "[parser-cross-arch-repro] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[parser-cross-arch-repro] latest matrix summary: ${latest_run_dir}/matrix_summary.json"
cat "${latest_run_dir}/matrix_summary.json"
echo "[parser-cross-arch-repro] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"

exit "$main_exit"
