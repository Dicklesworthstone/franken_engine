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

latest_complete_run_dir() {
  if [[ ! -d "${artifact_root}" ]]; then
    return 0
  fi

  find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d | sort | while IFS= read -r candidate; do
    [[ -f "${candidate}/run_manifest.json" ]] || continue
    [[ -f "${candidate}/matrix_summary.json" ]] || continue
    [[ -f "${candidate}/events.jsonl" ]] || continue
    printf '%s\n' "${candidate}"
  done | tail -n 1
}

latest_run_dir="$(latest_complete_run_dir)"
if [[ -z "${latest_run_dir}" ]]; then
  echo "parser cross-arch repro replay could not locate a complete run directory under ${artifact_root}" >&2
  exit "${main_exit:-1}"
fi

echo "[parser-cross-arch-repro] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[parser-cross-arch-repro] latest matrix summary: ${latest_run_dir}/matrix_summary.json"
cat "${latest_run_dir}/matrix_summary.json"
echo "[parser-cross-arch-repro] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"

exit "$main_exit"
