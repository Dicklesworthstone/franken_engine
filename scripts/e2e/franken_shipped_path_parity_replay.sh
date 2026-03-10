#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mode="${1:-run}"

cd "${root_dir}"
./scripts/run_franken_shipped_path_parity.sh "${mode}"

latest_run_dir="$(find artifacts/franken_shipped_path_parity -mindepth 2 -maxdepth 2 -type d | sort | tail -n1)"
if [[ -z "${latest_run_dir}" ]]; then
  echo "[franken-shipped-path-parity] no artifact directory found" >&2
  exit 1
fi

echo "[franken-shipped-path-parity] latest run dir: ${latest_run_dir}"
cat "${latest_run_dir}/run_manifest.json"
