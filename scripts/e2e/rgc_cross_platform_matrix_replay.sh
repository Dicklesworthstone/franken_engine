#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
: "${RGC_CROSS_PLATFORM_AUTO_DISCOVER_MANIFESTS:=1}"
export RGC_CROSS_PLATFORM_AUTO_DISCOVER_MANIFESTS

"${root_dir}/scripts/run_rgc_cross_platform_matrix_gate.sh" "${mode}"
