#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

mode="${1:-test}"
"${root_dir}/scripts/run_acquisition_experiment_oracle_suite.sh" "${mode}"
