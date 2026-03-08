#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mode="${1:-report}"

"${root_dir}/scripts/run_lockstep_runner_suite.sh" "${mode}"
