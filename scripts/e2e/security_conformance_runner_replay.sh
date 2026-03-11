#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mode="${1:-run}"

"${root_dir}/scripts/run_security_conformance_runner.sh" "${mode}"
