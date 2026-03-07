#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mode="${1:-ci}"
shift || true

"${root_dir}/scripts/run_rgc_claim_envelope_contract.sh" "${mode}" "$@"
