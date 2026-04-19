#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

mode="${1:-bundle}"
shift || true

ASUPERSYNC_LEVERAGE_ADOPTION_GATE_ARTIFACT_ROOT="${ASUPERSYNC_LEVERAGE_ADOPTION_GATE_ARTIFACT_ROOT:-artifacts/asupersync_leverage_adoption_gate/replay}" \
  ./scripts/run_asupersync_leverage_adoption_gate.sh "$mode" "$@"
