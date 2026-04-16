#!/usr/bin/env bash
# Float E2E Replay Script
# Replays the most recent float e2e test run or a specific run directory.
#
# Usage:
#   ./scripts/e2e/float_e2e_replay.sh [run_dir]
#   run_dir: Optional path to specific run directory. If omitted, uses most recent.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${FLOAT_E2E_ARTIFACT_ROOT:-artifacts/float_e2e}"

if [[ $# -ge 1 ]]; then
  run_dir="$1"
else
  # Find most recent run directory
  run_dir=$(find "$artifact_root" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r | head -1)
  if [[ -z "$run_dir" ]]; then
    echo "No float e2e runs found in $artifact_root" >&2
    exit 1
  fi
fi

export FLOAT_E2E_REPLAY_RUN_DIR="$run_dir"
exec "${root_dir}/scripts/run_float_e2e.sh" replay
