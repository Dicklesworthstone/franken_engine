#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

DOCS_ACCURACY_GATE_SCENARIO="smoke" \
DOCS_ACCURACY_GATE_MODE="report_only" \
  ./scripts/run_docs_accuracy_gate_suite.sh ci