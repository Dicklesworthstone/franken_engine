#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

scenario="${1:-full}"
mode="${2:-ci}"

case "${scenario}" in
  positive|negative|family|full)
    ;;
  *)
    echo "usage: $0 [positive|negative|family|full] [check|test|clippy|ci]" >&2
    exit 2
    ;;
esac

case "${mode}" in
  check|test|clippy|ci)
    ;;
  *)
    echo "usage: $0 [positive|negative|family|full] [check|test|clippy|ci]" >&2
    exit 2
    ;;
esac

PARSER_OPTIONAL_CHAINING_SCENARIO="${scenario}" \
  ./scripts/run_parser_optional_chaining_suite.sh "${mode}"
