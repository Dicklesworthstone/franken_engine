#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"

echo "Running deterministic resource budget escalation demo..."
echo

# Use the real implementation
export CARGO_TARGET_DIR="${repo_root}/target_resource_demo"
cd "${repo_root}"
cargo run --bin franken_resource_budget_demo -- "demo:budget-exhaustion"
