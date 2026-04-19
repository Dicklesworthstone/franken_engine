#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root="${EXTENSION_HOST_TOPOLOGY_ASSESSMENT_ARTIFACT_ROOT:-artifacts/extension_host_topology_assessment}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_dir="${CARGO_TARGET_DIR:-/var/tmp/rch_target_franken_engine_extension_host_topology_assessment}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-4}"
seed="${EXTENSION_HOST_TOPOLOGY_ASSESSMENT_SEED:-1316}"
run_dir="${artifact_root}/${timestamp}_${mode}_$$"
step_logs_dir="${run_dir}/rch_step_logs"

mkdir -p "$run_dir" "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for extension-host topology assessment cargo commands" >&2
  exit 2
fi

run_rch() {
  rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "CARGO_INCREMENTAL=0" \
    "$@"
}

run_test_rch() {
  rch exec "env RUSTFLAGS=\"-C linker=cc\" RUSTUP_TOOLCHAIN=${toolchain} CARGO_TARGET_DIR=${target_dir} CARGO_BUILD_JOBS=${cargo_build_jobs} CARGO_INCREMENTAL=0 $*"
}

run_step() {
  local name="$1"
  shift
  local log_path="${step_logs_dir}/${name}.log"
  echo "==> $*"
  "$@" > >(tee "$log_path") 2>&1
}

run_check() {
  run_step check run_rch cargo check -p frankenengine-engine --lib --bin franken_extension_host_topology_assessment
}

run_test() {
  run_step test run_test_rch cargo test -p frankenengine-engine --test extension_host_topology_assessment_cli
}

run_clippy() {
  run_step clippy run_rch cargo clippy -p frankenengine-engine --lib --bin franken_extension_host_topology_assessment --test extension_host_topology_assessment_cli -- -D warnings
}

run_fmt() {
  run_step fmt run_rch cargo fmt --check
}

run_bundle() {
  run_step bundle run_test_rch cargo run -p frankenengine-engine --bin franken_extension_host_topology_assessment -- --out-dir "$run_dir" --seed "$seed"
}

case "$mode" in
  check)
    run_check
    run_bundle
    ;;
  test)
    run_test
    run_bundle
    ;;
  clippy)
    run_clippy
    ;;
  fmt)
    run_fmt
    ;;
  bundle)
    run_bundle
    ;;
  ci)
    run_check
    run_test
    run_bundle
    run_clippy
    run_fmt
    ;;
  *)
    echo "usage: $0 [check|test|clippy|fmt|bundle|ci]" >&2
    exit 2
    ;;
esac

for artifact in topology_promotion_assessment.json run_manifest.json events.jsonl commands.txt trace_ids.json summary.md env.json repro.lock; do
  if [[ "$mode" != "clippy" && "$mode" != "fmt" && ! -f "${run_dir}/${artifact}" ]]; then
    echo "missing required artifact: ${run_dir}/${artifact}" >&2
    exit 1
  fi
done

echo "extension-host topology assessment artifacts: ${run_dir}"
