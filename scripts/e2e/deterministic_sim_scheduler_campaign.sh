#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${root_dir}"

mode="${1:-ci}"
seed="${SIM_SCHEDULER_SEED:-803}"
trials="${SIM_SCHEDULER_TRIALS:-3}"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
out_dir="${SIM_SCHEDULER_ARTIFACT_DIR:-artifacts/deterministic_sim_scheduler/${run_id}}"
log_prefix="[deterministic-sim-scheduler]"
export RUSTC_WRAPPER="${RUSTC_WRAPPER:-}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${root_dir}/target/deterministic_sim_scheduler}"

if ! command -v rch >/dev/null 2>&1; then
  echo "${log_prefix} rch is required for Cargo campaign steps" >&2
  exit 2
fi

log() {
  printf '%s %s\n' "${log_prefix}" "$*"
}

log_json() {
  local event="$1"
  local outcome="$2"
  local detail="$3"
  printf '{"component":"deterministic_sim_scheduler","event":"%s","outcome":"%s","seed":%s,"trials":%s,"out_dir":"%s","detail":"%s"}\n' \
    "${event}" "${outcome}" "${seed}" "${trials}" "${out_dir}" "${detail}"
}

require_file() {
  local path="$1"
  if [[ ! -s "${path}" ]]; then
    log_json "required_artifact_missing" "fail" "${path}"
    exit 42
  fi
  log_json "required_artifact_present" "pass" "${path}"
}

run_cargo_step() {
  rch exec -- env \
    "RUSTC_WRAPPER=${RUSTC_WRAPPER}" \
    "CARGO_INCREMENTAL=${CARGO_INCREMENTAL}" \
    "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}" \
    "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}" \
    cargo "$@"
}

log_json "start" "running" "mode=${mode}"
mkdir -p "${out_dir}"

run_cargo_step run -p frankenengine-engine --bin franken_deterministic_sim_scheduler_artifacts -- \
  --out-dir "${out_dir}" \
  --seed "${seed}" \
  --trials "${trials}"

required_files=(
  deterministic_simulation_report.json
  simulation_schedule_catalog.json
  simulated_nondeterminism_trace.jsonl
  simulation_oracle_matrix.json
  run_manifest.json
  events.jsonl
  commands.txt
  trace_ids.json
  env.json
  manifest.json
  repro.lock
)

for file in "${required_files[@]}"; do
  require_file "${out_dir}/${file}"
done

grep -q '"status": "pass"' "${out_dir}/deterministic_simulation_report.json"
grep -q '"overall_outcome": "pass"' "${out_dir}/simulation_oracle_matrix.json"
grep -q '"outcome":"pass"' "${out_dir}/events.jsonl"

if [[ "${mode}" == "full" ]]; then
  log_json "focused_tests" "running" "cargo test deterministic scheduler surfaces"
  run_cargo_step test -p frankenengine-engine --test deterministic_sim_scheduler_integration
  run_cargo_step test -p frankenengine-engine --test deterministic_sim_scheduler_enrichment_integration
  run_cargo_step test -p frankenengine-engine --test scheduler_metamorphic_queue_shape
  run_cargo_step test -p frankenengine-engine --test deterministic_sim_scheduler_artifacts
fi

log_json "complete" "pass" "artifact bundle verified"
log "artifact bundle verified at ${out_dir}"
