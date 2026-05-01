#!/usr/bin/env bash
set -euo pipefail

mode="${1:-ci}"
seed="${SIM_SCHEDULER_SEED:-803}"
trials="${SIM_SCHEDULER_TRIALS:-3}"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
out_dir="${SIM_SCHEDULER_ARTIFACT_DIR:-artifacts/deterministic_sim_scheduler/${run_id}}"
log_prefix="[deterministic-sim-scheduler]"

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

log_json "start" "running" "mode=${mode}"
mkdir -p "${out_dir}"

cargo run -p frankenengine-engine --bin franken_deterministic_sim_scheduler_artifacts -- \
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
  cargo test -p frankenengine-engine --test deterministic_sim_scheduler_integration
  cargo test -p frankenengine-engine --test deterministic_sim_scheduler_enrichment_integration
  cargo test -p frankenengine-engine --test scheduler_metamorphic_queue_shape
  cargo test -p frankenengine-engine --test deterministic_sim_scheduler_artifacts
fi

log_json "complete" "pass" "artifact bundle verified"
log "artifact bundle verified at ${out_dir}"
