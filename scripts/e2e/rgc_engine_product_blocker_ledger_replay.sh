#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${RGC_ENGINE_PRODUCT_BLOCKER_LEDGER_ARTIFACT_ROOT:-${root_dir}/artifacts/rgc_engine_product_blocker_ledger}"
explicit_run_dir="${RGC_ENGINE_PRODUCT_BLOCKER_LEDGER_REPLAY_RUN_DIR:-}"
mode="${1:-show}"
main_exit=0
pre_run_latest_artifact_dir_path=""

run_dir_is_complete() {
  local candidate="${1:-}"
  local first_step_log

  [[ -n "${candidate}" ]] || return 1
  [[ -f "${candidate}/run_manifest.json" ]] || return 1
  [[ -f "${candidate}/events.jsonl" ]] || return 1
  [[ -f "${candidate}/commands.txt" ]] || return 1
  [[ -f "${candidate}/support_surface_contract.json" ]] || return 1
  [[ -f "${candidate}/beads_snapshot.json" ]] || return 1
  [[ -f "${candidate}/engine_product_blocker_ledger.json" ]] || return 1
  [[ -f "${candidate}/cohort_readiness_rollup.json" ]] || return 1
  [[ -f "${candidate}/owner_routing_report.json" ]] || return 1
  [[ -f "${candidate}/gate_report.json" ]] || return 1
  [[ -f "${candidate}/trace_ids.json" ]] || return 1
  first_step_log="$(find "${candidate}/step_logs" -maxdepth 1 -type f -name 'step_*.log' | sort | head -n1)"
  [[ -n "${first_step_log}" ]] || return 1
}

latest_artifact_dir() {
  if [[ ! -d "${artifact_root}" ]]; then
    return 0
  fi

  find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1
}

latest_complete_run_dir() {
  if [[ ! -d "${artifact_root}" ]]; then
    return 0
  fi

  find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d | sort | while IFS= read -r candidate; do
    run_dir_is_complete "${candidate}" || continue
    printf '%s\n' "${candidate}"
  done | tail -n 1
}

missing_bundle_exit_code() {
  local prior_exit="${1:-1}"
  if [[ "${prior_exit}" -eq 0 ]]; then
    echo 1
    return
  fi

  echo "${prior_exit}"
}

warn_about_failed_gate_replay_source() {
  local prior_exit="${1:-0}"
  local prior_artifact_dir="${2:-}"
  if [[ "${prior_exit}" -eq 0 ]]; then
    return
  fi

  if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
    echo "[rgc-engine-product-blocker-ledger] gate exited with status ${prior_exit}; replay output reflects latest complete run directory ${latest_run_dir}" >&2
    return
  fi

  if [[ -n "${prior_artifact_dir}" && "${latest_run_dir}" == "${prior_artifact_dir}" ]]; then
    echo "[rgc-engine-product-blocker-ledger] gate exited with status ${prior_exit}; replay output reflects previous latest complete run directory ${latest_run_dir}" >&2
    return
  fi

  echo "[rgc-engine-product-blocker-ledger] gate exited with status ${prior_exit}; replay output reflects current run directory ${latest_run_dir}" >&2
}

if [[ -z "${explicit_run_dir}" && "${mode}" != "show" ]]; then
  pre_run_latest_artifact_dir_path="$(latest_artifact_dir)"
  "${root_dir}/scripts/run_rgc_engine_product_blocker_ledger.sh" "${mode}" || main_exit=$?
fi

latest_artifact_dir_path="$(latest_artifact_dir || true)"
latest_run_dir="$(latest_complete_run_dir || true)"
if [[ -n "${explicit_run_dir}" ]]; then
  latest_artifact_dir_path="${explicit_run_dir}"
  latest_run_dir=""
  if run_dir_is_complete "${explicit_run_dir}"; then
    latest_run_dir="${explicit_run_dir}"
  fi
fi

if [[ -z "${latest_run_dir}" ]]; then
  if [[ -n "${explicit_run_dir}" ]]; then
    echo "[rgc-engine-product-blocker-ledger] explicit run directory is incomplete: ${explicit_run_dir}" >&2
    exit 1
  fi
  if [[ -n "${latest_artifact_dir_path}" ]]; then
    echo "[rgc-engine-product-blocker-ledger] no complete bundle found under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "[rgc-engine-product-blocker-ledger] no complete bundle found under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[rgc-engine-product-blocker-ledger] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

warn_about_failed_gate_replay_source "${main_exit}" "${pre_run_latest_artifact_dir_path}"

first_step_log_path="$(find "${latest_run_dir}/step_logs" -maxdepth 1 -type f -name 'step_*.log' | sort | head -n1)"
echo "[rgc-engine-product-blocker-ledger] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo
echo "[rgc-engine-product-blocker-ledger] latest trace ids: ${latest_run_dir}/trace_ids.json"
cat "${latest_run_dir}/trace_ids.json"
echo
echo "[rgc-engine-product-blocker-ledger] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo
echo "[rgc-engine-product-blocker-ledger] latest gate report: ${latest_run_dir}/gate_report.json"
cat "${latest_run_dir}/gate_report.json"
echo
echo "[rgc-engine-product-blocker-ledger] latest ledger: ${latest_run_dir}/engine_product_blocker_ledger.json"
cat "${latest_run_dir}/engine_product_blocker_ledger.json"
echo
echo "[rgc-engine-product-blocker-ledger] latest cohort rollup: ${latest_run_dir}/cohort_readiness_rollup.json"
cat "${latest_run_dir}/cohort_readiness_rollup.json"
echo
echo "[rgc-engine-product-blocker-ledger] latest owner routing report: ${latest_run_dir}/owner_routing_report.json"
cat "${latest_run_dir}/owner_routing_report.json"
echo
echo "[rgc-engine-product-blocker-ledger] latest first step log: ${first_step_log_path}"
cat "${first_step_log_path}"

exit "${main_exit}"
