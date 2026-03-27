#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${RGC_CERTIFIED_OPTIMIZATION_HARNESS_ARTIFACT_ROOT:-${root_dir}/artifacts/rgc_certified_optimization_harness}"
explicit_run_dir="${RGC_CERTIFIED_OPTIMIZATION_HARNESS_REPLAY_RUN_DIR:-}"
mode="${1:-show}"
main_exit=0
pre_run_latest_artifact_dir_path=""

run_dir_is_complete() {
  local candidate="${1:-}"
  local first_rch_log

  [[ -n "${candidate}" ]] || return 1
  [[ -f "${candidate}/run_manifest.json" ]] || return 1
  [[ -f "${candidate}/events.jsonl" ]] || return 1
  [[ -f "${candidate}/commands.txt" ]] || return 1
  [[ -f "${candidate}/rewrite_proof_index.json" ]] || return 1
  [[ -f "${candidate}/egraph_rewrite_pack.json" ]] || return 1
  [[ -f "${candidate}/trace_ids.json" ]] || return 1
  first_rch_log="$(find "${candidate}" -maxdepth 1 -type f -name 'rch-log.*' | sort | head -n1)"
  [[ -n "${first_rch_log}" ]] || return 1
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
    echo "[rgc-certified-optimization-harness] gate exited with status ${prior_exit}; replay output reflects latest complete run directory ${latest_run_dir}" >&2
    return
  fi

  if [[ -n "${prior_artifact_dir}" && "${latest_run_dir}" == "${prior_artifact_dir}" ]]; then
    echo "[rgc-certified-optimization-harness] gate exited with status ${prior_exit}; replay output reflects previous latest complete run directory ${latest_run_dir}" >&2
    return
  fi

  echo "[rgc-certified-optimization-harness] gate exited with status ${prior_exit}; replay output reflects current run directory ${latest_run_dir}" >&2
}

if [[ -z "${explicit_run_dir}" && "${mode}" != "show" ]]; then
  pre_run_latest_artifact_dir_path="$(latest_artifact_dir)"
  "${root_dir}/scripts/run_rgc_certified_optimization_harness.sh" "${mode}" || main_exit=$?
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
    echo "[rgc-certified-optimization-harness] explicit run directory is incomplete: ${explicit_run_dir}" >&2
    exit 1
  fi
  if [[ -n "${latest_artifact_dir_path}" ]]; then
    echo "[rgc-certified-optimization-harness] no complete bundle found under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "[rgc-certified-optimization-harness] no complete bundle found under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[rgc-certified-optimization-harness] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

warn_about_failed_gate_replay_source "${main_exit}" "${pre_run_latest_artifact_dir_path}"

first_rch_log_path="$(find "${latest_run_dir}" -maxdepth 1 -type f -name 'rch-log.*' | sort | head -n1)"
echo "[rgc-certified-optimization-harness] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo
echo "[rgc-certified-optimization-harness] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo
echo "[rgc-certified-optimization-harness] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo
echo "[rgc-certified-optimization-harness] latest trace ids: ${latest_run_dir}/trace_ids.json"
cat "${latest_run_dir}/trace_ids.json"
echo
echo "[rgc-certified-optimization-harness] latest proof index: ${latest_run_dir}/rewrite_proof_index.json"
cat "${latest_run_dir}/rewrite_proof_index.json"
echo
echo "[rgc-certified-optimization-harness] latest rewrite pack: ${latest_run_dir}/egraph_rewrite_pack.json"
cat "${latest_run_dir}/egraph_rewrite_pack.json"
echo
echo "[rgc-certified-optimization-harness] latest first rch log: ${first_rch_log_path}"
cat "${first_rch_log_path}"

exit "${main_exit}"
