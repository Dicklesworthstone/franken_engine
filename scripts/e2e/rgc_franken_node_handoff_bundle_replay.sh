#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${root_dir}"

artifact_root="${RGC_FRANKEN_NODE_HANDOFF_ARTIFACT_ROOT:-${root_dir}/artifacts/rgc_franken_node_handoff_bundle}"
explicit_run_dir="${RGC_FRANKEN_NODE_HANDOFF_BUNDLE_REPLAY_RUN_DIR:-}"
mode="${1:-ci}"
main_exit=0

if [[ -z "${explicit_run_dir}" ]]; then
  "${root_dir}/scripts/run_rgc_franken_node_handoff_bundle.sh" "${mode}" || main_exit=$?
fi

artifact_dirs_by_mtime_desc() {
  local search_root="${1:-}"
  [[ -d "${search_root}" ]] || return 0

  find "${search_root}" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | cut -d' ' -f2-
}

latest_artifact_dir() {
  local candidate
  while IFS= read -r candidate; do
    printf '%s\n' "${candidate}"
    return 0
  done < <(artifact_dirs_by_mtime_desc "${artifact_root}")
}

run_dir_is_complete() {
  local candidate="${1:-}"
  [[ -f "${candidate}/run_manifest.json" ]] || return 1
  [[ -f "${candidate}/trace_ids.json" ]] || return 1
  [[ -f "${candidate}/events.jsonl" ]] || return 1
  [[ -f "${candidate}/commands.txt" ]] || return 1
  [[ -f "${candidate}/franken_node_handoff_manifest.json" ]] || return 1
  [[ -f "${candidate}/sibling_smoke_verification.json" ]] || return 1
  [[ -f "${candidate}/support_surface_summary.md" ]] || return 1
  [[ -f "${candidate}/franken_node_handoff_bundle_contract.json" ]] || return 1
  [[ -f "${candidate}/support_surface_contract.json" ]] || return 1
  [[ -f "${candidate}/engine_product_blocker_ledger.json" ]] || return 1
  [[ -f "${candidate}/repo_split_contract.md" ]] || return 1
  [[ -f "${candidate}/step_logs/step_000.log" ]] || return 1
}

latest_complete_run_dir() {
  local candidate
  while IFS= read -r candidate; do
    run_dir_is_complete "${candidate}" || continue
    printf '%s\n' "${candidate}"
    return 0
  done < <(artifact_dirs_by_mtime_desc "${artifact_root}")
}

missing_bundle_exit_code() {
  local prior_exit="${1:-1}"
  if [[ "${prior_exit}" -eq 0 ]]; then
    echo 1
    return
  fi

  echo "${prior_exit}"
}

latest_artifact_dir_path=""
latest_run_dir=""

if [[ -n "${explicit_run_dir}" ]]; then
  latest_run_dir="${explicit_run_dir}"
  if ! run_dir_is_complete "${latest_run_dir}"; then
    echo "rgc franken_node handoff replay explicit run directory ${latest_run_dir} is incomplete" >&2
    exit "$(missing_bundle_exit_code "${main_exit:-1}")"
  fi
  echo "[rgc-franken-node-handoff] using explicit preserved run directory ${latest_run_dir}" >&2
else
  latest_artifact_dir_path="$(latest_artifact_dir)"
  latest_run_dir="$(latest_complete_run_dir)"
  if [[ -z "${latest_run_dir}" ]]; then
    if [[ -n "${latest_artifact_dir_path}" ]]; then
      echo "rgc franken_node handoff replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
    else
      echo "rgc franken_node handoff replay could not locate a complete run directory under ${artifact_root}" >&2
    fi
    exit "$(missing_bundle_exit_code "${main_exit:-1}")"
  fi

  if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
    echo "[rgc-franken-node-handoff] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
  fi
fi

echo "[rgc-franken-node-handoff] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[rgc-franken-node-handoff] latest trace ids: ${latest_run_dir}/trace_ids.json"
cat "${latest_run_dir}/trace_ids.json"
echo "[rgc-franken-node-handoff] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo "[rgc-franken-node-handoff] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo "[rgc-franken-node-handoff] latest handoff manifest: ${latest_run_dir}/franken_node_handoff_manifest.json"
cat "${latest_run_dir}/franken_node_handoff_manifest.json"
echo "[rgc-franken-node-handoff] latest smoke verification: ${latest_run_dir}/sibling_smoke_verification.json"
cat "${latest_run_dir}/sibling_smoke_verification.json"
echo "[rgc-franken-node-handoff] latest summary: ${latest_run_dir}/support_surface_summary.md"
cat "${latest_run_dir}/support_surface_summary.md"
echo "[rgc-franken-node-handoff] latest contract: ${latest_run_dir}/franken_node_handoff_bundle_contract.json"
cat "${latest_run_dir}/franken_node_handoff_bundle_contract.json"
echo "[rgc-franken-node-handoff] latest support contract: ${latest_run_dir}/support_surface_contract.json"
cat "${latest_run_dir}/support_surface_contract.json"
if [[ ! -f "${latest_run_dir}/engine_product_blocker_ledger.json" ]]; then
  echo "rgc franken_node handoff replay selected supposedly complete run ${latest_run_dir} but engine_product_blocker_ledger.json is missing" >&2
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi
echo "[rgc-franken-node-handoff] latest blocker ledger: ${latest_run_dir}/engine_product_blocker_ledger.json"
cat "${latest_run_dir}/engine_product_blocker_ledger.json"
echo "[rgc-franken-node-handoff] latest repo split contract: ${latest_run_dir}/repo_split_contract.md"
cat "${latest_run_dir}/repo_split_contract.md"
if [[ ! -f "${latest_run_dir}/step_logs/step_000.log" ]]; then
  echo "rgc franken_node handoff replay selected supposedly complete run ${latest_run_dir} but step_logs/step_000.log is missing" >&2
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi
echo "[rgc-franken-node-handoff] latest first step log: ${latest_run_dir}/step_logs/step_000.log"
cat "${latest_run_dir}/step_logs/step_000.log"

exit "${main_exit}"
