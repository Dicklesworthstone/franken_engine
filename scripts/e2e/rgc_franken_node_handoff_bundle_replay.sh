#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${root_dir}"

artifact_root="${RGC_FRANKEN_NODE_HANDOFF_ARTIFACT_ROOT:-${root_dir}/artifacts/rgc_franken_node_handoff_bundle}"
mode="${1:-ci}"
main_exit=0

"${root_dir}/scripts/run_rgc_franken_node_handoff_bundle.sh" "${mode}" || main_exit=$?

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
    [[ -f "${candidate}/run_manifest.json" ]] || continue
    [[ -f "${candidate}/trace_ids.json" ]] || continue
    [[ -f "${candidate}/events.jsonl" ]] || continue
    [[ -f "${candidate}/commands.txt" ]] || continue
    [[ -f "${candidate}/franken_node_handoff_manifest.json" ]] || continue
    [[ -f "${candidate}/sibling_smoke_verification.json" ]] || continue
    [[ -f "${candidate}/support_surface_summary.md" ]] || continue
    [[ -f "${candidate}/franken_node_handoff_bundle_contract.json" ]] || continue
    [[ -f "${candidate}/support_surface_contract.json" ]] || continue
    [[ -f "${candidate}/engine_product_blocker_ledger.json" ]] || continue
    [[ -f "${candidate}/repo_split_contract.md" ]] || continue
    [[ -f "${candidate}/step_logs/step_000.log" ]] || continue
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
echo "[rgc-franken-node-handoff] latest blocker ledger: ${latest_run_dir}/engine_product_blocker_ledger.json"
cat "${latest_run_dir}/engine_product_blocker_ledger.json"
echo "[rgc-franken-node-handoff] latest repo split contract: ${latest_run_dir}/repo_split_contract.md"
cat "${latest_run_dir}/repo_split_contract.md"
echo "[rgc-franken-node-handoff] latest first step log: ${latest_run_dir}/step_logs/step_000.log"
cat "${latest_run_dir}/step_logs/step_000.log"

exit "${main_exit}"
