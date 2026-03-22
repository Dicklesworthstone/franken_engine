#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${RGC_ENGINE_PRODUCT_BLOCKER_LEDGER_ARTIFACT_ROOT:-${root_dir}/artifacts/rgc_engine_product_blocker_ledger}"
mode="${1:-show}"

if [[ "${mode}" != "show" ]]; then
  "${root_dir}/scripts/run_rgc_engine_product_blocker_ledger.sh" "${mode}"
fi

if [[ ! -d "${artifact_root}" ]]; then
  echo "[rgc-engine-product-blocker-ledger] artifact root missing: ${artifact_root}" >&2
  exit 1
fi

latest_complete_run_dir() {
  local candidate

  for candidate in $(find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d | sort -r); do
    [[ -f "${candidate}/run_manifest.json" ]] || continue
    [[ -f "${candidate}/engine_product_blocker_ledger.json" ]] || continue
    [[ -f "${candidate}/cohort_readiness_rollup.json" ]] || continue
    [[ -f "${candidate}/owner_routing_report.json" ]] || continue
    [[ -f "${candidate}/gate_report.json" ]] || continue
    [[ -f "${candidate}/trace_ids.json" ]] || continue
    printf '%s\n' "${candidate}"
    return 0
  done

  return 1
}

latest_run_dir="$(latest_complete_run_dir || true)"
if [[ -z "${latest_run_dir}" ]]; then
  echo "[rgc-engine-product-blocker-ledger] no complete bundle found under ${artifact_root}" >&2
  exit 1
fi

echo "[rgc-engine-product-blocker-ledger] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
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
