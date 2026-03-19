#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${RGC_METADATA_SUBSTRATE_EVIDENCE_ARTIFACT_ROOT:-artifacts/rgc_metadata_substrate_evidence}"
mode="${1:-run}"
main_exit=0

"${root_dir}/scripts/run_rgc_metadata_substrate_evidence.sh" "${mode}" || main_exit=$?

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
    [[ -f "${candidate}/runtime_metadata_substrate_report.json" ]] || continue
    [[ -f "${candidate}/runtime_metadata_substrate_evidence_manifest.json" ]] || continue
    [[ -f "${candidate}/cache_miss_profile.json" ]] || continue
    [[ -f "${candidate}/metadata_fallback_receipts.json" ]] || continue
    [[ -f "${candidate}/substrate_override_receipts.json" ]] || continue
    [[ -f "${candidate}/run_manifest.json" ]] || continue
    [[ -f "${candidate}/events.jsonl" ]] || continue
    [[ -f "${candidate}/commands.txt" ]] || continue
    [[ -f "${candidate}/trace_ids.json" ]] || continue
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
    echo "metadata substrate evidence replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "metadata substrate evidence replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[metadata-substrate-evidence] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

echo "[metadata-substrate-evidence] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[metadata-substrate-evidence] latest runtime metadata substrate report: ${latest_run_dir}/runtime_metadata_substrate_report.json"
cat "${latest_run_dir}/runtime_metadata_substrate_report.json"
echo "[metadata-substrate-evidence] latest evidence manifest: ${latest_run_dir}/runtime_metadata_substrate_evidence_manifest.json"
cat "${latest_run_dir}/runtime_metadata_substrate_evidence_manifest.json"
echo "[metadata-substrate-evidence] latest cache-miss profile: ${latest_run_dir}/cache_miss_profile.json"
cat "${latest_run_dir}/cache_miss_profile.json"
echo "[metadata-substrate-evidence] latest fallback receipts: ${latest_run_dir}/metadata_fallback_receipts.json"
cat "${latest_run_dir}/metadata_fallback_receipts.json"
echo "[metadata-substrate-evidence] latest override receipts: ${latest_run_dir}/substrate_override_receipts.json"
cat "${latest_run_dir}/substrate_override_receipts.json"
echo "[metadata-substrate-evidence] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo "[metadata-substrate-evidence] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo "[metadata-substrate-evidence] latest trace ids: ${latest_run_dir}/trace_ids.json"
cat "${latest_run_dir}/trace_ids.json"

first_step_log="$(find "${latest_run_dir}/step_logs" -mindepth 1 -maxdepth 1 -type f 2>/dev/null | sort | head -n 1)"
if [[ -n "${first_step_log}" ]]; then
  echo "[metadata-substrate-evidence] latest first step log: ${first_step_log}"
  cat "${first_step_log}"
fi

exit "${main_exit}"
