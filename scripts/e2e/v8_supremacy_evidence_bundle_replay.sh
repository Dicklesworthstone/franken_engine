#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${V8_SUPREMACY_EVIDENCE_BUNDLE_ARTIFACT_ROOT:-${root_dir}/artifacts/v8_supremacy_evidence_bundle}"
mode="${1:-ci}"
main_exit=0

"${root_dir}/scripts/run_v8_supremacy_evidence_bundle_suite.sh" "${mode}" || main_exit=$?

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
    [[ -f "${candidate}/events.jsonl" ]] || continue
    [[ -f "${candidate}/commands.txt" ]] || continue
    [[ -f "${candidate}/summary.md" ]] || continue
    [[ -f "${candidate}/v8_supremacy_evidence_summary.md" ]] || continue
    [[ -f "${candidate}/env.json" ]] || continue
    [[ -f "${candidate}/repro.lock" ]] || continue
    [[ -f "${candidate}/trace_ids.json" ]] || continue
    [[ -f "${candidate}/v8_supremacy_evidence_bundle.json" ]] || continue
    [[ -f "${candidate}/supremacy_claim_mode_matrix.json" ]] || continue
    [[ -f "${candidate}/publication_mode_receipts.json" ]] || continue
    [[ -f "${candidate}/support_bundle_observability_attestation.json" ]] || continue
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
    echo "V8 supremacy evidence bundle replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "V8 supremacy evidence bundle replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[v8-supremacy-evidence-bundle] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

echo "v8 supremacy evidence bundle replay manifest: ${latest_run_dir}/run_manifest.json"
echo "v8 supremacy evidence bundle replay summary: ${latest_run_dir}/v8_supremacy_evidence_summary.md"
echo "v8 supremacy evidence bundle replay bundle: ${latest_run_dir}/v8_supremacy_evidence_bundle.json"
echo "v8 supremacy evidence bundle replay receipts: ${latest_run_dir}/publication_mode_receipts.json"

exit "$main_exit"
