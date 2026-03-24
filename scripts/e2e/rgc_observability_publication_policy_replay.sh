#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${RGC_OBSERVABILITY_PUBLICATION_POLICY_ARTIFACT_ROOT:-artifacts/rgc_observability_publication_policy}"
explicit_run_dir="${RGC_OBSERVABILITY_PUBLICATION_POLICY_REPLAY_RUN_DIR:-}"
mode="${1:-ci}"
main_exit=0

run_dir_is_complete() {
  local candidate="${1:-}"
  [[ -n "${candidate}" ]] || return 1
  [[ -f "${candidate}/run_manifest.json" ]] || return 1
  [[ -f "${candidate}/trace_ids" ]] || return 1
  [[ -f "${candidate}/events.jsonl" ]] || return 1
  [[ -f "${candidate}/commands.txt" ]] || return 1
  [[ -f "${candidate}/step_logs/step-01.log" ]] || return 1
  [[ -f "${candidate}/observability_budget_sentinel_report.json" ]] || return 1
  [[ -f "${candidate}/observability_on_supremacy_matrix.json" ]] || return 1
  [[ -f "${candidate}/observability_claim_delta_report.json" ]] || return 1
  [[ -f "${candidate}/telemetry_demotion_receipts.json" ]] || return 1
  [[ -f "${candidate}/observability_publication_policy.json" ]] || return 1
  [[ -f "${candidate}/support_bundle_observability_attestation.json" ]] || return 1
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
  if [[ "${prior_exit}" -eq 0 ]]; then
    return
  fi

  if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
    echo "[rgc-observability-publication-policy] gate exited with status ${prior_exit}; replay output reflects latest complete run directory ${latest_run_dir}" >&2
    return
  fi

  echo "[rgc-observability-publication-policy] gate exited with status ${prior_exit}; replay output reflects current run directory ${latest_run_dir}" >&2
}

if [[ -z "${explicit_run_dir}" ]]; then
  "${root_dir}/scripts/run_rgc_observability_publication_policy.sh" "${mode}" || main_exit=$?
fi

latest_artifact_dir_path="$(latest_artifact_dir)"
latest_run_dir="$(latest_complete_run_dir)"
if [[ -n "${explicit_run_dir}" ]]; then
  latest_artifact_dir_path="${explicit_run_dir}"
  latest_run_dir=""
  if run_dir_is_complete "${explicit_run_dir}"; then
    latest_run_dir="${explicit_run_dir}"
  fi
fi

if [[ -z "${latest_run_dir}" ]]; then
  if [[ -n "${explicit_run_dir}" ]]; then
    echo "rgc observability publication policy replay explicit run directory is incomplete: ${explicit_run_dir}" >&2
    exit 1
  fi
  if [[ -n "${latest_artifact_dir_path}" ]]; then
    echo "rgc observability publication policy replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "rgc observability publication policy replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[rgc-observability-publication-policy] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

warn_about_failed_gate_replay_source "${main_exit}"

echo "[rgc-observability-publication-policy] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[rgc-observability-publication-policy] latest trace ids: ${latest_run_dir}/trace_ids"
cat "${latest_run_dir}/trace_ids"
echo "[rgc-observability-publication-policy] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo "[rgc-observability-publication-policy] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo "[rgc-observability-publication-policy] latest first step log: ${latest_run_dir}/step_logs/step-01.log"
cat "${latest_run_dir}/step_logs/step-01.log"
echo "[rgc-observability-publication-policy] latest budget sentinel report: ${latest_run_dir}/observability_budget_sentinel_report.json"
cat "${latest_run_dir}/observability_budget_sentinel_report.json"
echo "[rgc-observability-publication-policy] latest supremacy matrix: ${latest_run_dir}/observability_on_supremacy_matrix.json"
cat "${latest_run_dir}/observability_on_supremacy_matrix.json"
echo "[rgc-observability-publication-policy] latest claim delta report: ${latest_run_dir}/observability_claim_delta_report.json"
cat "${latest_run_dir}/observability_claim_delta_report.json"
echo "[rgc-observability-publication-policy] latest telemetry demotion receipts: ${latest_run_dir}/telemetry_demotion_receipts.json"
cat "${latest_run_dir}/telemetry_demotion_receipts.json"
echo "[rgc-observability-publication-policy] latest publication policy: ${latest_run_dir}/observability_publication_policy.json"
cat "${latest_run_dir}/observability_publication_policy.json"
echo "[rgc-observability-publication-policy] latest support bundle observability attestation: ${latest_run_dir}/support_bundle_observability_attestation.json"
cat "${latest_run_dir}/support_bundle_observability_attestation.json"

exit "$main_exit"
