#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${IFC_RELEASE_GATE_ARTIFACT_ROOT:-artifacts/ifc_release_gate}"
mode="${1:-gate}"
main_exit=0

"${root_dir}/scripts/run_ifc_release_gate.sh" "${mode}" || main_exit=$?

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
    [[ -f "${candidate}/ifc_release_gate_events.jsonl" ]] || continue
    [[ -f "${candidate}/commands.txt" ]] || continue
    [[ -d "${candidate}/ifc_conformance" ]] || continue
    find "${candidate}/ifc_conformance" -type f -name 'ifc_conformance_evidence.jsonl' -print -quit | grep -q . || continue
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

latest_evidence_path() {
  local run_dir="${1:-}"
  if [[ -z "${run_dir}" ]]; then
    return 0
  fi

  find "${run_dir}/ifc_conformance" -type f -name 'ifc_conformance_evidence.jsonl' | sort | tail -n 1
}

latest_artifact_dir_path="$(latest_artifact_dir)"
latest_run_dir="$(latest_complete_run_dir)"
if [[ -z "${latest_run_dir}" ]]; then
  if [[ -n "${latest_artifact_dir_path}" ]]; then
    echo "IFC release gate replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "IFC release gate replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[ifc-release-gate] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

latest_evidence_path="$(latest_evidence_path "${latest_run_dir}")"
if [[ -z "${latest_evidence_path}" ]]; then
  echo "IFC release gate replay could not locate ifc_conformance_evidence.jsonl under ${latest_run_dir}/ifc_conformance" >&2
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

echo "[ifc-release-gate] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[ifc-release-gate] latest events: ${latest_run_dir}/ifc_release_gate_events.jsonl"
cat "${latest_run_dir}/ifc_release_gate_events.jsonl"
echo "[ifc-release-gate] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo "[ifc-release-gate] latest evidence: ${latest_evidence_path}"
cat "${latest_evidence_path}"
echo "[ifc-release-gate] latest conformance output tree: ${latest_run_dir}/ifc_conformance"
ls -R "${latest_run_dir}/ifc_conformance"

exit "${main_exit}"
