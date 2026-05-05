#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${RGC_MODULE_COMPOSITION_DRIFT_GATE_ARTIFACT_ROOT:-${root_dir}/artifacts/rgc_module_composition_drift_gate}"
mode="${1:-ci}"
requested_run_dir="${2:-}"

if [[ -n "$requested_run_dir" ]]; then
  if [[ "$requested_run_dir" = /* ]]; then
    run_dir="$requested_run_dir"
  else
    run_dir="${root_dir}/${requested_run_dir}"
  fi
else
  run_dir=""
  while IFS= read -r candidate_dir; do
    candidate_report="${candidate_dir}/composition_drift_report.json"
    if [[ ! -f "$candidate_report" ]]; then
      continue
    fi

    candidate_mode="$(jq -r '.verification_mode' "$candidate_report")"
    if [[ "$candidate_mode" == "$mode" ]]; then
      run_dir="$candidate_dir"
      break
    fi
  done < <(find "$artifact_root" -mindepth 1 -maxdepth 1 -type d | LC_ALL=C sort -r)
fi

if [[ -z "${run_dir:-}" || ! -d "$run_dir" ]]; then
  echo "no module composition drift artifact directory found" >&2
  exit 1
fi

report_path="${run_dir}/composition_drift_report.json"
summary_path="${run_dir}/composition_drift_summary.md"
manifest_path="${run_dir}/manifest.json"
links_path="${run_dir}/claim_module_links.json"
statuses_path="${run_dir}/claim_statuses.json"

for required_path in "$report_path" "$summary_path" "$manifest_path" "$links_path" "$statuses_path"; do
  if [[ ! -f "$required_path" ]]; then
    echo "missing replay artifact: $required_path" >&2
    exit 1
  fi
done

artifact_mode="$(jq -r '.verification_mode' "$report_path")"
if [[ "$artifact_mode" != "$mode" ]]; then
  echo "selected artifact mode mismatch: expected ${mode}, got ${artifact_mode}" >&2
  exit 1
fi

echo "module_composition_drift_run_dir=$(realpath --relative-to="$root_dir" "$run_dir" 2>/dev/null || printf '%s' "$run_dir")"
echo "module_composition_drift_report=$(realpath --relative-to="$root_dir" "$report_path" 2>/dev/null || printf '%s' "$report_path")"
echo "module_composition_drift_summary=$(realpath --relative-to="$root_dir" "$summary_path" 2>/dev/null || printf '%s' "$summary_path")"
echo "module_composition_drift_manifest=$(realpath --relative-to="$root_dir" "$manifest_path" 2>/dev/null || printf '%s' "$manifest_path")"
echo "module_composition_drift_claim_links=$(realpath --relative-to="$root_dir" "$links_path" 2>/dev/null || printf '%s' "$links_path")"
echo "module_composition_drift_claim_statuses=$(realpath --relative-to="$root_dir" "$statuses_path" 2>/dev/null || printf '%s' "$statuses_path")"
echo
cat "$summary_path"
