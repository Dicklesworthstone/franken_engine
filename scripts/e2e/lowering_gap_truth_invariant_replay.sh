#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mode="${1:-ci}"
artifact_root="${LOWERING_GAP_TRUTH_INVARIANT_ARTIFACT_ROOT:-artifacts/lowering_gap_truth_invariant}"
explicit_run_dir="${LOWERING_GAP_TRUTH_INVARIANT_REPLAY_RUN_DIR:-}"
main_exit=0

run_dir_is_complete() {
  local candidate="${1:-}"
  [[ -n "${candidate}" ]] || return 1
  [[ -f "${candidate}/run_manifest.json" ]] || return 1
  [[ -f "${candidate}/trace_ids.json" ]] || return 1
  [[ -f "${candidate}/events.jsonl" ]] || return 1
  [[ -f "${candidate}/commands.txt" ]] || return 1
  [[ -f "${candidate}/lowering_gap_truth_invariant.json" ]] || return 1
  [[ -f "${candidate}/lowering_gap_truth_invariant_validation_report.json" ]] || return 1
  [[ -f "${candidate}/step_logs/step_000.log" ]] || return 1
}

cd "${root_dir}"
if [[ -z "${explicit_run_dir}" ]]; then
  ./scripts/run_lowering_gap_truth_invariant.sh "${mode}" || main_exit=$?
fi

latest_complete_run_dir() {
  if [[ ! -d "${artifact_root}" ]]; then
    return 0
  fi

  find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d | sort | while IFS= read -r candidate; do
    run_dir_is_complete "${candidate}" || continue
    printf '%s\n' "${candidate}"
  done | tail -n 1
}

latest_run_dir="$(latest_complete_run_dir)"
if [[ -n "${explicit_run_dir}" ]]; then
  latest_run_dir=""
  if run_dir_is_complete "${explicit_run_dir}"; then
    latest_run_dir="${explicit_run_dir}"
  fi
fi

if [[ -z "${latest_run_dir}" ]]; then
  if [[ -n "${explicit_run_dir}" ]]; then
    echo "lowering gap truth invariant replay explicit run directory is incomplete: ${explicit_run_dir}" >&2
  else
    echo "lowering gap truth invariant replay found no complete artifact directory under ${artifact_root}" >&2
  fi
  exit "${main_exit:-1}"
fi

echo "[lowering-gap-truth-invariant] latest run dir: ${latest_run_dir}"
echo "[lowering-gap-truth-invariant] run manifest:"
cat "${latest_run_dir}/run_manifest.json"
echo "[lowering-gap-truth-invariant] trace ids:"
cat "${latest_run_dir}/trace_ids.json"
echo "[lowering-gap-truth-invariant] events:"
cat "${latest_run_dir}/events.jsonl"
echo "[lowering-gap-truth-invariant] commands:"
cat "${latest_run_dir}/commands.txt"
echo "[lowering-gap-truth-invariant] contract:"
cat "${latest_run_dir}/lowering_gap_truth_invariant.json"
echo "[lowering-gap-truth-invariant] validation report:"
cat "${latest_run_dir}/lowering_gap_truth_invariant_validation_report.json"
echo "[lowering-gap-truth-invariant] step logs:"
for step_log in "${latest_run_dir}"/step_logs/step_*.log; do
  [[ -e "${step_log}" ]] || continue
  echo "--- ${step_log}"
  cat "${step_log}"
done

exit "${main_exit}"
