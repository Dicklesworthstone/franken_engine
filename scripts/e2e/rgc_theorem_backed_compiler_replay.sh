#!/usr/bin/env bash
#
# Deterministic replay wrapper for the G.9 theorem-backed-compiler proof-recheck
# gate (bd-cixqu.7.12). Locates the latest complete gate run, optionally reruns
# the gate, and prints the run_manifest.json + events.jsonl for operator review.
# Fail-closed: exits non-zero when no complete bundle exists.
#
# Usage:
#   ./scripts/e2e/rgc_theorem_backed_compiler_replay.sh [show|selftest|ci|verify]
#
#   show       (default) print the latest complete run; do not rerun the gate
#   selftest   rerun the gate in selftest mode, then print the latest run
#   ci|verify  rerun the gate in that mode, then print the latest run
#
# Environment:
#   RGC_THEOREM_BACKED_COMPILER_ARTIFACT_ROOT   artifact root to scan
#   RGC_THEOREM_BACKED_COMPILER_REPLAY_RUN_DIR  inspect this exact run dir
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ROOT_DIR
cd "${ROOT_DIR}"

readonly GATE_NAME="rgc_theorem_backed_compiler"
artifact_root="${RGC_THEOREM_BACKED_COMPILER_ARTIFACT_ROOT:-${ROOT_DIR}/artifacts/${GATE_NAME}}"
explicit_run_dir="${RGC_THEOREM_BACKED_COMPILER_REPLAY_RUN_DIR:-}"
mode="${1:-show}"
main_exit=0

run_dir_is_complete() {
  local candidate="${1:-}"
  [[ -n "${candidate}" ]] || return 1
  [[ -f "${candidate}/run_manifest.json" ]] || return 1
  [[ -f "${candidate}/events.jsonl" ]] || return 1
  [[ -f "${candidate}/proof_inventory.json" ]] || return 1
  [[ -f "${candidate}/claim_recheck_verdicts.json" ]] || return 1
}

latest_complete_run_dir() {
  [[ -d "${artifact_root}" ]] || return 0
  find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d | sort | while IFS= read -r candidate; do
    run_dir_is_complete "${candidate}" || continue
    printf '%s\n' "${candidate}"
  done | tail -n 1
}

# Rerun the gate unless we are only showing a preserved run.
if [[ -z "${explicit_run_dir}" && "${mode}" != "show" ]]; then
  "${ROOT_DIR}/scripts/run_rgc_theorem_backed_compiler.sh" "${mode}" || main_exit=$?
fi

if [[ -n "${explicit_run_dir}" ]]; then
  run_dir="${explicit_run_dir}"
else
  run_dir="$(latest_complete_run_dir || true)"
fi

if ! run_dir_is_complete "${run_dir}"; then
  if [[ -n "${explicit_run_dir}" ]]; then
    echo "[${GATE_NAME}] explicit run directory is incomplete: ${explicit_run_dir}" >&2
  else
    echo "[${GATE_NAME}] no complete bundle under ${artifact_root}; run the gate first" >&2
  fi
  exit 1
fi

echo "[${GATE_NAME}] latest manifest: ${run_dir}/run_manifest.json"
cat "${run_dir}/run_manifest.json"
echo
echo "[${GATE_NAME}] events: ${run_dir}/events.jsonl"
cat "${run_dir}/events.jsonl"
echo
echo "[${GATE_NAME}] proof inventory: ${run_dir}/proof_inventory.json"
cat "${run_dir}/proof_inventory.json"

exit "${main_exit}"
