#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mode="${1:-replay}"
artifact_root="${RGC_JSON_COMPOUND_PLACEHOLDER_CLOSURE_ARTIFACT_ROOT:-artifacts/rgc_json_compound_placeholder_closure}"
explicit_run_dir="${RGC_JSON_COMPOUND_PLACEHOLDER_CLOSURE_REPLAY_RUN_DIR:-}"
main_exit=0

run_dir_is_complete() {
  local candidate="${1:-}"
  [[ -n "${candidate}" ]] || return 1
  [[ -f "${candidate}/run_manifest.json" ]] || return 1
  [[ -f "${candidate}/events.jsonl" ]] || return 1
  [[ -f "${candidate}/commands.txt" ]] || return 1
  [[ -f "${candidate}/trace_ids.json" ]] || return 1
  [[ -f "${candidate}/json_compound_placeholder_closure_report.json" ]] || return 1
  [[ -f "${candidate}/step_logs/step_000.log" ]] || return 1
}

cd "${root_dir}"
if [[ -z "${explicit_run_dir}" ]]; then
  ./scripts/run_rgc_json_compound_placeholder_closure.sh "${mode}" || main_exit=$?
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
    echo "json compound placeholder closure replay explicit run directory is incomplete: ${explicit_run_dir}" >&2
  else
    echo "json compound placeholder closure replay found no complete artifact directory under ${artifact_root}" >&2
  fi
  exit "${main_exit:-1}"
fi

echo "[json-compound-placeholder-closure] latest run dir: ${latest_run_dir}"
echo "[json-compound-placeholder-closure] run manifest:"
cat "${latest_run_dir}/run_manifest.json"
echo "[json-compound-placeholder-closure] trace ids:"
cat "${latest_run_dir}/trace_ids.json"
echo "[json-compound-placeholder-closure] events:"
cat "${latest_run_dir}/events.jsonl"
echo "[json-compound-placeholder-closure] commands:"
cat "${latest_run_dir}/commands.txt"
echo "[json-compound-placeholder-closure] report:"
cat "${latest_run_dir}/json_compound_placeholder_closure_report.json"
echo "[json-compound-placeholder-closure] step logs:"
for step_log in "${latest_run_dir}"/step_logs/step_*.log; do
  [[ -e "${step_log}" ]] || continue
  echo "--- ${step_log}"
  cat "${step_log}"
done

exit "${main_exit}"
