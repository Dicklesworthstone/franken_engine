#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

artifact_root="${PARSER_OPERATOR_DEVELOPER_RUNBOOK_ARTIFACT_ROOT:-artifacts/parser_operator_developer_runbook}"
explicit_run_dir="${PARSER_OPERATOR_DEVELOPER_RUNBOOK_REPLAY_RUN_DIR:-}"
mode="${1:-ci}"
main_exit=0

run_dir_is_complete() {
  local candidate="${1:-}"
  [[ -n "${candidate}" ]] || return 1
  [[ -f "${candidate}/run_manifest.json" ]] || return 1
  [[ -f "${candidate}/events.jsonl" ]] || return 1
  [[ -f "${candidate}/commands.txt" ]] || return 1
  [[ -f "${candidate}/step_logs/step_000.log" ]] || return 1
}

if [[ -z "${explicit_run_dir}" ]]; then
  ./scripts/run_parser_operator_developer_runbook.sh "$mode" || main_exit=$?
fi

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
    echo "[parser-operator-runbook] gate exited with status ${prior_exit}; replay output reflects latest complete run directory ${latest_run_dir}" >&2
    return
  fi

  echo "[parser-operator-runbook] gate exited with status ${prior_exit}; replay output reflects current run directory ${latest_run_dir}" >&2
}

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
    echo "parser operator/developer runbook replay explicit run directory is incomplete: ${explicit_run_dir}" >&2
    exit 1
  fi
  if [[ -n "${latest_artifact_dir_path}" ]]; then
    echo "parser operator/developer runbook replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
  else
    echo "parser operator/developer runbook replay could not locate a complete run directory under ${artifact_root}" >&2
  fi
  exit "$(missing_bundle_exit_code "${main_exit:-1}")"
fi

if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
  echo "[parser-operator-runbook] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
fi

warn_about_failed_gate_replay_source "${main_exit}"

echo "[parser-operator-runbook] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[parser-operator-runbook] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo "[parser-operator-runbook] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"
echo "[parser-operator-runbook] latest first step log: ${latest_run_dir}/step_logs/step_000.log"
cat "${latest_run_dir}/step_logs/step_000.log"

exit "$main_exit"
