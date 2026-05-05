#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${SEMANTIC_DARK_MATTER_PIPELINE_ARTIFACT_ROOT:-artifacts/semantic_dark_matter_pipeline}"
mode="${1:-ci}"
explicit_run_dir="${SEMANTIC_DARK_MATTER_PIPELINE_REPLAY_RUN_DIR:-}"
main_exit=0

./scripts/run_semantic_dark_matter_pipeline_suite.sh "${mode}" || main_exit=$?

latest_artifact_dir() {
  if [[ ! -d "${artifact_root}" ]]; then
    return 0
  fi

  find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1
}

run_dir_complete() {
  local candidate="$1"
  [[ -n "$candidate" ]] || return 1
  [[ -f "${candidate}/run_manifest.json" ]] || return 1
  [[ -f "${candidate}/summary.md" ]] || return 1
  [[ -f "${candidate}/events.jsonl" ]] || return 1
  [[ -f "${candidate}/commands.txt" ]] || return 1
}

latest_complete_run_dir() {
  if [[ ! -d "${artifact_root}" ]]; then
    return 0
  fi

  find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d | sort | while IFS= read -r candidate; do
    run_dir_complete "${candidate}" || continue
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
if [[ -n "${explicit_run_dir}" ]]; then
  if ! run_dir_complete "${explicit_run_dir}"; then
    echo "semantic dark-matter pipeline replay explicit run directory is incomplete: ${explicit_run_dir}" >&2
    exit "$(missing_bundle_exit_code "${main_exit:-1}")"
  fi
  latest_run_dir="${explicit_run_dir}"
else
  latest_run_dir="$(latest_complete_run_dir)"
  if [[ -z "${latest_run_dir}" ]]; then
    if [[ -n "${latest_artifact_dir_path}" ]]; then
      echo "semantic dark-matter pipeline replay could not locate a complete run directory under ${artifact_root}; newest directory ${latest_artifact_dir_path} is incomplete" >&2
    else
      echo "semantic dark-matter pipeline replay could not locate a complete run directory under ${artifact_root}" >&2
    fi
    exit "$(missing_bundle_exit_code "${main_exit:-1}")"
  fi
  if [[ -n "${latest_artifact_dir_path}" && "${latest_artifact_dir_path}" != "${latest_run_dir}" ]]; then
    echo "[semantic-dark-matter-pipeline] newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}" >&2
  fi
fi

echo "[semantic-dark-matter-pipeline] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[semantic-dark-matter-pipeline] latest summary: ${latest_run_dir}/summary.md"
cat "${latest_run_dir}/summary.md"
echo "[semantic-dark-matter-pipeline] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
echo "[semantic-dark-matter-pipeline] latest commands: ${latest_run_dir}/commands.txt"
cat "${latest_run_dir}/commands.txt"

first_step_log="$(find "${latest_run_dir}/step_logs" -maxdepth 1 -type f | sort | head -n 1 || true)"
if [[ -n "${first_step_log}" ]]; then
  echo "[semantic-dark-matter-pipeline] latest first step log: ${first_step_log}"
  cat "${first_step_log}"
fi

exit "${main_exit}"
