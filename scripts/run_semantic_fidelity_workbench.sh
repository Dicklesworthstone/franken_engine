#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

artifact_root="${SEMANTIC_FIDELITY_ARTIFACT_ROOT:-artifacts/semantic_fidelity_workbench_gate}"
suite_path="${SEMANTIC_FIDELITY_SUITE:-scripts/testdata/semantic_fidelity_workbench/rangeerror_tointeger_suite.json}"
runner="scripts/semantic_fidelity_workbench.py"
replay_wrapper="scripts/e2e/semantic_fidelity_workbench_replay.sh"

usage() {
  cat >&2 <<'EOF'
usage:
  scripts/run_semantic_fidelity_workbench.sh ci [RUN_DIR]
  scripts/run_semantic_fidelity_workbench.sh replay [RUN_DIR|latest]
  scripts/run_semantic_fidelity_workbench.sh self-check [RUN_DIR]
  scripts/run_semantic_fidelity_workbench.sh smoke [check|selftest] [RUN_DIR]

Environment:
  SEMANTIC_FIDELITY_ARTIFACT_ROOT  Artifact root for auto-discovery.
  SEMANTIC_FIDELITY_SUITE          Suite JSON for ci mode.
  SEMANTIC_FIDELITY_RUN_ID         Stable run directory suffix.
  SEMANTIC_FIDELITY_NOW_UTC        Stable timestamp passed to the Python runner.

Cargo-heavy lanes must be validated through rch separately; this wrapper is
shell/Python/JSON only.
EOF
}

run_id() {
  if [[ -n "${SEMANTIC_FIDELITY_RUN_ID:-}" ]]; then
    printf '%s\n' "${SEMANTIC_FIDELITY_RUN_ID}"
    return
  fi
  date -u +%Y%m%dT%H%M%SZ
}

default_run_dir() {
  printf '%s/%s\n' "${artifact_root}" "$(run_id)"
}

run_runner() {
  local run_dir="$1"
  mkdir -p "${run_dir}"

  local cmd_display
  cmd_display="python3 ${runner} --suite ${suite_path} --out-dir ${run_dir} --pretty"
  if [[ -n "${SEMANTIC_FIDELITY_NOW_UTC:-}" ]]; then
    cmd_display="SEMANTIC_FIDELITY_NOW_UTC=${SEMANTIC_FIDELITY_NOW_UTC} ${cmd_display}"
  fi
  printf '%s\n' "${cmd_display}" >"${run_dir}/gate_commands.txt"
  printf '[semantic-fidelity] %s\n' "${cmd_display}"

  local runner_rc=0
  if [[ -n "${SEMANTIC_FIDELITY_NOW_UTC:-}" ]]; then
    if SEMANTIC_FIDELITY_NOW_UTC="${SEMANTIC_FIDELITY_NOW_UTC}" \
      python3 "${runner}" --suite "${suite_path}" --out-dir "${run_dir}" --pretty \
      >"${run_dir}/runner.stdout.log" 2>"${run_dir}/runner.stderr.log"; then
      runner_rc=0
    else
      runner_rc=$?
    fi
  else
    if python3 "${runner}" --suite "${suite_path}" --out-dir "${run_dir}" --pretty \
      >"${run_dir}/runner.stdout.log" 2>"${run_dir}/runner.stderr.log"; then
      runner_rc=0
    else
      runner_rc=$?
    fi
  fi

  printf '%s\n' "${runner_rc}" >"${run_dir}/runner.exit"
  cat "${run_dir}/runner.stdout.log"
  if [[ -s "${run_dir}/runner.stderr.log" ]]; then
    cat "${run_dir}/runner.stderr.log" >&2
  fi
  return "${runner_rc}"
}

run_ci() {
  local run_dir="${1:-$(default_run_dir)}"
  local runner_rc replay_rc

  set +e
  run_runner "${run_dir}"
  runner_rc=$?
  set -e

  set +e
  "${replay_wrapper}" "${run_dir}"
  replay_rc=$?
  set -e

  if [[ "${runner_rc}" -ne 0 ]]; then
    printf '[semantic-fidelity] runner failed with exit %s; artifacts: %s\n' "${runner_rc}" "${run_dir}" >&2
    return "${runner_rc}"
  fi
  if [[ "${replay_rc}" -ne 0 ]]; then
    printf '[semantic-fidelity] replay verification failed with exit %s; artifacts: %s\n' "${replay_rc}" "${run_dir}" >&2
    return "${replay_rc}"
  fi

  printf '[semantic-fidelity] PASS artifacts: %s\n' "${run_dir}"
}

write_malformed_bundle() {
  local dir="$1"
  mkdir -p "${dir}"
  printf 'not-json\n' >"${dir}/run_manifest.json"
  printf '{}\n' >"${dir}/events.jsonl"
  printf '{}\n' >"${dir}/vector_results.jsonl"
  printf '{}\n' >"${dir}/path_parity_report.json"
  printf '{}\n' >"${dir}/auto_triage_report.json"
  printf 'python3 scripts/semantic_fidelity_workbench.py --suite malformed\n' >"${dir}/commands.txt"
  printf '# malformed semantic fidelity bundle\n' >"${dir}/summary.md"
}

run_self_check() {
  local run_dir="${1:-$(default_run_dir)-self-check}"
  local valid_dir="${run_dir}/valid"
  local incomplete_dir="${run_dir}/incomplete"
  local malformed_dir="${run_dir}/malformed"
  mkdir -p "${run_dir}"

  python3 "${runner}" --self-test >"${run_dir}/runner-self-test.log"
  cat "${run_dir}/runner-self-test.log"

  SEMANTIC_FIDELITY_NOW_UTC="${SEMANTIC_FIDELITY_NOW_UTC:-2030-01-01T00:00:00Z}" \
    run_ci "${valid_dir}"

  mkdir -p "${incomplete_dir}"
  printf '{}\n' >"${incomplete_dir}/run_manifest.json"

  local incomplete_rc malformed_rc
  set +e
  "${replay_wrapper}" "${incomplete_dir}" >"${run_dir}/incomplete.replay.log" 2>&1
  incomplete_rc=$?
  set -e
  if [[ "${incomplete_rc}" -eq 0 ]]; then
    cat "${run_dir}/incomplete.replay.log" >&2
    printf '[semantic-fidelity] self-check FAIL: incomplete bundle replay succeeded\n' >&2
    return 1
  fi

  write_malformed_bundle "${malformed_dir}"
  set +e
  "${replay_wrapper}" "${malformed_dir}" >"${run_dir}/malformed.replay.log" 2>&1
  malformed_rc=$?
  set -e
  if [[ "${malformed_rc}" -eq 0 ]]; then
    cat "${run_dir}/malformed.replay.log" >&2
    printf '[semantic-fidelity] self-check FAIL: malformed bundle replay succeeded\n' >&2
    return 1
  fi

  printf '[semantic-fidelity] self-check PASS artifacts: %s\n' "${run_dir}"
}

mode="${1:-ci}"
case "${mode}" in
  ci)
    run_ci "${2:-}"
    ;;
  replay)
    "${replay_wrapper}" "${2:-latest}"
    ;;
  self-check|selftest)
    run_self_check "${2:-}"
    ;;
  smoke|test)
    "scripts/e2e/semantic_fidelity_workbench_smoke.sh" "${2:-check}" "${3:-}"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    exit 2
    ;;
esac
