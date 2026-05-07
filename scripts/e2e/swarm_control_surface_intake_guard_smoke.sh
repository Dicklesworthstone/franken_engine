#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
guard="${root_dir}/scripts/swarm_control_surface_intake_guard.sh"
docs_path="${root_dir}/docs/SWARM_CONTROL_SURFACE_INTAKE_GUARD.md"
fixtures_path="${root_dir}/scripts/testdata/swarm_control_surface_intake_guard/cases.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS swarm-control-surface-intake-guard %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-control-surface-intake-guard %s\n' "$1" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_control_surface_intake_guard_smoke.sh [check|selftest]
EOF
}

run_fixture_case() {
  local case_id="$1"
  local case_json tmp_root catalog proposal output_dir expected_action expected_exit status

  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing fixture case ${case_id}"
  fi

  tmp_root="${TMPDIR:-/tmp}/franken-engine-swarm-control-surface-intake-fixtures/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)/${case_id}"
  catalog="${tmp_root}/catalog.json"
  proposal="${tmp_root}/proposal.json"
  output_dir="${tmp_root}/out"
  mkdir -p "$output_dir"

  jq '.catalog' "$fixtures_path" >"$catalog"
  jq '.proposal' <<<"$case_json" >"$proposal"
  expected_action="$(jq -r '.expected.recommended_action' <<<"$case_json")"
  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"

  set +e
  "$guard" \
    --proposal-json "$proposal" \
    --catalog-json "$catalog" \
    --source-revision "fixture-${case_id}" \
    --output-dir "$output_dir" >/dev/null
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    record_failure "${case_id} expected exit ${expected_exit}, got ${status}"
  fi
  jq -e --arg action "$expected_action" '.recommended_action == $action' "${output_dir}/intake_guard_report.json" >/dev/null \
    || record_failure "${case_id} action mismatch"
  jq empty "${output_dir}/intake_guard_report.json"
  [[ -s "${output_dir}/events.jsonl" ]] || record_failure "${case_id} missing events"
  grep -Fq './scripts/swarm_control_surface_intake_guard.sh' "${output_dir}/commands.txt" \
    || record_failure "${case_id} missing commands invocation"
  grep -Fq 'recommended_action:' "${output_dir}/report.md" || record_failure "${case_id} missing markdown action"
  record_pass "$case_id"
}

run_check() {
  bash -n "$guard"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$fixtures_path"
  jq -e '.cases | length == 6' "$fixtures_path" >/dev/null
  grep -Fq 'The guard is advisory only.' "$docs_path" \
    || record_failure "missing advisory-only docs wording"
  record_pass "check"
}

run_selftest() {
  local case_id
  run_check
  while IFS= read -r case_id; do
    run_fixture_case "$case_id"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")
  record_pass "selftest"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    ;;
esac
