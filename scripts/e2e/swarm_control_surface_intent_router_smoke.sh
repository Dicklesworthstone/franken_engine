#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
router="${root_dir}/scripts/swarm_control_surface_intent_router.sh"
docs_path="${root_dir}/docs/SWARM_CONTROL_SURFACE_INTENT_ROUTER.md"
fixtures_path="${root_dir}/scripts/testdata/swarm_control_surface_intent_router/cases.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS swarm-control-surface-intent-router %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-control-surface-intent-router %s\n' "$1" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_control_surface_intent_router_smoke.sh [check|selftest]
EOF
}

run_fixture_case() {
  local case_id="$1"
  local case_json tmp_root catalog intent output_dir expected_decision expected_exit expected_surface expected_reason status

  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing fixture case ${case_id}"
  fi

  tmp_root="${TMPDIR:-/tmp}/franken-engine-swarm-control-surface-intent-fixtures/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)/${case_id}"
  catalog="${tmp_root}/catalog.json"
  intent="${tmp_root}/intent.json"
  output_dir="${tmp_root}/out"
  mkdir -p "$output_dir"

  if jq -e '.catalog != null' <<<"$case_json" >/dev/null; then
    jq '.catalog' <<<"$case_json" >"$catalog"
  else
    jq '.catalog' "$fixtures_path" >"$catalog"
  fi
  jq '.intent' <<<"$case_json" >"$intent"

  expected_decision="$(jq -r '.expected.decision' <<<"$case_json")"
  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"
  expected_surface="$(jq -r '.expected.surface_id // ""' <<<"$case_json")"
  expected_reason="$(jq -r '.expected.reason_code // ""' <<<"$case_json")"

  set +e
  "$router" \
    --catalog-json "$catalog" \
    --intent-json "$intent" \
    --source-revision "fixture-${case_id}" \
    --output-dir "$output_dir" >/dev/null
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    record_failure "${case_id} expected exit ${expected_exit}, got ${status}"
  fi
  jq -e --arg decision "$expected_decision" '.decision == $decision' "${output_dir}/swarm_control_surface_intent_plan.json" >/dev/null \
    || record_failure "${case_id} decision mismatch"

  if [[ -n "$expected_surface" ]]; then
    jq -e --arg surface "$expected_surface" '.recommendations[0].surface_id == $surface' "${output_dir}/swarm_control_surface_intent_plan.json" >/dev/null \
      || record_failure "${case_id} surface mismatch"
    jq -e '
      [
        .recommendations[0].matched_intent_tags[]?,
        .recommendations[0].matched_symptom_tags[]?
      ]
      | all(.[]; type == "string")
    ' "${output_dir}/swarm_control_surface_intent_plan.json" >/dev/null \
      || record_failure "${case_id} matched tags must be strings"
  fi
  if [[ -n "$expected_reason" ]]; then
    jq -e --arg code "$expected_reason" 'any(.fail_closed_reasons[]; .code == $code)' "${output_dir}/swarm_control_surface_intent_plan.json" >/dev/null \
      || record_failure "${case_id} missing reason ${expected_reason}"
  fi

  jq empty "${output_dir}/swarm_control_surface_intent_plan.json"
  [[ -s "${output_dir}/events.jsonl" ]] || record_failure "${case_id} missing events"
  grep -Fq './scripts/swarm_control_surface_intent_router.sh' "${output_dir}/commands.txt" \
    || record_failure "${case_id} missing commands invocation"
  grep -Fq 'decision:' "${output_dir}/report.md" || record_failure "${case_id} missing report decision"
  record_pass "$case_id"
}

run_check() {
  bash -n "$router"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$fixtures_path"
  jq -e '.cases | length >= 16' "$fixtures_path" >/dev/null
  grep -Fq 'The router is artifact-fed.' "$docs_path" \
    || record_failure "missing artifact-fed docs wording"
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
