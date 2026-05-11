#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
router="${root_dir}/scripts/swarm_control_surface_intent_router.sh"
docs_path="${root_dir}/docs/SWARM_CONTROL_SURFACE_INTENT_ROUTER.md"
fixtures_path="${root_dir}/scripts/testdata/swarm_control_surface_intent_router/cases.json"
golden_dir="${SWARM_CONTROL_SURFACE_INTENT_ROUTER_GOLDEN_DIR:-${root_dir}/scripts/testdata/goldens}"
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
  local suite_root="$2"
  local case_json tmp_root catalog intent output_dir expected_decision expected_exit expected_surface expected_reason status

  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing fixture case ${case_id}"
  fi

  tmp_root="${suite_root}/${case_id}"
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
  assert_case_golden "$case_id" "${output_dir}/swarm_control_surface_intent_plan.json" "$suite_root"
  record_pass "$case_id"
}

golden_case_names() {
  jq -r '.cases[].case_id' "$fixtures_path"
}

canonicalize_plan() {
  local plan="$1"
  local suite_root="$2"

  jq --arg suite_root "$suite_root" '
    def scrub:
      if type == "string" then
        gsub($suite_root; "[SMOKE_ROOT]")
        | gsub("/data/tmp/[A-Za-z0-9._-]+"; "[DATA_TMP_PATH]")
        | gsub("/tmp/rch_target_"; "[RCH_TARGET]/")
        | gsub("/tmp/[A-Za-z0-9._-]+"; "[TMP_PATH]")
      elif type == "array" then
        map(scrub)
      elif type == "object" then
        with_entries(.value |= scrub)
      else
        .
      end;
    scrub
  ' "$plan"
}

assert_case_golden() {
  local case_id="$1"
  local plan="$2"
  local suite_root="$3"
  local golden_path="${golden_dir}/swarm_control_surface_intent_router_${case_id}.golden"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    mkdir -p "$golden_dir"
    canonicalize_plan "$plan" "$suite_root" >"$golden_path"
    return 0
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "${case_id} missing golden"
  fi

  if ! diff -u "$golden_path" <(canonicalize_plan "$plan" "$suite_root"); then
    record_failure "${case_id} golden drift"
  fi
}

goldens_shape_ok() {
  local case_id golden_path

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    return 0
  fi

  while IFS= read -r case_id; do
    golden_path="${golden_dir}/swarm_control_surface_intent_router_${case_id}.golden"
    if [[ ! -f "$golden_path" ]]; then
      record_failure "${case_id} missing checked-in golden"
    fi
    jq empty "$golden_path" >/dev/null || record_failure "${case_id} invalid golden json"
  done < <(golden_case_names)
}

run_check() {
  bash -n "$router"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$fixtures_path"
  jq -e '.cases | length >= 16' "$fixtures_path" >/dev/null
  grep -Fq 'The router is artifact-fed.' "$docs_path" \
    || record_failure "missing artifact-fed docs wording"
  goldens_shape_ok
  record_pass "check"
}

run_selftest() {
  local case_id tmp_parent tmp_root
  run_check
  tmp_parent="${SWARM_CONTROL_SURFACE_INTENT_ROUTER_SMOKE_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-control-surface-intent-router.XXXXXX")"
  while IFS= read -r case_id; do
    run_fixture_case "$case_id" "$tmp_root"
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
