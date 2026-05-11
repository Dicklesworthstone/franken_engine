#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/idea_wizard_iv_validation_impact_planner.sh"
mode="${1:-check}"

record_pass() {
  printf 'PASS idea-wizard-iv-validation-impact %s\n' "$1"
}

record_failure() {
  printf 'FAIL idea-wizard-iv-validation-impact %s\n' "$1" >&2
  exit 1
}

run_case() {
  local case_id="$1"
  local changed_path="$2"
  local expected_decision="$3"
  local requires_rch="$4"
  local tmpdir output_dir status expected_exit

  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  if [[ "$expected_decision" == "fail_closed" ]]; then
    expected_exit=42
  else
    expected_exit=0
  fi

  set +e
  SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE="" \
    "$planner" \
    --bead-id "bd-k53rr-smoke" \
    --source-revision "smoke-${case_id}" \
    --output-dir "$output_dir" \
    --changed-path "$changed_path" >"${tmpdir}/stdout.log" 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    cat "${tmpdir}/stderr.log" >&2
    record_failure "unexpected exit for ${case_id}: got ${status}, expected ${expected_exit}"
  fi

  [[ -f "${output_dir}/validation_impact_plan.json" ]] || record_failure "missing plan for ${case_id}"
  [[ -f "${output_dir}/run_manifest.json" ]] || record_failure "missing manifest for ${case_id}"
  [[ -f "${output_dir}/events.jsonl" ]] || record_failure "missing events for ${case_id}"
  [[ -f "${output_dir}/commands.txt" ]] || record_failure "missing commands for ${case_id}"
  [[ -f "${output_dir}/report.md" ]] || record_failure "missing report for ${case_id}"

  jq -e --arg decision "$expected_decision" '.decision == $decision' "${output_dir}/validation_impact_plan.json" >/dev/null \
    || record_failure "decision mismatch for ${case_id}"
  jq -e '.schema_version == "franken-engine.idea-wizard-iv-validation-impact-plan.v1"' "${output_dir}/validation_impact_plan.json" >/dev/null \
    || record_failure "schema mismatch for ${case_id}"
  jq -e 'all(.recommended_commands[]?; (.command_kind | startswith("rch_cargo") | not) or .rch_wrapped == true)' "${output_dir}/validation_impact_plan.json" >/dev/null \
    || record_failure "unsafe heavy command for ${case_id}"

  if [[ "$requires_rch" == "true" ]]; then
    jq -e 'any(.recommended_commands[]?; .display | startswith("rch exec -- env CARGO_TARGET_DIR="))' "${output_dir}/validation_impact_plan.json" >/dev/null \
      || record_failure "missing rch command for ${case_id}"
  fi

  grep -Fq "recommended validation commands" "${output_dir}/commands.txt" \
    || record_failure "commands transcript missing recommendations for ${case_id}"

  record_pass "$case_id"
}

run_check() {
  bash -n "$planner" "${BASH_SOURCE[0]}"
  run_case "docs-json" "docs/idea_wizard_iv_saturation_convergence_v1.json" "degraded" "false"
  run_case "script" "scripts/idea_wizard_iv_validation_impact_planner.sh" "degraded" "false"
  run_case "engine-source" "crates/franken-engine/src/lib.rs" "degraded" "true"
  run_case "unknown-path" "examples/not-mapped.fixture" "fail_closed" "false"
  git -C "$root_dir" diff --check -- \
    docs/IDEA_WIZARD_IV_VALIDATION_IMPACT_PLANNER.md \
    scripts/idea_wizard_iv_validation_impact_planner.sh \
    scripts/e2e/idea_wizard_iv_validation_impact_planner_smoke.sh \
    docs/idea_wizard_iv_saturation_convergence_v1.json
  record_pass "check"
}

case "$mode" in
  check)
    run_check
    ;;
  -h|--help|help)
    printf 'Usage: ./scripts/e2e/idea_wizard_iv_validation_impact_planner_smoke.sh [check]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
