#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
suite="${root_dir}/scripts/idea_wizard_iv_acceptance_suite.sh"
mode="${1:-check}"

record_pass() { printf 'PASS idea-wizard-iv-acceptance-suite %s\n' "$1"; }
record_failure() { printf 'FAIL idea-wizard-iv-acceptance-suite %s\n' "$1" >&2; exit 1; }

run_case() {
  local case_id="$1"
  local expected_decision="$2"
  local expected_status="$3"
  local tmpdir output_dir status extra_args=()
  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  case "$case_id" in
    green)
      extra_args+=(--run-lightweight-smokes)
      ;;
    missing-child)
      cat >"${tmpdir}/children.json" <<'JSON'
[{"bead_id":"bd-missing","paths":["docs/DOES_NOT_EXIST_IW4_ACCEPTANCE.md"]}]
JSON
      extra_args+=(--child-artifacts-json "${tmpdir}/children.json")
      ;;
    local-fallback)
      printf '[RCH] local (fallback to local)\n' >"${tmpdir}/rch.log"
      extra_args+=(--rch-transcript "${tmpdir}/rch.log")
      ;;
  esac

  set +e
  IDEA_WIZARD_IV_ACCEPTANCE_GENERATED_AT_UTC="2026-05-11T00:00:00Z" \
    "$suite" \
    --source-revision "smoke-${case_id}" \
    --output-dir "$output_dir" \
    "${extra_args[@]}" >"${tmpdir}/stdout.log" 2>"${tmpdir}/stderr.log"
  status=$?
  set -e
  if [[ "$status" -ne "$expected_status" ]]; then
    cat "${tmpdir}/stderr.log" >&2
    record_failure "unexpected exit for ${case_id}: got ${status}, expected ${expected_status}"
  fi
  [[ -f "${output_dir}/acceptance_manifest.json" ]] || record_failure "missing manifest for ${case_id}"
  [[ -f "${output_dir}/run_manifest.json" ]] || record_failure "missing run manifest for ${case_id}"
  [[ -f "${output_dir}/commands.txt" ]] || record_failure "missing commands for ${case_id}"
  [[ -f "${output_dir}/trace_ids.json" ]] || record_failure "missing trace ids for ${case_id}"
  jq -e --arg decision "$expected_decision" '.acceptance_decision == $decision' "${output_dir}/acceptance_manifest.json" >/dev/null \
    || record_failure "decision mismatch for ${case_id}"
  jq -e 'all(.validation_commands[]?; (.display | test("cargo (check|test|clippy|build)") | not) or .rch_wrapped == true)' "${output_dir}/acceptance_manifest.json" >/dev/null \
    || record_failure "unsafe cargo guidance for ${case_id}"
  record_pass "$case_id"
}

run_check() {
  bash -n "$suite" "${BASH_SOURCE[0]}"
  run_case green green 0
  run_case missing-child fail_closed 42
  run_case local-fallback fail_closed 42
  git -C "$root_dir" diff --check -- \
    docs/IDEA_WIZARD_IV_ACCEPTANCE_SUITE.md \
    scripts/idea_wizard_iv_acceptance_suite.sh \
    scripts/e2e/idea_wizard_iv_acceptance_suite_smoke.sh \
    docs/idea_wizard_iv_saturation_convergence_v1.json
  record_pass "check"
}

case "$mode" in
  check) run_check ;;
  -h|--help|help) printf 'Usage: %s [check]\n' "${BASH_SOURCE[0]}" ;;
  *) printf 'unknown mode: %s\n' "$mode" >&2; exit 64 ;;
esac
