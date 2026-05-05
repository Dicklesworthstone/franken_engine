#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runner="${root_dir}/scripts/focused_proof_runner.sh"
gate="${root_dir}/scripts/focused_proof_cost_gate.sh"
golden_dir="${root_dir}/scripts/testdata/goldens"

record_pass() {
  printf 'PASS focused-proof-cost-gate %s\n' "$1"
}

record_failure() {
  printf 'FAIL focused-proof-cost-gate %s\n' "$1" >&2
}

write_budget() {
  local path="$1"
  local suite="$2"
  local max_compiled="$3"
  local max_linked="$4"
  local max_unexpected="$5"
  local max_tests="$6"
  local max_libs="$7"

  jq -n \
    --arg suite "${suite}" \
    --argjson max_compiled "${max_compiled}" \
    --argjson max_linked "${max_linked}" \
    --argjson max_unexpected "${max_unexpected}" \
    --argjson max_tests "${max_tests}" \
    --argjson max_libs "${max_libs}" \
    '{
      schema_version: "franken-engine.focused-proof-cost-budget.v1",
      suite: $suite,
      max_total_compiled_targets: $max_compiled,
      max_total_linked_targets: $max_linked,
      max_unexpected_targets: $max_unexpected,
      max_targets_by_kind: {
        test: $max_tests,
        lib: $max_libs
      },
      upstream_beads: ["bd-fn2zh", "bd-fk5cb"],
      gated_bead: "bd-ctebo"
    }' >"${path}"
}

canonicalize_diagnostics() {
  local diagnostics_path="$1"
  local tmp_root="$2"

  jq --arg tmp_root "${tmp_root}" '
    def scrub:
      if type == "object" then
        with_entries(.value |= scrub)
      elif type == "array" then
        map(scrub)
      elif type == "string" then
        split($tmp_root) | join("[SMOKE_ROOT]")
      else
        .
      end;
    scrub
  ' "${diagnostics_path}"
}

canonicalize_report() {
  local report_path="$1"
  local tmp_root="$2"

  jq -R -s -r -j --arg tmp_root "${tmp_root}" '
    split($tmp_root) | join("[SMOKE_ROOT]")
  ' "${report_path}"
}

write_case_golden() {
  local tmp_root="$1"
  local output_dir="$2"
  local actual_path="$3"

  {
    printf '=== DIAGNOSTICS ===\n'
    canonicalize_diagnostics "${output_dir}/diagnostics.json" "${tmp_root}"
    printf '=== REPORT ===\n'
    canonicalize_report "${output_dir}/report.md" "${tmp_root}"
  } >"${actual_path}"
}

compare_case_golden() {
  local case_name="$1"
  local actual_path="$2"
  local golden_path="$3"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    cp "${actual_path}" "${golden_path}"
    record_pass "updated golden ${case_name}"
    return 0
  fi

  if [[ ! -f "${golden_path}" ]]; then
    record_failure "missing golden ${golden_path}"
    return 1
  fi

  if ! diff -u "${golden_path}" "${actual_path}"; then
    record_failure "golden drift for ${case_name}; set UPDATE_GOLDENS=1 only after reviewing the diff"
    return 1
  fi

  record_pass "golden matches ${case_name}"
}

assert_case_golden() {
  local case_name="$1"
  local tmp_root="$2"
  local output_dir="$3"
  local golden_path="$4"
  local actual_path="${tmp_root}/${case_name}.actual.golden"

  write_case_golden "${tmp_root}" "${output_dir}" "${actual_path}"
  compare_case_golden "${case_name}" "${actual_path}" "${golden_path}"
}

run_focused_runner() {
  local case_root="$1"
  local run_id="$2"
  local expected_targets="$3"
  local observed_targets="$4"

  set +e
  FOCUSED_PROOF_ARTIFACT_ROOT="${case_root}" \
  FOCUSED_PROOF_RUN_ID="${run_id}" \
  FOCUSED_PROOF_BEAD_ID="bd-ctebo" \
  FOCUSED_PROOF_SUITE="focused_proof_cost_gate_smoke" \
  FOCUSED_PROOF_COMMAND="printf focused-proof-cost-gate-ok" \
  FOCUSED_PROOF_CARGO_PACKAGE="frankenengine-engine" \
  FOCUSED_PROOF_EXPECTED_TARGETS="${expected_targets}" \
  FOCUSED_PROOF_OBSERVED_TARGETS="${observed_targets}" \
  FOCUSED_PROOF_WORKER="cost-gate-smoke" \
  FOCUSED_PROOF_SYNC_ROOTS="/data/projects/franken_engine" \
  FOCUSED_PROOF_DURATION_MS_OVERRIDE=0 \
  "${runner}" >/dev/null
  local exit_code=$?
  set -e

  if [[ "${exit_code}" -ne 0 && "${exit_code}" -ne 42 ]]; then
    record_failure "focused runner exited ${exit_code}"
    return 1
  fi
}

run_gate_expect_pass() {
  local manifest_path="$1"
  local budget_path="$2"
  local output_dir="$3"

  "${gate}" "${manifest_path}" "${budget_path}" "${output_dir}" >/dev/null
  jq -e '
    .schema_version == "franken-engine.focused-proof-cost-gate-report.v1"
    and .status == "pass"
    and (.breaches | length) == 0
    and .budget.upstream_beads == ["bd-fn2zh", "bd-fk5cb"]
  ' "${output_dir}/diagnostics.json" >/dev/null
  record_pass "passing manifest stays within budget"
}

run_gate_expect_fail() {
  local manifest_path="$1"
  local budget_path="$2"
  local output_dir="$3"
  local expected_kind="$4"
  local output

  set +e
  output="$("${gate}" "${manifest_path}" "${budget_path}" "${output_dir}" 2>&1)"
  local exit_code=$?
  set -e

  if [[ "${exit_code}" -eq 0 ]]; then
    record_failure "gate unexpectedly passed for ${expected_kind}"
    printf '%s\n' "${output}" >&2
    return 1
  fi

  jq -e --arg expected_kind "${expected_kind}" '
    .status == "fail"
    and (.breaches | map(.kind) | index($expected_kind) != null)
    and (.remediation | length) >= 4
  ' "${output_dir}/diagnostics.json" >/dev/null
  record_pass "gate fails on ${expected_kind}"

  grep -Fq "${expected_kind}" "${output_dir}/report.md"
  record_pass "human report names ${expected_kind}"
}

run_selftest() {
  local tmp_parent tmp_root pass_root broad_root budget_pass budget_tight budget_unexpected
  local pass_manifest broad_manifest observed_pass observed_broad

  tmp_parent="${FOCUSED_PROOF_COST_GATE_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "${tmp_parent}"
  tmp_root="$(mktemp -d "${tmp_parent%/}/focused-proof-cost-gate.XXXXXX")"
  pass_root="${tmp_root}/runner-pass"
  broad_root="${tmp_root}/runner-broad"
  budget_pass="${tmp_root}/budget-pass.json"
  budget_tight="${tmp_root}/budget-tight.json"
  budget_unexpected="${tmp_root}/budget-unexpected.json"

  observed_pass=$'frankenengine-engine|test|focused_proof_cost_gate_smoke|test|true|true|explicit smoke\nfrankenengine-engine|lib|frankenengine-engine|test|true|false|test harness dependency'
  observed_broad=$'frankenengine-engine|test|focused_proof_cost_gate_smoke|test|true|true|explicit smoke\nfrankenengine-engine|test|unexpected_broad_target|test|true|true|hidden fanout'

  run_focused_runner "${pass_root}" "stable" "focused_proof_cost_gate_smoke,frankenengine-engine" "${observed_pass}"
  pass_manifest="${pass_root}/stable/proof_cost_manifest.json"
  write_budget "${budget_pass}" "focused_proof_cost_gate_smoke" 2 1 0 1 1
  run_gate_expect_pass "${pass_manifest}" "${budget_pass}" "${tmp_root}/gate-pass"
  assert_case_golden \
    "pass" \
    "${tmp_root}" \
    "${tmp_root}/gate-pass" \
    "${golden_dir}/focused_proof_cost_gate_pass.golden"

  write_budget "${budget_tight}" "focused_proof_cost_gate_smoke" 1 1 0 1 1
  run_gate_expect_fail "${pass_manifest}" "${budget_tight}" "${tmp_root}/gate-budget-fail" "compiled_target_budget"
  assert_case_golden \
    "compiled-budget-breach" \
    "${tmp_root}" \
    "${tmp_root}/gate-budget-fail" \
    "${golden_dir}/focused_proof_cost_gate_compiled_budget_breach.golden"

  run_focused_runner "${broad_root}" "broad" "focused_proof_cost_gate_smoke" "${observed_broad}"
  broad_manifest="${broad_root}/broad/proof_cost_manifest.json"
  write_budget "${budget_unexpected}" "focused_proof_cost_gate_smoke" 2 2 0 2 0
  run_gate_expect_fail "${broad_manifest}" "${budget_unexpected}" "${tmp_root}/gate-unexpected-fail" "unexpected_target_breach"
  assert_case_golden \
    "unexpected-target-breach" \
    "${tmp_root}" \
    "${tmp_root}/gate-unexpected-fail" \
    "${golden_dir}/focused_proof_cost_gate_unexpected_target_breach.golden"

  printf 'focused_proof_cost_gate_smoke_artifacts=%s\n' "${tmp_root}"
}

case "${1:-check}" in
  check|selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
