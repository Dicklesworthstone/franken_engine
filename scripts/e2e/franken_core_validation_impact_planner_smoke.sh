#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/franken_core_validation_impact_planner.sh"
contract_json="${root_dir}/docs/franken_core_validation_impact_planner_v1.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS franken-core-validation-impact %s\n' "$1"
}

record_failure() {
  printf 'FAIL franken-core-validation-impact %s\n' "$1" >&2
  exit 1
}

plan_shape_filter='
  .schema_version == "franken-engine.franken-core-validation-impact-plan.v1"
  and (.bead_id | length > 0)
  and (.source_revision | length > 0)
  and (.decision == "green" or .decision == "fail_closed")
  and (.changed_paths | type == "array")
  and (.change_classes | type == "array")
  and (.recommended_commands | type == "array")
  and (.workspace_inclusion_policy.workspace_inclusion_claim_supported == false)
  and (.workspace_inclusion_policy.standalone_core_validation_sufficient_for_workspace_inclusion == false)
  and all(.recommended_commands[]?; ((.command_kind | startswith("rch_cargo")) | not) or .rch_wrapped == true)
  and all(.recommended_commands[]?; ((.command_kind | startswith("rch_cargo")) | not) or (.display | startswith("rch exec -- env CARGO_TARGET_DIR=")))
'

assert_plan() {
  local plan_path="$1"
  local expected_decision="$2"
  local required_class="$3"
  local requires_rch="$4"

  jq -e "$plan_shape_filter" "$plan_path" >/dev/null \
    || record_failure "plan shape ${plan_path}"
  jq -e --arg decision "$expected_decision" '.decision == $decision' "$plan_path" >/dev/null \
    || record_failure "decision ${expected_decision}"
  jq -e --arg class "$required_class" '.change_classes | index($class)' "$plan_path" >/dev/null \
    || record_failure "missing class ${required_class}"

  if [[ "$requires_rch" == "true" ]]; then
    jq -e 'any(.recommended_commands[]?; .display | startswith("rch exec -- env CARGO_TARGET_DIR="))' "$plan_path" >/dev/null \
      || record_failure "missing rch command"
  fi
}

run_case() {
  local case_name="$1"
  local expected_decision="$2"
  local required_class="$3"
  local requires_rch="$4"
  shift 4
  local tmpdir output_dir status expected_exit plan_path
  local -a cmd

  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  if [[ "$expected_decision" == "fail_closed" ]]; then
    expected_exit=42
  else
    expected_exit=0
  fi

  cmd=("$planner" --bead-id "bd-4w7h9.3-smoke" --source-revision "smoke-${case_name}" --output-dir "$output_dir")
  while [[ "$#" -gt 0 ]]; do
    cmd+=(--changed-path "$1")
    shift
  done

  set +e
  "${cmd[@]}" >"${tmpdir}/stdout.log" 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    cat "${tmpdir}/stderr.log" >&2
    record_failure "${case_name} exit ${status}, expected ${expected_exit}"
  fi

  plan_path="${output_dir}/validation_impact_plan.json"
  [[ -f "$plan_path" ]] || record_failure "missing plan ${case_name}"
  [[ -f "${output_dir}/run_manifest.json" ]] || record_failure "missing manifest ${case_name}"
  [[ -f "${output_dir}/events.jsonl" ]] || record_failure "missing events ${case_name}"
  [[ -f "${output_dir}/commands.txt" ]] || record_failure "missing commands ${case_name}"
  [[ -f "${output_dir}/report.md" ]] || record_failure "missing report ${case_name}"
  grep -Fq "recommended validation commands" "${output_dir}/commands.txt" \
    || record_failure "commands missing recommendations ${case_name}"

  assert_plan "$plan_path" "$expected_decision" "$required_class" "$requires_rch"
  record_pass "$case_name"
}

run_check() {
  jq empty "$contract_json"
  bash -n "$planner" "${BASH_SOURCE[0]}"
  run_case "docs-only" "green" "docs_only" "false" "docs/FRANKEN_CORE_API_PARITY_LEDGER_V1.md"
  run_case "script-only" "green" "script_only" "false" "scripts/franken_core_validation_impact_planner.sh"
  run_case "franken-core" "green" "franken_core_only" "true" "crates/franken-core/src/parser.rs"
  run_case "engine-api" "green" "franken_engine_api_adjacent" "true" "crates/franken-engine/src/parser.rs"
  run_case "extension-host" "green" "extension_host_adjacent" "true" "crates/franken-extension-host/src/lib.rs"
  run_case "cargo-topology" "fail_closed" "cargo_topology" "true" "Cargo.toml"
  run_case "crate-cargo-topology" "fail_closed" "cargo_topology" "true" "crates/franken-core/Cargo.toml"
  run_case "mixed" "green" "franken_core_only" "true" "docs/FRANKEN_CORE_API_PARITY_LEDGER_V1.md" "crates/franken-core/src/parser.rs" "crates/franken-engine/src/parser.rs"
  run_case "unknown-path" "fail_closed" "unknown_path" "true" "examples/not-mapped.fixture"
  git -C "$root_dir" diff --check -- \
    docs/FRANKEN_CORE_VALIDATION_IMPACT_PLANNER_V1.md \
    docs/franken_core_validation_impact_planner_v1.json \
    scripts/franken_core_validation_impact_planner.sh \
    scripts/e2e/franken_core_validation_impact_planner_smoke.sh
  record_pass "check"
}

run_negative() {
  local tmpdir output_dir plan_path mutated_plan
  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  "$planner" --bead-id "bd-4w7h9.3-negative" --source-revision "negative" --output-dir "$output_dir" --changed-path "crates/franken-core/src/parser.rs" >/dev/null
  plan_path="${output_dir}/validation_impact_plan.json"
  mutated_plan="${tmpdir}/stale-command-shape.json"
  jq '(.recommended_commands[] | select(.command_kind | startswith("rch_cargo")) | .display) = "cargo check --all-targets"' "$plan_path" >"$mutated_plan"

  if jq -e "$plan_shape_filter" "$mutated_plan" >/dev/null; then
    record_failure "negative stale command shape"
  fi

  record_pass "negative stale command shape"
}

case "$mode" in
  check)
    run_check
    ;;
  negative)
    run_negative
    ;;
  -h|--help|help)
    printf 'Usage: ./scripts/e2e/franken_core_validation_impact_planner_smoke.sh [check|negative]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
