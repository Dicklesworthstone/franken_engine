#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${root_dir}/scripts/e2e/swarm_proof_broker_no_mock_drill.sh"
contract_path="${root_dir}/docs/swarm_proof_broker_no_mock_drill_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_PROOF_BROKER_NO_MOCK_DRILL.md"
cases_path="${root_dir}/scripts/testdata/swarm_proof_broker_no_mock_drill/cases.json"
mode="${1:-check}"
output_root="${2:-${SWARM_PROOF_BROKER_NO_MOCK_DRILL_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-proof-broker-no-mock-drill-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS swarm-proof-broker-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-proof-broker-no-mock-drill %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_proof_broker_no_mock_drill_smoke.sh [check|selftest] [output_root]
EOF
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-broker-no-mock-drill-contract.v1"
    and .bead_id == "bd-ua5n2.8"
    and (.required_outputs | length) == 12
    and (.required_outputs | index("truth_gate_report.json") != null)
    and (.required_outputs | index("operator_status_bundle.json") != null)
    and (.fail_closed_reasons | sort) == [
      "dirty_paths_outside_lane",
      "hidden_reuse_refusal",
      "incomplete_rch_artifact_retrieval",
      "local_fallback_contamination",
      "missing_agent_mail_evidence",
      "stale_br_bv_snapshot",
      "stale_proof_rejection",
      "under_specified_replay_bundle",
      "unsupported_shell_wrapped_cargo"
    ]
    and (.modes | sort) == ["live", "replay"]
    and .truth_gate_policy.live_mode_forbids_synthetic_substitution == true
    and .truth_gate_policy.hidden_green_status_allowed == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'never runs Cargo or RCH' "$docs_path" \
    && grep -Fq 'missing Agent Mail evidence' "$docs_path" \
    && grep -Fq 'truth_gate_report.json' "$docs_path" \
    && grep -Fq 'under-specified replay bundles' "$docs_path" \
    && grep -Fq 'Replay mode consumes a preserved bundle' "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-broker-no-mock-drill-fixtures.v1"
    and (.cases | length) == 5
    and ([.cases[].case_id] | sort) == [
      "duplicate_storm_coalescing",
      "healthy_reuse_lifecycle",
      "local_fallback_quarantine",
      "stale_proof_rejection",
      "under_specified_replay_rejection"
    ]
    and ([.cases[].expected.decision] | unique | sort) == ["fail_closed", "pass"]
    and ([.cases[].expected.fail_closed_reasons[]?] | unique | sort) == [
      "local_fallback_contamination",
      "stale_proof_rejection",
      "under_specified_replay_bundle"
    ]
  ' "$cases_path" >/dev/null
}

script_static_ok() {
  bash -n "$script_path"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$script_path" "${BASH_SOURCE[0]}"
  fi
}

expand_case() {
  local case_json="$1"
  jq -n \
    --slurpfile fixtures "$cases_path" \
    --argjson case "$case_json" '
      ($fixtures[0].base_input * ($case | del(.expected)))
      + {expected: $case.expected}
    '
}

assert_required_artifacts() {
  local output_dir="$1"
  local required=(
    proof_broker_lifecycle_bundle.json
    run_manifest.json
    events.jsonl
    commands.txt
    trace_ids.json
    request_capture.json
    equivalence_report.json
    artifact_index.json
    batch_plan.json
    chaos_scenarios.json
    operator_status_bundle.json
    truth_gate_report.json
  )
  local artifact

  for artifact in "${required[@]}"; do
    if [[ ! -s "${output_dir}/${artifact}" ]]; then
      record_failure "missing artifact ${artifact}"
    fi
  done
}

assert_case_output() {
  local case_json="$1"
  local output_dir="$2"
  local bundle_path="${output_dir}/proof_broker_lifecycle_bundle.json"
  local truth_path="${output_dir}/truth_gate_report.json"
  local manifest_path="${output_dir}/run_manifest.json"
  local case_id

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  assert_required_artifacts "$output_dir"
  jq empty \
    "$bundle_path" \
    "$truth_path" \
    "$manifest_path" \
    "${output_dir}/trace_ids.json" \
    "${output_dir}/request_capture.json" \
    "${output_dir}/equivalence_report.json" \
    "${output_dir}/artifact_index.json" \
    "${output_dir}/batch_plan.json" \
    "${output_dir}/chaos_scenarios.json" \
    "${output_dir}/operator_status_bundle.json" >/dev/null

  jq -e \
    --argjson expected "$(jq '.expected' <<<"$case_json")" \
    --arg case_id "$case_id" '
      .schema_version == "franken-engine.swarm-proof-broker-no-mock-drill.v1"
      and .case_id == $case_id
      and .mode == "replay"
      and .decision == $expected.decision
      and .fail_closed_reasons == $expected.fail_closed_reasons
      and .component_summaries == $expected.component_summaries
      and .trace_ids.trace_ids == $expected.trace_ids
      and (.bundle_hash | test("^[0-9a-f]{64}$"))
      and .truth_gate_report.decision == $expected.decision
      and .truth_gate_report.fail_closed_reasons == $expected.fail_closed_reasons
      and .truth_gate_report.no_mock_attestation.replay_mode_uses_preserved_bundle == true
      and .truth_gate_report.no_mock_attestation.live_mode_uses_synthetic_substitution == false
      and .truth_gate_report.no_mock_attestation.executes_cargo == false
      and .truth_gate_report.no_mock_attestation.executes_rch == false
      and .non_mutation_attestation.runs_cargo == false
      and .non_mutation_attestation.runs_rch == false
      and .non_mutation_attestation.mutates_br == false
    ' "$bundle_path" >/dev/null || record_failure "${case_id} lifecycle bundle mismatch"

  jq -e \
    --argjson expected "$(jq '.expected' <<<"$case_json")" \
    --arg case_id "$case_id" '
      .schema_version == "franken-engine.swarm-proof-broker-truth-gate.v1"
      and .case_id == $case_id
      and .decision == $expected.decision
      and .fail_closed_reasons == $expected.fail_closed_reasons
      and .no_mock_attestation.executes_cargo == false
      and .no_mock_attestation.executes_rch == false
      and .no_mock_attestation.mutates_live_queue == false
    ' "$truth_path" >/dev/null || record_failure "${case_id} truth gate mismatch"

  jq -e --arg case_id "$case_id" '
    .schema_version == "franken-engine.swarm-proof-broker-no-mock-drill-run-manifest.v1"
    and .case_id == $case_id
    and .executed_heavy_work == false
    and (.bundle_hash | test("^[0-9a-f]{64}$"))
  ' "$manifest_path" >/dev/null || record_failure "${case_id} manifest mismatch"
}

run_case() {
  local raw_case_json="$1"
  local tmp_root="$2"
  local case_json case_id case_dir fixture_path expected_exit actual_exit

  case_json="$(expand_case "$raw_case_json")"
  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${tmp_root}/${case_id}"
  fixture_path="${case_dir}/fixture.json"
  mkdir -p "$case_dir"
  jq 'del(.expected)' <<<"$case_json" >"$fixture_path"
  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"

  set +e
  "$script_path" --fixture-json "$fixture_path" --mode replay --output-dir "${case_dir}/out" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected ${expected_exit}"
    return
  fi
  assert_case_output "$case_json" "${case_dir}/out"
  record_pass "$case_id"
}

run_check() {
  jq empty "$contract_path" "$cases_path" >/dev/null
  script_static_ok
  contract_shape_ok || record_failure "contract shape"
  docs_shape_ok || record_failure "docs shape"
  fixtures_shape_ok || record_failure "fixture shape"
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  local tmp_root="$1"

  run_check
  if [[ "$failures" -ne 0 ]]; then
    return
  fi
  while IFS= read -r case_json; do
    run_case "$case_json" "$tmp_root"
  done < <(jq -c '.cases[]' "$cases_path")
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest "$output_root"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
