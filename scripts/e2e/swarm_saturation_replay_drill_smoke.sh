#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
drill="${root_dir}/scripts/swarm_saturation_replay_drill.sh"
fixtures_path="${SWARM_SATURATION_REPLAY_DRILL_FIXTURES:-${root_dir}/scripts/testdata/swarm_saturation_replay_drill/cases.json}"
contract_path="${root_dir}/docs/swarm_saturation_replay_drill_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_SATURATION_REPLAY_DRILL.md"
mode="${1:-check}"
output_dir="${2:-${SWARM_SATURATION_REPLAY_DRILL_OUTPUT_DIR:-}}"
failures=0

record_pass() {
  printf 'PASS swarm-saturation-replay-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-saturation-replay-drill %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_saturation_replay_drill_smoke.sh [check|run|selftest] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-saturation-replay-drill-fixtures.v1"
    and (.cases | length == 4)
    and any(.cases[]; .case_id == "large_64c_256gb" and .expected.decision == "pass" and .scenario.host.profile == "64c_256gb")
    and any(.cases[]; .case_id == "mid_size_mixed_fairness" and .expected.required_deferred_reason_code == "fairness_agent_cap" and .scenario.host.profile == "mid_size")
    and any(.cases[]; .case_id == "constrained_stale_ownership" and .expected.required_deferred_reason_code == "stale_ownership_requires_contact" and .scenario.host.profile == "constrained")
    and any(.cases[]; .case_id == "local_fallback_contaminated" and .expected.decision == "fail_closed" and .scenario.evidence.local_fallback_observed == true)
    and all(.cases[];
      .scenario.schema_version == "franken-engine.swarm-saturation-replay-scenario.v1"
      and (.scenario.requests | length) > 0
      and (.scenario.host.remote_rch_slots | type) == "number"
      and (.scenario.constraints.heavy_fanout_cap | type) == "number"
      and (.scenario.constraints.urgent_slack_slots | type) == "number"
      and (.scenario.constraints.max_heavy_per_agent | type) == "number"
      and .scenario.mutation_policy.fixture_fed_only == true
      and .scenario.mutation_policy.runs_cargo == false
      and .scenario.mutation_policy.runs_rch == false
      and .scenario.mutation_policy.mutates_remote_workers == false
      and all(.scenario.requests[]; (.command_class | IN("cargo_check","cargo_clippy","cargo_test","script_gate","docs_only","json_gate")))
    )
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-saturation-replay-drill-contract.v1"
    and .bead_id == "bd-2zn02"
    and .script == "scripts/swarm_saturation_replay_drill.sh"
    and .smoke_script == "scripts/e2e/swarm_saturation_replay_drill_smoke.sh"
    and .operator_docs == "docs/SWARM_SATURATION_REPLAY_DRILL.md"
    and .fixture_bundle == "scripts/testdata/swarm_saturation_replay_drill/cases.json"
    and .scenario_schema_version == "franken-engine.swarm-saturation-replay-scenario.v1"
    and .report_schema_version == "franken-engine.swarm-saturation-replay-report.v1"
    and .run_manifest_schema_version == "franken-engine.swarm-saturation-replay-run-manifest.v1"
    and .trace_ids_schema_version == "franken-engine.swarm-saturation-replay-trace-ids.v1"
    and (.required_outputs | index("run_manifest.json") != null)
    and (.required_outputs | index("events.jsonl") != null)
    and (.required_outputs | index("commands.txt") != null)
    and (.required_outputs | index("saturation_replay_report.json") != null)
    and (.required_outputs | index("trace_ids.json") != null)
    and (.required_report_fields | index("before_lane_decisions") != null)
    and (.required_report_fields | index("after_lane_decisions") != null)
    and (.required_report_fields | index("fairness_report.fairness_preserved") != null)
    and (.required_report_fields | index("fanout_report.heavy_fanout_capped") != null)
    and (.required_report_fields | index("fanout_report.urgent_slack_preserved") != null)
    and (.required_report_fields | index("contamination_report.local_fallback_contamination_avoided") != null)
    and any(.fixture_cases[]; .case_id == "large_64c_256gb" and .host_profile == "64c_256gb")
    and any(.fixture_cases[]; .case_id == "mid_size_mixed_fairness" and .required_reason_code == "fairness_agent_cap")
    and any(.fixture_cases[]; .case_id == "constrained_stale_ownership" and .required_reason_code == "stale_ownership_requires_contact")
    and any(.fixture_cases[]; .case_id == "local_fallback_contaminated" and .required_reason_code == "local_fallback_contamination")
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.replay_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.optional_live_mode_not_implemented == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'Machine-readable contract:' "$docs_path" \
    && grep -Fq 'Smoke gate:' "$docs_path" \
    && grep -Fq 'Fixture cases:' "$docs_path" \
    && grep -Fq '64-core/256GB' "$docs_path" \
    && grep -Fq 'stable replay hash' "$docs_path" \
    && grep -Fq 'does not execute build commands' "$docs_path" \
    && grep -Fq 'optional live collection path is intentionally not implemented' "$docs_path"
}

check_no_forbidden_commands() {
  local path="$1"
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      record_failure "${path#"$root_dir"/} has heavy Cargo command string: ${command}"
    fi
    if [[ "$command" =~ (^|[[:space:]])rch[[:space:]]+exec([[:space:]]|$) ]]; then
      record_failure "${path#"$root_dir"/} has RCH execution command string: ${command}"
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,260p' "$path")
}

materialize_case() {
  local case_json="$1"
  local case_dir="$2"
  mkdir -p "$case_dir"
  jq '.scenario' <<<"$case_json" >"${case_dir}/scenario.json"
  jq '.expected' <<<"$case_json" >"${case_dir}/expected.json"
}

validate_report() {
  local report="$1"
  local expected="$2"
  local manifest="$3"
  local trace_ids="$4"
  local events="$5"
  local case_id="$6"

  jq -e --slurpfile expected "$expected" '
    .schema_version == "franken-engine.swarm-saturation-replay-report.v1"
    and .bead_id == "bd-2zn02"
    and .decision == $expected[0].decision
    and .host_profile == $expected[0].expected_host_profile
    and (.before_lane_decisions | length) == .summary.total_requests
    and (.after_lane_decisions | length) == .summary.total_requests
    and .summary.admitted_count == $expected[0].admitted_count
    and .summary.deferred_count == $expected[0].deferred_count
    and .fairness_report.fairness_preserved == $expected[0].fairness_preserved
    and .fanout_report.heavy_fanout_capped == $expected[0].fanout_capped
    and .fanout_report.urgent_slack_preserved == $expected[0].urgent_slack_preserved
    and .contamination_report.local_fallback_contamination_avoided == $expected[0].local_fallback_avoided
    and all(.after_lane_decisions[]; has("request_id") and has("after_decision") and has("reason_codes") and has("transport"))
    and all(.after_lane_decisions[] | select(.transport == "rch_required"); (.after_decision == "admit") and (.command_class | IN("cargo_check","cargo_clippy","cargo_test")))
    and all(.after_lane_decisions[] | select(.command_class | IN("script_gate","docs_only","json_gate")) | select(.after_decision == "admit"); .transport == "fixture_only")
    and (
      (($expected[0].required_deferred_reason_code // "") | length) == 0
      or ((.summary.deferred_reason_codes | index($expected[0].required_deferred_reason_code)) != null)
      or ((.fail_closed_reasons | map(.code) | index($expected[0].required_deferred_reason_code)) != null)
    )
    and ((.hash_basis.replay_hash // "") | length) == 64
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.replay_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
  ' "$report" >/dev/null || {
    record_failure "${case_id} report shape mismatch"
    return
  }

  jq -e '
    .schema_version == "franken-engine.swarm-saturation-replay-run-manifest.v1"
    and ((.replay_id // "") | length) > 0
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
  ' "$manifest" >/dev/null || record_failure "${case_id} manifest shape mismatch"

  jq -e '
    .schema_version == "franken-engine.swarm-saturation-replay-trace-ids.v1"
    and ((.replay_id // "") | length) > 0
    and (.trace_ids | length) == 2
  ' "$trace_ids" >/dev/null || record_failure "${case_id} trace ids shape mismatch"

  jq -s '
    length >= 2
    and all(.[]; .schema_version == "franken-engine.swarm-saturation-replay-drill.event.v1" and .component == "swarm_saturation_replay_drill" and ((.event // "") | length) > 0 and ((.outcome // "") | length) > 0)
    and any(.[]; .event == "saturation_replay.emitted")
  ' "$events" >/dev/null || record_failure "${case_id} events missing replay emission"
}

run_case() {
  local case_json="$1"
  local root="$2"
  local case_id case_dir expected expected_code code report manifest trace_ids events prior_failures

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${root}/${case_id}"
  materialize_case "$case_json" "$case_dir"
  expected="${case_dir}/expected.json"
  expected_code="$(jq -r '.expected_exit_code' "$expected")"

  set +e
  bash "$drill" \
    --scenario-json "${case_dir}/scenario.json" \
    --source-revision fixture-revision \
    --output-dir "${case_dir}/out" >/dev/null
  code=$?
  set -e

  if [[ "$code" -ne "$expected_code" ]]; then
    record_failure "${case_id} expected exit ${expected_code}, got ${code}"
    return
  fi

  report="${case_dir}/out/saturation_replay_report.json"
  manifest="${case_dir}/out/run_manifest.json"
  trace_ids="${case_dir}/out/trace_ids.json"
  events="${case_dir}/out/events.jsonl"
  test -s "$report" || {
    record_failure "${case_id} missing saturation_replay_report.json"
    return
  }
  test -s "$manifest" || record_failure "${case_id} missing run_manifest.json"
  test -s "$trace_ids" || record_failure "${case_id} missing trace_ids.json"
  test -s "$events" || record_failure "${case_id} missing events.jsonl"
  test -s "${case_dir}/out/commands.txt" || record_failure "${case_id} missing commands.txt"

  prior_failures="$failures"
  validate_report "$report" "$expected" "$manifest" "$trace_ids" "$events" "$case_id"
  if [[ "$failures" -eq "$prior_failures" ]]; then
    record_pass "${case_id} saturation replay"
  fi
}

run_check() {
  bash -n "$drill"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$fixtures_path" "$contract_path"

  if fixtures_shape_ok; then
    record_pass "fixture shape"
  else
    record_failure "fixture shape mismatch"
  fi
  if contract_shape_ok; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi
  if docs_shape_ok; then
    record_pass "operator docs shape"
  else
    record_failure "operator docs shape mismatch"
  fi

  check_no_forbidden_commands "$drill"
  check_no_forbidden_commands "$fixtures_path"
  check_no_forbidden_commands "$contract_path"
  check_no_forbidden_commands "$docs_path"
}

run_all_cases() {
  local root="$1"
  mkdir -p "$root"
  while IFS= read -r case_json; do
    run_case "$case_json" "$root"
  done < <(jq -c '.cases[]' "$fixtures_path")
  printf 'swarm_saturation_replay_drill_smoke_artifacts=%s\n' "$root"
}

run_selftest() {
  local tmp_root hash_a hash_b
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-saturation-replay-drill-selftest.XXXXXX")"
  run_all_cases "$tmp_root"

  hash_a="$(jq -r '.hash_basis.replay_hash' "${tmp_root}/large_64c_256gb/out/saturation_replay_report.json")"
  bash "$drill" \
    --scenario-json "${tmp_root}/large_64c_256gb/scenario.json" \
    --source-revision fixture-revision \
    --output-dir "${tmp_root}/large_64c_256gb_repeat" >/dev/null
  hash_b="$(jq -r '.hash_basis.replay_hash' "${tmp_root}/large_64c_256gb_repeat/saturation_replay_report.json")"
  if [[ "$hash_a" != "$hash_b" ]]; then
    record_failure "stable replay hash mismatch for repeated large-host case"
  else
    record_pass "stable replay hash"
  fi

  if jq -e '.summary.admitted_count == 0 and .contamination_report.local_fallback_contamination_avoided == true and any(.fail_closed_reasons[]?; .code == "local_fallback_contamination")' "${tmp_root}/local_fallback_contaminated/out/saturation_replay_report.json" >/dev/null; then
    record_pass "selftest local fallback contamination fails closed"
  else
    record_failure "selftest expected local fallback fail-closed report"
  fi
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      if [[ -z "$output_dir" ]]; then
        output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-saturation-replay-drill-run.XXXXXX")"
      fi
      run_all_cases "$output_dir"
    fi
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest
    fi
    ;;
  -h|--help)
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
