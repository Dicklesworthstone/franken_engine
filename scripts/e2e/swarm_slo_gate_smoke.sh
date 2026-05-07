#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="${root_dir}/scripts/swarm_slo_gate.sh"
fixtures_path="${SWARM_SLO_GATE_FIXTURES:-${root_dir}/scripts/testdata/swarm_slo_gate/cases.json}"
contract_path="${root_dir}/docs/swarm_slo_gate_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_SLO_GATE.md"
mode="${1:-check}"
output_dir="${2:-${SWARM_SLO_GATE_OUTPUT_DIR:-}}"
failures=0

record_pass() {
  printf 'PASS swarm-slo-gate %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-slo-gate %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_slo_gate_smoke.sh [check|run|selftest] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-slo-gate-fixtures.v1"
    and (.cases | length == 5)
    and ([.cases[].case_id] | unique | length == 5)
    and any(.cases[]; .case_id == "green" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "warning" and .expected.decision == "warn" and .expected.required_error_code == "FE-SWARM-SLO-HEAVY-FANOUT-WARN")
    and any(.cases[]; .case_id == "brownout_fail" and .expected.decision == "fail_closed" and .expected.required_error_code == "FE-SWARM-SLO-HEAVY-FANOUT")
    and any(.cases[]; .case_id == "stale_tracker_fail" and .expected.decision == "fail_closed" and .expected.required_error_code == "FE-SWARM-SLO-STALE-TRACKER")
    and any(.cases[]; .case_id == "local_fallback_contamination" and .expected.decision == "fail_closed" and .expected.required_error_code == "local_fallback_contamination")
    and all(.cases[];
      ((["slo_input_json","admission_budget_plan_json","rch_rehabilitation_ledger_json","proof_cache_locality_plan_json","saturation_replay_report_json"] - (.inputs | keys_unsorted)) | length) == 0
      and .inputs.slo_input_json.schema_version == "franken-engine.swarm-slo-gate-input.v1"
      and ((["max_admitted_heavy_lanes","min_free_rch_slots","max_stale_progress_seconds","max_stale_tracker_age_seconds","max_unknown_dirty_files","max_proof_cache_pressure_rank"] - (.inputs.slo_input_json.thresholds | keys_unsorted)) | length) == 0
      and .inputs.admission_budget_plan_json.schema_version == "franken-engine.swarm-admission-budget-plan.v1"
      and .inputs.rch_rehabilitation_ledger_json.schema_version == "franken-engine.swarm-rch-stall-rehabilitation-ledger.v1"
      and .inputs.proof_cache_locality_plan_json.schema_version == "franken-engine.swarm-proof-cache-locality-plan.v1"
      and .inputs.saturation_replay_report_json.schema_version == "franken-engine.swarm-saturation-replay-report.v1"
      and (.expected.expected_exit_code | type) == "number"
      and (.expected.fail_count | type) == "number"
      and (.expected.warn_count | type) == "number"
    )
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-slo-gate-contract.v1"
    and .bead_id == "bd-u0mau"
    and .script == "scripts/swarm_slo_gate.sh"
    and .smoke_script == "scripts/e2e/swarm_slo_gate_smoke.sh"
    and .operator_docs == "docs/SWARM_SLO_GATE.md"
    and .fixture_bundle == "scripts/testdata/swarm_slo_gate/cases.json"
    and .input_schema_version == "franken-engine.swarm-slo-gate-input.v1"
    and .report_schema_version == "franken-engine.swarm-slo-gate-report.v1"
    and .run_manifest_schema_version == "franken-engine.swarm-slo-gate-run-manifest.v1"
    and ((["slo_input_json","admission_budget_plan_json","rch_rehabilitation_ledger_json","proof_cache_locality_plan_json","saturation_replay_report_json"] - .required_inputs) | length) == 0
    and ((["slo_gate_report.json","run_manifest.json","events.jsonl","commands.txt"] - .required_outputs) | length) == 0
    and ((["max_admitted_heavy_lanes","minimum_free_rch_slots","maximum_stale_progress_seconds","maximum_stale_tracker_age_seconds","maximum_unknown_dirty_files","maximum_proof_cache_pressure"] - .slo_ids) | length) == 0
    and ((["missing_or_bad_upstream_bundle","incomplete_worker_pressure_telemetry","local_fallback_contamination","upstream_fail_closed"] - .fail_closed_sources) | length) == 0
    and any(.fixture_cases[]; .case_id == "green" and .expected_decision == "pass")
    and any(.fixture_cases[]; .case_id == "warning" and .required_error_code == "FE-SWARM-SLO-HEAVY-FANOUT-WARN")
    and any(.fixture_cases[]; .case_id == "brownout_fail" and .required_error_code == "FE-SWARM-SLO-HEAVY-FANOUT")
    and any(.fixture_cases[]; .case_id == "stale_tracker_fail" and .required_error_code == "FE-SWARM-SLO-STALE-TRACKER")
    and any(.fixture_cases[]; .case_id == "local_fallback_contamination" and .required_error_code == "local_fallback_contamination")
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.gate_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.queries_live_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.writes_outside_output_dir == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'Machine-readable contract:' "$docs_path" \
    && grep -Fq 'Smoke gate:' "$docs_path" \
    && grep -Fq 'Fixture cases:' "$docs_path" \
    && grep -Fq 'max admitted heavy lanes' "$docs_path" \
    && grep -Fq 'local fallback' "$docs_path" \
    && grep -Fq 'does not query Agent Mail' "$docs_path" \
    && grep -Fq 'does not execute build commands' "$docs_path"
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
  local input_id
  mkdir -p "$case_dir"
  for input_id in slo_input_json admission_budget_plan_json rch_rehabilitation_ledger_json proof_cache_locality_plan_json saturation_replay_report_json; do
    jq --arg input_id "$input_id" '.inputs[$input_id]' <<<"$case_json" >"${case_dir}/${input_id}.json"
  done
  jq '.expected' <<<"$case_json" >"${case_dir}/expected.json"
}

validate_report() {
  local report="$1"
  local expected="$2"
  local manifest="$3"
  local events="$4"
  local case_id="$5"

  jq -e --slurpfile expected "$expected" '
    .schema_version == "franken-engine.swarm-slo-gate-report.v1"
    and .bead_id == "bd-u0mau"
    and .decision == $expected[0].decision
    and .summary.fail_count == $expected[0].fail_count
    and .summary.warn_count == $expected[0].warn_count
    and (.slo_verdicts | length) == 6
    and all(.slo_verdicts[];
      ((.slo_id // "") | length) > 0
      and has("observed")
      and has("threshold")
      and (.verdict | IN("pass","warn","fail"))
      and has("error_code")
      and ((.remediation_command // "") | length) > 0
      and ((.evidence_path // "") | length) > 0
    )
    and all(.slo_verdicts[] | select(.verdict == "fail");
      ((.error_code // "") | length) > 0
      and ((.remediation_command // "") | length) > 0
      and ((.evidence_path // "") | length) > 0
    )
    and .summary.every_fail_has_error_code_and_remediation == true
    and (
      (($expected[0].required_error_code // "") | length) == 0
      or ((.slo_verdicts | map(.error_code) | index($expected[0].required_error_code)) != null)
      or ((.fail_closed_reasons | map(.code) | index($expected[0].required_error_code)) != null)
    )
    and ((.hash_basis.report_hash // "") | length) == 64
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.gate_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.mutates_br == false
  ' "$report" >/dev/null || {
    record_failure "${case_id} report shape mismatch"
    return
  }

  jq -e '
    .schema_version == "franken-engine.swarm-slo-gate-run-manifest.v1"
    and ((.gate_id // "") | length) > 0
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.mutates_br == false
  ' "$manifest" >/dev/null || record_failure "${case_id} manifest shape mismatch"

  jq -s '
    length >= 6
    and all(.[]; .schema_version == "franken-engine.swarm-slo-gate.event.v1" and .component == "swarm_slo_gate")
    and any(.[]; .event == "slo_gate.emitted")
  ' "$events" >/dev/null || record_failure "${case_id} events missing SLO emission"
}

run_case() {
  local case_json="$1"
  local root="$2"
  local case_id case_dir expected expected_code code report manifest events prior_failures

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${root}/${case_id}"
  materialize_case "$case_json" "$case_dir"
  expected="${case_dir}/expected.json"
  expected_code="$(jq -r '.expected_exit_code' "$expected")"

  set +e
  bash "$gate" \
    --slo-input-json "${case_dir}/slo_input_json.json" \
    --admission-budget-plan-json "${case_dir}/admission_budget_plan_json.json" \
    --rch-rehabilitation-ledger-json "${case_dir}/rch_rehabilitation_ledger_json.json" \
    --proof-cache-locality-plan-json "${case_dir}/proof_cache_locality_plan_json.json" \
    --saturation-replay-report-json "${case_dir}/saturation_replay_report_json.json" \
    --source-revision fixture-revision \
    --output-dir "${case_dir}/out" >/dev/null
  code=$?
  set -e

  if [[ "$code" -ne "$expected_code" ]]; then
    record_failure "${case_id} expected exit ${expected_code}, got ${code}"
    return
  fi

  report="${case_dir}/out/slo_gate_report.json"
  manifest="${case_dir}/out/run_manifest.json"
  events="${case_dir}/out/events.jsonl"
  test -s "$report" || {
    record_failure "${case_id} missing slo_gate_report.json"
    return
  }
  test -s "$manifest" || record_failure "${case_id} missing run_manifest.json"
  test -s "$events" || record_failure "${case_id} missing events.jsonl"
  test -s "${case_dir}/out/commands.txt" || record_failure "${case_id} missing commands.txt"

  prior_failures="$failures"
  validate_report "$report" "$expected" "$manifest" "$events" "$case_id"
  if [[ "$failures" -eq "$prior_failures" ]]; then
    record_pass "${case_id} SLO gate"
  fi
}

run_check() {
  bash -n "$gate"
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

  check_no_forbidden_commands "$gate"
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
  printf 'swarm_slo_gate_smoke_artifacts=%s\n' "$root"
}

run_selftest() {
  local tmp_root green_case first_hash second_hash
  tmp_root="${output_dir:-${TMPDIR:-/tmp}/swarm-slo-gate-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)}"
  mkdir -p "$tmp_root"
  run_all_cases "$tmp_root/cases"

  green_case="$(jq -c '.cases[] | select(.case_id == "green")' "$fixtures_path")"
  run_case "$green_case" "$tmp_root/stable-a"
  run_case "$green_case" "$tmp_root/stable-b"
  first_hash="$(jq -r '.hash_basis.report_hash' "$tmp_root/stable-a/green/out/slo_gate_report.json")"
  second_hash="$(jq -r '.hash_basis.report_hash' "$tmp_root/stable-b/green/out/slo_gate_report.json")"
  if [[ "$first_hash" == "$second_hash" && ${#first_hash} -eq 64 ]]; then
    record_pass "stable report hash"
  else
    record_failure "stable report hash mismatch"
  fi

  if jq -e '
    .decision == "fail_closed"
    and ((.fail_closed_reasons | map(.code) | index("local_fallback_contamination")) != null)
  ' "$tmp_root/cases/local_fallback_contamination/out/slo_gate_report.json" >/dev/null; then
    record_pass "local fallback fail-closed reason"
  else
    record_failure "local fallback fail-closed reason missing"
  fi
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_all_cases "${output_dir:-${TMPDIR:-/tmp}/swarm-slo-gate-smoke/run-$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)}"
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
