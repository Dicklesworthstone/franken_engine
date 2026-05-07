#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
miner="${root_dir}/scripts/swarm_autopilot_promotion_candidate_miner.sh"
fixtures_path="${SWARM_AUTOPILOT_PROMOTION_CANDIDATE_MINER_FIXTURES:-${root_dir}/scripts/testdata/swarm_autopilot_promotion_candidate_miner/cases.json}"
contract_path="${root_dir}/docs/swarm_autopilot_promotion_candidate_miner_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_AUTOPILOT_PROMOTION_CANDIDATE_MINER.md"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-autopilot-promotion-candidate-miner %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-promotion-candidate-miner %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_promotion_candidate_miner_smoke.sh [check|selftest]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-promotion-candidate-miner-fixtures.v1"
    and .base_evidence_warehouse_json.schema_version == "franken-engine.swarm-autopilot-evidence-warehouse.v1"
    and .base_hindsight_chaos_scenarios_json.schema_version == "franken-engine.swarm-autopilot-hindsight-chaos-scenarios.v1"
    and (.base_evidence_warehouse_json.artifact_rows | length) >= 2
    and (.base_hindsight_chaos_scenarios_json.scenarios | length) >= 2
    and .base_evidence_warehouse_json.mutation_policy.advisory_only == true
    and .base_evidence_warehouse_json.mutation_policy.runs_cargo == false
    and .base_evidence_warehouse_json.mutation_policy.runs_rch == false
    and .base_hindsight_chaos_scenarios_json.mutation_policy.advisory_only == true
    and .base_hindsight_chaos_scenarios_json.mutation_policy.runs_cargo == false
    and .base_hindsight_chaos_scenarios_json.mutation_policy.runs_rch == false
    and (.cases | length) == 5
    and ([.cases[].case_id] | unique | length) == 5
    and any(.cases[]; .case_id == "promotable_repeated_success" and .expected.required_candidate_type == "promotion_candidate")
    and any(.cases[]; .case_id == "insufficient_evidence_degradation" and .expected.required_candidate_type == "degraded_insufficient_evidence")
    and any(.cases[]; .case_id == "contradictory_hindsight_block" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-PROMOTION-CONTRADICTORY-HINDSIGHT")
    and any(.cases[]; .case_id == "contamination_refusal" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-PROMOTION-CONTAMINATED")
    and any(.cases[]; .case_id == "stable_non_promotion_recommendation" and .expected.required_candidate_type == "stable_non_promotion")
    and all(.cases[];
      (.expected.expected_exit_code | type) == "number"
      and (.expected.decision | type) == "string"
      and ((.overrides // {}) | type) == "object"
    )
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-promotion-candidate-miner-contract.v1"
    and .bead_id == "bd-gra1z.3"
    and .parent_bead_id == "bd-gra1z"
    and ((["bd-gra1z.1","bd-09g6k"] - .depends_on) | length) == 0
    and .script == "scripts/swarm_autopilot_promotion_candidate_miner.sh"
    and .smoke_script == "scripts/e2e/swarm_autopilot_promotion_candidate_miner_smoke.sh"
    and .docs == "docs/SWARM_AUTOPILOT_PROMOTION_CANDIDATE_MINER.md"
    and .fixture_bundle == "scripts/testdata/swarm_autopilot_promotion_candidate_miner/cases.json"
    and .candidate_schema_version == "franken-engine.swarm-autopilot-promotion-candidates.v1"
    and .receipt_schema_version == "franken-engine.swarm-autopilot-promotion-candidate-receipts.v1"
    and ((["promotion_candidate","stable_non_promotion","degraded_insufficient_evidence"] - .candidate_types) | length) == 0
    and (([
      "FE-SWARM-AUTOPILOT-PROMOTION-SCHEMA-DRIFT",
      "FE-SWARM-AUTOPILOT-PROMOTION-STALE-HINDSIGHT",
      "FE-SWARM-AUTOPILOT-PROMOTION-CONTRADICTORY-HINDSIGHT",
      "FE-SWARM-AUTOPILOT-PROMOTION-CONTAMINATED"
    ] - .required_error_codes) | length) == 0
    and any(.selftest_cases[]; .case_id == "promotable_repeated_success" and .required_candidate_type == "promotion_candidate")
    and any(.selftest_cases[]; .case_id == "insufficient_evidence_degradation" and .required_candidate_type == "degraded_insufficient_evidence")
    and any(.selftest_cases[]; .case_id == "contradictory_hindsight_block" and .required_error_code == "FE-SWARM-AUTOPILOT-PROMOTION-CONTRADICTORY-HINDSIGHT")
    and any(.selftest_cases[]; .case_id == "contamination_refusal" and .required_error_code == "FE-SWARM-AUTOPILOT-PROMOTION-CONTAMINATED")
    and any(.selftest_cases[]; .case_id == "stable_non_promotion_recommendation" and .required_candidate_type == "stable_non_promotion")
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.reassigns_beads == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.promotes_candidates_automatically == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'The promotion candidate miner is advisory only and proof only.' "$docs_path" \
    && grep -Fq 'Promotion candidates require repeated healthy warehouse evidence and replayable hindsight scenarios.' "$docs_path" \
    && grep -Fq 'Each candidate preserves confidence band, required evidence count, observed evidence count, contradictory outcome reasons, and exact source artifact paths.' "$docs_path" \
    && grep -Fq 'Contradictory hindsight blocks promotion truth.' "$docs_path" \
    && grep -Fq 'The miner never promotes automatically.' "$docs_path"
}

materialize_case() {
  local case_id="$1"
  local case_dir="$2"
  jq --arg case_id "$case_id" '
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | $root.base_evidence_warehouse_json * ($case.overrides.evidence_warehouse_json // {})
  ' "$fixtures_path" >"${case_dir}/evidence_warehouse.json"
  jq --arg case_id "$case_id" '
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | $root.base_hindsight_chaos_scenarios_json * ($case.overrides.hindsight_chaos_scenarios_json // {})
  ' "$fixtures_path" >"${case_dir}/hindsight_chaos_scenarios.json"
  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected' "$fixtures_path" >"${case_dir}/expected.json"
}

validate_required_artifacts() {
  local output_case_dir="$1"
  local artifact
  for artifact in \
    swarm_autopilot_promotion_candidates.json \
    swarm_autopilot_promotion_candidate_receipts.json \
    events.jsonl \
    commands.txt \
    report.md; do
    if [[ ! -s "${output_case_dir}/${artifact}" ]]; then
      record_failure "${output_case_dir} missing ${artifact}"
    fi
  done
}

validate_outputs() {
  local output_case_dir="$1"
  local case_id="$2"
  local expected_json="$3"
  local candidates_json="${output_case_dir}/swarm_autopilot_promotion_candidates.json"
  local receipts_json="${output_case_dir}/swarm_autopilot_promotion_candidate_receipts.json"
  local required_error required_candidate

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-promotion-candidates.v1"
    and .bead_id == "bd-gra1z.3"
    and .decision == $expected[0].decision
    and (.candidate_summary.candidate_count == (.candidates | length))
    and .artifact_paths.evidence_warehouse_json
    and .artifact_paths.hindsight_chaos_scenarios_json
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.reassigns_beads == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.promotes_candidates_automatically == false
    and all(.candidates[]?;
      (.confidence_band | IN("high","medium","low"))
      and (.required_evidence_count | type) == "number"
      and (.observed_evidence_count | type) == "number"
      and ((.contradictory_outcome_reasons // null) | type) == "array"
      and ((.source_artifact_paths // null) | type) == "object"
      and ((.source_artifact_paths.evidence_warehouse_json // "") | length) > 0
      and ((.source_artifact_paths.hindsight_chaos_scenarios_json // "") | length) > 0
    )
  ' "$candidates_json" >/dev/null || record_failure "${case_id} candidates mismatch"

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-promotion-candidate-receipts.v1"
    and .bead_id == "bd-gra1z.3"
    and .decision == $expected[0].decision
    and ((.receipts // null) | type) == "array"
    and ((.fail_closed_reasons // null) | type) == "array"
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
  ' "$receipts_json" >/dev/null || record_failure "${case_id} receipts mismatch"

  required_candidate="$(jq -r '.required_candidate_type // ""' "$expected_json")"
  if [[ -n "$required_candidate" ]]; then
    jq -e --arg required_candidate "$required_candidate" '
      .candidates | any(.candidate_type == $required_candidate)
    ' "$candidates_json" >/dev/null || record_failure "${case_id} missing candidate type ${required_candidate}"

    jq -e --arg required_candidate "$required_candidate" '
      .receipts | any(.candidate_type == $required_candidate)
    ' "$receipts_json" >/dev/null || record_failure "${case_id} missing receipt type ${required_candidate}"
  fi

  required_error="$(jq -r '.required_error_code // ""' "$expected_json")"
  if [[ -n "$required_error" ]]; then
    jq -e --arg required_error "$required_error" '
      .fail_closed_reasons | map(.code) | index($required_error) != null
    ' "$candidates_json" >/dev/null || record_failure "${case_id} missing error code ${required_error}"
  fi

  jq -e 'select(.schema_version == "franken-engine.swarm-autopilot-promotion-candidate.event.v1")' "${output_case_dir}/events.jsonl" >/dev/null \
    || record_failure "${case_id} event log mismatch"

  grep -Fq './scripts/swarm_autopilot_promotion_candidate_miner.sh' "${output_case_dir}/commands.txt" \
    || record_failure "${case_id} commands.txt missing promotion miner command"
}

run_case() {
  local case_id="$1"
  local case_dir="$2"
  local output_case_dir="${case_dir}/output"
  local expected_json="${case_dir}/expected.json"
  local rc

  mkdir -p "$case_dir" "$output_case_dir"
  materialize_case "$case_id" "$case_dir"

  set +e
  bash "$miner" \
    --evidence-warehouse-json "${case_dir}/evidence_warehouse.json" \
    --hindsight-chaos-scenarios-json "${case_dir}/hindsight_chaos_scenarios.json" \
    --minimum-evidence-count 2 \
    --source-revision "fixture-${case_id}" \
    --output-dir "$output_case_dir"
  rc=$?
  set -e

  if [[ "$rc" -ne "$(jq -r '.expected_exit_code' "$expected_json")" ]]; then
    record_failure "${case_id} exit code ${rc} != expected $(jq -r '.expected_exit_code' "$expected_json")"
  fi

  validate_required_artifacts "$output_case_dir"
  validate_outputs "$output_case_dir" "$case_id" "$expected_json"
}

run_check() {
  fixtures_shape_ok || record_failure "fixtures shape mismatch"
  contract_shape_ok || record_failure "contract JSON shape mismatch"
  docs_shape_ok || record_failure "docs truth text mismatch"
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  local temp_dir
  temp_dir="$(mktemp -d)"

  while IFS= read -r case_id; do
    run_case "$case_id" "${temp_dir}/${case_id}"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")

  if [[ "$failures" -eq 0 ]]; then
    record_pass "selftest"
  else
    exit 1
  fi
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest
    else
      exit 1
    fi
    ;;
  *)
    usage
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
