#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
composer="${root_dir}/scripts/swarm_autopilot_replay_recipe_composer.sh"
fixtures_path="${SWARM_AUTOPILOT_REPLAY_RECIPE_FIXTURES:-${root_dir}/scripts/testdata/swarm_autopilot_replay_recipe_composer/cases.json}"
contract_path="${root_dir}/docs/swarm_autopilot_replay_recipe_composer_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_AUTOPILOT_REPLAY_RECIPE_COMPOSER.md"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-autopilot-replay-recipe-composer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-replay-recipe-composer %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_replay_recipe_composer_smoke.sh [check|selftest]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-replay-recipe-composer-fixtures.v1"
    and .base_cohort_diff_receipts_json.schema_version == "franken-engine.swarm-autopilot-cohort-diff-receipts.v1"
    and .base_anomaly_cohorts_json.schema_version == "franken-engine.swarm-autopilot-anomaly-cohorts.v1"
    and .base_replay_index_json.schema_version == "franken-engine.swarm-autopilot-replay-index.v1"
    and (.cases | length) == 5
    and ([.cases[].case_id] | unique | length) == 5
    and any(.cases[]; .case_id == "healthy_reference_replay" and .expected.required_replay_mode == "reference_baseline_replay")
    and any(.cases[]; .case_id == "blocked_counterexample_replay" and .expected.required_replay_mode == "counterexample_replay")
    and any(.cases[]; .case_id == "contaminated_replay_refusal" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-REPLAY-RECIPE-CONTAMINATED-BASELINE")
    and any(.cases[]; .case_id == "missing_replay_index_fail_closed" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-REPLAY-RECIPE-INCOMPLETE-INDEX")
    and any(.cases[]; .case_id == "stale_diff_fail_closed" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-REPLAY-RECIPE-STALE-DIFF")
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-replay-recipe-composer-contract.v1"
    and .bead_id == "bd-00ofm.3"
    and .parent_bead_id == "bd-00ofm"
    and ((["bd-00ofm.1","bd-00ofm.2"] - .depends_on) | length) == 0
    and .script == "scripts/swarm_autopilot_replay_recipe_composer.sh"
    and .smoke_script == "scripts/e2e/swarm_autopilot_replay_recipe_composer_smoke.sh"
    and .docs == "docs/SWARM_AUTOPILOT_REPLAY_RECIPE_COMPOSER.md"
    and .fixture_bundle == "scripts/testdata/swarm_autopilot_replay_recipe_composer/cases.json"
    and .recipe_bundle_schema_version == "franken-engine.swarm-autopilot-replay-recipe-bundle.v1"
    and .recipe_index_schema_version == "franken-engine.swarm-autopilot-replay-recipe-index.v1"
    and ((["reference_baseline_replay","counterexample_replay","quarantine_only"] - .replay_modes) | length) == 0
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.approves_replay_automatically == false
    and .mutation_policy.promotes_evidence_automatically == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'The replay recipe composer is advisory only and proof only.' "$docs_path" \
    && grep -Fq 'Reference baseline replay remains distinct from blocked or degraded counterexample replay.' "$docs_path" \
    && grep -Fq 'Blocked counterexample replay must preserve comparison pivots and raw replay evidence paths.' "$docs_path" \
    && grep -Fq 'Contaminated evidence cannot be selected as a remote-only replay baseline.' "$docs_path" \
    && grep -Fq 'Incomplete replay indexes fail closed.' "$docs_path"
}

materialize_case() {
  local case_id="$1"
  local case_dir="$2"
  jq --arg case_id "$case_id" '
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | {
        cohort_diff_receipts_json: ($root.base_cohort_diff_receipts_json * ($case.overrides.cohort_diff_receipts_json // {})),
        anomaly_cohorts_json: ($root.base_anomaly_cohorts_json * ($case.overrides.anomaly_cohorts_json // {})),
        replay_index_json: ($root.base_replay_index_json * ($case.overrides.replay_index_json // {}))
      }
  ' "$fixtures_path" >"${case_dir}/materialized_inputs.json"
  jq '.cohort_diff_receipts_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/cohort_diff_receipts.json"
  jq '.anomaly_cohorts_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/anomaly_cohorts.json"
  jq '.replay_index_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/replay_index.json"
  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected' "$fixtures_path" >"${case_dir}/expected.json"
}

validate_required_artifacts() {
  local case_dir="$1"
  local artifact
  for artifact in swarm_autopilot_replay_recipe_bundle.json swarm_autopilot_replay_recipe_index.json events.jsonl commands.txt report.md; do
    if [[ ! -s "${case_dir}/${artifact}" ]]; then
      record_failure "${case_dir} missing ${artifact}"
    fi
  done
}

validate_outputs() {
  local output_case_dir="$1"
  local case_id="$2"
  local expected_json="$3"
  local bundle_json="${output_case_dir}/swarm_autopilot_replay_recipe_bundle.json"
  local recipe_index_json="${output_case_dir}/swarm_autopilot_replay_recipe_index.json"
  local required_error required_mode required_classification

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-replay-recipe-bundle.v1"
    and .decision == $expected[0].decision
    and (.recipe_summary.recipe_count == (.replay_recipes | length))
    and (.replay_recipes | length) > 0
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.approves_replay_automatically == false
    and .mutation_policy.promotes_evidence_automatically == false
  ' "$bundle_json" >/dev/null || record_failure "${case_id} replay recipe bundle mismatch"

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-replay-recipe-index.v1"
    and .decision == $expected[0].decision
    and (.entries | length) > 0
  ' "$recipe_index_json" >/dev/null || record_failure "${case_id} recipe index mismatch"

  required_error="$(jq -r '.required_error_code // ""' "$expected_json")"
  if [[ -n "$required_error" ]]; then
    jq -e --arg required_error "$required_error" '.fail_closed_reasons | map(.code) | index($required_error) != null' "$bundle_json" >/dev/null \
      || record_failure "${case_id} missing required error code ${required_error}"
  fi

  required_mode="$(jq -r '.required_replay_mode // ""' "$expected_json")"
  if [[ -n "$required_mode" ]]; then
    jq -e --arg required_mode "$required_mode" '.replay_recipes | any(.replay_mode == $required_mode and .replay_ready == true)' "$bundle_json" >/dev/null \
      || record_failure "${case_id} missing replay mode ${required_mode}"
  fi

  required_classification="$(jq -r '.required_expected_classification // ""' "$expected_json")"
  if [[ -n "$required_classification" ]]; then
    jq -e --arg required_classification "$required_classification" '.replay_recipes | any(.expected_classification == $required_classification)' "$bundle_json" >/dev/null \
      || record_failure "${case_id} missing expected classification ${required_classification}"
  fi

  grep -Fq './scripts/swarm_autopilot_replay_recipe_composer.sh' "${output_case_dir}/commands.txt" \
    || record_failure "${case_id} commands.txt missing replay recipe command"
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
  bash "$composer" \
    --cohort-diff-receipts-json "${case_dir}/cohort_diff_receipts.json" \
    --anomaly-cohorts-json "${case_dir}/anomaly_cohorts.json" \
    --replay-index-json "${case_dir}/replay_index.json" \
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
