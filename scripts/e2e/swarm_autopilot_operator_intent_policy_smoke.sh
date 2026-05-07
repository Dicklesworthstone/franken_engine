#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
compiler="${root_dir}/scripts/swarm_autopilot_operator_intent_policy.sh"
fixtures_path="${SWARM_AUTOPILOT_OPERATOR_INTENT_POLICY_FIXTURES:-${root_dir}/scripts/testdata/swarm_autopilot_operator_intent_policy/cases.json}"
contract_path="${root_dir}/docs/swarm_autopilot_operator_intent_policy_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_AUTOPILOT_OPERATOR_INTENT_POLICY.md"
mode="${1:-check}"
output_dir="${2:-${SWARM_AUTOPILOT_OPERATOR_INTENT_POLICY_OUTPUT_DIR:-}}"
failures=0

record_pass() {
  printf 'PASS swarm-autopilot-operator-intent-policy %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-operator-intent-policy %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_operator_intent_policy_smoke.sh [check|run|selftest] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-operator-intent-policy-fixtures.v1"
    and .base_intent_json.schema_version == "franken-engine.swarm-autopilot-operator-intents.v1"
    and .base_evidence_warehouse_json.schema_version == "franken-engine.swarm-autopilot-evidence-warehouse.v1"
    and .base_forecaster_json.schema_version == "franken-engine.swarm-autopilot-brownout-forecaster.v1"
    and (.cases | length == 5)
    and ([.cases[].case_id] | unique | length == 5)
    and any(.cases[]; .case_id == "valid_policy_compilation" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "conflicting_latency_vs_utilization" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-POLICY-CONFLICT")
    and any(.cases[]; .case_id == "stale_evidence_rejection" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-POLICY-STALE-EVIDENCE")
    and any(.cases[]; .case_id == "fairness_precedence" and .expected.required_precedence_first == "bound_per_agent_fairness_skew")
    and any(.cases[]; .case_id == "safe_mode_fallback" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-POLICY-SAFE-MODE")
    and all(.cases[];
      (.expected.expected_exit_code | type) == "number"
      and (.expected.decision | type) == "string"
      and ((.overrides // {}) | type) == "object"
    )
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-operator-intent-policy-contract.v1"
    and .bead_id == "bd-7dr9z"
    and .script == "scripts/swarm_autopilot_operator_intent_policy.sh"
    and .smoke_script == "scripts/e2e/swarm_autopilot_operator_intent_policy_smoke.sh"
    and .operator_docs == "docs/SWARM_AUTOPILOT_OPERATOR_INTENT_POLICY.md"
    and .fixture_bundle == "scripts/testdata/swarm_autopilot_operator_intent_policy/cases.json"
    and .input_schema_versions.operator_intents == "franken-engine.swarm-autopilot-operator-intents.v1"
    and .output_schema_versions.compiled_policy == "franken-engine.swarm-autopilot-operator-intent-policy.v1"
    and ((["intent_json","evidence_warehouse_json","forecaster_json"] - .required_inputs) | length) == 0
    and ((["operator_intent_policy.json","verification_report.json","counterexamples.json","run_manifest.json","events.jsonl","commands.txt","report.md"] - .output_artifacts) | length) == 0
    and ((["reserve_urgent_rch_slack","cap_nonurgent_heavy_fanout","protect_p1_latency","prefer_warm_cache_reuse","avoid_drained_or_probe_workers","bound_per_agent_fairness_skew","safe_mode_on_degraded"] - .supported_intents) | length) == 0
    and any(.fixture_cases[]; .case_id == "safe_mode_fallback" and .expected_decision == "safe_mode")
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.writes_outside_output_dir == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'Machine-readable contract:' "$docs_path" \
    && grep -Fq 'Smoke gate:' "$docs_path" \
    && grep -Fq 'Fixture cases:' "$docs_path" \
    && grep -Fq 'Fairness precedence outranks warm-cache reuse' "$docs_path" \
    && grep -Fq 'Safe mode is deterministic fallback behavior' "$docs_path" \
    && grep -Fq 'does not mutate beads' "$docs_path"
}

check_no_heavy_cargo_commands() {
  local path="$1"
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      record_failure "${path#"$root_dir"/} has literal heavy Cargo command: ${command}"
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,260p' "$path")
}

materialize_case() {
  local case_id="$1"
  local case_dir="$2"

  jq --arg case_id "$case_id" '
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | $root.base_intent_json * (($case.overrides.intent_json // {}))
  ' "$fixtures_path" >"${case_dir}/intent.json"

  jq --arg case_id "$case_id" '
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | $root.base_evidence_warehouse_json * (($case.overrides.evidence_warehouse_json // {}))
  ' "$fixtures_path" >"${case_dir}/evidence_warehouse.json"

  jq --arg case_id "$case_id" '
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | $root.base_forecaster_json * (($case.overrides.forecaster_json // {}))
  ' "$fixtures_path" >"${case_dir}/forecaster.json"
}

validate_required_artifacts() {
  local case_dir="$1"
  local artifact
  for artifact in operator_intent_policy.json verification_report.json counterexamples.json run_manifest.json events.jsonl commands.txt report.md; do
    if [[ ! -s "${case_dir}/${artifact}" ]]; then
      record_failure "${case_dir} missing ${artifact}"
    fi
  done
}

validate_policy() {
  local policy_json="$1"
  local verification_json="$2"
  local counterexamples_json="$3"
  local expected_json="$4"
  local case_id="$5"

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-operator-intent-policy.v1"
    and .decision == $expected[0].decision
    and (.policy_id | test("^opip-[0-9a-f]{16}$"))
    and (.policy_hash | test("^[0-9a-f]{64}$"))
    and (.thresholds.min_free_rch_slots | type) == "number"
    and (.thresholds.max_nonurgent_heavy_lanes | type) == "number"
    and (.precedence_order | length) >= 5
    and .artifact_paths.commands_txt
    and .artifact_paths.events_jsonl
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and (
      (($expected[0].required_precedence_first // "") | length) == 0
      or .precedence_order[0] == $expected[0].required_precedence_first
    )
    and (
      (($expected[0].required_fallback_action // "") | length) == 0
      or (.fallback_behavior.actions | index($expected[0].required_fallback_action)) != null
    )
  ' "$policy_json" >/dev/null || record_failure "${case_id} policy mismatch"

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-operator-intent-policy-verification.v1"
    and .bead_id == "bd-7dr9z"
    and .decision == $expected[0].decision
    and (
      (($expected[0].required_error_code // "") | length) == 0
      or (
        ([.failure_reasons[]?.code, .conflict_diagnostics[]?.code, .safe_mode_reason.code] | index($expected[0].required_error_code)) != null
      )
    )
  ' "$verification_json" >/dev/null || record_failure "${case_id} verification mismatch"

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-operator-intent-counterexamples.v1"
    and .bead_id == "bd-7dr9z"
    and (
      (($expected[0].required_counterexample // "") | length) == 0
      or ([.counterexamples[].counterexample_id] | index($expected[0].required_counterexample)) != null
    )
    and all(.counterexamples[]?; (.inputs | type) == "object" and (.remediation_text | length) > 0)
  ' "$counterexamples_json" >/dev/null || record_failure "${case_id} counterexample mismatch"
}

validate_events_and_commands() {
  local case_dir="$1"
  local case_id="$2"

  jq -e 'select(.schema_version == "franken-engine.swarm-autopilot-operator-intent-policy.event.v1")' "${case_dir}/events.jsonl" >/dev/null \
    || record_failure "${case_id} event log mismatch"
  grep -Fq './scripts/swarm_autopilot_operator_intent_policy.sh' "${case_dir}/commands.txt" \
    || record_failure "${case_id} command capture mismatch"
}

run_case() {
  local case_json="$1"
  local root="$2"
  local case_id case_dir expected expected_code code prior_failures

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${root}/${case_id}"
  mkdir -p "$case_dir"
  expected="${case_dir}/expected.json"
  jq '.expected' <<<"$case_json" >"$expected"
  expected_code="$(jq -r '.expected_exit_code' "$expected")"
  materialize_case "$case_id" "$case_dir"

  set +e
  bash "$compiler" \
    --intent-json "${case_dir}/intent.json" \
    --evidence-warehouse-json "${case_dir}/evidence_warehouse.json" \
    --forecaster-json "${case_dir}/forecaster.json" \
    --source-revision fixture-revision \
    --output-dir "$case_dir" >/dev/null
  code=$?
  set -e

  if [[ "$code" -ne "$expected_code" ]]; then
    record_failure "${case_id} expected exit ${expected_code}, got ${code}"
    return
  fi

  prior_failures="$failures"
  validate_required_artifacts "$case_dir"
  validate_policy "${case_dir}/operator_intent_policy.json" "${case_dir}/verification_report.json" "${case_dir}/counterexamples.json" "$expected" "$case_id"
  validate_events_and_commands "$case_dir" "$case_id"
  if [[ "$failures" -eq "$prior_failures" ]]; then
    record_pass "${case_id} policy"
  fi
}

run_check() {
  bash -n "$compiler"
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
  check_no_heavy_cargo_commands "$contract_path"
  check_no_heavy_cargo_commands "$docs_path"
}

run_all_cases() {
  local root="$1"
  mkdir -p "$root"
  while IFS= read -r case_json; do
    run_case "$case_json" "$root"
  done < <(jq -c '.cases[]' "$fixtures_path")
  printf 'swarm_autopilot_operator_intent_policy_smoke_artifacts=%s\n' "$root"
}

run_stable_hash_check() {
  local root="$1"
  local first="${root}/policy-stable-a"
  local second="${root}/policy-stable-b"
  local first_hash second_hash

  run_case "$(jq -c '.cases[] | select(.case_id == "valid_policy_compilation")' "$fixtures_path")" "$first"
  run_case "$(jq -c '.cases[] | select(.case_id == "valid_policy_compilation")' "$fixtures_path")" "$second"
  first_hash="$(jq -r '.policy_hash' "${first}/valid_policy_compilation/operator_intent_policy.json")"
  second_hash="$(jq -r '.policy_hash' "${second}/valid_policy_compilation/operator_intent_policy.json")"
  if [[ "$first_hash" == "$second_hash" && "$first_hash" =~ ^[0-9a-f]{64}$ ]]; then
    record_pass "stable policy hash"
  else
    record_failure "stable policy hash mismatch"
  fi
}

run_selftest() {
  local tmp_root
  tmp_root="${output_dir:-${TMPDIR:-/tmp}/swarm-autopilot-operator-intent-policy-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)}"
  mkdir -p "$tmp_root"
  run_all_cases "${tmp_root}/cases"
  run_stable_hash_check "${tmp_root}/stable"
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_all_cases "${output_dir:-${TMPDIR:-/tmp}/swarm-autopilot-operator-intent-policy-smoke/run-$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)}"
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
