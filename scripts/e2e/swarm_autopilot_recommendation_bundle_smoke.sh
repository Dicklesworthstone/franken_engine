#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
bundle_script="${root_dir}/scripts/swarm_autopilot_recommendation_bundle.sh"
fixtures_path="${SWARM_AUTOPILOT_RECOMMENDATION_BUNDLE_FIXTURES:-${root_dir}/scripts/testdata/swarm_autopilot_recommendation_bundle/cases.json}"
contract_path="${root_dir}/docs/swarm_autopilot_recommendation_bundle_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_AUTOPILOT_RECOMMENDATION_BUNDLE.md"
mode="${1:-check}"
failures=0
fixed_now_epoch_seconds="1778123000"
stale_after_seconds="1800"

record_pass() {
  printf 'PASS swarm-autopilot-recommendation-bundle %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-recommendation-bundle %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_recommendation_bundle_smoke.sh [check|selftest]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-recommendation-bundle-fixtures.v1"
    and .base_operator_intent_policy_json.schema_version == "franken-engine.swarm-autopilot-operator-intent-policy.v1"
    and .base_brownout_forecaster_json.schema_version == "franken-engine.swarm-autopilot-brownout-forecaster.v1"
    and .base_resource_lease_plan_json.schema_version == "franken-engine.swarm-autopilot-resource-lease-plan.v1"
    and .base_resource_scarcity_receipts_json.schema_version == "franken-engine.swarm-autopilot-resource-scarcity-receipts.v1"
    and .base_control_plane_context_json.schema_version == "franken-engine.swarm-autopilot-control-plane-context.v1"
    and (.cases | length) == 5
    and ([.cases[].case_id] | unique | length) == 5
    and any(.cases[]; .case_id == "normal_admit_defer_mix" and .expected.required_action == "preserve_urgent_rch_slack")
    and any(.cases[]; .case_id == "degraded_safe_mode" and .expected.decision == "safe_mode" and .expected.required_action == "refresh_evidence")
    and any(.cases[]; .case_id == "fail_closed_contaminated_evidence" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-RECOMMEND-LOCAL-FALLBACK")
    and any(.cases[]; .case_id == "human_review_conflict" and .expected.required_action == "require_human_review")
    and any(.cases[]; .case_id == "operator_dashboard_projection" and .expected.required_dashboard_card_id == "brownout_state")
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-recommendation-bundle-contract.v1"
    and .bead_id == "bd-8e5cw"
    and .depends_on == ["bd-knanr"]
    and .script == "scripts/swarm_autopilot_recommendation_bundle.sh"
    and .smoke_script == "scripts/e2e/swarm_autopilot_recommendation_bundle_smoke.sh"
    and .docs == "docs/SWARM_AUTOPILOT_RECOMMENDATION_BUNDLE.md"
    and .fixture_bundle == "scripts/testdata/swarm_autopilot_recommendation_bundle/cases.json"
    and .bundle_schema_version == "franken-engine.swarm-autopilot-recommendation-bundle.v1"
    and .dashboard_projection_schema_version == "franken-engine.swarm-autopilot-dashboard-projection.v1"
    and ((["admit_lane","defer_lane","preserve_urgent_rch_slack","cool_proof_cache","rebalance_fair_share","refresh_evidence","require_human_review"] - .recommendation_actions) | length) == 0
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'The bundle is advisory only and proof only.' "$docs_path" \
    && grep -Fq 'Safe mode defers nonurgent admissions until telemetry and coordination evidence recover.' "$docs_path" \
    && grep -Fq 'Local fallback contamination fails closed.' "$docs_path" \
    && grep -Fq 'Human-review conflicts stay advisory and never auto-mutate beads, workers, or reservations.' "$docs_path" \
    && grep -Fq 'The dashboard projection preserves decision, overall state, top action, and evidence freshness.' "$docs_path"
}

materialize_case() {
  local case_id="$1"
  local case_dir="$2"
  jq --arg case_id "$case_id" '
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | {
        operator_intent_policy_json: ($root.base_operator_intent_policy_json * ($case.overrides.operator_intent_policy_json // {})),
        brownout_forecaster_json: ($root.base_brownout_forecaster_json * ($case.overrides.brownout_forecaster_json // {})),
        resource_lease_plan_json: ($root.base_resource_lease_plan_json * ($case.overrides.resource_lease_plan_json // {})),
        resource_scarcity_receipts_json: ($root.base_resource_scarcity_receipts_json * ($case.overrides.resource_scarcity_receipts_json // {})),
        control_plane_context_json: ($root.base_control_plane_context_json * ($case.overrides.control_plane_context_json // {}))
      }
  ' "$fixtures_path" >"${case_dir}/materialized_inputs.json"

  jq '.operator_intent_policy_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/operator_intent_policy.json"
  jq '.brownout_forecaster_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/brownout_forecaster.json"
  jq '.resource_lease_plan_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/resource_lease_plan.json"
  jq '.resource_scarcity_receipts_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/resource_scarcity_receipts.json"
  jq '.control_plane_context_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/control_plane_context.json"
}

validate_required_artifacts() {
  local case_dir="$1"
  local artifact
  for artifact in \
    swarm_autopilot_recommendation_bundle.json \
    swarm_autopilot_dashboard_projection.json \
    events.jsonl \
    commands.txt \
    report.md; do
    if [[ ! -s "${case_dir}/${artifact}" ]]; then
      record_failure "${case_dir} missing ${artifact}"
    fi
  done
}

validate_outputs() {
  local output_case_dir="$1"
  local case_id="$2"
  local expected_json="$3"
  local bundle_json="${output_case_dir}/swarm_autopilot_recommendation_bundle.json"
  local dashboard_json="${output_case_dir}/swarm_autopilot_dashboard_projection.json"
  local required_action required_error required_dashboard_card expected_dashboard_value expected_overall_state expected_top_action

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-recommendation-bundle.v1"
    and .decision == $expected[0].decision
    and (.recommendation_bundle_id | startswith("recommendation-bundle-"))
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and (.artifact_paths.bundle_json | length > 0)
    and (.artifact_paths.dashboard_projection_json | length > 0)
    and (.recommendations | length) > 0
    and all(.recommendations[];
      (.recommendation_id | length > 0)
      and (.priority | type == "number")
      and (.action | length > 0)
      and (.summary | length > 0)
      and (.deterministic_decision_id | length > 0)
      and ((.reason_codes | length) > 0)
      and ((.evidence_paths | length) > 0)
      and (.rollback_command | length > 0)
      and (.remediation_command | length > 0)
    )
  ' "$bundle_json" >/dev/null || record_failure "${case_id} bundle shape mismatch"

  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-dashboard-projection.v1"
    and (.dashboard_projection_id | startswith("dashboard-projection-"))
    and ((.summary_cards | length) >= 4)
    and (.top_action.action | length > 0)
    and (.top_recommendations | length) > 0
  ' "$dashboard_json" >/dev/null || record_failure "${case_id} dashboard projection shape mismatch"

  required_error="$(jq -r '.required_error_code // ""' "$expected_json")"
  if [[ -n "$required_error" ]]; then
    jq -e --arg required_error "$required_error" '.fail_closed_reasons | map(.code) | index($required_error) != null' "$bundle_json" >/dev/null \
      || record_failure "${case_id} missing required error code ${required_error}"
  fi

  required_action="$(jq -r '.required_action // ""' "$expected_json")"
  if [[ -n "$required_action" ]]; then
    jq -e --arg required_action "$required_action" '.recommendations | any(.action == $required_action)' "$bundle_json" >/dev/null \
      || record_failure "${case_id} missing required action ${required_action}"
  fi

  expected_overall_state="$(jq -r '.expected_overall_state // ""' "$expected_json")"
  if [[ -n "$expected_overall_state" ]]; then
    jq -e --arg expected_overall_state "$expected_overall_state" '.summary.overall_state == $expected_overall_state' "$bundle_json" >/dev/null \
      || record_failure "${case_id} unexpected overall state"
  fi

  expected_top_action="$(jq -r '.expected_top_action // ""' "$expected_json")"
  if [[ -n "$expected_top_action" ]]; then
    jq -e --arg expected_top_action "$expected_top_action" '.summary.top_action == $expected_top_action' "$bundle_json" >/dev/null \
      || record_failure "${case_id} unexpected bundle top action"
    jq -e --arg expected_top_action "$expected_top_action" '.top_action.action == $expected_top_action' "$dashboard_json" >/dev/null \
      || record_failure "${case_id} unexpected dashboard top action"
  fi

  required_dashboard_card="$(jq -r '.required_dashboard_card_id // ""' "$expected_json")"
  expected_dashboard_value="$(jq -r '.expected_dashboard_value // ""' "$expected_json")"
  if [[ -n "$required_dashboard_card" ]]; then
    if [[ -n "$expected_dashboard_value" ]]; then
      jq -e --arg card_id "$required_dashboard_card" --arg value "$expected_dashboard_value" '.summary_cards | any(.card_id == $card_id and .value == $value)' "$dashboard_json" >/dev/null \
        || record_failure "${case_id} missing dashboard card ${required_dashboard_card}/${expected_dashboard_value}"
    else
      jq -e --arg card_id "$required_dashboard_card" '.summary_cards | any(.card_id == $card_id)' "$dashboard_json" >/dev/null \
        || record_failure "${case_id} missing dashboard card ${required_dashboard_card}"
    fi
  fi

  grep -Fq './scripts/swarm_autopilot_recommendation_bundle.sh' "${output_case_dir}/commands.txt" \
    || record_failure "${case_id} commands.txt missing bundle command"
}

run_case() {
  local case_id="$1"
  local case_dir="$2"
  local expected_json="${case_dir}/expected.json"
  local output_case_dir="${case_dir}/output"
  local rc

  mkdir -p "$case_dir" "$output_case_dir"
  materialize_case "$case_id" "$case_dir"
  jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected' "$fixtures_path" >"$expected_json"

  set +e
  bash "$bundle_script" \
    --operator-intent-policy-json "${case_dir}/operator_intent_policy.json" \
    --brownout-forecaster-json "${case_dir}/brownout_forecaster.json" \
    --resource-lease-plan-json "${case_dir}/resource_lease_plan.json" \
    --resource-scarcity-receipts-json "${case_dir}/resource_scarcity_receipts.json" \
    --control-plane-context-json "${case_dir}/control_plane_context.json" \
    --source-revision "fixture-${case_id}" \
    --now-epoch-seconds "$fixed_now_epoch_seconds" \
    --stale-after-seconds "$stale_after_seconds" \
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
  trap 'rm -rf "$temp_dir"' RETURN

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
