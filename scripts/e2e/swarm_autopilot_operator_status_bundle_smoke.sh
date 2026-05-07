#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
bundle_script="${root_dir}/scripts/swarm_autopilot_operator_status_bundle.sh"
fixtures_path="${SWARM_AUTOPILOT_OPERATOR_STATUS_FIXTURES:-${root_dir}/scripts/testdata/swarm_autopilot_operator_status/cases.json}"
contract_path="${root_dir}/docs/swarm_autopilot_operator_status_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_AUTOPILOT_OPERATOR_STATUS.md"
mode="${1:-check}"
failures=0
fixed_now_epoch_seconds="1778123600"
stale_after_seconds="1800"

record_pass() {
  printf 'PASS swarm-autopilot-operator-status %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-operator-status %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_operator_status_bundle_smoke.sh [check|selftest]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-operator-status-fixtures.v1"
    and .base_operator_intent_policy_json.schema_version == "franken-engine.swarm-autopilot-operator-intent-policy.v1"
    and .base_brownout_forecaster_json.schema_version == "franken-engine.swarm-autopilot-brownout-forecaster.v1"
    and .base_resource_lease_plan_json.schema_version == "franken-engine.swarm-autopilot-resource-lease-plan.v1"
    and .base_resource_scarcity_receipts_json.schema_version == "franken-engine.swarm-autopilot-resource-scarcity-receipts.v1"
    and .base_recommendation_bundle_json.schema_version == "franken-engine.swarm-autopilot-recommendation-bundle.v1"
    and .base_dashboard_projection_json.schema_version == "franken-engine.swarm-autopilot-dashboard-projection.v1"
    and .base_hindsight_chaos_scenarios_json.schema_version == "franken-engine.swarm-autopilot-hindsight-chaos-scenarios.v1"
    and .base_hindsight_chaos_replay_index_json.schema_version == "franken-engine.swarm-autopilot-hindsight-chaos-replay-index.v1"
    and (.cases | length) == 5
    and any(.cases[]; .case_id == "healthy_autopilot")
    and any(.cases[]; .case_id == "degraded_forecast")
    and any(.cases[]; .case_id == "fail_closed_policy_conflict")
    and any(.cases[]; .case_id == "safe_mode_recommendation")
    and any(.cases[]; .case_id == "frankentui_panel_projection")
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-operator-status-contract.v1"
    and .bead_id == "bd-bhddc"
    and ((["bd-8e5cw","bd-09g6k"] - .depends_on) | length) == 0
    and .script == "scripts/swarm_autopilot_operator_status_bundle.sh"
    and .smoke_script == "scripts/e2e/swarm_autopilot_operator_status_bundle_smoke.sh"
    and .docs == "docs/SWARM_AUTOPILOT_OPERATOR_STATUS.md"
    and .fixture_bundle == "scripts/testdata/swarm_autopilot_operator_status/cases.json"
    and .operator_status_schema_version == "franken-engine.swarm-autopilot-operator-status.v1"
    and .panel_bundle_schema_version == "franken-engine.swarm-autopilot-frankentui-panels.v1"
    and .renderer_contract.provider == "/dp/frankentui"
    and .renderer_contract.local_renderer == false
    and .renderer_contract.no_local_tui_runtime == true
    and ((["forecast_state","policy_state","lease_scarcity","recommendation_rank","safe_mode_state","required_operator_action","chaos_replay_readiness"] - .required_panels) | length) == 0
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.local_renderer == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'The operator-status producer is advisory only and proof only.' "$docs_path" \
    && grep -Fq "The future rich renderer provider is \`/dp/frankentui\`; no local renderer ships in \`franken_engine\`." "$docs_path" \
    && grep -Fq 'Hidden panel state or missing evidence links fail closed.' "$docs_path" \
    && grep -Fq 'Fail-closed policy conflicts stay visibly fail-closed in both operator status and panel projection.' "$docs_path" \
    && grep -Fq 'Safe-mode recommendations stay visible as conservative operator guidance and do not claim live mutation authority.' "$docs_path"
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
        recommendation_bundle_json: ($root.base_recommendation_bundle_json * ($case.overrides.recommendation_bundle_json // {})),
        dashboard_projection_json: ($root.base_dashboard_projection_json * ($case.overrides.dashboard_projection_json // {})),
        hindsight_chaos_scenarios_json: ($root.base_hindsight_chaos_scenarios_json * ($case.overrides.hindsight_chaos_scenarios_json // {})),
        hindsight_chaos_replay_index_json: ($root.base_hindsight_chaos_replay_index_json * ($case.overrides.hindsight_chaos_replay_index_json // {}))
      }
  ' "$fixtures_path" >"${case_dir}/materialized_inputs.json"

  jq '.operator_intent_policy_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/operator_intent_policy.json"
  jq '.brownout_forecaster_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/brownout_forecaster.json"
  jq '.resource_lease_plan_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/resource_lease_plan.json"
  jq '.resource_scarcity_receipts_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/resource_scarcity_receipts.json"
  jq '.recommendation_bundle_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/recommendation_bundle.json"
  jq '.dashboard_projection_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/dashboard_projection.json"
  jq '.hindsight_chaos_scenarios_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/hindsight_chaos_scenarios.json"
  jq '.hindsight_chaos_replay_index_json' "${case_dir}/materialized_inputs.json" >"${case_dir}/hindsight_chaos_replay_index.json"
}

validate_required_artifacts() {
  local case_dir="$1"
  local artifact
  for artifact in \
    swarm_autopilot_operator_status.json \
    swarm_autopilot_frankentui_panels.json \
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
  local status_json="${output_case_dir}/swarm_autopilot_operator_status.json"
  local panels_json="${output_case_dir}/swarm_autopilot_frankentui_panels.json"
  local required_panel_id required_panel_state required_error_code expected_top_action

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-operator-status.v1"
    and .decision == $expected[0].decision
    and (.operator_status_id | startswith("autopilot-operator-status-"))
    and .renderer_contract.provider == "/dp/frankentui"
    and .renderer_contract.local_renderer == false
    and .renderer_contract.no_local_tui_runtime == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.local_renderer == false
    and ((.sections | keys | length) == 7)
  ' "$status_json" >/dev/null || record_failure "${case_id} status shape mismatch"

  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-frankentui-panels.v1"
    and (.panel_bundle_id | startswith("autopilot-panels-"))
    and .renderer_contract.provider == "/dp/frankentui"
    and .renderer_contract.local_renderer == false
    and .renderer_contract.no_local_tui_runtime == true
    and .status_bar.summary.panel_count == 7
    and ((.panels | length) == 7)
    and all(.panels[];
      (.panel_id | length > 0)
      and (.display_state | length > 0)
      and (.semantic_theme_token | length > 0)
      and (.focus_order | type == "number")
      and (.aria_label | length > 0)
      and (.supports_tiny_layout == true)
      and ((.visible_reasons | type) == "array")
    )
  ' "$panels_json" >/dev/null || record_failure "${case_id} panel bundle shape mismatch"

  required_error_code="$(jq -r '.required_error_code // ""' "$expected_json")"
  if [[ -n "$required_error_code" ]]; then
    jq -e --arg required_error_code "$required_error_code" '.fail_closed_reasons | map(.code) | index($required_error_code) != null' "$status_json" >/dev/null \
      || record_failure "${case_id} missing required error code ${required_error_code}"
  fi

  required_panel_id="$(jq -r '.required_panel_id // ""' "$expected_json")"
  required_panel_state="$(jq -r '.required_panel_state // ""' "$expected_json")"
  if [[ -n "$required_panel_id" && -n "$required_panel_state" ]]; then
    jq -e --arg required_panel_id "$required_panel_id" --arg required_panel_state "$required_panel_state" '.panels | any(.panel_id == $required_panel_id and .display_state == $required_panel_state)' "$panels_json" >/dev/null \
      || record_failure "${case_id} missing required panel state ${required_panel_id}/${required_panel_state}"
  fi

  expected_top_action="$(jq -r '.expected_top_action // ""' "$expected_json")"
  if [[ -n "$expected_top_action" ]]; then
    jq -e --arg expected_top_action "$expected_top_action" '.summary.top_action == $expected_top_action' "$status_json" >/dev/null \
      || record_failure "${case_id} unexpected status top action"
    jq -e --arg expected_top_action "$expected_top_action" '.status_bar.summary.top_action == $expected_top_action' "$panels_json" >/dev/null \
      || record_failure "${case_id} unexpected panel top action"
  fi

  grep -Fq './scripts/swarm_autopilot_operator_status_bundle.sh' "${output_case_dir}/commands.txt" \
    || record_failure "${case_id} commands.txt missing operator-status command"
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
    --recommendation-bundle-json "${case_dir}/recommendation_bundle.json" \
    --dashboard-projection-json "${case_dir}/dashboard_projection.json" \
    --hindsight-chaos-scenarios-json "${case_dir}/hindsight_chaos_scenarios.json" \
    --hindsight-chaos-replay-index-json "${case_dir}/hindsight_chaos_replay_index.json" \
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
