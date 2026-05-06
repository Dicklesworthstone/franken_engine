#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/swarm_admission_budget_planner.sh"
contract_json="${root_dir}/docs/swarm_admission_budget_planner_contract_v1.json"
dashboard_contract="${root_dir}/docs/swarm_predictive_dashboard_contract_v1.json"

record_pass() {
  printf 'PASS swarm-admission-budget-planner %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-admission-budget-planner %s\n' "$1" >&2
}

write_forecast_fixture() {
  local output_path="$1"
  local scenario="$2"
  local decision="pass"
  local overall_state="normal"
  local brownout_state="nominal"
  local compile_state="normal"
  local disk_state="normal"
  local rch_state="normal"
  local target_state="normal"
  local proof_state="normal"
  local coordination_state="normal"
  local auto_reopen="true"
  local lease_exchange="true"
  local contact_first_count=0
  local contradiction_count=0
  local fail_closed_reasons='[]'
  local blocked_categories='[]'
  local degraded_categories='[]'

  case "$scenario" in
    fair_share)
      ;;
    high_pressure)
      overall_state="brownout"
      brownout_state="brownout"
      compile_state="brownout"
      blocked_categories='["compile_pressure"]'
      ;;
    rch_degraded)
      overall_state="degraded"
      rch_state="degraded"
      degraded_categories='["rch_degradation"]'
      ;;
    disk_pressure)
      overall_state="degraded"
      disk_state="degraded"
      degraded_categories='["disk_memory_pressure"]'
      ;;
    active_owner)
      overall_state="degraded"
      coordination_state="blocked"
      auto_reopen="false"
      lease_exchange="false"
      contradiction_count=1
      blocked_categories='["coordination_pressure"]'
      ;;
    stale_lock)
      overall_state="degraded"
      coordination_state="blocked"
      auto_reopen="false"
      lease_exchange="false"
      contact_first_count=1
      blocked_categories='["coordination_pressure"]'
      ;;
    forecast_unavailable)
      decision="fail_closed"
      overall_state="degraded"
      compile_state="blocked"
      blocked_categories='["compile_pressure"]'
      fail_closed_reasons='[{"kind":"stale_required_telemetry","detail":"predictive telemetry expired"}]'
      ;;
    *)
      record_failure "unknown forecast scenario ${scenario}"
      return 1
      ;;
  esac

  # shellcheck disable=SC2094
  jq -n \
    --arg output_path "$output_path" \
    --arg decision "$decision" \
    --arg overall_state "$overall_state" \
    --arg brownout_state "$brownout_state" \
    --arg compile_state "$compile_state" \
    --arg disk_state "$disk_state" \
    --arg rch_state "$rch_state" \
    --arg target_state "$target_state" \
    --arg proof_state "$proof_state" \
    --arg coordination_state "$coordination_state" \
    --argjson auto_reopen "$auto_reopen" \
    --argjson lease_exchange "$lease_exchange" \
    --argjson contact_first_count "$contact_first_count" \
    --argjson contradiction_count "$contradiction_count" \
    --argjson fail_closed_reasons "$fail_closed_reasons" \
    --argjson blocked_categories "$blocked_categories" \
    --argjson degraded_categories "$degraded_categories" \
    '
    def risk_level($state):
      if ($state == "blocked" or $state == "brownout") then "high"
      elif $state == "degraded" then "medium"
      else "low"
      end;
    {
      schema_version: "franken-engine.swarm-capacity-forecast.v1",
      decision: $decision,
      confidence_band: "high",
      summary: {
        overall_state: $overall_state,
        brownout_state: $brownout_state,
        snapshot_age_seconds: 30,
        high_cost_command_count: 2,
        deferred_command_count: (if $overall_state == "normal" then 0 else 1 end),
        contact_first_count: $contact_first_count,
        blocked_categories: $blocked_categories,
        degraded_categories: $degraded_categories
      },
      assumptions: [
        "Smoke fixtures are deterministic.",
        "The planner remains fixture-fed."
      ],
      inherited_snapshot_failures: {
        snapshot_decision: (if $decision == "pass" then "pass" else "fail_closed" end),
        missing_required_fields: [],
        stale_inputs: [],
        contradictory_inputs: (if $contradiction_count > 0 then [{kind:"contradictory_owner",detail:"conflicting active owner"}] else [] end),
        non_replayable_artifact_refs: []
      },
      fail_closed_reasons: $fail_closed_reasons,
      resolved_inputs: [],
      forecasts: {
        compile_pressure: {
          state: $compile_state,
          risk_level: risk_level($compile_state),
          confidence_band: "high",
          confidence_score_millionths: 900000,
          assumptions: [],
          evidence: {},
          recommended_action: "narrow proofs"
        },
        disk_memory_pressure: {
          state: $disk_state,
          risk_level: risk_level($disk_state),
          confidence_band: "high",
          confidence_score_millionths: 900000,
          assumptions: [],
          evidence: {},
          recommended_action: "reduce pressure"
        },
        rch_degradation: {
          state: $rch_state,
          risk_level: risk_level($rch_state),
          confidence_band: "high",
          confidence_score_millionths: 900000,
          assumptions: [],
          evidence: {},
          recommended_action: "keep remote proofs narrow"
        },
        target_dir_heat: {
          state: $target_state,
          risk_level: risk_level($target_state),
          confidence_band: "high",
          confidence_score_millionths: 900000,
          assumptions: [],
          evidence: {},
          recommended_action: "rotate target dir"
        },
        proof_availability: {
          state: $proof_state,
          risk_level: risk_level($proof_state),
          confidence_band: "high",
          confidence_score_millionths: 900000,
          assumptions: [],
          evidence: {},
          recommended_action: "reuse proofs carefully"
        },
        coordination_pressure: {
          state: $coordination_state,
          risk_level: risk_level($coordination_state),
          confidence_band: "high",
          confidence_score_millionths: 900000,
          assumptions: [],
          evidence: {
            contradiction_count: $contradiction_count,
            reservation_count: 1,
            contact_first_count: $contact_first_count,
            safe_to_reopen_count: 0
          },
          auto_reopen_allowed: $auto_reopen,
          lease_exchange_allowed: $lease_exchange,
          recommended_action: "contact owner before widening writes"
        }
      },
      artifact_paths: {
        swarm_capacity_forecast_json: $output_path,
        report_md: "forecast_report.md"
      }
    }' >"$output_path"
}

write_requests_fixture() {
  local output_path="$1"
  local scenario="$2"

  case "$scenario" in
    fair_share)
      jq -n '
        {
          schema_version:"franken-engine.swarm-admission-request-set.v1",
          requests:[
            {
              request_id:"alpha-p1",
              agent_id:"AgentAlpha",
              bead_id:"bd-alpha-p1",
              bead_priority:1,
              requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_alpha_p1 cargo test -p frankenengine-engine --test alpha_p1 -- --nocapture",
              heavy_rust:true,
              proof_obligation:true,
              speculative:false,
              planned_write_paths:["scripts/swarm_admission_budget_planner.sh"]
            },
            {
              request_id:"alpha-p2",
              agent_id:"AgentAlpha",
              bead_id:"bd-alpha-p2",
              bead_priority:2,
              requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_alpha_p2 cargo test -p frankenengine-engine --test alpha_p2 -- --nocapture",
              heavy_rust:true,
              proof_obligation:true,
              speculative:false,
              planned_write_paths:["docs/SWARM_ADMISSION_BUDGET_PLANNER.md"]
            },
            {
              request_id:"alpha-p3-spec",
              agent_id:"AgentAlpha",
              bead_id:"bd-alpha-p3",
              bead_priority:3,
              requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_alpha_p3 cargo test -p frankenengine-engine --test alpha_p3 -- --nocapture",
              heavy_rust:true,
              proof_obligation:false,
              speculative:true,
              planned_write_paths:["docs/swarm_predictive_dashboard_contract_v1.json"]
            },
            {
              request_id:"beta-p2",
              agent_id:"AgentBeta",
              bead_id:"bd-beta-p2",
              bead_priority:2,
              requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_beta_p2 cargo test -p frankenengine-engine --test beta_p2 -- --nocapture",
              heavy_rust:true,
              proof_obligation:true,
              speculative:false,
              planned_write_paths:["docs/swarm_admission_budget_planner_contract_v1.json"]
            }
          ]
        }' >"$output_path"
      ;;
    high_pressure)
      jq -n '
        {
          schema_version:"franken-engine.swarm-admission-request-set.v1",
          requests:[
            {
              request_id:"p1-heavy",
              agent_id:"AgentAlpha",
              bead_id:"bd-p1",
              bead_priority:1,
              requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_p1 cargo test -p frankenengine-engine --test p1 -- --nocapture",
              heavy_rust:true,
              proof_obligation:true,
              speculative:false
            },
            {
              request_id:"p2-heavy",
              agent_id:"AgentBeta",
              bead_id:"bd-p2",
              bead_priority:2,
              requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_p2 cargo test -p frankenengine-engine --test p2 -- --nocapture",
              heavy_rust:true,
              proof_obligation:true,
              speculative:false
            },
            {
              request_id:"p3-spec",
              agent_id:"AgentGamma",
              bead_id:"bd-p3",
              bead_priority:3,
              requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_p3 cargo test -p frankenengine-engine --test p3 -- --nocapture",
              heavy_rust:true,
              proof_obligation:false,
              speculative:true
            }
          ]
        }' >"$output_path"
      ;;
    rch_degraded)
      jq -n '
        {
          schema_version:"franken-engine.swarm-admission-request-set.v1",
          requests:[
            {
              request_id:"rch-p1",
              agent_id:"AgentAlpha",
              bead_id:"bd-rch-p1",
              bead_priority:1,
              requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_rch_p1 cargo test -p frankenengine-engine --test rch_p1 -- --nocapture",
              heavy_rust:true,
              proof_obligation:true
            },
            {
              request_id:"rch-p2",
              agent_id:"AgentBeta",
              bead_id:"bd-rch-p2",
              bead_priority:2,
              requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_rch_p2 cargo test -p frankenengine-engine --test rch_p2 -- --nocapture",
              heavy_rust:true,
              proof_obligation:true
            },
            {
              request_id:"rch-p3-spec",
              agent_id:"AgentGamma",
              bead_id:"bd-rch-p3",
              bead_priority:3,
              requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_rch_p3 cargo test -p frankenengine-engine --test rch_p3 -- --nocapture",
              heavy_rust:true,
              proof_obligation:false,
              speculative:true
            }
          ]
        }' >"$output_path"
      ;;
    disk_pressure)
      jq -n '
        {
          schema_version:"franken-engine.swarm-admission-request-set.v1",
          requests:[
            {
              request_id:"disk-p1",
              agent_id:"AgentAlpha",
              bead_id:"bd-disk-p1",
              bead_priority:1,
              requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_disk_p1 cargo test -p frankenengine-engine --test disk_p1 -- --nocapture",
              heavy_rust:true,
              proof_obligation:true
            },
            {
              request_id:"disk-p3",
              agent_id:"AgentBeta",
              bead_id:"bd-disk-p3",
              bead_priority:3,
              requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_disk_p3 cargo test -p frankenengine-engine --test disk_p3 -- --nocapture",
              heavy_rust:true,
              proof_obligation:false,
              speculative:true
            }
          ]
        }' >"$output_path"
      ;;
    active_owner)
      jq -n '
        {
          schema_version:"franken-engine.swarm-admission-request-set.v1",
          requests:[
            {
              request_id:"owner-write",
              agent_id:"AgentAlpha",
              bead_id:"bd-owner-write",
              bead_priority:2,
              requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_owner cargo test -p frankenengine-engine --test owner_write -- --nocapture",
              heavy_rust:true,
              proof_obligation:true,
              requires_ownership_confirmation:true,
              planned_write_paths:["scripts/swarm_admission_budget_planner.sh"]
            },
            {
              request_id:"owner-readonly",
              agent_id:"AgentBeta",
              bead_id:"bd-owner-readonly",
              bead_priority:1,
              requested_command:"bash -n scripts/swarm_admission_budget_planner.sh",
              heavy_rust:false,
              docs_only:true,
              proof_obligation:true,
              planned_write_paths:[]
            }
          ]
        }' >"$output_path"
      ;;
    stale_lock)
      jq -n '
        {
          schema_version:"franken-engine.swarm-admission-request-set.v1",
          requests:[
            {
              request_id:"reopen-write",
              agent_id:"AgentAlpha",
              bead_id:"bd-reopen-write",
              bead_priority:2,
              requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_reopen cargo test -p frankenengine-engine --test reopen_write -- --nocapture",
              heavy_rust:true,
              proof_obligation:false,
              speculative:true,
              requires_ownership_confirmation:true,
              planned_write_paths:["docs/SWARM_ADMISSION_BUDGET_PLANNER.md"]
            },
            {
              request_id:"stale-p1",
              agent_id:"AgentBeta",
              bead_id:"bd-stale-p1",
              bead_priority:1,
              requested_command:"bash -n scripts/swarm_admission_budget_planner.sh",
              heavy_rust:false,
              docs_only:true,
              proof_obligation:true
            }
          ]
        }' >"$output_path"
      ;;
    forecast_unavailable)
      jq -n '
        {
          schema_version:"franken-engine.swarm-admission-request-set.v1",
          requests:[
            {
              request_id:"safe-p1",
              agent_id:"AgentAlpha",
              bead_id:"bd-safe-p1",
              bead_priority:1,
              requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_safe cargo test -p frankenengine-engine --test safe_p1 -- --nocapture",
              heavy_rust:true,
              proof_obligation:true
            },
            {
              request_id:"safe-p3",
              agent_id:"AgentBeta",
              bead_id:"bd-safe-p3",
              bead_priority:3,
              requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_safe_p3 cargo test -p frankenengine-engine --test safe_p3 -- --nocapture",
              heavy_rust:true,
              proof_obligation:false,
              speculative:true
            }
          ]
        }' >"$output_path"
      ;;
    *)
      record_failure "unknown request scenario ${scenario}"
      return 1
      ;;
  esac
}

write_optional_inputs() {
  local fixture_dir="$1"
  local scenario="$2"
  local collision_risk="none"
  local conflicting_agents='[]'
  local resource_decision="admit"
  local resource_findings='[]'
  local lease_decision="admit"
  local lease_reason="lease admitted"

  case "$scenario" in
    disk_pressure)
      resource_decision="defer"
      resource_findings='[{"signal":"disk_available_bytes","message":"disk pressure"}]'
      lease_decision="defer"
      lease_reason="requested target directory conflicts with active reservation or dirty state"
      ;;
    active_owner)
      collision_risk="reserved_overlap"
      conflicting_agents='["ScarletOwl"]'
      ;;
    stale_lock)
      collision_risk="dirty_overlap"
      ;;
  esac

  jq -n \
    --arg collision_risk "$collision_risk" \
    --argjson conflicting_agents "$conflicting_agents" \
    '{
      schema_version:"franken-engine.swarm-validation-plan.v1",
      decision:"admit",
      collision_risk:$collision_risk,
      conflicting_agents:$conflicting_agents,
      safe_alternatives:["docs/SWARM_ADMISSION_BUDGET_PLANNER.md"],
      reservation_recommendations:[],
      commands:[
        {
          command_id:"bash-n-budget-planner",
          display:"bash -n scripts/swarm_admission_budget_planner.sh",
          predicted_cost:{
            schema_version:"franken-engine.swarm-validation-predicted-cost.v1",
            state:"static",
            cost_class:"low"
          },
          risk_flags:[]
        }
      ]
    }' >"${fixture_dir}/validation_plan.json"

  jq -n \
    --arg decision "$resource_decision" \
    --argjson findings "$resource_findings" \
    '{
      schema_version:"franken-engine.swarm-resource-decision.v1",
      decision:$decision,
      findings:$findings
    }' >"${fixture_dir}/resource_decision.json"

  jq -n \
    --arg lease_decision "$lease_decision" \
    --arg lease_reason "$lease_reason" \
    '{
      schema_version:"franken-engine.swarm-resource-lease-plan.v1",
      lease_decision:$lease_decision,
      reason:$lease_reason,
      safe_alternatives:["Use a narrower validation surface first."],
      artifact_paths:{resource_lease_plan_json:"resource_lease_plan.json"}
    }' >"${fixture_dir}/resource_lease_plan.json"
}

run_check() {
  local scope_file

  bash -n "$planner"
  bash -n "${BASH_SOURCE[0]}"
  shellcheck -x "$planner" "${BASH_SOURCE[0]}"
  jq empty "$contract_json" "$dashboard_contract" >/dev/null
  jq -e '.admission_budget_planner.plan_schema_version == "franken-engine.swarm-admission-budget-plan.v1"' "$dashboard_contract" >/dev/null
  jq -e '(.fixture_cases | index("fair_share") != null) and (.fixture_cases | index("active_owner") != null) and (.fixture_cases | index("forecast_unavailable_safe_mode") != null)' "$contract_json" >/dev/null

  scope_file="$(mktemp "${TMPDIR:-/tmp}/swarm-admission-budget-planner-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/swarm_admission_budget_planner.sh" \
    "scripts/e2e/swarm_admission_budget_planner_smoke.sh" \
    "docs/SWARM_ADMISSION_BUDGET_PLANNER.md" \
    "docs/swarm_admission_budget_planner_contract_v1.json" \
    "docs/swarm_predictive_dashboard_contract_v1.json" \
    "docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/swarm-admission-budget-planner-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "syntax, shellcheck, contracts, and rch policy"
}

run_case() {
  local case_name="$1"
  local expected_exit="$2"
  local expected_jq="$3"
  local tmp_root fixture_dir output_dir exit_code

  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-admission-budget-planner-${case_name}.XXXXXX")"
  fixture_dir="${tmp_root}/fixtures"
  output_dir="${tmp_root}/out"
  mkdir -p "$fixture_dir" "$output_dir"

  write_forecast_fixture "${fixture_dir}/capacity_forecast.json" "$case_name"
  write_requests_fixture "${fixture_dir}/admission_requests.json" "$case_name"
  write_optional_inputs "$fixture_dir" "$case_name"

  set +e
  bash "${planner}" \
    --capacity-forecast-json "${fixture_dir}/capacity_forecast.json" \
    --admission-requests-json "${fixture_dir}/admission_requests.json" \
    --validation-plan-json "${fixture_dir}/validation_plan.json" \
    --resource-decision-json "${fixture_dir}/resource_decision.json" \
    --resource-lease-plan-json "${fixture_dir}/resource_lease_plan.json" \
    --output-dir "$output_dir" >/dev/null
  exit_code=$?
  set -e
  if [[ "$exit_code" -ne "$expected_exit" ]]; then
    record_failure "${case_name} expected exit ${expected_exit}, got ${exit_code}"
    return 1
  fi

  jq -e "$expected_jq" "${output_dir}/swarm_admission_budget_plan.json" >/dev/null
  record_pass "$case_name"
}

run_selftest() {
  run_check
  run_case "fair_share" 0 '
    .decision == "admit_narrow"
    and .budget_profile == "normal"
    and any(.priority_budgets[]?; .priority_class == "P3" and .decisions.defer == 1)
  '
  run_case "high_pressure" 0 '
    .decision == "admit_narrow"
    and .budget_profile == "high_pressure"
    and (.recommendations | map(select(.priority_class == "P1")) | first | .decision) == "admit_narrow"
    and (.recommendations | map(select(.priority_class == "P3")) | first | .decision) == "defer"
  '
  run_case "rch_degraded" 0 '
    .decision == "admit_narrow"
    and .budget_profile == "degraded"
    and any(.recommendations[]?; (.heavy_rust == true) and (.decision == "admit_narrow") and (.reasons | index("rch_degradation_requires_narrow_scope") != null))
  '
  run_case "disk_pressure" 0 '
    .decision == "admit_narrow"
    and any(.recommendations[]?; (.request_id == "disk-p1") and (.decision == "admit_narrow"))
    and any(.recommendations[]?; (.request_id == "disk-p3") and (.decision == "defer"))
  '
  run_case "active_owner" 0 '
    .decision == "admit_narrow"
    and any(.recommendations[]?; (.request_id == "owner-write") and (.decision == "defer") and (.reasons | index("active_owner_manual_confirmation_required") != null))
    and any(.recommendations[]?; (.request_id == "owner-readonly") and (.decision == "admit_narrow"))
  '
  run_case "stale_lock" 0 '
    .decision == "admit_narrow"
    and any(.recommendations[]?; (.request_id == "reopen-write") and (.decision == "defer") and (.reasons | index("stale_lock_contact_first") != null))
  '
  run_case "forecast_unavailable" 0 '
    .decision == "admit_narrow"
    and .budget_profile == "safe_mode"
    and (.warnings | index("capacity_forecast_safe_mode_active") != null)
    and any(.recommendations[]?; (.priority_class == "P3") and (.decision == "defer"))
  '
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    usage() {
      printf 'Usage: %s [check|selftest]\n' "${BASH_SOURCE[0]}" >&2
    }
    usage
    exit 64
    ;;
esac
