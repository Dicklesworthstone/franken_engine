#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
reporter="${root_dir}/scripts/swarm_operator_status_report.sh"
golden_dir="${root_dir}/scripts/testdata/goldens"
contract_doc="${root_dir}/docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md"
contract_json="${root_dir}/docs/swarm_predictive_dashboard_contract_v1.json"

record_pass() {
  printf 'PASS swarm-operator-status %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-operator-status %s\n' "$1" >&2
}

canonicalize_status() {
  local status_path="$1"
  local tmp_root="$2"

  jq --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "object" then
        with_entries(.value |= scrub)
      elif type == "array" then
        map(scrub)
      elif type == "string" then
        split($tmp_root) | join("[SMOKE_ROOT]")
      else
        .
      end;
    scrub
    | del(.artifact_paths)
  ' "$status_path"
}

compare_case_golden() {
  local case_name="$1"
  local actual_path="$2"
  local golden_path="$3"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    cp "$actual_path" "$golden_path"
    record_pass "updated golden ${case_name}"
    return 0
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "missing golden ${golden_path}"
    return 1
  fi

  if ! diff -u "$golden_path" "$actual_path"; then
    record_failure "golden drift for ${case_name}; set UPDATE_GOLDENS=1 only after reviewing the diff"
    return 1
  fi

  record_pass "golden matches ${case_name}"
}

write_healthy_fixtures() {
  local fixture_dir="$1"

  jq -n '[{id:"bd-p03vs", title:"Typed proof-evidence index", priority:1, status:"open", assignee:null}]' >"${fixture_dir}/ready.json"
  jq -n '[{id:"bd-0ub12", title:"Semantic dark matter scoring", priority:1, status:"in_progress", assignee:"CyanOak"}]' >"${fixture_dir}/in_progress.json"
  jq -n '{plan:{tracks:[{track_id:"track-B", items:[{id:"bd-p03vs", title:"Typed proof-evidence index", priority:1, status:"open"}]}]}}' >"${fixture_dir}/bv_plan.json"
  jq -n '[{path:"scripts/swarm_operator_status_report.sh", holder:"SandyThrush", exclusive:true}]' >"${fixture_dir}/reservations.json"
  jq -n '{decision:"admit", findings:[]}' >"${fixture_dir}/resource_decision.json"
  jq -n '{
    decision:"admit",
    collision_risk:"none",
    risk_flags:[],
    conflicting_agents:[],
    safe_alternatives:["scripts/swarm_operator_status_report.sh"],
    commands:[{
      command_id:"script-check",
      display:"bash -n scripts/swarm_operator_status_report.sh",
      command_kind:"shell_syntax",
      predicted_cost:{
        schema_version:"franken-engine.swarm-validation-predicted-cost.v1",
        state:"static",
        cost_class:"low",
        sample_count:0,
        elapsed_ms_p50:0,
        elapsed_ms_max:0,
        compiled_target_count_max:0,
        linked_target_count_max:0
      },
      risk_flags:[],
      cost_evidence:{status:"not_required", matched_rows:0, fresh_rows:0, stale_rows:0}
    }],
    omitted_commands:[],
    proof_cost_budgets:[]
  }' >"${fixture_dir}/validation_plan.json"
  jq -n '{queries:[{name:"recent_failed_gates", row_count:0},{name:"proof_by_bead", row_count:2}]}' >"${fixture_dir}/proof_index.json"
  jq -n '[{bead_id:"bd-1onpa", artifact_id:"plan", status:"pass"}]' >"${fixture_dir}/proof_outcomes.json"
  jq -n '[]' >"${fixture_dir}/stale_evidence.json"
  jq -n '[]' >"${fixture_dir}/dirty_files.json"
  jq -n '{collision_risk:"none", conflicting_agents:[], safe_alternatives:["scripts/swarm_operator_status_report.sh"], reservation_recommendations:[], conflicts:{reservations:[], dirty:[], in_progress:[]}}' >"${fixture_dir}/collision_receipt.json"
  jq -n '{schema_version:"franken-engine.proof-freshness-decay-report.v1", proof_artifact_id:"proof-current", freshness_state:"fresh", reusable:true, reason:"proof artifact is reusable", recommended_next_action:"Reuse the proof artifact.", covered_paths:["scripts/swarm_operator_status_report.sh"], changed_paths:[]}' >"${fixture_dir}/proof_freshness.json"
  jq -n '{status:"not_provided", failure_kind:"none", retry_safety:"not_required", recommended_next_action:"No rch incident packet was provided."}' >"${fixture_dir}/rch_incident_packet.json"
}

write_degraded_fixtures() {
  local fixture_dir="$1"

  jq -n '[{id:"bd-4kwo8", title:"Dark matter board receipts", priority:1, status:"open", assignee:null}]' >"${fixture_dir}/ready.json"
  jq -n '[{id:"bd-0ub12", title:"Semantic dark matter scoring", priority:1, status:"in_progress", assignee:"CyanOak"}]' >"${fixture_dir}/in_progress.json"
  jq -n '{plan:{tracks:[{track_id:"track-A", items:[{id:"bd-blocked", title:"Blocked dependent bead", priority:1, status:"blocked"}]}]}}' >"${fixture_dir}/bv_plan.json"
  jq -n '[{path:"crates/franken-engine/src/semantic_dark_matter_engine.rs", holder:"CyanOak", exclusive:true}]' >"${fixture_dir}/reservations.json"
  jq -n '{decision:"defer", findings:[{signal:"active_compile_count", decision:"defer"}]}' >"${fixture_dir}/resource_decision.json"
  jq -n '{decision:"fail_closed", collision_risk:"none", risk_flags:[], commands:[], omitted_commands:[{kind:"unknown_path_mapping", path:"unknown/path.rs"}], proof_cost_budgets:[]}' >"${fixture_dir}/validation_plan.json"
  jq -n '{queries:[]}' >"${fixture_dir}/proof_index.json"
  jq -n '[{bead_id:"bd-0ub12", artifact_id:"semantic-proof", status:"blocked"}]' >"${fixture_dir}/proof_outcomes.json"
  jq -n '[{artifact_id:"old-proof", stale:true, age_hours:72}]' >"${fixture_dir}/stale_evidence.json"
  jq -n '[{path:"crates/franken-engine/src/semantic_dark_matter_engine.rs", reserved:true, overlaps_ready:true}]' >"${fixture_dir}/dirty_files.json"
  jq -n '{collision_risk:"none", conflicting_agents:[], safe_alternatives:[], reservation_recommendations:[], conflicts:{reservations:[], dirty:[], in_progress:[]}}' >"${fixture_dir}/collision_receipt.json"
  jq -n '{schema_version:"franken-engine.proof-freshness-decay-report.v1", proof_artifact_id:"proof-current", freshness_state:"fresh", reusable:true, reason:"proof artifact is reusable", recommended_next_action:"Reuse the proof artifact.", covered_paths:["crates/franken-engine/src/semantic_dark_matter_engine.rs"], changed_paths:[]}' >"${fixture_dir}/proof_freshness.json"
  jq -n '{schema_version:"franken-engine.rch-incident-packet.v1", incident_id:"rch-incident-smoke", status:"fail", failure_kind:"worker_timeout", retry_safety:"safe_after_narrowing_or_timeout_adjustment", classification_confidence:"high", worker_id:"worker-smoke", command:"rch exec -- cargo test -p frankenengine-engine --test smoke", target_dir:"/tmp/rch_target_smoke", recommended_next_action:"Retry only after narrowing the command."}' >"${fixture_dir}/rch_incident_packet.json"
}

write_stale_proof_fixtures() {
  local fixture_dir="$1"

  write_healthy_fixtures "$fixture_dir"
  jq -n '{schema_version:"franken-engine.proof-freshness-decay-report.v1", proof_artifact_id:"proof-stale", artifact_path:"artifacts/proof/current/manifest.json", freshness_state:"stale_by_time", reusable:false, reason:"current time exceeds the artifact freshness deadline", recommended_next_action:"Refresh the proof artifact before publishing or relying on the claim.", covered_paths:["scripts/swarm_operator_status_report.sh"], changed_paths:[]}' >"${fixture_dir}/proof_freshness.json"
}

write_high_cost_fixtures() {
  local fixture_dir="$1"

  write_healthy_fixtures "$fixture_dir"
  jq -n '{
    decision:"admit",
    collision_risk:"none",
    risk_flags:["high_cost_history"],
    conflicting_agents:[],
    safe_alternatives:["crates/franken-engine/tests/proof_manifest_golden_artifacts.rs"],
    commands:[{
      command_id:"cargo-test-proof_manifest_golden_artifacts",
      display:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_high_cost cargo test -p frankenengine-engine --test proof_manifest_golden_artifacts",
      command_kind:"rch_cargo_test",
      predicted_cost:{
        schema_version:"franken-engine.swarm-validation-predicted-cost.v1",
        state:"matched",
        cost_class:"high",
        sample_count:3,
        elapsed_ms_p50:450000,
        elapsed_ms_max:900000,
        compiled_target_count_max:12,
        linked_target_count_max:2
      },
      risk_flags:["high_cost_history"],
      cost_evidence:{status:"matched", matched_rows:3, fresh_rows:3, stale_rows:0, source_revisions:["smoke-rev"]}
    }],
    omitted_commands:[],
    proof_cost_budgets:[{
      schema_version:"franken-engine.focused-proof-cost-budget.v1",
      suite:"proof_manifest_golden_artifacts",
      package:"frankenengine-engine",
      max_total_compiled_targets:2,
      max_total_linked_targets:1
    }]
  }' >"${fixture_dir}/validation_plan.json"
}

write_collision_risk_fixtures() {
  local fixture_dir="$1"

  write_healthy_fixtures "$fixture_dir"
  jq -n '[{path:"scripts/swarm_operator_status_report.sh", holder:"CyanOak", exclusive:true}]' >"${fixture_dir}/reservations.json"
  jq -n '{
    decision:"admit_narrow",
    collision_risk:"reserved_overlap",
    risk_flags:[],
    conflicting_agents:["CyanOak"],
    safe_alternatives:["docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md"],
    reservation_recommendations:[{action:"coordinate_reservation_holder", scope:"planned_write_set", reason:"planned write paths overlap active exclusive reservations"}],
    commands:[{
      command_id:"bash-n-dashboard-contract",
      display:"bash -n scripts/swarm_operator_status_report.sh",
      command_kind:"shell_syntax",
      predicted_cost:{schema_version:"franken-engine.swarm-validation-predicted-cost.v1", state:"static", cost_class:"low", sample_count:0, elapsed_ms_p50:0, elapsed_ms_max:0, compiled_target_count_max:0, linked_target_count_max:0},
      risk_flags:[],
      cost_evidence:{status:"not_required", matched_rows:0}
    }],
    omitted_commands:[],
    proof_cost_budgets:[]
  }' >"${fixture_dir}/validation_plan.json"
  jq -n '{
    collision_risk:"reserved_overlap",
    conflicting_agents:["CyanOak"],
    safe_alternatives:["docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md"],
    reservation_recommendations:[{action:"coordinate_reservation_holder", scope:"planned_write_set", reason:"planned write paths overlap active exclusive reservations"}],
    conflicts:{reservations:[{planned_path:"scripts/swarm_operator_status_report.sh", path_pattern:"scripts/swarm_operator_status_report.sh", agent:"CyanOak", bead_id:"bd-gc1ml", source:"reservation"}], dirty:[], in_progress:[]}
  }' >"${fixture_dir}/collision_receipt.json"
}

run_case() {
  local case_name="$1"
  local expected_status="$2"
  local agent_mail_status="$3"
  local rch_status="$4"
  local proof_index_status="$5"
  local tmp_root="$6"
  local fixture_dir="${tmp_root}/${case_name}-fixtures"
  local output_dir="${tmp_root}/${case_name}-out"
  local actual_path="${tmp_root}/${case_name}.actual.golden"
  local golden_path="${golden_dir}/swarm_operator_status_report_${case_name}.golden"

  mkdir -p "$fixture_dir"
  case "$case_name" in
    healthy)
      write_healthy_fixtures "$fixture_dir"
      ;;
    degraded)
      write_degraded_fixtures "$fixture_dir"
      ;;
    stale_proof)
      write_stale_proof_fixtures "$fixture_dir"
      ;;
    high_cost)
      write_high_cost_fixtures "$fixture_dir"
      ;;
    collision_risk)
      write_collision_risk_fixtures "$fixture_dir"
      ;;
    *)
      record_failure "unknown case: ${case_name}"
      exit 64
      ;;
  esac

  "$reporter" \
    --bead-id bd-jw854 \
    --source-revision smoke-rev \
    --output-dir "$output_dir" \
    --agent-mail-status "$agent_mail_status" \
    --rch-status "$rch_status" \
    --proof-index-status "$proof_index_status" \
    --ready-json "${fixture_dir}/ready.json" \
    --in-progress-json "${fixture_dir}/in_progress.json" \
    --bv-plan-json "${fixture_dir}/bv_plan.json" \
    --reservations-json "${fixture_dir}/reservations.json" \
    --resource-decision-json "${fixture_dir}/resource_decision.json" \
    --validation-plan-json "${fixture_dir}/validation_plan.json" \
    --proof-index-json "${fixture_dir}/proof_index.json" \
    --proof-outcomes-json "${fixture_dir}/proof_outcomes.json" \
    --stale-evidence-json "${fixture_dir}/stale_evidence.json" \
    --dirty-files-json "${fixture_dir}/dirty_files.json" \
    --collision-receipt-json "${fixture_dir}/collision_receipt.json" \
    --proof-freshness-json "${fixture_dir}/proof_freshness.json" \
    --rch-incident-packet-json "${fixture_dir}/rch_incident_packet.json" >/dev/null

  jq -e --arg expected_status "$expected_status" '
    .schema_version == "franken-engine.swarm-operator-status-report.v1"
    and .status == $expected_status
    and .tui_ready == true
    and .dashboard_contract.schema_version == "franken-engine.swarm-predictive-dashboard.v1"
    and .dashboard_contract.renderer.provider == "/dp/frankentui"
    and .dashboard_contract.renderer.shipped_in_franken_engine == false
    and .dashboard_contract.renderer.local_renderer == false
    and .predictive_dashboard.schema_version == "franken-engine.swarm-predictive-dashboard.v1"
    and .predictive_dashboard.renderer_contract.provider == "/dp/frankentui"
    and .predictive_dashboard.fixture_contract.local_tui_renderer == false
    and (.predictive_dashboard.predictive_cost.commands | type == "array")
    and (.predictive_dashboard.collision_risk.risk | type == "string")
    and (.predictive_dashboard.proof_freshness.state | type == "string")
    and (.predictive_dashboard.rch_incidents.incidents | type == "array")
    and (.recommendations | length) >= 1
  ' "${output_dir}/status.json" >/dev/null
  record_pass "${case_name} report validates"

  case "$case_name" in
    healthy)
      jq -e '
        .summary.high_cost_command_count == 0
        and .predictive_dashboard.collision_risk.risk == "none"
        and .predictive_dashboard.proof_freshness.state == "fresh"
        and .predictive_dashboard.rch_incidents.status == "none"
      ' "${output_dir}/status.json" >/dev/null
      ;;
    degraded)
      jq -e '
        .predictive_dashboard.rch_incidents.status == "degraded"
        and any(.degraded[]; .component == "rch_incident_packet")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    stale_proof)
      jq -e '
        .predictive_dashboard.proof_freshness.state == "stale_by_time"
        and .predictive_dashboard.proof_freshness.reusable == false
        and any(.degraded[]; .component == "proof_freshness")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    high_cost)
      jq -e '
        .summary.high_cost_command_count == 1
        and .predictive_dashboard.predictive_cost.status == "elevated"
        and any(.degraded[]; .component == "predictive_cost")
      ' "${output_dir}/status.json" >/dev/null
      ;;
    collision_risk)
      jq -e '
        .predictive_dashboard.collision_risk.risk == "reserved_overlap"
        and (.predictive_dashboard.collision_risk.conflicting_agents | index("CyanOak"))
        and any(.degraded[]; .component == "collision_risk")
      ' "${output_dir}/status.json" >/dev/null
      ;;
  esac
  record_pass "${case_name} dashboard fields validate"

  canonicalize_status "${output_dir}/status.json" "$tmp_root" >"$actual_path"
  compare_case_golden "$case_name" "$actual_path" "$golden_path"
}

assert_dashboard_contract_truth() {
  if [[ ! -f "$contract_doc" ]]; then
    record_failure "missing dashboard contract doc"
    return 1
  fi
  if [[ ! -f "$contract_json" ]]; then
    record_failure "missing dashboard contract json"
    return 1
  fi

  jq -e '
    .schema_version == "franken-engine.swarm-predictive-dashboard-contract.v1"
    and .renderer.repo_path == "/dp/frankentui"
    and .renderer.shipped_in_franken_engine == false
    and .renderer.local_renderer == false
    and (.golden_fixture_cases | index("healthy"))
    and (.golden_fixture_cases | index("degraded"))
    and (.golden_fixture_cases | index("stale_proof"))
    and (.golden_fixture_cases | index("high_cost"))
    and (.golden_fixture_cases | index("collision_risk"))
  ' "$contract_json" >/dev/null

  grep -Fq '/dp/frankentui' "$contract_doc"
  grep -Fq 'FrankenEngine does not ship a local TUI renderer for this contract.' "$contract_doc"

  if grep -Eiq 'franken_engine ships[[:space:]].*TUI|FrankenEngine ships[[:space:]].*TUI|ships a local TUI|local_renderer[[:space:]]*:[[:space:]]*true|shipped_in_franken_engine[[:space:]]*:[[:space:]]*true' "$contract_doc" "$contract_json"; then
    record_failure "dashboard docs claim a shipped local TUI"
    return 1
  fi

  record_pass "dashboard contract truth validates"
}

run_selftest() {
  local tmp_parent tmp_root

  tmp_parent="${SWARM_OPERATOR_STATUS_REPORT_SMOKE_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-operator-status.XXXXXX")"

  assert_dashboard_contract_truth
  run_case "healthy" "healthy" "ok" "ok" "ok" "$tmp_root"
  run_case "degraded" "degraded" "missing" "missing" "missing" "$tmp_root"
  run_case "stale_proof" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "high_cost" "degraded" "ok" "ok" "ok" "$tmp_root"
  run_case "collision_risk" "degraded" "ok" "ok" "ok" "$tmp_root"

  printf 'swarm_operator_status_report_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check|selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
