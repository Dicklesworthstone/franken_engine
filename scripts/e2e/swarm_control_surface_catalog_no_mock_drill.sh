#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/swarm_control_surface_catalog_normalizer.sh"
router="${root_dir}/scripts/swarm_control_surface_intent_router.sh"
drift_gate="${root_dir}/scripts/swarm_control_surface_drift_gate.sh"
intake_guard="${root_dir}/scripts/swarm_control_surface_intake_guard.sh"
operator_status="${root_dir}/scripts/swarm_operator_status_report.sh"
manifest="${root_dir}/docs/swarm_control_surface_catalog_contract_v1.json"
runbook="${root_dir}/docs/SWARM_CTRL_XVII_OPERATOR_RUNBOOK.md"
truth_contract="${root_dir}/docs/swarm_ctrl_xvii_runbook_truth_contract_v1.json"
mode="${1:-check}"

artifact_root="${SWARM_CONTROL_SURFACE_CATALOG_NO_MOCK_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-control-surface-no-mock}"
run_id="${SWARM_CONTROL_SURFACE_CATALOG_NO_MOCK_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_CONTROL_SURFACE_CATALOG_NO_MOCK_RUN_DIR:-${artifact_root}/${run_id}}"

record_pass() {
  printf 'PASS swarm-control-surface-catalog-no-mock %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-control-surface-catalog-no-mock %s\n' "$1" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_control_surface_catalog_no_mock_drill.sh [check|selftest]
EOF
}

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-control-surface-catalog-no-mock.event.v1" \
    --arg event_name "$1" \
    --arg detail "$2" \
    '{schema_version:$schema_version,event_name:$event_name,detail:$detail}' >>"${run_dir}/events.jsonl"
}

record_command() {
  printf '%s\n' "$*" >>"${run_dir}/commands.txt"
}

run_expect() {
  local expected="$1"
  shift
  local status

  record_command "$*"
  set +e
  "$@" >/dev/null
  status=$?
  set -e
  if [[ "$status" -ne "$expected" ]]; then
    record_failure "expected exit ${expected}, got ${status}: $*"
  fi
}

write_inputs() {
  jq -n '{
    intent_tags:["rch","stall","remote-proof","rehabilitation"],
    symptom_tags:["rch-stall","local-fallback"]
  }' >"${run_dir}/rch_stall_intent.json"

  jq -n '{
    intent_tags:["actionability","br-bv-divergence"],
    symptom_tags:["blocked-advertised-actionable"]
  }' >"${run_dir}/actionability_intent.json"

  jq -n '{
    title:"Add another RCH stall remediation control surface",
    description:"Proposed duplicate of the existing RCH stall rehabilitation surface.",
    intent_tags:["rch","stall","remote-proof","rehabilitation"],
    symptom_tags:["rch-stall","local-fallback"],
    acceptance_criteria:["route stalled remote proof work without live mutation"]
  }' >"${run_dir}/duplicate_rch_proposal.json"

  jq -n --arg drill_script "scripts/e2e/swarm_control_surface_catalog_no_mock_drill.sh" '{
    scripts:[$drill_script]
  }' >"${run_dir}/uncataloged_script_inventory.json"

  jq -n '{
    issues:[
      {id:"bd-djejh.1", status:"in_progress"},
      {id:"bd-1tsvb", status:"closed"},
      {id:"bd-7ayfz", status:"closed"}
    ]
  }' >"${run_dir}/shadow_owner_status.json"
}

run_drill() {
  mkdir -p "$run_dir"
  : >"${run_dir}/events.jsonl"
  : >"${run_dir}/commands.txt"
  write_inputs

  run_expect 0 "$normalizer" \
    --source-manifest-json "$manifest" \
    --workspace-root "$root_dir" \
    --source-revision no-mock-drill \
    --output-dir "${run_dir}/catalog"
  catalog_json="${run_dir}/catalog/swarm_control_surface_catalog.json"
  jq -e '.decision == "pass" or .decision == "degraded"' "$catalog_json" >/dev/null \
    || record_failure "catalog normalizer did not emit pass/degraded catalog"
  jq -e '.surface_count >= 13' "$catalog_json" >/dev/null \
    || record_failure "catalog normalizer lost real source inventory"
  write_event "catalog_normalized" "$(jq -r '.decision' "$catalog_json")"

  run_expect 0 "$router" \
    --catalog-json "$catalog_json" \
    --intent-json "${run_dir}/rch_stall_intent.json" \
    --source-revision no-mock-drill \
    --output-dir "${run_dir}/router_rch_stall"
  rch_plan="${run_dir}/router_rch_stall/swarm_control_surface_intent_plan.json"
  jq -e '.recommendations[0].surface_id == "swarm_rch_stall_rehabilitation_ledger"' "$rch_plan" >/dev/null \
    || record_failure "RCH stall intent did not route to RCH stall rehabilitation"
  write_event "rch_stall_routed" "swarm_rch_stall_rehabilitation_ledger"

  run_expect 0 "$router" \
    --catalog-json "$catalog_json" \
    --intent-json "${run_dir}/actionability_intent.json" \
    --source-revision no-mock-drill \
    --output-dir "${run_dir}/router_actionability"
  actionability_plan="${run_dir}/router_actionability/swarm_control_surface_intent_plan.json"
  jq -e '.recommendations[0].surface_id == "swarm_actionability_truth_gate"' "$actionability_plan" >/dev/null \
    || record_failure "actionability divergence did not route to actionability truth gate"
  write_event "actionability_routed" "swarm_actionability_truth_gate"

  run_expect 42 "$intake_guard" \
    --proposal-json "${run_dir}/duplicate_rch_proposal.json" \
    --catalog-json "$catalog_json" \
    --source-revision no-mock-drill \
    --output-dir "${run_dir}/intake_duplicate"
  intake_report="${run_dir}/intake_duplicate/intake_guard_report.json"
  jq -e '.recommended_action == "duplicate_reject"' "$intake_report" >/dev/null \
    || record_failure "duplicate proposal was not rejected"
  write_event "duplicate_rejected" "rch_stall"

  run_expect 42 "$drift_gate" \
    --catalog-json "$catalog_json" \
    --script-inventory-json "${run_dir}/uncataloged_script_inventory.json" \
    --workspace-root "$root_dir" \
    --source-revision no-mock-drill \
    --output-dir "${run_dir}/drift_uncataloged"
  uncataloged_drift="${run_dir}/drift_uncataloged/control_surface_drift_report.json"
  jq -e 'any(.findings[]; .code == "FE-SWARM-DRIFT-UNCATALOGED-SCRIPT")' "$uncataloged_drift" >/dev/null \
    || record_failure "uncataloged script drift did not fail closed"
  write_event "uncataloged_script_failed_closed" "swarm_control_surface_catalog_no_mock_drill"

  run_expect 42 "$drift_gate" \
    --catalog-json "$catalog_json" \
    --bead-status-json "${run_dir}/shadow_owner_status.json" \
    --workspace-root "$root_dir" \
    --source-revision no-mock-drill \
    --output-dir "${run_dir}/drift_shadow_owner"
  shadow_drift="${run_dir}/drift_shadow_owner/control_surface_drift_report.json"
  jq -e '
    any(.findings[]; .code == "FE-SWARM-DRIFT-STALE-OWNER-BEAD"
      and (.surface_id == "swarm_autopilot_shadow_daemon"))
  ' "$shadow_drift" >/dev/null \
    || record_failure "shadow-daemon active owner did not stay blocked/degraded"
  write_event "shadow_daemon_blocked" "bd-djejh.1"

  run_expect 0 "$operator_status" \
    --source-revision no-mock-drill \
    --agent-mail-status ok \
    --rch-status ok \
    --proof-index-status ok \
    --swarm-control-surface-catalog-json "$catalog_json" \
    --swarm-control-surface-intent-plan-json "$rch_plan" \
    --swarm-control-surface-drift-report-json "$shadow_drift" \
    --output-dir "${run_dir}/operator_status"
  operator_status_json="${run_dir}/operator_status/status.json"
  jq -e '
    .predictive_dashboard.swarm_control_surface_catalog.top_recommended_surface == "swarm_rch_stall_rehabilitation_ledger"
    and .predictive_dashboard.swarm_control_surface_catalog.drift_count >= 1
    and .predictive_dashboard.swarm_control_surface_catalog.mutation_policy.advisory_only == true
    and .predictive_dashboard.swarm_control_surface_catalog.mutation_policy.mutates_br == false
    and .predictive_dashboard.swarm_control_surface_catalog.mutation_policy.runs_cargo == false
    and .predictive_dashboard.swarm_control_surface_catalog.mutation_policy.runs_rch == false
  ' "$operator_status_json" >/dev/null \
    || record_failure "operator status did not expose control-surface handoff"
  write_event "operator_status_exposed_handoff" "swarm_control_surface_catalog"

  jq -n \
    --arg schema_version "franken-engine.swarm-control-surface-catalog-no-mock-drill-report.v1" \
    --arg catalog_json "$catalog_json" \
    --arg rch_plan "$rch_plan" \
    --arg actionability_plan "$actionability_plan" \
    --arg intake_report "$intake_report" \
    --arg uncataloged_drift "$uncataloged_drift" \
    --arg shadow_drift "$shadow_drift" \
    --arg operator_status_json "$operator_status_json" \
    --arg commands_txt "${run_dir}/commands.txt" \
    --arg events_jsonl "${run_dir}/events.jsonl" \
    '{
      schema_version:$schema_version,
      decision:"pass",
      cases:{
        rch_stall_routes_to:"swarm_rch_stall_rehabilitation_ledger",
        actionability_divergence_routes_to:"swarm_actionability_truth_gate",
        duplicate_proposal_rejected:true,
        uncataloged_script_fail_closed:true,
        operator_status_exposes_handoff:true,
        shadow_daemon_active_owner_blocked:true
      },
      artifact_paths:{
        catalog_json:$catalog_json,
        rch_intent_plan_json:$rch_plan,
        actionability_intent_plan_json:$actionability_plan,
        intake_guard_report_json:$intake_report,
        uncataloged_drift_report_json:$uncataloged_drift,
        shadow_owner_drift_report_json:$shadow_drift,
        operator_status_json:$operator_status_json,
        commands_txt:$commands_txt,
        events_jsonl:$events_jsonl
      },
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        fixture_fed_only:true,
        mutates_br:false,
        queries_live_agent_mail:false,
        sends_agent_mail:false,
        releases_reservations:false,
        runs_cargo:false,
        runs_rch:false,
        changes_live_queue_policy:false,
        replaces_operator_status_report:false
      }
    }' >"${run_dir}/swarm_control_surface_catalog_no_mock_drill_report.json"

  {
    printf '# Swarm Control-Surface Catalog No-Mock Drill\n\n'
    printf -- "- decision: \`pass\`\n"
    printf -- "- catalog: \`%s\`\n" "$catalog_json"
    printf -- "- RCH stall route: \`swarm_rch_stall_rehabilitation_ledger\`\n"
    printf -- "- actionability route: \`swarm_actionability_truth_gate\`\n"
    printf -- "- duplicate proposal: \`duplicate_reject\`\n"
    printf -- "- uncataloged drift: \`fail_closed\`\n"
    printf -- "- shadow daemon owner: \`blocked\`\n"
    printf -- "- operator status: \`%s\`\n" "$operator_status_json"
  } >"${run_dir}/report.md"

  jq empty "${run_dir}/swarm_control_surface_catalog_no_mock_drill_report.json"
  record_pass "drill"
  printf 'swarm_control_surface_catalog_no_mock_drill=%s\n' "${run_dir}/swarm_control_surface_catalog_no_mock_drill_report.json"
}

run_check() {
  bash -n "$normalizer" "$router" "$drift_gate" "$intake_guard" "$operator_status" "${BASH_SOURCE[0]}"
  jq empty "$manifest" "$truth_contract"
  grep -Fq 'scripts/swarm_operator_status_report.sh remains the only operator-status producer.' "$runbook" \
    || record_failure "runbook does not preserve operator-status producer boundary"
  run_drill
  record_pass "check"
}

run_selftest() {
  run_check
  jq -e '
    .cases.rch_stall_routes_to == "swarm_rch_stall_rehabilitation_ledger"
    and .cases.actionability_divergence_routes_to == "swarm_actionability_truth_gate"
    and .cases.duplicate_proposal_rejected == true
    and .cases.uncataloged_script_fail_closed == true
    and .cases.operator_status_exposes_handoff == true
    and .cases.shadow_daemon_active_owner_blocked == true
  ' "${run_dir}/swarm_control_surface_catalog_no_mock_drill_report.json" >/dev/null \
    || record_failure "selftest report case summary mismatch"
  record_pass "selftest"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    ;;
esac
