#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/proof_economy_replay_trace_normalizer.sh"
counterfactual_runner="${root_dir}/scripts/proof_economy_counterfactual_replay_runner.sh"
brownout_detector="${root_dir}/scripts/proof_queue_brownout_starvation_detector.sh"
what_if_report="${root_dir}/scripts/proof_economy_operator_what_if_report.sh"
docs_path="${root_dir}/docs/PROOF_ECONOMY_OPERATOR_WHAT_IF_REPORT.md"
contract_path="${root_dir}/docs/proof_economy_operator_what_if_contract_v1.json"

record_pass() {
  printf 'PASS proof-economy-what-if %s\n' "$1"
}

record_failure() {
  printf 'FAIL proof-economy-what-if %s\n' "$1" >&2
}

write_trace_fixture() {
  local dir="$1"

  jq -n '[
    {id:"bd-p1-proof-alpha", title:"P1 focused proof", priority:1, status:"open", assignee:null},
    {id:"bd-p3-broad-beta", title:"P3 broad validation", priority:3, status:"open", assignee:null},
    {id:"bd-p2-noisy-1", title:"Noisy agent first proof", priority:2, status:"open", assignee:null},
    {id:"bd-p2-noisy-2", title:"Noisy agent second proof", priority:2, status:"open", assignee:null},
    {id:"bd-p2-noisy-3", title:"Noisy agent third proof", priority:2, status:"open", assignee:null}
  ]' >"${dir}/ready.json"

  jq -n '{issues: []}' >"${dir}/in_progress.json"

  jq -n '{
    reservations: [
      {path_pattern:"/tmp/rch_target_alpha", agent_id:"AgentAlpha", bead_id:"bd-p1-proof-alpha", exclusive:true},
      {path_pattern:"/tmp/rch_target_noisy_1", agent_id:"AgentNoisy", bead_id:"bd-p2-noisy-1", exclusive:true}
    ]
  }' >"${dir}/reservations.json"

  jq -n '{
    plans: [
      {
        agent_id:"AgentAlpha",
        bead_id:"bd-p1-proof-alpha",
        requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_alpha cargo test -p frankenengine-engine --test focused -- --nocapture",
        target_dir:"/tmp/rch_target_alpha",
        lease_decision:"busy"
      },
      {
        agent_id:"AgentBeta",
        bead_id:"bd-p3-broad-beta",
        requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_beta cargo check --all-targets",
        target_dir:"/tmp/rch_target_beta",
        lease_decision:"busy"
      },
      {
        agent_id:"AgentNoisy",
        bead_id:"bd-p2-noisy-1",
        requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_noisy_1 cargo test -p frankenengine-engine --test alpha",
        target_dir:"/tmp/rch_target_noisy_1",
        lease_decision:"busy"
      },
      {
        agent_id:"AgentNoisy",
        bead_id:"bd-p2-noisy-2",
        requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_noisy_2 cargo clippy --all-targets -- -D warnings",
        target_dir:"/tmp/rch_target_noisy_2",
        lease_decision:"busy"
      },
      {
        agent_id:"AgentNoisy",
        bead_id:"bd-p2-noisy-3",
        requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_noisy_3 cargo test -p frankenengine-engine --test gamma",
        target_dir:"/tmp/rch_target_noisy_3",
        lease_decision:"busy"
      }
    ]
  }' >"${dir}/leases.json"

  jq -n '{cache_hit_artifacts: [], required_refreshes: []}' >"${dir}/proof_cache.json"
}

run_check() {
  local scope_file

  bash -n "$what_if_report"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  grep -q 'franken-engine.proof-economy-operator-what-if-report.v1' "$docs_path"
  grep -q 'dashboard_contract.json' "$docs_path"
  grep -q '/dp/frankentui' "$docs_path"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/proof-economy-what-if-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/proof_economy_operator_what_if_report.sh" \
    "scripts/e2e/proof_economy_operator_what_if_report_smoke.sh" \
    "docs/PROOF_ECONOMY_OPERATOR_WHAT_IF_REPORT.md" \
    "docs/proof_economy_operator_what_if_contract_v1.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/proof-economy-what-if-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "syntax docs contract and rch policy"
}

run_selftest() {
  local tmp_parent tmp_root fixture_dir trace_dir counterfactual_dir brownout_dir report_a report_b missing_dir
  local detector_exit report_exit

  run_check
  tmp_parent="${PROOF_ECONOMY_WHAT_IF_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/proof-economy-what-if.XXXXXX")"
  fixture_dir="${tmp_root}/fixtures"
  mkdir -p "$fixture_dir"
  write_trace_fixture "$fixture_dir"

  trace_dir="${tmp_root}/trace"
  "$normalizer" \
    --br-ready-json "${fixture_dir}/ready.json" \
    --br-in-progress-json "${fixture_dir}/in_progress.json" \
    --agent-mail-reservations-json "${fixture_dir}/reservations.json" \
    --resource-lease-plans-json "${fixture_dir}/leases.json" \
    --proof-cache-plan-json "${fixture_dir}/proof_cache.json" \
    --source-revision fixture-rev \
    --output-dir "$trace_dir" >/dev/null

  counterfactual_dir="${tmp_root}/counterfactual"
  "$counterfactual_runner" \
    --replay-trace-json "${trace_dir}/replay_trace.normalized.json" \
    --output-dir "$counterfactual_dir" >/dev/null

  brownout_dir="${tmp_root}/brownout"
  set +e
  "$brownout_detector" \
    --replay-trace-json "${trace_dir}/replay_trace.normalized.json" \
    --counterfactual-report-json "${counterfactual_dir}/counterfactual_replay_report.json" \
    --max-agent-share-millionths 400000 \
    --output-dir "$brownout_dir" >/dev/null
  detector_exit=$?
  set -e
  if [[ "$detector_exit" -ne 42 ]]; then
    record_failure "expected brownout fixture exit 42, got ${detector_exit}"
    return 1
  fi

  report_a="${tmp_root}/what-if-a"
  set +e
  "$what_if_report" \
    --replay-trace-json "${trace_dir}/replay_trace.normalized.json" \
    --counterfactual-report-json "${counterfactual_dir}/counterfactual_replay_report.json" \
    --brownout-report-json "${brownout_dir}/brownout_report.json" \
    --output-dir "$report_a" >/dev/null
  report_exit=$?
  set -e
  if [[ "$report_exit" -ne 42 ]]; then
    record_failure "expected what-if fail-closed exit 42, got ${report_exit}"
    return 1
  fi

  jq -e '
    .schema_version == "franken-engine.proof-economy-operator-what-if-report.v1"
    and .policy_decision == "fail_closed"
    and .dashboard.queue_depth == 5
    and (.dashboard.fair_share_score_millionths | type) == "number"
    and .dashboard.p1_slo_risk == "protected"
    and .dashboard.brownout_state == "fail_closed"
    and (.dashboard.recommended_operator_action | length) > 0
    and any(.changed_decision_evidence_links[];
      .bead_id == "bd-p3-broad-beta"
      and .policy_input_evidence.policy_matrix.policy_name == .policy_name
      and .policy_input_evidence.trace_command.bead_id == .bead_id
    )
  ' "${report_a}/what_if_report.json" >/dev/null
  record_pass "what-if evidence links and dashboard fields"

  jq -e '
    .schema_version == "franken-engine.proof-economy-operator-dashboard-contract.v1"
    and (.ui_reuse_policy | contains("/dp/frankentui"))
    and ([.field_inventory[].field] | index("queue_depth") != null)
    and ([.field_inventory[].field] | index("fair_share_score_millionths") != null)
    and ([.field_inventory[].field] | index("p1_slo_risk") != null)
    and ([.field_inventory[].field] | index("brownout_state") != null)
    and ([.field_inventory[].field] | index("recommended_operator_action") != null)
  ' "${report_a}/dashboard_contract.json" >/dev/null
  record_pass "dashboard contract field inventory"

  missing_dir="${tmp_root}/missing-artifact"
  set +e
  "$what_if_report" \
    --replay-trace-json "${trace_dir}/replay_trace.normalized.json" \
    --counterfactual-report-json "${counterfactual_dir}/counterfactual_replay_report.json" \
    --brownout-report-json "${tmp_root}/missing-brownout.json" \
    --output-dir "$missing_dir" >/dev/null
  report_exit=$?
  set -e
  if [[ "$report_exit" -ne 42 ]]; then
    record_failure "expected missing artifact fail-closed exit 42, got ${report_exit}"
    return 1
  fi
  jq -e '
    .policy_decision == "fail_closed"
    and any(.findings[]; .code == "missing_brownout_report" and (.remediation | length) > 0)
  ' "${missing_dir}/what_if_report.json" >/dev/null
  record_pass "missing replay artifact fails closed"

  report_b="${tmp_root}/what-if-b"
  set +e
  "$what_if_report" \
    --replay-trace-json "${trace_dir}/replay_trace.normalized.json" \
    --counterfactual-report-json "${counterfactual_dir}/counterfactual_replay_report.json" \
    --brownout-report-json "${brownout_dir}/brownout_report.json" \
    --output-dir "$report_b" >/dev/null
  report_exit=$?
  set -e
  if [[ "$report_exit" -ne 42 ]]; then
    record_failure "expected repeated fail-closed exit 42, got ${report_exit}"
    return 1
  fi
  diff -u \
    <(jq -cS 'del(.artifact_paths)' "${report_a}/what_if_report.json") \
    <(jq -cS 'del(.artifact_paths)' "${report_b}/what_if_report.json") >/dev/null
  diff -u \
    <(jq -cS 'del(.report_json)' "${report_a}/dashboard_contract.json") \
    <(jq -cS 'del(.report_json)' "${report_b}/dashboard_contract.json") >/dev/null
  record_pass "repeated what-if report is deterministic"

  printf 'proof_economy_what_if_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
