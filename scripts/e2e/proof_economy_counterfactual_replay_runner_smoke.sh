#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/proof_economy_replay_trace_normalizer.sh"
evaluator="${root_dir}/scripts/proof_economy_policy_evaluator.sh"
runner="${root_dir}/scripts/proof_economy_counterfactual_replay_runner.sh"
docs_path="${root_dir}/docs/PROOF_ECONOMY_COUNTERFACTUAL_REPLAY_RUNNER.md"
contract_path="${root_dir}/docs/proof_economy_counterfactual_replay_contract_v1.json"

record_pass() {
  printf 'PASS proof-economy-counterfactual %s\n' "$1"
}

record_failure() {
  printf 'FAIL proof-economy-counterfactual %s\n' "$1" >&2
}

write_trace_fixture() {
  local dir="$1"

  jq -n '[
    {id:"bd-p1-proof-alpha", title:"P1 focused proof", priority:1, status:"open", assignee:null},
    {id:"bd-p3-broad-beta", title:"P3 broad validation", priority:3, status:"open", assignee:null},
    {id:"bd-p2-noisy-1", title:"Noisy agent first proof", priority:2, status:"open", assignee:null},
    {id:"bd-p2-noisy-2", title:"Noisy agent second proof", priority:2, status:"open", assignee:null},
    {id:"bd-p2-warm-mismatch", title:"Warm target mismatch", priority:2, status:"open", assignee:null}
  ]' >"${dir}/ready.json"

  jq -n '{issues: []}' >"${dir}/in_progress.json"

  jq -n '{
    reservations: [
      {path_pattern:"/tmp/rch_target_alpha", agent_id:"AgentAlpha", bead_id:"bd-p1-proof-alpha", exclusive:true},
      {path_pattern:"/tmp/rch_target_noisy_1", agent_id:"AgentNoisy", bead_id:"bd-p2-noisy-1", exclusive:true},
      {path_pattern:"/tmp/rch_target_other", agent_id:"OtherAgent", bead_id:"bd-other", exclusive:true}
    ]
  }' >"${dir}/reservations.json"

  jq -n '{
    plans: [
      {
        agent_id:"AgentAlpha",
        bead_id:"bd-p1-proof-alpha",
        requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_alpha cargo test -p frankenengine-engine --test focused -- --nocapture",
        target_dir:"/tmp/rch_target_alpha",
        lease_decision:"admit"
      },
      {
        agent_id:"AgentBeta",
        bead_id:"bd-p3-broad-beta",
        requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_beta cargo check --all-targets",
        target_dir:"/tmp/rch_target_beta",
        lease_decision:"admit"
      },
      {
        agent_id:"AgentMismatch",
        bead_id:"bd-p2-warm-mismatch",
        requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_mismatch cargo test -p frankenengine-engine --test beta",
        target_dir:"/tmp/rch_target_mismatch",
        lease_decision:"admit"
      },
      {
        agent_id:"AgentNoisy",
        bead_id:"bd-p2-noisy-1",
        requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_noisy_1 cargo test -p frankenengine-engine --test alpha",
        target_dir:"/tmp/rch_target_noisy_1",
        lease_decision:"admit"
      },
      {
        agent_id:"AgentNoisy",
        bead_id:"bd-p2-noisy-2",
        requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_noisy_2 cargo clippy --all-targets -- -D warnings",
        target_dir:"/tmp/rch_target_noisy_2",
        lease_decision:"admit"
      }
    ]
  }' >"${dir}/leases.json"

  jq -n '{cache_hit_artifacts: [], required_refreshes: []}' >"${dir}/proof_cache.json"
}

run_check() {
  local scope_file

  bash -n "$runner"
  bash -n "${BASH_SOURCE[0]}"
  bash -n "$evaluator"
  jq empty "$contract_path"
  grep -q 'franken-engine.proof-economy-counterfactual-replay-report.v1' "$docs_path"
  grep -q 'counterfactual_replay_report.json' "$docs_path"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/proof-economy-counterfactual-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/proof_economy_counterfactual_replay_runner.sh" \
    "scripts/e2e/proof_economy_counterfactual_replay_runner_smoke.sh" \
    "docs/PROOF_ECONOMY_COUNTERFACTUAL_REPLAY_RUNNER.md" \
    "docs/proof_economy_counterfactual_replay_contract_v1.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/proof-economy-counterfactual-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "syntax docs contract and rch policy"
}

run_selftest() {
  local tmp_parent tmp_root fixture_dir trace_dir run_a run_b

  run_check
  tmp_parent="${PROOF_ECONOMY_COUNTERFACTUAL_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/proof-economy-counterfactual.XXXXXX")"
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

  run_a="${tmp_root}/counterfactual-a"
  "$runner" \
    --replay-trace-json "${trace_dir}/replay_trace.normalized.json" \
    --output-dir "$run_a" >/dev/null

  jq -e '
    . as $root
    |
    .schema_version == "franken-engine.proof-economy-counterfactual-replay-report.v1"
    and .policy_decision == "pass"
    and .assertions.baseline_reproduces_fixture_order == true
    and .assertions.fair_share_reduces_starvation == true
    and .assertions.high_pressure_defers_broad_p3 == true
    and .assertions.all_p1_slo_preserved == true
    and any($root.policy_outcomes[];
      .policy_name == "baseline"
      and .fixture_order_match == true
      and .scheduled_order == $root.trace_fixture_order
    )
    and any($root.policy_outcomes[];
      .policy_name == "fair_share"
      and .delta_from_baseline.monopoly_reduction_millionths > 0
      and any(.deferred_commands[]; .bead_id == "bd-p2-noisy-2" and .fairness_reason == "agent fairness throttle")
    )
    and any($root.policy_outcomes[];
      .policy_name == "high_pressure"
      and any(.deferred_commands[]; .bead_id == "bd-p3-broad-beta" and .fairness_reason == "pressure-aware deferral")
    )
    and any($root.policy_outcomes[];
      .policy_name == "fair_share"
      and any(.unchanged_commands[]; .bead_id == "bd-p1-proof-alpha" and .decision == "admit_preempt")
    )
  ' "${run_a}/counterfactual_replay_report.json" >/dev/null
  record_pass "baseline fair-share high-pressure outcomes"

  jq -e '
    all(.policy_outcomes[]; (.changed_commands | type) == "array")
    and all(.policy_outcomes[]; (.deferred_commands | type) == "array")
    and all(.policy_outcomes[]; (.unchanged_commands | type) == "array")
    and any(.policy_outcomes[].changed_commands[]?; (.explanation | length) > 0)
    and any(.policy_outcomes[].unchanged_commands[]?; (.explanation | length) > 0)
  ' "${run_a}/counterfactual_replay_report.json" >/dev/null
  record_pass "operator explanations for changed deferred and unchanged commands"

  run_b="${tmp_root}/counterfactual-b"
  "$runner" \
    --replay-trace-json "${trace_dir}/replay_trace.normalized.json" \
    --output-dir "$run_b" >/dev/null
  diff -u \
    <(jq -cS 'del(.artifact_paths)' "${run_a}/counterfactual_replay_report.json") \
    <(jq -cS 'del(.artifact_paths)' "${run_b}/counterfactual_replay_report.json") >/dev/null
  record_pass "repeated counterfactual report is deterministic"

  printf 'proof_economy_counterfactual_smoke_artifacts=%s\n' "$tmp_root"
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
