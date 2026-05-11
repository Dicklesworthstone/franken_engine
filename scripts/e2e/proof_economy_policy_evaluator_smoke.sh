#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/proof_economy_replay_trace_normalizer.sh"
evaluator="${root_dir}/scripts/proof_economy_policy_evaluator.sh"
docs_path="${root_dir}/docs/PROOF_ECONOMY_POLICY_EVALUATOR.md"
contract_path="${root_dir}/docs/proof_economy_policy_evaluator_contract_v1.json"
golden_path="${PROOF_ECONOMY_POLICY_GOLDEN:-${root_dir}/scripts/testdata/goldens/proof_economy_policy_scorecard.golden}"

record_pass() {
  printf 'PASS proof-economy-policy %s\n' "$1"
}

record_failure() {
  printf 'FAIL proof-economy-policy %s\n' "$1" >&2
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
      },
      {
        agent_id:"AgentMismatch",
        bead_id:"bd-p2-warm-mismatch",
        requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_mismatch cargo test -p frankenengine-engine --test beta",
        target_dir:"/tmp/rch_target_mismatch",
        lease_decision:"admit"
      }
    ]
  }' >"${dir}/leases.json"

  jq -n '{cache_hit_artifacts: [], required_refreshes: []}' >"${dir}/proof_cache.json"
}

canonicalize_scorecard() {
  local scorecard_path="$1"
  local tmp_root="$2"
  jq --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "string" then
        gsub($tmp_root; "[SMOKE_ROOT]")
        | gsub("/tmp/rch_target_"; "[RCH_TARGET]/")
      elif type == "array" then
        map(scrub)
      elif type == "object" then
        with_entries(.value |= scrub)
      else
        .
      end;
    scrub
  ' "$scorecard_path"
}

assert_scorecard_golden() {
  local scorecard_path="$1"
  local tmp_root="$2"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    mkdir -p "$(dirname "$golden_path")"
    canonicalize_scorecard "$scorecard_path" "$tmp_root" >"$golden_path"
    record_pass "updated policy scorecard golden"
    return
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "missing policy scorecard golden"
    return 1
  fi

  if ! diff -u "$golden_path" <(canonicalize_scorecard "$scorecard_path" "$tmp_root"); then
    record_failure "policy scorecard golden drift"
    return 1
  fi
  record_pass "policy scorecard golden matches"
}

run_check() {
  local scope_file

  bash -n "$evaluator"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  if [[ "${UPDATE_GOLDENS:-0}" != "1" ]]; then
    [[ -f "$golden_path" ]] || { record_failure "missing policy scorecard golden"; return 1; }
    jq empty "$golden_path"
  fi
  grep -q 'franken-engine.proof-economy-policy-scorecard.v1' "$docs_path"
  grep -q 'policy_scorecard.json' "$docs_path"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/proof-economy-policy-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/proof_economy_policy_evaluator.sh" \
    "scripts/e2e/proof_economy_policy_evaluator_smoke.sh" \
    "docs/PROOF_ECONOMY_POLICY_EVALUATOR.md" \
    "docs/proof_economy_policy_evaluator_contract_v1.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/proof-economy-policy-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "syntax docs contract and rch policy"
}

run_selftest() {
  local tmp_parent tmp_root fixture_dir trace_dir eval_a eval_b fail_dir fail_trace
  local fail_exit fail_output

  run_check
  tmp_parent="${PROOF_ECONOMY_POLICY_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/proof-economy-policy.XXXXXX")"
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

  eval_a="${tmp_root}/eval-a"
  "$evaluator" \
    --replay-trace-json "${trace_dir}/replay_trace.normalized.json" \
    --pressure-mode high \
    --max-heavy-per-agent 1 \
    --output-dir "$eval_a" >/dev/null

  jq -e '
    .schema_version == "franken-engine.proof-economy-policy-scorecard.v1"
    and .policy_decision == "pass"
    and .p1_slo_risk == "protected"
    and any(.decisions[]; .bead_id == "bd-p1-proof-alpha" and .decision == "admit_preempt")
    and any(.decisions[]; .bead_id == "bd-p3-broad-beta" and .decision == "defer" and .fairness_reason == "pressure-aware deferral")
    and any(.decisions[]; .bead_id == "bd-p2-noisy-2" and .decision == "defer" and .fairness_reason == "agent fairness throttle")
    and any(.decisions[]; .bead_id == "bd-p1-proof-alpha" and .warm_target_reuse == true)
    and any(.decisions[]; .bead_id == "bd-p2-warm-mismatch" and .warm_target_reuse == false)
  ' "${eval_a}/policy_scorecard.json" >/dev/null
  record_pass "fair-share pressure and warm-target decisions"
  assert_scorecard_golden "${eval_a}/policy_scorecard.json" "$tmp_root"

  eval_b="${tmp_root}/eval-b"
  "$evaluator" \
    --replay-trace-json "${trace_dir}/replay_trace.normalized.json" \
    --pressure-mode high \
    --max-heavy-per-agent 1 \
    --output-dir "$eval_b" >/dev/null
  diff -u \
    <(jq -cS 'del(.artifact_paths)' "${eval_a}/policy_scorecard.json") \
    <(jq -cS 'del(.artifact_paths)' "${eval_b}/policy_scorecard.json") >/dev/null
  record_pass "repeated policy scorecard is deterministic"

  fail_trace="${tmp_root}/fail-trace.json"
  jq '.command_rows[0].requested_command = "cargo test -p frankenengine-engine --test focused"' \
    "${trace_dir}/replay_trace.normalized.json" >"$fail_trace"
  fail_dir="${tmp_root}/fail"
  set +e
  fail_output="$("$evaluator" --replay-trace-json "$fail_trace" --output-dir "$fail_dir" 2>&1)"
  fail_exit=$?
  set -e
  if [[ "$fail_exit" -ne 42 ]]; then
    record_failure "expected fail-closed unwrapped heavy command, got ${fail_exit}"
    printf '%s\n' "$fail_output" >&2
    return 1
  fi
  jq -e '
    .policy_decision == "fail_closed"
    and any(.findings[]; .code == "unwrapped_heavy_command")
  ' "${fail_dir}/policy_scorecard.json" >/dev/null
  record_pass "unwrapped heavy command fails closed"

  printf 'proof_economy_policy_smoke_artifacts=%s\n' "$tmp_root"
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
