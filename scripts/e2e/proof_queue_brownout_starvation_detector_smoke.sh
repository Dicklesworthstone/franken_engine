#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/proof_economy_replay_trace_normalizer.sh"
counterfactual_runner="${root_dir}/scripts/proof_economy_counterfactual_replay_runner.sh"
detector="${root_dir}/scripts/proof_queue_brownout_starvation_detector.sh"
docs_path="${root_dir}/docs/PROOF_QUEUE_BROWNOUT_STARVATION_DETECTOR.md"
contract_path="${root_dir}/docs/proof_queue_brownout_detector_contract_v1.json"

record_pass() {
  printf 'PASS proof-queue-brownout %s\n' "$1"
}

record_failure() {
  printf 'FAIL proof-queue-brownout %s\n' "$1" >&2
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

  bash -n "$detector"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  grep -q 'franken-engine.proof-queue-brownout-report.v1' "$docs_path"
  grep -q 'brownout_report.json' "$docs_path"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/proof-queue-brownout-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/proof_queue_brownout_starvation_detector.sh" \
    "scripts/e2e/proof_queue_brownout_starvation_detector_smoke.sh" \
    "docs/PROOF_QUEUE_BROWNOUT_STARVATION_DETECTOR.md" \
    "docs/proof_queue_brownout_detector_contract_v1.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/proof-queue-brownout-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "syntax docs contract and rch policy"
}

run_selftest() {
  local tmp_parent tmp_root fixture_dir trace_dir counterfactual_dir brownout_a brownout_b
  local detector_exit

  run_check
  tmp_parent="${PROOF_QUEUE_BROWNOUT_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/proof-queue-brownout.XXXXXX")"
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

  brownout_a="${tmp_root}/brownout-a"
  set +e
  "$detector" \
    --replay-trace-json "${trace_dir}/replay_trace.normalized.json" \
    --counterfactual-report-json "${counterfactual_dir}/counterfactual_replay_report.json" \
    --max-agent-share-millionths 400000 \
    --output-dir "$brownout_a" >/dev/null
  detector_exit=$?
  set -e
  if [[ "$detector_exit" -ne 42 ]]; then
    record_failure "expected fail-closed brownout exit 42, got ${detector_exit}"
    return 1
  fi

  jq -e '
    .schema_version == "franken-engine.proof-queue-brownout-report.v1"
    and .policy_decision == "fail_closed"
    and .summary.all_workers_busy == true
    and any(.brownout_receipts[]; .code == "queue_brownout_all_workers_busy")
    and any(.findings[]; .code == "unfair_agent_slot_share" and .evidence.agent_id == "AgentNoisy")
    and any(.findings[]; .code == "low_priority_starvation" and .evidence.bead_id == "bd-p3-broad-beta" and (.remediation | length) > 0)
  ' "${brownout_a}/brownout_report.json" >/dev/null
  record_pass "busy queue monopolization and low-priority starvation findings"

  brownout_b="${tmp_root}/brownout-b"
  set +e
  "$detector" \
    --replay-trace-json "${trace_dir}/replay_trace.normalized.json" \
    --counterfactual-report-json "${counterfactual_dir}/counterfactual_replay_report.json" \
    --max-agent-share-millionths 400000 \
    --output-dir "$brownout_b" >/dev/null
  detector_exit=$?
  set -e
  if [[ "$detector_exit" -ne 42 ]]; then
    record_failure "expected repeated fail-closed brownout exit 42, got ${detector_exit}"
    return 1
  fi
  diff -u \
    <(jq -cS 'del(.artifact_paths)' "${brownout_a}/brownout_report.json") \
    <(jq -cS 'del(.artifact_paths)' "${brownout_b}/brownout_report.json") >/dev/null
  record_pass "repeated brownout report is deterministic"

  printf 'proof_queue_brownout_smoke_artifacts=%s\n' "$tmp_root"
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
