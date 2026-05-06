#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/proof_economy_replay_trace_normalizer.sh"
docs_path="${root_dir}/docs/PROOF_ECONOMY_REPLAY_TRACE_NORMALIZER.md"
contract_path="${root_dir}/docs/proof_economy_replay_trace_contract_v1.json"

record_pass() {
  printf 'PASS proof-economy-replay-trace %s\n' "$1"
}

record_failure() {
  printf 'FAIL proof-economy-replay-trace %s\n' "$1" >&2
}

write_fixtures() {
  local dir="$1"

  jq -n '[
    {id:"bd-p1-proof-alpha", title:"P1 focused proof", priority:1, status:"open", assignee:null},
    {id:"bd-p3-broad-beta", title:"P3 broad validation", priority:3, status:"open", assignee:null}
  ]' >"${dir}/ready.json"

  jq -n '{
    issues: [
      {id:"bd-active-gamma", title:"Active proof lane", priority:2, status:"in_progress", assignee:"AgentGamma"}
    ]
  }' >"${dir}/in_progress.json"

  jq -n '{
    reservations: [
      {path_pattern:"crates/franken-engine/src/runtime.rs", agent_id:"AgentGamma", bead_id:"bd-active-gamma", exclusive:true},
      {path_pattern:"docs/PROOF.md", agent_id:"AgentAlpha", bead_id:"bd-p1-proof-alpha", exclusive:true}
    ]
  }' >"${dir}/reservations.json"

  jq -n '{
    plans: [
      {
        agent_id:"AgentAlpha",
        bead_id:"bd-p1-proof-alpha",
        requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_alpha cargo test -p frankenengine-engine --test focused -- --nocapture",
        target_dir:"/tmp/rch_target_alpha",
        lease_decision:"admit",
        estimated_cpu_slots:4,
        estimated_memory_class:"large"
      },
      {
        agent_id:"AgentBeta",
        bead_id:"bd-p3-broad-beta",
        requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_beta cargo check --all-targets",
        target_dir:"/tmp/rch_target_beta",
        lease_decision:"defer",
        estimated_cpu_slots:8,
        estimated_memory_class:"xlarge"
      }
    ]
  }' >"${dir}/leases.json"

  jq -n '{
    cache_hit_artifacts: [
      {artifact_id:"proof-alpha", artifact_path:"artifacts/proofs/proof-alpha.json", artifact_role:"replay-critical"},
      {artifact_id:"proof-alpha-dup", artifact_path:"artifacts/proofs/proof-alpha.json", artifact_role:"replay-critical"}
    ],
    required_refreshes: [
      {artifact_id:"proof-beta", artifact_path:"artifacts/proofs/proof-beta.json", artifact_role:"broad-check"}
    ]
  }' >"${dir}/proof_cache.json"

  jq -n '{
    bundle_decision:"pass",
    artifact_paths: {
      bundle_report_json:"artifacts/bundle_report.json",
      phase_manifest_json:"artifacts/phase_manifest.json"
    }
  }' >"${dir}/resident_bundle.json"

  jq -n '{
    drill_decision:"pass",
    artifact_paths: {
      resident_remote_proof_no_mock_drill_report_json:"artifacts/resident_remote_proof_no_mock_drill_report.json",
      batch_manifest_json:"artifacts/batch_manifest.json"
    }
  }' >"${dir}/no_mock_drill.json"
}

run_check() {
  local scope_file

  bash -n "$normalizer"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  grep -q 'franken-engine.proof-economy-replay-trace.v1' "$docs_path"
  grep -q 'replay_trace.normalized.json' "$docs_path"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/proof-economy-replay-trace-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/proof_economy_replay_trace_normalizer.sh" \
    "scripts/e2e/proof_economy_replay_trace_normalizer_smoke.sh" \
    "docs/PROOF_ECONOMY_REPLAY_TRACE_NORMALIZER.md" \
    "docs/proof_economy_replay_trace_contract_v1.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/proof-economy-replay-trace-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "syntax docs contract and rch policy"
}

run_selftest() {
  local tmp_parent tmp_root fixture_dir run_a run_b degraded

  run_check
  tmp_parent="${PROOF_ECONOMY_REPLAY_TRACE_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/proof-economy-replay-trace.XXXXXX")"
  fixture_dir="${tmp_root}/fixtures"
  mkdir -p "$fixture_dir"
  write_fixtures "$fixture_dir"

  run_a="${tmp_root}/run-a"
  "$normalizer" \
    --br-ready-json "${fixture_dir}/ready.json" \
    --br-in-progress-json "${fixture_dir}/in_progress.json" \
    --agent-mail-reservations-json "${fixture_dir}/reservations.json" \
    --resource-lease-plans-json "${fixture_dir}/leases.json" \
    --proof-cache-plan-json "${fixture_dir}/proof_cache.json" \
    --resident-bundle-report-json "${fixture_dir}/resident_bundle.json" \
    --no-mock-drill-report-json "${fixture_dir}/no_mock_drill.json" \
    --source-revision fixture-rev \
    --output-dir "$run_a" >/dev/null

  jq -e '
    .schema_version == "franken-engine.proof-economy-replay-trace.v1"
    and .degraded_mode == false
    and .summary.agent_count == 3
    and .summary.bead_count == 3
    and .summary.reservation_count == 2
    and .summary.command_count == 2
    and (.summary.proof_artifact_count >= 5)
    and any(.proof_rows[]; .artifact_path == "artifacts/proofs/proof-alpha.json")
    and ([.proof_rows[] | select(.artifact_path == "artifacts/proofs/proof-alpha.json")] | length) == 1
  ' "${run_a}/replay_trace.normalized.json" >/dev/null
  record_pass "balanced fixture normalizes and deduplicates proof rows"

  run_b="${tmp_root}/run-b"
  "$normalizer" \
    --br-ready-json "${fixture_dir}/ready.json" \
    --br-in-progress-json "${fixture_dir}/in_progress.json" \
    --agent-mail-reservations-json "${fixture_dir}/reservations.json" \
    --resource-lease-plans-json "${fixture_dir}/leases.json" \
    --proof-cache-plan-json "${fixture_dir}/proof_cache.json" \
    --resident-bundle-report-json "${fixture_dir}/resident_bundle.json" \
    --no-mock-drill-report-json "${fixture_dir}/no_mock_drill.json" \
    --source-revision fixture-rev \
    --output-dir "$run_b" >/dev/null
  diff -u \
    <(jq -cS 'del(.artifact_paths)' "${run_a}/replay_trace.normalized.json") \
    <(jq -cS 'del(.artifact_paths)' "${run_b}/replay_trace.normalized.json") >/dev/null
  record_pass "repeated fixture trace is deterministic"

  degraded="${tmp_root}/degraded"
  "$normalizer" \
    --br-ready-json "${fixture_dir}/ready.json" \
    --br-in-progress-json "${fixture_dir}/in_progress.json" \
    --resource-lease-plans-json "${fixture_dir}/leases.json" \
    --source-revision fixture-rev \
    --output-dir "$degraded" >/dev/null
  jq -e '
    .degraded_mode == true
    and .input_statuses.agent_mail_reservations == "missing"
    and any(.findings[]; .code == "missing_agent_mail_reservations")
  ' "${degraded}/replay_trace.normalized.json" >/dev/null
  record_pass "missing Agent Mail snapshot degrades explicitly"

  printf 'proof_economy_replay_trace_smoke_artifacts=%s\n' "$tmp_root"
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
