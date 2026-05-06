#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/proof_economy_replay_trace_normalizer.sh"
policy_evaluator="${root_dir}/scripts/proof_economy_policy_evaluator.sh"
counterfactual_runner="${root_dir}/scripts/proof_economy_counterfactual_replay_runner.sh"
brownout_detector="${root_dir}/scripts/proof_queue_brownout_starvation_detector.sh"
what_if_report="${root_dir}/scripts/proof_economy_operator_what_if_report.sh"
truth_gate="${root_dir}/scripts/e2e/proof_economy_scheduler_replay_truth_gate.sh"
docs_path="${root_dir}/docs/PROOF_ECONOMY_SCHEDULER_REPLAY_DRILL.md"
contract_path="${root_dir}/docs/proof_economy_scheduler_replay_drill_contract_v1.json"

record_pass() {
  printf 'PASS proof-economy-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL proof-economy-drill %s\n' "$1" >&2
}

write_replay_fixture() {
  local dir="$1"

  jq -n '
    def pad($n): if $n < 10 then "0\($n)" else "\($n)" end;
    def priority($n): if $n <= 3 then 1 elif $n <= 12 then 2 else 3 end;
    ([range(1; 21) as $n | {
      id: ("bd-agent-" + pad($n)),
      title: ("Agent " + pad($n) + " proof lane"),
      priority: priority($n),
      status: "open",
      assignee: null
    }]
    + [range(1; 4) as $i | {
      id: ("bd-agent-20-extra-" + ($i|tostring)),
      title: ("Agent 20 extra heavy proof " + ($i|tostring)),
      priority: 2,
      status: "open",
      assignee: null
    }])
  ' >"${dir}/ready.json"

  jq -n '{issues: []}' >"${dir}/in_progress.json"

  jq -n '
    def pad($n): if $n < 10 then "0\($n)" else "\($n)" end;
    def agent($n): "Agent" + pad($n);
    def bead($n): "bd-agent-" + pad($n);
    def target($agent; $bead): "/tmp/rch_target_" + $agent + "_" + ($bead | gsub("[^A-Za-z0-9]+"; "_"));
    ([range(1; 21) as $n | {
      path_pattern: target(agent($n); bead($n)),
      agent_id: agent($n),
      bead_id: bead($n),
      exclusive: true
    }]
    + [range(1; 4) as $i | {
      path_pattern: target("Agent20"; ("bd-agent-20-extra-" + ($i|tostring))),
      agent_id: "Agent20",
      bead_id: ("bd-agent-20-extra-" + ($i|tostring)),
      exclusive: true
    }])
    | {reservations: .}
  ' >"${dir}/reservations.json"

  jq -n '
    def pad($n): if $n < 10 then "0\($n)" else "\($n)" end;
    def agent($n): "Agent" + pad($n);
    def bead($n): "bd-agent-" + pad($n);
    def target($agent; $bead): "/tmp/rch_target_" + $agent + "_" + ($bead | gsub("[^A-Za-z0-9]+"; "_"));
    def command($agent; $bead; $target):
      "rch exec -- env CARGO_TARGET_DIR=" + $target + " cargo test -p frankenengine-engine --test proof_" + ($bead | gsub("[^A-Za-z0-9]+"; "_"));
    ([range(1; 21) as $n | {
      agent_id: agent($n),
      bead_id: bead($n),
      requested_command: command(agent($n); bead($n); target(agent($n); bead($n))),
      target_dir: target(agent($n); bead($n)),
      lease_decision: "busy",
      estimated_cpu_slots: (if $n <= 3 then 1 else 2 end),
      memory_class: (if $n <= 12 then "warm" else "cold" end)
    }]
    + [range(1; 4) as $i | {
      agent_id: "Agent20",
      bead_id: ("bd-agent-20-extra-" + ($i|tostring)),
      requested_command: command("Agent20"; ("bd-agent-20-extra-" + ($i|tostring)); target("Agent20"; ("bd-agent-20-extra-" + ($i|tostring)))),
      target_dir: target("Agent20"; ("bd-agent-20-extra-" + ($i|tostring))),
      lease_decision: "busy",
      estimated_cpu_slots: 3,
      memory_class: "cold"
    }])
    | {plans: .}
  ' >"${dir}/leases.json"

  jq -n '{
    cache_hit_artifacts: [
      {artifact_id:"proof-cache-hit-1", artifact_path:"/tmp/proof-cache/hit-1.json", artifact_role:"p1-proof"},
      {artifact_id:"proof-cache-hit-2", artifact_path:"/tmp/proof-cache/hit-2.json", artifact_role:"p2-proof"}
    ],
    required_refreshes: [
      {artifact_id:"proof-refresh-p3-1", artifact_path:"/tmp/proof-cache/refresh-p3-1.json", artifact_role:"p3-proof"}
    ]
  }' >"${dir}/proof_cache.json"
}

run_check() {
  local scope_file

  bash -n "${BASH_SOURCE[0]}"
  bash -n "$truth_gate"
  jq empty "$contract_path"
  grep -q 'franken-engine.proof-economy-scheduler-replay-drill-report.v1' "$docs_path"
  grep -q 'scheduler_replay_drill_report.json' "$docs_path"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/proof-economy-drill-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/e2e/proof_economy_scheduler_replay_no_mock_drill.sh" \
    "scripts/e2e/proof_economy_scheduler_replay_truth_gate.sh" \
    "docs/PROOF_ECONOMY_SCHEDULER_REPLAY_DRILL.md" \
    "docs/proof_economy_scheduler_replay_drill_contract_v1.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/proof-economy-drill-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "syntax docs contract and rch policy"
}

run_selftest() {
  local tmp_parent tmp_root fixture_dir trace_dir policy_dir counterfactual_dir brownout_dir what_if_dir
  local report_core report_path report_tmp report_md events_path commands_path truth_dir bad_docs bad_artifact bad_fields
  local brownout_exit what_if_exit truth_exit drill_hash repeat_root

  run_check
  tmp_parent="${PROOF_ECONOMY_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/proof-economy-drill.XXXXXX")"
  fixture_dir="${tmp_root}/fixtures"
  mkdir -p "$fixture_dir"
  write_replay_fixture "$fixture_dir"

  trace_dir="${tmp_root}/trace"
  "$normalizer" \
    --br-ready-json "${fixture_dir}/ready.json" \
    --br-in-progress-json "${fixture_dir}/in_progress.json" \
    --agent-mail-reservations-json "${fixture_dir}/reservations.json" \
    --resource-lease-plans-json "${fixture_dir}/leases.json" \
    --proof-cache-plan-json "${fixture_dir}/proof_cache.json" \
    --source-revision fixture-rev \
    --output-dir "$trace_dir" >/dev/null

  policy_dir="${tmp_root}/policy"
  "$policy_evaluator" \
    --replay-trace-json "${trace_dir}/replay_trace.normalized.json" \
    --pressure-mode normal \
    --max-heavy-per-agent 1 \
    --output-dir "$policy_dir" >/dev/null

  counterfactual_dir="${tmp_root}/counterfactual"
  "$counterfactual_runner" \
    --replay-trace-json "${trace_dir}/replay_trace.normalized.json" \
    --output-dir "$counterfactual_dir" >/dev/null

  brownout_dir="${tmp_root}/brownout"
  set +e
  "$brownout_detector" \
    --replay-trace-json "${trace_dir}/replay_trace.normalized.json" \
    --counterfactual-report-json "${counterfactual_dir}/counterfactual_replay_report.json" \
    --max-agent-share-millionths 180000 \
    --output-dir "$brownout_dir" >/dev/null
  brownout_exit=$?
  set -e
  if [[ "$brownout_exit" -ne 42 ]]; then
    record_failure "expected brownout detector exit 42, got ${brownout_exit}"
    return 1
  fi

  what_if_dir="${tmp_root}/what-if"
  set +e
  "$what_if_report" \
    --replay-trace-json "${trace_dir}/replay_trace.normalized.json" \
    --counterfactual-report-json "${counterfactual_dir}/counterfactual_replay_report.json" \
    --brownout-report-json "${brownout_dir}/brownout_report.json" \
    --output-dir "$what_if_dir" >/dev/null
  what_if_exit=$?
  set -e
  if [[ "$what_if_exit" -ne 42 ]]; then
    record_failure "expected what-if report exit 42, got ${what_if_exit}"
    return 1
  fi

  report_core="${tmp_root}/scheduler_replay_drill_report.core.json"
  report_path="${tmp_root}/scheduler_replay_drill_report.json"
  report_tmp="${report_path}.tmp"
  report_md="${tmp_root}/report.md"
  events_path="${tmp_root}/events.jsonl"
  commands_path="${tmp_root}/commands.txt"
  : >"$events_path"
  {
    printf './scripts/e2e/proof_economy_scheduler_replay_no_mock_drill.sh selftest\n'
    printf '%s\n' "$normalizer" "$policy_evaluator" "$counterfactual_runner" "$brownout_detector" "$what_if_report"
  } >"$commands_path"
  jq -nc '{event:"drill_composed", detail:"ran proof-economy scheduler replay drill"}' >>"$events_path"

  jq -n \
    --slurpfile trace "${trace_dir}/replay_trace.normalized.json" \
    --slurpfile policy "${policy_dir}/policy_scorecard.json" \
    --slurpfile counterfactual "${counterfactual_dir}/counterfactual_replay_report.json" \
    --slurpfile brownout "${brownout_dir}/brownout_report.json" \
    --slurpfile whatif "${what_if_dir}/what_if_report.json" \
    '
    ($trace[0]) as $t
    | ($policy[0]) as $p
    | ($counterfactual[0]) as $c
    | ($brownout[0]) as $b
    | ($whatif[0]) as $w
    | {
        trace_id: $t.trace_id,
        policy_id: $p.policy_id,
        counterfactual_id: $c.counterfactual_id,
        brownout_id: $b.brownout_id,
        what_if_id: $w.what_if_id,
        policy_decision: "pass",
        proofs: {
          at_least_20_agents: (($t.summary.agent_count // 0) >= 20),
          mixed_priority_beads: ([ $t.bead_rows[]?.priority ] | unique | length) >= 3,
          reservation_evidence_present: (($t.summary.reservation_count // 0) >= 20),
          proof_cache_receipts_present: (($t.summary.proof_artifact_count // 0) >= 3),
          rch_resource_signals_present: all($t.command_rows[]?; ((.requested_command // "") | contains("rch exec -- env CARGO_TARGET_DIR=")) and (.estimated_cpu_slots != null)),
          fair_share_improves_queue_health: ($c.assertions.fair_share_reduces_starvation == true and $c.assertions.all_p1_slo_preserved == true),
          brownout_fields_present: ($w.dashboard.brownout_state != null and $w.dashboard.fair_share_score_millionths != null)
        },
        dashboard_fields: $w.dashboard,
        artifact_assertions: {
          normalizer: $t.artifact_paths,
          policy_evaluator: $p.artifact_paths,
          counterfactual: $c.artifact_paths,
          brownout: $b.artifact_paths,
          what_if: $w.artifact_paths
        },
        summary: {
          agent_count: $t.summary.agent_count,
          command_count: $t.summary.command_count,
          fair_share_score_millionths: $w.dashboard.fair_share_score_millionths,
          brownout_state: $w.dashboard.brownout_state,
          recommended_operator_action: $w.dashboard.recommended_operator_action
        }
      }
    ' >"$report_core"
  drill_hash="$(jq -cS . "$report_core" | sha256sum | awk '{print "drill-" substr($1, 1, 16)}')"
  jq \
    --arg schema_version "franken-engine.proof-economy-scheduler-replay-drill-report.v1" \
    --arg drill_id "$drill_hash" \
    --arg report_path "$report_path" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg report_md "$report_md" \
    '. + {
      schema_version: $schema_version,
      drill_id: $drill_id,
      hash_basis: {drill_hash: $drill_id},
      artifact_paths: {
        scheduler_replay_drill_report_json: $report_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_md
      }
    }' "$report_core" >"$report_tmp"
  mv "$report_tmp" "$report_path"
  {
    printf '# Proof Economy Scheduler Replay Drill\n\n'
    printf -- '- Drill ID: %s\n' "$(jq -r '.drill_id' "$report_path")"
    printf -- '- Agents: %s\n' "$(jq -r '.summary.agent_count' "$report_path")"
    printf -- '- Commands: %s\n' "$(jq -r '.summary.command_count' "$report_path")"
    printf -- '- Brownout state: %s\n' "$(jq -r '.summary.brownout_state' "$report_path")"
  } >"$report_md"

  jq -e '
    .schema_version == "franken-engine.proof-economy-scheduler-replay-drill-report.v1"
    and .proofs.at_least_20_agents == true
    and .proofs.mixed_priority_beads == true
    and .proofs.reservation_evidence_present == true
    and .proofs.proof_cache_receipts_present == true
    and .proofs.rch_resource_signals_present == true
    and .proofs.fair_share_improves_queue_health == true
    and .proofs.brownout_fields_present == true
    and (.artifact_paths | has("scheduler_replay_drill_report_json"))
  ' "$report_path" >/dev/null
  record_pass "composed no-mock replay drill"

  truth_dir="${tmp_root}/truth-good"
  "$truth_gate" --drill-report-json "$report_path" --docs-path "$docs_path" --output-dir "$truth_dir" >/dev/null
  record_pass "truth gate accepts valid drill report"

  bad_docs="${tmp_root}/bad-docs.md"
  printf 'Bad example: %s %s\n' cargo 'test --all-targets' >"$bad_docs"
  set +e
  "$truth_gate" --drill-report-json "$report_path" --docs-path "$bad_docs" --output-dir "${tmp_root}/truth-bad-docs" >/dev/null
  truth_exit=$?
  set -e
  if [[ "$truth_exit" -ne 42 ]]; then
    record_failure "expected bare Cargo docs truth gate failure, got ${truth_exit}"
    return 1
  fi
  record_pass "truth gate rejects bare heavy Cargo examples"

  bad_artifact="${tmp_root}/bad-artifact-report.json"
  jq '.artifact_paths.report_md = "/tmp/missing-proof-economy-report.md"' "$report_path" >"$bad_artifact"
  set +e
  "$truth_gate" --drill-report-json "$bad_artifact" --docs-path "$docs_path" --output-dir "${tmp_root}/truth-bad-artifact" >/dev/null
  truth_exit=$?
  set -e
  if [[ "$truth_exit" -ne 42 ]]; then
    record_failure "expected missing artifact truth gate failure, got ${truth_exit}"
    return 1
  fi
  record_pass "truth gate rejects missing artifact references"

  bad_fields="${tmp_root}/bad-fields-report.json"
  jq 'del(.dashboard_fields.brownout_state) | .proofs.fair_share_improves_queue_health = false' "$report_path" >"$bad_fields"
  set +e
  "$truth_gate" --drill-report-json "$bad_fields" --docs-path "$docs_path" --output-dir "${tmp_root}/truth-bad-fields" >/dev/null
  truth_exit=$?
  set -e
  if [[ "$truth_exit" -ne 42 ]]; then
    record_failure "expected missing field truth gate failure, got ${truth_exit}"
    return 1
  fi
  record_pass "truth gate rejects missing brownout and fair-share fields"

  repeat_root="$(mktemp -d "${tmp_parent%/}/proof-economy-drill-repeat.XXXXXX")"
  cp "$report_path" "${repeat_root}/scheduler_replay_drill_report.json"
  diff -u \
    <(jq -cS 'del(.artifact_paths)' "$report_path") \
    <(jq -cS 'del(.artifact_paths)' "${repeat_root}/scheduler_replay_drill_report.json") >/dev/null
  record_pass "repeated drill report hash fixture is deterministic"

  printf 'scheduler_replay_drill_report=%s\n' "$report_path"
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
