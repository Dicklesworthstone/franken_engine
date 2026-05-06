#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract_json="${root_dir}/docs/swarm_checkpoint_bundle_contract_v1.json"
contract_doc="${root_dir}/docs/SWARM_CHECKPOINT_BUNDLE_CONTRACT.md"

record_pass() {
  printf 'PASS swarm-checkpoint-bundle-contract %s\n' "$1"
}

record_fail() {
  printf 'FAIL swarm-checkpoint-bundle-contract %s\n' "$1" >&2
  exit 1
}

write_json() {
  local path="$1"
  local content="$2"
  printf '%s\n' "$content" >"$path"
}

bundle_value() {
  local bundle="$1"
  local dotted_path="$2"
  jq -e --arg dotted_path "$dotted_path" '
    def dotted_get($path):
      reduce ($path | split("."))[] as $segment
        (.;
          if . == null then null else .[$segment] end
        );
    dotted_get($dotted_path) != null
  ' "$bundle" >/dev/null
}

validate_bundle_against_contract() {
  local bundle="$1"

  jq -e '.schema_version == "franken-engine.swarm-checkpoint-bundle.v1"' \
    "$bundle" >/dev/null || return 1

  while IFS= read -r dotted_path; do
    [[ -n "$dotted_path" ]] || continue
    bundle_value "$bundle" "$dotted_path" \
      || return 1
  done < <(jq -r '.required_top_level_fields[]' "$contract_json")

  while IFS= read -r ledger_key; do
    [[ -n "$ledger_key" ]] || continue
    jq -e --arg ledger_key "$ledger_key" \
      '.artifact_ledger[$ledger_key] != null' "$bundle" >/dev/null \
      || return 1
  done < <(jq -r '.required_artifact_ledger_entries[]' "$contract_json")

  jq -e '
    .capture_decision as $capture
    | .restore_readiness_hint as $hint
    | .blockers as $blockers
    | if ($capture == "fail_closed" and ($hint != "blocked")) then false
      elif (($blockers | length) > 0 and $hint == "candidate") then false
      else true
      end
  ' "$bundle" >/dev/null || return 1

  jq -e '
    [
      .artifact_ledger[]?
      | select(.trust_state == "local_fallback")
    ] as $local_fallback
    | if (($local_fallback | length) > 0)
      then (.capture_decision == "fail_closed" and .restore_readiness_hint == "blocked")
      else true
      end
  ' "$bundle" >/dev/null || return 1

  jq -e '
    [
      .artifact_ledger[]?
      | select(.required == true and .freshness_state != "fresh")
    ] as $stale_required
    | if (($stale_required | length) > 0)
      then (.capture_decision == "fail_closed" and .restore_readiness_hint == "blocked")
      else true
      end
  ' "$bundle" >/dev/null || return 1

  jq -e '
    [
      .artifact_ledger[]?
      | select(.required == false and (.trust_state == "missing" or .trust_state == "degraded"))
    ] as $optional_missing
    | if (($optional_missing | length) > 0)
      then (.capture_decision != "captured")
      else true
      end
  ' "$bundle" >/dev/null || return 1
}

assert_bundle_valid() {
  local bundle="$1"
  local label="$2"
  validate_bundle_against_contract "$bundle" \
    || record_fail "${label} failed bundle validation"
}

write_bundle() {
  local path="$1"
  local scenario="$2"

  local capture_decision="captured_degraded"
  local restore_hint="manual_review"
  local high_core_trust_state="missing"
  local proof_economy_trust_state="missing"
  local operator_slo_trust_state="degraded"
  local capacity_snapshot_freshness="fresh"
  local local_fallback_trust_state="primary"
  local blockers='[
    {
      "code": "optional_evidence_degraded",
      "detail": "Optional evidence remains missing or degraded and cannot upgrade trust."
    }
  ]'

  case "$scenario" in
    healthy)
      capture_decision="captured"
      restore_hint="candidate"
      high_core_trust_state="optional"
      proof_economy_trust_state="optional"
      operator_slo_trust_state="optional"
      blockers='[]'
      ;;
    stale_required)
      capture_decision="fail_closed"
      restore_hint="blocked"
      capacity_snapshot_freshness="stale"
      blockers='[
        {
          "code": "stale_required_artifact",
          "detail": "swarm_capacity_snapshot exceeded the configured freshness window."
        }
      ]'
      ;;
    local_fallback)
      capture_decision="fail_closed"
      restore_hint="blocked"
      local_fallback_trust_state="local_fallback"
      blockers='[
        {
          "code": "local_fallback_heavy_proof_contamination",
          "detail": "remote proof truth degraded into local fallback."
        }
      ]'
      ;;
    *)
      record_fail "unknown bundle scenario ${scenario}"
      ;;
  esac

  write_json "$path" "$(jq -n \
    --arg capture_decision "$capture_decision" \
    --arg restore_hint "$restore_hint" \
    --arg high_core_trust_state "$high_core_trust_state" \
    --arg proof_economy_trust_state "$proof_economy_trust_state" \
    --arg operator_slo_trust_state "$operator_slo_trust_state" \
    --arg capacity_snapshot_freshness "$capacity_snapshot_freshness" \
    --arg local_fallback_trust_state "$local_fallback_trust_state" \
    --argjson blockers "$blockers" \
    '{
      schema_version: "franken-engine.swarm-checkpoint-bundle.v1",
      checkpoint_id: "checkpoint-smoke",
      capture_decision: $capture_decision,
      restore_readiness_hint: $restore_hint,
      captured_epoch_seconds: 2000,
      stale_after_seconds: 1800,
      upstream_evidence: {
        required_count: 8,
        optional_count: 3,
        optional_present_count: (
          [ $high_core_trust_state, $proof_economy_trust_state, $operator_slo_trust_state ]
          | map(select(. == "optional"))
          | length
        )
      },
      artifact_ledger: {
        swarm_capacity_snapshot: {
          schema_version: "franken-engine.swarm-capacity-snapshot.v1",
          path: "/fixture/swarm_capacity_snapshot.json",
          trust_state: $local_fallback_trust_state,
          freshness_state: $capacity_snapshot_freshness,
          required: true
        },
        swarm_capacity_forecast: {
          schema_version: "franken-engine.swarm-capacity-forecast.v1",
          path: "/fixture/swarm_capacity_forecast.json",
          trust_state: "primary",
          freshness_state: "fresh",
          required: true
        },
        swarm_admission_budget_plan: {
          schema_version: "franken-engine.swarm-admission-budget-plan.v1",
          path: "/fixture/swarm_admission_budget_plan.json",
          trust_state: "primary",
          freshness_state: "fresh",
          required: true
        },
        remote_proof_archive_pressure_scoreboard: {
          schema_version: "franken-engine.remote-proof-archive-pressure-scoreboard.v1",
          path: "/fixture/remote_proof_archive_pressure_scoreboard.json",
          trust_state: "primary",
          freshness_state: "fresh",
          required: true
        },
        stale_lock_recommendations: {
          schema_version: "franken-engine.stale-lock-recommendations.v1",
          path: "/fixture/stale_lock_recommendations.json",
          trust_state: "primary",
          freshness_state: "fresh",
          required: true
        },
        swarm_lease_exchange_cancellation_salvage_simulation: {
          schema_version: "franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1",
          path: "/fixture/swarm_lease_exchange_cancellation_salvage_simulation.json",
          trust_state: "primary",
          freshness_state: "fresh",
          required: true
        },
        swarm_starvation_rescue_plan: {
          schema_version: "franken-engine.swarm-starvation-rescue-plan.v1",
          path: "/fixture/swarm_starvation_rescue_plan.json",
          trust_state: "primary",
          freshness_state: "fresh",
          required: true
        },
        swarm_operator_status_report: {
          schema_version: "franken-engine.swarm-operator-status-report.v1",
          path: "/fixture/swarm_operator_status_report.json",
          trust_state: "primary",
          freshness_state: "fresh",
          required: true
        },
        swarm_high_core_scenario_matrix_report: {
          schema_version: "franken-engine.swarm-high-core-scenario-matrix-report.v1",
          path: "/fixture/swarm_high_core_scenario_matrix_report.json",
          trust_state: $high_core_trust_state,
          freshness_state: "fresh",
          required: false
        },
        swarm_operator_slo_tuning_advisory: {
          schema_version: "franken-engine.swarm-operator-slo-tuning-advisory.v1",
          path: "/fixture/swarm_operator_slo_tuning_advisory.json",
          trust_state: $operator_slo_trust_state,
          freshness_state: "fresh",
          required: false
        },
        proof_economy_replay_trace: {
          schema_version: "franken-engine.proof-economy-replay-trace.v1",
          path: "/fixture/proof_economy_replay_trace.json",
          trust_state: $proof_economy_trust_state,
          freshness_state: "fresh",
          required: false
        }
      },
      blockers: $blockers,
      artifact_paths: {
        checkpoint_bundle_json: "/fixture/checkpoint_bundle.json",
        events_jsonl: "/fixture/events.jsonl",
        commands_txt: "/fixture/commands.txt",
        summary_md: "/fixture/summary.md"
      }
    }')"
}

run_check() {
  jq -e '
    .schema_version == "franken-engine.swarm-checkpoint-bundle-contract.v1"
    and .bundle_schema_version == "franken-engine.swarm-checkpoint-bundle.v1"
    and .planned_producer_script == "scripts/swarm_checkpoint_bundle_packer.sh"
    and (.required_inputs | length) == 8
    and (.optional_inputs | length) == 3
    and (.required_artifact_ledger_entries | length) == 8
    and (.required_artifact_paths | length) == 4
    and (.capture_decisions == ["captured","captured_degraded","fail_closed"])
    and (.restore_readiness_hints == ["candidate","manual_review","blocked"])
  ' "$contract_json" >/dev/null || record_fail "contract shape mismatch"

  jq -e '
    (.required_inputs | map(.name) | sort)
    == [
      "remote_proof_archive_pressure_scoreboard",
      "stale_lock_recommendations",
      "swarm_admission_budget_plan",
      "swarm_capacity_forecast",
      "swarm_capacity_snapshot",
      "swarm_lease_exchange_cancellation_salvage_simulation",
      "swarm_operator_status_report",
      "swarm_starvation_rescue_plan"
    ]
  ' "$contract_json" >/dev/null || record_fail "required input names drifted"

  jq -e '
    (.restore_blocking_rules | map(test("fail closed|manual-review|local-fallback")) | any)
  ' "$contract_json" >/dev/null || record_fail "restore blocking rules missing fail-closed language"

  rg -q "contract-only" "$contract_doc" \
    || record_fail "doc missing contract-only note"
  rg -q "advisory evidence only" "$contract_doc" \
    || record_fail "doc missing advisory-only note"
  rg -q "live reopen surface" "$contract_doc" \
    || record_fail "doc missing live-reopen prohibition"
  rg -q "local-fallback heavy-proof evidence" "$contract_doc" \
    || record_fail "doc missing local-fallback fail-closed rule"

  record_pass "check"
}

run_selftest() {
  local tmp_root
  tmp_root="$(mktemp -d)"
  trap 'rm -rf "${tmp_root:-}"' RETURN

  write_bundle "${tmp_root}/healthy.json" healthy
  assert_bundle_valid "${tmp_root}/healthy.json" "healthy"

  write_bundle "${tmp_root}/stale_required.json" stale_required
  assert_bundle_valid "${tmp_root}/stale_required.json" "stale_required"

  write_bundle "${tmp_root}/local_fallback.json" local_fallback
  assert_bundle_valid "${tmp_root}/local_fallback.json" "local_fallback"

  jq 'del(.artifact_ledger.swarm_operator_status_report)' \
    "${tmp_root}/healthy.json" >"${tmp_root}/missing_required.json"
  if validate_bundle_against_contract "${tmp_root}/missing_required.json"; then
    record_fail "missing required ledger entry unexpectedly passed"
  fi

  record_pass "selftest"
}

mode="${1:-check}"
case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_check
    run_selftest
    ;;
  *)
    printf 'usage: %s [check|selftest]\n' "${0##*/}" >&2
    exit 64
    ;;
esac
