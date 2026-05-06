#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
advisory="${root_dir}/scripts/swarm_warm_target_prefetch_roi_advisory.sh"
contract_json="${root_dir}/docs/swarm_warm_target_prefetch_roi_advisory_contract_v1.json"

record_pass() {
  printf 'PASS swarm-warm-target-prefetch-roi-advisory %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-warm-target-prefetch-roi-advisory %s\n' "$1" >&2
}

write_forecast_fixture() {
  local output_path="$1"
  local scenario="$2"
  local overall_state="normal"
  local disk_state="normal"
  local proof_state="normal"

  case "$scenario" in
    high_roi|low_roi|stale_cache|missing_archive|salvage_pinned)
      ;;
    disk_pressure)
      overall_state="degraded"
      disk_state="degraded"
      proof_state="degraded"
      ;;
    *)
      record_failure "unknown forecast scenario ${scenario}"
      return 1
      ;;
  esac

  # shellcheck disable=SC2094
  jq -n \
    --arg output_path "$output_path" \
    --arg overall_state "$overall_state" \
    --arg disk_state "$disk_state" \
    --arg proof_state "$proof_state" \
    '{
      schema_version: "franken-engine.swarm-capacity-forecast.v1",
      decision: "pass",
      summary: {
        overall_state: $overall_state
      },
      forecasts: {
        disk_memory_pressure: {state: $disk_state},
        proof_availability: {state: $proof_state}
      },
      artifact_paths: {
        swarm_capacity_forecast_json: $output_path
      }
    }' >"$output_path"
}

write_admission_fixture() {
  local output_path="$1"

  # shellcheck disable=SC2094
  jq -n \
    --arg output_path "$output_path" \
    '{
      schema_version: "franken-engine.swarm-admission-budget-plan.v1",
      decision: "admit_narrow",
      budget_profile: "degraded",
      recommendations: [
        {
          request_id: "req-1",
          agent_id: "AgentAlpha",
          bead_id: "bd-prefetch",
          bead_priority: 2,
          decision: "admit_narrow",
          proof_obligation: true,
          budget_class: "protected"
        }
      ],
      artifact_paths: {
        swarm_admission_budget_plan_json: $output_path
      }
    }' >"$output_path"
}

write_cache_fixture() {
  local output_path="$1"
  local scenario="$2"
  local decision="cache_hit"
  local reason="all requested proof artifacts are safely reusable"
  local cache_hits='[{"artifact_id":"proof-hot-1","artifact_path":"/cache/proof-hot-1","reason":"fresh proof artifact may be reused"}]'
  local refreshes='[]'
  local refresh_commands='[]'
  local invalid='[]'

  case "$scenario" in
    high_roi|low_roi|disk_pressure|salvage_pinned)
      ;;
    stale_cache|missing_archive)
      decision="refresh_required"
      reason="all matching proof artifacts require refresh before reuse"
      cache_hits='[]'
      refreshes='[{"artifact_id":"proof-refresh-1","artifact_path":"/archive/proof-refresh-1","refresh_command":"rch exec -- env CARGO_TARGET_DIR=/tmp/prefetch cargo test -p frankenengine-engine --lib","reason":"freshness report requires refresh"}]'
      refresh_commands='["rch exec -- env CARGO_TARGET_DIR=/tmp/prefetch cargo test -p frankenengine-engine --lib"]'
      ;;
    *)
      record_failure "unknown cache scenario ${scenario}"
      return 1
      ;;
  esac

  # shellcheck disable=SC2094
  jq -n \
    --arg output_path "$output_path" \
    --arg decision "$decision" \
    --arg reason "$reason" \
    --argjson cache_hits "$cache_hits" \
    --argjson refreshes "$refreshes" \
    --argjson refresh_commands "$refresh_commands" \
    --argjson invalid "$invalid" \
    '{
      schema_version: "franken-engine.proof-reuse-cache-plan.v1",
      proof_cache_decision: $decision,
      reason: $reason,
      cache_hit_artifacts: $cache_hits,
      required_refreshes: $refreshes,
      invalid_artifacts: $invalid,
      invalidated_paths: [],
      refresh_commands: $refresh_commands,
      summary: {
        cache_hit_count: ($cache_hits | length),
        refresh_count: ($refreshes | length),
        invalid_count: ($invalid | length)
      },
      artifact_paths: {
        proof_cache_plan_json: $output_path
      }
    }' >"$output_path"
}

write_roi_fixture() {
  local output_path="$1"
  local scenario="$2"
  local decision="retain"
  local recommended_action="retain_warm_target"
  local reason="realized reuse value meets or exceeds expectation under bounded pressure"
  local expected=8
  local realized=10
  local delta=2
  local findings='["high_realized_reuse_value"]'

  case "$scenario" in
    high_roi|stale_cache|missing_archive|salvage_pinned)
      ;;
    low_roi)
      decision="evict"
      recommended_action="evict_warm_target"
      reason="warm target reuse value does not justify continued residency under current conditions"
      expected=8
      realized=5
      delta=-3
      findings='["low_realized_reuse_value"]'
      ;;
    disk_pressure)
      decision="evict"
      recommended_action="evict_warm_target"
      reason="critical disk or memory pressure overrides warm-target reuse value"
      expected=8
      realized=8
      delta=0
      findings='["critical_pressure_forced_eviction"]'
      ;;
    *)
      record_failure "unknown roi scenario ${scenario}"
      return 1
      ;;
  esac

  # shellcheck disable=SC2094
  jq -n \
    --arg output_path "$output_path" \
    --arg decision "$decision" \
    --arg recommended_action "$recommended_action" \
    --arg reason "$reason" \
    --argjson expected "$expected" \
    --argjson realized "$realized" \
    --argjson delta "$delta" \
    --argjson findings "$findings" \
    '{
      schema_version: "franken-engine.warm-target-roi-eviction-ledger.v1",
      bundle_id: "bundle-prefetch",
      worker_id: "vmi1156319",
      target_dir: "/tmp/rch_target_bundle_prefetch",
      decision: $decision,
      recommended_action: $recommended_action,
      reason: $reason,
      policy_findings: $findings,
      roi: {
        expected_reuse_score: $expected,
        realized_reuse_score: $realized,
        reuse_delta: $delta
      },
      artifact_paths: {
        warm_target_roi_ledger_json: $output_path
      }
    }' >"$output_path"
}

write_archive_fixture() {
  local output_path="$1"
  local scenario="$2"
  local advisory="retain"
  local action="retain_current_residency"
  local reason="bounded archive pressure does not justify eviction or compaction"
  local pressure="low"
  local findings='["low_pressure_retain"]'

  case "$scenario" in
    high_roi|low_roi|disk_pressure|stale_cache)
      ;;
    missing_archive)
      advisory="fail_closed"
      action="manual_review_required"
      reason="archive pack does not contain archived artifact evidence"
      pressure="elevated"
      findings='["insufficient_advisory_truth"]'
      ;;
    salvage_pinned)
      advisory="fail_closed"
      action="preserve_pinned_evidence"
      reason="salvage-pinned evidence prevents honest pressure relief"
      pressure="critical"
      findings='["salvage_pinned_blocks_eviction"]'
      ;;
    *)
      record_failure "unknown archive scenario ${scenario}"
      return 1
      ;;
  esac

  # shellcheck disable=SC2094
  jq -n \
    --arg output_path "$output_path" \
    --arg advisory "$advisory" \
    --arg action "$action" \
    --arg reason "$reason" \
    --arg pressure "$pressure" \
    --argjson findings "$findings" \
    '{
      schema_version: "franken-engine.remote-proof-archive-pressure-scoreboard.v1",
      bundle_id: "bundle-prefetch",
      pressure_level: $pressure,
      advisory: $advisory,
      recommended_action: $action,
      reason: $reason,
      policy_findings: $findings,
      artifact_paths: {
        remote_proof_archive_pressure_scoreboard_json: $output_path
      }
    }' >"$output_path"
}

write_trace_fixture() {
  local output_path="$1"
  local scenario="$2"
  local commands

  case "$scenario" in
    high_roi|stale_cache|missing_archive|salvage_pinned)
      commands='[
        {"agent_id":"AgentAlpha","bead_id":"bd-prefetch","requested_command":"rch exec -- env CARGO_TARGET_DIR=/tmp/one cargo test -p frankenengine-engine --lib","estimated_cpu_slots":4,"memory_class":"large"},
        {"agent_id":"AgentBeta","bead_id":"bd-prefetch","requested_command":"rch exec -- env CARGO_TARGET_DIR=/tmp/two cargo test -p frankenengine-engine --lib","estimated_cpu_slots":4,"memory_class":"large"}
      ]'
      ;;
    low_roi|disk_pressure)
      commands='[
        {"agent_id":"AgentAlpha","bead_id":"bd-prefetch","requested_command":"rch exec -- env CARGO_TARGET_DIR=/tmp/one cargo check -p frankenengine-engine --lib","estimated_cpu_slots":1,"memory_class":"small"}
      ]'
      ;;
    *)
      record_failure "unknown trace scenario ${scenario}"
      return 1
      ;;
  esac

  # shellcheck disable=SC2094
  jq -n \
    --arg output_path "$output_path" \
    --argjson commands "$commands" \
    '{
      schema_version: "franken-engine.proof-economy-replay-trace.v1",
      command_rows: $commands,
      artifact_paths: {
        replay_trace_json: $output_path
      }
    }' >"$output_path"
}

run_case() {
  local scenario="$1"
  local expected_advisory="$2"
  local expected_action="$3"
  local expected_exit="$4"
  local work_dir
  work_dir="$(mktemp -d)"

  write_forecast_fixture "${work_dir}/forecast.json" "$scenario"
  write_admission_fixture "${work_dir}/admission.json"
  write_cache_fixture "${work_dir}/cache.json" "$scenario"
  write_roi_fixture "${work_dir}/roi.json" "$scenario"
  write_archive_fixture "${work_dir}/archive.json" "$scenario"
  write_trace_fixture "${work_dir}/trace.json" "$scenario"

  local rc=0
  "${advisory}" \
    --capacity-forecast-json "${work_dir}/forecast.json" \
    --admission-budget-plan-json "${work_dir}/admission.json" \
    --proof-cache-plan-json "${work_dir}/cache.json" \
    --warm-target-roi-ledger-json "${work_dir}/roi.json" \
    --archive-pressure-scoreboard-json "${work_dir}/archive.json" \
    --replay-trace-json "${work_dir}/trace.json" \
    --source-revision smoke \
    --output-dir "${work_dir}/out" >/dev/null 2>&1 || rc=$?

  if [[ "$rc" -ne "$expected_exit" ]]; then
    record_failure "${scenario}: exit ${rc} != ${expected_exit}"
    return 1
  fi

  local output="${work_dir}/out/swarm_warm_target_prefetch_roi_advisory.json"
  jq -e --arg advisory "$expected_advisory" '.advisory == $advisory' "$output" >/dev/null
  jq -e --arg action "$expected_action" '.recommended_action == $action' "$output" >/dev/null
  jq -e '.hash_basis.advisory_hash | length > 0' "$output" >/dev/null
  jq -e '.artifact_paths.swarm_warm_target_prefetch_roi_advisory_json | type == "string"' "$output" >/dev/null
  test -s "${work_dir}/out/events.jsonl"
  test -s "${work_dir}/out/commands.txt"
  test -s "${work_dir}/out/report.md"
  record_pass "$scenario"
}

run_check() {
  jq -e '
    .schema_version == "franken-engine.swarm-warm-target-prefetch-roi-advisory-contract.v1"
    and (.advisory_schema_version == "franken-engine.swarm-warm-target-prefetch-roi-advisory.v1")
  ' "$contract_json" >/dev/null

  run_case high_roi reuse_hot_cache retain_target_and_reuse_cache 0
  run_case low_roi defer defer_prefetch_low_roi 75
  run_case disk_pressure defer defer_prefetch_pressure 75
  run_case stale_cache prefetch_archive prefetch_archive_and_retain_target 0
  run_case missing_archive fail_closed defer_until_archive_materialized 42
  run_case salvage_pinned fail_closed preserve_pinned_evidence 42
}

run_selftest() {
  local work_a work_b hash_a hash_b
  work_a="$(mktemp -d)"
  work_b="$(mktemp -d)"

  write_forecast_fixture "${work_a}/forecast.json" high_roi
  write_admission_fixture "${work_a}/admission.json"
  write_cache_fixture "${work_a}/cache.json" high_roi
  write_roi_fixture "${work_a}/roi.json" high_roi
  write_archive_fixture "${work_a}/archive.json" high_roi
  write_trace_fixture "${work_a}/trace.json" high_roi

  cp "${work_a}/forecast.json" "${work_b}/forecast.json"
  cp "${work_a}/admission.json" "${work_b}/admission.json"
  cp "${work_a}/cache.json" "${work_b}/cache.json"
  cp "${work_a}/roi.json" "${work_b}/roi.json"
  cp "${work_a}/archive.json" "${work_b}/archive.json"
  cp "${work_a}/trace.json" "${work_b}/trace.json"

  "${advisory}" \
    --capacity-forecast-json "${work_a}/forecast.json" \
    --admission-budget-plan-json "${work_a}/admission.json" \
    --proof-cache-plan-json "${work_a}/cache.json" \
    --warm-target-roi-ledger-json "${work_a}/roi.json" \
    --archive-pressure-scoreboard-json "${work_a}/archive.json" \
    --replay-trace-json "${work_a}/trace.json" \
    --source-revision selftest \
    --output-dir "${work_a}/out" >/dev/null

  "${advisory}" \
    --capacity-forecast-json "${work_b}/forecast.json" \
    --admission-budget-plan-json "${work_b}/admission.json" \
    --proof-cache-plan-json "${work_b}/cache.json" \
    --warm-target-roi-ledger-json "${work_b}/roi.json" \
    --archive-pressure-scoreboard-json "${work_b}/archive.json" \
    --replay-trace-json "${work_b}/trace.json" \
    --source-revision selftest \
    --output-dir "${work_b}/out" >/dev/null

  hash_a="$(jq -r '.hash_basis.advisory_hash' "${work_a}/out/swarm_warm_target_prefetch_roi_advisory.json")"
  hash_b="$(jq -r '.hash_basis.advisory_hash' "${work_b}/out/swarm_warm_target_prefetch_roi_advisory.json")"
  if [[ "$hash_a" != "$hash_b" ]]; then
    record_failure "selftest: advisory hash drift"
    return 1
  fi
  record_pass selftest
}

mode="${1:-check}"
case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode ${mode}"
    exit 64
    ;;
esac
