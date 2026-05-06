#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/swarm_resource_envelope_normalizer.sh"
docs_path="${root_dir}/docs/SWARM_RESOURCE_ENVELOPE.md"
contract_path="${root_dir}/docs/swarm_resource_envelope_contract_v1.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS swarm-resource-envelope-normalizer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-resource-envelope-normalizer %s\n' "$1" >&2
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_resource_envelope_normalizer_smoke.sh [check|selftest]
EOF
}

write_common_fixtures() {
  local dir="$1"

  mkdir -p "$dir"
  jq -n '{
    schema_version:"franken-engine.host-topology-snapshot.v1",
    host_id:"host-64c-256g",
    hostname:"swarm-host-a",
    architecture:"x86_64",
    cpu_logical_cores:96,
    cpu_physical_cores:48,
    numa_nodes:2,
    load_average_1m:18,
    observed_at:"2026-05-06T20:00:00Z"
  }' >"${dir}/host_topology.json"
  jq -n '{
    schema_version:"franken-engine.memory-pressure-snapshot.v1",
    total_bytes:274877906944,
    available_bytes:206158430208,
    swap_available_bytes:34359738368,
    telemetry_complete:true,
    observed_at:"2026-05-06T20:00:00Z"
  }' >"${dir}/memory_pressure.json"
  jq -n '{
    schema_version:"franken-engine.disk-pressure-snapshot.v1",
    filesystems:[{mount:"/data", available_bytes:549755813888, available_inodes:4000000}],
    target_dirs:[{path:"/mnt/rch/franken_engine", available_bytes:322122547200, warm:true}],
    telemetry_complete:true,
    observed_at:"2026-05-06T20:00:00Z"
  }' >"${dir}/disk_pressure.json"
  jq -n '{
    schema_version:"franken-engine.rch-queue-status-snapshot.v1",
    host_id:"host-64c-256g",
    workers:[
      {worker_id:"rch-a", slots_total:8, slots_available:6},
      {worker_id:"rch-b", slots_total:8, slots_available:6}
    ],
    build_slots:{total:16, active:4, available:12},
    queue_depth:0,
    observed_at:"2026-05-06T20:00:00Z"
  }' >"${dir}/rch_queue.json"
  jq -n '{leases:[{slot:"compile", holder:"AgentAlpha", expires_ts:"2026-05-06T20:30:00Z"}]}' >"${dir}/rch_build_slot.json"
  jq -n '{proof_cache_decision:"cache_hit", cache_hit_artifacts:["proof-a.json"]}' >"${dir}/proof_cache.json"
  jq -n '{advisory:"prefetch_recommended", expected_savings_seconds:180}' >"${dir}/warm_target_roi.json"
  jq -n '{scoreboard_status:"ok", archive_pressure:"low"}' >"${dir}/archive_pressure.json"
  jq -n '[{id:"bd-next", title:"Next bead", status:"open", priority:1}]' >"${dir}/br_ready.json"
  jq -n '{issues:[{id:"bd-3q66g", status:"in_progress", assignee:"BrownCreek"}]}' >"${dir}/br_in_progress.json"
  jq -n '{dirty_count:0, db_newer:false, jsonl_newer:false}' >"${dir}/br_sync_status.json"
  jq -n '{plan:{tracks:[{track_id:"swarm-scale",items:[{id:"bd-3q66g",status:"in_progress"}]}]}}' >"${dir}/bv_plan.json"
  jq -n '{reservations:[{path_pattern:"scripts/swarm_resource_envelope_normalizer.sh", agent_name:"BrownCreek", exclusive:true}]}' >"${dir}/reservations.json"
  jq -n '{paths:["scripts/swarm_resource_envelope_normalizer.sh"]}' >"${dir}/write_set.json"
  jq -n '{decision:"pass", anomalies:[]}' >"${dir}/causal_trace.json"
  jq -n '{commands:[{display:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch cargo check -p frankenengine-engine --lib", cost_class:"heavy", budget_class:"build_lane"}]}' >"${dir}/validation_costs.json"
}

run_normalizer_full() {
  local fixture_dir="$1"
  local output_dir="$2"

  "$normalizer" \
    --bead-id bd-3q66g \
    --source-revision fixture-rev \
    --reference-time "2026-05-06T20:10:00Z" \
    --host-topology-json "${fixture_dir}/host_topology.json" \
    --memory-pressure-json "${fixture_dir}/memory_pressure.json" \
    --disk-pressure-json "${fixture_dir}/disk_pressure.json" \
    --rch-queue-status-json "${fixture_dir}/rch_queue.json" \
    --rch-build-slot-json "${fixture_dir}/rch_build_slot.json" \
    --proof-cache-plan-json "${fixture_dir}/proof_cache.json" \
    --warm-target-prefetch-roi-json "${fixture_dir}/warm_target_roi.json" \
    --archive-pressure-scoreboard-json "${fixture_dir}/archive_pressure.json" \
    --br-ready-json "${fixture_dir}/br_ready.json" \
    --br-in-progress-json "${fixture_dir}/br_in_progress.json" \
    --br-sync-status-json "${fixture_dir}/br_sync_status.json" \
    --bv-actionable-plan-json "${fixture_dir}/bv_plan.json" \
    --agent-mail-file-reservations-json "${fixture_dir}/reservations.json" \
    --declared-write-set-json "${fixture_dir}/write_set.json" \
    --causal-trace-summary-json "${fixture_dir}/causal_trace.json" \
    --validation-cost-hints-json "${fixture_dir}/validation_costs.json" \
    --output-dir "$output_dir" >/dev/null
}

run_normalizer_core_only() {
  local fixture_dir="$1"
  local output_dir="$2"

  "$normalizer" \
    --bead-id bd-3q66g \
    --source-revision fixture-rev \
    --reference-time "2026-05-06T20:10:00Z" \
    --host-topology-json "${fixture_dir}/host_topology.json" \
    --memory-pressure-json "${fixture_dir}/memory_pressure.json" \
    --disk-pressure-json "${fixture_dir}/disk_pressure.json" \
    --rch-queue-status-json "${fixture_dir}/rch_queue.json" \
    --output-dir "$output_dir" >/dev/null
}

expect_decision() {
  local expected_decision="$1"
  local expected_status="$2"
  local fixture_dir="$3"
  local output_dir="$4"
  local runner="${5:-run_normalizer_full}"
  local status

  set +e
  "$runner" "$fixture_dir" "$output_dir"
  status=$?
  set -e
  if [[ "$status" -ne "$expected_status" ]]; then
    record_failure "expected exit ${expected_status} for ${expected_decision}, got ${status}"
    return 1
  fi
  jq -e --arg decision "$expected_decision" '.decision == $decision' "${output_dir}/swarm_resource_envelope.json" >/dev/null
}

run_check() {
  bash -n "$normalizer"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  jq -e '
    (.normalizer.script == "scripts/swarm_resource_envelope_normalizer.sh")
    and (.normalizer.smoke_script == "scripts/e2e/swarm_resource_envelope_normalizer_smoke.sh")
    and (.normalizer.artifacts | index("swarm_resource_envelope.json") != null)
  ' "$contract_path" >/dev/null
  grep -q 'swarm_resource_envelope.json' "$docs_path"
  grep -q 'fixture-fed' "$docs_path"
  record_pass "syntax docs and contract"
}

run_selftest() {
  local tmp_root
  local healthy
  local degraded
  local blocked
  local contaminated
  local contradictory
  local unsafe

  tmp_root="${TMPDIR:-/tmp}/franken-engine-swarm-resource-envelope-normalizer-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  healthy="${tmp_root}/healthy_high_core_host"
  degraded="${tmp_root}/degraded_missing_memory_telemetry"
  blocked="${tmp_root}/blocked_saturated_capacity"
  contaminated="${tmp_root}/contaminated_local_rch_fallback"
  contradictory="${tmp_root}/contradictory_slot_or_memory_evidence"
  unsafe="${tmp_root}/unsafe_mutation_wording"

  mkdir -p "$tmp_root"

  write_common_fixtures "$healthy"
  expect_decision "pass" 0 "$healthy" "${healthy}/out"
  jq -e '
    .host_identity.host_id == "host-64c-256g"
    and .capacity_budget.remote_rch_slot_limit == 12
    and .capacity_budget.build_lane_limit == 6
    and (.artifact_paths.envelope_json | test("swarm_resource_envelope.json$"))
  ' "${healthy}/out/swarm_resource_envelope.json" >/dev/null
  jq empty "${healthy}/out/swarm_resource_envelope_input.json" "${healthy}/out/swarm_resource_envelope_sources.json"

  write_common_fixtures "$degraded"
  jq '.telemetry_complete = false' "${degraded}/memory_pressure.json" >"${degraded}/memory_pressure.tmp"
  mv "${degraded}/memory_pressure.tmp" "${degraded}/memory_pressure.json"
  expect_decision "degraded" 0 "$degraded" "${degraded}/out" run_normalizer_core_only
  jq -e 'any(.degraded_reasons[]; .code == "memory_or_disk_optional_telemetry_missing")' "${degraded}/out/swarm_resource_envelope.json" >/dev/null

  write_common_fixtures "$blocked"
  jq '.load_average_1m = 128' "${blocked}/host_topology.json" >"${blocked}/host_topology.tmp"
  mv "${blocked}/host_topology.tmp" "${blocked}/host_topology.json"
  jq '.build_slots.available = 0 | .build_slots.active = 16 | .queue_depth = 7 | .workers[0].slots_available = 0 | .workers[1].slots_available = 0' "${blocked}/rch_queue.json" >"${blocked}/rch_queue.tmp"
  mv "${blocked}/rch_queue.tmp" "${blocked}/rch_queue.json"
  expect_decision "blocked" 75 "$blocked" "${blocked}/out"
  jq -e 'any(.blocked_reasons[]; .code == "rch_slots_saturated")' "${blocked}/out/swarm_resource_envelope.json" >/dev/null

  write_common_fixtures "$contaminated"
  jq '.local_fallback_detected = true | .last_stderr = "[RCH] local fallback marker rejected"' "${contaminated}/rch_queue.json" >"${contaminated}/rch_queue.tmp"
  mv "${contaminated}/rch_queue.tmp" "${contaminated}/rch_queue.json"
  expect_decision "fail_closed" 42 "$contaminated" "${contaminated}/out"
  jq -e 'any(.fail_closed_reasons[]; .code == "rch_local_fallback_contaminates_capacity")' "${contaminated}/out/swarm_resource_envelope.json" >/dev/null

  write_common_fixtures "$contradictory"
  jq '.available_bytes = (.total_bytes + 1)' "${contradictory}/memory_pressure.json" >"${contradictory}/memory_pressure.tmp"
  mv "${contradictory}/memory_pressure.tmp" "${contradictory}/memory_pressure.json"
  jq '.build_slots.total = 99' "${contradictory}/rch_queue.json" >"${contradictory}/rch_queue.tmp"
  mv "${contradictory}/rch_queue.tmp" "${contradictory}/rch_queue.json"
  expect_decision "fail_closed" 42 "$contradictory" "${contradictory}/out"
  jq -e '
    any(.fail_closed_reasons[]; .code == "contradictory_cpu_or_memory_capacity")
    and any(.fail_closed_reasons[]; .code == "rch_slot_snapshot_contradiction")
  ' "${contradictory}/out/swarm_resource_envelope.json" >/dev/null

  write_common_fixtures "$unsafe"
  jq '.operator_claim = "mutates live workers"' "${unsafe}/causal_trace.json" >"${unsafe}/causal_trace.tmp"
  mv "${unsafe}/causal_trace.tmp" "${unsafe}/causal_trace.json"
  expect_decision "fail_closed" 42 "$unsafe" "${unsafe}/out"
  jq -e 'any(.fail_closed_reasons[]; .code == "unsafe_live_mutation_claim")' "${unsafe}/out/swarm_resource_envelope.json" >/dev/null

  record_pass "selftest fixtures"
  printf 'swarm_resource_envelope_normalizer_smoke_artifacts=%s\n' "$tmp_root"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_check
    run_selftest
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac
