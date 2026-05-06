#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/swarm_resource_envelope_normalizer.sh"
planner="${root_dir}/scripts/swarm_fair_share_batch_planner.sh"
contract_path="${root_dir}/docs/swarm_resource_envelope_contract_v1.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS swarm-fair-share-batch-planner %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-fair-share-batch-planner %s\n' "$1" >&2
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_fair_share_batch_planner_smoke.sh [check|selftest]
EOF
}

write_envelope_fixtures() {
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
    telemetry_complete:true,
    observed_at:"2026-05-06T20:00:00Z"
  }' >"${dir}/memory_pressure.json"
  jq -n '{
    schema_version:"franken-engine.disk-pressure-snapshot.v1",
    filesystems:[{mount:"/data", available_bytes:549755813888}],
    target_dirs:[{path:"/mnt/rch/franken_engine", available_bytes:322122547200}],
    telemetry_complete:true,
    observed_at:"2026-05-06T20:00:00Z"
  }' >"${dir}/disk_pressure.json"
  jq -n '{
    schema_version:"franken-engine.rch-queue-status-snapshot.v1",
    workers:[{worker_id:"rch-a", slots_total:8, slots_available:6},{worker_id:"rch-b", slots_total:8, slots_available:6}],
    build_slots:{total:16, active:4, available:12},
    queue_depth:0,
    observed_at:"2026-05-06T20:00:00Z"
  }' >"${dir}/rch_queue.json"
}

write_plan_fixtures() {
  local dir="$1"

  jq -n '{
    plan:{
      tracks:[
        {track_id:"swarm-scale", items:[
          {id:"bd-heavy-a", title:"Heavy A", priority:1, agent_id:"AgentA", command_kind:"cargo_check", requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch cargo check -p frankenengine-engine --lib", requested_rch_slots:1, requested_memory_bytes:4294967296, planned_write_paths:["crates/franken-engine/src/a.rs"]},
          {id:"bd-heavy-b", title:"Heavy B", priority:1, agent_id:"AgentB", command_kind:"cargo_test", requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch cargo test -p frankenengine-engine --lib", requested_rch_slots:1, requested_memory_bytes:4294967296, planned_write_paths:["crates/franken-engine/src/b.rs"]},
          {id:"bd-script", title:"Script lane", priority:2, agent_id:"AgentA", command_kind:"script", requested_command:"bash scripts/e2e/example.sh", planned_write_paths:["scripts/e2e/example.sh"]}
        ]}
      ]
    }
  }' >"${dir}/bv_plan.json"
  jq -n '{commands:[
    {display:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch cargo check -p frankenengine-engine --lib", cost_class:"heavy", budget_class:"build_lane"},
    {display:"bash scripts/e2e/example.sh", cost_class:"script", budget_class:"script_lane"}
  ]}' >"${dir}/validation_costs.json"
  jq -n '{proof_cache_decision:"cache_hit", cache_hit_artifacts:["proof-a.json"]}' >"${dir}/proof_cache.json"
  jq -n '{reservations:[]}' >"${dir}/reservations.json"
  jq -n '{decision:"pass", anomalies:[]}' >"${dir}/causal_trace.json"
}

build_envelope() {
  local fixture_dir="$1"
  local output_dir="$2"

  "$normalizer" \
    --bead-id bd-adsq0 \
    --source-revision fixture-rev \
    --reference-time "2026-05-06T20:10:00Z" \
    --host-topology-json "${fixture_dir}/host_topology.json" \
    --memory-pressure-json "${fixture_dir}/memory_pressure.json" \
    --disk-pressure-json "${fixture_dir}/disk_pressure.json" \
    --rch-queue-status-json "${fixture_dir}/rch_queue.json" \
    --output-dir "$output_dir" >/dev/null
}

run_planner() {
  local fixture_dir="$1"
  local output_dir="$2"

  "$planner" \
    --source-revision fixture-rev \
    --reference-time "2026-05-06T20:10:00Z" \
    --resource-envelope-json "${fixture_dir}/envelope/swarm_resource_envelope.json" \
    --bv-actionable-plan-json "${fixture_dir}/bv_plan.json" \
    --validation-cost-hints-json "${fixture_dir}/validation_costs.json" \
    --proof-cache-plan-json "${fixture_dir}/proof_cache.json" \
    --active-reservations-json "${fixture_dir}/reservations.json" \
    --causal-trace-summary-json "${fixture_dir}/causal_trace.json" \
    --output-dir "$output_dir" >/dev/null
}

expect_decision() {
  local expected_decision="$1"
  local expected_status="$2"
  local fixture_dir="$3"
  local output_dir="$4"
  local status

  set +e
  run_planner "$fixture_dir" "$output_dir"
  status=$?
  set -e
  if [[ "$status" -ne "$expected_status" ]]; then
    record_failure "expected exit ${expected_status} for ${expected_decision}, got ${status}"
    return 1
  fi
  jq -e --arg decision "$expected_decision" '.decision == $decision' "${output_dir}/swarm_fair_share_batch_plan.json" >/dev/null
}

run_check() {
  bash -n "$planner"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  jq -e '
    (.fair_share_planner.script == "scripts/swarm_fair_share_batch_planner.sh")
    and (.fair_share_planner.smoke_script == "scripts/e2e/swarm_fair_share_batch_planner_smoke.sh")
    and (.fair_share_planner.artifacts | index("swarm_fair_share_batch_plan.json") != null)
  ' "$contract_path" >/dev/null
  record_pass "syntax and contract"
}

run_selftest() {
  local tmp_root
  local healthy
  local low_memory
  local disk_pressure
  local rch_brownout
  local reservation_conflict
  local contaminated

  tmp_root="${TMPDIR:-/tmp}/franken-engine-swarm-fair-share-batch-planner-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  healthy="${tmp_root}/healthy_high_core"
  low_memory="${tmp_root}/low_memory"
  disk_pressure="${tmp_root}/disk_pressure"
  rch_brownout="${tmp_root}/rch_brownout"
  reservation_conflict="${tmp_root}/reservation_conflict"
  contaminated="${tmp_root}/contaminated"
  mkdir -p "$tmp_root"

  write_envelope_fixtures "$healthy"
  write_plan_fixtures "$healthy"
  build_envelope "$healthy" "${healthy}/envelope"
  expect_decision "admit" 0 "$healthy" "${healthy}/plan"
  jq -e '
    .summary.heavy_admitted_count <= .summary.heavy_lane_limit
    and .summary.rch_slots_used <= .summary.remote_rch_slot_limit
    and (.admitted_lanes | length) == 3
  ' "${healthy}/plan/swarm_fair_share_batch_plan.json" >/dev/null

  write_envelope_fixtures "$low_memory"
  write_plan_fixtures "$low_memory"
  jq '.available_bytes = 17179869184' "${low_memory}/memory_pressure.json" >"${low_memory}/memory_pressure.tmp"
  mv "${low_memory}/memory_pressure.tmp" "${low_memory}/memory_pressure.json"
  set +e
  build_envelope "$low_memory" "${low_memory}/envelope"
  set -e
  expect_decision "defer" 75 "$low_memory" "${low_memory}/plan"

  write_envelope_fixtures "$disk_pressure"
  write_plan_fixtures "$disk_pressure"
  jq '.target_dirs[0].available_bytes = 536870912' "${disk_pressure}/disk_pressure.json" >"${disk_pressure}/disk_pressure.tmp"
  mv "${disk_pressure}/disk_pressure.tmp" "${disk_pressure}/disk_pressure.json"
  set +e
  build_envelope "$disk_pressure" "${disk_pressure}/envelope"
  set -e
  expect_decision "defer" 75 "$disk_pressure" "${disk_pressure}/plan"

  write_envelope_fixtures "$rch_brownout"
  write_plan_fixtures "$rch_brownout"
  jq '.build_slots.available = 0 | .build_slots.active = 16 | .workers[0].slots_available = 0 | .workers[1].slots_available = 0' "${rch_brownout}/rch_queue.json" >"${rch_brownout}/rch_queue.tmp"
  mv "${rch_brownout}/rch_queue.tmp" "${rch_brownout}/rch_queue.json"
  set +e
  build_envelope "$rch_brownout" "${rch_brownout}/envelope"
  set -e
  expect_decision "defer" 75 "$rch_brownout" "${rch_brownout}/plan"

  write_envelope_fixtures "$reservation_conflict"
  write_plan_fixtures "$reservation_conflict"
  jq -n '{reservations:[{path_pattern:"crates/franken-engine/src/a.rs", agent_name:"OtherAgent"}]}' >"${reservation_conflict}/reservations.json"
  build_envelope "$reservation_conflict" "${reservation_conflict}/envelope"
  expect_decision "admit_narrow" 0 "$reservation_conflict" "${reservation_conflict}/plan"
  jq -e 'any(.deferred_lanes[]; .bead_id == "bd-heavy-a" and (.reasons | index("conflicting_reservation") != null))' "${reservation_conflict}/plan/swarm_fair_share_batch_plan.json" >/dev/null

  write_envelope_fixtures "$contaminated"
  write_plan_fixtures "$contaminated"
  jq '.local_fallback_detected = true | .last_stderr = "[RCH] local fallback marker rejected"' "${contaminated}/rch_queue.json" >"${contaminated}/rch_queue.tmp"
  mv "${contaminated}/rch_queue.tmp" "${contaminated}/rch_queue.json"
  set +e
  build_envelope "$contaminated" "${contaminated}/envelope"
  set -e
  expect_decision "fail_closed" 42 "$contaminated" "${contaminated}/plan"
  jq -e '(.admitted_lanes | length) == 0 and any(.fail_closed_reasons[]; .code == "contaminated_resource_envelope" or .code == "local_rch_fallback_contamination")' "${contaminated}/plan/swarm_fair_share_batch_plan.json" >/dev/null

  record_pass "selftest fixtures"
  printf 'swarm_fair_share_batch_planner_smoke_artifacts=%s\n' "$tmp_root"
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
