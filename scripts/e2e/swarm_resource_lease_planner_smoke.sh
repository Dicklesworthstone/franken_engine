#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/swarm_resource_lease_planner.sh"
docs_path="${root_dir}/docs/SWARM_RESOURCE_LEASE_PLANNER.md"

record_pass() {
  printf 'PASS swarm-resource-lease-planner %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-resource-lease-planner %s\n' "$1" >&2
}

write_common_fixtures() {
  local fixture_dir="$1"
  local target_dir="$2"

  mkdir -p "$fixture_dir"
  jq -n '{beads:[{id:"bd-x82vp", status:"in_progress", assignee:"ScarletOwl"}]}' >"${fixture_dir}/br.json"
  jq -n '{reservations:[]}' >"${fixture_dir}/reservations.json"
  jq -n '[
    {path:"docs/SWARM_RESOURCE_LEASE_PLANNER.md", state:"dirty_unrelated"}
  ]' >"${fixture_dir}/dirty.json"
  jq -n \
    --arg target_dir "$target_dir" \
    '{workers:[
      {worker_id:"worker-a", status:"idle", cpu_slots_available:8, memory_class:"large", target_dir_root:"/tmp"},
      {worker_id:"worker-b", status:"busy", cpu_slots_available:0, memory_class:"xlarge", target_dir_root:"/tmp", active_target_dir:$target_dir}
    ]}' >"${fixture_dir}/workers.json"
}

run_case() {
  local case_name="$1"
  local expected_decision="$2"
  local expected_exit="$3"
  local output_dir="$4"
  shift 4
  local output
  local exit_code

  set +e
  output="$("$planner" --output-dir "$output_dir" "$@" 2>&1)"
  exit_code=$?
  set -e

  if [[ "$exit_code" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${exit_code}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  jq -e --arg expected_decision "$expected_decision" '
    .schema_version == "franken-engine.swarm-resource-lease-plan.v1"
    and (.agent_id | length > 0)
    and (.bead_id | length > 0)
    and (.requested_command | length > 0)
    and (.estimated_cpu_slots | type == "number")
    and (.estimated_memory_class | length > 0)
    and (.target_dir | length > 0)
    and .lease_decision == $expected_decision
    and (.lease_ttl_seconds | type == "number")
    and (.reason | length > 0)
    and (.safe_alternatives | type == "array")
    and (.artifact_paths.resource_lease_plan_json | length > 0)
    and (.artifact_paths.events_jsonl | length > 0)
    and (.artifact_paths.commands_txt | length > 0)
    and (.artifact_paths.report_md | length > 0)
  ' "${output_dir}/resource_lease_plan.json" >/dev/null

  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"
  record_pass "${case_name} decided ${expected_decision}"
}

run_check() {
  local scope_file

  bash -n "$planner"
  bash -n "${BASH_SOURCE[0]}"
  test -f "$docs_path"
  record_pass "bash syntax and docs exist"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/swarm-resource-lease-rch-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/swarm_resource_lease_planner.sh" \
    "scripts/e2e/swarm_resource_lease_planner_smoke.sh" \
    "docs/SWARM_RESOURCE_LEASE_PLANNER.md" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/swarm-resource-lease-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "rch policy compliance"
}

run_selftest() {
  local tmp_parent tmp_root fixture_dir target_dir

  run_check
  tmp_parent="${SWARM_RESOURCE_LEASE_PLANNER_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-resource-lease-planner.XXXXXX")"
  target_dir="/tmp/rch_target_franken_engine_bd_x82vp"
  fixture_dir="${tmp_root}/fixtures"
  write_common_fixtures "$fixture_dir" "$target_dir"

  run_case "light-shell-admit" "admit" 0 "${tmp_root}/light-shell-admit" \
    --agent-id ScarletOwl \
    --bead-id bd-x82vp \
    --requested-command "bash -n scripts/swarm_resource_lease_planner.sh" \
    --estimated-cpu-slots 1 \
    --estimated-memory-class small \
    --target-dir "$target_dir" \
    --reservation-snapshot-json "${fixture_dir}/reservations.json" \
    --br-snapshot-json "${fixture_dir}/br.json" \
    --rch-workers-json "${fixture_dir}/workers.json" \
    --dirty-files-json "${fixture_dir}/dirty.json"

  run_case "focused-rch-admit" "admit" 0 "${tmp_root}/focused-rch-admit" \
    --agent-id ScarletOwl \
    --bead-id bd-x82vp \
    --requested-command "rch exec -- env CARGO_TARGET_DIR=${target_dir} cargo test -p frankenengine-engine --test proof_manifest_golden_artifacts" \
    --estimated-cpu-slots 4 \
    --estimated-memory-class large \
    --target-dir "$target_dir" \
    --reservation-snapshot-json "${fixture_dir}/reservations.json" \
    --br-snapshot-json "${fixture_dir}/br.json" \
    --rch-workers-json "${fixture_dir}/workers.json" \
    --dirty-files-json "${fixture_dir}/dirty.json"

  run_case "over-budget-deny" "deny" 42 "${tmp_root}/over-budget-deny" \
    --agent-id ScarletOwl \
    --bead-id bd-x82vp \
    --requested-command "rch exec -- env CARGO_TARGET_DIR=${target_dir} cargo test --all-targets" \
    --estimated-cpu-slots 16 \
    --estimated-memory-class xlarge \
    --target-dir "$target_dir" \
    --max-cpu-slots 8 \
    --reservation-snapshot-json "${fixture_dir}/reservations.json" \
    --br-snapshot-json "${fixture_dir}/br.json" \
    --rch-workers-json "${fixture_dir}/workers.json" \
    --dirty-files-json "${fixture_dir}/dirty.json"

  run_case "missing-agent-mail-degraded" "admit_narrow" 0 "${tmp_root}/missing-agent-mail-degraded" \
    --agent-id ScarletOwl \
    --bead-id bd-x82vp \
    --requested-command "bash -n scripts/swarm_resource_lease_planner.sh" \
    --estimated-cpu-slots 1 \
    --estimated-memory-class small \
    --target-dir "$target_dir" \
    --br-snapshot-json "${fixture_dir}/br.json" \
    --rch-workers-json "${fixture_dir}/workers.json" \
    --dirty-files-json "${fixture_dir}/dirty.json"

  jq -n --arg target_dir "$target_dir" '{reservations:[{target_dir:$target_dir, agent_id:"CyanOak", bead_id:"bd-other", exclusive:true}]}' >"${fixture_dir}/target-conflict.json"
  run_case "target-dir-conflict" "defer" 75 "${tmp_root}/target-dir-conflict" \
    --agent-id ScarletOwl \
    --bead-id bd-x82vp \
    --requested-command "rch exec -- env CARGO_TARGET_DIR=${target_dir} cargo test -p frankenengine-engine --test proof_manifest_golden_artifacts" \
    --estimated-cpu-slots 4 \
    --estimated-memory-class large \
    --target-dir "$target_dir" \
    --reservation-snapshot-json "${fixture_dir}/target-conflict.json" \
    --br-snapshot-json "${fixture_dir}/br.json" \
    --rch-workers-json "${fixture_dir}/workers.json" \
    --dirty-files-json "${fixture_dir}/dirty.json"

  jq -n '{workers:[{worker_id:"worker-a", status:"busy", cpu_slots_available:0, memory_class:"large"}]}' >"${fixture_dir}/busy-workers.json"
  run_case "all-workers-busy" "defer" 75 "${tmp_root}/all-workers-busy" \
    --agent-id ScarletOwl \
    --bead-id bd-x82vp \
    --requested-command "rch exec -- env CARGO_TARGET_DIR=${target_dir} cargo test -p frankenengine-engine --test proof_manifest_golden_artifacts" \
    --estimated-cpu-slots 4 \
    --estimated-memory-class large \
    --target-dir "$target_dir" \
    --reservation-snapshot-json "${fixture_dir}/reservations.json" \
    --br-snapshot-json "${fixture_dir}/br.json" \
    --rch-workers-json "${fixture_dir}/busy-workers.json" \
    --dirty-files-json "${fixture_dir}/dirty.json"

  run_case "local-fallback-fail-closed" "fail_closed" 42 "${tmp_root}/local-fallback-fail-closed" \
    --agent-id ScarletOwl \
    --bead-id bd-x82vp \
    --requested-command "rch exec -- env CARGO_TARGET_DIR=${target_dir} cargo test -p frankenengine-engine --test proof_manifest_golden_artifacts" \
    --estimated-cpu-slots 4 \
    --estimated-memory-class large \
    --target-dir "$target_dir" \
    --rch-fallback-detected true \
    --reservation-snapshot-json "${fixture_dir}/reservations.json" \
    --br-snapshot-json "${fixture_dir}/br.json" \
    --rch-workers-json "${fixture_dir}/workers.json" \
    --dirty-files-json "${fixture_dir}/dirty.json"

  printf 'swarm_resource_lease_planner_smoke_artifacts=%s\n' "$tmp_root"
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
