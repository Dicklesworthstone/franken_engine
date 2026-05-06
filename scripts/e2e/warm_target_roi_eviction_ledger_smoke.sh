#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ledger="${root_dir}/scripts/warm_target_roi_eviction_ledger.sh"

record_pass() {
  printf 'PASS warm-target-roi-eviction %s\n' "$1"
}

record_failure() {
  printf 'FAIL warm-target-roi-eviction %s\n' "$1" >&2
}

write_json() {
  local path="$1"
  local text="$2"
  printf '%s\n' "$text" >"$path"
}

assert_ledger() {
  local case_dir="$1"
  local expected_decision="$2"
  local expected_action="$3"
  local expected_exit="$4"
  local expected_finding="$5"

  jq -e \
    --arg expected_decision "$expected_decision" \
    --arg expected_action "$expected_action" \
    --argjson expected_exit "$expected_exit" \
    --arg expected_finding "$expected_finding" '
      .schema_version == "franken-engine.warm-target-roi-eviction-ledger.v1"
      and .decision == $expected_decision
      and .recommended_action == $expected_action
      and .exit_code == $expected_exit
      and (.hash_basis.input_hash | length > 0)
      and (.hash_basis.ledger_hash | length > 0)
      and any(.policy_findings[]?; . == $expected_finding)
      and (.artifact_paths.warm_target_roi_ledger_json | length > 0)
      and (.artifact_paths.events_jsonl | length > 0)
      and (.artifact_paths.commands_txt | length > 0)
      and (.artifact_paths.report_md | length > 0)
    ' "${case_dir}/warm_target_roi_ledger.json" >/dev/null

  test -s "${case_dir}/events.jsonl"
  test -s "${case_dir}/commands.txt"
  test -s "${case_dir}/report.md"
}

run_case() {
  local tmp_root="$1"
  local case_name="$2"
  local expected_decision="$3"
  local expected_action="$4"
  local expected_exit="$5"
  local expected_finding="$6"
  local bundle_json="$7"
  local sticky_json="$8"
  local hotspot_json="$9"
  local pressure_json="${10}"
  local incidents_json="${11}"
  local case_dir="${tmp_root}/${case_name}"
  local bundle_path="${case_dir}.bundle.json"
  local sticky_path="${case_dir}.sticky.json"
  local hotspot_path="${case_dir}.hotspot.json"
  local pressure_path="${case_dir}.pressure.json"
  local incidents_path="${case_dir}.incidents.json"
  local actual_exit output

  write_json "$bundle_path" "$bundle_json"
  write_json "$sticky_path" "$sticky_json"
  write_json "$hotspot_path" "$hotspot_json"
  write_json "$pressure_path" "$pressure_json"
  write_json "$incidents_path" "$incidents_json"

  set +e
  output="$(
    "$ledger" \
      --output-dir "$case_dir" \
      --bundle-report-json "$bundle_path" \
      --sticky-plan-json "$sticky_path" \
      --hotspot-ledger-json "$hotspot_path" \
      --pressure-snapshot-json "$pressure_path" \
      --incident-history-json "$incidents_path" 2>&1
  )"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${actual_exit}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  assert_ledger "$case_dir" "$expected_decision" "$expected_action" "$expected_exit" "$expected_finding"
  record_pass "${case_name} => ${expected_action}"
}

run_selftest() {
  local tmp_parent tmp_root
  local hash_a hash_b

  tmp_parent="${WARM_TARGET_ROI_EVICTION_LEDGER_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/warm-target-roi-eviction.XXXXXX")"

  run_case \
    "$tmp_root" \
    "high-roi-retain" \
    "retain" \
    "retain_warm_target" \
    0 \
    "high_realized_reuse_value" \
    '{"bundle_id":"bundle-retain","bundle_decision":"pass","expected_worker_id":"vmi1156319","expected_target_dir":"/tmp/rch_target_bundle_retain","phase_count":3,"source_revision":"smoke-rev"}' \
    '{"plan_decision":"admit_sticky","assigned_worker_id":"vmi1156319","assigned_target_dir":"/tmp/rch_target_bundle_retain","manifest_phase_count":3}' \
    '{"analysis_status":"ok","repeated_hotspot_count":1,"total_full_sync_commands":0,"total_narrow_sync_commands":3}' \
    '{"disk_pressure":"low","memory_pressure":"low"}' \
    '{"incidents":[]}'

  run_case \
    "$tmp_root" \
    "low-roi-evict" \
    "evict" \
    "evict_warm_target" \
    42 \
    "low_realized_reuse_value" \
    '{"bundle_id":"bundle-evict","bundle_decision":"fail_closed","expected_worker_id":"vmi1293453","expected_target_dir":"/tmp/rch_target_bundle_evict","phase_count":1,"source_revision":"smoke-rev"}' \
    '{"plan_decision":"admit_fallback_worker","assigned_worker_id":"vmi1293453","assigned_target_dir":"/tmp/rch_target_bundle_other","manifest_phase_count":3}' \
    '{"analysis_status":"ok","repeated_hotspot_count":3,"total_full_sync_commands":2,"total_narrow_sync_commands":1}' \
    '{"disk_pressure":"medium","memory_pressure":"medium"}' \
    '{"incidents":[]}'

  run_case \
    "$tmp_root" \
    "disk-pressure-forced-eviction" \
    "evict" \
    "evict_warm_target" \
    42 \
    "critical_pressure_forced_eviction" \
    '{"bundle_id":"bundle-pressure","bundle_decision":"pass","expected_worker_id":"ts2","expected_target_dir":"/tmp/rch_target_bundle_pressure","phase_count":4,"source_revision":"smoke-rev"}' \
    '{"plan_decision":"admit_sticky","assigned_worker_id":"ts2","assigned_target_dir":"/tmp/rch_target_bundle_pressure","manifest_phase_count":4}' \
    '{"analysis_status":"ok","repeated_hotspot_count":2,"total_full_sync_commands":1,"total_narrow_sync_commands":3}' \
    '{"disk_pressure":"critical","memory_pressure":"low"}' \
    '{"incidents":[]}'

  run_case \
    "$tmp_root" \
    "incident-history-cooling" \
    "cool" \
    "cool_warm_target" \
    75 \
    "incident_history_cooling" \
    '{"bundle_id":"bundle-cool","bundle_decision":"pass","expected_worker_id":"vmi1264463","expected_target_dir":"/tmp/rch_target_bundle_cool","phase_count":3,"source_revision":"smoke-rev"}' \
    '{"plan_decision":"admit_sticky","assigned_worker_id":"vmi1264463","assigned_target_dir":"/tmp/rch_target_bundle_cool","manifest_phase_count":3}' \
    '{"analysis_status":"ok","repeated_hotspot_count":2,"total_full_sync_commands":1,"total_narrow_sync_commands":2}' \
    '{"disk_pressure":"low","memory_pressure":"medium"}' \
    '{"incidents":[{"failure_kind":"timed_out_transport_live_remote_compile","worker_id":"vmi1264463"},{"failure_kind":"canceled_build_live_orphaned_rustc","worker_id":"vmi1264463"}]}'

  run_case \
    "$tmp_root" \
    "high-roi-retain-repeat" \
    "retain" \
    "retain_warm_target" \
    0 \
    "high_realized_reuse_value" \
    '{"bundle_id":"bundle-retain","bundle_decision":"pass","expected_worker_id":"vmi1156319","expected_target_dir":"/tmp/rch_target_bundle_retain","phase_count":3,"source_revision":"smoke-rev"}' \
    '{"plan_decision":"admit_sticky","assigned_worker_id":"vmi1156319","assigned_target_dir":"/tmp/rch_target_bundle_retain","manifest_phase_count":3}' \
    '{"analysis_status":"ok","repeated_hotspot_count":1,"total_full_sync_commands":0,"total_narrow_sync_commands":3}' \
    '{"disk_pressure":"low","memory_pressure":"low"}' \
    '{"incidents":[]}'

  hash_a="$(jq -r '.hash_basis.ledger_hash' "${tmp_root}/high-roi-retain/warm_target_roi_ledger.json")"
  hash_b="$(jq -r '.hash_basis.ledger_hash' "${tmp_root}/high-roi-retain-repeat/warm_target_roi_ledger.json")"
  if [[ "$hash_a" != "$hash_b" ]]; then
    record_failure "stable hash mismatch for repeated retain fixture"
    exit 1
  fi
  record_pass "stable ledger hash retained across repeated fixture"

  printf 'warm_target_roi_eviction_smoke_artifacts=%s\n' "$tmp_root"
}

run_check() {
  bash -n "$ledger"
  bash -n "${BASH_SOURCE[0]}"
  shellcheck -x "$ledger" "${BASH_SOURCE[0]}"
  jq empty "${root_dir}/docs/warm_target_roi_eviction_contract_v1.json" >/dev/null
  record_pass "shell syntax, shellcheck, and contract JSON"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_check
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
