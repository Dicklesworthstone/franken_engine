#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
guard="${root_dir}/scripts/remote_proof_gc_guard.sh"

record_pass() {
  printf 'PASS remote-proof-gc-guard %s\n' "$1"
}

record_failure() {
  printf 'FAIL remote-proof-gc-guard %s\n' "$1" >&2
}

write_json() {
  local path="$1"
  local text="$2"
  printf '%s\n' "$text" >"$path"
}

assert_outputs() {
  local case_dir="$1"
  local expected_exit="$2"
  jq -e \
    --argjson expected_exit "$expected_exit" '
      .schema_version == "franken-engine.remote-proof-gc-guard.v1"
      and (.gc_guard_id | length > 0)
      and .exit_code == $expected_exit
      and (.hash_basis.input_hash | length > 0)
      and (.hash_basis.guard_hash | length > 0)
      and (.artifact_paths.remote_proof_gc_guard_report_json | length > 0)
      and (.artifact_paths.events_jsonl | length > 0)
      and (.artifact_paths.commands_txt | length > 0)
      and (.artifact_paths.report_md | length > 0)
    ' "${case_dir}/remote_proof_gc_guard_report.json" >/dev/null

  test -s "${case_dir}/events.jsonl"
  test -s "${case_dir}/commands.txt"
  test -s "${case_dir}/report.md"
}

run_case() {
  local tmp_root="$1"
  local case_name="$2"
  local retention_json="$3"
  local roi_json="$4"
  local salvage_json="$5"
  local archive_json="$6"
  local expected_exit="$7"
  local case_dir="${tmp_root}/${case_name}"
  local retention_path="${case_dir}.retention.json"
  local roi_path="${case_dir}.roi.json"
  local salvage_path="${case_dir}.salvage.json"
  local archive_path="${case_dir}.archive.json"
  local actual_exit output

  write_json "$retention_path" "$retention_json"
  write_json "$roi_path" "$roi_json"
  write_json "$salvage_path" "$salvage_json"
  write_json "$archive_path" "$archive_json"

  set +e
  output="$(
    bash "$guard" \
      --output-dir "$case_dir" \
      --retention-ledger-json "$retention_path" \
      --warm-target-roi-ledger-json "$roi_path" \
      --salvage-receipt-json "$salvage_path" \
      --archive-pack-json "$archive_path" 2>&1
  )"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${actual_exit}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  assert_outputs "$case_dir" "$expected_exit"
}

run_selftest() {
  local tmp_parent tmp_root
  local hash_a hash_b

  tmp_parent="${REMOTE_PROOF_GC_GUARD_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/remote-proof-gc-guard.XXXXXX")"

  run_case \
    "$tmp_root" \
    "active-warm-target-protected" \
    '{"bundle_id":"bundle-guard","retention_decision":"pass","class_counts":{"hot_replay_critical":2,"warm_operator_inspectable":1,"salvage_pinned":0,"cold_archival":0},"artifact_paths":{"retention_class_ledger_json":"/control/retention.json"}}' \
    '{"bundle_id":"bundle-guard","decision":"retain","recommended_action":"retain_warm_target","reason":"keep hot","target_dir":"/tmp/rch_target_bundle_guard","worker_id":"ts2","policy_findings":["high_realized_reuse_value"],"artifact_paths":{"warm_target_roi_ledger_json":"/control/roi.json"}}' \
    '{"bundle_id":"bundle-guard","workflow_state":"clean_finished","recovery_recommendation":"no_salvage_needed","observed_process_truth":{"live_remote_compile":false,"orphaned_process_detected":false,"worker_reachable":true,"recoverable_artifact_set":true},"artifact_paths":{"salvage_receipt_json":"/control/salvage.json"}}' \
    '{"bundle_id":"bundle-guard","archive_state":"cold_archived","restore_verdict":"verified","archive_artifact_count":4,"artifact_paths":{"archive_pack_json":"/archive/bundle-guard/archive_pack.json"}}' \
    42

  jq -e '
      .guard_decision == "deny_gc"
      and .recommended_action == "keep_hot"
      and any(.policy_findings[]?; . == "active_warm_target_protected")
    ' "${tmp_root}/active-warm-target-protected/remote_proof_gc_guard_report.json" >/dev/null
  record_pass "active warm-target bundle protected from GC"

  run_case \
    "$tmp_root" \
    "orphan-salvage-pinned" \
    '{"bundle_id":"bundle-orphan","retention_decision":"pass","class_counts":{"hot_replay_critical":0,"warm_operator_inspectable":0,"salvage_pinned":3,"cold_archival":1},"artifact_paths":{"retention_class_ledger_json":"/control/retention.json"}}' \
    '{"bundle_id":"bundle-orphan","decision":"evict","recommended_action":"evict_warm_target","reason":"low reuse","target_dir":"/tmp/rch_target_bundle_orphan","worker_id":"vmi1156319","policy_findings":["low_realized_reuse_value"],"artifact_paths":{"warm_target_roi_ledger_json":"/control/roi.json"}}' \
    '{"bundle_id":"bundle-orphan","workflow_state":"orphan_reconciliation_required","recovery_recommendation":"clear_orphan_before_retry","observed_process_truth":{"live_remote_compile":false,"orphaned_process_detected":true,"worker_reachable":true,"recoverable_artifact_set":true},"artifact_paths":{"salvage_receipt_json":"/control/salvage.json"}}' \
    '{"bundle_id":"bundle-orphan","archive_state":"cold_archived","restore_verdict":"verified","archive_artifact_count":5,"artifact_paths":{"archive_pack_json":"/archive/bundle-orphan/archive_pack.json"}}' \
    42

  jq -e '
      .guard_decision == "deny_gc"
      and .recommended_action == "pin_until_salvage_clears"
      and any(.policy_findings[]?; . == "orphan_salvage_pinned")
    ' "${tmp_root}/orphan-salvage-pinned/remote_proof_gc_guard_report.json" >/dev/null
  record_pass "orphan-salvage bundle remains pinned"

  run_case \
    "$tmp_root" \
    "cold-archived-gc-allowed" \
    '{"bundle_id":"bundle-cold","retention_decision":"pass","class_counts":{"hot_replay_critical":0,"warm_operator_inspectable":0,"salvage_pinned":0,"cold_archival":4},"artifact_paths":{"retention_class_ledger_json":"/control/retention.json"}}' \
    '{"bundle_id":"bundle-cold","decision":"evict","recommended_action":"evict_warm_target","reason":"low reuse","target_dir":"/tmp/rch_target_bundle_cold","worker_id":"vmi1293453","policy_findings":["low_realized_reuse_value"],"artifact_paths":{"warm_target_roi_ledger_json":"/control/roi.json"}}' \
    '{"bundle_id":"bundle-cold","workflow_state":"clean_finished","recovery_recommendation":"no_salvage_needed","observed_process_truth":{"live_remote_compile":false,"orphaned_process_detected":false,"worker_reachable":true,"recoverable_artifact_set":true},"artifact_paths":{"salvage_receipt_json":"/control/salvage.json"}}' \
    '{"bundle_id":"bundle-cold","archive_state":"cold_archived","restore_verdict":"verified","archive_artifact_count":4,"artifact_paths":{"archive_pack_json":"/archive/bundle-cold/archive_pack.json"}}' \
    0

  jq -e '
      .guard_decision == "allow_gc"
      and .recommended_action == "delete_cold_archived_bundle"
      and any(.policy_findings[]?; . == "cold_archived_bundle_gc_allowed")
    ' "${tmp_root}/cold-archived-gc-allowed/remote_proof_gc_guard_report.json" >/dev/null
  record_pass "cold archived bundle allowed for GC"

  run_case \
    "$tmp_root" \
    "cold-archived-gc-repeat" \
    '{"bundle_id":"bundle-cold","retention_decision":"pass","class_counts":{"hot_replay_critical":0,"warm_operator_inspectable":0,"salvage_pinned":0,"cold_archival":4},"artifact_paths":{"retention_class_ledger_json":"/control/retention.json"}}' \
    '{"bundle_id":"bundle-cold","decision":"evict","recommended_action":"evict_warm_target","reason":"low reuse","target_dir":"/tmp/rch_target_bundle_cold","worker_id":"vmi1293453","policy_findings":["low_realized_reuse_value"],"artifact_paths":{"warm_target_roi_ledger_json":"/control/roi.json"}}' \
    '{"bundle_id":"bundle-cold","workflow_state":"clean_finished","recovery_recommendation":"no_salvage_needed","observed_process_truth":{"live_remote_compile":false,"orphaned_process_detected":false,"worker_reachable":true,"recoverable_artifact_set":true},"artifact_paths":{"salvage_receipt_json":"/control/salvage.json"}}' \
    '{"bundle_id":"bundle-cold","archive_state":"cold_archived","restore_verdict":"verified","archive_artifact_count":4,"artifact_paths":{"archive_pack_json":"/archive/bundle-cold/archive_pack.json"}}' \
    0

  hash_a="$(jq -r '.hash_basis.guard_hash' "${tmp_root}/cold-archived-gc-allowed/remote_proof_gc_guard_report.json")"
  hash_b="$(jq -r '.hash_basis.guard_hash' "${tmp_root}/cold-archived-gc-repeat/remote_proof_gc_guard_report.json")"
  if [[ "$hash_a" != "$hash_b" ]]; then
    record_failure "stable guard hash mismatch for repeated fixture"
    exit 1
  fi
  record_pass "stable guard hash retained across repeated fixture"

  printf 'remote_proof_gc_guard_smoke_artifacts=%s\n' "$tmp_root"
}

run_check() {
  bash -n "$guard"
  bash -n "${BASH_SOURCE[0]}"
  shellcheck -x "$guard" "${BASH_SOURCE[0]}"
  jq empty "${root_dir}/docs/remote_proof_gc_guard_contract_v1.json" >/dev/null
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
