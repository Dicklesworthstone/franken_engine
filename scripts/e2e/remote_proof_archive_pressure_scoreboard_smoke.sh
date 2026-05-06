#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scoreboard="${root_dir}/scripts/remote_proof_archive_pressure_scoreboard.sh"
contract_json="${root_dir}/docs/remote_proof_archive_pressure_scoreboard_contract_v1.json"

record_pass() {
  printf 'PASS remote-proof-archive-pressure-scoreboard %s\n' "$1"
}

record_failure() {
  printf 'FAIL remote-proof-archive-pressure-scoreboard %s\n' "$1" >&2
}

write_json() {
  local path="$1"
  local payload="$2"
  printf '%s\n' "$payload" | jq -cS . >"$path"
}

run_case() {
  local tmp_root="$1"
  local case_name="$2"
  local expected_advisory="$3"
  local expected_action="$4"
  local expected_pressure="$5"
  local expected_exit="$6"
  local expected_finding="$7"
  local retention_json="$8"
  local compaction_json="$9"
  local gc_guard_json="${10}"
  local archive_json="${11}"
  local case_dir="${tmp_root}/${case_name}"
  local retention_path="${case_dir}.retention.json"
  local compaction_path="${case_dir}.compaction.json"
  local gc_guard_path="${case_dir}.gc-guard.json"
  local archive_path="${case_dir}.archive.json"
  local exit_code

  write_json "$retention_path" "$retention_json"
  write_json "$compaction_path" "$compaction_json"
  write_json "$gc_guard_path" "$gc_guard_json"
  write_json "$archive_path" "$archive_json"

  set +e
  "${scoreboard}" \
    --retention-ledger-json "$retention_path" \
    --compaction-plan-json "$compaction_path" \
    --gc-guard-report-json "$gc_guard_path" \
    --archive-pack-json "$archive_path" \
    --output-dir "$case_dir"
  exit_code=$?
  set -e

  if [[ "$exit_code" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${exit_code}, expected ${expected_exit}"
    printf 'remote_proof_archive_pressure_scoreboard=%s\n' "${case_dir}/remote_proof_archive_pressure_scoreboard.json" >&2
    exit 1
  fi

  jq -e \
    --arg advisory "$expected_advisory" \
    --arg action "$expected_action" \
    --arg pressure "$expected_pressure" \
    --arg finding "$expected_finding" '
      .schema_version == "franken-engine.remote-proof-archive-pressure-scoreboard.v1"
      and .advisory == $advisory
      and .recommended_action == $action
      and .pressure_level == $pressure
      and any(.policy_findings[]?; . == $finding)
    ' "${case_dir}/remote_proof_archive_pressure_scoreboard.json" >/dev/null
}

run_selftest() {
  local tmp_parent tmp_root hash_a hash_b

  tmp_parent="${REMOTE_PROOF_ARCHIVE_PRESSURE_SCOREBOARD_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/remote-proof-archive-pressure-scoreboard.XXXXXX")"

  run_case \
    "$tmp_root" \
    "low-pressure-retain" \
    "retain" \
    "retain_current_residency" \
    "low" \
    0 \
    "low_pressure_retain" \
    '{"bundle_id":"bundle-retain","retention_decision":"pass","class_counts":{"hot_replay_critical":1,"warm_operator_inspectable":1,"salvage_pinned":0,"cold_archival":0},"artifact_paths":{"retention_class_ledger_json":"/control/retention.json"}}' \
    '{"bundle_id":"bundle-retain","compacted_groups":[],"blocked_groups":[],"artifact_paths":{"remote_proof_compaction_plan_json":"/control/compaction.json"}}' \
    '{"bundle_id":"bundle-retain","guard_decision":"deny_gc","recommended_action":"keep_hot","reason":"active replay still resident","policy_findings":["active_warm_target_protected"],"artifact_paths":{"remote_proof_gc_guard_report_json":"/control/gc-guard.json"}}' \
    '{"bundle_id":"bundle-retain","archive_state":"warming","restore_verdict":"verified","archive_artifact_count":1,"artifact_paths":{"archive_pack_json":"/archive/bundle-retain/archive_pack.json"}}'
  record_pass "low-pressure retain advisory fixture"

  run_case \
    "$tmp_root" \
    "compaction-first-remediation" \
    "compaction_first" \
    "compact_before_eviction" \
    "elevated" \
    75 \
    "compaction_first_remediation" \
    '{"bundle_id":"bundle-compact","retention_decision":"pass","class_counts":{"hot_replay_critical":0,"warm_operator_inspectable":2,"salvage_pinned":0,"cold_archival":2},"artifact_paths":{"retention_class_ledger_json":"/control/retention.json"}}' \
    '{"bundle_id":"bundle-compact","compacted_groups":[{"content_address":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","retained_path":"/archive/replay-retained.bin","compacted_paths":["/archive/replay-duplicate.bin"]}],"blocked_groups":[],"artifact_paths":{"remote_proof_compaction_plan_json":"/control/compaction.json"}}' \
    '{"bundle_id":"bundle-compact","guard_decision":"cool_only","recommended_action":"cool_without_gc","reason":"archive can cool but is not yet deletable","policy_findings":["cool_without_gc"],"artifact_paths":{"remote_proof_gc_guard_report_json":"/control/gc-guard.json"}}' \
    '{"bundle_id":"bundle-compact","archive_state":"cold_archived","restore_verdict":"verified","archive_artifact_count":4,"artifact_paths":{"archive_pack_json":"/archive/bundle-compact/archive_pack.json"}}'
  record_pass "compaction-first remediation fixture"

  run_case \
    "$tmp_root" \
    "cold-archive-eviction-critical-pressure" \
    "evict_cold_archive" \
    "evict_archived_bundle" \
    "critical" \
    42 \
    "critical_pressure_cold_archive_evictable" \
    '{"bundle_id":"bundle-evict","retention_decision":"pass","class_counts":{"hot_replay_critical":0,"warm_operator_inspectable":1,"salvage_pinned":0,"cold_archival":5},"artifact_paths":{"retention_class_ledger_json":"/control/retention.json"}}' \
    '{"bundle_id":"bundle-evict","compacted_groups":[],"blocked_groups":[],"artifact_paths":{"remote_proof_compaction_plan_json":"/control/compaction.json"}}' \
    '{"bundle_id":"bundle-evict","guard_decision":"allow_gc","recommended_action":"delete_cold_archived_bundle","reason":"verified cold archive is honestly deletable","policy_findings":["cold_archived_bundle_gc_allowed"],"artifact_paths":{"remote_proof_gc_guard_report_json":"/control/gc-guard.json"}}' \
    '{"bundle_id":"bundle-evict","archive_state":"cold_archived","restore_verdict":"verified","archive_artifact_count":5,"artifact_paths":{"archive_pack_json":"/archive/bundle-evict/archive_pack.json"}}'
  record_pass "cold-archive eviction fixture under critical pressure"

  run_case \
    "$tmp_root" \
    "active-or-salvage-pinned-fail-closed" \
    "fail_closed" \
    "preserve_pinned_evidence" \
    "critical" \
    42 \
    "salvage_pinned_blocks_eviction" \
    '{"bundle_id":"bundle-pinned","retention_decision":"pass","class_counts":{"hot_replay_critical":1,"warm_operator_inspectable":0,"salvage_pinned":2,"cold_archival":3},"artifact_paths":{"retention_class_ledger_json":"/control/retention.json"}}' \
    '{"bundle_id":"bundle-pinned","compacted_groups":[],"blocked_groups":[{"content_address":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","reason":"provenance_mismatch","blocked_paths":["/archive/pinned-a.bin","/archive/pinned-b.bin"]}],"artifact_paths":{"remote_proof_compaction_plan_json":"/control/compaction.json"}}' \
    '{"bundle_id":"bundle-pinned","guard_decision":"deny_gc","recommended_action":"pin_until_salvage_clears","reason":"salvage reconciliation is still active","policy_findings":["orphan_salvage_pinned"],"artifact_paths":{"remote_proof_gc_guard_report_json":"/control/gc-guard.json"}}' \
    '{"bundle_id":"bundle-pinned","archive_state":"cold_archived","restore_verdict":"verified","archive_artifact_count":6,"artifact_paths":{"archive_pack_json":"/archive/bundle-pinned/archive_pack.json"}}'
  record_pass "active-or-salvage-pinned fail-closed advisory fixture"

  run_case \
    "$tmp_root" \
    "cold-archive-eviction-critical-pressure-repeat" \
    "evict_cold_archive" \
    "evict_archived_bundle" \
    "critical" \
    42 \
    "critical_pressure_cold_archive_evictable" \
    '{"bundle_id":"bundle-evict","retention_decision":"pass","class_counts":{"hot_replay_critical":0,"warm_operator_inspectable":1,"salvage_pinned":0,"cold_archival":5},"artifact_paths":{"retention_class_ledger_json":"/control/retention.json"}}' \
    '{"bundle_id":"bundle-evict","compacted_groups":[],"blocked_groups":[],"artifact_paths":{"remote_proof_compaction_plan_json":"/control/compaction.json"}}' \
    '{"bundle_id":"bundle-evict","guard_decision":"allow_gc","recommended_action":"delete_cold_archived_bundle","reason":"verified cold archive is honestly deletable","policy_findings":["cold_archived_bundle_gc_allowed"],"artifact_paths":{"remote_proof_gc_guard_report_json":"/control/gc-guard.json"}}' \
    '{"bundle_id":"bundle-evict","archive_state":"cold_archived","restore_verdict":"verified","archive_artifact_count":5,"artifact_paths":{"archive_pack_json":"/archive/bundle-evict/archive_pack.json"}}'

  hash_a="$(jq -r '.hash_basis.scoreboard_hash' "${tmp_root}/cold-archive-eviction-critical-pressure/remote_proof_archive_pressure_scoreboard.json")"
  hash_b="$(jq -r '.hash_basis.scoreboard_hash' "${tmp_root}/cold-archive-eviction-critical-pressure-repeat/remote_proof_archive_pressure_scoreboard.json")"
  if [[ "$hash_a" != "$hash_b" ]]; then
    record_failure "stable scoreboard hash mismatch for repeated eviction fixture"
    exit 1
  fi
  record_pass "stable scoreboard hash retained across repeated fixture"

  printf 'remote_proof_archive_pressure_scoreboard_smoke_artifacts=%s\n' "$tmp_root"
}

run_check() {
  bash -n "$scoreboard"
  bash -n "${BASH_SOURCE[0]}"
  shellcheck -x "$scoreboard" "${BASH_SOURCE[0]}"
  jq empty "$contract_json" >/dev/null
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
