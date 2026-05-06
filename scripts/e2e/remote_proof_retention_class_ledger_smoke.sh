#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ledger="${root_dir}/scripts/remote_proof_retention_class_ledger.sh"

record_pass() {
  printf 'PASS remote-proof-retention-class-ledger %s\n' "$1"
}

record_failure() {
  printf 'FAIL remote-proof-retention-class-ledger %s\n' "$1" >&2
}

write_json() {
  local path="$1"
  local text="$2"
  printf '%s\n' "$text" >"$path"
}

assert_entry_class() {
  local manifest_path="$1"
  local path="$2"
  local expected_class="$3"

  jq -e \
    --arg path "$path" \
    --arg expected_class "$expected_class" '
      any(.retention_entries[]?;
        .path == $path
        and .retention_class == $expected_class
      )
    ' "$manifest_path" >/dev/null
}

assert_outputs() {
  local case_dir="$1"
  local expected_exit="$2"

  jq -e \
    --argjson expected_exit "$expected_exit" '
      .schema_version == "franken-engine.remote-proof-retention-class-ledger.v1"
      and .residency_manifest_schema == "franken-engine.remote-proof-evidence-residency-manifest.v1"
      and .exit_code == $expected_exit
      and (.hash_basis.input_hash | length > 0)
      and (.hash_basis.manifest_hash | length > 0)
      and (.hash_basis.ledger_hash | length > 0)
      and (.artifact_paths.retention_class_ledger_json | length > 0)
      and (.artifact_paths.evidence_residency_manifest_json | length > 0)
      and (.artifact_paths.events_jsonl | length > 0)
      and (.artifact_paths.commands_txt | length > 0)
      and (.artifact_paths.report_md | length > 0)
    ' "${case_dir}/retention_class_ledger.json" >/dev/null

  jq -e '
      .schema_version == "franken-engine.remote-proof-evidence-residency-manifest.v1"
      and (.hash_basis.input_hash | length > 0)
      and (.hash_basis.manifest_hash | length > 0)
      and (.artifact_paths.evidence_residency_manifest_json | length > 0)
      and (.artifact_paths.retention_class_ledger_json | length > 0)
    ' "${case_dir}/evidence_residency_manifest.json" >/dev/null

  test -s "${case_dir}/events.jsonl"
  test -s "${case_dir}/commands.txt"
  test -s "${case_dir}/report.md"
}

run_case() {
  local tmp_root="$1"
  local case_name="$2"
  local bundle_json="$3"
  local mirror_json="$4"
  local batch_json="$5"
  local salvage_json="$6"
  local expected_exit="$7"
  local case_dir="${tmp_root}/${case_name}"
  local bundle_path="${case_dir}.bundle.json"
  local mirror_path="${case_dir}.mirror.json"
  local batch_path="${case_dir}.batch.json"
  local salvage_path="${case_dir}.salvage.json"
  local actual_exit output

  write_json "$bundle_path" "$bundle_json"
  write_json "$mirror_path" "$mirror_json"
  write_json "$batch_path" "$batch_json"
  write_json "$salvage_path" "$salvage_json"

  set +e
  output="$(
    "$ledger" \
      --output-dir "$case_dir" \
      --bundle-report-json "$bundle_path" \
      --mirror-manifest-json "$mirror_path" \
      --batch-manifest-json "$batch_path" \
      --salvage-receipt-json "$salvage_path" 2>&1
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

  tmp_parent="${REMOTE_PROOF_RETENTION_CLASS_LEDGER_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/remote-proof-retention-class-ledger.XXXXXX")"

  run_case \
    "$tmp_root" \
    "hot-replay" \
    '{"bundle_id":"bundle-hot","bundle_decision":"pass","expected_worker_id":"ts2","expected_target_dir":"/tmp/rch_target_bundle_hot","source_revision":"smoke-rev","artifact_paths":{"bundle_report_json":"/evidence/bundle-hot/bundle_report.json","run_manifest_json":"/evidence/bundle-hot/run_manifest.json","commands_txt":"/evidence/bundle-hot/commands.txt","events_jsonl":"/evidence/bundle-hot/events.jsonl","summary_md":"/evidence/bundle-hot/report.md"},"phase_results":[{"stdout_log":"/evidence/bundle-hot/phase_logs/check.stdout.log","stderr_log":"/evidence/bundle-hot/phase_logs/check.stderr.log"}]}' \
    '{"bundle_id":"bundle-hot","bundle_decision":"pass","artifacts":[{"path":"/evidence/bundle-hot/run_manifest.json","roles":["replay","manifest"],"replay_critical":true,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"path":"/evidence/bundle-hot/inspect-only.txt","roles":["inspect"],"replay_critical":false,"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],"retrieval_pack_artifacts":[{"path":"/evidence/bundle-hot/run_manifest.json","roles":["replay","manifest"],"replay_critical":true,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"artifact_paths":{"artifact_mirror_manifest_json":"/control/bundle-hot/artifact_mirror_manifest.json","retrieval_pack_json":"/control/bundle-hot/retrieval_pack.json","retrieval_verification_report_json":"/control/bundle-hot/retrieval_verification_report.json","report_md":"/control/bundle-hot/mirror-report.md","events_jsonl":"/control/bundle-hot/mirror-events.jsonl","commands_txt":"/control/bundle-hot/mirror-commands.txt"}}' \
    '{"packing_decision":"pass","batches":[{"batch_id":"batch-hot","worker_id":"ts2","target_dir":"/tmp/rch_target_bundle_hot","bundle_ids":["bundle-hot"]}],"artifact_paths":{"batch_manifest_json":"/control/bundle-hot/batch_manifest.json","report_md":"/control/bundle-hot/batch-report.md","events_jsonl":"/control/bundle-hot/batch-events.jsonl","commands_txt":"/control/bundle-hot/batch-commands.txt"}}' \
    '{"bundle_id":"bundle-hot","workflow_state":"clean_finished","recovery_recommendation":"no_salvage_needed","bundle_artifact_paths":{"bundle_report_json":"/evidence/bundle-hot/bundle_report.json"},"upstream_artifact_paths":{"bundle_report_json":"/evidence/bundle-hot/bundle_report.json"},"artifact_paths":{"salvage_receipt_json":"/control/bundle-hot/salvage_receipt.json","report_md":"/control/bundle-hot/salvage-report.md","events_jsonl":"/control/bundle-hot/salvage-events.jsonl","commands_txt":"/control/bundle-hot/salvage-commands.txt"}}' \
    0

  assert_entry_class "${tmp_root}/hot-replay/evidence_residency_manifest.json" "/evidence/bundle-hot/run_manifest.json" "hot_replay_critical"
  record_pass "hot-replay run manifest stays hot"
  assert_entry_class "${tmp_root}/hot-replay/evidence_residency_manifest.json" "/evidence/bundle-hot/inspect-only.txt" "cold_archival"
  record_pass "inspect-only artifact demotes to cold archival"

  run_case \
    "$tmp_root" \
    "salvage-pinned" \
    '{"bundle_id":"bundle-salvage","bundle_decision":"fail_closed","expected_worker_id":"vmi1156319","expected_target_dir":"/tmp/rch_target_bundle_salvage","source_revision":"smoke-rev","artifact_paths":{"bundle_report_json":"/evidence/bundle-salvage/bundle_report.json","run_manifest_json":"/evidence/bundle-salvage/run_manifest.json","summary_md":"/evidence/bundle-salvage/report.md"},"phase_results":[{"stdout_log":"/evidence/bundle-salvage/phase_logs/test.stdout.log","stderr_log":"/evidence/bundle-salvage/phase_logs/test.stderr.log"}]}' \
    '{"bundle_id":"bundle-salvage","bundle_decision":"fail_closed","artifacts":[{"path":"/evidence/bundle-salvage/run_manifest.json","roles":["replay"],"replay_critical":true,"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"retrieval_pack_artifacts":[{"path":"/evidence/bundle-salvage/run_manifest.json","roles":["replay"],"replay_critical":true,"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"artifact_paths":{"artifact_mirror_manifest_json":"/control/bundle-salvage/artifact_mirror_manifest.json","retrieval_pack_json":"/control/bundle-salvage/retrieval_pack.json","retrieval_verification_report_json":"/control/bundle-salvage/retrieval_verification_report.json"}}' \
    '{"packing_decision":"pass","batches":[{"batch_id":"batch-salvage","worker_id":"vmi1156319","target_dir":"/tmp/rch_target_bundle_salvage","bundle_ids":["bundle-salvage"]}],"artifact_paths":{"batch_manifest_json":"/control/bundle-salvage/batch_manifest.json"}}' \
    '{"bundle_id":"bundle-salvage","workflow_state":"orphan_reconciliation_required","recovery_recommendation":"clear_orphan_before_retry","bundle_artifact_paths":{"bundle_report_json":"/evidence/bundle-salvage/bundle_report.json","run_manifest_json":"/evidence/bundle-salvage/run_manifest.json"},"upstream_artifact_paths":{"worker_truth_report_json":"/control/bundle-salvage/worker_truth_report.json"},"artifact_paths":{"salvage_receipt_json":"/control/bundle-salvage/salvage_receipt.json","report_md":"/control/bundle-salvage/salvage-report.md","events_jsonl":"/control/bundle-salvage/salvage-events.jsonl","commands_txt":"/control/bundle-salvage/salvage-commands.txt"}}' \
    0

  assert_entry_class "${tmp_root}/salvage-pinned/evidence_residency_manifest.json" "/evidence/bundle-salvage/bundle_report.json" "salvage_pinned"
  record_pass "failed bundle evidence is pinned by salvage workflow"
  assert_entry_class "${tmp_root}/salvage-pinned/evidence_residency_manifest.json" "/control/bundle-salvage/salvage_receipt.json" "salvage_pinned"
  record_pass "salvage receipt stays pinned during reconciliation"

  run_case \
    "$tmp_root" \
    "hot-replay-repeat" \
    '{"bundle_id":"bundle-hot","bundle_decision":"pass","expected_worker_id":"ts2","expected_target_dir":"/tmp/rch_target_bundle_hot","source_revision":"smoke-rev","artifact_paths":{"bundle_report_json":"/evidence/bundle-hot/bundle_report.json","run_manifest_json":"/evidence/bundle-hot/run_manifest.json","commands_txt":"/evidence/bundle-hot/commands.txt","events_jsonl":"/evidence/bundle-hot/events.jsonl","summary_md":"/evidence/bundle-hot/report.md"},"phase_results":[{"stdout_log":"/evidence/bundle-hot/phase_logs/check.stdout.log","stderr_log":"/evidence/bundle-hot/phase_logs/check.stderr.log"}]}' \
    '{"bundle_id":"bundle-hot","bundle_decision":"pass","artifacts":[{"path":"/evidence/bundle-hot/run_manifest.json","roles":["replay","manifest"],"replay_critical":true,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"path":"/evidence/bundle-hot/inspect-only.txt","roles":["inspect"],"replay_critical":false,"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],"retrieval_pack_artifacts":[{"path":"/evidence/bundle-hot/run_manifest.json","roles":["replay","manifest"],"replay_critical":true,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"artifact_paths":{"artifact_mirror_manifest_json":"/control/bundle-hot/artifact_mirror_manifest.json","retrieval_pack_json":"/control/bundle-hot/retrieval_pack.json","retrieval_verification_report_json":"/control/bundle-hot/retrieval_verification_report.json","report_md":"/control/bundle-hot/mirror-report.md","events_jsonl":"/control/bundle-hot/mirror-events.jsonl","commands_txt":"/control/bundle-hot/mirror-commands.txt"}}' \
    '{"packing_decision":"pass","batches":[{"batch_id":"batch-hot","worker_id":"ts2","target_dir":"/tmp/rch_target_bundle_hot","bundle_ids":["bundle-hot"]}],"artifact_paths":{"batch_manifest_json":"/control/bundle-hot/batch_manifest.json","report_md":"/control/bundle-hot/batch-report.md","events_jsonl":"/control/bundle-hot/batch-events.jsonl","commands_txt":"/control/bundle-hot/batch-commands.txt"}}' \
    '{"bundle_id":"bundle-hot","workflow_state":"clean_finished","recovery_recommendation":"no_salvage_needed","bundle_artifact_paths":{"bundle_report_json":"/evidence/bundle-hot/bundle_report.json"},"upstream_artifact_paths":{"bundle_report_json":"/evidence/bundle-hot/bundle_report.json"},"artifact_paths":{"salvage_receipt_json":"/control/bundle-hot/salvage_receipt.json","report_md":"/control/bundle-hot/salvage-report.md","events_jsonl":"/control/bundle-hot/salvage-events.jsonl","commands_txt":"/control/bundle-hot/salvage-commands.txt"}}' \
    0

  hash_a="$(jq -r '.hash_basis.manifest_hash' "${tmp_root}/hot-replay/evidence_residency_manifest.json")"
  hash_b="$(jq -r '.hash_basis.manifest_hash' "${tmp_root}/hot-replay-repeat/evidence_residency_manifest.json")"
  if [[ "$hash_a" != "$hash_b" ]]; then
    record_failure "stable manifest hash mismatch for repeated fixture"
    exit 1
  fi
  record_pass "stable manifest hash retained across repeated fixture"

  printf 'remote_proof_retention_class_ledger_smoke_artifacts=%s\n' "$tmp_root"
}

run_check() {
  bash -n "$ledger"
  bash -n "${BASH_SOURCE[0]}"
  shellcheck -x "$ledger" "${BASH_SOURCE[0]}"
  jq empty "${root_dir}/docs/remote_proof_retention_class_contract_v1.json" >/dev/null
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
