#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exporter="${root_dir}/scripts/remote_proof_archive_exporter.sh"
golden_dir="${REMOTE_PROOF_ARCHIVE_EXPORTER_GOLDEN_DIR:-${root_dir}/scripts/testdata/goldens}"

record_pass() {
  printf 'PASS remote-proof-archive-exporter %s\n' "$1"
}

record_failure() {
  printf 'FAIL remote-proof-archive-exporter %s\n' "$1" >&2
}

golden_case_names() {
  cat <<'EOF'
archive-export-success
missing-replay-critical
restore-verify-success
tampered-archive-fails
EOF
}

write_json() {
  local path="$1"
  local text="$2"
  printf '%s\n' "$text" >"$path"
}

canonicalize_report() {
  local report_path="$1"
  local tmp_root="$2"

  jq --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "string" then
        gsub($tmp_root; "[SMOKE_ROOT]")
        | gsub("/tmp/rch_target_"; "[RCH_TARGET]/")
        | gsub("/tmp/[A-Za-z0-9._-]+"; "[TMP_PATH]")
      elif type == "array" then
        map(scrub)
      elif type == "object" then
        with_entries(.value |= scrub)
      else
        .
      end;
    scrub
  ' "$report_path"
}

assert_case_golden() {
  local case_name="$1"
  local report_path="$2"
  local tmp_root="$3"
  local golden_path="${golden_dir}/remote_proof_archive_exporter_${case_name}.golden"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    mkdir -p "$golden_dir"
    canonicalize_report "$report_path" "$tmp_root" >"$golden_path"
    return 0
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "${case_name} missing golden"
    return 1
  fi

  if ! diff -u "$golden_path" <(canonicalize_report "$report_path" "$tmp_root"); then
    record_failure "${case_name} golden drift"
    return 1
  fi
}

goldens_shape_ok() {
  local missing=0
  local case_name golden_path

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    return 0
  fi

  while IFS= read -r case_name; do
    golden_path="${golden_dir}/remote_proof_archive_exporter_${case_name}.golden"
    if [[ ! -f "$golden_path" ]]; then
      record_failure "${case_name} missing checked-in golden"
      missing=1
      continue
    fi
    jq empty "$golden_path" >/dev/null || {
      record_failure "${case_name} invalid golden json"
      missing=1
    }
  done < <(golden_case_names)

  [[ "$missing" -eq 0 ]]
}

assert_outputs() {
  local case_dir="$1"
  local expected_exit="$2"
  jq -e \
    --argjson expected_exit "$expected_exit" '
      .schema_version == "franken-engine.remote-proof-archive-restore-verification.v1"
      and .exit_code == $expected_exit
      and (.hash_basis.verification_hash | length > 0)
      and (.artifact_paths.archive_pack_json | length > 0)
      and (.artifact_paths.restore_verification_report_json | length > 0)
      and (.artifact_paths.events_jsonl | length > 0)
      and (.artifact_paths.commands_txt | length > 0)
      and (.artifact_paths.report_md | length > 0)
    ' "${case_dir}/restore_verification_report.json" >/dev/null

  test -s "${case_dir}/archive_pack.json"
  test -s "${case_dir}/events.jsonl"
  test -s "${case_dir}/commands.txt"
  test -s "${case_dir}/report.md"
}

run_export_case() {
  local tmp_root="$1"
  local case_name="$2"
  local residency_json="$3"
  local compaction_json="$4"
  local source_json="$5"
  local expected_exit="$6"
  local case_dir="${tmp_root}/${case_name}"
  local residency_path="${case_dir}.residency.json"
  local compaction_path="${case_dir}.compaction.json"
  local source_path="${case_dir}.source.json"
  local actual_exit output

  write_json "$residency_path" "$residency_json"
  write_json "$compaction_path" "$compaction_json"
  write_json "$source_path" "$source_json"

  set +e
  output="$(
    bash "$exporter" \
      --output-dir "$case_dir" \
      --residency-manifest-json "$residency_path" \
      --compaction-plan-json "$compaction_path" \
      --archive-source-files-json "$source_path" 2>&1
  )"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${actual_exit}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi
  assert_outputs "$case_dir" "$expected_exit"
  assert_case_golden "$case_name" "${case_dir}/restore_verification_report.json" "$tmp_root"
}

run_verify_case() {
  local tmp_root="$1"
  local case_name="$2"
  local residency_json="$3"
  local compaction_json="$4"
  local pack_json="$5"
  local expected_exit="$6"
  local case_dir="${tmp_root}/${case_name}"
  local residency_path="${case_dir}.residency.json"
  local compaction_path="${case_dir}.compaction.json"
  local pack_path="${case_dir}.pack-input.json"
  local actual_exit output

  write_json "$residency_path" "$residency_json"
  write_json "$compaction_path" "$compaction_json"
  write_json "$pack_path" "$pack_json"

  set +e
  output="$(
    bash "$exporter" \
      --output-dir "$case_dir" \
      --residency-manifest-json "$residency_path" \
      --compaction-plan-json "$compaction_path" \
      --archive-pack-json "$pack_path" 2>&1
  )"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${actual_exit}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi
  assert_outputs "$case_dir" "$expected_exit"
  assert_case_golden "$case_name" "${case_dir}/restore_verification_report.json" "$tmp_root"
}

run_selftest() {
  local tmp_parent tmp_root hash_a hash_b
  local residency_json compaction_json source_json success_pack tampered_pack

  tmp_parent="${REMOTE_PROOF_ARCHIVE_EXPORTER_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/remote-proof-archive-exporter.XXXXXX")"

  residency_json='{"bundle_id":"bundle-archive","retention_entries":[{"path":"/archive/replay-retained.bin","retention_class":"hot_replay_critical","roles":["replay"],"replay_critical":true,"content_addresses":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]},{"path":"/archive/status-report.json","retention_class":"warm_operator_inspectable","roles":["inspect","bundle_report"],"replay_critical":false,"content_addresses":["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]},{"path":"/archive/replay-duplicate.bin","retention_class":"hot_replay_critical","roles":["replay"],"replay_critical":true,"content_addresses":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}],"artifact_paths":{"evidence_residency_manifest_json":"/control/residency.json"}}'
  compaction_json='{"bundle_id":"bundle-archive","compacted_groups":[{"content_address":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","retained_path":"/archive/replay-retained.bin","compacted_paths":["/archive/replay-duplicate.bin"]}],"blocked_groups":[],"artifact_paths":{"remote_proof_compaction_plan_json":"/control/compaction.json"}}'
  source_json='{"source_files":[{"path":"/archive/replay-retained.bin","content_address":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","roles":["replay"],"replay_critical":true,"size_bytes":64},{"path":"/archive/status-report.json","content_address":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","roles":["inspect","bundle_report"],"replay_critical":false,"size_bytes":32}]}'

  run_export_case "$tmp_root" "archive-export-success" "$residency_json" "$compaction_json" "$source_json" 0
  jq -e '
      .restore_verdict == "verified"
      and .archive_state == "cold_archived"
      and (.missing_replay_paths | length) == 0
      and .tampered_manifest_hash == false
    ' "${tmp_root}/archive-export-success/restore_verification_report.json" >/dev/null
  jq -e '
      .schema_version == "franken-engine.remote-proof-archive-pack.v1"
      and .restore_verdict == "verified"
      and (.archived_artifacts | length) == 2
    ' "${tmp_root}/archive-export-success/archive_pack.json" >/dev/null
  record_pass "archive export succeeds with replay-critical and status artifacts"

  run_export_case \
    "$tmp_root" \
    "missing-replay-critical" \
    "$residency_json" \
    "$compaction_json" \
    '{"source_files":[{"path":"/archive/status-report.json","content_address":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","roles":["inspect","bundle_report"],"replay_critical":false,"size_bytes":32}]}' \
    42
  jq -e '
      .restore_verdict == "fail_closed"
      and .reason == "archive pack is missing replay-critical artifacts"
    ' "${tmp_root}/missing-replay-critical/restore_verification_report.json" >/dev/null
  record_pass "missing replay-critical artifact fails closed"

  success_pack="$(cat "${tmp_root}/archive-export-success/archive_pack.json")"
  run_verify_case "$tmp_root" "restore-verify-success" "$residency_json" "$compaction_json" "$success_pack" 0
  jq -e '.restore_verdict == "verified"' "${tmp_root}/restore-verify-success/restore_verification_report.json" >/dev/null
  record_pass "restore verification succeeds with stable hashes"

  tampered_pack='{
    "schema_version":"franken-engine.remote-proof-archive-pack.v1",
    "bundle_id":"bundle-archive",
    "archive_state":"cold_archived",
    "restore_verdict":"verified",
    "archived_artifacts":[
      {"path":"/archive/replay-retained.bin","original_paths":["/archive/replay-retained.bin","/archive/replay-duplicate.bin"],"retention_class":"hot_replay_critical","roles":["replay"],"replay_critical":true,"content_address":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
      {"path":"/archive/status-report.json","original_paths":["/archive/status-report.json"],"retention_class":"warm_operator_inspectable","roles":["inspect","bundle_report"],"replay_critical":false,"content_address":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
    ],
    "required_replay_paths":["/archive/replay-retained.bin"],
    "blocked_compaction_groups":[],
    "archive_artifact_count":2,
    "hash_basis":{"archive_manifest_hash":"deadbeef"},
    "artifact_paths":{"archive_pack_json":"/archive/fake/archive_pack.json"}
  }'
  run_verify_case "$tmp_root" "tampered-archive-fails" "$residency_json" "$compaction_json" "$tampered_pack" 42
  jq -e '
      .restore_verdict == "fail_closed"
      and .tampered_manifest_hash == true
    ' "${tmp_root}/tampered-archive-fails/restore_verification_report.json" >/dev/null
  record_pass "tampered archive restore fails closed"

  hash_a="$(jq -r '.hash_basis.verification_hash' "${tmp_root}/restore-verify-success/restore_verification_report.json")"
  hash_b="$(jq -r '.hash_basis.verification_hash' "${tmp_root}/archive-export-success/restore_verification_report.json")"
  if [[ "$hash_a" != "$hash_b" ]]; then
    record_failure "stable verification hash mismatch for repeated success fixture"
    exit 1
  fi
  record_pass "stable verification hash retained across repeated fixture"

  printf 'remote_proof_archive_exporter_smoke_artifacts=%s\n' "$tmp_root"
}

run_check() {
  bash -n "$exporter"
  bash -n "${BASH_SOURCE[0]}"
  shellcheck -x "$exporter" "${BASH_SOURCE[0]}"
  jq empty "${root_dir}/docs/remote_proof_archive_exporter_contract_v1.json" >/dev/null
  goldens_shape_ok
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
