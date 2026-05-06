#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/remote_proof_compaction_planner.sh"

record_pass() {
  printf 'PASS remote-proof-compaction-planner %s\n' "$1"
}

record_failure() {
  printf 'FAIL remote-proof-compaction-planner %s\n' "$1" >&2
}

write_json() {
  local path="$1"
  local text="$2"
  printf '%s\n' "$text" >"$path"
}

assert_outputs() {
  local case_dir="$1"
  jq -e '
      .schema_version == "franken-engine.remote-proof-compaction-plan.v1"
      and (.plan_id | length > 0)
      and (.hash_basis.input_hash | length > 0)
      and (.hash_basis.plan_hash | length > 0)
      and (.artifact_paths.remote_proof_compaction_plan_json | length > 0)
      and (.artifact_paths.events_jsonl | length > 0)
      and (.artifact_paths.commands_txt | length > 0)
      and (.artifact_paths.report_md | length > 0)
    ' "${case_dir}/remote_proof_compaction_plan.json" >/dev/null

  test -s "${case_dir}/events.jsonl"
  test -s "${case_dir}/commands.txt"
  test -s "${case_dir}/report.md"
}

run_case() {
  local tmp_root="$1"
  local case_name="$2"
  local residency_json="$3"
  local mirror_json="$4"
  local expected_exit="$5"
  local case_dir="${tmp_root}/${case_name}"
  local residency_path="${case_dir}.residency.json"
  local mirror_path="${case_dir}.mirror.json"
  local actual_exit output

  write_json "$residency_path" "$residency_json"
  write_json "$mirror_path" "$mirror_json"

  set +e
  output="$(
    bash "$planner" \
      --output-dir "$case_dir" \
      --residency-manifest-json "$residency_path" \
      --mirror-manifest-json "$mirror_path" 2>&1
  )"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${actual_exit}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  assert_outputs "$case_dir"
}

run_selftest() {
  local tmp_parent tmp_root
  local hash_a hash_b

  tmp_parent="${REMOTE_PROOF_COMPACTION_PLANNER_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/remote-proof-compaction-planner.XXXXXX")"

  run_case \
    "$tmp_root" \
    "duplicate-replay-compacts" \
    '{"bundle_id":"bundle-compact","bundle_decision":"pass","retention_entries":[{"path":"/mirror/replay-a.bin","retention_class":"hot_replay_critical","retention_reason":"hot","sources":["mirror_artifact"],"roles":["replay"],"replay_critical":true,"content_addresses":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]},{"path":"/mirror/replay-b.bin","retention_class":"hot_replay_critical","retention_reason":"hot","sources":["mirror_artifact"],"roles":["replay"],"replay_critical":true,"content_addresses":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}],"artifact_paths":{"evidence_residency_manifest_json":"/control/residency.json"}}' \
    '{"bundle_id":"bundle-compact","artifacts":[{"path":"/mirror/replay-a.bin","roles":["replay"],"replay_critical":true,"content_address":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"path":"/mirror/replay-b.bin","roles":["replay"],"replay_critical":true,"content_address":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"artifact_paths":{"artifact_mirror_manifest_json":"/control/mirror.json"}}' \
    0

  jq -e '
      .plan_decision == "pass"
      and (.compacted_groups | length) == 1
      and .compacted_groups[0].retained_path == "/mirror/replay-a.bin"
      and (.compacted_groups[0].compacted_paths == ["/mirror/replay-b.bin"])
      and .compacted_groups[0].reason? == null
    ' "${tmp_root}/duplicate-replay-compacts/remote_proof_compaction_plan.json" >/dev/null
  record_pass "duplicate replay artifacts compact into one retained address"

  run_case \
    "$tmp_root" \
    "retention-mismatch-blocked" \
    '{"bundle_id":"bundle-retention-mismatch","bundle_decision":"pass","retention_entries":[{"path":"/mirror/replay-hot.bin","retention_class":"hot_replay_critical","retention_reason":"hot","sources":["mirror_artifact"],"roles":["replay"],"replay_critical":true,"content_addresses":["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]},{"path":"/mirror/replay-cold.bin","retention_class":"cold_archival","retention_reason":"cold","sources":["mirror_artifact"],"roles":["replay"],"replay_critical":true,"content_addresses":["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}],"artifact_paths":{"evidence_residency_manifest_json":"/control/residency.json"}}' \
    '{"bundle_id":"bundle-retention-mismatch","artifacts":[{"path":"/mirror/replay-hot.bin","roles":["replay"],"replay_critical":true,"content_address":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},{"path":"/mirror/replay-cold.bin","roles":["replay"],"replay_critical":true,"content_address":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],"artifact_paths":{"artifact_mirror_manifest_json":"/control/mirror.json"}}' \
    0

  jq -e '
      (.blocked_groups | length) == 1
      and .blocked_groups[0].reason == "retention_class_mismatch"
    ' "${tmp_root}/retention-mismatch-blocked/remote_proof_compaction_plan.json" >/dev/null
  record_pass "retention-class mismatch blocks compaction"

  run_case \
    "$tmp_root" \
    "provenance-mismatch-blocked" \
    '{"bundle_id":"bundle-provenance-mismatch","bundle_decision":"pass","retention_entries":[{"path":"/mirror/replay-left.bin","retention_class":"hot_replay_critical","retention_reason":"hot","sources":["mirror_artifact"],"roles":["replay"],"replay_critical":true,"content_addresses":["sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]},{"path":"/mirror/replay-right.bin","retention_class":"hot_replay_critical","retention_reason":"hot","sources":["bundle_artifact_path"],"roles":["replay"],"replay_critical":true,"content_addresses":["sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]}],"artifact_paths":{"evidence_residency_manifest_json":"/control/residency.json"}}' \
    '{"bundle_id":"bundle-provenance-mismatch","artifacts":[{"path":"/mirror/replay-left.bin","roles":["replay"],"replay_critical":true,"content_address":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},{"path":"/mirror/replay-right.bin","roles":["replay"],"replay_critical":true,"content_address":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"artifact_paths":{"artifact_mirror_manifest_json":"/control/mirror.json"}}' \
    0

  jq -e '
      (.blocked_groups | length) == 1
      and .blocked_groups[0].reason == "provenance_mismatch"
    ' "${tmp_root}/provenance-mismatch-blocked/remote_proof_compaction_plan.json" >/dev/null
  record_pass "provenance mismatch blocks compaction"

  run_case \
    "$tmp_root" \
    "duplicate-replay-repeat" \
    '{"bundle_id":"bundle-compact","bundle_decision":"pass","retention_entries":[{"path":"/mirror/replay-a.bin","retention_class":"hot_replay_critical","retention_reason":"hot","sources":["mirror_artifact"],"roles":["replay"],"replay_critical":true,"content_addresses":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]},{"path":"/mirror/replay-b.bin","retention_class":"hot_replay_critical","retention_reason":"hot","sources":["mirror_artifact"],"roles":["replay"],"replay_critical":true,"content_addresses":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}],"artifact_paths":{"evidence_residency_manifest_json":"/control/residency.json"}}' \
    '{"bundle_id":"bundle-compact","artifacts":[{"path":"/mirror/replay-a.bin","roles":["replay"],"replay_critical":true,"content_address":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"path":"/mirror/replay-b.bin","roles":["replay"],"replay_critical":true,"content_address":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"artifact_paths":{"artifact_mirror_manifest_json":"/control/mirror.json"}}' \
    0

  hash_a="$(jq -r '.hash_basis.plan_hash' "${tmp_root}/duplicate-replay-compacts/remote_proof_compaction_plan.json")"
  hash_b="$(jq -r '.hash_basis.plan_hash' "${tmp_root}/duplicate-replay-repeat/remote_proof_compaction_plan.json")"
  if [[ "$hash_a" != "$hash_b" ]]; then
    record_failure "stable plan hash mismatch for repeated fixture"
    exit 1
  fi
  record_pass "stable plan hash retained across repeated fixture"

  printf 'remote_proof_compaction_planner_smoke_artifacts=%s\n' "$tmp_root"
}

run_check() {
  bash -n "$planner"
  bash -n "${BASH_SOURCE[0]}"
  shellcheck -x "$planner" "${BASH_SOURCE[0]}"
  jq empty "${root_dir}/docs/remote_proof_compaction_planner_contract_v1.json" >/dev/null
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
