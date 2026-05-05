#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/proof_reuse_cache_planner.sh"
docs_path="${root_dir}/docs/PROOF_REUSE_CACHE_PLANNER.md"

record_pass() {
  printf 'PASS proof-reuse-cache %s\n' "$1"
}

record_failure() {
  printf 'FAIL proof-reuse-cache %s\n' "$1" >&2
}

write_proof_index() {
  local output_path="$1"
  local metadata_json="$2"
  local artifact_id="$3"
  local artifact_path="$4"
  local source_revision="$5"

  jq -n \
    --arg schema_version "franken-engine.proof-evidence-query.v1" \
    --arg artifact_id "$artifact_id" \
    --arg artifact_path "$artifact_path" \
    --arg source_revision "$source_revision" \
    --arg metadata_json "$metadata_json" \
    '{
      schema_version: $schema_version,
      query_kind: "by_bead",
      rows: [
        {
          evidence_id: 1,
          bead_id: "bd-proof",
          source_revision: $source_revision,
          artifact_id: $artifact_id,
          artifact_path: $artifact_path,
          artifact_role: "proof_manifest",
          artifact_sha256: "sha-proof",
          receipt_kind: "proof_artifact",
          gate_status: "pass",
          generated_timestamp_ms: 1700000000000,
          freshness_deadline_ms: 1700000100000,
          metadata_json: $metadata_json
        }
      ]
    }' >"$output_path"
}

write_multi_row_proof_index() {
  local output_path="$1"
  local shell_metadata="$2"
  local heavy_metadata="$3"

  jq -n \
    --arg schema_version "franken-engine.proof-evidence-query.v1" \
    --arg shell_metadata "$shell_metadata" \
    --arg heavy_metadata "$heavy_metadata" \
    '{
      schema_version: $schema_version,
      query_kind: "by_bead",
      rows: [
        {
          evidence_id: 1,
          bead_id: "bd-proof",
          source_revision: "current-rev",
          artifact_id: "artifact-shell",
          artifact_path: "artifacts/shell-proof/report.json",
          artifact_role: "gate_report",
          artifact_sha256: "sha-shell",
          receipt_kind: "gate_report",
          gate_status: "pass",
          generated_timestamp_ms: 1700000000000,
          freshness_deadline_ms: 1700000100000,
          metadata_json: $shell_metadata
        },
        {
          evidence_id: 2,
          bead_id: "bd-proof",
          source_revision: "current-rev",
          artifact_id: "artifact-heavy",
          artifact_path: "artifacts/heavy-proof/report.json",
          artifact_role: "proof_manifest",
          artifact_sha256: "sha-heavy",
          receipt_kind: "proof_artifact",
          gate_status: "pass",
          generated_timestamp_ms: 1700000000000,
          freshness_deadline_ms: 1700000100000,
          metadata_json: $heavy_metadata
        }
      ]
    }' >"$output_path"
}

write_freshness_report() {
  local output_path="$1"
  local artifact_id="$2"
  local artifact_path="$3"
  local freshness_state="$4"
  local reusable="$5"
  local covered_paths_json="$6"
  local source_revision="${7:-current-rev}"

  jq -n \
    --arg schema_version "franken-engine.proof-freshness-decay-report.v1" \
    --arg artifact_id "$artifact_id" \
    --arg artifact_path "$artifact_path" \
    --arg freshness_state "$freshness_state" \
    --arg source_revision "$source_revision" \
    --arg expected_source_revision "current-rev" \
    --argjson reusable "$reusable" \
    --argjson covered_paths "$covered_paths_json" \
    '{
      schema_version: $schema_version,
      proof_artifact_id: $artifact_id,
      artifact_path: $artifact_path,
      source_revision: $source_revision,
      expected_source_revision: $expected_source_revision,
      freshness_state: $freshness_state,
      reusable: $reusable,
      reason: ("state=" + $freshness_state),
      recommended_next_action: "follow report",
      covered_paths: $covered_paths
    }' >"$output_path"
}

write_incomplete_freshness_report() {
  local output_path="$1"
  local artifact_id="$2"
  local artifact_path="$3"

  jq -n \
    --arg schema_version "franken-engine.proof-freshness-decay-report.v1" \
    --arg artifact_id "$artifact_id" \
    --arg artifact_path "$artifact_path" \
    '{
      schema_version: $schema_version,
      proof_artifact_id: $artifact_id,
      artifact_path: $artifact_path,
      freshness_state: "fresh",
      reusable: true
    }' >"$output_path"
}

assert_plan() {
  local plan_path="$1"
  local expected_decision="$2"
  local expected_hits="$3"
  local expected_refreshes="$4"
  local expected_invalid="$5"

  jq -e \
    --arg expected_decision "$expected_decision" \
    --argjson expected_hits "$expected_hits" \
    --argjson expected_refreshes "$expected_refreshes" \
    --argjson expected_invalid "$expected_invalid" \
    '.schema_version == "franken-engine.proof-reuse-cache-plan.v1"
      and .proof_cache_decision == $expected_decision
      and (.cache_hit_artifacts | length) == $expected_hits
      and (.required_refreshes | length) == $expected_refreshes
      and (.invalid_artifacts | length) == $expected_invalid
      and (.artifact_paths.proof_cache_plan_json | length > 0)
      and (.artifact_paths.events_jsonl | length > 0)
      and (.artifact_paths.commands_txt | length > 0)
      and (.artifact_paths.report_md | length > 0)' \
    "$plan_path" >/dev/null
}

run_case() {
  local tmp_root="$1"
  local case_name="$2"
  local proof_index_path="$3"
  local expected_decision="$4"
  local expected_hits="$5"
  local expected_refreshes="$6"
  local expected_invalid="$7"
  local expected_exit="$8"
  shift 8

  local case_dir="${tmp_root}/${case_name}"
  local actual_exit output

  set +e
  output="$(
    "$planner" \
      --proof-index-json "$proof_index_path" \
      --expected-source-revision current-rev \
      --output-dir "$case_dir" \
      "$@" 2>&1
  )"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${actual_exit}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  assert_plan "${case_dir}/proof_cache_plan.json" "$expected_decision" "$expected_hits" "$expected_refreshes" "$expected_invalid"
  test -s "${case_dir}/events.jsonl"
  test -s "${case_dir}/commands.txt"
  test -s "${case_dir}/report.md"
  record_pass "${case_name} planned as ${expected_decision}"
}

run_check() {
  local scope_file

  bash -n "$planner"
  bash -n "${BASH_SOURCE[0]}"
  record_pass "bash syntax"

  grep -q 'franken-engine.proof-reuse-cache-plan.v1' "$docs_path"
  grep -q 'rch exec -- env CARGO_TARGET_DIR=' "$docs_path"
  grep -q './scripts/proof_reuse_cache_planner.sh' "$docs_path"
  record_pass "docs contract and rch guidance"

  scope_file="${PROOF_REUSE_CACHE_SMOKE_SCOPE_FILE:-/tmp/franken-engine-proof-reuse-cache-scope.txt}"
  printf '%s\n' \
    "scripts/proof_reuse_cache_planner.sh" \
    "scripts/e2e/proof_reuse_cache_planner_smoke.sh" \
    "docs/PROOF_REUSE_CACHE_PLANNER.md" \
    >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${PROOF_REUSE_CACHE_SMOKE_POLICY_DIR:-/tmp/franken-engine-proof-reuse-cache-policy}" \
    --scope-file "$scope_file" >/dev/null
  record_pass "rch policy compliance"
}

run_selftest() {
  local tmp_parent tmp_root
  local exact_hit_index stale_time_index stale_source_index changed_path_index incomplete_index superseded_index mixed_index
  local shell_metadata heavy_metadata

  tmp_parent="${PROOF_REUSE_CACHE_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/proof-reuse-cache.XXXXXX")"

  exact_hit_index="${tmp_root}/exact-hit-index.json"
  stale_time_index="${tmp_root}/stale-time-index.json"
  stale_source_index="${tmp_root}/stale-source-index.json"
  changed_path_index="${tmp_root}/changed-path-index.json"
  incomplete_index="${tmp_root}/incomplete-index.json"
  superseded_index="${tmp_root}/superseded-index.json"
  mixed_index="${tmp_root}/mixed-index.json"

  shell_metadata="$(jq -nc '{covered_paths:["scripts/e2e/proof_cost_history_index_smoke.sh"], refresh_command:"./scripts/e2e/proof_cost_history_index_smoke.sh check"}')"
  heavy_metadata="$(jq -nc '{covered_paths:["crates/franken-engine/src/proof_evidence_index.rs"], refresh_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_proof_reuse cargo test -p frankenengine-engine --test proof_evidence_index_integration -- --nocapture"}')"

  write_proof_index "$exact_hit_index" "$shell_metadata" "artifact-shell" "artifacts/shell-proof/report.json" "current-rev"
  write_proof_index "$stale_time_index" "$heavy_metadata" "artifact-heavy" "artifacts/heavy-proof/report.json" "current-rev"
  write_proof_index "$stale_source_index" "$heavy_metadata" "artifact-heavy" "artifacts/heavy-proof/report.json" "old-rev"
  write_proof_index "$changed_path_index" "$heavy_metadata" "artifact-heavy" "artifacts/heavy-proof/report.json" "current-rev"
  write_proof_index "$incomplete_index" "$heavy_metadata" "artifact-heavy" "artifacts/heavy-proof/report.json" "current-rev"
  write_proof_index "$superseded_index" "$heavy_metadata" "artifact-heavy" "artifacts/heavy-proof/report.json" "current-rev"
  write_multi_row_proof_index "$mixed_index" "$shell_metadata" "$heavy_metadata"

  write_freshness_report "${tmp_root}/exact-hit.json" "artifact-shell" "artifacts/shell-proof/report.json" "fresh" true '["scripts/e2e/proof_cost_history_index_smoke.sh"]'
  write_freshness_report "${tmp_root}/stale-time.json" "artifact-heavy" "artifacts/heavy-proof/report.json" "stale_by_time" false '["crates/franken-engine/src/proof_evidence_index.rs"]'
  write_freshness_report "${tmp_root}/stale-source.json" "artifact-heavy" "artifacts/heavy-proof/report.json" "stale_by_source_revision" false '["crates/franken-engine/src/proof_evidence_index.rs"]' "old-rev"
  write_freshness_report "${tmp_root}/changed-path.json" "artifact-heavy" "artifacts/heavy-proof/report.json" "fresh" true '["crates/franken-engine/src/proof_evidence_index.rs"]'
  write_incomplete_freshness_report "${tmp_root}/incomplete.json" "artifact-heavy" "artifacts/heavy-proof/report.json"
  write_freshness_report "${tmp_root}/superseded.json" "artifact-heavy" "artifacts/heavy-proof/report.json" "superseded" false '["crates/franken-engine/src/proof_evidence_index.rs"]'
  write_freshness_report "${tmp_root}/mixed-shell.json" "artifact-shell" "artifacts/shell-proof/report.json" "fresh" true '["scripts/e2e/proof_cost_history_index_smoke.sh"]'
  write_freshness_report "${tmp_root}/mixed-heavy.json" "artifact-heavy" "artifacts/heavy-proof/report.json" "stale_by_time" false '["crates/franken-engine/src/proof_evidence_index.rs"]'

  run_case "$tmp_root" "exact-cache-hit" "$exact_hit_index" "cache_hit" 1 0 0 0 \
    --freshness-report "${tmp_root}/exact-hit.json"

  run_case "$tmp_root" "stale-by-time-miss" "$stale_time_index" "refresh_required" 0 1 0 0 \
    --freshness-report "${tmp_root}/stale-time.json"

  run_case "$tmp_root" "stale-by-source-miss" "$stale_source_index" "refresh_required" 0 1 0 0 \
    --freshness-report "${tmp_root}/stale-source.json"

  run_case "$tmp_root" "changed-path-invalidation" "$changed_path_index" "refresh_required" 0 1 0 0 \
    --freshness-report "${tmp_root}/changed-path.json" \
    --changed-path crates/franken-engine/src/proof_evidence_index.rs

  run_case "$tmp_root" "incomplete-artifact" "$incomplete_index" "fail_closed" 0 0 1 42 \
    --freshness-report "${tmp_root}/incomplete.json"

  run_case "$tmp_root" "superseded-artifact" "$superseded_index" "refresh_required" 0 1 0 0 \
    --freshness-report "${tmp_root}/superseded.json"

  run_case "$tmp_root" "mixed-partial-hit-refresh" "$mixed_index" "partial_refresh" 1 1 0 0 \
    --freshness-report "${tmp_root}/mixed-shell.json" \
    --freshness-report "${tmp_root}/mixed-heavy.json"

  jq -e '.refresh_commands | index("./scripts/e2e/proof_cost_history_index_smoke.sh check") == null' \
    "${tmp_root}/mixed-partial-hit-refresh/proof_cache_plan.json" >/dev/null
  jq -e '.refresh_commands | index("rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_proof_reuse cargo test -p frankenengine-engine --test proof_evidence_index_integration -- --nocapture") != null' \
    "${tmp_root}/mixed-partial-hit-refresh/proof_cache_plan.json" >/dev/null
  record_pass "mixed case keeps only actual refresh commands"

  printf 'proof_reuse_cache_smoke_artifacts=%s\n' "$tmp_root"
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
