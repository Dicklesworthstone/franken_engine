#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="${root_dir}/scripts/proof_freshness_decay_gate.sh"
docs_path="${root_dir}/docs/PROOF_FRESHNESS_DECAY_GATE.md"
golden_dir="${PROOF_FRESHNESS_DECAY_GOLDEN_DIR:-${root_dir}/scripts/testdata/goldens}"

record_pass() {
  printf 'PASS proof-freshness-decay %s\n' "$1"
}

record_failure() {
  printf 'FAIL proof-freshness-decay %s\n' "$1" >&2
}

golden_case_names() {
  cat <<'EOF'
fresh
stale-by-time
stale-by-source-revision
stale-by-changed-path
mismatched-schema
incomplete-bundle
superseded
false-fresh-missing-source
EOF
}

write_artifact() {
  local path="$1"
  local artifact_id="$2"
  local source_revision="$3"
  local generated_ms="$4"
  local deadline_ms="$5"
  local superseded_by="${6:-}"

  jq -n \
    --arg schema_version "franken-engine.proof-artifact-manifest.v1" \
    --arg proof_artifact_id "$artifact_id" \
    --arg source_revision "$source_revision" \
    --arg status "pass" \
    --arg superseded_by "$superseded_by" \
    --argjson generated_ms "$generated_ms" \
    --argjson deadline_ms "$deadline_ms" \
    '{
      schema_version: $schema_version,
      proof_artifact_id: $proof_artifact_id,
      source_revision: $source_revision,
      status: $status,
      generated_timestamp_ms: $generated_ms,
      freshness_deadline_ms: $deadline_ms,
      covered_paths: [
        "crates/franken-engine/src/proof_evidence_index.rs",
        "scripts/focused_proof_runner.sh"
      ],
      superseded_by: (if $superseded_by == "" then null else $superseded_by end)
    }' >"$path"
}

write_incomplete_artifact() {
  local path="$1"
  jq -n '{
    schema_version: "franken-engine.proof-artifact-manifest.v1",
    proof_artifact_id: "proof-incomplete",
    generated_timestamp_ms: 1700000000000,
    freshness_deadline_ms: 1700000100000,
    covered_paths: ["crates/franken-engine/src/proof_evidence_index.rs"]
  }' >"$path"
}

write_schema_mismatched_artifact() {
  local path="$1"
  jq -n '{
    schema_version: "franken-engine.unexpected-proof-artifact.v1",
    proof_artifact_id: "proof-schema-mismatch",
    source_revision: "current-rev",
    status: "pass",
    generated_timestamp_ms: 1700000000000,
    freshness_deadline_ms: 1700000100000,
    covered_paths: ["crates/franken-engine/src/proof_evidence_index.rs"]
  }' >"$path"
}

assert_report() {
  local case_dir="$1"
  local expected_state="$2"
  local expected_reusable="$3"

  jq -e \
    --arg expected_state "$expected_state" \
    --argjson expected_reusable "$expected_reusable" \
    '.schema_version == "franken-engine.proof-freshness-decay-report.v1"
      and .freshness_state == $expected_state
      and .reusable == $expected_reusable
      and (.reason | length > 0)
      and (.recommended_next_action | length > 0)
      and (.artifact_paths.proof_freshness_report_json | length > 0)
      and (.artifact_paths.events_jsonl | length > 0)
      and (.artifact_paths.commands_txt | length > 0)
      and (.artifact_paths.report_md | length > 0)' \
    "${case_dir}/proof_freshness_report.json" >/dev/null

  test -s "${case_dir}/events.jsonl"
  test -s "${case_dir}/commands.txt"
  test -s "${case_dir}/report.md"
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
        | gsub("/data/tmp/[A-Za-z0-9._-]+"; "[DATA_TMP_PATH]")
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
  local golden_path="${golden_dir}/proof_freshness_decay_gate_${case_name}.golden"

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
    golden_path="${golden_dir}/proof_freshness_decay_gate_${case_name}.golden"
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

run_case() {
  local tmp_root="$1"
  local case_name="$2"
  local artifact_path="$3"
  local expected_state="$4"
  local expected_reusable="$5"
  local expected_exit="$6"
  shift 6
  local case_dir="${tmp_root}/${case_name}"
  local actual_exit output

  set +e
  output="$(
    "$gate" \
      --artifact "$artifact_path" \
      --expected-source-revision current-rev \
      --expected-schema-version franken-engine.proof-artifact-manifest.v1 \
      --now-ms 1700000050000 \
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

  assert_report "$case_dir" "$expected_state" "$expected_reusable"
  assert_case_golden "$case_name" "${case_dir}/proof_freshness_report.json" "$tmp_root"
  record_pass "${case_name} classified as ${expected_state}"
}

run_selftest() {
  local tmp_parent tmp_root
  local fresh stale_time stale_rev stale_path mismatched incomplete superseded false_fresh

  tmp_parent="${PROOF_FRESHNESS_DECAY_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/proof-freshness-decay.XXXXXX")"

  fresh="${tmp_root}/fresh.json"
  stale_time="${tmp_root}/stale-time.json"
  stale_rev="${tmp_root}/stale-rev.json"
  stale_path="${tmp_root}/stale-path.json"
  mismatched="${tmp_root}/mismatched.json"
  incomplete="${tmp_root}/incomplete.json"
  superseded="${tmp_root}/superseded.json"
  false_fresh="${tmp_root}/false-fresh.json"

  write_artifact "$fresh" "proof-fresh" "current-rev" 1700000000000 1700000100000
  write_artifact "$stale_time" "proof-stale-time" "current-rev" 1699990000000 1699990100000
  write_artifact "$stale_rev" "proof-stale-rev" "old-rev" 1700000000000 1700000100000
  write_artifact "$stale_path" "proof-stale-path" "current-rev" 1700000000000 1700000100000
  write_schema_mismatched_artifact "$mismatched"
  write_incomplete_artifact "$incomplete"
  write_artifact "$superseded" "proof-superseded" "current-rev" 1700000000000 1700000100000 "proof-newer"
  write_incomplete_artifact "$false_fresh"

  run_case "$tmp_root" "fresh" "$fresh" "fresh" true 0
  run_case "$tmp_root" "stale-by-time" "$stale_time" "stale_by_time" false 42
  run_case "$tmp_root" "stale-by-source-revision" "$stale_rev" "stale_by_source_revision" false 42
  run_case "$tmp_root" "stale-by-changed-path" "$stale_path" "stale_by_changed_path" false 42 \
    --changed-path crates/franken-engine/src/proof_evidence_index.rs
  run_case "$tmp_root" "mismatched-schema" "$mismatched" "mismatched" false 42
  run_case "$tmp_root" "incomplete-bundle" "$incomplete" "incomplete" false 42
  run_case "$tmp_root" "superseded" "$superseded" "superseded" false 42
  run_case "$tmp_root" "false-fresh-missing-source" "$false_fresh" "incomplete" false 42

  if ! grep -q 'rch exec -- env CARGO_TARGET_DIR=' "$docs_path"; then
    record_failure "docs missing rch-wrapped rerun example"
    return 1
  fi
  record_pass "docs include rch-wrapped rerun example"

  printf 'proof_freshness_decay_smoke_artifacts=%s\n' "$tmp_root"
}

run_check() {
  local scope_file

  bash -n "$gate"
  bash -n "${BASH_SOURCE[0]}"
  goldens_shape_ok
  record_pass "bash syntax"

  jq empty "$docs_path" >/dev/null 2>&1 && {
    record_failure "docs unexpectedly parsed as JSON"
    return 1
  }
  grep -q 'franken-engine.proof-freshness-decay-report.v1' "$docs_path"
  record_pass "docs schema reference"

  scope_file="${PROOF_FRESHNESS_DECAY_SMOKE_SCOPE_FILE:-/tmp/franken-engine-proof-freshness-decay-scope.txt}"
  printf '%s\n' \
    "scripts/proof_freshness_decay_gate.sh" \
    "scripts/e2e/proof_freshness_decay_gate_smoke.sh" \
    "docs/PROOF_FRESHNESS_DECAY_GATE.md" \
    >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${PROOF_FRESHNESS_DECAY_SMOKE_POLICY_DIR:-/tmp/franken-engine-proof-freshness-decay-policy}" \
    --scope-file "$scope_file" >/dev/null
  record_pass "rch policy compliance"
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
