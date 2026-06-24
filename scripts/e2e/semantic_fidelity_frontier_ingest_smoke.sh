#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${root_dir}"

output_root="${1:-${SEMANTIC_FIDELITY_FRONTIER_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-semantic-fidelity-frontier-smoke-$$}}"
case_file="scripts/testdata/semantic_fidelity_frontier_ingest/cases.json"
expected_summary="scripts/testdata/semantic_fidelity_frontier_ingest/expected_capstone_ingest_summary.json"
expected_report="scripts/testdata/semantic_fidelity_frontier_ingest/expected_capstone_report.md"
ingest_json="${output_root}/capstone_frontier_ingest.json"
summary_json="${output_root}/capstone_frontier_summary.json"
report_md="${output_root}/capstone_frontier_report.md"

mkdir -p "${output_root}"

record_pass() {
  printf 'PASS semantic-fidelity-frontier %s\n' "$1"
}

record_failure() {
  printf 'FAIL semantic-fidelity-frontier %s\n' "$1" >&2
  exit 1
}

capstone_bundle_path() {
  jq -r '.cases[] | select(.case_id == "bd_mihky_capstone_subset") | .source_bundle_path' "${case_file}"
}

missing_bundle_path() {
  jq -r '.cases[] | select(.case_id == "missing_bundle_fails_closed") | .source_bundle_path' "${case_file}"
}

render_summary() {
  local ingest_path="$1"
  jq '{
    schema_version:"franken-engine.semantic-fidelity-frontier-ingest-summary.v1",
    owning_bead:"bd-09bea.3",
    generated_from,
    row_count:(.rows|length),
    state_counts:(.rows|group_by(.scope_state)|map({count:length,state:.[0].scope_state})|sort_by(.state)),
    coverage_counts:(.rows|group_by(.coverage_counting)|map({count:length,coverage:.[0].coverage_counting})|sort_by(.coverage)),
    declared_non_execution_rows:(.rows|map(select(.scope_state=="declared_non_execution")|{cluster_id,coverage_counting,oracle_mode,related_bead_ids,route,row_id,scope_state,semantic_family,unsupported_reason,vector_id})|sort_by(.vector_id)),
    accepted_external_oracle_sample:(.rows|map(select(.scope_state=="accepted_external_oracle"))|sort_by(.vector_id)[0]|{cluster_id,coverage_counting,oracle_mode,related_bead_ids,route,row_id,scope_state,semantic_family,unsupported_reason,vector_id})
  }' "${ingest_path}"
}

assert_transform() {
  local bundle_path
  bundle_path="$(capstone_bundle_path)"
  scripts/semantic_fidelity_frontier_ingest.py \
    --bundle "${bundle_path}" \
    --out "${ingest_json}" \
    --pretty

  jq empty "${ingest_json}"
  jq -e '
    .schema_version == "franken-engine.semantic-fidelity-frontier-ingest.v1"
    and .scope == "semantic_fidelity_subset"
    and .claim_policy == "no_claim_promotion"
    and (.rows | length) == 13
    and ([.rows[].cluster_id] == ([.rows[].cluster_id] | sort))
    and (([.rows[] | select(.scope_state == "accepted_external_oracle")] | length) == 11)
    and (([.rows[] | select(.scope_state == "declared_non_execution")] | length) == 2)
    and all(.rows[] | select(.scope_state == "declared_non_execution"); .coverage_counting == "non_passing_scoped_evidence")
  ' "${ingest_json}" >/dev/null

  render_summary "${ingest_json}" >"${summary_json}"
  diff -u "${expected_summary}" "${summary_json}"
  record_pass "capstone transform and stable cluster summary"
}

assert_report() {
  scripts/semantic_fidelity_frontier_report.py \
    --ingest "${ingest_json}" \
    --out "${report_md}"
  diff -u "${expected_report}" "${report_md}"
  grep -q 'not full E7 coverage' "${report_md}"
  grep -q 'mismatch | 0' "${report_md}"
  grep -q 'expected_unknown | 0' "${report_md}"
  grep -q 'declared_non_execution | 2' "${report_md}"
  record_pass "scoped report and claim-hygiene wording"
}

assert_missing_bundle_fails_closed() {
  local missing_path rc
  missing_path="$(missing_bundle_path)"
  set +e
  scripts/semantic_fidelity_frontier_ingest.py \
    --bundle "${missing_path}" \
    >"${output_root}/missing_bundle.stdout.json" \
    2>"${output_root}/missing_bundle.stderr.json"
  rc=$?
  set -e
  [[ "${rc}" -eq 2 ]] || record_failure "missing bundle returned ${rc}, expected 2"
  jq -e '
    .schema_version == "franken-engine.semantic-fidelity-frontier-ingest-error.v1"
    and .ok == false
    and .reason_code == "missing_source_artifact"
  ' "${output_root}/missing_bundle.stderr.json" >/dev/null
  record_pass "missing bundle fail-closed diagnostic"
}

assert_missing_report_fails_closed() {
  local rc
  set +e
  scripts/semantic_fidelity_frontier_report.py \
    --ingest "${output_root}/missing_ingest.json" \
    >"${output_root}/missing_report.stdout.json" \
    2>"${output_root}/missing_report.stderr.json"
  rc=$?
  set -e
  [[ "${rc}" -eq 2 ]] || record_failure "missing report ingest returned ${rc}, expected 2"
  jq -e '
    .schema_version == "franken-engine.semantic-fidelity-frontier-report-error.v1"
    and .ok == false
    and .reason_code == "missing_ingest_bundle"
  ' "${output_root}/missing_report.stderr.json" >/dev/null
  record_pass "missing report input fail-closed diagnostic"
}

jq empty "${case_file}" "${expected_summary}"
assert_transform
assert_report
assert_missing_bundle_fails_closed
assert_missing_report_fails_closed

printf 'semantic-fidelity-frontier smoke artifacts: %s\n' "${output_root}"
