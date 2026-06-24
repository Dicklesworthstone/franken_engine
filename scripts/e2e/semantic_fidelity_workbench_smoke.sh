#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runner="${root_dir}/scripts/semantic_fidelity_workbench.py"
gate_wrapper="${root_dir}/scripts/run_semantic_fidelity_workbench.sh"
replay_wrapper="${root_dir}/scripts/e2e/semantic_fidelity_workbench_replay.sh"
suite_dir="${root_dir}/scripts/testdata/semantic_fidelity_workbench"
schema_path="${root_dir}/docs/semantic_fidelity_vector_schema_v1.json"
mode="${1:-check}"
output_root="${2:-${SEMANTIC_FIDELITY_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-semantic-fidelity-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS semantic-fidelity-workbench %s\n' "$1"
}

record_failure() {
  printf 'FAIL semantic-fidelity-workbench %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: scripts/e2e/semantic_fidelity_workbench_smoke.sh [check|selftest] [output_root]

Runs build-free semantic-fidelity workbench checks. This script does not invoke
Cargo; any Cargo-heavy validation must be run through rch separately.
EOF
}

node_available() {
  command -v node >/dev/null 2>&1
}

run_python_runner() {
  local suite_path="$1"
  local out_dir="$2"
  mkdir -p "$out_dir"
  SEMANTIC_FIDELITY_NOW_UTC=2030-01-01T00:00:00Z \
    python3 "$runner" --suite "$suite_path" --out-dir "$out_dir" --pretty \
    >"${out_dir}/stdout.log" 2>"${out_dir}/stderr.log"
}

run_python_runner_allow_failure() {
  local suite_path="$1"
  local out_dir="$2"
  local actual_exit
  mkdir -p "$out_dir"
  set +e
  SEMANTIC_FIDELITY_NOW_UTC=2030-01-01T00:00:00Z \
    python3 "$runner" --suite "$suite_path" --out-dir "$out_dir" --pretty \
    >"${out_dir}/stdout.log" 2>"${out_dir}/stderr.log"
  actual_exit=$?
  set -e
  printf '%s\n' "$actual_exit" >"${out_dir}/exit_code"
  return 0
}

assert_required_bundle_files() {
  local out_dir="$1"
  local file
  for file in run_manifest.json events.jsonl commands.txt vector_results.jsonl path_parity_report.json auto_triage_report.json summary.md; do
    if [[ ! -f "${out_dir}/${file}" ]]; then
      record_failure "${out_dir} missing ${file}"
    elif [[ "${file}" != "vector_results.jsonl" && ! -s "${out_dir}/${file}" ]]; then
      record_failure "${out_dir} empty ${file}"
    fi
  done
  jq empty "${out_dir}/run_manifest.json" "${out_dir}/events.jsonl" "${out_dir}/vector_results.jsonl" "${out_dir}/path_parity_report.json" "${out_dir}/auto_triage_report.json" >/dev/null \
    || record_failure "${out_dir} contains invalid JSON artifacts"
}

assert_vector_logging_contract() {
  local out_dir="$1"
  jq -s -e '
    length > 0 and all(.[];
      .schema_version == "franken-engine.semantic-fidelity-vector-result.v1"
      and (.vector_id | type == "string")
      and (.source_sha256 | startswith("sha256:"))
      and (.dispatch_route.route_id | type == "string")
      and (.dispatch_route.route_kind | type == "string")
      and (.expected_outcome.kind | type == "string")
      and (.actual_outcome.kind | type == "string")
      and (.evidence_classification | type == "string")
      and (.command_replay_hints.vector_id == .vector_id)
      and (.command_replay_hints.runner_command | contains("semantic_fidelity_workbench.py"))
      and (.command_replay_hints.preserved_bundle_replay | contains("semantic_fidelity_workbench_replay.sh"))
      and ((.first_divergence == null) or (.first_divergence.reason_code | type == "string"))
    )
  ' "${out_dir}/vector_results.jsonl" >/dev/null \
    || record_failure "${out_dir} vector logging contract mismatch"

  jq -s -e '
    any(.[]; .event == "vector_evaluated"
      and (.source_sha256 | startswith("sha256:"))
      and (.dispatch_route.route_id | type == "string")
      and (.expected_outcome.kind | type == "string")
      and (.actual_outcome.kind | type == "string")
      and (.command_replay_hints.preserved_bundle_replay | contains("semantic_fidelity_workbench_replay.sh")))
  ' "${out_dir}/events.jsonl" >/dev/null \
    || record_failure "${out_dir} events do not carry structured vector diagnostics"
}

assert_path_parity_contract() {
  local out_dir="$1"
  jq -e '
    .schema_version == "franken-engine.semantic-fidelity-path-parity-report.v1"
    and (.summary.vector_count | type == "number")
    and (.summary.builtin_group_count | type == "number")
    and (.summary.route_disagreement_group_count | type == "number")
    and (.groups | type == "array")
    and all(.groups[];
      (.builtin | type == "string")
      and (.semantic_family | type == "string")
      and (.group_status | type == "string")
      and (.route_disagreement | type == "boolean")
      and (.routes | type == "array")
      and all(.routes[];
        (.dispatch_route.route_id | type == "string")
        and (.expected_signature | type == "string")
        and (.actual_signature | type == "string")))
  ' "${out_dir}/path_parity_report.json" >/dev/null \
    || record_failure "${out_dir} path parity schema mismatch"
}

assert_auto_triage_contract() {
  local out_dir="$1"
  jq -e '
    .schema_version == "franken-engine.semantic-fidelity-auto-triage-report.v1"
    and (.summary.entry_count | type == "number")
    and (.summary.confirmed_failure_count | type == "number")
    and (.summary.existing_bead_link_count | type == "number")
    and (.summary.suggested_bead_count | type == "number")
    and (.summary.unsupported_surface_count | type == "number")
    and (.summary.degraded_surface_count | type == "number")
    and (.entries | type == "array")
    and all(.entries[];
      (.vector_id | type == "string")
      and (.triage_classification | type == "string")
      and (.triage_action | type == "string")
      and (.validation_commands.vector_id == .vector_id)
      and ((.suggested_bead == null) or
        ((.suggested_bead.title | type == "string")
        and (.suggested_bead.description | contains("## Background"))
        and (.suggested_bead.description | contains("## Route"))
        and (.suggested_bead.description | contains("## Expected"))
        and (.suggested_bead.description | contains("## Actual"))
        and (.suggested_bead.description | contains("## Validation")))))
  ' "${out_dir}/auto_triage_report.json" >/dev/null \
    || record_failure "${out_dir} auto triage schema mismatch"
}

assert_rangeerror_suite() {
  local out_dir="${output_root}/rangeerror"
  run_python_runner "${suite_dir}/rangeerror_tointeger_suite.json" "$out_dir" \
    || record_failure "rangeerror suite should not fail closed"
  assert_required_bundle_files "$out_dir"
  assert_vector_logging_contract "$out_dir"
  assert_path_parity_contract "$out_dir"
  assert_auto_triage_contract "$out_dir"
  "$replay_wrapper" "$out_dir" >/dev/null || record_failure "rangeerror preserved replay failed"
  jq -e '
    .decision != "fail_closed"
    and (.validation_errors | length) == 0
  ' "${out_dir}/run_manifest.json" >/dev/null || record_failure "rangeerror manifest decision invalid"
  jq -e '
    length == 13
    and any(.vector_id == "semfid-engine-source-eval-string-from-code-point-high-expected-unknown"
      and .route_kind == "source_eval"
      and .expectation_kind == "expected_unknown"
      and .evidence_classification == "declared_non_execution")
    and any(.vector_id == "semfid-engine-source-eval-array-length-fractional-expected-unknown"
      and .route_kind == "source_eval"
      and .expectation_kind == "expected_unknown"
      and .evidence_classification == "declared_non_execution")
  ' <(jq -s '.' "${out_dir}/vector_results.jsonl") >/dev/null \
    || record_failure "rangeerror source-eval expected_unknown labelling invalid"
  if node_available; then
    jq -e '
      any(.vector_id == "semfid-string-repeat-negative-count-range-error"
        and .outcome == "passed"
        and .expected_outcome.error_class == "RangeError"
        and .actual_outcome.error_class == "RangeError"
        and .evidence_classification == "accepted_external_oracle")
    ' <(jq -s '.' "${out_dir}/vector_results.jsonl") >/dev/null \
      || record_failure "rangeerror node oracle did not prove RangeError vector"
  fi
  jq -e '
    .summary.route_disagreement_group_count >= 1
    and any(.groups[];
      .semantic_family == "string_from_code_point_range"
      and .route_disagreement == true
      and (.routes | any(.route_kind == "source_eval" and .evidence_classification == "declared_non_execution"))
      and (.routes | any(.route_kind == "node_oracle" and .outcome == "passed")))
  ' "${out_dir}/path_parity_report.json" >/dev/null \
    || record_failure "rangeerror path parity disagreement not surfaced"
  jq -e '
    .summary.unsupported_surface_count >= 2
    and any(.entries[];
      .vector_id == "semfid-engine-source-eval-string-from-code-point-high-expected-unknown"
      and .triage_classification == "unsupported_or_expected_unknown"
      and .triage_action == "classify_unsupported_surface"
      and .unsupported_surface == true)
  ' "${out_dir}/auto_triage_report.json" >/dev/null \
    || record_failure "rangeerror unsupported source-eval triage invalid"
  record_pass "rangeerror artifact/logging coverage"
}

assert_classifier_failure_suite() {
  local out_dir="${output_root}/classification"
  run_python_runner_allow_failure "${suite_dir}/classification_suite.json" "$out_dir"
  assert_required_bundle_files "$out_dir"
  assert_vector_logging_contract "$out_dir"
  assert_path_parity_contract "$out_dir"
  assert_auto_triage_contract "$out_dir"
  if node_available; then
    [[ "$(cat "${out_dir}/exit_code")" == "1" ]] \
      || record_failure "classification suite should exit 1 when node is available"
    jq -e '.decision == "fail_closed"' "${out_dir}/run_manifest.json" >/dev/null \
      || record_failure "classification suite should fail closed"
    jq -e '
      any(.vector_id == "semfid-classification-02-fail-error-class"
        and .outcome == "fail_closed"
        and .passed == false
        and .first_divergence.reason_code == "expected_error_class_mismatch"
        and .first_divergence.expected.error_class == "TypeError"
        and .first_divergence.actual.error_class == "RangeError")
    ' <(jq -s '.' "${out_dir}/vector_results.jsonl") >/dev/null \
      || record_failure "classification first-divergence record invalid"
    if "$replay_wrapper" "$out_dir" >/dev/null 2>&1; then
      record_failure "classification fail_closed bundle replay should fail"
    fi
    jq -e '
      .summary.failure_group_count >= 1
      and any(.failure_groups[];
        .semantic_family == "runner_classification"
        and .dispatch_route.route_id == "oracle.node.classification.fail-error-class"
        and .first_divergence.reason_code == "expected_error_class_mismatch")
    ' "${out_dir}/path_parity_report.json" >/dev/null \
      || record_failure "classification failure grouping invalid"
    jq -e '
      .summary.confirmed_failure_count >= 1
      and .summary.existing_bead_link_count >= 1
      and .summary.suggested_bead_count >= 1
      and any(.entries[];
        .vector_id == "semfid-classification-02-fail-error-class"
        and .triage_classification == "confirmed_failure"
        and .triage_action == "link_existing_bead"
        and (.existing_beads | any(.bead_id == "bd-mihky.3")))
      and any(.entries[];
        .vector_id == "semfid-classification-04-fail-new-drift"
        and .triage_classification == "confirmed_failure"
        and .triage_action == "suggest_new_bead"
        and (.suggested_bead.title | contains("[semantic-fidelity]"))
        and (.suggested_bead.description | contains("semfid-classification-04-fail-new-drift"))
        and (.suggested_bead.description | contains("## Validation")))
    ' "${out_dir}/auto_triage_report.json" >/dev/null \
      || record_failure "classification existing-bead triage invalid"
  fi
  jq -e '
    any(.vector_id == "semfid-classification-03-degraded-missing-runtime"
      and .outcome == "degraded"
      and .evidence_classification == "degraded_external_oracle"
      and (.reason_codes | index("external_oracle_unavailable")))
  ' <(jq -s '.' "${out_dir}/vector_results.jsonl") >/dev/null \
    || record_failure "classification degraded external oracle label invalid"
  record_pass "classifier fail/degraded diagnostics"
}

assert_malformed_suite() {
  local out_dir="${output_root}/malformed"
  run_python_runner_allow_failure "${suite_dir}/malformed_hash_suite.json" "$out_dir"
  assert_required_bundle_files "$out_dir"
  [[ "$(cat "${out_dir}/exit_code")" == "1" ]] \
    || record_failure "malformed hash suite should exit 1"
  jq -e '
    .decision == "fail_closed"
    and (.validation_errors | length) == 1
    and .validation_errors[0].code == "source_hash_mismatch"
  ' "${out_dir}/run_manifest.json" >/dev/null || record_failure "malformed manifest invalid"
  assert_path_parity_contract "$out_dir"
  assert_auto_triage_contract "$out_dir"
  jq -s 'length == 0' "${out_dir}/vector_results.jsonl" >/dev/null \
    || record_failure "malformed suite should emit no accepted vector results"
  if "$replay_wrapper" "$out_dir" >/dev/null 2>&1; then
    record_failure "malformed fail_closed replay should fail"
  fi
  record_pass "malformed fail-closed coverage"
}

assert_gate_wrapper() {
  local out_dir="${output_root}/gate-wrapper"
  SEMANTIC_FIDELITY_NOW_UTC=2030-01-01T00:00:00Z \
  SEMANTIC_FIDELITY_SUITE="${suite_dir}/minimal_suite.json" \
    "$gate_wrapper" ci "$out_dir" >/dev/null
  assert_required_bundle_files "$out_dir"
  assert_vector_logging_contract "$out_dir"
  assert_path_parity_contract "$out_dir"
  assert_auto_triage_contract "$out_dir"
  jq -e '
    .summary.route_disagreement_group_count == 1
    and any(.groups[];
      .builtin == "String.prototype.repeat"
      and .semantic_family == "string_repeat_range"
      and .route_disagreement == true
      and (.routes | length == 2)
      and (.routes | any(.route_kind == "node_oracle" and .outcome == "passed"))
      and (.routes | any(.route_kind == "source_eval" and .outcome == "expected_unknown")))
  ' "${out_dir}/path_parity_report.json" >/dev/null \
    || record_failure "gate wrapper minimal path parity disagreement invalid"
  jq -e '
    .summary.unsupported_surface_count == 1
    and any(.entries[];
      .vector_id == "semfid-source-eval-string-repeat-negative-count"
      and .triage_action == "classify_unsupported_surface")
  ' "${out_dir}/auto_triage_report.json" >/dev/null \
    || record_failure "gate wrapper unsupported triage invalid"
  "$gate_wrapper" self-check "${output_root}/gate-self-check" >/dev/null
  record_pass "gate wrapper ci+self-check"
}

run_check() {
  bash -n "$gate_wrapper" "$replay_wrapper" "${BASH_SOURCE[0]}"
  python3 -m py_compile "$runner"
  python3 "$runner" --self-test >/dev/null
  jq empty "$schema_path" "${suite_dir}"/*.json >/dev/null
  rg -n 'expected_outcome|actual_outcome|first_divergence|command_replay_hints|evidence_classification' "$runner" >/dev/null
  record_pass "check"
}

run_selftest() {
  mkdir -p "$output_root"
  run_check
  assert_rangeerror_suite
  assert_classifier_failure_suite
  assert_malformed_suite
  assert_gate_wrapper
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
