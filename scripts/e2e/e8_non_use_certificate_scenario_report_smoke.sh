#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}" || exit 1

report_script="scripts/e8_non_use_certificate_scenario_report.py"
fixture_root="scripts/testdata/e8_non_use_certificate_scenario_report"
golden_json="scripts/testdata/goldens/e8_non_use_certificate_scenario_report_healthy.golden"
golden_text="scripts/testdata/goldens/e8_non_use_certificate_scenario_report_healthy.txt.golden"
now_utc="2030-01-01T00:00:00Z"

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for E8 non-use certificate scenario report smoke test\n' >&2
  exit 2
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/e8-scenario-report-smoke.XXXXXX")"
log_path="${tmp_dir}/events.jsonl"
: >"${log_path}"

record_case() {
  local case_id="$1"
  local fixture_path="$2"
  local cmd_str="$3"
  local out_file="$4"
  local rc="$5"
  jq -cn \
    --arg case_id "${case_id}" \
    --arg fixture "${fixture_path}" \
    --arg command "${cmd_str}" \
    --argjson exit_code "${rc}" \
    --slurpfile receipt "${out_file}" \
    '{
      case_id: $case_id,
      fixture_path: $fixture,
      command_line: $command,
      exit_code: $exit_code,
      decision: ($receipt[0].decision // null),
      reason_codes: ($receipt[0].reason_codes // []),
      receipt_id: ($receipt[0].receipt_id // null),
      contract_hash_hex: ($receipt[0].e8_scenario.contract_hash_hex // null)
    }' >>"${log_path}"
}

fail_case() {
  local case_id="$1"
  local msg="$2"
  local fixture_path="$3"
  local cmd_str="$4"
  local out_file="$5"
  printf 'FAIL [%s]: %s\n  fixture: %s\n  command: %s\n' \
    "${case_id}" "${msg}" "${fixture_path}" "${cmd_str}" >&2
  if [[ -f "${out_file}" ]]; then
    jq '{decision, reason_codes, receipt_id, artifact_refs}' "${out_file}" >&2 || cat "${out_file}" >&2
  fi
  exit 1
}

assert_case() {
  local case_id="$1"
  local expected_decision="$2"
  local expected_rc_mode="$3"
  local required_reasons_csv="$4"
  local contract_arg="$5"
  local bundle_arg="$6"
  shift 6
  local out_file="${tmp_dir}/${case_id}.json"
  local cmd_str="E8_EXPLAINER_NOW_UTC=${now_utc} python3 ${report_script} --contract ${contract_arg} --bundle ${bundle_arg} --beads-jsonl ${fixture_root}/issues.jsonl --format json --pretty $*"

  set +e
  E8_EXPLAINER_NOW_UTC="${now_utc}" python3 "${report_script}" \
    --contract "${contract_arg}" \
    --bundle "${bundle_arg}" \
    --beads-jsonl "${fixture_root}/issues.jsonl" \
    --format json --pretty "$@" >"${out_file}"
  local rc=$?
  set -e

  record_case "${case_id}" "${bundle_arg}" "${cmd_str}" "${out_file}" "${rc}"

  if [[ "${expected_rc_mode}" == "zero" && "${rc}" -ne 0 ]]; then
    fail_case "${case_id}" "expected exit 0, got ${rc}" "${bundle_arg}" "${cmd_str}" "${out_file}"
  fi
  if [[ "${expected_rc_mode}" == "nonzero" && "${rc}" -eq 0 ]]; then
    fail_case "${case_id}" "expected non-zero exit, got 0" "${bundle_arg}" "${cmd_str}" "${out_file}"
  fi

  local actual_decision
  actual_decision="$(jq -r '.decision' "${out_file}")"
  if [[ "${actual_decision}" != "${expected_decision}" ]]; then
    fail_case "${case_id}" "decision ${actual_decision} != ${expected_decision}" "${bundle_arg}" "${cmd_str}" "${out_file}"
  fi

  if ! jq -e '
    .schema_version == "franken-engine.external-trust-artifact-explanation.v1"
    and (.receipt_id | startswith("e8-explain-"))
    and .mutation_policy.mutates_br == false
    and .mutation_policy.mutates_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.mutates_evidence_bundles == false
    and .renderer_boundary.future_rich_renderer_provider == "/dp/frankentui"
  ' "${out_file}" >/dev/null; then
    fail_case "${case_id}" "receipt contract invariant failed" "${bundle_arg}" "${cmd_str}" "${out_file}"
  fi

  if [[ -n "${required_reasons_csv}" ]]; then
    IFS=',' read -r -a req_codes <<<"${required_reasons_csv}"
    for req_code in "${req_codes[@]}"; do
      if ! jq -e --arg code "${req_code}" '(.reason_codes | index($code)) != null' "${out_file}" >/dev/null; then
        fail_case "${case_id}" "missing expected reason code ${req_code}" "${bundle_arg}" "${cmd_str}" "${out_file}"
      fi
    done
  else
    if ! jq -e '(.reason_codes | length) == 0' "${out_file}" >/dev/null; then
      fail_case "${case_id}" "expected empty reason_codes" "${bundle_arg}" "${cmd_str}" "${out_file}"
    fi
  fi
}

# 1. Healthy complete certificate (JSON + text goldens)
assert_case \
  "healthy" \
  "supported" \
  "zero" \
  "" \
  "${fixture_root}/contract_honest.json" \
  "${fixture_root}/certified_bundle"

if ! diff -u "${golden_json}" "${tmp_dir}/healthy.json"; then
  printf 'FAIL [healthy]: JSON golden drifted\n' >&2
  exit 1
fi

E8_EXPLAINER_NOW_UTC="${now_utc}" python3 "${report_script}" \
  --contract "${fixture_root}/contract_honest.json" \
  --bundle "${fixture_root}/certified_bundle" \
  --beads-jsonl "${fixture_root}/issues.jsonl" \
  --format text >"${tmp_dir}/healthy.txt"

if ! diff -u "${golden_text}" "${tmp_dir}/healthy.txt"; then
  printf 'FAIL [healthy]: text golden drifted\n' >&2
  exit 1
fi

# 2. Contradicted / uncertified smuggle bundle -> not_promotable
assert_case \
  "smuggle-contradicted" \
  "not_promotable" \
  "nonzero" \
  "explicit_e8_uncertified_refusal" \
  "${fixture_root}/contract_smuggle.json" \
  "${fixture_root}/smuggle_bundle"

# 3. Missing certifier output -> fail_closed (unavailable_e8_certifier)
assert_case \
  "missing-certifier-output" \
  "fail_closed" \
  "nonzero" \
  "unavailable_e8_certifier" \
  "${fixture_root}/contract_honest.json" \
  "${tmp_dir}/nonexistent_bundle"

# 4. Incomplete bundle missing capstone repro.lock -> fail_closed
mkdir -p "${tmp_dir}/incomplete_bundle"
for f in non_use_certificate.json use_certificate.json declassification_receipts.jsonl capability_trace.jsonl audit.md; do
  cp "${fixture_root}/certified_bundle/${f}" "${tmp_dir}/incomplete_bundle/${f}"
done
assert_case \
  "missing-capstone-repro-lock" \
  "fail_closed" \
  "nonzero" \
  "unavailable_e8_certifier,incomplete_artifact_bundle,missing_reproducibility_bundle" \
  "${fixture_root}/contract_honest.json" \
  "${tmp_dir}/incomplete_bundle"

# 5. Stale data contract (contract modified after certificate emission) -> fail_closed
jq '.allowed_capabilities += ["NetworkEgress"]' "${fixture_root}/contract_honest.json" >"${tmp_dir}/stale_contract.json"
assert_case \
  "stale-data-contract" \
  "fail_closed" \
  "nonzero" \
  "hash_mismatch,stale_artifact" \
  "${tmp_dir}/stale_contract.json" \
  "${fixture_root}/certified_bundle"

# 6. Mock-contaminated certificate -> fail_closed
mkdir -p "${tmp_dir}/mock_bundle"
cp "${fixture_root}/certified_bundle/"* "${tmp_dir}/mock_bundle/"
printf '\n<!-- MockCertificate fixture -->\n' >>"${tmp_dir}/mock_bundle/audit.md"
assert_case \
  "mock-certificate" \
  "fail_closed" \
  "nonzero" \
  "mock_contaminated" \
  "${fixture_root}/contract_honest.json" \
  "${tmp_dir}/mock_bundle"

# 7. Unsupported schema -> fail_closed
jq '.schema_version = "franken-engine.data-contract.v99"' "${fixture_root}/contract_honest.json" >"${tmp_dir}/unsupported_contract.json"
assert_case \
  "unsupported-schema" \
  "fail_closed" \
  "nonzero" \
  "unsupported_schema" \
  "${tmp_dir}/unsupported_contract.json" \
  "${fixture_root}/certified_bundle"

# 8. Duplicate binding / claim / route IDs -> fail_closed (duplicate_e8_identifier)
jq '
  .input_bindings += [.input_bindings[0]]
  | .requested_output_claims += [.requested_output_claims[0]]
  | .required_declassification_routes = [
      {
        route: {route_id: "dup-route", source_label: "Confidential", target_clearance: "Public", conditions: ["approved"]},
        required_for_claims: ["no-secret-open-sink"]
      },
      {
        route: {route_id: "dup-route", source_label: "Confidential", target_clearance: "Public", conditions: ["approved"]},
        required_for_claims: ["no-secret-open-sink"]
      }
    ]
' "${fixture_root}/contract_honest.json" >"${tmp_dir}/dup_contract.json"
assert_case \
  "duplicate-e8-ids" \
  "fail_closed" \
  "nonzero" \
  "duplicate_e8_identifier" \
  "${tmp_dir}/dup_contract.json" \
  "${fixture_root}/certified_bundle"

# 9. Unknown claim reference -> fail_closed (unknown_e8_claim_reference)
jq '
  .required_declassification_routes = [
    {
      route: {route_id: "route-1", source_label: "Confidential", target_clearance: "Public", conditions: ["approved"]},
      required_for_claims: ["undeclared-claim-id"]
    }
  ]
' "${fixture_root}/contract_honest.json" >"${tmp_dir}/unknown_ref_contract.json"
assert_case \
  "unknown-claim-ref" \
  "fail_closed" \
  "nonzero" \
  "unknown_e8_claim_reference" \
  "${tmp_dir}/unknown_ref_contract.json" \
  "${fixture_root}/certified_bundle"

# 10. Missing run-input content hash -> fail_closed (missing_required_field)
mkdir -p "${tmp_dir}/missing_run_hash_bundle"
cp "${fixture_root}/certified_bundle/"* "${tmp_dir}/missing_run_hash_bundle/"
jq 'del(.scope.run_input_content_hash_hex)' \
  "${fixture_root}/certified_bundle/non_use_certificate.json" \
  >"${tmp_dir}/missing_run_hash_bundle/non_use_certificate.json"
assert_case \
  "missing-run-input-hash" \
  "fail_closed" \
  "nonzero" \
  "missing_required_field" \
  "${fixture_root}/contract_honest.json" \
  "${tmp_dir}/missing_run_hash_bundle"

printf 'PASS E8 non-use certificate scenario report smoke (10 scenarios; log=%s)\n' "${log_path}"
