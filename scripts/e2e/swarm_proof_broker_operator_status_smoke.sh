#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${root_dir}/scripts/swarm_proof_broker_operator_status.sh"
contract_path="${root_dir}/docs/swarm_proof_broker_operator_status_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_PROOF_BROKER_OPERATOR_STATUS.md"
cases_path="${root_dir}/scripts/testdata/swarm_proof_broker_operator_status/cases.json"
mode="${1:-check}"
output_root="${2:-${SWARM_PROOF_BROKER_OPERATOR_STATUS_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-proof-broker-operator-status-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS swarm-proof-broker-operator-status %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-proof-broker-operator-status %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_proof_broker_operator_status_smoke.sh [check|selftest] [output_root]
EOF
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-broker-operator-status-contract.v1"
    and .bead_id == "bd-ua5n2.6"
    and (.depends_on | sort) == ["bd-ua5n2.2", "bd-ua5n2.3", "bd-ua5n2.4", "bd-ua5n2.5"]
    and (.required_outputs | index("operator_status_bundle.json") != null)
    and (.required_outputs | index("frankentui_panel_contract.json") != null)
    and (.summary_counts | sort) == [
      "coalesced_count",
      "contaminated_proof_count",
      "fairness_debt_total",
      "pending_request_count",
      "reusable_verdict_count",
      "reuse_refusal_count",
      "stale_proof_count"
    ]
    and (.fail_closed_reasons | sort) == [
      "panel_claims_live_mutation_authority",
      "panel_hides_stale_evidence",
      "panel_omits_refusal_reasons"
    ]
    and .frankentui_boundary.renderer_repo == "/dp/frankentui"
    and .frankentui_boundary.local_rich_renderer_implemented == false
    and .frankentui_boundary.mutation_authority == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_br == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'never runs Cargo or RCH' "$docs_path" \
    && grep -Fq '/dp/frankentui' "$docs_path" \
    && grep -Fq 'pending proof requests' "$docs_path" \
    && grep -Fq 'fairness debt' "$docs_path" \
    && grep -Fq 'omitting refusal reasons fails closed' "$docs_path" \
    && grep -Fq 'not_applicable' "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-broker-operator-status-fixtures.v1"
    and (.cases | length) == 8
    and all(.cases[]; has("case_id") and has("expected"))
    and ([.cases[].case_id] | sort) == [
      "contaminated_local_fallback",
      "duplicate_storm_coalesced",
      "fairness_debt_visible",
      "healthy_reusable_proof",
      "hidden_stale_fail_closed",
      "mutation_claim_fail_closed",
      "omitted_refusal_reason_fail_closed",
      "stale_proof_refused"
    ]
    and ([.cases[].expected.decision] | unique | sort) == ["fail_closed", "pass"]
    and ([.cases[].expected.fail_closed_reasons[]?] | unique | sort) == [
      "panel_claims_live_mutation_authority",
      "panel_hides_stale_evidence",
      "panel_omits_refusal_reasons"
    ]
  ' "$cases_path" >/dev/null
}

script_static_ok() {
  bash -n "$script_path"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$script_path" "${BASH_SOURCE[0]}"
  fi
}

expand_case() {
  local case_json="$1"
  jq -n \
    --slurpfile fixtures "$cases_path" \
    --argjson case "$case_json" '
      ($fixtures[0].base_input * ($case | del(.expected)))
      + {expected: $case.expected}
    '
}

assert_case_output() {
  local case_json="$1"
  local output_dir="$2"
  local bundle_path="${output_dir}/operator_status_bundle.json"
  local panel_path="${output_dir}/frankentui_panel_contract.json"
  local case_id

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  jq empty "$bundle_path" "$panel_path" >/dev/null
  test -f "${output_dir}/operator_status_rows.jsonl"
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"

  jq -e \
    --argjson expected "$(jq '.expected' <<<"$case_json")" \
    --argjson input "$case_json" \
    --arg case_id "$case_id" '
      def arr($v): if ($v | type) == "array" then $v else [] end;
      def reasons($row):
        if (($row.invalidation_reasons // null) | type) == "array" then $row.invalidation_reasons
        elif (($row.reason_codes // null) | type) == "array" then $row.reason_codes
        elif (($row.reason_summary // "") | length) > 0 then ($row.reason_summary | split(",") | map(select(length > 0)))
        else []
        end;
      def stale($row):
        (reasons($row) | index("expired_ttl")) != null
        or (($row.freshness // "") | IN("expired", "stale"));
      def contaminated($row):
        (reasons($row) | index("local_fallback_contamination")) != null
        or (reasons($row) | index("contaminated_command_shape")) != null
        or (($row.rch_posture // "") == "local_fallback")
        or (($row.local_fallback_observed // false) == true);
      def reusable_equiv($row): (($row.reuse_eligible // false) == true) or (($row.verdict // "") == "reuse_allowed");
      def command_for($fp):
        (arr($input.proof_requests) | map(select((.proof_fingerprint // "") == $fp)) | .[0].command // "");
      def underlying_counts:
        (arr($input.proof_requests)) as $requests
        | (arr($input.artifact_index)) as $artifacts
        | (arr($input.equivalence_receipts)) as $equiv
        | (arr($input.batch_recommendations)) as $batch
        | (arr($input.fairness_debt)) as $fairness
        | {
            pending_request_count: ($requests | length),
            reusable_verdict_count: (($artifacts | map(select((.reuse_eligible // false) == true)) | length) + ($equiv | map(select(reusable_equiv(.))) | length)),
            reuse_refusal_count: (($artifacts | map(select((.reuse_eligible // false) != true)) | length) + ($equiv | map(select(reusable_equiv(.) | not)) | length)),
            stale_proof_count: (($artifacts + $equiv) | map(select(stale(.))) | length),
            contaminated_proof_count: (($artifacts + $equiv) | map(select(contaminated(.))) | length),
            fairness_debt_total: ($fairness | map((.deferred_count // 0) | tonumber) | add // 0),
            coalesced_count: ($batch | map(select((.action // "") == "coalesce")) | length)
          };
      .schema_version == "franken-engine.swarm-proof-broker-operator-status.v1"
      and .case_id == $case_id
      and .decision == $expected.decision
      and .fail_closed_reasons == $expected.fail_closed_reasons
      and .summary_counts == $expected.summary_counts
      and .summary_counts == underlying_counts
      and (.status_hash | test("^[0-9a-f]{64}$"))
      and .hidden_green_status == false
      and (if .decision == "fail_closed" then .overall_status == "blocked" else .overall_status == "advisory" end)
      and all(.rows[]; (.command // "") != "" and ((.source_evidence // []) | length) >= 1 and ((.recommended_next_action // "") | length) >= 20)
      and all(.rows[]; (.command == "not_applicable") or ((.proof_fingerprint // "") == "") or (command_for(.proof_fingerprint) == "") or (.command == command_for(.proof_fingerprint)))
      and all(.rows[] | select(.status | test("refused$")); ((.refusal_reasons // []) | length) > 0)
      and .frankentui_boundary.renderer_boundary == "frankentui"
      and .frankentui_boundary.renderer_repo == "/dp/frankentui"
      and .frankentui_boundary.mutation_authority == false
      and .non_mutation_attestation.runs_cargo == false
      and .non_mutation_attestation.runs_rch == false
      and .non_mutation_attestation.mutates_br == false
      and .non_mutation_attestation.claims_live_mutation_authority == false
    ' "$bundle_path" >/dev/null || record_failure "${case_id} operator bundle mismatch"

  jq -e \
    --arg case_id "$case_id" '
      .schema_version == "franken-engine.swarm-proof-broker-frankentui-panel-contract.v1"
      and .case_id == $case_id
      and .renderer_boundary == "frankentui"
      and .renderer_repo == "/dp/frankentui"
      and .local_rich_renderer_implemented == false
      and .mutation_authority == false
      and .live_mutation_authority == false
      and .may_mutate_proofs == false
      and .may_close_beads == false
      and .hidden_green_status == false
      and (.required_row_fields | index("command") != null)
      and (.required_row_fields | index("source_evidence") != null)
    ' "$panel_path" >/dev/null || record_failure "${case_id} frankentui panel contract mismatch"
}

run_case() {
  local raw_case_json="$1"
  local tmp_root="$2"
  local case_json case_id case_dir fixture_path expected_exit actual_exit

  case_json="$(expand_case "$raw_case_json")"
  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${tmp_root}/${case_id}"
  fixture_path="${case_dir}/fixture.json"
  mkdir -p "$case_dir"
  jq 'del(.expected)' <<<"$case_json" >"$fixture_path"

  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"
  set +e
  "$script_path" --fixture-json "$fixture_path" --output-dir "${case_dir}/out" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected ${expected_exit}"
    return
  fi
  assert_case_output "$case_json" "${case_dir}/out"
  record_pass "$case_id"
}

run_check() {
  jq empty "$contract_path" "$cases_path" >/dev/null
  script_static_ok
  contract_shape_ok || record_failure "contract shape"
  docs_shape_ok || record_failure "docs shape"
  fixtures_shape_ok || record_failure "fixture shape"
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  local tmp_root="$1"

  run_check
  if [[ "$failures" -ne 0 ]]; then
    return
  fi
  while IFS= read -r case_json; do
    run_case "$case_json" "$tmp_root"
  done < <(jq -c '.cases[]' "$cases_path")
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest "$output_root"
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
