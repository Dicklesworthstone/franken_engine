#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docs_path="${SWARM_AUTOPILOT_SHADOW_DAEMON_DOC:-${root_dir}/docs/SWARM_AUTOPILOT_SHADOW_DAEMON_CONTRACT.md}"
contract_path="${SWARM_AUTOPILOT_SHADOW_DAEMON_CONTRACT:-${root_dir}/docs/swarm_autopilot_shadow_daemon_contract_v1.json}"
fixtures_path="${SWARM_AUTOPILOT_SHADOW_DAEMON_FIXTURES:-${root_dir}/scripts/testdata/swarm_autopilot_shadow_daemon_contract/cases.json}"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS swarm-autopilot-shadow-daemon-contract %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-shadow-daemon-contract %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_shadow_daemon_contract_smoke.sh [check|selftest|run]
EOF
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-shadow-daemon-contract.v1"
    and .bead_id == "bd-djejh.1"
    and .parent_bead_id == "bd-djejh"
    and .operator_docs == "docs/SWARM_AUTOPILOT_SHADOW_DAEMON_CONTRACT.md"
    and .smoke_script == "scripts/e2e/swarm_autopilot_shadow_daemon_contract_smoke.sh"
    and .fixture_bundle == "scripts/testdata/swarm_autopilot_shadow_daemon_contract/cases.json"
    and .sibling_reuse.persistence == "/dp/frankensqlite"
    and .sibling_reuse.tui == "/dp/frankentui"
    and .sibling_reuse.service_api == "/dp/fastapi_rust"
    and .sibling_reuse.local_sqlite_policy_stack_allowed == false
    and .sibling_reuse.local_tui_replacement_allowed == false
    and .sibling_reuse.local_api_framework_allowed == false
    and (([
      "br_queue_snapshot_json",
      "bv_robot_plan_json",
      "agent_mail_snapshot_json",
      "rch_status_snapshot_json",
      "git_state_snapshot_json",
      "artifact_bundle_snapshot_json"
    ] - .required_sources) | length) == 0
    and (([
      "source_id",
      "source_kind",
      "schema_version",
      "content_hash",
      "collected_epoch_seconds",
      "freshness_window_seconds",
      "fresh",
      "degraded",
      "raw_payload_ref",
      "error_codes"
    ] - .source_snapshot_required_fields) | length) == 0
    and ((["confirmed","degraded","blocked","contaminated"] - .truth_states) | length) == 0
    and ((["pass","degraded","blocked","fail_closed"] - .decisions) | length) == 0
    and any(.fixture_cases[]; .case_id == "healthy_advisory_output" and .expected_decision == "pass")
    and any(.fixture_cases[]; .case_id == "stale_source_refusal" and .required_error_code == "FE-SWARM-AUTOPILOT-SHADOW-STALE-SOURCE")
    and any(.fixture_cases[]; .case_id == "unsupported_mutation_claim" and .required_error_code == "FE-SWARM-AUTOPILOT-SHADOW-UNSUPPORTED-MUTATION")
    and any(.fixture_cases[]; .case_id == "degraded_agent_mail_rch_sources" and .expected_decision == "degraded")
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.reassigns_beads == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_git == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-shadow-daemon-fixtures.v1"
    and .base_shadow_status.schema_version == "franken-engine.swarm-autopilot-shadow-status.v1"
    and (.cases | length == 4)
    and ([.cases[].case_id] | unique | length == 4)
    and any(.cases[]; .case_id == "healthy_advisory_output" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "stale_source_refusal" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-SHADOW-STALE-SOURCE")
    and any(.cases[]; .case_id == "unsupported_mutation_claim" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-SHADOW-UNSUPPORTED-MUTATION")
    and any(.cases[]; .case_id == "degraded_agent_mail_rch_sources" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-SHADOW-DEGRADED-SOURCE")
    and all(.cases[];
      (.expected.expected_exit_code | type) == "number"
      and (.expected.truth_state | type) == "string"
      and (.expected.decision | type) == "string"
      and ((.status_overrides // {}) | type) == "object"
    )
  ' "$fixtures_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'contract-only surface' "$docs_path" \
    && grep -Fq 'The daemon is advisory only.' "$docs_path" \
    && grep -Fq '/dp/frankensqlite' "$docs_path" \
    && grep -Fq '/dp/frankentui' "$docs_path" \
    && grep -Fq '/dp/fastapi_rust' "$docs_path" \
    && grep -Fq 'Unsupported mutation claims fail closed' "$docs_path" \
    && grep -Fq 'healthy_advisory_output' "$docs_path"
}

check_no_forbidden_claims() {
  local path="$1"
  if grep -Eiq 'automatic mutation is allowed|executes mutations|mutates beads|releases reservations|sends Agent Mail|mutates workers|changes live queue policy|runs Cargo|runs RCH' "$path"; then
    record_failure "${path#"$root_dir"/} contains unsafe mutation wording"
  fi
}

validate_status_case() {
  local case_id="$1"

  jq -e --arg case_id "$case_id" --slurpfile contract "$contract_path" '
    def dotted_get($path):
      reduce ($path | split("."))[] as $segment
        (.;
          if . == null then null else .[$segment] end
        );

    . as $root
    | ($contract[0]) as $contract_doc
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | ($root.base_shadow_status * (($case.status_overrides // {}))) as $status
    | $status.schema_version == $contract_doc.shadow_status_schema_version
    and $status.truth_state == $case.expected.truth_state
    and $status.decision == $case.expected.decision
    and all($contract_doc.required_shadow_status_fields[];
      . as $field
      | ($status | dotted_get($field)) != null
    )
    and all($contract_doc.required_sources[];
      . as $source_kind
      | any($status.source_snapshot_status[]; .source_kind == $source_kind)
    )
    and all($status.source_snapshot_status[]; . as $snapshot |
      all($contract_doc.source_snapshot_required_fields[]; $snapshot[.] != null)
    )
    and all($status.advisory_recommendations[]; . as $recommendation |
      all($contract_doc.recommendation_required_fields[]; $recommendation[.] != null)
      and $recommendation.executes_mutation == false
      and $recommendation.remediation_only == true
      and ($recommendation.source_event_ids | length) > 0
      and ($recommendation.source_hashes | length) > 0
    )
    and all($status.rejected_mutation_claims[]?; .executed == false)
    and $status.mutation_policy.advisory_only == true
    and $status.mutation_policy.proof_only == true
    and $status.mutation_policy.mutates_br == false
    and $status.mutation_policy.reassigns_beads == false
    and $status.mutation_policy.releases_reservations == false
    and $status.mutation_policy.sends_agent_mail == false
    and $status.mutation_policy.runs_cargo == false
    and $status.mutation_policy.runs_rch == false
    and $status.mutation_policy.mutates_git == false
    and $status.mutation_policy.mutates_remote_workers == false
    and $status.mutation_policy.changes_live_queue_policy == false
    and $status.sibling_reuse.persistence == $contract_doc.sibling_reuse.persistence
    and $status.sibling_reuse.tui == $contract_doc.sibling_reuse.tui
    and $status.sibling_reuse.service_api == $contract_doc.sibling_reuse.service_api
    and (
      (($case.expected.required_error_code // "") | length) == 0
      or ($status.error_codes | index($case.expected.required_error_code)) != null
      or (
        [$status.source_snapshot_status[]?.error_codes[]?] | index($case.expected.required_error_code)
      ) != null
      or (
        [$status.rejected_mutation_claims[]?.rejection_error_code] | index($case.expected.required_error_code)
      ) != null
    )
    and (
      if $status.truth_state == "confirmed" then
        $status.decision == "pass"
        and all($status.source_snapshot_status[]; .fresh == true and .degraded == false)
        and ($status.error_codes | length) == 0
        and ($status.rejected_mutation_claims | length) == 0
      elif $status.truth_state == "degraded" then
        $status.decision == "degraded"
        and any($status.source_snapshot_status[]; .degraded == true)
      elif $status.truth_state == "blocked" then
        ($status.decision == "blocked" or $status.decision == "fail_closed")
        and ($status.error_codes | length) > 0
      elif $status.truth_state == "contaminated" then
        $status.decision == "fail_closed"
        and ($status.error_codes | length) > 0
      else
        false
      end
    )
  ' "$fixtures_path" >/dev/null
}

run_check() {
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path" "$fixtures_path"

  if contract_shape_ok; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi

  if fixtures_shape_ok; then
    record_pass "fixture shape"
  else
    record_failure "fixture shape mismatch"
  fi

  if docs_shape_ok; then
    record_pass "operator docs shape"
  else
    record_failure "operator docs shape mismatch"
  fi

  check_no_forbidden_claims "$contract_path"
  check_no_forbidden_claims "$docs_path"
  check_no_forbidden_claims "$fixtures_path"
}

run_selftest() {
  local case_id
  while IFS= read -r case_id; do
    if validate_status_case "$case_id"; then
      record_pass "${case_id} status"
    else
      record_failure "${case_id} status mismatch"
    fi
  done < <(jq -r '.cases[].case_id' "$fixtures_path")
}

case "$mode" in
  check)
    run_check
    ;;
  selftest|run)
    run_check
    run_selftest
    ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    usage
    exit 2
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
