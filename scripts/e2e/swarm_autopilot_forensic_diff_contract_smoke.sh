#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docs_path="${SWARM_AUTOPILOT_FORENSIC_DIFF_DOC:-${root_dir}/docs/SWARM_AUTOPILOT_FORENSIC_DIFF_CONTRACT.md}"
contract_path="${SWARM_AUTOPILOT_FORENSIC_DIFF_CONTRACT:-${root_dir}/docs/swarm_autopilot_forensic_diff_contract_v1.json}"
mode="${1:-check}"

record_pass() {
  printf 'PASS swarm-autopilot-forensic-diff-contract %s\n' "$1"
}

record_fail() {
  printf 'FAIL swarm-autopilot-forensic-diff-contract %s\n' "$1" >&2
  exit 1
}

write_json() {
  local path="$1"
  local content="$2"
  printf '%s\n' "$content" >"$path"
}

bundle_has_path() {
  local bundle="$1"
  local dotted_path="$2"
  jq -e --arg dotted_path "$dotted_path" '
    def dotted_get($path):
      reduce ($path | split("."))[] as $segment
        (.;
          if . == null then null else .[$segment] end
        );
    dotted_get($dotted_path) != null
  ' "$bundle" >/dev/null
}

validate_array_objects_have_fields() {
  local bundle="$1"
  local array_path="$2"
  local fields_path="$3"

  jq -e --arg array_path "$array_path" --argjson required_fields "$(jq "$fields_path" "$contract_path")" '
    def dotted_get($path):
      reduce ($path | split("."))[] as $segment
        (.;
          if . == null then null else .[$segment] end
        );
    dotted_get($array_path) as $rows
    | ($rows | type) == "array"
    and ($rows | length) > 0
    and all($rows[]; . as $row | all($required_fields[]; $row[.] != null))
  ' "$bundle" >/dev/null
}

validate_bundle_against_contract() {
  local bundle="$1"

  jq -e --slurpfile contract "$contract_path" '
    ($contract[0]) as $contract_doc
    | .schema_version == $contract_doc.comparison_bundle_schema_version
    and (.truth_state | IN("confirmed", "degraded", "blocked", "contaminated"))
    and (.decision | IN("pass", "degraded", "blocked", "fail_closed"))
    and (.comparison_class | IN("reference_vs_reference", "reference_vs_degraded", "reference_vs_blocked", "reference_vs_contaminated"))
    and (.comparison_safe_mutation_policy.advisory_only == true)
    and (.comparison_safe_mutation_policy.proof_only == true)
    and (.comparison_safe_mutation_policy.mutates_br == false)
    and (.comparison_safe_mutation_policy.runs_cargo == false)
    and (.comparison_safe_mutation_policy.runs_rch == false)
    and (.comparison_safe_mutation_policy.mutates_remote_workers == false)
    and (.comparison_safe_mutation_policy.changes_live_queue_policy == false)
    and (.comparison_safe_mutation_policy.approves_replay_automatically == false)
    and (.comparison_safe_mutation_policy.promotes_evidence_automatically == false)
  ' "$bundle" >/dev/null || return 1

  while IFS= read -r dotted_path; do
    [[ -n "$dotted_path" ]] || continue
    bundle_has_path "$bundle" "$dotted_path" || return 1
  done < <(jq -r '.required_bundle_fields[]' "$contract_path")

  validate_array_objects_have_fields "$bundle" "cohort_diff_receipts" '.cohort_diff_receipt_fields' || return 1
  validate_array_objects_have_fields "$bundle" "replay_recipe_bundles" '.replay_recipe_bundle_fields' || return 1
  validate_array_objects_have_fields "$bundle" "hypothesis_summaries" '.hypothesis_summary_fields' || return 1
  validate_array_objects_have_fields "$bundle" "operator_forensic_bundles" '.operator_forensic_bundle_fields' || return 1

  jq -e '
    .optional_snapshot_health.optional_present_count + .optional_snapshot_health.optional_missing_count
      == .optional_snapshot_health.optional_snapshot_count
    and (.contradiction_count >= 0)
    and (
      if .truth_state == "confirmed" then
        .decision == "pass"
        and .required_input_status.reference_cohorts_present == true
        and .required_input_status.comparison_cohorts_present == true
        and .required_input_status.reference_replay_index_present == true
        and .required_input_status.comparison_replay_index_present == true
        and .local_fallback_contamination == false
        and .optional_snapshot_health.optional_missing_count == 0
        and .contradiction_count == 0
        and (.error_codes | length) == 0
      elif .truth_state == "degraded" then
        .decision == "degraded"
        and .required_input_status.reference_cohorts_present == true
        and .required_input_status.comparison_cohorts_present == true
        and .required_input_status.reference_replay_index_present == true
        and .required_input_status.comparison_replay_index_present == true
        and .local_fallback_contamination == false
        and .optional_snapshot_health.optional_missing_count > 0
        and .contradiction_count == 0
      elif .truth_state == "blocked" then
        .decision == "blocked"
        and .local_fallback_contamination == false
        and .contradiction_count > 0
        and (.error_codes | index("FE-SWARM-AUTOPILOT-FORENSIC-CONTRADICTORY-COHORT") != null)
      elif .truth_state == "contaminated" then
        .decision == "fail_closed"
        and .local_fallback_contamination == true
        and (.error_codes | index("FE-SWARM-AUTOPILOT-FORENSIC-LOCAL-FALLBACK") != null)
      else
        false
      end
    )
  ' "$bundle" >/dev/null
}

assert_bundle_valid() {
  local bundle="$1"
  local label="$2"
  validate_bundle_against_contract "$bundle" \
    || record_fail "${label} failed bundle validation"
}

check_no_forbidden_claims() {
  local path="$1"
  if grep -Eiq 'automatic replay approval is allowed|automatic promotion is allowed|mutates beads|releases reservations|sends Agent Mail|mutates workers|changes live queue policy|runs Cargo|runs RCH' "$path"; then
    record_fail "${path#"$root_dir"/} contains unsafe truth or mutation wording"
  fi
}

write_bundle() {
  local path="$1"
  local scenario="$2"

  local truth_state="confirmed"
  local decision="pass"
  local comparison_class="reference_vs_reference"
  local reference_present="true"
  local comparison_present="true"
  local reference_replay_present="true"
  local comparison_replay_present="true"
  local optional_snapshot_count="4"
  local optional_present_count="4"
  local optional_missing_count="0"
  local local_fallback_contamination="false"
  local contradiction_count="0"
  local remote_truth_valid="true"
  local error_codes='[]'

  case "$scenario" in
    healthy_reference_comparison)
      ;;
    degraded_optional_snapshot)
      truth_state="degraded"
      decision="degraded"
      comparison_class="reference_vs_degraded"
      optional_present_count="1"
      optional_missing_count="3"
      ;;
    blocked_contradictory_cohort)
      truth_state="blocked"
      decision="blocked"
      comparison_class="reference_vs_blocked"
      contradiction_count="1"
      remote_truth_valid="false"
      error_codes='["FE-SWARM-AUTOPILOT-FORENSIC-CONTRADICTORY-COHORT"]'
      ;;
    contaminated_local_fallback)
      truth_state="contaminated"
      decision="fail_closed"
      comparison_class="reference_vs_contaminated"
      local_fallback_contamination="true"
      remote_truth_valid="false"
      error_codes='["FE-SWARM-AUTOPILOT-FORENSIC-LOCAL-FALLBACK"]'
      ;;
    *)
      record_fail "unknown bundle scenario ${scenario}"
      ;;
  esac

  write_json "$path" "$(jq -n \
    --arg truth_state "$truth_state" \
    --arg decision "$decision" \
    --arg comparison_class "$comparison_class" \
    --argjson reference_present "$reference_present" \
    --argjson comparison_present "$comparison_present" \
    --argjson reference_replay_present "$reference_replay_present" \
    --argjson comparison_replay_present "$comparison_replay_present" \
    --argjson optional_snapshot_count "$optional_snapshot_count" \
    --argjson optional_present_count "$optional_present_count" \
    --argjson optional_missing_count "$optional_missing_count" \
    --argjson local_fallback_contamination "$local_fallback_contamination" \
    --argjson contradiction_count "$contradiction_count" \
    --argjson remote_truth_valid "$remote_truth_valid" \
    --argjson error_codes "$error_codes" \
    '{
      schema_version: "franken-engine.swarm-autopilot-forensic-comparison-bundle.v1",
      forensic_bundle_id: "forensic-diff-smoke",
      truth_state: $truth_state,
      decision: $decision,
      comparison_class: $comparison_class,
      required_input_status: {
        reference_cohorts_present: $reference_present,
        comparison_cohorts_present: $comparison_present,
        reference_replay_index_present: $reference_replay_present,
        comparison_replay_index_present: $comparison_replay_present
      },
      optional_snapshot_health: {
        optional_snapshot_count: $optional_snapshot_count,
        optional_present_count: $optional_present_count,
        optional_missing_count: $optional_missing_count
      },
      cohort_diff_receipts: [
        {
          receipt_id: "diff-receipt-smoke",
          reference_cohort_id: "reference-cohort",
          comparison_cohort_id: "comparison-cohort",
          classification_transition: $comparison_class,
          added_fingerprints: [],
          removed_fingerprints: [],
          changed_fingerprints: ["fingerprint-topology-drift"],
          worker_deltas: ["rch-a->rch-b"],
          toolchain_deltas: [],
          topology_deltas: ["numa-node-drift"],
          raw_artifact_paths: {
            reference_cohorts_json: "artifacts/reference_cohorts.json",
            comparison_cohorts_json: "artifacts/comparison_cohorts.json"
          }
        }
      ],
      replay_recipe_bundles: [
        {
          recipe_id: "replay-recipe-smoke",
          cohort_diff_receipt_id: "diff-receipt-smoke",
          replay_class: $comparison_class,
          evidence_paths: ["artifacts/reference_cohorts.json", "artifacts/comparison_cohorts.json"],
          expected_classification: $truth_state,
          safe_rerun_instructions: ["rerun fixture-fed forensic replay only"],
          remote_truth_valid: $remote_truth_valid
        }
      ],
      hypothesis_summaries: [
        {
          hypothesis_id: "hypothesis-smoke",
          top_failure_pivot: "topology_drift",
          confidence_millionths: 650000,
          supporting_source_ids: ["comparison_cohort"],
          counterevidence_source_ids: ["reference_cohort"],
          remediation_suggestions: ["refresh queue-locality and replay evidence before promotion"]
        }
      ],
      operator_forensic_bundles: [
        {
          operator_bundle_id: "operator-forensic-smoke",
          advisory_summary: "advisory only forensic comparison",
          top_cohort_delta_ids: ["diff-receipt-smoke"],
          replay_ready_recipe_ids: ["replay-recipe-smoke"],
          blocked_reason_codes: $error_codes,
          artifact_paths: {
            cohort_diff_receipts_json: "artifacts/cohort_diff_receipts.json",
            replay_recipe_bundle_json: "artifacts/replay_recipe_bundle.json",
            hypothesis_summary_json: "artifacts/hypothesis_summary.json"
          }
        }
      ],
      source_fingerprints: [
        {
          source_id: "reference_cohort",
          sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        {
          source_id: "comparison_cohort",
          sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
      ],
      raw_artifact_paths: {
        reference_anomaly_cohorts_json: "artifacts/reference_cohorts.json",
        comparison_anomaly_cohorts_json: "artifacts/comparison_cohorts.json",
        reference_replay_index_json: "artifacts/reference_replay_index.json",
        comparison_replay_index_json: "artifacts/comparison_replay_index.json"
      },
      comparison_safe_mutation_policy: {
        advisory_only: true,
        proof_only: true,
        mutates_br: false,
        reassigns_beads: false,
        releases_reservations: false,
        sends_agent_mail: false,
        runs_cargo: false,
        runs_rch: false,
        mutates_remote_workers: false,
        changes_live_queue_policy: false,
        approves_replay_automatically: false,
        promotes_evidence_automatically: false
      },
      local_fallback_contamination: $local_fallback_contamination,
      contradiction_count: $contradiction_count,
      error_codes: $error_codes
    }')"
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-forensic-diff-contract.v1"
    and .bead_id == "bd-00ofm.1"
    and .parent_bead_id == "bd-00ofm"
    and (.depends_on | index("bd-gra1z.4") != null)
    and (.upstream_contracts | index("docs/swarm_autopilot_anomaly_cohort_packer_contract_v1.json") != null)
    and .smoke_script == "scripts/e2e/swarm_autopilot_forensic_diff_contract_smoke.sh"
    and .operator_docs == "docs/SWARM_AUTOPILOT_FORENSIC_DIFF_CONTRACT.md"
    and .comparison_bundle_schema_version == "franken-engine.swarm-autopilot-forensic-comparison-bundle.v1"
    and .cohort_diff_receipt_schema_version == "franken-engine.swarm-autopilot-cohort-diff-receipt.v1"
    and .replay_recipe_bundle_schema_version == "franken-engine.swarm-autopilot-replay-recipe-bundle.v1"
    and .hypothesis_summary_schema_version == "franken-engine.swarm-autopilot-forensic-hypothesis-summary.v1"
    and .operator_forensic_bundle_schema_version == "franken-engine.swarm-autopilot-operator-forensic-bundle.v1"
    and ((["reference_anomaly_cohorts_json","comparison_anomaly_cohorts_json","reference_replay_index_json","comparison_replay_index_json"] - .required_inputs) | length) == 0
    and ((["warehouse_retention_plan_json","storage_budget_ledger_json","operator_status_snapshot_json","hindsight_outcome_bundle_json"] - .optional_inputs) | length) == 0
    and ((["confirmed","degraded","blocked","contaminated"] - .truth_states) | length) == 0
    and ((["pass","degraded","blocked","fail_closed"] - .decisions) | length) == 0
    and (([
      "FE-SWARM-AUTOPILOT-FORENSIC-MISSING-INPUT",
      "FE-SWARM-AUTOPILOT-FORENSIC-STALE-REFERENCE",
      "FE-SWARM-AUTOPILOT-FORENSIC-MISSING-RAW-PATH",
      "FE-SWARM-AUTOPILOT-FORENSIC-CONTRADICTORY-COHORT",
      "FE-SWARM-AUTOPILOT-FORENSIC-LOCAL-FALLBACK",
      "FE-SWARM-AUTOPILOT-FORENSIC-UNSUPPORTED-MUTATION"
    ] - .required_error_codes) | length) == 0
    and any(.fixture_examples[]; .fixture_id == "healthy_reference_comparison" and .expected_truth_state == "confirmed")
    and any(.fixture_examples[]; .fixture_id == "degraded_optional_snapshot" and .expected_truth_state == "degraded")
    and any(.fixture_examples[]; .fixture_id == "blocked_contradictory_cohort" and .required_error_code == "FE-SWARM-AUTOPILOT-FORENSIC-CONTRADICTORY-COHORT")
    and any(.fixture_examples[]; .fixture_id == "contaminated_local_fallback" and .required_error_code == "FE-SWARM-AUTOPILOT-FORENSIC-LOCAL-FALLBACK")
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.comparison_safe == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.approves_replay_automatically == false
    and .mutation_policy.promotes_evidence_automatically == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'This contract is advisory only and proof only.' "$docs_path" \
    && grep -Fq 'Missing optional forensic snapshots degrade trust.' "$docs_path" \
    && grep -Fq 'Contradictory cohort identity must fail closed.' "$docs_path" \
    && grep -Fq 'Local fallback contamination must fail closed.' "$docs_path" \
    && grep -Fq 'no automatic replay approval' "$docs_path" \
    && grep -Fq 'no automatic promotion' "$docs_path" \
    && grep -Fq 'no worker mutation' "$docs_path" \
    && grep -Fq 'no queue mutation' "$docs_path" \
    && grep -Fq 'The forensic surfaces must not mutate beads, reservations, Agent Mail, workers, or live queue policy.' "$docs_path"
}

run_check() {
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"

  if contract_shape_ok; then
    record_pass "contract shape"
  else
    record_fail "contract shape mismatch"
  fi

  if docs_shape_ok; then
    record_pass "operator docs shape"
  else
    record_fail "operator docs shape mismatch"
  fi

  check_no_forbidden_claims "$docs_path"
  check_no_forbidden_claims "$contract_path"
}

run_selftest() {
  local tmp_dir bundle scenario
  tmp_dir="${TMPDIR:-/tmp}/swarm-autopilot-forensic-diff-contract-smoke/$USER-$$"
  mkdir -p "$tmp_dir"

  run_check
  for scenario in \
    healthy_reference_comparison \
    degraded_optional_snapshot \
    blocked_contradictory_cohort \
    contaminated_local_fallback; do
    bundle="${tmp_dir}/${scenario}.json"
    write_bundle "$bundle" "$scenario"
    assert_bundle_valid "$bundle" "$scenario"
    record_pass "${scenario} bundle"
  done
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help)
    printf 'Usage: %s [check|selftest]\n' "${BASH_SOURCE[0]}" >&2
    ;;
  *)
    record_fail "unknown mode: ${mode}"
    ;;
esac
