#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docs_path="${SWARM_EXECUTION_QUEUE_TUNING_POLICY_BUNDLE_DOC:-${root_dir}/docs/SWARM_EXECUTION_QUEUE_TUNING_POLICY_BUNDLE_CONTRACT.md}"
contract_path="${SWARM_EXECUTION_QUEUE_TUNING_POLICY_BUNDLE_CONTRACT:-${root_dir}/docs/swarm_execution_queue_tuning_policy_bundle_contract_v1.json}"
mode="${1:-check}"
bundle_path="${2:-}"
failures=0

record_pass() {
  printf 'PASS swarm-execution-queue-tuning-policy-bundle-contract %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-tuning-policy-bundle-contract %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_execution_queue_tuning_policy_bundle_contract_smoke.sh [check|selftest|validate-bundle FILE]

Validates the SWARM-CTRL-XIV-A tuning policy bundle contract and sample bundle
invariants. The bundle is an advisory-only planning artifact and never mutates
br, Agent Mail, remote workers, or live queue weights.
EOF
}

check_no_forbidden_claims() {
  local path="$1"
  if grep -Eiq 'automatic retuning is allowed|automatically retunes|applies retuning automatically|changes active queue automatically|manual approval is optional|manual approval may be skipped|live queue mutation surface|does not reject local fallback proof|local fallback proof is acceptable' "$path"; then
    record_failure "${path#"$root_dir"/} contains unsafe automation, approval, or local-fallback wording"
  fi
}

check_no_bare_heavy_cargo() {
  local path="$1"
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$line" != *"rch exec --"* || "$line" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "${path#"$root_dir"/} has bare heavy Cargo command: ${line}"
      fi
    fi
  done <"$path"
}

run_check() {
  if [[ ! -f "$docs_path" ]]; then
    record_failure "missing doc ${docs_path}"
    return 1
  fi
  if [[ ! -f "$contract_path" ]]; then
    record_failure "missing contract ${contract_path}"
    return 1
  fi

  jq empty "$contract_path" >/dev/null

  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-tuning-policy-bundle-contract.v1"
    and .bead_id == "bd-j2rny.1"
    and .parent_bead_id == "bd-j2rny"
    and (.depends_on | index("bd-d5daf") != null)
    and .bundle_schema_version == "franken-engine.swarm-execution-queue-tuning-policy-bundle.v1"
    and (.required_bundle_fields | index("promoted_candidate") != null)
    and (.required_bundle_fields | index("evidence_links") != null)
    and (.required_bundle_fields | index("manual_approval") != null)
    and (.required_bundle_fields | index("canary_constraints") != null)
    and (.required_bundle_fields | index("rollback_references") != null)
    and ([.upstream_artifacts[].field] | index("fidelity_score_receipt_json") != null)
    and ([.upstream_artifacts[].field] | index("drift_ledger_json") != null)
    and ([.upstream_artifacts[].field] | index("counterfactual_backtest_report_json") != null)
    and ([.upstream_artifacts[].field] | index("tuning_plan_json") != null)
    and ([.upstream_artifacts[].field] | index("frontier_json") != null)
    and ([.upstream_artifacts[].field] | index("operator_status_json") != null)
    and .approval_policy.manual_approval_required == true
    and .approval_policy.approval_artifact_required_before_promotion == true
    and .canary_policy.required == true
    and .canary_policy.stop_on_missing_evidence_required == true
    and (.canary_policy.rollback_drift_classes_required | index("proof_drift") != null)
    and (.canary_policy.rollback_drift_classes_required | index("ownership_drift") != null)
    and (.canary_policy.rollback_drift_classes_required | index("restore_drift") != null)
    and .rollback_policy.prior_policy_bundle_id_required == true
    and .rollback_policy.rollback_comparator_report_json_required == true
    and .mutation_policy.planning_artifact_only == true
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
    and (.fail_closed_rules | index("missing evidence links fail closed") != null)
    and (.fail_closed_rules | index("manual approval missing fail closed") != null)
    and (.fail_closed_rules | index("rollback references missing fail closed") != null)
    and (.fail_closed_rules | index("automatic retuning claims fail closed") != null)
    and (.fail_closed_rules | index("reject local fallback proof evidence") != null)
  ' "$contract_path" >/dev/null || record_failure "contract shape mismatch"

  while IFS= read -r required_text; do
    grep -Fq "$required_text" "$docs_path" || record_failure "doc missing required text: ${required_text}"
  done < <(jq -r '.required_doc_text[]' "$contract_path")

  check_no_forbidden_claims "$docs_path"
  check_no_forbidden_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  record_pass "static contract validates"
}

validate_bundle() {
  local path="$1"
  if [[ -z "$path" || ! -f "$path" ]]; then
    record_failure "missing bundle path"
    return 1
  fi
  jq empty "$path" >/dev/null

  jq -e --slurpfile contract "$contract_path" '
    ($contract[0]) as $contract_doc
    | $contract_doc.bundle_schema_version as $bundle_schema_version
    | [$contract_doc.upstream_artifacts[].field] as $required_artifacts
    | (.schema_version == $bundle_schema_version)
    and ((.bundle_id // "") | length > 0)
    and ((.source_revision // "") | length > 0)
    and ((.generated_at // "") | length > 0)
    and ((.promoted_candidate.candidate_id // "") | length > 0)
    and ((.promoted_candidate.expected_fidelity_delta_millionths // null) | type == "number")
    and ((.promoted_candidate.confidence_band // "") | IN("high", "medium", "low", "insufficient_evidence"))
    and ((.promoted_candidate.safety_status // "") | IN("manual_review", "safe_to_replay", "no_change", "unsafe"))
    and ((.promoted_candidate.source_tuning_plan_json // "") | length > 0)
    and ((.evidence_links // []) | type == "array")
    and ([.evidence_links[].artifact_kind] | sort == ($required_artifacts | sort))
    and all(.evidence_links[]; ((.path // "") | length > 0) and ((.sha256 // "") | test("^[0-9a-f]{64}$")))
    and .manual_approval.required == true
    and ((.manual_approval.approver_role // "") | IN("human_operator", "release_captain"))
    and ((.manual_approval.approval_artifact_path // "") | length > 0)
    and .canary_constraints.enabled == true
    and ((.canary_constraints.observation_window_seconds // 0) >= $contract_doc.canary_policy.minimum_observation_window_seconds)
    and ((.canary_constraints.max_queue_depth_delta // -1) >= 0)
    and ((.canary_constraints.max_candidate_weight_delta_millionths // 1000001) <= $contract_doc.canary_policy.maximum_candidate_weight_delta_millionths)
    and .canary_constraints.stop_on_missing_evidence == true
    and (.canary_constraints.rollback_on_drift_classes | index("proof_drift") != null)
    and (.canary_constraints.rollback_on_drift_classes | index("ownership_drift") != null)
    and (.canary_constraints.rollback_on_drift_classes | index("restore_drift") != null)
    and ((.rollback_references.prior_policy_bundle_id // "") | length > 0)
    and ((.rollback_references.prior_frontier_json // "") | length > 0)
    and ((.rollback_references.rollback_comparator_report_json // "") | length > 0)
    and ((.rollback_references.canary_verdict_ledger_json // "") | length > 0)
    and .mutation_policy.planning_artifact_only == true
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.rewrites_historical_outcomes == false
    and ((.automation_claim // "none") | test("automatic|automatically|live retuning|changes active queue") | not)
    and (.fail_closed_rules | index("missing evidence links fail closed") != null)
    and (.fail_closed_rules | index("manual approval missing fail closed") != null)
    and (.fail_closed_rules | index("rollback references missing fail closed") != null)
    and (.fail_closed_rules | index("automatic retuning claims fail closed") != null)
    and (.fail_closed_rules | index("reject local fallback proof evidence") != null)
  ' "$path" >/dev/null || record_failure "bundle invariant mismatch: ${path}"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  record_pass "bundle validates"
}

write_valid_bundle() {
  local path="$1"
  local digest="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

  jq -n \
    --arg digest "$digest" \
    '{
      schema_version: "franken-engine.swarm-execution-queue-tuning-policy-bundle.v1",
      bundle_id: "queue-tuning-policy-bundle-smoke",
      source_revision: "selftest",
      generated_at: "2026-05-06T00:00:00Z",
      promoted_candidate: {
        candidate_id: "raise_proof_health_penalty",
        expected_fidelity_delta_millionths: 240000,
        confidence_band: "high",
        safety_status: "manual_review",
        source_tuning_plan_json: "counterfactual/tuning_plan.json"
      },
      evidence_links: [
        {artifact_kind: "fidelity_score_receipt_json", path: "fidelity/fidelity_score_receipt.json", sha256: $digest},
        {artifact_kind: "drift_ledger_json", path: "fidelity/drift_ledger.json", sha256: $digest},
        {artifact_kind: "counterfactual_backtest_report_json", path: "counterfactual/counterfactual_backtest_report.json", sha256: $digest},
        {artifact_kind: "tuning_plan_json", path: "counterfactual/tuning_plan.json", sha256: $digest},
        {artifact_kind: "frontier_json", path: "counterfactual/frontier.json", sha256: $digest},
        {artifact_kind: "operator_status_json", path: "operator-status/status.json", sha256: $digest}
      ],
      manual_approval: {
        required: true,
        approver_role: "human_operator",
        approval_artifact_path: "approvals/manual-approval.json"
      },
      canary_constraints: {
        enabled: true,
        observation_window_seconds: 1800,
        max_queue_depth_delta: 1,
        max_candidate_weight_delta_millionths: 200000,
        rollback_on_drift_classes: ["proof_drift", "ownership_drift", "restore_drift"],
        stop_on_missing_evidence: true
      },
      rollback_references: {
        prior_policy_bundle_id: "queue-tuning-policy-bundle-current",
        prior_frontier_json: "rollback/prior_frontier.json",
        rollback_comparator_report_json: "rollback/comparator_report.json",
        canary_verdict_ledger_json: "rollback/canary_verdict_ledger.json"
      },
      mutation_policy: {
        planning_artifact_only: true,
        changes_active_queue: false,
        applies_live_retuning: false,
        mutates_br: false,
        sends_agent_mail: false,
        mutates_remote_workers: false,
        rewrites_historical_outcomes: false
      },
      automation_claim: "none",
      fail_closed_rules: [
        "missing evidence links fail closed",
        "manual approval missing fail closed",
        "rollback references missing fail closed",
        "automatic retuning claims fail closed",
        "unsafe canary constraints fail closed",
        "reject local fallback proof evidence"
      ]
    }' >"$path"
}

expect_bundle_failure() {
  local label="$1"
  local path="$2"
  if bash "${BASH_SOURCE[0]}" validate-bundle "$path" >/dev/null 2>&1; then
    record_failure "selftest expected rejection: ${label}"
  else
    record_pass "selftest rejects ${label}"
  fi
}

run_selftest() {
  local tmp_root valid_bundle missing_evidence no_manual auto_claim missing_rollback unsafe_canary
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-execution-queue-tuning-policy-bundle.XXXXXX")"

  run_check

  valid_bundle="${tmp_root}/valid-bundle.json"
  write_valid_bundle "$valid_bundle"
  bash "${BASH_SOURCE[0]}" validate-bundle "$valid_bundle" >/dev/null
  record_pass "selftest accepts valid bundle"

  missing_evidence="${tmp_root}/missing-evidence.json"
  jq 'del(.evidence_links[] | select(.artifact_kind == "frontier_json"))' "$valid_bundle" >"$missing_evidence"
  expect_bundle_failure "missing evidence link" "$missing_evidence"

  no_manual="${tmp_root}/manual-approval-missing.json"
  jq '.manual_approval.required = false' "$valid_bundle" >"$no_manual"
  expect_bundle_failure "missing manual approval" "$no_manual"

  auto_claim="${tmp_root}/automatic-retuning-claim.json"
  jq '.automation_claim = "automatically retunes live queue"' "$valid_bundle" >"$auto_claim"
  expect_bundle_failure "automatic retuning claim" "$auto_claim"

  missing_rollback="${tmp_root}/missing-rollback.json"
  jq '.rollback_references.prior_policy_bundle_id = ""' "$valid_bundle" >"$missing_rollback"
  expect_bundle_failure "missing rollback reference" "$missing_rollback"

  unsafe_canary="${tmp_root}/unsafe-canary.json"
  jq '.canary_constraints.max_candidate_weight_delta_millionths = 900000 | .canary_constraints.stop_on_missing_evidence = false' "$valid_bundle" >"$unsafe_canary"
  expect_bundle_failure "unsafe canary constraints" "$unsafe_canary"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  validate-bundle)
    validate_bundle "$bundle_path"
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac
