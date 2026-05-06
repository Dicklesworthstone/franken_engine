#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docs_path="${SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_RECEIPT_DOC:-${root_dir}/docs/SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_RECEIPT_CONTRACT.md}"
contract_path="${SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_RECEIPT_CONTRACT:-${root_dir}/docs/swarm_execution_queue_policy_adoption_receipt_contract_v1.json}"
mode="${1:-check}"
receipt_path="${2:-}"
failures=0

record_pass() {
  printf 'PASS swarm-execution-queue-policy-adoption-receipt-contract %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-policy-adoption-receipt-contract %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_execution_queue_policy_adoption_receipt_contract_smoke.sh [check|selftest|validate-receipt FILE]

Validates the SWARM-CTRL-XV-A policy adoption receipt contract and sample
receipt invariants. The receipt is an adoption receipt audit artifact and never
mutates br, Agent Mail, remote workers, or live queue weights by itself.
EOF
}

check_no_forbidden_claims() {
  local path="$1"
  if grep -Eiq 'automatically adopts|automatic adoption is allowed|automatically retunes|applies retuning automatically|changes active queue automatically|manual approval is optional|manual approval may be skipped|proves sustained gain|local fallback proof is acceptable|does not reject local fallback proof' "$path"; then
    record_failure "${path#"$root_dir"/} contains unsafe automation, approval, sustained-gain, or local-fallback wording"
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
    .schema_version == "franken-engine.swarm-execution-queue-policy-adoption-receipt-contract.v1"
    and .bead_id == "bd-my39p"
    and .parent_bead_id == "bd-6qnx9"
    and (.depends_on | index("bd-j2rny") != null)
    and .receipt_schema_version == "franken-engine.swarm-execution-queue-policy-adoption-receipt.v1"
    and ([.required_receipt_fields[]] | index("operator_decision") != null)
    and ([.required_receipt_fields[]] | index("evidence_links") != null)
    and ([.required_receipt_fields[]] | index("observation_window") != null)
    and ([.required_receipt_fields[]] | index("supersession") != null)
    and ([.upstream_artifacts[].field] | index("candidate_bundle_json") != null)
    and ([.upstream_artifacts[].field] | index("promotion_guard_receipt_json") != null)
    and ([.upstream_artifacts[].field] | index("rollout_plan_json") != null)
    and ([.upstream_artifacts[].field] | index("rollback_comparator_receipt_json") != null)
    and ([.upstream_artifacts[].field] | index("canary_verdict_ledger_json") != null)
    and ([.upstream_artifacts[].field] | index("operator_decision_json") != null)
    and .operator_decision_policy.manual_operator_approval_required == true
    and .operator_decision_policy.approval_artifact_required == true
    and .observation_policy.stop_on_missing_evidence_required == true
    and (.observation_policy.required_monitored_metrics | index("queue_fidelity_millionths") != null)
    and (.observation_policy.required_monitored_metrics | index("proof_drift_count") != null)
    and (.observation_policy.required_monitored_metrics | index("rollback_trigger_count") != null)
    and .supersession_policy.supersession_metadata_required == true
    and .mutation_policy.receipt_artifact_only == true
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
    and (.non_claim_boundaries | index("does not prove sustained gain") != null)
    and (.non_claim_boundaries | index("does not imply active queue changed without this receipt") != null)
    and (.fail_closed_rules | index("missing operator approval fails closed") != null)
    and (.fail_closed_rules | index("missing observation window fails closed") != null)
    and (.fail_closed_rules | index("missing supersession metadata fails closed") != null)
    and (.fail_closed_rules | index("automatic adoption claims fail closed") != null)
    and (.fail_closed_rules | index("sustained-gain claims fail closed") != null)
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

validate_receipt() {
  local path="$1"
  if [[ -z "$path" || ! -f "$path" ]]; then
    record_failure "missing receipt path"
    return 1
  fi
  jq empty "$path" >/dev/null

  jq -e --slurpfile contract "$contract_path" '
    ($contract[0]) as $contract_doc
    | . as $receipt
    | $contract_doc.receipt_schema_version as $receipt_schema_version
    | [$contract_doc.upstream_artifacts[].field] as $required_artifacts
    | (.schema_version == $receipt_schema_version)
    and ((.adoption_receipt_id // "") | length > 0)
    and ((.adopted_policy_bundle_id // "") | length > 0)
    and ((.source_revision // "") | length > 0)
    and ((.generated_at // "") | length > 0)
    and ((.operator_decision.decision // "") == "adopt")
    and ((.operator_decision.approved_by // "") | length > 0)
    and ((.operator_decision.approved_at // "") | length > 0)
    and ((.operator_decision.approval_artifact_path // "") | length > 0)
    and ((.operator_decision.decision_reason // "") | length > 0)
    and ((.operator_decision.adoption_state // "") | IN("recorded_pending_activation", "recorded_active_policy"))
    and ((.adopted_candidate.candidate_id // "") | length > 0)
    and ((.adopted_candidate.expected_fidelity_delta_millionths // null) | type == "number")
    and ((.adopted_candidate.source_policy_bundle_id // "") == (.adopted_policy_bundle_id // ""))
    and ((.adopted_candidate.source_promotion_guard_receipt_json // "") | length > 0)
    and ((.adopted_candidate.source_canary_verdict_ledger_json // "") | length > 0)
    and ((.evidence_links // []) | type == "array")
    and ([.evidence_links[].artifact_kind] | sort == ($required_artifacts | sort))
    and all(.evidence_links[]; ((.path // "") | length > 0) and ((.sha256 // "") | test("^[0-9a-f]{64}$")))
    and ((.observation_window.starts_at // "") | length > 0)
    and ((.observation_window.duration_seconds // 0) >= $contract_doc.observation_policy.minimum_duration_seconds)
    and ((.observation_window.minimum_sample_count // 0) >= $contract_doc.observation_policy.minimum_sample_count)
    and ((.observation_window.monitored_metrics // []) | type == "array")
    and all($contract_doc.observation_policy.required_monitored_metrics[]; . as $metric | ($receipt.observation_window.monitored_metrics | index($metric) != null))
    and .observation_window.stop_on_missing_evidence == true
    and (.supersession | has("supersedes_adoption_receipt_id"))
    and (.supersession | has("supersedes_policy_bundle_id"))
    and ((.supersession.supersession_reason // "") | length > 0)
    and ((.supersession.previous_policy_retention // "") | IN("retain_for_rollback", "archive_after_window"))
    and ((.supersession.expiry_policy // "") | length > 0)
    and .mutation_policy.receipt_artifact_only == true
    and .mutation_policy.records_operator_decision == true
    and .mutation_policy.changes_active_queue == false
    and .mutation_policy.applies_live_retuning == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.rewrites_historical_outcomes == false
    and (.non_claim_boundaries | index("does not prove sustained gain") != null)
    and (.non_claim_boundaries | index("does not authorize automatic live retuning") != null)
    and (.non_claim_boundaries | index("does not mutate scheduler behavior by itself") != null)
    and ((.automation_claim // "none") | test("automatic|automatically|live retuning|changes active queue|proves sustained gain") | not)
    and (.fail_closed_rules | index("missing operator approval fails closed") != null)
    and (.fail_closed_rules | index("missing evidence hashes fail closed") != null)
    and (.fail_closed_rules | index("missing observation window fails closed") != null)
    and (.fail_closed_rules | index("missing supersession metadata fails closed") != null)
    and (.fail_closed_rules | index("automatic adoption claims fail closed") != null)
    and (.fail_closed_rules | index("sustained-gain claims fail closed") != null)
    and (.fail_closed_rules | index("reject local fallback proof evidence") != null)
  ' "$path" >/dev/null || record_failure "receipt invariant mismatch: ${path}"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  record_pass "receipt validates"
}

write_valid_receipt() {
  local path="$1"
  local digest="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

  jq -n \
    --arg digest "$digest" \
    '{
      schema_version: "franken-engine.swarm-execution-queue-policy-adoption-receipt.v1",
      adoption_receipt_id: "queue-policy-adoption-receipt-smoke",
      adopted_policy_bundle_id: "swarm-execution-queue-tuning-policy-bundle-smoke",
      source_revision: "selftest",
      generated_at: "2026-05-06T00:00:00Z",
      operator_decision: {
        decision: "adopt",
        approved_by: "human_operator",
        approved_at: "2026-05-06T00:00:00Z",
        approval_artifact_path: "approvals/queue-policy-adoption.json",
        decision_reason: "eligible canary evidence is complete and rollback references are available",
        adoption_state: "recorded_pending_activation"
      },
      adopted_candidate: {
        candidate_id: "raise_proof_health_penalty",
        expected_fidelity_delta_millionths: 240000,
        source_policy_bundle_id: "swarm-execution-queue-tuning-policy-bundle-smoke",
        source_promotion_guard_receipt_json: "promotion/promotion_guard_receipt.json",
        source_canary_verdict_ledger_json: "rollback/canary_verdict_ledger.json"
      },
      evidence_links: [
        {artifact_kind: "candidate_bundle_json", path: "bundle/tuning_policy_bundle.json", sha256: $digest},
        {artifact_kind: "promotion_guard_receipt_json", path: "promotion/promotion_guard_receipt.json", sha256: $digest},
        {artifact_kind: "rollout_plan_json", path: "promotion/manual_approval_rollout_plan.json", sha256: $digest},
        {artifact_kind: "rollback_comparator_receipt_json", path: "rollback/rollback_comparator_receipt.json", sha256: $digest},
        {artifact_kind: "canary_verdict_ledger_json", path: "rollback/canary_verdict_ledger.json", sha256: $digest},
        {artifact_kind: "operator_decision_json", path: "approvals/queue-policy-adoption.json", sha256: $digest}
      ],
      observation_window: {
        starts_at: "2026-05-06T00:00:00Z",
        duration_seconds: 3600,
        minimum_sample_count: 3,
        monitored_metrics: ["queue_fidelity_millionths", "proof_drift_count", "rollback_trigger_count"],
        stop_on_missing_evidence: true
      },
      supersession: {
        supersedes_adoption_receipt_id: null,
        supersedes_policy_bundle_id: "current-policy-bundle",
        supersession_reason: "first recorded policy adoption receipt for this lifecycle",
        previous_policy_retention: "retain_for_rollback",
        expiry_policy: "expire after observation window if drift scorer rejects sustained gain"
      },
      mutation_policy: {
        receipt_artifact_only: true,
        records_operator_decision: true,
        changes_active_queue: false,
        applies_live_retuning: false,
        mutates_br: false,
        sends_agent_mail: false,
        mutates_remote_workers: false,
        rewrites_historical_outcomes: false
      },
      non_claim_boundaries: [
        "does not prove sustained gain",
        "does not prove canary success beyond linked evidence",
        "does not authorize automatic live retuning",
        "does not mutate scheduler behavior by itself",
        "does not replace later drift-forensics scoring",
        "does not imply active queue changed without this receipt"
      ],
      automation_claim: "none",
      fail_closed_rules: [
        "missing operator approval fails closed",
        "missing evidence links fail closed",
        "missing evidence hashes fail closed",
        "missing observation window fails closed",
        "missing supersession metadata fails closed",
        "automatic adoption claims fail closed",
        "live retuning claims fail closed",
        "sustained-gain claims fail closed",
        "reject local fallback proof evidence"
      ]
    }' >"$path"
}

expect_receipt_failure() {
  local label="$1"
  local path="$2"
  if bash "${BASH_SOURCE[0]}" validate-receipt "$path" >/dev/null 2>&1; then
    record_failure "selftest expected rejection: ${label}"
  else
    record_pass "selftest rejects ${label}"
  fi
}

run_selftest() {
  local tmp_root valid_receipt no_operator missing_hash no_observation no_supersession auto_claim sustained_gain_claim
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-execution-queue-policy-adoption-receipt.XXXXXX")"

  run_check

  valid_receipt="${tmp_root}/valid-receipt.json"
  write_valid_receipt "$valid_receipt"
  bash "${BASH_SOURCE[0]}" validate-receipt "$valid_receipt" >/dev/null
  record_pass "selftest accepts valid receipt"

  no_operator="${tmp_root}/missing-operator-approval.json"
  jq '.operator_decision.approval_artifact_path = ""' "$valid_receipt" >"$no_operator"
  expect_receipt_failure "missing operator approval" "$no_operator"

  missing_hash="${tmp_root}/missing-evidence-hash.json"
  jq '(.evidence_links[] | select(.artifact_kind == "operator_decision_json") | .sha256) = ""' "$valid_receipt" >"$missing_hash"
  expect_receipt_failure "missing evidence hash" "$missing_hash"

  no_observation="${tmp_root}/missing-observation-window.json"
  jq 'del(.observation_window.duration_seconds)' "$valid_receipt" >"$no_observation"
  expect_receipt_failure "missing observation window" "$no_observation"

  no_supersession="${tmp_root}/missing-supersession-metadata.json"
  jq 'del(.supersession.previous_policy_retention)' "$valid_receipt" >"$no_supersession"
  expect_receipt_failure "missing supersession metadata" "$no_supersession"

  auto_claim="${tmp_root}/automatic-adoption-claim.json"
  jq '.automation_claim = "automatically adopts and retunes the live queue"' "$valid_receipt" >"$auto_claim"
  expect_receipt_failure "automatic adoption claim" "$auto_claim"

  sustained_gain_claim="${tmp_root}/sustained-gain-claim.json"
  jq '.automation_claim = "proves sustained gain for this queue policy"' "$valid_receipt" >"$sustained_gain_claim"
  expect_receipt_failure "sustained gain claim" "$sustained_gain_claim"

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
  validate-receipt)
    validate_receipt "$receipt_path"
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
