#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract_path="${root_dir}/docs/swarm_proof_broker_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_PROOF_BROKER.md"
cases_path="${root_dir}/scripts/testdata/swarm_proof_broker/contracts/cases.json"
failures=0

record_pass() {
  printf 'PASS swarm-proof-broker-contract %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-proof-broker-contract %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_proof_broker_contract_smoke.sh [check]
EOF
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-broker-contract.v1"
    and .bead_id == "bd-ua5n2.1"
    and .parent_bead_id == "bd-ua5n2"
    and .contract_status == "advisory_evidence_contract"
    and .mutation_policy.advisory_only == true
    and .mutation_policy.receipt_can_close_beads == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
    and .command_shape_policy.accepted_rust_proof_prefix == "rch exec -- env ... cargo ..."
    and (.accepted_env_allowlist | index("CARGO_TARGET_DIR") != null)
    and (.accepted_env_allowlist | index("CARGO_INCREMENTAL") != null)
    and (.proof_request_fingerprint.id_prefix == "spbreq-")
    and (.verdict_receipt.statuses | map(.status) | sort) == ["contaminated", "failed", "inconclusive", "passed", "reuse_refused", "stale"]
    and (.fixture_cases | length) == 8
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'advisory-only' "$docs_path" \
    && grep -Fq 'cannot close a bead' "$docs_path" \
    && grep -Fq 'normalized command argv' "$docs_path" \
    && grep -Fq 'local fallback' "$docs_path" \
    && grep -Fq 'A wider all-targets proof does not automatically satisfy' "$docs_path" \
    && grep -Fq 'rch exec -- env CARGO_INCREMENTAL=0' "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-broker-contract-fixtures.v1"
    and .contract_schema_version == "franken-engine.swarm-proof-broker-contract.v1"
    and (.cases | length) == 8
    and (.canonicalization_samples | length) == 2
    and any(.canonicalization_samples[]; .sample_id == "env_allowlist_sorted" and .expected_same_fingerprint == true)
    and any(.canonicalization_samples[]; .sample_id == "argv_order_semantic" and .expected_same_fingerprint == false)
    and all(.cases[]; has("case_id") and has("request_patch") and has("receipt") and has("expected"))
  ' "$cases_path" >/dev/null
}

fingerprint_inputs_ok() {
  jq -n \
    --slurpfile contract "$contract_path" \
    --slurpfile fixtures "$cases_path" '
      ($contract[0].proof_request_fingerprint.required_inputs | map(.field)) as $required
      | ($contract[0].proof_request_fingerprint.stable_input_fields) as $stable
      | ($fixtures[0].base_proof_request | keys) as $base_keys
      | all($required[]; ($stable | index(.)) != null and ($base_keys | index(.)) != null)
      and ($required | length) == 18
      and ($stable | length) == 18
    ' >/dev/null
}

receipt_statuses_ok() {
  jq -n \
    --slurpfile contract "$contract_path" \
    --slurpfile fixtures "$cases_path" '
      ($contract[0].verdict_receipt.statuses | map(.status)) as $allowed
      | all($fixtures[0].cases[];
          . as $case
          | ($allowed | index($case.expected.status)) != null
          and $case.receipt.status == $case.expected.status
          and $case.receipt.reuse_eligible == $case.expected.reuse_eligible
          and ($case.expected.status == "passed" or $case.expected.reuse_eligible == false)
          and ($case.receipt.invalidation_reasons == $case.expected.invalidation_reasons)
          and ($case.receipt.remediation | length) >= 40
        )
      and ([$fixtures[0].cases[].expected.status] | unique | sort) == ($allowed | sort)
    ' >/dev/null
}

reason_coverage_ok() {
  jq -n \
    --slurpfile contract "$contract_path" \
    --slurpfile fixtures "$cases_path" '
      ($contract[0].invalidation_reasons | map(select(.fail_closed == true) | .code) | unique | sort) as $contract_reasons
      | ([$fixtures[0].cases[].expected.invalidation_reasons[]] | unique | sort) as $fixture_reasons
      | (($contract_reasons - $fixture_reasons) | length) == 0
      and all($contract[0].invalidation_reasons[] | select(.fail_closed == true); (.required_remediation | length) >= 40)
      and all($fixtures[0].cases[] | select(.expected.fail_closed == true); (.receipt.remediation | length) >= 40)
    ' >/dev/null
}

artifact_bundle_policy_ok() {
  jq -n \
    --slurpfile contract "$contract_path" \
    --slurpfile fixtures "$cases_path" '
      ($contract[0].required_artifacts) as $required_artifacts
      | all($fixtures[0].cases[] | select(.receipt.artifact_bundle.complete == true);
          (.receipt.artifact_bundle.artifacts | sort) == ($required_artifacts | sort)
        )
      and all($fixtures[0].cases[] | select(.receipt.artifact_bundle.complete == false);
          .expected.reuse_eligible == false
        )
    ' >/dev/null
}

assert_lightweight_verification_commands() {
  local command

  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      record_failure "contract verification command runs Cargo: ${command}"
    fi
    if [[ "$command" =~ (^|[[:space:]])rch[[:space:]]+exec([[:space:]]|$) ]]; then
      record_failure "contract verification command invokes rch: ${command}"
    fi
  done < <(jq -r '.verification_commands[]?' "$contract_path")
}

run_check() {
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path" "$cases_path" >/dev/null

  contract_shape_ok || record_failure "contract shape"
  docs_shape_ok || record_failure "docs shape"
  fixtures_shape_ok || record_failure "fixture shape"
  fingerprint_inputs_ok || record_failure "fingerprint input coverage"
  receipt_statuses_ok || record_failure "receipt status coverage"
  reason_coverage_ok || record_failure "fail-closed reason remediation coverage"
  artifact_bundle_policy_ok || record_failure "artifact bundle policy"
  assert_lightweight_verification_commands

  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

case "${1:-check}" in
  check)
    run_check
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
