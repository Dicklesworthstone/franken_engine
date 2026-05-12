#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract_json="${root_dir}/docs/franken_core_graduation_contract_v1.json"
contract_doc="${root_dir}/docs/FRANKEN_CORE_GRADUATION_CONTRACT_V1.md"
root_cargo="${root_dir}/Cargo.toml"
mode="${1:-check}"

record_pass() {
  printf 'PASS franken-core-graduation %s\n' "$1"
}

record_failure() {
  printf 'FAIL franken-core-graduation %s\n' "$1" >&2
  exit 1
}

json_shape_filter='
  . as $root
  | .schema_version == "franken-engine.franken-core-graduation-contract.v1"
  and .contract_version == "1.0.0"
  and .bead_id == "bd-4w7h9.1"
  and .parent_bead_id == "bd-4w7h9"
  and .acceptance_suite_bead_id == "bd-4w7h9.8"
  and .policy_id == "policy-franken-core-graduation-v1"
  and .status == "active"
  and .decision.current_workspace_state == "excluded"
  and .decision.green_state_requires_acceptance_suite == true
  and .decision.workspace_inclusion_complete == false
  and .mutation_boundary.mutates_workspace_membership == false
  and .mutation_boundary.edits_root_workspace_members == false
  and .mutation_boundary.edits_root_workspace_exclude == false
  and .mutation_boundary.mutates_franken_node == false
  and .mutation_boundary.introduces_core_to_node_dependency == false
  and .mutation_boundary.introduces_node_engine_fork == false
  and .mutation_boundary.runs_heavy_cargo_locally == false
  and .mutation_boundary.requires_separate_change_bead_for_membership == true
  and .workspace_membership_policy.current_root_cargo_exclude == "crates/franken-core"
  and .workspace_membership_policy.allowed_change_requires_separate_bead == true
  and .workspace_membership_policy.allowed_change_requires_acceptance_suite == "bd-4w7h9.8"
  and .workspace_membership_policy.default_when_missing_evidence == "remain_excluded"
  and ([.historical_inputs[].bead_id] | sort) == (["bd-dymfz", "bd-nwhcp", "bd-ucemx", "bd-zsais"] | sort)
  and (.required_doc_sections | length) >= 10
  and (.fail_closed_conditions | index("missing_required_doc_section"))
  and (.fail_closed_conditions | index("unknown_proof_state"))
  and (.fail_closed_conditions | index("workspace_inclusion_claim_before_acceptance"))
  and (.fail_closed_conditions | index("root_cargo_exclude_mismatch"))
  and (.rch_policy.required_heavy_cargo_prefix == "rch exec -- env CARGO_TARGET_DIR=")
  and (.rch_policy.canonical_heavy_cargo_example | contains("rch exec -- env CARGO_TARGET_DIR="))
  and (.rch_policy.canonical_heavy_cargo_example | contains("CARGO_BUILD_JOBS=1"))
  and (.forbidden_shortcuts | index("claim standalone compileability means workspace inclusion is complete"))
  and (.validation_commands | index("bash scripts/e2e/franken_core_graduation_contract_smoke.sh negative"))
  and all(.accepted_evidence[]; (.proof_state as $state | $root.allowed_proof_states | index($state)))
'

json_shape_ok() {
  jq -e "${json_shape_filter}" "$contract_json" >/dev/null
}

doc_shape_ok() {
  local section
  while IFS= read -r section; do
    grep -Fq "$section" "$contract_doc" || return 1
  done < <(jq -r '.required_doc_sections[]' "$contract_json")

  grep -Fq 'Machine-readable contract: `docs/franken_core_graduation_contract_v1.json`' "$contract_doc" \
    && grep -Fq '`crates/franken-core` remains excluded from the root workspace' "$contract_doc" \
    && grep -Fq 'bd-4w7h9.8' "$contract_doc" \
    && grep -Fq 'root `Cargo.toml`, workspace membership' "$contract_doc" \
    && grep -Fq 'rch exec -- env CARGO_TARGET_DIR=' "$contract_doc"
}

root_cargo_state_ok() {
  grep -Fq 'exclude = ["crates/franken-core"]' "$root_cargo" \
    && grep -Fq 'standalone manifest is compileable' "$root_cargo" \
    && grep -Fq 'deliberate workspace integration pass validates the extracted API boundary' "$root_cargo"
}

no_bare_heavy_cargo_examples() {
  ! rg -n '^[[:space:]]*cargo (check|test|clippy|build)([[:space:]]|$)' \
    "$contract_doc" "$contract_json" >/dev/null
}

run_check() {
  jq empty "$contract_json"
  bash -n "${BASH_SOURCE[0]}"
  json_shape_ok || record_failure "json shape"
  doc_shape_ok || record_failure "doc shape"
  root_cargo_state_ok || record_failure "root Cargo.toml state"
  no_bare_heavy_cargo_examples || record_failure "bare heavy cargo example"
  git -C "$root_dir" diff --check -- \
    docs/FRANKEN_CORE_GRADUATION_CONTRACT_V1.md \
    docs/franken_core_graduation_contract_v1.json \
    scripts/e2e/franken_core_graduation_contract_smoke.sh
  record_pass "check"
}

expect_invalid() {
  local name="$1"
  local mutation="$2"

  if jq "$mutation" "$contract_json" | jq -e "${json_shape_filter}" >/dev/null; then
    record_failure "negative ${name}"
  fi

  record_pass "negative ${name}"
}

run_negative() {
  expect_invalid "missing required doc section" 'del(.required_doc_sections[0])'
  expect_invalid "unknown proof state" '.accepted_evidence[0].proof_state = "workspace_inclusion_complete"'
  expect_invalid "inclusion complete claim" '.decision.workspace_inclusion_complete = true'
  expect_invalid "missing acceptance suite" 'del(.acceptance_suite_bead_id)'
  expect_invalid "local heavy cargo allowed" '.mutation_boundary.runs_heavy_cargo_locally = true'
}

case "$mode" in
  check)
    run_check
    ;;
  negative)
    run_negative
    ;;
  -h|--help|help)
    printf 'Usage: ./scripts/e2e/franken_core_graduation_contract_smoke.sh [check|negative]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
