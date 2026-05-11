#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract_json="${root_dir}/docs/idea_wizard_iv_saturation_convergence_v1.json"
contract_doc="${root_dir}/docs/IDEA_WIZARD_IV_SATURATION_CONVERGENCE.md"
mode="${1:-check}"

record_pass() {
  printf 'PASS idea-wizard-iv-saturation %s\n' "$1"
}

record_failure() {
  printf 'FAIL idea-wizard-iv-saturation %s\n' "$1" >&2
  exit 1
}

json_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.idea-wizard-iv-saturation-convergence.v1"
    and .bead_id == "bd-vaths.1"
    and .parent_bead_id == "bd-vaths"
    and .global_mutation_boundary.advisory_only == true
    and .global_mutation_boundary.proof_only == true
    and .global_mutation_boundary.mutates_br == false
    and .global_mutation_boundary.sends_agent_mail == false
    and .global_mutation_boundary.repairs_agent_mail_db == false
    and .global_mutation_boundary.runs_cargo == false
    and .global_mutation_boundary.runs_rch == false
    and .global_rch_policy.required_heavy_cargo_prefix == "rch exec -- env CARGO_TARGET_DIR="
    and (.zero_ready_classifications | sort) == ([
      "coordination_degraded",
      "proof_integrity_gap",
      "resource_pressure_blocked",
      "tracker_blind_spot",
      "true_saturation",
      "validation_map_missing"
    ] | sort)
    and (.failure_reason_codes | index("FE-IW4-DUPLICATE-SURFACE"))
    and (.failure_reason_codes | index("FE-IW4-LOCAL-FALLBACK-CONTAMINATION"))
    and (.surfaces | length) == 8
    and (. as $root | all(.surfaces[]; (. as $surface | all($root.required_surface_fields[]; . as $field | $surface | has($field)))))
    and all(.surfaces[]; .mutation_policy.advisory_only == true and .mutation_policy.proof_only == true)
    and all(.surfaces[]; .rch_policy.required_prefix == "rch exec -- env CARGO_TARGET_DIR=")
    and all(.surfaces[]; (.duplicate_surface_refs | length) > 0)
  ' "$contract_json" >/dev/null
}

doc_shape_ok() {
  grep -Fq "This contract exists because an empty ready queue is not, by itself, evidence" "$contract_doc" \
    && grep -Fq "The contract is advisory only." "$contract_doc" \
    && grep -Fq "FE-IW4-DUPLICATE-SURFACE" "$contract_doc" \
    && grep -Fq "true_saturation" "$contract_doc" \
    && grep -Fq "rch exec -- env CARGO_TARGET_DIR=" "$contract_doc" \
    && grep -Fq "does not automatically reopen work, repair Agent Mail, mutate queue policy" "$contract_doc"
}

no_bare_heavy_cargo_examples() {
  ! rg -n '^[[:space:]]*cargo (check|test|clippy|build)([[:space:]]|$)' "$contract_doc" "$contract_json" >/tmp/iw4_bare_cargo_hits 2>/dev/null
}

run_check() {
  jq empty "$contract_json"
  bash -n "${BASH_SOURCE[0]}"
  json_shape_ok || record_failure "json shape"
  doc_shape_ok || record_failure "doc shape"
  no_bare_heavy_cargo_examples || {
    cat /tmp/iw4_bare_cargo_hits >&2
    record_failure "bare heavy cargo example"
  }
  rg -n 'rch exec -- env CARGO_TARGET_DIR=' "$contract_doc" "$contract_json" >/dev/null \
    || record_failure "missing rch wrapped heavy cargo example"
  git -C "$root_dir" diff --check -- \
    docs/IDEA_WIZARD_IV_SATURATION_CONVERGENCE.md \
    docs/idea_wizard_iv_saturation_convergence_v1.json \
    scripts/e2e/idea_wizard_iv_saturation_convergence_contract_smoke.sh
  record_pass "check"
}

case "$mode" in
  check)
    run_check
    ;;
  -h|--help|help)
    printf 'Usage: ./scripts/e2e/idea_wizard_iv_saturation_convergence_contract_smoke.sh [check]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
