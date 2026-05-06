#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docs_path="${TYPED_PERSISTENCE_ENFORCEMENT_DOC:-${root_dir}/docs/TYPED_PERSISTENCE_ENFORCEMENT_CONTRACT.md}"
contract_path="${TYPED_PERSISTENCE_ENFORCEMENT_CONTRACT:-${root_dir}/docs/typed_persistence_enforcement_contract_v1.json}"
inventory_path="${TYPED_PERSISTENCE_ENFORCEMENT_INVENTORY:-${root_dir}/docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md}"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS typed-persistence-enforcement-contract %s\n' "$1"
}

record_failure() {
  printf 'FAIL typed-persistence-enforcement-contract %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/typed_persistence_enforcement_contract_smoke.sh [check|selftest]

Validates the SQLMODEL-TYPED-P0-A typed persistence enforcement contract and
the current typed-boundary evidence it depends on.
EOF
}

check_no_forbidden_claims() {
  local path="$1"
  if grep -Eiq 'already fully enforced end-to-end|legacy inputs are accepted implicitly|ambiguous legacy data is allowed|generic authority remains authoritative' "$path"; then
    record_failure "${path#"$root_dir"/} contains untruthful enforcement wording"
  fi
}

check_code_evidence() {
  local item_count
  item_count="$(jq '.code_evidence | length' "$contract_path")"
  local index=0
  while [[ "$index" -lt "$item_count" ]]; do
    local rel_path
    rel_path="$(jq -r ".code_evidence[$index].path" "$contract_path")"
    local abs_path="${root_dir}/${rel_path}"
    if [[ ! -f "$abs_path" ]]; then
      record_failure "missing code evidence path ${rel_path}"
      index=$((index + 1))
      continue
    fi
    while IFS= read -r symbol; do
      [[ -z "$symbol" ]] && continue
      grep -Fq "$symbol" "$abs_path" || record_failure "${rel_path} missing evidence symbol: ${symbol}"
    done < <(jq -r ".code_evidence[$index].must_contain[]" "$contract_path")
    index=$((index + 1))
  done
}

run_check() {
  [[ -f "$docs_path" ]] || { record_failure "missing doc ${docs_path}"; return 1; }
  [[ -f "$contract_path" ]] || { record_failure "missing contract ${contract_path}"; return 1; }
  [[ -f "$inventory_path" ]] || { record_failure "missing inventory ${inventory_path}"; return 1; }

  jq empty "$contract_path" >/dev/null

  jq -e '
    .schema_version == "franken-engine.typed-persistence-enforcement-contract.v1"
    and .bead_id == "bd-gvnex"
    and .parent_bead_id == "bd-xyku0"
    and .inventory_doc == "docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md"
    and (.scope_store_kinds | sort == ["IfcProvenance", "ReplacementLineage", "SpecializationIndex"])
    and (.scope_inventory_rows | length == 3)
    and (.typed_boundary_requirements.primary_authority_required == true)
    and (.typed_boundary_requirements.generic_authority_must_become_non_authoritative == true)
    and (.typed_boundary_requirements.legacy_inputs_allowed_only_for_explicit_lossless_backfill_planning == true)
    and (.typed_boundary_requirements.implicit_legacy_acceptance_forbidden == true)
    and (.typed_boundary_requirements.ambiguous_legacy_data_fails_closed == true)
    and (.typed_boundary_requirements.authoritative_helpers | index("TypedStorageAdapterExt.put_typed") != null)
    and (.typed_boundary_requirements.authoritative_helpers | index("TypedStorageAdapterExt.get_typed_by_id") != null)
    and (.typed_boundary_requirements.authoritative_helpers | index("TypedStorageAdapterExt.query_typed") != null)
    and (.typed_boundary_requirements.legacy_planning_helpers | index("plan_typed_store_backfill") != null)
    and (.typed_boundary_requirements.legacy_planning_helpers | index("map_legacy_replacement_lineage_record") != null)
    and (.typed_boundary_requirements.legacy_planning_helpers | index("map_legacy_ifc_provenance_record") != null)
    and (.typed_boundary_requirements.legacy_planning_helpers | index("map_legacy_specialization_index_record") != null)
  ' "$contract_path" >/dev/null || record_failure "contract shape mismatch"

  while IFS= read -r required_text; do
    grep -Fq "$required_text" "$docs_path" || record_failure "doc missing required text: ${required_text}"
  done < <(jq -r '.required_doc_text[]' "$contract_path")

  grep -Fq '| replacement lineage log | sqlmodel_rust on frankensqlite |' "$inventory_path" || record_failure "inventory missing replacement lineage typed row"
  grep -Fq '| IFC provenance index | sqlmodel_rust on frankensqlite |' "$inventory_path" || record_failure "inventory missing IFC provenance typed row"
  grep -Fq '| specialization index | sqlmodel_rust on frankensqlite |' "$inventory_path" || record_failure "inventory missing specialization index typed row"

  check_no_forbidden_claims "$docs_path"
  check_no_forbidden_claims "$contract_path"
  check_code_evidence

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  record_pass "static contract and code evidence validate"
}

run_selftest() {
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap '[[ -n "${tmpdir:-}" ]] && rm -rf "$tmpdir"' EXIT

  cp "$docs_path" "$tmpdir/doc.md"
  cp "$contract_path" "$tmpdir/contract.json"

  local failed=0

  jq 'del(.scope_store_kinds[0])' "$contract_path" >"$tmpdir/missing_store.json"
  if TYPED_PERSISTENCE_ENFORCEMENT_DOC="$docs_path" \
     TYPED_PERSISTENCE_ENFORCEMENT_CONTRACT="$tmpdir/missing_store.json" \
     TYPED_PERSISTENCE_ENFORCEMENT_INVENTORY="$inventory_path" \
     "$0" check >/dev/null 2>&1; then
    record_failure "selftest missing_scope_store_fails did not fail"
    failed=1
  else
    record_pass "selftest missing_scope_store_fails"
  fi

  sed 's/Ambiguous legacy data must fail closed\./Ambiguous legacy data gets handled somehow./' \
    "$docs_path" >"$tmpdir/doc_missing_text.md"
  if TYPED_PERSISTENCE_ENFORCEMENT_DOC="$tmpdir/doc_missing_text.md" \
     TYPED_PERSISTENCE_ENFORCEMENT_CONTRACT="$contract_path" \
     TYPED_PERSISTENCE_ENFORCEMENT_INVENTORY="$inventory_path" \
     "$0" check >/dev/null 2>&1; then
    record_failure "selftest doc_missing_required_text_fails did not fail"
    failed=1
  else
    record_pass "selftest doc_missing_required_text_fails"
  fi

  jq '.code_evidence[0].must_contain[0] = "totally_missing_typed_symbol"' "$contract_path" >"$tmpdir/missing_symbol.json"
  if TYPED_PERSISTENCE_ENFORCEMENT_DOC="$docs_path" \
     TYPED_PERSISTENCE_ENFORCEMENT_CONTRACT="$tmpdir/missing_symbol.json" \
     TYPED_PERSISTENCE_ENFORCEMENT_INVENTORY="$inventory_path" \
     "$0" check >/dev/null 2>&1; then
    record_failure "selftest code_evidence_symbol_missing_fails did not fail"
    failed=1
  else
    record_pass "selftest code_evidence_symbol_missing_fails"
  fi

  if [[ "$failed" -ne 0 ]]; then
    return 1
  fi
  record_pass "selftest suite validates failure cases"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    usage
    exit 64
    ;;
esac
