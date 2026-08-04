#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
schema_path="${root_dir}/docs/e8_refusal_ledger_schema_v1.json"
inventory_path="${root_dir}/docs/e8_analyzed_subset_refusal_ledger_v1.json"
fixture_dir="${root_dir}/scripts/testdata/e8_refusal_ledger"
mode="${1:-check}"
failures=0

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/e8_refusal_ledger_smoke.sh [check|selftest]

Runs shell/JQ-only checks for the E8 refusal-ledger schema and deterministic
fixtures. This smoke harness does not run Cargo, rch, or live frankenctl.
EOF
}

record_pass() {
  printf 'PASS e8-refusal-ledger %s\n' "$1"
}

record_failure() {
  printf 'FAIL e8-refusal-ledger %s\n' "$1" >&2
  failures=$((failures + 1))
}

require_tools() {
  if ! command -v jq >/dev/null 2>&1; then
    printf 'jq is required for E8 refusal-ledger smoke\n' >&2
    exit 2
  fi
}

collect_fixtures() {
  shopt -s nullglob
  fixture_paths=("${fixture_dir}"/*.json)
  shopt -u nullglob
  if [[ "${#fixture_paths[@]}" -eq 0 ]]; then
    printf 'no E8 refusal-ledger fixtures found under %s\n' "$fixture_dir" >&2
    exit 1
  fi
}

parse_json_inputs() {
  jq empty "$schema_path" >/dev/null
  jq empty "$inventory_path" >/dev/null
  jq empty "${fixture_paths[@]}" >/dev/null
}

check_schema_inventory_contract() {
  jq -e -s '
    .[0] as $schema
    | .[1] as $inventory
    | ($schema.properties.schema_version.const == "franken-engine.e8-refusal-ledger.v1")
    and ($inventory.schema_version == "franken-engine.e8-analyzed-subset-refusal-ledger.v1")
    and ($inventory.threat_model.scope == "explicit_flow_ifc_v1")
    and (($schema.properties.result_class.enum | sort) == ($inventory.result_classes | map(.code) | sort))
    and (($schema."$defs".refusal_code.properties.code.enum | sort) == ($inventory.refusal_codes | map(.code) | sort))
    and (($schema."$defs".refusal_code.properties.class.enum | sort) == ($inventory.refusal_codes | map(.class) | unique | sort))
  ' "$schema_path" "$inventory_path" >/dev/null
}

check_fixture_coverage() {
  jq -e -s '
    (map(.ledger_id) | sort) == [
      "e8-refusal-ledger-certifiable-subset",
      "e8-refusal-ledger-fallback-flow",
      "e8-refusal-ledger-hash-mismatch",
      "e8-refusal-ledger-out-of-scope-timing",
      "e8-refusal-ledger-unsupported-syntax"
    ]
    and (map(.result_class) | sort) == [
      "certifiable_subset",
      "degraded",
      "fail_closed",
      "out_of_scope",
      "uncertified"
    ]
  ' "${fixture_paths[@]}" >/dev/null
}

check_fixture_invariants() {
  jq -e -s '
    def unique_ids($xs): (($xs | length) == ($xs | unique | length));

    all(.[]; . as $fixture
      | ($fixture.schema_version == "franken-engine.e8-refusal-ledger.v1")
      and ($fixture.threat_model_scope == "explicit_flow_ifc_v1")
      and ($fixture.positive_non_use_claim_allowed == false)
      and (($fixture.source_refs | length) > 0)
      and unique_ids($fixture.source_refs | map(.id))
      and all($fixture.refusal_codes[]?; .source_ref_id as $source_ref_id | (($fixture.source_refs | map(.id)) | index($source_ref_id)) != null)
      and (if $fixture.result_class == "certifiable_subset" then
          ($fixture.certifier_input_allowed == true)
          and ($fixture.must_block_certificate == false)
          and (($fixture.refusal_codes | length) == 0)
          and ($fixture.analyzed_surface_count > 0)
          and ($fixture.unanalyzed_surface_count == 0)
          and ($fixture.degraded_surface_count == 0)
        else
          ($fixture.certifier_input_allowed == false)
          and ($fixture.must_block_certificate == true)
          and (($fixture.refusal_codes | length) > 0)
        end)
      and (if $fixture.result_class == "uncertified" then $fixture.unanalyzed_surface_count > 0 else true end)
      and (if $fixture.result_class == "degraded" then $fixture.degraded_surface_count > 0 else true end)
      and (if $fixture.result_class == "fail_closed" then any($fixture.refusal_codes[]; .class == "fail_closed") else true end)
      and (if $fixture.result_class == "out_of_scope" then any($fixture.refusal_codes[]; .class == "out_of_scope") else true end)
    )
  ' "${fixture_paths[@]}" >/dev/null
}

check_refusal_vocabulary() {
  jq -e -s '
    .[0] as $schema
    | .[1] as $inventory
    | .[2:] as $fixtures
    | ($schema."$defs".refusal_code.properties.code.enum) as $schema_codes
    | ($schema."$defs".refusal_code.properties.class.enum) as $schema_classes
    | ($inventory.refusal_codes | map({key: .code, value: .class}) | from_entries) as $inventory_class_by_code
    | all($fixtures[]; all(.refusal_codes[]?;
        (.code as $code
        | .class as $class
        | (($schema_codes | index($code)) != null)
        and (($schema_classes | index($class)) != null)
        and ($inventory_class_by_code[$code] == $class))
      ))
  ' "$schema_path" "$inventory_path" "${fixture_paths[@]}" >/dev/null
}

run_check() {
  require_tools
  collect_fixtures

  parse_json_inputs || record_failure "json parse"
  check_schema_inventory_contract || record_failure "schema inventory contract"
  check_fixture_coverage || record_failure "fixture coverage"
  check_fixture_invariants || record_failure "fixture invariants"
  check_refusal_vocabulary || record_failure "refusal vocabulary"
  bash -n "${BASH_SOURCE[0]}" || record_failure "bash syntax"

  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

case "$mode" in
  check|selftest)
    run_check
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
