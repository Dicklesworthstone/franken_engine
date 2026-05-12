#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ledger_json="${root_dir}/docs/franken_core_api_parity_ledger_v1.json"
ledger_doc="${root_dir}/docs/FRANKEN_CORE_API_PARITY_LEDGER_V1.md"
core_lib="${root_dir}/crates/franken-core/src/lib.rs"
engine_lib="${root_dir}/crates/franken-engine/src/lib.rs"
mode="${1:-check}"

record_pass() {
  printf 'PASS franken-core-api-parity %s\n' "$1"
}

record_failure() {
  printf 'FAIL franken-core-api-parity %s\n' "$1" >&2
  exit 1
}

json_shape_filter='
  . as $root
  | .schema_version == "franken-engine.franken-core-api-parity-ledger.v1"
  and .contract_version == "1.0.0"
  and .bead_id == "bd-4w7h9.2"
  and .parent_bead_id == "bd-4w7h9"
  and .graduation_contract_bead_id == "bd-4w7h9.1"
  and .acceptance_suite_bead_id == "bd-4w7h9.8"
  and .policy_id == "policy-franken-core-api-parity-ledger-v1"
  and .status == "active"
  and .decision.current_workspace_state == "excluded"
  and .decision.workspace_inclusion_complete == false
  and .summary.workspace_inclusion_complete == false
  and .summary.core_module_count == (.rows | length)
  and .summary.matching_engine_export_count == ([.rows[] | select(.engine_export_present == true)] | length)
  and .summary.missing_engine_export_count == ([.rows[] | select(.engine_export_present != true)] | length)
  and .summary.identical_file_count == ([.rows[] | select(.file_relation == "identical")] | length)
  and .summary.different_file_count == ([.rows[] | select(.file_relation == "different")] | length)
  and .summary.unclassified_row_count == ([.rows[] | select((.status as $status | $root.allowed_statuses | index($status) | not))] | length)
  and .summary.unclassified_row_count == 0
  and (([.rows[].module] | unique | length) == (.rows | length))
  and all(.rows[]; (. as $row | all($root.required_row_fields[]; . as $field | $row | has($field))))
  and all(.rows[]; (.status as $status | $root.allowed_statuses | index($status)))
  and all(.rows[]; (.file_relation as $relation | $root.allowed_file_relations | index($relation)))
  and all(.rows[]; .canonical_owner == "unsettled_until_acceptance")
  and all(.rows[]; .engine_export_present == true)
'

core_modules_json() {
  awk '/^pub mod / {gsub(";", "", $3); print $3}' "$core_lib" | sort | jq -R . | jq -s .
}

engine_modules_json() {
  awk '/^pub mod / {gsub(";", "", $3); print $3}' "$engine_lib" | sort | jq -R . | jq -s .
}

json_shape_ok() {
  jq -e "${json_shape_filter}" "$1" >/dev/null
}

doc_shape_ok() {
  grep -Fq 'Machine-readable ledger: `docs/franken_core_api_parity_ledger_v1.json`' "$ledger_doc" \
    && grep -Fq 'The current inventory has 41 franken-core module exports.' "$ledger_doc" \
    && grep -Fq 'For this first ledger, every row is `pending_graduation`.' "$ledger_doc" \
    && grep -Fq 'workspace inclusion is complete' "$ledger_doc" \
    && grep -Fq 'bash scripts/e2e/franken_core_api_parity_ledger_smoke.sh negative' "$ledger_doc"
}

module_set_ok() {
  local json_path="$1"
  local core_json engine_json rows_json missing_engine_json

  core_json="$(core_modules_json)"
  engine_json="$(engine_modules_json)"
  rows_json="$(jq '[.rows[].module] | sort' "$json_path")"
  missing_engine_json="$(jq -n --argjson core "$core_json" --argjson engine "$engine_json" '$core - $engine')"

  jq -n -e --argjson a "$core_json" --argjson b "$rows_json" '$a == $b' >/dev/null \
    || return 1
  jq -n -e --argjson missing "$missing_engine_json" '$missing == []' >/dev/null \
    || return 1
}

row_paths_current() {
  local json_path="$1"
  local row module core_path engine_path expected_relation actual_relation

  while IFS= read -r row; do
    module="$(jq -r '.module' <<<"$row")"
    core_path="$(jq -r '.core_path' <<<"$row")"
    engine_path="$(jq -r '.engine_path' <<<"$row")"
    expected_relation="$(jq -r '.file_relation' <<<"$row")"

    [[ -f "${root_dir}/${core_path}" ]] || return 1
    [[ -f "${root_dir}/${engine_path}" ]] || return 1
    grep -Fq "pub mod ${module};" "$core_lib" || return 1
    grep -Fq "pub mod ${module};" "$engine_lib" || return 1

    if cmp -s "${root_dir}/${core_path}" "${root_dir}/${engine_path}"; then
      actual_relation="identical"
    else
      actual_relation="different"
    fi
    [[ "$actual_relation" == "$expected_relation" ]] || return 1
  done < <(jq -c '.rows[]' "$json_path")
}

no_bare_heavy_cargo_examples() {
  ! rg -n '^[[:space:]]*cargo (check|test|clippy|build)([[:space:]]|$)' \
    "$ledger_doc" "$ledger_json" >/dev/null
}

run_check() {
  jq empty "$ledger_json"
  bash -n "${BASH_SOURCE[0]}"
  json_shape_ok "$ledger_json" || record_failure "json shape"
  doc_shape_ok || record_failure "doc shape"
  module_set_ok "$ledger_json" || record_failure "module set"
  row_paths_current "$ledger_json" || record_failure "row paths or file relation"
  no_bare_heavy_cargo_examples || record_failure "bare heavy cargo example"
  git -C "$root_dir" diff --check -- \
    docs/FRANKEN_CORE_API_PARITY_LEDGER_V1.md \
    docs/franken_core_api_parity_ledger_v1.json \
    scripts/e2e/franken_core_api_parity_ledger_smoke.sh
  record_pass "check"
}

expect_invalid_shape() {
  local name="$1"
  local mutation="$2"

  if jq "$mutation" "$ledger_json" | jq -e "${json_shape_filter}" >/dev/null; then
    record_failure "negative ${name}"
  fi

  record_pass "negative ${name}"
}

expect_invalid_module_set() {
  local name="$1"
  local mutation="$2"

  if module_set_ok <(jq "$mutation" "$ledger_json"); then
    record_failure "negative ${name}"
  fi

  record_pass "negative ${name}"
}

expect_invalid_paths() {
  local name="$1"
  local mutation="$2"

  if row_paths_current <(jq "$mutation" "$ledger_json"); then
    record_failure "negative ${name}"
  fi

  record_pass "negative ${name}"
}

run_negative() {
  expect_invalid_shape "missing row count" 'del(.rows[0])'
  expect_invalid_shape "duplicate module key" '.rows += [.rows[0]] | .summary.core_module_count += 1 | .summary.matching_engine_export_count += 1 | .summary.different_file_count += 1'
  expect_invalid_shape "unknown status" '.rows[0].status = "workspace_inclusion_complete" | .summary.unclassified_row_count = 1'
  expect_invalid_shape "inclusion complete claim" '.decision.workspace_inclusion_complete = true'
  expect_invalid_module_set "missing live module row" 'del(.rows[0]) | .summary.core_module_count -= 1 | .summary.matching_engine_export_count -= 1 | .summary.different_file_count -= 1'
  expect_invalid_paths "stale path" '.rows[0].core_path = "crates/franken-core/src/not_real.rs"'
  expect_invalid_paths "stale file relation" '.rows[0].file_relation = "identical" | .summary.identical_file_count += 1 | .summary.different_file_count -= 1'
}

case "$mode" in
  check)
    run_check
    ;;
  negative)
    run_negative
    ;;
  -h|--help|help)
    printf 'Usage: ./scripts/e2e/franken_core_api_parity_ledger_smoke.sh [check|negative]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
