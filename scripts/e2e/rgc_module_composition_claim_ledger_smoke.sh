#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
default_contract="${root_dir}/docs/rgc_module_composition_claim_ledger_v1.json"

expected_composition_ids=(
  "parser_frontier_harness"
  "rgc_066c_observability_publication_bundle"
  "rgc_611_tail_latency_control_plane"
  "rgc_707_semantic_dark_matter_engine"
  "rgc_cold_start_compilation_lane"
  "runtime_diagnostics_doctor"
)

validation_failures=0

record_failure() {
  printf 'FAIL: %s\n' "$1" >&2
  validation_failures=$((validation_failures + 1))
}

record_pass() {
  printf 'PASS: %s\n' "$1"
}

check_path_exists() {
  local rel_path="$1"
  if [[ -z "$rel_path" || "$rel_path" == "null" ]]; then
    record_failure "referenced path is empty"
    return
  fi
  if [[ ! -e "${root_dir}/${rel_path}" ]]; then
    record_failure "missing referenced path ${rel_path}"
  else
    record_pass "path exists ${rel_path}"
  fi
}

validate_contract() {
  local contract_path="$1"
  local contract_json
  local actual_ids expected_ids claim composition_id proof_posture source_kind source_path
  local start_line end_line status_note

  validation_failures=0

  if [[ ! -e "$contract_path" ]]; then
    record_failure "contract file not found: ${contract_path}"
    return 1
  fi

  if ! command -v jq >/dev/null 2>&1; then
    record_failure "jq is required"
    return 1
  fi

  contract_json="$(cat "$contract_path")"

  if ! jq -e '
    .schema_version == "franken-engine.module-composition-claim-ledger.v1"
    and .bead_id == "bd-37q56"
    and (.verification_commands | type == "array")
    and (.verification_commands | length) == 3
    and (.claims | type == "array")
    and (.claims | length) == 6
  ' <<<"$contract_json" >/dev/null; then
    record_failure "top-level schema/bead/verification/count contract mismatch"
  else
    record_pass "top-level schema/bead/verification/count contract"
  fi

  actual_ids="$(jq -r '.claims[].composition_id' <<<"$contract_json" | tr '\n' '|' | sed 's/|$//')"
  expected_ids="$(printf '%s\n' "${expected_composition_ids[@]}" | tr '\n' '|' | sed 's/|$//')"
  if [[ "$actual_ids" != "$expected_ids" ]]; then
    record_failure "composition ids are not in the expected stable order"
  else
    record_pass "composition ids match expected stable order"
  fi

  while IFS= read -r claim; do
    composition_id="$(jq -r '.composition_id' <<<"$claim")"
    proof_posture="$(jq -r '.proof_posture' <<<"$claim")"
    source_kind="$(jq -r '.source_kind' <<<"$claim")"
    source_path="$(jq -r '.source_path' <<<"$claim")"
    start_line="$(jq -r '.source_span.start_line' <<<"$claim")"
    end_line="$(jq -r '.source_span.end_line' <<<"$claim")"
    status_note="$(jq -r '.status_note // ""' <<<"$claim")"

    case "$proof_posture" in
      observed|provisional)
        record_pass "${composition_id}: proof_posture=${proof_posture}"
        ;;
      *)
        record_failure "${composition_id}: unexpected proof_posture=${proof_posture}"
        ;;
    esac

    case "$source_kind" in
      docs_contract|readme_contract|rust_module_doc)
        record_pass "${composition_id}: source_kind=${source_kind}"
        ;;
      *)
        record_failure "${composition_id}: unexpected source_kind=${source_kind}"
        ;;
    esac

    if [[ "$start_line" -le 0 || "$end_line" -lt "$start_line" ]]; then
      record_failure "${composition_id}: invalid source span ${start_line}-${end_line}"
    else
      record_pass "${composition_id}: source span ${start_line}-${end_line}"
    fi

    check_path_exists "$source_path"

    if (( "$(jq '.primary_paths | length' <<<"$claim")" == 0 )); then
      record_failure "${composition_id}: primary_paths must be non-empty"
    fi
    while IFS= read -r rel_path; do
      check_path_exists "$rel_path"
    done < <(jq -r '.primary_paths[]' <<<"$claim")

    if (( "$(jq '.verification_commands | length' <<<"$claim")" == 0 )); then
      record_failure "${composition_id}: verification_commands must be non-empty"
    else
      record_pass "${composition_id}: verification_commands present"
    fi

    if (( "$(jq '.child_substrates | length' <<<"$claim")" == 0 )); then
      record_failure "${composition_id}: child_substrates must be non-empty"
    fi

    if ! jq -e '.child_substrates == (.child_substrates | sort_by(.surface_id))' <<<"$claim" >/dev/null; then
      record_failure "${composition_id}: child_substrates must be sorted by surface_id"
    else
      record_pass "${composition_id}: child_substrates sorted by surface_id"
    fi

    while IFS= read -r child; do
      if [[ -z "$(jq -r '.surface_id // empty' <<<"$child")" ]]; then
        record_failure "${composition_id}: child substrate missing surface_id"
      fi
      if (( "$(jq '.primary_paths | length' <<<"$child")" == 0 )); then
        record_failure "${composition_id}: child substrate missing primary_paths"
      fi
      while IFS= read -r rel_path; do
        check_path_exists "$rel_path"
      done < <(jq -r '.primary_paths[]' <<<"$child")
    done < <(jq -c '.child_substrates[]' <<<"$claim")

    while IFS= read -r fragment; do
      [[ -z "$fragment" ]] && continue
      if ! sed -n "${start_line},${end_line}p" "${root_dir}/${source_path}" | grep -Fq -- "$fragment"; then
        record_failure "${composition_id}: source span missing fragment ${fragment}"
      else
        record_pass "${composition_id}: source span contains fragment ${fragment}"
      fi
    done < <(jq -r '.source_span.must_contain[]' <<<"$claim")

    case "$proof_posture" in
      observed)
        if (( "$(jq '.allowed_provisional_fallbacks | length' <<<"$claim")" != 0 )); then
          record_failure "${composition_id}: observed claims must not list provisional fallbacks"
        else
          record_pass "${composition_id}: observed claim has no provisional fallbacks"
        fi
        ;;
      provisional)
        if (( "$(jq '.allowed_provisional_fallbacks | length' <<<"$claim")" == 0 )); then
          record_failure "${composition_id}: provisional claim must list provisional fallbacks"
        else
          record_pass "${composition_id}: provisional fallbacks present"
        fi
        if [[ -z "$status_note" ]]; then
          record_failure "${composition_id}: provisional claim requires status_note"
        else
          record_pass "${composition_id}: provisional status_note present"
        fi
        while IFS= read -r fallback; do
          if [[ -z "$(jq -r '.surface_id // empty' <<<"$fallback")" ]]; then
            record_failure "${composition_id}: provisional fallback missing surface_id"
          fi
          if [[ -z "$(jq -r '.current_behavior // empty' <<<"$fallback")" ]]; then
            record_failure "${composition_id}: provisional fallback missing current_behavior"
          fi
          if [[ -z "$(jq -r '.blocking_bead // empty' <<<"$fallback")" ]]; then
            record_failure "${composition_id}: provisional fallback missing blocking_bead"
          fi
        done < <(jq -c '.allowed_provisional_fallbacks[]' <<<"$claim")
        ;;
    esac
  done < <(jq -c '.claims[]' <<<"$contract_json")

  if (( validation_failures > 0 )); then
    return 1
  fi
}

run_selftest() {
  if (
    validate_contract <(jq '
    (.claims[]
      | select(.composition_id == "rgc_707_semantic_dark_matter_engine")
      | .allowed_provisional_fallbacks) = []
  ' "$default_contract")
  ) >/dev/null 2>&1; then
    record_failure "selftest expected provisional fallback validation failure"
    return 1
  fi
  record_pass "selftest rejects provisional claim without fallback metadata"
}

mode="${1:-check}"

case "$mode" in
  check)
    validate_contract "$default_contract"
    ;;
  selftest)
    validate_contract "$default_contract"
    run_selftest
    ;;
  *)
    echo "usage: $0 [check|selftest]" >&2
    exit 64
    ;;
esac

if (( validation_failures > 0 )); then
  exit 1
fi
