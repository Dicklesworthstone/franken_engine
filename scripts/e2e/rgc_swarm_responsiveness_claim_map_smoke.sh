#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
default_contract="${root_dir}/docs/rgc_swarm_responsiveness_claim_map_v1.json"

expected_child_ids=(
  "bd-bdrwq.1"
  "bd-bdrwq.2"
  "bd-bdrwq.3"
  "bd-bdrwq.4"
  "bd-bdrwq.5"
  "bd-bdrwq.6"
  "bd-bdrwq.7"
  "bd-bdrwq.8"
  "bd-bdrwq.9"
  "bd-bdrwq.10"
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
    return 0
  fi
  if [[ "$rel_path" == *"<timestamp>"* || "$rel_path" == *"$PWD"* ]]; then
    return 0
  fi
  if [[ ! -e "${root_dir}/${rel_path}" ]]; then
    record_failure "missing referenced path ${rel_path}"
  else
    record_pass "path exists ${rel_path}"
  fi
}

validate_contract() {
  local contract_path="$1"
  local actual actual_mapped child_id claim_status surface_kind cmd_count required_count blocking_count
  local impl_count status_note artifact_root gate_script replay_wrapper

  validation_failures=0

  if [[ ! -f "$contract_path" ]]; then
    record_failure "contract file not found: ${contract_path}"
    return 1
  fi

  if ! jq -e '
    .schema_version == "franken-engine.swarm-responsiveness-claim-map.v1"
    and .bead_id == "bd-bdrwq.11"
    and (.mapped_child_bead_ids | length) == 10
    and (.claims | length) == 10
  ' "$contract_path" >/dev/null; then
    record_failure "top-level schema/bead/count contract mismatch"
  else
    record_pass "top-level schema/bead/count contract"
  fi

  actual="$(
    jq -r '.claims[].child_bead_id' "$contract_path" | sort | tr '\n' ' ' | sed 's/ $//'
  )"
  if [[ "$actual" != "$(printf '%s\n' "${expected_child_ids[@]}" | sort | tr '\n' ' ' | sed 's/ $//')" ]]; then
    record_failure "mapped child bead ids do not exactly match bd-bdrwq.{1..10}"
  else
    record_pass "mapped child bead ids exactly match bd-bdrwq.{1..10}"
  fi

  actual_mapped="$(
    jq -r '.mapped_child_bead_ids[]' "$contract_path" | sort | tr '\n' ' ' | sed 's/ $//'
  )"
  if [[ "$actual_mapped" != "$(printf '%s\n' "${expected_child_ids[@]}" | sort | tr '\n' ' ' | sed 's/ $//')" ]]; then
    record_failure "top-level mapped_child_bead_ids do not exactly match bd-bdrwq.{1..10}"
  else
    record_pass "top-level mapped_child_bead_ids exactly match bd-bdrwq.{1..10}"
  fi

  while IFS= read -r claim; do
    child_id="$(jq -r '.child_bead_id' <<<"$claim")"
    claim_status="$(jq -r '.claim_status' <<<"$claim")"
    surface_kind="$(jq -r '.surface_kind' <<<"$claim")"
    cmd_count="$(jq '.verification_commands | length' <<<"$claim")"
    required_count="$(jq '.required_artifacts | length' <<<"$claim")"
    blocking_count="$(jq '.blocking_beads | length' <<<"$claim")"
    impl_count="$(jq '.implementation_commits | length' <<<"$claim")"
    status_note="$(jq -r '.status_note // ""' <<<"$claim")"
    artifact_root="$(jq -r '.artifact_root // empty' <<<"$claim")"
    gate_script="$(jq -r '.gate_runner.script // empty' <<<"$claim")"
    replay_wrapper="$(jq -r '.gate_runner.replay_wrapper // empty' <<<"$claim")"

    case "$claim_status" in
      published|implemented_pending_validation|blocked)
        record_pass "${child_id}: claim_status=${claim_status}"
        ;;
      *)
        record_failure "${child_id}: unexpected claim_status=${claim_status}"
        ;;
    esac

    case "$surface_kind" in
      source_test_surface|smoke_script_surface|gate_bundle_surface|operator_dashboard_surface)
        record_pass "${child_id}: surface_kind=${surface_kind}"
        ;;
      *)
        record_failure "${child_id}: unexpected surface_kind=${surface_kind}"
        ;;
    esac

    if (( cmd_count == 0 )); then
      record_failure "${child_id}: verification_commands must be non-empty"
    else
      record_pass "${child_id}: verification_commands present"
    fi

    while IFS= read -r rel_path; do
      check_path_exists "$rel_path"
    done < <(jq -r '.primary_paths[]' <<<"$claim")

    check_path_exists "$gate_script"
    check_path_exists "$replay_wrapper"

    case "$claim_status" in
      published)
        if (( blocking_count != 0 )); then
          record_failure "${child_id}: published claims must not declare blocking_beads"
        else
          record_pass "${child_id}: published claim has no blocking_beads"
        fi
        case "$surface_kind" in
          smoke_script_surface|gate_bundle_surface)
            if [[ -z "$artifact_root" ]]; then
              record_failure "${child_id}: bundle/smoke surface requires artifact_root"
            else
              record_pass "${child_id}: artifact_root present"
            fi
            if (( required_count == 0 )); then
              record_failure "${child_id}: bundle/smoke surface requires required_artifacts"
            else
              record_pass "${child_id}: required_artifacts present"
            fi
            ;;
        esac
        ;;
      implemented_pending_validation)
        if (( impl_count == 0 )); then
          record_failure "${child_id}: implemented_pending_validation requires implementation_commits"
        else
          record_pass "${child_id}: implementation_commits present"
        fi
        if [[ -z "$status_note" ]]; then
          record_failure "${child_id}: implemented_pending_validation requires status_note"
        else
          record_pass "${child_id}: status_note present"
        fi
        case "$surface_kind" in
          smoke_script_surface|gate_bundle_surface)
            if [[ -z "$artifact_root" ]]; then
              record_failure "${child_id}: unpublished bundle/smoke surface still requires artifact_root"
            else
              record_pass "${child_id}: unpublished bundle/smoke surface has artifact_root"
            fi
            if (( required_count == 0 )); then
              record_failure "${child_id}: unpublished bundle/smoke surface still requires required_artifacts"
            else
              record_pass "${child_id}: unpublished bundle/smoke surface has required_artifacts"
            fi
            ;;
        esac
        ;;
      blocked)
        if (( blocking_count == 0 )); then
          record_failure "${child_id}: blocked claims require blocking_beads"
        else
          record_pass "${child_id}: blocking_beads present"
        fi
        if [[ -z "$status_note" ]]; then
          record_failure "${child_id}: blocked claims require status_note"
        else
          record_pass "${child_id}: status_note present"
        fi
        ;;
    esac
  done < <(jq -c '.claims[]' "$contract_path")

  if (( validation_failures > 0 )); then
    printf 'SUMMARY: %d validation failure(s)\n' "$validation_failures" >&2
    return 1
  fi

  record_pass "contract validation completed without failures"
}

run_selftest() {
  local contract_path="$1"
  local tmp_dir broken_contract

  printf 'SELFTEST: validating real contract %s\n' "$contract_path"
  validate_contract "$contract_path"

  tmp_dir="$(mktemp -d)"
  broken_contract="${tmp_dir}/broken_claim_map.json"
  jq '
    .claims[0].primary_paths[0] = "docs/DOES_NOT_EXIST_SWARM_CLAIM_MAP.json"
  ' "$contract_path" >"$broken_contract"

  printf 'SELFTEST: validating intentionally broken contract %s\n' "$broken_contract"
  if validate_contract "$broken_contract"; then
    record_failure "broken contract unexpectedly passed"
    rm -rf "$tmp_dir"
    return 1
  fi

  record_pass "broken contract failed closed as expected"
  rm -rf "$tmp_dir"
}

mode="${1:-check}"
contract_path="${2:-$default_contract}"

case "$mode" in
  check)
    validate_contract "$contract_path"
    ;;
  selftest)
    run_selftest "$contract_path"
    ;;
  *)
    echo "usage: $0 [check|selftest] [contract-path]" >&2
    exit 2
    ;;
esac
