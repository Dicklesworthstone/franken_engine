#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract_path="${root_dir}/docs/swarm_execution_queue_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_EXECUTION_QUEUE_CONTRACT.md"
fixture_dir="${root_dir}/scripts/testdata/swarm_execution_queue"

fixtures=(
  "healthy_input.json"
  "stale_owner_input.json"
  "proof_brownout_input.json"
  "blocked_parent_input.json"
)

failures=0

record_pass() {
  printf 'PASS swarm-execution-queue-contract %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-contract %s\n' "$1" >&2
  failures=$((failures + 1))
}

check_path_exists() {
  local relative_path="$1"
  if [[ -z "$relative_path" || "$relative_path" == "null" ]]; then
    record_failure "referenced path is empty"
    return
  fi
  if [[ ! -e "${root_dir}/${relative_path}" ]]; then
    record_failure "missing referenced path ${relative_path}"
  else
    record_pass "referenced path exists ${relative_path}"
  fi
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'automatic reopen is allowed|automatically reopens|runs br update|will run br update|br update .*--status|release_file_reservations|will release reservations|sends Agent Mail automatically|live worker mutation is performed' "$path"; then
    record_failure "${path#"$root_dir"/} contains live-mutation wording"
  else
    record_pass "${path#"$root_dir"/} has advisory-only wording"
  fi
}

check_no_bare_heavy_cargo() {
  local path="$1"
  local command
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$command" != *"rch exec --"* || "$command" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "${path#"$root_dir"/} has bare heavy Cargo command: ${command}"
      fi
    fi
  done < <(jq -r '.. | strings' "$path")
}

validate_contract() {
  local path="$1"
  jq empty "$path"

  if jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-contract.v1"
    and .bead_id == "bd-1wrlq"
    and .parent_bead_id == "bd-g347f"
    and .rust_module == "crates/franken-engine/src/swarm_control_loop.rs"
    and (.output_artifact_contracts | length) == 8
    and (.fixture_examples | length) == 4
    and .mutation_policy.mutates_br == false
    and .mutation_policy.reassigns_beads == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
  ' "$path" >/dev/null; then
    record_pass "top-level contract"
  else
    record_failure "top-level contract mismatch"
  fi

  if jq -e '
    (.required_task_fields | index("first_action") != null)
    and (.required_queue_entry_fields | index("first_action") != null)
    and (.fail_closed_rules | map(test("first_action")) | any)
    and (.fail_closed_rules | map(test("local-rch fallback")) | any)
  ' "$path" >/dev/null; then
    record_pass "fail-closed first-action/local-rch rules"
  else
    record_failure "missing first-action/local-rch fail-closed rules"
  fi

  while IFS= read -r path_ref; do
    check_path_exists "$path_ref"
  done < <(jq -r '.fixture_examples[].path' "$path")

  check_no_bare_heavy_cargo "$path"
}

validate_fixture() {
  local path="$1"
  jq empty "$path"

  if jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-input.v1"
    and (.tasks | type == "array")
    and (.tasks | length) > 0
    and (.expected_output_assertions.top_queue | type == "array")
    and (.expected_output_assertions.conservative_mode | type == "boolean")
  ' "$path" >/dev/null; then
    record_pass "${path#"$root_dir"/} basic shape"
  else
    record_failure "${path#"$root_dir"/} basic shape mismatch"
  fi

  if jq -e '
    all(.tasks[]; (
      (.task_id | length) > 0
      and (.title | length) > 0
      and (.depends_on | type == "array")
      and (.dependents | type == "array")
      and (.open_blocker_count | type == "number")
      and (.owner_freshness.state | length) > 0
      and (.reservation_pressure.active_reservation_count | type == "number")
      and (.proof_transport.local_fallback_detected | type == "boolean")
      and (.scores.impact_millionths | type == "number")
      and (.scores.confidence_millionths | type == "number")
      and (.scores.reuse_millionths | type == "number")
      and (.scores.effort_millionths | type == "number")
      and (.scores.friction_millionths | type == "number")
      and (.fallback_trigger | length) > 0
      and (.first_action | length) > 0
    ))
  ' "$path" >/dev/null; then
    record_pass "${path#"$root_dir"/} task fields"
  else
    record_failure "${path#"$root_dir"/} task field contract mismatch"
  fi

  if jq -e 'any(.tasks[]; .proof_transport.local_fallback_detected == true)' "$path" >/dev/null; then
    record_failure "${path#"$root_dir"/} promotes local-rch fallback"
  else
    record_pass "${path#"$root_dir"/} has no local-rch fallback promotion"
  fi
}

run_check() {
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  grep -q 'SWARM-CTRL-XII' "$docs_path"
  grep -q 'advisory evidence only' "$docs_path"
  validate_contract "$contract_path"
  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$contract_path"

  for fixture in "${fixtures[@]}"; do
    validate_fixture "${fixture_dir}/${fixture}"
  done

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
}

run_selftest() {
  local tmp_parent tmp_root bad_contract bad_fixture bad_doc
  tmp_parent="${SWARM_EXECUTION_QUEUE_CONTRACT_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-execution-queue-contract.XXXXXX")"

  run_check

  bad_contract="${tmp_root}/bad_contract.json"
  jq 'del(.output_artifact_contracts[] | select(.path_key == "artifact_paths.operator_summary_md"))' \
    "$contract_path" >"$bad_contract"
  if jq -e '(.output_artifact_contracts | length) == 8' "$bad_contract" >/dev/null; then
    record_failure "bad contract without operator summary artifact should fail"
  else
    record_pass "bad contract without operator summary artifact fails"
  fi

  bad_fixture="${tmp_root}/bad_fixture.json"
  jq '.tasks[0].first_action = ""' "${fixture_dir}/healthy_input.json" >"$bad_fixture"
  if jq -e 'all(.tasks[]; (.first_action | length) > 0)' "$bad_fixture" >/dev/null; then
    record_failure "bad fixture without first_action should fail"
  else
    record_pass "bad fixture without first_action fails"
  fi

  bad_doc="${tmp_root}/bad_doc.md"
  printf 'This lane automatically reopens beads with br update --status open.\n' >"$bad_doc"
  if grep -Eiq 'automatic reopen is allowed|automatically reopens|br update .*--status' "$bad_doc"; then
    record_pass "bad mutation wording fails"
  else
    record_failure "bad mutation wording should fail"
  fi

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  printf 'swarm_execution_queue_contract_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
