#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
default_contract="${root_dir}/docs/swarm_validation_control_plane_contract_v1.json"

expected_surface_ids=(
  "bead_graph_state"
  "coordination_mail_reservations"
  "focused_proof_cost_gate"
  "focused_proof_runner"
  "module_composition_claim_ledger"
  "proof_artifact_manifest"
  "rch_wrapped_release_gate"
  "reproduce_entrypoint"
)

expected_signal_ids=(
  "active_cargo_rustc_count"
  "disk_available_bytes"
  "file_reservation_overlap"
  "git_dirty_state"
  "memory_available_bytes"
  "rch_local_fallback"
  "rch_status"
  "target_dir_writable"
)

expected_decisions="admit|admit_narrow|defer|fail_closed"
validation_failures=0

record_failure() {
  printf 'FAIL: %s\n' "$1" >&2
  validation_failures=$((validation_failures + 1))
}

record_pass() {
  printf 'PASS: %s\n' "$1"
}

join_expected() {
  printf '%s\n' "$@" | tr '\n' '|' | sed 's/|$//'
}

check_path_exists() {
  local path="$1"

  if [[ -z "$path" || "$path" == "null" ]]; then
    record_failure "referenced path is empty"
    return
  fi

  if [[ "$path" = /* ]]; then
    if [[ ! -e "$path" ]]; then
      record_failure "missing absolute referenced path ${path}"
    else
      record_pass "absolute path exists ${path}"
    fi
    return
  fi

  if [[ ! -e "${root_dir}/${path}" ]]; then
    record_failure "missing repo referenced path ${path}"
  else
    record_pass "repo path exists ${path}"
  fi
}

check_heavy_cargo_command_shape() {
  local contract_path="$1"
  local command

  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$command" != *"rch exec -- env"* || "$command" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "heavy cargo command is not rch-target-dir wrapped: ${command}"
      else
        record_pass "heavy cargo command is rch-target-dir wrapped"
      fi
    fi
  done < <(jq -r '.. | strings' "$contract_path")
}

validate_top_level() {
  local contract_path="$1"

  if ! jq -e '
    .schema_version == "franken-engine.swarm-validation-control-plane-contract.v1"
    and .bead_id == "bd-vcloy"
    and .policy_id == "policy-swarm-validation-control-plane-v1"
    and (.verification_commands | length) == 5
    and (.workload_surfaces | length) == 8
    and (.capacity_signals | length) == 8
    and (.downstream_contracts | length) == 6
    and (.sibling_reuse_policy | length) == 3
    and (.output_artifact_contracts | length) == 3
  ' "$contract_path" >/dev/null; then
    record_failure "top-level schema/count contract mismatch"
  else
    record_pass "top-level schema/count contract"
  fi

  if ! jq -e '
    .safe_mode_semantics.default_decision == "fail_closed"
    and .safe_mode_semantics.allowed_decisions == ["admit", "admit_narrow", "defer", "fail_closed"]
    and .safe_mode_semantics.missing_required_signal == "fail_closed"
    and .safe_mode_semantics.operator_note_required_for_override == true
  ' "$contract_path" >/dev/null; then
    record_failure "safe-mode semantics are not fail-closed"
  else
    record_pass "safe-mode semantics are fail-closed"
  fi
}

validate_order_and_uniqueness() {
  local contract_path="$1"
  local actual expected

  actual="$(jq -r '.workload_surfaces[].surface_id' "$contract_path" | tr '\n' '|' | sed 's/|$//')"
  expected="$(join_expected "${expected_surface_ids[@]}")"
  if [[ "$actual" != "$expected" ]]; then
    record_failure "workload surfaces are not in expected stable order"
  else
    record_pass "workload surfaces match expected stable order"
  fi

  actual="$(jq -r '.capacity_signals[].signal_id' "$contract_path" | tr '\n' '|' | sed 's/|$//')"
  expected="$(join_expected "${expected_signal_ids[@]}")"
  if [[ "$actual" != "$expected" ]]; then
    record_failure "capacity signals are not in expected stable order"
  else
    record_pass "capacity signals match expected stable order"
  fi

  if ! jq -e '
    [.workload_surfaces[].surface_id] as $ids
    | ($ids | length) == ($ids | unique | length)
  ' "$contract_path" >/dev/null; then
    record_failure "duplicate workload surface ids"
  else
    record_pass "workload surface ids are unique"
  fi

  if ! jq -e '
    [.capacity_signals[].signal_id] as $ids
    | ($ids | length) == ($ids | unique | length)
  ' "$contract_path" >/dev/null; then
    record_failure "duplicate capacity signal ids"
  else
    record_pass "capacity signal ids are unique"
  fi
}

validate_surfaces() {
  local contract_path="$1"
  local surface surface_id source_kind

  while IFS= read -r surface; do
    surface_id="$(jq -r '.surface_id' <<<"$surface")"
    source_kind="$(jq -r '.source_kind' <<<"$surface")"

    case "$source_kind" in
      agent_mail|beads|json_contract|rust_contract|shell_gate)
        record_pass "${surface_id}: source_kind=${source_kind}"
        ;;
      *)
        record_failure "${surface_id}: unexpected source_kind=${source_kind}"
        ;;
    esac

    if ! jq -e '
      (.role | length) > 0
      and (.repo_paths | type == "array")
      and (.repo_paths | length) > 0
      and (.read_commands | type == "array")
      and (.read_commands | length) > 0
      and (.artifacts_emitted | type == "array")
      and (.artifacts_emitted | length) > 0
      and (.downstream_beads | type == "array")
      and (.downstream_beads | length) > 0
    ' <<<"$surface" >/dev/null; then
      record_failure "${surface_id}: missing role/path/command/artifact/downstream fields"
    else
      record_pass "${surface_id}: required fields present"
    fi

    while IFS= read -r path; do
      check_path_exists "$path"
    done < <(jq -r '.repo_paths[]' <<<"$surface")
  done < <(jq -c '.workload_surfaces[]' "$contract_path")
}

validate_capacity_signals() {
  local contract_path="$1"
  local signal signal_id required missing degraded

  while IFS= read -r signal; do
    signal_id="$(jq -r '.signal_id' <<<"$signal")"
    required="$(jq -r '.required_for_decision' <<<"$signal")"
    missing="$(jq -r '.missing_evidence_decision' <<<"$signal")"
    degraded="$(jq -r '.degraded_decision' <<<"$signal")"

    if ! jq -e '
      (.source_kind | length) > 0
      and (.capture_command | length) > 0
      and (.notes | length) > 0
    ' <<<"$signal" >/dev/null; then
      record_failure "${signal_id}: missing source/capture/notes fields"
    else
      record_pass "${signal_id}: required fields present"
    fi

    if [[ ! "$missing" =~ ^(${expected_decisions})$ ]]; then
      record_failure "${signal_id}: invalid missing_evidence_decision=${missing}"
    elif [[ "$required" == "true" && "$missing" != "fail_closed" ]]; then
      record_failure "${signal_id}: required signal must fail_closed when missing"
    else
      record_pass "${signal_id}: missing evidence decision=${missing}"
    fi

    if [[ ! "$degraded" =~ ^(${expected_decisions})$ ]]; then
      record_failure "${signal_id}: invalid degraded_decision=${degraded}"
    else
      record_pass "${signal_id}: degraded decision=${degraded}"
    fi
  done < <(jq -c '.capacity_signals[]' "$contract_path")
}

validate_downstream_contracts() {
  local contract_path="$1"

  if ! jq -e '
    all(.downstream_contracts[]; (.bead_id | test("^bd-")) and (.requires_surfaces | length > 0) and (.requires_signals | length > 0))
    and ([.workload_surfaces[].surface_id] as $surfaces
      | all(.downstream_contracts[].requires_surfaces[]; $surfaces | index(.) != null))
    and ([.capacity_signals[].signal_id] as $signals
      | all(.downstream_contracts[].requires_signals[]; $signals | index(.) != null))
  ' "$contract_path" >/dev/null; then
    record_failure "downstream contracts reference unknown surfaces or signals"
  else
    record_pass "downstream contracts reference known surfaces and signals"
  fi
}

validate_sibling_reuse_policy() {
  local contract_path="$1"
  local sibling repo_id path

  if ! jq -e '
    [.sibling_reuse_policy[].repo_id] == ["frankensqlite", "frankentui", "sqlmodel_rust"]
    and all(.sibling_reuse_policy[]; .local_reimplementation_allowed == false)
  ' "$contract_path" >/dev/null; then
    record_failure "sibling reuse policy drifted"
  else
    record_pass "sibling reuse policy keeps canonical repo order"
  fi

  while IFS= read -r sibling; do
    repo_id="$(jq -r '.repo_id' <<<"$sibling")"
    path="$(jq -r '.declared_path' <<<"$sibling")"
    check_path_exists "$path"
    record_pass "${repo_id}: sibling reuse path checked"
  done < <(jq -c '.sibling_reuse_policy[]' "$contract_path")
}

validate_contract() {
  local contract_path="$1"

  validation_failures=0

  if [[ ! -e "$contract_path" ]]; then
    record_failure "contract file not found: ${contract_path}"
    return 1
  fi

  if ! command -v jq >/dev/null 2>&1; then
    record_failure "jq is required"
    return 1
  fi

  if ! jq empty "$contract_path" >/dev/null; then
    record_failure "contract is not valid JSON: ${contract_path}"
    return 1
  fi

  validate_top_level "$contract_path"
  validate_order_and_uniqueness "$contract_path"
  validate_surfaces "$contract_path"
  validate_capacity_signals "$contract_path"
  validate_downstream_contracts "$contract_path"
  validate_sibling_reuse_policy "$contract_path"
  check_heavy_cargo_command_shape "$contract_path"

  if (( validation_failures > 0 )); then
    return 1
  fi
}

run_selftest() {
  if (
    validate_contract <(jq '
      .capacity_signals |= map(select(.signal_id != "target_dir_writable"))
    ' "$default_contract")
  ) >/dev/null 2>&1; then
    record_failure "selftest expected missing required capacity signal failure"
    return 1
  fi
  record_pass "selftest rejects missing required capacity signal"

  if (
    validate_contract <(jq '
      (.capacity_signals[] | select(.signal_id == "rch_local_fallback") | .missing_evidence_decision) = "admit"
    ' "$default_contract")
  ) >/dev/null 2>&1; then
    record_failure "selftest expected unsafe rch fallback decision failure"
    return 1
  fi
  record_pass "selftest rejects unsafe rch fallback decision"

  if (
    validate_contract <(jq '
      .verification_commands += ["cargo test -p frankenengine-engine --lib"]
    ' "$default_contract")
  ) >/dev/null 2>&1; then
    record_failure "selftest expected bare heavy cargo command failure"
    return 1
  fi
  record_pass "selftest rejects bare heavy cargo command"
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
