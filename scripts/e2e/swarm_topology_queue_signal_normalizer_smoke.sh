#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/swarm_topology_queue_signal_normalizer.sh"
docs_path="${root_dir}/docs/SWARM_TOPOLOGY_QUEUE_SIGNAL_NORMALIZER.md"
contract_path="${root_dir}/docs/swarm_topology_queue_signal_input_contract_v1.json"
fixture_bundle_path="${root_dir}/scripts/testdata/swarm_topology_queue_signal/queue_signal_fixtures.json"
golden_dir="${SWARM_TOPOLOGY_QUEUE_SIGNAL_NORMALIZER_GOLDEN_DIR:-${root_dir}/scripts/testdata/goldens}"
failures=0

record_pass() {
  printf 'PASS swarm-topology-queue-signal-normalizer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-topology-queue-signal-normalizer %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_topology_queue_signal_normalizer_smoke.sh [check|selftest]
EOF
}

extract_fixture_input() {
  local scenario="$1"
  local input_id="$2"
  local output_path="$3"
  local is_null
  is_null="$(jq -r --arg scenario "$scenario" --arg input_id "$input_id" '
    .scenarios[] | select(.scenario_id == $scenario) | (.inputs[$input_id] == null)
  ' "$fixture_bundle_path")"
  if [[ "$is_null" == "true" ]]; then
    return 1
  fi
  jq --arg scenario "$scenario" --arg input_id "$input_id" '
    .scenarios[] | select(.scenario_id == $scenario) | .inputs[$input_id]
  ' "$fixture_bundle_path" >"$output_path"
}

materialize_fixture_dir() {
  local scenario="$1"
  local dir="$2"
  mkdir -p "$dir"
  extract_fixture_input "$scenario" "execution_queue_input_json" "${dir}/execution_queue_input.json" || return 1
  extract_fixture_input "$scenario" "topology_placement_input_json" "${dir}/topology_placement_input.json" || return 1
  extract_fixture_input "$scenario" "rehabilitation_ledger_json" "${dir}/rehabilitation_ledger.json" || return 1
  extract_fixture_input "$scenario" "placement_adoption_history_json" "${dir}/placement_adoption_history.json" || true
  extract_fixture_input "$scenario" "operator_status_snapshot_json" "${dir}/operator_status_snapshot.json" || true
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'mutates remote workers|pins workers automatically|changes live queue policy automatically|updates beads automatically|releases reservations automatically|sends Agent Mail automatically|runs Cargo automatically|runs RCH automatically' "$path"; then
    record_failure "${path#"$root_dir"/} contains forbidden mutation wording"
  fi
}

check_no_bare_heavy_cargo() {
  local path="$1"
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$command" != *"rch exec --"* || "$command" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "${path#"$root_dir"/} has bare heavy Cargo command: ${command}"
      fi
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,240p' "$path")
}

golden_case_names() {
  jq -r '.scenarios[].scenario_id' "$fixture_bundle_path"
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-topology-queue-signal-normalizer-contract.v1"
    and .bead_id == "bd-t58g5"
    and .parent_bead_id == "bd-2pn2x"
    and (.depends_on | index("bd-f3cmp") != null)
    and (.depends_on | index("bd-zp0m5") != null)
    and .script == "scripts/swarm_topology_queue_signal_normalizer.sh"
    and .smoke_script == "scripts/e2e/swarm_topology_queue_signal_normalizer_smoke.sh"
    and .docs == "docs/SWARM_TOPOLOGY_QUEUE_SIGNAL_NORMALIZER.md"
    and .fixture_bundle == "scripts/testdata/swarm_topology_queue_signal/queue_signal_fixtures.json"
    and .input_schema_version == "franken-engine.swarm-topology-queue-signal-input.v1"
    and .source_schema_version == "franken-engine.swarm-topology-queue-signal-sources.v1"
    and (.required_inputs | length == 3)
    and (.optional_inputs | length == 2)
    and (.normalized_input_fields | index("queue_signal_hints") != null)
    and (.normalized_input_fields | index("rehabilitation_context") != null)
    and (.truth_states | index("contaminated") != null)
    and (.fail_closed_rules | map(test("local fallback contamination"; "i")) | any)
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and (.selftest_scenarios | index("drain_exclusion") != null)
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-topology-queue-signal-normalizer-fixtures.v1"
    and (.scenarios | length) == 5
    and any(.scenarios[]; .scenario_id == "healthy_hot_cache" and .expected_rank_bias_mode == "prefer_hot_cache_locality")
    and any(.scenarios[]; .scenario_id == "blocked_contradictory_locality" and .expected_exit_code == 75)
    and any(.scenarios[]; .scenario_id == "contaminated_local_fallback" and .expected_exit_code == 42)
    and any(.scenarios[]; .scenario_id == "drain_exclusion" and (.expected_excluded_worker_ids | index("rch-e") != null))
  ' "$fixture_bundle_path" >/dev/null
}

canonicalize_signal_input() {
  local signal_path="$1"
  local tmp_root="$2"

  jq --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "string" then
        gsub($tmp_root; "[SMOKE_ROOT]")
        | gsub("/tmp/rch_target_"; "[RCH_TARGET]/")
        | gsub("/tmp/[A-Za-z0-9._-]+"; "[TMP_PATH]")
        | gsub("/data/tmp/[A-Za-z0-9._-]+"; "[DATA_TMP_PATH]")
      elif type == "array" then
        map(scrub)
      elif type == "object" then
        with_entries(.value |= scrub)
      else
        .
      end;
    scrub
    | .queue_signal_input_id = "[QUEUE_SIGNAL_INPUT_ID]"
  ' "$signal_path"
}

assert_case_golden() {
  local scenario="$1"
  local signal_path="$2"
  local tmp_root="$3"
  local golden_path="${golden_dir}/swarm_topology_queue_signal_normalizer_${scenario}.golden"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    mkdir -p "$golden_dir"
    canonicalize_signal_input "$signal_path" "$tmp_root" >"$golden_path"
    return 0
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "${scenario} missing golden"
    return 1
  fi

  if ! diff -u "$golden_path" <(canonicalize_signal_input "$signal_path" "$tmp_root"); then
    record_failure "${scenario} golden drift"
    return 1
  fi
}

goldens_shape_ok() {
  local scenario golden_path

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    return 0
  fi

  while IFS= read -r scenario; do
    golden_path="${golden_dir}/swarm_topology_queue_signal_normalizer_${scenario}.golden"
    if [[ ! -f "$golden_path" ]]; then
      record_failure "${scenario} missing checked-in golden"
      continue
    fi
    jq empty "$golden_path" >/dev/null || record_failure "${scenario} invalid golden json"
  done < <(golden_case_names)
}

run_case() {
  local scenario="$1"
  local input_dir="$2"
  local output_dir="$3"
  local tmp_root="$4"
  local expected_decision expected_truth_state expected_exit_code expected_rank_bias_mode
  expected_decision="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_decision' "$fixture_bundle_path")"
  expected_truth_state="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_truth_state' "$fixture_bundle_path")"
  expected_exit_code="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_exit_code' "$fixture_bundle_path")"
  expected_rank_bias_mode="$(jq -r --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_rank_bias_mode' "$fixture_bundle_path")"
  mkdir -p "$output_dir"
  local args=(
    --source-revision fixture-rev
    --execution-queue-input-json "${input_dir}/execution_queue_input.json"
    --topology-placement-input-json "${input_dir}/topology_placement_input.json"
    --rehabilitation-ledger-json "${input_dir}/rehabilitation_ledger.json"
    --output-dir "$output_dir"
  )
  [[ -f "${input_dir}/placement_adoption_history.json" ]] && args+=(--placement-adoption-history-json "${input_dir}/placement_adoption_history.json")
  [[ -f "${input_dir}/operator_status_snapshot.json" ]] && args+=(--operator-status-snapshot-json "${input_dir}/operator_status_snapshot.json")

  local code=0
  set +e
  bash "$normalizer" "${args[@]}" >/dev/null
  code=$?
  set -e
  if [[ "$code" -ne "$expected_exit_code" ]]; then
    record_failure "${scenario} expected exit ${expected_exit_code}, got ${code}"
    return 1
  fi
  jq -e --arg decision "$expected_decision" --arg truth_state "$expected_truth_state" --arg rank_bias_mode "$expected_rank_bias_mode" '
    .decision == $decision and .truth_state == $truth_state and .queue_signal_hints.rank_bias_mode == $rank_bias_mode
  ' "${output_dir}/swarm_topology_queue_signal_input.json" >/dev/null || {
    record_failure "${scenario} decision, truth state, or rank bias mismatch"
    return 1
  }
  assert_case_golden "$scenario" "${output_dir}/swarm_topology_queue_signal_input.json" "$tmp_root" || return 1
}

run_check() {
  bash -n "$normalizer"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path" "$fixture_bundle_path"
  if contract_shape_ok; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi
  if fixtures_shape_ok; then
    record_pass "fixture bundle shape"
  else
    record_failure "fixture bundle shape mismatch"
  fi
  goldens_shape_ok

  grep -Fq 'advisory-only' "$docs_path" || record_failure "docs must say advisory-only"
  grep -Fq 'local fallback contamination fails closed' "$docs_path" || record_failure "docs must mention local fallback contamination"
  grep -Fq 'drain_recommended' "$docs_path" || record_failure "docs must mention drain exclusion proof"

  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$contract_path"
}

run_selftest() {
  local tmp_root scenario input_dir output_dir
  tmp_root="${TMPDIR:-/tmp}/swarm-topology-queue-signal-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$tmp_root"
  while IFS= read -r scenario; do
    input_dir="${tmp_root}/${scenario}/in"
    output_dir="${tmp_root}/${scenario}/out"
    materialize_fixture_dir "$scenario" "$input_dir" || {
      record_failure "could not materialize fixture ${scenario}"
      continue
    }
    run_case "$scenario" "$input_dir" "$output_dir" "$tmp_root" || continue

    jq -e \
      --argjson expected_usable "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_usable_preferred_worker_ids' "$fixture_bundle_path")" \
      --argjson expected_excluded "$(jq -c --arg scenario "$scenario" '.scenarios[] | select(.scenario_id == $scenario) | .expected_excluded_worker_ids' "$fixture_bundle_path")" \
      '.queue_signal_hints.usable_preferred_worker_ids == $expected_usable and .rehabilitation_context.excluded_worker_ids == $expected_excluded' \
      "${output_dir}/swarm_topology_queue_signal_input.json" >/dev/null || {
        record_failure "${scenario} usable/excluded worker sets mismatch"
        continue
      }
    record_pass "selftest ${scenario}"
  done < <(jq -r '.scenarios[].scenario_id' "$fixture_bundle_path")
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest
    fi
    ;;
  -h|--help)
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
