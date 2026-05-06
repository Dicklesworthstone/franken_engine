#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ledger_script="${root_dir}/scripts/swarm_rch_stall_rehabilitation_ledger.sh"
docs_path="${root_dir}/docs/SWARM_RCH_STALL_REHABILITATION_LEDGER.md"
contract_path="${root_dir}/docs/swarm_rch_stall_rehabilitation_ledger_contract_v1.json"
fixture_bundle_path="${root_dir}/scripts/testdata/swarm_rch_stall_rehabilitation/rehab_fixtures.json"
failures=0

record_pass() {
  printf 'PASS swarm-rch-stall-rehabilitation-ledger %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-rch-stall-rehabilitation-ledger %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_rch_stall_rehabilitation_ledger_smoke.sh [check|selftest]
EOF
}

write_case_inputs() {
  local case_json="$1"
  local case_dir="$2"
  mkdir -p "$case_dir"
  jq '.inputs.swarm_ops_state_snapshot_json' <<<"$case_json" >"${case_dir}/swarm_ops_state_snapshot.json"
  jq '.inputs.worker_status_json' <<<"$case_json" >"${case_dir}/worker_status.json"
  jq '.inputs.stall_observations_json' <<<"$case_json" >"${case_dir}/stall_observations.json"
  jq '.inputs.worker_capabilities_json' <<<"$case_json" >"${case_dir}/worker_capabilities.json"
  jq '.inputs.operator_actions_json' <<<"$case_json" >"${case_dir}/operator_actions.json"
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'executes rch workers drain|executes rch workers enable|executes rch workers probe|mutates remote workers|releases reservations automatically|sends Agent Mail automatically|updates beads automatically' "$path"; then
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

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-rch-stall-rehabilitation-ledger-contract.v1"
    and .bead_id == "bd-7ayfz"
    and (.depends_on | index("bd-eozx0") != null)
    and (.depends_on | index("bd-lfwy6") != null)
    and .script == "scripts/swarm_rch_stall_rehabilitation_ledger.sh"
    and .smoke_script == "scripts/e2e/swarm_rch_stall_rehabilitation_ledger_smoke.sh"
    and .docs == "docs/SWARM_RCH_STALL_REHABILITATION_LEDGER.md"
    and .fixture_bundle == "scripts/testdata/swarm_rch_stall_rehabilitation/rehab_fixtures.json"
    and (.worker_classifications | index("healthy") != null)
    and (.worker_classifications | index("watch") != null)
    and (.worker_classifications | index("probe_required") != null)
    and (.worker_classifications | index("drain_recommended") != null)
    and (.worker_classifications | index("drained") != null)
    and (.worker_classifications | index("rehab_candidate") != null)
    and (.required_receipt_fields | index("operator_commands") != null)
    and (.operator_command_contract | index("rch workers drain -y WORKER") != null)
    and (.classification_rules | map(test("repeated remote transport stalls"; "i")) | any)
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-rch-stall-rehabilitation-fixtures.v1"
    and (.cases | length) == 7
    and any(.cases[]; .case_id == "fresh_progress" and .expected_classification == "healthy")
    and any(.cases[]; .case_id == "stale_progress_fresh_heartbeat" and .expected_classification == "drain_recommended")
    and any(.cases[]; .case_id == "telemetry_gap" and .expected_classification == "probe_required")
    and any(.cases[]; .case_id == "successful_rehab" and .expected_classification == "rehab_candidate")
    and any(.cases[]; .case_id == "drained_worker" and .expected_classification == "drained")
    and any(.cases[]; .case_id == "local_fallback_contaminated" and .expected_classification == "probe_required")
  ' "$fixture_bundle_path" >/dev/null
}

run_case() {
  local case_json="$1"
  local root="$2"
  local case_id expected_decision expected_classification expected_worker_id expected_reason_code
  local case_dir output_dir expected_cmds_json

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  expected_decision="$(jq -r '.expected_decision' <<<"$case_json")"
  expected_classification="$(jq -r '.expected_classification' <<<"$case_json")"
  expected_worker_id="$(jq -r '.expected_worker_id' <<<"$case_json")"
  expected_reason_code="$(jq -r '.expected_reason_code' <<<"$case_json")"
  expected_cmds_json="$(jq -c '.expected_command_contains' <<<"$case_json")"
  case_dir="${root}/${case_id}"
  output_dir="${case_dir}/out"

  write_case_inputs "$case_json" "$case_dir"

  bash "$ledger_script" \
    --source-revision fixture-revision \
    --output-dir "$output_dir" \
    --swarm-ops-state-snapshot-json "${case_dir}/swarm_ops_state_snapshot.json" \
    --worker-status-json "${case_dir}/worker_status.json" \
    --stall-observations-json "${case_dir}/stall_observations.json" \
    --worker-capabilities-json "${case_dir}/worker_capabilities.json" \
    --operator-actions-json "${case_dir}/operator_actions.json" >/dev/null

  jq -e --arg expected_decision "$expected_decision" '
    .schema_version == "franken-engine.swarm-rch-stall-rehabilitation-ledger.v1"
    and .decision == $expected_decision
  ' "${output_dir}/swarm_rch_stall_rehabilitation_ledger.json" >/dev/null \
    || record_failure "${case_id} ledger decision mismatch"

  jq -e \
    --arg worker_id "$expected_worker_id" \
    --arg classification "$expected_classification" \
    --arg reason_code "$expected_reason_code" \
    --argjson expected_cmds "$expected_cmds_json" '
      (.workers[] | select(.worker_id == $worker_id)) as $worker
      | $worker.classification == $classification
      and ($worker.reason_codes | index($reason_code) != null)
      and all($expected_cmds[]; ($worker.operator_commands | index(.) != null))
    ' "${output_dir}/swarm_rch_stall_rehabilitation_ledger.json" >/dev/null \
    || record_failure "${case_id} worker classification or commands mismatch"

  jq -e '
    .schema_version == "franken-engine.swarm-rch-stall-rehabilitation-receipts.v1"
    and (.receipts | length) >= 1
  ' "${output_dir}/swarm_rch_stall_rehabilitation_receipts.json" >/dev/null \
    || record_failure "${case_id} receipts output mismatch"
}

run_check() {
  bash -n "$ledger_script"
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
  grep -Fq 'advisory-only' "$docs_path" || record_failure "docs must say advisory-only"
  grep -Fq 'rch workers drain -y WORKER' "$docs_path" || record_failure "docs must mention exact drain receipt"
  grep -Fq 'local fallback contamination' "$docs_path" || record_failure "docs must mention local fallback contamination"
  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$contract_path"
}

run_selftest() {
  local tmp_root
  tmp_root="${TMPDIR:-/tmp}/swarm-rch-stall-rehabilitation-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$tmp_root"
  while IFS= read -r case_json; do
    run_case "$case_json" "$tmp_root"
  done < <(jq -c '.cases[]' "$fixture_bundle_path")

  if jq -e '
    any(.workers[]?; .classification == "drain_recommended" and (.operator_commands | index("rch workers drain -y rch-b") != null))
  ' "${tmp_root}/stale_progress_fresh_heartbeat/out/swarm_rch_stall_rehabilitation_ledger.json" >/dev/null; then
    record_pass "selftest repeated stalls recommend drain before retry"
  else
    record_failure "selftest repeated stalls failed to recommend drain before retry"
  fi

  printf 'swarm_rch_stall_rehabilitation_smoke_artifacts=%s\n' "$tmp_root"
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
