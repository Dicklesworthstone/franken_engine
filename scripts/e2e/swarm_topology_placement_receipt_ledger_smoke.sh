#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ledger_script="${root_dir}/scripts/swarm_topology_placement_receipt_ledger.sh"
fixtures_path="${SWARM_TOPOLOGY_PLACEMENT_RECEIPT_LEDGER_FIXTURES:-${root_dir}/scripts/testdata/swarm_topology_placement_receipt_ledger/cases.json}"
mode="${1:-check}"
output_dir="${2:-${SWARM_TOPOLOGY_PLACEMENT_RECEIPT_LEDGER_OUTPUT_DIR:-}}"
failures=0

record_pass() {
  printf 'PASS swarm-topology-placement-receipt-ledger %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-topology-placement-receipt-ledger %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_topology_placement_receipt_ledger_smoke.sh [check|run|selftest] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-topology-placement-receipt-ledger-fixtures.v1"
    and (.cases | length == 5)
    and any(.cases[]; .case_id == "healthy_adopted_hot_cache" and .expected.adoption_status == "adopted")
    and any(.cases[]; .case_id == "drifted_worker" and .expected.required_reason_code == "worker_drift")
    and any(.cases[]; .case_id == "expired_receipt" and .expected.required_reason_code == "receipt_expired")
    and any(.cases[]; .case_id == "blocked_plan" and .expected.decision == "blocked")
    and any(.cases[]; .case_id == "cache_cold_adopted_no_reuse" and .expected.required_reason_code == "cache_cold_no_reuse_claim")
    and all(.cases[]; .placement_plan.schema_version == "franken-engine.swarm-topology-placement-plan.v1")
  ' "$fixtures_path" >/dev/null
}

check_no_live_mutation_claims() {
  local path="$1"
  if grep -Eiq 'pins workers automatically|rebinds hosts automatically|updates beads automatically|reassigns beads automatically|changes live queue policy automatically|enforces placement automatically' "$path"; then
    record_failure "${path#"$root_dir"/} contains forbidden live-mutation wording"
  fi
}

check_no_bare_heavy_commands() {
  local path="$1"
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$command" != *"rch exec --"* || "$command" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "${path#"$root_dir"/} has bare heavy Cargo command: ${command}"
      fi
    fi
    if [[ "$command" =~ (^|[[:space:]])rch[[:space:]]+exec([[:space:]]|$) ]]; then
      record_failure "${path#"$root_dir"/} executes RCH instead of emitting advisory evidence: ${command}"
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,260p' "$path")
}

run_case() {
  local case_json="$1"
  local root="$2"
  local case_id case_dir plan observation expected receipt ledger events code expected_code args=()

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${root}/${case_id}"
  mkdir -p "$case_dir"
  plan="${case_dir}/swarm_topology_placement_plan.json"
  observation="${case_dir}/adoption_observation.json"
  expected="${case_dir}/expected.json"
  jq '.placement_plan' <<<"$case_json" >"$plan"
  jq '.expected' <<<"$case_json" >"$expected"
  expected_code="$(jq -r '.expected_exit_code' "$expected")"
  args+=(--placement-plan-json "$plan")
  if [[ "$(jq -r '.adoption_observation == null' <<<"$case_json")" != "true" ]]; then
    jq '.adoption_observation' <<<"$case_json" >"$observation"
    args+=(--adoption-observation-json "$observation")
  fi

  set +e
  "$ledger_script" "${args[@]}" \
    --reference-time "$(jq -r '.reference_time' "$fixtures_path")" \
    --ttl-seconds "$(jq -r '.ttl_seconds' "$fixtures_path")" \
    --source-revision fixture-revision \
    --output-dir "${case_dir}/out" >/dev/null
  code=$?
  set -e

  if [[ "$code" -ne "$expected_code" ]]; then
    record_failure "${case_id} expected exit ${expected_code}, got ${code}"
    return
  fi

  receipt="${case_dir}/out/swarm_topology_placement_receipt.json"
  ledger="${case_dir}/out/swarm_topology_placement_evidence_ledger.json"
  events="${case_dir}/out/events.jsonl"
  if [[ ! -f "$receipt" || ! -f "$ledger" ]]; then
    record_failure "${case_id} missing receipt or ledger artifact"
    return
  fi

  jq -e --slurpfile expected "$expected" '
    .schema_version == "franken-engine.swarm-topology-placement-receipt.v1"
    and .decision == $expected[0].decision
    and .adoption_status == $expected[0].adoption_status
    and .validity_window.ttl_seconds == $expected[0].ttl_seconds
    and (.recommended_placement_targets | type == "array")
    and (.adoption_drift_reason_codes | index($expected[0].required_reason_code) != null)
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.pins_workers_automatically == false
    and .mutation_policy.rebinds_hosts_automatically == false
    and .mutation_policy.enforces_placement_automatically == false
  ' "$receipt" >/dev/null || {
    record_failure "${case_id} receipt shape mismatch"
    return
  }

  jq -e --slurpfile receipt "$receipt" '
    .schema_version == "franken-engine.swarm-topology-placement-evidence-ledger.v1"
    and (.receipts | length == 1)
    and (.adoption_history | length == 1)
    and .receipts[0].receipt_id == $receipt[0].receipt_id
    and .adoption_history[0].drift_reason_codes == $receipt[0].adoption_drift_reason_codes
    and .mutation_policy.advisory_only == true
  ' "$ledger" >/dev/null || {
    record_failure "${case_id} ledger shape mismatch"
    return
  }

  case "$case_id" in
    healthy_adopted_hot_cache)
      jq -e '
        (.adoption_drift_reason_codes | index("adopted_recommended_target") != null)
        and (.adoption_drift_reason_codes | index("cache_reuse_confirmed") != null)
        and .adoption_observation.cache_reuse_observed == true
      ' "$receipt" >/dev/null || record_failure "healthy case must confirm hot-cache adoption"
      ;;
    drifted_worker)
      jq -e '
        (.adoption_drift_reason_codes | index("worker_drift") != null)
        and .adoption_status == "drifted"
        and .decision == "degraded"
      ' "$receipt" >/dev/null || record_failure "drifted worker case must degrade with worker_drift"
      ;;
    expired_receipt)
      jq -e '
        (.adoption_drift_reason_codes | index("receipt_expired") != null)
        and .validity_window.expired_at_observation == true
        and .adoption_status == "expired"
      ' "$receipt" >/dev/null || record_failure "expired case must record expired validity"
      ;;
    blocked_plan)
      jq -e '
        (.adoption_drift_reason_codes | index("blocked_plan_not_adoptable") != null)
        and (.recommended_placement_targets | length) == 0
        and .adoption_status == "not_applicable"
      ' "$receipt" >/dev/null || record_failure "blocked plan must not produce adoption target"
      ;;
    cache_cold_adopted_no_reuse)
      jq -e '
        (.adoption_drift_reason_codes | index("cache_cold_no_reuse_claim") != null)
        and (.adoption_drift_reason_codes | index("cache_reuse_missing") == null)
        and .adoption_observation.cache_reuse_observed == false
      ' "$receipt" >/dev/null || record_failure "cold-cache case must not overclaim cache reuse"
      ;;
  esac

  jq -s '
    length >= 2
    and all(.[]; has("schema_version") and has("component") and has("event") and has("outcome") and has("evidence_path"))
    and any(.[]; .component == "swarm_topology_placement_receipt_ledger" and .event == "receipt.emitted")
  ' "$events" >/dev/null || record_failure "${case_id} events missing receipt emission"
  test -s "${case_dir}/out/commands.txt" || record_failure "${case_id} commands receipt missing"
  test -s "${case_dir}/out/report.md" || record_failure "${case_id} report missing"

  record_pass "${case_id} ledger"
}

run_check() {
  bash -n "$ledger_script"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$fixtures_path"

  if fixtures_shape_ok; then
    record_pass "fixture shape"
  else
    record_failure "fixture shape mismatch"
  fi

  grep -Fq 'advisory' "$ledger_script" || record_failure "ledger script must describe advisory scope"
  grep -Fq 'swarm_topology_placement_receipt.json' "$ledger_script" || record_failure "ledger script must emit receipt artifact"
  grep -Fq 'swarm_topology_placement_evidence_ledger.json' "$ledger_script" || record_failure "ledger script must emit evidence ledger artifact"
  check_no_live_mutation_claims "$ledger_script"
  check_no_live_mutation_claims "$fixtures_path"
  check_no_bare_heavy_commands "$ledger_script"
  check_no_bare_heavy_commands "$fixtures_path"
}

run_all_cases() {
  local root="$1"
  mkdir -p "$root"
  while IFS= read -r case_json; do
    run_case "$case_json" "$root"
  done < <(jq -c '.cases[]' "$fixtures_path")
  printf 'swarm_topology_placement_receipt_ledger_smoke_artifacts=%s\n' "$root"
}

run_selftest() {
  local tmp_root
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-topology-placement-receipt-ledger-selftest.XXXXXX")"
  run_all_cases "$tmp_root"
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      if [[ -z "$output_dir" ]]; then
        output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-topology-placement-receipt-ledger-run.XXXXXX")"
      fi
      run_all_cases "$output_dir"
    fi
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
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
