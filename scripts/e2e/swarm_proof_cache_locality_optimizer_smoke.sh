#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
optimizer="${root_dir}/scripts/swarm_proof_cache_locality_optimizer.sh"
fixtures_path="${SWARM_PROOF_CACHE_LOCALITY_OPTIMIZER_FIXTURES:-${root_dir}/scripts/testdata/swarm_proof_cache_locality_optimizer/cases.json}"
contract_path="${root_dir}/docs/swarm_proof_cache_locality_optimizer_contract_v1.json"
mode="${1:-check}"
output_dir="${2:-${SWARM_PROOF_CACHE_LOCALITY_OPTIMIZER_OUTPUT_DIR:-}}"
failures=0

input_ids=(
  admission_budget_plan_json
  warm_target_prefetch_roi_advisory_json
  proof_cache_plan_json
  archive_pressure_scoreboard_json
  worker_truth_report_json
  swarm_resource_envelope_json
  swarm_topology_placement_plan_json
  swarm_topology_placement_receipt_json
  swarm_topology_placement_evidence_ledger_json
)

record_pass() {
  printf 'PASS swarm-proof-cache-locality-optimizer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-proof-cache-locality-optimizer %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_proof_cache_locality_optimizer_smoke.sh [check|run|selftest] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-cache-locality-optimizer-fixtures.v1"
    and (.cases | length == 6)
    and any(.cases[]; .case_id == "high_roi_reuse" and .expected.decision == "pass" and .expected.required_action == "reuse_warm_target")
    and any(.cases[]; .case_id == "cold_fresh_target" and .expected.required_action == "allocate_fresh_target")
    and any(.cases[]; .case_id == "disk_pressure_cooling" and .expected.required_action == "cool_target")
    and any(.cases[]; .case_id == "active_target_pinned" and .expected.decision == "blocked" and .expected.required_action == "preserve_active_target")
    and any(.cases[]; .case_id == "stale_archive_evidence" and .expected.required_reason_code == "stale_archive_evidence")
    and any(.cases[]; .case_id == "missing_swarm_scale_ii_evidence" and .expected.decision == "fail_closed" and .expected.required_reason_code == "missing_swarm_scale_ii_evidence")
    and all(.cases[]; .inputs.admission_budget_plan_json.schema_version == "franken-engine.swarm-admission-budget-plan.v1")
    and all(.cases[]; .inputs.swarm_topology_placement_plan_json.schema_version | type == "string")
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-cache-locality-optimizer-contract.v1"
    and .bead_id == "bd-wuj5w"
    and .script == "scripts/swarm_proof_cache_locality_optimizer.sh"
    and .smoke_script == "scripts/e2e/swarm_proof_cache_locality_optimizer_smoke.sh"
    and .fixture_bundle == "scripts/testdata/swarm_proof_cache_locality_optimizer/cases.json"
    and .output_schema_version == "franken-engine.swarm-proof-cache-locality-plan.v1"
    and (.required_inputs | index("swarm_topology_placement_receipt_json") != null)
    and (.required_outputs | index("locality_plan.json") != null)
    and (.actions | index("reuse_warm_target") != null)
    and (.actions | index("allocate_fresh_target") != null)
    and (.actions | index("cool_target") != null)
    and (.actions | index("preserve_active_target") != null)
    and (.fail_closed_rules | index("missing_swarm_scale_ii_evidence") != null)
    and .mutation_policy.advisory_only == true
    and .mutation_policy.deletes_or_overwrites_target_dirs == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
  ' "$contract_path" >/dev/null
}

check_no_forbidden_commands() {
  local path="$1"
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      record_failure "${path#"$root_dir"/} has bare heavy Cargo command: ${command}"
    fi
    if [[ "$command" =~ (^|[[:space:]])rch[[:space:]]+exec([[:space:]]|$) ]]; then
      record_failure "${path#"$root_dir"/} executes RCH instead of consuming fixture evidence: ${command}"
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,260p' "$path")
}

materialize_case() {
  local case_json="$1"
  local case_dir="$2"
  local input_id

  mkdir -p "$case_dir"
  for input_id in "${input_ids[@]}"; do
    jq --arg input_id "$input_id" '.inputs[$input_id]' <<<"$case_json" >"${case_dir}/${input_id}.json"
  done
}

run_case() {
  local case_json="$1"
  local root="$2"
  local case_id case_dir expected expected_code plan

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${root}/${case_id}"
  expected="${case_dir}/expected.json"
  materialize_case "$case_json" "$case_dir"
  jq '.expected' <<<"$case_json" >"$expected"
  expected_code="$(jq -r '.expected.expected_exit_code' <<<"$case_json")"

  set +e
  bash "$optimizer" \
    --admission-budget-plan-json "${case_dir}/admission_budget_plan_json.json" \
    --warm-target-prefetch-roi-advisory-json "${case_dir}/warm_target_prefetch_roi_advisory_json.json" \
    --proof-cache-plan-json "${case_dir}/proof_cache_plan_json.json" \
    --archive-pressure-scoreboard-json "${case_dir}/archive_pressure_scoreboard_json.json" \
    --worker-truth-report-json "${case_dir}/worker_truth_report_json.json" \
    --swarm-resource-envelope-json "${case_dir}/swarm_resource_envelope_json.json" \
    --swarm-topology-placement-plan-json "${case_dir}/swarm_topology_placement_plan_json.json" \
    --swarm-topology-placement-receipt-json "${case_dir}/swarm_topology_placement_receipt_json.json" \
    --swarm-topology-placement-evidence-ledger-json "${case_dir}/swarm_topology_placement_evidence_ledger_json.json" \
    --source-revision fixture-revision \
    --output-dir "${case_dir}/out" >/dev/null
  code=$?
  set -e

  if [[ "$code" -ne "$expected_code" ]]; then
    record_failure "${case_id} expected exit ${expected_code}, got ${code}"
    return
  fi

  plan="${case_dir}/out/locality_plan.json"
  test -f "$plan" || {
    record_failure "${case_id} missing locality_plan.json"
    return
  }

  jq -e --slurpfile expected "$expected" '
    .schema_version == "franken-engine.swarm-proof-cache-locality-plan.v1"
    and .decision == $expected[0].decision
    and any(.recommendations[]?; .action == $expected[0].required_action)
    and (if (($expected[0].required_reason_code // "") | length) > 0 then
      (((.fail_closed_reasons + .blocked_reasons + .degraded_reasons) | map(.code) | index($expected[0].required_reason_code)) != null)
    else true end)
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.deletes_or_overwrites_target_dirs == false
    and all(.recommendations[]?; .deletes_or_overwrites_artifacts == false)
  ' "$plan" >/dev/null || {
    record_failure "${case_id} plan shape mismatch"
    return
  }

  case "$case_id" in
    high_roi_reuse)
      jq -e '.host_profile == "64c_256g" and .summary.reuse_recommendation_count == 1 and .recommendations[0].manual_confirmation_required == false' "$plan" >/dev/null || record_failure "high ROI case must reuse on large-host profile"
      ;;
    cold_fresh_target)
      jq -e '.summary.fresh_target_recommendation_count == 1 and .recommendations[0].target_dir == null' "$plan" >/dev/null || record_failure "cold case must allocate fresh target without claiming reuse"
      ;;
    disk_pressure_cooling)
      jq -e '.summary.cooling_recommendation_count == 1 and any(.degraded_reasons[]?; .code == "target_pressure_requires_cooling")' "$plan" >/dev/null || record_failure "disk pressure case must cool target"
      ;;
    active_target_pinned)
      jq -e '.decision == "blocked" and .summary.preserve_active_target_count == 1 and any(.blocked_reasons[]?; .code == "active_target_pinned")' "$plan" >/dev/null || record_failure "active target case must preserve pinned target"
      ;;
    stale_archive_evidence)
      jq -e '.decision == "degraded" and any(.recommendations[]?; .action == "refresh_archive_evidence")' "$plan" >/dev/null || record_failure "stale archive case must refresh evidence"
      ;;
    missing_swarm_scale_ii_evidence)
      jq -e '.decision == "fail_closed" and any(.fail_closed_reasons[]?; .code == "missing_swarm_scale_ii_evidence")' "$plan" >/dev/null || record_failure "missing SWARM-SCALE-II case must fail closed"
      ;;
  esac

  jq -s '
    length >= 2
    and all(.[]; has("schema_version") and has("component") and has("event") and has("outcome") and has("evidence_path"))
    and any(.[]; .event == "locality_plan.emitted")
  ' "${case_dir}/out/events.jsonl" >/dev/null || record_failure "${case_id} events missing plan emission"
  test -s "${case_dir}/out/commands.txt" || record_failure "${case_id} commands receipt missing"
  test -s "${case_dir}/out/report.md" || record_failure "${case_id} report missing"

  record_pass "${case_id} locality plan"
}

run_check() {
  bash -n "$optimizer"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$fixtures_path" "$contract_path"

  if fixtures_shape_ok; then
    record_pass "fixture shape"
  else
    record_failure "fixture shape mismatch"
  fi
  if contract_shape_ok; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi

  check_no_forbidden_commands "$optimizer"
  check_no_forbidden_commands "$fixtures_path"
  check_no_forbidden_commands "$contract_path"
}

run_all_cases() {
  local root="$1"
  mkdir -p "$root"
  while IFS= read -r case_json; do
    run_case "$case_json" "$root"
  done < <(jq -c '.cases[]' "$fixtures_path")
  printf 'swarm_proof_cache_locality_optimizer_smoke_artifacts=%s\n' "$root"
}

run_selftest() {
  local tmp_root hash_a hash_b
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-proof-cache-locality-optimizer-selftest.XXXXXX")"
  run_all_cases "$tmp_root"
  hash_a="$(jq -r '.hash_basis.plan_hash' "${tmp_root}/high_roi_reuse/out/locality_plan.json")"
  bash "$optimizer" \
    --admission-budget-plan-json "${tmp_root}/high_roi_reuse/admission_budget_plan_json.json" \
    --warm-target-prefetch-roi-advisory-json "${tmp_root}/high_roi_reuse/warm_target_prefetch_roi_advisory_json.json" \
    --proof-cache-plan-json "${tmp_root}/high_roi_reuse/proof_cache_plan_json.json" \
    --archive-pressure-scoreboard-json "${tmp_root}/high_roi_reuse/archive_pressure_scoreboard_json.json" \
    --worker-truth-report-json "${tmp_root}/high_roi_reuse/worker_truth_report_json.json" \
    --swarm-resource-envelope-json "${tmp_root}/high_roi_reuse/swarm_resource_envelope_json.json" \
    --swarm-topology-placement-plan-json "${tmp_root}/high_roi_reuse/swarm_topology_placement_plan_json.json" \
    --swarm-topology-placement-receipt-json "${tmp_root}/high_roi_reuse/swarm_topology_placement_receipt_json.json" \
    --swarm-topology-placement-evidence-ledger-json "${tmp_root}/high_roi_reuse/swarm_topology_placement_evidence_ledger_json.json" \
    --source-revision fixture-revision \
    --output-dir "${tmp_root}/high_roi_reuse_repeat" >/dev/null
  hash_b="$(jq -r '.hash_basis.plan_hash' "${tmp_root}/high_roi_reuse_repeat/locality_plan.json")"
  if [[ "$hash_a" != "$hash_b" ]]; then
    record_failure "stable plan hash mismatch for repeated high ROI case"
  else
    record_pass "stable plan hash"
  fi
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      if [[ -z "$output_dir" ]]; then
        output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-proof-cache-locality-optimizer-run.XXXXXX")"
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
