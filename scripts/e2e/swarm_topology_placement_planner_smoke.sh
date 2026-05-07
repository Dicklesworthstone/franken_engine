#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/swarm_topology_placement_planner.sh"
fixtures_path="${SWARM_TOPOLOGY_PLACEMENT_PLANNER_FIXTURES:-${root_dir}/scripts/testdata/swarm_topology_placement_planner/cases.json}"
mode="${1:-check}"
output_dir="${2:-${SWARM_TOPOLOGY_PLACEMENT_PLANNER_OUTPUT_DIR:-}}"
failures=0

record_pass() {
  printf 'PASS swarm-topology-placement-planner %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-topology-placement-planner %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_topology_placement_planner_smoke.sh [check|run|selftest] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-topology-placement-planner-fixtures.v1"
    and (.cases | length == 4)
    and any(.cases[]; .case_id == "healthy_balanced_host" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "partial_topology_degraded" and .expected.decision == "degraded")
    and any(.cases[]; .case_id == "contradictory_locality_blocked" and .expected.decision == "blocked")
    and any(.cases[]; .case_id == "cache_cold_fallback" and .expected.required_opportunity == "cache_cold_fallback")
    and all(.cases[]; .placement_input.schema_version == "franken-engine.swarm-topology-placement-input.v1")
    and all(.cases[]; .expected | has("decision") and has("readiness") and has("recommended_topology_class") and has("expected_exit_code"))
  ' "$fixtures_path" >/dev/null
}

check_no_live_mutation_claims() {
  local path="$1"
  if grep -Eiq 'pins workers automatically|rebinds hosts automatically|updates beads automatically|reassigns beads automatically|changes live queue policy automatically|starts workers automatically' "$path"; then
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
  local case_id case_dir input expected plan events code expected_code

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${root}/${case_id}"
  mkdir -p "$case_dir"
  input="${case_dir}/swarm_topology_placement_input.json"
  expected="${case_dir}/expected.json"
  jq '.placement_input' <<<"$case_json" >"$input"
  jq '.expected' <<<"$case_json" >"$expected"
  expected_code="$(jq -r '.expected_exit_code' "$expected")"

  set +e
  "$planner" --placement-input-json "$input" --source-revision fixture-revision --output-dir "${case_dir}/out" >/dev/null
  code=$?
  set -e

  if [[ "$code" -ne "$expected_code" ]]; then
    record_failure "${case_id} expected exit ${expected_code}, got ${code}"
    return
  fi

  plan="${case_dir}/out/swarm_topology_placement_plan.json"
  events="${case_dir}/out/events.jsonl"
  if [[ ! -f "$plan" ]]; then
    record_failure "${case_id} did not emit plan"
    return
  fi

  jq -e --slurpfile expected "$expected" '
    .schema_version == "franken-engine.swarm-topology-placement-plan.v1"
    and .decision == $expected[0].decision
    and .placement_readiness == $expected[0].readiness
    and .recommended_topology_class == $expected[0].recommended_topology_class
    and .warm_cache_residency_state == $expected[0].warm_cache_residency_state
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
    and .mutation_policy.repairs_target_dirs_automatically == false
    and (.operator_advisories | all(startswith("# advisory-only ")))
  ' "$plan" >/dev/null || {
    record_failure "${case_id} plan shape mismatch"
    return
  }

  case "$case_id" in
    healthy_balanced_host)
      jq -e '
        .summary.heavy_target_count >= 1
        and .summary.latency_sensitive_target_count >= 1
        and any(.recommended_worker_targets[]?; .lane_class == "heavy" and .worker_id == "rch-a" and .cache_reuse == true)
        and any(.recommended_worker_targets[]?; .lane_class == "latency_sensitive" and .worker_id == "rch-a" and .cache_reuse == true)
        and any(.warm_cache_opportunities[]?; .opportunity_id == "reuse_hot_cache" and .certainty == "confirmed")
      ' "$plan" >/dev/null || record_failure "healthy case must reuse hot cache for heavy and latency-sensitive lanes"
      ;;
    partial_topology_degraded)
      jq -e '
        any(.degraded_reasons[]?; .code == "partial_topology_or_cache_context")
        and any(.warm_cache_opportunities[]?; .opportunity_id == "cache_evidence_unavailable")
        and all(.warm_cache_opportunities[]?; .certainty != "confirmed")
      ' "$plan" >/dev/null || record_failure "partial topology case must remain degraded without hot-cache certainty"
      ;;
    contradictory_locality_blocked)
      jq -e '
        any(.blocked_reasons[]?; .code == "contradictory_locality_evidence")
        and (.recommended_worker_targets | length) == 0
        and (.warm_cache_opportunities | length) == 0
      ' "$plan" >/dev/null || record_failure "contradictory locality case must block placement advice"
      ;;
    cache_cold_fallback)
      jq -e '
        .decision == "pass"
        and any(.warm_cache_opportunities[]?; .opportunity_id == "cache_cold_fallback" and .certainty == "bounded_uncertain")
        and all(.warm_cache_opportunities[]?; .certainty != "confirmed")
        and all(.recommended_worker_targets[]?; .cache_reuse == false and (.reason_codes | index("cache_cold_fallback") != null))
      ' "$plan" >/dev/null || record_failure "cache-cold case must avoid overclaiming warm-cache reuse"
      ;;
  esac

  jq -s '
    length >= 2
    and all(.[]; has("schema_version") and has("component") and has("event") and has("outcome") and has("evidence_path"))
    and any(.[]; .component == "swarm_topology_placement_planner" and .event == "plan.emitted")
  ' "$events" >/dev/null || record_failure "${case_id} events missing planner receipt"
  test -s "${case_dir}/out/commands.txt" || record_failure "${case_id} commands receipt missing"
  test -s "${case_dir}/out/report.md" || record_failure "${case_id} report missing"

  record_pass "${case_id} plan"
}

run_check() {
  bash -n "$planner"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$fixtures_path"

  if fixtures_shape_ok; then
    record_pass "fixture shape"
  else
    record_failure "fixture shape mismatch"
  fi

  grep -Fq 'advisory' "$planner" || record_failure "planner must describe advisory scope"
  grep -Fq 'swarm_topology_placement_plan.json' "$planner" || record_failure "planner must emit the topology placement plan artifact"
  check_no_live_mutation_claims "$planner"
  check_no_live_mutation_claims "$fixtures_path"
  check_no_bare_heavy_commands "$planner"
  check_no_bare_heavy_commands "$fixtures_path"
}

run_all_cases() {
  local root="$1"
  mkdir -p "$root"
  while IFS= read -r case_json; do
    run_case "$case_json" "$root"
  done < <(jq -c '.cases[]' "$fixtures_path")
  printf 'swarm_topology_placement_planner_smoke_artifacts=%s\n' "$root"
}

run_selftest() {
  local tmp_root
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-topology-placement-planner-selftest.XXXXXX")"
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
        output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-topology-placement-planner-run.XXXXXX")"
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
