#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
catalog_normalizer="${root_dir}/scripts/swarm_benchmark_workload_catalog_normalizer.sh"
bundle_normalizer="${root_dir}/scripts/swarm_benchmark_bundle_replay_normalizer.sh"
scorer="${root_dir}/scripts/swarm_benchmark_responsiveness_scorer.sh"
docs_path="${root_dir}/docs/SWARM_BENCHMARK_RESPONSIVENESS_SCORER.md"
fixtures_path="${root_dir}/scripts/testdata/swarm_benchmark_responsiveness_scorer/cases.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS swarm-benchmark-responsiveness-scorer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-benchmark-responsiveness-scorer %s\n' "$1" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_benchmark_responsiveness_scorer_smoke.sh [check|selftest]
EOF
}

materialize_case_inputs() {
  local case_json="$1"
  local workspace="$2"
  mkdir -p "$workspace"
  jq '.inputs.normalized_workload_catalog_json' <<<"$case_json" >"${workspace}/catalog.json"
  jq '.inputs.normalized_benchmark_bundle_json' <<<"$case_json" >"${workspace}/bundle.json"
  jq '.inputs.resource_envelope_json' <<<"$case_json" >"${workspace}/resource.json"
  jq '.inputs.topology_locality_json' <<<"$case_json" >"${workspace}/topology.json"
  jq '.inputs.proof_cache_locality_plan_json' <<<"$case_json" >"${workspace}/proof_cache.json"
}

assert_advisory() {
  local advisory_path="$1"
  local expected_decision="$2"
  local expected_truth_state="$3"
  local expected_bottleneck="$5"
  local expected_command="$6"
  local expected_throughput_gap="$7"
  local expected_utilization="$8"
  local expected_cache_recommendation="$9"
  local expected_remote_confidence="${10}"

  jq -e \
    --arg decision "$expected_decision" \
    --arg truth_state "$expected_truth_state" \
    --arg throughput_gap "$expected_throughput_gap" \
    --arg utilization "$expected_utilization" \
    --arg cache_recommendation "$expected_cache_recommendation" \
    --arg remote_confidence "$expected_remote_confidence" \
    '
      .schema_version == "franken-engine.swarm-benchmark-responsiveness-advisory.v1"
      and .decision == $decision
      and .truth_state == $truth_state
      and .throughput_gap_band == $throughput_gap
      and .utilization_pressure_band == $utilization
      and .cold_warm_cache_recommendation == $cache_recommendation
      and .remote_proof_confidence_state == $remote_confidence
      and (.artifact_paths.swarm_benchmark_responsiveness_advisory_json | test("swarm_benchmark_responsiveness_advisory.json$"))
    ' "$advisory_path" >/dev/null || return 1

  if [[ -n "$expected_bottleneck" ]]; then
    jq -e --arg bottleneck "$expected_bottleneck" 'any(.bottleneck_classes[]?; .bottleneck_class == $bottleneck)' "$advisory_path" >/dev/null || return 1
  fi
  if [[ -n "$expected_command" ]]; then
    jq -e --arg command "$expected_command" 'any(.advisory_commands[]?; .command == $command)' "$advisory_path" >/dev/null || return 1
  fi
  return 0
}

run_real_repo_check() {
  local tmp_root catalog_dir bundle_dir scorer_dir request_path extension_manifest extension_events sibling_manifest resource_json topology_json proof_json status
  tmp_root="${TMPDIR:-/tmp}/franken-engine-swarm-benchmark-responsiveness-real/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  catalog_dir="${tmp_root}/catalog"
  bundle_dir="${tmp_root}/bundle"
  scorer_dir="${tmp_root}/scorer"
  request_path="${tmp_root}/bundle_request.json"
  mkdir -p "$catalog_dir" "$bundle_dir" "$scorer_dir"

  "$catalog_normalizer" \
    --source-manifest-json "${root_dir}/docs/swarm_benchmark_workload_catalog_contract_v1.json" \
    --workspace-root "$root_dir" \
    --source-revision scorer-real-repo \
    --output-dir "$catalog_dir" >/dev/null

  extension_manifest="$(find "${root_dir}/artifacts" -path '*/extension_heavy_benchmark_spec/*/run_manifest.json' | sort | tail -n 1)"
  extension_events="$(find "${root_dir}/artifacts" -path '*/extension_heavy_benchmark_spec/*/extension_heavy_benchmark_spec_events.jsonl' | sort | tail -n 1)"
  sibling_manifest="$(find "${root_dir}/artifacts" -path '*/sibling_integration_benchmark_gate/*/run_manifest.json' | sort | tail -n 1)"

  jq -n \
    --arg source_manifest_json "docs/swarm_benchmark_workload_catalog_contract_v1.json" \
    --arg extension_manifest "${extension_manifest#"${root_dir}"/}" \
    --arg extension_events "${extension_events#"${root_dir}"/}" \
    --arg sibling_manifest "${sibling_manifest#"${root_dir}"/}" \
    '{
      schema_version: "franken-engine.swarm-benchmark-bundle-replay-normalizer.request.v1",
      source_manifest_json: $source_manifest_json,
      evidence_rows: [
        {
          workload_id: "extension_heavy_benchmark_spec",
          evidence_kind: "run_manifest",
          primary_artifact_json: $extension_manifest,
          events_jsonl: $extension_events,
          stall_bundle_json: null
        },
        {
          workload_id: "sibling_integration_benchmark_gate",
          evidence_kind: "run_manifest",
          primary_artifact_json: $sibling_manifest,
          events_jsonl: null,
          stall_bundle_json: null
        },
        {
          workload_id: "frankenengine_throughput_baseline_status",
          evidence_kind: "throughput_baselines",
          primary_artifact_json: "docs/throughput_baseline_measurements_v1.json",
          events_jsonl: null,
          stall_bundle_json: null
        }
      ]
    }' >"$request_path"

  "$bundle_normalizer" \
    --bundle-request-json "$request_path" \
    --workspace-root "$root_dir" \
    --source-revision scorer-real-repo \
    --output-dir "$bundle_dir" >/dev/null

  resource_json="${tmp_root}/resource.json"
  topology_json="${tmp_root}/topology.json"
  proof_json="${tmp_root}/proof.json"

  jq -n '{
    schema_version: "franken-engine.swarm-resource-envelope.v1",
    decision: "pass",
    readiness: "ready",
    memory_pressure: {available_bytes: 206158430208},
    rch_slots: {available: 8},
    capacity_budget: {remote_rch_slot_limit: 8}
  }' >"$resource_json"
  jq -n '{
    schema_version: "franken-engine.swarm-topology-aware-queue-advisory.v1",
    decision: "pass",
    recommended_topology_class: "numa_local_hot_cache",
    warm_cache_residency_state: "hot"
  }' >"$topology_json"
  jq -n '{
    schema_version: "franken-engine.swarm-proof-cache-locality-plan.v1",
    decision: "pass",
    proof_cache_summary: {proof_cache_decision: "cache_hit"},
    topology_summary: {warm_cache_residency_state: "hot"}
  }' >"$proof_json"

  set +e
  "$scorer" \
    --normalized-workload-catalog-json "${catalog_dir}/swarm_benchmark_workload_catalog.json" \
    --normalized-benchmark-bundle-json "${bundle_dir}/swarm_benchmark_bundle.json" \
    --resource-envelope-json "$resource_json" \
    --topology-locality-json "$topology_json" \
    --proof-cache-locality-plan-json "$proof_json" \
    --source-revision scorer-real-repo \
    --output-dir "$scorer_dir" >/dev/null
  status=$?
  set -e

  if [[ "$status" -ne 0 ]]; then
    record_failure "real repo scorer exited ${status}"
  fi

  jq -e '
    .decision == "degraded"
    and .throughput_gap_band == "blocked_measurement"
    and .remote_proof_confidence_state == "degraded"
    and any(.bottleneck_classes[]?; .bottleneck_class == "blocked_runtime_measurement")
  ' "${scorer_dir}/swarm_benchmark_responsiveness_advisory.json" >/dev/null || record_failure "real repo advisory shape mismatch"

  record_pass "real repo"
}

run_fixture_case() {
  local case_id="$1"
  local case_json tmp_root workspace output_dir expected_decision expected_truth_state expected_exit expected_bottleneck expected_command expected_throughput expected_utilization expected_cache expected_remote status

  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing fixture case ${case_id}"
  fi

  tmp_root="${TMPDIR:-/tmp}/franken-engine-swarm-benchmark-responsiveness-fixtures/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)/${case_id}"
  workspace="${tmp_root}/workspace"
  output_dir="${tmp_root}/out"
  mkdir -p "$output_dir"
  materialize_case_inputs "$case_json" "$workspace"

  expected_decision="$(jq -r '.expected.decision' <<<"$case_json")"
  expected_truth_state="$(jq -r '.expected.truth_state' <<<"$case_json")"
  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"
  expected_bottleneck="$(jq -r '.expected.required_bottleneck // ""' <<<"$case_json")"
  expected_command="$(jq -r '.expected.required_command // ""' <<<"$case_json")"
  expected_throughput="$(jq -r '.expected.throughput_gap_band' <<<"$case_json")"
  expected_utilization="$(jq -r '.expected.utilization_pressure_band' <<<"$case_json")"
  expected_cache="$(jq -r '.expected.cold_warm_cache_recommendation' <<<"$case_json")"
  expected_remote="$(jq -r '.expected.remote_proof_confidence_state' <<<"$case_json")"

  set +e
  "$scorer" \
    --normalized-workload-catalog-json "${workspace}/catalog.json" \
    --normalized-benchmark-bundle-json "${workspace}/bundle.json" \
    --resource-envelope-json "${workspace}/resource.json" \
    --topology-locality-json "${workspace}/topology.json" \
    --proof-cache-locality-plan-json "${workspace}/proof_cache.json" \
    --source-revision "fixture-${case_id}" \
    --output-dir "$output_dir" >/dev/null
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    record_failure "${case_id} expected exit ${expected_exit}, got ${status}"
  fi
  assert_advisory "${output_dir}/swarm_benchmark_responsiveness_advisory.json" "$expected_decision" "$expected_truth_state" "$expected_exit" "$expected_bottleneck" "$expected_command" "$expected_throughput" "$expected_utilization" "$expected_cache" "$expected_remote" || record_failure "${case_id} advisory assertion failed"
  record_pass "$case_id"
}

run_check() {
  bash -n "$scorer"
  bash -n "${BASH_SOURCE[0]}"
  shellcheck -x "$scorer" "${BASH_SOURCE[0]}"
  jq empty "$fixtures_path" >/dev/null
  jq -e '.cases | length == 7' "$fixtures_path" >/dev/null
  grep -Fq 'bare heavy Cargo as forbidden recommendation output' "$docs_path" || record_failure "missing bare cargo policy wording"
  grep -Fq "\`blocked_runtime_measurement\`" "$docs_path" || record_failure "missing bottleneck class wording"
  run_real_repo_check
  record_pass "check"
}

run_selftest() {
  local case_id
  run_check
  while IFS= read -r case_id; do
    run_fixture_case "$case_id"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")
  record_pass "selftest"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    ;;
esac
