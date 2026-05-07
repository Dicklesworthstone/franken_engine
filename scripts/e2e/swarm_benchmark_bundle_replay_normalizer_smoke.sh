#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/swarm_benchmark_bundle_replay_normalizer.sh"
docs_path="${root_dir}/docs/SWARM_BENCHMARK_BUNDLE_REPLAY_NORMALIZER.md"
fixtures_path="${root_dir}/scripts/testdata/swarm_benchmark_bundle_replay_normalizer/cases.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS swarm-benchmark-bundle-replay-normalizer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-benchmark-bundle-replay-normalizer %s\n' "$1" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_benchmark_bundle_replay_normalizer_smoke.sh [check|selftest]
EOF
}

write_workspace_file() {
  local workspace="$1"
  local path="$2"
  local kind="$3"
  local full_path="${workspace}/${path}"

  mkdir -p "$(dirname "$full_path")"
  case "$kind" in
    markdown)
      printf '# Fixture Document\n' >"$full_path"
      ;;
    contract)
      jq -n --arg schema_version "franken-engine.fixture-contract.v1" '{schema_version:$schema_version}' >"$full_path"
      ;;
    run_manifest_pass)
      jq -n '{
        schema_version: "franken-engine.fixture-run-manifest.v1",
        component: "fixture_component",
        mode: "ci",
        generated_at_utc: "20260507T080000Z",
        outcome: "pass",
        artifacts: { manifest: "artifacts/fixture/run_manifest.json" },
        failed_command: null
      }' >"$full_path"
      ;;
    run_manifest_fail)
      jq -n '{
        schema_version: "franken-engine.fixture-run-manifest.v1",
        component: "fixture_component",
        mode: "ci",
        generated_at_utc: "20260507T080000Z",
        outcome: "fail",
        artifacts: { manifest: "artifacts/fixture/run_manifest.json" },
        failed_command: "cargo test -p frankenengine-engine"
      }' >"$full_path"
      ;;
    run_manifest_missing_primary)
      jq -n '{
        schema_version: "franken-engine.fixture-run-manifest.v1",
        component: "",
        mode: "ci",
        generated_at_utc: "",
        outcome: "pass",
        artifacts: {},
        failed_command: null
      }' >"$full_path"
      ;;
    malformed_json)
      printf '{not-json\n' >"$full_path"
      ;;
    events_jsonl)
      {
        jq -nc '{schema_version:"franken-engine.fixture-event.v1",event:"started",outcome:"pass"}'
        jq -nc '{schema_version:"franken-engine.fixture-event.v1",event:"completed",outcome:"pass"}'
      } >"$full_path"
      ;;
    malformed_events_jsonl)
      printf '{not-json\n' >"$full_path"
      ;;
    throughput_blocked)
      jq -n '{
        schema_version: "franken-engine.throughput-baselines.v1",
        decision: "partial_blocked",
        runtimes: {
          frankenengine: {
            version: "not-measured",
            baseline_ops_per_second: 0,
            workload_results: {},
            measurement_status: "blocked",
            observed_workload_count: 0,
            blockers: [
              {
                code: "runner_not_configured",
                detail: "requires a real runner",
                remediation: "configure runner"
              }
            ]
          }
        }
      }' >"$full_path"
      ;;
    throughput_placeholder)
      jq -n '{
        schema_version: "franken-engine.throughput-baselines.v1",
        decision: "partial_blocked",
        runtimes: {
          frankenengine: {
            version: "not-measured",
            baseline_ops_per_second: 42,
            workload_results: { fibonacci: 1234 },
            measurement_status: "blocked",
            observed_workload_count: 1,
            blockers: [
              {
                code: "runner_not_configured",
                detail: "requires a real runner",
                remediation: "configure runner"
              }
            ]
          }
        }
      }' >"$full_path"
      ;;
    stall_confirmed)
      jq -n '{
        schema_version: "franken-engine.rch-remote-compile-stall-bundle.v1",
        capture_decision: "captured",
        truth_state: "confirmed",
        local_fallback_observed: false,
        stall_subject: { build_id: "build-1", worker_id: "worker-a" },
        snapshot_health: { contradictory_snapshot_count: 0 },
        blockers: []
      }' >"$full_path"
      ;;
    stall_contaminated)
      jq -n '{
        schema_version: "franken-engine.rch-remote-compile-stall-bundle.v1",
        capture_decision: "fail_closed",
        truth_state: "contaminated",
        local_fallback_observed: true,
        stall_subject: { build_id: "build-2", worker_id: "worker-b" },
        snapshot_health: { contradictory_snapshot_count: 0 },
        blockers: [
          { code: "local_fallback_observed", detail: "contaminated by local fallback" }
        ]
      }' >"$full_path"
      ;;
    stall_blocked)
      jq -n '{
        schema_version: "franken-engine.rch-remote-compile-stall-bundle.v1",
        capture_decision: "fail_closed",
        truth_state: "blocked",
        local_fallback_observed: false,
        stall_subject: { build_id: "build-3", worker_id: "worker-c" },
        snapshot_health: { contradictory_snapshot_count: 1 },
        blockers: [
          { code: "queue_status_conflict", detail: "contradictory queue/status evidence" }
        ]
      }' >"$full_path"
      ;;
    *)
      printf 'fixture\n' >"$full_path"
      ;;
  esac
}

materialize_workspace() {
  local case_json="$1"
  local workspace="$2"
  local request_path="$3"
  local file_json

  mkdir -p "$workspace"
  while IFS= read -r file_json; do
    local path kind
    path="$(jq -r '.path' <<<"$file_json")"
    kind="$(jq -r '.kind' <<<"$file_json")"
    write_workspace_file "$workspace" "$path" "$kind"
  done < <(jq -c '.workspace_files[]' <<<"$case_json")

  jq '.source_manifest' <<<"$case_json" >"${workspace}/source_manifest.json"
  jq '.request' <<<"$case_json" >"$request_path"
}

assert_bundle() {
  local output_dir="$1"
  local expected_decision="$2"
  local expected_reason="$3"

  jq -e --arg decision "$expected_decision" '
    .schema_version == "franken-engine.swarm-benchmark-bundle.v1"
    and .decision == $decision
    and (.artifact_paths.swarm_benchmark_bundle_json | test("swarm_benchmark_bundle.json$"))
    and (.artifact_paths.report_md | test("report.md$"))
  ' "${output_dir}/swarm_benchmark_bundle.json" >/dev/null || return 1

  if [[ -n "$expected_reason" ]]; then
    jq -e --arg code "$expected_reason" 'any(.findings[]; .code == $code)' "${output_dir}/benchmark_findings.json" >/dev/null || return 1
  fi

  jq empty "${output_dir}/swarm_benchmark_bundle.json" "${output_dir}/benchmark_findings.json" >/dev/null
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"
}

run_real_repo_check() {
  local tmp_root request_path output_dir extension_manifest extension_events sibling_manifest status
  tmp_root="${TMPDIR:-/tmp}/franken-engine-swarm-benchmark-bundle-real/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  request_path="${tmp_root}/request.json"
  output_dir="${tmp_root}/out"
  mkdir -p "$output_dir"

  extension_manifest="$(find "${root_dir}/artifacts" -path '*/extension_heavy_benchmark_spec/*/run_manifest.json' | sort | tail -n 1)"
  extension_events="$(find "${root_dir}/artifacts" -path '*/extension_heavy_benchmark_spec/*/extension_heavy_benchmark_spec_events.jsonl' | sort | tail -n 1)"
  sibling_manifest="$(find "${root_dir}/artifacts" -path '*/sibling_integration_benchmark_gate/*/run_manifest.json' | sort | tail -n 1)"
  jq -n \
    --arg source_manifest_json "docs/swarm_benchmark_workload_catalog_contract_v1.json" \
    --arg extension_manifest "${extension_manifest#"${root_dir}"/}" \
    --arg extension_events "${extension_events#"${root_dir}"/}" \
    --arg sibling_manifest "${sibling_manifest#"${root_dir}"/}" \
    --arg throughput_json "docs/throughput_baseline_measurements_v1.json" \
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
          primary_artifact_json: $throughput_json,
          events_jsonl: null,
          stall_bundle_json: null
        }
      ]
    }' >"$request_path"

  set +e
  "$normalizer" \
    --bundle-request-json "$request_path" \
    --workspace-root "$root_dir" \
    --source-revision smoke-real-repo \
    --output-dir "$output_dir" >/dev/null
  status=$?
  set -e

  if [[ "$status" -ne 0 ]]; then
    record_failure "real repo normalization exited ${status}"
  fi

  jq -e '
    .decision == "degraded"
    and any(.rows[]; .workload_id == "extension_heavy_benchmark_spec" and .row_state == "observed")
    and any(.rows[]; .workload_id == "sibling_integration_benchmark_gate" and .row_state == "observed")
    and any(.rows[]; .workload_id == "frankenengine_throughput_baseline_status" and .row_state == "blocked")
  ' "${output_dir}/swarm_benchmark_bundle.json" >/dev/null || record_failure "real repo bundle shape mismatch"

  record_pass "real repo"
}

run_fixture_case() {
  local case_id="$1"
  local case_json tmp_root workspace request_path output_dir expected_decision expected_exit expected_reason status

  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing fixture case ${case_id}"
  fi

  tmp_root="${TMPDIR:-/tmp}/franken-engine-swarm-benchmark-bundle-fixtures/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)/${case_id}"
  workspace="${tmp_root}/workspace"
  request_path="${tmp_root}/request.json"
  output_dir="${tmp_root}/out"
  mkdir -p "$output_dir"

  materialize_workspace "$case_json" "$workspace" "$request_path"

  expected_decision="$(jq -r '.expected.decision' <<<"$case_json")"
  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"
  expected_reason="$(jq -r '.expected.reason_code // ""' <<<"$case_json")"

  set +e
  "$normalizer" \
    --bundle-request-json "$request_path" \
    --workspace-root "$workspace" \
    --source-revision "fixture-${case_id}" \
    --output-dir "$output_dir" >/dev/null
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    record_failure "${case_id} expected exit ${expected_exit}, got ${status}"
  fi
  assert_bundle "$output_dir" "$expected_decision" "$expected_reason" || record_failure "${case_id} bundle assertion failed"
  record_pass "$case_id"
}

run_check() {
  bash -n "$normalizer"
  bash -n "${BASH_SOURCE[0]}"
  shellcheck -x "$normalizer" "${BASH_SOURCE[0]}"
  jq empty "$fixtures_path" >/dev/null
  jq -e '.cases | length == 7' "$fixtures_path" >/dev/null
  grep -Fq 'Placeholder throughput claims are never accepted.' "$docs_path" || record_failure "missing placeholder fail-closed wording"
  grep -Fq "\`recovered_remote_stall\`" "$docs_path" || record_failure "missing recovered stall wording"
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
