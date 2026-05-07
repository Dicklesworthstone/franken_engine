#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/swarm_benchmark_workload_catalog_normalizer.sh"
contract_path="${root_dir}/docs/swarm_benchmark_workload_catalog_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_BENCHMARK_WORKLOAD_CATALOG.md"
fixtures_path="${root_dir}/scripts/testdata/swarm_benchmark_workload_catalog/cases.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS swarm-benchmark-workload-catalog-normalizer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-benchmark-workload-catalog-normalizer %s\n' "$1" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_benchmark_workload_catalog_normalizer_smoke.sh [check|selftest]
EOF
}

write_workspace_file() {
  local workspace="$1"
  local path="$2"
  local kind="$3"
  local full_path="${workspace}/${path}"

  mkdir -p "$(dirname "$full_path")"
  case "$kind" in
    contract)
      jq -n --arg schema_version "franken-engine.test-contract.v1" '{schema_version:$schema_version}' >"$full_path"
      ;;
    malformed_contract)
      printf '{not-json\n' >"$full_path"
      ;;
    shell)
      printf '#!/usr/bin/env bash\nset -euo pipefail\n' >"$full_path"
      ;;
    markdown)
      printf '# Test Benchmark Surface\n' >"$full_path"
      ;;
    json)
      jq -n '{ok:true}' >"$full_path"
      ;;
    *)
      printf 'fixture\n' >"$full_path"
      ;;
  esac
}

materialize_workspace() {
  local case_json="$1"
  local workspace="$2"
  local file_json

  mkdir -p "$workspace"
  while IFS= read -r file_json; do
    local path kind
    path="$(jq -r '.path' <<<"$file_json")"
    kind="$(jq -r '.kind' <<<"$file_json")"
    write_workspace_file "$workspace" "$path" "$kind"
  done < <(jq -c '.workspace_files[]' <<<"$case_json")
}

run_real_contract_check() {
  local tmp_root output_dir status
  tmp_root="${TMPDIR:-/tmp}/franken-engine-swarm-benchmark-workload-real/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)"
  output_dir="${tmp_root}/out"
  mkdir -p "$output_dir"

  set +e
  "$normalizer" \
    --source-manifest-json "$contract_path" \
    --workspace-root "$root_dir" \
    --source-revision smoke-real-contract \
    --output-dir "$output_dir" >/dev/null
  status=$?
  set -e

  if [[ "$status" -ne 0 ]]; then
    record_failure "real contract normalization exited ${status}"
  fi
  jq -e '
    .workload_count >= 6
    and .decision == "degraded"
    and any(.workloads[]; .workload_id == "benchmark_denominator_suite" and .replay_evidence_state == "missing_optional")
    and any(.workloads[]; .workload_id == "parser_phase0_artifact_contract" and .replay_evidence_state == "provided")
    and (.artifact_paths.swarm_benchmark_workload_catalog_json | test("swarm_benchmark_workload_catalog.json$"))
  ' "${output_dir}/swarm_benchmark_workload_catalog.json" >/dev/null \
    || record_failure "real contract catalog shape mismatch"
  jq empty "${output_dir}/swarm_benchmark_workload_catalog.json" "${output_dir}/catalog_findings.json"
  record_pass "real contract"
}

run_fixture_case() {
  local case_id="$1"
  local case_json tmp_root workspace manifest output_dir expected_decision expected_exit expected_reason status

  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing fixture case ${case_id}"
  fi

  tmp_root="${TMPDIR:-/tmp}/franken-engine-swarm-benchmark-workload-fixtures/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)/${case_id}"
  workspace="${tmp_root}/workspace"
  manifest="${tmp_root}/manifest.json"
  output_dir="${tmp_root}/out"
  mkdir -p "$output_dir"

  materialize_workspace "$case_json" "$workspace"
  jq '.manifest' <<<"$case_json" >"$manifest"

  expected_decision="$(jq -r '.expected.decision' <<<"$case_json")"
  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"
  expected_reason="$(jq -r '.expected.reason_code // ""' <<<"$case_json")"

  set +e
  "$normalizer" \
    --source-manifest-json "$manifest" \
    --workspace-root "$workspace" \
    --source-revision "fixture-${case_id}" \
    --output-dir "$output_dir" >/dev/null
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    record_failure "${case_id} expected exit ${expected_exit}, got ${status}"
  fi
  jq -e --arg decision "$expected_decision" '.decision == $decision' "${output_dir}/swarm_benchmark_workload_catalog.json" >/dev/null \
    || record_failure "${case_id} decision mismatch"

  if [[ -n "$expected_reason" ]]; then
    jq -e --arg code "$expected_reason" 'any(.findings[]; .code == $code)' "${output_dir}/catalog_findings.json" >/dev/null \
      || record_failure "${case_id} missing reason ${expected_reason}"
  fi

  jq empty "${output_dir}/swarm_benchmark_workload_catalog.json" "${output_dir}/catalog_findings.json"
  [[ -s "${output_dir}/events.jsonl" ]] || record_failure "${case_id} missing events"
  grep -Fq './scripts/swarm_benchmark_workload_catalog_normalizer.sh' "${output_dir}/commands.txt" \
    || record_failure "${case_id} missing commands invocation"
  grep -Fq 'decision:' "${output_dir}/report.md" || record_failure "${case_id} missing report decision"
  record_pass "$case_id"
}

run_check() {
  bash -n "$normalizer"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path" "$fixtures_path"
  jq -e '.required_workload_fields | index("workload_id") and index("validation_commands")' "$contract_path" >/dev/null
  jq -e '.cases | length == 7' "$fixtures_path" >/dev/null
  grep -Fq 'Any heavy Cargo example must start with' "$docs_path" \
    || record_failure "missing RCH policy wording"
  grep -Fq 'Optional replay entrypoints may degrade' "$docs_path" \
    || record_failure "missing replay degradation wording"
  run_real_contract_check
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
