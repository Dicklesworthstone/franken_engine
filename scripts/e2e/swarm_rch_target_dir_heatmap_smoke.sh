#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
heatmap_script="${root_dir}/scripts/swarm_rch_target_dir_heatmap.sh"
fixtures_path="${SWARM_RCH_TARGET_DIR_HEATMAP_FIXTURES:-${root_dir}/scripts/testdata/swarm_rch_target_dir_heatmap/cases.json}"
mode="${1:-check}"
output_dir="${2:-${SWARM_RCH_TARGET_DIR_HEATMAP_OUTPUT_DIR:-}}"
failures=0

case_ids=(
  warm_reusable_target
  cold_target
  disk_pressure
  worker_saturated
  local_fallback_contamination
  missing_rch_snapshot
)

record_pass() {
  printf 'PASS swarm-rch-target-dir-heatmap %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-rch-target-dir-heatmap %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_rch_target_dir_heatmap_smoke.sh [check|selftest|run] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-rch-target-dir-heatmap.fixtures.v1"
    and (.default_input.schema_version == "franken-engine.swarm-rch-target-dir-heatmap.input.v1")
    and ([.cases[].case_id] | sort) == ([
      "cold_target",
      "disk_pressure",
      "local_fallback_contamination",
      "missing_rch_snapshot",
      "warm_reusable_target",
      "worker_saturated"
    ] | sort)
    and any(.cases[]; .case_id == "warm_reusable_target" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "cold_target" and .expected.expected_recommendation == "allocate_fresh_target")
    and any(.cases[]; .case_id == "disk_pressure" and (.expected.degraded_reasons | index("disk_or_memory_pressure") != null))
    and any(.cases[]; .case_id == "worker_saturated" and (.expected.degraded_reasons | index("worker_saturated") != null))
    and any(.cases[]; .case_id == "local_fallback_contamination" and (.expected.fail_closed_reasons | index("local_rch_fallback_contamination") != null))
    and any(.cases[]; .case_id == "missing_rch_snapshot" and (.expected.degraded_reasons | index("missing_rch_snapshot") != null))
  ' "$fixtures_path" >/dev/null
}

run_check() {
  bash -n "$heatmap_script"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$heatmap_script" "${BASH_SOURCE[0]}"
  fi
  jq empty "$fixtures_path" >/dev/null
  fixtures_shape_ok
  grep -Fq 'runs_rch: false' "$heatmap_script"
  grep -Fq 'deletes_caches: false' "$heatmap_script"
  grep -Fq 'local_rch_fallback_contamination' "$heatmap_script"
  record_pass "shell syntax and fixture shape"
}

write_case_input() {
  local case_id="$1"
  local input_path="$2"
  jq --arg case_id "$case_id" '
    (.cases[] | select(.case_id == $case_id)) as $case
    | (.default_input * ($case.input_patch // {}))
    | .case_id = $case.case_id
  ' "$fixtures_path" >"$input_path"
}

run_case() {
  local tmp_root="$1"
  local case_id="$2"
  local case_dir="${tmp_root}/${case_id}"
  local input_path="${case_dir}/input.json"
  local actual_exit expected_decision expected_recommendation expected_fail expected_degraded
  mkdir -p "$case_dir"
  write_case_input "$case_id" "$input_path"

  expected_decision="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected.decision' "$fixtures_path")"
  expected_recommendation="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .expected.expected_recommendation // ""' "$fixtures_path")"
  expected_fail="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | (.expected.fail_closed_reasons // []) | join(",")' "$fixtures_path")"
  expected_degraded="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | (.expected.degraded_reasons // []) | join(",")' "$fixtures_path")"

  set +e
  "$heatmap_script" \
    --input-json "$input_path" \
    --source-revision fixture-revision \
    --output-dir "${case_dir}/out" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$expected_decision" == "fail_closed" && "$actual_exit" -ne 42 ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected 42"
    return
  fi
  if [[ "$expected_decision" != "fail_closed" && "$actual_exit" -ne 0 ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected 0"
    return
  fi

  jq -e --arg expected_decision "$expected_decision" '
    .schema_version == "franken-engine.swarm-rch-target-dir-heatmap.v1"
    and .decision == $expected_decision
    and .non_mutation_attestation.runs_rch == false
    and .non_mutation_attestation.deletes_caches == false
    and .non_mutation_attestation.mutates_rch_config == false
  ' "${case_dir}/out/target_dir_heatmap.json" >/dev/null || {
    record_failure "${case_id} heatmap shape mismatch"
    return
  }

  if [[ -n "$expected_recommendation" ]]; then
    jq -e --arg expected_recommendation "$expected_recommendation" \
      'any(.target_dir_rows[]?; .recommendation == $expected_recommendation)' \
      "${case_dir}/out/target_dir_heatmap.json" >/dev/null || {
      record_failure "${case_id} missing recommendation ${expected_recommendation}"
      return
    }
  fi

  if [[ -n "$expected_fail" ]]; then
    IFS=',' read -r -a reason_codes <<<"$expected_fail"
    for reason_code in "${reason_codes[@]}"; do
      jq -e --arg reason_code "$reason_code" \
        'any(.fail_closed_reasons[]?; .code == $reason_code)' \
        "${case_dir}/out/target_dir_heatmap.json" >/dev/null || {
        record_failure "${case_id} missing fail-closed reason ${reason_code}"
        return
      }
    done
  fi

  if [[ -n "$expected_degraded" ]]; then
    IFS=',' read -r -a reason_codes <<<"$expected_degraded"
    for reason_code in "${reason_codes[@]}"; do
      jq -e --arg reason_code "$reason_code" \
        'any(.degraded_reasons[]?; .code == $reason_code)' \
        "${case_dir}/out/target_dir_heatmap.json" >/dev/null || {
        record_failure "${case_id} missing degraded reason ${reason_code}"
        return
      }
    done
  fi

  jq -s 'length >= 1' "${case_dir}/out/events.jsonl" >/dev/null
  grep -Fq './scripts/swarm_rch_target_dir_heatmap.sh' "${case_dir}/out/commands.txt"
  grep -Fq 'Target-Dir Heat Map Advice' "${case_dir}/out/target_dir_advice.md"
  grep -Fq 'Swarm RCH Target-Dir Heat Map' "${case_dir}/out/report.md"
  record_pass "$case_id"
}

run_selftest() {
  local tmp_root="$1"
  for case_id in "${case_ids[@]}"; do
    run_case "$tmp_root" "$case_id"
  done
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest "$(mktemp -d "${TMPDIR:-/tmp}/swarm-rch-target-dir-heatmap.XXXXXX")"
    fi
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      if [[ -z "$output_dir" ]]; then
        output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-rch-target-dir-heatmap-run.XXXXXX")"
      fi
      mkdir -p "$output_dir"
      run_selftest "$output_dir"
      printf 'swarm_rch_target_dir_heatmap_smoke_artifacts=%s\n' "$output_dir"
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
