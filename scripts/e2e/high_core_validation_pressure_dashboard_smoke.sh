#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
dashboard_script="${root_dir}/scripts/high_core_validation_pressure_dashboard.sh"
docs_path="${root_dir}/docs/HIGH_CORE_VALIDATION_PRESSURE_DASHBOARD.md"
contract_path="${root_dir}/docs/high_core_validation_pressure_dashboard_contract_v2.json"
fixtures_path="${HIGH_CORE_VALIDATION_PRESSURE_FIXTURES:-${root_dir}/scripts/testdata/high_core_validation_pressure_dashboard/cases.json}"
golden_dir="${HIGH_CORE_VALIDATION_PRESSURE_GOLDEN_DIR:-${root_dir}/scripts/testdata/goldens}"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS high-core-validation-pressure-dashboard %s\n' "$1"
}

record_failure() {
  printf 'FAIL high-core-validation-pressure-dashboard %s\n' "$1" >&2
  failures=$((failures + 1))
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.high-core-validation-pressure-dashboard-contract.v2"
    and .bead_id == "bd-f7zfw"
    and .surface_id == "high_core_validation_pressure_dashboard"
    and (.required_inputs | sort) == ([
      "br_readiness_json",
      "mail_health_json",
      "process_counts_json",
      "proof_shard_plan_json",
      "rch_jobs_json",
      "resource_envelope_json"
    ] | sort)
    and (.emitted_artifacts | sort) == ([
      "commands.txt",
      "events.jsonl",
      "high_core_validation_pressure_dashboard.json",
      "high_core_validation_pressure_dashboard.md"
    ] | sort)
    and .mutation_policy.mutates_live_queues == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .rch_policy.local_cargo_allowed == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq "run_rch_proof" "$docs_path" \
    && grep -Fq "run_cheap_local_non_cargo_checks" "$docs_path" \
    && grep -Fq "split_file_blocker_bead" "$docs_path" \
    && grep -Fq "RCH_PRIORITY=low RCH_VISIBILITY=summary rch exec -- env" "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.high-core-validation-pressure-dashboard-fixtures.v2"
    and ([.cases[].case_id] | sort) == ([
      "degraded_mail_fixture",
      "idle_host_fixture",
      "local_cargo_contention_fixture",
      "saturated_rch_fixture",
      "zero_ready_beads_fixture"
    ] | sort)
    and any(.cases[]; .case_id == "idle_host_fixture" and .expected.recommendation == "run_rch_proof")
    and any(.cases[]; .case_id == "saturated_rch_fixture" and .expected.recommendation == "wait")
    and any(.cases[]; .case_id == "local_cargo_contention_fixture" and .expected.reason_code == "HCVD2-LOCAL-CARGO-CONTENTION")
    and any(.cases[]; .case_id == "zero_ready_beads_fixture" and .expected.reason_code == "HCVD2-ZERO-READY-BEADS")
    and any(.cases[]; .case_id == "degraded_mail_fixture" and .expected.reason_code == "HCVD2-MAIL-DEGRADED")
  ' "$fixtures_path" >/dev/null
}

write_json_field() {
  local case_json="$1"
  local field="$2"
  local path="$3"
  jq ".${field}" <<<"$case_json" >"$path"
}

canonicalize_dashboard() {
  local dashboard_path="$1"
  local tmp_root="$2"

  jq -S --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "object" then
        with_entries(.value |= scrub)
      elif type == "array" then
        map(scrub)
      elif type == "string" then
        split($tmp_root) | join("[SMOKE_ROOT]")
      else
        .
      end;
    scrub
  ' "$dashboard_path"
}

assert_case_golden() {
  local case_id="$1"
  local dashboard_path="$2"
  local tmp_root="$3"
  local actual_path="${tmp_root}/${case_id}.actual.golden"
  local golden_path="${golden_dir}/high_core_validation_pressure_dashboard_${case_id}.golden"

  canonicalize_dashboard "$dashboard_path" "$tmp_root" >"$actual_path"
  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    mkdir -p "$golden_dir"
    cp "$actual_path" "$golden_path"
    record_pass "updated golden ${case_id}"
    return
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "missing golden ${golden_path}"
    return
  fi
  if ! diff -u "$golden_path" "$actual_path"; then
    record_failure "golden drift ${case_id}; set UPDATE_GOLDENS=1 only after reviewing the diff"
    return
  fi
  record_pass "golden matches ${case_id}"
}

run_case() {
  local case_id="$1"
  local case_json tmpdir output_dir status dashboard expected_recommendation expected_pressure expected_reason

  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing case ${case_id}"
    return
  fi

  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  mkdir -p "$output_dir"
  write_json_field "$case_json" "resource_envelope_json" "${tmpdir}/resource_envelope.json"
  write_json_field "$case_json" "rch_jobs_json" "${tmpdir}/rch_jobs.json"
  write_json_field "$case_json" "process_counts_json" "${tmpdir}/process_counts.json"
  write_json_field "$case_json" "proof_shard_plan_json" "${tmpdir}/proof_shard_plan.json"
  write_json_field "$case_json" "br_readiness_json" "${tmpdir}/br_readiness.json"
  write_json_field "$case_json" "mail_health_json" "${tmpdir}/mail_health.json"

  expected_recommendation="$(jq -r '.expected.recommendation' <<<"$case_json")"
  expected_pressure="$(jq -r '.expected.pressure_level' <<<"$case_json")"
  expected_reason="$(jq -r '.expected.reason_code // ""' <<<"$case_json")"

  set +e
  "$dashboard_script" \
    --resource-envelope-json "${tmpdir}/resource_envelope.json" \
    --rch-jobs-json "${tmpdir}/rch_jobs.json" \
    --process-counts-json "${tmpdir}/process_counts.json" \
    --proof-shard-plan-json "${tmpdir}/proof_shard_plan.json" \
    --br-readiness-json "${tmpdir}/br_readiness.json" \
    --mail-health-json "${tmpdir}/mail_health.json" \
    --case-id "$case_id" \
    --source-revision "fixture-${case_id}" \
    --output-dir "$output_dir" \
    >/dev/null 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$status" -ne 0 ]]; then
    printf 'expected exit 0 for %s, got %s\n' "$case_id" "$status" >&2
    cat "${tmpdir}/stderr.log" >&2
    record_failure "unexpected exit ${case_id}"
    return
  fi

  dashboard="${output_dir}/high_core_validation_pressure_dashboard.json"
  [[ -f "$dashboard" ]] || { record_failure "missing dashboard ${case_id}"; return; }
  [[ -f "${output_dir}/high_core_validation_pressure_dashboard.md" ]] || { record_failure "missing markdown ${case_id}"; return; }
  [[ -f "${output_dir}/commands.txt" ]] || { record_failure "missing commands ${case_id}"; return; }
  [[ -f "${output_dir}/events.jsonl" ]] || { record_failure "missing events ${case_id}"; return; }

  jq -e \
    --arg recommendation "$expected_recommendation" \
    --arg pressure "$expected_pressure" '
      .schema_version == "franken-engine.high-core-validation-pressure-dashboard.v2"
      and .bead_id == "bd-f7zfw"
      and .recommendation == $recommendation
      and .pressure_level == $pressure
      and .mutation_policy.advisory_only == true
      and .mutation_policy.mutates_live_queues == false
      and .mutation_policy.runs_cargo == false
      and .mutation_policy.runs_rch == false
      and .mutation_policy.queries_live_processes == false
      and .mutation_policy.queries_live_workers == false
      and (.recommended_commands | length) > 0
    ' "$dashboard" >/dev/null || record_failure "dashboard mismatch ${case_id}"

  if [[ -n "$expected_reason" ]]; then
    jq -e --arg code "$expected_reason" '
      any(.pressure_reasons[]?; .code == $code)
    ' "$dashboard" >/dev/null || record_failure "missing reason ${expected_reason} ${case_id}"
  fi

  if [[ "$case_id" == "idle_host_fixture" ]]; then
    jq -e '
      .recommended_commands[0]
      | startswith("RCH_PRIORITY=low RCH_VISIBILITY=summary rch exec -- env")
    ' "$dashboard" >/dev/null || record_failure "idle host missing rch proof command"
  fi
  if [[ "$case_id" == "local_cargo_contention_fixture" ]]; then
    jq -e '
      .recommended_commands
      | all(.[]; contains("cargo check") | not)
    ' "$dashboard" >/dev/null || record_failure "local contention recommended cargo"
  fi
  assert_case_golden "$case_id" "$dashboard" "$tmpdir"
  record_pass "$case_id"
}

run_check() {
  jq empty "$contract_path" "$fixtures_path"
  bash -n "$dashboard_script" "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$dashboard_script" "${BASH_SOURCE[0]}"
  fi
  contract_shape_ok || record_failure "contract shape"
  docs_shape_ok || record_failure "docs shape"
  fixtures_shape_ok || record_failure "fixture shape"
  if [[ "$failures" -ne 0 ]]; then
    exit 1
  fi
  record_pass "check"
}

run_selftest() {
  run_check
  while IFS= read -r case_id; do
    run_case "$case_id"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")
  if [[ "$failures" -ne 0 ]]; then
    exit 1
  fi
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
    printf 'Usage: ./scripts/e2e/high_core_validation_pressure_dashboard_smoke.sh [check|selftest]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
