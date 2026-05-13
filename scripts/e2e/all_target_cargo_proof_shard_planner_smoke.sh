#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner_script="${root_dir}/scripts/all_target_cargo_proof_shard_planner.sh"
docs_path="${root_dir}/docs/ALL_TARGET_CARGO_PROOF_SHARD_PLANNER.md"
contract_path="${root_dir}/docs/all_target_cargo_proof_shard_planner_contract_v1.json"
fixtures_path="${ALL_TARGET_CARGO_PROOF_SHARD_FIXTURES:-${root_dir}/scripts/testdata/all_target_cargo_proof_shard_planner/cases.json}"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS all-target-cargo-proof-shard-planner %s\n' "$1"
}

record_failure() {
  printf 'FAIL all-target-cargo-proof-shard-planner %s\n' "$1" >&2
  failures=$((failures + 1))
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.all-target-cargo-proof-shard-planner-contract.v1"
    and .bead_id == "bd-j3lwi"
    and (.lanes | sort) == ["bin_test","check","clippy","doctest","integration_test","lib_test"]
    and .command_policy.required_prefix == "rch exec -- env CARGO_TARGET_DIR="
    and .command_policy.worker_selection_preflight_required == true
    and .command_policy.worker_pressure_snapshot_required == true
    and .command_policy.critical_worker_pressure_is_fail_closed == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq "never runs Cargo" "$docs_path" \
    && grep -Fq "RCH-wrapped proof command shards" "$docs_path" \
    && grep -Fq "local-fallback transcripts fail closed" "$docs_path" \
    && grep -Fq "preflight.diagnose_command" "$docs_path" \
    && grep -Fq "critical pressure" "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.all-target-cargo-proof-shard-planner-fixtures.v1"
    and ([.cases[].case_id] | sort) == ([
      "clippy_only_lint_fixture",
      "fixture_workspace_targets",
      "malformed_metadata_fixture",
      "stale_target_fixture"
    ] | sort)
    and any(.cases[]; .case_id == "fixture_workspace_targets" and .expected.shard_count == 6)
    and any(.cases[]; .case_id == "clippy_only_lint_fixture" and .expected.clippy_prior_failure_matches == 1)
    and any(.cases[]; .case_id == "malformed_metadata_fixture" and .expected.required_reason_code == "FE-IW3-SHARD-MALFORMED-METADATA")
    and any(.cases[]; .case_id == "stale_target_fixture" and .expected.required_reason_code == "FE-IW3-SHARD-STALE-TARGET")
  ' "$fixtures_path" >/dev/null
}

run_case() {
  local case_id="$1"
  local case_json tmpdir output_dir status expected_exit expected_decision expected_shards expected_stale expected_reason expected_lanes
  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing case ${case_id}"
    return
  fi

  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  mkdir -p "$output_dir"
  jq '.cargo_metadata_json' <<<"$case_json" >"${tmpdir}/cargo_metadata.json"
  jq '.prior_rch_failures_json' <<<"$case_json" >"${tmpdir}/prior_rch_failures.json"

  expected_decision="$(jq -r '.expected.decision' <<<"$case_json")"
  expected_shards="$(jq -r '.expected.shard_count' <<<"$case_json")"
  expected_stale="$(jq -r '.expected.stale_diagnostics' <<<"$case_json")"
  expected_reason="$(jq -r '.expected.required_reason_code // ""' <<<"$case_json")"
  expected_lanes="$(jq -c '.expected.lanes // []' <<<"$case_json")"
  if [[ "$expected_decision" == "fail_closed" ]]; then
    expected_exit=42
  else
    expected_exit=0
  fi

  set +e
  "$planner_script" \
    --cargo-metadata-json "${tmpdir}/cargo_metadata.json" \
    --prior-rch-failures-json "${tmpdir}/prior_rch_failures.json" \
    --case-id "$case_id" \
    --source-revision "smoke-${case_id}" \
    --output-dir "$output_dir" \
    >/dev/null 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    printf 'expected exit %s for %s, got %s\n' "$expected_exit" "$case_id" "$status" >&2
    cat "${tmpdir}/stderr.log" >&2
    record_failure "unexpected exit ${case_id}"
    return
  fi

  local manifest="${output_dir}/shard_manifest.json"
  [[ -f "$manifest" ]] || { record_failure "missing manifest ${case_id}"; return; }
  [[ -f "${output_dir}/commands.txt" ]] || { record_failure "missing commands ${case_id}"; return; }
  [[ -f "${output_dir}/commands.jsonl" ]] || { record_failure "missing commands jsonl ${case_id}"; return; }
  [[ -f "${output_dir}/stale_target_diagnostics.jsonl" ]] || { record_failure "missing stale diagnostics ${case_id}"; return; }
  [[ -f "${output_dir}/events.jsonl" ]] || { record_failure "missing events ${case_id}"; return; }
  [[ -f "${output_dir}/report.md" ]] || { record_failure "missing report ${case_id}"; return; }

  jq -e \
    --arg decision "$expected_decision" \
    --argjson shards "$expected_shards" \
    --argjson stale "$expected_stale" \
    --argjson lanes "$expected_lanes" '
      .schema_version == "franken-engine.all-target-cargo-proof-shard-manifest.v1"
      and .decision == $decision
      and .shard_count == $shards
      and (.stale_target_diagnostics | length) == $stale
      and (if ($lanes | length) == 0 then true else (.lanes | sort) == ($lanes | sort) end)
      and all(.shards[]?; (.command | test("^rch exec -- env CARGO_TARGET_DIR=")) and (.command | contains(" cargo ")) and .rch_policy.direct_rch_exec == true and .rch_policy.requires_cargo_target_dir == true)
      and all(.shards[]?; (.preflight.diagnose_command | test("^rch diagnose --json -- env CARGO_TARGET_DIR=")) and .preflight.worker_status_command == "rch --json status --workers --jobs")
      and all(.shards[]?; .rch_policy.requires_worker_selection_preflight == true and .rch_policy.requires_worker_pressure_snapshot == true and .rch_policy.rejects_critical_worker_pressure == true)
      and .mutation_policy.runs_cargo == false
      and .mutation_policy.runs_rch == false
      and .mutation_policy.mutates_br == false
      and .mutation_policy.sends_agent_mail == false
    ' "$manifest" >/dev/null || record_failure "manifest mismatch ${case_id}"
  if [[ -n "$expected_reason" ]]; then
    jq -e --arg code "$expected_reason" 'any((.degraded_reasons + .fail_closed_reasons)[]?; .code == $code)' "$manifest" >/dev/null \
      || record_failure "missing reason ${expected_reason} ${case_id}"
  fi
  if [[ "$case_id" == "clippy_only_lint_fixture" ]]; then
    jq -e 'any(.shards[]; .lane == "clippy" and .prior_failure_matches == 1)' "$manifest" >/dev/null \
      || record_failure "missing clippy prior failure match"
  fi
  record_pass "$case_id"
}

run_check() {
  jq empty "$contract_path" "$fixtures_path"
  bash -n "$planner_script" "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$planner_script" "${BASH_SOURCE[0]}"
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
    printf 'Usage: ./scripts/e2e/all_target_cargo_proof_shard_planner_smoke.sh [check|selftest]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
