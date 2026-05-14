#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
producer="${root_dir}/scripts/optimization_promotion_replay_drill.sh"
fixtures_path="${OPTIMIZATION_PROMOTION_REPLAY_DRILL_FIXTURES:-${root_dir}/scripts/testdata/optimization_promotion_replay_drill/cases.json}"
contract_path="${root_dir}/docs/optimization_promotion_replay_drill_contract_v1.json"
docs_path="${root_dir}/docs/OPTIMIZATION_PROMOTION_REPLAY_DRILL.md"
mode="${1:-check}"
failures=0

usage() {
  cat >&2 <<'USAGE'
Usage: ./scripts/e2e/optimization_promotion_replay_drill_smoke.sh [check|selftest]
USAGE
}

record_pass() {
  printf 'PASS optimization-promotion-replay-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL optimization-promotion-replay-drill %s\n' "$1" >&2
  failures=$((failures + 1))
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.optimization-promotion-replay-drill-contract.v1"
    and .bead_id == "bd-xbesa"
    and .parent_bead_id == "bd-xg3d6"
    and ((["bd-sisok","bd-4j2ck","bd-or2e1","bd-jp4r0","bd-yo0eh"] - .depends_on) | length) == 0
    and .script == "scripts/optimization_promotion_replay_drill.sh"
    and .smoke_script == "scripts/e2e/optimization_promotion_replay_drill_smoke.sh"
    and .docs == "docs/OPTIMIZATION_PROMOTION_REPLAY_DRILL.md"
    and .fixture_bundle == "scripts/testdata/optimization_promotion_replay_drill/cases.json"
    and (([
      "promotable_evidence",
      "stale_evidence",
      "transfer_refusal",
      "rollback_demotion",
      "synthetic_contamination",
      "missing_artifact_fail_closed"
    ] - .covered_cases) | length) == 0
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.mutates_runtime_policy == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.publishes_benchmark_claims == false
    and (.selftest_cases | length) == 6
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.optimization-promotion-replay-drill-fixtures.v1"
    and .base.real_hot_path_bundle == "scripts/testdata/real_hot_path_proof_contract/valid/run_manifest.json"
    and (.cases | length) == 6
    and ([.cases[].case_id] | unique | length) == 6
    and all(.cases[]; (.expected.expected_exit_code | type) == "number" and (.expected.expected_lane_state | type) == "string")
  ' "$fixtures_path" >/dev/null
}

docs_shape_ok() {
  while IFS= read -r required; do
    grep -Fq "$required" "$docs_path" || return 1
  done < <(jq -r '.required_doc_text[]' "$contract_path")
}

validate_run_outputs() {
  local case_id="$1"
  local run_dir="$2"
  local expected_json="$3"
  local manifest="${run_dir}/run_manifest.json"

  for artifact in "$manifest" "${run_dir}/events.jsonl" "${run_dir}/commands.txt" "${run_dir}/trace_ids.json" "${run_dir}/report.md"; do
    [[ -s "$artifact" ]] || record_failure "${case_id} missing $(basename "$artifact")"
  done

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.optimization-promotion-replay-drill.run-manifest.v1"
    and .bead_id == "bd-xbesa"
    and .parent_bead_id == "bd-xg3d6"
    and .case_id == $expected[0].case_id
    and .lane_state == $expected[0].expected_lane_state
    and ((.stage_results // []) | type) == "array"
    and (.mutation_policy.runs_cargo // false) == false
    and (.mutation_policy.runs_rch // false) == false
  ' "$manifest" >/dev/null || record_failure "${case_id} manifest mismatch"

  required_error="$(jq -r '.required_error_code // ""' "$expected_json")"
  if [[ -n "$required_error" ]]; then
    jq -e --arg required_error "$required_error" '.error_code == $required_error or (.truth_gate.violations | map(.code) | index($required_error) != null)' "$manifest" >/dev/null \
      || record_failure "${case_id} missing error code ${required_error}"
  fi

  if [[ "$(jq -r '.expected_replay_exit_code // empty' "$expected_json")" != "" ]]; then
    replay_dir="${run_dir}/replay"
    set +e
    "$producer" --mode replay --manifest-json "$manifest" --output-dir "$replay_dir" --source-revision "replay-${case_id}" >/dev/null 2>"${run_dir}/replay.stderr"
    replay_exit="$?"
    set -e
    expected_replay="$(jq -r '.expected_replay_exit_code' "$expected_json")"
    if [[ "$replay_exit" != "$expected_replay" ]]; then
      record_failure "${case_id} replay expected ${expected_replay} got ${replay_exit}"
    fi
    jq -e '.mode == "replay" and .decision == "pass" and .verified_stage_count >= 5' "${replay_dir}/run_manifest.json" >/dev/null \
      || record_failure "${case_id} replay manifest mismatch"
  fi
}

case "$mode" in
  check|selftest) ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage
    exit 64
    ;;
esac

if contract_shape_ok; then
  record_pass "contract shape"
else
  record_failure "contract shape"
fi
if fixtures_shape_ok; then
  record_pass "fixtures shape"
else
  record_failure "fixtures shape"
fi
if docs_shape_ok; then
  record_pass "docs required text"
else
  record_failure "docs required text"
fi

if [[ "$mode" == "selftest" ]]; then
  work_dir="$(mktemp -d "${TMPDIR:-/tmp}/optimization-promotion-replay-drill-smoke.XXXXXX")"
  while IFS= read -r case_id; do
    case_dir="${work_dir}/${case_id}"
    mkdir -p "$case_dir"
    expected_json="${case_dir}/expected.json"
    jq --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | (.expected + {case_id:$case_id})' "$fixtures_path" >"$expected_json"
    expected_exit="$(jq -r '.expected_exit_code' "$expected_json")"
    set +e
    "$producer" --mode run --case "$case_id" --fixtures-json "$fixtures_path" --source-revision "smoke-${case_id}" --output-dir "${case_dir}/out" >/dev/null 2>"${case_dir}/stderr.txt"
    actual_exit="$?"
    set -e
    if [[ "$actual_exit" != "$expected_exit" ]]; then
      record_failure "${case_id} expected exit ${expected_exit} got ${actual_exit}"
    fi
    validate_run_outputs "$case_id" "${case_dir}/out" "$expected_json"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")
fi

if [[ "$failures" -ne 0 ]]; then
  printf 'optimization promotion replay drill smoke failed with %s failure(s)\n' "$failures" >&2
  exit 1
fi

printf 'optimization promotion replay drill smoke %s passed\n' "$mode"
