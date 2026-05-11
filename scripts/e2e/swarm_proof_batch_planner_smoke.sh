#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${root_dir}/scripts/swarm_proof_batch_planner.sh"
contract_path="${root_dir}/docs/swarm_proof_batch_planner_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_PROOF_BATCH_PLANNER.md"
cases_path="${root_dir}/scripts/testdata/swarm_proof_batch_planner/cases.json"
golden_dir="${SWARM_PROOF_BATCH_PLANNER_GOLDEN_DIR:-${root_dir}/scripts/testdata/goldens}"
mode="${1:-check}"
output_root="${2:-${SWARM_PROOF_BATCH_PLANNER_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-proof-batch-planner-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS swarm-proof-batch-planner %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-proof-batch-planner %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_proof_batch_planner_smoke.sh [check|selftest] [output_root]
EOF
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-batch-planner-contract.v1"
    and .bead_id == "bd-ua5n2.5"
    and (.actions | sort) == ["coalesce", "human_review", "keep_isolated", "rerun_later", "rerun_now", "reuse"]
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.mutates_remote_workers == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'never runs Cargo or RCH' "$docs_path" \
    && grep -Fq 'coalesce' "$docs_path" \
    && grep -Fq 'Warm-cache recommendations are advisory only' "$docs_path" \
    && grep -Fq 'rollback note' "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-batch-planner-fixtures.v1"
    and (.cases | length) == 7
    and ([.cases[].expected_actions[]] | unique | sort) == ["coalesce", "human_review", "keep_isolated", "rerun_later", "rerun_now", "reuse"]
  ' "$cases_path" >/dev/null
}

script_static_ok() {
  bash -n "$script_path"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$script_path" "${BASH_SOURCE[0]}"
  fi
}

expand_case() {
  local case_json="$1"
  jq -n \
    --slurpfile fixtures "$cases_path" \
    --argjson case "$case_json" '
      ($fixtures[0].base_input) as $base_input
      | ($fixtures[0].base_request) as $base_request
      | $base_input
        + $case
        + {
          requests: (
            if ($case.requests // null) != null then
              ($case.requests | map($base_request + .))
            else
              [$base_request]
            end
          )
        }
    '
}

canonicalize_report() {
  local report_path="$1"
  local tmp_root="$2"

  jq --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "string" then
        gsub($tmp_root; "[SMOKE_ROOT]")
        | gsub("/tmp/rch_target_"; "[RCH_TARGET]/")
        | gsub("/tmp/[A-Za-z0-9._-]+"; "[TMP_PATH]")
      elif type == "array" then
        map(scrub)
      elif type == "object" then
        with_entries(.value |= scrub)
      else
        .
      end;
    scrub | .source_revision = "[SOURCE_REVISION]"
  ' "$report_path"
}

assert_case_golden() {
  local case_id="$1"
  local report_path="$2"
  local tmp_root="$3"
  local golden_path="${golden_dir}/swarm_proof_batch_planner_${case_id}.golden"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    mkdir -p "$golden_dir"
    canonicalize_report "$report_path" "$tmp_root" >"$golden_path"
    return
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "${case_id} missing golden"
    return
  fi

  if ! diff -u "$golden_path" <(canonicalize_report "$report_path" "$tmp_root"); then
    record_failure "${case_id} golden drift"
  fi
}

assert_case_output() {
  local case_json="$1"
  local output_dir="$2"
  local plan_path="${output_dir}/batch_plan.json"
  local case_id

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  jq empty "$plan_path" >/dev/null
  test -s "${output_dir}/recommendations.jsonl"
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"

  jq -e \
    --argjson expected_actions "$(jq '.expected_actions' <<<"$case_json")" \
    --argjson expected_reasons "$(jq '.expected_reasons // []' <<<"$case_json")" \
    --arg case_id "$case_id" '
      .schema_version == "franken-engine.swarm-proof-batch-plan.v1"
      and .case_id == $case_id
      and ([.recommendations[].action] == $expected_actions)
      and (if ($expected_reasons | length) > 0 then [.recommendations[].reason] == $expected_reasons else true end)
      and (.plan_hash | test("^[0-9a-f]{64}$"))
      and all(.recommendations[]; (.evidence_paths | length) >= 3 and (.rollback_note | length) >= 20 and (.remediation | length) >= 20)
      and .non_mutation_attestation.runs_cargo == false
      and .non_mutation_attestation.runs_rch == false
      and .non_mutation_attestation.mutates_br == false
      and .non_mutation_attestation.creates_deletes_target_dirs == false
    ' "$plan_path" >/dev/null || record_failure "${case_id} plan mismatch"
}

run_case() {
  local raw_case_json="$1"
  local tmp_root="$2"
  local case_json case_id case_dir fixture_path

  case_json="$(expand_case "$raw_case_json")"
  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${tmp_root}/${case_id}"
  fixture_path="${case_dir}/fixture.json"
  mkdir -p "$case_dir"
  jq '.' <<<"$case_json" >"$fixture_path"

  "$script_path" --fixture-json "$fixture_path" --output-dir "${case_dir}/out" >/dev/null
  assert_case_output "$case_json" "${case_dir}/out"
  assert_case_golden "$case_id" "${case_dir}/out/batch_plan.json" "$tmp_root"
  record_pass "$case_id"
}

goldens_shape_ok() {
  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    return 0
  fi

  while IFS= read -r case_id; do
    local golden_path="${golden_dir}/swarm_proof_batch_planner_${case_id}.golden"
    [[ -f "$golden_path" ]] || { record_failure "${case_id} missing checked-in golden"; continue; }
    jq empty "$golden_path" >/dev/null || record_failure "${case_id} invalid golden json"
  done < <(jq -r '.cases[].case_id' "$cases_path")
}

run_check() {
  jq empty "$contract_path" "$cases_path" >/dev/null
  script_static_ok
  contract_shape_ok || record_failure "contract shape"
  docs_shape_ok || record_failure "docs shape"
  fixtures_shape_ok || record_failure "fixture shape"
  goldens_shape_ok
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  local tmp_root="$1"

  run_check
  if [[ "$failures" -ne 0 ]]; then
    return
  fi
  while IFS= read -r case_json; do
    run_case "$case_json" "$tmp_root"
  done < <(jq -c '.cases[]' "$cases_path")
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest "$output_root"
    ;;
  -h|--help|help)
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
