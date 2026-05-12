#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tower_script="${root_dir}/scripts/proof_economy_control_tower.sh"
docs_path="${root_dir}/docs/PROOF_ECONOMY_CONTROL_TOWER.md"
contract_path="${root_dir}/docs/proof_economy_control_tower_contract_v1.json"
fixtures_path="${PROOF_ECONOMY_CONTROL_TOWER_FIXTURES:-${root_dir}/scripts/testdata/proof_economy_control_tower/cases.json}"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS proof-economy-control-tower %s\n' "$1"
}

record_failure() {
  printf 'FAIL proof-economy-control-tower %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/proof_economy_control_tower_smoke.sh [check|selftest]
EOF
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'automatically mutates|automatically closes|automatically claims|queries live Agent Mail automatically|runs Cargo automatically|runs rch automatically|changes live queue policy' "$path"; then
    record_failure "${path#"$root_dir"/} contains forbidden mutation wording"
  fi
}

check_no_bare_heavy_cargo() {
  local path="$1"
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$command" != *"rch exec --"* || "$command" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "${path#"$root_dir"/} has bare heavy Cargo command: ${command}"
      fi
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,260p' "$path")
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.proof-economy-control-tower-contract.v1"
    and .bead_id == "bd-i36b4"
    and .operator_entrypoint == "scripts/proof_economy_control_tower.sh"
    and .smoke_script == "scripts/e2e/proof_economy_control_tower_smoke.sh"
    and ([.required_fixture_cases[]] | sort) == (["degraded_refresh_advisory","fail_closed_component","pass_all_components"] | sort)
    and (.component_inputs | length) == 3
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.queries_live_agent_mail == false
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.proof-economy-control-tower-fixtures.v1"
    and ([.cases[].case_id] | sort) == (["degraded_refresh_advisory","fail_closed_component","pass_all_components"] | sort)
    and any(.cases[]; .expected.decision == "pass")
    and any(.cases[]; .expected.decision == "degraded")
    and any(.cases[]; .expected.decision == "fail_closed")
  ' "$fixtures_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq "./scripts/proof_economy_control_tower.sh" "$docs_path" \
    && grep -Fq -- "--proof-reuse-admission-json" "$docs_path" \
    && grep -Fq -- "--tail-latency-rescue-json" "$docs_path" \
    && grep -Fq -- "--agent-run-evidence-index-json" "$docs_path" \
    && grep -Fq "read-only" "$docs_path"
}

help_shape_ok() {
  local help
  help="$("$tower_script" --help 2>&1)"
  grep -Fq "Compose proof-economy control tower evidence for operator review." <<<"$help" \
    && grep -Fq -- "--proof-reuse-admission-json" <<<"$help" \
    && grep -Fq -- "--tail-latency-rescue-json" <<<"$help" \
    && grep -Fq -- "--agent-run-evidence-index-json" <<<"$help" \
    && grep -Fq "read-only" <<<"$help"
}

write_inputs() {
  local case_json="$1"
  local dir="$2"
  local reuse_decision tail_decision evidence_decision
  reuse_decision="$(jq -r '.proof_reuse_decision' <<<"$case_json")"
  tail_decision="$(jq -r '.tail_latency_decision' <<<"$case_json")"
  evidence_decision="$(jq -r '.agent_evidence_decision' <<<"$case_json")"

  jq -n --arg decision "$reuse_decision" '{
    schema_version:"franken-engine.proof-reuse-admission-bundle.v1",
    source_revision:"fixture-rev",
    expected_source_revision:"fixture-rev",
    admission_decision:$decision,
    admission_rows:[
      {artifact_id:"artifact-fixture", classification:(if $decision == "admit_reuse" then "reusable" elif $decision == "fail_closed" then "invalid" else "refresh_required" end), admission_allowed:($decision == "admit_reuse")}
    ],
    summary:{edge_count:1}
  }' >"${dir}/proof_reuse_admission.json"

  jq -n --arg decision "$tail_decision" '{
    schema_version:"franken-engine.proof-queue-tail-latency-rescue-receipt.v1",
    source_revision:"fixture-rev",
    decision:$decision,
    tail_latency_context:{state:"captured"},
    rescue_recommendations:(if $decision == "healthy" then [] else [{cause:"fixture", severity:"warning"}] end)
  }' >"${dir}/tail_latency_rescue.json"

  jq -n --arg decision "$evidence_decision" '{
    schema_version:"franken-engine.agent-run-evidence-index.v1",
    bead_id:"bd-run",
    agent_name:"AgentAlpha",
    source_revision:"fixture-rev",
    decision:$decision,
    summary:{edge_count:6, missing_edge_count:(if $decision == "fail_closed" then 1 else 0 end), degraded_edge_count:(if $decision == "degraded" then 1 else 0 end)},
    fail_closed_reasons:(if $decision == "fail_closed" then [{code:"fixture_fail_closed"}] else [] end),
    degraded_reasons:(if $decision == "degraded" then [{code:"fixture_degraded"}] else [] end)
  }' >"${dir}/agent_run_evidence_index.json"
}

run_case() {
  local case_id="$1"
  local case_json tmpdir output_dir expected_exit expected_decision actual_exit output
  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing case ${case_id}"
    return
  fi

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/proof-economy-control-tower.XXXXXX")"
  output_dir="${tmpdir}/out"
  write_inputs "$case_json" "$tmpdir"

  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"
  expected_decision="$(jq -r '.expected.decision' <<<"$case_json")"

  set +e
  output="$(
    "$tower_script" \
      --proof-reuse-admission-json "${tmpdir}/proof_reuse_admission.json" \
      --tail-latency-rescue-json "${tmpdir}/tail_latency_rescue.json" \
      --agent-run-evidence-index-json "${tmpdir}/agent_run_evidence_index.json" \
      --source-revision "smoke-${case_id}" \
      --output-dir "$output_dir" 2>&1
  )"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return
  fi

  for artifact in proof_economy_control_tower_report.json events.jsonl commands.txt report.md; do
    [[ -f "${output_dir}/${artifact}" ]] || record_failure "${case_id} missing ${artifact}"
  done

  local report="${output_dir}/proof_economy_control_tower_report.json"
  jq -e --arg decision "$expected_decision" '.decision == $decision' "$report" >/dev/null \
    || record_failure "${case_id} decision mismatch"
  jq -e '(.components | length == 3) and all(.components[]; (.component_id | length) > 0 and (.evidence_path | length) > 0)' "$report" >/dev/null \
    || record_failure "${case_id} component shape mismatch"
  jq -e '.mutation_policy.advisory_only == true and .mutation_policy.runs_cargo == false and .mutation_policy.runs_rch == false and .mutation_policy.queries_live_agent_mail == false and .mutation_policy.mutates_br == false' "$report" >/dev/null \
    || record_failure "${case_id} unsafe mutation policy"

  record_pass "$case_id"
}

run_check() {
  jq empty "$contract_path" "$fixtures_path"
  bash -n "$tower_script" "${BASH_SOURCE[0]}"
  contract_shape_ok || record_failure "contract shape"
  fixtures_shape_ok || record_failure "fixture shape"
  docs_shape_ok || record_failure "docs shape"
  help_shape_ok || record_failure "help shape"
  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$contract_path"
  check_no_bare_heavy_cargo "$tower_script"

  local case_id
  while IFS= read -r case_id; do
    run_case "$case_id"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")

  if [[ "$failures" -ne 0 ]]; then
    exit 1
  fi
  record_pass "check"
}

run_selftest() {
  run_check
  for expected in pass degraded fail_closed; do
    jq -e --arg expected "$expected" 'any(.cases[]; .expected.decision == $expected)' "$fixtures_path" >/dev/null \
      || { record_failure "selftest missing ${expected}"; exit 1; }
  done
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
    exit 64
    ;;
esac
