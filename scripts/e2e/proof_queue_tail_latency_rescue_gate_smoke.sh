#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate_script="${root_dir}/scripts/proof_queue_tail_latency_rescue_gate.sh"
docs_path="${root_dir}/docs/PROOF_QUEUE_TAIL_LATENCY_RESCUE_GATE.md"
contract_path="${root_dir}/docs/proof_queue_tail_latency_rescue_gate_contract_v1.json"
fixtures_path="${PROOF_QUEUE_TAIL_LATENCY_RESCUE_FIXTURES:-${root_dir}/scripts/testdata/proof_queue_tail_latency_rescue_gate/cases.json}"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS proof-queue-tail-latency-rescue %s\n' "$1"
}

record_failure() {
  printf 'FAIL proof-queue-tail-latency-rescue %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/proof_queue_tail_latency_rescue_gate_smoke.sh [check|selftest]
EOF
}

check_no_bare_heavy_cargo() {
  local path="$1"
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$command" != *"rch exec --"* || "$command" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "${path#"$root_dir"/} has bare heavy Cargo command: ${command}"
      fi
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,240p' "$path")
}

check_no_mutation_words() {
  local path="$1"
  if grep -Eiq 'automatically mutates|automatically releases|automatically closes|sends Agent Mail automatically|repairs Agent Mail automatically|changes live queue policy' "$path"; then
    record_failure "${path#"$root_dir"/} contains forbidden mutation wording"
  fi
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.proof-queue-tail-latency-rescue-gate-contract.v1"
    and .bead_id == "bd-ciutb"
    and .implementation_script == "scripts/proof_queue_tail_latency_rescue_gate.sh"
    and .smoke_script == "scripts/e2e/proof_queue_tail_latency_rescue_gate_smoke.sh"
    and (.required_artifacts | index("run_manifest.json") != null)
    and (.required_artifacts | index("tail_latency_rescue_receipt.json") != null)
    and (.required_artifacts | index("brownout_detector/brownout_report.json") != null)
    and ([.required_fixture_cases[]] | sort) == (["all_workers_busy","counterfactual_all_policies_brownout","healthy","low_priority_starvation","unfair_agent_slot_share"] | sort)
    and ([.required_detection_codes[]] | sort) == (["counterfactual_all_policies_brownout","low_priority_starvation","queue_brownout_all_workers_busy","unfair_agent_slot_share"] | sort)
    and .mutation_policy.advisory_only == true
    and .mutation_policy.mutates_live_workers == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.changes_live_queue_policy == false
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.proof-queue-tail-latency-rescue-gate-fixtures.v1"
    and ([.cases[].case_id] | sort) == (["all_workers_busy","counterfactual_all_policies_brownout","healthy","low_priority_starvation","unfair_agent_slot_share"] | sort)
    and all(.cases[]; .sources.replay_trace_json.schema_version == "franken-engine.proof-economy-replay-trace.v1")
    and all(.cases[]; .sources.counterfactual_report_json.schema_version == "franken-engine.proof-economy-counterfactual-replay-report.v1")
    and all(.cases[]; .sources.tail_latency_report_json.schema_version == "franken-engine.tail-latency-control-plane.v1")
  ' "$fixtures_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq "proof_queue_brownout_starvation_detector.sh" "$docs_path" \
    && grep -Fq "never mutates live workers" "$docs_path" \
    && grep -Fq "queue_brownout_all_workers_busy" "$docs_path" \
    && grep -Fq "counterfactual_all_policies_brownout" "$docs_path" \
    && grep -Fq "tail_latency_rescue_receipt.json" "$docs_path"
}

run_case() {
  local case_id="$1"
  local case_json tmpdir output_dir expected_exit expected_decision required_code status
  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing case ${case_id}"
    return
  fi

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/proof-queue-tail-rescue.XXXXXX")"
  output_dir="${tmpdir}/out"
  mkdir -p "$output_dir"
  jq '.sources.replay_trace_json' <<<"$case_json" >"${tmpdir}/replay_trace.json"
  jq '.sources.counterfactual_report_json' <<<"$case_json" >"${tmpdir}/counterfactual_report.json"
  jq '.sources.tail_latency_report_json' <<<"$case_json" >"${tmpdir}/tail_latency_report.json"

  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"
  expected_decision="$(jq -r '.expected.decision' <<<"$case_json")"
  required_code="$(jq -r '.expected.required_code // ""' <<<"$case_json")"

  set +e
  "$gate_script" \
    --replay-trace-json "${tmpdir}/replay_trace.json" \
    --counterfactual-report-json "${tmpdir}/counterfactual_report.json" \
    --tail-latency-report-json "${tmpdir}/tail_latency_report.json" \
    --max-agent-share-millionths "$(jq -r '.max_agent_share_millionths' <<<"$case_json")" \
    --source-revision "smoke-${case_id}" \
    --generated-epoch-seconds 1800000000 \
    --output-dir "$output_dir" >/dev/null 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    cat "${tmpdir}/stderr.log" >&2
    record_failure "case ${case_id} expected exit ${expected_exit}, got ${status}"
  fi

  for artifact in run_manifest.json tail_latency_rescue_receipt.json events.jsonl commands.txt report.md brownout_detector/brownout_report.json; do
    [[ -f "${output_dir}/${artifact}" ]] || record_failure "case ${case_id} missing ${artifact}"
  done

  local receipt="${output_dir}/tail_latency_rescue_receipt.json"
  jq -e --arg decision "$expected_decision" '.decision == $decision' "$receipt" >/dev/null \
    || record_failure "case ${case_id} decision mismatch"
  jq -e '.mutation_policy.advisory_only == true and .mutation_policy.mutates_live_workers == false and .mutation_policy.mutates_br == false and .mutation_policy.sends_agent_mail == false and .mutation_policy.releases_reservations == false and .mutation_policy.runs_cargo == false and .mutation_policy.runs_rch == false' "$receipt" >/dev/null \
    || record_failure "case ${case_id} unsafe mutation policy"
  jq -e 'all(.rescue_recommendations[]?; (.cause | type) == "string" and (.affected_agents | type) == "array" and (.affected_beads | type) == "array" and (.fairness_evidence | type) == "object" and (.proposed_bounded_action | type) == "object" and .proposed_bounded_action.mutates_live_state == false)' "$receipt" >/dev/null \
    || record_failure "case ${case_id} receipt field shape mismatch"
  if [[ -n "$required_code" ]]; then
    jq -e --arg code "$required_code" 'any(.rescue_recommendations[]?; .cause == $code)' "$receipt" >/dev/null \
      || record_failure "case ${case_id} missing recommendation ${required_code}"
  else
    jq -e '(.rescue_recommendations | length) == 0' "$receipt" >/dev/null \
      || record_failure "case ${case_id} expected no recommendations"
  fi
  jq -e '.tail_latency_context.state == "captured"' "$receipt" >/dev/null \
    || record_failure "case ${case_id} missing captured tail-latency context"
  grep -Fq "./scripts/proof_queue_brownout_starvation_detector.sh" "${output_dir}/commands.txt" \
    || record_failure "case ${case_id} commands missing detector invocation"

  record_pass "$case_id"
}

run_check() {
  jq empty "$contract_path" "$fixtures_path"
  bash -n "$gate_script" "${BASH_SOURCE[0]}"
  contract_shape_ok || record_failure "contract shape"
  fixtures_shape_ok || record_failure "fixture shape"
  docs_shape_ok || record_failure "docs shape"
  check_no_mutation_words "$docs_path"
  check_no_mutation_words "$contract_path"
  check_no_mutation_words "$fixtures_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$contract_path"
  check_no_bare_heavy_cargo "$fixtures_path"
  check_no_bare_heavy_cargo "$gate_script"
  check_no_bare_heavy_cargo "${BASH_SOURCE[0]}"

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
  for code in queue_brownout_all_workers_busy unfair_agent_slot_share low_priority_starvation counterfactual_all_policies_brownout; do
    jq -e --arg code "$code" 'any(.cases[]; .expected.required_code == $code)' "$fixtures_path" >/dev/null \
      || { record_failure "selftest missing ${code}"; exit 1; }
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
