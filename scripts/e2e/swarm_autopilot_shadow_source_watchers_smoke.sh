#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
watcher="${root_dir}/scripts/swarm_autopilot_shadow_source_watchers.sh"
contract_path="${root_dir}/docs/swarm_autopilot_shadow_source_watchers_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_AUTOPILOT_SHADOW_SOURCE_WATCHERS.md"
fixtures_path="${SWARM_AUTOPILOT_SHADOW_SOURCE_WATCHERS_FIXTURES:-${root_dir}/scripts/testdata/swarm_autopilot_shadow_source_watchers/cases.json}"
mode="${1:-check}"
output_root="${2:-${SWARM_AUTOPILOT_SHADOW_SOURCE_WATCHERS_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-shadow-source-watchers-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS swarm-autopilot-shadow-source-watchers %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-shadow-source-watchers %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_shadow_source_watchers_smoke.sh [check|selftest|run] [output_root]
EOF
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-shadow-source-watchers-contract.v1"
    and .bead_id == "bd-djejh.3"
    and .parent_bead_id == "bd-djejh"
    and .upstream_contract == "docs/swarm_autopilot_shadow_daemon_contract_v1.json"
    and .script == "scripts/swarm_autopilot_shadow_source_watchers.sh"
    and .smoke_script == "scripts/e2e/swarm_autopilot_shadow_source_watchers_smoke.sh"
    and .operator_docs == "docs/SWARM_AUTOPILOT_SHADOW_SOURCE_WATCHERS.md"
    and .fixture_bundle == "scripts/testdata/swarm_autopilot_shadow_source_watchers/cases.json"
    and (([
      "br_queue_snapshot_json",
      "bv_robot_plan_json",
      "agent_mail_snapshot_json",
      "rch_status_snapshot_json",
      "git_state_snapshot_json",
      "artifact_bundle_snapshot_json"
    ] - .required_sources) | length) == 0
    and (([
      "source_snapshots.jsonl",
      "source_snapshot_summary.json",
      "events.jsonl",
      "commands.txt",
      "report.md"
    ] - .output_artifacts) | length) == 0
    and any(.fixture_cases[]; .case_id == "missing_artifact_bundle" and .required_error_code == "FE-SWARM-AUTOPILOT-SHADOW-MISSING-SOURCE")
    and any(.fixture_cases[]; .case_id == "rch_local_fallback_contamination" and .expected_truth_state == "contaminated")
    and any(.fixture_cases[]; .case_id == "contradictory_bead_ownership" and .required_error_code == "FE-SWARM-AUTOPILOT-SHADOW-CONTRADICTORY-OWNERSHIP")
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_git == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-shadow-source-watchers-fixtures.v1"
    and ((["br_queue","bv_robot_plan","agent_mail","rch_status","git_state","artifact_bundles"] - (.base_inputs | keys)) | length) == 0
    and (.cases | length == 6)
    and ([.cases[].case_id] | unique | length == 6)
    and all(.cases[];
      (.expected.truth_state | type) == "string"
      and (.expected.decision | type) == "string"
      and (.expected.expected_exit_code | type) == "number"
      and ((.overrides // {}) | type) == "object"
    )
  ' "$fixtures_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'one-shot source' "$docs_path" \
    && grep -Fq 'does not write the journal' "$docs_path" \
    && grep -Fq 'does not mutate beads' "$docs_path" \
    && grep -Fq 'source_snapshots.jsonl' "$docs_path" \
    && grep -Fq 'exit 42' "$docs_path"
}

check_no_forbidden_claims() {
  local path="$1"
  if grep -Eiq 'mutates beads|releases reservations|sends Agent Mail|runs Cargo|runs rch workloads|mutates workers|changes live queue policy' "$path"; then
    record_failure "${path#"$root_dir"/} contains unsafe mutation wording"
  fi
}

case_omits_source() {
  local case_id="$1"
  local source_key="$2"
  jq -e --arg case_id "$case_id" --arg source_key "$source_key" '
    (.cases[] | select(.case_id == $case_id) | (.omit_sources // []) | index($source_key)) != null
  ' "$fixtures_path" >/dev/null
}

materialize_source() {
  local case_id="$1"
  local source_key="$2"
  local output_path="$3"

  jq --arg case_id "$case_id" --arg source_key "$source_key" '
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | $root.base_inputs[$source_key] * (($case.overrides[$source_key] // {}))
  ' "$fixtures_path" >"$output_path"
}

run_case() {
  local case_json="$1"
  local case_id case_dir input_dir out_dir code expected_code expected_file summary_path

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${output_root}/${case_id}"
  input_dir="${case_dir}/inputs"
  out_dir="${case_dir}/out"
  mkdir -p "$input_dir" "$out_dir"

  expected_file="${case_dir}/expected.json"
  jq '.expected' <<<"$case_json" >"$expected_file"
  expected_code="$(jq -r '.expected_exit_code' "$expected_file")"

  local br_arg=()
  local bv_arg=()
  local mail_arg=()
  local rch_arg=()
  local git_arg=()
  local artifacts_arg=()

  if ! case_omits_source "$case_id" "br_queue"; then
    materialize_source "$case_id" "br_queue" "${input_dir}/br_queue.json"
    br_arg=(--br-queue-json "${input_dir}/br_queue.json")
  fi
  if ! case_omits_source "$case_id" "bv_robot_plan"; then
    materialize_source "$case_id" "bv_robot_plan" "${input_dir}/bv_robot_plan.json"
    bv_arg=(--bv-robot-plan-json "${input_dir}/bv_robot_plan.json")
  fi
  if ! case_omits_source "$case_id" "agent_mail"; then
    materialize_source "$case_id" "agent_mail" "${input_dir}/agent_mail.json"
    mail_arg=(--agent-mail-json "${input_dir}/agent_mail.json")
  fi
  if ! case_omits_source "$case_id" "rch_status"; then
    materialize_source "$case_id" "rch_status" "${input_dir}/rch_status.json"
    rch_arg=(--rch-status-json "${input_dir}/rch_status.json")
  fi
  if ! case_omits_source "$case_id" "git_state"; then
    materialize_source "$case_id" "git_state" "${input_dir}/git_state.json"
    git_arg=(--git-state-json "${input_dir}/git_state.json")
  fi
  if ! case_omits_source "$case_id" "artifact_bundles"; then
    materialize_source "$case_id" "artifact_bundles" "${input_dir}/artifact_bundles.json"
    artifacts_arg=(--artifact-bundles-json "${input_dir}/artifact_bundles.json")
  fi

  set +e
  bash "$watcher" \
    "${br_arg[@]}" \
    "${bv_arg[@]}" \
    "${mail_arg[@]}" \
    "${rch_arg[@]}" \
    "${git_arg[@]}" \
    "${artifacts_arg[@]}" \
    --source-revision fixture-revision \
    --generated-epoch-seconds 1778123000 \
    --freshness-window-seconds 300 \
    --output-dir "$out_dir" >/dev/null
  code=$?
  set -e

  if [[ "$code" -ne "$expected_code" ]]; then
    record_failure "${case_id} expected exit ${expected_code}, got ${code}"
    return
  fi

  summary_path="${out_dir}/source_snapshot_summary.json"
  for artifact in source_snapshots.jsonl source_snapshot_summary.json events.jsonl commands.txt report.md; do
    if [[ ! -s "${out_dir}/${artifact}" ]]; then
      record_failure "${case_id} missing ${artifact}"
      return
    fi
  done

  jq -e --slurpfile expected "$expected_file" --slurpfile contract "$contract_path" '
    ($expected[0]) as $expected_doc
    | ($contract[0]) as $contract_doc
    | .schema_version == $contract_doc.summary_schema_version
    and .truth_state == $expected_doc.truth_state
    and .decision == $expected_doc.decision
    and ((["br_queue","bv_robot_plan","agent_mail","rch_status","git_state","artifact_bundles"] - (.source_snapshot_status | keys)) | length) == 0
    and all(.source_snapshot_status[]; . as $snapshot |
      all($contract_doc.required_snapshot_fields[]; $snapshot[.] != null)
    )
    and all(.source_snapshot_status[]; .mutation_policy? == null)
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_git == false
    and (
      (($expected_doc.required_error_code // "") | length) == 0
      or (.error_codes | index($expected_doc.required_error_code)) != null
    )
  ' "$summary_path" >/dev/null || {
    record_failure "${case_id} summary mismatch"
    return
  }

  jq -e 'select(.schema_version == "franken-engine.swarm-autopilot-shadow-source-watchers.event.v1")' "${out_dir}/events.jsonl" >/dev/null \
    || record_failure "${case_id} events mismatch"

  record_pass "${case_id} watcher"
}

run_check() {
  bash -n "$watcher" "${BASH_SOURCE[0]}"
  jq empty "$contract_path" "$fixtures_path"

  if contract_shape_ok; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi

  if fixtures_shape_ok; then
    record_pass "fixture shape"
  else
    record_failure "fixture shape mismatch"
  fi

  if docs_shape_ok; then
    record_pass "operator docs shape"
  else
    record_failure "operator docs shape mismatch"
  fi

  check_no_forbidden_claims "$contract_path"
  check_no_forbidden_claims "$docs_path"
}

run_selftest() {
  mkdir -p "$output_root"
  while IFS= read -r case_json; do
    run_case "$case_json"
  done < <(jq -c '.cases[]' "$fixtures_path")
  printf 'swarm_autopilot_shadow_source_watchers_smoke_artifacts=%s\n' "$output_root"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest|run)
    run_check
    run_selftest
    ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    usage
    exit 2
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
