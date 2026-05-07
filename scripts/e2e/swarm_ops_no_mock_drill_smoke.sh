#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
drill="${root_dir}/scripts/e2e/swarm_ops_no_mock_drill.sh"
fixtures_path="${SWARM_OPS_NO_MOCK_DRILL_FIXTURES:-${root_dir}/scripts/testdata/swarm_ops_no_mock_drill/cases.json}"
contract_path="${root_dir}/docs/swarm_ops_no_mock_drill_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_OPS_NO_MOCK_DRILL.md"
mode="${1:-check}"
output_dir="${2:-${SWARM_OPS_NO_MOCK_DRILL_OUTPUT_DIR:-}}"
failures=0

record_pass() {
  printf 'PASS swarm-ops-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-ops-no-mock-drill %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_ops_no_mock_drill_smoke.sh [check|run|selftest] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-ops-no-mock-drill-fixtures.v1"
    and (.cases | length == 4)
    and ([.cases[].case_id] | unique | length == 4)
    and any(.cases[]; .case_id == "green" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "stale_bv_fail" and .expected.required_error_code == "FE-SWARM-OPS-STALE-BV")
    and any(.cases[]; .case_id == "rch_stale_progress" and .expected.required_error_code == "FE-SWARM-OPS-RCH-STALL-NOT-UPGRADED")
    and any(.cases[]; .case_id == "bare_cargo_contamination" and .expected.required_error_code == "FE-SWARM-OPS-BARE-CARGO")
    and all(.cases[];
      (.state_capture | type) == "object"
      and ((["br_ready_json","br_in_progress_json","br_sync_status_json","bv_plan_txt","agent_mail_agents_json","agent_mail_inbox_json","agent_mail_reservations_txt","rch_status_json","rch_queue_json","git_status_txt"] - (.state_capture | keys_unsorted)) | length) == 0
      and (.capacity_envelope.total_cpu_slots | type) == "number"
      and (.capacity_envelope.total_rch_slots | type) == "number"
      and (.candidate_lanes | type) == "array"
      and all(.candidate_lanes[]; has("lane_id") and has("priority") and has("lane_class") and has("cpu_slots") and has("memory_bytes") and has("rch_slots") and has("target_dir_bytes"))
      and .worker_status_json.schema_version == "franken-engine.swarm-rch-worker-status.v1"
      and .stall_observations_json.schema_version == "franken-engine.swarm-rch-stall-observations.v1"
      and (.expected.expected_exit_code | type) == "number"
    )
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-ops-no-mock-drill-contract.v1"
    and .bead_id == "bd-r1abw"
    and .script == "scripts/e2e/swarm_ops_no_mock_drill.sh"
    and .smoke_script == "scripts/e2e/swarm_ops_no_mock_drill_smoke.sh"
    and .operator_docs == "docs/SWARM_OPS_NO_MOCK_DRILL.md"
    and .fixture_bundle == "scripts/testdata/swarm_ops_no_mock_drill/cases.json"
    and ((["live","fixture","replay"] - .modes) | length) == 0
    and ((["run_manifest.json","events.jsonl","commands.txt","trace_ids.json","state_snapshot.json","admission_plan.json","recovery_receipts.json","rch_rehab_ledger.json","locality_plan.json","dashboard_bundle.json","saturation_replay_report.json","slo_gate_report.json","truth_gate_report.json"] - .required_outputs) | length) == 0
    and (.stage_scripts | length) == 8
    and any(.fixture_cases[]; .case_id == "green" and .expected_decision == "pass")
    and any(.fixture_cases[]; .case_id == "stale_bv_fail" and .required_error_code == "FE-SWARM-OPS-STALE-BV")
    and any(.fixture_cases[]; .case_id == "rch_stale_progress" and .required_error_code == "FE-SWARM-OPS-RCH-STALL-NOT-UPGRADED")
    and any(.fixture_cases[]; .case_id == "bare_cargo_contamination" and .required_error_code == "FE-SWARM-OPS-BARE-CARGO")
    and .mutation_policy.live_capture_allowed == true
    and .mutation_policy.fixture_mode_deterministic == true
    and .mutation_policy.replay_verification_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch_heavy_commands == false
    and .mutation_policy.mutates_remote_workers == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'Machine-readable contract:' "$docs_path" \
    && grep -Fq 'Smoke gate:' "$docs_path" \
    && grep -Fq 'Fixture cases:' "$docs_path" \
    && grep -Fq 'Live no-mock mode' "$docs_path" \
    && grep -Fq 'Replay mode' "$docs_path" \
    && grep -Fq 'does not mutate beads' "$docs_path" \
    && grep -Fq 'heavy Cargo command' "$docs_path"
}

check_no_doc_heavy_commands() {
  local path="$1"
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      record_failure "${path#"$root_dir"/} has literal heavy Cargo command: ${command}"
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,260p' "$path")
}

validate_required_artifacts() {
  local run_root="$1"
  local missing=0
  local artifact
  for artifact in run_manifest.json events.jsonl commands.txt trace_ids.json state_snapshot.json admission_plan.json recovery_receipts.json rch_rehab_ledger.json locality_plan.json dashboard_bundle.json saturation_replay_report.json slo_gate_report.json truth_gate_report.json; do
    if [[ ! -s "${run_root}/${artifact}" ]]; then
      record_failure "${run_root} missing ${artifact}"
      missing=1
    fi
  done
  return "$missing"
}

validate_report() {
  local report="$1"
  local expected="$2"
  local case_id="$3"

  jq -e --slurpfile expected "$expected" '
    .schema_version == "franken-engine.swarm-ops-no-mock-drill-truth-gate.v1"
    and .bead_id == "bd-r1abw"
    and .decision == $expected[0].decision
    and (.stage_decisions | length) == 8
    and (.artifact_paths | has("state_snapshot_json"))
    and .mutation_policy.mutates_br == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch_heavy_commands == false
    and (
      (($expected[0].required_error_code // "") | length) == 0
      or ((.truth_gate_reasons | map(.code) | index($expected[0].required_error_code)) != null)
    )
  ' "$report" >/dev/null || record_failure "${case_id} truth report mismatch"
}

run_case() {
  local case_json="$1"
  local root="$2"
  local case_id case_dir expected expected_code code prior_failures

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${root}/${case_id}"
  mkdir -p "$case_dir"
  expected="${case_dir}/expected.json"
  jq '.expected' <<<"$case_json" >"$expected"
  expected_code="$(jq -r '.expected_exit_code' "$expected")"

  set +e
  bash "$drill" \
    --fixtures-json "$fixtures_path" \
    --case-id "$case_id" \
    --source-revision fixture-revision \
    --output-dir "$case_dir" >/dev/null
  code=$?
  set -e

  if [[ "$code" -ne "$expected_code" ]]; then
    record_failure "${case_id} expected exit ${expected_code}, got ${code}"
    return
  fi

  prior_failures="$failures"
  validate_required_artifacts "$case_dir" || true
  validate_report "${case_dir}/truth_gate_report.json" "$expected" "$case_id"
  if [[ "$failures" -eq "$prior_failures" ]]; then
    record_pass "${case_id} no-mock drill"
  fi
}

run_check() {
  bash -n "$drill"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$fixtures_path" "$contract_path"
  if fixtures_shape_ok; then
    record_pass "fixture shape"
  else
    record_failure "fixture shape mismatch"
  fi
  if contract_shape_ok; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi
  if docs_shape_ok; then
    record_pass "operator docs shape"
  else
    record_failure "operator docs shape mismatch"
  fi
  check_no_doc_heavy_commands "$contract_path"
  check_no_doc_heavy_commands "$docs_path"
}

run_all_cases() {
  local root="$1"
  mkdir -p "$root"
  while IFS= read -r case_json; do
    run_case "$case_json" "$root"
  done < <(jq -c '.cases[]' "$fixtures_path")
  printf 'swarm_ops_no_mock_drill_smoke_artifacts=%s\n' "$root"
}

run_selftest() {
  local tmp_root latest_root replay_out
  tmp_root="${output_dir:-${TMPDIR:-/tmp}/swarm-ops-no-mock-drill-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)}"
  latest_root="${tmp_root}/latest"
  replay_out="${tmp_root}/replay-green"
  mkdir -p "$tmp_root" "$latest_root"
  run_all_cases "${tmp_root}/cases"

  bash "$drill" \
    --fixtures-json "$fixtures_path" \
    --case-id green \
    --source-revision fixture-revision \
    --output-dir "${latest_root}/20260507T000000Z" >/dev/null

  bash "$drill" --latest-from "$latest_root" --output-dir "$replay_out" >/dev/null
  if jq -e '.decision == "pass" and .mutation_policy.replay_verification_only == true' "${replay_out}/truth_gate_report.json" >/dev/null; then
    record_pass "latest replay verification"
  else
    record_failure "latest replay verification mismatch"
  fi
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_all_cases "${output_dir:-${TMPDIR:-/tmp}/swarm-ops-no-mock-drill-smoke/run-$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)}"
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest
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
