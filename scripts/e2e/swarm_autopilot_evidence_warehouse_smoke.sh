#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
warehouse="${root_dir}/scripts/swarm_autopilot_evidence_warehouse.sh"
fixtures_path="${SWARM_AUTOPILOT_EVIDENCE_WAREHOUSE_FIXTURES:-${root_dir}/scripts/testdata/swarm_autopilot_evidence_warehouse/cases.json}"
contract_path="${root_dir}/docs/swarm_autopilot_evidence_warehouse_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_AUTOPILOT_EVIDENCE_WAREHOUSE.md"
mode="${1:-check}"
output_dir="${2:-${SWARM_AUTOPILOT_EVIDENCE_WAREHOUSE_OUTPUT_DIR:-}}"
failures=0

record_pass() {
  printf 'PASS swarm-autopilot-evidence-warehouse %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-autopilot-evidence-warehouse %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_evidence_warehouse_smoke.sh [check|run|selftest] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-evidence-warehouse-fixtures.v1"
    and (.base_swarm_ops_bundle | type) == "object"
    and (.base_queue_locality_json.schema_version == "franken-engine.swarm-topology-aware-queue-advisory.v1")
    and (.base_operator_intent_policy_json.schema_version == "franken-engine.swarm-autopilot-operator-intent-policy.v1")
    and (([
      "run_manifest_json",
      "events_jsonl",
      "commands_txt",
      "trace_ids_json",
      "state_snapshot_json",
      "admission_plan_json",
      "recovery_receipts_json",
      "rch_rehab_ledger_json",
      "locality_plan_json",
      "dashboard_bundle_json",
      "saturation_replay_report_json",
      "slo_gate_report_json",
      "truth_gate_report_json"
    ] - (.base_swarm_ops_bundle | keys_unsorted)) | length) == 0
    and (.cases | length == 5)
    and ([.cases[].case_id] | unique | length == 5)
    and any(.cases[]; .case_id == "green" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "stale_swarm_ops" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-STALE-SWARM-OPS")
    and any(.cases[]; .case_id == "missing_queue_locality" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-MISSING-QUEUE-LOCALITY")
    and any(.cases[]; .case_id == "local_fallback_contamination" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-LOCAL-FALLBACK")
    and any(.cases[]; .case_id == "schema_drift" and .expected.required_error_code == "FE-SWARM-AUTOPILOT-SCHEMA-DRIFT")
    and all(.cases[];
      (.expected.expected_exit_code | type) == "number"
      and (.expected.decision | type) == "string"
      and ((.overrides // {}) | type) == "object"
    )
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-autopilot-evidence-warehouse-contract.v1"
    and .bead_id == "bd-4t4oi"
    and .script == "scripts/swarm_autopilot_evidence_warehouse.sh"
    and .smoke_script == "scripts/e2e/swarm_autopilot_evidence_warehouse_smoke.sh"
    and .operator_docs == "docs/SWARM_AUTOPILOT_EVIDENCE_WAREHOUSE.md"
    and .fixture_bundle == "scripts/testdata/swarm_autopilot_evidence_warehouse/cases.json"
    and .warehouse_schema_version == "franken-engine.swarm-autopilot-evidence-warehouse.v1"
    and ((["swarm_ops_bundle_dir","queue_locality_json"] - .required_inputs) | length) == 0
    and ((["short_lived_raw_capture","long_lived_replay_evidence","audit_log","policy_snapshot"] - .retention_classes) | length) == 0
    and ((["evidence_warehouse.json","run_manifest.json","events.jsonl","commands.txt","report.md"] - .output_artifacts) | length) == 0
    and (([
      "run_manifest.json",
      "events.jsonl",
      "commands.txt",
      "trace_ids.json",
      "state_snapshot.json",
      "admission_plan.json",
      "recovery_receipts.json",
      "rch_rehab_ledger.json",
      "locality_plan.json",
      "dashboard_bundle.json",
      "saturation_replay_report.json",
      "slo_gate_report.json",
      "truth_gate_report.json"
    ] - .required_swarm_ops_bundle_members) | length) == 0
    and any(.fixture_cases[]; .case_id == "green" and .expected_decision == "pass")
    and any(.fixture_cases[]; .case_id == "schema_drift" and .required_error_code == "FE-SWARM-AUTOPILOT-SCHEMA-DRIFT")
    and .mutation_policy.advisory_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.writes_outside_output_dir == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'Machine-readable contract:' "$docs_path" \
    && grep -Fq 'Smoke gate:' "$docs_path" \
    && grep -Fq 'Fixture cases:' "$docs_path" \
    && grep -Fq 'warehouse_hash' "$docs_path" \
    && grep -Fq 'Local fallback contamination fails closed.' "$docs_path" \
    && grep -Fq 'does not mutate beads' "$docs_path"
}

check_no_heavy_cargo_commands() {
  local path="$1"
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      record_failure "${path#"$root_dir"/} has literal heavy Cargo command: ${command}"
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,260p' "$path")
}

materialize_case() {
  local case_id="$1"
  local case_dir="$2"
  local bundle_file="${case_dir}/bundle.json"
  local bundle_dir="${case_dir}/swarm_ops_bundle"
  local queue_file="${case_dir}/queue_locality.json"
  local operator_policy_file="${case_dir}/operator_intent_policy.json"
  local member key file

  mkdir -p "$bundle_dir"
  jq --arg case_id "$case_id" '
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | $root.base_swarm_ops_bundle * (($case.overrides.swarm_ops_bundle // {}))
  ' "$fixtures_path" >"$bundle_file"

  for member in \
    "run_manifest_json:run_manifest.json" \
    "trace_ids_json:trace_ids.json" \
    "state_snapshot_json:state_snapshot.json" \
    "admission_plan_json:admission_plan.json" \
    "recovery_receipts_json:recovery_receipts.json" \
    "rch_rehab_ledger_json:rch_rehab_ledger.json" \
    "locality_plan_json:locality_plan.json" \
    "dashboard_bundle_json:dashboard_bundle.json" \
    "saturation_replay_report_json:saturation_replay_report.json" \
    "slo_gate_report_json:slo_gate_report.json" \
    "truth_gate_report_json:truth_gate_report.json"; do
    key="${member%%:*}"
    file="${member#*:}"
    jq ".${key}" "$bundle_file" >"${bundle_dir}/${file}"
  done
  jq -r '.events_jsonl' "$bundle_file" >"${bundle_dir}/events.jsonl"
  jq -r '.commands_txt' "$bundle_file" >"${bundle_dir}/commands.txt"

  if ! jq -e --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | (.omit_queue_locality_json // false) == true' "$fixtures_path" >/dev/null; then
    jq --arg case_id "$case_id" '
      . as $root
      | ($root.cases[] | select(.case_id == $case_id)) as $case
      | $root.base_queue_locality_json * (($case.overrides.queue_locality_json // {}))
    ' "$fixtures_path" >"$queue_file"
  fi

  jq --arg case_id "$case_id" '
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | $root.base_operator_intent_policy_json * (($case.overrides.operator_intent_policy_json // {}))
  ' "$fixtures_path" >"$operator_policy_file"
}

validate_required_artifacts() {
  local case_dir="$1"
  local artifact
  for artifact in evidence_warehouse.json run_manifest.json events.jsonl commands.txt report.md; do
    if [[ ! -s "${case_dir}/${artifact}" ]]; then
      record_failure "${case_dir} missing ${artifact}"
    fi
  done
}

validate_warehouse() {
  local warehouse_json="$1"
  local expected_json="$2"
  local case_id="$3"

  jq -e --slurpfile expected "$expected_json" '
    .schema_version == "franken-engine.swarm-autopilot-evidence-warehouse.v1"
    and .bead_id == "bd-4t4oi"
    and .decision == $expected[0].decision
    and (.hash_basis.warehouse_hash | test("^[0-9a-f]{64}$"))
    and (.artifact_rows | length >= 15)
    and ((["run_manifest_json","events_jsonl","commands_txt","truth_gate_report_json","queue_locality_json","operator_intent_policy_json"] - [.artifact_rows[].source_id]) | length) == 0
    and (.retention_classes.short_lived_raw_capture | index("state_snapshot_json") != null)
    and (.retention_classes.long_lived_replay_evidence | index("queue_locality_json") != null)
    and (.retention_classes.audit_log | index("commands_txt") != null)
    and (.retention_classes.policy_snapshot | index("operator_intent_policy_json") != null)
    and .artifact_paths.commands_txt
    and .artifact_paths.events_jsonl
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and (
      (($expected[0].required_error_code // "") | length) == 0
      or (
        ([.fail_closed_reasons[].code] | index($expected[0].required_error_code)) != null
        and all(.fail_closed_reasons[]; (.remediation_command | length) > 0)
        and (.remediation_commands | length) > 0
      )
    )
  ' "$warehouse_json" >/dev/null || record_failure "${case_id} warehouse mismatch"
}

validate_events_and_commands() {
  local case_dir="$1"
  local case_id="$2"

  jq -e 'select(.schema_version == "franken-engine.swarm-autopilot-evidence-warehouse.event.v1")' "${case_dir}/events.jsonl" >/dev/null \
    || record_failure "${case_id} event log mismatch"
  grep -Fq './scripts/swarm_autopilot_evidence_warehouse.sh' "${case_dir}/commands.txt" \
    || record_failure "${case_id} command capture mismatch"
}

run_case() {
  local case_json="$1"
  local root="$2"
  local case_id case_dir expected expected_code code prior_failures
  local queue_file operator_policy_file
  local args

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${root}/${case_id}"
  mkdir -p "$case_dir"
  expected="${case_dir}/expected.json"
  jq '.expected' <<<"$case_json" >"$expected"
  expected_code="$(jq -r '.expected_exit_code' "$expected")"

  materialize_case "$case_id" "$case_dir"
  queue_file="${case_dir}/queue_locality.json"
  operator_policy_file="${case_dir}/operator_intent_policy.json"
  args=(
    --swarm-ops-bundle-dir "${case_dir}/swarm_ops_bundle"
    --operator-intent-policy-json "$operator_policy_file"
    --source-revision fixture-revision
    --output-dir "$case_dir"
  )
  if [[ -s "$queue_file" ]]; then
    args+=(--queue-locality-json "$queue_file")
  fi

  set +e
  bash "$warehouse" "${args[@]}" >/dev/null
  code=$?
  set -e

  if [[ "$code" -ne "$expected_code" ]]; then
    record_failure "${case_id} expected exit ${expected_code}, got ${code}"
    return
  fi

  prior_failures="$failures"
  validate_required_artifacts "$case_dir"
  validate_warehouse "${case_dir}/evidence_warehouse.json" "$expected" "$case_id"
  validate_events_and_commands "$case_dir" "$case_id"
  if [[ "$failures" -eq "$prior_failures" ]]; then
    record_pass "${case_id} warehouse"
  fi
}

run_check() {
  bash -n "$warehouse"
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
  check_no_heavy_cargo_commands "$contract_path"
  check_no_heavy_cargo_commands "$docs_path"
}

run_all_cases() {
  local root="$1"
  mkdir -p "$root"
  while IFS= read -r case_json; do
    run_case "$case_json" "$root"
  done < <(jq -c '.cases[]' "$fixtures_path")
  printf 'swarm_autopilot_evidence_warehouse_smoke_artifacts=%s\n' "$root"
}

run_stable_hash_check() {
  local root="$1"
  local first="${root}/green-stable-a"
  local second="${root}/green-stable-b"
  local first_hash second_hash

  run_case "$(jq -c '.cases[] | select(.case_id == "green")' "$fixtures_path")" "$first"
  run_case "$(jq -c '.cases[] | select(.case_id == "green")' "$fixtures_path")" "$second"
  first_hash="$(jq -r '.hash_basis.warehouse_hash' "${first}/green/evidence_warehouse.json")"
  second_hash="$(jq -r '.hash_basis.warehouse_hash' "${second}/green/evidence_warehouse.json")"
  if [[ "$first_hash" == "$second_hash" && "$first_hash" =~ ^[0-9a-f]{64}$ ]]; then
    record_pass "stable warehouse hash"
  else
    record_failure "stable warehouse hash mismatch"
  fi
}

run_selftest() {
  local tmp_root
  tmp_root="${output_dir:-${TMPDIR:-/tmp}/swarm-autopilot-evidence-warehouse-smoke/$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)}"
  mkdir -p "$tmp_root"
  run_all_cases "${tmp_root}/cases"
  run_stable_hash_check "${tmp_root}/stable"
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_all_cases "${output_dir:-${TMPDIR:-/tmp}/swarm-autopilot-evidence-warehouse-smoke/run-$USER-$$-$(date -u +%Y%m%dT%H%M%SZ)}"
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
