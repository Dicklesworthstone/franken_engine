#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_AUTOPILOT_WAREHOUSE_LIFECYCLE_DRILL_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-autopilot-warehouse-lifecycle-drill}"
run_id="${SWARM_AUTOPILOT_WAREHOUSE_LIFECYCLE_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AUTOPILOT_WAREHOUSE_LIFECYCLE_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-fixture}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

fixtures_json="${root_dir}/scripts/testdata/swarm_autopilot_warehouse_lifecycle_no_mock_drill/cases.json"
evidence_warehouse_json=""
hindsight_chaos_scenarios_json=""
replay_run_dir=""
scenario_filter=""
source_revision=""

retention_script="${root_dir}/scripts/swarm_autopilot_warehouse_retention_planner.sh"
promotion_script="${root_dir}/scripts/swarm_autopilot_promotion_candidate_miner.sh"
cohort_script="${root_dir}/scripts/swarm_autopilot_anomaly_cohort_packer.sh"
truth_gate_script="${root_dir}/scripts/e2e/swarm_autopilot_warehouse_lifecycle_truth_gate.sh"

events_path=""
commands_path=""
case_results_path=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_warehouse_lifecycle_no_mock_drill.sh [fixture|live|replay|check|selftest] [OPTIONS]

Options:
  --fixtures-json FILE
  --evidence-warehouse-json FILE
  --hindsight-chaos-scenarios-json FILE
  --replay-run-dir DIR
  --scenario-id ID
  --output-dir DIR
  --source-revision REV
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --fixtures-json)
      fixtures_json="${2:-}"
      shift 2
      ;;
    --evidence-warehouse-json)
      evidence_warehouse_json="${2:-}"
      shift 2
      ;;
    --hindsight-chaos-scenarios-json)
      hindsight_chaos_scenarios_json="${2:-}"
      shift 2
      ;;
    --replay-run-dir)
      replay_run_dir="${2:-}"
      shift 2
      ;;
    --scenario-id)
      scenario_filter="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the warehouse lifecycle no-mock drill\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for the warehouse lifecycle no-mock drill\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

refresh_paths() {
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  case_results_path="${run_dir}/case_results.jsonl"
}

ensure_run_dir() {
  refresh_paths
  mkdir -p "$run_dir"
  : >"$events_path"
  : >"$commands_path"
  : >"$case_results_path"
}

log_command() {
  local rendered="" arg quoted
  for arg in "$@"; do
    printf -v quoted '%q' "$arg"
    rendered+="${rendered:+ }${quoted}"
  done
  printf '%s\n' "$rendered" >>"$commands_path"
}

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-warehouse-lifecycle-drill.event.v1" \
    --arg event_name "$1" \
    --arg scenario_id "$2" \
    --arg decision "$3" \
    --arg artifact_path "$4" \
    '{schema_version:$schema_version,event_name:$event_name,scenario_id:$scenario_id,decision:$decision,artifact_path:$artifact_path}' \
    >>"$events_path"
}

run_step() {
  local scenario_id="$1"
  local step_id="$2"
  local expected_codes="$3"
  shift 3
  local step_dir="${run_dir}/${scenario_id}/${step_id}"
  local stdout_path="${step_dir}/stdout.log"
  local stderr_path="${step_dir}/stderr.log"
  local exit_code expected
  mkdir -p "$step_dir"
  log_command "$@"
  set +e
  "$@" >"$stdout_path" 2>"$stderr_path"
  exit_code=$?
  set -e
  IFS=',' read -r -a expected_list <<<"$expected_codes"
  for expected in "${expected_list[@]}"; do
    if [[ "$exit_code" == "$expected" ]]; then
      write_event "step_complete" "$scenario_id" "$step_id" "$step_dir"
      return 0
    fi
  done
  printf 'scenario %s step %s expected exit %s, got %s\n' "$scenario_id" "$step_id" "$expected_codes" "$exit_code" >&2
  return "$exit_code"
}

merge_case_input() {
  local scenario_id="$1"
  local source_name="$2"
  local output_path="$3"
  jq --arg scenario_id "$scenario_id" --arg source_name "$source_name" '
    def merge_rows($base; $overrides):
      if (($overrides // null) | type) != "array" then
        $base
      else
        ($overrides | map({key:.source_id, value:.}) | from_entries) as $by_id
        | [$base[] | . * ($by_id[.source_id] // {})]
      end;
    . as $root
    | ($root.cases[] | select(.scenario_id == $scenario_id)) as $case
    | if $source_name == "evidence_warehouse_json" then
        ($root.base_evidence_warehouse_json * (($case.overrides.evidence_warehouse_json // {}))) as $merged
        | $merged
        | .artifact_rows = merge_rows($root.base_evidence_warehouse_json.artifact_rows; (($case.overrides.evidence_warehouse_json // {}).artifact_rows // null))
      elif $source_name == "hindsight_chaos_scenarios_json" then
        $root.base_hindsight_chaos_scenarios_json * (($case.overrides.hindsight_chaos_scenarios_json // {}))
      else
        error("unknown source")
      end
  ' "$fixtures_json" >"$output_path"
}

write_operator_status_bundle() {
  local scenario_id="$1"
  local scenario_dir="$2"
  local output_path="${scenario_dir}/operator_status_bundle.json"
  local output_tmp="${output_path}.tmp"

  jq -n \
    --slurpfile warehouse "${scenario_dir}/inputs/evidence_warehouse.json" \
    --slurpfile retention "${scenario_dir}/retention/swarm_autopilot_warehouse_retention_plan.json" \
    --slurpfile storage "${scenario_dir}/retention/swarm_autopilot_storage_budget_ledger.json" \
    --slurpfile promotion "${scenario_dir}/promotion/swarm_autopilot_promotion_candidates.json" \
    --slurpfile receipts "${scenario_dir}/promotion/swarm_autopilot_promotion_candidate_receipts.json" \
    --slurpfile cohorts "${scenario_dir}/cohort/swarm_autopilot_anomaly_cohorts.json" \
    --slurpfile replay "${scenario_dir}/cohort/swarm_autopilot_replay_index.json" \
    --arg scenario_id "$scenario_id" \
    --arg output_path "$output_path" \
    '
      def codes($x): [ $x.fail_closed_reasons[]?.code?, $x.error_codes[]? ] | map(select(. != null)) | unique;
      ($warehouse[0]) as $wh
      | ($retention[0]) as $ret
      | ($storage[0]) as $storage
      | ($promotion[0]) as $promo
      | ($receipts[0]) as $receipts
      | ($cohorts[0]) as $cohorts
      | ($replay[0]) as $replay
      | ([codes($wh)[], codes($ret)[], codes($promo)[], codes($cohorts)[]] | unique) as $error_codes
      | (($error_codes | any(test("LOCAL-FALLBACK|CONTAMINATED"; "i"))) or (($wh.fail_closed_reasons // []) | any(((.code // "") + " " + (.detail // "")) | test("LOCAL-FALLBACK|contaminated"; "i")))) as $contaminated
      | (($error_codes | any(test("CONTRADICT|MISSING|STALE"; "i"))) or (($ret.decision // "") == "fail_closed") or (($promo.decision // "") == "fail_closed") or (($cohorts.decision // "") == "fail_closed")) as $blocked
      | ((($ret.decision // "") == "degraded") or (($promo.decision // "") == "degraded") or (($cohorts.decision // "") == "degraded")) as $degraded
      | {
          schema_version: "franken-engine.swarm-autopilot-warehouse-lifecycle-operator-status-bundle.v1",
          scenario_id: $scenario_id,
          truth_state: (if $contaminated then "contaminated" elif $blocked then "blocked" elif $degraded then "degraded" else "confirmed" end),
          decision: (if ($contaminated or $blocked) then "fail_closed" elif $degraded then "degraded" else "pass" end),
          warehouse_lifecycle: {
            retention_decision: ($ret.decision // "unknown"),
            storage_pressure_state: ($ret.storage_pressure_state // "unknown"),
            promotion_decision: ($promo.decision // "unknown"),
            cohort_decision: ($cohorts.decision // "unknown"),
            replay_index_entry_count: (($replay.entries // $replay.replay_entries // []) | length)
          },
          error_codes: $error_codes,
          artifact_paths: {
            warehouse_json: "warehouse.json",
            retention_plan_json: "retention_plan.json",
            storage_budget_ledger_json: "storage_budget_ledger.json",
            promotion_candidates_json: "promotion_candidates.json",
            promotion_candidate_receipts_json: "promotion_candidate_receipts.json",
            anomaly_cohorts_json: "anomaly_cohorts.json",
            replay_index_json: "replay_index.json",
            operator_status_bundle_json: $output_path
          },
          mutation_policy: {
            advisory_only: true,
            proof_only: true,
            mutates_br: false,
            reassigns_beads: false,
            releases_reservations: false,
            sends_agent_mail: false,
            runs_cargo: false,
            runs_rch: false,
            mutates_remote_workers: false,
            changes_live_queue_policy: false
          }
        }
    ' >"$output_tmp"
  mv "$output_tmp" "$output_path"
}

record_case_result() {
  local scenario_id="$1"
  local scenario_dir="$2"
  local expected_json="$3"

  jq -n \
    --slurpfile status "${scenario_dir}/operator_status_bundle.json" \
    --slurpfile expected "$expected_json" \
    --arg scenario_id "$scenario_id" \
    '
      ($status[0]) as $status_doc
      | ($expected[0]) as $expected_doc
      | {
          scenario_id: $scenario_id,
          decision: ($status_doc.decision // "unknown"),
          truth_state: ($status_doc.truth_state // "unknown"),
          expected_decision: $expected_doc.decision,
          expected_truth_state: ($expected_doc.required_truth_state // null),
          error_codes: ($status_doc.error_codes // []),
          matches_expected: (
            ($status_doc.decision == $expected_doc.decision)
            and (((($expected_doc.required_truth_state // "") | length) == 0) or $status_doc.truth_state == $expected_doc.required_truth_state)
            and (((($expected_doc.required_error_code // "") | length) == 0) or (($status_doc.error_codes // []) | index($expected_doc.required_error_code) != null))
          ),
          artifact_paths: $status_doc.artifact_paths
        }
    ' >>"$case_results_path"
}

copy_primary_outputs() {
  local scenario_dir="$1"
  cp "${scenario_dir}/inputs/evidence_warehouse.json" "${run_dir}/warehouse.json"
  cp "${scenario_dir}/retention/swarm_autopilot_warehouse_retention_plan.json" "${run_dir}/retention_plan.json"
  cp "${scenario_dir}/retention/swarm_autopilot_storage_budget_ledger.json" "${run_dir}/storage_budget_ledger.json"
  cp "${scenario_dir}/promotion/swarm_autopilot_promotion_candidates.json" "${run_dir}/promotion_candidates.json"
  cp "${scenario_dir}/promotion/swarm_autopilot_promotion_candidate_receipts.json" "${run_dir}/promotion_candidate_receipts.json"
  cp "${scenario_dir}/cohort/swarm_autopilot_anomaly_cohorts.json" "${run_dir}/anomaly_cohorts.json"
  cp "${scenario_dir}/cohort/swarm_autopilot_replay_index.json" "${run_dir}/replay_index.json"
  cp "${scenario_dir}/operator_status_bundle.json" "${run_dir}/operator_status_bundle.json"
}

run_lifecycle_case() {
  local scenario_id="$1"
  local scenario_dir="${run_dir}/${scenario_id}"
  local input_dir="${scenario_dir}/inputs"
  local expected_json="${scenario_dir}/expected.json"
  mkdir -p "$input_dir"

  if [[ "$mode" == "live" ]]; then
    cp "$evidence_warehouse_json" "${input_dir}/evidence_warehouse.json"
    cp "$hindsight_chaos_scenarios_json" "${input_dir}/hindsight_chaos_scenarios.json"
    jq -n '{decision:"pass"}' >"$expected_json"
  else
    merge_case_input "$scenario_id" "evidence_warehouse_json" "${input_dir}/evidence_warehouse.json"
    merge_case_input "$scenario_id" "hindsight_chaos_scenarios_json" "${input_dir}/hindsight_chaos_scenarios.json"
    jq --arg scenario_id "$scenario_id" '.cases[] | select(.scenario_id == $scenario_id) | .expected' "$fixtures_json" >"$expected_json"
  fi

  run_step "$scenario_id" "retention" "0,42" \
    bash "$retention_script" \
    --evidence-warehouse-json "${input_dir}/evidence_warehouse.json" \
    --source-revision "$source_revision" \
    --output-dir "${scenario_dir}/retention"

  run_step "$scenario_id" "promotion" "0,42" \
    bash "$promotion_script" \
    --evidence-warehouse-json "${input_dir}/evidence_warehouse.json" \
    --hindsight-chaos-scenarios-json "${input_dir}/hindsight_chaos_scenarios.json" \
    --source-revision "$source_revision" \
    --output-dir "${scenario_dir}/promotion"

  run_step "$scenario_id" "cohort" "0,42" \
    bash "$cohort_script" \
    --evidence-warehouse-json "${input_dir}/evidence_warehouse.json" \
    --source-revision "$source_revision" \
    --output-dir "${scenario_dir}/cohort"

  write_operator_status_bundle "$scenario_id" "$scenario_dir"
  record_case_result "$scenario_id" "$scenario_dir" "$expected_json"
  write_event "case_complete" "$scenario_id" "$(jq -r '.decision' "${scenario_dir}/operator_status_bundle.json")" "${scenario_dir}/operator_status_bundle.json"
}

run_fixture_mode() {
  ensure_run_dir
  jq -n \
    --arg schema_version "franken-engine.swarm-autopilot-warehouse-lifecycle-drill-manifest.v1" \
    --arg run_id "$run_id" \
    --arg source_revision "$source_revision" \
    --arg mode "$mode" \
    '{schema_version:$schema_version,run_id:$run_id,source_revision:$source_revision,mode:$mode}' >"${run_dir}/run_manifest.json"

  while IFS= read -r scenario_id; do
    if [[ -n "$scenario_filter" && "$scenario_id" != "$scenario_filter" ]]; then
      continue
    fi
    run_lifecycle_case "$scenario_id"
  done < <(jq -r '.cases[].scenario_id' "$fixtures_json")

  primary_scenario="$(jq -r '.primary_scenario_id' "$fixtures_json")"
  if [[ -n "$scenario_filter" ]]; then
    primary_scenario="$scenario_filter"
  fi
  copy_primary_outputs "${run_dir}/${primary_scenario}"

  set +e
  "$truth_gate_script" --run-dir "$run_dir" --output "${run_dir}/truth_gate_report.json"
  truth_code=$?
  set -e
  if [[ "$truth_code" -ne 0 ]]; then
    exit "$truth_code"
  fi
}

run_live_mode() {
  if [[ -z "$evidence_warehouse_json" || -z "$hindsight_chaos_scenarios_json" ]]; then
    printf 'live mode requires --evidence-warehouse-json and --hindsight-chaos-scenarios-json\n' >&2
    exit 64
  fi
  ensure_run_dir
  jq -n \
    --arg schema_version "franken-engine.swarm-autopilot-warehouse-lifecycle-drill-manifest.v1" \
    --arg run_id "$run_id" \
    --arg source_revision "$source_revision" \
    --arg mode "live" \
    '{schema_version:$schema_version,run_id:$run_id,source_revision:$source_revision,mode:$mode}' >"${run_dir}/run_manifest.json"
  run_lifecycle_case "live_warehouse_lifecycle"
  copy_primary_outputs "${run_dir}/live_warehouse_lifecycle"
  "$truth_gate_script" --run-dir "$run_dir" --output "${run_dir}/truth_gate_report.json"
}

run_replay_mode() {
  if [[ -z "$replay_run_dir" ]]; then
    printf 'replay mode requires --replay-run-dir\n' >&2
    exit 64
  fi
  mkdir -p "$run_dir"
  local required
  for required in run_manifest.json case_results.jsonl truth_gate_report.json warehouse.json retention_plan.json storage_budget_ledger.json promotion_candidates.json promotion_candidate_receipts.json anomaly_cohorts.json replay_index.json operator_status_bundle.json; do
    if [[ ! -s "${replay_run_dir}/${required}" ]]; then
      printf 'replay source missing %s\n' "$required" >&2
      exit 42
    fi
  done
  jq -n \
    --slurpfile prior "${replay_run_dir}/truth_gate_report.json" \
    --arg schema_version "franken-engine.swarm-autopilot-warehouse-lifecycle-truth-gate.v1" \
    --arg replay_run_dir "$replay_run_dir" \
    '{
      schema_version: $schema_version,
      decision: (if $prior[0].decision == "pass" then "pass" else "fail_closed" end),
      replay_verified: ($prior[0].decision == "pass"),
      replay_run_dir: $replay_run_dir,
      required_coverage: $prior[0].required_coverage,
      failure_reasons: (if $prior[0].decision == "pass" then [] else [{code:"FE-SWARM-AUTOPILOT-WAREHOUSE-REPLAY-SOURCE-FAILED",detail:"source truth gate was not pass"}] end)
    }' >"${run_dir}/truth_gate_report.json"
  if jq -e '.decision == "pass" and .replay_verified == true' "${run_dir}/truth_gate_report.json" >/dev/null; then
    exit 0
  fi
  exit 42
}

case "$mode" in
  fixture|selftest)
    run_fixture_mode
    ;;
  live)
    run_live_mode
    ;;
  replay)
    run_replay_mode
    ;;
  check)
    bash -n "${BASH_SOURCE[0]}" "$truth_gate_script"
    jq empty "$fixtures_json" >/dev/null
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    exit 64
    ;;
esac
