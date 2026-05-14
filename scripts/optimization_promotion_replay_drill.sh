#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${OPTIMIZATION_PROMOTION_REPLAY_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-optimization-promotion-replay-drill}"
run_id="${OPTIMIZATION_PROMOTION_REPLAY_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${OPTIMIZATION_PROMOTION_REPLAY_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${OPTIMIZATION_PROMOTION_REPLAY_DRILL_SOURCE_REVISION:-unknown}"
fixtures_path="${OPTIMIZATION_PROMOTION_REPLAY_DRILL_FIXTURES:-${root_dir}/scripts/testdata/optimization_promotion_replay_drill/cases.json}"
mode="run"
case_id="promotable_evidence"
manifest_json=""
original_args=("$@")

usage() {
  cat >&2 <<'USAGE'
Usage: ./scripts/optimization_promotion_replay_drill.sh [OPTIONS]

Run or replay the source-only optimization promotion-control drill. Run mode
invokes the real child producer scripts over checked-in deterministic fixtures.
Replay mode verifies stable hashes and schemas from a pinned run manifest.

Options:
  --mode run|replay
  --case CASE_ID
  --fixtures-json FILE
  --manifest-json FILE
  --source-revision REV
  --output-dir DIR

Exit codes:
  0   drill or replay verified
  42  fail-closed drill case or replay mismatch
  64  invalid input or arguments
USAGE
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --mode)
      mode="${2:-}"
      shift 2
      ;;
    --case)
      case_id="${2:-}"
      shift 2
      ;;
    --fixtures-json)
      fixtures_path="${2:-}"
      shift 2
      ;;
    --manifest-json)
      manifest_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
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

case "$mode" in
  run|replay) ;;
  *)
    printf 'invalid --mode: %s\n' "$mode" >&2
    usage
    exit 64
    ;;
esac

if [[ "$mode" == "run" && ! -f "$fixtures_path" ]]; then
  printf 'fixtures JSON not found: %s\n' "$fixtures_path" >&2
  exit 64
fi
if [[ "$mode" == "replay" && ! -f "$manifest_json" ]]; then
  printf 'manifest JSON not found: %s\n' "$manifest_json" >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for optimization promotion replay drill\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for optimization promotion replay drill\n' >&2
  exit 2
fi
if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
stages_dir="${run_dir}/stages"
inputs_dir="${run_dir}/inputs"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
report_md="${run_dir}/report.md"
mkdir -p "$stages_dir" "$inputs_dir"
: >"$events_path"

printf './scripts/optimization_promotion_replay_drill.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.optimization-promotion-replay-drill.event.v1" \
    --arg trace_id "trace-optimization-promotion-replay-drill-${run_id}" \
    --arg component "optimization_promotion_replay_drill" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg error_code "$3" \
    '{schema_version:$schema_version,trace_id:$trace_id,component:$component,event:$event,outcome:$outcome,error_code:(if $error_code == "" then null else $error_code end)}' \
    >>"$events_path"
}

write_trace_ids() {
  jq -n \
    --arg schema_version "franken-engine.optimization-promotion-replay-drill.trace-ids.v1" \
    --arg bead_id "bd-xbesa" \
    --arg parent_bead_id "bd-xg3d6" \
    --arg trace_id "trace-optimization-promotion-replay-drill-${run_id}" \
    --arg decision_id "decision-optimization-promotion-replay-drill-${run_id}" \
    '{schema_version:$schema_version,bead_id:$bead_id,parent_bead_id:$parent_bead_id,trace_ids:[$trace_id],decision_ids:[$decision_id]}' \
    >"$trace_ids_path"
}

materialize_case() {
  local fixture_file="$1"
  local wanted_case="$2"
  local out_path="$3"
  jq --arg case_id "$wanted_case" '
    . as $root
    | ($root.cases[] | select(.case_id == $case_id)) as $case
    | ($root.base_input * ($case.overrides // {}))
    | .case_id = $case.case_id
  ' "$fixture_file" >"$out_path"
}

case_field() {
  local field="$1"
  jq -r --arg case_id "$case_id" --arg field "$field" '
    .cases[] | select(.case_id == $case_id) | .[$field] // ""
  ' "$fixtures_path"
}

run_stage() {
  local stage_name="$1"
  local script_path="$2"
  local input_path="$3"
  local output_dir="${stages_dir}/${stage_name}"
  local stdout_path="${output_dir}/stdout.log"
  local stderr_path="${output_dir}/stderr.log"
  local status=0
  mkdir -p "$output_dir"
  set +e
  "$script_path" --input-json "$input_path" --source-revision "drill-${case_id}" --output-dir "$output_dir" >"$stdout_path" 2>"$stderr_path"
  status="$?"
  set -e
  printf '%s\n' "$status" >"${output_dir}/exit_code.txt"
}

stage_result_json() {
  local stage_name="$1"
  local output_file="$2"
  local schema_version="$3"
  local output_path="${stages_dir}/${stage_name}/${output_file}"
  local exit_code
  exit_code="$(cat "${stages_dir}/${stage_name}/exit_code.txt")"
  if [[ -f "$output_path" ]]; then
    local output_hash
    output_hash="$(sha256sum "$output_path" | awk '{print $1}')"
    jq -n \
      --arg stage "$stage_name" \
      --arg output_path "$output_path" \
      --arg output_sha256 "$output_hash" \
      --arg schema_version "$schema_version" \
      --argjson exit_code "$exit_code" \
      '{stage:$stage,exit_code:$exit_code,output_path:$output_path,output_sha256:$output_sha256,expected_schema_version:$schema_version}'
  else
    jq -n \
      --arg stage "$stage_name" \
      --arg output_path "$output_path" \
      --arg schema_version "$schema_version" \
      --argjson exit_code "$exit_code" \
      '{stage:$stage,exit_code:$exit_code,output_path:$output_path,output_sha256:null,expected_schema_version:$schema_version}'
  fi
}

run_mode() {
  write_trace_ids
  write_event "run_started" "captured" ""
  if ! jq -e --arg case_id "$case_id" 'any(.cases[]; .case_id == $case_id)' "$fixtures_path" >/dev/null; then
    printf 'unknown drill case: %s\n' "$case_id" >&2
    exit 64
  fi

  local hot_path_bundle_path hot_path_bundle_abs error_code lane_state
  hot_path_bundle_path="$(case_field real_hot_path_bundle)"
  hot_path_bundle_abs="${root_dir}/${hot_path_bundle_path}"
  if [[ ! -f "$hot_path_bundle_abs" ]]; then
    error_code="FE-OPT-REPLAY-MISSING-HOT-PATH-BUNDLE"
    jq -n \
      --arg schema_version "franken-engine.optimization-promotion-replay-drill.run-manifest.v1" \
      --arg bead_id "bd-xbesa" \
      --arg parent_bead_id "bd-xg3d6" \
      --arg case_id "$case_id" \
      --arg source_revision "$source_revision" \
      --arg mode "$mode" \
      --arg decision "fail_closed" \
      --arg lane_state "fail_closed" \
      --arg error_code "$error_code" \
      --arg hot_path_bundle "$hot_path_bundle_path" \
      --arg events_path "$events_path" \
      --arg commands_path "$commands_path" \
      --arg trace_ids_path "$trace_ids_path" \
      --arg report_md "$report_md" \
      '{schema_version:$schema_version,bead_id:$bead_id,parent_bead_id:$parent_bead_id,mode:$mode,case_id:$case_id,source_revision:$source_revision,decision:$decision,lane_state:$lane_state,error_code:$error_code,real_hot_path_bundle:{path:$hot_path_bundle,present:false},stage_results:[],truth_gate:{decision:"fail_closed",violations:[{code:$error_code,detail:"real hot-path evidence bundle shape is missing"}]},mutation_policy:{advisory_only:true,proof_only:true,fixture_fed_only:true,mutates_runtime_policy:false,mutates_br:false,sends_agent_mail:false,releases_reservations:false,runs_cargo:false,runs_rch:false,mutates_remote_workers:false,publishes_benchmark_claims:false},artifact_paths:{events_jsonl:$events_path,commands_txt:$commands_path,trace_ids_json:$trace_ids_path,report_md:$report_md}}' \
      >"$manifest_path"
    printf "# Optimization Promotion Replay Drill\n\n- Decision: \`fail_closed\`\n- Error: \`%s\`\n" "$error_code" >"$report_md"
    write_event "run_completed" "fail_closed" "$error_code"
    exit 42
  fi

  local control_case eligibility_case demotion_case transfer_case operator_text
  control_case="$(case_field control_case)"
  eligibility_case="$(case_field eligibility_case)"
  demotion_case="$(case_field demotion_case)"
  transfer_case="$(case_field transfer_case)"
  operator_text="$(jq -r --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id) | .operator_status_text // ""' "$fixtures_path")"

  materialize_case "${root_dir}/scripts/testdata/optimization_promotion_control_contract/cases.json" "$control_case" "${inputs_dir}/control.json"
  materialize_case "${root_dir}/scripts/testdata/optimization_promotion_eligibility_composer/cases.json" "$eligibility_case" "${inputs_dir}/eligibility.json"
  materialize_case "${root_dir}/scripts/testdata/optimization_demotion_replay_receipts/cases.json" "$demotion_case" "${inputs_dir}/demotion.json"
  materialize_case "${root_dir}/scripts/testdata/optimization_transfer_guard/cases.json" "$transfer_case" "${inputs_dir}/transfer.json"

  run_stage "control_contract" "${root_dir}/scripts/optimization_promotion_control_contract.sh" "${inputs_dir}/control.json"
  run_stage "eligibility_composer" "${root_dir}/scripts/optimization_promotion_eligibility_composer.sh" "${inputs_dir}/eligibility.json"
  run_stage "demotion_receipts" "${root_dir}/scripts/optimization_demotion_replay_receipts.sh" "${inputs_dir}/demotion.json"
  run_stage "transfer_guard" "${root_dir}/scripts/optimization_transfer_guard.sh" "${inputs_dir}/transfer.json"

  jq -n \
    --slurpfile promotion "${stages_dir}/eligibility_composer/optimization_promotion_plan.json" \
    --slurpfile demotion "${stages_dir}/demotion_receipts/optimization_demotion_receipt.json" \
    --slurpfile transfer "${stages_dir}/transfer_guard/optimization_transfer_guard.json" \
    --arg source_revision "drill-${case_id}" \
    --arg operator_status_text "$operator_text" \
    '{
      schema_version:"franken-engine.optimization-promotion-operator-status.input.v1",
      source_revision:$source_revision,
      expected_source_revision:$source_revision,
      candidate:{candidate_id:($promotion[0].candidate.candidate_id // "unknown_candidate")},
      optimization_promotion_plan:$promotion[0],
      optimization_demotion_receipt:$demotion[0],
      optimization_transfer_guard:$transfer[0],
      operator_status_text:$operator_status_text
    }' >"${inputs_dir}/operator_status.json"
  run_stage "operator_status" "${root_dir}/scripts/optimization_promotion_operator_status.sh" "${inputs_dir}/operator_status.json"

  lane_state="$(jq -r '.operator_state // "fail_closed"' "${stages_dir}/operator_status/optimization_promotion_operator_status.json")"
  jq -r '.next_validation_commands[]?.command' "${stages_dir}/operator_status/optimization_promotion_operator_status.json" >>"$commands_path"

  local control_result eligibility_result demotion_result transfer_result operator_result
  control_result="$(stage_result_json "control_contract" "optimization_promotion_control_contract.json" "franken-engine.optimization-promotion-control.report.v1")"
  eligibility_result="$(stage_result_json "eligibility_composer" "optimization_promotion_plan.json" "franken-engine.optimization-promotion-plan.v1")"
  demotion_result="$(stage_result_json "demotion_receipts" "optimization_demotion_receipt.json" "franken-engine.optimization-demotion-receipt.v1")"
  transfer_result="$(stage_result_json "transfer_guard" "optimization_transfer_guard.json" "franken-engine.optimization-transfer-guard.v1")"
  operator_result="$(stage_result_json "operator_status" "optimization_promotion_operator_status.json" "franken-engine.optimization-promotion-operator-status.v1")"

  jq -n \
    --arg schema_version "franken-engine.optimization-promotion-replay-drill.run-manifest.v1" \
    --arg bead_id "bd-xbesa" \
    --arg parent_bead_id "bd-xg3d6" \
    --arg case_id "$case_id" \
    --arg source_revision "$source_revision" \
    --arg mode "$mode" \
    --arg decision "pass" \
    --arg lane_state "$lane_state" \
    --arg hot_path_bundle "$hot_path_bundle_path" \
    --arg hot_path_schema "$(jq -r '.schema_version // "missing"' "$hot_path_bundle_abs")" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg trace_ids_path "$trace_ids_path" \
    --arg report_md "$report_md" \
    --argjson control_result "$control_result" \
    --argjson eligibility_result "$eligibility_result" \
    --argjson demotion_result "$demotion_result" \
    --argjson transfer_result "$transfer_result" \
    --argjson operator_result "$operator_result" \
    '{
      schema_version:$schema_version,
      bead_id:$bead_id,
      parent_bead_id:$parent_bead_id,
      mode:$mode,
      case_id:$case_id,
      source_revision:$source_revision,
      decision:$decision,
      lane_state:$lane_state,
      error_code:null,
      real_hot_path_bundle:{path:$hot_path_bundle,present:true,schema_version:$hot_path_schema},
      stage_results:[$control_result,$eligibility_result,$demotion_result,$transfer_result,$operator_result],
      truth_gate:{decision:"pass",violations:[]},
      mutation_policy:{advisory_only:true,proof_only:true,fixture_fed_only:true,mutates_runtime_policy:false,mutates_br:false,sends_agent_mail:false,releases_reservations:false,runs_cargo:false,runs_rch:false,mutates_remote_workers:false,publishes_benchmark_claims:false},
      artifact_paths:{events_jsonl:$events_path,commands_txt:$commands_path,trace_ids_json:$trace_ids_path,report_md:$report_md}
    }' >"$manifest_path"

  jq -r '
    "# Optimization Promotion Replay Drill\n\n"
    + "- Decision: `" + .decision + "`\n"
    + "- Lane state: `" + .lane_state + "`\n"
    + "- Case: `" + .case_id + "`\n"
    + "- Stages: `" + ((.stage_results | length) | tostring) + "`\n\n"
    + "## Stage Results\n"
    + (.stage_results | map("- `" + .stage + "` exit `" + (.exit_code | tostring) + "` hash `" + (.output_sha256 // "missing") + "`") | join("\n"))
    + "\n"
  ' "$manifest_path" >"$report_md"
  write_event "run_completed" "pass" ""
}

replay_mode() {
  write_trace_ids
  write_event "replay_started" "captured" ""
  if ! jq -e '.schema_version == "franken-engine.optimization-promotion-replay-drill.run-manifest.v1"' "$manifest_json" >/dev/null; then
    printf 'manifest has unexpected schema: %s\n' "$manifest_json" >&2
    exit 64
  fi
  local failures=0
  while IFS=$'\t' read -r stage output_path output_sha expected_schema; do
    if [[ ! -f "$output_path" ]]; then
      printf 'missing replay stage output: %s\n' "$output_path" >&2
      failures=$((failures + 1))
      continue
    fi
    actual_sha="$(sha256sum "$output_path" | awk '{print $1}')"
    if [[ "$actual_sha" != "$output_sha" ]]; then
      printf 'hash mismatch for %s: %s != %s\n' "$stage" "$actual_sha" "$output_sha" >&2
      failures=$((failures + 1))
    fi
    if ! jq -e --arg expected_schema "$expected_schema" '.schema_version == $expected_schema' "$output_path" >/dev/null; then
      printf 'schema mismatch for %s\n' "$stage" >&2
      failures=$((failures + 1))
    fi
  done < <(jq -r '.stage_results[] | [.stage,.output_path,.output_sha256,.expected_schema_version] | @tsv' "$manifest_json")

  local decision error_code
  if [[ "$failures" -eq 0 ]]; then
    decision="pass"
    error_code=""
  else
    decision="fail_closed"
    error_code="FE-OPT-REPLAY-HASH-OR-SCHEMA-MISMATCH"
  fi
  jq -n \
    --arg schema_version "franken-engine.optimization-promotion-replay-drill.run-manifest.v1" \
    --arg bead_id "bd-xbesa" \
    --arg parent_bead_id "bd-xg3d6" \
    --arg mode "replay" \
    --arg case_id "$(jq -r '.case_id // "unknown"' "$manifest_json")" \
    --arg source_revision "$source_revision" \
    --arg decision "$decision" \
    --arg lane_state "$(jq -r '.lane_state // "unknown"' "$manifest_json")" \
    --arg error_code "$error_code" \
    --argjson verified_count "$(jq '.stage_results | length' "$manifest_json")" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg trace_ids_path "$trace_ids_path" \
    --arg report_md "$report_md" \
    '{schema_version:$schema_version,bead_id:$bead_id,parent_bead_id:$parent_bead_id,mode:$mode,case_id:$case_id,source_revision:$source_revision,decision:$decision,lane_state:$lane_state,error_code:(if $error_code == "" then null else $error_code end),verified_stage_count:$verified_count,artifact_paths:{events_jsonl:$events_path,commands_txt:$commands_path,trace_ids_json:$trace_ids_path,report_md:$report_md}}' \
    >"$manifest_path"
  jq -r '"# Optimization Promotion Replay Verification\n\n- Decision: `" + .decision + "`\n- Verified stages: `" + (.verified_stage_count | tostring) + "`\n"' "$manifest_path" >"$report_md"
  if [[ "$failures" -eq 0 ]]; then
    write_event "replay_completed" "pass" ""
    exit 0
  fi
  write_event "replay_completed" "fail_closed" "$error_code"
  exit 42
}

case "$mode" in
  run) run_mode ;;
  replay) replay_mode ;;
esac
