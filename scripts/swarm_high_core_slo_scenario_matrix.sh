#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
normalizer="${root_dir}/scripts/swarm_telemetry_snapshot_normalizer.sh"
default_matrix_json="${root_dir}/scripts/testdata/swarm_high_core_slo/scenario_matrix.json"

matrix_json="$default_matrix_json"
output_dir=""
source_revision=""
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_high_core_slo_scenario_matrix.sh [--matrix-json FILE] --output-dir DIR [--source-revision REV]

Build a deterministic SWARM-CTRL-IX high-core scenario matrix by replaying
fixture-fed scenarios through scripts/swarm_telemetry_snapshot_normalizer.sh and
emitting scrubbed representative outputs suitable for golden comparison.

Required:
  --output-dir DIR

Optional:
  --matrix-json FILE
  --source-revision REV

Artifacts:
  swarm_high_core_scenario_matrix_report.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  matrix generated and all cases matched expectations
  1  matrix generated but one or more cases drifted from expected outcomes
  64 invalid input, malformed matrix, or malformed generated scenario fixtures
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --matrix-json)
      matrix_json="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
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
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$output_dir" ]]; then
  printf 'swarm high-core scenario matrix requires --output-dir\n' >&2
  usage
  exit 64
fi
if [[ ! -f "$matrix_json" ]]; then
  printf 'matrix fixture JSON not found: %s\n' "$matrix_json" >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm high-core scenario matrix generation\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi
if ! jq empty "$matrix_json" >/dev/null 2>&1; then
  printf 'invalid matrix fixture JSON: %s\n' "$matrix_json" >&2
  exit 64
fi
if ! jq -e '
  .schema_version == "franken-engine.swarm-high-core-scenario-matrix.v1"
  and (.golden_policy | type == "object")
  and (.required_scenario_classes | type == "array")
  and (.cases | type == "array" and length > 0)
' "$matrix_json" >/dev/null; then
  printf 'matrix fixture missing required schema fields: %s\n' "$matrix_json" >&2
  exit 64
fi
if ! jq -e '
  ([.cases[].case_id] | unique | length) == (.cases | length)
  and (.required_scenario_classes - ([.cases[].scenario_class] | unique)) == []
' "$matrix_json" >/dev/null; then
  printf 'matrix fixture has duplicate case ids or missing required scenario classes: %s\n' "$matrix_json" >&2
  exit 64
fi

mkdir -p "$output_dir"
cases_dir="${output_dir}/cases"
case_summaries_dir="${output_dir}/case_summaries"
events_path="${output_dir}/events.jsonl"
commands_path="${output_dir}/commands.txt"
report_path="${output_dir}/report.md"
report_json_path="${output_dir}/swarm_high_core_scenario_matrix_report.json"
report_tmp="${report_json_path}.tmp"
matrix_rel_path="$(realpath --relative-to="$root_dir" "$matrix_json")"

mkdir -p "$cases_dir" "$case_summaries_dir"
: >"$events_path"

printf './scripts/swarm_high_core_slo_scenario_matrix.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-high-core-scenario-matrix.event.v1" \
    --arg event_name "$1" \
    --arg case_id "$2" \
    --arg detail "$3" \
    '{
      schema_version: $schema_version,
      event_name: $event_name,
      case_id: $case_id,
      detail: $detail
    }' >>"$events_path"
}

write_common_artifacts() {
  local artifact_dir="$1"

  mkdir -p "$artifact_dir"
  printf '{}\n' >"${artifact_dir}/resource_lease_plan.json"
  printf '{}\n' >"${artifact_dir}/proof_cache_plan.json"
  printf '{}\n' >"${artifact_dir}/build_storm_batch_plan.json"
  printf '{}\n' >"${artifact_dir}/stale_lock_recommendations.json"
  printf '{}\n' >"${artifact_dir}/staged_ownership_report.json"
  printf '{}\n' >"${artifact_dir}/proof_freshness_report.json"
  printf '{}\n' >"${artifact_dir}/collision_receipt.json"
  printf '{}\n' >"${artifact_dir}/operator_status.json"
  printf '{}\n' >"${artifact_dir}/archive_pack.json"
  printf '{}\n' >"${artifact_dir}/restore_verification_report.json"
  printf '{}\n' >"${artifact_dir}/scheduler_replay_report.json"
}

write_wrapper_reports() {
  local case_json="$1"
  local case_dir="$2"
  local artifact_dir="${case_dir}/artifacts"
  local now_epoch
  local resource_plan_rel="artifacts/resource_lease_plan.json"
  local proof_cache_rel="artifacts/proof_cache_plan.json"
  local qos_plan_rel="artifacts/build_storm_batch_plan.json"
  local stale_report_rel="artifacts/stale_lock_recommendations.json"
  local contamination_report_rel="artifacts/staged_ownership_report.json"
  local collision_rel="artifacts/collision_receipt.json"
  local proof_freshness_rel="artifacts/proof_freshness_report.json"
  local operator_status_rel="artifacts/operator_status.json"
  local archive_pack_rel="artifacts/archive_pack.json"
  local restore_rel="artifacts/restore_verification_report.json"
  local scheduler_replay_rel="artifacts/scheduler_replay_report.json"

  now_epoch="$(jq -r '.now_epoch_seconds' <<<"$case_json")"

  jq -n \
    --arg resource_plan "$resource_plan_rel" \
    --arg proof_cache "$proof_cache_rel" \
    --arg qos_plan "$qos_plan_rel" \
    --arg stale_report "$stale_report_rel" \
    --arg contamination_report "$contamination_report_rel" \
    '{
      schema_version:"franken-engine.swarm-admission-drill-report.v1",
      drill_decision:"pass",
      child_artifacts:{
        resource_lease_plan_json:$resource_plan,
        proof_cache_plan_json:$proof_cache,
        build_storm_batch_plan_json:$qos_plan,
        stale_lock_recommendations_json:$stale_report,
        staged_ownership_report_json:$contamination_report
      }
    }' >"${case_dir}/admission_drill_report.json"

  jq -n \
    --arg collision "$collision_rel" \
    --arg proof_freshness "$proof_freshness_rel" \
    --arg operator_status "$operator_status_rel" \
    --argjson now_epoch "$now_epoch" \
    '{
      schema_version:"franken-engine.swarm-predictive-orchestration-e2e-wrapper.v1",
      status:"pass",
      captured_epoch_seconds:$now_epoch,
      artifact_paths:{
        collision_receipt_json:$collision,
        proof_freshness_report_json:$proof_freshness,
        operator_status_json:$operator_status
      }
    }' >"${case_dir}/predictive_wrapper_report.json"

  jq -n \
    --arg archive_pack "$archive_pack_rel" \
    --arg restore "$restore_rel" \
    --argjson now_epoch "$now_epoch" \
    '{
      schema_version:"franken-engine.remote-proof-archive-lifecycle-no-mock-drill-report.v1",
      drill_decision:"pass",
      captured_epoch_seconds:$now_epoch,
      artifact_paths:{
        archive_pack_json:$archive_pack,
        restore_verification_report_json:$restore
      }
    }' >"${case_dir}/archive_lifecycle_report.json"

  jq -n \
    --arg report "$scheduler_replay_rel" \
    --argjson now_epoch "$now_epoch" \
    '{
      schema_version:"franken-engine.proof-economy-scheduler-replay-drill-report.v1",
      drill_decision:"pass",
      captured_epoch_seconds:$now_epoch,
      artifact_paths:{
        scheduler_replay_drill_report_json:$report
      }
    }' >"${case_dir}/proof_economy_drill_report.json"
}

write_case_fixtures() {
  local case_json="$1"
  local case_dir="$2"
  local tail_dir_timestamp
  local stress_commands_json
  local chaos_commands_json
  local claim_map_json
  local stress_dir tail_dir chaos_dir claim_map_dir

  mkdir -p "$case_dir"
  write_common_artifacts "${case_dir}/artifacts"
  write_wrapper_reports "$case_json" "$case_dir"

  jq '.ready' <<<"$case_json" >"${case_dir}/ready.json"
  jq '.in_progress' <<<"$case_json" >"${case_dir}/in_progress.json"
  jq '.validation_plan' <<<"$case_json" >"${case_dir}/validation_plan.json"
  jq '.resource_decision' <<<"$case_json" >"${case_dir}/resource_decision.json"
  jq '.reservations' <<<"$case_json" >"${case_dir}/reservations.json"
  jq '.stale_lock_recommendations' <<<"$case_json" >"${case_dir}/stale_lock_recommendations.json"
  jq '.proof_freshness' <<<"$case_json" >"${case_dir}/proof_freshness.json"

  stress_dir="${case_dir}/high_core/stress"
  mkdir -p "$stress_dir"
  jq -r '.high_core.stress.commands[]' <<<"$case_json" >"${stress_dir}/commands.txt"
  jq '.high_core.stress.run_manifest' <<<"$case_json" >"${stress_dir}/suite_run_manifest.json"
  stress_commands_json="$(jq -c '.high_core.stress.commands' <<<"$case_json")"
  jq -n \
    --arg generated_at_utc "$(jq -r '.high_core.stress.generated_at_utc' <<<"$case_json")" \
    --arg outcome "$(jq -r '.high_core.stress.outcome' <<<"$case_json")" \
    --argjson commands "$stress_commands_json" \
    '{
      schema_version:"franken-engine.stress-concurrency.suite-manifest.v1",
      generated_at_utc:$generated_at_utc,
      outcome:$outcome,
      commands:$commands,
      artifacts:{
        stress_manifest:"suite_run_manifest.json"
      }
    }' >"${stress_dir}/suite_run_manifest_input.json"

  tail_dir_timestamp="$(jq -r '.tail_dir_timestamp' <<<"$case_json")"
  tail_dir="${case_dir}/high_core/tail/${tail_dir_timestamp}_tail_latency"
  mkdir -p "$tail_dir"
  jq -r '.high_core.tail.commands[]' <<<"$case_json" >"${tail_dir}/commands.txt"
  jq '.high_core.tail.run_manifest' <<<"$case_json" >"${tail_dir}/run_manifest.json"
  jq '.high_core.tail.report' <<<"$case_json" >"${tail_dir}/latency_control_plane_report.json"

  chaos_dir="${case_dir}/high_core/chaos"
  mkdir -p "$chaos_dir"
  jq -r '.high_core.chaos.commands[]' <<<"$case_json" >"${chaos_dir}/commands.txt"
  jq '.high_core.chaos.run_manifest' <<<"$case_json" >"${chaos_dir}/run_manifest.json"
  chaos_commands_json="$(jq -c '.high_core.chaos.commands' <<<"$case_json")"
  jq -n \
    --arg generated_at_utc "$(jq -r '.high_core.chaos.generated_at_utc' <<<"$case_json")" \
    --arg outcome "$(jq -r '.high_core.chaos.outcome' <<<"$case_json")" \
    --argjson commands "$chaos_commands_json" \
    --argjson summary "$(jq -c '.high_core.chaos.summary' <<<"$case_json")" \
    '{
      schema_version:"franken-engine.rgc-fault-injection-chaos-verification-pack.report.v1",
      generated_at_utc:$generated_at_utc,
      outcome:$outcome,
      commands:$commands,
      summary:$summary,
      evidence_inputs:{
        source:"scenario-matrix"
      }
    }' >"${chaos_dir}/chaos_verification_report.json"

  claim_map_dir="${case_dir}/high_core/claim_map"
  mkdir -p "$claim_map_dir"
  claim_map_json="$(jq -c '.high_core.claim_map' <<<"$case_json")"
  jq -n --argjson document "$claim_map_json" '$document' >"${claim_map_dir}/swarm_responsiveness_claim_map.json"
}

scrub_capacity_snapshot() {
  local raw_path="$1"
  local out_path="$2"
  jq '
    del(.artifact_paths)
    | .source_revision = "[SOURCE_REVISION]"
    | .snapshot_id = "[SNAPSHOT_ID]"
  ' "$raw_path" >"$out_path"
}

scrub_slo_snapshot() {
  local raw_path="$1"
  local out_path="$2"
  jq '
    del(.artifact_paths)
    | .source_revision = "[SOURCE_REVISION]"
    | .snapshot_id = "[SNAPSHOT_ID]"
    | .parent_snapshot_id = "[PARENT_SNAPSHOT_ID]"
  ' "$raw_path" >"$out_path"
}

failure_count=0

while IFS= read -r case_json; do
  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${cases_dir}/${case_id}"
  write_event "case_started" "$case_id" "writing case fixtures"
  write_case_fixtures "$case_json" "$case_dir"

  set +e
  "${normalizer}" \
    --ready-json "${case_dir}/ready.json" \
    --in-progress-json "${case_dir}/in_progress.json" \
    --validation-plan-json "${case_dir}/validation_plan.json" \
    --resource-decision-json "${case_dir}/resource_decision.json" \
    --agent-mail-reservations-json "${case_dir}/reservations.json" \
    --stale-lock-recommendations-json "${case_dir}/stale_lock_recommendations.json" \
    --proof-freshness-json "${case_dir}/proof_freshness.json" \
    --admission-drill-report-json "${case_dir}/admission_drill_report.json" \
    --predictive-wrapper-report-json "${case_dir}/predictive_wrapper_report.json" \
    --archive-lifecycle-report-json "${case_dir}/archive_lifecycle_report.json" \
    --proof-economy-drill-report-json "${case_dir}/proof_economy_drill_report.json" \
    --stress-suite-manifest-json "${case_dir}/high_core/stress/suite_run_manifest_input.json" \
    --tail-latency-report-json "$(find "${case_dir}/high_core/tail" -name latency_control_plane_report.json -print -quit)" \
    --chaos-verification-report-json "${case_dir}/high_core/chaos/chaos_verification_report.json" \
    --swarm-responsiveness-claim-map-json "${case_dir}/high_core/claim_map/swarm_responsiveness_claim_map.json" \
    --source-revision "$source_revision" \
    --now-epoch-seconds "$(jq -r '.now_epoch_seconds' <<<"$case_json")" \
    --stale-after-seconds "$(jq -r '.stale_after_seconds' <<<"$case_json")" \
    --output-dir "$case_dir" >/dev/null
  exit_code=$?
  set -e

  capacity_path="${case_dir}/swarm_capacity_snapshot.json"
  slo_path="${case_dir}/swarm_slo_input_snapshot.json"
  if [[ ! -f "$capacity_path" || ! -f "$slo_path" ]]; then
    printf 'expected normalized outputs missing for case %s\n' "$case_id" >&2
    exit 64
  fi

  expected_exit_code="$(jq -r '.expected.exit_code' <<<"$case_json")"
  expected_capacity_decision="$(jq -r '.expected.capacity_decision' <<<"$case_json")"
  expected_slo_decision="$(jq -r '.expected.slo_decision' <<<"$case_json")"
  actual_capacity_decision="$(jq -r '.decision' "$capacity_path")"
  actual_slo_decision="$(jq -r '.decision' "$slo_path")"

  actual_stress_traceability="$(jq -r '.swarm_capacity_snapshot.swarm_slo_inputs.stress_concurrency.traceability' "$capacity_path")"
  actual_tail_traceability="$(jq -r '.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.traceability' "$capacity_path")"
  actual_chaos_traceability="$(jq -r '.swarm_capacity_snapshot.swarm_slo_inputs.chaos_verification.traceability' "$capacity_path")"
  actual_claim_map_traceability="$(jq -r '.swarm_capacity_snapshot.swarm_slo_inputs.responsiveness_claim_map.traceability' "$capacity_path")"

  matched_expected=true
  [[ "$exit_code" -eq "$expected_exit_code" ]] || matched_expected=false
  [[ "$actual_capacity_decision" == "$expected_capacity_decision" ]] || matched_expected=false
  [[ "$actual_slo_decision" == "$expected_slo_decision" ]] || matched_expected=false
  [[ "$actual_stress_traceability" == "$(jq -r '.expected.traceability.stress' <<<"$case_json")" ]] || matched_expected=false
  [[ "$actual_tail_traceability" == "$(jq -r '.expected.traceability.tail' <<<"$case_json")" ]] || matched_expected=false
  [[ "$actual_chaos_traceability" == "$(jq -r '.expected.traceability.chaos' <<<"$case_json")" ]] || matched_expected=false
  [[ "$actual_claim_map_traceability" == "$(jq -r '.expected.traceability.claim_map' <<<"$case_json")" ]] || matched_expected=false
  if [[ "$matched_expected" != true ]]; then
    failure_count=$((failure_count + 1))
  fi

  scrub_capacity_snapshot "$capacity_path" "${case_dir}/swarm_capacity_snapshot.scrubbed.json"
  scrub_slo_snapshot "$slo_path" "${case_dir}/swarm_slo_input_snapshot.scrubbed.json"

  jq -n \
    --arg case_id "$case_id" \
    --arg scenario_class "$(jq -r '.scenario_class' <<<"$case_json")" \
    --arg description "$(jq -r '.description' <<<"$case_json")" \
    --arg resource_decision "$(jq -r '.resource_decision.decision' <<<"$case_json")" \
    --arg proof_freshness_state "$(jq -r '.proof_freshness.freshness_state' <<<"$case_json")" \
    --arg collision_risk "$(jq -r '.validation_plan.collision_risk' <<<"$case_json")" \
    --argjson exit_code "$exit_code" \
    --arg capacity_decision "$actual_capacity_decision" \
    --arg slo_decision "$actual_slo_decision" \
    --arg stress_traceability "$actual_stress_traceability" \
    --arg tail_traceability "$actual_tail_traceability" \
    --arg chaos_traceability "$actual_chaos_traceability" \
    --arg claim_map_traceability "$actual_claim_map_traceability" \
    --arg relative_capacity_path "$(realpath --relative-to="$output_dir" "$capacity_path")" \
    --arg relative_slo_path "$(realpath --relative-to="$output_dir" "$slo_path")" \
    --arg relative_events_path "$(realpath --relative-to="$output_dir" "${case_dir}/events.jsonl")" \
    --arg relative_report_path "$(realpath --relative-to="$output_dir" "${case_dir}/report.md")" \
    --argjson expected "$(jq -c '.expected' <<<"$case_json")" \
    --argjson matched_expected "$matched_expected" \
    --slurpfile capacity "${case_dir}/swarm_capacity_snapshot.scrubbed.json" \
    --slurpfile slo "${case_dir}/swarm_slo_input_snapshot.scrubbed.json" \
    '{
      case_id: $case_id,
      scenario_class: $scenario_class,
      description: $description,
      input_summary: {
        resource_decision: $resource_decision,
        proof_freshness_state: $proof_freshness_state,
        collision_risk: $collision_risk
      },
      expected: $expected,
      actual: {
        exit_code: $exit_code,
        capacity_decision: $capacity_decision,
        slo_decision: $slo_decision,
        traceability: {
          stress: $stress_traceability,
          tail: $tail_traceability,
          chaos: $chaos_traceability,
          claim_map: $claim_map_traceability
        }
      },
      matched_expected: $matched_expected,
      artifact_paths: {
        swarm_capacity_snapshot_json: $relative_capacity_path,
        swarm_slo_input_snapshot_json: $relative_slo_path,
        events_jsonl: $relative_events_path,
        report_md: $relative_report_path
      },
      capacity_snapshot: $capacity[0],
      slo_input_snapshot: $slo[0]
    }' >"${case_summaries_dir}/${case_id}.json"

  write_event "case_completed" "$case_id" "decision=${actual_capacity_decision} matched_expected=${matched_expected}"
done < <(jq -c '.cases[]' "$matrix_json")

jq -s \
  --arg source_revision_placeholder "[SOURCE_REVISION]" \
  --arg matrix_fixture_json "$matrix_rel_path" \
  --slurpfile matrix "$matrix_json" \
  '{
    schema_version:"franken-engine.swarm-high-core-scenario-matrix-report.v1",
    source_revision:$source_revision_placeholder,
    matrix_schema_version:($matrix[0].schema_version),
    contract_json:"docs/swarm_high_core_scenario_matrix_contract_v1.json",
    matrix_fixture_json:$matrix_fixture_json,
    golden_policy:($matrix[0].golden_policy),
    required_scenario_classes:($matrix[0].required_scenario_classes),
    scenario_count:length,
    failure_count:(map(select(.matched_expected != true)) | length),
    summary:{
      passing_case_count:(map(select(.actual.capacity_decision == "pass")) | length),
      fail_closed_case_count:(map(select(.actual.capacity_decision == "fail_closed")) | length),
      mismatch_case_ids:(map(select(.matched_expected != true) | .case_id)),
      scenario_classes:(map(.scenario_class) | unique | sort)
    },
    cases:.
  }' "${case_summaries_dir}"/*.json >"$report_tmp"
mv "$report_tmp" "$report_json_path"

{
  printf '# High-Core Scenario Matrix\n\n'
  printf -- "- Matrix fixture: \`%s\`\n" "$matrix_rel_path"
  printf -- "- Scenario count: \`%s\`\n" "$(jq '.scenario_count' "$report_json_path")"
  printf -- "- Failure count: \`%s\`\n" "$(jq '.failure_count' "$report_json_path")"
  printf -- "- Pass cases: \`%s\`\n" "$(jq '.summary.passing_case_count' "$report_json_path")"
  printf -- "- Fail-closed cases: \`%s\`\n\n" "$(jq '.summary.fail_closed_case_count' "$report_json_path")"
  jq -r '
    .cases[]
    | "- `\(.case_id)` (`\(.scenario_class)`): capacity=\(.actual.capacity_decision) slo=\(.actual.slo_decision) traceability=[stress:\(.actual.traceability.stress), tail:\(.actual.traceability.tail), chaos:\(.actual.traceability.chaos), claim_map:\(.actual.traceability.claim_map)]"
  ' "$report_json_path"
} >"$report_path"

printf 'swarm_high_core_scenario_matrix_report_json=%s\n' "$report_json_path"
printf 'swarm_high_core_scenario_matrix_report_md=%s\n' "$report_path"

if [[ "$failure_count" -ne 0 ]]; then
  exit 1
fi
exit 0
