#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
normalizer="${root_dir}/scripts/swarm_starvation_rescue_input_normalizer.sh"
default_matrix_json="${root_dir}/scripts/testdata/swarm_starvation_rescue/scenario_matrix.json"

matrix_json="$default_matrix_json"
output_dir=""
source_revision=""
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_starvation_rescue_scenario_matrix.sh [--matrix-json FILE] --output-dir DIR [--source-revision REV]

Build a deterministic SWARM-CTRL-X starvation-rescue scenario matrix by replaying
fixture-fed scenarios through scripts/swarm_starvation_rescue_input_normalizer.sh
and emitting scrubbed representative outputs suitable for golden comparison.

Required:
  --output-dir DIR

Optional:
  --matrix-json FILE
  --source-revision REV

Artifacts:
  swarm_starvation_rescue_scenario_matrix_report.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  matrix generated and all cases matched expectations
  1  matrix generated but one or more cases drifted from expected outcomes
  64 invalid input, malformed matrix, or malformed generated fixtures
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
  printf 'swarm starvation rescue scenario matrix requires --output-dir\n' >&2
  usage
  exit 64
fi
if [[ ! -f "$matrix_json" ]]; then
  printf 'matrix fixture JSON not found: %s\n' "$matrix_json" >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm starvation rescue scenario matrix generation\n' >&2
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
  .schema_version == "franken-engine.swarm-starvation-rescue-scenario-matrix.v1"
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
report_json_path="${output_dir}/swarm_starvation_rescue_scenario_matrix_report.json"
report_tmp="${report_json_path}.tmp"
matrix_rel_path="$(realpath --relative-to="$root_dir" "$matrix_json")"

mkdir -p "$cases_dir" "$case_summaries_dir"
: >"$events_path"

printf './scripts/swarm_starvation_rescue_scenario_matrix.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-starvation-rescue-scenario-matrix.event.v1" \
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

write_case_fixtures() {
  local case_json="$1"
  local case_dir="$2"

  mkdir -p "$case_dir"
  jq '.brownout_report' <<<"$case_json" >"${case_dir}/brownout.json"
  jq '.stale_lock_recommendations' <<<"$case_json" >"${case_dir}/stale.json"
  jq '.lease_exchange_salvage_simulation' <<<"$case_json" >"${case_dir}/lease.json"
  jq '.admission_budget_plan' <<<"$case_json" >"${case_dir}/admission.json"
  jq '.capacity_forecast' <<<"$case_json" >"${case_dir}/capacity.json"
  jq '.slo_threshold_receipt' <<<"$case_json" >"${case_dir}/slo.json"
}

scrub_report() {
  local raw_path="$1"
  local out_path="$2"

  jq '
    del(.artifact_paths, .contract_paths, .hash_basis, .report_id)
    | .source_revision = "[SOURCE_REVISION]"
    | .resolved_inputs |= map(.path = ("[INPUT:" + .input + "]"))
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
    --brownout-report-json "${case_dir}/brownout.json" \
    --stale-lock-recommendations-json "${case_dir}/stale.json" \
    --lease-exchange-salvage-simulation-json "${case_dir}/lease.json" \
    --admission-budget-plan-json "${case_dir}/admission.json" \
    --capacity-forecast-json "${case_dir}/capacity.json" \
    --slo-threshold-receipt-json "${case_dir}/slo.json" \
    --source-revision "$source_revision" \
    --now-epoch-seconds "$(jq -r '.now_epoch_seconds' <<<"$case_json")" \
    --stale-after-seconds "$(jq -r '.stale_after_seconds' <<<"$case_json")" \
    --output-dir "$case_dir" >/dev/null
  exit_code=$?
  set -e

  report_json="${case_dir}/swarm_starvation_rescue_input.json"
  if [[ ! -f "$report_json" ]]; then
    printf 'expected normalized output missing for case %s\n' "$case_id" >&2
    exit 64
  fi

  actual_decision="$(jq -r '.decision' "$report_json")"
  actual_readiness="$(jq -r '.summary.readiness' "$report_json")"
  actual_local_fallback="$(jq -r '.derived_truth.local_rch_fallback_detected' "$report_json")"

  expected_exit_code="$(jq -r '.expected.exit_code' <<<"$case_json")"
  expected_decision="$(jq -r '.expected.decision' <<<"$case_json")"
  expected_readiness="$(jq -r '.expected.readiness' <<<"$case_json")"
  expected_local_fallback="$(jq -r '.expected.local_rch_fallback_detected' <<<"$case_json")"

  matched_expected=true
  [[ "$exit_code" -eq "$expected_exit_code" ]] || matched_expected=false
  [[ "$actual_decision" == "$expected_decision" ]] || matched_expected=false
  [[ "$actual_readiness" == "$expected_readiness" ]] || matched_expected=false
  [[ "$actual_local_fallback" == "$expected_local_fallback" ]] || matched_expected=false
  if [[ "$matched_expected" != true ]]; then
    failure_count=$((failure_count + 1))
  fi

  scrub_report "$report_json" "${case_dir}/swarm_starvation_rescue_input.scrubbed.json"

  jq -n \
    --arg case_id "$case_id" \
    --arg scenario_class "$(jq -r '.scenario_class' <<<"$case_json")" \
    --arg description "$(jq -r '.description' <<<"$case_json")" \
    --argjson exit_code "$exit_code" \
    --arg decision "$actual_decision" \
    --arg readiness "$actual_readiness" \
    --arg local_fallback "$actual_local_fallback" \
    --arg relative_report_path "$(realpath --relative-to="$output_dir" "$report_json")" \
    --argjson expected "$(jq -c '.expected' <<<"$case_json")" \
    --argjson matched_expected "$matched_expected" \
    --slurpfile report "${case_dir}/swarm_starvation_rescue_input.scrubbed.json" \
    '{
      case_id: $case_id,
      scenario_class: $scenario_class,
      description: $description,
      expected: $expected,
      actual: {
        exit_code: $exit_code,
        decision: $decision,
        readiness: $readiness,
        local_rch_fallback_detected: $local_fallback
      },
      matched_expected: $matched_expected,
      artifact_paths: {
        swarm_starvation_rescue_input_json: $relative_report_path
      },
      starvation_rescue_input: $report[0]
    }' >"${case_summaries_dir}/${case_id}.json"

  write_event "case_completed" "$case_id" "decision=${actual_decision} readiness=${actual_readiness} matched_expected=${matched_expected}"
done < <(jq -c '.cases[]' "$matrix_json")

jq -s \
  --arg source_revision_placeholder "[SOURCE_REVISION]" \
  --arg matrix_fixture_json "$matrix_rel_path" \
  --slurpfile matrix "$matrix_json" \
  '{
    schema_version:"franken-engine.swarm-starvation-rescue-scenario-matrix-report.v1",
    source_revision:$source_revision_placeholder,
    matrix_schema_version:($matrix[0].schema_version),
    contract_json:"docs/swarm_starvation_rescue_scenario_matrix_contract_v1.json",
    matrix_fixture_json:$matrix_fixture_json,
    golden_policy:($matrix[0].golden_policy),
    required_scenario_classes:($matrix[0].required_scenario_classes),
    scenario_count:length,
    failure_count:(map(select(.matched_expected != true)) | length),
    summary:{
      pass_case_count:(map(select(.actual.decision == "pass")) | length),
      fail_closed_case_count:(map(select(.actual.decision == "fail_closed")) | length),
      mismatch_case_ids:(map(select(.matched_expected != true) | .case_id)),
      scenario_classes:(map(.scenario_class) | unique | sort)
    },
    cases:.
  }' "${case_summaries_dir}"/*.json >"$report_tmp"
mv "$report_tmp" "$report_json_path"

{
  printf '# Starvation Rescue Scenario Matrix\n\n'
  printf -- "- Matrix fixture: \`%s\`\n" "$matrix_rel_path"
  printf -- "- Scenario count: \`%s\`\n" "$(jq '.scenario_count' "$report_json_path")"
  printf -- "- Failure count: \`%s\`\n" "$(jq '.failure_count' "$report_json_path")"
  printf -- "- Pass cases: \`%s\`\n" "$(jq '.summary.pass_case_count' "$report_json_path")"
  printf -- "- Fail-closed cases: \`%s\`\n\n" "$(jq '.summary.fail_closed_case_count' "$report_json_path")"
  jq -r '
    .cases[]
    | "- `\(.case_id)` (`\(.scenario_class)`): decision=\(.actual.decision) readiness=\(.actual.readiness) local_fallback=\(.actual.local_rch_fallback_detected)"
  ' "$report_json_path"
} >"$report_path"

printf 'swarm_starvation_rescue_scenario_matrix_report_json=%s\n' "$report_json_path"
printf 'swarm_starvation_rescue_scenario_matrix_report_md=%s\n' "$report_path"

if [[ "$failure_count" -ne 0 ]]; then
  exit 1
fi
exit 0
