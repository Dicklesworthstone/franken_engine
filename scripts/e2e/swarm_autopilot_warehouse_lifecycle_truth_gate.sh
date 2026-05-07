#!/usr/bin/env bash
set -euo pipefail

run_dir=""
output_path=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_warehouse_lifecycle_truth_gate.sh --run-dir DIR [--output FILE]
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --run-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --output)
      output_path="${2:-}"
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

if [[ -z "$run_dir" ]]; then
  usage
  exit 64
fi
if [[ -z "$output_path" ]]; then
  output_path="${run_dir}/truth_gate_report.json"
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the warehouse lifecycle truth gate\n' >&2
  exit 2
fi

case_results="${run_dir}/case_results.jsonl"
commands_path="${run_dir}/commands.txt"
if [[ ! -s "$case_results" ]]; then
  printf 'missing case results: %s\n' "$case_results" >&2
  exit 64
fi

required_outputs=(
  run_manifest.json
  events.jsonl
  commands.txt
  warehouse.json
  retention_plan.json
  storage_budget_ledger.json
  promotion_candidates.json
  promotion_candidate_receipts.json
  anomaly_cohorts.json
  replay_index.json
  operator_status_bundle.json
)

missing_outputs_jsonl="${run_dir}/truth_gate_missing_outputs.jsonl"
: >"$missing_outputs_jsonl"
for artifact in "${required_outputs[@]}"; do
  if [[ ! -s "${run_dir}/${artifact}" ]]; then
    jq -nc --arg artifact "$artifact" '{artifact:$artifact}' >>"$missing_outputs_jsonl"
  fi
done

heavy_command_count="0"
if [[ -s "$commands_path" ]]; then
  heavy_command_count="$(
    grep -Ec '(^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$)|(^|[[:space:]])rch[[:space:]]+exec([[:space:]]|$)' "$commands_path" || true
  )"
fi

jq -s \
  --slurpfile missing_outputs "$missing_outputs_jsonl" \
  --argjson heavy_command_count "$heavy_command_count" \
  '
    def has_case($id): any(.[]; .scenario_id == $id);
    def case_ok($id; $decision):
      any(.[]; .scenario_id == $id and .decision == $decision and .matches_expected == true);
    def has_error($id; $code):
      any(.[]; .scenario_id == $id and (.error_codes | index($code) != null));

    {
      schema_version: "franken-engine.swarm-autopilot-warehouse-lifecycle-truth-gate.v1",
      decision: "pass",
      replay_verified: false,
      required_coverage: {
        healthy_lifecycle: case_ok("healthy_lifecycle"; "pass"),
        retention_pressure_degradation: case_ok("retention_pressure_degradation"; "degraded"),
        promotion_contradiction_block: (case_ok("promotion_contradiction_block"; "fail_closed") and has_error("promotion_contradiction_block"; "FE-SWARM-AUTOPILOT-PROMOTION-CONTRADICTORY-HINDSIGHT")),
        anomaly_cohort_replay_success: case_ok("anomaly_cohort_replay_success"; "pass"),
        local_fallback_contamination: (case_ok("local_fallback_contamination"; "fail_closed") and has_error("local_fallback_contamination"; "FE-SWARM-AUTOPILOT-WAREHOUSE-LOCAL-FALLBACK"))
      },
      case_results: .,
      missing_outputs: $missing_outputs,
      heavy_command_count: $heavy_command_count,
      failure_reasons: []
    }
    | .failure_reasons = (
        []
        + (if (.missing_outputs | length) > 0 then [{code:"FE-SWARM-AUTOPILOT-WAREHOUSE-DRILL-MISSING-OUTPUT", detail:"required lifecycle drill output is missing"}] else [] end)
        + (if .heavy_command_count > 0 then [{code:"FE-SWARM-AUTOPILOT-WAREHOUSE-DRILL-HEAVY-COMMAND", detail:"drill command log contains Cargo or rch exec"}] else [] end)
        + (if ([.required_coverage[]] | all(. == true)) then [] else [{code:"FE-SWARM-AUTOPILOT-WAREHOUSE-DRILL-COVERAGE", detail:"required lifecycle scenarios are not all covered"}] end)
      )
    | .decision = (if (.failure_reasons | length) == 0 then "pass" else "fail_closed" end)
  ' "$case_results" >"$output_path"

if jq -e '.decision == "pass"' "$output_path" >/dev/null; then
  exit 0
fi
exit 42
