#!/usr/bin/env bash
set -euo pipefail

run_dir=""
output_path=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_autopilot_forensic_diff_truth_gate.sh --run-dir DIR [--output FILE]
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
  printf 'jq is required for forensic diff truth gate\n' >&2
  exit 2
fi

case_results_path="${run_dir}/case_results.jsonl"
commands_path="${run_dir}/commands.txt"
if [[ ! -s "$case_results_path" ]]; then
  printf 'missing case results: %s\n' "$case_results_path" >&2
  exit 42
fi

missing_outputs_jsonl="${run_dir}/truth_gate_missing_outputs.jsonl"
: >"$missing_outputs_jsonl"
for required in \
  run_manifest.json \
  events.jsonl \
  commands.txt \
  warehouse.json \
  reference_anomaly_cohorts.json \
  comparison_anomaly_cohorts.json \
  reference_replay_index.json \
  comparison_replay_index.json \
  cohort_diff_receipts.json \
  fingerprint_delta_plan.json \
  replay_recipe_bundle.json \
  replay_recipe_index.json \
  forensic_hypothesis_summary.json \
  forensic_hypothesis_evidence.json \
  operator_status_bundle.json; do
  if [[ ! -s "${run_dir}/${required}" ]]; then
    jq -nc --arg path "$required" '{path:$path}' >>"$missing_outputs_jsonl"
  fi
done

heavy_command_count=0
if [[ -s "$commands_path" ]]; then
  heavy_command_count="$(grep -Ec '(^|[[:space:]])(cargo[[:space:]]+(build|check|test|clippy|bench|run)|rch[[:space:]]+exec)([[:space:]]|$)' "$commands_path" || true)"
fi

jq -s \
  --slurpfile missing "$missing_outputs_jsonl" \
  --argjson heavy_command_count "$heavy_command_count" \
  --arg schema_version "franken-engine.swarm-autopilot-forensic-diff-truth-gate.v1" \
  '
    . as $cases
    | {
        schema_version: $schema_version,
        decision: (
          if (($missing[0] | length) == 0)
             and ($heavy_command_count == 0)
             and (($cases | length) > 0)
             and all($cases[]; .matches_expected == true)
             and any($cases[]; .scenario_id == "healthy_forensic_comparison" and .matches_expected)
             and any($cases[]; .scenario_id == "blocked_locality_contradiction_replay" and .matches_expected)
             and any($cases[]; .scenario_id == "contaminated_replay_refusal" and .matches_expected)
             and any($cases[]; .scenario_id == "low_evidence_degraded_hypothesis" and .matches_expected)
             and any($cases[]; .scenario_id == "stale_reference_fail_closed" and .matches_expected)
          then "pass" else "fail_closed" end
        ),
        replay_verified: false,
        required_coverage: {
          healthy_forensic_comparison: any($cases[]; .scenario_id == "healthy_forensic_comparison" and .matches_expected),
          blocked_locality_contradiction_replay: any($cases[]; .scenario_id == "blocked_locality_contradiction_replay" and .matches_expected),
          contaminated_replay_refusal: any($cases[]; .scenario_id == "contaminated_replay_refusal" and .matches_expected),
          low_evidence_degraded_hypothesis: any($cases[]; .scenario_id == "low_evidence_degraded_hypothesis" and .matches_expected),
          stale_reference_fail_closed: any($cases[]; .scenario_id == "stale_reference_fail_closed" and .matches_expected)
        },
        case_results: $cases,
        missing_outputs: $missing[0],
        heavy_command_count: $heavy_command_count,
        failure_reasons: (
          []
          + (if (($missing[0] | length) > 0) then [{code:"FE-SWARM-AUTOPILOT-FORENSIC-DRILL-MISSING-OUTPUT",detail:"one or more required root artifacts are missing"}] else [] end)
          + (if $heavy_command_count > 0 then [{code:"FE-SWARM-AUTOPILOT-FORENSIC-DRILL-HEAVY-COMMAND",detail:"drill command log contains Cargo or RCH heavy execution"}] else [] end)
          + (if all($cases[]; .matches_expected == true) then [] else [{code:"FE-SWARM-AUTOPILOT-FORENSIC-DRILL-CASE-MISMATCH",detail:"one or more forensic scenarios did not match expected truth state"}] end)
          + (if (
              any($cases[]; .scenario_id == "healthy_forensic_comparison" and .matches_expected)
              and any($cases[]; .scenario_id == "blocked_locality_contradiction_replay" and .matches_expected)
              and any($cases[]; .scenario_id == "contaminated_replay_refusal" and .matches_expected)
              and any($cases[]; .scenario_id == "low_evidence_degraded_hypothesis" and .matches_expected)
              and any($cases[]; .scenario_id == "stale_reference_fail_closed" and .matches_expected)
            ) then [] else [{code:"FE-SWARM-AUTOPILOT-FORENSIC-DRILL-COVERAGE",detail:"required forensic scenarios are not all covered"}] end)
        )
      }
  ' "$case_results_path" >"$output_path"

if jq -e '.decision == "pass"' "$output_path" >/dev/null; then
  exit 0
fi
exit 42
