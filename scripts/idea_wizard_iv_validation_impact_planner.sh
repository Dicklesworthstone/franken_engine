#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${IDEA_WIZARD_IV_VALIDATION_IMPACT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-iw4-validation-impact}"
run_id="${IDEA_WIZARD_IV_VALIDATION_IMPACT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${IDEA_WIZARD_IV_VALIDATION_IMPACT_RUN_DIR:-${artifact_root}/${run_id}}"
bead_id="${IDEA_WIZARD_IV_VALIDATION_IMPACT_BEAD_ID:-bd-k53rr}"
source_revision="${IDEA_WIZARD_IV_VALIDATION_IMPACT_SOURCE_REVISION:-}"
original_args=("$@")
declare -a planner_args=()
changed_path_count=0

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/idea_wizard_iv_validation_impact_planner.sh --changed-path PATH [OPTIONS]

Emit an IDEA-WIZARD-IV validation_impact_plan.json by reusing the existing
swarm validation planner. This adapter is advisory only and never executes
recommended validation commands.

Options:
  --bead-id ID
  --source-revision REV
  --output-dir DIR
  --changed-path PATH
  --planned-write-path PATH
  --proof-cost-history-json PATH
  --reservation-snapshot-json PATH
  --in-progress-json PATH
  --native-route-advisory-json PATH
  --package PACKAGE
  --test-target TARGET
  --allow-broad
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bead-id)
      bead_id="${2:-}"
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
    --changed-path)
      planner_args+=("--changed-path" "${2:-}")
      changed_path_count=$((changed_path_count + 1))
      shift 2
      ;;
    --planned-write-path|--proof-cost-history-json|--reservation-snapshot-json|--in-progress-json|--native-route-advisory-json|--package|--test-target)
      planner_args+=("$1" "${2:-}")
      shift 2
      ;;
    --allow-broad)
      planner_args+=("$1")
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
    *)
      planner_args+=("--changed-path" "$1")
      changed_path_count=$((changed_path_count + 1))
      shift
      ;;
  esac
done

if [[ "$changed_path_count" -eq 0 ]]; then
  printf 'idea-wizard-iv validation impact planner requires at least one --changed-path\n' >&2
  usage
  exit 64
fi

if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
planner_dir="${run_dir}/swarm_validation_planner"
plan_path="${run_dir}/validation_impact_plan.json"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
trace_ids_path="${run_dir}/trace_ids.json"
planner_stdout="${run_dir}/swarm_validation_planner.stdout"
planner_stderr="${run_dir}/swarm_validation_planner.stderr"

: >"$events_path"
printf './scripts/idea_wizard_iv_validation_impact_planner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.idea-wizard-iv-validation-impact.event.v1" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    --arg bead_id "$bead_id" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event:$event,outcome:$outcome,detail:$detail,bead_id:$bead_id,source_revision:$source_revision}' >>"$events_path"
}

write_event "planner_start" "started" "invoking swarm validation planner"
set +e
SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE="${SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE-}" \
  "$root_dir/scripts/swarm_validation_planner.sh" \
  --bead-id "$bead_id" \
  --source-revision "$source_revision" \
  --output-dir "$planner_dir" \
  "${planner_args[@]}" >"$planner_stdout" 2>"$planner_stderr"
planner_status=$?
set -e

if [[ "$planner_status" -ne 0 && "$planner_status" -ne 42 ]]; then
  write_event "planner_complete" "error" "underlying planner exited unexpectedly"
  cat "$planner_stderr" >&2
  exit "$planner_status"
fi

planner_plan="${planner_dir}/plan.json"
if [[ ! -f "$planner_plan" ]]; then
  write_event "planner_complete" "error" "underlying planner did not emit plan.json"
  exit 66
fi

planner_decision="$(jq -r '.decision' "$planner_plan")"
if [[ "$planner_decision" == "fail_closed" || "$planner_status" -eq 42 ]]; then
  decision="fail_closed"
  proof_sufficiency="insufficient"
elif [[ "$planner_decision" == "admit" ]]; then
  decision="green"
  proof_sufficiency="sufficient_focused"
else
  decision="degraded"
  proof_sufficiency="sufficient_with_degraded_coordination"
fi

unsafe_heavy_count="$(
  jq '[.commands[]? | select((.command_kind | startswith("rch_cargo")) and ((.display | startswith("rch exec -- env CARGO_TARGET_DIR=")) | not))] | length' "$planner_plan"
)"
if [[ "$unsafe_heavy_count" -ne 0 ]]; then
  decision="fail_closed"
  proof_sufficiency="insufficient"
fi

jq -n \
  --arg schema_version "franken-engine.idea-wizard-iv-validation-impact-plan.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg proof_sufficiency "$proof_sufficiency" \
  --arg planner_decision "$planner_decision" \
  --arg planner_plan_path "$planner_plan" \
  --arg planner_collision_path "${planner_dir}/collision_receipt.json" \
  --arg run_dir "$run_dir" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg events_path "$events_path" \
  --arg manifest_path "$manifest_path" \
  --argjson unsafe_heavy_count "$unsafe_heavy_count" \
  --slurpfile planner "$planner_plan" '
    ($planner[0] // {}) as $p
    | {
        schema_version: $schema_version,
        bead_id: $bead_id,
        source_revision: $source_revision,
        decision: $decision,
        proof_sufficiency: $proof_sufficiency,
        underlying_planner_decision: $planner_decision,
        changed_paths: ($p.changed_paths // []),
        planned_write_paths: ($p.planned_write_paths // []),
        cost_class: (
          if (($p.commands // []) | length) == 0 then "none"
          elif any($p.commands[]?; (.predicted_cost.cost_class // "unknown") == "high") then "high"
          elif any($p.commands[]?; (.predicted_cost.cost_class // "unknown") == "medium") then "medium"
          elif any($p.commands[]?; (.predicted_cost.cost_class // "unknown") == "unknown") then "unknown"
          else "low"
          end
        ),
        recommended_commands: [
          ($p.commands // [])[]
          | {
              command_id,
              display,
              command_kind,
              package,
              target,
              cost_class: (.predicted_cost.cost_class // "unknown"),
              cost_evidence_status: (.cost_evidence.status // "unknown"),
              rch_wrapped: (
                if (.command_kind | startswith("rch_cargo")) then
                  (.display | startswith("rch exec -- env CARGO_TARGET_DIR="))
                else
                  true
                end
              ),
              risk_flags: (.risk_flags // [])
            }
        ],
        path_mappings: ($p.path_mappings // []),
        omitted_commands: ($p.omitted_commands // []),
        warnings: ($p.warnings // []),
        reason_codes: (
          (($p.reason_codes // [])
          + (if $unsafe_heavy_count > 0 then ["FE-IW4-BARE-HEAVY-CARGO"] else [] end))
          | sort
          | unique
        ),
        rch_policy: {
          advisory_only: true,
          executes_recommended_commands: false,
          required_heavy_cargo_prefix: "rch exec -- env CARGO_TARGET_DIR=",
          unsafe_heavy_command_count: $unsafe_heavy_count
        },
        mutation_policy: {
          advisory_only: true,
          proof_only: true,
          mutates_br: false,
          sends_agent_mail: false,
          repairs_agent_mail_db: false,
          runs_cargo: false,
          runs_rch: false,
          mutates_git: false,
          mutates_remote_workers: false
        },
        source_planner_artifacts: {
          plan_json: $planner_plan_path,
          collision_receipt_json: $planner_collision_path
        },
        artifact_paths: {
          run_dir: $run_dir,
          validation_impact_plan_json: ($run_dir + "/validation_impact_plan.json"),
          run_manifest_json: $manifest_path,
          events_jsonl: $events_path,
          commands_txt: $commands_path,
          report_md: $report_path
        }
      }' >"$plan_path"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-iv-validation-impact.run-manifest.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg run_dir "$run_dir" \
  --arg plan_path "$plan_path" \
  --arg planner_plan "$planner_plan" \
  '{
    schema_version: $schema_version,
    bead_id: $bead_id,
    source_revision: $source_revision,
    decision: $decision,
    run_dir: $run_dir,
    artifacts: {
      validation_impact_plan_json: $plan_path,
      source_planner_plan_json: $planner_plan
    }
  }' >"$manifest_path"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-iv-validation-impact.trace-ids.v1" \
  --arg trace_id "iw4-validation-impact-${run_id}" \
  --arg bead_id "$bead_id" \
  '{schema_version:$schema_version,trace_id:$trace_id,bead_id:$bead_id}' >"$trace_ids_path"

{
  printf '# IDEA-WIZARD-IV Validation Impact Plan\n\n'
  printf -- "- Bead: \`%s\`\n" "$bead_id"
  printf -- "- Decision: \`%s\`\n" "$decision"
  printf -- "- Proof sufficiency: \`%s\`\n" "$proof_sufficiency"
  printf -- "- Underlying planner decision: \`%s\`\n" "$planner_decision"
  printf -- "- Recommended commands: \`%s\`\n\n" "$(jq '.recommended_commands | length' "$plan_path")"
  jq -r '.recommended_commands[]? | "- `" + .command_id + "`: " + .display + " (cost: `" + .cost_class + "`, rch_wrapped: `" + (.rch_wrapped|tostring) + "`)"' "$plan_path"
  if [[ "$(jq '.omitted_commands | length' "$plan_path")" -ne 0 ]]; then
    printf '\n## Omitted Commands\n\n'
    jq -r '.omitted_commands[] | "- `" + .kind + "` for `" + .path + "`: " + .reason' "$plan_path"
  fi
} >"$report_path"

{
  printf '\n# recommended validation commands\n'
  jq -r '.recommended_commands[]?.display' "$plan_path"
} >>"$commands_path"

write_event "planner_complete" "$decision" "validation impact plan emitted"
printf 'validation_impact_plan=%s\n' "$plan_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
