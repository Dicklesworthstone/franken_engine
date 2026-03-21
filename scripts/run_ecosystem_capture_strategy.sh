#!/usr/bin/env bash
set -euo pipefail

mode="${1:-ci}"

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
contract_json="${root_dir}/docs/ecosystem_capture_strategy_v1.json"
doc_path="${root_dir}/docs/ECOSYSTEM_CAPTURE_STRATEGY_V1.md"
artifact_root="${root_dir}/artifacts/ecosystem_capture_strategy"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
step_log_dir="${run_dir}/step_logs"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
manifest_path="${run_dir}/run_manifest.json"
milestone_report_path="${run_dir}/milestone_status_report.json"
blocker_report_path="${run_dir}/blocker_status_report.json"
summary_path="${run_dir}/strategy_summary.md"
copied_contract_path="${run_dir}/ecosystem_capture_strategy_v1.json"
copied_doc_path="${run_dir}/ecosystem_capture_strategy_v1.md"
issues_snapshot_path="${run_dir}/issue_snapshot.json"
target_dir="${root_dir}/target_rch_ecosystem_capture_strategy_verify"

trace_id="trace-rgc-ecosystem-capture-strategy-${timestamp}"
decision_id="decision-rgc-ecosystem-capture-strategy-${timestamp}"
policy_id="policy-ecosystem-capture-strategy-v1"
component="ecosystem_capture_strategy"

declare -a commands_run=()
step_index=0

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

append_event() {
  local event="$1"
  local outcome="$2"
  local error_code="${3:-}"
  jq -nc \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: $event,
      outcome: $outcome,
      error_code: (if ($error_code | length) > 0 then $error_code else null end),
      generated_at_utc: $generated_at_utc
    }' >> "$events_path"
}

command_string() {
  printf '%q ' "$@"
}

run_logged_command() {
  local event="$1"
  shift
  local log_path
  local cmd_str
  log_path="$(printf '%s/step_%03d.log' "$step_log_dir" "$step_index")"
  cmd_str="$(command_string "$@")"
  commands_run+=("$cmd_str")
  if "$@" >"$log_path" 2>&1; then
    append_event "$event" "success"
  else
    append_event "$event" "failure" "command_failed"
    return 1
  fi
  step_index=$((step_index + 1))
}

prepare_bundle() {
  mkdir -p "$step_log_dir"
  : >"$events_path"
}

write_trace_ids() {
  jq -n \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    '{
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component
    }' > "$trace_ids_path"
}

write_commands() {
  printf '%s\n' "${commands_run[@]}" >"$commands_path"
}

write_reports() {
  br list --all --json 2>/dev/null >"$issues_snapshot_path"

  jq -n \
    --slurpfile contract "$contract_json" \
    --slurpfile issues "$issues_snapshot_path" \
    '
    def contract_doc: $contract[0];
    def issues_doc: ($issues[0] // []);
    def issue_or_missing($id):
      ([ issues_doc[]? | select(.id == $id) ][0] // {
        id: $id,
        status: "missing",
        title: null,
        assignee: null
      });
    {
      bead_id: contract_doc.bead_id,
      execution_pillars: (contract_doc.execution_pillars | map(
        . + {
          bead_statuses: (.delivery_beads | map(issue_or_missing(.))),
          all_delivery_beads_closed:
            ((.delivery_beads | map(issue_or_missing(.).status == "closed")) | all)
        }
      )),
      adoption_targets: (contract_doc.adoption_targets | map(
        . + {
          bead_statuses: (.delivery_beads | map(issue_or_missing(.))),
          all_delivery_beads_closed:
            ((.delivery_beads | map(issue_or_missing(.).status == "closed")) | all)
        }
      ))
    }' > "$milestone_report_path"

  jq -n \
    --slurpfile contract "$contract_json" \
    --slurpfile issues "$issues_snapshot_path" \
    '
    def contract_doc: $contract[0];
    def issues_doc: ($issues[0] // []);
    def issue_or_missing($id):
      ([ issues_doc[]? | select(.id == $id) ][0] // {
        id: $id,
        status: "missing",
        title: null,
        assignee: null
      });
    {
      bead_id: contract_doc.bead_id,
      upstream_prerequisites: (contract_doc.upstream_prerequisites | map(
        . + {
          bead: issue_or_missing(.bead_id),
          is_closed: (issue_or_missing(.bead_id).status == "closed")
        }
      ))
    }' > "$blocker_report_path"

  cp "$contract_json" "$copied_contract_path"
  cp "$doc_path" "$copied_doc_path"
}

write_summary() {
  local pillars_ok
  local targets_ok
  local blockers_ok

  pillars_ok="$(jq -r '[.execution_pillars[].all_delivery_beads_closed] | all' "$milestone_report_path")"
  targets_ok="$(jq -r '[.adoption_targets[].all_delivery_beads_closed] | all' "$milestone_report_path")"
  blockers_ok="$(jq -r '[.upstream_prerequisites[].is_closed] | all' "$blocker_report_path")"

  cat >"$summary_path" <<EOF
# Ecosystem Capture Strategy Summary

- bead: bd-3bz4
- generated_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- execution_pillars_closed: ${pillars_ok}
- adoption_targets_closed: ${targets_ok}
- upstream_prerequisites_closed: ${blockers_ok}
- ready_to_close: $(if [[ "$pillars_ok" == "true" && "$targets_ok" == "true" && "$blockers_ok" == "true" ]]; then echo true; else echo false; fi)
- parent_epic: bd-1jak

## Verification Inputs

- contract: ${contract_json}
- doc: ${doc_path}
- milestone_report: ${milestone_report_path}
- blocker_report: ${blocker_report_path}
EOF
}

write_manifest() {
  jq -n \
    --arg schema_version "franken-engine.ecosystem-capture-strategy.run-manifest.v1" \
    --arg mode "$mode" \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg commands_path "$commands_path" \
    --arg events_path "$events_path" \
    --arg trace_ids_path "$trace_ids_path" \
    --arg milestone_report_path "$milestone_report_path" \
    --arg blocker_report_path "$blocker_report_path" \
    --arg summary_path "$summary_path" \
    --arg contract_copy "$copied_contract_path" \
    --arg doc_copy "$copied_doc_path" \
    --slurpfile contract "$contract_json" \
    '{
      schema_version: $schema_version,
      mode: $mode,
      generated_at_utc: $generated_at_utc,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      contract_schema_version: $contract[0].schema_version,
      artifacts: [
        $commands_path,
        $events_path,
        $trace_ids_path,
        $milestone_report_path,
        $blocker_report_path,
        $summary_path,
        $contract_copy,
        $doc_copy
      ]
    }' > "$manifest_path"
}

bundle_local_artifacts() {
  require_command jq
  require_command br

  run_logged_command validate_contract jq empty "$contract_json"
  run_logged_command validate_doc grep -q "# Ecosystem Capture Strategy V1" "$doc_path"
  write_reports
  write_summary

  if [[ "$(jq -r '[.execution_pillars[].all_delivery_beads_closed] | all' "$milestone_report_path")" != "true" ]]; then
    append_event "validate_execution_pillars" "failure" "open_execution_pillar"
    echo "ecosystem capture strategy has open execution pillars" >&2
    exit 1
  fi
  if [[ "$(jq -r '[.adoption_targets[].all_delivery_beads_closed] | all' "$milestone_report_path")" != "true" ]]; then
    append_event "validate_adoption_targets" "failure" "open_adoption_target"
    echo "ecosystem capture strategy has open adoption targets" >&2
    exit 1
  fi
  if [[ "$(jq -r '[.upstream_prerequisites[].is_closed] | all' "$blocker_report_path")" != "true" ]]; then
    append_event "validate_upstream_prerequisites" "failure" "open_upstream_prerequisite"
    echo "ecosystem capture strategy has open upstream prerequisites" >&2
    exit 1
  fi

  append_event "validate_execution_pillars" "success"
  append_event "validate_adoption_targets" "success"
  append_event "validate_upstream_prerequisites" "success"
}

run_remote_gate() {
  local event="$1"
  shift
  require_command rch
  run_logged_command "$event" \
    timeout 5400 \
    rch exec -- \
    env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR="$target_dir" CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 \
    "$@"
}

prepare_bundle
write_trace_ids

case "$mode" in
  check)
    run_remote_gate cargo_check cargo check -p frankenengine-engine --test ecosystem_capture_strategy
    ;;
  test)
    run_remote_gate cargo_test cargo test -p frankenengine-engine --test ecosystem_capture_strategy
    ;;
  clippy)
    run_remote_gate cargo_clippy cargo clippy -p frankenengine-engine --test ecosystem_capture_strategy -- -D warnings
    ;;
  bundle)
    bundle_local_artifacts
    ;;
  ci)
    run_remote_gate cargo_check cargo check -p frankenengine-engine --test ecosystem_capture_strategy
    run_remote_gate cargo_test cargo test -p frankenengine-engine --test ecosystem_capture_strategy
    run_remote_gate cargo_clippy cargo clippy -p frankenengine-engine --test ecosystem_capture_strategy -- -D warnings
    bundle_local_artifacts
    ;;
  *)
    echo "usage: $0 [check|test|clippy|bundle|ci]" >&2
    exit 1
    ;;
esac

write_commands
write_manifest
