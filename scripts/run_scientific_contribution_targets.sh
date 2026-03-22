#!/usr/bin/env bash
set -euo pipefail

mode="${1:-bundle}"

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
contract_json="${root_dir}/docs/scientific_contribution_targets_v1.json"
doc_path="${root_dir}/docs/SCIENTIFIC_CONTRIBUTION_TARGETS_V1.md"
plan_path="${root_dir}/PLAN_TO_CREATE_FRANKEN_ENGINE.md"
artifact_root="${root_dir}/artifacts/scientific_contribution_targets"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
step_log_dir="${run_dir}/step_logs"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
manifest_path="${run_dir}/run_manifest.json"
contribution_report_path="${run_dir}/contribution_status_report.json"
output_contract_report_path="${run_dir}/output_contract_status_report.json"
dependency_report_path="${run_dir}/dependency_status_report.json"
summary_path="${run_dir}/scientific_contribution_summary.md"
copied_contract_path="${run_dir}/scientific_contribution_targets_v1.json"
copied_doc_path="${run_dir}/scientific_contribution_targets_v1.md"
issues_snapshot_path="${run_dir}/issue_snapshot.json"
target_dir="${root_dir}/target_rch_scientific_contribution_targets_verify"

trace_id="trace-rgc-scientific-contribution-targets-${timestamp}"
decision_id="decision-rgc-scientific-contribution-targets-${timestamp}"
policy_id="policy-scientific-contribution-targets-v1"
component="scientific_contribution_targets"

declare -a commands_run=()
declare -a validation_errors=()
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
    --arg schema_version "franken-engine.scientific-contribution-targets.event.v1" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
      schema_version: $schema_version,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: $event,
      outcome: $outcome,
      error_code: (if ($error_code | length) > 0 then $error_code else null end),
      generated_at_utc: $generated_at_utc
    }' >>"$events_path"
}

command_string() {
  printf '%q ' "$@"
}

run_logged_command() {
  local event="$1"
  shift
  local log_path
  local cmd_str
  local status=0

  log_path="$(printf '%s/step_%03d.log' "$step_log_dir" "$step_index")"
  cmd_str="$(command_string "$@")"
  commands_run+=("$cmd_str")

  if "$@" >"$log_path" 2>&1; then
    status=0
  else
    status=$?
  fi

  step_index=$((step_index + 1))

  if [[ "$status" -eq 0 ]]; then
    append_event "$event" "success"
    return 0
  fi

  append_event "$event" "failure" "command_failed"
  return 1
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
    }' >"$trace_ids_path"
}

write_commands() {
  printf '%s\n' "${commands_run[@]}" >"$commands_path"
}

copy_contract_artifacts() {
  cp "$contract_json" "$copied_contract_path"
  cp "$doc_path" "$copied_doc_path"
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
      ([issues_doc[]? | select(.id == $id)][0] // {
        id: $id,
        status: "missing",
        title: null,
        assignee: null
      });
    {
      bead_id: contract_doc.bead_id,
      required_contributions: (contract_doc.required_contributions | map(
        . + {
          bead_statuses: (.delivery_beads | map(issue_or_missing(.))),
          all_delivery_beads_closed:
            ((.delivery_beads | map(issue_or_missing(.).status == "closed")) | all)
        }
      ))
    }' >"$contribution_report_path"

  jq -n \
    --slurpfile contract "$contract_json" \
    --slurpfile issues "$issues_snapshot_path" \
    '
    def contract_doc: $contract[0];
    def issues_doc: ($issues[0] // []);
    def issue_or_missing($id):
      ([issues_doc[]? | select(.id == $id)][0] // {
        id: $id,
        status: "missing",
        title: null,
        assignee: null
      });
    {
      bead_id: contract_doc.bead_id,
      output_contract_milestones: (contract_doc.output_contract_milestones | map(
        . + {
          status_bead: issue_or_missing(.status_bead_id),
          supporting_delivery_statuses: (.supporting_delivery_beads | map(issue_or_missing(.))),
          all_supporting_delivery_beads_closed:
            ((.supporting_delivery_beads | map(issue_or_missing(.).status == "closed")) | all),
          status_bead_closed: (issue_or_missing(.status_bead_id).status == "closed"),
          milestone_closed:
            (
              (issue_or_missing(.status_bead_id).status == "closed")
              and ((.supporting_delivery_beads | map(issue_or_missing(.).status == "closed")) | all)
            )
        }
      ))
    }' >"$output_contract_report_path"

  jq -n \
    --slurpfile contract "$contract_json" \
    --slurpfile issues "$issues_snapshot_path" \
    '
    def contract_doc: $contract[0];
    def issues_doc: ($issues[0] // []);
    def issue_or_missing($id):
      ([issues_doc[]? | select(.id == $id)][0] // {
        id: $id,
        status: "missing",
        title: null,
        assignee: null
      });
    {
      bead_id: contract_doc.bead_id,
      upstream_dependencies: (contract_doc.upstream_dependencies | map(
        . + {
          bead: issue_or_missing(.bead_id),
          is_closed: (issue_or_missing(.bead_id).status == "closed")
        }
      ))
    }' >"$dependency_report_path"
}

write_summary() {
  local contributions_ok
  local milestones_ok
  local dependencies_ok
  local open_milestones

  contributions_ok="$(jq -r '[.required_contributions[].all_delivery_beads_closed] | all' "$contribution_report_path")"
  milestones_ok="$(jq -r '[.output_contract_milestones[].milestone_closed] | all' "$output_contract_report_path")"
  dependencies_ok="$(jq -r '[.upstream_dependencies[].is_closed] | all' "$dependency_report_path")"
  open_milestones="$(jq -r '
      [.output_contract_milestones[]
       | select(.milestone_closed != true)
       | "- `\(.status_bead_id)` — \(.description)"]
      | if length == 0 then "- None" else join("\n") end
    ' "$output_contract_report_path")"

  cat >"$summary_path" <<EOF
# Scientific Contribution Targets Summary

- bead: bd-2501
- generated_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- required_contributions_closed: ${contributions_ok}
- output_contract_milestones_closed: ${milestones_ok}
- upstream_dependencies_closed: ${dependencies_ok}
- ready_to_close: $(if [[ "$contributions_ok" == "true" && "$milestones_ok" == "true" && "$dependencies_ok" == "true" ]]; then echo true; else echo false; fi)
- parent_epic: bd-esst

## Open Output-Contract Milestones

${open_milestones}

## Verification Inputs

- contract: ${contract_json}
- doc: ${doc_path}
- plan: ${plan_path}
- contribution_report: ${contribution_report_path}
- output_contract_report: ${output_contract_report_path}
- dependency_report: ${dependency_report_path}
EOF
}

bundle_local_artifacts() {
  local contract_valid=false
  local source_input_path
  local -a declared_source_inputs=()

  require_command jq
  require_command br

  validation_errors=()

  if run_logged_command validate_contract jq empty "$contract_json"; then
    contract_valid=true
  else
    validation_errors+=("scientific contribution targets contract JSON is invalid")
  fi
  if ! run_logged_command validate_doc grep -q "# Scientific Contribution Targets V1" "$doc_path"; then
    validation_errors+=("scientific contribution targets doc header is missing")
  fi
  if ! run_logged_command validate_plan_source test -f "$plan_path"; then
    validation_errors+=("plan source is missing: ${plan_path}")
  fi

  if [[ "$contract_valid" == "true" ]]; then
    mapfile -t declared_source_inputs < <(jq -r '.source_inputs[]' "$contract_json")
    for source_input_path in "${declared_source_inputs[@]}"; do
      if [[ ! -e "${root_dir}/${source_input_path}" ]]; then
        validation_errors+=("declared source input is missing: ${source_input_path}")
      fi
    done
  fi

  write_reports
  copy_contract_artifacts
  write_summary

  if [[ "$(jq -r '[.required_contributions[].all_delivery_beads_closed] | all' "$contribution_report_path")" != "true" ]]; then
    validation_errors+=("scientific contribution targets have open or missing required contribution beads")
  fi
  if [[ "$(jq -r '[.output_contract_milestones[].milestone_closed] | all' "$output_contract_report_path")" != "true" ]]; then
    validation_errors+=("scientific contribution targets have open output-contract milestone beads")
  fi
  if [[ "$(jq -r '[.upstream_dependencies[].is_closed] | all' "$dependency_report_path")" != "true" ]]; then
    validation_errors+=("scientific contribution targets have open or missing upstream dependencies")
  fi

  if (( ${#validation_errors[@]} > 0 )); then
    append_event scientific_contribution_status_validation "failure" "status_bundle_incomplete"
    printf '%s\n' "${validation_errors[@]}" >&2
    return 1
  fi

  append_event scientific_contribution_status_validation "success"
  return 0
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

write_manifest() {
  local exit_code="${1:-0}"
  local outcome="pass"
  local git_commit

  if [[ "$exit_code" -ne 0 ]]; then
    outcome="fail"
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"

  jq -n \
    --arg schema_version "franken-engine.scientific-contribution-targets.run-manifest.v1" \
    --arg bead_id "bd-2501" \
    --arg mode "$mode" \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg git_commit "$git_commit" \
    --arg outcome "$outcome" \
    --arg manifest "$manifest_path" \
    --arg commands_path "$commands_path" \
    --arg events_path "$events_path" \
    --arg trace_ids_path "$trace_ids_path" \
    --arg contribution_report_path "$contribution_report_path" \
    --arg output_contract_report_path "$output_contract_report_path" \
    --arg dependency_report_path "$dependency_report_path" \
    --arg summary_path "$summary_path" \
    --arg contract_copy "$copied_contract_path" \
    --arg doc_copy "$copied_doc_path" \
    --arg step_logs "$step_log_dir" \
    --argjson validation_errors "$(printf '%s\n' "${validation_errors[@]}" | jq -R . | jq -s .)" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      mode: $mode,
      generated_at_utc: $generated_at_utc,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      git_commit: $git_commit,
      outcome: $outcome,
      validation_errors: $validation_errors,
      artifacts: {
        manifest: $manifest,
        events: $events_path,
        commands: $commands_path,
        trace_ids: $trace_ids_path,
        contribution_status_report: $contribution_report_path,
        output_contract_status_report: $output_contract_report_path,
        dependency_status_report: $dependency_report_path,
        scientific_contribution_summary: $summary_path,
        scientific_contribution_targets_contract: $contract_copy,
        scientific_contribution_targets_doc: $doc_copy,
        step_logs: $step_logs
      }
    }' >"$manifest_path"
}

prepare_bundle
write_trace_ids

main_exit=0

case "$mode" in
  check)
    run_remote_gate cargo_check cargo check -p frankenengine-engine --test scientific_contribution_targets || main_exit=$?
    if [[ "$main_exit" -eq 0 ]]; then
      bundle_local_artifacts || main_exit=$?
    fi
    ;;
  test)
    run_remote_gate cargo_test cargo test -p frankenengine-engine --test scientific_contribution_targets || main_exit=$?
    if [[ "$main_exit" -eq 0 ]]; then
      bundle_local_artifacts || main_exit=$?
    fi
    ;;
  clippy)
    run_remote_gate cargo_clippy cargo clippy -p frankenengine-engine --test scientific_contribution_targets -- -D warnings || main_exit=$?
    if [[ "$main_exit" -eq 0 ]]; then
      bundle_local_artifacts || main_exit=$?
    fi
    ;;
  bundle)
    bundle_local_artifacts || main_exit=$?
    ;;
  ci)
    run_remote_gate cargo_check cargo check -p frankenengine-engine --test scientific_contribution_targets || main_exit=$?
    if [[ "$main_exit" -eq 0 ]]; then
      run_remote_gate cargo_test cargo test -p frankenengine-engine --test scientific_contribution_targets || main_exit=$?
    fi
    if [[ "$main_exit" -eq 0 ]]; then
      run_remote_gate cargo_clippy cargo clippy -p frankenengine-engine --test scientific_contribution_targets -- -D warnings || main_exit=$?
    fi
    bundle_local_artifacts || main_exit=$?
    ;;
  *)
    echo "usage: $0 [check|test|clippy|bundle|ci]" >&2
    exit 1
    ;;
esac

write_commands
write_manifest "$main_exit"

exit "$main_exit"
