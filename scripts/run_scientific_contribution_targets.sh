#!/usr/bin/env bash
set -euo pipefail

mode="${1:-bundle}"

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
contract_json="${root_dir}/docs/scientific_contribution_targets_v1.json"
doc_path="${root_dir}/docs/SCIENTIFIC_CONTRIBUTION_TARGETS_V1.md"
report_catalog_json="${root_dir}/docs/scientific_report_catalog_v1.json"
report_catalog_doc_path="${root_dir}/docs/SCIENTIFIC_REPORT_CATALOG_V1.md"
external_replication_catalog_json="${root_dir}/docs/external_replication_catalog_v1.json"
external_replication_catalog_doc_path="${root_dir}/docs/EXTERNAL_REPLICATION_CATALOG_V1.md"
open_tool_adoption_catalog_json="${root_dir}/docs/open_tool_adoption_catalog_v1.json"
open_tool_adoption_catalog_doc_path="${root_dir}/docs/OPEN_TOOL_ADOPTION_CATALOG_V1.md"
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
technical_report_status_path="${run_dir}/technical_report_status_report.json"
external_replication_status_path="${run_dir}/external_replication_status_report.json"
open_tool_adoption_status_path="${run_dir}/open_tool_adoption_status_report.json"
summary_path="${run_dir}/scientific_contribution_summary.md"
copied_contract_path="${run_dir}/scientific_contribution_targets_v1.json"
copied_doc_path="${run_dir}/scientific_contribution_targets_v1.md"
copied_report_catalog_json_path="${run_dir}/scientific_report_catalog_v1.json"
copied_report_catalog_doc_path="${run_dir}/SCIENTIFIC_REPORT_CATALOG_V1.md"
copied_external_replication_catalog_json_path="${run_dir}/external_replication_catalog_v1.json"
copied_external_replication_catalog_doc_path="${run_dir}/EXTERNAL_REPLICATION_CATALOG_V1.md"
copied_open_tool_adoption_catalog_json_path="${run_dir}/open_tool_adoption_catalog_v1.json"
copied_open_tool_adoption_catalog_doc_path="${run_dir}/OPEN_TOOL_ADOPTION_CATALOG_V1.md"
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
  cp "$report_catalog_json" "$copied_report_catalog_json_path"
  cp "$report_catalog_doc_path" "$copied_report_catalog_doc_path"
  cp "$external_replication_catalog_json" "$copied_external_replication_catalog_json_path"
  cp "$external_replication_catalog_doc_path" "$copied_external_replication_catalog_doc_path"
  cp "$open_tool_adoption_catalog_json" "$copied_open_tool_adoption_catalog_json_path"
  cp "$open_tool_adoption_catalog_doc_path" "$copied_open_tool_adoption_catalog_doc_path"
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

  jq -n \
    --slurpfile catalog "$report_catalog_json" \
    --slurpfile issues "$issues_snapshot_path" \
    '
    def catalog_doc: $catalog[0];
    def issues_doc: ($issues[0] // []);
    def issue_or_missing($id):
      ([issues_doc[]? | select(.id == $id)][0] // {
        id: $id,
        status: "missing",
        title: null,
        assignee: null
      });
    {
      bead_id: catalog_doc.bead_id,
      minimum_report_count: catalog_doc.minimum_report_count,
      report_count: (catalog_doc.reports | length),
      report_count_requirement_met: ((catalog_doc.reports | length) >= catalog_doc.minimum_report_count),
      reports: (catalog_doc.reports | map(
        . + {
          status_bead: issue_or_missing(.status_bead_id),
          supporting_bead_statuses: (.supporting_beads | map(issue_or_missing(.))),
          primary_doc_exists: false
        }
      ))
    }' >"$technical_report_status_path"

  while IFS=$'\t' read -r report_id primary_doc; do
    local doc_exists=false
    if [[ -f "${root_dir}/${primary_doc}" ]]; then
      doc_exists=true
    fi

    jq \
      --arg report_id "$report_id" \
      --argjson doc_exists "$doc_exists" \
      '(.reports[] | select(.report_id == $report_id).primary_doc_exists) = $doc_exists' \
      "$technical_report_status_path" >"${technical_report_status_path}.tmp"
    mv "${technical_report_status_path}.tmp" "$technical_report_status_path"
  done < <(jq -r '.reports[] | [.report_id, .primary_doc] | @tsv' "$technical_report_status_path")

  jq \
    '
    .reports |= map(
      . + {
        status_bead_closed: (.status_bead.status == "closed"),
        supporting_beads_closed: ((.supporting_bead_statuses | map(.status == "closed")) | all),
        verification_commands_declared: ((.verification_commands | length) > 0),
        artifact_root_declared: ((.artifact_root | length) > 0),
        ready_for_publication: (
          .status_bead.status == "closed"
          and ((.supporting_bead_statuses | map(.status == "closed")) | all)
          and .primary_doc_exists
          and ((.verification_commands | length) > 0)
          and ((.artifact_root | length) > 0)
        )
      }
    )
    ' "$technical_report_status_path" >"${technical_report_status_path}.tmp"
  mv "${technical_report_status_path}.tmp" "$technical_report_status_path"

  jq -n \
    --slurpfile catalog "$external_replication_catalog_json" \
    --slurpfile issues "$issues_snapshot_path" \
    '
    def catalog_doc: $catalog[0];
    def issues_doc: ($issues[0] // []);
    def issue_or_missing($id):
      ([issues_doc[]? | select(.id == $id)][0] // {
        id: $id,
        status: "missing",
        title: null,
        assignee: null
      });
    {
      bead_id: catalog_doc.bead_id,
      minimum_claim_count: catalog_doc.minimum_claim_count,
      claim_count: (catalog_doc.claims | length),
      claim_count_requirement_met: ((catalog_doc.claims | length) >= catalog_doc.minimum_claim_count),
      claims: (catalog_doc.claims | map(
        . + {
          status_bead: issue_or_missing(.status_bead_id),
          supporting_bead_statuses: (.supporting_beads | map(issue_or_missing(.))),
          primary_doc_exists: false,
          verifier_doc_exists: false
        }
      ))
    }' >"$external_replication_status_path"

  while IFS=$'\t' read -r claim_id primary_doc verifier_doc; do
    local primary_doc_exists=false
    local verifier_doc_exists=false
    if [[ -f "${root_dir}/${primary_doc}" ]]; then
      primary_doc_exists=true
    fi
    if [[ -f "${root_dir}/${verifier_doc}" ]]; then
      verifier_doc_exists=true
    fi

    jq \
      --arg claim_id "$claim_id" \
      --argjson primary_doc_exists "$primary_doc_exists" \
      --argjson verifier_doc_exists "$verifier_doc_exists" \
      '(.claims[] | select(.claim_id == $claim_id).primary_doc_exists) = $primary_doc_exists
       | (.claims[] | select(.claim_id == $claim_id).verifier_doc_exists) = $verifier_doc_exists' \
      "$external_replication_status_path" >"${external_replication_status_path}.tmp"
    mv "${external_replication_status_path}.tmp" "$external_replication_status_path"
  done < <(jq -r '.claims[] | [.claim_id, .primary_doc, .verifier_doc] | @tsv' "$external_replication_status_path")

  jq \
    '
    .claims |= map(
      . + {
        status_bead_closed: (.status_bead.status == "closed"),
        supporting_beads_closed: ((.supporting_bead_statuses | map(.status == "closed")) | all),
        verification_commands_declared: ((.verification_commands | length) > 0),
        artifact_root_declared: ((.artifact_root | length) > 0),
        ready_for_external_replication: (
          .status_bead.status == "closed"
          and ((.supporting_bead_statuses | map(.status == "closed")) | all)
          and .primary_doc_exists
          and .verifier_doc_exists
          and ((.verification_commands | length) > 0)
          and ((.artifact_root | length) > 0)
        )
      }
    )
    ' "$external_replication_status_path" >"${external_replication_status_path}.tmp"
  mv "${external_replication_status_path}.tmp" "$external_replication_status_path"

  jq -n \
    --slurpfile catalog "$open_tool_adoption_catalog_json" \
    --slurpfile issues "$issues_snapshot_path" \
    '
    def catalog_doc: $catalog[0];
    def issues_doc: ($issues[0] // []);
    def issue_or_missing($id):
      ([issues_doc[]? | select(.id == $id)][0] // {
        id: $id,
        status: "missing",
        title: null,
        assignee: null
      });
    {
      bead_id: catalog_doc.bead_id,
      minimum_tool_count: catalog_doc.minimum_tool_count,
      tool_count: (catalog_doc.tools | length),
      tool_count_requirement_met: ((catalog_doc.tools | length) >= catalog_doc.minimum_tool_count),
      tools: (catalog_doc.tools | map(
        . + {
          release_status_bead: issue_or_missing(.release_status_bead_id),
          supporting_bead_statuses: (.supporting_beads | map(issue_or_missing(.))),
          primary_doc_exists: false,
          adoption_evidence_doc_exists: false
        }
      ))
    }' >"$open_tool_adoption_status_path"

  while IFS=$'\t' read -r tool_id primary_doc adoption_evidence_doc; do
    local primary_doc_exists=false
    local adoption_evidence_doc_exists=false
    if [[ -f "${root_dir}/${primary_doc}" ]]; then
      primary_doc_exists=true
    fi
    if [[ -f "${root_dir}/${adoption_evidence_doc}" ]]; then
      adoption_evidence_doc_exists=true
    fi

    jq \
      --arg tool_id "$tool_id" \
      --argjson primary_doc_exists "$primary_doc_exists" \
      --argjson adoption_evidence_doc_exists "$adoption_evidence_doc_exists" \
      '(.tools[] | select(.tool_id == $tool_id).primary_doc_exists) = $primary_doc_exists
       | (.tools[] | select(.tool_id == $tool_id).adoption_evidence_doc_exists) = $adoption_evidence_doc_exists' \
      "$open_tool_adoption_status_path" >"${open_tool_adoption_status_path}.tmp"
    mv "${open_tool_adoption_status_path}.tmp" "$open_tool_adoption_status_path"
  done < <(jq -r '.tools[] | [.tool_id, .primary_doc, .adoption_evidence_doc] | @tsv' "$open_tool_adoption_status_path")

  jq \
    '
    .tools |= map(
      . + {
        release_status_bead_closed: (.release_status_bead.status == "closed"),
        supporting_beads_closed: ((.supporting_bead_statuses | map(.status == "closed")) | all),
        verification_commands_declared: ((.verification_commands | length) > 0),
        artifact_root_declared: ((.artifact_root | length) > 0),
        release_ready: (
          .release_status_bead.status == "closed"
          and ((.supporting_bead_statuses | map(.status == "closed")) | all)
          and .primary_doc_exists
          and ((.verification_commands | length) > 0)
          and ((.artifact_root | length) > 0)
        ),
        ready_for_external_adoption: (
          .release_status_bead.status == "closed"
          and ((.supporting_bead_statuses | map(.status == "closed")) | all)
          and .primary_doc_exists
          and .adoption_evidence_doc_exists
          and ((.verification_commands | length) > 0)
          and ((.artifact_root | length) > 0)
        )
      }
    )
    ' "$open_tool_adoption_status_path" >"${open_tool_adoption_status_path}.tmp"
  mv "${open_tool_adoption_status_path}.tmp" "$open_tool_adoption_status_path"
}

write_summary() {
  local contributions_ok
  local milestones_ok
  local dependencies_ok
  local report_catalog_ok
  local external_replication_catalog_ok
  local open_tool_catalog_ok
  local ready_reports
  local ready_external_claims
  local release_ready_tools
  local adoption_ready_tools
  local open_milestones
  local not_ready_reports
  local not_ready_external_claims
  local not_ready_tools

  contributions_ok="$(jq -r '[.required_contributions[].all_delivery_beads_closed] | all' "$contribution_report_path")"
  milestones_ok="$(jq -r '[.output_contract_milestones[].milestone_closed] | all' "$output_contract_report_path")"
  dependencies_ok="$(jq -r '[.upstream_dependencies[].is_closed] | all' "$dependency_report_path")"
  report_catalog_ok="$(jq -r '.report_count_requirement_met' "$technical_report_status_path")"
  external_replication_catalog_ok="$(jq -r '.claim_count_requirement_met' "$external_replication_status_path")"
  open_tool_catalog_ok="$(jq -r '.tool_count_requirement_met' "$open_tool_adoption_status_path")"
  ready_reports="$(jq -r '[.reports[] | select(.ready_for_publication == true)] | length' "$technical_report_status_path")"
  ready_external_claims="$(jq -r '[.claims[] | select(.ready_for_external_replication == true)] | length' "$external_replication_status_path")"
  release_ready_tools="$(jq -r '[.tools[] | select(.release_ready == true)] | length' "$open_tool_adoption_status_path")"
  adoption_ready_tools="$(jq -r '[.tools[] | select(.ready_for_external_adoption == true)] | length' "$open_tool_adoption_status_path")"
  open_milestones="$(jq -r '
      [.output_contract_milestones[]
       | select(.milestone_closed != true)
       | "- `\(.status_bead_id)` — \(.description)"]
      | if length == 0 then "- None" else join("\n") end
    ' "$output_contract_report_path")"
  not_ready_reports="$(jq -r '
      [.reports[]
       | select(.ready_for_publication != true)
       | "- `\(.report_id)` — status bead `\(.status_bead_id)` is `\(.status_bead.status)`"]
      | if length == 0 then "- None" else join("\n") end
    ' "$technical_report_status_path")"
  not_ready_external_claims="$(jq -r '
      [.claims[]
       | select(.ready_for_external_replication != true)
       | "- `\(.claim_id)` — status bead `\(.status_bead_id)` is `\(.status_bead.status)`"]
      | if length == 0 then "- None" else join("\n") end
    ' "$external_replication_status_path")"
  not_ready_tools="$(jq -r '
      [.tools[]
       | select(.ready_for_external_adoption != true)
       | "- `\(.tool_id)` — release bead `\(.release_status_bead_id)` is `\(.release_status_bead.status)`, adoption evidence doc present: \(.adoption_evidence_doc_exists)"]
      | if length == 0 then "- None" else join("\n") end
    ' "$open_tool_adoption_status_path")"

  cat >"$summary_path" <<EOF
# Scientific Contribution Targets Summary

- bead: bd-2501
- generated_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- required_contributions_closed: ${contributions_ok}
- output_contract_milestones_closed: ${milestones_ok}
- upstream_dependencies_closed: ${dependencies_ok}
- report_catalog_threshold_met: ${report_catalog_ok}
- external_replication_catalog_threshold_met: ${external_replication_catalog_ok}
- open_tool_catalog_threshold_met: ${open_tool_catalog_ok}
- ready_reports: ${ready_reports}
- ready_external_replication_claims: ${ready_external_claims}
- release_ready_tools: ${release_ready_tools}
- ready_for_external_adoption_tools: ${adoption_ready_tools}
- ready_to_close: $(if [[ "$contributions_ok" == "true" && "$milestones_ok" == "true" && "$dependencies_ok" == "true" && "$report_catalog_ok" == "true" && "$external_replication_catalog_ok" == "true" && "$open_tool_catalog_ok" == "true" ]]; then echo true; else echo false; fi)
- parent_epic: bd-esst

## Open Output-Contract Milestones

${open_milestones}

## Report Lanes Not Yet Ready

${not_ready_reports}

## External Replication Lanes Not Yet Ready

${not_ready_external_claims}

## Tool Lanes Not Yet Externally Adopted

${not_ready_tools}

## Verification Inputs

- contract: ${contract_json}
- doc: ${doc_path}
- report_catalog_doc: ${report_catalog_doc_path}
- report_catalog_json: ${report_catalog_json}
- external_replication_catalog_doc: ${external_replication_catalog_doc_path}
- external_replication_catalog_json: ${external_replication_catalog_json}
- open_tool_adoption_catalog_doc: ${open_tool_adoption_catalog_doc_path}
- open_tool_adoption_catalog_json: ${open_tool_adoption_catalog_json}
- plan: ${plan_path}
- contribution_report: ${contribution_report_path}
- output_contract_report: ${output_contract_report_path}
- dependency_report: ${dependency_report_path}
- technical_report_status_report: ${technical_report_status_path}
- external_replication_status_report: ${external_replication_status_path}
- open_tool_adoption_status_report: ${open_tool_adoption_status_path}
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
  if ! run_logged_command validate_report_catalog_json jq empty "$report_catalog_json"; then
    validation_errors+=("scientific report catalog JSON is invalid")
  fi
  if ! run_logged_command validate_report_catalog_doc grep -q "# Scientific Report Catalog V1" "$report_catalog_doc_path"; then
    validation_errors+=("scientific report catalog doc header is missing")
  fi
  if ! run_logged_command validate_external_replication_catalog_json jq empty "$external_replication_catalog_json"; then
    validation_errors+=("external replication catalog JSON is invalid")
  fi
  if ! run_logged_command validate_external_replication_catalog_doc grep -q "# External Replication Catalog V1" "$external_replication_catalog_doc_path"; then
    validation_errors+=("external replication catalog doc header is missing")
  fi
  if ! run_logged_command validate_open_tool_adoption_catalog_json jq empty "$open_tool_adoption_catalog_json"; then
    validation_errors+=("open tool adoption catalog JSON is invalid")
  fi
  if ! run_logged_command validate_open_tool_adoption_catalog_doc grep -q "# Open Tool Adoption Catalog V1" "$open_tool_adoption_catalog_doc_path"; then
    validation_errors+=("open tool adoption catalog doc header is missing")
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
  if [[ "$(jq -r '.report_count_requirement_met' "$technical_report_status_path")" != "true" ]]; then
    validation_errors+=("scientific report catalog has fewer than four declared report lanes")
  fi
  if [[ "$(jq -r '.claim_count_requirement_met' "$external_replication_status_path")" != "true" ]]; then
    validation_errors+=("external replication catalog has fewer than two declared claim lanes")
  fi
  if [[ "$(jq -r '.tool_count_requirement_met' "$open_tool_adoption_status_path")" != "true" ]]; then
    validation_errors+=("open tool adoption catalog has fewer than one declared tool lane")
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
    --arg technical_report_status_path "$technical_report_status_path" \
    --arg external_replication_status_path "$external_replication_status_path" \
    --arg open_tool_adoption_status_path "$open_tool_adoption_status_path" \
    --arg summary_path "$summary_path" \
    --arg contract_copy "$copied_contract_path" \
    --arg doc_copy "$copied_doc_path" \
    --arg report_catalog_json_copy "$copied_report_catalog_json_path" \
    --arg report_catalog_doc_copy "$copied_report_catalog_doc_path" \
    --arg external_replication_catalog_json_copy "$copied_external_replication_catalog_json_path" \
    --arg external_replication_catalog_doc_copy "$copied_external_replication_catalog_doc_path" \
    --arg open_tool_adoption_catalog_json_copy "$copied_open_tool_adoption_catalog_json_path" \
    --arg open_tool_adoption_catalog_doc_copy "$copied_open_tool_adoption_catalog_doc_path" \
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
        technical_report_status_report: $technical_report_status_path,
        external_replication_status_report: $external_replication_status_path,
        open_tool_adoption_status_report: $open_tool_adoption_status_path,
        scientific_contribution_summary: $summary_path,
        scientific_contribution_targets_contract: $contract_copy,
        scientific_contribution_targets_doc: $doc_copy,
        scientific_report_catalog_json: $report_catalog_json_copy,
        scientific_report_catalog_doc: $report_catalog_doc_copy,
        external_replication_catalog_json: $external_replication_catalog_json_copy,
        external_replication_catalog_doc: $external_replication_catalog_doc_copy,
        open_tool_adoption_catalog_json: $open_tool_adoption_catalog_json_copy,
        open_tool_adoption_catalog_doc: $open_tool_adoption_catalog_doc_copy,
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
