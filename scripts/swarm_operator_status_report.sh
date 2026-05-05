#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_OPERATOR_STATUS_REPORT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-operator-status}"
run_id="${SWARM_OPERATOR_STATUS_REPORT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_OPERATOR_STATUS_REPORT_RUN_DIR:-${artifact_root}/${run_id}}"
bead_id="${SWARM_OPERATOR_STATUS_REPORT_BEAD_ID:-bd-jw854}"
source_revision="${SWARM_OPERATOR_STATUS_REPORT_SOURCE_REVISION:-smoke-rev}"
agent_mail_status="unknown"
rch_status="unknown"
proof_index_status="unknown"

ready_json=""
in_progress_json=""
bv_plan_json=""
reservations_json=""
resource_decision_json=""
validation_plan_json=""
proof_index_json=""
proof_outcomes_json=""
stale_evidence_json=""
dirty_files_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_operator_status_report.sh [OPTIONS]

Builds a fixture-fed operator status report. Inputs are explicit JSON snapshots
from br/bv, Agent Mail, rch, validation plans, resource decisions, and proof
evidence. The script does not claim beads, edit tracker state, or query live
services by itself.

Options:
  --output-dir DIR
  --bead-id ID
  --source-revision REV
  --agent-mail-status ok|degraded|missing|unknown
  --rch-status ok|degraded|missing|unknown
  --proof-index-status ok|degraded|missing|unknown
  --ready-json FILE
  --in-progress-json FILE
  --bv-plan-json FILE
  --reservations-json FILE
  --resource-decision-json FILE
  --validation-plan-json FILE
  --proof-index-json FILE
  --proof-outcomes-json FILE
  --stale-evidence-json FILE
  --dirty-files-json FILE
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      run_dir="$2"
      shift 2
      ;;
    --bead-id)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      bead_id="$2"
      shift 2
      ;;
    --source-revision)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      source_revision="$2"
      shift 2
      ;;
    --agent-mail-status)
      agent_mail_status="$2"
      shift 2
      ;;
    --rch-status)
      rch_status="$2"
      shift 2
      ;;
    --proof-index-status)
      proof_index_status="$2"
      shift 2
      ;;
    --ready-json)
      ready_json="$2"
      shift 2
      ;;
    --in-progress-json)
      in_progress_json="$2"
      shift 2
      ;;
    --bv-plan-json)
      bv_plan_json="$2"
      shift 2
      ;;
    --reservations-json)
      reservations_json="$2"
      shift 2
      ;;
    --resource-decision-json)
      resource_decision_json="$2"
      shift 2
      ;;
    --validation-plan-json)
      validation_plan_json="$2"
      shift 2
      ;;
    --proof-index-json)
      proof_index_json="$2"
      shift 2
      ;;
    --proof-outcomes-json)
      proof_outcomes_json="$2"
      shift 2
      ;;
    --stale-evidence-json)
      stale_evidence_json="$2"
      shift 2
      ;;
    --dirty-files-json)
      dirty_files_json="$2"
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

mkdir -p "$run_dir"
status_path="${run_dir}/status.json"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

printf './scripts/swarm_operator_status_report.sh' >"$commands_path"
printf ' --output-dir %q' "$run_dir" >>"$commands_path"
printf '\n' >>"$commands_path"

json_or_default() {
  local path="$1"
  local default_json="$2"
  local label="$3"

  if [[ -z "$path" ]]; then
    printf '%s' "$default_json"
    return 0
  fi
  if [[ ! -f "$path" ]]; then
    printf 'swarm-operator-status missing %s file: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null; then
    printf 'swarm-operator-status invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -c . "$path"
}

ready_data="$(json_or_default "$ready_json" '[]' 'ready')"
in_progress_data="$(json_or_default "$in_progress_json" '[]' 'in-progress')"
bv_plan_data="$(json_or_default "$bv_plan_json" '{"plan":{"tracks":[]}}' 'bv-plan')"
reservations_data="$(json_or_default "$reservations_json" '[]' 'reservations')"
resource_decision_data="$(json_or_default "$resource_decision_json" '{"decision":"unknown","findings":[]}' 'resource-decision')"
validation_plan_data="$(json_or_default "$validation_plan_json" '{"decision":"unknown","commands":[],"omitted_commands":[]}' 'validation-plan')"
proof_index_data="$(json_or_default "$proof_index_json" '{"queries":[]}' 'proof-index')"
proof_outcomes_data="$(json_or_default "$proof_outcomes_json" '[]' 'proof-outcomes')"
stale_evidence_data="$(json_or_default "$stale_evidence_json" '[]' 'stale-evidence')"
dirty_files_data="$(json_or_default "$dirty_files_json" '[]' 'dirty-files')"

# shellcheck disable=SC2094
jq -n \
  --arg schema_version "franken-engine.swarm-operator-status-report.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg agent_mail_status "$agent_mail_status" \
  --arg rch_status "$rch_status" \
  --arg proof_index_status "$proof_index_status" \
  --arg status_path "$status_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --argjson ready "$ready_data" \
  --argjson in_progress "$in_progress_data" \
  --argjson bv_plan "$bv_plan_data" \
  --argjson reservations "$reservations_data" \
  --argjson resource_decision "$resource_decision_data" \
  --argjson validation_plan "$validation_plan_data" \
  --argjson proof_index "$proof_index_data" \
  --argjson proof_outcomes "$proof_outcomes_data" \
  --argjson stale_evidence "$stale_evidence_data" \
  --argjson dirty_files "$dirty_files_data" \
  '
  def degraded($component; $status; $impact; $remediation):
    if ($status == "ok") then empty
    else {component: $component, status: $status, impact: $impact, remediation: $remediation}
    end;
  def bead_row:
    {
      id: .id,
      title: .title,
      priority: (.priority // null),
      status: (.status // null),
      assignee: (.assignee // null)
    };
  def recommendation($action; $bead; $reason):
    {action: $action, bead_id: $bead, reason: $reason};

  ($ready | map(bead_row) | sort_by(.priority // 999, .id)) as $ready_rows
  | ($in_progress | map(bead_row) | sort_by(.id)) as $in_progress_rows
  | ($dirty_files | map(select(.reserved == true or .overlaps_ready == true))) as $dirty_reserved
  | ($stale_evidence | map(select((.stale // false) == true))) as $stale
  | ($proof_outcomes | map(select((.status // "") | test("fail|blocked|stale")))) as $bad_proofs
  | ([($bv_plan.plan.tracks // [])[]?.items[]? | select((.status // "") == "blocked")]) as $blocked_items
  | ([
      degraded("agent_mail"; $agent_mail_status; "reservation and inbox data may be incomplete"; "Use bead assignee and dirty paths as degraded fallback evidence."),
      degraded("rch"; $rch_status; "remote proof routing may be unavailable"; "Defer heavy validation until rch status is ok or use script-only proof."),
      degraded("proof_evidence_index"; $proof_index_status; "proof queries may be incomplete"; "Use explicit proof outcome snapshots until bd-p03vs lands.")
    ]
    + (if (($validation_plan.decision // "") == "fail_closed") then
        [{component: "validation_plan", status: "fail_closed", impact: "planned validation cannot run safely", remediation: "Fix unknown path mappings or ownership before running validation."}]
      else [] end)
    + (if (($resource_decision.decision // "") | IN("defer", "fail_closed")) then
        [{component: "resource_governor", status: ($resource_decision.decision // "unknown"), impact: "resource admission is not green", remediation: "Follow resource-governor remediation before starting heavy validation."}]
      else [] end)
    + ($dirty_reserved | map({component: "dirty_reserved_file", status: "degraded", impact: (.path + " is dirty or reserved"), remediation: "Avoid this file or coordinate with the holder."}))
    + ($stale | map({component: "stale_proof_artifact", status: "degraded", impact: (.artifact_id + " is stale"), remediation: "Refresh or mark the proof stale before relying on it."}))
    + ($bad_proofs | map({component: "proof_outcome", status: (.status // "degraded"), impact: (.bead_id + " proof is not passing"), remediation: "Inspect the proof outcome before recommending dependent work."}))
    + ($blocked_items | map({component: "blocked_bead_chain", status: "blocked", impact: (.id + " is blocked in the bv track"), remediation: "Inspect dependencies before recommending this bead."}))
    ) as $degraded
  | {
      schema_version: $schema_version,
      bead_id: $bead_id,
      source_revision: $source_revision,
      status: (if ($degraded | length) == 0 then "healthy" else "degraded" end),
      tui_ready: true,
      summary: {
        ready_count: ($ready_rows | length),
        in_progress_count: ($in_progress_rows | length),
        reservation_count: ($reservations | length),
        degraded_count: ($degraded | length),
        planned_command_count: (($validation_plan.commands // []) | length),
        stale_evidence_count: ($stale | length),
        dirty_reserved_count: ($dirty_reserved | length),
        blocked_bead_count: ($blocked_items | length)
      },
      services: {
        agent_mail: $agent_mail_status,
        rch: $rch_status,
        proof_evidence_index: $proof_index_status
      },
      ready_beads: $ready_rows,
      in_progress_beads: $in_progress_rows,
      bv_tracks: ($bv_plan.plan.tracks // []),
      active_reservations: ($reservations | sort_by(.path // .path_pattern // "")),
      resource_decision: $resource_decision,
      validation_plan: {
        decision: ($validation_plan.decision // "unknown"),
        commands: ($validation_plan.commands // []),
        omitted_commands: ($validation_plan.omitted_commands // [])
      },
      proof_evidence_index: $proof_index,
      proof_outcomes: ($proof_outcomes | sort_by(.bead_id // "", .artifact_id // "")),
      stale_evidence: ($stale_evidence | sort_by(.artifact_id // "")),
      dirty_files: ($dirty_files | sort_by(.path)),
      degraded: $degraded,
      recommendations: (
        if ($dirty_reserved | length) != 0 then
          [recommendation("avoid_dirty_reserved_files"; null; "dirty or reserved files overlap active work")]
        elif ($agent_mail_status != "ok") then
          [recommendation("use_degraded_coordination"; null; "Agent Mail is not healthy")]
        elif (($resource_decision.decision // "") == "admit" or ($resource_decision.decision // "") == "admit_narrow") and ($ready_rows | length) > 0 then
          [recommendation("pick_next_ready_bead"; $ready_rows[0].id; "resource governor admits validation and bead is ready")]
        elif (($resource_decision.decision // "") == "defer") then
          [recommendation("defer_heavy_validation"; null; "resource governor reports pressure")]
        else
          [recommendation("inspect_degraded_fields"; null; "one or more required status surfaces are degraded")]
        end
      ),
      artifact_paths: {
        status_json: $status_path,
        commands_txt: $commands_path,
        report_md: $report_path
      }
    }
  ' >"$status_path"

{
  printf '# Swarm Operator Status\n\n'
  printf -- "- Status: \`%s\`\n" "$(jq -r '.status' "$status_path")"
  printf -- "- Ready beads: \`%s\`\n" "$(jq '.summary.ready_count' "$status_path")"
  printf -- "- In progress: \`%s\`\n" "$(jq '.summary.in_progress_count' "$status_path")"
  printf -- "- Degraded fields: \`%s\`\n\n" "$(jq '.summary.degraded_count' "$status_path")"
  jq -r '.recommendations[] | "- `" + .action + "`" + (if .bead_id == null then "" else " for `" + .bead_id + "`" end) + ": " + .reason' "$status_path"
  if [[ "$(jq '.degraded | length' "$status_path")" -ne 0 ]]; then
    printf '\n## Degraded\n\n'
    jq -r '.degraded[] | "- `" + .component + "` `" + .status + "`: " + .impact + ". " + .remediation' "$status_path"
  fi
} >"$report_path"

printf 'swarm_operator_status_report=%s\n' "$status_path"
printf 'swarm_operator_status_markdown=%s\n' "$report_path"
