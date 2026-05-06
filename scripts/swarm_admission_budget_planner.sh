#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_ADMISSION_BUDGET_PLANNER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-admission-budget-planner}"
run_id="${SWARM_ADMISSION_BUDGET_PLANNER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_ADMISSION_BUDGET_PLANNER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

capacity_forecast_json=""
admission_requests_json=""
validation_plan_json=""
resource_decision_json=""
resource_lease_plan_json=""
source_revision=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_admission_budget_planner.sh --capacity-forecast-json FILE --admission-requests-json FILE [OPTIONS]

Converts predictive capacity forecasts into bounded dry-run admission budgets.
The planner is fixture-fed only. It does not query live br, Agent Mail, or rch,
execute Cargo, or mutate workers.

Required:
  --capacity-forecast-json FILE   franken-engine.swarm-capacity-forecast.v1 artifact
  --admission-requests-json FILE  franken-engine.swarm-admission-request-set.v1 fixture

Optional compatibility inputs:
  --validation-plan-json FILE     franken-engine.swarm-validation-plan.v1
  --resource-decision-json FILE   franken-engine.swarm-resource-decision.v1
  --resource-lease-plan-json FILE franken-engine.swarm-resource-lease-plan.v1
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_admission_budget_plan.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  at least one request admitted or admitted-narrow
  42 fail-closed due to malformed required inputs
  64 missing required path / invalid JSON / invalid schema
  75 all requests deferred
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --capacity-forecast-json)
      capacity_forecast_json="${2:-}"
      shift 2
      ;;
    --admission-requests-json)
      admission_requests_json="${2:-}"
      shift 2
      ;;
    --validation-plan-json)
      validation_plan_json="${2:-}"
      shift 2
      ;;
    --resource-decision-json)
      resource_decision_json="${2:-}"
      shift 2
      ;;
    --resource-lease-plan-json)
      resource_lease_plan_json="${2:-}"
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
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$capacity_forecast_json" || -z "$admission_requests_json" ]]; then
  printf 'swarm admission budget planner requires --capacity-forecast-json and --admission-requests-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm admission budget planning\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/swarm_admission_budget_plan.json"
plan_tmp="${plan_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

forecast_normalized="${run_dir}/capacity_forecast.normalized.json"
requests_normalized="${run_dir}/admission_requests.normalized.json"
validation_normalized="${run_dir}/validation_plan.normalized.json"
resource_normalized="${run_dir}/resource_decision.normalized.json"
lease_normalized="${run_dir}/resource_lease_plan.normalized.json"

: >"$events_path"

printf './scripts/swarm_admission_budget_planner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

json_input() {
  local path="$1"
  local default_json="$2"
  local output_path="$3"
  local label="$4"
  local required="$5"

  if [[ -z "$path" ]]; then
    if [[ "$required" == "true" ]]; then
      printf 'swarm admission budget planner missing required %s JSON\n' "$label" >&2
      exit 64
    fi
    printf '%s\n' "$default_json" >"$output_path"
    printf 'missing'
    return 0
  fi
  if [[ ! -f "$path" ]]; then
    printf 'swarm admission budget planner missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'swarm admission budget planner invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -c . "$path" >"$output_path"
  printf 'provided'
}

validate_shape() {
  local file="$1"
  local expr="$2"
  local label="$3"

  if ! jq -e "$expr" "$file" >/dev/null 2>&1; then
    printf 'swarm admission budget planner invalid %s shape\n' "$label" >&2
    exit 64
  fi
}

forecast_status="$(json_input "$capacity_forecast_json" '{}' "$forecast_normalized" 'capacity forecast' true)"
requests_status="$(json_input "$admission_requests_json" '{}' "$requests_normalized" 'admission requests' true)"
validation_status="$(json_input "$validation_plan_json" '{}' "$validation_normalized" 'validation plan' false)"
resource_status="$(json_input "$resource_decision_json" '{}' "$resource_normalized" 'resource decision' false)"
lease_status="$(json_input "$resource_lease_plan_json" '{}' "$lease_normalized" 'resource lease plan' false)"

validate_shape "$forecast_normalized" '
  .schema_version == "franken-engine.swarm-capacity-forecast.v1"
  and (.decision | type == "string")
  and (.summary | type == "object")
  and (.forecasts | type == "object")
  and (.forecasts.compile_pressure.state | type == "string")
  and (.forecasts.disk_memory_pressure.state | type == "string")
  and (.forecasts.rch_degradation.state | type == "string")
  and (.forecasts.target_dir_heat.state | type == "string")
  and (.forecasts.proof_availability.state | type == "string")
  and (.forecasts.coordination_pressure.state | type == "string")
  and (.forecasts.coordination_pressure.auto_reopen_allowed | type == "boolean")
  and (.forecasts.coordination_pressure.lease_exchange_allowed | type == "boolean")
' 'capacity forecast'
validate_shape "$requests_normalized" '
  .schema_version == "franken-engine.swarm-admission-request-set.v1"
  and (.requests | type == "array")
  and ((.requests | length) > 0)
  and all(.requests[]?;
    ((.agent_id // "") | type == "string")
    and ((.bead_id // "") | type == "string")
    and ((.requested_command // .command // "") | type == "string")
    and ((.bead_priority // .priority // 3) | tonumber? != null)
    and (((.bead_priority // .priority // 3) | tonumber) >= 1)
    and (((.bead_priority // .priority // 3) | tonumber) <= 3)
  )
' 'admission requests'

if [[ "$validation_status" == "provided" ]]; then
  validate_shape "$validation_normalized" '
    (.schema_version == "franken-engine.swarm-validation-plan.v1")
    and (.decision | type == "string")
    and (.commands | type == "array")
  ' 'validation plan'
fi
if [[ "$resource_status" == "provided" ]]; then
  validate_shape "$resource_normalized" '
    (.schema_version == "franken-engine.swarm-resource-decision.v1")
    and (.decision | type == "string")
    and (.findings | type == "array")
  ' 'resource decision'
fi
if [[ "$lease_status" == "provided" ]]; then
  validate_shape "$lease_normalized" '
    (.schema_version == "franken-engine.swarm-resource-lease-plan.v1")
    and (.lease_decision | type == "string")
    and (.reason | type == "string")
  ' 'resource lease plan'
fi

jq -n \
  --slurpfile forecast "$forecast_normalized" \
  --slurpfile requests "$requests_normalized" \
  --slurpfile validation "$validation_normalized" \
  --slurpfile resource "$resource_normalized" \
  --slurpfile lease "$lease_normalized" \
  --arg schema_version "franken-engine.swarm-admission-budget-plan.v1" \
  --arg source_revision "$source_revision" \
  --arg plan_path "$plan_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg forecast_status "$forecast_status" \
  --arg requests_status "$requests_status" \
  --arg validation_status "$validation_status" \
  --arg resource_status "$resource_status" \
  --arg lease_status "$lease_status" \
  '
  def low($x): (($x // "unknown") | tostring | ascii_downcase);
  def priority_class($n): "P" + (($n | tonumber) | tostring);
  def protected_request($r):
    (($r.bead_priority // 3) == 1) or ((($r.bead_priority // 3) == 2) and (($r.proof_obligation // false) == true));
  def risk_level($state):
    if $state == "blocked" or $state == "brownout" then "high"
    elif $state == "degraded" then "medium"
    else "low"
    end;
  def policy($profile):
    if $profile == "normal" then
      {
        profile: $profile,
        max_heavy_total: 3,
        max_per_agent_total: 2,
        p1_mode: "admit",
        p2_mode: "admit",
        p3_mode: "admit_narrow"
      }
    elif $profile == "degraded" then
      {
        profile: $profile,
        max_heavy_total: 2,
        max_per_agent_total: 1,
        p1_mode: "admit",
        p2_mode: "admit_narrow",
        p3_mode: "defer"
      }
    else
      {
        profile: $profile,
        max_heavy_total: 1,
        max_per_agent_total: 1,
        p1_mode: "admit_narrow",
        p2_mode: "admit_narrow",
        p3_mode: "defer"
      }
    end;
  def decision_scope($decision):
    if $decision == "admit" then "focused"
    elif $decision == "admit_narrow" then "narrow"
    else "deferred"
    end;
  def classify_request($r; $forecast; $validation; $resource; $lease; $policy):
    ([low($forecast.forecasts.compile_pressure.state),
      low($forecast.forecasts.disk_memory_pressure.state),
      low($forecast.forecasts.rch_degradation.state),
      low($forecast.forecasts.target_dir_heat.state),
      low($forecast.forecasts.proof_availability.state),
      low($forecast.forecasts.coordination_pressure.state)]) as $states
    | (low($forecast.forecasts.rch_degradation.state)) as $rch_state
    | (low($forecast.forecasts.disk_memory_pressure.state)) as $disk_state
    | (low($forecast.forecasts.coordination_pressure.state)) as $coord_state
    | (low($validation.decision // "unknown")) as $validation_decision
    | (low($validation.collision_risk // "none")) as $validation_collision
    | (low($resource.decision // "admit")) as $resource_decision
    | (low($lease.lease_decision // "admit")) as $lease_decision
    | {
        request_id: ($r.request_id // (($r.agent_id // "unknown-agent") + ":" + ($r.bead_id // "unknown-bead"))),
        agent_id: ($r.agent_id // "unknown-agent"),
        bead_id: ($r.bead_id // "unknown-bead"),
        bead_priority: (($r.bead_priority // $r.priority // 3) | tonumber),
        priority_class: priority_class(($r.bead_priority // $r.priority // 3)),
        requested_command: ($r.requested_command // $r.command // ""),
        planned_write_paths: ($r.planned_write_paths // []),
        changed_paths: ($r.changed_paths // []),
        docs_only: (($r.docs_only // false) == true),
        heavy_rust: (
          (($r.heavy_rust // $r.heavy // false) == true)
          or (($r.requested_command // $r.command // "") | test("(^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$)"))
        ),
        proof_obligation: (($r.proof_obligation // false) == true),
        speculative: (($r.speculative // false) == true),
        requires_ownership_confirmation: (($r.requires_ownership_confirmation // false) == true),
        protected_priority: protected_request($r),
        budget_class: (
          if protected_request($r) then "protected"
          elif (($r.speculative // false) == true) then "speculative"
          else "standard"
          end
        ),
        decision: (
          if (($r.bead_priority // $r.priority // 3) | tonumber) == 1 then $policy.p1_mode
          elif protected_request($r) then $policy.p2_mode
          else $policy.p3_mode
          end
        ),
        reasons: (
          if protected_request($r) then ["protected_priority_obligation"]
          elif (($r.speculative // false) == true) then ["speculative_work_throttled"]
          else ["lower_priority_validation"]
          end
        )
      }
    | if $policy.profile == "safe_mode" then
        .decision = (if .budget_class == "protected" then "admit_narrow" else "defer" end)
        | .reasons += ["forecast_unavailable_safe_mode"]
      else .
      end
    | if ($validation_status == "provided") and ($validation_decision == "fail_closed") then
        .decision = (if .budget_class == "protected" then "admit_narrow" else "defer" end)
        | .reasons += ["validation_plan_fail_closed"]
      else .
      end
    | if ($coord_state == "blocked") and (.requires_ownership_confirmation or (($validation_collision != "none") and ((.planned_write_paths | length) > 0))) then
        .decision = "defer"
        | .reasons += [if (($forecast.forecasts.coordination_pressure.evidence.contact_first_count // 0) > 0) then "stale_lock_contact_first" else "active_owner_manual_confirmation_required" end]
      elif ($coord_state == "blocked") and (.decision == "admit") then
        .decision = "admit_narrow"
        | .reasons += ["coordination_blocked_requires_narrow_scope"]
      elif ($coord_state == "degraded") and (.decision == "admit") then
        .decision = "admit_narrow"
        | .reasons += ["coordination_risk_requires_narrow_scope"]
      else .
      end
    | if ($rch_state != "normal") and .heavy_rust then
        .decision = (if .budget_class == "protected" then "admit_narrow" else "defer" end)
        | .reasons += ["rch_degradation_requires_narrow_scope"]
      else .
      end
    | if ($disk_state != "normal") and .heavy_rust then
        .decision = (if .budget_class == "protected" then "admit_narrow" else "defer" end)
        | .reasons += [if .budget_class == "protected" then "disk_or_memory_pressure_requires_narrow_scope" else "disk_or_memory_pressure_defers_non_protected_heavy_work" end]
      else .
      end
    | if ($resource_status == "provided") and ($resource_decision != "admit") and .heavy_rust then
        .decision = (if .budget_class == "protected" then "admit_narrow" else "defer" end)
        | .reasons += ["resource_governor_restricted"]
      else .
      end
    | if ($lease_status == "provided") and ($lease_decision | test("busy|defer|deny|fail")) and .heavy_rust then
        .decision = (if .budget_class == "protected" then "admit_narrow" else "defer" end)
        | .reasons += ["resource_lease_restricted"]
      else .
      end
    | .reasons |= unique
    | .recommended_validation_scope = decision_scope(.decision)
    | .recommended_validation_commands = (
        if .decision == "defer" then []
        elif ($validation_status == "provided") then (($validation.commands // []) | map(.display // .command // empty) | map(select(. != "")))
        else []
        end
      )
    | .safe_alternatives = (
        [($validation.safe_alternatives // [])[], ($lease.safe_alternatives // [])[]]
        | map(select(type == "string" and length > 0))
        | unique
      );

  ($forecast[0]) as $forecast
  | ($requests[0]) as $request_set
  | ($validation[0]) as $validation
  | ($resource[0]) as $resource
  | ($lease[0]) as $lease
  | ([low($forecast.forecasts.compile_pressure.state),
      low($forecast.forecasts.disk_memory_pressure.state),
      low($forecast.forecasts.rch_degradation.state),
      low($forecast.forecasts.target_dir_heat.state),
      low($forecast.forecasts.proof_availability.state),
      low($forecast.forecasts.coordination_pressure.state)]) as $states
  | (
      if low($forecast.decision) != "pass" then "safe_mode"
      elif low($forecast.summary.overall_state) == "brownout" then "high_pressure"
      elif any($states[]; . == "blocked" or . == "brownout") then "high_pressure"
      elif any($states[]; . == "degraded") then "degraded"
      else "normal"
      end
    ) as $profile
  | policy($profile) as $policy
  | ($request_set.requests
      | map({
          request_id: (.request_id // ((.agent_id // "unknown-agent") + ":" + (.bead_id // "unknown-bead") + ":" + (.requested_command // .command // "no-command"))),
          agent_id: (.agent_id // "unknown-agent"),
          bead_id: (.bead_id // "unknown-bead"),
          bead_priority: ((.bead_priority // .priority // 3) | tonumber),
          requested_command: (.requested_command // .command // ""),
          planned_write_paths: (.planned_write_paths // []),
          changed_paths: (.changed_paths // []),
          docs_only: ((.docs_only // false) == true),
          heavy_rust: ((.heavy_rust // .heavy // false) == true),
          proof_obligation: ((.proof_obligation // false) == true),
          speculative: ((.speculative // false) == true),
          requires_ownership_confirmation: ((.requires_ownership_confirmation // false) == true)
        })
      | sort_by(.bead_priority, (if .proof_obligation then 0 else 1 end), (if .speculative then 1 else 0 end), .agent_id, .bead_id, .request_id)
    ) as $sorted
  | (
      reduce $sorted[] as $request (
        {
          rows: [],
          focused_heavy_used: 0,
          agent_counts: {}
        };
        (classify_request($request; $forecast; $validation; $resource; $lease; $policy)) as $base
        | (($base.agent_id // "unknown-agent")) as $agent_id
        | ((.agent_counts[$agent_id] // 0)) as $agent_used
        | if $base.decision == "defer" then
            .rows += [$base]
          else
            (
              if ($base.heavy_rust and $base.decision == "admit" and .focused_heavy_used >= $policy.max_heavy_total) then
                if $base.budget_class == "protected" then
                  $base + {
                    decision: "admit_narrow",
                    reasons: ($base.reasons + ["global_heavy_budget_exhausted"] | unique),
                    recommended_validation_scope: "narrow"
                  }
                else
                  $base + {
                    decision: "defer",
                    reasons: ($base.reasons + ["global_heavy_budget_exhausted"] | unique),
                    recommended_validation_scope: "deferred",
                    recommended_validation_commands: []
                  }
                end
              else
                $base
              end
            ) as $after_heavy
            | (
              if ($agent_used >= $policy.max_per_agent_total) then
                if ($after_heavy.budget_class == "protected") and ($after_heavy.decision == "admit") then
                  $after_heavy + {
                    decision: "admit_narrow",
                    reasons: ($after_heavy.reasons + ["agent_fair_share_exhausted"] | unique),
                    recommended_validation_scope: "narrow"
                  }
                else
                  $after_heavy + {
                    decision: "defer",
                    reasons: ($after_heavy.reasons + ["agent_fair_share_exhausted"] | unique),
                    recommended_validation_scope: "deferred",
                    recommended_validation_commands: []
                  }
                end
              else
                $after_heavy
              end
            ) as $final
            | .rows += [$final]
            | if $final.decision != "defer" then
                .agent_counts[$agent_id] = ($agent_used + 1)
              else .
              end
            | if ($final.decision == "admit") and $final.heavy_rust then
                .focused_heavy_used += 1
              else .
              end
          end
      )
    ) as $state
  | ($state.rows | sort_by(.bead_priority, .agent_id, .bead_id, .request_id)) as $rows
  | ($rows | map(.reasons[]) | unique | sort) as $reason_codes
  | ($rows | map(select(.decision == "admit")) | length) as $admit_count
  | ($rows | map(select(.decision == "admit_narrow")) | length) as $narrow_count
  | ($rows | map(select(.decision == "defer")) | length) as $defer_count
  | ($rows | map(.agent_id) | unique | sort) as $agent_ids
  | ($rows | map(.priority_class) | unique | sort) as $priority_classes
  | {
      schema_version: $schema_version,
      source_revision: $source_revision,
      decision: (
        if $admit_count > 0 and $narrow_count == 0 and $defer_count == 0 then "admit"
        elif ($admit_count + $narrow_count) > 0 then "admit_narrow"
        else "defer"
        end
      ),
      budget_profile: $policy.profile,
      protected_priority_classes: ["P1", "P2"],
      forecast_status: {
        decision: ($forecast.decision // "unknown"),
        confidence_band: ($forecast.confidence_band // "unknown"),
        overall_state: ($forecast.summary.overall_state // "unknown"),
        brownout_state: ($forecast.summary.brownout_state // "unknown")
      },
      budget_policy: {
        max_focused_heavy_total: $policy.max_heavy_total,
        max_admitted_requests_per_agent: $policy.max_per_agent_total,
        protected_priorities: ["P1", "P2"],
        priority_modes: {
          P1: $policy.p1_mode,
          P2: $policy.p2_mode,
          P3: $policy.p3_mode
        }
      },
      reason_codes: $reason_codes,
      summary: {
        requested_count: ($rows | length),
        admitted_count: $admit_count,
        admitted_narrow_count: $narrow_count,
        deferred_count: $defer_count,
        focused_heavy_admissions: ($rows | map(select(.decision == "admit" and .heavy_rust)) | length),
        blocked_categories: ($forecast.summary.blocked_categories // []),
        degraded_categories: ($forecast.summary.degraded_categories // [])
      },
      priority_budgets: (
        ["P1", "P2", "P3"]
        | map(
            . as $priority
            | {
                priority_class: $priority,
                configured_mode: (
                  if $priority == "P1" then $policy.p1_mode
                  elif $priority == "P2" then $policy.p2_mode
                  else $policy.p3_mode
                  end
                ),
                requested: ($rows | map(select(.priority_class == $priority)) | length),
                protected_requests: ($rows | map(select(.priority_class == $priority and .budget_class == "protected")) | length),
                decisions: {
                  admit: ($rows | map(select(.priority_class == $priority and .decision == "admit")) | length),
                  admit_narrow: ($rows | map(select(.priority_class == $priority and .decision == "admit_narrow")) | length),
                  defer: ($rows | map(select(.priority_class == $priority and .decision == "defer")) | length)
                }
              }
          )
      ),
      agent_budgets: (
        $agent_ids
        | map(
            . as $agent
            | {
                agent_id: $agent,
                max_admitted_requests: $policy.max_per_agent_total,
                requested: ($rows | map(select(.agent_id == $agent)) | length),
                decisions: {
                  admit: ($rows | map(select(.agent_id == $agent and .decision == "admit")) | length),
                  admit_narrow: ($rows | map(select(.agent_id == $agent and .decision == "admit_narrow")) | length),
                  defer: ($rows | map(select(.agent_id == $agent and .decision == "defer")) | length)
                },
                focused_heavy_admissions: ($rows | map(select(.agent_id == $agent and .decision == "admit" and .heavy_rust)) | length)
              }
          )
      ),
      recommendations: $rows,
      warnings: [
        (if $policy.profile == "safe_mode" then "capacity_forecast_safe_mode_active" else empty end),
        (if $validation_status == "missing" then "validation_plan_missing_budgeting_from_forecast_only" else empty end),
        (if $resource_status == "missing" then "resource_decision_missing_budgeting_from_forecast_only" else empty end),
        (if $lease_status == "missing" then "resource_lease_plan_missing_budgeting_from_forecast_only" else empty end)
      ],
      resolved_inputs: [
        {input:"capacity_forecast_json", status:$forecast_status, path:($forecast.artifact_paths.swarm_capacity_forecast_json // null), schema_version:($forecast.schema_version // null)},
        {input:"admission_requests_json", status:$requests_status, path:null, schema_version:($request_set.schema_version // null)},
        {input:"validation_plan_json", status:$validation_status, path:($validation.artifact_paths.plan_json // null), schema_version:($validation.schema_version // null)},
        {input:"resource_decision_json", status:$resource_status, path:null, schema_version:($resource.schema_version // null)},
        {input:"resource_lease_plan_json", status:$lease_status, path:($lease.artifact_paths.resource_lease_plan_json // null), schema_version:($lease.schema_version // null)}
      ],
      artifact_paths: {
        swarm_admission_budget_plan_json: $plan_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      },
      contract_paths: {
        budget_contract_json: "docs/swarm_admission_budget_planner_contract_v1.json",
        dashboard_contract_json: "docs/swarm_predictive_dashboard_contract_v1.json"
      }
    }
  ' >"$plan_tmp"
mv "$plan_tmp" "$plan_path"

jq -nc \
  --arg schema_version "franken-engine.swarm-admission-budget-plan.event.v1" \
  --arg event_name "swarm_admission_budget_planner.completed" \
  --arg decision "$(jq -r '.decision' "$plan_path")" \
  --arg profile "$(jq -r '.budget_profile' "$plan_path")" \
  --arg plan_json "$plan_path" \
  '{
    schema_version: $schema_version,
    event_name: $event_name,
    decision: $decision,
    budget_profile: $profile,
    plan_json: $plan_json
  }' >>"$events_path"

{
  printf '# Swarm Admission Budget Plan\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$plan_path")"
  printf -- "- Budget profile: \`%s\`\n" "$(jq -r '.budget_profile' "$plan_path")"
  printf -- "- Requested: \`%s\`\n" "$(jq '.summary.requested_count' "$plan_path")"
  printf -- "- Admitted: \`%s\`\n" "$(jq '.summary.admitted_count' "$plan_path")"
  printf -- "- Admit narrow: \`%s\`\n" "$(jq '.summary.admitted_narrow_count' "$plan_path")"
  printf -- "- Deferred: \`%s\`\n" "$(jq '.summary.deferred_count' "$plan_path")"
  printf -- "- Focused heavy admissions: \`%s\`\n" "$(jq '.summary.focused_heavy_admissions' "$plan_path")"
  printf -- "- Protected priorities: \`%s\`\n" "$(jq -r '.protected_priority_classes | join(", ")' "$plan_path")"
} >"$report_path"

case "$(jq -r '.decision' "$plan_path")" in
  admit|admit_narrow)
    exit 0
    ;;
  defer)
    exit 75
    ;;
  *)
    exit 42
    ;;
esac
