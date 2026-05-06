#!/usr/bin/env bash
set -euo pipefail

artifact_root="${PROOF_ECONOMY_WHAT_IF_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-proof-economy-what-if}"
run_id="${PROOF_ECONOMY_WHAT_IF_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${PROOF_ECONOMY_WHAT_IF_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

replay_trace_json=""
counterfactual_report_json=""
brownout_report_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/proof_economy_operator_what_if_report.sh --replay-trace-json FILE [OPTIONS]

Builds an operator-facing proof-economy what-if report and dashboard contract
from replay artifacts. This script emits JSON and Markdown only; future
interactive UI surfaces must reuse /dp/frankentui.

Required:
  --replay-trace-json FILE

Optional:
  --counterfactual-report-json FILE
  --brownout-report-json FILE
  --output-dir DIR

Artifacts:
  what_if_report.json
  dashboard_contract.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  report generated without fail-closed diagnostics
  42 missing required replay artifacts or brownout fail-closed
  64 invalid input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --replay-trace-json)
      replay_trace_json="${2:-}"
      shift 2
      ;;
    --counterfactual-report-json)
      counterfactual_report_json="${2:-}"
      shift 2
      ;;
    --brownout-report-json)
      brownout_report_json="${2:-}"
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

if [[ -z "$replay_trace_json" ]]; then
  printf 'operator what-if report requires --replay-trace-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for operator what-if reporting\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for operator what-if reporting\n' >&2
  exit 2
fi
if [[ ! -f "$replay_trace_json" ]]; then
  printf 'operator what-if report missing replay trace JSON: %s\n' "$replay_trace_json" >&2
  exit 64
fi
if ! jq -e '.schema_version == "franken-engine.proof-economy-replay-trace.v1"' \
  "$replay_trace_json" >/dev/null; then
  printf 'replay trace must use franken-engine.proof-economy-replay-trace.v1: %s\n' "$replay_trace_json" >&2
  exit 64
fi

mkdir -p "$run_dir"
trace_normalized="${run_dir}/replay_trace.normalized.json"
counterfactual_normalized="${run_dir}/counterfactual_report.normalized.json"
brownout_normalized="${run_dir}/brownout_report.normalized.json"
missing_inputs_path="${run_dir}/missing_inputs.json"
report_core="${run_dir}/what_if_report.core.json"
report_tmp="${run_dir}/what_if_report.json.tmp"
report_path="${run_dir}/what_if_report.json"
dashboard_path="${run_dir}/dashboard_contract.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
human_report_path="${run_dir}/report.md"
: >"$events_path"

jq -cS . "$replay_trace_json" >"$trace_normalized"
missing_inputs=()

if [[ -z "$counterfactual_report_json" || ! -f "$counterfactual_report_json" ]]; then
  missing_inputs+=("counterfactual_report")
  jq -n '{missing: true}' >"$counterfactual_normalized"
elif ! jq -e '.schema_version == "franken-engine.proof-economy-counterfactual-replay-report.v1"' \
  "$counterfactual_report_json" >/dev/null; then
  printf 'counterfactual report must use franken-engine.proof-economy-counterfactual-replay-report.v1: %s\n' \
    "$counterfactual_report_json" >&2
  exit 64
else
  jq -cS . "$counterfactual_report_json" >"$counterfactual_normalized"
fi

if [[ -z "$brownout_report_json" || ! -f "$brownout_report_json" ]]; then
  missing_inputs+=("brownout_report")
  jq -n '{missing: true}' >"$brownout_normalized"
elif ! jq -e '.schema_version == "franken-engine.proof-queue-brownout-report.v1"' \
  "$brownout_report_json" >/dev/null; then
  printf 'brownout report must use franken-engine.proof-queue-brownout-report.v1: %s\n' \
    "$brownout_report_json" >&2
  exit 64
else
  jq -cS . "$brownout_report_json" >"$brownout_normalized"
fi

printf '%s\n' "${missing_inputs[@]}" | jq -R 'select(length > 0)' | jq -s . >"$missing_inputs_path"

printf './scripts/proof_economy_operator_what_if_report.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg event "$1" \
    --arg detail "$2" \
    '{event: $event, detail: $detail}' >>"$events_path"
}

write_event "inputs_loaded" "loaded operator what-if replay artifacts"

jq -n \
  --slurpfile trace "$trace_normalized" \
  --slurpfile counterfactual "$counterfactual_normalized" \
  --slurpfile brownout "$brownout_normalized" \
  --slurpfile missing "$missing_inputs_path" \
  '
  def command_match($commands; $decision):
    first($commands[]? | select(
      (.bead_id // "") == ($decision.bead_id // "")
      and (.agent_id // "") == ($decision.agent_id // "")
    ));
  def policy_match($policies; $policy_name):
    first($policies[]? | select((.policy_name // "") == ($policy_name // "")));
  def fair_share_score($outcomes):
    (first($outcomes[]? | select(.policy_name == "fair_share")) // {}) as $fair
    | (1000000 - (($fair.max_agent_slot_share_millionths // 1000000))) as $score
    | if $score < 0 then 0 else $score end;
  def p1_slo_risk($outcomes):
    if any($outcomes[]?; (.p1_slo_risk // "unknown") != "protected") then "at_risk" else "protected" end;
  def brownout_state($brownout):
    if ($brownout.missing // false) then "missing"
    elif ($brownout.policy_decision // "") == "fail_closed" then "fail_closed"
    elif (($brownout.severity_counts.warning // 0) > 0) then "warning"
    else "nominal"
    end;
  def recommended_action($state; $p1; $missing_count):
    if $missing_count > 0 then
      "Provide the missing replay artifacts and rerun the what-if report before making scheduling changes."
    elif $state == "fail_closed" then
      "Pause broad proof fanout, drain protected P1/P2 work, refresh queue capacity, and rerun counterfactual replay."
    elif $p1 == "at_risk" then
      "Protect P1 lanes first and defer broad proof work until P1 SLO risk returns to protected."
    elif $state == "warning" then
      "Apply bounded remediation from the brownout findings and rerun the report before escalating."
    else
      "Continue with the selected fair-share policy and keep replay artifacts for audit."
    end;
  ($trace[0]) as $t
  | ($counterfactual[0]) as $cf
  | ($brownout[0]) as $bo
  | ($missing[0]) as $missing_inputs
  | ($t.command_rows // []) as $commands
  | ($cf.policy_matrix // []) as $policies
  | ($cf.policy_outcomes // []) as $outcomes
  | (brownout_state($bo)) as $brownout_state
  | (p1_slo_risk($outcomes)) as $p1_slo
  | (recommended_action($brownout_state; $p1_slo; ($missing_inputs | length))) as $action
  | (
      [ $outcomes[]? as $outcome
        | ($outcome.changed_commands // [])[]? as $changed
        | {
            link_id: ("what-if-link-" + (($outcome.policy_name // "policy") | gsub("[^A-Za-z0-9]+"; "-") | ascii_downcase) + "-" + (($changed.bead_id // "bead") | gsub("[^A-Za-z0-9]+"; "-") | ascii_downcase)),
            policy_name: ($outcome.policy_name // "unknown"),
            bead_id: ($changed.bead_id // ""),
            agent_id: ($changed.agent_id // ""),
            before: ($changed.before // ""),
            after: ($changed.after // ""),
            fairness_reason: ($changed.fairness_reason // ""),
            explanation: ($changed.explanation // ""),
            policy_input_evidence: {
              policy_matrix: policy_match($policies; $outcome.policy_name),
              trace_command: command_match($commands; $changed),
              counterfactual_policy_id: ($outcome.policy_id // "unknown"),
              brownout_findings: [ ($bo.findings // [])[]? | select((.evidence.bead_id // "") == ($changed.bead_id // "") or (.code // "") == "queue_brownout_all_workers_busy") ]
            }
          } ]
    ) as $evidence_links
  | (
      [ $missing_inputs[]? | {
          finding_id: ("missing-" + .),
          severity: "error",
          code: ("missing_" + .),
          message: ("Required replay artifact is missing: " + .),
          remediation: "Provide this artifact path and rerun the operator what-if report."
        } ]
      + [ ($bo.findings // [])[]? | select(.severity == "error") | {
          finding_id: (.finding_id // ("brownout-" + (.code // "error"))),
          severity: "error",
          code: (.code // "brownout_error"),
          message: (.message // "Brownout report failed closed."),
          remediation: (.remediation // "Review brownout report and rerun replay.")
        } ]
    ) as $findings
  | {
      trace_id: ($t.trace_id // "unknown"),
      counterfactual_id: ($cf.counterfactual_id // null),
      brownout_id: ($bo.brownout_id // null),
      policy_decision: (if ($findings | length) > 0 then "fail_closed" else "pass" end),
      dashboard: {
        queue_depth: ($t.summary.command_count // ($commands | length)),
        fair_share_score_millionths: fair_share_score($outcomes),
        p1_slo_risk: $p1_slo,
        brownout_state: $brownout_state,
        recommended_operator_action: $action
      },
      dashboard_contract: {
        schema_version: "franken-engine.proof-economy-operator-dashboard-contract.v1",
        ui_reuse_policy: "Future interactive UI must reuse /dp/frankentui; this artifact is JSON/Markdown only.",
        field_inventory: [
          {field: "queue_depth", type: "integer", source_json_pointer: "/dashboard/queue_depth", required: true},
          {field: "fair_share_score_millionths", type: "integer", source_json_pointer: "/dashboard/fair_share_score_millionths", required: true},
          {field: "p1_slo_risk", type: "string", source_json_pointer: "/dashboard/p1_slo_risk", required: true},
          {field: "brownout_state", type: "string", source_json_pointer: "/dashboard/brownout_state", required: true},
          {field: "recommended_operator_action", type: "string", source_json_pointer: "/dashboard/recommended_operator_action", required: true}
        ]
      },
      changed_decision_evidence_links: $evidence_links,
      findings: $findings,
      summary: {
        changed_decision_count: ($evidence_links | length),
        missing_artifact_count: ($missing_inputs | length),
        finding_count: ($findings | length)
      }
    }
  ' >"$report_core"

what_if_hash="$(jq -cS . "$report_core" | sha256sum | awk '{print "what-if-" substr($1, 1, 16)}')"

jq \
  --arg schema_version "franken-engine.proof-economy-operator-what-if-report.v1" \
  --arg what_if_id "$what_if_hash" \
  --arg report_path "$report_path" \
  --arg dashboard_path "$dashboard_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg human_report_path "$human_report_path" \
  '. + {
    schema_version: $schema_version,
    what_if_id: $what_if_id,
    hash_basis: {
      what_if_hash: $what_if_id
    },
    artifact_paths: {
      what_if_report_json: $report_path,
      dashboard_contract_json: $dashboard_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $human_report_path
    }
  }' "$report_core" >"$report_tmp"
mv "$report_tmp" "$report_path"

jq \
  --arg what_if_id "$what_if_hash" \
  --arg report_path "$report_path" \
  '.dashboard_contract + {
    what_if_id: $what_if_id,
    report_json: $report_path,
    dashboard_sample: .dashboard
  }' "$report_path" >"$dashboard_path"

write_event "what_if_reported" "$what_if_hash"

{
  printf '# Proof Economy Operator What-If Report\n\n'
  printf -- '- What-if ID: %s\n' "$(jq -r '.what_if_id' "$report_path")"
  printf -- '- Decision: %s\n' "$(jq -r '.policy_decision' "$report_path")"
  printf -- '- Queue depth: %s\n' "$(jq -r '.dashboard.queue_depth' "$report_path")"
  printf -- '- P1 SLO risk: %s\n' "$(jq -r '.dashboard.p1_slo_risk' "$report_path")"
  printf -- '- Brownout state: %s\n' "$(jq -r '.dashboard.brownout_state' "$report_path")"
  printf -- '- Recommended action: %s\n' "$(jq -r '.dashboard.recommended_operator_action' "$report_path")"
} >"$human_report_path"

printf 'proof_economy_operator_what_if_report=%s\n' "$report_path"
if [[ "$(jq -r '.policy_decision' "$report_path")" == "fail_closed" ]]; then
  exit 42
fi
