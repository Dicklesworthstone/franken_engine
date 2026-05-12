#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${PROOF_QUEUE_TAIL_LATENCY_RESCUE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-proof-queue-tail-latency-rescue}"
run_id="${PROOF_QUEUE_TAIL_LATENCY_RESCUE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${PROOF_QUEUE_TAIL_LATENCY_RESCUE_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${PROOF_QUEUE_TAIL_LATENCY_RESCUE_SOURCE_REVISION:-}"
generated_epoch_seconds="${PROOF_QUEUE_TAIL_LATENCY_RESCUE_GENERATED_EPOCH_SECONDS:-$(date -u +%s)}"
max_agent_share_millionths="500000"
original_args=("$@")

replay_trace_json=""
counterfactual_report_json=""
tail_latency_report_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/proof_queue_tail_latency_rescue_gate.sh --replay-trace-json FILE [OPTIONS]

Turns preserved proof queue replay evidence into an advisory-only tail-latency
rescue receipt. The gate reuses proof_queue_brownout_starvation_detector.sh and
never mutates workers, br, reservations, Agent Mail, or queue policy.

Required:
  --replay-trace-json FILE

Optional:
  --counterfactual-report-json FILE
  --tail-latency-report-json FILE
  --max-agent-share-millionths N
  --source-revision REV
  --generated-epoch-seconds N
  --output-dir DIR

Artifacts:
  run_manifest.json
  tail_latency_rescue_receipt.json
  events.jsonl
  commands.txt
  report.md
  brownout_detector/

Exit codes:
  0   healthy or advisory receipt emitted
  42  fail-closed pressure receipt emitted
  64  invalid or missing input
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
    --tail-latency-report-json)
      tail_latency_report_json="${2:-}"
      shift 2
      ;;
    --max-agent-share-millionths)
      max_agent_share_millionths="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --generated-epoch-seconds)
      generated_epoch_seconds="${2:-}"
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
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

is_int() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

validate_json() {
  local path="$1"
  local label="$2"
  if [[ ! -f "$path" ]]; then
    printf 'missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
}

if [[ -z "$replay_trace_json" ]]; then
  printf 'tail-latency rescue gate requires --replay-trace-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for proof queue tail-latency rescue gating\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for proof queue tail-latency rescue gating\n' >&2
  exit 2
fi
if ! is_int "$max_agent_share_millionths" || ! is_int "$generated_epoch_seconds"; then
  printf 'max-agent-share and generated epoch seconds must be non-negative integers\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

validate_json "$replay_trace_json" "replay trace"
if ! jq -e '.schema_version == "franken-engine.proof-economy-replay-trace.v1"' "$replay_trace_json" >/dev/null; then
  printf 'replay trace must use franken-engine.proof-economy-replay-trace.v1\n' >&2
  exit 64
fi
if [[ -n "$counterfactual_report_json" ]]; then
  validate_json "$counterfactual_report_json" "counterfactual report"
  if ! jq -e '.schema_version == "franken-engine.proof-economy-counterfactual-replay-report.v1"' "$counterfactual_report_json" >/dev/null; then
    printf 'counterfactual report must use franken-engine.proof-economy-counterfactual-replay-report.v1\n' >&2
    exit 64
  fi
fi
if [[ -n "$tail_latency_report_json" ]]; then
  validate_json "$tail_latency_report_json" "tail-latency report"
fi

mkdir -p "$run_dir"
run_manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/tail_latency_rescue_receipt.json"
report_tmp="${report_path}.tmp"
report_md_path="${run_dir}/report.md"
brownout_dir="${run_dir}/brownout_detector"

for artifact_path in "$run_manifest_path" "$events_path" "$commands_path" "$report_path" "$report_md_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/proof_queue_tail_latency_rescue_gate.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  local event_name="$1"
  local outcome="$2"
  local detail="$3"
  local evidence_path="$4"
  jq -nc \
    --arg schema_version "franken-engine.proof-queue-tail-latency-rescue-gate.event.v1" \
    --arg event_name "$event_name" \
    --arg outcome "$outcome" \
    --arg detail "$detail" \
    --arg evidence_path "$evidence_path" \
    --arg source_revision "$source_revision" \
    '{
      schema_version: $schema_version,
      event_name: $event_name,
      outcome: $outcome,
      detail: $detail,
      evidence_path: (if $evidence_path == "" then null else $evidence_path end),
      source_revision: $source_revision
    }' >>"$events_path"
}

write_event "gate_started" "started" "validated replay inputs" "$replay_trace_json"

brownout_cmd=(
  "${root_dir}/scripts/proof_queue_brownout_starvation_detector.sh"
  --replay-trace-json "$replay_trace_json"
  --max-agent-share-millionths "$max_agent_share_millionths"
  --output-dir "$brownout_dir"
)
if [[ -n "$counterfactual_report_json" ]]; then
  brownout_cmd+=(--counterfactual-report-json "$counterfactual_report_json")
fi

printf './scripts/proof_queue_brownout_starvation_detector.sh' >>"$commands_path"
for arg in "${brownout_cmd[@]:1}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

set +e
"${brownout_cmd[@]}" >"${run_dir}/brownout_detector.stdout" 2>"${run_dir}/brownout_detector.stderr"
brownout_exit_code=$?
set -e

if [[ "$brownout_exit_code" -ne 0 && "$brownout_exit_code" -ne 42 ]]; then
  printf 'brownout detector failed with exit %s\n' "$brownout_exit_code" >&2
  exit "$brownout_exit_code"
fi
if [[ ! -f "${brownout_dir}/brownout_report.json" ]]; then
  printf 'brownout detector did not emit brownout_report.json\n' >&2
  exit 64
fi
write_event "brownout_detector_completed" "captured" "brownout detector emitted report" "brownout_detector/brownout_report.json"

tail_arg=(--argjson tail_latency null)
if [[ -n "$tail_latency_report_json" ]]; then
  tail_arg=(--slurpfile tail_latency "$tail_latency_report_json")
fi

jq -n \
  --slurpfile trace "$replay_trace_json" \
  --slurpfile brownout "${brownout_dir}/brownout_report.json" \
  "${tail_arg[@]}" \
  --arg schema_version "franken-engine.proof-queue-tail-latency-rescue-receipt.v1" \
  --arg source_revision "$source_revision" \
  --argjson generated_epoch_seconds "$generated_epoch_seconds" \
  --argjson brownout_exit_code "$brownout_exit_code" \
  --argjson max_agent_share_millionths "$max_agent_share_millionths" \
  --arg replay_trace_json "$replay_trace_json" \
  --arg counterfactual_report_json "$counterfactual_report_json" \
  --arg tail_latency_report_json "$tail_latency_report_json" \
  --arg brownout_report_json "brownout_detector/brownout_report.json" \
  --arg events_jsonl "events.jsonl" \
  --arg commands_txt "commands.txt" \
  --arg report_md "report.md" \
  '
  def doc($x):
    if $x == null then null
    elif ($x | type) == "array" then ($x[0] // null)
    else $x
    end;
  def command_rows($trace_doc): ($trace_doc.command_rows // []);
  def uniq_sorted($items): ($items | map(select(. != null and . != "")) | unique | sort);
  def agents_for($finding; $commands):
    if $finding.code == "unfair_agent_slot_share" then
      uniq_sorted([($finding.evidence.agent_id // "")])
    elif $finding.code == "low_priority_starvation" then
      uniq_sorted([($finding.evidence.agent_id // "")])
    else
      uniq_sorted([ $commands[]? | .agent_id // empty ])
    end;
  def beads_for($finding; $commands):
    if $finding.code == "unfair_agent_slot_share" then
      ($finding.evidence.agent_id // "") as $agent
      | uniq_sorted([ $commands[]? | select((.agent_id // "") == $agent) | .bead_id // empty ])
    elif $finding.code == "low_priority_starvation" then
      uniq_sorted([($finding.evidence.bead_id // "")])
    else
      uniq_sorted([ $commands[]? | .bead_id // empty ])
    end;
  def bounded_action($code):
    if $code == "queue_brownout_all_workers_busy" then
      {
        action: "pause_broad_proof_fanout",
        max_new_heavy_proofs: 0,
        requires_fresh_slot_snapshot: true,
        requires_operator_review: false,
        mutates_live_state: false,
        detail: "Admit no new broad proof work until a fresh worker/slot snapshot shows capacity."
      }
    elif $code == "unfair_agent_slot_share" then
      {
        action: "split_monopolizing_agent_lane",
        max_new_heavy_proofs_per_agent: 1,
        requires_fresh_slot_snapshot: true,
        requires_operator_review: false,
        mutates_live_state: false,
        detail: "Keep the monopolizing agent to one heavy proof lane and rotate other work behind independent agents."
      }
    elif $code == "low_priority_starvation" then
      {
        action: "bound_low_priority_deferral_window",
        max_deferral_window_minutes: 30,
        requires_fresh_slot_snapshot: true,
        requires_operator_review: false,
        mutates_live_state: false,
        detail: "Bound P3 deferral and retry only after protected P1/P2 work drains."
      }
    elif $code == "counterfactual_all_policies_brownout" then
      {
        action: "stop_accepting_new_heavy_proofs",
        max_new_heavy_proofs: 0,
        requires_fresh_slot_snapshot: true,
        requires_operator_review: true,
        mutates_live_state: false,
        detail: "All replayed policies brown out; stop admission and refresh worker capacity before replaying choices."
      }
    else
      {
        action: "review_replay_artifacts",
        requires_fresh_slot_snapshot: true,
        requires_operator_review: true,
        mutates_live_state: false,
        detail: "Review replay artifacts before taking any rescue action."
      }
    end;
  def tail_context($tail):
    if $tail == null then
      {state:"missing", schema_version:null, guardrail_state:null, fallback_activated:null}
    elif ($tail.schema_version // "") == "franken-engine.tail-latency-control-plane.v1" then
      {
        state:"captured",
        schema_version:$tail.schema_version,
        guardrail_state:($tail.guardrails.state // null),
        fallback_activated:($tail.guardrails.fallback_activated // null),
        violated_stage_count:($tail.guardrails.violated_stage_count // null)
      }
    else
      {state:"unknown_schema", schema_version:($tail.schema_version // null), guardrail_state:null, fallback_activated:null}
    end;
  def receipt($finding; $commands; $brownout_doc):
    {
      receipt_id: ("tail-rescue-" + ($finding.finding_id // ($finding.code // "unknown"))),
      cause: ($finding.code // "unknown"),
      severity: ($finding.severity // "warning"),
      message: ($finding.message // ""),
      affected_agents: agents_for($finding; $commands),
      affected_beads: beads_for($finding; $commands),
      fairness_evidence: {
        finding_evidence: ($finding.evidence // {}),
        agent_slot_shares: ($brownout_doc.agent_slot_shares // []),
        threshold_millionths: $max_agent_share_millionths
      },
      proposed_bounded_action: bounded_action($finding.code // "unknown"),
      remediation: ($finding.remediation // "")
    };
  ($trace[0]) as $trace_doc
  | ($brownout[0]) as $brownout_doc
  | (doc($tail_latency)) as $tail_doc
  | (command_rows($trace_doc)) as $commands
  | (($brownout_doc.findings // []) | map(receipt(.; $commands; $brownout_doc))) as $receipts
  | (if any($receipts[]?; .severity == "error") then "fail_closed_advisory"
     elif ($receipts | length) > 0 then "advisory"
     else "healthy"
     end) as $decision
  | {
      schema_version: $schema_version,
      source_revision: $source_revision,
      generated_epoch_seconds: $generated_epoch_seconds,
      trace_id: ("trace-tail-latency-rescue-" + (($brownout_doc.brownout_id // "unknown") | gsub("[^A-Za-z0-9_-]"; "-"))),
      decision: $decision,
      brownout_detector_exit_code: $brownout_exit_code,
      policy_decision: ($brownout_doc.policy_decision // "unknown"),
      tail_latency_context: tail_context($tail_doc),
      summary: {
        command_count: ($commands | length),
        recommendation_count: ($receipts | length),
        error_recommendation_count: ([ $receipts[] | select(.severity == "error") ] | length),
        warning_recommendation_count: ([ $receipts[] | select(.severity == "warning") ] | length),
        affected_agent_count: (uniq_sorted([ $receipts[]?.affected_agents[]? ]) | length),
        affected_bead_count: (uniq_sorted([ $receipts[]?.affected_beads[]? ]) | length)
      },
      rescue_recommendations: $receipts,
      mutation_policy: {
        advisory_only: true,
        mutates_live_workers: false,
        mutates_br: false,
        sends_agent_mail: false,
        releases_reservations: false,
        runs_cargo: false,
        runs_rch: false,
        changes_live_queue_policy: false
      },
      source_paths: {
        replay_trace_json: $replay_trace_json,
        counterfactual_report_json: (if $counterfactual_report_json == "" then null else $counterfactual_report_json end),
        tail_latency_report_json: (if $tail_latency_report_json == "" then null else $tail_latency_report_json end),
        brownout_report_json: $brownout_report_json
      },
      artifact_paths: {
        run_manifest_json: "run_manifest.json",
        tail_latency_rescue_receipt_json: "tail_latency_rescue_receipt.json",
        events_jsonl: $events_jsonl,
        commands_txt: $commands_txt,
        report_md: $report_md,
        brownout_detector_dir: "brownout_detector",
        brownout_report_json: $brownout_report_json
      }
    }
  ' >"$report_tmp"

report_hash="$(jq -cS . "$report_tmp" | sha256sum | awk '{print $1}')"
report_id="tail-latency-rescue-${report_hash:0:16}"
jq --arg report_id "$report_id" --arg report_hash "$report_hash" \
  '. + {report_id:$report_id, hash_basis:{report_hash:$report_hash}}' \
  "$report_tmp" >"$report_path"
rm -f "$report_tmp"

decision="$(jq -r '.decision' "$report_path")"
write_event "rescue_receipt_emitted" "$decision" "tail-latency rescue receipt emitted" "tail_latency_rescue_receipt.json"

jq -n \
  --slurpfile receipt "$report_path" \
  --arg schema_version "franken-engine.proof-queue-tail-latency-rescue-gate.run-manifest.v1" \
  --arg source_revision "$source_revision" \
  --argjson generated_epoch_seconds "$generated_epoch_seconds" \
  --arg decision "$decision" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    generated_epoch_seconds: $generated_epoch_seconds,
    decision: $decision,
    artifact_paths: $receipt[0].artifact_paths,
    source_paths: $receipt[0].source_paths,
    mutation_policy: $receipt[0].mutation_policy
  }' >"$run_manifest_path"

{
  printf '# Proof Queue Tail-Latency Rescue Gate\n\n'
  printf -- '%s\n' "- Decision: \`${decision}\`"
  printf -- '%s\n' "- Recommendations: \`$(jq '.summary.recommendation_count' "$report_path")\`"
  printf -- '%s\n' "- Affected agents: \`$(jq '.summary.affected_agent_count' "$report_path")\`"
  printf -- '%s\n\n' "- Affected beads: \`$(jq '.summary.affected_bead_count' "$report_path")\`"
  if [[ "$(jq '.rescue_recommendations | length' "$report_path")" -gt 0 ]]; then
    printf '## Recommendations\n\n'
    jq -r '.rescue_recommendations[] | "- `" + .cause + "` -> `" + .proposed_bounded_action.action + "` for agents `" + (.affected_agents | join(",")) + "` / beads `" + (.affected_beads | join(",")) + "`"' "$report_path"
    printf '\n'
  fi
  printf '## Artifacts\n\n'
  printf -- '%s\n' "- \`run_manifest.json\`"
  printf -- '%s\n' "- \`tail_latency_rescue_receipt.json\`"
  printf -- '%s\n' "- \`events.jsonl\`"
  printf -- '%s\n' "- \`commands.txt\`"
  printf -- '%s\n' "- \`brownout_detector/\`"
} >"$report_md_path"

printf 'tail_latency_rescue_receipt=%s\n' "$report_path"
if [[ "$decision" == "fail_closed_advisory" ]]; then
  exit 42
fi
exit 0
