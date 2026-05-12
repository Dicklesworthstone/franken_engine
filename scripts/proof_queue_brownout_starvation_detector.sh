#!/usr/bin/env bash
set -euo pipefail

artifact_root="${PROOF_QUEUE_BROWNOUT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-proof-queue-brownout}"
run_id="${PROOF_QUEUE_BROWNOUT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${PROOF_QUEUE_BROWNOUT_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

replay_trace_json=""
counterfactual_report_json=""
max_agent_share_millionths="500000"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/proof_queue_brownout_starvation_detector.sh --replay-trace-json FILE [OPTIONS]

Detects proof-queue brownout, starvation, and unfair scheduling patterns from
fixture replay artifacts. This script does not query live workers and does not
run proof commands.

Required:
  --replay-trace-json FILE

Optional:
  --counterfactual-report-json FILE
  --max-agent-share-millionths N
  --output-dir DIR

Artifacts:
  brownout_report.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  no fail-closed brownout detected
  42 fail-closed brownout detected
  64 invalid or missing input
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
    --max-agent-share-millionths)
      max_agent_share_millionths="${2:-}"
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

is_int() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

if [[ -z "$replay_trace_json" ]]; then
  printf 'proof-queue brownout detector requires --replay-trace-json\n' >&2
  usage
  exit 64
fi
if ! is_int "$max_agent_share_millionths"; then
  printf 'max agent share must be a non-negative integer\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for proof-queue brownout detection\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for proof-queue brownout detection\n' >&2
  exit 2
fi
if [[ ! -f "$replay_trace_json" ]]; then
  printf 'proof-queue brownout detector missing replay trace JSON: %s\n' "$replay_trace_json" >&2
  exit 64
fi
if ! jq -e '.schema_version == "franken-engine.proof-economy-replay-trace.v1"' \
  "$replay_trace_json" >/dev/null; then
  printf 'replay trace must use franken-engine.proof-economy-replay-trace.v1: %s\n' "$replay_trace_json" >&2
  exit 64
fi
if [[ -n "$counterfactual_report_json" ]]; then
  if [[ ! -f "$counterfactual_report_json" ]]; then
    printf 'proof-queue brownout detector missing counterfactual report JSON: %s\n' "$counterfactual_report_json" >&2
    exit 64
  fi
  if ! jq -e '.schema_version == "franken-engine.proof-economy-counterfactual-replay-report.v1"' \
    "$counterfactual_report_json" >/dev/null; then
    printf 'counterfactual report must use franken-engine.proof-economy-counterfactual-replay-report.v1: %s\n' \
      "$counterfactual_report_json" >&2
    exit 64
  fi
fi

mkdir -p "$run_dir"
trace_normalized="${run_dir}/replay_trace.normalized.json"
counterfactual_normalized="${run_dir}/counterfactual_report.normalized.json"
report_core="${run_dir}/brownout_report.core.json"
report_tmp="${run_dir}/brownout_report.json.tmp"
report_path="${run_dir}/brownout_report.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
human_report_path="${run_dir}/report.md"
: >"$events_path"

jq -cS . "$replay_trace_json" >"$trace_normalized"
if [[ -n "$counterfactual_report_json" ]]; then
  jq -cS . "$counterfactual_report_json" >"$counterfactual_normalized"
else
  jq -n '{}' >"$counterfactual_normalized"
fi

printf './scripts/proof_queue_brownout_starvation_detector.sh' >"$commands_path"
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

write_event "inputs_loaded" "loaded proof queue replay artifacts"

jq -n \
  --slurpfile trace "$trace_normalized" \
  --slurpfile counterfactual "$counterfactual_normalized" \
  --argjson max_agent_share_millionths "$max_agent_share_millionths" \
  '
  def millionths($n; $d):
    if $d == 0 then 0 else (($n * 1000000 / $d) | floor) end;
  def busy_decision($decision):
    (($decision // "") | ascii_downcase) as $d
    | ($d == "busy" or $d == "defer" or $d == "deferred" or $d == "queued" or $d == "wait" or $d == "throttle");
  def stable_id($code; $suffix):
    ("finding-" + $code + "-" + (($suffix // "queue") | gsub("[^A-Za-z0-9]+"; "-") | ascii_downcase));
  def remediation($code):
    if $code == "queue_brownout_all_workers_busy" then
      "Pause broad proof fanout, admit one P1/P2 lane first, and retry deferred commands only after a fresh slot snapshot."
    elif $code == "unfair_agent_slot_share" then
      "Split the monopolizing agent work into one heavy proof slot, rotate remaining work behind other agents, and require a new counterfactual report before re-admission."
    elif $code == "low_priority_starvation" then
      "Bound the P3 deferral window, split the broad proof target, and schedule a retry after protected P1/P2 lanes drain."
    elif $code == "counterfactual_all_policies_brownout" then
      "Stop accepting new heavy proof work and refresh worker capacity before replaying policy choices."
    else
      "Review the replay artifacts and rerun the detector with a fresh counterfactual report."
    end;
  ($trace[0]) as $t
  | ($counterfactual[0]) as $cf
  | ($t.command_rows // []) as $commands
  | ($cf.policy_outcomes // []) as $outcomes
  | ($commands | length) as $command_count
  | ($command_count > 0 and all($commands[]; busy_decision(.lease_decision))) as $all_busy
  | (
      if $command_count == 0 then
        []
      else
        $commands
        | sort_by(.agent_id)
        | group_by(.agent_id)
        | map({
            agent_id: .[0].agent_id,
            command_count: length,
            share_millionths: millionths(length; $command_count)
          })
        | sort_by(-.share_millionths, .agent_id)
      end
    ) as $agent_shares
  | (($agent_shares[0] // {agent_id: "", share_millionths: 0})) as $max_agent
  | (
      [ $outcomes[]?.deferred_commands[]? | select((.priority // 99) > 2) | {
          bead_id,
          agent_id,
          priority,
          policy_name: (input_filename // ""),
          fairness_reason: (.fairness_reason // ""),
          explanation: (.explanation // "")
        } ]
    ) as $low_priority_deferred
  | ($outcomes | length > 0 and all($outcomes[]; (.scheduled_count // 0) == 0 or (.policy_decision // "") == "fail_closed")) as $all_policy_brownout
  | (
      [
        if $all_busy then
          {
            finding_id: stable_id("queue_brownout_all_workers_busy"; ($t.trace_id // "trace")),
            severity: "error",
            code: "queue_brownout_all_workers_busy",
            message: "All replayed proof commands report busy, queued, or deferred lease decisions.",
            remediation: remediation("queue_brownout_all_workers_busy"),
            evidence: {
              command_count: $command_count,
              trace_id: ($t.trace_id // "unknown")
            }
          }
        else empty end,
        if (($max_agent.share_millionths // 0) > $max_agent_share_millionths) then
          {
            finding_id: stable_id("unfair_agent_slot_share"; $max_agent.agent_id),
            severity: "warning",
            code: "unfair_agent_slot_share",
            message: "One agent owns more than the configured proof queue share.",
            remediation: remediation("unfair_agent_slot_share"),
            evidence: {
              agent_id: $max_agent.agent_id,
              share_millionths: $max_agent.share_millionths,
              threshold_millionths: $max_agent_share_millionths
            }
          }
        else empty end,
        if $all_policy_brownout then
          {
            finding_id: stable_id("counterfactual_all_policies_brownout"; ($cf.counterfactual_id // "counterfactual")),
            severity: "error",
            code: "counterfactual_all_policies_brownout",
            message: "Every counterfactual policy has no scheduled commands or failed closed.",
            remediation: remediation("counterfactual_all_policies_brownout"),
            evidence: {
              counterfactual_id: ($cf.counterfactual_id // "unknown")
            }
          }
        else empty end
      ]
      + [
        $low_priority_deferred[]? as $deferred
        | {
            finding_id: stable_id("low_priority_starvation"; ($deferred.bead_id // "p3")),
            severity: "warning",
            code: "low_priority_starvation",
            message: "Low-priority proof work is deferred by counterfactual policy and needs bounded remediation.",
            remediation: remediation("low_priority_starvation"),
            evidence: $deferred
          }
      ]
      | unique_by(.finding_id)
      | sort_by(.severity, .code, .finding_id)
    ) as $findings
  | {
      trace_id: ($t.trace_id // "unknown"),
      counterfactual_id: ($cf.counterfactual_id // null),
      policy_decision: (
        if any($findings[]; .severity == "error") then "fail_closed" else "pass" end
      ),
      severity_counts: {
        error: ([ $findings[] | select(.severity == "error") ] | length),
        warning: ([ $findings[] | select(.severity == "warning") ] | length)
      },
      agent_slot_shares: $agent_shares,
      brownout_receipts: (
        [ $findings[] | select(.code == "queue_brownout_all_workers_busy" or .code == "counterfactual_all_policies_brownout")
          | {
              receipt_id: ("brownout-" + .finding_id),
              finding_id,
              code,
              severity,
              remediation,
              evidence
            } ]
      ),
      findings: $findings,
      summary: {
        command_count: $command_count,
        policy_count: ($outcomes | length),
        finding_count: ($findings | length),
        max_agent_share_millionths: ($max_agent.share_millionths // 0),
        all_workers_busy: $all_busy
      }
    }
  ' >"$report_core"

brownout_hash="$(jq -cS . "$report_core" | sha256sum | awk '{print "brownout-" substr($1, 1, 16)}')"

jq \
  --arg schema_version "franken-engine.proof-queue-brownout-report.v1" \
  --arg brownout_id "$brownout_hash" \
  --arg report_path "$report_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg human_report_path "$human_report_path" \
  '. + {
    schema_version: $schema_version,
    brownout_id: $brownout_id,
    hash_basis: {
      brownout_hash: $brownout_id
    },
    artifact_paths: {
      brownout_report_json: $report_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $human_report_path
    }
  }' "$report_core" >"$report_tmp"
mv "$report_tmp" "$report_path"

write_event "brownout_reported" "$brownout_hash"

{
  printf '# Proof Queue Brownout Report\n\n'
  printf -- '- Brownout ID: %s\n' "$(jq -r '.brownout_id' "$report_path")"
  printf -- '- Decision: %s\n' "$(jq -r '.policy_decision' "$report_path")"
  printf -- '- Commands: %s\n' "$(jq -r '.summary.command_count' "$report_path")"
  printf -- '- Findings: %s\n' "$(jq -r '.summary.finding_count' "$report_path")"
  printf -- '- Error findings: %s\n' "$(jq -r '.severity_counts.error' "$report_path")"
  printf -- '- Warning findings: %s\n' "$(jq -r '.severity_counts.warning' "$report_path")"
} >"$human_report_path"

printf 'proof_queue_brownout_report=%s\n' "$report_path"
if [[ "$(jq -r '.policy_decision' "$report_path")" == "fail_closed" ]]; then
  exit 42
fi
