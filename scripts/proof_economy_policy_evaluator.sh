#!/usr/bin/env bash
set -euo pipefail

artifact_root="${PROOF_ECONOMY_POLICY_EVALUATOR_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-proof-economy-policy-evaluator}"
run_id="${PROOF_ECONOMY_POLICY_EVALUATOR_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${PROOF_ECONOMY_POLICY_EVALUATOR_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

replay_trace_json=""
max_heavy_per_agent="1"
pressure_mode="normal"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/proof_economy_policy_evaluator.sh --replay-trace-json FILE [OPTIONS]

Evaluates fair-share proof-economy policy decisions over a normalized replay
trace. Inputs are fixtures only; this script does not query live workers or run
proof commands.

Required:
  --replay-trace-json FILE

Optional:
  --output-dir DIR
  --max-heavy-per-agent N
  --pressure-mode normal|high

Artifacts:
  policy_scorecard.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  evaluated successfully
  42 fail-closed policy violation
  64 invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --replay-trace-json)
      replay_trace_json="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --max-heavy-per-agent)
      max_heavy_per_agent="${2:-}"
      shift 2
      ;;
    --pressure-mode)
      pressure_mode="${2:-}"
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
  printf 'proof-economy policy evaluator requires --replay-trace-json\n' >&2
  usage
  exit 64
fi
if ! is_int "$max_heavy_per_agent"; then
  printf 'max heavy per agent must be a non-negative integer\n' >&2
  exit 64
fi
case "$pressure_mode" in
  normal|high) ;;
  *)
    printf 'pressure mode must be normal or high\n' >&2
    exit 64
    ;;
esac
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for proof-economy policy evaluation\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for proof-economy policy evaluation\n' >&2
  exit 2
fi
if [[ ! -f "$replay_trace_json" ]]; then
  printf 'proof-economy policy evaluator missing replay trace JSON: %s\n' "$replay_trace_json" >&2
  exit 64
fi
if ! jq -e '.schema_version == "franken-engine.proof-economy-replay-trace.v1"' \
  "$replay_trace_json" >/dev/null; then
  printf 'replay trace must use franken-engine.proof-economy-replay-trace.v1: %s\n' "$replay_trace_json" >&2
  exit 64
fi

mkdir -p "$run_dir"
scorecard_path="${run_dir}/policy_scorecard.json"
scorecard_tmp="${scorecard_path}.tmp"
scorecard_core="${run_dir}/policy_scorecard.core.json"
trace_normalized="${run_dir}/replay_trace.normalized.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
: >"$events_path"

jq -cS . "$replay_trace_json" >"$trace_normalized"

printf './scripts/proof_economy_policy_evaluator.sh' >"$commands_path"
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

write_event "trace_loaded" "loaded normalized proof-economy replay trace"

jq -n \
  --slurpfile trace "$trace_normalized" \
  --arg pressure_mode "$pressure_mode" \
  --argjson max_heavy_per_agent "$max_heavy_per_agent" \
  '
  def is_heavy($cmd):
    (($cmd // "") | test("(^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$)"));
  def is_rch_wrapped($cmd):
    (($cmd // "") | contains("rch exec -- env")) and (($cmd // "") | contains("CARGO_TARGET_DIR="));
  def priority_for($trace_row; $bead_id):
    (first($trace_row.bead_rows[]? | select(.bead_id == $bead_id) | .priority) // 4);
  def reservation_agrees($trace_row; $cmd):
    (($cmd.target_dir // "") != "")
    and any($trace_row.reservation_rows[]?;
      ((.agent_id // "") == ($cmd.agent_id // "") or (.bead_id // "") == ($cmd.bead_id // ""))
    );
  def command_key($cmd):
    (($cmd.agent_id // "") + "|" + ($cmd.bead_id // "") + "|" + ($cmd.requested_command // ""));
  def heavy_rank($commands; $cmd):
    (
      $commands
      | map(select((.agent_id // "") == ($cmd.agent_id // "") and is_heavy(.requested_command)))
      | sort_by(.bead_id, .requested_command)
      | map(command_key(.))
      | index(command_key($cmd))
    ) // 0;
  def decision_for($trace_row; $commands; $cmd):
    (priority_for($trace_row; $cmd.bead_id // "")) as $priority
    | is_heavy($cmd.requested_command) as $heavy
    | heavy_rank($commands; $cmd) as $rank
    | is_rch_wrapped($cmd.requested_command) as $rch
    | reservation_agrees($trace_row; $cmd) as $warm_ok
    | if $heavy and ($rch | not) then
        {
          decision: "fail_closed",
          reason: "heavy proof command is not rch-wrapped",
          fairness_reason: "invalid heavy command",
          slo_class: (if $priority <= 1 then "p1" elif $priority <= 2 then "p2" else "p3" end),
          warm_target_reuse: false,
          warm_target_reason: "not evaluated because command is invalid"
        }
      elif $heavy and ($rank >= $max_heavy_per_agent) and ($priority > 1) then
        {
          decision: "defer",
          reason: "per-agent heavy proof cap exceeded",
          fairness_reason: "agent fairness throttle",
          slo_class: (if $priority <= 2 then "p2" else "p3" end),
          warm_target_reuse: $warm_ok,
          warm_target_reason: (if $warm_ok then "reservation and command ownership agree" else "no matching reservation ownership evidence" end)
        }
      elif $pressure_mode == "high" and $heavy and ($priority > 2) then
        {
          decision: "defer",
          reason: "high-pressure mode defers low-priority broad proof work",
          fairness_reason: "pressure-aware deferral",
          slo_class: "p3",
          warm_target_reuse: $warm_ok,
          warm_target_reason: (if $warm_ok then "reservation and command ownership agree" else "no matching reservation ownership evidence" end)
        }
      elif $priority <= 1 then
        {
          decision: "admit_preempt",
          reason: "P1 proof lane protected by proof-economy policy",
          fairness_reason: "high-priority SLO protection",
          slo_class: "p1",
          warm_target_reuse: $warm_ok,
          warm_target_reason: (if $warm_ok then "reservation and command ownership agree" else "no matching reservation ownership evidence" end)
        }
      else
        {
          decision: "admit",
          reason: "within fair-share policy budget",
          fairness_reason: "within agent fair-share budget",
          slo_class: (if $priority <= 2 then "p2" else "p3" end),
          warm_target_reuse: $warm_ok,
          warm_target_reason: (if $warm_ok then "reservation and command ownership agree" else "no matching reservation ownership evidence" end)
        }
      end;
  $trace[0] as $t
  | ($t.command_rows // [] | sort_by(.agent_id, .bead_id, .requested_command)) as $commands
  | [
      $commands[] as $cmd
      | (decision_for($t; $commands; $cmd)) as $decision
      | {
          agent_id: ($cmd.agent_id // ""),
          bead_id: ($cmd.bead_id // ""),
          priority: priority_for($t; $cmd.bead_id // ""),
          requested_command: ($cmd.requested_command // ""),
          target_dir: ($cmd.target_dir // ""),
          lease_decision: ($cmd.lease_decision // "unknown")
        } + $decision
    ] as $decisions
  | {
      trace_id: ($t.trace_id // "unknown"),
      source_revision: ($t.source_revision // "unknown"),
      pressure_mode: $pressure_mode,
      max_heavy_per_agent: $max_heavy_per_agent,
      policy_decision: (
        if any($decisions[]; .decision == "fail_closed") then "fail_closed" else "pass" end
      ),
      p1_slo_risk: (
        if any($decisions[]; .slo_class == "p1" and (.decision != "admit_preempt" and .decision != "admit")) then
          "at_risk"
        else
          "protected"
        end
      ),
      fair_share_score_millionths: (
        ([ $decisions[] | select(.decision == "defer") ] | length) as $deferred
        | ([ $decisions[] | select(.decision == "fail_closed") ] | length) as $failed
        | (1000000 - ($deferred * 150000) - ($failed * 400000)) | if . < 0 then 0 else . end
      ),
      decisions: $decisions,
      per_agent: (
        $decisions
        | group_by(.agent_id)
        | map({
            agent_id: .[0].agent_id,
            admitted: ([.[] | select(.decision == "admit" or .decision == "admit_preempt")] | length),
            deferred: ([.[] | select(.decision == "defer")] | length),
            fail_closed: ([.[] | select(.decision == "fail_closed")] | length)
          })
      ),
      findings: (
        [ $decisions[] | select(.decision == "fail_closed") | {
            severity: "error",
            code: "unwrapped_heavy_command",
            message: ("Heavy command for " + .bead_id + " is not rch-wrapped")
          } ]
      ),
      summary: {
        command_count: ($decisions | length),
        admitted_count: ([ $decisions[] | select(.decision == "admit" or .decision == "admit_preempt") ] | length),
        deferred_count: ([ $decisions[] | select(.decision == "defer") ] | length),
        fail_closed_count: ([ $decisions[] | select(.decision == "fail_closed") ] | length),
        warm_target_reuse_count: ([ $decisions[] | select(.warm_target_reuse == true) ] | length)
      }
    }
  ' >"$scorecard_core"

policy_hash="$(jq -cS . "$scorecard_core" | sha256sum | awk '{print "policy-" substr($1, 1, 16)}')"

jq \
  --arg schema_version "franken-engine.proof-economy-policy-scorecard.v1" \
  --arg policy_id "$policy_hash" \
  --arg scorecard_path "$scorecard_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  '. + {
    schema_version: $schema_version,
    policy_id: $policy_id,
    hash_basis: {
      policy_hash: $policy_id
    },
    artifact_paths: {
      policy_scorecard_json: $scorecard_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path
    }
  }' "$scorecard_core" >"$scorecard_tmp"
mv "$scorecard_tmp" "$scorecard_path"

write_event "policy_evaluated" "$policy_hash"

{
  printf '# Proof Economy Policy Scorecard\n\n'
  printf -- '- Policy ID: %s\n' "$(jq -r '.policy_id' "$scorecard_path")"
  printf -- '- Decision: %s\n' "$(jq -r '.policy_decision' "$scorecard_path")"
  printf -- '- P1 SLO risk: %s\n' "$(jq -r '.p1_slo_risk' "$scorecard_path")"
  printf -- '- Fair-share score: %s\n' "$(jq -r '.fair_share_score_millionths' "$scorecard_path")"
  printf -- '- Deferred commands: %s\n' "$(jq -r '.summary.deferred_count' "$scorecard_path")"
} >"$report_path"

printf 'proof_economy_policy_scorecard=%s\n' "$scorecard_path"
if [[ "$(jq -r '.policy_decision' "$scorecard_path")" == "fail_closed" ]]; then
  exit 42
fi
