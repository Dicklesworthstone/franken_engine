#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
evaluator="${root_dir}/scripts/proof_economy_policy_evaluator.sh"
artifact_root="${PROOF_ECONOMY_COUNTERFACTUAL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-proof-economy-counterfactual}"
run_id="${PROOF_ECONOMY_COUNTERFACTUAL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${PROOF_ECONOMY_COUNTERFACTUAL_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

replay_trace_json=""
policy_matrix_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/proof_economy_counterfactual_replay_runner.sh --replay-trace-json FILE [OPTIONS]

Runs fixture-only counterfactual scheduler replay policies over one normalized
proof-economy trace. This script does not query live workers and does not run
proof commands.

Required:
  --replay-trace-json FILE

Optional:
  --policy-matrix-json FILE
  --output-dir DIR

Artifacts:
  counterfactual_replay_report.json
  policy_scorecards.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  counterfactual replay passed
  42 fail-closed counterfactual or policy violation
  64 invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --replay-trace-json)
      replay_trace_json="${2:-}"
      shift 2
      ;;
    --policy-matrix-json)
      policy_matrix_json="${2:-}"
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
  printf 'counterfactual replay runner requires --replay-trace-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for counterfactual replay\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for counterfactual replay\n' >&2
  exit 2
fi
if [[ ! -x "$evaluator" ]]; then
  printf 'proof-economy policy evaluator is not executable: %s\n' "$evaluator" >&2
  exit 64
fi
if [[ ! -f "$replay_trace_json" ]]; then
  printf 'counterfactual replay runner missing replay trace JSON: %s\n' "$replay_trace_json" >&2
  exit 64
fi
if ! jq -e '.schema_version == "franken-engine.proof-economy-replay-trace.v1"' \
  "$replay_trace_json" >/dev/null; then
  printf 'replay trace must use franken-engine.proof-economy-replay-trace.v1: %s\n' "$replay_trace_json" >&2
  exit 64
fi

mkdir -p "$run_dir"
trace_normalized="${run_dir}/replay_trace.normalized.json"
policy_matrix_normalized="${run_dir}/policy_matrix.normalized.json"
policy_runs_dir="${run_dir}/policy-runs"
scorecards_jsonl="${run_dir}/policy_scorecards.jsonl"
scorecards_path="${run_dir}/policy_scorecards.json"
report_core="${run_dir}/counterfactual_replay_report.core.json"
report_tmp="${run_dir}/counterfactual_replay_report.json.tmp"
report_path="${run_dir}/counterfactual_replay_report.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
human_report_path="${run_dir}/report.md"
mkdir -p "$policy_runs_dir"
: >"$events_path"
: >"$scorecards_jsonl"

jq -cS . "$replay_trace_json" >"$trace_normalized"

printf './scripts/proof_economy_counterfactual_replay_runner.sh' >"$commands_path"
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

write_event "trace_loaded" "loaded normalized proof-economy trace for counterfactual replay"

if [[ -z "$policy_matrix_json" ]]; then
  jq -n '{
    policies: [
      {
        policy_index: 0,
        policy_name: "baseline",
        policy_label: "Fixture-order baseline",
        pressure_mode: "normal",
        max_heavy_per_agent: 99,
        ordering_strategy: "fixture",
        explanation: "Reproduce fixture command order and measure baseline slot share."
      },
      {
        policy_index: 1,
        policy_name: "fair_share",
        policy_label: "Fair-share cap",
        pressure_mode: "normal",
        max_heavy_per_agent: 1,
        ordering_strategy: "priority_preempt",
        explanation: "Bound per-agent heavy proof fanout while preserving P1 admission."
      },
      {
        policy_index: 2,
        policy_name: "high_pressure",
        policy_label: "High-pressure brownout",
        pressure_mode: "high",
        max_heavy_per_agent: 1,
        ordering_strategy: "priority_preempt",
        explanation: "Defer broad P3 proof work when slots are under pressure."
      }
    ]
  }' >"$policy_matrix_normalized"
else
  if [[ ! -f "$policy_matrix_json" ]]; then
    printf 'counterfactual replay runner missing policy matrix JSON: %s\n' "$policy_matrix_json" >&2
    exit 64
  fi
  if ! jq empty "$policy_matrix_json" >/dev/null; then
    printf 'counterfactual replay runner invalid policy matrix JSON: %s\n' "$policy_matrix_json" >&2
    exit 64
  fi
  jq -cS '
    if type == "array" then {policies: .} else . end
    | .policies |= sort_by(.policy_index // 999999, .policy_name // "")
  ' "$policy_matrix_json" >"$policy_matrix_normalized"
fi

if ! jq -e '
  (.policies | type) == "array"
  and (.policies | length) > 0
  and all(.policies[];
    ((.policy_name // "") | length) > 0
    and (.pressure_mode == "normal" or .pressure_mode == "high")
    and ((.max_heavy_per_agent | type) == "number")
    and (.max_heavy_per_agent >= 0)
    and ((.ordering_strategy // "fixture") == "fixture" or (.ordering_strategy // "fixture") == "priority_preempt")
  )
' "$policy_matrix_normalized" >/dev/null; then
  printf 'policy matrix must define policies with policy_name, pressure_mode, max_heavy_per_agent, and ordering_strategy\n' >&2
  exit 64
fi

write_event "policy_matrix_loaded" "loaded counterfactual policy matrix"

while IFS= read -r policy; do
  policy_index="$(jq -r '.policy_index // 0' <<<"$policy")"
  policy_name="$(jq -r '.policy_name' <<<"$policy")"
  policy_label="$(jq -r '.policy_label // .policy_name' <<<"$policy")"
  pressure_mode="$(jq -r '.pressure_mode' <<<"$policy")"
  max_heavy_per_agent="$(jq -r '.max_heavy_per_agent | floor' <<<"$policy")"
  ordering_strategy="$(jq -r '.ordering_strategy // "fixture"' <<<"$policy")"
  policy_dir="${policy_runs_dir}/${policy_index}-${policy_name}"
  mkdir -p "$policy_dir"

  set +e
  "$evaluator" \
    --replay-trace-json "$trace_normalized" \
    --pressure-mode "$pressure_mode" \
    --max-heavy-per-agent "$max_heavy_per_agent" \
    --output-dir "$policy_dir" >/dev/null
  policy_exit=$?
  set -e
  if [[ "$policy_exit" -ne 0 && "$policy_exit" -ne 42 ]]; then
    printf 'policy evaluator failed for %s with exit code %s\n' "$policy_name" "$policy_exit" >&2
    exit "$policy_exit"
  fi

  jq -c \
    --arg policy_name "$policy_name" \
    --arg policy_label "$policy_label" \
    --arg pressure_mode "$pressure_mode" \
    --arg ordering_strategy "$ordering_strategy" \
    --arg policy_exit "$policy_exit" \
    --argjson policy_index "$policy_index" \
    --argjson max_heavy_per_agent "$max_heavy_per_agent" \
    '. + {
      policy_index: $policy_index,
      policy_name: $policy_name,
      policy_label: $policy_label,
      pressure_mode: $pressure_mode,
      max_heavy_per_agent: $max_heavy_per_agent,
      ordering_strategy: $ordering_strategy,
      policy_exit_code: ($policy_exit | tonumber)
    }' "${policy_dir}/policy_scorecard.json" >>"$scorecards_jsonl"
  write_event "policy_evaluated" "$policy_name"
done < <(jq -c '.policies[]' "$policy_matrix_normalized")

jq -s 'sort_by(.policy_index, .policy_name)' "$scorecards_jsonl" >"$scorecards_path"

jq -n \
  --slurpfile trace "$trace_normalized" \
  --slurpfile policies "$policy_matrix_normalized" \
  --slurpfile scorecards "$scorecards_path" \
  '
  def command_key($cmd):
    (($cmd.agent_id // "") + "|" + ($cmd.bead_id // "") + "|" + ($cmd.requested_command // ""));
  def millionths($n; $d):
    if $d == 0 then 0 else (($n * 1000000 / $d) | floor) end;
  def trace_rank($commands; $decision):
    (first($commands | to_entries[] | select(command_key(.value) == command_key($decision))) // {key: 999999}).key;
  def enriched_decisions($commands; $score):
    [
      ($score.decisions // [])[] as $decision
      | (trace_rank($commands; $decision)) as $rank
      | $decision + {
          fixture_rank: $rank,
          fixture_order: ($rank + 1),
          explanation: (
            if $decision.decision == "defer" then
              (($decision.fairness_reason // "deferred") + ": " + ($decision.reason // "policy deferral"))
            elif $decision.decision == "admit_preempt" then
              (($decision.fairness_reason // "admitted") + ": " + ($decision.reason // "P1 protected"))
            elif $decision.decision == "fail_closed" then
              (($decision.fairness_reason // "fail closed") + ": " + ($decision.reason // "policy violation"))
            else
              (($decision.fairness_reason // "admitted") + ": " + ($decision.reason // "within policy"))
            end
          )
        }
    ];
  def scheduled_decisions($score; $decisions):
    if ($score.ordering_strategy // "fixture") == "fixture" then
      [ $decisions[] | select(.decision == "admit" or .decision == "admit_preempt") ]
      | sort_by(.fixture_rank, .bead_id)
    else
      [ $decisions[] | select(.decision == "admit" or .decision == "admit_preempt") ]
      | sort_by((if .decision == "admit_preempt" then -1 else .fixture_rank end), .fixture_rank, .bead_id)
    end;
  def deferred_decisions($decisions):
    [ $decisions[] | select(.decision == "defer" or .decision == "fail_closed") ]
    | sort_by(.fixture_rank, .bead_id);
  def agent_shares($scheduled):
    ($scheduled | length) as $total
    | if $total == 0 then
        []
      else
        ($scheduled | sort_by(.agent_id) | group_by(.agent_id)
          | map({
              agent_id: .[0].agent_id,
              scheduled_count: length,
              share_millionths: millionths(length; $total)
            }))
      end;
  def outcome_for($commands; $fixture_order; $score):
    (enriched_decisions($commands; $score)) as $decisions
    | (scheduled_decisions($score; $decisions)) as $scheduled
    | (deferred_decisions($decisions)) as $deferred
    | (agent_shares($scheduled)) as $shares
    | {
        policy_index: ($score.policy_index // 0),
        policy_name: ($score.policy_name // "unknown"),
        policy_label: ($score.policy_label // $score.policy_name // "unknown"),
        pressure_mode: ($score.pressure_mode // "normal"),
        max_heavy_per_agent: ($score.max_heavy_per_agent // null),
        ordering_strategy: ($score.ordering_strategy // "fixture"),
        policy_id: ($score.policy_id // "unknown"),
        policy_decision: ($score.policy_decision // "unknown"),
        p1_slo_risk: ($score.p1_slo_risk // "unknown"),
        scheduled_order: ($scheduled | map(.bead_id)),
        deferred_order: ($deferred | map(.bead_id)),
        fixture_order_match: (($scheduled | map(.bead_id)) == $fixture_order),
        scheduled_count: ($scheduled | length),
        deferred_count: ($deferred | length),
        fail_closed_count: ([ $decisions[] | select(.decision == "fail_closed") ] | length),
        max_agent_slot_share_millionths: (([ $shares[].share_millionths ] | max) // 0),
        agent_slot_shares: $shares,
        changed_commands: (
          [ $deferred[] | {
              bead_id,
              agent_id,
              before: "scheduled",
              after: .decision,
              fairness_reason: (.fairness_reason // ""),
              explanation
            } ]
        ),
        deferred_commands: (
          [ $deferred[] | select(.decision == "defer") | {
              bead_id,
              agent_id,
              priority,
              fairness_reason: (.fairness_reason // ""),
              explanation
            } ]
        ),
        unchanged_commands: (
          [ $scheduled | to_entries[] | . as $entry | $entry.value | {
              bead_id,
              agent_id,
              decision,
              fixture_order,
              scheduled_order: ($entry.key + 1),
              explanation
            } ]
        )
      };
  ($trace[0]) as $t
  | ($t.command_rows // []) as $commands
  | ($commands | map(.bead_id)) as $fixture_order
  | ($scorecards[0] | sort_by(.policy_index, .policy_name)) as $scores
  | [ $scores[] | outcome_for($commands; $fixture_order; .) ] as $raw_outcomes
  | (first($raw_outcomes[] | select(.policy_name == "baseline")) // $raw_outcomes[0]) as $baseline
  | [
      $raw_outcomes[] as $outcome
      | $outcome + {
          delta_from_baseline: {
            order_changed: ($outcome.scheduled_order != $baseline.scheduled_order),
            deferred_delta: ($outcome.deferred_count - $baseline.deferred_count),
            monopoly_reduction_millionths: ($baseline.max_agent_slot_share_millionths - $outcome.max_agent_slot_share_millionths),
            p1_slo_preserved: ($outcome.p1_slo_risk == "protected")
          }
        }
    ] as $outcomes
  | {
      trace_id: ($t.trace_id // "unknown"),
      source_revision: ($t.source_revision // "unknown"),
      policy_decision: (
        if any($scores[]; (.policy_decision // "") == "fail_closed") then
          "fail_closed"
        elif any($outcomes[]; .p1_slo_risk != "protected") then
          "fail_closed"
        else
          "pass"
        end
      ),
      trace_fixture_order: $fixture_order,
      policy_matrix: ($policies[0].policies // []),
      policy_outcomes: $outcomes,
      assertions: {
        baseline_reproduces_fixture_order: (
          (first($outcomes[] | select(.policy_name == "baseline") | .fixture_order_match) // false) == true
        ),
        fair_share_reduces_starvation: (
          any($outcomes[];
            .policy_name == "fair_share"
            and .delta_from_baseline.monopoly_reduction_millionths > 0
            and .delta_from_baseline.p1_slo_preserved == true
          )
        ),
        high_pressure_defers_broad_p3: (
          any($outcomes[];
            .policy_name == "high_pressure"
            and any(.deferred_commands[]; .priority > 2 and .fairness_reason == "pressure-aware deferral")
          )
        ),
        all_p1_slo_preserved: all($outcomes[]; .p1_slo_risk == "protected")
      },
      findings: (
        [
          if ((first($outcomes[] | select(.policy_name == "baseline") | .fixture_order_match) // false) | not) then
            {
              severity: "error",
              code: "baseline_order_drift",
              message: "Baseline policy did not reproduce fixture order."
            }
          else empty end,
          if (any($outcomes[];
            .policy_name == "fair_share"
            and .delta_from_baseline.monopoly_reduction_millionths > 0
            and .delta_from_baseline.p1_slo_preserved == true
          ) | not) then
            {
              severity: "error",
              code: "fair_share_starvation_not_reduced",
              message: "Fair-share policy did not reduce slot monopolization while preserving P1 SLO."
            }
          else empty end,
          if (any($outcomes[];
            .policy_name == "high_pressure"
            and any(.deferred_commands[]; .priority > 2 and .fairness_reason == "pressure-aware deferral")
          ) | not) then
            {
              severity: "error",
              code: "high_pressure_missing_p3_deferral",
              message: "High-pressure policy did not defer broad P3 proof work."
            }
          else empty end
        ]
        + [ $scores[] | select(.policy_decision == "fail_closed") | {
            severity: "error",
            code: "counterfactual_policy_fail_closed",
            message: ("Policy " + (.policy_name // "unknown") + " failed closed.")
          } ]
      ),
      summary: {
        policy_count: ($outcomes | length),
        command_count: ($commands | length),
        changed_policy_count: ([ $outcomes[] | select(.delta_from_baseline.order_changed == true or .deferred_count > 0) ] | length),
        fail_closed_policy_count: ([ $scores[] | select(.policy_decision == "fail_closed") ] | length)
      }
    }
  ' >"$report_core"

counterfactual_hash="$(jq -cS . "$report_core" | sha256sum | awk '{print "counterfactual-" substr($1, 1, 16)}')"

jq \
  --arg schema_version "franken-engine.proof-economy-counterfactual-replay-report.v1" \
  --arg counterfactual_id "$counterfactual_hash" \
  --arg report_path "$report_path" \
  --arg scorecards_path "$scorecards_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg human_report_path "$human_report_path" \
  '. + {
    schema_version: $schema_version,
    counterfactual_id: $counterfactual_id,
    hash_basis: {
      counterfactual_hash: $counterfactual_id
    },
    artifact_paths: {
      counterfactual_replay_report_json: $report_path,
      policy_scorecards_json: $scorecards_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $human_report_path
    }
  }' "$report_core" >"$report_tmp"
mv "$report_tmp" "$report_path"

write_event "counterfactual_replay_reported" "$counterfactual_hash"

{
  printf '# Proof Economy Counterfactual Replay\n\n'
  printf -- '- Counterfactual ID: %s\n' "$(jq -r '.counterfactual_id' "$report_path")"
  printf -- '- Decision: %s\n' "$(jq -r '.policy_decision' "$report_path")"
  printf -- '- Policies: %s\n' "$(jq -r '.summary.policy_count' "$report_path")"
  printf -- '- Commands: %s\n' "$(jq -r '.summary.command_count' "$report_path")"
  printf -- '- Changed policies: %s\n' "$(jq -r '.summary.changed_policy_count' "$report_path")"
  printf -- '- Findings: %s\n' "$(jq -r '.findings | length' "$report_path")"
} >"$human_report_path"

printf 'proof_economy_counterfactual_replay_report=%s\n' "$report_path"
if [[ "$(jq -r '.policy_decision' "$report_path")" == "fail_closed" ]]; then
  exit 42
fi
