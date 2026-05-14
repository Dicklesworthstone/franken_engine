#!/usr/bin/env bash
set -euo pipefail

artifact_root="${OPTIMIZATION_PROMOTION_OPERATOR_STATUS_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-optimization-promotion-operator-status}"
run_id="${OPTIMIZATION_PROMOTION_OPERATOR_STATUS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${OPTIMIZATION_PROMOTION_OPERATOR_STATUS_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${OPTIMIZATION_PROMOTION_OPERATOR_STATUS_SOURCE_REVISION:-unknown}"
input_json=""
original_args=("$@")

usage() {
  cat >&2 <<'USAGE'
Usage: ./scripts/optimization_promotion_operator_status.sh --input-json FILE [OPTIONS]

Compose a deterministic source-only operator status bundle from saved
promotion, demotion, and transfer guard receipts. The command never runs
Cargo/RCH and never mutates runtime policy, br, Agent Mail, reservations,
workers, or benchmark claims.

Required:
  --input-json FILE

Optional:
  --source-revision REV
  --output-dir DIR

Artifacts:
  optimization_promotion_operator_status.json
  optimization_promotion_truth_gate_report.json
  operator_status.md
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   operator status emitted and truth gate passed
  42  operator wording failed closed
  64  invalid input or arguments
USAGE
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --input-json)
      input_json="${2:-}"
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
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$input_json" ]]; then
  printf 'missing required --input-json\n' >&2
  usage
  exit 64
fi
if [[ ! -f "$input_json" ]]; then
  printf 'input JSON not found: %s\n' "$input_json" >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for optimization promotion operator status\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for optimization promotion operator status\n' >&2
  exit 2
fi
if ! jq empty "$input_json" >/dev/null 2>&1; then
  printf 'invalid input JSON: %s\n' "$input_json" >&2
  exit 64
fi
if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(git rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
status_json="${run_dir}/optimization_promotion_operator_status.json"
status_json_tmp="${status_json}.tmp"
truth_report_json="${run_dir}/optimization_promotion_truth_gate_report.json"
truth_report_json_tmp="${truth_report_json}.tmp"
operator_status_md="${run_dir}/operator_status.md"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
normalized_input="${run_dir}/input.normalized.json"

jq -cS . "$input_json" >"$normalized_input"
input_hash="$(sha256sum "$normalized_input" | awk '{print $1}')"
status_hash="$input_hash"

printf './scripts/optimization_promotion_operator_status.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

: >"$events_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.optimization-promotion-operator-status.event.v1" \
    --arg trace_id "trace-optimization-promotion-operator-status-${run_id}" \
    --arg component "$1" \
    --arg event "$2" \
    --arg outcome "$3" \
    --arg error_code "$4" \
    '{schema_version:$schema_version,trace_id:$trace_id,component:$component,event:$event,outcome:$outcome,error_code:(if $error_code == "" then null else $error_code end)}' \
    >>"$events_path"
}

write_event "optimization_promotion_operator_status" "input_loaded" "captured" ""

jq -n \
  --slurpfile input "$normalized_input" \
  --arg source_revision "$source_revision" \
  --arg input_json "$input_json" \
  --arg normalized_input "$normalized_input" \
  --arg input_hash "$input_hash" \
  --arg status_hash "$status_hash" \
  --arg status_json "$status_json" \
  --arg truth_report_json "$truth_report_json" \
  --arg operator_status_md "$operator_status_md" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" '
  def src: $input[0];
  def promotion: (src.optimization_promotion_plan // {});
  def demotion: (src.optimization_demotion_receipt // {});
  def transfer: (src.optimization_transfer_guard // {});
  def lower($v): ($v // "" | tostring | ascii_downcase);
  def violation($code; $phrase; $detail):
    {code:$code, phrase:$phrase, detail:$detail};
  def supplied_text: lower(src.operator_status_text // "");
  def truth_violations:
    []
    + (if (supplied_text | test("live mutation|mutates runtime policy|automatically (promote|demote|pin|mutate)|applies runtime policy automatically")) then [
        violation("FE-OPT-STATUS-LIVE-MUTATION-CLAIM"; "live mutation"; "operator text claims automatic runtime mutation")
      ] else [] end)
    + (if (supplied_text | test("automatic benchmark publication|automatically publish.*benchmark|publishes benchmark.*automatically")) then [
        violation("FE-OPT-STATUS-AUTOMATIC-BENCHMARK-PUBLICATION"; "automatic benchmark publication"; "operator text claims benchmark publication without release gates")
      ] else [] end)
    + (if ((supplied_text | test("(^|[^a-z])cargo (check|test|clippy|fmt|run|bench)")) and ((supplied_text | contains("rch exec -- env")) | not)) then [
        violation("FE-OPT-STATUS-BARE-CARGO-VALIDATION"; "bare Cargo validation"; "operator text gives bare Cargo validation instead of rch-wrapped commands")
      ] else [] end)
    + (if ((supplied_text | test("denominator win|denominator wins|beats node|beats bun")) and ((supplied_text | contains("release gate")) | not)) then [
        violation("FE-OPT-STATUS-DENOMINATOR-WIN-OVERCLAIM"; "denominator win"; "operator text claims denominator wins without release gates")
      ] else [] end);
  def transfer_passed:
    (transfer.promotion_side_conditions.transfer_guard_passed // false) == true
    or (transfer.recommended_state // "") == "allow_same_regime"
    or (transfer.recommended_state // "") == "allow_transfer";
  def raw_state:
    if (promotion.decision // "pass") == "fail_closed"
      or (demotion.decision // "pass") == "fail_closed"
      or (transfer.decision // "pass") == "fail_closed" then "fail_closed"
    elif (demotion.recommended_state // "") == "demote_now" then "demote"
    elif (demotion.recommended_state // "") == "quarantine_candidate" then "quarantine"
    elif (promotion.recommended_state // "") == "pin" and transfer_passed then "pin"
    elif (promotion.recommended_state // "") == "promote" and transfer_passed then "promote"
    else "observe"
    end;
  def state_reason($state):
    if $state == "observe" then "candidate remains observed until promotion side conditions are stronger"
    elif $state == "promote" then "promotion side conditions are satisfied by saved receipts"
    elif $state == "pin" then "pin request is supported by saved promotion and transfer receipts"
    elif $state == "demote" then "demotion receipt requests rollback-safe demotion"
    elif $state == "quarantine" then "demotion receipt requests quarantine for semantic or transfer risk"
    else "one or more saved receipts failed closed or operator wording was unsafe"
    end;
  def collect_commands:
    [
      promotion.next_validation_commands[]?.command,
      demotion.next_validation_commands[]?.command,
      transfer.next_validation_commands[]?.command
    ]
    | map(select(type == "string" and startswith("rch exec -- env ")))
    | unique;
  (truth_violations) as $violations
  | (if ($violations | length) > 0 then "fail_closed" else raw_state end) as $operator_state
  | {
      schema_version: "franken-engine.optimization-promotion-operator-status.v1",
      bead_id: "bd-yo0eh",
      parent_bead_id: "bd-xg3d6",
      component: "optimization_promotion_operator_status",
      source_revision: (src.source_revision // $source_revision),
      input: {
        path: $input_json,
        normalized_path: $normalized_input,
        sha256: $input_hash,
        schema_version: (src.schema_version // null),
        case_id: (src.case_id // null)
      },
      status_hash: $status_hash,
      decision: (if ($violations | length) > 0 then "fail_closed" else "pass" end),
      operator_state: $operator_state,
      state_reason: state_reason($operator_state),
      candidate: {
        candidate_id: (src.candidate.candidate_id // promotion.candidate.candidate_id // demotion.candidate.candidate_id // transfer.candidate.candidate_id // "unknown_candidate"),
        workload_regime: (src.candidate.workload_regime // promotion.candidate.workload_regime // transfer.candidate.target_regime // "unknown"),
        source_paths: (src.candidate.source_paths // promotion.candidate.source_paths // transfer.candidate.source_paths // [])
      },
      saved_receipts: {
        promotion: {
          decision: (promotion.decision // "missing"),
          recommended_state: (promotion.recommended_state // "missing"),
          side_conditions: (promotion.side_conditions // {})
        },
        demotion: {
          decision: (demotion.decision // "missing"),
          recommended_state: (demotion.recommended_state // "missing"),
          triggers: (demotion.triggers // [])
        },
        transfer: {
          decision: (transfer.decision // "missing"),
          recommended_state: (transfer.recommended_state // "missing"),
          required_additional_proof: (transfer.required_additional_proof // [])
        }
      },
      evidence_freshness: (src.evidence_freshness // {}),
      side_condition_failures: (
        (promotion.fail_closed_reasons // [])
        + (demotion.fail_closed_reasons // [])
        + (transfer.fail_closed_reasons // [])
      ),
      next_validation_commands: (collect_commands | map({purpose:"operator copy/paste validation", command:.})),
      truth_gate: {
        schema_version: "franken-engine.optimization-promotion-operator-truth-gate.v1",
        decision: (if ($violations | length) > 0 then "fail_closed" else "pass" end),
        violations: $violations,
        scanned_operator_text_present: ((src.operator_status_text // "") != "")
      },
      artifact_paths: {
        status_json: $status_json,
        truth_gate_report_json: $truth_report_json,
        operator_status_md: $operator_status_md,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_md
      },
      mutation_policy: {
        advisory_only: true,
        proof_only: true,
        fixture_fed_only: true,
        mutates_runtime_policy: false,
        mutates_br: false,
        sends_agent_mail: false,
        releases_reservations: false,
        runs_cargo: false,
        runs_rch: false,
        mutates_remote_workers: false,
        publishes_benchmark_claims: false
      }
    }
  ' >"$status_json_tmp"
mv "$status_json_tmp" "$status_json"

jq '{
  schema_version: .truth_gate.schema_version,
  bead_id: .bead_id,
  parent_bead_id: .parent_bead_id,
  source_revision: .source_revision,
  decision: .truth_gate.decision,
  operator_state: .operator_state,
  violations: .truth_gate.violations,
  mutation_policy: .mutation_policy,
  artifacts: {
    status_json: .artifact_paths.status_json,
    operator_status_md: .artifact_paths.operator_status_md,
    commands_txt: .artifact_paths.commands_txt
  }
}' "$status_json" >"$truth_report_json_tmp"
mv "$truth_report_json_tmp" "$truth_report_json"

jq -r '.next_validation_commands[]?.command' "$status_json" | while IFS= read -r command_line; do
  [[ -n "$command_line" ]] && printf '%s\n' "$command_line" >>"$commands_path"
done

jq -r '
  "# Optimization Promotion Operator Status\n\n"
  + "- State: `" + .operator_state + "`\n"
  + "- Candidate: `" + .candidate.candidate_id + "`\n"
  + "- Reason: " + .state_reason + "\n"
  + "- Truth gate: `" + .truth_gate.decision + "`\n"
  + "- Mode: advisory only; no runtime policy mutation or benchmark publication.\n\n"
  + "## Saved Receipts\n"
  + "- Promotion: `" + .saved_receipts.promotion.recommended_state + "`\n"
  + "- Demotion: `" + .saved_receipts.demotion.recommended_state + "`\n"
  + "- Transfer: `" + .saved_receipts.transfer.recommended_state + "`\n\n"
  + "## Validation Commands\n"
  + (if (.next_validation_commands | length) == 0 then "- `none`" else (.next_validation_commands | map("- `" + .command + "`") | join("\n")) end)
  + "\n"
' "$status_json" >"$operator_status_md"
cp "$operator_status_md" "$report_md"

jq -c '.truth_gate.violations[]? | {schema_version:"franken-engine.optimization-promotion-operator-status.event.v1",event:"truth_violation",outcome:"fail_closed",code:.code,detail:.detail}' "$status_json" >>"$events_path"

decision="$(jq -r '.truth_gate.decision' "$status_json")"
if [[ "$decision" == "pass" ]]; then
  write_event "optimization_promotion_operator_status" "status_emitted" "pass" ""
  exit 0
fi

first_error="$(jq -r '.truth_gate.violations[0].code // "FE-OPT-STATUS-FAIL-CLOSED"' "$status_json")"
write_event "optimization_promotion_operator_status" "status_emitted" "fail_closed" "$first_error"
exit 42
