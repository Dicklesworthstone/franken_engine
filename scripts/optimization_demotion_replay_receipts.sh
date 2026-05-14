#!/usr/bin/env bash
set -euo pipefail

artifact_root="${OPTIMIZATION_DEMOTION_RECEIPT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-optimization-demotion-receipts}"
run_id="${OPTIMIZATION_DEMOTION_RECEIPT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${OPTIMIZATION_DEMOTION_RECEIPT_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${OPTIMIZATION_DEMOTION_RECEIPT_SOURCE_REVISION:-unknown}"
input_json=""
original_args=("$@")

usage() {
  cat >&2 <<'USAGE'
Usage: ./scripts/optimization_demotion_replay_receipts.sh --input-json FILE [OPTIONS]

Compose a deterministic source-only demotion, rollback, and safe-mode replay
receipt from saved evidence snapshots. The command never runs Cargo/RCH and
never mutates runtime policy, br, Agent Mail, reservations, workers, or
benchmark claims.

Required:
  --input-json FILE

Optional:
  --source-revision REV
  --output-dir DIR

Artifacts:
  optimization_demotion_receipt.json
  optimization_demotion_counterexample_bundle.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   receipt emitted with keep_observed, demote_now, or quarantine_candidate state
  42  missing rollback token, unsafe safe-mode fallback, or invalid evidence failed closed
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
  printf 'jq is required for optimization demotion replay receipts\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for optimization demotion replay receipts\n' >&2
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
receipt_json="${run_dir}/optimization_demotion_receipt.json"
receipt_json_tmp="${receipt_json}.tmp"
counterexample_json="${run_dir}/optimization_demotion_counterexample_bundle.json"
counterexample_json_tmp="${counterexample_json}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
normalized_input="${run_dir}/input.normalized.json"

jq -cS . "$input_json" >"$normalized_input"
input_hash="$(sha256sum "$normalized_input" | awk '{print $1}')"
receipt_hash="$input_hash"

printf './scripts/optimization_demotion_replay_receipts.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

: >"$events_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.optimization-demotion-receipt.event.v1" \
    --arg trace_id "trace-optimization-demotion-receipt-${run_id}" \
    --arg component "$1" \
    --arg event "$2" \
    --arg outcome "$3" \
    --arg error_code "$4" \
    '{schema_version:$schema_version,trace_id:$trace_id,component:$component,event:$event,outcome:$outcome,error_code:(if $error_code == "" then null else $error_code end)}' \
    >>"$events_path"
}

write_event "optimization_demotion_replay_receipts" "input_loaded" "captured" ""

jq -n \
  --slurpfile input "$normalized_input" \
  --arg source_revision "$source_revision" \
  --arg input_json "$input_json" \
  --arg normalized_input "$normalized_input" \
  --arg input_hash "$input_hash" \
  --arg receipt_hash "$receipt_hash" \
  --arg receipt_json "$receipt_json" \
  --arg counterexample_json "$counterexample_json" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" '
  def src: $input[0];
  def evidence: (src.evidence // {});
  def required_evidence_ids: [
    "proof_specialization_receipt",
    "policy_epoch",
    "semantic_parity",
    "rollback_health",
    "safe_mode_fallback",
    "performance_regression"
  ];
  def failure($code; $source_id; $detail; $remediation):
    {code:$code, source_id:$source_id, detail:$detail, remediation:$remediation};
  def trigger($code; $state; $source_id; $detail; $artifact_path; $sha256):
    {code:$code, recommended_state:$state, source_id:$source_id, detail:$detail, artifact_path:$artifact_path, sha256:$sha256};
  def missing_required:
    [required_evidence_ids[] as $id | select((evidence[$id] // null) == null) | $id];
  def field_hashes:
    [required_evidence_ids[] as $id
      | evidence[$id]? as $item
      | select($item != null)
      | select(($item.sha256 // "") != "")
      | {
          source_id: $id,
          artifact_path: ($item.artifact_path // null),
          sha256: $item.sha256
        }];
  def policy_epoch_drift:
    ((evidence.policy_epoch.epoch // src.policy_epoch // "") != (evidence.policy_epoch.expected_epoch // src.expected_policy_epoch // src.policy_epoch // ""))
    or ((evidence.policy_epoch.freshness // "fresh") != "fresh");
  def source_revision_mismatch:
    ((src.expected_source_revision // src.source_revision // $source_revision) != (src.source_revision // $source_revision));
  def proof_stale:
    ((evidence.proof_specialization_receipt.freshness // "fresh") != "fresh")
    or (evidence.proof_specialization_receipt.proof_inputs_current != true);
  def semantic_divergence:
    ((evidence.semantic_parity.freshness // "fresh") != "fresh")
    or ((evidence.semantic_parity.outcome // "match") != "match");
  def tail_regression:
    ((evidence.performance_regression.freshness // "fresh") != "fresh")
    or (evidence.performance_regression.tail_budget_ok != true);
  def rollback_ready:
    evidence.rollback_health.ready == true;
  def rollback_token_present:
    ((evidence.rollback_health.rollback_token // "") | type) == "string"
    and ((evidence.rollback_health.rollback_token // "") | length) > 0;
  def safe_mode_ready:
    evidence.safe_mode_fallback.ready == true
    and ((evidence.safe_mode_fallback.replay_command // "") | startswith("rch exec -- env "));
  def safe_mode_replay_command:
    if ((evidence.safe_mode_fallback.replay_command // "") | startswith("rch exec -- env ")) then
      evidence.safe_mode_fallback.replay_command
    else
      "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_or2e1 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p frankenengine-engine --test safe_mode_fallback_integration -- --nocapture"
    end;
  def has_synthetic:
    (src.contamination.synthetic_only // false) == true
    or any(required_evidence_ids[]; (evidence[.].synthetic_only // false) == true);
  (
    []
    + (if proof_stale then [
        trigger("OPT_DEMOTION_STALE_PROOF_RECEIPT"; "demote_now"; "proof_specialization_receipt";
          "proof-specialization receipt is stale or its proof inputs are not current";
          (evidence.proof_specialization_receipt.artifact_path // null);
          (evidence.proof_specialization_receipt.sha256 // null))
      ] else [] end)
    + (if policy_epoch_drift then [
        trigger("OPT_DEMOTION_POLICY_EPOCH_DRIFT"; "demote_now"; "policy_epoch";
          "policy epoch evidence no longer matches the expected epoch";
          (evidence.policy_epoch.artifact_path // null);
          (evidence.policy_epoch.sha256 // null))
      ] else [] end)
    + (if semantic_divergence then [
        trigger("OPT_DEMOTION_SEMANTIC_DIVERGENCE"; "quarantine_candidate"; "semantic_parity";
          "specialized and unspecialized behavior diverged";
          (evidence.semantic_parity.artifact_path // null);
          (evidence.semantic_parity.sha256 // null))
      ] else [] end)
    + (if tail_regression then [
        trigger("OPT_DEMOTION_TAIL_REGRESSION"; "demote_now"; "performance_regression";
          "candidate violates tail-latency budget";
          (evidence.performance_regression.artifact_path // null);
          (evidence.performance_regression.sha256 // null))
      ] else [] end)
  ) as $triggers
  | (
      if any($triggers[]?; .recommended_state == "quarantine_candidate") then "quarantine_candidate"
      elif ($triggers | length) > 0 then "demote_now"
      else "keep_observed"
      end
    ) as $action_state
  | ($action_state == "demote_now" or $action_state == "quarantine_candidate") as $needs_replay
  | (
    []
    + (missing_required
        | map(failure("FE-OPT-DEMOTION-MISSING-EVIDENCE"; .;
            "required demotion evidence is missing";
            "Provide this evidence family before composing demotion receipts.")))
    + (if source_revision_mismatch then [
        failure("FE-OPT-DEMOTION-SOURCE-REVISION-MISMATCH"; "source_revision";
          "evidence source revision does not match expected source revision";
          "Regenerate demotion evidence for the current source revision.")
      ] else [] end)
    + (if has_synthetic then [
        failure("FE-OPT-DEMOTION-SYNTHETIC-CONTAMINATION"; "contamination";
          "synthetic-only evidence cannot drive advisory demotion receipts";
          "Replace synthetic material with real runtime evidence or keep it fixture-scoped.")
      ] else [] end)
    + (if $needs_replay and ((rollback_ready | not) or (rollback_token_present | not)) then [
        failure("FE-OPT-DEMOTION-MISSING-ROLLBACK-TOKEN"; "rollback_health";
          "demotion or quarantine requires a ready rollback token";
          "Refresh specialization_rollback_gate evidence and include a rollback token before demotion.")
      ] else [] end)
    + (if $needs_replay and (safe_mode_ready | not) then [
        failure("FE-OPT-DEMOTION-SAFE-MODE-UNREADY"; "safe_mode_fallback";
          "demotion or quarantine requires a ready safe-mode replay command";
          "Refresh safe_mode_fallback evidence before demotion.")
      ] else [] end)
  ) as $failures
  | (
      if ($failures | length) > 0 then "fail_closed" else "pass" end
    ) as $decision
  | (
      if $decision == "fail_closed" then "fail_closed" else $action_state end
    ) as $recommended_state
  | {
      schema_version: "franken-engine.optimization-demotion-receipt.v1",
      bead_id: "bd-or2e1",
      parent_bead_id: "bd-xg3d6",
      component: "optimization_demotion_replay_receipts",
      source_revision: (src.source_revision // $source_revision),
      input: {
        path: $input_json,
        normalized_path: $normalized_input,
        sha256: $input_hash,
        schema_version: (src.schema_version // null),
        case_id: (src.case_id // null)
      },
      receipt_hash: $receipt_hash,
      decision: $decision,
      recommended_state: $recommended_state,
      candidate: {
        candidate_id: (src.candidate.candidate_id // "unknown_candidate"),
        current_state: (src.candidate.current_state // "observed"),
        workload_regime: (src.candidate.workload_regime // "unknown"),
        source_paths: (src.candidate.source_paths // [])
      },
      side_conditions: {
        source_revision_aligned: (source_revision_mismatch | not),
        policy_epoch_aligned: (policy_epoch_drift | not),
        proof_inputs_current: (proof_stale | not),
        semantic_parity_matched: (semantic_divergence | not),
        tail_budget_ok: (tail_regression | not),
        rollback_token_present_when_needed: (if $needs_replay then (rollback_ready and rollback_token_present) else true end),
        safe_mode_ready_when_needed: (if $needs_replay then safe_mode_ready else true end),
        no_synthetic_contamination: (has_synthetic | not)
      },
      triggers: $triggers,
      fail_closed_reasons: $failures,
      preserved_evidence_hashes: field_hashes,
      rollback: {
        required: $needs_replay,
        ready: rollback_ready,
        rollback_token_present: rollback_token_present,
        rollback_token_sha256: (evidence.rollback_health.rollback_token_sha256 // null),
        commands: (
          if $needs_replay then [{
            purpose: "advisory rollback validation",
            command: "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_or2e1 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p frankenengine-engine --test specialization_rollback_gate_integration -- --nocapture"
          }] else [] end
        )
      },
      safe_mode_replay: {
        required: $needs_replay,
        ready: safe_mode_ready,
        commands: (
          if $needs_replay then [{
            purpose: "safe-mode replay validation",
            command: safe_mode_replay_command
          }] else [] end
        )
      },
      counterexample_bundle: {
        path: $counterexample_json,
        required: ($triggers | length) > 0,
        trigger_count: ($triggers | length),
        minimal_sources: ($triggers | map({source_id, code, artifact_path, sha256}))
      },
      next_validation_commands: [
        {
          purpose: "focused demotion replay receipt proof",
          command: "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_or2e1 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p frankenengine-engine --lib demotion_rollback -- --nocapture"
        }
      ],
      artifact_paths: {
        receipt_json: $receipt_json,
        counterexample_bundle_json: $counterexample_json,
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
  ' >"$receipt_json_tmp"
mv "$receipt_json_tmp" "$receipt_json"

jq -n \
  --slurpfile receipt "$receipt_json" '
  def src: $receipt[0];
  {
    schema_version: "franken-engine.optimization-demotion-counterexample-bundle.v1",
    bead_id: "bd-or2e1",
    parent_bead_id: "bd-xg3d6",
    source_revision: src.source_revision,
    candidate: src.candidate,
    recommended_state: src.recommended_state,
    decision: src.decision,
    triggers: src.triggers,
    fail_closed_reasons: src.fail_closed_reasons,
    preserved_evidence_hashes: src.preserved_evidence_hashes,
    rollback_required: src.rollback.required,
    safe_mode_replay_required: src.safe_mode_replay.required
  }
  ' >"$counterexample_json_tmp"
mv "$counterexample_json_tmp" "$counterexample_json"

jq -r '
  (.rollback.commands[]?.command),
  (.safe_mode_replay.commands[]?.command),
  (.next_validation_commands[]?.command)
' "$receipt_json" | while IFS= read -r command_line; do
  [[ -n "$command_line" ]] && printf '%s\n' "$command_line" >>"$commands_path"
done

jq -r '
  "# Optimization Demotion Receipt\n\n"
  + "- Decision: `" + .decision + "`\n"
  + "- Recommended state: `" + .recommended_state + "`\n"
  + "- Candidate: `" + .candidate.candidate_id + "`\n"
  + "- Receipt hash: `" + .receipt_hash + "`\n"
  + "- Trigger count: `" + ((.triggers | length) | tostring) + "`\n"
  + "- Fail-closed reasons: `" + ((.fail_closed_reasons | length) | tostring) + "`\n\n"
  + "## Triggers\n"
  + (if (.triggers | length) == 0 then "- `none`" else (.triggers | map("- `" + .code + "`") | join("\n")) end)
  + "\n\n## Replay Commands\n"
  + ([
      .rollback.commands[]?.command,
      .safe_mode_replay.commands[]?.command,
      .next_validation_commands[]?.command
    ] | if length == 0 then "- `none`" else map("- `" + . + "`") | join("\n") end)
  + "\n"
' "$receipt_json" >"$report_md"

decision="$(jq -r '.decision' "$receipt_json")"
if [[ "$decision" == "pass" ]]; then
  write_event "optimization_demotion_replay_receipts" "receipt_emitted" "pass" ""
  exit 0
fi

first_error="$(jq -r '.fail_closed_reasons[0].code // "FE-OPT-DEMOTION-FAIL-CLOSED"' "$receipt_json")"
write_event "optimization_demotion_replay_receipts" "receipt_emitted" "fail_closed" "$first_error"
exit 42
