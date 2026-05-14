#!/usr/bin/env bash
set -euo pipefail

artifact_root="${OPTIMIZATION_TRANSFER_GUARD_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-optimization-transfer-guard}"
run_id="${OPTIMIZATION_TRANSFER_GUARD_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${OPTIMIZATION_TRANSFER_GUARD_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${OPTIMIZATION_TRANSFER_GUARD_SOURCE_REVISION:-unknown}"
input_json=""
original_args=("$@")

usage() {
  cat >&2 <<'USAGE'
Usage: ./scripts/optimization_transfer_guard.sh --input-json FILE [OPTIONS]

Compose a deterministic source-only workload-regime transfer guard from saved
evidence snapshots. The command never runs Cargo/RCH and never mutates runtime
policy, br, Agent Mail, reservations, workers, or benchmark claims.

Required:
  --input-json FILE

Optional:
  --source-revision REV
  --output-dir DIR

Artifacts:
  optimization_transfer_guard.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   guard emitted with allow or refusal state
  42  missing, ambiguous, contradictory, stale, or synthetic evidence failed closed
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
  printf 'jq is required for optimization transfer guard\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for optimization transfer guard\n' >&2
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
guard_json="${run_dir}/optimization_transfer_guard.json"
guard_json_tmp="${guard_json}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
normalized_input="${run_dir}/input.normalized.json"

jq -cS . "$input_json" >"$normalized_input"
input_hash="$(sha256sum "$normalized_input" | awk '{print $1}')"
guard_hash="$input_hash"

printf './scripts/optimization_transfer_guard.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

: >"$events_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.optimization-transfer-guard.event.v1" \
    --arg trace_id "trace-optimization-transfer-guard-${run_id}" \
    --arg component "$1" \
    --arg event "$2" \
    --arg outcome "$3" \
    --arg error_code "$4" \
    '{schema_version:$schema_version,trace_id:$trace_id,component:$component,event:$event,outcome:$outcome,error_code:(if $error_code == "" then null else $error_code end)}' \
    >>"$events_path"
}

write_event "optimization_transfer_guard" "input_loaded" "captured" ""

jq -n \
  --slurpfile input "$normalized_input" \
  --arg source_revision "$source_revision" \
  --arg input_json "$input_json" \
  --arg normalized_input "$normalized_input" \
  --arg input_hash "$input_hash" \
  --arg guard_hash "$guard_hash" \
  --arg guard_json "$guard_json" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" '
  def src: $input[0];
  def evidence: (src.evidence // {});
  def required_evidence_ids: [
    "cross_workload_transfer",
    "workload_manifold",
    "performance_regression",
    "real_hot_path_evidence"
  ];
  def failure($code; $source_id; $detail; $remediation):
    {code:$code, source_id:$source_id, detail:$detail, remediation:$remediation};
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
  def candidate: (src.candidate // {});
  def source_regime: (candidate.source_regime // evidence.real_hot_path_evidence.regime_id // evidence.workload_manifold.source_regime // "");
  def target_regime: (candidate.target_regime // evidence.workload_manifold.target_regime // "");
  def benefit_scope: (evidence.cross_workload_transfer.benefit_scope // "all_regimes");
  def transfer_confidence: (evidence.cross_workload_transfer.confidence // "missing");
  def supported_regimes: (evidence.cross_workload_transfer.supported_regimes // []);
  def excluded_regimes: (evidence.cross_workload_transfer.excluded_regimes // []);
  def counterevidence: (evidence.cross_workload_transfer.counterevidence // []);
  def source_revision_mismatch:
    ((src.expected_source_revision // src.source_revision // $source_revision) != (src.source_revision // $source_revision));
  def ambiguous_identity:
    (evidence.workload_manifold.identity_ambiguous // false) == true
    or (source_regime == "")
    or (target_regime == "");
  def contradictory_labels:
    ((candidate.source_regime // source_regime) != source_regime)
    or ((candidate.target_regime // target_regime) != target_regime)
    or ((evidence.real_hot_path_evidence.regime_id // source_regime) != source_regime)
    or ((evidence.workload_manifold.source_regime // source_regime) != source_regime)
    or ((evidence.workload_manifold.target_regime // target_regime) != target_regime);
  def has_synthetic:
    (src.contamination.synthetic_only // false) == true
    or any(required_evidence_ids[]; (evidence[.].synthetic_only // false) == true)
    or (evidence.real_hot_path_evidence.real_runtime_execution != true);
  def transfer_evidence_ready:
    evidence.cross_workload_transfer.available == true
    and ((evidence.cross_workload_transfer.freshness // "fresh") == "fresh")
    and ((evidence.workload_manifold.freshness // "fresh") == "fresh")
    and ((evidence.performance_regression.freshness // "fresh") == "fresh")
    and ((evidence.real_hot_path_evidence.freshness // "fresh") == "fresh");
  def tail_budget_ok:
    evidence.performance_regression.tail_budget_ok == true;
  def target_supported:
    any(supported_regimes[]?; . == target_regime);
  def target_excluded:
    any(excluded_regimes[]?; . == target_regime);
  (
    []
    + (missing_required
        | map(failure("FE-OPT-TRANSFER-MISSING-EVIDENCE"; .;
            "required transfer evidence is missing";
            "Provide this evidence family before composing transfer guard receipts.")))
    + (if source_revision_mismatch then [
        failure("FE-OPT-TRANSFER-SOURCE-REVISION-MISMATCH"; "source_revision";
          "evidence source revision does not match expected source revision";
          "Regenerate transfer evidence for the current source revision.")
      ] else [] end)
    + (if ambiguous_identity then [
        failure("FE-OPT-TRANSFER-AMBIGUOUS-WORKLOAD-IDENTITY"; "workload_identity";
          "workload identity or regime is ambiguous";
          "Normalize source and target workload identity before promotion.")
      ] else [] end)
    + (if contradictory_labels then [
        failure("FE-OPT-TRANSFER-CONTRADICTORY-REGIME-LABELS"; "workload_regime";
          "candidate, hot-path, and manifold evidence disagree on workload regimes";
          "Regenerate regime labels from one workload-manifold source before promotion.")
      ] else [] end)
    + (if has_synthetic then [
        failure("FE-OPT-TRANSFER-SYNTHETIC-CONTAMINATION"; "contamination";
          "synthetic-only evidence cannot support transfer promotion";
          "Replace synthetic material with real runtime transfer evidence or keep it fixture-scoped.")
      ] else [] end)
    + (if (missing_required | length) == 0 and (transfer_evidence_ready | not) then [
        failure("FE-OPT-TRANSFER-MISSING-EVIDENCE"; "cross_workload_transfer";
          "transfer evidence is absent, stale, unavailable, or incomplete";
          "Refresh cross-workload transfer, manifold, performance, and hot-path evidence.")
      ] else [] end)
  ) as $failures
  | (
      if source_regime == target_regime and target_supported and tail_budget_ok and (counterevidence | length) == 0 then {
        state: "allow_same_regime",
        reasons: ["OPT_TRANSFER_SAME_REGIME_SUPPORTED"],
        additional_proof: []
      }
      elif source_regime != target_regime and target_supported and (target_excluded | not) and transfer_confidence == "high" and tail_budget_ok and benefit_scope == "all_regimes" and (counterevidence | length) == 0 then {
        state: "allow_transfer",
        reasons: ["OPT_TRANSFER_CROSS_REGIME_SUPPORTED"],
        additional_proof: []
      }
      elif benefit_scope == "cold_start_only" then {
        state: "refuse_transfer",
        reasons: ["OPT_TRANSFER_COLD_START_ONLY_WIN"],
        additional_proof: ["warm-cache hot-path evidence for target regime", "steady-state tail regression proof for target regime"]
      }
      elif benefit_scope == "warmed_cache_only" then {
        state: "refuse_transfer",
        reasons: ["OPT_TRANSFER_WARMED_CACHE_ONLY_WIN"],
        additional_proof: ["cold-start proof for target regime", "cache-independent semantic parity proof"]
      }
      else {
        state: "refuse_transfer",
        reasons: ["OPT_TRANSFER_UNSUPPORTED_REGIME"],
        additional_proof: ["target-regime real hot-path evidence", "target-regime performance regression proof", "target-regime semantic parity proof"]
      }
      end
    ) as $guard_decision
  | (
      if ($failures | length) > 0 then "fail_closed" else "pass" end
    ) as $decision
  | (
      if $decision == "fail_closed" then "fail_closed" else $guard_decision.state end
    ) as $recommended_state
  | {
      schema_version: "franken-engine.optimization-transfer-guard.v1",
      bead_id: "bd-jp4r0",
      parent_bead_id: "bd-xg3d6",
      component: "optimization_transfer_guard",
      source_revision: (src.source_revision // $source_revision),
      input: {
        path: $input_json,
        normalized_path: $normalized_input,
        sha256: $input_hash,
        schema_version: (src.schema_version // null),
        case_id: (src.case_id // null)
      },
      guard_hash: $guard_hash,
      decision: $decision,
      recommended_state: $recommended_state,
      candidate: {
        candidate_id: (candidate.candidate_id // "unknown_candidate"),
        source_workload_id: (candidate.source_workload_id // "unknown_source_workload"),
        target_workload_id: (candidate.target_workload_id // "unknown_target_workload"),
        source_regime: source_regime,
        target_regime: target_regime,
        requested_state: (candidate.requested_state // "promote"),
        source_paths: (candidate.source_paths // [])
      },
      supported_regimes: supported_regimes,
      excluded_regimes: excluded_regimes,
      confidence: transfer_confidence,
      proximity_millionths: (evidence.cross_workload_transfer.proximity_millionths // null),
      benefit_scope: benefit_scope,
      counterevidence: counterevidence,
      required_additional_proof: (if $decision == "fail_closed" then [] else $guard_decision.additional_proof end),
      reason_codes: (if $decision == "fail_closed" then ($failures | map(.code)) else $guard_decision.reasons end),
      fail_closed_reasons: $failures,
      preserved_evidence_hashes: field_hashes,
      promotion_side_conditions: {
        transfer_guard_passed: ($decision == "pass" and ($recommended_state == "allow_same_regime" or $recommended_state == "allow_transfer")),
        workload_identity_unambiguous: (ambiguous_identity | not),
        regime_labels_consistent: (contradictory_labels | not),
        transfer_evidence_ready: transfer_evidence_ready,
        target_regime_supported: target_supported,
        target_regime_excluded: target_excluded,
        tail_budget_ok: tail_budget_ok,
        no_synthetic_contamination: (has_synthetic | not)
      },
      next_validation_commands: [
        {
          purpose: "focused transfer guard proof",
          command: "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_jp4r0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p frankenengine-engine --test cross_workload_transfer_integration -- --nocapture"
        },
        {
          purpose: "workload manifold transfer proof",
          command: "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_jp4r0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p frankenengine-engine --test workload_manifold_transfer_integration -- --nocapture"
        }
      ],
      artifact_paths: {
        guard_json: $guard_json,
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
  ' >"$guard_json_tmp"
mv "$guard_json_tmp" "$guard_json"

jq -r '.next_validation_commands[]?.command' "$guard_json" | while IFS= read -r command_line; do
  [[ -n "$command_line" ]] && printf '%s\n' "$command_line" >>"$commands_path"
done

jq -r '
  "# Optimization Transfer Guard\n\n"
  + "- Decision: `" + .decision + "`\n"
  + "- Recommended state: `" + .recommended_state + "`\n"
  + "- Candidate: `" + .candidate.candidate_id + "`\n"
  + "- Source regime: `" + .candidate.source_regime + "`\n"
  + "- Target regime: `" + .candidate.target_regime + "`\n"
  + "- Guard hash: `" + .guard_hash + "`\n"
  + "- Required additional proof count: `" + ((.required_additional_proof | length) | tostring) + "`\n\n"
  + "## Reason Codes\n"
  + (.reason_codes | map("- `" + . + "`") | join("\n"))
  + "\n\n## Next Validation Commands\n"
  + (.next_validation_commands | map("- `" + .command + "`") | join("\n"))
  + "\n"
' "$guard_json" >"$report_md"

decision="$(jq -r '.decision' "$guard_json")"
if [[ "$decision" == "pass" ]]; then
  write_event "optimization_transfer_guard" "guard_emitted" "pass" ""
  exit 0
fi

first_error="$(jq -r '.fail_closed_reasons[0].code // "FE-OPT-TRANSFER-FAIL-CLOSED"' "$guard_json")"
write_event "optimization_transfer_guard" "guard_emitted" "fail_closed" "$first_error"
exit 42
