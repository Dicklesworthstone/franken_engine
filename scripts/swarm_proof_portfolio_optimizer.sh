#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_PROOF_PORTFOLIO_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-proof-portfolio}"
run_id="${SWARM_PROOF_PORTFOLIO_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_PROOF_PORTFOLIO_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${SWARM_PROOF_PORTFOLIO_SOURCE_REVISION:-unknown}"
input_json=""
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_proof_portfolio_optimizer.sh --input-json FILE [OPTIONS]

Ranks saved proof command candidates for a bead or swarm slice. The optimizer
is advisory-only: it reads fixture/export JSON, emits proof portfolio artifacts,
and never runs Cargo, invokes rch, mutates beads, sends Agent Mail, or claims
that a proof command succeeded.

Required:
  --input-json FILE

Options:
  --source-revision REV
  --output-dir DIR

Artifacts:
  proof_portfolio_plan.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   portfolio emitted with pass or degraded decision
  42  stale, contradictory, local-fallback, or unsafe candidate evidence forced fail_closed
  64  invalid input
EOF
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
  printf 'jq is required for swarm proof portfolio optimizer\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm proof portfolio optimizer\n' >&2
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
plan_path="${run_dir}/proof_portfolio_plan.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
normalized_input="${run_dir}/input.normalized.json"
plan_tmp="${plan_path}.tmp"

for artifact_path in "$plan_path" "$events_path" "$commands_path" "$report_path" "$normalized_input" "$plan_tmp"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

jq -cS . "$input_json" >"$normalized_input"
input_hash="$(sha256sum "$normalized_input" | awk '{print $1}')"

printf './scripts/swarm_proof_portfolio_optimizer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -n \
  --slurpfile input "$normalized_input" \
  --arg source_revision "$source_revision" \
  --arg input_json "$input_json" \
  --arg normalized_input "$normalized_input" \
  --arg input_hash "$input_hash" \
  --arg plan_path "$plan_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def src: $input[0];
  def candidates: (src.candidate_commands // []);
  def compile_blockers: (src.compile_blockers // []);
  def contradictions: (src.contradictions // []);
  def failure($code; $source_id; $detail; $remediation):
    {code:$code, source_id:$source_id, detail:$detail, remediation:$remediation};
  def heavy_cargo($command):
    ($command | test("(^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$)"));
  def rch_wrapped($command):
    ($command | contains("rch exec --"));
  def risk_weight($risk):
    if $risk == "low" then 0
    elif $risk == "medium" then 1
    elif $risk == "high" then 2
    else 3 end;
  def candidate_missing_fields($candidate):
    (($candidate.command_id // "") == "")
    or (($candidate.command // "") == "")
    or (($candidate.target // "") == "")
    or (($candidate.expected_evidence // "") == "")
    or (($candidate.risk_class // "") == "")
    or (($candidate.prerequisites // []) | length == 0)
    or (($candidate.safe_alternative // "") == "");

  (
    []
    + (if ((src.contract_profile.decision // "") == "pass") then [] else [
        failure("missing_contract_profile"; "bd-gvhsx.6";
          "contract/profile evidence is missing or not passing";
          "Run the bd-gvhsx.6 contract/profile gate and provide a passing profile artifact.")
      ] end)
    + (if ((src.evidence_freshness // "fresh") == "fresh") then [] else [
        failure("stale_artifact_evidence"; "evidence_freshness";
          "proof portfolio input contains stale evidence";
          "Refresh saved artifacts or downgrade the proof recommendation.")
      ] end)
    + (if ((src.local_rch_fallback_detected // false) == true) then [
        failure("local_rch_fallback_contamination"; "rch";
          "input observed local rch fallback contamination";
          "Do not recommend proof commands until remote rch evidence is clean.")
      ] else [] end)
    + ([contradictions[]
        | failure("contradictory_artifacts"; (.source_id // "contradiction");
            (.detail // "contradictory proof artifacts");
            (.remediation // "Resolve contradictory proof artifacts before ranking commands."))])
    + ([candidates[]
        | select(candidate_missing_fields(.))
        | failure("candidate_missing_required_fields"; (.command_id // "unknown_candidate");
            "candidate command is missing command, target, evidence, risk, prerequisites, or safe alternative";
            "Provide a complete candidate command record before ranking.")])
    + ([candidates[]
        | select(heavy_cargo(.command // "") and (rch_wrapped(.command // "") | not))
        | failure("bare_cargo_candidate"; (.command_id // "unknown_candidate");
            "heavy Cargo candidate is not wrapped with rch exec --";
            "Rewrite the candidate as an rch-wrapped command with an explicit target directory.")])
  ) as $failures
  | (if ($failures | length) > 0 then "fail_closed"
     elif (compile_blockers | length) > 0 then "degraded"
     elif ((src.resource_state.slots_available // 0) | tonumber) <= 0 then "degraded"
     elif (candidates | length) == 0 then "degraded"
     else "pass" end) as $decision
  | (if ($failures | length) > 0 then "fail_closed"
     elif (compile_blockers | length) > 0 then "compile_blocker"
     elif ((src.resource_state.slots_available // 0) | tonumber) <= 0 then "no_worker_slot"
     elif (candidates | length) == 0 then "no_candidate_commands"
     else "ranked" end) as $portfolio_state
  | ([candidates[]
      | {
          command_id,
          command,
          exact_target: (.target // ""),
          expected_evidence,
          risk_class,
          prerequisites: (.prerequisites // []),
          safe_alternative,
          source_artifacts: (.source_artifacts // []),
          priority: (.priority // 999),
          risk_weight: risk_weight(.risk_class // "unknown"),
          recommendation_state: (
            if $decision == "fail_closed" then "blocked"
            elif $portfolio_state == "compile_blocker" then "blocked"
            elif $portfolio_state == "no_worker_slot" then "deferred"
            elif $portfolio_state == "no_candidate_commands" then "blocked"
            else "recommended" end
          ),
          recommendation_reason: (
            if $decision == "fail_closed" then "fail-closed evidence prevents proof recommendation"
            elif $portfolio_state == "compile_blocker" then "current-head compile blockers must be surfaced first"
            elif $portfolio_state == "no_worker_slot" then "no worker slot is available for this proof"
            elif $portfolio_state == "no_candidate_commands" then "no complete candidate commands were provided"
            else "candidate satisfies portfolio prerequisites" end
          )
        }]
      | sort_by(.priority, .risk_weight, .command_id)) as $portfolio_items
  | {
      schema_version: "franken-engine.swarm-proof-portfolio-plan.v1",
      component: "swarm_proof_portfolio_optimizer",
      source_revision: $source_revision,
      input: {
        path: $input_json,
        normalized_path: $normalized_input,
        sha256: $input_hash,
        schema_version: (src.schema_version // null),
        case_id: (src.case_id // null)
      },
      decision: $decision,
      portfolio_state: $portfolio_state,
      fail_closed_reasons: $failures,
      compile_blockers: compile_blockers,
      resource_state: (src.resource_state // {}),
      contract_profile: (src.contract_profile // {}),
      portfolio_items: $portfolio_items,
      recommended_commands: [$portfolio_items[] | select(.recommendation_state == "recommended")],
      blocked_or_deferred_commands: [$portfolio_items[] | select(.recommendation_state != "recommended")],
      artifact_paths: {
        proof_portfolio_plan_json: $plan_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      },
      non_mutation_attestation: {
        reads_saved_files_only: true,
        mutates_beads: false,
        sends_agent_mail: false,
        runs_cargo: false,
        runs_rch: false,
        claims_command_success: false
      }
    }
' >"$plan_tmp"
mv "$plan_tmp" "$plan_path"

jq -c '
  if (.decision == "fail_closed") then
    [.fail_closed_reasons[]
      | {
          schema_version: "franken-engine.swarm-proof-portfolio.event.v1",
          component: "swarm_proof_portfolio_optimizer",
          event: "fail_closed_reason",
          outcome: "fail_closed",
          error_code: .code,
          source_id: .source_id,
          detail: .detail
        }]
  elif (.decision == "degraded") then
    [{
      schema_version: "franken-engine.swarm-proof-portfolio.event.v1",
      component: "swarm_proof_portfolio_optimizer",
      event: "portfolio_degraded",
      outcome: "degraded",
      error_code: .portfolio_state,
      source_id: null,
      detail: "portfolio emitted degraded recommendation"
    }]
  else
    [{
      schema_version: "franken-engine.swarm-proof-portfolio.event.v1",
      component: "swarm_proof_portfolio_optimizer",
      event: "portfolio_ranked",
      outcome: "pass",
      error_code: null,
      source_id: null,
      detail: "proof portfolio ranked"
    }]
  end
  | .[]
' "$plan_path" >"$events_path"

jq -r '
  "# Swarm Proof Portfolio Plan",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Portfolio state: `" + .portfolio_state + "`"),
  ("- Recommended commands: `" + (.recommended_commands | length | tostring) + "`"),
  ("- Blocked/deferred commands: `" + (.blocked_or_deferred_commands | length | tostring) + "`"),
  "",
  "## Fail-Closed Reasons",
  "",
  (if (.fail_closed_reasons | length) == 0 then
    "none"
  else
    (.fail_closed_reasons[]
      | "- `" + .code + "` `" + .source_id + "`: " + .detail + " Remediation: " + .remediation)
  end),
  "",
  "## Recommended Commands",
  "",
  (if (.recommended_commands | length) == 0 then
    "none"
  else
    (.recommended_commands[]
      | "- `" + .command_id + "` target `" + .exact_target + "` risk `" + .risk_class + "`\n  command: `" + .command + "`\n  expected evidence: " + .expected_evidence + "\n  safe alternative: " + .safe_alternative)
  end),
  "",
  "## Blocked Or Deferred",
  "",
  (if (.blocked_or_deferred_commands | length) == 0 then
    "none"
  else
    (.blocked_or_deferred_commands[]
      | "- `" + .command_id + "` `" + .recommendation_state + "`: " + .recommendation_reason + "\n  safe alternative: " + .safe_alternative)
  end)
' "$plan_path" >"$report_path"

printf 'proof_portfolio_plan=%s\n' "$plan_path"
printf 'proof_portfolio_events=%s\n' "$events_path"

if jq -e '.decision == "fail_closed"' "$plan_path" >/dev/null; then
  exit 42
fi
exit 0
