#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${IDEA_WIZARD_IV_OPERATOR_TRUTH_GATE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-iw4-operator-truth-gate}"
run_id="${IDEA_WIZARD_IV_OPERATOR_TRUTH_GATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${IDEA_WIZARD_IV_OPERATOR_TRUTH_GATE_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${IDEA_WIZARD_IV_OPERATOR_TRUTH_GATE_SOURCE_REVISION:-}"
generated_at_utc="${IDEA_WIZARD_IV_OPERATOR_TRUTH_GATE_GENERATED_AT_UTC:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
bead_id="${IDEA_WIZARD_IV_OPERATOR_TRUTH_GATE_BEAD_ID:-bd-ks5p4}"
original_args=("$@")

saturation_report_json=""
closed_bead_proof_json=""
source_gap_picker_json=""
readme_path=""
operator_doc_path=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/idea_wizard_iv_operator_status_truth_gate.sh --saturation-report-json FILE --operator-doc PATH [OPTIONS]

Scan operator-facing IW4 saturation language and emit a truth-gated status
bundle. This script is advisory only and never mutates docs, beads, Agent Mail,
or validation state.

Required:
  --saturation-report-json FILE
  --operator-doc PATH

Optional:
  --closed-bead-proof-json FILE
  --source-gap-picker-json FILE
  --readme PATH
  --source-revision REV
  --generated-at-utc TIMESTAMP
  --output-dir DIR
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --saturation-report-json) saturation_report_json="${2:-}"; shift 2 ;;
    --closed-bead-proof-json) closed_bead_proof_json="${2:-}"; shift 2 ;;
    --source-gap-picker-json) source_gap_picker_json="${2:-}"; shift 2 ;;
    --operator-doc) operator_doc_path="${2:-}"; shift 2 ;;
    --readme) readme_path="${2:-}"; shift 2 ;;
    --source-revision) source_revision="${2:-}"; shift 2 ;;
    --generated-at-utc) generated_at_utc="${2:-}"; shift 2 ;;
    --output-dir) run_dir="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage; exit 64 ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for operator status truth gate\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi
if [[ -z "$saturation_report_json" || -z "$operator_doc_path" ]]; then
  printf 'operator truth gate requires --saturation-report-json and --operator-doc\n' >&2
  usage
  exit 64
fi
if [[ ! -f "$saturation_report_json" ]]; then
  printf 'saturation report not found: %s\n' "$saturation_report_json" >&2
  exit 64
fi
if ! jq empty "$saturation_report_json" >/dev/null 2>&1; then
  printf 'saturation report is malformed: %s\n' "$saturation_report_json" >&2
  exit 64
fi
if [[ -n "$closed_bead_proof_json" ]]; then
  if [[ ! -f "$closed_bead_proof_json" ]]; then
    printf 'closed bead proof report not found: %s\n' "$closed_bead_proof_json" >&2
    exit 64
  fi
  if ! jq empty "$closed_bead_proof_json" >/dev/null 2>&1; then
    printf 'closed bead proof report is malformed: %s\n' "$closed_bead_proof_json" >&2
    exit 64
  fi
fi
if [[ -n "$source_gap_picker_json" ]]; then
  if [[ ! -f "$source_gap_picker_json" ]]; then
    printf 'source-gap picker report not found: %s\n' "$source_gap_picker_json" >&2
    exit 64
  fi
  if ! jq empty "$source_gap_picker_json" >/dev/null 2>&1; then
    printf 'source-gap picker report is malformed: %s\n' "$source_gap_picker_json" >&2
    exit 64
  fi
fi
if [[ ! -f "$operator_doc_path" ]]; then
  printf 'operator doc not found: %s\n' "$operator_doc_path" >&2
  exit 64
fi
if [[ -n "$readme_path" && ! -f "$readme_path" ]]; then
  printf 'README path not found: %s\n' "$readme_path" >&2
  exit 64
fi

mkdir -p "$run_dir"
truth_report="${run_dir}/operator_truth_gate_report.json"
status_md="${run_dir}/operator_status.md"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
report_md="${run_dir}/report.md"
docs_text="${run_dir}/operator_docs.txt"
closed_bead_proof_input="${run_dir}/closed_bead_proof.input.json"
source_gap_picker_input="${run_dir}/source_gap_picker.input.json"

for artifact_path in "$truth_report" "$status_md" "$manifest_path" "$events_path" "$commands_path" "$trace_ids_path" "$report_md" "$docs_text" "$closed_bead_proof_input" "$source_gap_picker_input"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/idea_wizard_iv_operator_status_truth_gate.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

{
  printf '# operator-doc: %s\n' "$operator_doc_path"
  cat "$operator_doc_path"
  if [[ -n "$readme_path" ]]; then
    printf '\n# readme: %s\n' "$readme_path"
    cat "$readme_path"
  fi
} >"$docs_text"

if [[ -n "$closed_bead_proof_json" ]]; then
  jq '.' "$closed_bead_proof_json" >"$closed_bead_proof_input"
else
  printf '{}\n' >"$closed_bead_proof_input"
fi
if [[ -n "$source_gap_picker_json" ]]; then
  jq '.' "$source_gap_picker_json" >"$source_gap_picker_input"
else
  printf '{}\n' >"$source_gap_picker_input"
fi

# shellcheck disable=SC2094 # truth_report is passed as metadata and is not read by this jq invocation.
jq -n \
  --slurpfile saturation "$saturation_report_json" \
  --slurpfile closed_proof "$closed_bead_proof_input" \
  --slurpfile source_gap "$source_gap_picker_input" \
  --rawfile docs "$docs_text" \
  --arg schema_version "franken-engine.idea-wizard-iv-operator-truth-gate.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg generated_at_utc "$generated_at_utc" \
  --arg saturation_report_json "$saturation_report_json" \
  --arg closed_bead_proof_json "$closed_bead_proof_json" \
  --arg source_gap_picker_json "$source_gap_picker_json" \
  --arg operator_doc_path "$operator_doc_path" \
  --arg readme_path "$readme_path" \
  --arg truth_report "$truth_report" \
  --arg status_md "$status_md" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg trace_ids_path "$trace_ids_path" \
  --arg report_md "$report_md" '
    def low($v): ($v // "" | tostring | ascii_downcase);
    def violation($code; $phrase; $detail): {code:$code,phrase:$phrase,detail:$detail};
    def required($code; $phrase; $detail): {code:$code,phrase:$phrase,detail:$detail};
    ($saturation[0] // {}) as $sat
    | ($closed_proof[0] // {}) as $closed
    | ($source_gap[0] // {}) as $gap
    | (low($docs)) as $text
    | (((($sat.child_reports // [])[]? | select(.surface_id == "coordination_health_packet") | .decision) // "missing") | tostring) as $coordination_decision
    | (($closed.semantic_contradiction_count // 0) | tonumber) as $semantic_contradictions
    | (($gap.proposal_count // 0) | tonumber) as $source_gap_proposals
    | ([
        if ($closed_bead_proof_json == "") then "FE-IWXII-MISSING-CLOSED-BEAD-PROOF" else empty end,
        if ($source_gap_picker_json == "") then "FE-IWXII-MISSING-SOURCE-GAP-PICKER" else empty end,
        if ($semantic_contradictions > 0) then "FE-IWXII-SEMANTIC-CONTRADICTION" else empty end,
        if ($source_gap_proposals > 0) then "FE-IWXII-SOURCE-GAP-PROPOSAL" else empty end,
        if ($coordination_decision == "degraded" or $coordination_decision == "fail_closed") then "FE-IWXII-DEGRADED-COORDINATION" else empty end
      ]) as $zero_ready_reason_codes
    | (if ($closed_bead_proof_json == "" or $source_gap_picker_json == "") then "degraded_unknown"
       elif ($semantic_contradictions > 0 or $source_gap_proposals > 0) then "source_gap_found"
       elif ((($closed.decision // "") == "green" or (($closed.weak_evidence_count // 0) == 0 and ($semantic_contradictions == 0)))
         and (($gap.decision // "") == "no_actionable_source_gap" or ($gap.classification // "") == "true_zero_ready_no_source_gaps")) then "true_saturation"
       else "degraded_unknown"
       end) as $zero_ready_state
    | (if $zero_ready_state == "source_gap_found" then
        [
          "Review " + (if $source_gap_picker_json == "" then "the source-gap picker report" else $source_gap_picker_json end) + " and create one bounded follow-up bead from proposed_beads.json.",
          "For semantic contradictions, start with the closed bead proof report and keep validation rch-wrapped."
        ]
      elif $zero_ready_state == "degraded_unknown" then
        [
          "Run scripts/idea_wizard_iv_closed_bead_proof_integrity.sh with --source-marker-json and preserve closed_bead_proof_integrity.json.",
          "Run scripts/idea_wizard_xii_zero_ready_source_gap_picker.sh with br ready/open snapshots and preserve zero_ready_source_gap_picker.json.",
          "If Agent Mail is degraded, keep bead assignment as the soft lock and do not repair the DB from this gate."
        ]
      else
        [
          "Attach operator_status.md and the preserved zero-ready truth artifacts to the handoff.",
          "No source-gap bead is proposed by this bundle."
        ]
      end) as $next_commands
    | ([
        if ($text | test("automatically (repair|fix).*agent mail|agent mail.*automatically (repair|fix)")) then violation("automatic_agent_mail_repair_claim"; "automatic Agent Mail repair"; "Operator docs imply Agent Mail is repaired automatically.") else empty end,
        if ($text | test("automatically (reopen|close|claim|assign).*bead|bead.*automatically (reopen|close|claim|assign)")) then violation("automatic_bead_mutation_claim"; "automatic bead mutation"; "Operator docs imply queue mutation.") else empty end,
        if (($text | test("production guarantee|project-wide completion|proves project-wide|guarantees saturation")) and (($text | contains("without evidence")) | not)) then violation("production_or_project_wide_overclaim"; "production/project-wide guarantee"; "Operator docs overstate proof scope.") else empty end
      ]) as $violations
    | ([
        if (($text | contains("advisory")) | not) then required("missing_advisory_mode"; "advisory"; "Docs must say the control plane is advisory.") else empty end,
        if (($text | test("required artifact|required artifacts")) | not) then required("missing_required_artifacts"; "required artifacts"; "Docs must mention required artifacts.") else empty end,
        if (($text | contains("rch exec -- env cargo_target_dir=")) | not) then required("missing_rch_backed_validation"; "rch exec -- env CARGO_TARGET_DIR="; "Docs must mention RCH-backed validation shape.") else empty end,
        if (($text | test("degraded coordination|agent mail.*degraded|coordination.*degraded")) | not) then required("missing_degraded_coordination_limit"; "degraded coordination"; "Docs must mention degraded coordination limitations.") else empty end
      ]) as $missing_required
    | ([
        if (($saturation_report_json | length) == 0 or (($sat.schema_version // "") == "")) then violation("missing_acceptance_bundle"; "saturation_convergence_report"; "A preserved saturation convergence report is required.") else empty end
      ]) as $bundle_violations
    | ($violations + $missing_required + $bundle_violations) as $all_violations
    | (if ($all_violations | length) > 0 then "fail_closed"
       elif ($zero_ready_state == "source_gap_found" or $zero_ready_state == "degraded_unknown") then "degraded"
       elif (($sat.decision // "") == "green") then "green"
       else "degraded"
       end) as $decision
    | {
        schema_version:$schema_version,
        bead_id:$bead_id,
        source_revision:$source_revision,
        generated_at_utc:$generated_at_utc,
        decision:$decision,
        claim_sensitivity_checks:{
          advisory_mode_required:true,
          required_artifacts_required:true,
          rch_backed_validation_required:true,
          degraded_coordination_limit_required:true,
          forbidden_automatic_mutation_claims:true
        },
        observed_claims:{
          saturation_decision:($sat.decision // "missing"),
          saturation_classification:($sat.classification // "missing"),
          br_ready_count:($sat.br_ready_count // null),
          child_reports:($sat.child_reports // []),
          closed_bead_proof_decision:($closed.decision // "missing"),
          closed_bead_proof_classification:($closed.classification // "missing"),
          source_gap_picker_decision:($gap.decision // "missing"),
          source_gap_picker_classification:($gap.classification // "missing")
        },
        zero_ready_truth:{
          state:$zero_ready_state,
          reason_codes:$zero_ready_reason_codes,
          semantic_contradiction_count:$semantic_contradictions,
          source_gap_proposal_count:$source_gap_proposals,
          closed_bead_proof_json_present:($closed_bead_proof_json != ""),
          source_gap_picker_json_present:($source_gap_picker_json != ""),
          coordination_decision:$coordination_decision,
          next_commands:$next_commands,
          proposed_beads:($gap.proposed_beads // [])
        },
        targeted_claims:[
          "advisory proof-only status",
          "required artifacts gate",
          "RCH-backed validation guidance",
          "degraded coordination limitation",
          "zero-ready truth state"
        ],
        violations:$all_violations,
        operator_status:{
          zero_ready_truth_state:$zero_ready_state,
          headline:(if ($all_violations | length) > 0 then "IW4 saturation status blocked by truth-gate violations"
            elif ($zero_ready_state == "source_gap_found") then "IW4/IWXII zero-ready status has source gaps"
            elif ($zero_ready_state == "true_saturation") then "IW4/IWXII zero-ready status is true_saturation for the preserved bundle"
            else "IW4/IWXII zero-ready status is degraded_unknown for the preserved bundle" end),
          pasteable_summary:(
            "IW4/IWXII zero-ready " + $zero_ready_state
            + ": decision=" + $decision
            + ": classification=" + (($sat.classification // "missing") | tostring)
            + ", ready_count=" + (($sat.br_ready_count // "unknown") | tostring)
            + ", semantic_contradictions=" + ($semantic_contradictions | tostring)
            + ", source_gap_proposals=" + ($source_gap_proposals | tostring)
            + ", coordination=" + (((($sat.child_reports // [])[]? | select(.surface_id == "coordination_health_packet") | .decision) // "missing") | tostring)
            + ", validation=" + (((($sat.child_reports // [])[]? | select(.surface_id == "validation_impact_plan") | .decision) // "missing") | tostring)
            + ", resource=" + (((($sat.child_reports // [])[]? | select(.surface_id == "resource_proof_heatmap") | .decision) // "missing") | tostring)
            + ". Advisory only; no automatic Agent Mail repair or bead mutation."
          )
        },
        mutation_policy:{advisory_only:true,proof_only:true,mutates_git:false,mutates_br:false,sends_agent_mail:false,repairs_agent_mail_db:false,runs_cargo:false,runs_rch:false},
        rch_policy:{runs_rch:false,emits_commands_only:false,required_heavy_cargo_prefix:"rch exec -- env CARGO_TARGET_DIR="},
        artifact_paths:{
          operator_truth_gate_report_json:$truth_report,
          operator_status_md:$status_md,
          run_manifest_json:$manifest_path,
          events_jsonl:$events_path,
          commands_txt:$commands_path,
          trace_ids_json:$trace_ids_path,
          report_md:$report_md
        },
        input_artifacts:{
          saturation_report_json:$saturation_report_json,
          closed_bead_proof_json:(if $closed_bead_proof_json == "" then null else $closed_bead_proof_json end),
          source_gap_picker_json:(if $source_gap_picker_json == "" then null else $source_gap_picker_json end),
          operator_doc_path:$operator_doc_path,
          readme_path:(if $readme_path == "" then null else $readme_path end)
        }
      }
  ' >"$truth_report"

{
  printf '# IDEA-WIZARD-IV Operator Status\n\n'
  jq -r '.operator_status.pasteable_summary' "$truth_report"
  printf '\n\n'
  printf '## Next Commands\n\n'
  jq -r '.zero_ready_truth.next_commands[]? | "- " + .' "$truth_report"
  printf '\n'
  jq -r '.violations[]? | "- `" + .code + "`: " + .detail' "$truth_report"
} >"$status_md"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-iv-operator-truth-gate.run-manifest.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg decision "$(jq -r '.decision' "$truth_report")" \
  --arg truth_report "$truth_report" \
  '{schema_version:$schema_version,bead_id:$bead_id,source_revision:$source_revision,decision:$decision,artifacts:{operator_truth_gate_report_json:$truth_report}}' >"$manifest_path"
jq -n \
  --arg schema_version "franken-engine.idea-wizard-iv-operator-truth-gate.trace-ids.v1" \
  --arg trace_id "iw4-operator-truth-gate-${run_id}" \
  --arg bead_id "$bead_id" \
  '{schema_version:$schema_version,trace_id:$trace_id,bead_id:$bead_id}' >"$trace_ids_path"
jq -c '.violations[]? | {schema_version:"franken-engine.idea-wizard-iv-operator-truth-gate.event.v1",event:"violation",outcome:"fail_closed",code:.code,detail:.detail}' "$truth_report" >>"$events_path"
cp "$status_md" "$report_md"

printf 'operator_truth_gate_report=%s\n' "$truth_report"
if [[ "$(jq -r '.decision' "$truth_report")" == "fail_closed" ]]; then
  exit 42
fi
