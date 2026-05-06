#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_STARVATION_RESCUE_CONFORMANCE_GATE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-starvation-rescue-conformance-gate}"
run_id="${SWARM_STARVATION_RESCUE_CONFORMANCE_GATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_STARVATION_RESCUE_CONFORMANCE_GATE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

starvation_rescue_plan_json=""
source_revision=""
now_epoch_seconds="$(date -u +%s)"
stale_after_seconds="1800"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_starvation_rescue_conformance_gate.sh --starvation-rescue-plan-json FILE [OPTIONS]

Checks that a starvation-rescue planner receipt stays ownership-safe,
fairness-honest, and artifact-grounded. The gate is report-only: it validates
planner truth and drill transcripts without mutating beads, reservations, or
worker state.

Required:
  --starvation-rescue-plan-json FILE

Optional:
  --source-revision REV
  --now-epoch-seconds N
  --stale-after-seconds N
  --output-dir DIR

Artifacts:
  swarm_starvation_rescue_conformance_report.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  conformance report emitted without gate failures
  42 fail-closed due to contradictory ownership, stale rescue evidence,
     salvage/manual-review drift, local-fallback transport drift, missing
     artifact lineage, or bare cargo drill commands
  64 invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --starvation-rescue-plan-json)
      starvation_rescue_plan_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --now-epoch-seconds)
      now_epoch_seconds="${2:-}"
      shift 2
      ;;
    --stale-after-seconds)
      stale_after_seconds="${2:-}"
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

canonical_path() {
  local path="$1"
  if [[ -e "$path" ]]; then
    local dir
    dir="$(cd "$(dirname "$path")" && pwd)"
    printf '%s/%s\n' "$dir" "$(basename "$path")"
  else
    printf '%s\n' "$path"
  fi
}

normalize_json_copy() {
  local input_path="$1"
  local output_path="$2"
  local label="$3"

  if [[ -z "$input_path" ]]; then
    printf 'missing %s path\n' "$label" >&2
    exit 64
  fi
  if [[ ! -f "$input_path" ]]; then
    printf 'missing %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'invalid %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  jq -cS . "$input_path" >"$output_path"
}

json_has_fail_reason() {
  local json_path="$1"
  local reason_kind="$2"
  jq -e \
    --arg reason_kind "$reason_kind" \
    'any((.fail_closed_reasons // [])[]?; (.kind // "") == $reason_kind)' \
    "$json_path" >/dev/null 2>&1
}

json_has_recommendation() {
  local json_path="$1"
  local action_name="$2"
  jq -e \
    --arg action_name "$action_name" \
    'any((.recommendations // [])[]?; (.action // "") == $action_name)' \
    "$json_path" >/dev/null 2>&1
}

if [[ -z "$starvation_rescue_plan_json" ]]; then
  printf 'swarm starvation rescue conformance gate requires --starvation-rescue-plan-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm starvation rescue conformance gating\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm starvation rescue conformance gating\n' >&2
  exit 2
fi
if ! command -v grep >/dev/null 2>&1; then
  printf 'grep is required for swarm starvation rescue conformance gating\n' >&2
  exit 2
fi
if ! is_int "$now_epoch_seconds" || ! is_int "$stale_after_seconds"; then
  printf 'now/stale thresholds must be non-negative integers\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
report_path="${run_dir}/swarm_starvation_rescue_conformance_report.json"
report_tmp="${report_path}.tmp"
core_path="${run_dir}/swarm_starvation_rescue_conformance_report.core.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md_path="${run_dir}/report.md"
gate_failures_jsonl="${run_dir}/gate_failures.jsonl"
invariants_jsonl="${run_dir}/invariants.jsonl"
checked_commands_jsonl="${run_dir}/checked_commands.jsonl"

plan_normalized="${run_dir}/swarm_starvation_rescue_plan.normalized.json"
input_normalized="${run_dir}/swarm_starvation_rescue_input.normalized.json"
matrix_normalized="${run_dir}/swarm_starvation_rescue_scenario_matrix.normalized.json"

: >"$events_path"
: >"$gate_failures_jsonl"
: >"$invariants_jsonl"
: >"$checked_commands_jsonl"

printf './scripts/swarm_starvation_rescue_conformance_gate.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-starvation-rescue-conformance-gate.event.v1" \
    --arg event_name "$1" \
    --arg detail "$2" \
    --arg source_revision "$source_revision" \
    '{
      schema_version: $schema_version,
      event_name: $event_name,
      detail: $detail,
      source_revision: $source_revision
    }' >>"$events_path"
}

append_gate_failure() {
  jq -nc \
    --arg code "$1" \
    --arg detail "$2" \
    '{code:$code, detail:$detail}' >>"$gate_failures_jsonl"
}

record_invariant() {
  jq -nc \
    --arg name "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    '{name:$name, outcome:$outcome, detail:$detail}' >>"$invariants_jsonl"
}

normalize_json_copy "$starvation_rescue_plan_json" "$plan_normalized" "starvation rescue plan"

if ! jq -e '
  .schema_version == "franken-engine.swarm-starvation-rescue-plan.v1"
  and (.decision | type == "string")
  and (.scenario_class | type == "string")
  and (.summary | type == "object")
  and (.policy_basis.matched_case_ids | type == "array")
  and (.recommendations | type == "array")
  and (.artifact_paths.swarm_starvation_rescue_plan_json | type == "string")
  and (.artifact_paths.events_jsonl | type == "string")
  and (.artifact_paths.commands_txt | type == "string")
  and (.artifact_paths.report_md | type == "string")
  and (.resolved_inputs | type == "array")
' "$plan_normalized" >/dev/null 2>&1; then
  printf 'starvation rescue plan shape mismatch for conformance gate\n' >&2
  exit 64
fi

resolved_input_path="$(jq -r '.resolved_inputs[] | select(.input == "starvation_rescue_input_json") | .path' "$plan_normalized")"
resolved_matrix_path="$(jq -r '.resolved_inputs[] | select(.input == "scenario_matrix_report_json") | .path' "$plan_normalized")"
normalize_json_copy "$resolved_input_path" "$input_normalized" "resolved starvation rescue input"
normalize_json_copy "$resolved_matrix_path" "$matrix_normalized" "resolved scenario matrix report"

if ! jq -e '
  .schema_version == "franken-engine.swarm-starvation-rescue-input.v1"
  and (.decision | type == "string")
  and (.summary | type == "object")
  and (.derived_truth | type == "object")
  and (.fail_closed_reasons | type == "array")
' "$input_normalized" >/dev/null 2>&1; then
  printf 'resolved starvation rescue input shape mismatch for conformance gate\n' >&2
  exit 64
fi

if ! jq -e '
  .schema_version == "franken-engine.swarm-starvation-rescue-scenario-matrix-report.v1"
  and (.required_scenario_classes | type == "array")
  and (.cases | type == "array")
  and (.failure_count | type == "number")
' "$matrix_normalized" >/dev/null 2>&1; then
  printf 'resolved starvation rescue scenario matrix shape mismatch for conformance gate\n' >&2
  exit 64
fi

write_event "swarm_starvation_rescue_conformance_gate.inputs_loaded" "loaded planner receipt and resolved rescue inputs"

plan_path_canon="$(canonical_path "$starvation_rescue_plan_json")"
plan_path_claim="$(jq -r '.artifact_paths.swarm_starvation_rescue_plan_json' "$plan_normalized")"
if [[ "$(canonical_path "$plan_path_claim")" != "$plan_path_canon" ]]; then
  append_gate_failure "plan_artifact_path_mismatch" "planner artifact path does not resolve back to the checked plan JSON"
fi

while IFS= read -r artifact_path; do
  [[ -n "$artifact_path" ]] || continue
  if [[ ! -f "$artifact_path" ]]; then
    append_gate_failure "missing_artifact_path" "planner referenced missing artifact path ${artifact_path}"
  fi
done < <(
  jq -r '
    .artifact_paths.swarm_starvation_rescue_plan_json,
    .artifact_paths.events_jsonl,
    .artifact_paths.commands_txt,
    .artifact_paths.report_md
  ' "$plan_normalized"
)

while IFS= read -r input_path; do
  [[ -n "$input_path" ]] || continue
  if [[ ! -f "$input_path" ]]; then
    append_gate_failure "missing_resolved_input_path" "planner resolved input path is missing: ${input_path}"
  fi
done < <(jq -r '.resolved_inputs[]?.path // empty' "$plan_normalized")

matched_case_count="$(jq -r '.policy_basis.matched_case_count // 0' "$plan_normalized")"
matched_case_ids_count="$(jq -r '(.policy_basis.matched_case_ids // []) | length' "$plan_normalized")"
if [[ "$matched_case_count" != "$matched_case_ids_count" ]]; then
  append_gate_failure "matched_case_count_mismatch" "matched_case_count does not equal number of matched_case_ids"
fi
if [[ "$matched_case_ids_count" == "0" ]]; then
  append_gate_failure "missing_matched_case_ids" "planner did not cite any matched scenario matrix cases"
fi
while IFS= read -r case_id; do
  [[ -n "$case_id" ]] || continue
  if ! jq -e --arg case_id "$case_id" '
    any((.cases // [])[]?; .case_id == $case_id and (.matched_expected // false) == true)
  ' "$matrix_normalized" >/dev/null 2>&1; then
    append_gate_failure "missing_matrix_case_receipt" "planner cites missing or failing scenario matrix case ${case_id}"
  fi
done < <(jq -r '.policy_basis.matched_case_ids[]? // empty' "$plan_normalized")

input_generated_epoch_seconds="$(jq -r '.generated_epoch_seconds // 0' "$input_normalized")"
if is_int "$input_generated_epoch_seconds"; then
  input_age_seconds=$((now_epoch_seconds - input_generated_epoch_seconds))
else
  input_age_seconds=-1
fi
if (( input_age_seconds > stale_after_seconds )); then
  append_gate_failure "stale_rescue_input_evidence" "normalized rescue input age ${input_age_seconds}s exceeds ${stale_after_seconds}s"
  record_invariant "fresh_rescue_input_evidence" "fail" "normalized rescue input is stale"
else
  record_invariant "fresh_rescue_input_evidence" "pass" "normalized rescue input age is within the allowed threshold"
fi

plan_decision="$(jq -r '.decision' "$plan_normalized")"
scenario_class="$(jq -r '.scenario_class' "$plan_normalized")"
contradictory_ownership_detected="$(jq -r '.derived_truth.contradictory_ownership_detected // false' "$input_normalized")"
local_rch_fallback_detected="$(jq -r '.derived_truth.local_rch_fallback_detected // false' "$input_normalized")"
contact_first_count="$(jq -r '.summary.contact_first_count // 0' "$input_normalized")"
manual_review_count="$(jq -r '.summary.manual_review_count // 0' "$input_normalized")"
lease_decision="$(jq -r '.derived_truth.lease_decision // "unknown"' "$input_normalized")"

if [[ "$contradictory_ownership_detected" == "true" ]]; then
  if [[ "$plan_decision" != "fail_closed" ]]; then
    append_gate_failure "contradictory_ownership_not_blocked" "planner remained ${plan_decision} despite contradictory ownership truth"
    record_invariant "contradictory_ownership_blocks_rescue" "fail" "planner did not fail closed under contradictory ownership"
  elif ! json_has_fail_reason "$plan_normalized" "contradictory_ownership"; then
    append_gate_failure "contradictory_ownership_not_cited" "planner failed closed without citing contradictory ownership"
    record_invariant "contradictory_ownership_blocks_rescue" "fail" "planner decision blocked rescue but omitted contradictory ownership reason"
  else
    record_invariant "contradictory_ownership_blocks_rescue" "pass" "planner failed closed and cited contradictory ownership"
  fi
else
  record_invariant "contradictory_ownership_blocks_rescue" "pass" "contradictory ownership truth was not active"
fi

if [[ "$local_rch_fallback_detected" == "true" ]]; then
  if [[ "$plan_decision" != "fail_closed" ]]; then
    append_gate_failure "local_fallback_not_blocked" "planner remained ${plan_decision} despite degraded-rch local fallback truth"
    record_invariant "local_fallback_forces_fail_closed" "fail" "planner did not fail closed under local fallback transport drift"
  elif ! json_has_fail_reason "$plan_normalized" "local_rch_fallback_admitted"; then
    append_gate_failure "local_fallback_not_cited" "planner failed closed without citing local fallback admission"
    record_invariant "local_fallback_forces_fail_closed" "fail" "planner omitted the local fallback fail-closed reason"
  elif [[ "$scenario_class" != "local_fallback" ]]; then
    append_gate_failure "local_fallback_scenario_drift" "planner scenario class ${scenario_class} did not preserve local_fallback truth"
    record_invariant "local_fallback_forces_fail_closed" "fail" "planner scenario class drifted away from local_fallback"
  else
    record_invariant "local_fallback_forces_fail_closed" "pass" "planner failed closed and preserved local_fallback scenario truth"
  fi
else
  record_invariant "local_fallback_forces_fail_closed" "pass" "local fallback transport truth was not active"
fi

if (( contact_first_count > 0 )); then
  if [[ "$plan_decision" == "advisory" ]]; then
    append_gate_failure "contact_first_uncertainty_ignored" "planner remained advisory despite stale-lock contact-first uncertainty"
    record_invariant "contact_first_blocks_advisory" "fail" "planner stayed advisory while contact-first uncertainty was active"
  elif ! json_has_recommendation "$plan_normalized" "contact_owner_before_exchange"; then
    append_gate_failure "contact_first_missing_action" "planner did not emit contact_owner_before_exchange under stale-lock uncertainty"
    record_invariant "contact_first_blocks_advisory" "fail" "planner omitted the contact-first recommendation"
  else
    record_invariant "contact_first_blocks_advisory" "pass" "planner preserved contact-first uncertainty"
  fi
else
  record_invariant "contact_first_blocks_advisory" "pass" "stale-lock contact-first uncertainty was not active"
fi

if (( manual_review_count > 0 )) || [[ "$lease_decision" == "manual_review_required" ]]; then
  if [[ "$plan_decision" == "advisory" ]]; then
    append_gate_failure "salvage_manual_review_ignored" "planner remained advisory despite salvage/manual-review truth"
    record_invariant "salvage_pinned_blocks_advisory" "fail" "planner stayed advisory while salvage/manual-review pressure was active"
  elif ! json_has_recommendation "$plan_normalized" "preserve_pinned_evidence"; then
    append_gate_failure "salvage_preservation_missing" "planner did not emit preserve_pinned_evidence under salvage/manual-review truth"
    record_invariant "salvage_pinned_blocks_advisory" "fail" "planner omitted the evidence-preservation recommendation"
  elif [[ "$scenario_class" == "healthy" ]]; then
    append_gate_failure "salvage_scenario_drift" "planner kept healthy scenario class despite salvage/manual-review pressure"
    record_invariant "salvage_pinned_blocks_advisory" "fail" "planner scenario class drifted away from salvage/manual-review truth"
  else
    record_invariant "salvage_pinned_blocks_advisory" "pass" "planner preserved salvage/manual-review pressure"
  fi
else
  record_invariant "salvage_pinned_blocks_advisory" "pass" "salvage/manual-review pressure was not active"
fi

plan_commands_txt="$(jq -r '.artifact_paths.commands_txt' "$plan_normalized")"
command_file_count=0
if [[ -f "$plan_commands_txt" ]]; then
  jq -nc --arg path "$plan_commands_txt" '{path:$path}' >>"$checked_commands_jsonl"
  command_file_count=$((command_file_count + 1))
  if grep -nE '(^|[[:space:]])cargo([[:space:]]|$)' "$plan_commands_txt" | grep -vq 'rch exec --'; then
    append_gate_failure "bare_cargo_command_detected" "bare cargo command found in planner commands transcript ${plan_commands_txt}"
  fi
else
  append_gate_failure "missing_planner_commands_txt" "planner commands transcript is missing: ${plan_commands_txt}"
fi

matrix_root="$(cd "$(dirname "$resolved_matrix_path")" && pwd)"
drill_command_files_found=0
while IFS= read -r command_path; do
  [[ -n "$command_path" ]] || continue
  drill_command_files_found=1
  command_file_count=$((command_file_count + 1))
  jq -nc --arg path "$command_path" '{path:$path}' >>"$checked_commands_jsonl"
  if grep -nE '(^|[[:space:]])cargo([[:space:]]|$)' "$command_path" | grep -vq 'rch exec --'; then
    append_gate_failure "bare_cargo_command_detected" "bare cargo command found in scenario drill transcript ${command_path}"
    break
  fi
done < <(find "${matrix_root}/cases" -type f -name 'commands.txt' | sort 2>/dev/null || true)
if [[ "$drill_command_files_found" -eq 0 ]]; then
  append_gate_failure "missing_drill_command_transcripts" "scenario matrix report did not resolve to any case commands.txt drill transcripts"
fi
if grep -nE '(^|[[:space:]])cargo([[:space:]]|$)' "$commands_path" | grep -vq 'rch exec --'; then
  append_gate_failure "bare_cargo_command_detected" "bare cargo command found in conformance gate commands transcript ${commands_path}"
fi
if grep -nE '(^|[[:space:]])cargo([[:space:]]|$)' "$report_md_path" 2>/dev/null | grep -vq 'rch exec --'; then
  append_gate_failure "bare_cargo_command_detected" "bare cargo command found in conformance gate markdown report ${report_md_path}"
fi

if [[ ! -s "$gate_failures_jsonl" ]]; then
  record_invariant "artifact_lineage_is_real" "pass" "planner artifact paths and resolved inputs all exist"
else
  if jq -e 'any(.code == "missing_artifact_path" or .code == "missing_resolved_input_path" or .code == "missing_matrix_case_receipt" or .code == "matched_case_count_mismatch" or .code == "missing_matched_case_ids" or .code == "plan_artifact_path_mismatch"; .)' "$gate_failures_jsonl" >/dev/null 2>&1; then
    record_invariant "artifact_lineage_is_real" "fail" "planner claim-to-artifact lineage drifted"
  else
    record_invariant "artifact_lineage_is_real" "pass" "planner claim-to-artifact lineage resolved cleanly"
  fi
fi

report_decision="pass"
exit_code=0
if [[ -s "$gate_failures_jsonl" ]]; then
  report_decision="fail_closed"
  exit_code=42
fi

plan_hash="$(jq -cS . "$plan_normalized" | sha256sum | awk '{print $1}')"
input_hash="$(jq -cS . "$input_normalized" | sha256sum | awk '{print $1}')"
matrix_hash="$(jq -cS . "$matrix_normalized" | sha256sum | awk '{print $1}')"

jq -n \
  --slurpfile plan "$plan_normalized" \
  --slurpfile input "$input_normalized" \
  --slurpfile matrix "$matrix_normalized" \
  --slurpfile gate_failures "$gate_failures_jsonl" \
  --slurpfile invariants "$invariants_jsonl" \
  --slurpfile checked_commands "$checked_commands_jsonl" \
  --arg schema_version "franken-engine.swarm-starvation-rescue-conformance-report.v1" \
  --arg source_revision "$source_revision" \
  --arg decision "$report_decision" \
  --argjson exit_code "$exit_code" \
  --arg plan_path "$starvation_rescue_plan_json" \
  --arg plan_hash "$plan_hash" \
  --arg input_path "$resolved_input_path" \
  --arg input_hash "$input_hash" \
  --arg matrix_path "$resolved_matrix_path" \
  --arg matrix_hash "$matrix_hash" \
  --arg report_path "$report_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md_path "$report_md_path" \
  --arg contract_json "docs/swarm_starvation_rescue_conformance_gate_contract_v1.json" \
  --argjson now_epoch_seconds "$now_epoch_seconds" \
  --argjson stale_after_seconds "$stale_after_seconds" \
  --argjson input_age_seconds "$input_age_seconds" \
  --argjson checked_command_file_count "$command_file_count" \
  '($plan[0]) as $plan_doc |
   ($input[0]) as $input_doc |
   ($matrix[0]) as $matrix_doc |
   {
     schema_version: $schema_version,
     source_revision: $source_revision,
     decision: $decision,
     exit_code: $exit_code,
     summary: {
       plan_decision: ($plan_doc.decision // "unknown"),
       scenario_class: ($plan_doc.scenario_class // "unknown"),
       gate_failure_count: ($gate_failures | length),
       invariant_count: ($invariants | length),
       checked_command_file_count: $checked_command_file_count,
       matched_case_count: ($plan_doc.policy_basis.matched_case_count // 0),
       input_age_seconds: $input_age_seconds,
       stale_after_seconds: $stale_after_seconds,
       readiness: ($input_doc.summary.readiness // "unknown")
     },
     assumptions: [
       "This conformance gate validates planner honesty only; it never executes rescue actions.",
       "Ownership safety and artifact-grounded truth outrank throughput whenever rescue evidence conflicts.",
       "Bare cargo in drill transcripts is treated as evidence drift, not as an allowed optimization."
     ],
     verified_invariants: $invariants,
     gate_failures: $gate_failures,
     resolved_sources: {
       starvation_rescue_plan_json: {
         path: $plan_path,
         hash: $plan_hash,
         schema_version: ($plan_doc.schema_version // null)
       },
       starvation_rescue_input_json: {
         path: $input_path,
         hash: $input_hash,
         schema_version: ($input_doc.schema_version // null)
       },
       scenario_matrix_report_json: {
         path: $matrix_path,
         hash: $matrix_hash,
         schema_version: ($matrix_doc.schema_version // null)
       }
     },
     checked_commands: $checked_commands,
     artifact_paths: {
       swarm_starvation_rescue_conformance_report_json: $report_path,
       events_jsonl: $events_path,
       commands_txt: $commands_path,
       report_md: $report_md_path
     },
     contract_paths: {
       conformance_gate_contract_json: $contract_json
     }
   }' >"$core_path"

report_hash="$(jq -cS . "$core_path" | sha256sum | awk '{print $1}')"
report_id="swarm-starvation-rescue-conformance-${report_hash:0:16}"

jq \
  --arg report_id "$report_id" \
  --arg report_hash "$report_hash" \
  '
  . + {
    report_id: $report_id,
    hash_basis: {
      report_hash: $report_hash
    }
  }' "$core_path" >"$report_tmp"
mv "$report_tmp" "$report_path"

write_event "swarm_starvation_rescue_conformance_gate.completed" \
  "$(jq -r '.decision + " / plan_decision=" + .summary.plan_decision' "$report_path")"

{
  printf '# Swarm Starvation Rescue Conformance Report\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$report_path")"
  printf -- "- Planner decision: \`%s\`\n" "$(jq -r '.summary.plan_decision' "$report_path")"
  printf -- "- Scenario class: \`%s\`\n" "$(jq -r '.summary.scenario_class' "$report_path")"
  printf -- "- Checked command files: \`%s\`\n" "$(jq -r '.summary.checked_command_file_count' "$report_path")"
  printf -- "- Gate failures: \`%s\`\n" "$(jq -r '.summary.gate_failure_count' "$report_path")"
  if [[ "$(jq '.gate_failures | length' "$report_path")" -ne 0 ]]; then
    printf '\n## Gate failures\n'
    jq -r '.gate_failures[] | "- [" + .code + "] " + .detail' "$report_path"
  fi
} >"$report_md_path"

printf 'swarm_starvation_rescue_conformance_report=%s\n' "$report_path"
if [[ "$report_decision" == "pass" ]]; then
  exit 0
fi
exit 42
