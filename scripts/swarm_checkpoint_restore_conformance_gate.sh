#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_CHECKPOINT_RESTORE_CONFORMANCE_GATE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-checkpoint-restore-conformance-gate}"
run_id="${SWARM_CHECKPOINT_RESTORE_CONFORMANCE_GATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_CHECKPOINT_RESTORE_CONFORMANCE_GATE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

checkpoint_bundle_json=""
checkpoint_restore_plan_json=""
source_revision=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_checkpoint_restore_conformance_gate.sh --checkpoint-bundle-json FILE --checkpoint-restore-plan-json FILE [OPTIONS]

Checks that a checkpoint bundle and restore plan stay truthful when composed.
The gate is report-only: it validates restore truth without mutating beads,
reservations, or worker state.

Required:
  --checkpoint-bundle-json FILE
  --checkpoint-restore-plan-json FILE

Optional:
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_checkpoint_restore_conformance_report.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  conformance report emitted without gate failures
  42 fail-closed due to stale/incomplete checkpoint promotion, local-fallback
     promotion, contradictory ownership downgrade, salvage manual-review
     suppression, dirty resume promotion, or missing artifact lineage
  64 invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --checkpoint-bundle-json)
      checkpoint_bundle_json="${2:-}"
      shift 2
      ;;
    --checkpoint-restore-plan-json)
      checkpoint_restore_plan_json="${2:-}"
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
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$checkpoint_bundle_json" || -z "$checkpoint_restore_plan_json" ]]; then
  printf 'swarm checkpoint restore conformance gate requires both bundle and restore plan JSON\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for checkpoint restore conformance gating\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for checkpoint restore conformance gating\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
report_path="${run_dir}/swarm_checkpoint_restore_conformance_report.json"
report_tmp="${report_path}.tmp"
core_path="${run_dir}/swarm_checkpoint_restore_conformance_report.core.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md_path="${run_dir}/report.md"
gate_failures_jsonl="${run_dir}/gate_failures.jsonl"
invariants_jsonl="${run_dir}/verified_invariants.jsonl"
bundle_normalized="${run_dir}/checkpoint_bundle.normalized.json"
plan_normalized="${run_dir}/checkpoint_restore_plan.normalized.json"

: >"$events_path"
: >"$gate_failures_jsonl"
: >"$invariants_jsonl"

printf './scripts/swarm_checkpoint_restore_conformance_gate.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-checkpoint-restore-conformance-gate.event.v1" \
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
    '{code: $code, detail: $detail}' >>"$gate_failures_jsonl"
}

record_invariant() {
  jq -nc \
    --arg name "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    '{name: $name, outcome: $outcome, detail: $detail}' >>"$invariants_jsonl"
}

normalize_json_copy() {
  local input_path="$1"
  local output_path="$2"
  local label="$3"

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
    'any((.drift_receipt.fail_closed_reasons // [])[]?; (.kind // "") == $reason_kind)' \
    "$json_path" >/dev/null 2>&1
}

json_has_drift_finding() {
  local json_path="$1"
  local finding_kind="$2"
  jq -e \
    --arg finding_kind "$finding_kind" \
    'any((.drift_receipt.findings // [])[]?; (.kind // "") == $finding_kind)' \
    "$json_path" >/dev/null 2>&1
}

json_contains_local_fallback() {
  local json_path="$1"
  jq -e '
    [.. | scalars | tostring | ascii_downcase | select(test("local_fallback|fallback_to_local|running locally|rch-e326"))]
    | length > 0
  ' "$json_path" >/dev/null 2>&1
}

ensure_path_exists() {
  local path="$1"
  local label="$2"
  if [[ -z "$path" || ! -f "$path" ]]; then
    append_gate_failure "missing_artifact_lineage" "${label} does not resolve to a real file"
    return 1
  fi
  return 0
}

normalize_json_copy "$checkpoint_bundle_json" "$bundle_normalized" "checkpoint bundle"
normalize_json_copy "$checkpoint_restore_plan_json" "$plan_normalized" "checkpoint restore plan"

if ! jq -e '
  .schema_version == "franken-engine.swarm-checkpoint-bundle.v1"
  and (.checkpoint_id | type == "string")
  and (.capture_decision | type == "string")
  and (.restore_readiness_hint | type == "string")
  and (.upstream_evidence | type == "object")
  and (.artifact_paths.checkpoint_bundle_json | type == "string")
  and (.artifact_paths.events_jsonl | type == "string")
  and (.artifact_paths.commands_txt | type == "string")
  and (.artifact_paths.summary_md | type == "string")
' "$bundle_normalized" >/dev/null 2>&1; then
  printf 'checkpoint bundle shape mismatch for conformance gate\n' >&2
  exit 64
fi

if ! jq -e '
  .schema_version == "franken-engine.swarm-checkpoint-restore-plan.v1"
  and (.checkpoint_id | type == "string")
  and (.decision | type == "string")
  and (.summary | type == "object")
  and (.drift_receipt | type == "object")
  and (.artifact_paths.swarm_checkpoint_restore_plan_json | type == "string")
  and (.artifact_paths.events_jsonl | type == "string")
  and (.artifact_paths.commands_txt | type == "string")
  and (.artifact_paths.report_md | type == "string")
' "$plan_normalized" >/dev/null 2>&1; then
  printf 'checkpoint restore plan shape mismatch for conformance gate\n' >&2
  exit 64
fi

write_event "checkpoint_restore_conformance_gate.inputs_loaded" "loaded checkpoint bundle and restore plan"

bundle_checkpoint_id="$(jq -r '.checkpoint_id' "$bundle_normalized")"
plan_checkpoint_id="$(jq -r '.checkpoint_id' "$plan_normalized")"
plan_decision="$(jq -r '.decision' "$plan_normalized")"
bundle_capture_decision="$(jq -r '.capture_decision' "$bundle_normalized")"
bundle_restore_hint="$(jq -r '.restore_readiness_hint' "$bundle_normalized")"
bundle_blocker_count="$(jq -r '.upstream_evidence.blocker_count // 0' "$bundle_normalized")"
checkpoint_age_seconds="$(jq -r '.drift_receipt.checkpoint_age_seconds // 0' "$plan_normalized")"
allowed_restore_age_seconds="$(jq -r '.checkpoint_snapshot.allowed_restore_age_seconds // 0' "$plan_normalized")"
plan_freshness_state="$(jq -r '.checkpoint_snapshot.checkpoint_freshness_state // "unknown"' "$plan_normalized")"
missing_current_comparisons="$(jq -r '.summary.missing_current_comparison_count // 0' "$plan_normalized")"
plan_top_restore_action="$(jq -r '.summary.top_restore_action // "unknown"' "$plan_normalized")"

if [[ "$bundle_checkpoint_id" == "$plan_checkpoint_id" ]]; then
  record_invariant "checkpoint_id_alignment" "pass" "bundle and restore plan refer to the same checkpoint id"
else
  append_gate_failure "checkpoint_id_mismatch" "restore plan checkpoint id does not match the source checkpoint bundle"
  record_invariant "checkpoint_id_alignment" "fail" "bundle and restore plan disagree on checkpoint id"
fi

needs_fail_closed=false
if [[ "$bundle_capture_decision" == "fail_closed" || "$bundle_restore_hint" == "blocked" || "$bundle_blocker_count" != "0" || "$plan_freshness_state" != "fresh" ]]; then
  needs_fail_closed=true
fi
if [[ "$allowed_restore_age_seconds" =~ ^[0-9]+$ ]] && [[ "$checkpoint_age_seconds" =~ ^[0-9]+$ ]] && (( checkpoint_age_seconds > allowed_restore_age_seconds )); then
  needs_fail_closed=true
fi

if [[ "$needs_fail_closed" == "true" && "$plan_decision" != "fail_closed" ]]; then
  append_gate_failure "stale_or_incomplete_checkpoint_promoted" "restore plan did not fail closed despite stale or incomplete checkpoint truth"
  record_invariant "stale_or_incomplete_checkpoint_blocks_restore" "fail" "checkpoint required fail_closed but plan decision was ${plan_decision}"
else
  record_invariant "stale_or_incomplete_checkpoint_blocks_restore" "pass" "checkpoint freshness and blocking truth stayed consistent with the restore decision"
fi

if json_contains_local_fallback "$bundle_normalized"; then
  if [[ "$plan_decision" != "fail_closed" ]] || ! json_has_fail_reason "$plan_normalized" "checkpoint_local_fallback_truth"; then
    append_gate_failure "local_fallback_promoted" "local-fallback checkpoint evidence was not preserved as fail_closed restore truth"
    record_invariant "local_fallback_checkpoint_blocks_restore" "fail" "local-fallback truth was not explicitly fail_closed in the restore plan"
  else
    record_invariant "local_fallback_checkpoint_blocks_restore" "pass" "local-fallback checkpoint truth stayed fail_closed"
  fi
else
  record_invariant "local_fallback_checkpoint_blocks_restore" "pass" "checkpoint bundle does not contain local-fallback truth"
fi

if json_has_fail_reason "$plan_normalized" "ownership_drift" || json_has_fail_reason "$plan_normalized" "ownership_contact_first" || json_has_fail_reason "$plan_normalized" "salvage_contradiction"; then
  if [[ "$plan_decision" != "fail_closed" ]]; then
    append_gate_failure "contradictory_ownership_downgraded" "ownership or contradictory salvage fail-closed reasons were downgraded below fail_closed"
    record_invariant "contradictory_ownership_blocks_restore" "fail" "ownership contradiction drift did not stay fail_closed"
  else
    record_invariant "contradictory_ownership_blocks_restore" "pass" "ownership contradiction drift stayed fail_closed"
  fi
else
  record_invariant "contradictory_ownership_blocks_restore" "pass" "no contradictory ownership fail-closed reasons were present"
fi

if json_has_drift_finding "$plan_normalized" "salvage_manual_review"; then
  if [[ "$plan_decision" == "resume" || "$plan_top_restore_action" != "review_salvage_pressure_before_resume" ]]; then
    append_gate_failure "salvage_manual_review_ignored" "salvage manual-review drift was not preserved as review-before-resume truth"
    record_invariant "salvage_manual_review_blocks_resume" "fail" "salvage manual-review drift was ignored"
  else
    record_invariant "salvage_manual_review_blocks_resume" "pass" "salvage manual-review drift stayed advisory or fail_closed"
  fi
else
  record_invariant "salvage_manual_review_blocks_resume" "pass" "no salvage manual-review drift was present"
fi

if [[ "$plan_decision" == "resume" ]]; then
  if [[ "$bundle_capture_decision" != "captured" || "$bundle_restore_hint" != "candidate" || "$missing_current_comparisons" != "0" ]] || jq -e '(.drift_receipt.fail_closed_reasons | length) != 0 or (.drift_receipt.findings | length) != 0' "$plan_normalized" >/dev/null 2>&1; then
    append_gate_failure "resume_without_clean_comparison_set" "resume plan still had degraded bundle state, missing comparisons, or unresolved drift"
    record_invariant "resume_requires_clean_comparison_set" "fail" "resume plan was emitted without a clean comparison set"
  else
    record_invariant "resume_requires_clean_comparison_set" "pass" "resume plan only emitted from a clean comparison set"
  fi
else
  record_invariant "resume_requires_clean_comparison_set" "pass" "restore plan is not attempting a resume path"
fi

checked_artifact_path_count=0
for path_value in \
  "$(jq -r '.artifact_paths.checkpoint_bundle_json' "$bundle_normalized")" \
  "$(jq -r '.artifact_paths.events_jsonl' "$bundle_normalized")" \
  "$(jq -r '.artifact_paths.commands_txt' "$bundle_normalized")" \
  "$(jq -r '.artifact_paths.summary_md' "$bundle_normalized")" \
  "$(jq -r '.artifact_paths.swarm_checkpoint_restore_plan_json' "$plan_normalized")" \
  "$(jq -r '.artifact_paths.events_jsonl' "$plan_normalized")" \
  "$(jq -r '.artifact_paths.commands_txt' "$plan_normalized")" \
  "$(jq -r '.artifact_paths.report_md' "$plan_normalized")"; do
  if ensure_path_exists "$path_value" "$path_value"; then
    checked_artifact_path_count=$((checked_artifact_path_count + 1))
  fi
done

if jq -s -e 'length == 0' "$gate_failures_jsonl" >/dev/null 2>&1; then
  record_invariant "artifact_lineage_is_real" "pass" "bundle and plan artifact paths resolved to real evidence"
else
  record_invariant "artifact_lineage_is_real" "fail" "one or more bundle or plan artifact paths did not resolve"
fi

gate_failures_json="$(jq -s '.' "$gate_failures_jsonl")"
verified_invariants_json="$(jq -s '.' "$invariants_jsonl")"
gate_failure_count="$(jq -s 'length' "$gate_failures_jsonl")"
decision="pass"
exit_code=0
if [[ "$gate_failure_count" != "0" ]]; then
  decision="fail_closed"
  exit_code=42
fi

jq -n \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg restore_decision "$plan_decision" \
  --arg checkpoint_capture_decision "$bundle_capture_decision" \
  --arg checkpoint_id "$bundle_checkpoint_id" \
  --arg top_restore_action "$plan_top_restore_action" \
  --arg bundle_path "$checkpoint_bundle_json" \
  --arg plan_path "$checkpoint_restore_plan_json" \
  --arg bundle_schema_version "$(jq -r '.schema_version' "$bundle_normalized")" \
  --arg plan_schema_version "$(jq -r '.schema_version' "$plan_normalized")" \
  --argjson exit_code "$exit_code" \
  --argjson gate_failure_count "$gate_failure_count" \
  --argjson checked_artifact_path_count "$checked_artifact_path_count" \
  --argjson verified_invariants "$verified_invariants_json" \
  --argjson gate_failures "$gate_failures_json" \
  '{
    source_revision: $source_revision,
    checkpoint_id: $checkpoint_id,
    decision: $decision,
    exit_code: $exit_code,
    summary: {
      restore_decision: $restore_decision,
      checkpoint_capture_decision: $checkpoint_capture_decision,
      top_restore_action: $top_restore_action,
      gate_failure_count: $gate_failure_count,
      checked_artifact_path_count: $checked_artifact_path_count
    },
    verified_invariants: $verified_invariants,
    gate_failures: $gate_failures,
    resolved_sources: {
      checkpoint_bundle_json: {
        path: $bundle_path,
        schema_version: $bundle_schema_version
      },
      checkpoint_restore_plan_json: {
        path: $plan_path,
        schema_version: $plan_schema_version
      }
    }
  }' >"$core_path"

report_hash="$(jq -cS . "$core_path" | sha256sum | awk '{print $1}')"
report_id="swarm-checkpoint-restore-conformance-${report_hash:0:16}"

jq \
  --arg schema_version "franken-engine.swarm-checkpoint-restore-conformance-report.v1" \
  --arg report_id "$report_id" \
  --arg report_hash "$report_hash" \
  --arg report_path "$report_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md_path "$report_md_path" \
  --arg contract_json "docs/swarm_checkpoint_restore_conformance_gate_contract_v1.json" \
  '
  . + {
    schema_version: $schema_version,
    report_id: $report_id,
    hash_basis: {
      report_hash: $report_hash
    },
    artifact_paths: {
      swarm_checkpoint_restore_conformance_report_json: $report_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_md_path
    },
    contract_paths: {
      checkpoint_restore_conformance_gate_contract_json: $contract_json
    }
  }' "$core_path" >"$report_tmp"
mv "$report_tmp" "$report_path"

write_event "checkpoint_restore_conformance_gate.completed" "$(jq -r '.decision + " / restore_decision=" + .summary.restore_decision' "$report_path")"

{
  printf '# Swarm Checkpoint Restore Conformance Report\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$report_path")"
  printf -- "- Restore decision: \`%s\`\n" "$(jq -r '.summary.restore_decision' "$report_path")"
  printf -- "- Top restore action: \`%s\`\n" "$(jq -r '.summary.top_restore_action' "$report_path")"
  printf -- "- Gate failure count: \`%s\`\n" "$(jq -r '.summary.gate_failure_count' "$report_path")"
  if [[ "$(jq '.gate_failures | length' "$report_path")" -ne 0 ]]; then
    printf '\n## Gate failures\n'
    jq -r '.gate_failures[] | "- [" + .code + "] " + .detail' "$report_path"
  fi
} >"$report_md_path"

printf 'swarm_checkpoint_restore_conformance_report=%s\n' "$report_path"
exit "$exit_code"
