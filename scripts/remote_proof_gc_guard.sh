#!/usr/bin/env bash
set -euo pipefail

artifact_root="${REMOTE_PROOF_GC_GUARD_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-remote-proof-gc-guard}"
run_id="${REMOTE_PROOF_GC_GUARD_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${REMOTE_PROOF_GC_GUARD_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

retention_ledger_json=""
warm_target_roi_ledger_json=""
salvage_receipt_json=""
archive_pack_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/remote_proof_gc_guard.sh --retention-ledger-json FILE --warm-target-roi-ledger-json FILE --salvage-receipt-json FILE --archive-pack-json FILE [OPTIONS]

Classify a remote-proof artifact set for GC safety. The guard is fail-closed and
only allows deletion after archive verification succeeds and no warm-target or
salvage pin remains active.

Required:
  --retention-ledger-json FILE
  --warm-target-roi-ledger-json FILE
  --salvage-receipt-json FILE
  --archive-pack-json FILE

Optional:
  --output-dir DIR

Artifacts:
  remote_proof_gc_guard_report.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   GC is allowed for the archived cold bundle
  42  GC is denied or fail-closed
  75  bundle may be cooled but not deleted
  64  invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --retention-ledger-json)
      retention_ledger_json="${2:-}"
      shift 2
      ;;
    --warm-target-roi-ledger-json)
      warm_target_roi_ledger_json="${2:-}"
      shift 2
      ;;
    --salvage-receipt-json)
      salvage_receipt_json="${2:-}"
      shift 2
      ;;
    --archive-pack-json)
      archive_pack_json="${2:-}"
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

if [[ -z "$retention_ledger_json" || -z "$warm_target_roi_ledger_json" || -z "$salvage_receipt_json" || -z "$archive_pack_json" ]]; then
  printf 'remote proof GC guard requires all four input JSON files\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for remote proof GC guard\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for remote proof GC guard\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
report_path="${run_dir}/remote_proof_gc_guard_report.json"
report_tmp="${report_path}.tmp"
summary_path="${run_dir}/report.md"
summary_tmp="${summary_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
retention_normalized="${run_dir}/retention_ledger.normalized.json"
roi_normalized="${run_dir}/warm_target_roi_ledger.normalized.json"
salvage_normalized="${run_dir}/salvage_receipt.normalized.json"
archive_normalized="${run_dir}/archive_pack.normalized.json"
report_core="${run_dir}/gc_guard.core.json"
: >"$events_path"

printf './scripts/remote_proof_gc_guard.sh' >"$commands_path"
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

normalize_required_json() {
  local path="$1"
  local output_path="$2"
  local label="$3"

  if [[ ! -f "$path" ]]; then
    printf 'remote proof GC guard missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'remote proof GC guard invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
}

normalize_required_json "$retention_ledger_json" "$retention_normalized" "retention ledger"
normalize_required_json "$warm_target_roi_ledger_json" "$roi_normalized" "warm target ROI ledger"
normalize_required_json "$salvage_receipt_json" "$salvage_normalized" "salvage receipt"
normalize_required_json "$archive_pack_json" "$archive_normalized" "archive pack"

jq -cS '
  {
    bundle_id: (.bundle_id // "unknown"),
    retention_decision: (.retention_decision // "unknown"),
    class_counts: {
      hot_replay_critical: (.class_counts.hot_replay_critical // 0),
      warm_operator_inspectable: (.class_counts.warm_operator_inspectable // 0),
      salvage_pinned: (.class_counts.salvage_pinned // 0),
      cold_archival: (.class_counts.cold_archival // 0)
    },
    artifact_paths: (.artifact_paths // {})
  }
' "$retention_normalized" >"${retention_normalized}.tmp"
mv "${retention_normalized}.tmp" "$retention_normalized"
write_event "retention_ledger_loaded" "normalized remote proof retention ledger"

jq -cS '
  {
    bundle_id: (.bundle_id // "unknown"),
    decision: (.decision // "unknown"),
    recommended_action: (.recommended_action // "unknown"),
    reason: (.reason // ""),
    target_dir: (.target_dir // ""),
    worker_id: (.worker_id // null),
    policy_findings: (
      (.policy_findings // [])
      | if type == "array" then map(tostring) else [] end
      | unique
      | sort
    ),
    artifact_paths: (.artifact_paths // {})
  }
' "$roi_normalized" >"${roi_normalized}.tmp"
mv "${roi_normalized}.tmp" "$roi_normalized"
write_event "warm_target_roi_loaded" "normalized warm target ROI ledger"

jq -cS '
  {
    bundle_id: (.bundle_id // "unknown"),
    workflow_state: (.workflow_state // "unknown"),
    recovery_recommendation: (.recovery_recommendation // "unknown"),
    reason: (.reason // ""),
    observed_process_truth: {
      live_remote_compile: (.observed_process_truth.live_remote_compile // false),
      orphaned_process_detected: (.observed_process_truth.orphaned_process_detected // false),
      worker_reachable: (.observed_process_truth.worker_reachable // false),
      recoverable_artifact_set: (.observed_process_truth.recoverable_artifact_set // false)
    },
    artifact_paths: (.artifact_paths // {})
  }
' "$salvage_normalized" >"${salvage_normalized}.tmp"
mv "${salvage_normalized}.tmp" "$salvage_normalized"
write_event "salvage_receipt_loaded" "normalized remote proof salvage receipt"

jq -cS '
  {
    bundle_id: (.bundle_id // "unknown"),
    archive_state: (.archive_state // .archive_status // .state // "unknown"),
    restore_verdict: (.restore_verdict // .verification_decision // .restore_status // "unknown"),
    archive_artifact_count: (
      if (.archive_artifact_count | type) == "number" then .archive_artifact_count
      elif (.archived_artifacts | type) == "array" then (.archived_artifacts | length)
      elif (.artifacts | type) == "array" then (.artifacts | length)
      else 0
      end
    ),
    artifact_paths: (.artifact_paths // {})
  }
' "$archive_normalized" >"${archive_normalized}.tmp"
mv "${archive_normalized}.tmp" "$archive_normalized"
write_event "archive_pack_loaded" "normalized archive pack snapshot"

jq -n \
  --slurpfile retention "$retention_normalized" \
  --slurpfile roi "$roi_normalized" \
  --slurpfile salvage "$salvage_normalized" \
  --slurpfile archive "$archive_normalized" '
  ($retention[0]) as $retention
  | ($roi[0]) as $roi
  | ($salvage[0]) as $salvage
  | ($archive[0]) as $archive
  | ($retention.class_counts // {}) as $counts
  | (($roi.decision // "") == "retain" or ($roi.recommended_action // "") == "retain_warm_target") as $warm_target_active
  | (($salvage.workflow_state // "unknown") != "clean_finished") as $salvage_active
  | (($salvage.workflow_state // "") == "orphan_reconciliation_required") as $orphan_salvage
  | (($archive.archive_state // "") == "cold_archived") as $cold_archived
  | (($archive.restore_verdict // "") == "verified" or ($archive.restore_verdict // "") == "pass" or ($archive.restore_verdict // "") == "restorable") as $restore_verified
  | (($counts.hot_replay_critical // 0) == 0 and ($counts.warm_operator_inspectable // 0) == 0 and ($counts.salvage_pinned // 0) == 0 and ($counts.cold_archival // 0) > 0) as $cold_only
  | [
      (if (($retention.bundle_id // "unknown") == "unknown") then {code: "missing_retention_bundle_id", message: "retention ledger must declare bundle_id"} else empty end),
      (if (($roi.bundle_id // "unknown") != ($retention.bundle_id // "unknown")) then {code: "roi_bundle_mismatch", message: "ROI ledger bundle_id does not match retention ledger"} else empty end),
      (if (($salvage.bundle_id // "unknown") != ($retention.bundle_id // "unknown")) then {code: "salvage_bundle_mismatch", message: "salvage receipt bundle_id does not match retention ledger"} else empty end),
      (if (($archive.bundle_id // "unknown") != ($retention.bundle_id // "unknown")) then {code: "archive_bundle_mismatch", message: "archive pack bundle_id does not match retention ledger"} else empty end),
      (if (($archive.archive_artifact_count // 0) == 0) then {code: "archive_artifacts_missing", message: "archive pack does not contain archived artifact evidence"} else empty end)
    ] as $validation_errors
  | (
      if (($validation_errors | length) > 0) then
        {
          guard_decision: "fail_closed",
          recommended_action: "manual_review_required",
          reason: "upstream retention, ROI, salvage, or archive evidence is inconsistent",
          exit_code: 42,
          policy_findings: ["validation_failure"]
        }
      elif $warm_target_active then
        {
          guard_decision: "deny_gc",
          recommended_action: "keep_hot",
          reason: "warm-target ROI still requires active hot residency, so GC must stay blocked",
          exit_code: 42,
          policy_findings: ["active_warm_target_protected"]
        }
      elif $salvage_active then
        {
          guard_decision: "deny_gc",
          recommended_action: "pin_until_salvage_clears",
          reason: (if $orphan_salvage then
            "orphan-salvage reconciliation is still active, so the artifact set must remain pinned"
          else
            "salvage workflow is still active, so the artifact set must remain pinned"
          end),
          exit_code: 42,
          policy_findings: [if $orphan_salvage then "orphan_salvage_pinned" else "salvage_pinned" end]
        }
      elif $cold_only and $cold_archived and $restore_verified then
        {
          guard_decision: "allow_gc",
          recommended_action: "delete_cold_archived_bundle",
          reason: "the artifact set is cold-only, archived, and restore-verified, so GC is allowed",
          exit_code: 0,
          policy_findings: ["cold_archived_bundle_gc_allowed"]
        }
      else
        {
          guard_decision: "cool_only",
          recommended_action: "cool_without_gc",
          reason: "the artifact set is not actively pinned, but it is not yet cold-and-verified enough for deletion",
          exit_code: 75,
          policy_findings: ["cool_before_delete"]
        }
      end
    ) as $decision
  | {
      schema_version: "franken-engine.remote-proof-gc-guard.v1",
      bundle_id: $retention.bundle_id,
      guard_decision: $decision.guard_decision,
      recommended_action: $decision.recommended_action,
      reason: $decision.reason,
      policy_findings: $decision.policy_findings,
      gc_eligible: ($decision.guard_decision == "allow_gc"),
      retention_summary: {
        retention_decision: $retention.retention_decision,
        class_counts: $counts
      },
      warm_target_roi_summary: {
        decision: $roi.decision,
        recommended_action: $roi.recommended_action,
        target_dir: $roi.target_dir,
        worker_id: $roi.worker_id
      },
      salvage_summary: {
        workflow_state: $salvage.workflow_state,
        recovery_recommendation: $salvage.recovery_recommendation,
        observed_process_truth: $salvage.observed_process_truth
      },
      archive_summary: {
        archive_state: $archive.archive_state,
        restore_verdict: $archive.restore_verdict,
        archive_artifact_count: $archive.archive_artifact_count
      },
      validation_errors: $validation_errors,
      exit_code: $decision.exit_code
    }
' >"$report_core"

input_hash="$(
  jq -n \
    --slurpfile retention "$retention_normalized" \
    --slurpfile roi "$roi_normalized" \
    --slurpfile salvage "$salvage_normalized" \
    --slurpfile archive "$archive_normalized" \
    '{
      retention_ledger: ($retention[0]),
      warm_target_roi_ledger: ($roi[0]),
      salvage_receipt: ($salvage[0]),
      archive_pack: ($archive[0])
    }' | jq -cS . | sha256sum | awk '{print $1}'
)"
guard_hash="$(jq -cS . "$report_core" | sha256sum | awk '{print $1}')"

jq \
  --arg input_hash "$input_hash" \
  --arg guard_hash "$guard_hash" \
  --arg guard_id "gc-guard-${guard_hash:0:16}" \
  --arg report_path "$report_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg summary_path "$summary_path" \
  --arg retention_ledger_path "$retention_ledger_json" \
  --arg warm_target_roi_ledger_path "$warm_target_roi_ledger_json" \
  --arg salvage_receipt_path "$salvage_receipt_json" \
  --arg archive_pack_path "$archive_pack_json" '
  . + {
    gc_guard_id: $guard_id,
    hash_basis: {
      input_hash: $input_hash,
      guard_hash: $guard_hash
    },
    upstream_artifact_paths: {
      retention_ledger_json: $retention_ledger_path,
      warm_target_roi_ledger_json: $warm_target_roi_ledger_path,
      salvage_receipt_json: $salvage_receipt_path,
      archive_pack_json: $archive_pack_path
    },
    artifact_paths: {
      remote_proof_gc_guard_report_json: $report_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $summary_path
    }
  }
' "$report_core" >"$report_tmp"
mv "$report_tmp" "$report_path"

write_event "gc_guard_written" "$(jq -r '.guard_decision + \" / \" + .recommended_action' "$report_path")"

{
  printf '# Remote Proof GC Guard\n\n'
  printf '%s\n' "- Decision: \`$(jq -r '.guard_decision' "$report_path")\`"
  printf '%s\n' "- Recommended action: \`$(jq -r '.recommended_action' "$report_path")\`"
  printf '%s\n' "- Reason: $(jq -r '.reason' "$report_path")"
  printf '%s\n' "- GC eligible: \`$(jq -r '.gc_eligible' "$report_path")\`"
  printf '%s\n' "- Warm-target ROI: \`$(jq -r '.warm_target_roi_summary.decision' "$report_path")\`"
  printf '%s\n' "- Salvage workflow: \`$(jq -r '.salvage_summary.workflow_state' "$report_path")\`"
  printf '%s\n' "- Archive state: \`$(jq -r '.archive_summary.archive_state' "$report_path")\` / restore \`$(jq -r '.archive_summary.restore_verdict' "$report_path")\`"
  printf '\n## Policy Findings\n\n'
  jq -r '.policy_findings[] | "- " + .' "$report_path"
} >"$summary_tmp"
mv "$summary_tmp" "$summary_path"

printf 'remote_proof_gc_guard_report=%s\n' "$report_path"

exit "$(jq -r '.exit_code' "$report_path")"
