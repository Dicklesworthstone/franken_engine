#!/usr/bin/env bash
set -euo pipefail

artifact_root="${REMOTE_PROOF_SALVAGE_RECEIPT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-remote-proof-salvage-receipt}"
run_id="${REMOTE_PROOF_SALVAGE_RECEIPT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${REMOTE_PROOF_SALVAGE_RECEIPT_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

bundle_report_json=""
incident_packet_json=""
worker_truth_report_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/remote_proof_salvage_receipt.sh --bundle-report-json FILE --incident-packet-json FILE --worker-truth-report-json FILE [OPTIONS]

Compose resident remote proof bundle results, incident packets, and worker-truth
parity evidence into one compact salvage receipt and operator recommendation.

Required:
  --bundle-report-json FILE
  --incident-packet-json FILE
  --worker-truth-report-json FILE

Optional:
  --output-dir DIR

Artifacts:
  salvage_receipt.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   clean finished bundle; no salvage required
  42  salvage, orphan reconciliation, quarantine, or manual review required
  64  invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bundle-report-json)
      bundle_report_json="${2:-}"
      shift 2
      ;;
    --incident-packet-json)
      incident_packet_json="${2:-}"
      shift 2
      ;;
    --worker-truth-report-json)
      worker_truth_report_json="${2:-}"
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

if [[ -z "$bundle_report_json" || -z "$incident_packet_json" || -z "$worker_truth_report_json" ]]; then
  printf 'remote proof salvage receipt requires --bundle-report-json, --incident-packet-json, and --worker-truth-report-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for remote proof salvage receipts\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
receipt_path="${run_dir}/salvage_receipt.json"
receipt_tmp="${receipt_path}.tmp"
summary_path="${run_dir}/report.md"
summary_tmp="${summary_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
bundle_normalized="${run_dir}/bundle_report.normalized.json"
incident_normalized="${run_dir}/incident_packet.normalized.json"
worker_truth_normalized="${run_dir}/worker_truth_report.normalized.json"
: >"$events_path"

printf './scripts/remote_proof_salvage_receipt.sh' >"$commands_path"
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

sha256_text() {
  local text="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$text" | sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s' "$text" | shasum -a 256 | awk '{print $1}'
  else
    printf '%s' "$text" | openssl dgst -sha256 | awk '{print $NF}'
  fi
}

normalize_required_json() {
  local path="$1"
  local output_path="$2"
  local label="$3"

  if [[ ! -f "$path" ]]; then
    printf 'remote proof salvage receipt missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'remote proof salvage receipt invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
}

normalize_required_json "$bundle_report_json" "$bundle_normalized" "bundle report"
normalize_required_json "$incident_packet_json" "$incident_normalized" "incident packet"
normalize_required_json "$worker_truth_report_json" "$worker_truth_normalized" "worker truth report"

jq -cS '
  {
    schema_version: (.schema_version // "unknown"),
    bundle_id: (.bundle_id // "unknown"),
    bundle_decision: (.bundle_decision // "unknown"),
    expected_worker_id: (.expected_worker_id // ""),
    expected_target_dir: (.expected_target_dir // ""),
    source_revision: (.source_revision // "unknown"),
    phase_results: (
      (.phase_results // [])
      | if type == "array" then . else [] end
      | map({
          phase: (.phase // "unknown"),
          stdout_log: (.stdout_log // null),
          stderr_log: (.stderr_log // null)
        })
      | sort_by(.phase)
    ),
    artifact_paths: (.artifact_paths // {})
  }
' "$bundle_normalized" >"${bundle_normalized}.tmp"
mv "${bundle_normalized}.tmp" "$bundle_normalized"
write_event "bundle_report_loaded" "normalized resident bundle report"

jq -cS '
  {
    schema_version: (.schema_version // "unknown"),
    status: (.status // "unknown"),
    failure_kind: (.failure_kind // "unknown"),
    retry_safety: (.retry_safety // "unknown"),
    recommended_next_action: (.recommended_next_action // ""),
    worker_id: (.worker_id // ""),
    target_dir: (.target_dir // ""),
    exit_code: (.exit_code // null)
  }
' "$incident_normalized" >"${incident_normalized}.tmp"
mv "${incident_normalized}.tmp" "$incident_normalized"
write_event "incident_packet_loaded" "normalized incident packet"

jq -cS '
  {
    schema_version: (.schema_version // "unknown"),
    decision: (.decision // "unknown"),
    drift_count: (.drift_count // 0),
    ghost_job_detected: (.ghost_job_detected // false),
    findings: (
      (.findings // [])
      | if type == "array" then . else [] end
      | map({
          code: (.code // "unknown"),
          worker_id: (.worker_id // null)
        })
      | sort_by(.code, .worker_id)
    ),
    worker_rows: (
      (.worker_rows // [])
      | if type == "array" then . else [] end
      | map({
          worker_id: (.worker_id // ""),
          daemon_present: (.daemon_present // false),
          daemon_drained: (.daemon_drained // false),
          probe_present: (.probe_present // false),
          probe_schedulable: (.probe_schedulable // false),
          queue_present: (.queue_present // false),
          queue_schedulable: (.queue_schedulable // false)
        })
      | map(select(.worker_id != ""))
      | sort_by(.worker_id)
    ),
    incident_evidence: (.incident_evidence // {})
  }
' "$worker_truth_normalized" >"${worker_truth_normalized}.tmp"
mv "${worker_truth_normalized}.tmp" "$worker_truth_normalized"
write_event "worker_truth_loaded" "normalized worker truth report"

bundle_error="$(
  jq -r '
    if (.bundle_id | length) == 0 or .bundle_id == "unknown" then
      "bundle report must declare bundle_id"
    elif (.expected_worker_id | length) == 0 then
      "bundle report must declare expected_worker_id"
    elif (.expected_target_dir | length) == 0 then
      "bundle report must declare expected_target_dir"
    else
      ""
    end
  ' "$bundle_normalized"
)"
if [[ -n "$bundle_error" ]]; then
  printf 'remote proof salvage receipt invalid bundle report: %s\n' "$bundle_error" >&2
  exit 64
fi

jq -n \
  --arg bundle_report_path "$bundle_report_json" \
  --arg incident_packet_path "$incident_packet_json" \
  --arg worker_truth_report_path "$worker_truth_report_json" \
  --arg receipt_path "$receipt_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg summary_path "$summary_path" \
  --slurpfile bundle "$bundle_normalized" \
  --slurpfile incident "$incident_normalized" \
  --slurpfile worker "$worker_truth_normalized" '
  ($bundle[0]) as $bundle
  | ($incident[0]) as $incident
  | ($worker[0]) as $worker
  | (
      (
        (($bundle.artifact_paths.bundle_report_json // "") != "")
        and (($bundle.artifact_paths.run_manifest_json // "") != "")
        and (
          (($bundle.artifact_paths.phase_logs_dir // "") != "")
          or (
            (($bundle.phase_results // []) | length) > 0
            and all(($bundle.phase_results // [])[]; (.stdout_log != null and .stderr_log != null))
          )
        )
      )
    ) as $recoverable_artifact_set
  | (
      (($incident.failure_kind // "") == "timed_out_transport_live_remote_compile")
      or (($worker.ghost_job_detected // false) == true)
    ) as $live_remote_compile
  | (
      (($incident.failure_kind // "") == "canceled_build_live_orphaned_rustc")
      or (($worker.incident_evidence.failure_kind // "") == "canceled_build_live_orphaned_rustc")
    ) as $orphaned_process_detected
  | ((($incident.failure_kind // "") != "worker_unreachable_degraded")) as $worker_reachable
  | (
      if (($incident.failure_kind // "") == "clean_remote_success")
         and (($bundle.bundle_decision // "") == "pass")
         and ($live_remote_compile | not)
      then
        {
          workflow_state: "clean_finished",
          recovery_recommendation: "no_salvage_needed",
          reason: "bundle finished cleanly with no live remote compile or orphaned process evidence",
          operator_actions: [
            "Record the resident bundle as complete.",
            "Reuse the bundle artifacts normally."
          ],
          exit_code: 0
        }
      elif (($incident.failure_kind // "") == "timed_out_transport_live_remote_compile") then
        {
          workflow_state: "live_compile_salvageable",
          recovery_recommendation: "wait_then_salvage_artifacts",
          reason: "transport timed out while remote compile evidence stayed live; preserve the bundle and salvage artifacts after the worker settles",
          operator_actions: [
            "Wait for the live remote compile to finish or cool down.",
            "Salvage the existing artifact set before rerunning the bundle."
          ],
          exit_code: 42
        }
      elif (($incident.failure_kind // "") == "canceled_build_live_orphaned_rustc") then
        {
          workflow_state: "orphan_reconciliation_required",
          recovery_recommendation: "clear_orphan_before_retry",
          reason: "the bundle was canceled while orphaned rustc evidence remained live on the worker",
          operator_actions: [
            "Capture the orphaned rustc evidence in the salvage receipt.",
            "Clear or isolate the worker before retrying the bundle."
          ],
          exit_code: 42
        }
      elif (($incident.failure_kind // "") == "worker_unreachable_degraded") then
        {
          workflow_state: "worker_unreachable_degraded",
          recovery_recommendation: "quarantine_worker_and_reroute",
          reason: "the worker is unreachable, so salvage must stop at preserved artifacts and the worker should be rerouted or quarantined",
          operator_actions: [
            "Quarantine or mark the worker degraded.",
            "Reroute the next bundle attempt to a healthy worker."
          ],
          exit_code: 42
        }
      else
        {
          workflow_state: "manual_review_required",
          recovery_recommendation: "manual_classification_required",
          reason: "the incident does not match a known automatic salvage workflow",
          operator_actions: [
            "Preserve the current bundle, incident, and worker-truth artifacts.",
            "Classify the failure manually before retrying."
          ],
          exit_code: 42
        }
      end
    ) as $decision
  | {
      schema_version: "franken-engine.remote-proof-salvage-receipt.v1",
      bundle_id: $bundle.bundle_id,
      source_revision: $bundle.source_revision,
      workflow_state: $decision.workflow_state,
      recovery_recommendation: $decision.recovery_recommendation,
      reason: $decision.reason,
      operator_actions: $decision.operator_actions,
      exit_code: $decision.exit_code,
      bundle_decision: $bundle.bundle_decision,
      incident_status: $incident.status,
      incident_failure_kind: $incident.failure_kind,
      worker_truth_decision: $worker.decision,
      expected_worker_id: $bundle.expected_worker_id,
      expected_target_dir: $bundle.expected_target_dir,
      observed_process_truth: {
        live_remote_compile: $live_remote_compile,
        orphaned_process_detected: $orphaned_process_detected,
        worker_reachable: $worker_reachable,
        recoverable_artifact_set: $recoverable_artifact_set
      },
      parity_findings: ($worker.findings // []),
      upstream_artifact_paths: {
        bundle_report_json: $bundle_report_path,
        incident_packet_json: $incident_packet_path,
        worker_truth_report_json: $worker_truth_report_path
      },
      bundle_artifact_paths: ($bundle.artifact_paths // {}),
      artifact_paths: {
        salvage_receipt_json: $receipt_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $summary_path
      }
    }
' >"$receipt_tmp"

salvage_id="$(sha256_text "$(jq -r '.bundle_id + "|" + .incident_failure_kind + "|" + .expected_worker_id + "|" + .expected_target_dir' "$receipt_tmp")" | cut -c1-16)"
jq \
  --arg salvage_id "salvage-${salvage_id}" \
  '. + {salvage_id: $salvage_id}' \
  "$receipt_tmp" >"${receipt_tmp}.id"
mv "${receipt_tmp}.id" "$receipt_path"
rm -f "$receipt_tmp"

write_event "salvage_receipt_written" "$(jq -r '.workflow_state + " / " + .recovery_recommendation' "$receipt_path")"

{
  printf '# Remote Proof Salvage Receipt\n\n'
  printf '%s\n' "- Bundle ID: \`$(jq -r '.bundle_id' "$receipt_path")\`"
  printf '%s\n' "- Salvage ID: \`$(jq -r '.salvage_id' "$receipt_path")\`"
  printf '%s\n' "- Workflow state: \`$(jq -r '.workflow_state' "$receipt_path")\`"
  printf '%s\n' "- Recommendation: \`$(jq -r '.recovery_recommendation' "$receipt_path")\`"
  printf '%s\n' "- Reason: $(jq -r '.reason' "$receipt_path")"
  printf '%s\n' "- Live remote compile: \`$(jq -r '.observed_process_truth.live_remote_compile' "$receipt_path")\`"
  printf '%s\n' "- Orphaned process: \`$(jq -r '.observed_process_truth.orphaned_process_detected' "$receipt_path")\`"
  printf '%s\n' "- Recoverable artifact set: \`$(jq -r '.observed_process_truth.recoverable_artifact_set' "$receipt_path")\`"
  printf '\n## Operator Actions\n\n'
  jq -r '.operator_actions[] | "- " + .' "$receipt_path"
} >"$summary_tmp"
mv "$summary_tmp" "$summary_path"

printf 'remote_proof_salvage_receipt=%s\n' "$receipt_path"
printf 'remote_proof_salvage_report=%s\n' "$summary_path"

exit "$(jq -r '.exit_code' "$receipt_path")"
