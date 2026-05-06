#!/usr/bin/env bash
set -euo pipefail

artifact_root="${REMOTE_PROOF_RETENTION_CLASS_LEDGER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-remote-proof-retention-class-ledger}"
run_id="${REMOTE_PROOF_RETENTION_CLASS_LEDGER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${REMOTE_PROOF_RETENTION_CLASS_LEDGER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

bundle_report_json=""
mirror_manifest_json=""
batch_manifest_json=""
salvage_receipt_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/remote_proof_retention_class_ledger.sh --bundle-report-json FILE --mirror-manifest-json FILE --batch-manifest-json FILE --salvage-receipt-json FILE [OPTIONS]

Classify remote-proof artifacts into deterministic retention classes and emit one
evidence residency manifest that downstream archive and GC layers can trust.

Required:
  --bundle-report-json FILE
  --mirror-manifest-json FILE
  --batch-manifest-json FILE
  --salvage-receipt-json FILE

Optional:
  --output-dir DIR

Artifacts:
  retention_class_ledger.json
  evidence_residency_manifest.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   retention ledger emitted successfully
  42  fail-closed due to inconsistent upstream evidence
  64  invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bundle-report-json)
      bundle_report_json="${2:-}"
      shift 2
      ;;
    --mirror-manifest-json)
      mirror_manifest_json="${2:-}"
      shift 2
      ;;
    --batch-manifest-json)
      batch_manifest_json="${2:-}"
      shift 2
      ;;
    --salvage-receipt-json)
      salvage_receipt_json="${2:-}"
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

if [[ -z "$bundle_report_json" || -z "$mirror_manifest_json" || -z "$batch_manifest_json" || -z "$salvage_receipt_json" ]]; then
  printf 'remote proof retention class ledger requires all four input JSON files\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for remote proof retention class ledger\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for remote proof retention class ledger\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
ledger_path="${run_dir}/retention_class_ledger.json"
ledger_tmp="${ledger_path}.tmp"
manifest_path="${run_dir}/evidence_residency_manifest.json"
manifest_tmp="${manifest_path}.tmp"
summary_path="${run_dir}/report.md"
summary_tmp="${summary_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
bundle_normalized="${run_dir}/bundle_report.normalized.json"
mirror_normalized="${run_dir}/mirror_manifest.normalized.json"
batch_normalized="${run_dir}/batch_manifest.normalized.json"
salvage_normalized="${run_dir}/salvage_receipt.normalized.json"
manifest_core="${run_dir}/residency_manifest.core.json"
ledger_core="${run_dir}/retention_ledger.core.json"
: >"$events_path"

printf './scripts/remote_proof_retention_class_ledger.sh' >"$commands_path"
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
    printf 'remote proof retention class ledger missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'remote proof retention class ledger invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
}

normalize_required_json "$bundle_report_json" "$bundle_normalized" "bundle report"
normalize_required_json "$mirror_manifest_json" "$mirror_normalized" "mirror manifest"
normalize_required_json "$batch_manifest_json" "$batch_normalized" "batch manifest"
normalize_required_json "$salvage_receipt_json" "$salvage_normalized" "salvage receipt"

jq -cS '
  {
    bundle_id: (.bundle_id // "unknown"),
    bundle_decision: (.bundle_decision // "unknown"),
    expected_worker_id: (.expected_worker_id // ""),
    expected_target_dir: (.expected_target_dir // ""),
    source_revision: (.source_revision // "unknown"),
    phase_log_paths: (
      [(.phase_results // [])[]? | .stdout_log? // empty, .stderr_log? // empty]
      | map(tostring)
      | map(select(length > 0))
      | unique
      | sort
    ),
    artifact_paths: (.artifact_paths // {})
  }
' "$bundle_normalized" >"${bundle_normalized}.tmp"
mv "${bundle_normalized}.tmp" "$bundle_normalized"
write_event "bundle_report_loaded" "normalized resident bundle report"

jq -cS '
  def role_list($artifact):
    (
      if (($artifact.roles? // null) | type) == "array" then
        $artifact.roles
      elif (($artifact.role? // null) | type) == "string" then
        [$artifact.role]
      else
        []
      end
    ) | map(tostring) | map(select(length > 0)) | unique | sort;
  def normalized_artifact($artifact):
    (role_list($artifact)) as $roles
    | ($artifact.path // $artifact.logical_path // $artifact.artifact_path // "") as $path
    | ($artifact.sha256 // $artifact.content_hash // $artifact.digest // "") as $sha
    | {
        path: ($path | tostring),
        size_bytes: ($artifact.size_bytes // 0),
        roles: $roles,
        replay_critical: ($artifact.replay_critical // ($roles | index("replay") != null)),
        sha256: ($sha | tostring | ascii_downcase),
        content_address: (
          ($sha | tostring | ascii_downcase) as $normalized
          | if ($normalized | length) > 0 then "sha256:" + $normalized else "" end
        )
      };
  {
    bundle_id: (.bundle_id // "unknown"),
    bundle_decision: (.bundle_decision // "unknown"),
    artifacts: (
      if (.artifacts | type) == "array" then .artifacts else [] end
      | map(normalized_artifact(.))
      | sort_by(.path, .content_address)
    ),
    retrieval_pack_artifacts: (
      (.retrieval_pack_artifacts // .selected_artifacts // [])
      | if type == "array" then . else [] end
      | map(normalized_artifact(.))
      | sort_by(.path, .content_address)
    ),
    artifact_paths: (.artifact_paths // {})
  }
' "$mirror_normalized" >"${mirror_normalized}.tmp"
mv "${mirror_normalized}.tmp" "$mirror_normalized"
write_event "mirror_manifest_loaded" "normalized mirror manifest"

jq -cS '
  {
    packing_decision: (.packing_decision // "unknown"),
    batches: (
      (.batches // [])
      | if type == "array" then . else [] end
      | map({
          batch_id: (.batch_id // "unknown"),
          worker_id: (.worker_id // ""),
          target_dir: (.target_dir // ""),
          bundle_ids: (
            (.bundle_ids // [])
            | if type == "array" then map(tostring) else [] end
            | unique
            | sort
          )
        })
      | sort_by(.batch_id, .worker_id, .target_dir)
    ),
    artifact_paths: (.artifact_paths // {})
  }
' "$batch_normalized" >"${batch_normalized}.tmp"
mv "${batch_normalized}.tmp" "$batch_normalized"
write_event "batch_manifest_loaded" "normalized locality-aware batch manifest"

jq -cS '
  {
    bundle_id: (.bundle_id // "unknown"),
    workflow_state: (.workflow_state // "unknown"),
    recovery_recommendation: (.recovery_recommendation // "unknown"),
    upstream_artifact_paths: (.upstream_artifact_paths // {}),
    bundle_artifact_paths: (.bundle_artifact_paths // {}),
    artifact_paths: (.artifact_paths // {})
  }
' "$salvage_normalized" >"${salvage_normalized}.tmp"
mv "${salvage_normalized}.tmp" "$salvage_normalized"
write_event "salvage_receipt_loaded" "normalized salvage receipt"

jq -n \
  --slurpfile bundle "$bundle_normalized" \
  --slurpfile mirror "$mirror_normalized" \
  --slurpfile batch "$batch_normalized" \
  --slurpfile salvage "$salvage_normalized" '
  def path_entry($path; $source; $roles; $replay_critical; $selected_for_retrieval; $salvage_referenced; $content_address):
    {
      path: $path,
      source: $source,
      roles: ($roles | unique | sort),
      replay_critical: $replay_critical,
      selected_for_retrieval: $selected_for_retrieval,
      salvage_referenced: $salvage_referenced,
      content_address: $content_address
    };
  def bundle_artifact_entries($artifact_paths):
    ($artifact_paths // {})
    | to_entries
    | map(select((.value | type) == "string" and (.value | length) > 0))
    | map(
        if .key == "run_manifest_json" then
          path_entry(.value; "bundle_artifact_path"; ["replay", "run_manifest"]; true; false; false; "")
        elif .key == "commands_txt" then
          path_entry(.value; "bundle_artifact_path"; ["replay", "commands"]; true; false; false; "")
        elif .key == "bundle_report_json" then
          path_entry(.value; "bundle_artifact_path"; ["inspect", "bundle_report"]; false; false; false; "")
        elif .key == "summary_md" or .key == "report_md" then
          path_entry(.value; "bundle_artifact_path"; ["inspect", "report"]; false; false; false; "")
        elif .key == "events_jsonl" then
          path_entry(.value; "bundle_artifact_path"; ["inspect", "events"]; false; false; false; "")
        else
          path_entry(.value; "bundle_artifact_path"; ["inspect", .key]; false; false; false; "")
        end
      );
  def phase_log_entries($paths):
    ($paths // [])
    | map(select(length > 0))
    | unique
    | sort
    | map(path_entry(.; "bundle_phase_log"; ["inspect", "phase_log"]; false; false; false; ""));
  def mirror_artifact_entries($artifacts):
    ($artifacts // [])
    | map(path_entry(.path; "mirror_artifact"; (.roles // []); (.replay_critical == true); false; false; (.content_address // "")));
  def mirror_selected_entries($artifacts):
    ($artifacts // [])
    | map(path_entry(.path; "mirror_selected_artifact"; (.roles // []); (.replay_critical == true); true; false; (.content_address // "")));
  def control_artifact_entries($artifact_paths; $source):
    ($artifact_paths // {})
    | to_entries
    | map(select((.value | type) == "string" and (.value | length) > 0))
    | map(path_entry(.value; $source; ["inspect", .key]; false; false; false; ""));
  def salvage_reference_entries($artifact_paths; $source; $salvage_active):
    ($artifact_paths // {})
    | to_entries
    | map(select((.value | type) == "string" and (.value | length) > 0))
    | map(path_entry(.value; $source; ["salvage", .key]; false; false; $salvage_active; ""));
  def merge_entries($entries):
    $entries
    | group_by(.path)
    | map({
        path: .[0].path,
        sources: (map(.source) | unique | sort),
        roles: (map(.roles[]) | unique | sort),
        replay_critical: any(.[]; .replay_critical),
        selected_for_retrieval: any(.[]; .selected_for_retrieval),
        salvage_referenced: any(.[]; .salvage_referenced),
        content_addresses: (
          map(.content_address)
          | map(select(length > 0))
          | unique
          | sort
        )
      });
  def retention_class($entry; $salvage_active):
    if $salvage_active and $entry.salvage_referenced then
      "salvage_pinned"
    elif $entry.replay_critical then
      "hot_replay_critical"
    elif $entry.selected_for_retrieval
      or any($entry.sources[]?;
        . == "bundle_artifact_path"
        or . == "bundle_phase_log"
        or . == "batch_artifact_path"
        or . == "mirror_artifact_path"
        or . == "salvage_artifact_path"
      ) then
      "warm_operator_inspectable"
    else
      "cold_archival"
    end;
  def retention_reason($entry; $salvage_active):
    if $salvage_active and $entry.salvage_referenced then
      "salvage workflow keeps this evidence pinned for reconciliation"
    elif $entry.replay_critical then
      "artifact is marked replay critical by upstream bundle or mirror evidence"
    elif $entry.selected_for_retrieval then
      "artifact remains warm because the mirror retrieval pack still selects it"
    elif any($entry.sources[]?;
      . == "bundle_artifact_path"
      or . == "bundle_phase_log"
      or . == "batch_artifact_path"
      or . == "mirror_artifact_path"
      or . == "salvage_artifact_path"
    ) then
      "artifact remains warm for bounded operator inspection"
    else
      "artifact is inspect-only and can demote to cold archival storage"
    end;
  ($bundle[0]) as $bundle
  | ($mirror[0]) as $mirror
  | ($batch[0]) as $batch
  | ($salvage[0]) as $salvage
  | (($salvage.workflow_state // "unknown") != "clean_finished") as $salvage_active
  | (first(($batch.batches // [])[]? | select((.bundle_ids // []) | index($bundle.bundle_id))) // null) as $batch_row
  | (
      bundle_artifact_entries($bundle.artifact_paths)
      + phase_log_entries($bundle.phase_log_paths)
      + mirror_artifact_entries($mirror.artifacts)
      + mirror_selected_entries($mirror.retrieval_pack_artifacts)
      + control_artifact_entries($mirror.artifact_paths; "mirror_artifact_path")
      + control_artifact_entries($batch.artifact_paths; "batch_artifact_path")
      + salvage_reference_entries($salvage.bundle_artifact_paths; "salvage_bundle_reference"; $salvage_active)
      + salvage_reference_entries($salvage.upstream_artifact_paths; "salvage_upstream_reference"; $salvage_active)
      + control_artifact_entries($salvage.artifact_paths; "salvage_artifact_path")
    ) as $candidate_entries
  | (
      merge_entries(
        $candidate_entries
        | map(
            if (.source == "salvage_artifact_path") and $salvage_active then
              . + {salvage_referenced: true}
            else
              .
            end
          )
      )
    ) as $merged_entries
  | (
      [
        (if (($bundle.bundle_id // "") | length) == 0 or $bundle.bundle_id == "unknown" then
           {code: "missing_bundle_id", message: "bundle report must declare bundle_id"}
         else empty end),
        (if (($bundle.expected_worker_id // "") | length) == 0 then
           {code: "missing_expected_worker", message: "bundle report must declare expected_worker_id"}
         else empty end),
        (if (($bundle.expected_target_dir // "") | length) == 0 then
           {code: "missing_expected_target", message: "bundle report must declare expected_target_dir"}
         else empty end),
        (if (($mirror.bundle_id // "unknown") != ($bundle.bundle_id // "unknown")) then
           {code: "mirror_bundle_mismatch", message: "mirror manifest bundle_id does not match bundle report"}
         else empty end),
        (if (($salvage.bundle_id // "unknown") != ($bundle.bundle_id // "unknown")) then
           {code: "salvage_bundle_mismatch", message: "salvage receipt bundle_id does not match bundle report"}
         else empty end),
        (if $batch_row == null then
           {code: "batch_membership_missing", message: "batch manifest does not contain the target bundle"}
         else empty end),
        (if (($mirror.artifacts // []) | length) == 0 and (($mirror.retrieval_pack_artifacts // []) | length) == 0 then
           {code: "mirror_artifacts_missing", message: "mirror manifest does not contain artifact evidence"}
         else empty end),
        (($merged_entries[]? | select((.content_addresses | length) > 1) | {
          code: "content_address_conflict",
          message: ("path " + .path + " carries conflicting content addresses")
        })),
        (if ($merged_entries | length) == 0 then
           {code: "artifact_surface_empty", message: "no artifact entries could be derived from upstream evidence"}
         else empty end)
      ]
    ) as $validation_errors
  | (
      $merged_entries
      | map(
          . + {
            retention_class: retention_class(.; $salvage_active),
            retention_reason: retention_reason(.; $salvage_active)
          }
        )
      | sort_by(.retention_class, .path)
    ) as $retention_entries
  | {
      schema_version: "franken-engine.remote-proof-evidence-residency-manifest.v1",
      bundle_id: $bundle.bundle_id,
      bundle_decision: $bundle.bundle_decision,
      expected_worker_id: $bundle.expected_worker_id,
      expected_target_dir: $bundle.expected_target_dir,
      batch_context: {
        packing_decision: $batch.packing_decision,
        batch_id: ($batch_row.batch_id // null),
        worker_id: ($batch_row.worker_id // null),
        target_dir: ($batch_row.target_dir // null)
      },
      salvage_context: {
        workflow_state: $salvage.workflow_state,
        recovery_recommendation: $salvage.recovery_recommendation,
        salvage_active: $salvage_active
      },
      retention_entries: $retention_entries,
      class_counts: {
        hot_replay_critical: ($retention_entries | map(select(.retention_class == "hot_replay_critical")) | length),
        warm_operator_inspectable: ($retention_entries | map(select(.retention_class == "warm_operator_inspectable")) | length),
        salvage_pinned: ($retention_entries | map(select(.retention_class == "salvage_pinned")) | length),
        cold_archival: ($retention_entries | map(select(.retention_class == "cold_archival")) | length)
      },
      validation_errors: $validation_errors
    }
' >"$manifest_core"

input_hash="$(
  jq -n \
    --slurpfile bundle "$bundle_normalized" \
    --slurpfile mirror "$mirror_normalized" \
    --slurpfile batch "$batch_normalized" \
    --slurpfile salvage "$salvage_normalized" \
    '{
      bundle_report: ($bundle[0]),
      mirror_manifest: ($mirror[0]),
      batch_manifest: ($batch[0]),
      salvage_receipt: ($salvage[0])
    }' | jq -cS . | sha256sum | awk '{print $1}'
)"
manifest_hash="$(jq -cS . "$manifest_core" | sha256sum | awk '{print $1}')"

jq -n \
  --slurpfile manifest "$manifest_core" '
  ($manifest[0]) as $manifest
  | {
      schema_version: "franken-engine.remote-proof-retention-class-ledger.v1",
      residency_manifest_schema: "franken-engine.remote-proof-evidence-residency-manifest.v1",
      bundle_id: $manifest.bundle_id,
      retention_decision: (
        if (($manifest.validation_errors // []) | length) == 0 then "pass" else "fail_closed" end
      ),
      reason: (
        if (($manifest.validation_errors // []) | length) == 0 then
          "deterministic retention classes emitted from bundle, mirror, batch, and salvage evidence"
        else
          "upstream residency evidence is inconsistent or incomplete"
        end
      ),
      batch_context: $manifest.batch_context,
      salvage_context: $manifest.salvage_context,
      normalized_artifact_count: (($manifest.retention_entries // []) | length),
      class_counts: $manifest.class_counts,
      validation_errors: $manifest.validation_errors,
      exit_code: (
        if (($manifest.validation_errors // []) | length) == 0 then 0 else 42 end
      )
    }
' >"$ledger_core"

ledger_hash="$(jq -cS . "$ledger_core" | sha256sum | awk '{print $1}')"

jq \
  --arg input_hash "$input_hash" \
  --arg manifest_hash "$manifest_hash" \
  --arg manifest_path "$manifest_path" \
  --arg ledger_path "$ledger_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg summary_path "$summary_path" \
  --arg bundle_report_path "$bundle_report_json" \
  --arg mirror_manifest_path "$mirror_manifest_json" \
  --arg batch_manifest_path "$batch_manifest_json" \
  --arg salvage_receipt_path "$salvage_receipt_json" '
  . + {
    hash_basis: {
      input_hash: $input_hash,
      manifest_hash: $manifest_hash
    },
    upstream_artifact_paths: {
      bundle_report_json: $bundle_report_path,
      mirror_manifest_json: $mirror_manifest_path,
      batch_manifest_json: $batch_manifest_path,
      salvage_receipt_json: $salvage_receipt_path
    },
    artifact_paths: {
      evidence_residency_manifest_json: $manifest_path,
      retention_class_ledger_json: $ledger_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $summary_path
    }
  }
' "$manifest_core" >"$manifest_tmp"
mv "$manifest_tmp" "$manifest_path"

jq \
  --arg input_hash "$input_hash" \
  --arg manifest_hash "$manifest_hash" \
  --arg ledger_hash "$ledger_hash" \
  --arg ledger_path "$ledger_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg summary_path "$summary_path" \
  --arg bundle_report_path "$bundle_report_json" \
  --arg mirror_manifest_path "$mirror_manifest_json" \
  --arg batch_manifest_path "$batch_manifest_json" \
  --arg salvage_receipt_path "$salvage_receipt_json" '
  . + {
    hash_basis: {
      input_hash: $input_hash,
      manifest_hash: $manifest_hash,
      ledger_hash: $ledger_hash
    },
    upstream_artifact_paths: {
      bundle_report_json: $bundle_report_path,
      mirror_manifest_json: $mirror_manifest_path,
      batch_manifest_json: $batch_manifest_path,
      salvage_receipt_json: $salvage_receipt_path
    },
    artifact_paths: {
      retention_class_ledger_json: $ledger_path,
      evidence_residency_manifest_json: $manifest_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $summary_path
    }
  }
' "$ledger_core" >"$ledger_tmp"
mv "$ledger_tmp" "$ledger_path"

write_event "retention_ledger_written" "$(jq -r '.retention_decision + \" / artifacts=\" + (.normalized_artifact_count | tostring)' "$ledger_path")"

{
  printf '# Remote Proof Retention Class Ledger\n\n'
  printf '%s\n' "- Decision: \`$(jq -r '.retention_decision' "$ledger_path")\`"
  printf '%s\n' "- Reason: $(jq -r '.reason' "$ledger_path")"
  printf '%s\n' "- Bundle ID: \`$(jq -r '.bundle_id' "$ledger_path")\`"
  printf '%s\n' "- Artifact count: \`$(jq -r '.normalized_artifact_count' "$ledger_path")\`"
  printf '%s\n' "- Hot replay-critical: \`$(jq -r '.class_counts.hot_replay_critical' "$ledger_path")\`"
  printf '%s\n' "- Warm operator-inspectable: \`$(jq -r '.class_counts.warm_operator_inspectable' "$ledger_path")\`"
  printf '%s\n' "- Salvage-pinned: \`$(jq -r '.class_counts.salvage_pinned' "$ledger_path")\`"
  printf '%s\n' "- Cold archival: \`$(jq -r '.class_counts.cold_archival' "$ledger_path")\`"
  printf '\n## Validation Errors\n\n'
  if jq -e '(.validation_errors | length) == 0' "$ledger_path" >/dev/null; then
    printf '%s\n' '- none'
  else
    jq -r '.validation_errors[] | "- `" + .code + "`: " + .message' "$ledger_path"
  fi
  printf '\n## Residency Classes\n\n'
  jq -r '.retention_entries[] | "- `" + .path + "` => `" + .retention_class + "` (" + .retention_reason + ")"' "$manifest_path"
} >"$summary_tmp"
mv "$summary_tmp" "$summary_path"

printf 'remote_proof_retention_class_ledger=%s\n' "$ledger_path"
printf 'remote_proof_evidence_residency_manifest=%s\n' "$manifest_path"

exit "$(jq -r '.exit_code' "$ledger_path")"
