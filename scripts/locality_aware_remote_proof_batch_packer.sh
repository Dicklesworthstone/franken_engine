#!/usr/bin/env bash
set -euo pipefail

artifact_root="${LOCALITY_AWARE_REMOTE_PROOF_BATCH_PACKER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-locality-aware-remote-proof-batch-packer}"
run_id="${LOCALITY_AWARE_REMOTE_PROOF_BATCH_PACKER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${LOCALITY_AWARE_REMOTE_PROOF_BATCH_PACKER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

bundle_reports_json=""
mirror_manifests_json=""
roi_ledgers_json=""
fairness_policy_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/locality_aware_remote_proof_batch_packer.sh --bundle-reports-json FILE --mirror-manifests-json FILE --roi-ledgers-json FILE --fairness-policy-json FILE [OPTIONS]

Build a deterministic multi-suite remote proof batch manifest that groups
resident proof bundles by worker warmth, warm-target compatibility, shared
closure-root locality, and fairness constraints. This script is planning-only:
it consumes fixture snapshots and emits a packing decision without running
Cargo, querying rch, or touching remote workers.

Required:
  --bundle-reports-json FILE
  --mirror-manifests-json FILE
  --roi-ledgers-json FILE
  --fairness-policy-json FILE

Optional:
  --output-dir DIR

Artifacts:
  batch_manifest.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  batch plan emitted successfully
  42 fail-closed due to missing locality evidence, unsafe worker/target drift,
     or bundles that cannot be assigned truthfully
  64 invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bundle-reports-json)
      bundle_reports_json="${2:-}"
      shift 2
      ;;
    --mirror-manifests-json)
      mirror_manifests_json="${2:-}"
      shift 2
      ;;
    --roi-ledgers-json)
      roi_ledgers_json="${2:-}"
      shift 2
      ;;
    --fairness-policy-json)
      fairness_policy_json="${2:-}"
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

if [[ -z "$bundle_reports_json" || -z "$mirror_manifests_json" || -z "$roi_ledgers_json" || -z "$fairness_policy_json" ]]; then
  printf 'locality-aware batch packer requires all four input JSON files\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for locality-aware remote proof batch packing\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for locality-aware remote proof batch packing\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
manifest_path="${run_dir}/batch_manifest.json"
manifest_tmp="${manifest_path}.tmp"
summary_path="${run_dir}/report.md"
summary_tmp="${summary_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
bundle_normalized="${run_dir}/bundle_reports.normalized.json"
mirror_normalized="${run_dir}/mirror_manifests.normalized.json"
roi_normalized="${run_dir}/roi_ledgers.normalized.json"
fairness_normalized="${run_dir}/fairness_policy.normalized.json"
manifest_core="${run_dir}/batch_manifest.core.json"
: >"$events_path"

printf './scripts/locality_aware_remote_proof_batch_packer.sh' >"$commands_path"
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

json_input() {
  local path="$1"
  local output_path="$2"
  local label="$3"

  if [[ ! -f "$path" ]]; then
    printf 'locality-aware batch packer missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'locality-aware batch packer invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
}

json_input "$bundle_reports_json" "$bundle_normalized" "bundle reports"
json_input "$mirror_manifests_json" "$mirror_normalized" "mirror manifests"
json_input "$roi_ledgers_json" "$roi_normalized" "ROI ledgers"
json_input "$fairness_policy_json" "$fairness_normalized" "fairness policy"

jq -cS '
  def string_list($value):
    if ($value | type) == "array" then
      $value | map(tostring) | map(select(length > 0)) | unique | sort
    elif ($value | type) == "string" and ($value | length) > 0 then
      [$value]
    else
      []
    end;
  def item_list:
    if type == "array" then .
    else (.bundles // .bundle_reports // [])
    end
    | if type == "array" then . else [] end;
  {
    bundles: (
      item_list
      | map({
          bundle_id: (.bundle_id // .suite_id // .id // "unknown"),
          expected_worker_id: (.expected_worker_id // .worker_id // .worker // ""),
          expected_target_dir: (.expected_target_dir // .target_dir // .cargo_target_dir // ""),
          allowed_worker_ids: (
            string_list(.allowed_worker_ids // .candidate_worker_ids // .worker_allowlist // [])
            + string_list(.expected_worker_id // .worker_id // .worker // "")
          ) | unique | sort,
          allowed_target_dirs: (
            string_list(.allowed_target_dirs // .candidate_target_dirs // .target_dir_allowlist // [])
            + string_list(.expected_target_dir // .target_dir // .cargo_target_dir // "")
          ) | unique | sort,
          closure_roots: string_list(.closure_roots // .sync_closure_roots // .closure_root // []),
          phase_count: (
            if (.phase_count | type) == "number" then .phase_count
            elif (.phase_results | type) == "array" then (.phase_results | length)
            else 1
            end
          ),
          predicted_cost_units: (
            if (.predicted_cost_units | type) == "number" then .predicted_cost_units
            elif (.phase_count | type) == "number" then .phase_count
            elif (.phase_results | type) == "array" then (.phase_results | length)
            else 1
            end
          ),
          source_revision: (.source_revision // .revision // "unknown")
        })
      | sort_by(.bundle_id)
    )
  }
' "$bundle_normalized" >"${bundle_normalized}.tmp"
mv "${bundle_normalized}.tmp" "$bundle_normalized"
write_event "bundle_reports_loaded" "normalized resident bundle inputs"

jq -cS '
  def string_list($value):
    if ($value | type) == "array" then
      $value | map(tostring) | map(select(length > 0)) | unique | sort
    elif ($value | type) == "string" and ($value | length) > 0 then
      [$value]
    else
      []
    end;
  def item_list:
    if type == "array" then .
    else (.bundles // .mirror_manifests // .packs // .mirrors // [])
    end
    | if type == "array" then . else [] end;
  {
    bundles: (
      item_list
      | map({
          bundle_id: (.bundle_id // .suite_id // .id // "unknown"),
          closure_roots: string_list(.closure_roots // .shared_closure_roots // .sync_closure_roots // []),
          retrieval_pack_artifacts: (
            (.retrieval_pack_artifacts // .selected_artifacts // .artifacts // [])
            | if type == "array" then map(tostring) else [] end
            | unique | sort
          ),
          mirror_manifest_hash: (.mirror_manifest_hash // .manifest_hash // "")
        })
      | sort_by(.bundle_id)
    )
  }
' "$mirror_normalized" >"${mirror_normalized}.tmp"
mv "${mirror_normalized}.tmp" "$mirror_normalized"
write_event "mirror_manifests_loaded" "normalized artifact mirror inputs"

jq -cS '
  def string_list($value):
    if ($value | type) == "array" then
      $value | map(tostring) | map(select(length > 0)) | unique | sort
    elif ($value | type) == "string" and ($value | length) > 0 then
      [$value]
    else
      []
    end;
  def item_list:
    if type == "array" then .
    else (.bundles // .roi_ledgers // .ledgers // [])
    end
    | if type == "array" then . else [] end;
  {
    bundles: (
      item_list
      | map({
          bundle_id: (.bundle_id // .suite_id // .id // "unknown"),
          decision: (.decision // .plan_decision // "unknown"),
          recommended_action: (.recommended_action // .plan_decision // "unknown"),
          expected_worker_id: (.expected_worker_id // .assigned_worker_id // .worker_id // ""),
          expected_target_dir: (.expected_target_dir // .assigned_target_dir // .target_dir // ""),
          realized_reuse_score: (
            if (.realized_reuse_score | type) == "number" then .realized_reuse_score
            elif (.roi_score | type) == "number" then .roi_score
            else 0
            end
          ),
          predicted_cost_units: (
            if (.predicted_cost_units | type) == "number" then .predicted_cost_units
            else 0
            end
          ),
          policy_findings: string_list(.policy_findings // [])
        })
      | sort_by(.bundle_id)
    )
  }
' "$roi_normalized" >"${roi_normalized}.tmp"
mv "${roi_normalized}.tmp" "$roi_normalized"
write_event "roi_ledgers_loaded" "normalized ROI evidence inputs"

jq -cS '
  def string_list($value):
    if ($value | type) == "array" then
      $value | map(tostring) | map(select(length > 0)) | unique | sort
    elif ($value | type) == "string" and ($value | length) > 0 then
      [$value]
    else
      []
    end;
  {
    max_bundles_per_worker: (
      if (.max_bundles_per_worker | type) == "number" then .max_bundles_per_worker
      else 2
      end
    ),
    max_total_cost_per_worker: (
      if (.max_total_cost_per_worker | type) == "number" then .max_total_cost_per_worker
      else 12
      end
    ),
    starvation_escape_bundle_ids: string_list(.starvation_escape_bundle_ids // []),
    explicit_incompatibilities: (
      (.explicit_incompatibilities // .incompatible_assignments // [])
      | if type == "array" then . else [] end
      | map({
          bundle_id: (.bundle_id // ""),
          worker_id: (.worker_id // ""),
          target_dir: (.target_dir // ""),
          reason: (.reason // "explicit_incompatibility")
        })
      | sort_by(.bundle_id, .worker_id, .target_dir, .reason)
    )
  }
' "$fairness_normalized" >"${fairness_normalized}.tmp"
mv "${fairness_normalized}.tmp" "$fairness_normalized"
write_event "fairness_policy_loaded" "normalized fairness policy"

jq -n \
  --slurpfile bundles "$bundle_normalized" \
  --slurpfile mirrors "$mirror_normalized" \
  --slurpfile rois "$roi_normalized" \
  --slurpfile fairness "$fairness_normalized" '
  def has_member($list; $value):
    any($list[]?; . == $value);
  def shared_count($left; $right):
    reduce $left[]? as $item (0; . + (if has_member($right; $item) then 1 else 0 end));
  def safe_worker($bundle; $roi):
    if (($roi.expected_worker_id // "") | length) > 0
       and ((($bundle.allowed_worker_ids | length) == 0) or has_member($bundle.allowed_worker_ids; $roi.expected_worker_id))
    then $roi.expected_worker_id
    elif ($bundle.expected_worker_id | length) > 0 then $bundle.expected_worker_id
    elif ($bundle.allowed_worker_ids | length) > 0 then $bundle.allowed_worker_ids[0]
    else ""
    end;
  def safe_target($bundle; $roi):
    if (($roi.expected_target_dir // "") | length) > 0
       and ((($bundle.allowed_target_dirs | length) == 0) or has_member($bundle.allowed_target_dirs; $roi.expected_target_dir))
    then $roi.expected_target_dir
    elif ($bundle.expected_target_dir | length) > 0 then $bundle.expected_target_dir
    elif ($bundle.allowed_target_dirs | length) > 0 then $bundle.allowed_target_dirs[0]
    else ""
    end;
  def incompatibility_reason($bundle_id; $worker_id; $target_dir; $policy):
    first(
      ($policy.explicit_incompatibilities // [])[]?
      | select(
          .bundle_id == $bundle_id
          and (((.worker_id // "") | length) == 0 or .worker_id == $worker_id)
          and (((.target_dir // "") | length) == 0 or .target_dir == $target_dir)
        )
      | .reason
    ) // "";
  def compatible($bundle; $batch; $policy):
    ($bundle.preferred_worker_id == $batch.worker_id)
    and ($bundle.preferred_target_dir == $batch.target_dir)
    and (($batch.bundle_ids | length) < $policy.max_bundles_per_worker)
    and (($batch.total_predicted_cost_units + $bundle.predicted_cost_units) <= $policy.max_total_cost_per_worker)
    and (
      (($bundle.allowed_worker_ids | length) == 0)
      or has_member($bundle.allowed_worker_ids; $batch.worker_id)
    )
    and (
      (($bundle.allowed_target_dirs | length) == 0)
      or has_member($bundle.allowed_target_dirs; $batch.target_dir)
    )
    and ((incompatibility_reason($bundle.bundle_id; $batch.worker_id; $batch.target_dir; $policy) | length) == 0);
  def candidate_score($bundle; $batch):
    ((shared_count($bundle.closure_roots; $batch.closure_roots)) * 10)
    + (if $bundle.expected_worker_id == $batch.worker_id then 20 else 0 end)
    + (if $bundle.expected_target_dir == $batch.target_dir then 20 else 0 end)
    + (if ($bundle.roi.decision == "retain" or $bundle.roi.recommended_action == "retain_warm_target") then 5 else 0 end);
  def split_reason($bundle; $batches; $policy):
    if any($batches[]?; .worker_id == $bundle.preferred_worker_id and .target_dir == $bundle.preferred_target_dir and (.bundle_ids | length) >= $policy.max_bundles_per_worker) then
      "fairness_split:max_bundles_per_worker"
    elif any($batches[]?; .worker_id == $bundle.preferred_worker_id and .target_dir == $bundle.preferred_target_dir and ((.total_predicted_cost_units + $bundle.predicted_cost_units) > $policy.max_total_cost_per_worker)) then
      "fairness_split:max_total_cost_per_worker"
    elif any($batches[]?; shared_count($bundle.closure_roots; .closure_roots) > 0) then
      "compatibility_split:worker_or_target_incompatibility"
    else
      "new_anchor_batch"
    end;
  def batch_id_for($index; $worker_id):
    "batch-"
    + (if ($index + 1) < 10 then "0" else "" end)
    + (($index + 1) | tostring)
    + "-"
    + ($worker_id | gsub("[^A-Za-z0-9._-]"; "_"));
  def row_for($bundle; $locality_reason; $fairness_reason):
    {
      bundle_id: $bundle.bundle_id,
      preferred_worker_id: $bundle.preferred_worker_id,
      preferred_target_dir: $bundle.preferred_target_dir,
      predicted_cost_units: $bundle.predicted_cost_units,
      closure_roots: $bundle.closure_roots,
      locality_reason: $locality_reason,
      fairness_reason: $fairness_reason,
      mirror_manifest_hash: $bundle.mirror.mirror_manifest_hash,
      retrieval_pack_artifact_count: ($bundle.mirror.retrieval_pack_artifacts | length),
      roi_decision: $bundle.roi.decision,
      roi_recommended_action: $bundle.roi.recommended_action,
      roi_reuse_score: $bundle.roi.realized_reuse_score
    };
  def merge_bundle($bundle; $mirror; $roi):
    {
      bundle_id: $bundle.bundle_id,
      expected_worker_id: $bundle.expected_worker_id,
      expected_target_dir: $bundle.expected_target_dir,
      allowed_worker_ids: $bundle.allowed_worker_ids,
      allowed_target_dirs: $bundle.allowed_target_dirs,
      closure_roots: (($bundle.closure_roots + $mirror.closure_roots) | unique | sort),
      predicted_cost_units: (if ($roi.predicted_cost_units // 0) > 0 then $roi.predicted_cost_units else $bundle.predicted_cost_units end),
      phase_count: $bundle.phase_count,
      source_revision: $bundle.source_revision,
      mirror: $mirror,
      roi: $roi,
      preferred_worker_id: safe_worker($bundle; $roi),
      preferred_target_dir: safe_target($bundle; $roi)
    };
  ($bundles[0].bundles // []) as $bundle_items
  | ($mirrors[0].bundles // []) as $mirror_items
  | ($rois[0].bundles // []) as $roi_items
  | ($fairness[0]) as $policy
  | (reduce $mirror_items[] as $item ({}; .[$item.bundle_id] = $item)) as $mirror_map
  | (reduce $roi_items[] as $item ({}; .[$item.bundle_id] = $item)) as $roi_map
  | [
      $bundle_items[] as $bundle
      | ($mirror_map[$bundle.bundle_id]) as $mirror
      | ($roi_map[$bundle.bundle_id]) as $roi
      | if $mirror == null then
          {bundle_id: $bundle.bundle_id, message: "bundle missing artifact mirror evidence"}
        elif $roi == null then
          {bundle_id: $bundle.bundle_id, message: "bundle missing ROI ledger evidence"}
        else
          (merge_bundle($bundle; $mirror; $roi)) as $merged
          | if ($merged.preferred_worker_id | length) == 0 then
              {bundle_id: $bundle.bundle_id, message: "bundle has no safe worker assignment"}
            elif ($merged.preferred_target_dir | length) == 0 then
              {bundle_id: $bundle.bundle_id, message: "bundle has no safe target-dir assignment"}
            elif (($merged.closure_roots | length) == 0) then
              {bundle_id: $bundle.bundle_id, message: "bundle lacks closure-root locality evidence"}
            else
              empty
            end
        end
    ] as $validation_errors
  | if ($validation_errors | length) > 0 then
      {
        schema_version: "franken-engine.locality-aware-remote-proof-batch-plan.v1",
        packing_decision: "fail_closed",
        reason: "one or more bundles are missing locality or assignment evidence",
        validation_errors: $validation_errors,
        fairness_policy: $policy,
        batches: [],
        split_reasons: [],
        total_bundle_count: ($bundle_items | length)
      }
    else
      [
        $bundle_items[] as $bundle
        | merge_bundle($bundle; $mirror_map[$bundle.bundle_id]; $roi_map[$bundle.bundle_id])
      ]
      | sort_by(.preferred_worker_id, .preferred_target_dir, .bundle_id)
      | reduce .[] as $bundle (
          {
            schema_version: "franken-engine.locality-aware-remote-proof-batch-plan.v1",
            packing_decision: "pass",
            reason: "deterministic locality-aware packing completed",
            validation_errors: [],
            fairness_policy: $policy,
            batches: [],
            split_reasons: [],
            total_bundle_count: 0
          };
          .total_bundle_count += 1
          | ([.batches | to_entries[]? | select(compatible($bundle; .value; $policy)) | {index: .key, score: candidate_score($bundle; .value)}] | sort_by(-.score, .index) | .[0]?) as $candidate
          | if $candidate != null then
              .batches[$candidate.index].bundle_ids += [$bundle.bundle_id]
              | .batches[$candidate.index].closure_roots = ((.batches[$candidate.index].closure_roots + $bundle.closure_roots) | unique | sort)
              | .batches[$candidate.index].shared_locality_score += $candidate.score
              | .batches[$candidate.index].total_predicted_cost_units += $bundle.predicted_cost_units
              | .batches[$candidate.index].bundle_rows += [
                  row_for(
                    $bundle;
                    (if (shared_count($bundle.closure_roots; .batches[$candidate.index].closure_roots) > 0) then "shared_closure_roots" else "shared_worker_target_only" end);
                    "within_fairness_budget"
                  )
                ]
            else
              (split_reason($bundle; .batches; $policy)) as $reason
              | if ($reason != "new_anchor_batch") then
                  .split_reasons += [$reason]
                else
                  .
                end
              | .batches += [
                  {
                    worker_id: $bundle.preferred_worker_id,
                    target_dir: $bundle.preferred_target_dir,
                    bundle_ids: [$bundle.bundle_id],
                    closure_roots: $bundle.closure_roots,
                    total_predicted_cost_units: $bundle.predicted_cost_units,
                    shared_locality_score: (
                      (if $bundle.expected_worker_id == $bundle.preferred_worker_id then 20 else 0 end)
                      + (if $bundle.expected_target_dir == $bundle.preferred_target_dir then 20 else 0 end)
                      + (if ($bundle.roi.decision == "retain" or $bundle.roi.recommended_action == "retain_warm_target") then 5 else 0 end)
                    ),
                    bundle_rows: [
                      row_for(
                        $bundle;
                        (if ($reason == "compatibility_split:worker_or_target_incompatibility") then "worker_or_target_incompatibility" else "anchor_bundle" end);
                        (if ($reason | startswith("fairness_split:")) then ($reason | split(":")[1]) else "anchor_bundle" end)
                      )
                    ]
                  }
                ]
            end
        )
      | .split_reasons |= unique
      | .batches |= (
          sort_by(.worker_id, .target_dir, .bundle_ids[0])
          | to_entries
          | map(
              .key as $index
              | .value as $batch
              | ($batch.closure_roots) as $batch_roots
              | (batch_id_for($index; $batch.worker_id)) as $batch_id
              | {
                  batch_id: $batch_id,
                  worker_id: $batch.worker_id,
                  target_dir: $batch.target_dir,
                  bundle_ids: ($batch.bundle_ids | unique | sort),
                  closure_roots: $batch_roots,
                  shared_locality_score: $batch.shared_locality_score,
                  total_predicted_cost_units: $batch.total_predicted_cost_units,
                  bundle_rows: (
                    $batch.bundle_rows
                    | sort_by(-(shared_count(.closure_roots; $batch_roots)), .bundle_id)
                    | to_entries
                    | map(
                        .value
                        + {
                            pack_order: (.key + 1),
                            batch_id: $batch_id
                          }
                      )
                  )
                }
            )
        )
    end
' >"$manifest_core"

input_hash="$(
  cat "$bundle_normalized" "$mirror_normalized" "$roi_normalized" "$fairness_normalized" \
    | sha256sum \
    | awk '{print $1}'
)"
manifest_hash="$(sha256sum "$manifest_core" | awk '{print $1}')"

jq \
  --arg manifest_path "$manifest_path" \
  --arg summary_path "$summary_path" \
  --arg commands_path "$commands_path" \
  --arg events_path "$events_path" \
  --arg input_hash "$input_hash" \
  --arg manifest_hash "$manifest_hash" '
  . + {
    batch_manifest_id: ("locality-batch-" + ($manifest_hash[0:16])),
    artifact_paths: {
      batch_manifest_json: $manifest_path,
      report_md: $summary_path,
      commands_txt: $commands_path,
      events_jsonl: $events_path
    },
    hash_basis: {
      input_hash: $input_hash,
      manifest_hash: $manifest_hash
    }
  }
' "$manifest_core" >"$manifest_tmp"
mv "$manifest_tmp" "$manifest_path"
write_event "batch_manifest_written" "computed deterministic locality-aware batch manifest"

jq -r '
  [
    "# Locality-Aware Remote Proof Batch Packer",
    "",
    "- Decision: `" + .packing_decision + "`",
    "- Batch Manifest ID: `" + .batch_manifest_id + "`",
    "- Total Bundles: `" + (.total_bundle_count | tostring) + "`",
    "- Batches: `" + ((.batches | length) | tostring) + "`",
    "- Split Reasons: `" + ((.split_reasons // []) | join(", ")) + "`",
    "",
    "## Batches",
    (
      if (.batches | length) == 0 then
        "- none"
      else
        (.batches[] | "- `" + .batch_id + "` worker=`" + .worker_id + "` target=`" + .target_dir + "` bundles=`" + (.bundle_ids | join(", ")) + "`")
      end
    ),
    "",
    "## Validation Errors",
    (
      if (.validation_errors | length) == 0 then
        "- none"
      else
        (.validation_errors[] | "- `" + .bundle_id + "`: " + .message)
      end
    )
  ] | flatten | .[]
' "$manifest_path" >"$summary_tmp"
mv "$summary_tmp" "$summary_path"
write_event "summary_written" "rendered packing summary markdown"

decision="$(jq -r '.packing_decision' "$manifest_path")"
if [[ "$decision" == "pass" ]]; then
  exit 0
fi
exit 42
