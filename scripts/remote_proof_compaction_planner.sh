#!/usr/bin/env bash
set -euo pipefail

artifact_root="${REMOTE_PROOF_COMPACTION_PLANNER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-remote-proof-compaction-planner}"
run_id="${REMOTE_PROOF_COMPACTION_PLANNER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${REMOTE_PROOF_COMPACTION_PLANNER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

residency_manifest_json=""
mirror_manifest_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/remote_proof_compaction_planner.sh --residency-manifest-json FILE --mirror-manifest-json FILE [OPTIONS]

Plan safe compaction for duplicate content-addressed remote-proof artifacts
without crossing retention-class, replay-critical, or provenance boundaries.

Required:
  --residency-manifest-json FILE
  --mirror-manifest-json FILE

Optional:
  --output-dir DIR

Artifacts:
  remote_proof_compaction_plan.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   compaction plan emitted successfully
  42  fail-closed due to inconsistent upstream evidence
  64  invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --residency-manifest-json)
      residency_manifest_json="${2:-}"
      shift 2
      ;;
    --mirror-manifest-json)
      mirror_manifest_json="${2:-}"
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

if [[ -z "$residency_manifest_json" || -z "$mirror_manifest_json" ]]; then
  printf 'remote proof compaction planner requires --residency-manifest-json and --mirror-manifest-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for remote proof compaction planning\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for remote proof compaction planning\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/remote_proof_compaction_plan.json"
plan_tmp="${plan_path}.tmp"
summary_path="${run_dir}/report.md"
summary_tmp="${summary_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
residency_normalized="${run_dir}/residency_manifest.normalized.json"
mirror_normalized="${run_dir}/mirror_manifest.normalized.json"
plan_core="${run_dir}/compaction_plan.core.json"
: >"$events_path"

printf './scripts/remote_proof_compaction_planner.sh' >"$commands_path"
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
    printf 'remote proof compaction planner missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'remote proof compaction planner invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
}

normalize_required_json "$residency_manifest_json" "$residency_normalized" "residency manifest"
normalize_required_json "$mirror_manifest_json" "$mirror_normalized" "mirror manifest"

jq -cS '
  {
    bundle_id: (.bundle_id // "unknown"),
    bundle_decision: (.bundle_decision // "unknown"),
    retention_entries: (
      (.retention_entries // [])
      | if type == "array" then . else [] end
      | map({
          path: (.path // ""),
          retention_class: (.retention_class // "unknown"),
          retention_reason: (.retention_reason // ""),
          sources: (
            (.sources // [])
            | if type == "array" then map(tostring) else [] end
            | unique
            | sort
          ),
          roles: (
            (.roles // [])
            | if type == "array" then map(tostring) else [] end
            | unique
            | sort
          ),
          replay_critical: (.replay_critical // false),
          content_addresses: (
            (.content_addresses // [])
            | if type == "array" then map(tostring) else [] end
            | map(select(length > 0))
            | unique
            | sort
          )
        })
      | sort_by(.path)
    ),
    artifact_paths: (.artifact_paths // {})
  }
' "$residency_normalized" >"${residency_normalized}.tmp"
mv "${residency_normalized}.tmp" "$residency_normalized"
write_event "residency_manifest_loaded" "normalized evidence residency manifest"

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
    ) | map(tostring) | unique | sort;
  {
    bundle_id: (.bundle_id // "unknown"),
    artifacts: (
      (.artifacts // [])
      | if type == "array" then . else [] end
      | map({
          path: (.path // ""),
          roles: role_list(.),
          replay_critical: (.replay_critical // false),
          content_address: (.content_address // "")
        })
      | sort_by(.path, .content_address)
    ),
    artifact_paths: (.artifact_paths // {})
  }
' "$mirror_normalized" >"${mirror_normalized}.tmp"
mv "${mirror_normalized}.tmp" "$mirror_normalized"
write_event "mirror_manifest_loaded" "normalized content-addressed mirror manifest"

jq -n \
  --slurpfile residency "$residency_normalized" \
  --slurpfile mirror "$mirror_normalized" '
  def mirror_index($artifacts):
    reduce ($artifacts // [])[] as $artifact ({}; .[$artifact.path] = $artifact);
  def first_address($entry):
    if (($entry.content_addresses // []) | length) > 0 then
      $entry.content_addresses[0]
    else
      ""
    end;
  ($residency[0]) as $residency
  | ($mirror[0]) as $mirror
  | (mirror_index($mirror.artifacts)) as $mirror_map
  | (
      $residency.retention_entries
      | map(
          . as $entry
          | ($mirror_map[$entry.path] // null) as $mirror_entry
          | {
              path: $entry.path,
              retention_class: $entry.retention_class,
              retention_reason: $entry.retention_reason,
              sources: $entry.sources,
              retention_roles: $entry.roles,
              mirror_roles: ($mirror_entry.roles // []),
              replay_critical: (($entry.replay_critical // false) or ($mirror_entry.replay_critical // false)),
              content_address: (
                if (first_address($entry) | length) > 0 then first_address($entry)
                else ($mirror_entry.content_address // "")
                end
              ),
              provenance_key: (($entry.sources // []) | unique | sort | join("+"))
            }
        )
      | sort_by(.path)
    ) as $items
  | (
      [
        (if (($residency.bundle_id // "unknown") != ($mirror.bundle_id // "unknown")) then
           {code: "bundle_mismatch", message: "residency manifest bundle_id does not match mirror manifest"}
         else empty end),
        ($items[] | select((.path | length) == 0) | {code: "missing_path", message: "retention entry is missing path evidence"}),
        ($items[] | select(.retention_class == "hot_replay_critical" and (.content_address | length) == 0) | {
          code: "missing_content_address",
          message: ("hot replay-critical artifact lacks content-address evidence: " + .path)
        }),
        ($items[] | select(.retention_class == "hot_replay_critical" and (.path as $path | ($mirror_map[$path] == null))) | {
          code: "missing_mirror_artifact",
          message: ("hot replay-critical artifact is absent from the mirror manifest: " + .path)
        })
      ]
    ) as $validation_errors
  | (
      $items
      | map(select(.replay_critical == true and (.content_address | length) > 0))
      | group_by(.content_address)
      | map(select(length > 1))
    ) as $duplicate_groups
  | (
      $duplicate_groups
      | map(
          . as $group
          | (($group | map(.retention_class) | unique | sort)) as $classes
          | (($group | map(.provenance_key) | unique | sort)) as $provenances
          | (($group | map(.replay_critical) | all)) as $all_replay
          | if ($all_replay | not) then
              {
                decision: "blocked",
                content_address: $group[0].content_address,
                blocked_paths: ($group | map(.path) | unique | sort),
                reason: "replay_role_mismatch",
                retention_classes: $classes,
                provenance_keys: $provenances
              }
            elif (($classes | length) > 1) then
              {
                decision: "blocked",
                content_address: $group[0].content_address,
                blocked_paths: ($group | map(.path) | unique | sort),
                reason: "retention_class_mismatch",
                retention_classes: $classes,
                provenance_keys: $provenances
              }
            elif (($provenances | length) > 1) then
              {
                decision: "blocked",
                content_address: $group[0].content_address,
                blocked_paths: ($group | map(.path) | unique | sort),
                reason: "provenance_mismatch",
                retention_classes: $classes,
                provenance_keys: $provenances
              }
            else
              ($group | map(.path) | unique | sort) as $paths
              | {
                  decision: "compact",
                  content_address: $group[0].content_address,
                  retained_path: $paths[0],
                  compacted_paths: ($paths[1:] // []),
                  retention_class: $classes[0],
                  provenance_key: $provenances[0],
                  reclaimed_artifact_count: (($paths | length) - 1)
                }
            end
        )
    ) as $group_decisions
  | ($group_decisions | map(select(.decision == "compact"))) as $compacted_groups
  | ($group_decisions | map(select(.decision == "blocked"))) as $blocked_groups
  | {
      schema_version: "franken-engine.remote-proof-compaction-plan.v1",
      bundle_id: $residency.bundle_id,
      bundle_decision: $residency.bundle_decision,
      plan_decision: (
        if ($validation_errors | length) == 0 then "pass" else "fail_closed" end
      ),
      reason: (
        if ($validation_errors | length) > 0 then
          "upstream content-address or residency evidence is inconsistent"
        elif ($compacted_groups | length) > 0 then
          "duplicate replay-critical artifacts can be compacted safely"
        elif ($blocked_groups | length) > 0 then
          "duplicate content-address groups were detected but blocked as unsafe"
        else
          "no duplicate replay-critical artifact groups require compaction"
        end
      ),
      grouped_artifact_count: (($duplicate_groups | map(length) | add) // 0),
      compacted_groups: $compacted_groups,
      blocked_groups: $blocked_groups,
      unchanged_replay_artifacts: (
        $items
        | map(select(.replay_critical == true and (.content_address | length) > 0))
        | map(select(.path as $path | any($compacted_groups[]?.compacted_paths[]?; . == $path) | not))
        | map(select(.path as $path | any($compacted_groups[]?.retained_path; . == $path) | not))
        | map(select(.path as $path | any($blocked_groups[]?.blocked_paths[]?; . == $path) | not))
        | map(.path)
        | unique
        | sort
      ),
      compaction_stats: {
        candidate_group_count: ($duplicate_groups | length),
        compacted_group_count: ($compacted_groups | length),
        blocked_group_count: ($blocked_groups | length),
        reclaimed_artifact_count: (($compacted_groups | map(.reclaimed_artifact_count) | add) // 0)
      },
      validation_errors: $validation_errors,
      exit_code: (
        if ($validation_errors | length) == 0 then 0 else 42 end
      )
    }
' >"$plan_core"

input_hash="$(
  jq -n \
    --slurpfile residency "$residency_normalized" \
    --slurpfile mirror "$mirror_normalized" \
    '{
      residency_manifest: ($residency[0]),
      mirror_manifest: ($mirror[0])
    }' | jq -cS . | sha256sum | awk '{print $1}'
)"
plan_hash="$(jq -cS . "$plan_core" | sha256sum | awk '{print $1}')"

jq \
  --arg input_hash "$input_hash" \
  --arg plan_hash "$plan_hash" \
  --arg plan_path "$plan_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg summary_path "$summary_path" \
  --arg residency_manifest_path "$residency_manifest_json" \
  --arg mirror_manifest_path "$mirror_manifest_json" '
  . + {
    plan_id: ("remote-proof-compaction-" + ($plan_hash[0:16])),
    hash_basis: {
      input_hash: $input_hash,
      plan_hash: $plan_hash
    },
    upstream_artifact_paths: {
      residency_manifest_json: $residency_manifest_path,
      mirror_manifest_json: $mirror_manifest_path
    },
    artifact_paths: {
      remote_proof_compaction_plan_json: $plan_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $summary_path
    }
  }
' "$plan_core" >"$plan_tmp"
mv "$plan_tmp" "$plan_path"

write_event "compaction_plan_written" "$(jq -r '.plan_decision + \" / compacted=\" + (.compaction_stats.compacted_group_count | tostring)' "$plan_path")"

{
  printf '# Remote Proof Compaction Planner\n\n'
  printf '%s\n' "- Decision: \`$(jq -r '.plan_decision' "$plan_path")\`"
  printf '%s\n' "- Reason: $(jq -r '.reason' "$plan_path")"
  printf '%s\n' "- Plan ID: \`$(jq -r '.plan_id' "$plan_path")\`"
  printf '%s\n' "- Candidate duplicate groups: \`$(jq -r '.compaction_stats.candidate_group_count' "$plan_path")\`"
  printf '%s\n' "- Compacted groups: \`$(jq -r '.compaction_stats.compacted_group_count' "$plan_path")\`"
  printf '%s\n' "- Blocked groups: \`$(jq -r '.compaction_stats.blocked_group_count' "$plan_path")\`"
  printf '%s\n' "- Reclaimed artifacts: \`$(jq -r '.compaction_stats.reclaimed_artifact_count' "$plan_path")\`"
  printf '\n## Compacted Groups\n\n'
  if jq -e '(.compacted_groups | length) == 0' "$plan_path" >/dev/null; then
    printf '%s\n' '- none'
  else
    jq -r '.compacted_groups[] | "- `" + .content_address + "` retain `" + .retained_path + "` compact `" + (.compacted_paths | join(", ")) + "`"' "$plan_path"
  fi
  printf '\n## Blocked Groups\n\n'
  if jq -e '(.blocked_groups | length) == 0' "$plan_path" >/dev/null; then
    printf '%s\n' '- none'
  else
    jq -r '.blocked_groups[] | "- `" + .content_address + "` blocked: `" + .reason + "` on `" + (.blocked_paths | join(", ")) + "`"' "$plan_path"
  fi
} >"$summary_tmp"
mv "$summary_tmp" "$summary_path"

printf 'remote_proof_compaction_plan=%s\n' "$plan_path"

exit "$(jq -r '.exit_code' "$plan_path")"
