#!/usr/bin/env bash
set -euo pipefail

artifact_root="${REMOTE_PROOF_ARCHIVE_EXPORTER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-remote-proof-archive-exporter}"
run_id="${REMOTE_PROOF_ARCHIVE_EXPORTER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${REMOTE_PROOF_ARCHIVE_EXPORTER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

residency_manifest_json=""
compaction_plan_json=""
archive_source_files_json=""
archive_pack_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/remote_proof_archive_exporter.sh --residency-manifest-json FILE --compaction-plan-json FILE [OPTIONS]

Export retained remote-proof evidence into a replay-ready archive pack and
verify that the exported or preserved pack can restore the required replay set
deterministically.

Required:
  --residency-manifest-json FILE
  --compaction-plan-json FILE

Optional:
  --archive-source-files-json FILE  Generate a new archive pack from this source inventory.
  --archive-pack-json FILE          Verify a preserved archive pack instead of generating one.
  --output-dir DIR

At least one of --archive-source-files-json or --archive-pack-json must be
provided.

Artifacts:
  archive_pack.json
  restore_verification_report.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   archive pack is replay-ready and restore verification passed
  42  fail-closed due to missing replay evidence, tampered pack, or drift
  64  invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --residency-manifest-json)
      residency_manifest_json="${2:-}"
      shift 2
      ;;
    --compaction-plan-json)
      compaction_plan_json="${2:-}"
      shift 2
      ;;
    --archive-source-files-json)
      archive_source_files_json="${2:-}"
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

if [[ -z "$residency_manifest_json" || -z "$compaction_plan_json" ]]; then
  printf 'remote proof archive exporter requires --residency-manifest-json and --compaction-plan-json\n' >&2
  usage
  exit 64
fi
if [[ -z "$archive_source_files_json" && -z "$archive_pack_json" ]]; then
  printf 'remote proof archive exporter requires --archive-source-files-json or --archive-pack-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for remote proof archive export\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for remote proof archive export\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
pack_path="${run_dir}/archive_pack.json"
pack_tmp="${pack_path}.tmp"
report_path="${run_dir}/restore_verification_report.json"
report_tmp="${report_path}.tmp"
summary_path="${run_dir}/report.md"
summary_tmp="${summary_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
residency_normalized="${run_dir}/residency_manifest.normalized.json"
compaction_normalized="${run_dir}/compaction_plan.normalized.json"
source_files_normalized="${run_dir}/archive_source_files.normalized.json"
pack_normalized="${run_dir}/archive_pack.normalized.json"
expected_core="${run_dir}/expected_archive.core.json"
pack_core="${run_dir}/archive_pack.core.json"
report_core="${run_dir}/restore_verification.core.json"
: >"$events_path"

printf './scripts/remote_proof_archive_exporter.sh' >"$commands_path"
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
    printf 'remote proof archive exporter missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'remote proof archive exporter invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
}

normalize_required_json "$residency_manifest_json" "$residency_normalized" "residency manifest"
normalize_required_json "$compaction_plan_json" "$compaction_normalized" "compaction plan"
if [[ -n "$archive_source_files_json" ]]; then
  normalize_required_json "$archive_source_files_json" "$source_files_normalized" "archive source files"
else
  printf '%s\n' '{"source_files":[]}' >"$source_files_normalized"
fi
if [[ -n "$archive_pack_json" ]]; then
  normalize_required_json "$archive_pack_json" "$pack_normalized" "archive pack"
fi

jq -cS '
  {
    bundle_id: (.bundle_id // "unknown"),
    retention_entries: (
      (.retention_entries // [])
      | if type == "array" then . else [] end
      | map({
          path: (.path // ""),
          retention_class: (.retention_class // "unknown"),
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
  {
    bundle_id: (.bundle_id // "unknown"),
    compacted_groups: (
      (.compacted_groups // [])
      | if type == "array" then . else [] end
      | map({
          content_address: (.content_address // ""),
          retained_path: (.retained_path // ""),
          compacted_paths: (
            (.compacted_paths // [])
            | if type == "array" then map(tostring) else [] end
            | unique
            | sort
          )
        })
      | sort_by(.content_address, .retained_path)
    ),
    blocked_groups: (
      (.blocked_groups // [])
      | if type == "array" then . else [] end
      | map({
          content_address: (.content_address // ""),
          blocked_paths: (
            (.blocked_paths // [])
            | if type == "array" then map(tostring) else [] end
            | unique
            | sort
          ),
          reason: (.reason // "unknown")
        })
      | sort_by(.content_address, .reason)
    ),
    artifact_paths: (.artifact_paths // {})
  }
' "$compaction_normalized" >"${compaction_normalized}.tmp"
mv "${compaction_normalized}.tmp" "$compaction_normalized"
write_event "compaction_plan_loaded" "normalized compaction plan"

if [[ -n "$archive_source_files_json" ]]; then
  jq -cS '
    {
      source_files: (
        if (.source_files | type) == "array" then .source_files
        elif (.artifacts | type) == "array" then .artifacts
        elif type == "array" then .
        else []
        end
        | map({
            path: (.path // ""),
            content_address: (
              if (.content_address // "") | length > 0 then .content_address
              elif (.sha256 // "") | length > 0 then "sha256:" + (.sha256 | ascii_downcase)
              else ""
              end
            ),
            roles: (
              (.roles // [])
              | if type == "array" then map(tostring) else [] end
              | unique
              | sort
            ),
            replay_critical: (.replay_critical // false),
            size_bytes: (.size_bytes // 0)
          })
        | sort_by(.path, .content_address)
      )
    }
  ' "$source_files_normalized" >"${source_files_normalized}.tmp"
  mv "${source_files_normalized}.tmp" "$source_files_normalized"
  write_event "archive_source_files_loaded" "normalized archive source inventory"
fi

build_expected_archive_core() {
  local require_source_presence
  if [[ -n "$archive_source_files_json" ]]; then
    require_source_presence=true
  else
    require_source_presence=false
  fi

  jq -n \
    --argjson require_source_presence "$require_source_presence" \
    --slurpfile residency "$residency_normalized" \
    --slurpfile compaction "$compaction_normalized" \
    --slurpfile source "$source_files_normalized" '
    def first_address($entry):
      if (($entry.content_addresses // []) | length) > 0 then
        $entry.content_addresses[0]
      else
        ""
      end;
    ($residency[0]) as $residency
    | ($compaction[0]) as $compaction
    | (($source[0].source_files // [])) as $source_files
    | (
        reduce ($compaction.compacted_groups // [])[] as $group ({};
          .[$group.retained_path] = {
            content_address: $group.content_address,
            compacted_paths: ($group.compacted_paths // [])
          }
        )
      ) as $retain_map
    | (
        reduce ($compaction.compacted_groups // [])[] as $group ({};
          reduce ($group.compacted_paths // [])[] as $path (.;
            .[$path] = $group.retained_path
          )
        )
      ) as $compacted_path_map
    | (
        reduce $source_files[] as $item ({};
          .[$item.path] = $item
        )
      ) as $source_map
    | ($residency.retention_entries // []) as $entries
    | (
        $entries
        | map(
            . as $entry
            | ($compacted_path_map[$entry.path] // $entry.path) as $archive_path
            | {
                original_path: $entry.path,
                archive_path: $archive_path,
                retention_class: $entry.retention_class,
                roles: $entry.roles,
                replay_critical: $entry.replay_critical,
                content_address: (
                  if ($retain_map[$archive_path].content_address // "") | length > 0 then
                    $retain_map[$archive_path].content_address
                  else
                    first_address($entry)
                  end
                ),
                source_file: (
                  if $source_map[$archive_path] != null then $source_map[$archive_path]
                  elif $source_map[$entry.path] != null then $source_map[$entry.path]
                  else null
                  end
                )
              }
          )
      ) as $candidate_items
    | (
        $candidate_items
        | map(
            select(
              (.content_address | length) > 0
              and (
                if $require_source_presence then
                  .source_file != null
                else
                  true
                end
              )
            )
          )
        | group_by(.archive_path)
        | map({
            path: .[0].archive_path,
            original_paths: (map(.original_path) | unique | sort),
            retention_class: ((map(.retention_class) | unique | sort) | .[0]),
            roles: (map(.roles[]) | unique | sort),
            replay_critical: any(.[]; .replay_critical),
            content_address: .[0].content_address,
            size_bytes: (first(map(.source_file.size_bytes // 0)) // 0)
          })
        | sort_by(.path, .content_address)
    ) as $archived_artifacts
    | (
        $candidate_items
        | map(select(.replay_critical == true and (.content_address | length) > 0))
        | map(.archive_path)
        | unique
        | sort
      ) as $required_replay_paths
    | {
        bundle_id: $residency.bundle_id,
        archived_artifacts: $archived_artifacts,
        required_replay_paths: $required_replay_paths,
        blocked_compaction_groups: ($compaction.blocked_groups // []),
        archive_artifact_count: ($archived_artifacts | length)
      }
  ' >"$expected_core"
}

build_expected_archive_core
write_event "expected_archive_built" "derived expected archive selection from residency manifest and compaction plan"

if [[ -z "$archive_pack_json" ]]; then
  jq -n \
    --slurpfile expected "$expected_core" '
    ($expected[0]) as $expected
    | {
        schema_version: "franken-engine.remote-proof-archive-pack.v1",
        bundle_id: $expected.bundle_id,
        archive_state: "cold_archived",
        archived_artifacts: $expected.archived_artifacts,
        required_replay_paths: $expected.required_replay_paths,
        blocked_compaction_groups: $expected.blocked_compaction_groups,
        archive_artifact_count: $expected.archive_artifact_count
      }
  ' >"$pack_core"

  archive_manifest_hash=""
  jq \
    --arg archive_manifest_hash "$archive_manifest_hash" \
    --arg pack_path "$pack_path" \
    --arg report_path "$report_path" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg summary_path "$summary_path" \
    --arg residency_manifest_path "$residency_manifest_json" \
    --arg compaction_plan_path "$compaction_plan_json" \
    --arg archive_source_files_path "$archive_source_files_json" '
    . + {
      restore_verdict: "unverified",
      hash_basis: {
        archive_manifest_hash: $archive_manifest_hash
      },
      upstream_artifact_paths: {
        residency_manifest_json: $residency_manifest_path,
        compaction_plan_json: $compaction_plan_path,
        archive_source_files_json: $archive_source_files_path
      },
      artifact_paths: {
        archive_pack_json: $pack_path,
        restore_verification_report_json: $report_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $summary_path
      }
    }
  ' "$pack_core" >"$pack_tmp"
  mv "$pack_tmp" "$pack_path"
  normalize_required_json "$pack_path" "$pack_normalized" "generated archive pack"
  write_event "archive_pack_written" "generated archive pack from source inventory"
else
  write_event "archive_pack_loaded" "using preserved archive pack for restore verification"
fi

jq -cS '
  {
    schema_version: (.schema_version // "unknown"),
    bundle_id: (.bundle_id // "unknown"),
    archive_state: (.archive_state // "unknown"),
    restore_verdict: (.restore_verdict // "unknown"),
    archived_artifacts: (
      (.archived_artifacts // [])
      | if type == "array" then . else [] end
      | map({
          path: (.path // ""),
          original_paths: (
            (.original_paths // [])
            | if type == "array" then map(tostring) else [] end
            | unique
            | sort
          ),
          retention_class: (.retention_class // "unknown"),
          roles: (
            (.roles // [])
            | if type == "array" then map(tostring) else [] end
            | unique
            | sort
          ),
          replay_critical: (.replay_critical // false),
          content_address: (.content_address // "")
        })
      | sort_by(.path, .content_address)
    ),
    required_replay_paths: (
      (.required_replay_paths // [])
      | if type == "array" then map(tostring) else [] end
      | unique
      | sort
    ),
    blocked_compaction_groups: (
      (.blocked_compaction_groups // [])
      | if type == "array" then . else [] end
      | map({
          content_address: (.content_address // ""),
          blocked_paths: (
            (.blocked_paths // [])
            | if type == "array" then map(tostring) else [] end
            | unique
            | sort
          ),
          reason: (.reason // "unknown")
        })
      | sort_by(.content_address, .reason)
    ),
    archive_artifact_count: (.archive_artifact_count // 0),
    hash_basis: (.hash_basis // {}),
    upstream_artifact_paths: (.upstream_artifact_paths // {}),
    artifact_paths: (.artifact_paths // {})
  }
' "$pack_normalized" >"${pack_normalized}.tmp"
mv "${pack_normalized}.tmp" "$pack_normalized"

if [[ -z "$archive_pack_json" ]]; then
  archive_manifest_hash="$(
    jq -cS '{
        schema_version: .schema_version,
        bundle_id: .bundle_id,
        archive_state: .archive_state,
        archived_artifacts: .archived_artifacts,
        required_replay_paths: .required_replay_paths,
        blocked_compaction_groups: .blocked_compaction_groups,
        archive_artifact_count: .archive_artifact_count
      }' "$pack_normalized" | sha256sum | awk '{print $1}'
  )"
  jq \
    --arg archive_manifest_hash "$archive_manifest_hash" '
    .hash_basis.archive_manifest_hash = $archive_manifest_hash
  ' "$pack_normalized" >"${pack_normalized}.hashed"
  mv "${pack_normalized}.hashed" "$pack_normalized"
  cp "$pack_normalized" "$pack_path"
fi

archive_manifest_hash_actual="$(
  jq -cS '{
      schema_version: .schema_version,
      bundle_id: .bundle_id,
      archive_state: .archive_state,
      archived_artifacts: .archived_artifacts,
      required_replay_paths: .required_replay_paths,
      blocked_compaction_groups: .blocked_compaction_groups,
      archive_artifact_count: .archive_artifact_count
    }' "$pack_normalized" | sha256sum | awk '{print $1}'
)"

jq -n \
  --arg actual_archive_manifest_hash "$archive_manifest_hash_actual" \
  --slurpfile expected "$expected_core" \
  --slurpfile pack "$pack_normalized" '
  ($expected[0]) as $expected
  | ($pack[0]) as $pack
  | (($expected.required_replay_paths // []) - (($pack.archived_artifacts // []) | map(select(.replay_critical == true) | .path) | unique | sort)) as $missing_replay_paths
  | ((($pack.archived_artifacts // []) | map(.path) | unique | sort) - (($expected.archived_artifacts // []) | map(.path) | unique | sort)) as $unexpected_paths
  | ((($expected.archived_artifacts // []) | map(.path) | unique | sort) - (($pack.archived_artifacts // []) | map(.path) | unique | sort)) as $missing_expected_paths
  | (($pack.hash_basis.archive_manifest_hash // "") != $actual_archive_manifest_hash) as $tampered_hash
  | (
      if (($pack.bundle_id // "unknown") != ($expected.bundle_id // "unknown")) then
        {
          restore_verdict: "fail_closed",
          reason: "archive pack bundle_id does not match expected residency bundle",
          exit_code: 42
        }
      elif (($missing_replay_paths | length) > 0) then
        {
          restore_verdict: "fail_closed",
          reason: "archive pack is missing replay-critical artifacts",
          exit_code: 42
        }
      elif (($missing_expected_paths | length) > 0) then
        {
          restore_verdict: "fail_closed",
          reason: "archive pack is missing expected retained artifacts",
          exit_code: 42
        }
      elif (($unexpected_paths | length) > 0) then
        {
          restore_verdict: "fail_closed",
          reason: "archive pack contains unexpected artifact paths",
          exit_code: 42
        }
      elif $tampered_hash then
        {
          restore_verdict: "fail_closed",
          reason: "archive pack manifest hash does not match its actual contents",
          exit_code: 42
        }
      else
        {
          restore_verdict: "verified",
          reason: "archive pack covers the expected retained artifacts and its manifest hash is stable",
          exit_code: 0
        }
      end
    ) as $decision
  | {
      schema_version: "franken-engine.remote-proof-archive-restore-verification.v1",
      bundle_id: $expected.bundle_id,
      restore_verdict: $decision.restore_verdict,
      reason: $decision.reason,
      missing_replay_paths: $missing_replay_paths,
      missing_expected_paths: $missing_expected_paths,
      unexpected_paths: $unexpected_paths,
      tampered_manifest_hash: $tampered_hash,
      archive_state: ($pack.archive_state // "unknown"),
      exit_code: $decision.exit_code
    }
' >"$report_core"

verification_hash="$(jq -cS . "$report_core" | sha256sum | awk '{print $1}')"
jq \
  --arg verification_hash "$verification_hash" \
  --arg report_path "$report_path" \
  --arg pack_path "$pack_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg summary_path "$summary_path" \
  --arg residency_manifest_path "$residency_manifest_json" \
  --arg compaction_plan_path "$compaction_plan_json" \
  --arg archive_source_files_path "$archive_source_files_json" \
  --arg archive_pack_input_path "$archive_pack_json" '
  . + {
    hash_basis: {
      verification_hash: $verification_hash
    },
    upstream_artifact_paths: {
      residency_manifest_json: $residency_manifest_path,
      compaction_plan_json: $compaction_plan_path,
      archive_source_files_json: $archive_source_files_path,
      archive_pack_input_json: $archive_pack_input_path
    },
    artifact_paths: {
      archive_pack_json: $pack_path,
      restore_verification_report_json: $report_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $summary_path
    }
  }
' "$report_core" >"$report_tmp"
mv "$report_tmp" "$report_path"

if jq -e '.restore_verdict == "verified"' "$report_path" >/dev/null; then
  jq '.restore_verdict = "verified"' "$pack_normalized" >"${pack_tmp}.verified"
  mv "${pack_tmp}.verified" "$pack_path"
else
  cp "$pack_normalized" "$pack_path"
fi

write_event "restore_verification_written" "$(jq -r '.restore_verdict + " / " + .reason' "$report_path")"

{
  printf '# Remote Proof Archive Exporter\n\n'
  printf '%s\n' "- Restore verdict: \`$(jq -r '.restore_verdict' "$report_path")\`"
  printf '%s\n' "- Reason: $(jq -r '.reason' "$report_path")"
  printf '%s\n' "- Bundle ID: \`$(jq -r '.bundle_id' "$report_path")\`"
  printf '%s\n' "- Archive state: \`$(jq -r '.archive_state' "$report_path")\`"
  printf '%s\n' "- Missing replay paths: \`$(jq -r '(.missing_replay_paths | length)' "$report_path")\`"
  printf '%s\n' "- Unexpected paths: \`$(jq -r '(.unexpected_paths | length)' "$report_path")\`"
  printf '%s\n' "- Tampered manifest hash: \`$(jq -r '.tampered_manifest_hash' "$report_path")\`"
} >"$summary_tmp"
mv "$summary_tmp" "$summary_path"

printf 'remote_proof_archive_pack=%s\n' "$pack_path"
printf 'remote_proof_archive_restore_verification=%s\n' "$report_path"

exit "$(jq -r '.exit_code' "$report_path")"
