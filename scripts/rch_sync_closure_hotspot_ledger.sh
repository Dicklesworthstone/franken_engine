#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${RCH_SYNC_CLOSURE_HOTSPOT_LEDGER_ARTIFACT_ROOT:-artifacts/rch_sync_closure_hotspot_ledger}"
run_id="${RCH_SYNC_CLOSURE_HOTSPOT_LEDGER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${RCH_SYNC_CLOSURE_HOTSPOT_LEDGER_RUN_DIR:-${artifact_root}/${run_id}}"
suite_manifest_json=""
transfer_log_jsonl=""
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/rch_sync_closure_hotspot_ledger.sh --suite-manifest-json FILE [OPTIONS]

Build a deterministic sync-closure hotspot ledger from preserved remote-proof
suite manifests and transfer logs. This script is classifier-only: it does not
query live rch state or execute proof commands.

Required:
  --suite-manifest-json FILE

Optional:
  --transfer-log-jsonl FILE
  --output-dir DIR

Artifacts:
  sync_closure_hotspots.json
  sync_closure_summary.md
  commands.txt
  events.jsonl

Behavior:
  - Missing transfer logs produce a degraded ledger instead of failing open.
  - Invalid JSON or missing required manifest input exits 64.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --suite-manifest-json)
      suite_manifest_json="${2:-}"
      shift 2
      ;;
    --transfer-log-jsonl)
      transfer_log_jsonl="${2:-}"
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

if [[ -z "$suite_manifest_json" ]]; then
  printf 'sync closure hotspot ledger requires --suite-manifest-json\n' >&2
  usage
  exit 64
fi

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for sync closure hotspot ledger generation\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for sync closure hotspot ledger generation\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
ledger_path="${run_dir}/sync_closure_hotspots.json"
ledger_tmp="${ledger_path}.tmp"
summary_path="${run_dir}/sync_closure_summary.md"
summary_tmp="${summary_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
manifest_normalized="${run_dir}/suite_manifest.normalized.json"
transfer_rows="${run_dir}/transfer_rows.normalized.json"
ledger_core="${run_dir}/ledger_core.json"
: >"$events_path"

printf './scripts/rch_sync_closure_hotspot_ledger.sh' >"$commands_path"
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

if [[ ! -f "$suite_manifest_json" ]]; then
  printf 'sync closure hotspot ledger missing suite manifest JSON: %s\n' "$suite_manifest_json" >&2
  exit 64
fi
if ! jq empty "$suite_manifest_json" >/dev/null 2>&1; then
  printf 'sync closure hotspot ledger invalid suite manifest JSON: %s\n' "$suite_manifest_json" >&2
  exit 64
fi

jq -cS '
  {
    schema_version: (.schema_version // "unknown"),
    suite_id: (.suite_id // .suite // "unknown"),
    commands: (
      (.commands // [])
      | if type == "array" then . else [] end
      | map({
          command_id: (.command_id // .id // .requested_command // .command // "unknown"),
          bead_id: (.bead_id // .issue_id // ""),
          worker_id: (.worker_id // .worker // ""),
          requested_command: (.requested_command // .command // "")
        })
      | sort_by(.command_id, .bead_id, .requested_command)
    )
  }
' "$suite_manifest_json" >"$manifest_normalized"
write_event "suite_manifest_loaded" "normalized suite manifest"

analysis_status="ok"
degradation_reason=""
transfer_log_status="provided"

if [[ -z "$transfer_log_jsonl" ]]; then
  printf '[]\n' >"$transfer_rows"
  analysis_status="degraded"
  degradation_reason="missing_transfer_log"
  transfer_log_status="missing"
  write_event "transfer_log_missing" "no preserved transfer log was supplied"
else
  if [[ ! -f "$transfer_log_jsonl" ]]; then
    printf 'sync closure hotspot ledger missing transfer log JSONL: %s\n' "$transfer_log_jsonl" >&2
    exit 64
  fi
  if ! jq -cs '
    map(
      {
        suite_id: (.suite_id // .manifest_id // .suite // "unknown"),
        command_id: (.command_id // .plan_command_id // .command // .requested_command // "unknown"),
        worker_id: (.worker_id // .worker // .host // "unknown"),
        transfer_bytes: (
          (.transfer_bytes // .bytes_transferred // .sync_bytes // 0)
          | if type == "number" then . else 0 end
        ),
        closure_roots: (
          (.closure_roots // .sync_closure_roots // .roots // .transferred_roots // [])
          | if type == "array" then map(tostring) | unique | sort else [] end
        )
      }
      | .root_count = (.closure_roots | length)
      | .closure_class = (if .root_count >= 16 then "full" else "narrow" end)
    )
    | map(select(.root_count > 0))
    | sort_by(.command_id, .worker_id, .suite_id)
  ' "$transfer_log_jsonl" >"$transfer_rows"; then
    printf 'sync closure hotspot ledger invalid transfer log JSONL: %s\n' "$transfer_log_jsonl" >&2
    exit 64
  fi
  write_event "transfer_log_loaded" "normalized preserved transfer log rows"
fi

jq -n \
  --arg analysis_status "$analysis_status" \
  --arg degradation_reason "$degradation_reason" \
  --arg transfer_log_status "$transfer_log_status" \
  --slurpfile manifest "$manifest_normalized" \
  --slurpfile rows "$transfer_rows" '
  ($manifest[0]) as $manifest
  | ($rows[0] // []) as $rows
  | (
      [
        $rows[] as $row
        | $row.closure_roots[]
        | {
            root: .,
            command_id: $row.command_id,
            suite_id: $row.suite_id,
            worker_id: $row.worker_id,
            closure_class: $row.closure_class
          }
      ]
    ) as $root_hits
  | (
      $root_hits
      | group_by(.root)
      | map({
          root: .[0].root,
          occurrence_count: length,
          full_sync_hits: (map(select(.closure_class == "full")) | length),
          narrow_sync_hits: (map(select(.closure_class == "narrow")) | length),
          commands: (map(.command_id) | unique | sort),
          suites: (map(.suite_id) | unique | sort),
          workers: (map(.worker_id) | unique | sort)
        })
      | map(.sort_key = [-(.occurrence_count), -(.full_sync_hits), -(.narrow_sync_hits), .root])
      | sort_by(.sort_key)
      | map(del(.sort_key))
    ) as $hotspots
  | {
      schema_version: "franken-engine.rch-sync-closure-hotspot-ledger.v1",
      analysis_status: $analysis_status,
      degradation_reason: (
        if $analysis_status == "degraded" then
          $degradation_reason
        else
          null
        end
      ),
      suite_manifest_status: "provided",
      transfer_log_status: $transfer_log_status,
      suite_id: ($manifest.suite_id // "unknown"),
      manifest_command_count: ($manifest.commands | length),
      logged_command_count: ($rows | length),
      total_unique_roots: ($hotspots | length),
      repeated_hotspot_count: ($hotspots | map(select(.occurrence_count > 1)) | length),
      total_full_sync_commands: ($rows | map(select(.closure_class == "full")) | length),
      total_narrow_sync_commands: ($rows | map(select(.closure_class == "narrow")) | length),
      unobserved_command_ids: (
        [ $manifest.commands[]?.command_id ] as $manifest_ids
        | [ $rows[]?.command_id ] as $logged_ids
        | ($manifest_ids - $logged_ids | unique | sort)
      ),
      command_summaries: (
        $rows
        | map({
            command_id,
            suite_id,
            worker_id,
            closure_class,
            root_count,
            transfer_bytes,
            closure_roots
          })
      ),
      hotspots: $hotspots
    }
' >"$ledger_core"

input_hash="$(
  jq -n --slurpfile manifest "$manifest_normalized" --slurpfile rows "$transfer_rows" '
    {
      suite_manifest: ($manifest[0]),
      transfer_rows: ($rows[0] // [])
    }
  ' | jq -cS . | sha256sum | awk '{print $1}'
)"

ledger_hash="$(jq -cS . "$ledger_core" | sha256sum | awk '{print $1}')"

jq \
  --arg input_hash "$input_hash" \
  --arg ledger_hash "$ledger_hash" \
  --arg ledger_path "$ledger_path" \
  --arg summary_path "$summary_path" \
  --arg commands_path "$commands_path" \
  --arg events_path "$events_path" '
  . + {
    hash_basis: {
      input_hash: $input_hash,
      ledger_hash: $ledger_hash
    },
    artifact_paths: {
      sync_closure_hotspots_json: $ledger_path,
      sync_closure_summary_md: $summary_path,
      commands_txt: $commands_path,
      events_jsonl: $events_path
    }
  }
' "$ledger_core" >"$ledger_tmp"
mv "$ledger_tmp" "$ledger_path"

{
  printf '# RCH Sync Closure Hotspot Ledger\n\n'
  printf -- '- Analysis status: %s\n' "$(jq -r '.analysis_status' "$ledger_path")"
  printf -- '- Degradation reason: %s\n' "$(jq -r '.degradation_reason // "none"' "$ledger_path")"
  printf -- '- Suite ID: %s\n' "$(jq -r '.suite_id' "$ledger_path")"
  printf -- '- Transfer log status: %s\n' "$(jq -r '.transfer_log_status' "$ledger_path")"
  printf -- '- Manifest commands: %s\n' "$(jq -r '.manifest_command_count' "$ledger_path")"
  printf -- '- Logged sync commands: %s\n' "$(jq -r '.logged_command_count' "$ledger_path")"
  printf -- '- Unique roots: %s\n' "$(jq -r '.total_unique_roots' "$ledger_path")"
  printf -- '- Repeated hotspots: %s\n' "$(jq -r '.repeated_hotspot_count' "$ledger_path")"
  printf -- '- Input hash: `%s`\n' "$(jq -r '.hash_basis.input_hash' "$ledger_path")"
  printf -- '- Ledger hash: `%s`\n' "$(jq -r '.hash_basis.ledger_hash' "$ledger_path")"
  printf '\n## Top Hotspots\n\n'
  jq -r '
    if (.hotspots | length) == 0 then
      "_No sync hotspots observed._"
    else
      (
        [
          "| Root | Occurrences | Full | Narrow | Commands |",
          "| --- | ---: | ---: | ---: | --- |"
        ]
        + (
          .hotspots[:10]
          | map(
              "| \(.root) | \(.occurrence_count) | \(.full_sync_hits) | \(.narrow_sync_hits) | \(.commands | join(", ")) |"
            )
        )
      ) | join("\n")
    end
  ' "$ledger_path"
} >"$summary_tmp"
mv "$summary_tmp" "$summary_path"

write_event "ledger_written" "wrote sync closure hotspot ledger artifacts"
