#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
contract_json="${root_dir}/docs/rch_remote_compile_stall_bundle_contract_v1.json"

output_dir=""
bead_id=""
queue_json=""
status_json=""
bead_metadata_json=""
remote_command=""
command_log=""
worker_inventory_json=""
operator_note=""
captured_at_epoch_seconds=""
stall_bundle_id=""
has_command_log=false
has_worker_inventory=false
has_operator_note=false

usage() {
  cat <<'USAGE'
usage: scripts/rch_remote_compile_stall_bundle_capture.sh --output-dir DIR --bead-id ID [options]

Options:
  --queue-json PATH              Use captured `rch queue --json` snapshot
  --status-json PATH             Use captured `rch status --workers --jobs --json` snapshot
  --bead-metadata-json PATH      Use captured `br show <bead_id> --json` snapshot
  --remote-command TEXT          Override primary remote command receipt command
  --command-log PATH             Optional command stderr/stdout excerpt for local-fallback detection
  --worker-inventory-json PATH   Optional `rch workers probe --all --json` snapshot
  --operator-note PATH           Optional operator note markdown/text file
  --captured-at-epoch-seconds N  Deterministic top-level capture timestamp override
  --stall-bundle-id ID           Deterministic bundle id override
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    --bead-id)
      bead_id="${2:-}"
      shift 2
      ;;
    --queue-json)
      queue_json="${2:-}"
      shift 2
      ;;
    --status-json)
      status_json="${2:-}"
      shift 2
      ;;
    --bead-metadata-json)
      bead_metadata_json="${2:-}"
      shift 2
      ;;
    --remote-command)
      remote_command="${2:-}"
      shift 2
      ;;
    --command-log)
      command_log="${2:-}"
      shift 2
      ;;
    --worker-inventory-json)
      worker_inventory_json="${2:-}"
      shift 2
      ;;
    --operator-note)
      operator_note="${2:-}"
      shift 2
      ;;
    --captured-at-epoch-seconds)
      captured_at_epoch_seconds="${2:-}"
      shift 2
      ;;
    --stall-bundle-id)
      stall_bundle_id="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "$output_dir" || -z "$bead_id" ]]; then
  usage >&2
  exit 64
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 2
fi

if [[ ! -f "$contract_json" ]]; then
  echo "contract missing: $contract_json" >&2
  exit 66
fi

for required_path in "$queue_json" "$status_json" "$bead_metadata_json" "$command_log" "$worker_inventory_json" "$operator_note"; do
  if [[ -n "$required_path" && ! -f "$required_path" ]]; then
    echo "input not found: $required_path" >&2
    exit 66
  fi
done

mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

bundle_path="${output_dir}/stall_bundle.json"
events_path="${output_dir}/events.jsonl"
commands_path="${output_dir}/commands.txt"
summary_path="${output_dir}/summary.md"
raw_queue_path="${output_dir}/rch_queue_snapshot.raw.json"
raw_status_path="${output_dir}/rch_status_workers_jobs_snapshot.raw.json"
raw_bead_metadata_path="${output_dir}/bead_metadata.raw.json"
remote_command_receipt_path="${output_dir}/remote_command_receipt.json"
raw_worker_inventory_path="${output_dir}/worker_inventory_snapshot.raw.json"
raw_command_log_path="${output_dir}/command_log_excerpt.txt"
raw_operator_note_path="${output_dir}/operator_note.txt"

for artifact in \
  "$bundle_path" \
  "$events_path" \
  "$commands_path" \
  "$summary_path" \
  "$raw_queue_path" \
  "$raw_status_path" \
  "$raw_bead_metadata_path" \
  "$remote_command_receipt_path"; do
  if [[ -e "$artifact" ]]; then
    echo "refusing to overwrite existing artifact: $artifact" >&2
    exit 73
  fi
done

touch "$commands_path"

capture_json() {
  local provided_path="$1"
  local live_command="$2"
  local destination="$3"

  if [[ -n "$provided_path" ]]; then
    cp "$provided_path" "$destination"
    printf 'fixture:%s\n' "$provided_path" >>"$commands_path"
  else
    printf '%s\n' "$live_command" >>"$commands_path"
    eval "$live_command" >"$destination"
  fi
}

if [[ -z "$bead_metadata_json" ]]; then
  bead_metadata_json="${output_dir}/.live_bead_metadata.json"
  printf 'br show %q --json\n' "$bead_id" >>"$commands_path"
  br show "$bead_id" --json >"$bead_metadata_json"
fi

capture_json "$queue_json" "rch queue --json" "$raw_queue_path"
capture_json "$status_json" "rch status --workers --jobs --json" "$raw_status_path"
cp "$bead_metadata_json" "$raw_bead_metadata_path"
printf 'fixture:%s\n' "$bead_metadata_json" >>"$commands_path"

if [[ -n "$worker_inventory_json" ]]; then
  cp "$worker_inventory_json" "$raw_worker_inventory_path"
  printf 'fixture:%s\n' "$worker_inventory_json" >>"$commands_path"
  has_worker_inventory=true
fi

if [[ -n "$command_log" ]]; then
  cp "$command_log" "$raw_command_log_path"
  printf 'fixture:%s\n' "$command_log" >>"$commands_path"
  has_command_log=true
fi

if [[ -n "$operator_note" ]]; then
  cp "$operator_note" "$raw_operator_note_path"
  printf 'fixture:%s\n' "$operator_note" >>"$commands_path"
  has_operator_note=true
fi

queue_timestamp_epoch="$(
  jq -r '
    def parse_iso_epoch:
      . as $value
      | ($value | sub("\\.[0-9]+(?=[+-Z])"; "")) as $trimmed
      | (
          ($trimmed | fromdateiso8601?)
          // (
            ($trimmed | capture("(?<base>.*?)(?<tz>Z|[+-][0-9]{2}:[0-9]{2})$")?) as $parts
            | if $parts == null then empty
              else (
                $parts.base
                + (
                  if $parts.tz == "Z" then "+0000"
                  else ($parts.tz | sub(":"; ""))
                  end
                )
                | strptime("%Y-%m-%dT%H:%M:%S%z")?
                | mktime?
              )
              end
          )
        );
    def epochish:
      if . == null or . == "" then 0
      elif type == "number" then floor
      elif type == "string" and test("^[0-9]+$") then tonumber
      else (parse_iso_epoch // 0)
      end;
    (.timestamp // .data.timestamp // "") | epochish
  ' "$raw_queue_path"
)"

status_timestamp_epoch="$(
  jq -r '
    def parse_iso_epoch:
      . as $value
      | ($value | sub("\\.[0-9]+(?=[+-Z])"; "")) as $trimmed
      | (
          ($trimmed | fromdateiso8601?)
          // (
            ($trimmed | capture("(?<base>.*?)(?<tz>Z|[+-][0-9]{2}:[0-9]{2})$")?) as $parts
            | if $parts == null then empty
              else (
                $parts.base
                + (
                  if $parts.tz == "Z" then "+0000"
                  else ($parts.tz | sub(":"; ""))
                  end
                )
                | strptime("%Y-%m-%dT%H:%M:%S%z")?
                | mktime?
              )
              end
          )
        );
    def epochish:
      if . == null or . == "" then 0
      elif type == "number" then floor
      elif type == "string" and test("^[0-9]+$") then tonumber
      else (parse_iso_epoch // 0)
      end;
    (.timestamp // .data.timestamp // "") | epochish
  ' "$raw_status_path"
)"

if [[ -z "$captured_at_epoch_seconds" ]]; then
  captured_at_epoch_seconds="$(
    jq -n \
      --argjson queue_epoch "$queue_timestamp_epoch" \
      --argjson status_epoch "$status_timestamp_epoch" \
      '[$queue_epoch, $status_epoch, now | floor] | max'
  )"
fi

if [[ -z "$stall_bundle_id" ]]; then
  stall_bundle_id="rch-remote-compile-stall-${bead_id}-${captured_at_epoch_seconds}"
fi

if [[ -n "$command_log" ]]; then
  local_fallback_observed=false
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326|refusing local fallback' "$command_log"; then
    local_fallback_observed=true
  fi
else
  local_fallback_observed=false
fi

queue_builds_json="$(
  jq -c '
    [
      (.data.active_builds // [])[]
      | {
          build_id: ((.id // "") | tostring),
          worker_id: (.worker_id // ""),
          command: (.command // ""),
          heartbeat_phase: (.heartbeat_phase // ""),
          heartbeat_detail: (.heartbeat_detail // ""),
          last_progress_at: (.last_progress_at // ""),
          progress_age_secs: (.progress_age_secs // 0),
          last_heartbeat_at: (.last_heartbeat_at // "")
        }
    ]
    | sort_by(.build_id, .worker_id)
  ' "$raw_queue_path"
)"

status_builds_json="$(
  jq -c '
    [
      (.data.daemon.active_builds // [])[]
      | {
          build_id: ((.id // "") | tostring),
          worker_id: (.worker_id // ""),
          command: (.command // ""),
          heartbeat_phase: (.heartbeat_phase // ""),
          heartbeat_detail: (.heartbeat_detail // ""),
          last_progress_at: (.last_progress_at // ""),
          progress_age_secs: (.progress_age_secs // 0),
          last_heartbeat_at: (.last_heartbeat_at // "")
        }
    ]
    | sort_by(.build_id, .worker_id)
  ' "$raw_status_path"
)"

worker_inventory_summary_json="$(
  if [[ -n "$worker_inventory_json" ]]; then
    jq -c '
      {
        present: true,
        worker_count: ((.workers // .data.workers // []) | length),
        raw_path: input_filename
      }
    ' "$raw_worker_inventory_path"
  else
    jq -nc '{present:false, worker_count:0, raw_path:null}'
  fi
)"

bead_metadata_summary_json="$(
  jq -c '
    (if type == "array" then .[0] else . end) as $row
    | {
        present: ($row != null),
        bead_id: ($row.id // ""),
        status: ($row.status // ""),
        assignee: ($row.assignee // ""),
        title: ($row.title // "")
      }
  ' "$raw_bead_metadata_path"
)"

remote_command_receipt_json="$(
  jq -n \
    --arg remote_command "$remote_command" \
    --arg bead_id "$bead_id" \
    --arg raw_command_log_path "$raw_command_log_path" \
    --argjson has_command_log "$has_command_log" \
    --argjson local_fallback_observed "$local_fallback_observed" \
    --argjson queue_builds "$queue_builds_json" '
      ($queue_builds[0] // {}) as $primary
      | {
          schema_version: "franken-engine.rch-remote-command-receipt.v1",
          bead_id: $bead_id,
          command: (if ($remote_command | length) > 0 then $remote_command else ($primary.command // "") end),
          source: (if ($remote_command | length) > 0 then "cli_override" else "queue_snapshot" end),
          local_fallback_observed: $local_fallback_observed,
          command_log_excerpt_path: (
            if $has_command_log
            then $raw_command_log_path
            else null
            end
          )
        }
    '
)"
printf '%s\n' "$remote_command_receipt_json" >"$remote_command_receipt_path"

bundle_json="$(
  jq -n \
    --slurpfile contract "$contract_json" \
    --arg stall_bundle_id "$stall_bundle_id" \
    --arg bead_id "$bead_id" \
    --argjson captured_at_epoch_seconds "$captured_at_epoch_seconds" \
    --argjson local_fallback_observed "$local_fallback_observed" \
    --argjson queue_timestamp_epoch "$queue_timestamp_epoch" \
    --argjson status_timestamp_epoch "$status_timestamp_epoch" \
    --arg raw_queue_path "$raw_queue_path" \
    --arg raw_status_path "$raw_status_path" \
    --arg raw_bead_metadata_path "$raw_bead_metadata_path" \
    --arg remote_command_receipt_path "$remote_command_receipt_path" \
    --arg raw_worker_inventory_path "$raw_worker_inventory_path" \
    --arg raw_command_log_path "$raw_command_log_path" \
    --arg raw_operator_note_path "$raw_operator_note_path" \
    --argjson has_command_log "$has_command_log" \
    --argjson has_worker_inventory "$has_worker_inventory" \
    --argjson has_operator_note "$has_operator_note" \
    --arg bundle_path "$bundle_path" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg summary_path "$summary_path" \
    --argjson queue_builds "$queue_builds_json" \
    --argjson status_builds "$status_builds_json" \
    --argjson worker_inventory_summary "$worker_inventory_summary_json" \
    --argjson bead_metadata_summary "$bead_metadata_summary_json" \
    --argjson remote_command_receipt "$remote_command_receipt_json" '
      def parse_iso_epoch($value):
        ($value | sub("\\.[0-9]+(?=[+-Z])"; "")) as $trimmed
        | (
            ($trimmed | fromdateiso8601?)
            // (
              ($trimmed | capture("(?<base>.*?)(?<tz>Z|[+-][0-9]{2}:[0-9]{2})$")?) as $parts
              | if $parts == null then empty
                else (
                  $parts.base
                  + (
                    if $parts.tz == "Z" then "+0000"
                    else ($parts.tz | sub(":"; ""))
                    end
                  )
                  | strptime("%Y-%m-%dT%H:%M:%S%z")?
                  | mktime?
                )
                end
            )
          );
      def epochish($value):
        if $value == null or $value == "" then 0
        elif ($value | type) == "number" then ($value | floor)
        elif ($value | type) == "string" and ($value | test("^[0-9]+$")) then ($value | tonumber)
        else (parse_iso_epoch($value) // 0)
        end;
      def absnum:
        if . < 0 then -. else . end;
      def contradiction_codes($queue_row; $status_row):
        [
          if ($queue_row == null or $status_row == null) then "build_missing_from_one_snapshot" else empty end,
          if ($queue_row != null and $status_row != null and ($queue_row.worker_id // "") != ($status_row.worker_id // "")) then "worker_id_mismatch" else empty end,
          if ($queue_row != null and $status_row != null and ($queue_row.command // "") != ($status_row.command // "")) then "command_mismatch" else empty end,
          if ($queue_row != null and $status_row != null and ($queue_row.heartbeat_phase // "") != ($status_row.heartbeat_phase // "")) then "heartbeat_phase_mismatch" else empty end,
          if ($queue_row != null and $status_row != null and ($queue_row.heartbeat_detail // "") != ($status_row.heartbeat_detail // "")) then "heartbeat_detail_mismatch" else empty end,
          if (
            $queue_row != null and $status_row != null
            and ((($queue_row.progress_age_secs // 0) - ($status_row.progress_age_secs // 0)) | absnum) > 5
          ) then "progress_age_mismatch" else empty end
        ];
      def blocker($code; $detail):
        {code:$code, detail:$detail};
      ($contract[0]) as $contract_doc
      | ($queue_builds | map(.build_id) | map(select(length > 0))) as $queue_ids
      | ($status_builds | map(.build_id) | map(select(length > 0))) as $status_ids
      | (($queue_ids + $status_ids) | unique | sort) as $union_ids
      | (reduce $queue_builds[] as $row ({}; .[$row.build_id] = $row)) as $queue_map
      | (reduce $status_builds[] as $row ({}; .[$row.build_id] = $row)) as $status_map
      | (
          $union_ids
          | map(
              . as $build_id
              | ($queue_map[$build_id] // null) as $queue_row
              | ($status_map[$build_id] // null) as $status_row
              | {
                  build_id: $build_id,
                  queue_present: ($queue_row != null),
                  status_present: ($status_row != null),
                  worker_id: ($queue_row.worker_id // $status_row.worker_id // ""),
                  command: ($queue_row.command // $status_row.command // ""),
                  heartbeat: {
                    phase: ($queue_row.heartbeat_phase // $status_row.heartbeat_phase // ""),
                    detail: ($queue_row.heartbeat_detail // $status_row.heartbeat_detail // ""),
                    last_heartbeat_epoch_seconds: epochish($queue_row.last_heartbeat_at // $status_row.last_heartbeat_at // "")
                  },
                  last_progress_epoch_seconds: epochish($queue_row.last_progress_at // $status_row.last_progress_at // ""),
                  progress_age_seconds: ($queue_row.progress_age_secs // $status_row.progress_age_secs // 0),
                  contradiction_codes: contradiction_codes($queue_row; $status_row)
                }
            )
        ) as $observed_builds
      | ($observed_builds[0] // {
          build_id: "",
          worker_id: "",
          command: ($remote_command_receipt.command // ""),
          heartbeat: {phase:"", detail:"", last_heartbeat_epoch_seconds:0},
          last_progress_epoch_seconds: 0,
          progress_age_seconds: 0,
          contradiction_codes: []
        }) as $primary
      | ([
          if ($bead_metadata_summary.present | not) then blocker("missing_bead_metadata"; "bead metadata snapshot missing") else empty end,
          if (($remote_command_receipt.command // "") | length) == 0 then blocker("missing_command_form"; "remote command receipt is missing the command form") else empty end,
          if (($queue_builds | length) == 0) then blocker("missing_queue_active_builds"; "rch queue snapshot reported no active builds") else empty end,
          if (($status_builds | length) == 0) then blocker("missing_status_active_builds"; "rch status snapshot reported no active builds") else empty end,
          if (($union_ids | length) == 0) then blocker("missing_build_identifiers"; "no shared build identifiers were preserved across queue/status snapshots") else empty end,
          if (($primary.build_id // "") | length) == 0 then blocker("missing_primary_build_id"; "primary stall subject build id is missing") else empty end,
          if (($primary.worker_id // "") | length) == 0 then blocker("missing_primary_worker_id"; "primary stall subject worker id is missing") else empty end,
          if (($primary.heartbeat.phase // "") | length) == 0 then blocker("missing_heartbeat_phase"; "primary stall subject heartbeat phase is missing") else empty end,
          if (($primary.heartbeat.detail // "") | length) == 0 then blocker("missing_heartbeat_detail"; "primary stall subject heartbeat detail is missing") else empty end,
          if ($primary.last_progress_epoch_seconds > $captured_at_epoch_seconds) then blocker("progress_age_timestamp_contradiction"; "last progress timestamp is later than the bundle capture timestamp") else empty end
        ]
        + ($observed_builds | map(.contradiction_codes[]) | unique | map(blocker("queue_status_conflict"; .)))
      ) as $blockers_without_fallback
      | (
          (if $worker_inventory_summary.present then 1 else 0 end)
          + (if $has_command_log then 1 else 0 end)
          + (if $has_operator_note then 1 else 0 end)
        ) as $optional_present_count
      | (3 - $optional_present_count) as $optional_missing_count
      | (
          if $local_fallback_observed then
            $blockers_without_fallback + [blocker("local_fallback_observed"; "rch local fallback markers contaminate remote-only stall truth")]
          elif $optional_missing_count > 0 then
            $blockers_without_fallback + [blocker("optional_snapshot_missing"; "one or more optional snapshots are missing, so the bundle remains advisory degraded evidence")]
          else
            $blockers_without_fallback
          end
        ) as $blockers
      | {
          schema_version: $contract_doc.bundle_schema_version,
          stall_bundle_id: $stall_bundle_id,
          bead_id: $bead_id,
          capture_decision: (
            if $local_fallback_observed then "fail_closed"
            elif ($blockers_without_fallback | length) > 0 then "fail_closed"
            elif ($optional_missing_count > 0) then "captured_degraded"
            else "captured"
            end
          ),
          truth_state: (
            if $local_fallback_observed then "contaminated"
            elif ($blockers_without_fallback | length) > 0 then "blocked"
            elif ($optional_missing_count > 0) then "degraded"
            else "confirmed"
            end
          ),
          captured_at_epoch_seconds: $captured_at_epoch_seconds,
          local_fallback_observed: $local_fallback_observed,
          stall_subject: {
            command: ($remote_command_receipt.command // $primary.command // ""),
            worker_id: ($primary.worker_id // ""),
            build_id: ($primary.build_id // ""),
            heartbeat: $primary.heartbeat,
            last_progress_epoch_seconds: ($primary.last_progress_epoch_seconds // 0),
            progress_age_seconds: ($primary.progress_age_seconds // 0)
          },
          observed_builds: $observed_builds,
          snapshot_health: {
            required_snapshot_count: 4,
            required_present_count: (
              (if $bead_metadata_summary.present then 1 else 0 end)
              + 1
              + 1
              + 1
            ),
            optional_snapshot_count: 3,
            optional_present_count: $optional_present_count,
            optional_missing_count: $optional_missing_count,
            contradictory_snapshot_count: (
              $observed_builds
              | map(select((.contradiction_codes | length) > 0))
              | length
            )
          },
          bead_metadata: $bead_metadata_summary,
          queue_snapshot: {
            capture_command: "rch queue --json",
            captured_at_epoch_seconds: $queue_timestamp_epoch,
            queue_depth: 0,
            active_build_count: ($queue_builds | length),
            active_build_ids: ($queue_builds | map(.build_id)),
            raw_path: $raw_queue_path
          },
          status_snapshot: {
            capture_command: "rch status --workers --jobs --json",
            captured_at_epoch_seconds: $status_timestamp_epoch,
            active_build_count: ($status_builds | length),
            active_build_ids: ($status_builds | map(.build_id)),
            raw_path: $raw_status_path
          },
          worker_inventory_snapshot: $worker_inventory_summary,
          remote_command_receipt: $remote_command_receipt,
          blockers: $blockers,
          artifact_paths: {
            stall_bundle_json: $bundle_path,
            events_jsonl: $events_path,
            commands_txt: $commands_path,
            summary_md: $summary_path,
            bead_metadata_json: $raw_bead_metadata_path,
            remote_command_receipt_json: $remote_command_receipt_path,
            queue_snapshot_raw_json: $raw_queue_path,
            status_snapshot_raw_json: $raw_status_path,
            worker_inventory_snapshot_raw_json: (if $worker_inventory_summary.present then $raw_worker_inventory_path else null end),
            command_log_excerpt_txt: (if $has_command_log then $raw_command_log_path else null end),
            operator_note_txt: (if $has_operator_note then $raw_operator_note_path else null end)
          }
        }
    '
)"

printf '%s\n' "$bundle_json" >"$bundle_path"

jq -c '
  {
    schema_version: "franken-engine.rch-remote-compile-stall-bundle.event.v1",
    event: "stall_bundle_captured",
    bead_id: .bead_id,
    stall_bundle_id: .stall_bundle_id,
    capture_decision: .capture_decision,
    truth_state: .truth_state,
    local_fallback_observed: .local_fallback_observed,
    observed_build_count: (.observed_builds | length),
    contradictory_snapshot_count: .snapshot_health.contradictory_snapshot_count,
    blocker_codes: (.blockers | map(.code))
  }
' "$bundle_path" >"$events_path"

jq -r '
  "# RCH Remote Compile Stall Bundle",
  "",
  ("- Bead: `" + .bead_id + "`"),
  ("- Bundle: `" + .stall_bundle_id + "`"),
  ("- Capture decision: `" + .capture_decision + "`"),
  ("- Truth state: `" + .truth_state + "`"),
  ("- Local fallback observed: `" + (.local_fallback_observed | tostring) + "`"),
  ("- Observed builds: `" + ((.observed_builds | length) | tostring) + "`"),
  "",
  "## Primary Stall Subject",
  "",
  ("- Build id: `" + .stall_subject.build_id + "`"),
  ("- Worker id: `" + .stall_subject.worker_id + "`"),
  ("- Heartbeat phase: `" + .stall_subject.heartbeat.phase + "`"),
  ("- Heartbeat detail: `" + .stall_subject.heartbeat.detail + "`"),
  ("- Progress age seconds: `" + (.stall_subject.progress_age_seconds | tostring) + "`"),
  ("- Command: `" + .stall_subject.command + "`"),
  "",
  "## Blockers",
  "",
  (
    if (.blockers | length) == 0 then
      "- none"
    else
      (.blockers[] | "- `" + .code + "`: " + .detail)
    end
  ),
  "",
  "## Artifact Paths",
  "",
  (.artifact_paths | to_entries[] | "- `" + .key + "`: `" + ((.value // "null") | tostring) + "`")
' "$bundle_path" >"$summary_path"

printf 'rch_remote_compile_stall_bundle=%s\n' "$bundle_path"

truth_state="$(jq -r '.truth_state' "$bundle_path")"
if [[ "$truth_state" == "blocked" || "$truth_state" == "contaminated" ]]; then
  exit 42
fi
