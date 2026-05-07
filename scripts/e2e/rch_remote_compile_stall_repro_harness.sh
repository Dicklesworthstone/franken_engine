#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
capture_script="${root_dir}/scripts/rch_remote_compile_stall_bundle_capture.sh"
output_dir=""
case_id="cargo-check-lib"
bead_id="bd-wi6n3"
timeout_seconds="${RCH_REMOTE_COMPILE_STALL_REPRO_TIMEOUT_SECONDS:-900}"
stall_progress_age_threshold_seconds="${RCH_REMOTE_COMPILE_STALL_STALE_PROGRESS_SECONDS:-300}"
fresh_heartbeat_age_threshold_seconds="${RCH_REMOTE_COMPILE_STALL_FRESH_HEARTBEAT_SECONDS:-30}"
queue_json=""
status_json=""
bead_metadata_json=""
command_log=""
worker_inventory_json=""
operator_note=""
captured_at_epoch_seconds=""
remote_command_override=""

usage() {
  cat <<'USAGE'
usage: scripts/e2e/rch_remote_compile_stall_repro_harness.sh --output-dir DIR [options]

Options:
  --case-id ID                    one of: cargo-check-lib, focused-engine-test
  --bead-id ID                    bead identifier for captured artifacts
  --timeout-seconds N             timeout for live remote execution
  --stall-progress-age-seconds N  threshold for fresh-heartbeat/frozen-progress stall
  --fresh-heartbeat-age-seconds N threshold for fresh heartbeat detection
  --queue-json PATH               fixture queue snapshot
  --status-json PATH              fixture status snapshot
  --bead-metadata-json PATH       fixture bead metadata snapshot
  --command-log PATH              fixture or override command log
  --worker-inventory-json PATH    optional fixture worker inventory snapshot
  --operator-note PATH            optional operator note
  --captured-at-epoch-seconds N   deterministic capture timestamp override
  --remote-command TEXT           override canonical command string
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    --case-id)
      case_id="${2:-}"
      shift 2
      ;;
    --bead-id)
      bead_id="${2:-}"
      shift 2
      ;;
    --timeout-seconds)
      timeout_seconds="${2:-}"
      shift 2
      ;;
    --stall-progress-age-seconds)
      stall_progress_age_threshold_seconds="${2:-}"
      shift 2
      ;;
    --fresh-heartbeat-age-seconds)
      fresh_heartbeat_age_threshold_seconds="${2:-}"
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
    --remote-command)
      remote_command_override="${2:-}"
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

if [[ -z "$output_dir" ]]; then
  usage >&2
  exit 64
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 2
fi

for input_path in "$queue_json" "$status_json" "$bead_metadata_json" "$command_log" "$worker_inventory_json" "$operator_note"; do
  if [[ -n "$input_path" && ! -f "$input_path" ]]; then
    echo "input not found: $input_path" >&2
    exit 66
  fi
done

mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report_path="${output_dir}/repro_report.json"
events_path="${output_dir}/events.jsonl"
commands_path="${output_dir}/commands.txt"
summary_path="${output_dir}/summary.md"
harness_log_path="${output_dir}/remote_command.log"
bundle_dir="${output_dir}/stall_bundle"

for artifact in "$report_path" "$events_path" "$commands_path" "$summary_path" "$harness_log_path"; do
  if [[ -e "$artifact" ]]; then
    echo "refusing to overwrite existing artifact: $artifact" >&2
    exit 73
  fi
done

canonical_command() {
  case "$1" in
    cargo-check-lib)
      printf '%s\n' "rch exec -- env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=/data/tmp/rch_target_franken_engine_stall_check CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 cargo check -p frankenengine-engine --lib"
      ;;
    focused-engine-test)
      printf '%s\n' "rch exec -- env RUSTUP_TOOLCHAIN=nightly RUSTFLAGS='-Cdebuginfo=0' CARGO_TARGET_DIR=/data/tmp/rch_target_franken_engine_stall_test CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 cargo test -p frankenengine-engine replacement_lineage_log::tests:: --lib"
      ;;
    *)
      printf 'unknown case-id: %s\n' "$1" >&2
      exit 64
      ;;
  esac
}

log_has_local_fallback() {
  local path="$1"
  grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326|refusing local fallback' "$path"
}

log_has_ssh_timeout() {
  local path="$1"
  grep -Eiq 'SSH timeout|SSH command timed out|Remote execution failed on .* with SSH timeout' "$path"
}

selected_worker_from_log() {
  local path="$1"
  sed -n 's/.*Selected worker: \([^ ]*\).*/\1/p' "$path" | tail -n1
}

remote_exit_code_from_log() {
  local path="$1"
  local marker
  marker="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$path" | tail -n1 || true)"
  if [[ -n "$marker" ]]; then
    printf '%s\n' "$marker"
  fi
}

remote_command_text="${remote_command_override:-$(canonical_command "$case_id")}"

{
  printf 'case_id=%s\n' "$case_id"
  printf 'canonical_remote_command=%s\n' "$remote_command_text"
} >"$commands_path"

fixture_mode=false
if [[ -n "$queue_json" || -n "$status_json" || -n "$bead_metadata_json" || -n "$command_log" ]]; then
  fixture_mode=true
fi

run_status=0
if [[ "$fixture_mode" == true ]]; then
  if [[ -z "$queue_json" || -z "$status_json" || -z "$bead_metadata_json" || -z "$command_log" ]]; then
    echo "fixture mode requires queue/status/bead metadata/command log inputs" >&2
    exit 64
  fi
  if [[ -z "$captured_at_epoch_seconds" ]]; then
    captured_at_epoch_seconds="$(
      jq -n \
        --slurpfile queue "$queue_json" \
        --slurpfile status "$status_json" '
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
          [
            (($queue[0].timestamp // $queue[0].data.timestamp // "") | epochish),
            (($status[0].timestamp // $status[0].data.timestamp // "") | epochish)
          ] | max
        '
    )"
  fi
  cp "$command_log" "$harness_log_path"
  printf 'fixture_command_log=%s\n' "$command_log" >>"$commands_path"
else
  if ! command -v rch >/dev/null 2>&1; then
    echo "rch is required for live remote repro harness" >&2
    exit 2
  fi
  set +e
  timeout "$timeout_seconds" bash -lc "$remote_command_text" >"$harness_log_path" 2>&1
  run_status=$?
  set -e
fi

capture_args=(
  --output-dir "$bundle_dir"
  --bead-id "$bead_id"
  --remote-command "$remote_command_text"
  --command-log "$harness_log_path"
)
[[ -n "$queue_json" ]] && capture_args+=(--queue-json "$queue_json")
[[ -n "$status_json" ]] && capture_args+=(--status-json "$status_json")
[[ -n "$bead_metadata_json" ]] && capture_args+=(--bead-metadata-json "$bead_metadata_json")
[[ -n "$worker_inventory_json" ]] && capture_args+=(--worker-inventory-json "$worker_inventory_json")
[[ -n "$operator_note" ]] && capture_args+=(--operator-note "$operator_note")
[[ -n "$captured_at_epoch_seconds" ]] && capture_args+=(--captured-at-epoch-seconds "$captured_at_epoch_seconds")
printf 'capture_bundle_command=%q ' "$capture_script" "${capture_args[@]}" >>"$commands_path"
printf '\n' >>"$commands_path"

bundle_exit=0
set +e
"$capture_script" "${capture_args[@]}" >/dev/null 2>&1
bundle_exit=$?
set -e

bundle_path="${bundle_dir}/stall_bundle.json"
if [[ ! -f "$bundle_path" ]]; then
  echo "capture script did not produce stall_bundle.json" >&2
  exit 42
fi

selected_worker="$(selected_worker_from_log "$harness_log_path" || true)"
remote_exit_code="$(remote_exit_code_from_log "$harness_log_path" || true)"
local_fallback_observed=false
if log_has_local_fallback "$harness_log_path"; then
  local_fallback_observed=true
fi
ssh_timeout_observed=false
if log_has_ssh_timeout "$harness_log_path"; then
  ssh_timeout_observed=true
fi

report_json="$(
  jq -n \
    --arg case_id "$case_id" \
    --arg bead_id "$bead_id" \
    --arg remote_command "$remote_command_text" \
    --arg harness_log_path "$harness_log_path" \
    --arg bundle_path "$bundle_path" \
    --arg report_path "$report_path" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg summary_path "$summary_path" \
    --arg selected_worker "$selected_worker" \
    --arg remote_exit_code "$remote_exit_code" \
    --argjson timeout_seconds "$timeout_seconds" \
    --argjson run_status "$run_status" \
    --argjson bundle_exit "$bundle_exit" \
    --argjson local_fallback_observed "$local_fallback_observed" \
    --argjson ssh_timeout_observed "$ssh_timeout_observed" \
    --argjson stall_progress_age_threshold_seconds "$stall_progress_age_threshold_seconds" \
    --argjson fresh_heartbeat_age_threshold_seconds "$fresh_heartbeat_age_threshold_seconds" \
    --slurpfile bundle "$bundle_path" '
      ($bundle[0]) as $bundle_doc
      | ($bundle_doc.captured_at_epoch_seconds - ($bundle_doc.stall_subject.heartbeat.last_heartbeat_epoch_seconds // 0)) as $heartbeat_age_seconds
      | ($bundle_doc.stall_subject.progress_age_seconds // 0) as $progress_age_seconds
      | ($bundle_doc.truth_state == "contaminated" or $local_fallback_observed) as $contaminated
      | (
          ($remote_exit_code | length) == 0
          and ($ssh_timeout_observed | not)
          and ($heartbeat_age_seconds <= $fresh_heartbeat_age_threshold_seconds)
          and ($progress_age_seconds >= $stall_progress_age_threshold_seconds)
        ) as $fresh_stall
      | if $contaminated then
          {
            final_verdict: "contaminated_local_fallback",
            reason_code: "local_fallback_contaminated",
            source_evidence: false,
            harness_exit_code: 42
          }
        elif (($remote_exit_code | length) > 0 and $remote_exit_code == "0") then
          {
            final_verdict: "source_pass",
            reason_code: "remote_command_exit_zero",
            source_evidence: true,
            harness_exit_code: 0
          }
        elif (($remote_exit_code | length) > 0) then
          {
            final_verdict: "source_failure",
            reason_code: "remote_source_diagnostic",
            source_evidence: true,
            harness_exit_code: 0
          }
        elif $ssh_timeout_observed then
          {
            final_verdict: "transport_timeout",
            reason_code: "ssh_timeout_no_final_verdict",
            source_evidence: false,
            harness_exit_code: 0
          }
        elif $fresh_stall then
          {
            final_verdict: "fresh_heartbeat_frozen_progress_stall",
            reason_code: "fresh_heartbeat_frozen_progress",
            source_evidence: false,
            harness_exit_code: 0
          }
        else
          {
            final_verdict: "missing_remote_proof",
            reason_code: "missing_worker_or_command_evidence",
            source_evidence: false,
            harness_exit_code: 42
          }
        end
      | . + {
          schema_version: "franken-engine.rch-remote-compile-stall-repro-report.v1",
          bead_id: $bead_id,
          case_id: $case_id,
          canonical_remote_command: $remote_command,
          timeout_seconds: $timeout_seconds,
          process_exit_code: $run_status,
          remote_exit_code: (if ($remote_exit_code | length) > 0 then ($remote_exit_code | tonumber) else null end),
          bundle_capture_exit_code: $bundle_exit,
          selected_worker: (if ($selected_worker | length) > 0 then $selected_worker else ($bundle_doc.stall_subject.worker_id // null) end),
          stall_observation: {
            capture_decision: $bundle_doc.capture_decision,
            truth_state: $bundle_doc.truth_state,
            heartbeat_age_seconds: $heartbeat_age_seconds,
            progress_age_seconds: $progress_age_seconds,
            threshold_seconds: {
              fresh_heartbeat_age: $fresh_heartbeat_age_threshold_seconds,
              stalled_progress_age: $stall_progress_age_threshold_seconds
            },
            local_fallback_observed: $bundle_doc.local_fallback_observed,
            blocker_codes: ($bundle_doc.blockers | map(.code))
          },
          artifact_paths: {
            repro_report_json: $report_path,
            stall_bundle_json: $bundle_path,
            harness_log_txt: $harness_log_path,
            events_jsonl: $events_path,
            commands_txt: $commands_path,
            summary_md: $summary_path
          }
        }
    '
)"
printf '%s\n' "$report_json" >"$report_path"

jq -c '
  {
    schema_version: "franken-engine.rch-remote-compile-stall-repro.event.v1",
    event: "remote_stall_repro_classified",
    bead_id: .bead_id,
    case_id: .case_id,
    final_verdict: .final_verdict,
    reason_code: .reason_code,
    selected_worker: .selected_worker,
    source_evidence: .source_evidence,
    capture_decision: .stall_observation.capture_decision,
    truth_state: .stall_observation.truth_state,
    heartbeat_age_seconds: .stall_observation.heartbeat_age_seconds,
    progress_age_seconds: .stall_observation.progress_age_seconds,
    local_fallback_observed: .stall_observation.local_fallback_observed
  }
' "$report_path" >"$events_path"

jq -r '
  "# RCH Remote Compile Stall Repro Harness",
  "",
  ("- Bead: `" + .bead_id + "`"),
  ("- Case: `" + .case_id + "`"),
  ("- Verdict: `" + .final_verdict + "`"),
  ("- Reason: `" + .reason_code + "`"),
  ("- Source evidence: `" + (.source_evidence | tostring) + "`"),
  ("- Selected worker: `" + (.selected_worker // "unknown") + "`"),
  ("- Process exit: `" + (.process_exit_code | tostring) + "`"),
  ("- Remote exit: `" + ((.remote_exit_code // "null") | tostring) + "`"),
  ("- Bundle capture decision: `" + .stall_observation.capture_decision + "`"),
  ("- Bundle truth state: `" + .stall_observation.truth_state + "`"),
  ("- Heartbeat age seconds: `" + (.stall_observation.heartbeat_age_seconds | tostring) + "`"),
  ("- Progress age seconds: `" + (.stall_observation.progress_age_seconds | tostring) + "`"),
  ("- Local fallback observed: `" + (.stall_observation.local_fallback_observed | tostring) + "`"),
  "",
  "## Command",
  "",
  ("`" + .canonical_remote_command + "`"),
  "",
  "## Artifacts",
  "",
  (.artifact_paths | to_entries[] | "- `" + .key + "`: `" + .value + "`")
' "$report_path" >"$summary_path"

printf 'rch_remote_compile_stall_repro_report=%s\n' "$report_path"

exit "$(jq -r '.harness_exit_code' "$report_path")"
