#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${RCH_INCIDENT_PACKET_ARTIFACT_ROOT:-artifacts/rch_incident_packet_gate}"
run_id="${RCH_INCIDENT_PACKET_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${RCH_INCIDENT_PACKET_RUN_DIR:-${artifact_root}/${run_id}}"
command_text="${RCH_INCIDENT_COMMAND:-}"
target_dir="${RCH_INCIDENT_TARGET_DIR:-}"
worker_id="${RCH_INCIDENT_WORKER:-}"
source_revision="${RCH_INCIDENT_SOURCE_REVISION:-}"
stdout_file=""
stderr_file=""
exit_code="${RCH_INCIDENT_EXIT_CODE:-unknown}"
completion_marker="${RCH_INCIDENT_COMPLETION_MARKER:-unknown}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/rch_incident_packet_gate.sh [OPTIONS]

Classifies captured rch remote-proof output into a deterministic incident packet.
This gate does not execute commands, restart daemons, or mutate worker state.

Options:
  --output-dir DIR             Artifact output directory.
  --command TEXT               Command text being classified.
  --target-dir DIR             CARGO_TARGET_DIR used by the command, if any.
  --worker ID                  Worker id when known.
  --source-revision REV        Source revision. Defaults to git rev-parse HEAD.
  --stdout-file FILE           Captured stdout from the rch command.
  --stderr-file FILE           Captured stderr from the rch command.
  --exit-code CODE             Observed command exit code.
  --completion-marker STATE    present, missing, or unknown.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      run_dir="$2"
      shift 2
      ;;
    --command)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      command_text="$2"
      shift 2
      ;;
    --target-dir)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      target_dir="$2"
      shift 2
      ;;
    --worker)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      worker_id="$2"
      shift 2
      ;;
    --source-revision)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      source_revision="$2"
      shift 2
      ;;
    --stdout-file)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      stdout_file="$2"
      shift 2
      ;;
    --stderr-file)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      stderr_file="$2"
      shift 2
      ;;
    --exit-code)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      exit_code="$2"
      shift 2
      ;;
    --completion-marker)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      completion_marker="$2"
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

case "$completion_marker" in
  present|missing|unknown)
    ;;
  *)
    printf 'completion marker must be present, missing, or unknown\n' >&2
    exit 64
    ;;
esac

if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
incident_packet_path="${run_dir}/incident_packet.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
stdout_capture_path="${run_dir}/stdout.log"
stderr_capture_path="${run_dir}/stderr.log"
combined_capture_path="${run_dir}/combined.log"
: >"$events_path"
: >"$stdout_capture_path"
: >"$stderr_capture_path"
: >"$combined_capture_path"

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

copy_capture() {
  local source_path="$1"
  local dest_path="$2"
  if [[ -z "$source_path" ]]; then
    return 0
  fi
  if [[ ! -f "$source_path" ]]; then
    printf 'missing capture file: %s\n' "$source_path" >>"$dest_path"
    return 0
  fi
  cat "$source_path" >"$dest_path"
}

write_event() {
  local event="$1"
  local detail="$2"

  jq -nc \
    --arg event "$event" \
    --arg detail "$detail" \
    --arg source_revision "$source_revision" \
    '{event: $event, detail: $detail, source_revision: $source_revision}' >>"$events_path"
}

has_pattern() {
  local pattern="$1"
  grep -Eiq "$pattern" "$combined_capture_path"
}

infer_worker() {
  if [[ -n "$worker_id" ]]; then
    return 0
  fi

  worker_id="$(
    {
      grep -Eo '\[RCH\] remote [^[:space:]]+' "$combined_capture_path" || true
      grep -Eo 'worker[=: ][A-Za-z0-9._-]+' "$combined_capture_path" || true
    } | head -n 1 | awk '{print $NF}' | sed 's/^worker[=: ]//'
  )"
}

copy_capture "$stdout_file" "$stdout_capture_path"
copy_capture "$stderr_file" "$stderr_capture_path"
{
  printf '=== STDOUT ===\n'
  cat "$stdout_capture_path"
  printf '\n=== STDERR ===\n'
  cat "$stderr_capture_path"
  printf '\n'
} >"$combined_capture_path"

{
  printf './scripts/rch_incident_packet_gate.sh'
  [[ -n "$command_text" ]] && printf ' --command %q' "$command_text"
  [[ -n "$target_dir" ]] && printf ' --target-dir %q' "$target_dir"
  [[ -n "$worker_id" ]] && printf ' --worker %q' "$worker_id"
  printf ' --source-revision %q' "$source_revision"
  printf ' --exit-code %q' "$exit_code"
  printf ' --completion-marker %q\n' "$completion_marker"
  [[ -n "$command_text" ]] && printf 'classified_command=%s\n' "$command_text"
} >"$commands_path"

write_event "capture_loaded" "stdout and stderr captures normalized"
infer_worker

status="fail"
failure_kind="unknown_failure_text"
classification_confidence="low"

# rch-policy-waive: local_fallback_not_rejected reason=intentional classifier rejects rch local fallback markers
if has_pattern '(\[RCH\] local|falling back to local|fallback to local|local fallback|running locally|Dependency preflight blocked remote execution|RCH-E326)'; then
  failure_kind="local_fallback"
  classification_confidence="high"
elif has_pattern '(artifact retrieval failed|failed to retrieve artifacts|rsync[^[:cntrl:]]*(code 23|failed)|sync[^[:cntrl:]]*failed|retrieval failure)'; then
  failure_kind="artifact_retrieval_failure"
  classification_confidence="high"
elif has_pattern '(SIGKILL|signal: 9|signal 9|exit status 137|exit_code[=: ]137|Killed)'; then
  failure_kind="remote_sigkill"
  classification_confidence="high"
elif has_pattern '(timed out|timeout|stuck detector|auto-cancelled|auto-canceled|exit_code[=: ]130|exit code 130|exit=130)'; then
  failure_kind="worker_timeout"
  classification_confidence="high"
elif [[ "$completion_marker" == "missing" ]]; then
  failure_kind="missing_completion_marker"
  classification_confidence="medium"
elif [[ "$exit_code" == "0" && "$completion_marker" == "present" ]] && has_pattern '(\[RCH\] remote|remote .*completed|remote proof completed)'; then
  status="pass"
  failure_kind="clean_remote_success"
  classification_confidence="high"
fi

case "$failure_kind" in
  clean_remote_success)
    retry_safety="no_retry_needed"
    recommended_next_action="Record the remote proof as clean and proceed with normal artifact verification."
    ;;
  local_fallback)
    retry_safety="unsafe_until_remote_routing_is_fixed"
    recommended_next_action="Do not accept local Cargo output; fix rch routing or narrow to non-heavy shell checks before retrying."
    ;;
  worker_timeout)
    retry_safety="safe_after_narrowing_or_timeout_adjustment"
    recommended_next_action="Retry only after narrowing the command, increasing the remote timeout, or selecting a healthier worker."
    ;;
  remote_sigkill)
    retry_safety="unsafe_without_resource_reduction"
    recommended_next_action="Treat as worker resource pressure; reduce target fanout or capture worker memory/disk state before retry."
    ;;
  artifact_retrieval_failure)
    retry_safety="safe_to_replay_after_artifact_sync_diagnosis"
    recommended_next_action="Inspect rch transfer logs and preserve remote artifacts before rerunning the proof."
    ;;
  missing_completion_marker)
    retry_safety="unsafe_to_trust_without_rerun"
    recommended_next_action="Do not rely on the partial run; rerun or inspect wrapper logs until a completion marker is present."
    ;;
  *)
    retry_safety="unsafe_unknown_failure"
    recommended_next_action="Keep the packet, classify the failure text manually, and file or update a follow-up before retrying."
    ;;
esac

incident_id="rch-incident-$(sha256_text "${source_revision}|${failure_kind}|${command_text}|${exit_code}|${completion_marker}" | cut -c1-16)"

# shellcheck disable=SC2094
jq -n \
  --arg schema_version "franken-engine.rch-incident-packet.v1" \
  --arg incident_id "$incident_id" \
  --arg status "$status" \
  --arg failure_kind "$failure_kind" \
  --arg classification_confidence "$classification_confidence" \
  --arg retry_safety "$retry_safety" \
  --arg recommended_next_action "$recommended_next_action" \
  --arg worker_id "$worker_id" \
  --arg command "$command_text" \
  --arg target_dir "$target_dir" \
  --arg source_revision "$source_revision" \
  --arg exit_code "$exit_code" \
  --arg completion_marker "$completion_marker" \
  --arg incident_packet_path "$incident_packet_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg stdout_capture_path "$stdout_capture_path" \
  --arg stderr_capture_path "$stderr_capture_path" \
  --arg combined_capture_path "$combined_capture_path" \
  '{
    schema_version: $schema_version,
    incident_id: $incident_id,
    status: $status,
    failure_kind: $failure_kind,
    classification_confidence: $classification_confidence,
    retry_safety: $retry_safety,
    recommended_next_action: $recommended_next_action,
    worker_id: (if $worker_id == "" then null else $worker_id end),
    command: (if $command == "" then null else $command end),
    target_dir: (if $target_dir == "" then null else $target_dir end),
    source_revision: $source_revision,
    exit_code: (if $exit_code == "unknown" then null else ($exit_code | tonumber) end),
    completion_marker: $completion_marker,
    artifact_paths: {
      incident_packet_json: $incident_packet_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path,
      stdout_log: $stdout_capture_path,
      stderr_log: $stderr_capture_path,
      combined_log: $combined_capture_path
    }
  }' >"$incident_packet_path"

write_event "classified" "$failure_kind"

{
  printf '# RCH Incident Packet\n\n'
  printf -- "- Incident: \`%s\`\n" "$incident_id"
  printf -- "- Status: \`%s\`\n" "$status"
  printf -- "- Failure kind: \`%s\`\n" "$failure_kind"
  printf -- "- Retry safety: \`%s\`\n" "$retry_safety"
  printf -- "- Recommended next action: %s\n" "$recommended_next_action"
  [[ -n "$worker_id" ]] && printf -- "- Worker: \`%s\`\n" "$worker_id"
  [[ -n "$target_dir" ]] && printf -- "- Target dir: \`%s\`\n" "$target_dir"
} >"$report_path"

printf 'rch_incident_packet=%s\n' "$incident_packet_path"
printf 'rch_incident_report=%s\n' "$report_path"

if [[ "$status" == "pass" ]]; then
  exit 0
fi
exit 42
