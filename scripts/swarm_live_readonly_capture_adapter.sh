#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bundle_script="${SWARM_LIVE_READONLY_BUNDLE_SCRIPT:-${root_dir}/scripts/swarm_live_readonly_snapshot_bundle.sh}"
artifact_root="${SWARM_LIVE_READONLY_CAPTURE_ADAPTER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-live-readonly-capture-adapter}"
run_id="${SWARM_LIVE_READONLY_CAPTURE_ADAPTER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_LIVE_READONLY_CAPTURE_ADAPTER_RUN_DIR:-${artifact_root}/${run_id}}"
profile_json="${SWARM_LIVE_READONLY_CAPTURE_PROFILE:-${root_dir}/docs/swarm_live_readonly_capture_profile_v1.json}"
source_revision="${SWARM_LIVE_READONLY_SOURCE_REVISION:-}"
now_ts="${SWARM_LIVE_READONLY_NOW_TS:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

swarm_ops_state_json=""
br_ready_json=""
br_in_progress_json=""
br_sync_status_json=""
bv_plan_json=""
agent_mail_json=""
rch_status_json=""
rch_queue_json=""
git_status_json=""
git_diff_check_json=""
resource_pressure_json=""
proof_transcript_json=""
diff_paths=()
validate_commands=()

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_live_readonly_capture_adapter.sh [OPTIONS]

Captures read-only br, bv, git, and rch snapshots or copies fixture snapshots,
then round-trips them through scripts/swarm_live_readonly_snapshot_bundle.sh.
Agent Mail is accepted only as an operator-supplied JSON file.

Options:
  --output-dir DIR
  --profile-json FILE
  --source-revision REV
  --now-ts ISO8601_Z
  --swarm-ops-state-json FILE
  --br-ready-json FILE
  --br-in-progress-json FILE
  --br-sync-status-json FILE
  --bv-plan-json FILE
  --agent-mail-json FILE
  --rch-status-json FILE
  --rch-queue-json FILE
  --git-status-json FILE
  --git-diff-check-json FILE
  --resource-pressure-json FILE
  --proof-transcript-json FILE
  --diff-path PATH                 scoped path for git diff --check
  --validate-command COMMAND       validate an adapter command plan without running it

The adapter refuses mutating command patterns before capture.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --profile-json)
      profile_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --now-ts)
      now_ts="${2:-}"
      shift 2
      ;;
    --swarm-ops-state-json)
      swarm_ops_state_json="${2:-}"
      shift 2
      ;;
    --br-ready-json)
      br_ready_json="${2:-}"
      shift 2
      ;;
    --br-in-progress-json)
      br_in_progress_json="${2:-}"
      shift 2
      ;;
    --br-sync-status-json)
      br_sync_status_json="${2:-}"
      shift 2
      ;;
    --bv-plan-json)
      bv_plan_json="${2:-}"
      shift 2
      ;;
    --agent-mail-json)
      agent_mail_json="${2:-}"
      shift 2
      ;;
    --rch-status-json)
      rch_status_json="${2:-}"
      shift 2
      ;;
    --rch-queue-json)
      rch_queue_json="${2:-}"
      shift 2
      ;;
    --git-status-json)
      git_status_json="${2:-}"
      shift 2
      ;;
    --git-diff-check-json)
      git_diff_check_json="${2:-}"
      shift 2
      ;;
    --resource-pressure-json)
      resource_pressure_json="${2:-}"
      shift 2
      ;;
    --proof-transcript-json)
      proof_transcript_json="${2:-}"
      shift 2
      ;;
    --diff-path)
      diff_paths+=("${2:-}")
      shift 2
      ;;
    --validate-command)
      validate_commands+=("${2:-}")
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

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the SWARM live read-only capture adapter\n' >&2
  exit 2
fi
if [[ ! -x "$bundle_script" ]]; then
  printf 'missing executable bundle writer: %s\n' "$bundle_script" >&2
  exit 64
fi
if [[ ! -f "$profile_json" ]]; then
  printf 'missing capture profile JSON: %s\n' "$profile_json" >&2
  exit 64
fi
jq empty "$profile_json" >/dev/null

if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi
if [[ "${#diff_paths[@]}" -eq 0 ]]; then
  diff_paths=(".")
fi

raw_dir="${run_dir}/raw"
bundle_dir="${run_dir}/bundle"
mkdir -p "$raw_dir" "$bundle_dir"

adapter_json="${run_dir}/capture_adapter.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
: >"$events_path"
: >"$commands_path"

forbidden_command_re='(^|[[:space:]])br[[:space:]]+(update|close|reopen|assign)([[:space:]]|$)|(^|[[:space:]])br[[:space:]]+sync[[:space:]].*--flush-only|(^|[[:space:]])git[[:space:]]+(add|commit|reset|checkout)([[:space:]]|$)|(^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$)|(^|[[:space:]])rch[[:space:]]+exec([[:space:]]|$)|(^|[[:space:]])rch[[:space:]]+workers?[[:space:]]+disable([[:space:]]|$)|rm[[:space:]]+-rf'

reject_if_mutating() {
  local command_text="$1"
  if grep -Eiq "$forbidden_command_re" <<<"$command_text"; then
    printf 'refusing mutating capture command: %s\n' "$command_text" >&2
    return 42
  fi
}

record_command() {
  local component="$1"
  local mutation_class="$2"
  local command_text="$3"
  reject_if_mutating "$command_text"
  printf 'component=%s mutation_class=%s command=%q\n' "$component" "$mutation_class" "$command_text" >>"$commands_path"
}

write_event() {
  local component="$1"
  local event="$2"
  local outcome="$3"
  local error_code="$4"
  local evidence_path="$5"
  jq -cn \
    --arg schema_version "franken-engine.swarm-live-readonly-capture-adapter-event.v1" \
    --arg trace_id "trace-swarm-live-readonly-capture-adapter-${run_id}" \
    --arg component "$component" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    --arg evidence_path "$evidence_path" \
    '{
      schema_version: $schema_version,
      trace_id: $trace_id,
      component: $component,
      event: $event,
      outcome: $outcome,
      error_code: (if $error_code == "" then null else $error_code end),
      evidence_path: $evidence_path
    }' >>"$events_path"
}

normalize_json_timestamp() {
  local path="$1"
  local tmp="${path}.tmp"
  if jq empty "$path" >/dev/null 2>&1; then
    jq --arg captured_at "$now_ts" '
      if type == "object" then
        if has("captured_at") or has("capture_ts") or has("captured_ts") then . else . + {captured_at: $captured_at} end
      else
        {captured_at: $captured_at, items: .}
      end
    ' "$path" >"$tmp"
    mv "$tmp" "$path"
  fi
}

copy_or_capture_json() {
  local component="$1"
  local fixture="$2"
  local output="$3"
  shift 3
  local command_text="$*"
  local raw_output="${output}.raw"
  local stderr_path="${output}.stderr"
  local exit_code stderr_excerpt

  if [[ -n "$fixture" ]]; then
    record_command "$component" "input_file_only" "fixture ${component}: ${fixture}"
    cp "$fixture" "$output"
    normalize_json_timestamp "$output"
    write_event "$component" "fixture_copied" "captured" "" "${output#"$root_dir"/}"
    return
  fi

  record_command "$component" "read_only" "$command_text"
  set +e
  "$@" >"$raw_output" 2>"$stderr_path"
  exit_code=$?
  set -e
  if [[ "$exit_code" -eq 0 ]] && jq empty "$raw_output" >/dev/null 2>&1; then
    cp "$raw_output" "$output"
    normalize_json_timestamp "$output"
    write_event "$component" "live_capture" "captured" "" "${output#"$root_dir"/}"
  else
    stderr_excerpt="$(sed -n '1,20p' "$stderr_path" | tr '\n' ' ')"
    jq -n \
      --arg captured_at "$now_ts" \
      --arg component "$component" \
      --argjson exit_code "$exit_code" \
      --arg stderr_excerpt "$stderr_excerpt" \
      '{captured_at: $captured_at, capture_error: true, component: $component, exit_code: $exit_code, stderr_excerpt: $stderr_excerpt}' >"$output"
    write_event "$component" "live_capture" "degraded" "FE-SWARM-LIVE-ADAPTER-CAPTURE-ERROR" "${output#"$root_dir"/}"
  fi
}

copy_or_generate_swarm_ops_state() {
  local output="$1"
  if [[ -n "$swarm_ops_state_json" ]]; then
    record_command "swarm_ops_state" "input_file_only" "fixture swarm_ops_state: ${swarm_ops_state_json}"
    cp "$swarm_ops_state_json" "$output"
    normalize_json_timestamp "$output"
  else
    record_command "swarm_ops_state" "generated" "generate minimal bd-eozx0-compatible live state JSON"
    jq -n --arg captured_at "$now_ts" --arg source_revision "$source_revision" '{
      schema_version: "franken-engine.swarm-ops-state-bundle.v1",
      captured_at: $captured_at,
      source_revision: $source_revision,
      decision: "pass",
      source_components: []
    }' >"$output"
  fi
  write_event "swarm_ops_state" "prepared" "captured" "" "${output#"$root_dir"/}"
}

capture_git_status() {
  local output="$1"
  local raw_output="${output}.raw"
  local stderr_path="${output}.stderr"
  local exit_code stderr_excerpt
  if [[ -n "$git_status_json" ]]; then
    record_command "git_status" "input_file_only" "fixture git_status: ${git_status_json}"
    cp "$git_status_json" "$output"
    normalize_json_timestamp "$output"
    write_event "git_status" "fixture_copied" "captured" "" "${output#"$root_dir"/}"
    return
  fi
  record_command "git_status" "read_only" "git status --short"
  set +e
  git -C "$root_dir" status --short >"$raw_output" 2>"$stderr_path"
  exit_code=$?
  set -e
  if [[ "$exit_code" -eq 0 ]]; then
    jq -Rn --arg captured_at "$now_ts" '{
      captured_at: $captured_at,
      dirty_paths: [inputs | select(length > 0) | {raw: ., path: (sub("^[ MARCUD?!]{1,2}[ ]+"; "")), class: "unknown"}]
    }' <"$raw_output" >"$output"
    write_event "git_status" "live_capture" "captured" "" "${output#"$root_dir"/}"
  else
    stderr_excerpt="$(sed -n '1,20p' "$stderr_path" | tr '\n' ' ')"
    jq -n --arg captured_at "$now_ts" --argjson exit_code "$exit_code" --arg stderr_excerpt "$stderr_excerpt" \
      '{captured_at: $captured_at, capture_error: true, component: "git_status", exit_code: $exit_code, stderr_excerpt: $stderr_excerpt}' >"$output"
    write_event "git_status" "live_capture" "degraded" "FE-SWARM-LIVE-ADAPTER-CAPTURE-ERROR" "${output#"$root_dir"/}"
  fi
}

capture_git_diff_check() {
  local output="$1"
  local raw_output="${output}.raw"
  local stderr_path="${output}.stderr"
  local exit_code stderr_excerpt
  if [[ -n "$git_diff_check_json" ]]; then
    record_command "git_diff_check" "input_file_only" "fixture git_diff_check: ${git_diff_check_json}"
    cp "$git_diff_check_json" "$output"
    normalize_json_timestamp "$output"
    write_event "git_diff_check" "fixture_copied" "captured" "" "${output#"$root_dir"/}"
    return
  fi
  record_command "git_diff_check" "read_only" "git diff --check -- ${diff_paths[*]}"
  set +e
  git -C "$root_dir" diff --check -- "${diff_paths[@]}" >"$raw_output" 2>"$stderr_path"
  exit_code=$?
  set -e
  stderr_excerpt="$(sed -n '1,20p' "$stderr_path" | tr '\n' ' ')"
  jq -n \
    --arg captured_at "$now_ts" \
    --argjson exit_code "$exit_code" \
    --arg stdout "$(sed -n '1,40p' "$raw_output" | tr '\n' ' ')" \
    --arg stderr_excerpt "$stderr_excerpt" \
    --argjson checked_paths "$(printf '%s\n' "${diff_paths[@]}" | jq -R . | jq -s .)" \
    '{
      captured_at: $captured_at,
      diff_check_status: (if $exit_code == 0 then "pass" else "fail" end),
      exit_code: $exit_code,
      checked_paths: $checked_paths,
      stdout_excerpt: $stdout,
      stderr_excerpt: $stderr_excerpt
    }' >"$output"
  if [[ "$exit_code" -eq 0 ]]; then
    write_event "git_diff_check" "live_capture" "captured" "" "${output#"$root_dir"/}"
  else
    write_event "git_diff_check" "live_capture" "blocked" "FE-SWARM-LIVE-DIFF-CHECK-FAILED" "${output#"$root_dir"/}"
  fi
}

for command_text in "${validate_commands[@]}"; do
  reject_if_mutating "$command_text"
  printf 'validated read-only command: %q\n' "$command_text" >>"$commands_path"
done

copy_or_generate_swarm_ops_state "${raw_dir}/swarm_ops_state.json"
copy_or_capture_json "br_ready" "$br_ready_json" "${raw_dir}/br_ready.json" br ready --json
copy_or_capture_json "br_in_progress" "$br_in_progress_json" "${raw_dir}/br_in_progress.json" br list --status=in_progress --json
copy_or_capture_json "br_sync_status" "$br_sync_status_json" "${raw_dir}/br_sync_status.json" br sync --status --json
copy_or_capture_json "bv_plan" "$bv_plan_json" "${raw_dir}/bv_plan.json" bv --recipe actionable --robot-plan
copy_or_capture_json "rch_status" "$rch_status_json" "${raw_dir}/rch_status.json" rch status --workers --jobs --json
copy_or_capture_json "rch_queue" "$rch_queue_json" "${raw_dir}/rch_queue.json" rch queue --json
capture_git_status "${raw_dir}/git_status.json"
capture_git_diff_check "${raw_dir}/git_diff_check.json"

bundle_args=(
  --output-dir "$bundle_dir"
  --profile-json "$profile_json"
  --source-revision "$source_revision"
  --now-ts "$now_ts"
  --swarm-ops-state-json "${raw_dir}/swarm_ops_state.json"
  --br-ready-json "${raw_dir}/br_ready.json"
  --br-in-progress-json "${raw_dir}/br_in_progress.json"
  --br-sync-status-json "${raw_dir}/br_sync_status.json"
  --bv-plan-json "${raw_dir}/bv_plan.json"
  --rch-status-json "${raw_dir}/rch_status.json"
  --rch-queue-json "${raw_dir}/rch_queue.json"
  --git-status-json "${raw_dir}/git_status.json"
  --git-diff-check-json "${raw_dir}/git_diff_check.json"
)
if [[ -n "$agent_mail_json" ]]; then
  record_command "agent_mail_snapshot" "input_file_only" "operator-supplied Agent Mail snapshot: ${agent_mail_json}"
  bundle_args+=(--agent-mail-json "$agent_mail_json")
fi
if [[ -n "$resource_pressure_json" ]]; then
  record_command "resource_pressure" "input_file_only" "operator-supplied resource pressure snapshot: ${resource_pressure_json}"
  bundle_args+=(--resource-pressure-json "$resource_pressure_json")
fi
if [[ -n "$proof_transcript_json" ]]; then
  record_command "proof_transcript" "input_file_only" "operator-supplied proof transcript: ${proof_transcript_json}"
  bundle_args+=(--proof-transcript-json "$proof_transcript_json")
fi

"$bundle_script" "${bundle_args[@]}" >/dev/null
write_event "swarm_live_readonly_capture_adapter" "bundle_round_trip" "captured" "" "${bundle_dir#"$root_dir"/}/snapshot.json"

jq -n \
  --arg schema_version "franken-engine.swarm-live-readonly-capture-adapter.v1" \
  --arg generated_at "$now_ts" \
  --arg source_revision "$source_revision" \
  --arg commands_path "${commands_path#"$root_dir"/}" \
  --arg events_path "${events_path#"$root_dir"/}" \
  --arg bundle_snapshot "${bundle_dir#"$root_dir"/}/snapshot.json" \
  --arg bundle_report "${bundle_dir#"$root_dir"/}/report.md" \
  '{
    schema_version: $schema_version,
    generated_at: $generated_at,
    source_revision: $source_revision,
    mutation_boundary: {
      mutates_br: false,
      sends_agent_mail: false,
      queries_live_agent_mail: false,
      runs_cargo: false,
      runs_rch_exec: false,
      mutates_remote_workers: false
    },
    artifact_paths: {
      commands_txt: $commands_path,
      events_jsonl: $events_path,
      bundle_snapshot_json: $bundle_snapshot,
      bundle_report_md: $bundle_report
    }
  }' >"$adapter_json"

cat >"$report_path" <<EOF
# SWARM Live Read-Only Capture Adapter

- adapter: ${adapter_json}
- bundle snapshot: ${bundle_dir}/snapshot.json
- bundle report: ${bundle_dir}/report.md
- commands: ${commands_path}
- events: ${events_path}

The adapter used only read-only capture commands and did not query live Agent
Mail. Agent Mail evidence is accepted only from an operator-supplied JSON file.
EOF

printf 'swarm live read-only capture adapter: %s\n' "$adapter_json"
