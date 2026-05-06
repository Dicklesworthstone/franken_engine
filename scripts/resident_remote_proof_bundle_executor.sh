#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${RESIDENT_REMOTE_PROOF_BUNDLE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-resident-remote-proof-bundle}"
run_id="${RESIDENT_REMOTE_PROOF_BUNDLE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${RESIDENT_REMOTE_PROOF_BUNDLE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

agent_id=""
bead_id=""
phase_manifest_json=""
phase_receipts_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/resident_remote_proof_bundle_executor.sh --agent-id ID --bead-id ID --phase-manifest-json FILE [OPTIONS]

Run or validate a resident remote proof bundle. The bundle keeps declared
check/test/clippy phases on one worker and one warm CARGO_TARGET_DIR, then
emits deterministic receipts for replay and downstream artifact retrieval.

Required:
  --agent-id ID
  --bead-id ID
  --phase-manifest-json FILE

Optional:
  --phase-receipts-json FILE  Validate preserved receipts instead of executing.
  --output-dir DIR

Artifacts:
  bundle_report.json
  run_manifest.json
  commands.txt
  events.jsonl
  summary.md
  phase_logs/*.stdout.log
  phase_logs/*.stderr.log

Exit codes:
  0  bundle passed with one worker, one target-dir, and completion markers
  42 fail-closed due to drift, local fallback, missing receipt, or bad phase
  64 invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --agent-id)
      agent_id="${2:-}"
      shift 2
      ;;
    --bead-id)
      bead_id="${2:-}"
      shift 2
      ;;
    --phase-manifest-json)
      phase_manifest_json="${2:-}"
      shift 2
      ;;
    --phase-receipts-json)
      phase_receipts_json="${2:-}"
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

if [[ -z "$agent_id" || -z "$bead_id" || -z "$phase_manifest_json" ]]; then
  printf 'resident bundle executor requires --agent-id, --bead-id, and --phase-manifest-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for resident remote proof bundle execution\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for resident remote proof bundle execution\n' >&2
  exit 2
fi
if [[ ! -f "$phase_manifest_json" ]]; then
  printf 'resident bundle executor missing phase manifest JSON: %s\n' "$phase_manifest_json" >&2
  exit 64
fi
if ! jq empty "$phase_manifest_json" >/dev/null 2>&1; then
  printf 'resident bundle executor invalid phase manifest JSON: %s\n' "$phase_manifest_json" >&2
  exit 64
fi
if [[ -n "$phase_receipts_json" ]]; then
  if [[ ! -f "$phase_receipts_json" ]]; then
    printf 'resident bundle executor missing phase receipts JSON: %s\n' "$phase_receipts_json" >&2
    exit 64
  fi
  if ! jq empty "$phase_receipts_json" >/dev/null 2>&1; then
    printf 'resident bundle executor invalid phase receipts JSON: %s\n' "$phase_receipts_json" >&2
    exit 64
  fi
fi

mkdir -p "$run_dir"
phase_logs_dir="${run_dir}/phase_logs"
mkdir -p "$phase_logs_dir"

bundle_report_path="${run_dir}/bundle_report.json"
bundle_report_tmp="${bundle_report_path}.tmp"
run_manifest_path="${run_dir}/run_manifest.json"
run_manifest_tmp="${run_manifest_path}.tmp"
summary_path="${run_dir}/summary.md"
summary_tmp="${summary_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
manifest_normalized="${run_dir}/phase_manifest.normalized.json"
receipts_normalized="${run_dir}/phase_receipts.normalized.json"
receipts_jsonl="${run_dir}/phase_receipts.jsonl"
logs_index_jsonl="${run_dir}/phase_logs_index.jsonl"
logs_index_json="${run_dir}/phase_logs_index.json"
report_core="${run_dir}/bundle_report_core.json"
: >"$events_path"
: >"$receipts_jsonl"
: >"$logs_index_jsonl"

printf './scripts/resident_remote_proof_bundle_executor.sh' >"$commands_path"
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

safe_file_part() {
  printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'
}

jq -cS '
  {
    schema_version: (.schema_version // "unknown"),
    bundle_id: (.bundle_id // .suite_id // .id // "unknown"),
    expected_worker_id: (.expected_worker_id // .worker_id // .worker // ""),
    expected_target_dir: (.expected_target_dir // .target_dir // .cargo_target_dir // ""),
    phases: (
      (.phases // .commands // [])
      | if type == "array" then . else [] end
      | map({
          phase: (.phase // .lane // .kind // "unknown"),
          command_id: (.command_id // .id // .phase // "unknown"),
          requested_command: (.requested_command // .command // ""),
          required_artifacts: (
            (.required_artifacts // .artifacts // [])
            | if type == "array" then map(tostring) else [] end
          )
        })
      | sort_by(.phase, .command_id, .requested_command)
    )
  }
' "$phase_manifest_json" >"$manifest_normalized"
write_event "phase_manifest_loaded" "normalized resident bundle phase manifest"

manifest_error="$(
  jq -r '
    if (.bundle_id | length) == 0 or .bundle_id == "unknown" then
      "manifest must declare bundle_id"
    elif (.expected_worker_id | length) == 0 then
      "manifest must declare expected_worker_id"
    elif (.expected_target_dir | length) == 0 then
      "manifest must declare expected_target_dir"
    elif ((.phases // []) | length) == 0 then
      "manifest must declare at least one phase"
    else
      ""
    end
  ' "$manifest_normalized"
)"
if [[ -n "$manifest_error" ]]; then
  printf 'resident bundle executor invalid manifest: %s\n' "$manifest_error" >&2
  exit 64
fi

normalize_receipts_input() {
  jq -cS '
    {
      receipts: (
        if type == "array" then
          .
        else
          (.receipts // .phase_receipts // [])
        end
        | if type == "array" then . else [] end
        | map({
            phase: (.phase // "unknown"),
            command_id: (.command_id // .id // .phase // "unknown"),
            worker_id: (.worker_id // .worker // ""),
            target_dir: (.target_dir // .cargo_target_dir // ""),
            requested_command: (.requested_command // .command // ""),
            exit_code: (.exit_code // 0),
            completion_marker: (.completion_marker // "unknown"),
            stdout: (.stdout // ""),
            stderr: (.stderr // ""),
            artifact_paths: (.artifact_paths // {})
          })
        | sort_by(.phase, .command_id)
      )
    }
  ' "$phase_receipts_json" >"$receipts_normalized"
}

command_has_required_shape() {
  local command="$1"
  local target_dir="$2"

  [[ "$command" == *"rch exec -- env"* ]] || return 1
  [[ "$command" == *"CARGO_TARGET_DIR=${target_dir}"* ]] || return 1
  [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(check|test|clippy)([[:space:]]|$) ]] || return 1
  return 0
}

infer_worker_from_logs() {
  local combined_log="$1"
  {
    grep -Eo '\[RCH\] remote [A-Za-z0-9._-]+' "$combined_log" || true
    grep -Eo 'worker[=: ][A-Za-z0-9._-]+' "$combined_log" || true
  } | head -n 1 | awk '{print $NF}' | sed 's/^worker[=: ]//'
}

has_local_fallback_marker() {
  local combined_log="$1"
  # rch-policy-waive: local_fallback_not_rejected reason=detector rejects fallback markers before bundle promotion
  grep -Eiq '(\[RCH\] local|falling back to local|fallback to local|local fallback|running locally|Dependency preflight blocked remote execution|RCH-E326)' "$combined_log"
}

execute_manifest_phases() {
  local expected_target_dir row phase command_id command safe_id stdout_path stderr_path combined_path
  local actual_exit worker_id completion_marker

  expected_target_dir="$(jq -r '.expected_target_dir' "$manifest_normalized")"
  while IFS= read -r row; do
    phase="$(jq -r '.phase' <<<"$row")"
    command_id="$(jq -r '.command_id' <<<"$row")"
    command="$(jq -r '.requested_command' <<<"$row")"
    safe_id="$(safe_file_part "$command_id")"
    stdout_path="${phase_logs_dir}/${safe_id}.stdout.log"
    stderr_path="${phase_logs_dir}/${safe_id}.stderr.log"
    combined_path="${phase_logs_dir}/${safe_id}.combined.log"
    : >"$stdout_path"
    : >"$stderr_path"

    if ! command_has_required_shape "$command" "$expected_target_dir"; then
      jq -nc \
        --arg phase "$phase" \
        --arg command_id "$command_id" \
        --arg command "$command" \
        --arg target_dir "$expected_target_dir" \
        '{
          phase: $phase,
          command_id: $command_id,
          requested_command: $command,
          worker_id: "",
          target_dir: $target_dir,
          exit_code: 42,
          completion_marker: "missing",
          stdout: "",
          stderr: "phase command is not rch exec -- env CARGO_TARGET_DIR wrapped"
        }' >>"$receipts_jsonl"
      continue
    fi

    printf 'phase[%s]=%s\n' "$command_id" "$command" >>"$commands_path"
    set +e
    bash -o pipefail -c "$command" >"$stdout_path" 2>"$stderr_path"
    actual_exit=$?
    set -e
    {
      printf '=== STDOUT ===\n'
      cat "$stdout_path"
      printf '\n=== STDERR ===\n'
      cat "$stderr_path"
    } >"$combined_path"

    worker_id="$(infer_worker_from_logs "$combined_path")"
    completion_marker="missing"
    if [[ "$actual_exit" -eq 0 ]] && ! has_local_fallback_marker "$combined_path"; then
      completion_marker="present"
    fi

    jq -nc \
      --arg phase "$phase" \
      --arg command_id "$command_id" \
      --arg command "$command" \
      --arg worker_id "$worker_id" \
      --arg target_dir "$expected_target_dir" \
      --arg completion_marker "$completion_marker" \
      --arg stdout "$(cat "$stdout_path")" \
      --arg stderr "$(cat "$stderr_path")" \
      --argjson exit_code "$actual_exit" \
      '{
        phase: $phase,
        command_id: $command_id,
        requested_command: $command,
        worker_id: $worker_id,
        target_dir: $target_dir,
        exit_code: $exit_code,
        completion_marker: $completion_marker,
        stdout: $stdout,
        stderr: $stderr
      }' >>"$receipts_jsonl"
  done < <(jq -c '.phases[]' "$manifest_normalized")

  jq -s '{receipts: . | sort_by(.phase, .command_id)}' "$receipts_jsonl" >"$receipts_normalized"
}

if [[ -n "$phase_receipts_json" ]]; then
  normalize_receipts_input
  write_event "phase_receipts_loaded" "using preserved phase receipts"
else
  execute_manifest_phases
  write_event "phase_commands_executed" "executed manifest phases and captured receipts"
fi

while IFS= read -r row; do
  command_id="$(jq -r '.command_id' <<<"$row")"
  safe_id="$(safe_file_part "$command_id")"
  stdout_path="${phase_logs_dir}/${safe_id}.stdout.log"
  stderr_path="${phase_logs_dir}/${safe_id}.stderr.log"
  jq -r '.stdout // ""' <<<"$row" >"$stdout_path"
  jq -r '.stderr // ""' <<<"$row" >"$stderr_path"
  jq -nc \
    --arg command_id "$command_id" \
    --arg stdout_log "$stdout_path" \
    --arg stderr_log "$stderr_path" \
    '{command_id: $command_id, stdout_log: $stdout_log, stderr_log: $stderr_log}' >>"$logs_index_jsonl"
done < <(jq -c '.receipts[]' "$receipts_normalized")
jq -s '{logs: .}' "$logs_index_jsonl" >"$logs_index_json"

jq -n \
  --arg agent_id "$agent_id" \
  --arg bead_id "$bead_id" \
  --slurpfile manifest "$manifest_normalized" \
  --slurpfile receipts "$receipts_normalized" \
  --slurpfile logs "$logs_index_json" '
  def command_class($command):
    if ($command | test("(^|[[:space:]])cargo[[:space:]]+check([[:space:]]|$)")) then
      "check"
    elif ($command | test("(^|[[:space:]])cargo[[:space:]]+test([[:space:]]|$)")) then
      "test"
    elif ($command | test("(^|[[:space:]])cargo[[:space:]]+clippy([[:space:]]|$)")) then
      "clippy"
    else
      "other"
    end;
  def local_fallback_text($text):
    # rch-policy-waive: local_fallback_not_rejected reason=detector maps fallback text to fail_closed
    ($text | test("(\\[RCH\\] local|falling back to local|fallback to local|local fallback|running locally|Dependency preflight blocked remote execution|RCH-E326)"; "i"));
  def log_for($id; $field):
    first(($logs[0].logs // [])[]? | select(.command_id == $id) | .[$field]) // null;
  ($manifest[0]) as $manifest
  | ($receipts[0].receipts // []) as $receipts
  | ($manifest.phases // []) as $phases
  | ($manifest.expected_worker_id // "") as $expected_worker
  | ($manifest.expected_target_dir // "") as $expected_target
  | (
      $phases
      | map(
          . + {
            command_class: command_class(.requested_command),
            command_has_rch_wrapper: (.requested_command | contains("rch exec -- env")),
            command_has_target_dir: (.requested_command | contains("CARGO_TARGET_DIR=" + $expected_target))
          }
        )
    ) as $phase_specs
  | (
      $phase_specs
      | map(select((.command_has_rch_wrapper | not) or (.command_has_target_dir | not) or (.command_class == "other")))
    ) as $invalid_commands
  | (
      $phases
      | map(.command_id) as $expected_ids
      | ($receipts | map(.command_id)) as $actual_ids
      | ($expected_ids - $actual_ids)
    ) as $missing_receipts
  | (
      $receipts
      | map(select((.worker_id // "") != $expected_worker))
    ) as $worker_drift
  | (
      $receipts
      | map(select((.target_dir // "") != $expected_target))
    ) as $target_drift
  | (
      $receipts
      | map(select((.exit_code // 0) != 0))
    ) as $failed_phases
  | (
      $receipts
      | map(select((.completion_marker // "missing") != "present"))
    ) as $missing_completion_markers
  | (
      $receipts
      | map(select(local_fallback_text((.stdout // "") + "\n" + (.stderr // ""))))
    ) as $local_fallback_markers
  | (
      if (($invalid_commands | length) > 0) then
        {
          bundle_decision: "fail_closed",
          reason: "one or more phases are not rch exec -- env CARGO_TARGET_DIR wrapped",
          exit_code: 42
        }
      elif (($missing_receipts | length) > 0) then
        {
          bundle_decision: "fail_closed",
          reason: "one or more manifest phases did not produce receipts",
          exit_code: 42
        }
      elif (($worker_drift | length) > 0) then
        {
          bundle_decision: "fail_closed",
          reason: "phase receipts show worker identity drift",
          exit_code: 42
        }
      elif (($target_drift | length) > 0) then
        {
          bundle_decision: "fail_closed",
          reason: "phase receipts show CARGO_TARGET_DIR drift",
          exit_code: 42
        }
      elif (($local_fallback_markers | length) > 0) then
        {
          bundle_decision: "fail_closed",
          reason: "rch local fallback marker detected in phase output",
          exit_code: 42
        }
      elif (($failed_phases | length) > 0) then
        {
          bundle_decision: "fail_closed",
          reason: "one or more phases exited nonzero",
          exit_code: 42
        }
      elif (($missing_completion_markers | length) > 0) then
        {
          bundle_decision: "fail_closed",
          reason: "one or more phases are missing completion markers",
          exit_code: 42
        }
      else
        {
          bundle_decision: "pass",
          reason: "all phases stayed on one worker and one CARGO_TARGET_DIR with completion markers",
          exit_code: 0
        }
      end
    ) as $decision
  | {
      schema_version: "franken-engine.resident-remote-proof-bundle.v1",
      agent_id: $agent_id,
      bead_id: $bead_id,
      bundle_id: ($manifest.bundle_id // "unknown"),
      bundle_decision: $decision.bundle_decision,
      reason: $decision.reason,
      expected_worker_id: $expected_worker,
      expected_target_dir: $expected_target,
      phase_count: ($phases | length),
      receipt_count: ($receipts | length),
      invalid_phase_commands: $invalid_commands,
      missing_receipt_command_ids: $missing_receipts,
      worker_drift_receipts: $worker_drift,
      target_dir_drift_receipts: $target_drift,
      failed_phase_receipts: $failed_phases,
      missing_completion_marker_receipts: $missing_completion_markers,
      local_fallback_marker_receipts: $local_fallback_markers,
      phase_results: (
        $phase_specs
        | map(
            . as $phase
            | (first($receipts[]? | select(.command_id == $phase.command_id)) // {}) as $receipt
            | {
                phase: $phase.phase,
                command_id: $phase.command_id,
                command_class: $phase.command_class,
                worker_id: ($receipt.worker_id // null),
                target_dir: ($receipt.target_dir // null),
                exit_code: ($receipt.exit_code // null),
                completion_marker: ($receipt.completion_marker // "missing"),
                stdout_log: log_for($phase.command_id; "stdout_log"),
                stderr_log: log_for($phase.command_id; "stderr_log")
              }
          )
      ),
      exit_code: $decision.exit_code
    }
' >"$report_core"

input_hash="$(
  jq -n \
    --slurpfile manifest "$manifest_normalized" \
    --slurpfile receipts "$receipts_normalized" \
    '{phase_manifest: ($manifest[0]), phase_receipts: ($receipts[0])}' |
    jq -cS . |
    sha256sum |
    awk '{print $1}'
)"
bundle_hash="$(jq -cS . "$report_core" | sha256sum | awk '{print $1}')"
source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"

jq \
  --arg input_hash "$input_hash" \
  --arg bundle_hash "$bundle_hash" \
  --arg source_revision "$source_revision" \
  --arg bundle_report_path "$bundle_report_path" \
  --arg run_manifest_path "$run_manifest_path" \
  --arg summary_path "$summary_path" \
  --arg commands_path "$commands_path" \
  --arg events_path "$events_path" \
  --arg phase_logs_dir "$phase_logs_dir" '
  . + {
    source_revision: $source_revision,
    hash_basis: {
      input_hash: $input_hash,
      bundle_hash: $bundle_hash
    },
    artifact_paths: {
      bundle_report_json: $bundle_report_path,
      run_manifest_json: $run_manifest_path,
      summary_md: $summary_path,
      commands_txt: $commands_path,
      events_jsonl: $events_path,
      phase_logs_dir: $phase_logs_dir
    }
  }
' "$report_core" >"$bundle_report_tmp"
mv "$bundle_report_tmp" "$bundle_report_path"

jq -n \
  --slurpfile report "$bundle_report_path" \
  '{
    schema_version: "franken-engine.resident-remote-proof-run-manifest.v1",
    bundle_id: $report[0].bundle_id,
    bundle_decision: $report[0].bundle_decision,
    source_revision: $report[0].source_revision,
    expected_worker_id: $report[0].expected_worker_id,
    expected_target_dir: $report[0].expected_target_dir,
    phase_results: $report[0].phase_results,
    hash_basis: $report[0].hash_basis,
    artifact_paths: $report[0].artifact_paths
  }' >"$run_manifest_tmp"
mv "$run_manifest_tmp" "$run_manifest_path"

{
  printf '# Resident Remote Proof Bundle\n\n'
  printf -- '- Decision: %s\n' "$(jq -r '.bundle_decision' "$bundle_report_path")"
  printf -- '- Reason: %s\n' "$(jq -r '.reason' "$bundle_report_path")"
  printf -- '- Bundle ID: %s\n' "$(jq -r '.bundle_id' "$bundle_report_path")"
  printf -- '- Worker: %s\n' "$(jq -r '.expected_worker_id' "$bundle_report_path")"
  printf -- '- Target dir: %s\n' "$(jq -r '.expected_target_dir' "$bundle_report_path")"
  printf -- '- Phase count: %s\n' "$(jq -r '.phase_count' "$bundle_report_path")"
  printf -- '- Receipt count: %s\n' "$(jq -r '.receipt_count' "$bundle_report_path")"
  printf -- "- Input hash: \`%s\`\n" "$(jq -r '.hash_basis.input_hash' "$bundle_report_path")"
  printf -- "- Bundle hash: \`%s\`\n" "$(jq -r '.hash_basis.bundle_hash' "$bundle_report_path")"
  printf '\n## Phase Results\n\n'
  jq -r '
    [
      "| Phase | Class | Worker | Target Dir | Exit | Completion |",
      "| --- | --- | --- | --- | ---: | --- |"
    ]
    + (
      .phase_results
      | map("| \(.phase) | \(.command_class) | \(.worker_id // "none") | \(.target_dir // "none") | \(.exit_code // -1) | \(.completion_marker) |")
    )
    | join("\n")
  ' "$bundle_report_path"
} >"$summary_tmp"
mv "$summary_tmp" "$summary_path"

write_event "bundle_report_written" "wrote resident remote proof bundle artifacts"

printf 'resident_remote_proof_bundle_report=%s\n' "$bundle_report_path"
printf 'resident_remote_proof_run_manifest=%s\n' "$run_manifest_path"

exit "$(jq -r '.exit_code' "$bundle_report_path")"
