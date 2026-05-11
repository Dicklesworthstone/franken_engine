#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${RCH_PROOF_FAILURE_CAPSULE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-rch-proof-failure-capsule}"
run_id="${RCH_PROOF_FAILURE_CAPSULE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${RCH_PROOF_FAILURE_CAPSULE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

transcript_path=""
metadata_json=""
source_revision="${RCH_PROOF_FAILURE_CAPSULE_SOURCE_REVISION:-}"
case_id_override=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/rch_proof_failure_capsule.sh --transcript FILE --metadata-json FILE [OPTIONS]

Classifies preserved rch proof output and emits a deterministic failure capsule.
The script is evidence-only: it does not run Cargo, invoke rch, mutate beads,
send Agent Mail, or change workers.

Required inputs:
  --transcript FILE       Captured rch stdout/stderr snippet
  --metadata-json FILE    Command metadata JSON with command, worker, exit, timing

Options:
  --output-dir DIR
  --source-revision REV
  --case-id ID

Artifacts:
  proof_failure_capsule.json
  next_command_advice.json
  run_manifest.json
  commands.txt
  events.jsonl
  report.md

Exit codes:
  0   Remote proof succeeded and is usable source evidence
  42  Proof failed, is blocked, interrupted, or contaminated
  64  Invalid option or malformed/missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --transcript)
      transcript_path="${2:-}"
      shift 2
      ;;
    --metadata-json)
      metadata_json="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --case-id)
      case_id_override="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$transcript_path" || -z "$metadata_json" ]]; then
  printf 'rch proof failure capsule requires --transcript and --metadata-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for rch proof failure capsule\n' >&2
  exit 2
fi
if [[ ! -f "$transcript_path" ]]; then
  printf 'transcript not found: %s\n' "$transcript_path" >&2
  exit 64
fi
if [[ ! -f "$metadata_json" ]]; then
  printf 'metadata JSON not found: %s\n' "$metadata_json" >&2
  exit 64
fi
if ! jq empty "$metadata_json" >/dev/null 2>&1; then
  printf 'invalid metadata JSON: %s\n' "$metadata_json" >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
capsule_path="${run_dir}/proof_failure_capsule.json"
advice_path="${run_dir}/next_command_advice.json"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
metadata_normalized_path="${run_dir}/command_metadata.normalized.json"
transcript_excerpt_path="${run_dir}/transcript_excerpt.txt"
first_errors_path="${run_dir}/first_relevant_errors.txt"
capsule_tmp="${capsule_path}.tmp"
manifest_tmp="${manifest_path}.tmp"

for artifact_path in \
  "$capsule_path" \
  "$advice_path" \
  "$manifest_path" \
  "$events_path" \
  "$commands_path" \
  "$report_path" \
  "$metadata_normalized_path" \
  "$transcript_excerpt_path" \
  "$first_errors_path" \
  "$capsule_tmp" \
  "$manifest_tmp"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/rch_proof_failure_capsule.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  local event="$1"
  local outcome="$2"
  local detail="$3"
  local evidence_path="$4"

  jq -nc \
    --arg schema_version "franken-engine.rch-proof-failure-capsule.event.v1" \
    --arg component "rch_proof_failure_capsule" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg detail "$detail" \
    --arg evidence_path "$evidence_path" \
    '{
      schema_version: $schema_version,
      component: $component,
      event: $event,
      outcome: $outcome,
      detail: $detail,
      evidence_path: $evidence_path
    }' >>"$events_path"
}

has_marker() {
  local pattern="$1"
  grep -Eiq "$pattern" "$transcript_path"
}

bool_from_marker() {
  local pattern="$1"
  if has_marker "$pattern"; then
    printf 'true'
  else
    printf 'false'
  fi
}

derive_safe_remote_command() {
  local captured_command="$1"
  local preferred_command="$2"
  local target_dir_value="$3"

  if [[ -n "$preferred_command" ]]; then
    printf '%s\n' "$preferred_command"
    return
  fi

  if [[ -z "$target_dir_value" ]]; then
    target_dir_value="/tmp/franken-engine-rch-proof-capsule"
  fi

  if [[ "$captured_command" == RCH_REQUIRE_REMOTE=1* ]]; then
    printf '%s\n' "$captured_command"
  elif [[ "$captured_command" == *"rch exec --"* ]]; then
    printf 'RCH_REQUIRE_REMOTE=1 %s\n' "$captured_command"
  elif [[ "$captured_command" == cargo\ * ]]; then
    printf 'RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=%s CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 %s\n' "$target_dir_value" "$captured_command"
  elif [[ -n "$captured_command" ]]; then
    printf 'RCH_REQUIRE_REMOTE=1 rch exec -- %s\n' "$captured_command"
  else
    printf 'RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=%s CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check -p frankenengine-engine --tests\n' "$target_dir_value"
  fi
}

jq -cS . "$metadata_json" >"$metadata_normalized_path"
sed -n '1,240p' "$transcript_path" >"$transcript_excerpt_path"
awk '
  BEGIN { count = 0 }
  /^(error(\[[^]]+\])?:|error:)/ || /error\[[^]]+\]:/ || /^[[:space:]]+-->/ {
    print
    count++
    if (count >= 8) {
      exit
    }
  }
' "$transcript_path" >"$first_errors_path"

write_event "input.loaded" "ok" "normalized command metadata" "$metadata_json"
write_event "input.loaded" "ok" "captured transcript excerpt" "$transcript_path"

command_text="$(jq -r '.command // .validation_command // ""' "$metadata_normalized_path")"
worker_id="$(jq -r '.worker_id // .selected_worker // .worker // ""' "$metadata_normalized_path")"
build_id="$(jq -r '.build_id // .build // ""' "$metadata_normalized_path")"
target_dir="$(jq -r '.target_dir // .cargo_target_dir // ""' "$metadata_normalized_path")"
duration_ms="$(jq -r '(.duration_ms // .elapsed_ms // "") | tostring' "$metadata_normalized_path")"
exit_code="$(jq -r 'if (.exit_code // .remote_exit_code // null) == null then "" else ((.exit_code // .remote_exit_code) | tostring) end' "$metadata_normalized_path")"
started_at="$(jq -r '.started_at // .remote_started_at // ""' "$metadata_normalized_path")"
completed_at="$(jq -r '.completed_at // .remote_completed_at // ""' "$metadata_normalized_path")"
recommended_narrow_command="$(jq -r '.recommended_narrow_command // ""' "$metadata_normalized_path")"
case_id="$(jq -r '.case_id // ""' "$metadata_normalized_path")"
if [[ -n "$case_id_override" ]]; then
  case_id="$case_id_override"
fi

metadata_remote_started="$(jq -r 'if (.remote_started // .remote_command_started // false) == true then "true" else "false" end' "$metadata_normalized_path")"
metadata_remote_finished="$(jq -r 'if (.remote_finished // .remote_command_finished // false) == true then "true" else "false" end' "$metadata_normalized_path")"

local_fallback_observed="$(bool_from_marker 'local fallback|fallback to local|falling back to local|Executing command locally|running locally|Failed to query daemon|refusing local fallback|RCH-E326|\[RCH\] local')"
queue_timeout_observed="$(bool_from_marker 'queue timeout|timed out waiting for remote worker|timeout waiting in queue|queued .*timed out|no remote worker available|no workers available')"
worker_toolchain_missing_observed="$(bool_from_marker 'cargo-clippy.*not installed|component .*not installed|toolchain.*missing|command not found: (cargo|rustc)|(cargo|rustc): command not found|linker .*not found|No such file or directory.*(cargo|rustc)')"
interrupted_observed="$(bool_from_marker 'interrupted|cancelled|canceled|received signal|SIGINT|SIGTERM|KeyboardInterrupt|terminated by user')"
target_dir_fingerprint_observed="$(bool_from_marker 'could not parse/generate dep info|debug/\.fingerprint/[^[:space:]]+/(dep-[^[:space:]]+|invoked\.timestamp).*No such file or directory|extern location for [^[:space:]]+ does not exist: [^[:space:]]+\.rmeta|failed to write .*debug/\.fingerprint|dep-test-integration-test-[^[:space:]]+: No such file or directory')"

remote_started=false
if [[ "$metadata_remote_started" == "true" ]] || has_marker 'Selected worker:|Executing command remotely|Remote command started'; then
  remote_started=true
fi
remote_finished=false
if [[ "$metadata_remote_finished" == "true" || -n "$exit_code" ]] || has_marker 'Remote command finished'; then
  remote_finished=true
fi

classification="missing_remote_proof"
decision="fail_closed"
reason_code="missing_worker_or_command_evidence"
truth_state="blocked"
source_evidence=false
proof_usable=false
recommended_action="rerun_remote_proof"
conservative_action="Rerun through rch with preserved selected-worker and remote-finished markers before citing proof."
recommended_command="$(derive_safe_remote_command "$command_text" "$recommended_narrow_command" "$target_dir")"

if [[ "$local_fallback_observed" == "true" ]]; then
  classification="local_fallback"
  decision="fail_closed"
  reason_code="local_fallback_refused"
  truth_state="contaminated"
  recommended_action="refuse_local_fallback_and_rerun_remote"
  conservative_action="Do not count this as proof. Rerun only with remote-required rch evidence after the daemon or worker pool is healthy."
elif [[ "$queue_timeout_observed" == "true" ]]; then
  classification="queue_timeout"
  decision="blocked"
  reason_code="queue_timeout_no_remote_result"
  truth_state="blocked"
  recommended_action="wait_for_remote_capacity_or_split_target"
  conservative_action="Do not infer pass or fail. Wait for remote capacity, split the proof target, or rerun a narrower command through rch."
elif [[ "$worker_toolchain_missing_observed" == "true" ]]; then
  classification="worker_toolchain_missing"
  decision="blocked"
  reason_code="worker_toolchain_missing"
  truth_state="blocked"
  recommended_action="reroute_or_repair_worker_toolchain"
  conservative_action="Do not count this as source evidence. Reroute to a worker advertising the required toolchain or repair the selected worker."
elif [[ "$interrupted_observed" == "true" ]]; then
  classification="interrupted_build"
  decision="interrupted"
  reason_code="remote_build_interrupted"
  truth_state="incomplete"
  recommended_action="rerun_exact_remote_proof"
  conservative_action="Do not count interrupted output as proof. Salvage artifacts if available, then rerun the exact remote proof command."
elif [[ "$target_dir_fingerprint_observed" == "true" ]]; then
  classification="target_dir_fingerprint_corruption"
  decision="blocked"
  reason_code="cargo_target_dir_fingerprint_corruption"
  truth_state="validation_environment_blocker"
  recommended_action="discard_corrupt_target_and_rerun_remote"
  conservative_action="Do not count this as source evidence. Use a fresh isolated CARGO_TARGET_DIR and rerun through rch/native-dependency routing; this classifier must not delete target directories."
elif [[ "$remote_started" == "true" && "$remote_finished" == "true" && "$exit_code" == "0" ]]; then
  classification="remote_success"
  decision="pass"
  reason_code="remote_command_exit_zero"
  truth_state="valid_remote_proof"
  source_evidence=true
  proof_usable=true
  recommended_action="record_success_evidence"
  conservative_action="Record the remote command, worker, exit code, and commit as validation evidence."
  recommended_command=""
elif [[ "$remote_started" == "true" && "$remote_finished" == "true" && -n "$exit_code" ]]; then
  classification="remote_compile_failure"
  decision="source_failure"
  reason_code="remote_source_diagnostic"
  truth_state="failed_remote_proof"
  source_evidence=true
  proof_usable=true
  recommended_action="fix_or_file_touched_target_blocker"
  conservative_action="Treat as a real remote source failure if it reaches the touched target; otherwise file or cite the unrelated current-head blocker and rerun a narrower proof."
fi

first_errors_text="$(sed -n '1,8p' "$first_errors_path")"
if [[ -z "$first_errors_text" ]]; then
  first_errors_text="none captured"
fi

case "$classification" in
  remote_success)
    blocker_text=""
    ;;
  remote_compile_failure)
    blocker_text="$(
      printf "RCH remote proof failed on worker %s with exit %s for command '%s'.\nFirst compiler errors:\n%s\nAdvice: %s" \
        "${worker_id:-unknown}" \
        "${exit_code:-unknown}" \
        "${command_text:-unknown}" \
        "$first_errors_text" \
        "$conservative_action"
    )"
    ;;
  local_fallback)
    blocker_text="$(
      printf "RCH proof refused: local fallback markers were observed for command '%s'; this is not valid remote proof.\nAdvice: %s\nNext command: '%s'" \
        "${command_text:-unknown}" \
        "$conservative_action" \
        "$recommended_command"
    )"
    ;;
  queue_timeout)
    blocker_text="$(
      printf "RCH proof blocked: queue timeout produced no remote source verdict for command '%s'.\nAdvice: %s" \
        "${command_text:-unknown}" \
        "$conservative_action"
    )"
    ;;
  worker_toolchain_missing)
    blocker_text="$(
      printf "RCH proof blocked: worker %s is missing required toolchain support for command '%s'.\nAdvice: %s" \
        "${worker_id:-unknown}" \
        "${command_text:-unknown}" \
        "$conservative_action"
    )"
    ;;
  interrupted_build)
    blocker_text="$(
      printf "RCH proof interrupted before a usable verdict for command '%s' on worker %s.\nAdvice: %s\nNext command: '%s'" \
        "${command_text:-unknown}" \
        "${worker_id:-unknown}" \
        "$conservative_action" \
        "$recommended_command"
    )"
    ;;
  target_dir_fingerprint_corruption)
    blocker_text="$(
      printf "RCH proof blocked: Cargo target-dir dep-info/fingerprint corruption prevented a usable source verdict for command '%s' on worker %s.\nFirst target-dir errors:\n%s\nAdvice: %s\nNext command: '%s'" \
        "${command_text:-unknown}" \
        "${worker_id:-unknown}" \
        "$first_errors_text" \
        "$conservative_action" \
        "$recommended_command"
    )"
    ;;
  *)
    blocker_text="$(
      printf "RCH proof missing remote evidence for command '%s'; selected worker and remote-finished markers were not both preserved.\nAdvice: %s\nNext command: '%s'" \
        "${command_text:-unknown}" \
        "$conservative_action" \
        "$recommended_command"
    )"
    ;;
esac

jq -n \
  --rawfile first_errors "$first_errors_path" \
  --arg schema_version "franken-engine.rch-proof-failure-capsule.v1" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg classification "$classification" \
  --arg decision "$decision" \
  --arg reason_code "$reason_code" \
  --arg truth_state "$truth_state" \
  --arg command "$command_text" \
  --arg worker_id "$worker_id" \
  --arg build_id "$build_id" \
  --arg target_dir "$target_dir" \
  --arg exit_code "$exit_code" \
  --arg duration_ms "$duration_ms" \
  --arg started_at "$started_at" \
  --arg completed_at "$completed_at" \
  --arg transcript_path "$transcript_path" \
  --arg metadata_json "$metadata_json" \
  --arg transcript_excerpt_path "$transcript_excerpt_path" \
  --arg capsule_path "$capsule_path" \
  --arg advice_path "$advice_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg blocker_text "$blocker_text" \
  --argjson source_evidence "$source_evidence" \
  --argjson proof_usable "$proof_usable" \
  --argjson local_fallback_observed "$local_fallback_observed" \
  --argjson queue_timeout_observed "$queue_timeout_observed" \
  --argjson worker_toolchain_missing_observed "$worker_toolchain_missing_observed" \
  --argjson interrupted_observed "$interrupted_observed" \
  --argjson target_dir_fingerprint_observed "$target_dir_fingerprint_observed" \
  --argjson remote_started "$remote_started" \
  --argjson remote_finished "$remote_finished" \
  '{
    schema_version: $schema_version,
    case_id: (if $case_id == "" then null else $case_id end),
    source_revision: $source_revision,
    classification: $classification,
    decision: $decision,
    reason_code: $reason_code,
    truth_state: $truth_state,
    source_evidence: $source_evidence,
    proof_usable: $proof_usable,
    remote_proof: {
      command: $command,
      worker_id: (if $worker_id == "" then null else $worker_id end),
      build_id: (if $build_id == "" then null else $build_id end),
      target_dir: (if $target_dir == "" then null else $target_dir end),
      exit_code: (if $exit_code == "" then null else ($exit_code | tonumber) end),
      duration_ms: (if $duration_ms == "" then null else ($duration_ms | tonumber) end),
      started_at: (if $started_at == "" then null else $started_at end),
      completed_at: (if $completed_at == "" then null else $completed_at end),
      remote_started: $remote_started,
      remote_finished: $remote_finished
    },
    observed_markers: {
      local_fallback: $local_fallback_observed,
      queue_timeout: $queue_timeout_observed,
      worker_toolchain_missing: $worker_toolchain_missing_observed,
      interrupted: $interrupted_observed,
      target_dir_fingerprint: $target_dir_fingerprint_observed
    },
    first_relevant_errors: ($first_errors | split("\n") | map(select(length > 0))),
    blocker_text: (if $blocker_text == "" then null else $blocker_text end),
    input_artifacts: {
      transcript: $transcript_path,
      metadata_json: $metadata_json,
      transcript_excerpt: $transcript_excerpt_path
    },
    artifact_paths: {
      proof_failure_capsule_json: $capsule_path,
      next_command_advice_json: $advice_path,
      run_manifest_json: $manifest_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path
    },
    non_mutation_attestation: {
      runs_cargo: false,
      runs_rch: false,
      mutates_beads: false,
      sends_agent_mail: false,
      changes_workers: false,
      writes_outside_output_dir: false
    }
  }' >"$capsule_tmp"
mv "$capsule_tmp" "$capsule_path"

jq -n \
  --arg schema_version "franken-engine.rch-proof-next-command-advice.v1" \
  --arg classification "$classification" \
  --arg decision "$decision" \
  --arg reason_code "$reason_code" \
  --arg recommended_action "$recommended_action" \
  --arg recommended_command "$recommended_command" \
  --arg conservative_action "$conservative_action" \
  --arg blocker_text "$blocker_text" \
  --argjson source_evidence "$source_evidence" \
  --argjson proof_usable "$proof_usable" \
  '{
    schema_version: $schema_version,
    classification: $classification,
    decision: $decision,
    reason_code: $reason_code,
    source_evidence: $source_evidence,
    proof_usable: $proof_usable,
    recommended_action: $recommended_action,
    recommended_command: (if $recommended_command == "" then null else $recommended_command end),
    blocker_text: (if $blocker_text == "" then null else $blocker_text end),
    operator_note: $conservative_action,
    conservative_guards: {
      never_claim_success_from_failed_output: true,
      refuses_local_fallback_as_proof: true,
      runs_cargo: false,
      runs_rch: false,
      mutates_repository: false
    }
  }' >"$advice_path"

jq -n \
  --arg schema_version "franken-engine.rch-proof-failure-capsule-run-manifest.v1" \
  --arg source_revision "$source_revision" \
  --arg capsule_path "$capsule_path" \
  --arg advice_path "$advice_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg transcript_excerpt_path "$transcript_excerpt_path" \
  --arg metadata_normalized_path "$metadata_normalized_path" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    artifact_paths: {
      proof_failure_capsule_json: $capsule_path,
      next_command_advice_json: $advice_path,
      run_manifest_json: $manifest_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path,
      transcript_excerpt_txt: $transcript_excerpt_path,
      command_metadata_normalized_json: $metadata_normalized_path
    },
    mutation_policy: {
      fixture_fed_only: true,
      advisory_only: true,
      runs_cargo: false,
      runs_rch: false,
      mutates_br: false,
      sends_agent_mail: false,
      mutates_remote_workers: false
    }
  }' >"$manifest_tmp"
mv "$manifest_tmp" "$manifest_path"

jq -r \
  --slurpfile advice "$advice_path" \
  '
    "# RCH Proof Failure Capsule",
    "",
    ("- Classification: `" + .classification + "`"),
    ("- Decision: `" + .decision + "`"),
    ("- Reason: `" + .reason_code + "`"),
    ("- Source evidence: `" + (.source_evidence | tostring) + "`"),
    ("- Proof usable: `" + (.proof_usable | tostring) + "`"),
    ("- Worker: `" + (.remote_proof.worker_id // "none") + "`"),
    ("- Exit code: `" + ((.remote_proof.exit_code // "none") | tostring) + "`"),
    "",
    "## Command",
    "",
    ("`" + .remote_proof.command + "`"),
    "",
    "## First Relevant Errors",
    "",
    (if (.first_relevant_errors | length) == 0 then "none captured" else (.first_relevant_errors[] | "- `" + . + "`") end),
    "",
    "## Blocker Text",
    "",
    (.blocker_text // "remote proof succeeded"),
    "",
    "## Next Command Advice",
    "",
    ("- Action: `" + $advice[0].recommended_action + "`"),
    ("- Command: `" + ($advice[0].recommended_command // "none") + "`")
  ' "$capsule_path" >"$report_path"

write_event "capsule.classified" "$decision" "$reason_code" "$capsule_path"
write_event "advice.written" "ok" "$recommended_action" "$advice_path"

printf 'rch_proof_failure_capsule=%s\n' "$capsule_path"
printf 'rch_proof_next_command_advice=%s\n' "$advice_path"
printf 'rch_proof_failure_report=%s\n' "$report_path"

if [[ "$decision" == "pass" ]]; then
  exit 0
fi
exit 42
