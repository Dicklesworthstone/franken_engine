#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "error: rch is required for this suite" >&2
  exit 1
fi

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_guardplane_policy_actions_${timestamp}}"
artifact_root="${GUARDPLANE_POLICY_ACTIONS_ARTIFACT_ROOT:-artifacts/guardplane_policy_actions_suite}"
run_dir="$artifact_root/$timestamp"
manifest_path="$run_dir/run_manifest.json"
events_path="$run_dir/events.jsonl"
commands_path="$run_dir/commands.txt"
guardplane_log_path="$run_dir/guardplane_decision_log.jsonl"
containment_log_path="$run_dir/containment_workflow_log.jsonl"
containment_timeline_path="$run_dir/containment_timeline.json"
logs_dir="$run_dir/logs"
bead_id="${GUARDPLANE_POLICY_ACTIONS_BEAD_ID:-bd-1lsy.6.3}"
replay_command="${GUARDPLANE_POLICY_ACTIONS_REPLAY_COMMAND:-./scripts/run_guardplane_policy_actions_suite.sh ci}"
replay_command_encoded="${replay_command// /__FRANKEN_ENGINE_SPACE__}"
guardplane_log_env_path="$guardplane_log_path"
containment_log_env_path="$containment_log_path"
containment_detection_source_event="${GUARDPLANE_CONTAINMENT_DETECTION_SOURCE_EVENT:-delegate_declassification}"
containment_latency_slo_ns="${GUARDPLANE_CONTAINMENT_SLO_NS:-250000000}"
guardplane_log_begin_marker="__FE_GUARDPLANE_DECISION_LOG_BEGIN__"
guardplane_log_end_marker="__FE_GUARDPLANE_DECISION_LOG_END__"
containment_log_begin_marker="__FE_CONTAINMENT_WORKFLOW_LOG_BEGIN__"
containment_log_end_marker="__FE_CONTAINMENT_WORKFLOW_LOG_END__"

if [[ "$guardplane_log_env_path" != /* ]]; then
  guardplane_log_env_path="$root_dir/$guardplane_log_env_path"
fi
if [[ "$containment_log_env_path" != /* ]]; then
  containment_log_env_path="$root_dir/$containment_log_env_path"
fi

trace_id="trace-guardplane-policy-actions-${timestamp}"
decision_id="decision-guardplane-policy-actions-${timestamp}"
policy_id="policy-guardplane-policy-actions-v1"
component="guardplane_policy_actions_suite"

mkdir -p "$run_dir" "$logs_dir"

run_rch() {
  rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
}

ensure_remote_only() {
  local log_path="$1"
  if rg -qi "Remote toolchain failure, falling back to local|running locally" "$log_path"; then
    echo "error: detected local fallback in rch output: $log_path" >&2
    return 1
  fi
  if ! rg -q "Remote command finished: exit=" "$log_path"; then
    echo "error: missing remote completion marker in rch output: $log_path" >&2
    return 1
  fi
  return 0
}

declare -a commands_run=()
declare -a command_logs=()
artifact_capture_log_path=""
failed_command=""
failed_log_path=""
manifest_written=false
mode_completed=false

run_step() {
  local command_text="$1"
  shift
  local step_index="${#commands_run[@]}"
  local log_path="${logs_dir}/step_$(printf '%02d' "$step_index").log"
  commands_run+=("$command_text")
  command_logs+=("$log_path")
  echo "==> $command_text"
  if run_rch "$@" > >(tee "$log_path") 2>&1; then
    if ! ensure_remote_only "$log_path"; then
      failed_command="$command_text"
      failed_log_path="$log_path"
      return 1
    fi
    return 0
  fi
  failed_command="$command_text"
  failed_log_path="$log_path"
  return 1
}

write_containment_timeline() {
  if [[ ! "$containment_latency_slo_ns" =~ ^[0-9]+$ ]]; then
    echo "error: GUARDPLANE_CONTAINMENT_SLO_NS must be an unsigned integer (ns)" >&2
    return 1
  fi

  local guardplane_array
  local containment_array
  guardplane_array="$(mktemp)"
  containment_array="$(mktemp)"
  jq -s '.' "$guardplane_log_path" >"$guardplane_array"
  jq -s '.' "$containment_log_path" >"$containment_array"

  if ! jq -n \
    --arg schema_version "franken-engine.containment-timeline.v1" \
    --arg component "$component" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg source_event "$containment_detection_source_event" \
    --arg generated_at_utc "$timestamp" \
    --argjson containment_latency_slo_ns "$containment_latency_slo_ns" \
    --slurpfile guardplane "$guardplane_array" \
    --slurpfile containment "$containment_array" \
    '
      ($guardplane[0] | sort_by(.timestamp_ns)) as $guard_log
      | ($containment[0] | sort_by(.timestamp_ns)) as $containment_log
      | ($guard_log | map(select(.source_event == $source_event)) | first) as $detection
      | ($containment_log | first) as $first_containment
      | ($containment_log | map(select(.action == "quarantine")) | first) as $quarantine
      | ($detection.timestamp_ns // null) as $detection_ts
      | ($first_containment.timestamp_ns // null) as $first_containment_ts
      | ($quarantine.timestamp_ns // null) as $quarantine_ts
      | (
          if $detection_ts != null and $first_containment_ts != null then
            ($first_containment_ts - $detection_ts)
          else
            null
          end
        ) as $detection_to_first_containment_ns
      | (
          if $detection_ts != null and $quarantine_ts != null then
            ($quarantine_ts - $detection_ts)
          else
            null
          end
        ) as $detection_to_quarantine_ns
      | {
          schema_version: $schema_version,
          component: $component,
          trace_id: $trace_id,
          decision_id: $decision_id,
          policy_id: $policy_id,
          generated_at_utc: $generated_at_utc,
          detection: {
            source_event: $source_event,
            timestamp_ns: $detection_ts
          },
          metrics: {
            detection_to_first_containment_ns: $detection_to_first_containment_ns,
            detection_to_quarantine_ns: $detection_to_quarantine_ns
          },
          slo: {
            target_detection_to_first_containment_ns: $containment_latency_slo_ns,
            met: (
              $detection_to_first_containment_ns != null
              and $detection_to_first_containment_ns <= $containment_latency_slo_ns
            ),
            measured_detection_to_first_containment_ns: $detection_to_first_containment_ns
          },
          timeline: (
            $containment_log
            | map({
                timestamp_ns,
                source_event,
                action,
                event,
                outcome,
                error_code,
                lifecycle_transition,
                resulting_state,
                mesh_propagated,
                mesh_attempted_fanout: (.mesh_attempted_targets | length),
                mesh_fanout: (.mesh_targets | length),
                mesh_failed_fanout: (.mesh_failed_targets | length),
                mesh_attempted_targets,
                mesh_failed_targets,
                mesh_targets
              })
          ),
          checkpoints: {
            containment_first_event: $first_containment_ts,
            quarantine_established_at_ns: $quarantine_ts,
            quarantine_attempted_fanout: (($quarantine.mesh_attempted_targets | length) // 0),
            quarantine_fanout: (($quarantine.mesh_targets | length) // 0),
            quarantine_failed_fanout: (($quarantine.mesh_failed_targets | length) // 0),
            quarantine_mesh_propagated: (($quarantine.mesh_propagated) // false)
          }
        }
    ' >"$containment_timeline_path"; then
    rm -f "$guardplane_array" "$containment_array"
    echo "error: unable to write containment timeline artifact" >&2
    return 1
  fi

  rm -f "$guardplane_array" "$containment_array"
}

extract_artifact_from_step_log() {
  local step_log_path="$1"
  local begin_marker="$2"
  local end_marker="$3"
  local output_path="$4"

  mkdir -p "$(dirname "$output_path")"
  awk \
    -v begin="$begin_marker" \
    -v end="$end_marker" \
    '
      $0 == begin {capture=1; found_begin=1; next}
      $0 == end {
        if (capture) {
          found_end=1
          exit
        }
      }
      capture {print}
      END {
        if (!found_begin || !found_end) {
          exit 2
        }
      }
    ' "$step_log_path" >"$output_path"
}

run_guardplane_artifact_capture_step() {
  run_step "cargo test -p frankenengine-extension-host --lib guardplane_policy_action_logs_can_emit_jsonl_artifacts" \
    env \
      "FE_GUARDPLANE_DECISION_LOG_PATH=$guardplane_log_env_path" \
      "FE_CONTAINMENT_WORKFLOW_LOG_PATH=$containment_log_env_path" \
      "FE_GUARDPLANE_REPLAY_COMMAND_ENCODED=$replay_command_encoded" \
      "FE_GUARDPLANE_EMIT_STDOUT_MARKERS=1" \
      cargo test -p frankenengine-extension-host --lib guardplane_policy_action_logs_can_emit_jsonl_artifacts -- --nocapture
  artifact_capture_log_path="${command_logs[$(( ${#command_logs[@]} - 1 ))]}"
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-extension-host --lib" \
        cargo check -p frankenengine-extension-host --lib
      ;;
    test)
      run_step "cargo test -p frankenengine-extension-host --lib guardplane_action_thresholds_are_deterministic" \
        cargo test -p frankenengine-extension-host --lib guardplane_action_thresholds_are_deterministic
      run_step "cargo test -p frankenengine-extension-host --lib guardplane_policy_actions_progress_from_challenge_to_quarantine" \
        cargo test -p frankenengine-extension-host --lib guardplane_policy_actions_progress_from_challenge_to_quarantine
      run_step "cargo test -p frankenengine-extension-host --lib guardplane_safe_mode_fallback_is_fail_closed" \
        cargo test -p frankenengine-extension-host --lib guardplane_safe_mode_fallback_is_fail_closed
      run_step "cargo test -p frankenengine-extension-host --lib quarantine_mesh_targets_are_sorted_and_recorded" \
        cargo test -p frankenengine-extension-host --lib quarantine_mesh_targets_are_sorted_and_recorded
      run_step "cargo test -p frankenengine-extension-host --lib quarantine_mesh_partial_failures_are_recorded" \
        cargo test -p frankenengine-extension-host --lib quarantine_mesh_partial_failures_are_recorded
      run_step "cargo test -p frankenengine-extension-host --lib quarantine_mesh_total_failure_is_recorded" \
        cargo test -p frankenengine-extension-host --lib quarantine_mesh_total_failure_is_recorded
      run_step "cargo test -p frankenengine-extension-host --test delegate_cell_edge_cases guardplane_safe_mode_fallback_escalates_nominal_challenge_to_sandbox_on_denial -- --exact" \
        cargo test -p frankenengine-extension-host --test delegate_cell_edge_cases guardplane_safe_mode_fallback_escalates_nominal_challenge_to_sandbox_on_denial -- --exact
      run_step "cargo test -p frankenengine-extension-host --test delegate_cell_edge_cases guardplane_decision_logs_are_replay_stable_for_mixed_fault_sequence -- --exact" \
        cargo test -p frankenengine-extension-host --test delegate_cell_edge_cases guardplane_decision_logs_are_replay_stable_for_mixed_fault_sequence -- --exact
      run_guardplane_artifact_capture_step
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-extension-host --lib -- -D warnings" \
        cargo clippy -p frankenengine-extension-host --lib -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-extension-host --lib" \
        cargo check -p frankenengine-extension-host --lib
      run_step "cargo test -p frankenengine-extension-host --lib guardplane_action_thresholds_are_deterministic" \
        cargo test -p frankenengine-extension-host --lib guardplane_action_thresholds_are_deterministic
      run_step "cargo test -p frankenengine-extension-host --lib guardplane_policy_actions_progress_from_challenge_to_quarantine" \
        cargo test -p frankenengine-extension-host --lib guardplane_policy_actions_progress_from_challenge_to_quarantine
      run_step "cargo test -p frankenengine-extension-host --lib guardplane_safe_mode_fallback_is_fail_closed" \
        cargo test -p frankenengine-extension-host --lib guardplane_safe_mode_fallback_is_fail_closed
      run_step "cargo test -p frankenengine-extension-host --lib quarantine_mesh_targets_are_sorted_and_recorded" \
        cargo test -p frankenengine-extension-host --lib quarantine_mesh_targets_are_sorted_and_recorded
      run_step "cargo test -p frankenengine-extension-host --lib quarantine_mesh_partial_failures_are_recorded" \
        cargo test -p frankenengine-extension-host --lib quarantine_mesh_partial_failures_are_recorded
      run_step "cargo test -p frankenengine-extension-host --lib quarantine_mesh_total_failure_is_recorded" \
        cargo test -p frankenengine-extension-host --lib quarantine_mesh_total_failure_is_recorded
      run_step "cargo test -p frankenengine-extension-host --test delegate_cell_edge_cases guardplane_safe_mode_fallback_escalates_nominal_challenge_to_sandbox_on_denial -- --exact" \
        cargo test -p frankenengine-extension-host --test delegate_cell_edge_cases guardplane_safe_mode_fallback_escalates_nominal_challenge_to_sandbox_on_denial -- --exact
      run_step "cargo test -p frankenengine-extension-host --test delegate_cell_edge_cases guardplane_decision_logs_are_replay_stable_for_mixed_fault_sequence -- --exact" \
        cargo test -p frankenengine-extension-host --test delegate_cell_edge_cases guardplane_decision_logs_are_replay_stable_for_mixed_fault_sequence -- --exact
      run_guardplane_artifact_capture_step
      run_step "cargo clippy -p frankenengine-extension-host --lib -- -D warnings" \
        cargo clippy -p frankenengine-extension-host --lib -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac

  if [[ "$mode" == "test" || "$mode" == "ci" ]]; then
    local final_step_log="$artifact_capture_log_path"
    if [[ -z "$final_step_log" ]]; then
      echo "error: missing artifact capture step log path" >&2
      failed_command="guardplane_policy_action_logs_can_emit_jsonl_artifacts"
      failed_log_path="$run_dir"
      return 1
    fi
    if ! extract_artifact_from_step_log \
      "$final_step_log" \
      "$guardplane_log_begin_marker" \
      "$guardplane_log_end_marker" \
      "$guardplane_log_path"; then
      echo "error: unable to extract guardplane decision log from $final_step_log" >&2
      failed_command="guardplane_policy_action_logs_can_emit_jsonl_artifacts"
      failed_log_path="$final_step_log"
      return 1
    fi
    if ! extract_artifact_from_step_log \
      "$final_step_log" \
      "$containment_log_begin_marker" \
      "$containment_log_end_marker" \
      "$containment_log_path"; then
      echo "error: unable to extract containment workflow log from $final_step_log" >&2
      failed_command="guardplane_policy_action_logs_can_emit_jsonl_artifacts"
      failed_log_path="$final_step_log"
      return 1
    fi

    if [[ ! -s "$guardplane_log_path" ]]; then
      echo "error: missing guardplane decision log artifact: $guardplane_log_path" >&2
      failed_command="guardplane_policy_action_logs_can_emit_jsonl_artifacts"
      failed_log_path="$guardplane_log_path"
      return 1
    fi
    if [[ ! -s "$containment_log_path" ]]; then
      echo "error: missing containment workflow log artifact: $containment_log_path" >&2
      failed_command="guardplane_policy_action_logs_can_emit_jsonl_artifacts"
      failed_log_path="$containment_log_path"
      return 1
    fi
    if ! jq -s -e --arg replay_command "$replay_command" \
      'all(.[]; .replay_command == $replay_command)' \
      "$guardplane_log_path" >/dev/null; then
      echo "error: guardplane decision log replay_command drift: $guardplane_log_path" >&2
      failed_command="guardplane_policy_action_logs_can_emit_jsonl_artifacts"
      failed_log_path="$guardplane_log_path"
      return 1
    fi
    if ! jq -s -e --arg replay_command "$replay_command" \
      'all(.[]; .replay_command == $replay_command)' \
      "$containment_log_path" >/dev/null; then
      echo "error: containment workflow log replay_command drift: $containment_log_path" >&2
      failed_command="guardplane_policy_action_logs_can_emit_jsonl_artifacts"
      failed_log_path="$containment_log_path"
      return 1
    fi
    if ! write_containment_timeline; then
      failed_command="containment_timeline_generation"
      failed_log_path="$containment_timeline_path"
      return 1
    fi
    if [[ ! -s "$containment_timeline_path" ]]; then
      echo "error: missing containment timeline artifact: $containment_timeline_path" >&2
      failed_command="containment_timeline_generation"
      failed_log_path="$containment_timeline_path"
      return 1
    fi
    if ! jq -e '.detection.timestamp_ns != null and .checkpoints.containment_first_event != null' \
      "$containment_timeline_path" >/dev/null; then
      echo "error: containment timeline missing detection/first-containment anchors: $containment_timeline_path" >&2
      failed_command="containment_timeline_generation"
      failed_log_path="$containment_timeline_path"
      return 1
    fi
  fi

  mode_completed=true
}

json_or_null() {
  local value="$1"
  if [[ -n "$value" ]]; then
    printf '"%s"' "$value"
  else
    printf 'null'
  fi
}

write_manifest() {
  local exit_code="${1:-0}"
  local git_commit dirty_worktree outcome idx comma error_code_json failed_log_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 && "$mode_completed" == true ]]; then
    outcome="pass"
    error_code_json='null'
  else
    outcome="fail"
    error_code_json='"FE-DELEGATE-0006"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  if [[ "$mode" == "test" || "$mode" == "ci" ]]; then
    if [[ ! -s "$guardplane_log_path" || ! -s "$containment_log_path" || ! -s "$containment_timeline_path" ]]; then
      outcome="fail"
      error_code_json='"FE-DELEGATE-0007"'
    fi
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  failed_log_json="$(json_or_null "$failed_log_path")"

  {
    echo "{\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.guardplane-policy-actions-suite.run-manifest.v1",'
    echo "  \"component\": \"${component}\","
    echo "  \"bead_id\": \"${bead_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"mode_completed\": ${mode_completed},"
    echo "  \"commands_executed\": ${#commands_run[@]},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    echo "  \"failed_log\": ${failed_log_json},"
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "command_logs": ['
    for idx in "${!command_logs[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#command_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${command_logs[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"guardplane_decision_log\": \"${guardplane_log_path}\","
    echo "    \"containment_workflow_log\": \"${containment_log_path}\","
    echo "    \"containment_timeline\": \"${containment_timeline_path}\","
    echo "    \"logs_dir\": \"${logs_dir}\","
    echo '    "source_module": "crates/franken-extension-host/src/lib.rs",'
    echo '    "suite_script": "scripts/run_guardplane_policy_actions_suite.sh"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${guardplane_log_path}\","
    echo "    \"cat ${containment_log_path}\","
    echo "    \"cat ${containment_timeline_path}\","
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "guardplane policy actions manifest: $manifest_path"
  echo "guardplane policy actions events: $events_path"
  echo "guardplane decision log: $guardplane_log_path"
  echo "containment workflow log: $containment_log_path"
  echo "containment timeline: $containment_timeline_path"
}

trap 'write_manifest $?' EXIT
run_mode
