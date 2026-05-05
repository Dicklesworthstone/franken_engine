#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_RESOURCE_GOVERNOR_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-resource-governor}"
run_id="${SWARM_RESOURCE_GOVERNOR_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_RESOURCE_GOVERNOR_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

bead_id="${SWARM_RESOURCE_GOVERNOR_BEAD_ID:-}"
active_compile_count="unknown"
max_active_compile_count="2"
disk_available_bytes="unknown"
min_disk_available_bytes="1073741824"
target_dir=""
target_dir_writable="unknown"
memory_available_bytes="unknown"
min_memory_available_bytes="1073741824"
rch_present="unknown"
rch_status="unknown"
rch_local_fallback="unknown"
command_exit_code="none"
command_failure_kind="none"
ownership_state="unknown"
dirty_state="unknown"
override_note=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_resource_governor.sh --bead-id ID [OPTIONS]

Required decision signals:
  --active-compile-count N       Current cargo/rustc process count.
  --disk-available-bytes N       Available bytes for validation artifacts.
  --target-dir DIR               Intended off-repo CARGO_TARGET_DIR.
  --target-dir-writable BOOL     true/false result for target-dir writability.
  --rch-present BOOL             true/false whether rch is available.
  --rch-status STATUS            ok, degraded, missing, or unknown.
  --rch-fallback-detected BOOL   true/false whether rch fallback-to-local was observed.
  --command-exit-code N|none     Prior command exit code when classifying a result.
  --command-failure-kind KIND    none, queue_timeout, worker_unavailable,
                                 fallback_to_local, build_failure, or unknown.
  --ownership-state STATE        none, overlap, or unknown.
  --dirty-state STATE            clean, unrelated, overlap, or unknown.

Optional signals:
  --memory-available-bytes N     Missing/unknown memory is visible safe mode.
  --override-note TEXT           Required to override high local compile count.
  --output-dir DIR               Write decision artifacts to DIR.

The governor does not execute builds, clean files, or mutate repository state.
It writes decision.json, commands.txt, and report.md.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bead-id)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      bead_id="$2"
      shift 2
      ;;
    --output-dir)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      run_dir="$2"
      shift 2
      ;;
    --active-compile-count)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      active_compile_count="$2"
      shift 2
      ;;
    --max-active-compile-count)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      max_active_compile_count="$2"
      shift 2
      ;;
    --disk-available-bytes)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      disk_available_bytes="$2"
      shift 2
      ;;
    --min-disk-available-bytes)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      min_disk_available_bytes="$2"
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
    --target-dir-writable)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      target_dir_writable="$2"
      shift 2
      ;;
    --memory-available-bytes)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      memory_available_bytes="$2"
      shift 2
      ;;
    --min-memory-available-bytes)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      min_memory_available_bytes="$2"
      shift 2
      ;;
    --rch-present)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      rch_present="$2"
      shift 2
      ;;
    --rch-status)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      rch_status="$2"
      shift 2
      ;;
    --rch-fallback-detected)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      rch_local_fallback="$2"
      shift 2
      ;;
    --command-exit-code)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      command_exit_code="$2"
      shift 2
      ;;
    --command-failure-kind)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      command_failure_kind="$2"
      shift 2
      ;;
    --ownership-state)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      ownership_state="$2"
      shift 2
      ;;
    --dirty-state)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      dirty_state="$2"
      shift 2
      ;;
    --override-note)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      override_note="$2"
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

if [[ -z "$bead_id" ]]; then
  printf 'swarm-resource-governor requires --bead-id\n' >&2
  usage
  exit 64
fi

mkdir -p "$run_dir"
decision_path="${run_dir}/decision.json"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
findings_jsonl="${run_dir}/findings.jsonl"
: >"$findings_jsonl"

printf './scripts/swarm_resource_governor.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

is_int() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

is_bool() {
  [[ "$1" == "true" || "$1" == "false" ]]
}

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

emit_finding() {
  local decision="$1"
  local signal="$2"
  local reason="$3"
  local remediation="$4"

  jq -nc \
    --arg decision "$decision" \
    --arg signal "$signal" \
    --arg reason "$reason" \
    --arg remediation "$remediation" \
    '{decision: $decision, signal: $signal, reason: $reason, remediation: $remediation}' >>"$findings_jsonl"
}

require_int_signal() {
  local value="$1"
  local signal="$2"

  if ! is_int "$value"; then
    emit_finding "fail_closed" "$signal" "missing_or_non_numeric" "Capture a numeric ${signal} value before admitting validation work."
    return 1
  fi
  return 0
}

require_bool_signal() {
  local value="$1"
  local signal="$2"

  if ! is_bool "$value"; then
    emit_finding "fail_closed" "$signal" "missing_or_non_boolean" "Capture ${signal}=true|false before admitting validation work."
    return 1
  fi
  return 0
}

if require_int_signal "$active_compile_count" "active_compile_count"; then
  if (( active_compile_count > max_active_compile_count )); then
    if [[ -n "$override_note" ]]; then
      emit_finding "admit_narrow" "active_compile_count" "operator_override_high_compile_count" "Proceed only with narrow/script-only validation and preserve the override note in evidence."
    else
      emit_finding "defer" "active_compile_count" "high_compile_count" "Wait for local cargo/rustc pressure to fall or provide an explicit override note for narrow validation."
    fi
  fi
fi

if require_int_signal "$disk_available_bytes" "disk_available_bytes"; then
  if (( disk_available_bytes < min_disk_available_bytes )); then
    emit_finding "fail_closed" "disk_available_bytes" "disk_pressure" "Free disk outside this governor or choose a host with enough artifact headroom before validation."
  fi
fi

if [[ -z "$target_dir" ]]; then
  emit_finding "fail_closed" "target_dir" "missing_target_dir" "Set an explicit off-repo CARGO_TARGET_DIR before admitting heavy validation."
else
  target_dir_abs="$(realpath -m "$target_dir" 2>/dev/null || printf '%s' "$target_dir")"
  case "$target_dir_abs" in
    "$root_dir"|"$root_dir"/*)
      emit_finding "fail_closed" "target_dir" "repo_local_target_dir" "Use an off-repo CARGO_TARGET_DIR so validation cannot fill the shared workspace target directory."
      ;;
  esac
fi

if require_bool_signal "$target_dir_writable" "target_dir_writable"; then
  if [[ "$target_dir_writable" == "false" ]]; then
    emit_finding "fail_closed" "target_dir_writable" "non_writable_target_dir" "Pick or create a writable off-repo target directory before running validation."
  fi
fi

if [[ "$memory_available_bytes" == "unknown" || -z "$memory_available_bytes" ]]; then
  emit_finding "admit_narrow" "memory_available_bytes" "missing_optional_memory_signal" "Memory evidence is unavailable; keep validation narrow and record the missing optional signal."
elif require_int_signal "$memory_available_bytes" "memory_available_bytes"; then
  if (( memory_available_bytes < min_memory_available_bytes )); then
    emit_finding "defer" "memory_available_bytes" "memory_pressure" "Wait for memory headroom or route validation to a healthier worker."
  fi
fi

if require_bool_signal "$rch_present" "rch_present"; then
  if [[ "$rch_present" == "false" ]]; then
    emit_finding "fail_closed" "rch_present" "missing_rch" "Install or repair rch before admitting heavy validation."
  fi
fi

case "$rch_status" in
  ok|healthy|remote)
    ;;
  degraded|busy)
    emit_finding "defer" "rch_status" "rch_degraded" "Wait for rch capacity or narrow the validation request before proceeding."
    ;;
  missing|unknown|"")
    emit_finding "fail_closed" "rch_status" "missing_rch_status" "Capture rch status evidence before admitting validation work."
    ;;
  *)
    emit_finding "fail_closed" "rch_status" "unsupported_rch_status" "Use one of: ok, healthy, remote, degraded, busy, missing, unknown."
    ;;
esac

if require_bool_signal "$rch_local_fallback" "rch_local_fallback"; then
  if [[ "$rch_local_fallback" == "true" ]]; then
    emit_finding "fail_closed" "rch_local_fallback" "local_fallback_detected" "Reject fallback-to-local markers and rerun only when rch reports a remote execution path."
  fi
fi

if [[ "$command_exit_code" == "none" || -z "$command_exit_code" ]]; then
  if [[ "$command_failure_kind" != "none" ]]; then
    emit_finding "fail_closed" "command_failure_kind" "failure_kind_without_exit_code" "Record the command exit code with any command failure classification."
  fi
elif require_int_signal "$command_exit_code" "command_exit_code"; then
  if (( command_exit_code == 0 )); then
    if [[ "$command_failure_kind" != "none" ]]; then
      emit_finding "fail_closed" "command_failure_kind" "failure_kind_with_success_exit" "Do not attach a failure classification to a successful command receipt."
    fi
  else
    case "$command_failure_kind" in
      queue_timeout|worker_unavailable)
        emit_finding "defer" "command_failure_kind" "$command_failure_kind" "Treat transient remote-capacity failures as deferral, not as permission to run locally."
        ;;
      fallback_to_local)
        emit_finding "fail_closed" "command_failure_kind" "fallback_to_local" "Reject fallback-to-local command receipts before publishing validation evidence."
        ;;
      build_failure)
        emit_finding "fail_closed" "command_failure_kind" "build_failure" "Keep the validation bead open and surface the command failure before admitting dependent proof."
        ;;
      none|unknown|"")
        emit_finding "fail_closed" "command_failure_kind" "unclassified_command_failure" "Classify the nonzero command exit before admitting or indexing validation evidence."
        ;;
      *)
        emit_finding "fail_closed" "command_failure_kind" "unsupported_command_failure_kind" "Use one of: none, queue_timeout, worker_unavailable, fallback_to_local, build_failure, unknown."
        ;;
    esac
  fi
fi

case "$ownership_state" in
  none)
    ;;
  overlap)
    emit_finding "defer" "ownership_state" "reserved_file_overlap" "Coordinate with the reservation holder or pick a non-overlapping bead."
    ;;
  unknown|"")
    emit_finding "fail_closed" "ownership_state" "unknown_file_ownership" "Resolve Agent Mail reservations or bead ownership before admitting validation work."
    ;;
  *)
    emit_finding "fail_closed" "ownership_state" "unsupported_ownership_state" "Use one of: none, overlap, unknown."
    ;;
esac

case "$dirty_state" in
  clean)
    ;;
  unrelated)
    emit_finding "admit_narrow" "dirty_state" "unrelated_dirty_worktree" "Proceed only with the planned narrow write set and avoid unrelated dirty files."
    ;;
  overlap)
    emit_finding "defer" "dirty_state" "dirty_overlap" "Defer or coordinate before touching dirty overlapping paths."
    ;;
  unknown|"")
    emit_finding "fail_closed" "dirty_state" "unknown_dirty_state" "Capture git dirty-state evidence before admitting validation work."
    ;;
  *)
    emit_finding "fail_closed" "dirty_state" "unsupported_dirty_state" "Use one of: clean, unrelated, overlap, unknown."
    ;;
esac

fail_count="$(jq -s '[.[] | select(.decision == "fail_closed")] | length' "$findings_jsonl")"
defer_count="$(jq -s '[.[] | select(.decision == "defer")] | length' "$findings_jsonl")"
narrow_count="$(jq -s '[.[] | select(.decision == "admit_narrow")] | length' "$findings_jsonl")"
decision="admit"
exit_code=0
if [[ "$fail_count" -ne 0 ]]; then
  decision="fail_closed"
  exit_code=42
elif [[ "$defer_count" -ne 0 ]]; then
  decision="defer"
  exit_code=75
elif [[ "$narrow_count" -ne 0 ]]; then
  decision="admit_narrow"
fi

decision_id_input="$(
  jq -c -n \
    --arg bead_id "$bead_id" \
    --arg active_compile_count "$active_compile_count" \
    --arg disk_available_bytes "$disk_available_bytes" \
    --arg target_dir "$target_dir" \
    --arg target_dir_writable "$target_dir_writable" \
    --arg memory_available_bytes "$memory_available_bytes" \
    --arg rch_present "$rch_present" \
    --arg rch_status "$rch_status" \
    --arg rch_local_fallback "$rch_local_fallback" \
    --arg command_exit_code "$command_exit_code" \
    --arg command_failure_kind "$command_failure_kind" \
    --arg ownership_state "$ownership_state" \
    --arg dirty_state "$dirty_state" \
    --arg override_note "$override_note" \
    '{
      bead_id: $bead_id,
      active_compile_count: $active_compile_count,
      disk_available_bytes: $disk_available_bytes,
      target_dir: $target_dir,
      target_dir_writable: $target_dir_writable,
      memory_available_bytes: $memory_available_bytes,
      rch_present: $rch_present,
      rch_status: $rch_status,
      rch_local_fallback: $rch_local_fallback,
      command_exit_code: $command_exit_code,
      command_failure_kind: $command_failure_kind,
      ownership_state: $ownership_state,
      dirty_state: $dirty_state,
      override_note: $override_note
    }'
)"
decision_id="swarm-resource-governor-$(sha256_text "$decision_id_input" | cut -c1-16)"

# shellcheck disable=SC2094
jq -n \
  --arg schema_version "franken-engine.swarm-resource-governor-decision.v1" \
  --arg decision_id "$decision_id" \
  --arg bead_id "$bead_id" \
  --arg decision "$decision" \
  --arg target_dir "$target_dir" \
  --arg override_note "$override_note" \
  --arg decision_path "$decision_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --argjson active_compile_count "$(if is_int "$active_compile_count"; then printf '%s' "$active_compile_count"; else printf 'null'; fi)" \
  --argjson max_active_compile_count "$max_active_compile_count" \
  --argjson disk_available_bytes "$(if is_int "$disk_available_bytes"; then printf '%s' "$disk_available_bytes"; else printf 'null'; fi)" \
  --argjson min_disk_available_bytes "$min_disk_available_bytes" \
  --argjson target_dir_writable "$(if is_bool "$target_dir_writable"; then printf '%s' "$target_dir_writable"; else printf 'null'; fi)" \
  --argjson memory_available_bytes "$(if is_int "$memory_available_bytes"; then printf '%s' "$memory_available_bytes"; else printf 'null'; fi)" \
  --argjson min_memory_available_bytes "$min_memory_available_bytes" \
  --argjson rch_present "$(if is_bool "$rch_present"; then printf '%s' "$rch_present"; else printf 'null'; fi)" \
  --arg rch_status "$rch_status" \
  --argjson rch_local_fallback "$(if is_bool "$rch_local_fallback"; then printf '%s' "$rch_local_fallback"; else printf 'null'; fi)" \
  --argjson command_exit_code "$(if is_int "$command_exit_code"; then printf '%s' "$command_exit_code"; else printf 'null'; fi)" \
  --arg command_failure_kind "$command_failure_kind" \
  --arg ownership_state "$ownership_state" \
  --arg dirty_state "$dirty_state" \
  --slurpfile findings "$findings_jsonl" \
  '{
    schema_version: $schema_version,
    decision_id: $decision_id,
    bead_id: $bead_id,
    decision: $decision,
    evidence_ready: ($decision == "admit" or $decision == "admit_narrow"),
    override_note: (if $override_note == "" then null else $override_note end),
    thresholds: {
      max_active_compile_count: $max_active_compile_count,
      min_disk_available_bytes: $min_disk_available_bytes,
      min_memory_available_bytes: $min_memory_available_bytes
    },
    signals: {
      active_compile_count: $active_compile_count,
      disk_available_bytes: $disk_available_bytes,
      target_dir: (if $target_dir == "" then null else $target_dir end),
      target_dir_writable: $target_dir_writable,
      memory_available_bytes: $memory_available_bytes,
      rch_present: $rch_present,
      rch_status: $rch_status,
      rch_local_fallback: $rch_local_fallback,
      command_exit_code: $command_exit_code,
      command_failure_kind: $command_failure_kind,
      ownership_state: $ownership_state,
      dirty_state: $dirty_state
    },
    findings: ($findings | sort_by(.decision, .signal, .reason)),
    remediation: ($findings | map(.remediation) | sort | unique),
    artifact_paths: {
      decision_json: $decision_path,
      commands_txt: $commands_path,
      report_md: $report_path
    }
  }' >"$decision_path"

{
  printf '# Swarm Resource Governor Decision\n\n'
  printf -- "- Bead: \`%s\`\n" "$bead_id"
  printf -- "- Decision: \`%s\`\n" "$decision"
  printf -- "- Evidence ready: \`%s\`\n\n" "$(jq -r '.evidence_ready' "$decision_path")"
  if [[ "$(jq '.findings | length' "$decision_path")" -eq 0 ]]; then
    printf 'No degraded signals were found.\n'
  else
    jq -r '.findings[] | "- `" + .signal + "` -> `" + .decision + "`: " + .reason + ". " + .remediation' "$decision_path"
  fi
} >"$report_path"

printf 'swarm_resource_governor_decision=%s\n' "$decision_path"
printf 'swarm_resource_governor_report=%s\n' "$report_path"

exit "$exit_code"
