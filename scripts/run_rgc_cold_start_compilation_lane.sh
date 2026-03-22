#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
cargo_incremental="${CARGO_INCREMENTAL:-0}"
artifact_root="${RGC_COLD_START_COMPILATION_LANE_ARTIFACT_ROOT:-artifacts/rgc_cold_start_compilation_lane}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_rgc_cold_start_compilation_lane_${target_namespace}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/cold_start_compilation_report.json"
observability_delta_path="${run_dir}/cold_start_observability_delta.json"
aot_bundle_path="${run_dir}/aot_bundle_compilation_report.json"
runtime_image_manifest_path="${run_dir}/runtime_image_manifest.json"
trace_ids_path="${run_dir}/trace_ids.json"
summary_path="${run_dir}/summary.md"
step_logs_dir="${run_dir}/step_logs"

doc_path="docs/RGC_COLD_START_COMPILATION_LANE_V1.md"
trace_id="trace-rgc-cold-start-compilation-lane-${timestamp}"
decision_id="decision-rgc-cold-start-compilation-lane-${timestamp}"
policy_id="policy-rgc-cold-start-compilation-lane-v1"
component="rgc_cold_start_compilation_lane_gate"
scenario_id="rgc-610-parent"
replay_command="./scripts/e2e/rgc_cold_start_compilation_lane_replay.sh ${mode}"
dirty_worktree_json="true"
source_commit="$(git rev-parse HEAD 2>/dev/null || printf 'unknown')"
bundle_json_begin_marker="__RGC_COLD_START_COMPILATION_LANE_BUNDLE_JSON_BEGIN__"
bundle_json_end_marker="__RGC_COLD_START_COMPILATION_LANE_BUNDLE_JSON_END__"

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  worktree_status="$(
    git status --short --untracked-files=normal -- . \
      ":(exclude)${artifact_root%/}/" \
      ":(exclude).beads/" \
      ":(exclude).claude/" 2>/dev/null || true
  )"
  if [[ -z "$worktree_status" ]]; then
    dirty_worktree_json="false"
  fi
fi

mkdir -p "$run_dir" "$step_logs_dir"

if [[ ! -f "$doc_path" ]]; then
  echo "FE-RGC-610-CONTRACT-0001: missing doc (${doc_path})" >&2
  exit 1
fi

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC cold-start compilation lane heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "CARGO_INCREMENTAL=${cargo_incremental}" \
    "$@"
}

rch_strip_ansi() {
  sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g' "$1"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n1 || true)"
  if [[ -z "$remote_exit_line" ]]; then
    return 1
  fi

  remote_exit_code="${remote_exit_line##*=}"
  if [[ -z "$remote_exit_code" ]]; then
    return 1
  fi

  printf '%s\n' "$remote_exit_code"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_recovered_success() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | rg -q 'Remote command finished: exit=0|Finished.*profile|test result: ok\.' \
    && ! rch_strip_ansi "$log_path" | rg -qi 'error(\[[[:alnum:]]+\])?:'; then
    return 0
  fi
  return 1
}

json_array_from_args() {
  if [[ "$#" -eq 0 ]]; then
    printf '[]'
    return
  fi

  printf '%s\n' "$@" | jq -R . | jq -s .
}

declare -a commands_run=()
declare -a validation_errors=()
failed_command=""
step_log_index=0
last_step_log_path=""

run_step() {
  local command_text="$1"
  local log_path status remote_exit_code
  shift

  commands_run+=("${command_text}")
  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  step_log_index=$((step_log_index + 1))
  last_step_log_path="${log_path}"

  echo "==> ${command_text}"

  set +e
  run_rch "$@" > >(tee "$log_path") 2>&1
  status=$?
  set -e

  if [[ "${status}" -ne 0 ]]; then
    if [[ "${status}" -eq 124 ]]; then
      echo "==> failure: rch command timed out after ${rch_timeout_seconds}s" | tee -a "$log_path"
      failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      return 1
    fi

    if rch_recovered_success "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
      if [[ -n "${remote_exit_code}" ]]; then
        failed_command="${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})"
      else
        failed_command="${command_text} (rch-exit=${status}; missing-remote-exit-marker)"
      fi
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -z "$remote_exit_code" ]]; then
    failed_command="${command_text} (rch-exit=${status}; missing-remote-exit-marker)"
    return 1
  fi
  if [[ "$remote_exit_code" != "0" ]]; then
    failed_command="${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})"
    return 1
  fi
}

record_error() {
  validation_errors+=("$1")
}

run_mode() {
  local selected_mode="${1:-$mode}"
  local mode_exit=0

  case "$selected_mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test cold_start_compilation_lane --bin franken_cold_start_compilation_lane" \
        cargo check -p frankenengine-engine --test cold_start_compilation_lane --bin franken_cold_start_compilation_lane || mode_exit=$?
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test cold_start_compilation_lane -- --nocapture" \
        cargo test -p frankenengine-engine --test cold_start_compilation_lane -- --nocapture || mode_exit=$?
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test cold_start_compilation_lane --bin franken_cold_start_compilation_lane -- -D warnings" \
        cargo clippy -p frankenengine-engine --test cold_start_compilation_lane --bin franken_cold_start_compilation_lane -- -D warnings || mode_exit=$?
      ;;
    run)
      run_step "cargo run -p frankenengine-engine --bin franken_cold_start_compilation_lane -- --artifact-dir ${run_dir} --trace-id ${trace_id} --decision-id ${decision_id} --policy-id ${policy_id} --run-id ${timestamp} --generated-at-utc ${generated_at_utc} --source-commit ${source_commit} --toolchain ${toolchain} --summary --emit-local-bundle-json" \
        cargo run -p frankenengine-engine --bin franken_cold_start_compilation_lane -- \
          --artifact-dir "${run_dir}" \
          --trace-id "${trace_id}" \
          --decision-id "${decision_id}" \
          --policy-id "${policy_id}" \
          --run-id "${timestamp}" \
          --generated-at-utc "${generated_at_utc}" \
          --source-commit "${source_commit}" \
          --toolchain "${toolchain}" \
          --summary \
          --emit-local-bundle-json || mode_exit=$?
      ;;
    ci)
      run_mode check || mode_exit=$?
      if [[ "${mode_exit}" -eq 0 ]]; then
        run_mode test || mode_exit=$?
      fi
      if [[ "${mode_exit}" -eq 0 ]]; then
        run_mode clippy || mode_exit=$?
      fi
      if [[ "${mode_exit}" -eq 0 ]]; then
        run_mode run || mode_exit=$?
      fi
      ;;
    *)
      echo "unknown mode '${selected_mode}' (expected: check|test|clippy|run|ci)" >&2
      exit 1
      ;;
  esac

  return "${mode_exit}"
}

extract_remote_bundle_json() {
  local log_path="$1"
  local payload

  payload="$(
    rch_strip_ansi "$log_path" | awk \
      -v begin="${bundle_json_begin_marker}" \
      -v end="${bundle_json_end_marker}" '
        $0 == begin { capture = 1; next }
        $0 == end { capture = 0; exit }
        capture { print }
      '
  )"

  if [[ -z "${payload}" ]]; then
    return 1
  fi

  printf '%s\n' "${payload}"
}

ensure_local_bundle_materialized() {
  case "$mode" in
    run|ci) ;;
    *)
      return 0
      ;;
  esac

  if [[ -f "${report_path}" ]] \
    && [[ -f "${observability_delta_path}" ]] \
    && [[ -f "${aot_bundle_path}" ]] \
    && [[ -f "${runtime_image_manifest_path}" ]] \
    && [[ -f "${trace_ids_path}" ]] \
    && [[ -f "${summary_path}" ]] \
    && [[ -f "${run_dir}/persistent_cache_contract/persistent_cache_contract.json" ]]; then
    return 0
  fi

  if [[ -n "${last_step_log_path}" ]] && extract_remote_bundle_json "${last_step_log_path}" >/dev/null; then
    while IFS= read -r entry; do
      local relative_path destination_path
      relative_path="$(printf '%s\n' "${entry}" | jq -r '.relative_path')"
      destination_path="${run_dir}/${relative_path}"
      mkdir -p "$(dirname "${destination_path}")"
      printf '%s\n' "${entry}" | jq -r '.contents' >"${destination_path}"
    done < <(extract_remote_bundle_json "${last_step_log_path}" | jq -cr '.files[]')
    return 0
  fi

  record_error "remote bundle archive could not be materialized locally"
  return 1
}

validate_artifacts() {
  case "$mode" in
    run|ci) ;;
    *)
      return 0
      ;;
  esac

  commands_run+=("jq '.schema_version' ${report_path}")
  commands_run+=("jq '.schema_version' ${observability_delta_path}")
  commands_run+=("jq '.schema_version' ${aot_bundle_path}")
  commands_run+=("jq '.schema_version' ${runtime_image_manifest_path}")
  commands_run+=("jq '.schema_version' ${trace_ids_path}")

  [[ -f "${report_path}" ]] || record_error "missing ${report_path}"
  [[ -f "${observability_delta_path}" ]] || record_error "missing ${observability_delta_path}"
  [[ -f "${aot_bundle_path}" ]] || record_error "missing ${aot_bundle_path}"
  [[ -f "${runtime_image_manifest_path}" ]] || record_error "missing ${runtime_image_manifest_path}"
  [[ -f "${trace_ids_path}" ]] || record_error "missing ${trace_ids_path}"
  [[ -f "${summary_path}" ]] || record_error "missing ${summary_path}"
  [[ -f "${run_dir}/persistent_cache_contract/persistent_cache_contract.json" ]] || record_error "missing persistent cache subbundle contract"

  if [[ -f "${report_path}" ]]; then
    jq -e '.schema_version == "franken-engine.rgc-cold-start-compilation-report.v1"' "${report_path}" >/dev/null \
      || record_error "report schema_version mismatch"
  fi
  if [[ -f "${observability_delta_path}" ]]; then
    jq -e '.schema_version == "franken-engine.rgc-cold-start-observability-delta.v1"' "${observability_delta_path}" >/dev/null \
      || record_error "observability delta schema_version mismatch"
  fi
  if [[ -f "${aot_bundle_path}" ]]; then
    jq -e '.schema_version == "franken-engine.rgc-cold-start-aot-bundle.v1"' "${aot_bundle_path}" >/dev/null \
      || record_error "AOT bundle schema_version mismatch"
  fi
  if [[ -f "${runtime_image_manifest_path}" ]]; then
    jq -e '.schema_version == "franken-engine.rgc-cold-start-runtime-image-manifest.v1"' "${runtime_image_manifest_path}" >/dev/null \
      || record_error "runtime image manifest schema_version mismatch"
  fi
  if [[ -f "${trace_ids_path}" ]]; then
    jq -e '.schema_version == "franken-engine.rgc-cold-start-trace-ids.v1"' "${trace_ids_path}" >/dev/null \
      || record_error "trace_ids schema_version mismatch"
  fi
}

write_commands_file() {
  printf '%s\n' "${commands_run[@]}" >"${commands_path}"
}

write_manifest() {
  local validation_errors_json
  validation_errors_json="$(json_array_from_args "${validation_errors[@]}")"

  jq -n \
    --arg schema_version "franken-engine.rgc-cold-start-compilation-run-manifest.v1" \
    --arg component "${component}" \
    --arg bead_id "bd-1lsy.7.10" \
    --arg policy_id "${policy_id}" \
    --arg scenario_id "${scenario_id}" \
    --arg mode "${mode}" \
    --arg generated_at_utc "${generated_at_utc}" \
    --arg source_commit "${source_commit}" \
    --arg toolchain "${toolchain}" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg replay_command "${replay_command}" \
    --arg report_path "${report_path}" \
    --arg observability_delta_path "${observability_delta_path}" \
    --arg aot_bundle_path "${aot_bundle_path}" \
    --arg runtime_image_manifest_path "${runtime_image_manifest_path}" \
    --arg trace_ids_path "${trace_ids_path}" \
    --arg summary_path "${summary_path}" \
    --arg commands_path "${commands_path}" \
    --arg events_path "${events_path}" \
    --arg step_logs_dir "${step_logs_dir}" \
    --argjson dirty_worktree "${dirty_worktree_json}" \
    --arg failed_command "${failed_command}" \
    --argjson validation_errors "${validation_errors_json}" \
    '{
      schema_version: $schema_version,
      component: $component,
      bead_id: $bead_id,
      policy_id: $policy_id,
      scenario_id: $scenario_id,
      mode: $mode,
      generated_at_utc: $generated_at_utc,
      source_commit: $source_commit,
      toolchain: $toolchain,
      trace_id: $trace_id,
      decision_id: $decision_id,
      replay_command: $replay_command,
      dirty_worktree: $dirty_worktree,
      failed_command: (if $failed_command == "" then null else $failed_command end),
      validation_errors: $validation_errors,
      artifacts: {
        cold_start_compilation_report: (if ($mode == "run" or $mode == "ci") then $report_path else null end),
        cold_start_observability_delta: (if ($mode == "run" or $mode == "ci") then $observability_delta_path else null end),
        aot_bundle_compilation_report: (if ($mode == "run" or $mode == "ci") then $aot_bundle_path else null end),
        runtime_image_manifest: (if ($mode == "run" or $mode == "ci") then $runtime_image_manifest_path else null end),
        trace_ids: (if ($mode == "run" or $mode == "ci") then $trace_ids_path else null end),
        summary: (if ($mode == "run" or $mode == "ci") then $summary_path else null end),
        persistent_cache_contract: (if ($mode == "run" or $mode == "ci") then ($report_path | sub("/cold_start_compilation_report.json$"; "/persistent_cache_contract/persistent_cache_contract.json")) else null end),
        commands: $commands_path,
        events: $events_path,
        step_logs_dir: $step_logs_dir
      }
    }' >"${manifest_path}"
}

write_events() {
  local outcome error_code
  if [[ -n "${failed_command}" || ${#validation_errors[@]} -gt 0 ]]; then
    outcome="failed"
    error_code="FE-RGC-610-LANE-0001"
  else
    outcome="ok"
    error_code=""
  fi

  jq -cn \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg component "${component}" \
    --arg event "lane_completed" \
    --arg outcome "${outcome}" \
    --arg scenario_id "${scenario_id}" \
    --arg detail "cold-start compilation lane completed" \
    --arg error_code "${error_code}" \
    '{
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: $event,
      outcome: $outcome,
      error_code: (if $error_code == "" then null else $error_code end),
      scenario_id: $scenario_id,
      detail: $detail
    }' >"${events_path}"
}

mode_exit=0
if ! run_mode; then
  mode_exit=$?
  if [[ -z "${failed_command}" ]]; then
    failed_command="mode-${mode} exited ${mode_exit}"
  fi
fi

if [[ "${mode_exit}" -eq 0 ]]; then
  ensure_local_bundle_materialized || true
  validate_artifacts
fi
write_commands_file
write_manifest
write_events

if [[ "${mode_exit}" -ne 0 || -n "${failed_command}" || ${#validation_errors[@]} -gt 0 ]]; then
  printf '%s\n' "${validation_errors[@]}" >&2
  exit 1
fi
