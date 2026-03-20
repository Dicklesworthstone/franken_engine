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
artifact_root="${RGC_SUPPORT_SURFACE_CONTRACT_ARTIFACT_ROOT:-artifacts/rgc_support_surface_contract}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_rgc_support_surface_contract_${target_namespace}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
schema_report_path="${run_dir}/support_surface_schema_report.json"
copied_contract_path="${run_dir}/support_surface_contract.json"
copied_mode_matrix_path="${run_dir}/support_surface_mode_matrix.json"
step_logs_dir="${run_dir}/step_logs"

contract_doc="docs/RGC_SUPPORT_SURFACE_CONTRACT_V1.md"
contract_json="docs/support_surface_contract.json"
mode_matrix_json="docs/support_surface_mode_matrix.json"

trace_id="trace-rgc-support-surface-contract-${timestamp}"
decision_id="decision-rgc-support-surface-contract-${timestamp}"
policy_id="policy-rgc-support-surface-contract-v1"
component="rgc_support_surface_contract_gate"
scenario_id="rgc-408a"
replay_command="./scripts/e2e/rgc_support_surface_contract_replay.sh ${mode}"
dirty_worktree_json="true"

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

if [[ ! -f "$contract_doc" ]]; then
  echo "FE-RGC-408A-CONTRACT-0001: missing contract doc (${contract_doc})" >&2
  exit 1
fi

if [[ ! -f "$contract_json" ]]; then
  echo "FE-RGC-408A-CONTRACT-0002: missing contract JSON (${contract_json})" >&2
  exit 1
fi

if [[ ! -f "$mode_matrix_json" ]]; then
  echo "FE-RGC-408A-CONTRACT-0003: missing mode matrix JSON (${mode_matrix_json})" >&2
  exit 1
fi

if ! jq -e '.' "$contract_json" >/dev/null 2>&1; then
  echo "FE-RGC-408A-CONTRACT-0004: failed to parse contract JSON (${contract_json})" >&2
  exit 1
fi

if ! jq -e '.' "$mode_matrix_json" >/dev/null 2>&1; then
  echo "FE-RGC-408A-CONTRACT-0005: failed to parse mode matrix JSON (${mode_matrix_json})" >&2
  exit 1
fi

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC support-surface contract heavy commands" >&2
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
manifest_written=false
step_log_index=0

run_step() {
  local command_text="$1"
  local log_path status remote_exit_code
  shift

  commands_run+=("${command_text}")
  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  step_log_index=$((step_log_index + 1))

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

validate_source_inputs() {
  local input

  commands_run+=("jq empty ${contract_json}")
  commands_run+=("jq empty ${mode_matrix_json}")

  mapfile -t source_inputs < <(jq -r '.source_inputs[]' "$contract_json")
  validation_errors=()

  for input in "${source_inputs[@]}"; do
    if [[ ! -e "$input" ]]; then
      validation_errors+=("missing source input: ${input}")
    fi
  done

  mapfile -t required_areas < <(printf '%s\n' parser typescript runtime module platform_support observability_mode)
  for input in "${required_areas[@]}"; do
    if ! jq -e --arg area "$input" '.surface_rows | any(.area == $area)' "$contract_json" >/dev/null; then
      validation_errors+=("missing support-surface area: ${input}")
    fi
  done

  if ! jq -e '
      .surface_rows
      | all(
          if .support_status == "shipped" then
            .claim_language_state == "shipped_fact"
          else
            .claim_language_state == "target_only"
            and (.user_visible_diagnostic != null)
            and ((.user_visible_diagnostic.message_template // "") | length > 0)
            and ((.user_visible_diagnostic.remediation // "") | length > 0)
            and (.fallback_policy.user_visible_diagnostics_required == true)
          end
        )
    ' "$contract_json" >/dev/null; then
    validation_errors+=("support-surface rows violate guidance or claim-language invariants")
  fi

  if ! jq -e '
      .modes
      | map(.mode_id)
      | index("default_capture")
      and index("degraded")
      and index("exact_shadow")
      and index("support_bundle_export")
      and index("incident_full_capture")
    ' "$mode_matrix_json" >/dev/null; then
    validation_errors+=("mode matrix missing one or more required modes")
  fi

  if (( ${#validation_errors[@]} > 0 )); then
    printf '%s\n' "${validation_errors[@]}" >&2
    return 1
  fi

  return 0
}

copy_contract_artifacts() {
  commands_run+=("cp ${contract_json} ${copied_contract_path}")
  commands_run+=("cp ${mode_matrix_json} ${copied_mode_matrix_path}")
  cp "$contract_json" "$copied_contract_path"
  cp "$mode_matrix_json" "$copied_mode_matrix_path"
}

run_mode() {
  local mode_exit=0

  case "$mode" in
  check)
    run_step "cargo check -p frankenengine-engine --test support_surface_contract" \
      cargo check -p frankenengine-engine --test support_surface_contract || mode_exit=$?
    ;;
  test)
    run_step "cargo test -p frankenengine-engine --test support_surface_contract" \
      cargo test -p frankenengine-engine --test support_surface_contract || mode_exit=$?
    ;;
  clippy)
    run_step "cargo clippy -p frankenengine-engine --test support_surface_contract -- -D warnings" \
      cargo clippy -p frankenengine-engine --test support_surface_contract -- -D warnings || mode_exit=$?
    ;;
  ci)
    run_step "cargo check -p frankenengine-engine --test support_surface_contract" \
      cargo check -p frankenengine-engine --test support_surface_contract || mode_exit=$?
    if [[ "$mode_exit" -eq 0 ]]; then
      run_step "cargo test -p frankenengine-engine --test support_surface_contract" \
        cargo test -p frankenengine-engine --test support_surface_contract || mode_exit=$?
    fi
    if [[ "$mode_exit" -eq 0 ]]; then
      run_step "cargo clippy -p frankenengine-engine --test support_surface_contract -- -D warnings" \
        cargo clippy -p frankenengine-engine --test support_surface_contract -- -D warnings || mode_exit=$?
    fi
    ;;
  *)
    echo "usage: $0 [check|test|clippy|ci]" >&2
    exit 2
    ;;
  esac

  return "$mode_exit"
}

write_report() {
  local outcome="$1"
  local source_inputs_json areas_json status_counts_json non_shipped_json mode_rows_json

  source_inputs_json="$(jq '.source_inputs' "$contract_json")"
  areas_json="$(jq '[.surface_rows[].area] | unique' "$contract_json")"
  status_counts_json="$(jq '[.surface_rows[].support_status] | reduce .[] as $status ({}; .[$status] = ((.[$status] // 0) + 1))' "$contract_json")"
  non_shipped_json="$(jq '[.surface_rows[] | select(.support_status != "shipped") | .surface_id]' "$contract_json")"
  mode_rows_json="$(jq '.surface_mode_rows' "$mode_matrix_json")"

  jq -n \
    --arg schema_version "franken-engine.rgc-support-surface-contract.schema-report.v1" \
    --arg bead_id "bd-1lsy.5.10.1" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg generated_at_utc "$timestamp" \
    --arg outcome "$outcome" \
    --arg contract_doc "$contract_doc" \
    --arg contract_json_path "$copied_contract_path" \
    --arg mode_matrix_json_path "$copied_mode_matrix_path" \
    --argjson source_inputs "$source_inputs_json" \
    --argjson areas "$areas_json" \
    --argjson status_counts "$status_counts_json" \
    --argjson non_shipped_surfaces "$non_shipped_json" \
    --argjson mode_rows "$mode_rows_json" \
    --argjson validation_errors "$(json_array_from_args "${validation_errors[@]}")" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      generated_at_utc: $generated_at_utc,
      outcome: $outcome,
      inputs: {
        contract_doc: $contract_doc,
        contract_json: $contract_json_path,
        mode_matrix_json: $mode_matrix_json_path,
        source_inputs: $source_inputs
      },
      coverage: {
        areas: $areas,
        status_counts: $status_counts,
        non_shipped_surfaces: $non_shipped_surfaces,
        mode_rows: $mode_rows
      },
      validation_errors: $validation_errors
    }' >"$schema_report_path"
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome git_commit error_code_json contract_operator_verification_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-408A-GATE-0001"'
  fi

  write_report "$outcome"
  jq -n --arg trace_id "$trace_id" '[$trace_id]' >"$trace_ids_path"
  contract_operator_verification_json="$(jq '.operator_verification' "$contract_json")"

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  jq -cn \
    --arg schema_version "franken-engine.rgc-support-surface-contract.event.v1" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg event "gate_completed" \
    --arg surface_id "support_surface_contract" \
    --arg outcome "$outcome" \
    --argjson error_code "$error_code_json" \
    '{schema_version: $schema_version, trace_id: $trace_id, decision_id: $decision_id, policy_id: $policy_id, component: $component, event: $event, surface_id: $surface_id, outcome: $outcome, error_code: $error_code}' \
    >"$events_path"

  jq -n \
    --arg schema_version "franken-engine.rgc-support-surface-contract.run-manifest.v1" \
    --arg bead_id "bd-1lsy.5.10.1" \
    --arg component "$component" \
    --arg scenario_id "$scenario_id" \
    --arg mode "$mode" \
    --arg toolchain "$toolchain" \
    --arg cargo_target_dir "$target_dir" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg git_commit "$git_commit" \
    --arg generated_at_utc "$timestamp" \
    --arg outcome "$outcome" \
    --arg replay_command "$replay_command" \
    --arg manifest "$manifest_path" \
    --arg events "$events_path" \
    --arg commands "$commands_path" \
    --arg trace_ids "$trace_ids_path" \
    --arg schema_report "$schema_report_path" \
    --arg contract_json_path "$copied_contract_path" \
    --arg mode_matrix_json_path "$copied_mode_matrix_path" \
    --arg contract_doc_path "$contract_doc" \
    --arg step_logs "$step_logs_dir" \
    --arg failed_command "$failed_command" \
    --argjson dirty_worktree "$dirty_worktree_json" \
    --argjson rch_exec_timeout_seconds "$rch_timeout_seconds" \
    --argjson contract_operator_verification "$contract_operator_verification_json" \
    --argjson commands_run "$(json_array_from_args "${commands_run[@]}")" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      component: $component,
      scenario_id: $scenario_id,
      mode: $mode,
      toolchain: $toolchain,
      cargo_target_dir: $cargo_target_dir,
      rch_exec_timeout_seconds: $rch_exec_timeout_seconds,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      git_commit: $git_commit,
      dirty_worktree: $dirty_worktree,
      generated_at_utc: $generated_at_utc,
      outcome: $outcome,
      failed_command: (if ($failed_command | length) > 0 then $failed_command else null end),
      replay_command: $replay_command,
      commands: $commands_run,
      artifacts: {
        manifest: $manifest,
        events: $events,
        commands: $commands,
        trace_ids: $trace_ids,
        support_surface_schema_report: $schema_report,
        support_surface_contract: $contract_json_path,
        support_surface_mode_matrix: $mode_matrix_json_path,
        contract_doc: $contract_doc_path,
        step_logs: $step_logs,
        contract_test: "crates/franken-engine/tests/support_surface_contract.rs"
      },
      operator_verification: [
        ("cat " + $manifest),
        ("cat " + $events),
        ("cat " + $commands),
        ("cat " + $trace_ids),
        ("cat " + $schema_report)
      ] + $contract_operator_verification
    }' >"$manifest_path"

  echo "rgc support-surface contract manifest: ${manifest_path}"
  echo "rgc support-surface contract events: ${events_path}"
}

main_exit=0
copy_contract_artifacts
validate_source_inputs || main_exit=$?
if [[ "$main_exit" -eq 0 ]]; then
  run_mode || main_exit=$?
fi
write_manifest "$main_exit"
exit "$main_exit"
