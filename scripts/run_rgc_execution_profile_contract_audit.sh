#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/data/projects/franken_engine/target_rch_rgc_execution_profile_contract}"
artifact_root="${RGC_EXECUTION_PROFILE_CONTRACT_ARTIFACT_ROOT:-artifacts/rgc_execution_profile_contract_audit}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/execution_profile_contract_report.json"
step_logs_dir="${run_dir}/step_logs"

contract_doc="docs/RGC_EXECUTION_PROFILE_CONTRACT_MIGRATION_V1.md"
contract_json="docs/rgc_execution_profile_contract_v1.json"

trace_id="trace-rgc-execution-profile-contract-${timestamp}"
decision_id="decision-rgc-execution-profile-contract-${timestamp}"
policy_id="policy-rgc-execution-profile-contract-v1"
component="rgc_execution_profile_contract_gate"
scenario_id="rgc-310a"
replay_command="./scripts/e2e/rgc_execution_profile_contract_audit_replay.sh ${mode}"

mkdir -p "$run_dir" "$step_logs_dir"

if [[ ! -f "$contract_doc" ]]; then
  echo "FE-RGC-310A-CONTRACT-0001: missing migration doc (${contract_doc})" >&2
  exit 1
fi

if [[ ! -f "$contract_json" ]]; then
  echo "FE-RGC-310A-CONTRACT-0002: missing contract JSON (${contract_json})" >&2
  exit 1
fi

if ! jq -e '.' "$contract_json" >/dev/null 2>&1; then
  echo "FE-RGC-310A-CONTRACT-0003: failed to parse contract JSON (${contract_json})" >&2
  exit 1
fi

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for the execution-profile contract audit" >&2
  exit 2
fi

declare -a commands_run=()
declare -a missing_readme_fragments=()
declare -a banned_readme_fragments_found=()
declare -a missing_migration_fragments=()
declare -a missing_source_checks=()
failed_command=""
step_log_index=0
last_step_log_path=""
run_status="failed"
exit_code=1

json_array_from_args() {
  if [[ "$#" -eq 0 ]]; then
    printf '[]'
    return
  fi

  printf '%s\n' "$@" | jq -R . | jq -s .
}

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
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

run_step() {
  local command_text="$1"
  local log_path status remote_exit_code
  shift

  commands_run+=("${command_text}")
  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  step_log_index=$((step_log_index + 1))
  last_step_log_path="$log_path"

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

validate_readme_against_contract() {
  local fragment
  mapfile -t required_readme_fragments < <(jq -r '.required_readme_fragments[]' "$contract_json")
  mapfile -t banned_readme_fragments < <(jq -r '.banned_readme_fragments[]' "$contract_json")

  missing_readme_fragments=()
  banned_readme_fragments_found=()

  for fragment in "${required_readme_fragments[@]}"; do
    if ! rg -Fq -- "$fragment" README.md; then
      missing_readme_fragments+=("$fragment")
    fi
  done

  for fragment in "${banned_readme_fragments[@]}"; do
    if rg -Fq -- "$fragment" README.md; then
      banned_readme_fragments_found+=("$fragment")
    fi
  done

  if [[ "${#missing_readme_fragments[@]}" -gt 0 || "${#banned_readme_fragments_found[@]}" -gt 0 ]]; then
    for fragment in "${missing_readme_fragments[@]}"; do
      echo "missing README fragment: ${fragment}" >&2
    done
    for fragment in "${banned_readme_fragments_found[@]}"; do
      echo "unsupported README fragment still present: ${fragment}" >&2
    done
    return 1
  fi

  return 0
}

validate_migration_doc_against_contract() {
  local fragment
  mapfile -t required_migration_fragments < <(jq -r '.required_migration_fragments[]' "$contract_json")

  missing_migration_fragments=()

  for fragment in "${required_migration_fragments[@]}"; do
    if ! rg -Fq -- "$fragment" "$contract_doc"; then
      missing_migration_fragments+=("$fragment")
    fi
  done

  if [[ "${#missing_migration_fragments[@]}" -gt 0 ]]; then
    for fragment in "${missing_migration_fragments[@]}"; do
      echo "missing migration-doc fragment: ${fragment}" >&2
    done
    return 1
  fi

  return 0
}

validate_source_fragments_against_contract() {
  local check_json path fragment
  missing_source_checks=()

  while IFS= read -r check_json; do
    path="$(jq -r '.path' <<<"$check_json")"
    fragment="$(jq -r '.fragment' <<<"$check_json")"
    if ! rg -Fq -- "$fragment" "$path"; then
      missing_source_checks+=("${path} :: ${fragment}")
    fi
  done < <(jq -rc '.source_fragment_checks[]' "$contract_json")

  if [[ "${#missing_source_checks[@]}" -gt 0 ]]; then
    for check in "${missing_source_checks[@]}"; do
      echo "missing source fragment: ${check}" >&2
    done
    return 1
  fi

  return 0
}

write_manifest() {
  cat >"$manifest_path" <<EOF
{
  "schema_version": "franken-engine.rgc-execution-profile-contract.run-manifest.v1",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "policy_id": "${policy_id}",
  "component": "${component}",
  "scenario_id": "${scenario_id}",
  "mode": "${mode}",
  "run_dir": "${run_dir}",
  "contract_doc": "${contract_doc}",
  "contract_json": "${contract_json}",
  "replay_command": "${replay_command}",
  "deterministic_environment": {
$(parser_frontier_emit_manifest_environment_fields "    " "null")
  }
}
EOF
}

write_report() {
  local commands_json missing_readme_json banned_readme_json missing_migration_json missing_source_json

  commands_json="$(json_array_from_args "${commands_run[@]}")"
  missing_readme_json="$(json_array_from_args "${missing_readme_fragments[@]}")"
  banned_readme_json="$(json_array_from_args "${banned_readme_fragments_found[@]}")"
  missing_migration_json="$(json_array_from_args "${missing_migration_fragments[@]}")"
  missing_source_json="$(json_array_from_args "${missing_source_checks[@]}")"

  jq -n \
    --arg schema_version "franken-engine.rgc-execution-profile-contract.report.v1" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg scenario_id "$scenario_id" \
    --arg mode "$mode" \
    --arg status "$run_status" \
    --arg failed_command "$failed_command" \
    --arg contract_doc "$contract_doc" \
    --arg contract_json "$contract_json" \
    --argjson commands_run "$commands_json" \
    --argjson missing_readme_fragments "$missing_readme_json" \
    --argjson banned_readme_fragments_found "$banned_readme_json" \
    --argjson missing_migration_fragments "$missing_migration_json" \
    --argjson missing_source_checks "$missing_source_json" \
    '{
      schema_version: $schema_version,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      scenario_id: $scenario_id,
      mode: $mode,
      status: $status,
      failed_command: (if $failed_command == "" then null else $failed_command end),
      contract_doc: $contract_doc,
      contract_json: $contract_json,
      commands_run: $commands_run,
      validation: {
        missing_readme_fragments: $missing_readme_fragments,
        banned_readme_fragments_found: $banned_readme_fragments_found,
        missing_migration_fragments: $missing_migration_fragments,
        missing_source_checks: $missing_source_checks
      }
    }' >"$report_path"
}

write_events() {
  local error_code_json="null"

  if [[ "$run_status" != "passed" ]]; then
    error_code_json='"FE-RGC-310A-AUDIT-FAILED"'
  fi

  jq -cn \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg event "execution_profile_contract_audit_completed" \
    --arg scenario_id "$scenario_id" \
    --arg path_type "audit_gate" \
    --arg outcome "$run_status" \
    --arg failed_command "$failed_command" \
    --argjson error_code "$error_code_json" \
    '{
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: $event,
      scenario_id: $scenario_id,
      path_type: $path_type,
      outcome: $outcome,
      error_code: $error_code,
      failed_command: (if $failed_command == "" then null else $failed_command end)
    }' >"$events_path"
}

finalize_artifacts() {
  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  write_manifest
  write_report
  write_events
}

trap finalize_artifacts EXIT

run_check_mode() {
  run_step \
    "cargo test -p frankenengine-engine --no-run --lib --bin frankenctl --test baseline_interpreter_edge_cases --test eval_pipeline_integration --test runtime_decision_core_integration --test runtime_decision_theory_enrichment_integration --test frankenctl_cli" \
    cargo test -p frankenengine-engine --no-run --lib \
      --bin frankenctl \
      --test baseline_interpreter_edge_cases \
      --test eval_pipeline_integration \
      --test runtime_decision_core_integration \
      --test runtime_decision_theory_enrichment_integration \
      --test frankenctl_cli
}

run_test_mode() {
  run_step \
    "cargo test -p frankenengine-engine --lib --test baseline_interpreter_edge_cases --test eval_pipeline_integration --test runtime_decision_core_integration --test runtime_decision_theory_enrichment_integration --test frankenctl_cli" \
    cargo test -p frankenengine-engine --lib \
      --test baseline_interpreter_edge_cases \
      --test eval_pipeline_integration \
      --test runtime_decision_core_integration \
      --test runtime_decision_theory_enrichment_integration \
      --test frankenctl_cli
}

run_clippy_mode() {
  run_step \
    "cargo clippy -p frankenengine-engine --lib --bin frankenctl --test baseline_interpreter_edge_cases --test eval_pipeline_integration --test runtime_decision_core_integration --test runtime_decision_theory_enrichment_integration --test frankenctl_cli -- -D warnings" \
    cargo clippy -p frankenengine-engine --lib \
      --bin frankenctl \
      --test baseline_interpreter_edge_cases \
      --test eval_pipeline_integration \
      --test runtime_decision_core_integration \
      --test runtime_decision_theory_enrichment_integration \
      --test frankenctl_cli -- -D warnings
}

main() {
  validate_readme_against_contract || {
    failed_command="validate_readme_against_contract"
    return 1
  }

  validate_migration_doc_against_contract || {
    failed_command="validate_migration_doc_against_contract"
    return 1
  }

  validate_source_fragments_against_contract || {
    failed_command="validate_source_fragments_against_contract"
    return 1
  }

  case "$mode" in
    check)
      run_check_mode || return 1
      ;;
    test)
      run_test_mode || return 1
      ;;
    clippy)
      run_clippy_mode || return 1
      ;;
    ci)
      run_check_mode || return 1
      run_test_mode || return 1
      run_clippy_mode || return 1
      ;;
    *)
      echo "unsupported mode: ${mode} (expected check|test|clippy|ci)" >&2
      failed_command="invalid_mode:${mode}"
      return 1
      ;;
  esac

  return 0
}

if main; then
  run_status="passed"
  exit_code=0
fi

exit "$exit_code"
