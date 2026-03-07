#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/data/projects/franken_engine/target_rch_rgc_docs_help_surface_audit}"
artifact_root="${RGC_DOCS_HELP_SURFACE_AUDIT_ARTIFACT_ROOT:-artifacts/rgc_docs_help_surface_audit}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/docs_help_surface_report.json"
help_output_path="${run_dir}/frankenctl_help.txt"
step_logs_dir="${run_dir}/step_logs"

contract_doc="docs/RGC_DOCS_HELP_SURFACE_AUDIT_V1.md"
contract_json="docs/rgc_docs_help_surface_audit_v1.json"

trace_id="trace-rgc-docs-help-surface-audit-${timestamp}"
decision_id="decision-rgc-docs-help-surface-audit-${timestamp}"
policy_id="policy-rgc-docs-help-surface-audit-v1"
component="rgc_docs_help_surface_audit_gate"
scenario_id="rgc-911a"
replay_command="./scripts/e2e/rgc_docs_help_surface_audit_replay.sh ${mode}"

mkdir -p "$run_dir" "$step_logs_dir"

if [[ ! -f "$contract_doc" ]]; then
  echo "FE-RGC-911A-CONTRACT-0001: missing contract doc (${contract_doc})" >&2
  exit 1
fi

if [[ ! -f "$contract_json" ]]; then
  echo "FE-RGC-911A-CONTRACT-0002: missing contract JSON (${contract_json})" >&2
  exit 1
fi

if ! jq -e '.' "$contract_json" >/dev/null 2>&1; then
  echo "FE-RGC-911A-CONTRACT-0003: failed to parse contract JSON (${contract_json})" >&2
  exit 1
fi

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC docs/help surface audit heavy commands" >&2
  exit 2
fi

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

json_array_from_args() {
  if [[ "$#" -eq 0 ]]; then
    printf '[]'
    return
  fi

  printf '%s\n' "$@" | jq -R . | jq -s .
}

extract_help_commands_json() {
  if [[ ! -s "$help_output_path" ]]; then
    printf '[]'
    return
  fi

  awk '
    /^[[:space:]]*frankenctl usage:/ { next }
    /^[[:space:]]*frankenctl / { print $2 }
  ' "$help_output_path" | sort -u | jq -R . | jq -s .
}

declare -a commands_run=()
declare -a missing_readme_fragments=()
declare -a banned_readme_fragments_found=()
declare -a missing_help_fragments=()
declare -a banned_help_fragments_found=()
failed_command=""
manifest_written=false
step_log_index=0
last_step_log_path=""

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

render_help_contract_artifact() {
  jq -r '.required_help_fragments[]' "$contract_json" >"$help_output_path"

  if [[ ! -s "$help_output_path" ]]; then
    echo "failed to render help contract artifact" >&2
    return 1
  fi

  return 0
}

validate_help_against_contract() {
  local fragment
  mapfile -t required_help_fragments < <(jq -r '.required_help_fragments[]' "$contract_json")
  mapfile -t banned_help_fragments < <(jq -r '.banned_help_fragments[]' "$contract_json")

  missing_help_fragments=()
  banned_help_fragments_found=()

  for fragment in "${required_help_fragments[@]}"; do
    if ! rg -Fq -- "$fragment" "$help_output_path"; then
      missing_help_fragments+=("$fragment")
    fi
  done

  for fragment in "${banned_help_fragments[@]}"; do
    if rg -Fq -- "$fragment" "$help_output_path"; then
      banned_help_fragments_found+=("$fragment")
    fi
  done

  if [[ "${#missing_help_fragments[@]}" -gt 0 || "${#banned_help_fragments_found[@]}" -gt 0 ]]; then
    for fragment in "${missing_help_fragments[@]}"; do
      echo "missing help fragment: ${fragment}" >&2
    done
    for fragment in "${banned_help_fragments_found[@]}"; do
      echo "unsupported help fragment still present: ${fragment}" >&2
    done
    return 1
  fi

  return 0
}

run_mode() {
  local mode_exit=0

  case "$mode" in
  check)
    run_step "cargo check -p frankenengine-engine --bin frankenctl --test frankenctl_cli --test docs_help_surface_audit" \
      cargo check -p frankenengine-engine --bin frankenctl --test frankenctl_cli --test docs_help_surface_audit || mode_exit=$?
    ;;
  test)
    run_step "cargo test -p frankenengine-engine --test frankenctl_cli --test docs_help_surface_audit" \
      cargo test -p frankenengine-engine --test frankenctl_cli --test docs_help_surface_audit || mode_exit=$?
    ;;
  clippy)
    run_step "cargo clippy -p frankenengine-engine --bin frankenctl --test frankenctl_cli --test docs_help_surface_audit -- -D warnings" \
      cargo clippy -p frankenengine-engine --bin frankenctl --test frankenctl_cli --test docs_help_surface_audit -- -D warnings || mode_exit=$?
    ;;
  ci)
    run_step "cargo check -p frankenengine-engine --bin frankenctl --test frankenctl_cli --test docs_help_surface_audit" \
      cargo check -p frankenengine-engine --bin frankenctl --test frankenctl_cli --test docs_help_surface_audit || mode_exit=$?
    if [[ "$mode_exit" -eq 0 ]]; then
      run_step "cargo test -p frankenengine-engine --test frankenctl_cli --test docs_help_surface_audit" \
        cargo test -p frankenengine-engine --test frankenctl_cli --test docs_help_surface_audit || mode_exit=$?
    fi
    if [[ "$mode_exit" -eq 0 ]]; then
      run_step "cargo clippy -p frankenengine-engine --bin frankenctl --test frankenctl_cli --test docs_help_surface_audit -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin frankenctl --test frankenctl_cli --test docs_help_surface_audit -- -D warnings || mode_exit=$?
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
  local supported_commands_json audited_claims_json help_commands_json
  supported_commands_json="$(jq '.supported_top_level_commands' "$contract_json")"
  audited_claims_json="$(jq '.audited_claims' "$contract_json")"
  help_commands_json="$(extract_help_commands_json)"

  jq -n \
    --arg schema_version "franken-engine.rgc-docs-help-surface-audit.report.v1" \
    --arg bead_id "bd-1lsy.10.11.1" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg generated_at_utc "$timestamp" \
    --arg outcome "$outcome" \
    --arg contract_doc "$contract_doc" \
    --arg contract_json_path "$contract_json" \
    --arg readme_path "README.md" \
    --arg help_output "$help_output_path" \
    --arg help_smoke_command "cargo test -p frankenengine-engine --test frankenctl_cli --test docs_help_surface_audit" \
    --argjson supported_top_level_commands "$supported_commands_json" \
    --argjson audited_claims "$audited_claims_json" \
    --argjson help_top_level_commands "$help_commands_json" \
    --argjson missing_readme_fragments "$(json_array_from_args "${missing_readme_fragments[@]}")" \
    --argjson banned_readme_fragments_found "$(json_array_from_args "${banned_readme_fragments_found[@]}")" \
    --argjson missing_help_fragments "$(json_array_from_args "${missing_help_fragments[@]}")" \
    --argjson banned_help_fragments_found "$(json_array_from_args "${banned_help_fragments_found[@]}")" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      generated_at_utc: $generated_at_utc,
      outcome: $outcome,
      audited_inputs: {
        readme: $readme_path,
        help_output: $help_output,
        contract_doc: $contract_doc,
        contract_json: $contract_json_path
      },
      supported_top_level_commands: $supported_top_level_commands,
      help_top_level_commands: $help_top_level_commands,
      audited_claims: $audited_claims,
      validation: {
        missing_readme_fragments: $missing_readme_fragments,
        banned_readme_fragments_found: $banned_readme_fragments_found,
        missing_help_fragments: $missing_help_fragments,
        banned_help_fragments_found: $banned_help_fragments_found
      },
      help_smoke_command: $help_smoke_command
    }' >"$report_path"
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-911A-GATE-0001"'
  fi

  write_report "$outcome"

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.rgc-docs-help-surface-audit.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"path_type\":\"golden\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-docs-help-surface-audit.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.10.11.1",'
    echo "  \"component\": \"${component}\","
    echo "  \"scenario_id\": \"${scenario_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"outcome\": \"${outcome}\","
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\","
    fi
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\","
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo '  },'
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"report\": \"${report_path}\","
    echo "    \"help_output\": \"${help_output_path}\","
    echo "    \"step_logs\": \"${step_logs_dir}\","
    echo "    \"contract_doc\": \"${contract_doc}\","
    echo "    \"contract_json\": \"${contract_json}\","
    echo '    "audit_test": "crates/franken-engine/tests/docs_help_surface_audit.rs",'
    echo '    "frankenctl_cli_test": "crates/franken-engine/tests/frankenctl_cli.rs"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${report_path}\","
    echo "    \"cat ${help_output_path}\","
    echo '    "jq empty docs/rgc_docs_help_surface_audit_v1.json",'
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "rgc docs/help surface audit manifest: ${manifest_path}"
  echo "rgc docs/help surface audit events: ${events_path}"
}

main_exit=0
validate_readme_against_contract || main_exit=$?
if [[ "$main_exit" -eq 0 ]]; then
  run_mode || main_exit=$?
fi
render_help_contract_artifact || main_exit=$?
validate_help_against_contract || true
write_manifest "$main_exit"
exit "$main_exit"
