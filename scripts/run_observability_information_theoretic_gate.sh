#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/.rch_target/observability_information_theoretic_${timestamp}}"
artifact_root="${OBSERVABILITY_INFORMATION_THEORETIC_ARTIFACT_ROOT:-artifacts/observability_information_theoretic}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

trace_id="trace-observability-information-theoretic-${timestamp}"
decision_id="decision-observability-information-theoretic-${timestamp}"
policy_id="policy-observability-information-theoretic-v1"
component="observability_information_theoretic_gate"
replay_command="${0} ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for observability information-theoretic heavy commands" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for event JSON validation" >&2
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
  perl -pe 's/\e\[[0-9;?]*[ -\/]*[@-~]//g' "$1"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(
    rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n 1 || true
  )"
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
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote execution failed: Project sync failed|running locally|Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \('; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_recovered_success() {
  local log_path="$1"

  if rch_strip_ansi "$log_path" | rg -q "Remote command finished: exit=0"; then
    return 0
  fi

  if rch_strip_ansi "$log_path" | rg -q "Finished .* profile" \
    && ! rch_strip_ansi "$log_path" | rg -q "error\\[|error:|FAILED"; then
    return 0
  fi

  if rch_strip_ansi "$log_path" | rg -q "test result: ok\\." \
    && ! rch_strip_ansi "$log_path" | rg -q "FAILED"; then
    return 0
  fi

  return 1
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path remote_exit_code
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"

  log_path="$(mktemp)"
  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    if rch_recovered_success "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" \
        | tee -a "$log_path"
    else
      remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
      rm -f "$log_path"
      if [[ -n "$remote_exit_code" ]]; then
        failed_command="${command_text} (remote-exit=${remote_exit_code})"
      else
        failed_command="$command_text"
      fi
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    rm -f "$log_path"
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -n "$remote_exit_code" && "$remote_exit_code" != "0" ]]; then
    if rch_recovered_success "$log_path"; then
      echo "==> recovered: remote exit=${remote_exit_code} with successful build markers" \
        | tee -a "$log_path"
    else
    rm -f "$log_path"
    failed_command="${command_text} (remote-exit=${remote_exit_code})"
    return 1
    fi
  fi

  rm -f "$log_path"
  failed_command=""
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test observability_channel_model --test entropy_evidence_compressor_integration --test entropy_evidence_compressor_enrichment_integration" \
        cargo check -p frankenengine-engine --test observability_channel_model \
          --test entropy_evidence_compressor_integration \
          --test entropy_evidence_compressor_enrichment_integration || return $?
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test observability_channel_model --test entropy_evidence_compressor_integration --test entropy_evidence_compressor_enrichment_integration" \
        cargo test -p frankenengine-engine --test observability_channel_model \
          --test entropy_evidence_compressor_integration \
          --test entropy_evidence_compressor_enrichment_integration || return $?
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test observability_channel_model --test entropy_evidence_compressor_integration --test entropy_evidence_compressor_enrichment_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test observability_channel_model \
          --test entropy_evidence_compressor_integration \
          --test entropy_evidence_compressor_enrichment_integration -- -D warnings || return $?
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test observability_channel_model --test entropy_evidence_compressor_integration --test entropy_evidence_compressor_enrichment_integration" \
        cargo check -p frankenengine-engine --test observability_channel_model \
          --test entropy_evidence_compressor_integration \
          --test entropy_evidence_compressor_enrichment_integration || return $?
      run_step "cargo test -p frankenengine-engine --test observability_channel_model --test entropy_evidence_compressor_integration --test entropy_evidence_compressor_enrichment_integration" \
        cargo test -p frankenengine-engine --test observability_channel_model \
          --test entropy_evidence_compressor_integration \
          --test entropy_evidence_compressor_enrichment_integration || return $?
      run_step "cargo clippy -p frankenengine-engine --test observability_channel_model --test entropy_evidence_compressor_integration --test entropy_evidence_compressor_enrichment_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test observability_channel_model \
          --test entropy_evidence_compressor_integration \
          --test entropy_evidence_compressor_enrichment_integration -- -D warnings || return $?
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
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
    failed_command=""
  else
    outcome="fail"
    error_code_json='"FE-OBSERVABILITY-CHANNEL-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.observability-log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.observability-information-theoretic.run-manifest.v1",'
    echo '  "bead_id": "bd-mjh3.17",'
    echo '  "feature_contract_version": "frx-17.information-theoretic-observability.v1",'
    echo "  \"component\": \"${component}\","
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
    echo "  \"error_code\": ${error_code_json},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo "  ],"
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo '    "contract_doc": "docs/OBSERVABILITY_INFORMATION_THEORETIC_CHANNEL.md",'
    echo '    "integration_tests": ['
    echo '      "crates/franken-engine/tests/observability_channel_model.rs",'
    echo '      "crates/franken-engine/tests/entropy_evidence_compressor_integration.rs",'
    echo '      "crates/franken-engine/tests/entropy_evidence_compressor_enrichment_integration.rs"'
    echo '    ]'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "observability information-theoretic manifest: ${manifest_path}"
  echo "observability information-theoretic events: ${events_path}"
}

validate_events() {
  jq -e -c . "$events_path" >/dev/null
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"

if ! validate_events; then
  failed_command="${failed_command:-validate_events_jsonl}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
