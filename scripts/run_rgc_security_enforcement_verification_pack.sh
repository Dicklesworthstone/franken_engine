#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_rgc_security_enforcement_verification_pack}"
artifact_root="${RGC_SECURITY_ENFORCEMENT_VERIFICATION_PACK_ARTIFACT_ROOT:-artifacts/rgc_security_enforcement_verification_pack}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/security_verification_report.json"

contract_json="docs/rgc_security_enforcement_verification_pack_v1.json"
vectors_json="docs/rgc_security_enforcement_verification_vectors_v1.json"

trace_id="trace-rgc-security-enforcement-verification-pack-${timestamp}"
decision_id="decision-rgc-security-enforcement-verification-pack-${timestamp}"
policy_id="policy-rgc-security-enforcement-verification-pack-v1"
component="rgc_security_enforcement_verification_pack_gate"
scenario_id="rgc-059"
replay_command="./scripts/e2e/rgc_security_enforcement_verification_pack_replay.sh ${mode}"

mkdir -p "$run_dir"

if [[ ! -f "$contract_json" ]]; then
  echo "FE-RGC-059-CONTRACT-0001: missing contract JSON (${contract_json})" >&2
  exit 1
fi

if [[ ! -f "$vectors_json" ]]; then
  echo "FE-RGC-059-VECTORS-0001: missing vectors JSON (${vectors_json})" >&2
  exit 1
fi

if ! jq -e '.' "$vectors_json" >/dev/null 2>&1; then
  echo "FE-RGC-059-VECTORS-0002: failed to parse vectors JSON (${vectors_json})" >&2
  exit 1
fi

validate_vectors_contract() {
  local duplicate_ids duplicate_seeds
  local -a required_classes=()
  local -a attack_classes=()
  local -a scenario_ids=()
  local -a deterministic_seeds=()
  local -a validation_errors=()

  mapfile -t required_classes < <(jq -r '.required_attack_classes[]? // empty' "$contract_json")
  mapfile -t attack_classes < <(jq -r '.vectors[]?.attack_class // empty' "$vectors_json")
  mapfile -t scenario_ids < <(jq -r '.vectors[]?.scenario_id // empty' "$vectors_json")
  mapfile -t deterministic_seeds < <(jq -r '.vectors[]?.deterministic_seed // empty' "$vectors_json")

  if (( ${#scenario_ids[@]} == 0 )); then
    validation_errors+=("vectors array must be non-empty")
  fi

  if (( ${#required_classes[@]} == 0 )); then
    validation_errors+=("contract required_attack_classes must be non-empty")
  fi

  duplicate_ids="$(printf '%s\n' "${scenario_ids[@]:-}" | sed '/^$/d' | sort | uniq -d | paste -sd ',' -)"
  if [[ -n "$duplicate_ids" ]]; then
    validation_errors+=("duplicate scenario_id values: ${duplicate_ids}")
  fi

  duplicate_seeds="$(printf '%s\n' "${deterministic_seeds[@]:-}" | sed '/^$/d' | sort | uniq -d | paste -sd ',' -)"
  if [[ -n "$duplicate_seeds" ]]; then
    validation_errors+=("duplicate deterministic_seed values: ${duplicate_seeds}")
  fi

  for required_class in "${required_classes[@]}"; do
    if ! printf '%s\n' "${attack_classes[@]:-}" | rg -qx "$required_class"; then
      validation_errors+=("missing required attack_class coverage: ${required_class}")
    fi
  done

  if ! jq -e '(.vectors // []) | all(.requires_replay == true)' "$vectors_json" >/dev/null; then
    validation_errors+=("all vectors must set requires_replay=true")
  fi

  if ! jq -e '(.vectors // []) | all(((.command_template // "") | gsub("^\\s+|\\s+$"; "") | length) > 0)' "$vectors_json" >/dev/null; then
    validation_errors+=("all vectors must provide non-empty command_template")
  fi

  if ! jq -e '(.vectors // []) | all((.path_type == "golden") or (.path_type == "failure"))' "$vectors_json" >/dev/null; then
    validation_errors+=("path_type must be one of: golden|failure")
  fi

  if (( ${#validation_errors[@]} > 0 )); then
    for error in "${validation_errors[@]}"; do
      echo "vector validation error: ${error}" >&2
    done
    return 1
  fi

  return 0
}

if ! validate_vectors_contract; then
  echo "FE-RGC-059-VECTORS-0003: vector contract validation failed (${vectors_json})" >&2
  exit 1
fi

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC security enforcement verification pack heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -q -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false
step_log_index=0

run_step() {
  local command_text="$1"
  local step_log_path="${run_dir}/step_$(printf '%03d' "$step_log_index").log"
  step_log_index=$((step_log_index + 1))
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"

  if ! run_rch "$@" > >(tee "$step_log_path") 2>&1; then
    if rg -q "Remote command finished: exit=0" "$step_log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$step_log_path"
    else
      failed_command="$command_text"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$step_log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi
}

run_mode() {
  case "$mode" in
  check)
    run_step "cargo check -p frankenengine-engine --test rgc_security_enforcement_verification_pack" \
      cargo check -p frankenengine-engine --test rgc_security_enforcement_verification_pack
    ;;
  test)
    run_step "cargo test -p frankenengine-engine --test rgc_security_enforcement_verification_pack" \
      cargo test -p frankenengine-engine --test rgc_security_enforcement_verification_pack
    ;;
  clippy)
    run_step "cargo clippy -p frankenengine-engine --test rgc_security_enforcement_verification_pack -- -D warnings" \
      cargo clippy -p frankenengine-engine --test rgc_security_enforcement_verification_pack -- -D warnings
    ;;
  ci)
    run_step "cargo check -p frankenengine-engine --test rgc_security_enforcement_verification_pack" \
      cargo check -p frankenengine-engine --test rgc_security_enforcement_verification_pack
    run_step "cargo test -p frankenengine-engine --test rgc_security_enforcement_verification_pack" \
      cargo test -p frankenengine-engine --test rgc_security_enforcement_verification_pack
    run_step "cargo clippy -p frankenengine-engine --test rgc_security_enforcement_verification_pack -- -D warnings" \
      cargo clippy -p frankenengine-engine --test rgc_security_enforcement_verification_pack -- -D warnings
    ;;
  *)
    echo "usage: $0 [check|test|clippy|ci]" >&2
    exit 2
    ;;
  esac
}

write_report() {
  local outcome="$1"
  jq -n \
    --arg schema_version "franken-engine.rgc-security-enforcement-verification-pack.report.v1" \
    --arg bead_id "bd-1lsy.11.9" \
    --arg policy_id "$policy_id" \
    --arg scenario_id "$scenario_id" \
    --arg outcome "$outcome" \
    --arg contract_json "$contract_json" \
    --arg vectors_json "$vectors_json" \
    --arg generated_at_utc "$timestamp" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      policy_id: $policy_id,
      scenario_id: $scenario_id,
      outcome: $outcome,
      generated_at_utc: $generated_at_utc,
      evidence_inputs: {
        contract_json: $contract_json,
        vectors_json: $vectors_json
      }
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
    error_code_json='"FE-RGC-059-GATE-0001"'
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
    echo "{\"schema_version\":\"franken-engine.rgc-security-enforcement-verification-pack.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"attack_class\":\"matrix\",\"path_type\":\"golden\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-security-enforcement-verification-pack.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.11.9",'
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
    echo '    "contract_doc": "docs/RGC_SECURITY_ENFORCEMENT_VERIFICATION_PACK_V1.md",'
    echo '    "contract_json": "docs/rgc_security_enforcement_verification_pack_v1.json",'
    echo '    "vectors_json": "docs/rgc_security_enforcement_verification_vectors_v1.json",'
    echo '    "gate_tests": "crates/franken-engine/tests/rgc_security_enforcement_verification_pack.rs"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo "    \"cat ${report_path}\"," 
    echo '    "jq empty docs/rgc_security_enforcement_verification_pack_v1.json",'
    echo '    "jq empty docs/rgc_security_enforcement_verification_vectors_v1.json",'
    echo '    "rch exec -- env CARGO_TARGET_DIR=\"$PWD/target_rch_rgc_security_enforcement_verification_pack_verify\" cargo test -p frankenengine-engine --test rgc_security_enforcement_verification_pack",'
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "rgc security enforcement verification pack manifest: ${manifest_path}"
  echo "rgc security enforcement verification pack events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"
exit "$main_exit"
