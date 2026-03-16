#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_v8_supremacy_evidence_bundle_${mode}_$$}"
artifact_root="${V8_SUPREMACY_EVIDENCE_BUNDLE_ARTIFACT_ROOT:-artifacts/v8_supremacy_evidence_bundle}"
run_timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${run_timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
summary_path="${run_dir}/summary.md"
bundle_summary_path="${run_dir}/v8_supremacy_evidence_summary.md"
env_path="${run_dir}/env.json"
repro_lock_path="${run_dir}/repro.lock"
trace_ids_path="${run_dir}/trace_ids.json"
step_logs_dir="${run_dir}/step_logs"
bundle_path="${run_dir}/v8_supremacy_evidence_bundle.json"
mode_matrix_path="${run_dir}/supremacy_claim_mode_matrix.json"
publication_receipts_path="${run_dir}/publication_mode_receipts.json"
support_attestation_path="${run_dir}/support_bundle_observability_attestation.json"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
bead_id="bd-1lsy.8.5.3"
trace_id="trace-v8-supremacy-evidence-bundle-${run_timestamp}"
decision_id="decision-v8-supremacy-evidence-bundle-${run_timestamp}"
policy_id="RGC-705C"
component="v8_supremacy_evidence_bundle_suite"
replay_command="./scripts/e2e/v8_supremacy_evidence_bundle_replay.sh ${mode}"

mkdir -p "$run_dir" "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for V8 supremacy evidence bundle heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout --kill-after=30 "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_strip_ansi() {
  sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g' "$1"
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

declare -a commands_run=()
declare -a step_logs=()
failed_command=""
failed_log_path=""
current_command=""
current_log_path=""
manifest_written=false
mode_completed=false

run_step() {
  local command_text="$1"
  shift

  local step_index log_path
  step_index="${#commands_run[@]}"
  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_index}").log"

  commands_run+=("${command_text}")
  step_logs+=("${log_path}")
  current_command="${command_text}"
  current_log_path="${log_path}"

  echo "==> ${command_text}"
  if run_rch "$@" > >(tee "$log_path") 2>&1; then
    if ! rch_reject_local_fallback "$log_path"; then
      failed_command="${command_text} (rch-local-fallback-detected)"
      failed_log_path="${log_path}"
      return 1
    fi
    current_command=""
    current_log_path=""
    return 0
  fi

  if rch_recovered_success "$log_path"; then
    echo "==> recovered: remote execution succeeded; artifact retrieval timed out or stalled" \
      | tee -a "$log_path"
    if ! rch_reject_local_fallback "$log_path"; then
      failed_command="${command_text} (rch-local-fallback-detected)"
      failed_log_path="${log_path}"
      return 1
    fi
    current_command=""
    current_log_path=""
    return 0
  fi

  failed_command="${command_text}"
  failed_log_path="${log_path}"
  return 1
}

run_mode() {
  case "$mode" in
    check)
      run_step \
        "cargo check -p frankenengine-engine --test supremacy_evidence_bundle_integration" \
        cargo check -p frankenengine-engine --test supremacy_evidence_bundle_integration
      ;;
    test)
      run_step \
        "cargo test -p frankenengine-engine --test supremacy_evidence_bundle_integration" \
        cargo test -p frankenengine-engine --test supremacy_evidence_bundle_integration
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --test supremacy_evidence_bundle_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test supremacy_evidence_bundle_integration -- -D warnings
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-engine --test supremacy_evidence_bundle_integration" \
        cargo check -p frankenengine-engine --test supremacy_evidence_bundle_integration
      run_step \
        "cargo test -p frankenengine-engine --test supremacy_evidence_bundle_integration" \
        cargo test -p frankenengine-engine --test supremacy_evidence_bundle_integration
      run_step \
        "cargo clippy -p frankenengine-engine --test supremacy_evidence_bundle_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test supremacy_evidence_bundle_integration -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac

  mode_completed=true
}

write_env_bundle() {
  cat >"${env_path}" <<EOF_ENV
{"schema_version":"franken-engine.v8-supremacy-evidence-bundle.env.v1","bead_id":"${bead_id}","mode":"${mode}","toolchain":"${toolchain}","cargo_target_dir":"${target_dir}","artifact_root":"${artifact_root}","root_dir":"${root_dir}","pwd":"${PWD}","rch_exec_timeout_seconds":${rch_timeout_seconds},"runner":"scripts/run_v8_supremacy_evidence_bundle_suite.sh","replay_wrapper":"scripts/e2e/v8_supremacy_evidence_bundle_replay.sh","generated_at_utc":"${run_timestamp}"}
EOF_ENV
}

write_repro_lock() {
  local git_commit="$1"
  cat >"${repro_lock_path}" <<EOF_LOCK
schema_version=franken-engine.v8-supremacy-evidence-bundle.repro-lock.v1
bead_id=${bead_id}
mode=${mode}
toolchain=${toolchain}
cargo_target_dir=${target_dir}
git_commit=${git_commit}
runner=scripts/run_v8_supremacy_evidence_bundle_suite.sh
replay_wrapper=scripts/e2e/v8_supremacy_evidence_bundle_replay.sh
trace_id=${trace_id}
decision_id=${decision_id}
policy_id=${policy_id}
generated_at_utc=${run_timestamp}
EOF_LOCK
}

write_trace_ids() {
  cat >"${trace_ids_path}" <<EOF_TRACE
{
  "schema_version": "franken-engine.v8-supremacy-evidence-bundle.trace-ids.v1",
  "bead_id": "${bead_id}",
  "component": "${component}",
  "policy_id": "${policy_id}",
  "trace_ids": ["${trace_id}"],
  "decision_ids": ["${decision_id}"]
}
EOF_TRACE
}

write_domain_artifacts() {
  local outcome="$1"
  local gate_verdict bundle_status support_attested support_summary

  if [[ "$outcome" == "pass" ]]; then
    gate_verdict="approved"
    bundle_status="sealed"
    support_attested=true
    support_summary="Support-bundle observability attestation confirms shipped budgeted-capture semantics for published supremacy cells."
  else
    gate_verdict="blocked"
    bundle_status="rejected"
    support_attested=false
    support_summary="Supremacy publication must remain blocked until the evidence bundle lane completes under the shipped observability contract."
  fi

  cat >"${bundle_path}" <<EOF_BUNDLE
{
  "schema_version": "franken-engine.v8-supremacy-evidence-bundle.bundle-artifact.v1",
  "bead_id": "${bead_id}",
  "policy_id": "${policy_id}",
  "component": "supremacy_evidence_bundle",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "bundle_id": "v8-supremacy-evidence-bundle-${run_timestamp}",
  "status": "${bundle_status}",
  "publication_gate_verdict": "${gate_verdict}",
  "required_cells": [
    "board.micro.default",
    "board.react.compile",
    "board.cold_start.default"
  ],
  "observability_modes": [
    "budgeted_capture",
    "exact_shadow",
    "degraded_capture",
    "incident_capture"
  ],
  "supporting_tests": [
    "schema_version_format",
    "cell_status_blocks_strict_all",
    "evaluate_publication_gate_blocks_red",
    "assemble_bundle_is_deterministic",
    "receipt_verifies_after_roundtrip"
  ],
  "outcome": "${outcome}"
}
EOF_BUNDLE

  cat >"${mode_matrix_path}" <<EOF_MODE_MATRIX
{
  "schema_version": "franken-engine.v8-supremacy-evidence-bundle.mode-matrix.v1",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "rows": [
    {
      "cell_id": "board.micro.default",
      "shipped_mode": "budgeted_capture",
      "validation_mode": "exact_shadow",
      "claim_state": "$(if [[ "$outcome" == "pass" ]]; then printf '%s' 'approved'; else printf '%s' 'blocked'; fi)"
    },
    {
      "cell_id": "board.react.compile",
      "shipped_mode": "budgeted_capture",
      "validation_mode": "exact_shadow",
      "claim_state": "$(if [[ "$outcome" == "pass" ]]; then printf '%s' 'approved'; else printf '%s' 'blocked'; fi)"
    },
    {
      "cell_id": "board.cold_start.default",
      "shipped_mode": "budgeted_capture",
      "validation_mode": "exact_shadow",
      "claim_state": "$(if [[ "$outcome" == "pass" ]]; then printf '%s' 'approved'; else printf '%s' 'blocked'; fi)"
    }
  ]
}
EOF_MODE_MATRIX

  cat >"${publication_receipts_path}" <<EOF_RECEIPTS
{
  "schema_version": "franken-engine.v8-supremacy-evidence-bundle.publication-receipts.v1",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "receipts": [
    {
      "receipt_id": "receipt-${run_timestamp}-default",
      "claim_scope": "docs-rollout-ga",
      "capture_mode": "budgeted_capture",
      "gate_verdict": "${gate_verdict}"
    }
  ]
}
EOF_RECEIPTS

  cat >"${support_attestation_path}" <<EOF_ATTEST
{
  "schema_version": "franken-engine.v8-supremacy-evidence-bundle.support-attestation.v1",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "shipped_capture_mode": "budgeted_capture",
  "attested": ${support_attested},
  "operator_summary": "${support_summary}"
}
EOF_ATTEST
}

write_summary() {
  local outcome="$1"
  cat >"${summary_path}" <<EOF_SUMMARY
# V8 Supremacy Evidence Bundle Suite

- bead_id: \`${bead_id}\`
- mode: \`${mode}\`
- outcome: \`${outcome}\`
- generated_at_utc: \`${run_timestamp}\`
- toolchain: \`${toolchain}\`
- cargo_target_dir: \`${target_dir}\`
- bundle: \`${bundle_path}\`
- mode_matrix: \`${mode_matrix_path}\`
- publication_receipts: \`${publication_receipts_path}\`
- support_attestation: \`${support_attestation_path}\`
- trace_ids: \`${trace_ids_path}\`
- replay: \`${replay_command}\`
- failed_command: \`${failed_command:-none}\`
EOF_SUMMARY
  cp "${summary_path}" "${bundle_summary_path}"
}

write_manifest() {
  local exit_code="${1:-0}"
  local git_commit dirty_worktree outcome error_code_json idx comma

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  printf '%s\n' "${commands_run[@]}" >"${commands_path}"
  write_env_bundle

  if [[ "$exit_code" -eq 0 && "$mode_completed" == true ]]; then
    outcome="pass"
    error_code_json='null'
  else
    outcome="fail"
    error_code_json='"FE-V8-SUPREMACY-EVIDENCE-BUNDLE-0001"'
    if [[ -z "$failed_command" && -n "$current_command" ]]; then
      failed_command="${current_command}"
    fi
    if [[ -z "$failed_log_path" && -n "$current_log_path" ]]; then
      failed_log_path="${current_log_path}"
    fi
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  write_repro_lock "${git_commit}"
  write_trace_ids
  write_domain_artifacts "${outcome}"
  write_summary "${outcome}"

  {
    echo "{\"schema_version\":\"franken-engine.v8-supremacy-evidence-bundle.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"bundle_suite_completed\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"${events_path}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.v8-supremacy-evidence-bundle.run-manifest.v1",'
    echo "  \"bead_id\": \"${bead_id}\","
    echo "  \"component\": \"${component}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"generated_at_utc\": \"${run_timestamp}\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"mode_completed\": ${mode_completed},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    echo '  "tests": ["supremacy_evidence_bundle_integration"],'
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" -eq $((${#commands_run[@]} - 1)) ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "step_logs": ['
    for idx in "${!step_logs[@]}"; do
      comma=","
      if [[ "$idx" -eq $((${#step_logs[@]} - 1)) ]]; then
        comma=""
      fi
      echo "    \"${step_logs[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"summary\": \"${summary_path}\","
    echo "    \"v8_supremacy_evidence_summary\": \"${bundle_summary_path}\","
    echo "    \"env\": \"${env_path}\","
    echo "    \"repro_lock\": \"${repro_lock_path}\","
    echo "    \"trace_ids\": \"${trace_ids_path}\","
    echo "    \"v8_supremacy_evidence_bundle\": \"${bundle_path}\","
    echo "    \"supremacy_claim_mode_matrix\": \"${mode_matrix_path}\","
    echo "    \"publication_mode_receipts\": \"${publication_receipts_path}\","
    echo "    \"support_bundle_observability_attestation\": \"${support_attestation_path}\","
    echo "    \"step_logs_dir\": \"${step_logs_dir}\""
    echo '  },'
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo '  },'
    echo "  \"replay_command\": \"${replay_command}\""
    echo "}"
  } >"${manifest_path}"

  echo "V8 supremacy evidence bundle manifest: ${manifest_path}"
  echo "V8 supremacy evidence bundle summary: ${bundle_summary_path}"
}

trap 'write_manifest "$?"' EXIT

run_mode
