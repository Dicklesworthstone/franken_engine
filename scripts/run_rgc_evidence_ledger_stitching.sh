#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root="${RGC_EVIDENCE_LEDGER_STITCHING_ARTIFACT_ROOT:-artifacts/rgc_evidence_ledger_stitching}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_dir="${CARGO_TARGET_DIR:-/data/projects/franken_engine/target_rch_rgc_evidence_ledger_stitching}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-1800}"
rch_build_timeout_sec="${RCH_BUILD_TIMEOUT_SEC:-${RCH_BUILD_TIMEOUT_SECONDS:-${rch_timeout_seconds}}}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-2}"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/suite_run_manifest.json"
trace_id="${RGC_EVIDENCE_LEDGER_TRACE_ID:-trace.rgc.811b}"
decision_id="${RGC_EVIDENCE_LEDGER_DECISION_ID:-decision.rgc.811b}"
policy_id="${RGC_EVIDENCE_LEDGER_POLICY_ID:-policy.rgc.811b}"
run_id="run-rgc-evidence-ledger-stitching-${timestamp}"
source_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
suite_commands_path="${run_dir}/suite_commands.txt"
step_logs_dir="${run_dir}/step_logs"

contract_doc="docs/RGC_EVIDENCE_LEDGER_STITCHING_V1.md"
contract_json="docs/rgc_evidence_ledger_stitching_v1.json"

mkdir -p "$run_dir" "$step_logs_dir"

if [[ ! -f "$contract_doc" ]]; then
  echo "missing contract doc: ${contract_doc}" >&2
  exit 1
fi

if [[ ! -f "$contract_json" ]]; then
  echo "missing contract json: ${contract_json}" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for evidence ledger stitching artifacts" >&2
  exit 2
fi

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for evidence ledger stitching heavy commands" >&2
  exit 2
fi

run_rch() {
  RCH_BUILD_TIMEOUT_SEC="${rch_build_timeout_sec}" \
    RCH_BUILD_TIMEOUT_SECONDS="${rch_build_timeout_sec}" \
    timeout --kill-after=30 "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "$@"
}

rch_strip_ansi() {
  local input="$1"
  sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' "$input"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|Remote execution failed.*running locally|running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_last_remote_exit_code() {
  local log_path="$1"
  local exit_line
  exit_line="$(rch_strip_ansi "$log_path" | grep -Eo 'Remote command finished: exit=[0-9]+' | tail -n 1 || true)"
  if [[ -z "$exit_line" ]]; then
    echo ""
    return
  fi
  echo "${exit_line##*=}"
}

rch_reported_timeout_seconds() {
  local log_path="$1"
  local timeout_value
  timeout_value="$(
    rch_strip_ansi "$log_path" | sed -nE 's/.*timeout_secs: ([0-9]+).*/\1/p' | tail -n 1
  )"
  if [[ -z "$timeout_value" ]]; then
    echo ""
    return
  fi
  echo "$timeout_value"
}

rch_has_recoverable_artifact_timeout() {
  local log_path="$1"
  rch_strip_ansi "$log_path" | grep -Eiq 'artifact retrieval timed out|artifact transfer timed out|timed out waiting for artifacts|failed to retrieve artifacts|failed to download artifacts'
}

rch_reject_artifact_retrieval_failure() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Artifact retrieval failed|Failed to retrieve artifacts:|rsync artifact retrieval failed|rsync error: .*code 23'; then
    echo "rch artifact retrieval failed; refusing to mark heavy command as successful" >&2
    return 1
  fi
}

declare -a commands_run=()
declare -a step_logs=()
failed_command=""
failed_step_log_path=""
step_counter=0
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path run_rc remote_exit_code reported_timeout
  shift
  commands_run+=("$command_text")
  step_counter=$((step_counter + 1))
  log_path="${step_logs_dir}/step_${step_counter}.log"
  step_logs+=("$log_path")
  echo "==> $command_text"

  if run_rch "$@" > >(tee "$log_path") 2>&1; then
    run_rc=0
  else
    run_rc=$?
    remote_exit_code="$(rch_last_remote_exit_code "$log_path")"
    reported_timeout="$(rch_reported_timeout_seconds "$log_path")"
    if [[ "$rch_build_timeout_sec" =~ ^[0-9]+$ && "$reported_timeout" =~ ^[0-9]+$ ]] &&
      (( reported_timeout < rch_build_timeout_sec )); then
      echo "rch reported timeout_secs=${reported_timeout} but requested build timeout is ${rch_build_timeout_sec}" | tee -a "$log_path"
      failed_command="${command_text} (rch-timeout-mismatch-${reported_timeout}-lt-${rch_build_timeout_sec})"
      failed_step_log_path="$log_path"
      return 1
    fi
    if [[ "$remote_exit_code" == "0" ]] && rch_has_recoverable_artifact_timeout "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      if [[ "$run_rc" -eq 124 ]]; then
        failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      elif [[ -n "$remote_exit_code" ]]; then
        failed_command="${command_text} (remote-exit-${remote_exit_code})"
      else
        failed_command="${command_text} (rch-exit-${run_rc})"
      fi
      failed_step_log_path="$log_path"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    failed_step_log_path="$log_path"
    return 1
  fi

  if ! rch_reject_artifact_retrieval_failure "$log_path"; then
    failed_command="${command_text} (rch-artifact-retrieval-failed)"
    failed_step_log_path="$log_path"
    return 1
  fi

  reported_timeout="$(rch_reported_timeout_seconds "$log_path")"
  if [[ "$rch_build_timeout_sec" =~ ^[0-9]+$ && "$reported_timeout" =~ ^[0-9]+$ ]] &&
    (( reported_timeout < rch_build_timeout_sec )); then
    echo "rch reported timeout_secs=${reported_timeout} but requested build timeout is ${rch_build_timeout_sec}" | tee -a "$log_path"
    failed_command="${command_text} (rch-timeout-mismatch-${reported_timeout}-lt-${rch_build_timeout_sec})"
    failed_step_log_path="$log_path"
    return 1
  fi

  remote_exit_code="$(rch_last_remote_exit_code "$log_path")"
  if [[ "$remote_exit_code" != "0" ]]; then
    if [[ -z "$remote_exit_code" ]]; then
      echo "rch output missing remote exit marker; failing closed" | tee -a "$log_path"
      failed_command="${command_text} (missing-remote-exit-marker)"
    else
      failed_command="${command_text} (remote-exit-${remote_exit_code})"
    fi
    failed_step_log_path="$log_path"
    return 1
  fi
}

verify_bundle() {
  local artifact
  for artifact in \
    artifact_lineage_index.json \
    commands.txt \
    decision_semantics_log.jsonl \
    env.json \
    evidence_ledger_graph.json \
    evidence_ledger_stitching_bundle.json \
    evidence_query_surface_snapshot.json \
    events.jsonl \
    manifest.json \
    repro.lock \
    run_manifest.json \
    summary.md \
    trace_ids.json; do
    [[ -f "${run_dir}/${artifact}" ]] || {
      echo "missing required artifact: ${artifact}" >&2
      return 1
    }
  done

  jq -e '.schema_version == "franken-engine.rgc-evidence-ledger-stitching-run-manifest.v1"' \
    "${run_dir}/run_manifest.json" >/dev/null
  jq -e '.nodes | length >= 5 and .edges | length >= 5' \
    "${run_dir}/evidence_ledger_graph.json" >/dev/null
  jq -e '.decisions[0].artifact_ids | length == 3' \
    "${run_dir}/evidence_query_surface_snapshot.json" >/dev/null
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --lib --test evidence_ledger_integration --bin franken_evidence_ledger_stitching" \
        cargo check -p frankenengine-engine --lib --test evidence_ledger_integration --bin franken_evidence_ledger_stitching
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --lib evidence_ledger::tests:: -- --nocapture" \
        cargo test -p frankenengine-engine --lib evidence_ledger::tests:: -- --nocapture
      run_step "cargo test -p frankenengine-engine --test evidence_ledger_integration -- --nocapture" \
        cargo test -p frankenengine-engine --test evidence_ledger_integration -- --nocapture
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --lib --test evidence_ledger_integration --bin franken_evidence_ledger_stitching -- -D warnings" \
        cargo clippy -p frankenengine-engine --lib --test evidence_ledger_integration --bin franken_evidence_ledger_stitching -- -D warnings
      ;;
    run)
      run_step "cargo run -p frankenengine-engine --bin franken_evidence_ledger_stitching -- --artifact-dir ${run_dir} --trace-id ${trace_id} --decision-id ${decision_id} --policy-id ${policy_id} --run-id ${run_id} --generated-at-utc ${generated_at_utc} --source-commit ${source_commit} --toolchain ${toolchain} --summary" \
        cargo run -p frankenengine-engine --bin franken_evidence_ledger_stitching -- \
          --artifact-dir "${run_dir}" \
          --trace-id "${trace_id}" \
          --decision-id "${decision_id}" \
          --policy-id "${policy_id}" \
          --run-id "${run_id}" \
          --generated-at-utc "${generated_at_utc}" \
          --source-commit "${source_commit}" \
          --toolchain "${toolchain}" \
          --summary
      verify_bundle
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --lib --test evidence_ledger_integration --bin franken_evidence_ledger_stitching" \
        cargo check -p frankenengine-engine --lib --test evidence_ledger_integration --bin franken_evidence_ledger_stitching
      run_step "cargo test -p frankenengine-engine --lib evidence_ledger::tests:: -- --nocapture" \
        cargo test -p frankenengine-engine --lib evidence_ledger::tests:: -- --nocapture
      run_step "cargo test -p frankenengine-engine --test evidence_ledger_integration -- --nocapture" \
        cargo test -p frankenengine-engine --test evidence_ledger_integration -- --nocapture
      run_step "cargo clippy -p frankenengine-engine --lib --test evidence_ledger_integration --bin franken_evidence_ledger_stitching -- -D warnings" \
        cargo clippy -p frankenengine-engine --lib --test evidence_ledger_integration --bin franken_evidence_ledger_stitching -- -D warnings
      run_step "cargo run -p frankenengine-engine --bin franken_evidence_ledger_stitching -- --artifact-dir ${run_dir} --trace-id ${trace_id} --decision-id ${decision_id} --policy-id ${policy_id} --run-id ${run_id} --generated-at-utc ${generated_at_utc} --source-commit ${source_commit} --toolchain ${toolchain} --summary" \
        cargo run -p frankenengine-engine --bin franken_evidence_ledger_stitching -- \
          --artifact-dir "${run_dir}" \
          --trace-id "${trace_id}" \
          --decision-id "${decision_id}" \
          --policy-id "${policy_id}" \
          --run-id "${run_id}" \
          --generated-at-utc "${generated_at_utc}" \
          --source-commit "${source_commit}" \
          --toolchain "${toolchain}" \
          --summary
      verify_bundle
      ;;
    *)
      echo "usage: $0 [check|test|clippy|run|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome dirty_worktree idx comma
  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
  else
    outcome="fail"
  fi

  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"${suite_commands_path}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-evidence-ledger-stitching-suite.v1",'
    echo "  \"component\": \"${EVIDENCE_LEDGER_STITCHING_COMPONENT:-rgc_evidence_ledger_stitching_suite}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"git_commit\": \"${source_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"${generated_at_utc}\","
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"requested_rch_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"requested_rch_build_timeout_seconds\": ${rch_build_timeout_sec},"
    if [[ -n "${failed_command}" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    if [[ -n "${failed_step_log_path}" ]]; then
      echo "  \"failed_step_log\": \"${failed_step_log_path}\","
    fi
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$((${#commands_run[@]} - 1))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"command_log\": \"${suite_commands_path}\","
    echo "    \"step_logs_dir\": \"${step_logs_dir}\","
    echo "    \"bundle\": \"${run_dir}/evidence_ledger_stitching_bundle.json\","
    echo "    \"graph\": \"${run_dir}/evidence_ledger_graph.json\","
    echo "    \"query_surface\": \"${run_dir}/evidence_query_surface_snapshot.json\","
    echo "    \"runner_manifest\": \"${run_dir}/run_manifest.json\","
    echo "    \"suite_manifest\": \"${manifest_path}\""
    echo '  },'
    echo '  "step_logs": ['
    for idx in "${!step_logs[@]}"; do
      comma=","
      if [[ "$idx" == "$((${#step_logs[@]} - 1))" ]]; then
        comma=""
      fi
      echo "    \"${step_logs[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "operator_verification": ['
    echo "    \"cat ${run_dir}/summary.md\","
    echo "    \"cat ${run_dir}/run_manifest.json\","
    echo "    \"jq '.decisions[0]' ${run_dir}/evidence_query_surface_snapshot.json\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"${manifest_path}"
}

trap 'write_manifest $?' EXIT
run_mode
