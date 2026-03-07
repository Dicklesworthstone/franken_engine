#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/data/projects/franken_engine/target_rch_controller_operator_graph}"
artifact_root="${CONTROLLER_OPERATOR_GRAPH_ARTIFACT_ROOT:-artifacts/controller_operator_graph}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
artifact_test_filter="controller_operator_graph_artifact"
replay_command="./scripts/run_controller_operator_graph_suite.sh ${mode}"

mkdir -p "$run_dir"
run_dir="$(cd "$run_dir" && pwd)"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
controller_registry_path="${run_dir}/controller_registry.json"
controller_operator_graph_path="${run_dir}/controller_operator_graph.json"
controller_telemetry_snapshot_path="${run_dir}/controller_telemetry_snapshot.json"
spectral_edge_trace_path="${run_dir}/spectral_edge_trace.jsonl"
controller_edge_uncertainty_ledger_path="${run_dir}/controller_edge_uncertainty_ledger.json"
trace_ids_path="${run_dir}/trace_ids.json"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for controller operator graph suite runs" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rg -o 'Remote command finished: exit=[0-9]+' "$log_path" | tail -n 1 || true)"
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
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|Remote execution failed.*running locally|running locally' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
last_worker_id=""
last_worker_user=""
last_worker_host=""
last_worker_identity_file=""

worker_identity_file() {
  local worker_id="$1"

  awk -v worker_id="$worker_id" '
    /^\[\[workers\]\]/ {
      in_block = 0
      next
    }
    $0 == "id = \"" worker_id "\"" {
      in_block = 1
      next
    }
    in_block && /^identity_file = / {
      gsub(/^identity_file = "/, "", $0)
      gsub(/"$/, "", $0)
      print
      exit
    }
  ' "$HOME/.config/rch/workers.toml"
}

capture_selected_worker() {
  local log_path="$1"
  local worker_line worker_spec

  worker_line="$(sed -n 's/.*Selected worker: \([^ ]*\) at \([^ ]*\) (.*/\1|\2/p' "$log_path" | tail -n 1 || true)"
  if [[ -z "$worker_line" ]]; then
    return 0
  fi

  last_worker_id="${worker_line%%|*}"
  worker_spec="${worker_line#*|}"
  last_worker_user="${worker_spec%@*}"
  last_worker_host="${worker_spec#*@}"
  last_worker_identity_file="$(worker_identity_file "$last_worker_id")"
  last_worker_identity_file="${last_worker_identity_file/#\~/$HOME}"
}

run_step() {
  local command_text="$1"
  local log_path remote_exit_code
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="$(mktemp "${run_dir}/rch-log.XXXXXX")"

  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    if rg -q "Remote command finished: exit=0" "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      rm -f "$log_path"
      failed_command="$command_text"
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
    rm -f "$log_path"
    failed_command="${command_text} (remote-exit=${remote_exit_code})"
    return 1
  fi

  capture_selected_worker "$log_path"
  rm -f "$log_path"
}

validate_artifacts() {
  local missing=0
  for path in \
    "$manifest_path" \
    "$events_path" \
    "$commands_path" \
    "$controller_registry_path" \
    "$controller_operator_graph_path" \
    "$controller_telemetry_snapshot_path" \
    "$spectral_edge_trace_path" \
    "$controller_edge_uncertainty_ledger_path" \
    "$trace_ids_path"; do
    if [[ ! -s "$path" ]]; then
      echo "missing or empty expected artifact: $path" >&2
      missing=1
    fi
  done

  if [[ "$missing" -ne 0 ]]; then
    failed_command="${failed_command:-artifact-validation}"
    return 1
  fi
}

fetch_remote_artifacts_via_scp() {
  local remote_path

  if [[ -z "$last_worker_user" || -z "$last_worker_host" || -z "$last_worker_identity_file" ]]; then
    echo "unable to resolve selected worker SSH identity for artifact fetch" >&2
    failed_command="${failed_command:-artifact-fetch-worker-identity}"
    return 1
  fi

  for remote_path in \
    "$manifest_path" \
    "$events_path" \
    "$commands_path" \
    "$controller_registry_path" \
    "$controller_operator_graph_path" \
    "$controller_telemetry_snapshot_path" \
    "$spectral_edge_trace_path" \
    "$controller_edge_uncertainty_ledger_path" \
    "$trace_ids_path"; do
    scp -q \
      -i "$last_worker_identity_file" \
      -o BatchMode=yes \
      -o StrictHostKeyChecking=no \
      "${last_worker_user}@${last_worker_host}:${remote_path}" \
      "$run_dir/"
  done
}

run_artifact_test() {
  local command_text
  command_text="env CONTROLLER_OPERATOR_GRAPH_ARTIFACT_DIR=${run_dir} cargo test -p frankenengine-engine --test controller_composition_matrix_integration ${artifact_test_filter} -- --nocapture"

  run_step "$command_text" \
    env \
    CONTROLLER_OPERATOR_GRAPH_ARTIFACT_DIR="${run_dir}" \
    cargo test -p frankenengine-engine --test controller_composition_matrix_integration "${artifact_test_filter}" -- --nocapture

  fetch_remote_artifacts_via_scp
  validate_artifacts
}

run_mode() {
  case "$mode" in
    check)
      run_step \
        "cargo check -p frankenengine-engine --test controller_composition_matrix_integration" \
        cargo check -p frankenengine-engine --test controller_composition_matrix_integration
      ;;
    test)
      run_artifact_test
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --test controller_composition_matrix_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test controller_composition_matrix_integration -- -D warnings
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-engine --test controller_composition_matrix_integration" \
        cargo check -p frankenengine-engine --test controller_composition_matrix_integration
      run_artifact_test
      run_step \
        "cargo clippy -p frankenengine-engine --test controller_composition_matrix_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test controller_composition_matrix_integration -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

run_mode
echo "controller operator graph artifacts: ${run_dir}"
