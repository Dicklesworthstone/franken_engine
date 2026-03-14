#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root="${RGC_CROSS_PLATFORM_MATRIX_ARTIFACT_ROOT:-artifacts/rgc_cross_platform_matrix}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
rch_ready_attempts="${RCH_READY_ATTEMPTS:-18}"
rch_ready_sleep_seconds="${RCH_READY_SLEEP_SECONDS:-2}"
rch_step_retry_attempts="${RCH_STEP_RETRY_ATTEMPTS:-3}"
rch_step_retry_sleep_seconds="${RCH_STEP_RETRY_SLEEP_SECONDS:-2}"
require_matrix="${RGC_CROSS_PLATFORM_REQUIRE_MATRIX:-0}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_target_dir="/data/projects/franken_engine/target_rch_rgc_cross_platform_matrix"
target_dir="${CARGO_TARGET_DIR:-${default_target_dir}}"

run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
matrix_deltas_path="${run_dir}/matrix_target_deltas.jsonl"
matrix_summary_path="${run_dir}/matrix_summary.json"
contract_json_path="docs/rgc_cross_platform_matrix_v1.json"
contract_doc_path="docs/RGC_CROSS_PLATFORM_MATRIX_V1.md"

trace_id="trace-rgc-cross-platform-matrix-${timestamp}"
decision_id="decision-rgc-cross-platform-matrix-${timestamp}"
policy_id="policy-rgc-cross-platform-matrix-v1"
component="rgc_cross_platform_matrix_gate"
scenario_id="rgc-063"
replay_command="./scripts/e2e/rgc_cross_platform_matrix_replay.sh ${mode}"

linux_x64_manifest="${RGC_CROSS_PLATFORM_LINUX_X64_MANIFEST:-}"
linux_arm64_manifest="${RGC_CROSS_PLATFORM_LINUX_ARM64_MANIFEST:-}"
macos_x64_manifest="${RGC_CROSS_PLATFORM_MACOS_X64_MANIFEST:-}"
macos_arm64_manifest="${RGC_CROSS_PLATFORM_MACOS_ARM64_MANIFEST:-}"
windows_x64_manifest="${RGC_CROSS_PLATFORM_WINDOWS_X64_MANIFEST:-}"
windows_arm64_manifest="${RGC_CROSS_PLATFORM_WINDOWS_ARM64_MANIFEST:-}"
manifest_set_root="${RGC_CROSS_PLATFORM_MANIFEST_SET_ROOT:-artifacts/rgc_cross_platform_matrix_inputs}"
auto_discover_manifests="${RGC_CROSS_PLATFORM_AUTO_DISCOVER_MANIFESTS:-1}"

linux_x64_manifest_source="missing"
linux_arm64_manifest_source="missing"
macos_x64_manifest_source="missing"
macos_arm64_manifest_source="missing"
windows_x64_manifest_source="missing"
windows_arm64_manifest_source="missing"
auto_discovered_manifest_set_dir=""

mkdir -p "$run_dir"
: >"$matrix_deltas_path"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for cross-platform matrix heavy commands" >&2
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

  remote_exit_line="$(rg -o 'Remote command finished: exit=[0-9]+' "$log_path" | tail -n1 || true)"
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
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

run_rch_strict_logged() {
  local log_path="$1"
  shift

  local fifo_path fallback_flag_path reader_pid rch_pid rch_status=0
  local line

  fifo_path="$(mktemp -u "${run_dir}/rch-stream.XXXXXX")"
  fallback_flag_path="$(mktemp "${run_dir}/rch-fallback.XXXXXX")"
  rm -f "$fallback_flag_path"
  mkfifo "$fifo_path"
  : >"$log_path"

  {
    while IFS= read -r line || [[ -n "$line" ]]; do
      printf '%s\n' "$line" | tee -a "$log_path"
      if [[ "$line" == *"Remote toolchain failure, falling back to local"* ||
        "$line" == *"falling back to local"* ||
        "$line" == *"fallback to local"* ||
        "$line" == *"local fallback"* ||
        "$line" == *"running locally"* ||
        "$line" == *"[RCH] local ("* ]]; then
        : >"$fallback_flag_path"
        if [[ -n "${rch_pid:-}" ]]; then
          kill "$rch_pid" 2>/dev/null || true
        fi
        pkill -f "CARGO_TARGET_DIR=${target_dir}" 2>/dev/null || true
        pkill -f "${target_dir}" 2>/dev/null || true
      fi
    done <"$fifo_path"
  } &
  reader_pid=$!

  run_rch "$@" >"$fifo_path" 2>&1 &
  rch_pid=$!
  wait "$rch_pid" || rch_status=$?
  wait "$reader_pid" || true
  rm -f "$fifo_path"

  if [[ -f "$fallback_flag_path" ]]; then
    rm -f "$fallback_flag_path"
    pkill -f "CARGO_TARGET_DIR=${target_dir}" 2>/dev/null || true
    return 125
  fi

  rm -f "$fallback_flag_path"
  return "$rch_status"
}

declare -a commands_run=()
declare -a step_logs=()
failed_command=""
manifest_written=false

strict_matrix=false
matrix_complete=false
matrix_eval_error=""
critical_delta_count=0
warning_delta_count=0
required_target_missing_count=0

baseline_available=false
baseline_manifest=""
baseline_outcome="unknown"
baseline_error="missing_input"
baseline_digest="missing-input"
baseline_runtime_digest="unknown"
baseline_cli_digest="unknown"
baseline_toolchain="unknown"

target_ids=(
  "linux-x64"
  "linux-arm64"
  "macos-x64"
  "macos-arm64"
  "windows-x64"
  "windows-arm64"
)

target_os() {
  local target_id="$1"
  case "$target_id" in
    linux-x64 | linux-arm64)
      echo "linux"
      ;;
    macos-x64 | macos-arm64)
      echo "macos"
      ;;
    windows-x64 | windows-arm64)
      echo "windows"
      ;;
    *)
      echo "unknown"
      ;;
  esac
}

target_arch() {
  local target_id="$1"
  case "$target_id" in
    linux-x64 | macos-x64 | windows-x64)
      echo "x64"
      ;;
    linux-arm64 | macos-arm64 | windows-arm64)
      echo "arm64"
      ;;
    *)
      echo "unknown"
      ;;
  esac
}

target_required() {
  local target_id="$1"
  case "$target_id" in
    windows-arm64)
      echo "false"
      ;;
    *)
      echo "true"
      ;;
  esac
}

target_manifest_path() {
  local target_id="$1"
  case "$target_id" in
    linux-x64)
      echo "$linux_x64_manifest"
      ;;
    linux-arm64)
      echo "$linux_arm64_manifest"
      ;;
    macos-x64)
      echo "$macos_x64_manifest"
      ;;
    macos-arm64)
      echo "$macos_arm64_manifest"
      ;;
    windows-x64)
      echo "$windows_x64_manifest"
      ;;
    windows-arm64)
      echo "$windows_arm64_manifest"
      ;;
    *)
      echo ""
      ;;
  esac
}

target_manifest_var_name() {
  local target_id="$1"
  case "$target_id" in
    linux-x64)
      echo "linux_x64_manifest"
      ;;
    linux-arm64)
      echo "linux_arm64_manifest"
      ;;
    macos-x64)
      echo "macos_x64_manifest"
      ;;
    macos-arm64)
      echo "macos_arm64_manifest"
      ;;
    windows-x64)
      echo "windows_x64_manifest"
      ;;
    windows-arm64)
      echo "windows_arm64_manifest"
      ;;
    *)
      echo ""
      ;;
  esac
}

target_manifest_source_var_name() {
  local target_id="$1"
  case "$target_id" in
    linux-x64)
      echo "linux_x64_manifest_source"
      ;;
    linux-arm64)
      echo "linux_arm64_manifest_source"
      ;;
    macos-x64)
      echo "macos_x64_manifest_source"
      ;;
    macos-arm64)
      echo "macos_arm64_manifest_source"
      ;;
    windows-x64)
      echo "windows_x64_manifest_source"
      ;;
    windows-arm64)
      echo "windows_arm64_manifest_source"
      ;;
    *)
      echo ""
      ;;
  esac
}

target_manifest_filename() {
  local target_id="$1"
  printf '%s.run_manifest.json\n' "$target_id"
}

set_target_manifest_resolution() {
  local target_id="$1"
  local manifest_path="$2"
  local source="$3"
  local path_var source_var

  path_var="$(target_manifest_var_name "$target_id")"
  source_var="$(target_manifest_source_var_name "$target_id")"

  if [[ -n "$path_var" ]]; then
    printf -v "$path_var" '%s' "$manifest_path"
  fi
  if [[ -n "$source_var" ]]; then
    printf -v "$source_var" '%s' "$source"
  fi
}

resolve_explicit_target_manifest_sources() {
  local target_id path_var current_value

  for target_id in "${target_ids[@]}"; do
    path_var="$(target_manifest_var_name "$target_id")"
    current_value="${!path_var:-}"
    if [[ -n "$current_value" ]]; then
      set_target_manifest_resolution "$target_id" "$current_value" "env"
    else
      set_target_manifest_resolution "$target_id" "" "missing"
    fi
  done
}

manifest_set_has_required_targets() {
  local set_dir="$1"
  local target_id required_target candidate_path

  for target_id in "${target_ids[@]}"; do
    required_target="$(target_required "$target_id")"
    if [[ "$required_target" != "true" ]]; then
      continue
    fi
    candidate_path="${set_dir}/$(target_manifest_filename "$target_id")"
    if [[ ! -f "$candidate_path" ]]; then
      return 1
    fi
  done

  return 0
}

find_latest_complete_manifest_set_dir() {
  local candidate_dir

  if [[ "$auto_discover_manifests" != "1" || ! -d "$manifest_set_root" ]]; then
    return 0
  fi

  while IFS= read -r candidate_dir; do
    [[ -z "$candidate_dir" ]] && continue
    if manifest_set_has_required_targets "$candidate_dir"; then
      printf '%s\n' "$candidate_dir"
      return 0
    fi
  done < <(find "$manifest_set_root" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r)
}

auto_discover_target_manifests() {
  local target_id source_var candidate_path

  resolve_explicit_target_manifest_sources

  if [[ "$auto_discover_manifests" != "1" ]]; then
    return 0
  fi

  auto_discovered_manifest_set_dir="$(find_latest_complete_manifest_set_dir || true)"
  if [[ -z "$auto_discovered_manifest_set_dir" ]]; then
    return 0
  fi

  for target_id in "${target_ids[@]}"; do
    source_var="$(target_manifest_source_var_name "$target_id")"
    if [[ "${!source_var:-missing}" == "env" ]]; then
      continue
    fi
    candidate_path="${auto_discovered_manifest_set_dir}/$(target_manifest_filename "$target_id")"
    if [[ -f "$candidate_path" ]]; then
      set_target_manifest_resolution "$target_id" "$candidate_path" "auto_discovered"
    fi
  done
}

ensure_rch_ready() {
  local attempts="${1:-5}"
  local sleep_seconds="${2:-2}"
  local attempt
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if rch check >/dev/null 2>&1; then
      return 0
    fi
    sleep "${sleep_seconds}"
  done
  return 1
}

run_step_expect_exit() {
  local command_text="$1"
  local expected_exit="$2"
  local log_path remote_exit_code run_status attempt
  local fallback_detected lock_contention non_compilation_marker
  shift 2

  commands_run+=("$command_text")
  echo "==> $command_text"
  for ((attempt = 1; attempt <= rch_step_retry_attempts; attempt++)); do
    log_path="$(mktemp "${run_dir}/rch-log.XXXXXX")"
    step_logs+=("$log_path")

    if ! ensure_rch_ready "${rch_ready_attempts}" "${rch_ready_sleep_seconds}"; then
      echo "==> warning: rch check not ready after ${rch_ready_attempts} attempts; attempting remote execution anyway" \
        | tee -a "$log_path"
    fi

    run_rch_strict_logged "$log_path" "$@"
    run_status=$?
    fallback_detected=false
    if [[ "$run_status" -eq 125 ]]; then
      fallback_detected=true
    fi

    if ! rch_reject_local_fallback "$log_path"; then
      fallback_detected=true
    fi

    if [[ "$fallback_detected" == true ]]; then
      if [[ "$attempt" -lt "$rch_step_retry_attempts" ]]; then
        echo "==> warning: detected rch local fallback signature (attempt ${attempt}/${rch_step_retry_attempts}); retrying step after daemon nudge" \
          | tee -a "$log_path"
        rch daemon start >/dev/null 2>&1 || true
        sleep "${rch_step_retry_sleep_seconds}"
        continue
      fi
      failed_command="${command_text} (rch-local-fallback-detected)"
      return 1
    fi

    lock_contention=false
    if rg -qi 'Blocking waiting for file lock on artifact directory|waiting for file lock on artifact directory' "$log_path"; then
      lock_contention=true
    fi
    non_compilation_marker=false
    if rg -q 'exec called with non-compilation command' "$log_path"; then
      non_compilation_marker=true
    fi

    if [[ "$run_status" -ne 0 ]]; then
      if rg -q "Remote command finished: exit=${expected_exit}" "$log_path"; then
        echo "==> recovered: remote execution produced expected exit=${expected_exit}" \
          | tee -a "$log_path"
      elif rg -q 'Remote command finished: exit=0' "$log_path"; then
        echo "==> recovered: remote execution succeeded; artifact retrieval timed out" \
          | tee -a "$log_path"
      elif [[ "$run_status" -eq "$expected_exit" ]]; then
        echo "==> info: accepted rch process exit=${run_status} (daemon output omitted remote-exit marker)" \
          | tee -a "$log_path"
      else
        if [[ "$attempt" -lt "$rch_step_retry_attempts" ]]; then
          if [[ "$lock_contention" == true ]]; then
            echo "==> warning: cargo artifact-directory lock contention detected (attempt ${attempt}/${rch_step_retry_attempts}); retrying" \
              | tee -a "$log_path"
          else
            echo "==> warning: rch command exited ${run_status} without acceptable remote marker (attempt ${attempt}/${rch_step_retry_attempts}); retrying" \
              | tee -a "$log_path"
          fi
          rch daemon start >/dev/null 2>&1 || true
          sleep "${rch_step_retry_sleep_seconds}"
          continue
        fi
        failed_command="$command_text"
        return 1
      fi
    fi

    remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
    if [[ -z "$remote_exit_code" ]]; then
      if [[ "$run_status" -eq "$expected_exit" ]]; then
        if [[ "$non_compilation_marker" == true ]]; then
          echo "==> info: remote exit marker missing for non-compilation command; accepted rch process exit=${run_status}" \
            | tee -a "$log_path"
          return 0
        fi
        if [[ "$attempt" -lt "$rch_step_retry_attempts" ]]; then
          echo "==> warning: remote exit marker missing with process exit=${run_status} (attempt ${attempt}/${rch_step_retry_attempts}); retrying for deterministic provenance" \
            | tee -a "$log_path"
          sleep "${rch_step_retry_sleep_seconds}"
          continue
        fi
        echo "==> info: remote exit marker missing; accepted rch process exit=${run_status}" \
          | tee -a "$log_path"
        return 0
      fi
      if [[ "$attempt" -lt "$rch_step_retry_attempts" ]]; then
        echo "==> warning: remote exit marker missing with unexpected process exit=${run_status} (attempt ${attempt}/${rch_step_retry_attempts}); retrying" \
          | tee -a "$log_path"
        sleep "${rch_step_retry_sleep_seconds}"
        continue
      fi
      failed_command="${command_text} (remote-exit=missing, expected=${expected_exit})"
      return 1
    fi

    if [[ "$remote_exit_code" != "$expected_exit" ]]; then
      if [[ "$attempt" -lt "$rch_step_retry_attempts" ]]; then
        echo "==> warning: remote exit ${remote_exit_code} != expected ${expected_exit} (attempt ${attempt}/${rch_step_retry_attempts}); retrying" \
          | tee -a "$log_path"
        sleep "${rch_step_retry_sleep_seconds}"
        continue
      fi
      failed_command="${command_text} (remote-exit=${remote_exit_code:-missing}, expected=${expected_exit})"
      return 1
    fi

    return 0
  done
}

run_step() {
  local command_text="$1"
  shift
  run_step_expect_exit "$command_text" 0 "$@"
}

manifest_value_or_unknown() {
  local manifest="$1"
  local jq_expr="$2"
  if [[ -z "$manifest" || ! -f "$manifest" ]]; then
    echo "unknown"
    return
  fi
  jq -r "${jq_expr} // \"unknown\"" "$manifest"
}

manifest_error_code_or_null() {
  local manifest="$1"
  if [[ -z "$manifest" || ! -f "$manifest" ]]; then
    echo "missing_input"
    return
  fi
  jq -r 'if .error_code == null then "null" else (.error_code | tostring) end' "$manifest"
}

manifest_witness_digest() {
  local manifest="$1"
  local explicit
  if [[ -z "$manifest" || ! -f "$manifest" ]]; then
    echo "missing-input"
    return
  fi

  explicit="$(jq -r '.witness_digest // empty' "$manifest")"
  if [[ -n "$explicit" ]]; then
    echo "$explicit"
    return
  fi

  jq -c '{schema_version, component, outcome, error_code, commands, artifacts}' "$manifest" | parser_frontier_sha256
}

manifest_runtime_digest() {
  local manifest="$1"
  manifest_value_or_unknown "$manifest" '.runtime_digest // .runtime_workload_digest'
}

manifest_cli_digest() {
  local manifest="$1"
  manifest_value_or_unknown "$manifest" '.cli_digest // .cli_workflow_digest'
}

append_delta_row() {
  local target_id="$1"
  local target_os_name="$2"
  local target_arch_name="$3"
  local required_target="$4"
  local target_manifest="$5"
  local target_outcome="$6"
  local target_error="$7"
  local target_digest="$8"
  local target_runtime_digest="$9"
  local target_cli_digest="${10}"
  local target_toolchain="${11}"
  local delta_class="${12}"
  local severity="${13}"
  local reason="${14}"

  jq -nc \
    --arg target_id "$target_id" \
    --arg target_os "$target_os_name" \
    --arg target_arch "$target_arch_name" \
    --argjson required_target "$required_target" \
    --arg target_manifest "$target_manifest" \
    --arg baseline_target_id "linux-x64" \
    --arg baseline_manifest "$baseline_manifest" \
    --arg baseline_outcome "$baseline_outcome" \
    --arg baseline_error_code "$baseline_error" \
    --arg baseline_witness_digest "$baseline_digest" \
    --arg baseline_runtime_digest "$baseline_runtime_digest" \
    --arg baseline_cli_digest "$baseline_cli_digest" \
    --arg baseline_toolchain_fingerprint "$baseline_toolchain" \
    --arg target_outcome "$target_outcome" \
    --arg target_error_code "$target_error" \
    --arg target_witness_digest "$target_digest" \
    --arg target_runtime_digest "$target_runtime_digest" \
    --arg target_cli_digest "$target_cli_digest" \
    --arg target_toolchain_fingerprint "$target_toolchain" \
    --arg delta_class "$delta_class" \
    --arg severity "$severity" \
    --arg reason "$reason" \
    '{
      target_id: $target_id,
      target_os: $target_os,
      target_arch: $target_arch,
      required_target: $required_target,
      target_manifest: $target_manifest,
      baseline_target_id: $baseline_target_id,
      baseline_manifest: $baseline_manifest,
      baseline_outcome: $baseline_outcome,
      baseline_error_code: $baseline_error_code,
      baseline_witness_digest: $baseline_witness_digest,
      baseline_runtime_digest: $baseline_runtime_digest,
      baseline_cli_digest: $baseline_cli_digest,
      baseline_toolchain_fingerprint: $baseline_toolchain_fingerprint,
      target_outcome: $target_outcome,
      target_error_code: $target_error_code,
      target_witness_digest: $target_witness_digest,
      target_runtime_digest: $target_runtime_digest,
      target_cli_digest: $target_cli_digest,
      target_toolchain_fingerprint: $target_toolchain_fingerprint,
      delta_class: $delta_class,
      severity: $severity,
      reason: $reason
    }' >>"$matrix_deltas_path"
}

matrix_manifest_exists_json() {
  local manifest_path="$1"
  if [[ -n "$manifest_path" && -f "$manifest_path" ]]; then
    echo true
  else
    echo false
  fi
}

build_matrix_inputs_json() {
  local linux_x64_exists linux_arm64_exists macos_x64_exists
  local macos_arm64_exists windows_x64_exists windows_arm64_exists

  linux_x64_exists="$(matrix_manifest_exists_json "$linux_x64_manifest")"
  linux_arm64_exists="$(matrix_manifest_exists_json "$linux_arm64_manifest")"
  macos_x64_exists="$(matrix_manifest_exists_json "$macos_x64_manifest")"
  macos_arm64_exists="$(matrix_manifest_exists_json "$macos_arm64_manifest")"
  windows_x64_exists="$(matrix_manifest_exists_json "$windows_x64_manifest")"
  windows_arm64_exists="$(matrix_manifest_exists_json "$windows_arm64_manifest")"

  jq -n \
    --arg manifest_set_root "$manifest_set_root" \
    --argjson auto_discover_manifests "$( [[ "$auto_discover_manifests" == "1" ]] && echo true || echo false )" \
    --arg auto_discovered_manifest_set_dir "$auto_discovered_manifest_set_dir" \
    --arg linux_x64_manifest "$linux_x64_manifest" \
    --arg linux_x64_source "$linux_x64_manifest_source" \
    --argjson linux_x64_exists "$linux_x64_exists" \
    --arg linux_arm64_manifest "$linux_arm64_manifest" \
    --arg linux_arm64_source "$linux_arm64_manifest_source" \
    --argjson linux_arm64_exists "$linux_arm64_exists" \
    --arg macos_x64_manifest "$macos_x64_manifest" \
    --arg macos_x64_source "$macos_x64_manifest_source" \
    --argjson macos_x64_exists "$macos_x64_exists" \
    --arg macos_arm64_manifest "$macos_arm64_manifest" \
    --arg macos_arm64_source "$macos_arm64_manifest_source" \
    --argjson macos_arm64_exists "$macos_arm64_exists" \
    --arg windows_x64_manifest "$windows_x64_manifest" \
    --arg windows_x64_source "$windows_x64_manifest_source" \
    --argjson windows_x64_exists "$windows_x64_exists" \
    --arg windows_arm64_manifest "$windows_arm64_manifest" \
    --arg windows_arm64_source "$windows_arm64_manifest_source" \
    --argjson windows_arm64_exists "$windows_arm64_exists" \
    '{
      manifest_set_root: $manifest_set_root,
      auto_discover_manifests: $auto_discover_manifests,
      auto_discovered_manifest_set_dir: (
        if $auto_discovered_manifest_set_dir == "" then null else $auto_discovered_manifest_set_dir end
      ),
      manifest_filename_template: "<target-id>.run_manifest.json",
      targets: {
        "linux-x64": {
          path: (if $linux_x64_manifest == "" then null else $linux_x64_manifest end),
          source: $linux_x64_source,
          exists: $linux_x64_exists
        },
        "linux-arm64": {
          path: (if $linux_arm64_manifest == "" then null else $linux_arm64_manifest end),
          source: $linux_arm64_source,
          exists: $linux_arm64_exists
        },
        "macos-x64": {
          path: (if $macos_x64_manifest == "" then null else $macos_x64_manifest end),
          source: $macos_x64_source,
          exists: $macos_x64_exists
        },
        "macos-arm64": {
          path: (if $macos_arm64_manifest == "" then null else $macos_arm64_manifest end),
          source: $macos_arm64_source,
          exists: $macos_arm64_exists
        },
        "windows-x64": {
          path: (if $windows_x64_manifest == "" then null else $windows_x64_manifest end),
          source: $windows_x64_source,
          exists: $windows_x64_exists
        },
        "windows-arm64": {
          path: (if $windows_arm64_manifest == "" then null else $windows_arm64_manifest end),
          source: $windows_arm64_source,
          exists: $windows_arm64_exists
        }
      }
    }'
}

load_baseline_summary() {
  baseline_manifest="$(target_manifest_path "linux-x64")"
  if [[ -n "$baseline_manifest" && -f "$baseline_manifest" ]]; then
    baseline_available=true
    baseline_outcome="$(manifest_value_or_unknown "$baseline_manifest" '.outcome')"
    baseline_error="$(manifest_error_code_or_null "$baseline_manifest")"
    baseline_digest="$(manifest_witness_digest "$baseline_manifest")"
    baseline_runtime_digest="$(manifest_runtime_digest "$baseline_manifest")"
    baseline_cli_digest="$(manifest_cli_digest "$baseline_manifest")"
    baseline_toolchain="$(manifest_value_or_unknown "$baseline_manifest" '.deterministic_environment.toolchain_fingerprint')"
  else
    baseline_available=false
    baseline_outcome="unknown"
    baseline_error="missing_input"
    baseline_digest="missing-input"
    baseline_runtime_digest="unknown"
    baseline_cli_digest="unknown"
    baseline_toolchain="unknown"
    required_target_missing_count=$((required_target_missing_count + 1))
  fi
}

evaluate_target() {
  local target_id="$1"
  local target_os_name target_arch_name required_target target_manifest
  local target_outcome target_error target_digest target_runtime_digest target_cli_digest target_toolchain
  local delta_class severity reason

  target_os_name="$(target_os "$target_id")"
  target_arch_name="$(target_arch "$target_id")"
  required_target="$(target_required "$target_id")"
  target_manifest="$(target_manifest_path "$target_id")"

  if [[ -z "$target_manifest" || ! -f "$target_manifest" ]]; then
    if [[ "$required_target" == "true" && "$target_id" != "linux-x64" ]]; then
      required_target_missing_count=$((required_target_missing_count + 1))
    fi
    delta_class="candidate_target_input_missing"
    severity="warning"
    reason="candidate target manifest input missing"
    if [[ "$required_target" == "true" ]]; then
      delta_class="missing_target_input"
      severity="critical"
      reason="required target manifest input missing"
      critical_delta_count=$((critical_delta_count + 1))
    else
      warning_delta_count=$((warning_delta_count + 1))
    fi
    append_delta_row \
      "$target_id" \
      "$target_os_name" \
      "$target_arch_name" \
      "$required_target" \
      "$target_manifest" \
      "unknown" \
      "missing_input" \
      "missing-input" \
      "unknown" \
      "unknown" \
      "unknown" \
      "$delta_class" \
      "$severity" \
      "$reason"
    return
  fi

  target_outcome="$(manifest_value_or_unknown "$target_manifest" '.outcome')"
  target_error="$(manifest_error_code_or_null "$target_manifest")"
  target_digest="$(manifest_witness_digest "$target_manifest")"
  target_runtime_digest="$(manifest_runtime_digest "$target_manifest")"
  target_cli_digest="$(manifest_cli_digest "$target_manifest")"
  target_toolchain="$(manifest_value_or_unknown "$target_manifest" '.deterministic_environment.toolchain_fingerprint')"

  if [[ "$baseline_available" != true ]]; then
    delta_class="missing_baseline_input"
    severity="critical"
    reason="baseline linux-x64 manifest missing; drift comparison invalid"
    critical_delta_count=$((critical_delta_count + 1))
  elif [[ "$baseline_outcome" != "$target_outcome" || "$baseline_error" != "$target_error" ]]; then
    delta_class="workflow_behavior_drift"
    severity="critical"
    reason="outcome or error_code diverged from baseline"
    critical_delta_count=$((critical_delta_count + 1))
  elif [[ "$baseline_digest" == "$target_digest" ]]; then
    delta_class="none"
    severity="info"
    reason="outcome, error_code, and digest are equal to baseline"
  elif [[ "$baseline_runtime_digest" == "$target_runtime_digest" && "$baseline_cli_digest" == "$target_cli_digest" ]]; then
    delta_class="artifact_only_drift"
    severity="warning"
    reason="digest drift but normalized runtime/CLI digests match baseline"
    warning_delta_count=$((warning_delta_count + 1))
  elif [[ "$baseline_toolchain" != "$target_toolchain" ]]; then
    delta_class="toolchain_fingerprint_delta"
    severity="warning"
    reason="digest drift explained by target toolchain fingerprint"
    warning_delta_count=$((warning_delta_count + 1))
  else
    delta_class="unexplained_digest_drift"
    severity="critical"
    reason="digest drift has no normalization or toolchain explanation"
    critical_delta_count=$((critical_delta_count + 1))
  fi

  append_delta_row \
    "$target_id" \
    "$target_os_name" \
    "$target_arch_name" \
    "$required_target" \
    "$target_manifest" \
    "$target_outcome" \
    "$target_error" \
    "$target_digest" \
    "$target_runtime_digest" \
    "$target_cli_digest" \
    "$target_toolchain" \
    "$delta_class" \
    "$severity" \
    "$reason"
}

evaluate_matrix() {
  local target_id required_target target_manifest

  : >"$matrix_deltas_path"
  matrix_complete=true
  matrix_eval_error=""
  critical_delta_count=0
  warning_delta_count=0
  required_target_missing_count=0

  load_baseline_summary

  for target_id in "${target_ids[@]}"; do
    evaluate_target "$target_id"
  done

  for target_id in "${target_ids[@]}"; do
    required_target="$(target_required "$target_id")"
    target_manifest="$(target_manifest_path "$target_id")"
    if [[ "$required_target" == "true" && ( -z "$target_manifest" || ! -f "$target_manifest" ) ]]; then
      matrix_complete=false
      break
    fi
  done

  if [[ "$strict_matrix" == true && "$matrix_complete" != true ]]; then
    matrix_eval_error="required matrix target manifests are incomplete"
  fi

  if [[ "$strict_matrix" == true && "$critical_delta_count" -gt 0 ]]; then
    if [[ -n "$matrix_eval_error" ]]; then
      matrix_eval_error="${matrix_eval_error}; critical drifts detected"
    else
      matrix_eval_error="critical drifts detected"
    fi
  fi

  if [[ "$strict_matrix" == true && -n "$matrix_eval_error" ]]; then
    return 1
  fi
  return 0
}

write_matrix_summary() {
  local target_deltas_json
  local matrix_inputs_json
  target_deltas_json="$(jq -s '.' "$matrix_deltas_path")"
  matrix_inputs_json="$(build_matrix_inputs_json)"

  jq -n \
    --arg schema_version "franken-engine.rgc-cross-platform-matrix.summary.v1" \
    --arg bead_id "bd-1lsy.11.13" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg generated_at_utc "$timestamp" \
    --arg mode "$mode" \
    --arg scenario_id "$scenario_id" \
    --arg replay_command "$replay_command" \
    --arg matrix_eval_error "$matrix_eval_error" \
    --argjson strict_mode "$strict_matrix" \
    --argjson matrix_complete "$matrix_complete" \
    --argjson required_target_missing_count "$required_target_missing_count" \
    --argjson critical_delta_count "$critical_delta_count" \
    --argjson warning_delta_count "$warning_delta_count" \
    --argjson matrix_inputs "$matrix_inputs_json" \
    --argjson target_deltas "$target_deltas_json" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      policy_id: $policy_id,
      component: $component,
      generated_at_utc: $generated_at_utc,
      mode: $mode,
      scenario_id: $scenario_id,
      strict_mode: $strict_mode,
      matrix_complete: $matrix_complete,
      required_target_missing_count: $required_target_missing_count,
      critical_delta_count: $critical_delta_count,
      warning_delta_count: $warning_delta_count,
      matrix_inputs: $matrix_inputs,
      replay_command: $replay_command,
      matrix_eval_error: (if $matrix_eval_error == "" then null else $matrix_eval_error end),
      target_deltas: $target_deltas
    }' >"$matrix_summary_path"
}

run_mode() {
  case "$mode" in
    check)
      run_step "jq empty ${contract_json_path}" jq empty "$contract_json_path" || return $?
      run_step "test -f ${contract_doc_path}" test -f "$contract_doc_path" || return $?
      run_step "cargo check -p frankenengine-engine --test rgc_cross_platform_matrix" \
        cargo check -p frankenengine-engine --test rgc_cross_platform_matrix || return $?
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test rgc_cross_platform_matrix" \
        cargo test -p frankenengine-engine --test rgc_cross_platform_matrix || return $?
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test rgc_cross_platform_matrix -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_cross_platform_matrix -- -D warnings || return $?
      ;;
    ci)
      run_mode check || return $?
      run_mode test || return $?
      run_mode clippy || return $?
      evaluate_matrix || return $?
      ;;
    matrix)
      run_step \
        "cargo test -p frankenengine-engine --test rgc_cross_platform_matrix -- --exact rgc_063_drift_classifier_assigns_expected_classes" \
        cargo test -p frankenengine-engine --test rgc_cross_platform_matrix -- --exact rgc_063_drift_classifier_assigns_expected_classes \
        || return $?
      evaluate_matrix || return $?
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci|matrix]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma
  local matrix_inputs_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-CROSS-PLATFORM-MATRIX-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  write_matrix_summary
  matrix_inputs_json="$(build_matrix_inputs_json)"

  {
    echo "{\"schema_version\":\"franken-engine.rgc-cross-platform-matrix.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"target_id\":\"all\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"

    while IFS= read -r row || [[ -n "$row" ]]; do
      [[ -z "${row// }" ]] && continue
      target_id="$(jq -r '.target_id' <<<"$row")"
      delta_class="$(jq -r '.delta_class' <<<"$row")"
      severity="$(jq -r '.severity' <<<"$row")"
      row_outcome="pass"
      row_error_code_json="null"
      if [[ "$severity" == "critical" ]]; then
        row_outcome="fail"
        row_error_code_json='"FE-RGC-CROSS-PLATFORM-MATRIX-DELTA-0001"'
      fi
      echo "{\"schema_version\":\"franken-engine.rgc-cross-platform-matrix.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"target_drift_evaluated\",\"target_id\":\"$(parser_frontier_json_escape "${target_id}")\",\"outcome\":\"${row_outcome}\",\"error_code\":${row_error_code_json},\"delta_class\":\"$(parser_frontier_json_escape "${delta_class}")\"}"
    done <"$matrix_deltas_path"
  } >"$events_path"

  {
    echo '{'
    echo '  "schema_version": "franken-engine.rgc-cross-platform-matrix.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.11.13",'
    echo "  \"component\": \"${component}\","
    echo "  \"scenario_id\": \"${scenario_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"strict_matrix\": ${strict_matrix},"
    echo "  \"manifest_set_root\": \"$(parser_frontier_json_escape "${manifest_set_root}")\","
    echo "  \"auto_discover_manifests\": $([[ "$auto_discover_manifests" == "1" ]] && echo true || echo false),"
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"error_code\": ${error_code_json},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\","
    fi
    echo "  \"matrix_complete\": ${matrix_complete},"
    echo "  \"required_target_missing_count\": ${required_target_missing_count},"
    echo "  \"critical_delta_count\": ${critical_delta_count},"
    echo "  \"warning_delta_count\": ${warning_delta_count},"
    if [[ -n "$matrix_eval_error" ]]; then
      echo "  \"matrix_eval_error\": \"$(parser_frontier_json_escape "${matrix_eval_error}")\","
    fi
    echo "  \"matrix_inputs\": ${matrix_inputs_json},"
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo '  },'
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\","
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=,
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=''
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"matrix_target_deltas\": \"${matrix_deltas_path}\","
    echo "    \"matrix_summary\": \"${matrix_summary_path}\","
    echo '    "gate_script": "scripts/run_rgc_cross_platform_matrix_gate.sh",'
    echo '    "replay_wrapper": "scripts/e2e/rgc_cross_platform_matrix_replay.sh",'
    echo '    "contract_json": "docs/rgc_cross_platform_matrix_v1.json",'
    echo '    "contract_doc": "docs/RGC_CROSS_PLATFORM_MATRIX_V1.md",'
    echo '    "contract_tests": "crates/franken-engine/tests/rgc_cross_platform_matrix.rs"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${matrix_deltas_path}\","
    echo "    \"cat ${matrix_summary_path}\","
    echo "    \"${replay_command}\""
    echo '  ],'
    echo '  "rch_step_logs": ['
    for idx in "${!step_logs[@]}"; do
      comma=,
      if [[ "$idx" == "$(( ${#step_logs[@]} - 1 ))" ]]; then
        comma=''
      fi
      echo "    \"$(parser_frontier_json_escape "${step_logs[$idx]}")\"${comma}"
    done
    echo '  ]'
    echo '}'
  } >"$manifest_path"

  echo "rgc cross-platform matrix manifest: ${manifest_path}"
  echo "rgc cross-platform matrix events: ${events_path}"
  echo "rgc cross-platform matrix commands: ${commands_path}"
  echo "rgc cross-platform matrix deltas: ${matrix_deltas_path}"
  echo "rgc cross-platform matrix summary: ${matrix_summary_path}"
}

if [[ "$mode" == "matrix" || "$require_matrix" == "1" ]]; then
  strict_matrix=true
fi

auto_discover_target_manifests

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"
exit "$main_exit"
