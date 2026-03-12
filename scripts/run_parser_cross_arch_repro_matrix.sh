#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_parser_cross_arch_repro_matrix}"
artifact_root="${PARSER_CROSS_ARCH_REPRO_ARTIFACT_ROOT:-artifacts/parser_cross_arch_repro_matrix}"
scenario_id="${PARSER_CROSS_ARCH_REPRO_SCENARIO:-psrp-07-2}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
require_matrix="${PARSER_CROSS_ARCH_REQUIRE_MATRIX:-0}"
auto_discover_manifests="${PARSER_CROSS_ARCH_AUTO_DISCOVER_MANIFESTS:-1}"
event_ast_artifact_root="${PARSER_CROSS_ARCH_EVENT_AST_ARTIFACT_ROOT:-artifacts/parser_event_ast_equivalence}"
parallel_artifact_root="${PARSER_CROSS_ARCH_PARALLEL_INTERFERENCE_ARTIFACT_ROOT:-artifacts/parser_parallel_interference}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
matrix_deltas_path="${run_dir}/matrix_lane_deltas.jsonl"
matrix_summary_path="${run_dir}/matrix_summary.json"

x86_event_ast_manifest="${PARSER_CROSS_ARCH_X86_EVENT_AST_MANIFEST:-}"
arm64_event_ast_manifest="${PARSER_CROSS_ARCH_ARM64_EVENT_AST_MANIFEST:-}"
x86_parallel_manifest="${PARSER_CROSS_ARCH_X86_PARALLEL_INTERFERENCE_MANIFEST:-}"
arm64_parallel_manifest="${PARSER_CROSS_ARCH_ARM64_PARALLEL_INTERFERENCE_MANIFEST:-}"
x86_event_ast_manifest_source="missing"
arm64_event_ast_manifest_source="missing"
x86_parallel_manifest_source="missing"
arm64_parallel_manifest_source="missing"

trace_id="trace-parser-cross-arch-repro-matrix-${timestamp}"
decision_id="decision-parser-cross-arch-repro-matrix-${timestamp}"
policy_id="policy-parser-cross-arch-repro-matrix-v1"
component="parser_cross_arch_repro_matrix_gate"
replay_command="./scripts/e2e/parser_cross_arch_repro_matrix_replay.sh ${mode}"

mkdir -p "$run_dir"
touch "$matrix_deltas_path"

declare -a registered_temp_paths=()

register_temp_path() {
  local path="${1:-}"
  if [[ -n "$path" ]]; then
    registered_temp_paths+=("$path")
  fi
}

unregister_temp_path() {
  local path_to_remove="${1:-}"
  local kept=()
  local path=""

  for path in "${registered_temp_paths[@]}"; do
    if [[ "$path" != "$path_to_remove" ]]; then
      kept+=("$path")
    fi
  done

  registered_temp_paths=("${kept[@]}")
}

cleanup_temp_path() {
  local path="${1:-}"
  if [[ -z "$path" ]]; then
    return
  fi

  rm -f "$path" 2>/dev/null || true
  unregister_temp_path "$path"
}

cleanup_registered_temp_paths() {
  local path=""
  for path in "${registered_temp_paths[@]}"; do
    rm -f "$path" 2>/dev/null || true
  done
  registered_temp_paths=()
}

trap cleanup_registered_temp_paths EXIT

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for parser cross-arch reproducibility matrix heavy commands" >&2
  exit 2
fi

run_rch() {
  RCH_EXEC_TIMEOUT_SECONDS="${rch_timeout_seconds}" \
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

run_rch_strict_logged() {
  local log_path="$1"
  shift

  local fifo_path fallback_flag_path rch_pid_path reader_pid rch_pid rch_status=0
  local line current_rch_pid

  fifo_path="$(mktemp -u "${run_dir}/rch-stream.XXXXXX")"
  fallback_flag_path="$(mktemp "${run_dir}/rch-fallback.XXXXXX")"
  rch_pid_path="$(mktemp "${run_dir}/rch-pid.XXXXXX")"
  register_temp_path "$fifo_path"
  register_temp_path "$fallback_flag_path"
  register_temp_path "$rch_pid_path"
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
        current_rch_pid="$(tr -d '[:space:]' <"$rch_pid_path" 2>/dev/null || true)"
        if [[ -n "$current_rch_pid" ]]; then
          kill "$current_rch_pid" 2>/dev/null || true
          pkill -P "$current_rch_pid" 2>/dev/null || true
        fi
        pkill -f 'frankenengine-engine --test parser_cross_arch_repro_matrix' 2>/dev/null || true
        pkill -f "CARGO_TARGET_DIR=${target_dir}" 2>/dev/null || true
        pkill -f "${target_dir}" 2>/dev/null || true
      fi
    done <"$fifo_path"
  } &
  reader_pid=$!

  run_rch "$@" >"$fifo_path" 2>&1 &
  rch_pid=$!
  printf '%s\n' "$rch_pid" >"$rch_pid_path"
  wait "$rch_pid" || rch_status=$?
  wait "$reader_pid" || true
  cleanup_temp_path "$fifo_path"

  if [[ -f "$fallback_flag_path" ]]; then
    cleanup_temp_path "$fallback_flag_path"
    pkill -f "CARGO_TARGET_DIR=${target_dir}" 2>/dev/null || true
    pkill -f "${target_dir}" 2>/dev/null || true
    cleanup_temp_path "$rch_pid_path"
    return 125
  fi

  cleanup_temp_path "$fallback_flag_path"
  cleanup_temp_path "$rch_pid_path"
  return "$rch_status"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|Remote execution failed.*running locally|running locally|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_last_remote_exit_code() {
  local log_path="$1"
  local exit_line
  exit_line="$(grep -Eo 'Remote command finished: exit=[0-9]+' "$log_path" | tail -n 1 || true)"
  if [[ -z "$exit_line" ]]; then
    echo ""
    return
  fi
  echo "${exit_line##*=}"
}

rch_has_recoverable_artifact_timeout() {
  local log_path="$1"
  grep -Eiq 'artifact retrieval timed out|artifact transfer timed out|timed out waiting for artifacts' "$log_path"
}

rch_reject_artifact_retrieval_failure() {
  local log_path="$1"
  if grep -Eiq 'Artifact retrieval failed|Failed to retrieve artifacts:|rsync artifact retrieval failed|artifact retrieval .*rsync error' "$log_path"; then
    echo "rch artifact retrieval failed; refusing to mark heavy command as successful" >&2
    return 1
  fi
}

manifest_matches_arch() {
  local manifest="$1"
  local expected_arch="$2"
  jq -er --arg expected_arch "$expected_arch" \
    '(.arch_profile // .deterministic_environment.rust_host // "") == $expected_arch' \
    "$manifest" >/dev/null 2>&1
}

find_latest_manifest_for_arch() {
  local artifact_root="$1"
  local expected_arch="$2"

  if [[ ! -d "$artifact_root" ]]; then
    return 0
  fi

  find "$artifact_root" -type f -name run_manifest.json 2>/dev/null \
    | sort \
    | while IFS= read -r candidate; do
        if manifest_matches_arch "$candidate" "$expected_arch"; then
          printf '%s\n' "$candidate"
        fi
      done \
    | tail -n 1
}

resolve_manifest_input() {
  local manifest_var_name="$1"
  local source_var_name="$2"
  local artifact_root="$3"
  local expected_arch="$4"
  local current_value="${!manifest_var_name:-}"
  local discovered_manifest=""

  if [[ -n "$current_value" ]]; then
    printf -v "$source_var_name" '%s' "env"
    return
  fi

  if [[ "$auto_discover_manifests" != "1" ]]; then
    printf -v "$source_var_name" '%s' "missing"
    return
  fi

  discovered_manifest="$(find_latest_manifest_for_arch "$artifact_root" "$expected_arch")"
  if [[ -n "$discovered_manifest" ]]; then
    printf -v "$manifest_var_name" '%s' "$discovered_manifest"
    printf -v "$source_var_name" '%s' "auto_discovered"
    return
  fi

  printf -v "$source_var_name" '%s' "missing"
}

json_string_or_null() {
  local value="${1:-}"
  if [[ -z "$value" ]]; then
    printf 'null'
  else
    printf '"%s"' "$(parser_frontier_json_escape "$value")"
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false
matrix_complete=false
critical_delta_count=0
matrix_eval_error=""
matrix_input_status="pending_upstream_matrix"
matrix_mode_strict=false

if [[ "$mode" == "matrix" || "$require_matrix" == "1" ]]; then
  matrix_mode_strict=true
fi

resolve_manifest_input \
  x86_event_ast_manifest \
  x86_event_ast_manifest_source \
  "$event_ast_artifact_root" \
  "x86_64-unknown-linux-gnu"
resolve_manifest_input \
  arm64_event_ast_manifest \
  arm64_event_ast_manifest_source \
  "$event_ast_artifact_root" \
  "aarch64-unknown-linux-gnu"
resolve_manifest_input \
  x86_parallel_manifest \
  x86_parallel_manifest_source \
  "$parallel_artifact_root" \
  "x86_64-unknown-linux-gnu"
resolve_manifest_input \
  arm64_parallel_manifest \
  arm64_parallel_manifest_source \
  "$parallel_artifact_root" \
  "aarch64-unknown-linux-gnu"

run_step() {
  local command_text="$1"
  local log_path run_rc remote_exit_code
  local fallback_detected=false
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="$(mktemp)"

  if run_rch_strict_logged "$log_path" "$@"; then
    run_rc=0
  else
    run_rc=$?
  fi

  if [[ "$run_rc" -eq 125 ]]; then
    fallback_detected=true
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    fallback_detected=true
  fi

  if [[ "$fallback_detected" == true ]]; then
    rm -f "$log_path"
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  if [[ "$run_rc" -ne 0 ]]; then
    remote_exit_code="$(rch_last_remote_exit_code "$log_path")"
    if [[ "$remote_exit_code" == "0" ]] && rch_has_recoverable_artifact_timeout "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      rm -f "$log_path"
      if [[ -n "$remote_exit_code" ]]; then
        failed_command="${command_text} (remote-exit-${remote_exit_code})"
      else
        failed_command="$command_text"
      fi
      return 1
    fi
  fi

  if ! rch_reject_artifact_retrieval_failure "$log_path"; then
    rm -f "$log_path"
    failed_command="${command_text} (rch-artifact-retrieval-failed)"
    return 1
  fi

  remote_exit_code="$(rch_last_remote_exit_code "$log_path")"
  if [[ -n "$remote_exit_code" && "$remote_exit_code" != "0" ]]; then
    rm -f "$log_path"
    failed_command="${command_text} (remote-exit-${remote_exit_code})"
    return 1
  fi

  rm -f "$log_path"
}

run_mode() {
  case "$mode" in
    check)
      run_step \
        "cargo check -p frankenengine-engine --test parser_cross_arch_repro_matrix" \
        cargo check -p frankenengine-engine --test parser_cross_arch_repro_matrix || return 1
      ;;
    test)
      run_step \
        "cargo test -p frankenengine-engine --test parser_cross_arch_repro_matrix" \
        cargo test -p frankenengine-engine --test parser_cross_arch_repro_matrix || return 1
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --test parser_cross_arch_repro_matrix -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_cross_arch_repro_matrix -- -D warnings || return 1
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-engine --test parser_cross_arch_repro_matrix" \
        cargo check -p frankenengine-engine --test parser_cross_arch_repro_matrix || return 1
      run_step \
        "cargo test -p frankenengine-engine --test parser_cross_arch_repro_matrix" \
        cargo test -p frankenengine-engine --test parser_cross_arch_repro_matrix || return 1
      run_step \
        "cargo clippy -p frankenengine-engine --test parser_cross_arch_repro_matrix -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_cross_arch_repro_matrix -- -D warnings || return 1
      ;;
    matrix)
      run_step \
        "cargo test -p frankenengine-engine --test parser_cross_arch_repro_matrix -- --exact parser_cross_arch_matrix_delta_classifier_assigns_expected_classes" \
        cargo test -p frankenengine-engine --test parser_cross_arch_repro_matrix -- --exact parser_cross_arch_matrix_delta_classifier_assigns_expected_classes || return 1
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci|matrix]" >&2
      exit 2
      ;;
  esac
}

append_delta_row() {
  local lane_id="$1"
  local x86_manifest="$2"
  local arm64_manifest="$3"
  local x86_arch="$4"
  local arm64_arch="$5"
  local x86_outcome="$6"
  local arm64_outcome="$7"
  local x86_error_code="$8"
  local arm64_error_code="$9"
  local x86_digest="${10}"
  local arm64_digest="${11}"
  local x86_toolchain_fp="${12}"
  local arm64_toolchain_fp="${13}"
  local x86_replay="${14}"
  local arm64_replay="${15}"
  local delta_class="${16}"
  local severity="${17}"
  local reason="${18}"

  jq -nc \
    --arg lane_id "$lane_id" \
    --arg x86_manifest "$x86_manifest" \
    --arg arm64_manifest "$arm64_manifest" \
    --arg x86_arch_profile "$x86_arch" \
    --arg arm64_arch_profile "$arm64_arch" \
    --arg x86_outcome "$x86_outcome" \
    --arg arm64_outcome "$arm64_outcome" \
    --arg x86_error_code "$x86_error_code" \
    --arg arm64_error_code "$arm64_error_code" \
    --arg x86_witness_digest "$x86_digest" \
    --arg arm64_witness_digest "$arm64_digest" \
    --arg x86_toolchain_fingerprint "$x86_toolchain_fp" \
    --arg arm64_toolchain_fingerprint "$arm64_toolchain_fp" \
    --arg x86_replay_command "$x86_replay" \
    --arg arm64_replay_command "$arm64_replay" \
    --arg delta_class "$delta_class" \
    --arg severity "$severity" \
    --arg reason "$reason" \
    '{
      lane_id: $lane_id,
      x86_manifest: $x86_manifest,
      arm64_manifest: $arm64_manifest,
      x86_arch_profile: $x86_arch_profile,
      arm64_arch_profile: $arm64_arch_profile,
      x86_outcome: $x86_outcome,
      arm64_outcome: $arm64_outcome,
      x86_error_code: $x86_error_code,
      arm64_error_code: $arm64_error_code,
      x86_witness_digest: $x86_witness_digest,
      arm64_witness_digest: $arm64_witness_digest,
      x86_toolchain_fingerprint: $x86_toolchain_fingerprint,
      arm64_toolchain_fingerprint: $arm64_toolchain_fingerprint,
      x86_replay_command: $x86_replay_command,
      arm64_replay_command: $arm64_replay_command,
      delta_class: $delta_class,
      severity: $severity,
      reason: $reason
    }' >>"$matrix_deltas_path"
}

append_missing_delta() {
  local lane_id="$1"
  local x86_manifest="$2"
  local arm64_manifest="$3"
  local reason="$4"
  local severity="critical"
  local classified_reason="$reason"

  if [[ "$matrix_mode_strict" != true ]]; then
    severity="info"
    classified_reason="optional manifest input missing outside strict matrix mode: ${reason}"
  fi

  append_delta_row \
    "$lane_id" \
    "$x86_manifest" \
    "$arm64_manifest" \
    "x86_64-unknown-linux-gnu" \
    "aarch64-unknown-linux-gnu" \
    "unknown" \
    "unknown" \
    "missing_input" \
    "missing_input" \
    "missing-input" \
    "missing-input" \
    "unknown" \
    "unknown" \
    "./scripts/e2e/parser_cross_arch_repro_matrix_replay.sh" \
    "./scripts/e2e/parser_cross_arch_repro_matrix_replay.sh" \
    "missing_input" \
    "$severity" \
    "$classified_reason"
}

manifest_value_or_unknown() {
  local manifest="$1"
  local jq_expr="$2"
  if [[ ! -f "$manifest" ]]; then
    echo "unknown"
    return
  fi
  jq -r "${jq_expr} // \"unknown\"" "$manifest"
}

manifest_error_code_or_null() {
  local manifest="$1"
  if [[ ! -f "$manifest" ]]; then
    echo "missing_input"
    return
  fi
  jq -r 'if .error_code == null then "null" else (.error_code | tostring) end' "$manifest"
}

manifest_witness_digest() {
  local manifest="$1"
  if [[ ! -f "$manifest" ]]; then
    echo "missing-input"
    return
  fi
  jq -c '{schema_version, component, outcome, error_code, commands}' "$manifest" | parser_frontier_sha256
}

evaluate_lane_pair() {
  local lane_id="$1"
  local x86_manifest="$2"
  local arm64_manifest="$3"
  local x86_outcome arm64_outcome x86_error arm64_error x86_digest arm64_digest
  local x86_toolchain arm64_toolchain x86_arch arm64_arch x86_replay arm64_replay
  local delta_class severity reason

  if [[ ! -f "$x86_manifest" || ! -f "$arm64_manifest" ]]; then
    append_missing_delta \
      "$lane_id" \
      "$x86_manifest" \
      "$arm64_manifest" \
      "required manifest input is missing for ${lane_id}"
    return
  fi

  x86_outcome="$(manifest_value_or_unknown "$x86_manifest" '.outcome')"
  arm64_outcome="$(manifest_value_or_unknown "$arm64_manifest" '.outcome')"
  x86_error="$(manifest_error_code_or_null "$x86_manifest")"
  arm64_error="$(manifest_error_code_or_null "$arm64_manifest")"
  x86_digest="$(manifest_witness_digest "$x86_manifest")"
  arm64_digest="$(manifest_witness_digest "$arm64_manifest")"
  x86_toolchain="$(manifest_value_or_unknown "$x86_manifest" '.deterministic_environment.toolchain_fingerprint')"
  arm64_toolchain="$(manifest_value_or_unknown "$arm64_manifest" '.deterministic_environment.toolchain_fingerprint')"
  x86_arch="$(manifest_value_or_unknown "$x86_manifest" '.arch_profile // .deterministic_environment.rust_host')"
  arm64_arch="$(manifest_value_or_unknown "$arm64_manifest" '.arch_profile // .deterministic_environment.rust_host')"
  x86_replay="$(manifest_value_or_unknown "$x86_manifest" '.replay_command')"
  arm64_replay="$(manifest_value_or_unknown "$arm64_manifest" '.replay_command')"

  if [[ "$x86_outcome" != "$arm64_outcome" || "$x86_error" != "$arm64_error" ]]; then
    delta_class="upstream_lane_regression"
    severity="critical"
    reason="outcome or error_code diverged across architectures"
  elif [[ "$x86_digest" == "$arm64_digest" ]]; then
    delta_class="none"
    severity="info"
    reason="outcome, error_code, and witness digest are identical"
  elif [[ "$x86_toolchain" != "$arm64_toolchain" ]]; then
    delta_class="toolchain_fingerprint_delta"
    severity="warning"
    reason="digest differs with toolchain fingerprint delta"
  else
    delta_class="digest_delta_unexplained"
    severity="critical"
    reason="digest differs without toolchain fingerprint explanation"
  fi

  append_delta_row \
    "$lane_id" \
    "$x86_manifest" \
    "$arm64_manifest" \
    "$x86_arch" \
    "$arm64_arch" \
    "$x86_outcome" \
    "$arm64_outcome" \
    "$x86_error" \
    "$arm64_error" \
    "$x86_digest" \
    "$arm64_digest" \
    "$x86_toolchain" \
    "$arm64_toolchain" \
    "$x86_replay" \
    "$arm64_replay" \
    "$delta_class" \
    "$severity" \
    "$reason"
}

evaluate_matrix() {
  : >"$matrix_deltas_path"
  matrix_complete=false
  matrix_eval_error=""

  evaluate_lane_pair \
    "parser_event_ast_equivalence" \
    "$x86_event_ast_manifest" \
    "$arm64_event_ast_manifest"
  evaluate_lane_pair \
    "parser_parallel_interference" \
    "$x86_parallel_manifest" \
    "$arm64_parallel_manifest"

  critical_delta_count="$(
    jq -s '[.[] | select(.severity == "critical")] | length' "$matrix_deltas_path"
  )"

  if [[ -f "$x86_event_ast_manifest" && -f "$arm64_event_ast_manifest" && -f "$x86_parallel_manifest" && -f "$arm64_parallel_manifest" ]]; then
    matrix_complete=true
  fi

  if [[ "$matrix_mode_strict" == true && "$matrix_complete" != true ]]; then
    matrix_eval_error="strict matrix mode requires all x86_64 and arm64 lane manifest inputs"
    return 1
  fi

  if [[ "$matrix_mode_strict" == true && "$critical_delta_count" -gt 0 ]]; then
    matrix_eval_error="critical cross-architecture deltas detected"
    return 1
  fi

  return 0
}

classify_matrix_input_status() {
  if [[ "$matrix_complete" != true ]]; then
    if [[ "$matrix_mode_strict" == true ]]; then
      matrix_input_status="incomplete_matrix"
    else
      matrix_input_status="pending_upstream_matrix"
    fi
    return
  fi

  if [[ "$critical_delta_count" =~ ^[0-9]+$ && "$critical_delta_count" -gt 0 ]]; then
    matrix_input_status="blocked_critical_deltas"
    return
  fi

  matrix_input_status="ready_for_external_rerun"
}

delta_class_error_code() {
  local delta_class="${1:-}"
  case "$delta_class" in
    digest_delta_unexplained)
      echo "FE-PARSER-CROSS-ARCH-MATRIX-0001"
      ;;
    upstream_lane_regression)
      echo "FE-PARSER-CROSS-ARCH-MATRIX-0002"
      ;;
    missing_input)
      echo "FE-PARSER-CROSS-ARCH-MATRIX-0003"
      ;;
    *)
      echo ""
      ;;
  esac
}

gate_error_code() {
  local exit_code="${1:-0}"
  local first_critical_delta=""
  local specific_code=""

  if [[ "$exit_code" -eq 0 ]]; then
    echo ""
    return
  fi

  if [[ -n "$failed_command" && "$failed_command" != "evaluate_matrix" ]]; then
    echo "FE-PARSER-CROSS-ARCH-REPRO-MATRIX-0001"
    return
  fi

  if [[ -s "$matrix_deltas_path" ]]; then
    first_critical_delta="$(
      jq -rs '[.[] | select(.severity == "critical")] | .[0].delta_class // ""' \
        "$matrix_deltas_path" 2>/dev/null
    )"
    specific_code="$(delta_class_error_code "$first_critical_delta")"
    if [[ -n "$specific_code" ]]; then
      echo "$specific_code"
      return
    fi
  fi

  echo "FE-PARSER-CROSS-ARCH-REPRO-MATRIX-0001"
}

write_matrix_summary() {
  local lane_deltas_json
  lane_deltas_json="$(jq -s '.' "$matrix_deltas_path")"

  jq -n \
    --arg schema_version "franken-engine.parser-cross-arch-repro-matrix.summary.v1" \
    --arg bead_id "bd-2mds.1.7.2" \
    --arg policy_id "$policy_id" \
    --arg component "$component" \
    --arg generated_at_utc "$timestamp" \
    --arg mode "$mode" \
    --arg scenario_id "$scenario_id" \
    --arg matrix_input_status "$matrix_input_status" \
    --arg host_arch "$PARSER_FRONTIER_RUST_HOST" \
    --arg toolchain_fingerprint "$PARSER_FRONTIER_TOOLCHAIN_FINGERPRINT" \
    --arg replay_command "$replay_command" \
    --arg matrix_eval_error "$matrix_eval_error" \
    --arg auto_discover_manifests "$auto_discover_manifests" \
    --arg x86_event_ast_manifest "$x86_event_ast_manifest" \
    --arg arm64_event_ast_manifest "$arm64_event_ast_manifest" \
    --arg x86_parallel_manifest "$x86_parallel_manifest" \
    --arg arm64_parallel_manifest "$arm64_parallel_manifest" \
    --arg x86_event_ast_manifest_source "$x86_event_ast_manifest_source" \
    --arg arm64_event_ast_manifest_source "$arm64_event_ast_manifest_source" \
    --arg x86_parallel_manifest_source "$x86_parallel_manifest_source" \
    --arg arm64_parallel_manifest_source "$arm64_parallel_manifest_source" \
    --argjson matrix_complete "$matrix_complete" \
    --argjson critical_delta_count "$critical_delta_count" \
    --argjson lane_deltas "$lane_deltas_json" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      policy_id: $policy_id,
      component: $component,
      generated_at_utc: $generated_at_utc,
      mode: $mode,
      scenario_id: $scenario_id,
      matrix_input_status: $matrix_input_status,
      matrix_complete: $matrix_complete,
      critical_delta_count: $critical_delta_count,
      host_arch_profile: $host_arch,
      host_toolchain_fingerprint: $toolchain_fingerprint,
      replay_command: $replay_command,
      matrix_inputs: {
        auto_discovery_enabled: ($auto_discover_manifests == "1"),
        parser_event_ast_equivalence: {
          x86_64_manifest: (if $x86_event_ast_manifest == "" then null else $x86_event_ast_manifest end),
          x86_64_source: $x86_event_ast_manifest_source,
          aarch64_manifest: (if $arm64_event_ast_manifest == "" then null else $arm64_event_ast_manifest end),
          aarch64_source: $arm64_event_ast_manifest_source
        },
        parser_parallel_interference: {
          x86_64_manifest: (if $x86_parallel_manifest == "" then null else $x86_parallel_manifest end),
          x86_64_source: $x86_parallel_manifest_source,
          aarch64_manifest: (if $arm64_parallel_manifest == "" then null else $arm64_parallel_manifest end),
          aarch64_source: $arm64_parallel_manifest_source
        }
      },
      matrix_eval_error: (if $matrix_eval_error == "" then null else $matrix_eval_error end),
      lane_deltas: $lane_deltas
    }' >"$matrix_summary_path"
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code git_commit dirty_worktree idx comma

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
  else
    outcome="fail"
  fi
  error_code="$(gate_error_code "$exit_code")"

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.parser-cross-arch-repro-matrix.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"matrix_input_status\":\"${matrix_input_status}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":$(json_string_or_null "${error_code}")}"

    while IFS= read -r row || [[ -n "$row" ]]; do
      [[ -z "${row// }" ]] && continue
      lane_id="$(jq -r '.lane_id' <<<"$row")"
      delta_class="$(jq -r '.delta_class' <<<"$row")"
      severity="$(jq -r '.severity' <<<"$row")"
      reason="$(jq -r '.reason' <<<"$row")"
      lane_outcome="pass"
      lane_error_code=""
      if [[ "$severity" == "critical" ]]; then
        lane_outcome="fail"
        lane_error_code="$(delta_class_error_code "$delta_class")"
      fi
      echo "{\"schema_version\":\"franken-engine.parser-cross-arch-repro-matrix.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"lane_delta_evaluated\",\"scenario_id\":\"$(parser_frontier_json_escape "${lane_id}")\",\"delta_class\":\"$(parser_frontier_json_escape "${delta_class}")\",\"delta_reason\":\"$(parser_frontier_json_escape "${reason}")\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${lane_outcome}\",\"error_code\":$(json_string_or_null "${lane_error_code}")}"
    done <"$matrix_deltas_path"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-cross-arch-repro-matrix.run-manifest.v1",'
    echo '  "bead_id": "bd-2mds.1.7.2",'
    echo "  \"deterministic_env_schema_version\": \"${PARSER_FRONTIER_ENV_SCHEMA_VERSION}\","
    echo "  \"component\": \"${component}\","
    echo "  \"scenario_id\": \"${scenario_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"error_code\": $(json_string_or_null "${error_code}"),"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\","
    fi
    echo "  \"matrix_complete\": ${matrix_complete},"
    echo "  \"critical_delta_count\": ${critical_delta_count},"
    if [[ -n "$matrix_eval_error" ]]; then
      echo "  \"matrix_eval_error\": \"$(parser_frontier_json_escape "${matrix_eval_error}")\","
    fi
    echo "  \"matrix_input_status\": \"${matrix_input_status}\","
    echo '  "matrix_dimensions": {'
    echo '    "architectures": ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"],'
    echo '    "required_lanes": ["parser_event_ast_equivalence", "parser_parallel_interference"]'
    echo '  },'
    echo '  "matrix_inputs": {'
    echo "    \"auto_discovery_enabled\": $([[ "$auto_discover_manifests" == "1" ]] && echo true || echo false),"
    echo '    "parser_event_ast_equivalence": {'
    echo "      \"x86_64_manifest\": $(json_string_or_null "$x86_event_ast_manifest"),"
    echo "      \"x86_64_source\": \"${x86_event_ast_manifest_source}\","
    echo "      \"aarch64_manifest\": $(json_string_or_null "$arm64_event_ast_manifest"),"
    echo "      \"aarch64_source\": \"${arm64_event_ast_manifest_source}\""
    echo '    },'
    echo '    "parser_parallel_interference": {'
    echo "      \"x86_64_manifest\": $(json_string_or_null "$x86_parallel_manifest"),"
    echo "      \"x86_64_source\": \"${x86_parallel_manifest_source}\","
    echo "      \"aarch64_manifest\": $(json_string_or_null "$arm64_parallel_manifest"),"
    echo "      \"aarch64_source\": \"${arm64_parallel_manifest_source}\""
    echo '    }'
    echo '  },'
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo "  },"
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\","
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo "  ],"
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"matrix_lane_deltas\": \"${matrix_deltas_path}\","
    echo "    \"matrix_summary\": \"${matrix_summary_path}\","
    echo '    "contract_doc": "docs/PARSER_CROSS_ARCH_REPRO_MATRIX.md",'
    echo '    "fixture": "crates/franken-engine/tests/fixtures/parser_cross_arch_repro_matrix_v1.json",'
    echo '    "integration_tests": "crates/franken-engine/tests/parser_cross_arch_repro_matrix.rs",'
    echo '    "replay_wrapper": "scripts/e2e/parser_cross_arch_repro_matrix_replay.sh"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${matrix_summary_path}\","
    echo "    \"cat ${matrix_deltas_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "parser cross-arch repro matrix manifest: ${manifest_path}"
  echo "parser cross-arch repro matrix summary: ${matrix_summary_path}"
  echo "parser cross-arch repro matrix events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?

if ! evaluate_matrix; then
  if [[ "$main_exit" -eq 0 ]]; then
    main_exit=1
  fi
  if [[ -z "$failed_command" ]]; then
    failed_command="evaluate_matrix"
  fi
fi
classify_matrix_input_status
write_matrix_summary
write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "$events_path"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
