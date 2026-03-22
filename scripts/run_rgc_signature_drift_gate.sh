#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
epoch="${RGC_SIGNATURE_DRIFT_GATE_EPOCH:-42}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
cargo_incremental="${CARGO_INCREMENTAL:-0}"
artifact_root="${RGC_SIGNATURE_DRIFT_GATE_ARTIFACT_ROOT:-artifacts/rgc_signature_drift_gate}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_rgc_signature_drift_gate_${target_namespace}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/signature_drift_gate_report.json"
trace_ids_path="${run_dir}/trace_ids.json"
summary_path="${run_dir}/summary.md"
env_path="${run_dir}/env.json"
repro_lock_path="${run_dir}/repro.lock"
step_logs_dir="${run_dir}/step_logs"
script_logs_dir="${run_dir}/script_logs"

doc_path="docs/RGC_SIGNATURE_DRIFT_GATE_V1.md"
trace_id="trace-rgc-signature-drift-gate-${timestamp}"
decision_id="decision-rgc-signature-drift-gate-${timestamp}"
policy_id="RGC-617C"
component="rgc_signature_drift_gate"
scenario_id="rgc-617c-parent"
source_commit="$(git rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${run_dir}" "${script_logs_dir}"

if [[ ! -f "$doc_path" ]]; then
  echo "FE-RGC-617C-CONTRACT-0001: missing doc (${doc_path})" >&2
  exit 1
fi

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for the RGC signature drift gate runner" >&2
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

declare -a validation_errors=()
required_artifacts=(
  "run_manifest.json"
  "events.jsonl"
  "commands.txt"
  "trace_ids.json"
  "signature_drift_gate_report.json"
  "summary.md"
  "env.json"
  "repro.lock"
)
failed_command=""
last_step_log_path=""
step_log_index=0

run_step() {
  local command_text="$1"
  local log_path status remote_exit_code
  shift

  log_path="${script_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
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

  last_step_log_path="${log_path}"
}

extract_streamed_artifacts() {
  local stripped_log marker_prefix required artifact_path

  marker_prefix="__RGC_SIGNATURE_DRIFT_GATE_ARTIFACT__"
  stripped_log="$(mktemp)"
  rch_strip_ansi "${last_step_log_path}" >"${stripped_log}"

  for required in "${required_artifacts[@]}"; do
    artifact_path="${run_dir}/${required}"
    mkdir -p "$(dirname "${artifact_path}")"
    awk \
      -v begin="${marker_prefix}:BEGIN:${required}" \
      -v end="${marker_prefix}:END:${required}" \
      '
        $0 == begin { capture = 1; next }
        $0 == end { capture = 0; exit }
        capture { print }
      ' \
      "${stripped_log}" >"${artifact_path}"

    if [[ ! -s "${artifact_path}" ]]; then
      rm -f "${stripped_log}"
      failed_command="stream artifact bundle (missing ${required})"
      return 1
    fi
  done

  rm -f "${stripped_log}"
}

run_step \
  "cargo run -p frankenengine-engine --bin franken_signature_drift_gate -- --out-dir ${run_dir} --epoch ${epoch} && stream artifact bundle" \
  cargo run -p frankenengine-engine --bin franken_signature_drift_gate -- \
  --out-dir "${run_dir}" \
  --epoch "${epoch}" \
  --trace-id "${trace_id}" \
  --decision-id "${decision_id}" \
  --policy-id "${policy_id}" \
  --generated-at-utc "${generated_at_utc}" \
  --source-commit "${source_commit}" \
  --toolchain "${toolchain}" \
  --emit-artifact-stream

extract_streamed_artifacts || true

for required in "${required_artifacts[@]}"; do
  [[ -f "${run_dir}/${required}" ]] || validation_errors+=("missing expected artifact: ${run_dir}/${required}")
done

if [[ -f "${report_path}" ]] && ! jq -e '
    .component == "signature_drift_gate"
    and .evidence_specimen_count > 0
    and .all_specimens_match_expected == true
  ' "${report_path}" >/dev/null; then
  validation_errors+=("report JSON missing required fields or specimens do not match")
fi

if [[ -f "${manifest_path}" ]] && ! jq -e '
    .artifact_paths.signature_drift_gate_report == "signature_drift_gate_report.json"
    and .artifact_paths.trace_ids == "trace_ids.json"
    and .artifact_paths.events_jsonl == "events.jsonl"
  ' "${manifest_path}" >/dev/null; then
  validation_errors+=("run manifest artifact paths are incomplete")
fi

if [[ -f "${trace_ids_path}" ]] && ! jq -e '
    .component == "signature_drift_gate"
    and .policy_id == "RGC-617C"
  ' "${trace_ids_path}" >/dev/null; then
  validation_errors+=("trace_ids contract is incomplete")
fi

if [[ -f "${commands_path}" ]] && ! grep -q 'franken_signature_drift_gate' "${commands_path}"; then
  validation_errors+=("commands.txt does not reference the runner binary")
fi

if [[ -f "${repro_lock_path}" ]] && ! jq -e --arg epoch "${epoch}" '
    (.epoch | tostring) == $epoch
    and (.replay_command | contains("--epoch " + $epoch))
  ' "${repro_lock_path}" >/dev/null; then
  validation_errors+=("repro.lock does not preserve the active epoch in replay_command")
fi

if [[ "${#validation_errors[@]}" -gt 0 ]]; then
  printf '%s\n' "${validation_errors[@]}" >&2
  exit 1
fi

echo "rgc signature-drift gate manifest: ${manifest_path}"
echo "rgc signature-drift gate trace ids: ${trace_ids_path}"
echo "rgc signature-drift gate report: ${report_path}"
