#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
uid="$(id -u)"
artifact_root="${RGC_ZERO_PLACEHOLDER_GATE_ARTIFACT_ROOT:-artifacts/rgc_zero_placeholder_gate}"
out_dir="${RGC_ZERO_PLACEHOLDER_GATE_OUT_DIR:-${artifact_root}/${timestamp}_uid${uid}_${mode}_$$}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_rgc_zero_placeholder_gate_${target_namespace}}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
waivers_path="${RGC_ZERO_PLACEHOLDER_GATE_WAIVERS:-}"
epoch_raw="${RGC_ZERO_PLACEHOLDER_GATE_EPOCH:-100}"
staged_waivers_path=""

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for zero-placeholder gate execution" >&2
  exit 2
fi

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"
if [[ -n "$waivers_path" ]]; then
  if [[ ! -f "$waivers_path" ]]; then
    echo "zero-placeholder gate waivers file not found: $waivers_path" >&2
    exit 1
  fi
  waivers_path="$(cd "$(dirname "$waivers_path")" && pwd)/$(basename "$waivers_path")"
  staged_waivers_path="${out_dir}/input_waivers.json"
  if [[ "$waivers_path" != "$staged_waivers_path" ]]; then
    cp "$waivers_path" "$staged_waivers_path"
  fi
fi

rch_output="$(mktemp)"
cleanup() {
  rm -f "$rch_output"
}
trap cleanup EXIT

last_worker_id=""
last_worker_user=""
last_worker_host=""
last_worker_identity_file=""

rch_strip_ansi() {
  sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g' "$1"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n 1 || true)"
  if [[ -z "$remote_exit_line" ]]; then
    return 1
  fi

  remote_exit_code="${remote_exit_line##*=}"
  if [[ -z "$remote_exit_code" ]]; then
    return 1
  fi

  printf '%s\n' "$remote_exit_code"
}

rch_selected_worker_id() {
  local log_path="$1"
  rch_strip_ansi "$log_path" | sed -n 's/.*Selected worker: \([^ ]*\) at .*/\1/p' | tail -n 1
}

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

  worker_line="$(rch_strip_ansi "$log_path" | sed -n 's/.*Selected worker: \([^ ]*\) at \([^ ]*\) (.*/\1|\2/p' | tail -n 1 || true)"
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

rch_has_recoverable_artifact_timeout() {
  local log_path="$1"
  rch_strip_ansi "$log_path" | grep -Eiq \
    'artifact retrieval timed out|artifact transfer timed out|timed out waiting for artifacts|failed to retrieve artifacts|failed to download artifacts'
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq \
    'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

cmd=(
  cargo run -p frankenengine-engine --bin franken_zero_placeholder_gate --
  --out-dir "$out_dir"
  --epoch "$epoch_raw"
)
if [[ -n "$staged_waivers_path" ]]; then
  cmd+=(--waivers "$staged_waivers_path")
fi

set +e
timeout "${rch_timeout_seconds}" \
  rch exec --color never -- env \
  "RUSTUP_TOOLCHAIN=${toolchain}" \
  "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
  "CARGO_TARGET_DIR=${target_dir}" \
  "${cmd[@]}" 2>&1 | tee "$rch_output"
run_status=$?
set -e

remote_exit_code="$(rch_remote_exit_code "$rch_output" || true)"
if [[ "$run_status" -ne 0 ]]; then
  if [[ "$run_status" -eq 124 ]]; then
    echo "rch command timed out after ${rch_timeout_seconds}s" >&2
    exit 1
  fi

  if [[ "$remote_exit_code" == "0" ]] && rch_has_recoverable_artifact_timeout "$rch_output"; then
    echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$rch_output"
  else
    if [[ -z "$remote_exit_code" ]]; then
      echo "rch output missing remote exit marker; failing closed" >&2
    else
      echo "rch reported non-zero remote exit ${remote_exit_code} for zero-placeholder gate command" >&2
    fi
    exit 1
  fi
fi

if ! rch_reject_local_fallback "$rch_output"; then
  exit 1
fi

if [[ -z "$remote_exit_code" ]]; then
  echo "rch output missing remote exit marker; failing closed" >&2
  exit 1
fi

if [[ "$remote_exit_code" != "0" ]]; then
  echo "rch reported non-zero remote exit ${remote_exit_code} for zero-placeholder gate command" >&2
  exit 1
fi

worker="$(rch_selected_worker_id "$rch_output" || true)"
capture_selected_worker "$rch_output"
if [[ -z "$worker" ]]; then
  echo "failed to determine rch worker for artifact sync" >&2
  exit 1
fi

if [[ -z "$last_worker_user" || -z "$last_worker_host" || -z "$last_worker_identity_file" ]]; then
  echo "failed to resolve zero-placeholder gate worker SSH identity for artifact sync" >&2
  exit 1
fi

if ! scp -q -r \
  -i "$last_worker_identity_file" \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=no \
  "${last_worker_user}@${last_worker_host}:${out_dir}/." \
  "$out_dir/"; then
  echo "failed to sync zero-placeholder gate artifacts from rch worker ${last_worker_id}" >&2
  exit 1
fi

test -f "$out_dir/placeholder_gate_report.json"
test -f "$out_dir/waiver_manifest.json"
test -f "$out_dir/trace_ids.json"
test -f "$out_dir/run_manifest.json"
test -f "$out_dir/events.jsonl"
test -f "$out_dir/commands.txt"

printf 'zero-placeholder gate artifacts: %s\n' "$out_dir"
