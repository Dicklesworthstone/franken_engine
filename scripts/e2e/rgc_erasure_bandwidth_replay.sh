#!/usr/bin/env bash
#
# rgc_erasure_bandwidth_replay.sh — deterministic-replay verifier for the
# Track II.3 erasure-vs-replication bandwidth gate (bd-cixqu.35.3).
#
# Runs `frankenctl gates erasure-bandwidth` twice over identical inputs and
# asserts the produced bandwidth report is byte-identical — the audit-verification
# property the gate depends on. Each step is recorded to an ISO-8601 timestamped
# step log under the artifact directory.
#
# Environment overrides:
#   EBW_CONFIG        optional bandwidth config JSON
#   EBW_ARTIFACT_ROOT artifact root (default: <repo>/artifacts/rgc_erasure_bandwidth_replay)
#   CARGO_TARGET_DIR  cargo target dir (default: <repo>/target)
#   RUSTUP_TOOLCHAIN  toolchain (default: nightly-x86_64-unknown-linux-gnu)
#   CARGO_BIN         cargo binary (default: cargo)
#
# Exit codes: 0 identical, 2 setup error, 3 divergence.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CARGO_BIN="${CARGO_BIN:-cargo}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly-x86_64-unknown-linux-gnu}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
ARTIFACT_ROOT="${EBW_ARTIFACT_ROOT:-${REPO_ROOT}/artifacts/rgc_erasure_bandwidth_replay}"
RUN_DIR="${ARTIFACT_ROOT}/${RUN_ID}"
STEP_LOG_DIR="${RUN_DIR}/step_logs"
mkdir -p "${STEP_LOG_DIR}"

STEP_INDEX=0
log_step() {
  # log_step <message>
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local file
  file="$(printf '%s/step_%03d.log' "${STEP_LOG_DIR}" "${STEP_INDEX}")"
  printf '%s  %s\n' "${ts}" "$*" | tee "${file}"
  STEP_INDEX=$((STEP_INDEX + 1))
}

cd "${REPO_ROOT}"

log_step "build frankenctl"
if ! "${CARGO_BIN}" build -p frankenengine-engine --bin frankenctl \
  >"${RUN_DIR}/build.log" 2>&1; then
  log_step "FAIL: could not build frankenctl (see ${RUN_DIR}/build.log)"
  cat "${RUN_DIR}/build.log" >&2 || true
  exit 2
fi
FRANKENCTL="${CARGO_TARGET_DIR}/debug/frankenctl"

CONFIG_ARGS=()
if [[ -n "${EBW_CONFIG:-}" ]]; then
  CONFIG_ARGS=(--config "${EBW_CONFIG}")
fi

log_step "run erasure-bandwidth report (run A)"
"${FRANKENCTL}" gates erasure-bandwidth --out-dir "${RUN_DIR}/a" "${CONFIG_ARGS[@]}" >/dev/null

log_step "run erasure-bandwidth report (run B)"
"${FRANKENCTL}" gates erasure-bandwidth --out-dir "${RUN_DIR}/b" "${CONFIG_ARGS[@]}" >/dev/null

log_step "compare bandwidth reports for byte-identical replay"
if cmp -s "${RUN_DIR}/a/bandwidth_efficiency_report.json" \
  "${RUN_DIR}/b/bandwidth_efficiency_report.json"; then
  digest="$(grep -o '"report_hash": *"[^"]*"' \
    "${RUN_DIR}/a/bandwidth_efficiency_report.json" | head -1)"
  log_step "PASS: bandwidth report is deterministic (${digest})"
  echo "✅ erasure-bandwidth report is deterministic (byte-identical replay)"
  echo "   ${digest}"
  echo "   step logs: ${STEP_LOG_DIR}"
  exit 0
else
  log_step "FAIL: bandwidth report diverged across identical runs"
  echo "❌ erasure-bandwidth report diverged across identical runs" >&2
  diff "${RUN_DIR}/a/bandwidth_efficiency_report.json" \
    "${RUN_DIR}/b/bandwidth_efficiency_report.json" | head -40 >&2 || true
  exit 3
fi
