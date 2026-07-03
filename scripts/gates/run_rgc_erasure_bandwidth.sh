#!/usr/bin/env bash
#
# run_rgc_erasure_bandwidth.sh — Track II.3 gate (bd-cixqu.35.3).
#
# Produces the erasure-vs-full-replication bandwidth-efficiency report via
# `frankenctl gates erasure-bandwidth`, verifies the artifact bundle, and proves
# deterministic (byte-identical) replay of the signed report. The report is
# honest about the shipped XOR single-parity scheme — it never fabricates
# Reed-Solomon behavior.
#
# Artifact bundle (under ${EBW_ARTIFACT_ROOT}/${EBW_RUN_ID}/):
#   run_manifest.json   gate-level manifest (schema, run id, outcome, lanes)
#   commands.txt        every command the gate ran, in order
#   summary.md          human-readable lane table
#   report_a/           first bandwidth report bundle
#   report_b/           second bundle (must be byte-identical to report_a)
#   logs/               per-lane logs
#
# Environment overrides:
#   EBW_ARTIFACT_ROOT   artifact root (default: <repo>/artifacts/rgc_erasure_bandwidth)
#   EBW_RUN_ID          run id / bundle dir name (default: UTC timestamp)
#   EBW_CONFIG          optional bandwidth config JSON passed to the gate
#   CARGO_TARGET_DIR    cargo target dir (default: <repo>/target)
#   RUSTUP_TOOLCHAIN    toolchain (default: nightly-x86_64-unknown-linux-gnu)
#   CARGO_BIN           cargo binary (default: cargo)
#
# Exit codes:
#   0  all lanes passed
#   2  setup/usage error (missing tool, bad argument)
#   3  a lane failed (build/run error, bundle mismatch, or test regression)
set -euo pipefail

MODE="${1:-ci}"
case "${MODE}" in
  ci | full) ;;
  *)
    echo "usage: $0 [ci|full]" >&2
    exit 2
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CARGO_BIN="${CARGO_BIN:-cargo}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly-x86_64-unknown-linux-gnu}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"
PKG="frankenengine-engine"

RUN_ID="${EBW_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
ARTIFACT_ROOT="${EBW_ARTIFACT_ROOT:-${REPO_ROOT}/artifacts/rgc_erasure_bandwidth}"
BUNDLE_DIR="${ARTIFACT_ROOT}/${RUN_ID}"
LOG_DIR="${BUNDLE_DIR}/logs"
COMMANDS_FILE="${BUNDLE_DIR}/commands.txt"
mkdir -p "${LOG_DIR}"
: >"${COMMANDS_FILE}"

record_cmd() { printf '%s\n' "$*" >>"${COMMANDS_FILE}"; }

fail=0
declare -a LANE_NAMES=()
declare -a LANE_STATUS=()

record_lane() {
  LANE_NAMES+=("$1")
  LANE_STATUS+=("$2")
  if [[ "$2" == "pass" ]]; then
    echo "✅ $1"
  else
    echo "❌ $1"
    fail=1
  fi
}

run_lane() {
  # run_lane <name> <logfile> <cmd...>
  local name="$1" log="$2"
  shift 2
  record_cmd "$*"
  if "$@" >"${log}" 2>&1; then
    record_lane "${name}" "pass"
  else
    echo "   (see ${log})"
    record_lane "${name}" "fail"
  fi
}

CONFIG_ARGS=()
if [[ -n "${EBW_CONFIG:-}" ]]; then
  CONFIG_ARGS=(--config "${EBW_CONFIG}")
fi

cd "${REPO_ROOT}"

# 1. Build frankenctl.
run_lane "build_frankenctl" "${LOG_DIR}/build.log" \
  "${CARGO_BIN}" build -p "${PKG}" --bin frankenctl

FRANKENCTL="${CARGO_TARGET_DIR}/debug/frankenctl"

# 2. Run the bandwidth gate twice into separate directories.
if [[ "${LANE_STATUS[0]}" == "pass" && -x "${FRANKENCTL}" ]]; then
  run_lane "report_run_a" "${LOG_DIR}/report_a.log" \
    "${FRANKENCTL}" gates erasure-bandwidth --out-dir "${BUNDLE_DIR}/report_a" "${CONFIG_ARGS[@]}"
  run_lane "report_run_b" "${LOG_DIR}/report_b.log" \
    "${FRANKENCTL}" gates erasure-bandwidth --out-dir "${BUNDLE_DIR}/report_b" "${CONFIG_ARGS[@]}"

  # 3. Deterministic replay: the two reports must be byte-identical.
  record_cmd "cmp report_a/bandwidth_efficiency_report.json report_b/bandwidth_efficiency_report.json"
  if cmp -s "${BUNDLE_DIR}/report_a/bandwidth_efficiency_report.json" \
    "${BUNDLE_DIR}/report_b/bandwidth_efficiency_report.json"; then
    record_lane "deterministic_replay" "pass"
  else
    record_lane "deterministic_replay" "fail"
  fi

  # 4. Required artifacts present and gate outcome is pass.
  ok=1
  for art in bandwidth_efficiency_report.json run_manifest.json summary.md; do
    if [[ ! -f "${BUNDLE_DIR}/report_a/${art}" ]]; then
      echo "   missing artifact: ${art}"
      ok=0
    fi
  done
  if ! grep -q '"outcome": "pass"' "${BUNDLE_DIR}/report_a/run_manifest.json" 2>/dev/null; then
    ok=0
  fi
  # 5. Honesty guard: the report must record the XOR single-parity scheme and
  #    must NOT fabricate a Reed-Solomon-over-GF scheme claim.
  if ! grep -q '"coding_scheme": "xor-single-parity-v1"' \
    "${BUNDLE_DIR}/report_a/run_manifest.json" 2>/dev/null; then
    echo "   report does not record the xor-single-parity scheme"
    ok=0
  fi
  # The honesty notes intentionally MENTION "Reed-Solomon" to disclaim it, so we
  # only reject an actual Reed-Solomon value in the coding_scheme field.
  if grep -qiE '"coding_scheme": *"reed-solomon' \
    "${BUNDLE_DIR}/report_a/bandwidth_efficiency_report.json" 2>/dev/null; then
    echo "   report fabricates a Reed-Solomon scheme claim"
    ok=0
  fi
  if [[ "${ok}" == "1" ]]; then
    record_lane "bundle_valid" "pass"
  else
    record_lane "bundle_valid" "fail"
  fi
else
  record_lane "report_run_a" "fail"
fi

# 6. Rust test lane.
run_lane "bandwidth_tests" "${LOG_DIR}/tests.log" \
  "${CARGO_BIN}" test -p "${PKG}" --test erasure_bandwidth_accounting_integration

# 7. Gate manifest + summary.
OUTCOME="pass"
[[ "${fail}" == "0" ]] || OUTCOME="fail"

LANES_JSON=""
for i in "${!LANE_NAMES[@]}"; do
  sep=","
  [[ "${i}" -eq 0 ]] && sep=""
  LANES_JSON="${LANES_JSON}${sep}{\"lane\":\"${LANE_NAMES[$i]}\",\"status\":\"${LANE_STATUS[$i]}\"}"
done

cat >"${BUNDLE_DIR}/run_manifest.json" <<JSON
{
  "schema_version": "franken-engine.erasure-bandwidth-gate.v1",
  "bead": "bd-cixqu.35.3",
  "run_id": "${RUN_ID}",
  "mode": "${MODE}",
  "outcome": "${OUTCOME}",
  "lanes": [${LANES_JSON}]
}
JSON

{
  echo "# Erasure-bandwidth gate — ${RUN_ID}"
  echo
  echo "- outcome: ${OUTCOME}"
  echo "- mode: ${MODE}"
  echo
  echo "| lane | status |"
  echo "| --- | --- |"
  for i in "${!LANE_NAMES[@]}"; do
    echo "| ${LANE_NAMES[$i]} | ${LANE_STATUS[$i]} |"
  done
} >"${BUNDLE_DIR}/summary.md"

echo "bundle: ${BUNDLE_DIR}"
if [[ "${OUTCOME}" == "pass" ]]; then
  exit 0
else
  exit 3
fi
