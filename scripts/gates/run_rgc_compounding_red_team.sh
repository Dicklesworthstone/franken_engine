#!/usr/bin/env bash
#
# run_rgc_compounding_red_team.sh — Track U.4 gate (bd-cixqu.21.4).
#
# Orchestrates the compounding red-team campaign (U.1 generation + U.3 novelty +
# U.2 corpus promotion) via `frankenctl gates compounding-red-team`, verifies the
# produced artifact bundle, and proves deterministic (byte-identical) replay.
#
# Artifact bundle (under ${CRT_ARTIFACT_ROOT}/${CRT_RUN_ID}/):
#   run_manifest.json   gate-level manifest (schema, run id, outcome, lanes)
#   commands.txt        every command the gate ran, in order
#   summary.md          human-readable lane table
#   campaign_a/         first campaign bundle
#   campaign_b/         second campaign bundle (must be byte-identical to campaign_a)
#   logs/               per-lane logs
#
# Environment overrides:
#   CRT_ARTIFACT_ROOT   artifact root (default: <repo>/artifacts/rgc_compounding_red_team)
#   CRT_RUN_ID          run id / bundle dir name (default: UTC timestamp)
#   CRT_CONFIG          optional campaign config TOML passed to the gate
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

RUN_ID="${CRT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
ARTIFACT_ROOT="${CRT_ARTIFACT_ROOT:-${REPO_ROOT}/artifacts/rgc_compounding_red_team}"
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
if [[ -n "${CRT_CONFIG:-}" ]]; then
  CONFIG_ARGS=(--config "${CRT_CONFIG}")
fi

cd "${REPO_ROOT}"

# 1. Build frankenctl.
run_lane "build_frankenctl" "${LOG_DIR}/build.log" \
  "${CARGO_BIN}" build -p "${PKG}" --bin frankenctl

FRANKENCTL="${CARGO_TARGET_DIR}/debug/frankenctl"

# 2. Run the campaign gate twice into separate directories.
if [[ "${LANE_STATUS[0]}" == "pass" && -x "${FRANKENCTL}" ]]; then
  run_lane "campaign_run_a" "${LOG_DIR}/campaign_a.log" \
    "${FRANKENCTL}" gates compounding-red-team --out-dir "${BUNDLE_DIR}/campaign_a" "${CONFIG_ARGS[@]}"
  run_lane "campaign_run_b" "${LOG_DIR}/campaign_b.log" \
    "${FRANKENCTL}" gates compounding-red-team --out-dir "${BUNDLE_DIR}/campaign_b" "${CONFIG_ARGS[@]}"

  # 3. Deterministic replay: the two bundles must be byte-identical.
  record_cmd "cmp campaign_a/compounding_red_team_bundle.json campaign_b/compounding_red_team_bundle.json"
  if cmp -s "${BUNDLE_DIR}/campaign_a/compounding_red_team_bundle.json" \
    "${BUNDLE_DIR}/campaign_b/compounding_red_team_bundle.json"; then
    record_lane "deterministic_replay" "pass"
  else
    record_lane "deterministic_replay" "fail"
  fi

  # 4. Required artifacts present and campaign outcome is pass.
  ok=1
  for art in compounding_red_team_bundle.json run_manifest.json summary.md; do
    if [[ ! -f "${BUNDLE_DIR}/campaign_a/${art}" ]]; then
      echo "   missing artifact: ${art}"
      ok=0
    fi
  done
  if ! grep -q '"outcome": "pass"' "${BUNDLE_DIR}/campaign_a/run_manifest.json" 2>/dev/null; then
    ok=0
  fi
  if [[ "${ok}" == "1" ]]; then
    record_lane "bundle_valid" "pass"
  else
    record_lane "bundle_valid" "fail"
  fi
else
  record_lane "campaign_run_a" "fail"
fi

# 5. Rust test lane.
run_lane "campaign_tests" "${LOG_DIR}/tests.log" \
  "${CARGO_BIN}" test -p "${PKG}" --test compounding_red_team_campaign_integration

# 6. Gate manifest + summary.
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
  "schema_version": "franken-engine.compounding-red-team-gate.v1",
  "bead": "bd-cixqu.21.4",
  "run_id": "${RUN_ID}",
  "mode": "${MODE}",
  "outcome": "${OUTCOME}",
  "lanes": [${LANES_JSON}]
}
JSON

{
  echo "# Compounding red-team gate — ${RUN_ID}"
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
