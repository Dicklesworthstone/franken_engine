#!/usr/bin/env bash
# RGC fleet-counterfactual-replay gate replay wrapper (bd-cixqu.19.3)
#
# Re-runs the Track-S gate at
# scripts/run_rgc_fleet_counterfactual_replay.sh against the pinned-or-latest
# previous bundle and compares verdict + the content-addressed required-surface
# set (sha256 per artifact). This is the deterministic-replay proof that the
# fleet-counterfactual proof surface has not drifted between runs.
#
# Source-bundle selection:
#   - RGC_FLEET_COUNTERFACTUAL_REPLAY_RUN_DIR=<dir>  (pinned), else
#   - the latest complete bundle under the artifact root (auto-detect).
# Fails closed (exit 1) if no complete bundle is available.
#
# Usage:
#   scripts/e2e/rgc_fleet_counterfactual_replay_e2e.sh [ci|selftest]
#   RGC_FLEET_COUNTERFACTUAL_REPLAY_RUN_DIR=path \
#     scripts/e2e/rgc_fleet_counterfactual_replay_e2e.sh
#
# Exit codes:
#   0 — verdict + surface match
#   1 — no complete source bundle
#   2 — source bundle invalid / gate produced no manifest
#   3 — verdict mismatch
#   4 — required-surface (content-address) mismatch

set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_DIR}"

mode="${1:-ci}"

readonly GATE_NAME="rgc_fleet_counterfactual_replay"
readonly GATE_SCRIPT="${PROJECT_DIR}/scripts/run_${GATE_NAME}.sh"
readonly MANIFEST_SCHEMA="franken-engine.rgc-fleet-counterfactual-replay-gate.manifest.v1"
readonly ARTIFACT_ROOT="${RGC_FLEET_COUNTERFACTUAL_REPLAY_ARTIFACT_ROOT:-artifacts/fleet_counterfactual_replay}"
readonly REPLAY_TS="$(date -u +%Y%m%dT%H%M%SZ)"
readonly REPLAY_DIR="${ARTIFACT_ROOT}_replay/${REPLAY_TS}"
mkdir -p "${REPLAY_DIR}"

readonly PIN="${RGC_FLEET_COUNTERFACTUAL_REPLAY_RUN_DIR:-}"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 2
fi
if [[ ! -x "${GATE_SCRIPT}" ]]; then
  echo "ERROR: gate script not executable: ${GATE_SCRIPT}" >&2
  exit 2
fi

# Returns 0 if the directory is a complete gate bundle.
is_complete_bundle() {
  local dir="$1"
  [[ -d "${dir}" ]] || return 1
  [[ -f "${dir}/run_manifest.json" ]] || return 1
  [[ -f "${dir}/trace_ids.json" ]] || return 1
  jq -e --arg s "${MANIFEST_SCHEMA}" '.schema_version == $s' \
    "${dir}/run_manifest.json" >/dev/null 2>&1 || return 1
  return 0
}

if [[ -n "${PIN}" ]]; then
  if ! is_complete_bundle "${PIN}"; then
    echo "ERROR: pinned source bundle is not complete: ${PIN}" >&2
    exit 1
  fi
  source_bundle="${PIN}"
else
  source_bundle=""
  if [[ -d "${ARTIFACT_ROOT}" ]]; then
    # Newest-first; pick the first complete bundle.
    while IFS= read -r candidate; do
      if is_complete_bundle "${candidate}"; then
        source_bundle="${candidate}"
        break
      fi
    done < <(find "${ARTIFACT_ROOT}" -maxdepth 1 -mindepth 1 -type d -name "*T*Z" | sort -r)
  fi
  if [[ -z "${source_bundle}" ]]; then
    echo "ERROR: no complete source bundle under ${ARTIFACT_ROOT} — run the gate first" >&2
    exit 1
  fi
fi

echo "replay source bundle: ${source_bundle}"

source_manifest="${source_bundle}/run_manifest.json"
source_verdict="$(jq -r '.verdict' "${source_manifest}")"
# Content-addressed surface: sorted (path,sha256) pairs.
source_surface="$(jq -cS '[.required_surface[] | {path, sha256}] | sort_by(.path)' "${source_manifest}")"

replay_run_dir="${REPLAY_DIR}/replay_run"
mkdir -p "${replay_run_dir}"
if ! RGC_FLEET_COUNTERFACTUAL_REPLAY_RUN_DIR="${replay_run_dir}" \
     "${GATE_SCRIPT}" "${mode}" "${replay_run_dir}" \
     >"${REPLAY_DIR}/replay_stdout.log" 2>"${REPLAY_DIR}/replay_stderr.log"; then
  echo "NOTE: replay gate exited non-zero — comparison still proceeds" >&2
fi

replay_manifest="${replay_run_dir}/run_manifest.json"
if [[ ! -f "${replay_manifest}" ]]; then
  echo "ERROR: replay gate did not emit a manifest at ${replay_run_dir}" >&2
  exit 2
fi

replay_verdict="$(jq -r '.verdict' "${replay_manifest}")"
replay_surface="$(jq -cS '[.required_surface[] | {path, sha256}] | sort_by(.path)' "${replay_manifest}")"

exit_code=0
if [[ "${source_surface}" != "${replay_surface}" ]]; then
  echo "DIFF: required-surface content-address mismatch" >&2
  exit_code=4
fi
if [[ "${source_verdict}" != "${replay_verdict}" ]]; then
  echo "DIFF: verdict mismatch (source=${source_verdict} replay=${replay_verdict})" >&2
  if [[ "${exit_code}" -eq 0 ]]; then
    exit_code=3
  fi
fi

jq -n \
  --arg schema "franken-engine.rgc-fleet-counterfactual-replay-gate.replay-report.v1" \
  --arg replay_ts "${REPLAY_TS}" \
  --arg mode "${mode}" \
  --arg source_bundle "${source_bundle}" \
  --arg replay_bundle "${replay_run_dir}" \
  --arg source_verdict "${source_verdict}" \
  --arg replay_verdict "${replay_verdict}" \
  --argjson source_surface "${source_surface}" \
  --argjson replay_surface "${replay_surface}" \
  --argjson exit_code "${exit_code}" \
  '{
    schema_version: $schema,
    replay_ts: $replay_ts,
    mode: $mode,
    source_bundle: $source_bundle,
    replay_bundle: $replay_bundle,
    source_verdict: $source_verdict,
    replay_verdict: $replay_verdict,
    verdict_match: ($source_verdict == $replay_verdict),
    surface_match: ($source_surface == $replay_surface),
    source_surface: $source_surface,
    replay_surface: $replay_surface,
    exit_code: $exit_code
  }' >"${REPLAY_DIR}/comparison_report.json"

{
  printf -- '# RGC fleet-counterfactual-replay gate replay — %s\n\n' "${REPLAY_TS}"
  printf -- '- Mode: `%s`\n' "${mode}"
  printf -- '- Source bundle: `%s`\n' "${source_bundle}"
  printf -- '- Replay bundle: `%s`\n' "${replay_run_dir}"
  printf -- '- Source verdict: `%s`\n' "${source_verdict}"
  printf -- '- Replay verdict: `%s`\n' "${replay_verdict}"
  printf -- '- Surface content-address match: %s\n' \
    "$([[ "${source_surface}" == "${replay_surface}" ]] && echo yes || echo no)"
  printf -- '- Exit code: %s\n' "${exit_code}"
} >"${REPLAY_DIR}/replay_summary.md"

echo "rgc_fleet_counterfactual_replay_report=${REPLAY_DIR}/comparison_report.json"
echo "rgc_fleet_counterfactual_replay_summary=${REPLAY_DIR}/replay_summary.md"

exit ${exit_code}
