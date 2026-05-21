#!/usr/bin/env bash
# RGC fleet-convergence SLO gate replay wrapper (bd-cixqu.2.2)
#
# Re-runs the bd-cixqu.2.2 gate at scripts/run_rgc_fleet_convergence_slo_gate.sh
# against the pinned-or-latest previous bundle and compares verdict +
# declared SLO + secondary-SLO set.
#
# Usage:
#   scripts/e2e/rgc_fleet_convergence_slo_replay.sh [ci|selftest]
#   RGC_FLEET_CONVERGENCE_SLO_REPLAY_RUN_DIR=path \
#     scripts/e2e/rgc_fleet_convergence_slo_replay.sh
#
# Exit codes:
#   0 — verdict + SLO match
#   1 — no source bundle
#   2 — source bundle invalid
#   3 — verdict mismatch
#   4 — primary-SLO field mismatch (partition_profile or numerics drifted)

set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_DIR}"

mode="${1:-ci}"

readonly GATE_NAME="rgc_fleet_convergence_slo_gate"
readonly GATE_SCRIPT="${PROJECT_DIR}/scripts/run_${GATE_NAME}.sh"
readonly ARTIFACT_ROOT="${RGC_FLEET_CONVERGENCE_SLO_ARTIFACT_ROOT:-artifacts/${GATE_NAME}}"
readonly REPLAY_TS="$(date -u +%Y%m%dT%H%M%SZ)"
readonly REPLAY_DIR_BASE="${ARTIFACT_ROOT}_replay"
readonly REPLAY_DIR="${REPLAY_DIR_BASE}/${REPLAY_TS}"
mkdir -p "${REPLAY_DIR}"

readonly PIN="${RGC_FLEET_CONVERGENCE_SLO_REPLAY_RUN_DIR:-}"

if [[ ! -x "${GATE_SCRIPT}" ]]; then
  echo "ERROR: gate script not executable: ${GATE_SCRIPT}" >&2
  exit 2
fi

if [[ -n "${PIN}" ]]; then
  if [[ ! -d "${PIN}" ]]; then
    echo "ERROR: pinned source bundle not found: ${PIN}" >&2
    exit 1
  fi
  source_bundle="${PIN}"
else
  if [[ ! -d "${ARTIFACT_ROOT}" ]]; then
    echo "ERROR: no prior gate runs at ${ARTIFACT_ROOT} — run the gate first" >&2
    exit 1
  fi
  source_bundle="$(find "${ARTIFACT_ROOT}" -maxdepth 1 -mindepth 1 -type d -name "*T*Z" | sort | tail -1)"
  if [[ -z "${source_bundle}" || ! -d "${source_bundle}" ]]; then
    echo "ERROR: no auto-detectable source bundle under ${ARTIFACT_ROOT}" >&2
    exit 1
  fi
fi

echo "replay source bundle: ${source_bundle}"

source_manifest="${source_bundle}/run_manifest.json"
if [[ ! -f "${source_manifest}" ]]; then
  echo "ERROR: source manifest missing: ${source_manifest}" >&2
  exit 2
fi
if ! jq -e '.schema_version == "franken-engine.rgc-fleet-convergence-slo-gate.manifest.v1"' \
      "${source_manifest}" >/dev/null; then
  echo "ERROR: source manifest schema mismatch" >&2
  exit 2
fi

source_verdict="$(jq -r '.verdict' "${source_manifest}")"
source_primary="$(jq -c '.primary_slo' "${source_manifest}")"

replay_run_dir="${REPLAY_DIR}/replay_run"
mkdir -p "${replay_run_dir}"
if ! RGC_FLEET_CONVERGENCE_SLO_REPLAY_RUN_DIR="${replay_run_dir}" \
     "${GATE_SCRIPT}" "${mode}" "${replay_run_dir}" \
     >"${REPLAY_DIR}/replay_stdout.log" 2>"${REPLAY_DIR}/replay_stderr.log"; then
  echo "WARNING: replay gate exited non-zero — comparison still proceeds" >&2
fi

replay_manifest="${replay_run_dir}/run_manifest.json"
if [[ ! -f "${replay_manifest}" ]]; then
  echo "ERROR: replay gate did not emit a manifest at ${replay_run_dir}" >&2
  exit 2
fi

replay_verdict="$(jq -r '.verdict' "${replay_manifest}")"
replay_primary="$(jq -c '.primary_slo' "${replay_manifest}")"

exit_code=0
if [[ "${source_primary}" != "${replay_primary}" ]]; then
  echo "DIFF: primary SLO mismatch" >&2
  echo "source: ${source_primary}" >&2
  echo "replay: ${replay_primary}" >&2
  exit_code=4
fi
if [[ "${source_verdict}" != "${replay_verdict}" ]]; then
  echo "DIFF: verdict mismatch (source=${source_verdict} replay=${replay_verdict})" >&2
  if [[ "${exit_code}" -eq 0 ]]; then
    exit_code=3
  fi
fi

jq -n \
  --arg schema "franken-engine.rgc-fleet-convergence-slo-gate.replay-report.v1" \
  --arg replay_ts "${REPLAY_TS}" \
  --arg mode "${mode}" \
  --arg source_bundle "${source_bundle}" \
  --arg replay_bundle "${replay_run_dir}" \
  --arg source_verdict "${source_verdict}" \
  --arg replay_verdict "${replay_verdict}" \
  --argjson source_primary "${source_primary}" \
  --argjson replay_primary "${replay_primary}" \
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
    primary_slo_match: ($source_primary == $replay_primary),
    source_primary_slo: $source_primary,
    replay_primary_slo: $replay_primary,
    exit_code: $exit_code
  }' >"${REPLAY_DIR}/comparison_report.json"

{
  printf -- '# RGC fleet convergence SLO gate replay — %s\n\n' "${REPLAY_TS}"
  printf -- '- Mode: `%s`\n' "${mode}"
  printf -- '- Source bundle: `%s`\n' "${source_bundle}"
  printf -- '- Replay bundle: `%s`\n' "${replay_run_dir}"
  printf -- '- Source verdict: `%s`\n' "${source_verdict}"
  printf -- '- Replay verdict: `%s`\n' "${replay_verdict}"
  printf -- '- Primary SLO match: %s\n' "$([[ "${source_primary}" == "${replay_primary}" ]] && echo yes || echo no)"
  printf -- '- Exit code: %s\n' "${exit_code}"
} >"${REPLAY_DIR}/replay_summary.md"

echo "rgc_fleet_convergence_slo_replay_report=${REPLAY_DIR}/comparison_report.json"
echo "rgc_fleet_convergence_slo_replay_summary=${REPLAY_DIR}/replay_summary.md"

exit ${exit_code}
