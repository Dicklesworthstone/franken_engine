#!/usr/bin/env bash
# RGC capability-typed compile-time gate replay wrapper (bd-cixqu.3.4)
#
# Re-runs the gate at `scripts/run_rgc_capability_typed_compile_time.sh`
# against a pinned (or auto-detected latest) previous bundle and
# compares verdicts. Used by the matrix-promotion gate to confirm
# bd-cixqu.3.5 prerequisites are still green.
#
# Usage:
#   scripts/e2e/rgc_capability_typed_compile_time_replay.sh [ci|dev|selftest]
#   RGC_CAPABILITY_TYPED_COMPILE_TIME_REPLAY_RUN_DIR=path \
#     scripts/e2e/rgc_capability_typed_compile_time_replay.sh
#
# Environment:
#   RGC_CAPABILITY_TYPED_COMPILE_TIME_REPLAY_RUN_DIR
#     Pin to a specific previous bundle (its scenario_corpus.json +
#     verdict are the baseline). If unset, auto-detects the most-recent
#     bundle under artifacts/rgc_capability_typed_compile_time/.
#   RGC_CAPABILITY_TYPED_COMPILE_TIME_ARTIFACT_ROOT
#     Override base artifacts directory.
#
# Exit codes:
#   0 — replay verdict matches original verdict and scenario set
#   1 — no previous bundle found
#   2 — bundle validation failed
#   3 — verdict mismatch between original and replay
#   4 — scenario-set mismatch between original and replay

set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_DIR}"

mode="${1:-selftest}"

readonly GATE_NAME="rgc_capability_typed_compile_time"
readonly GATE_SCRIPT="${PROJECT_DIR}/scripts/run_${GATE_NAME}.sh"
readonly ARTIFACT_ROOT="${RGC_CAPABILITY_TYPED_COMPILE_TIME_ARTIFACT_ROOT:-artifacts/${GATE_NAME}}"
readonly REPLAY_TS="$(date -u +%Y%m%dT%H%M%SZ)"
readonly REPLAY_DIR_BASE="${ARTIFACT_ROOT}_replay"
readonly REPLAY_DIR="${REPLAY_DIR_BASE}/${REPLAY_TS}"
mkdir -p "${REPLAY_DIR}"

readonly PIN="${RGC_CAPABILITY_TYPED_COMPILE_TIME_REPLAY_RUN_DIR:-}"

if [[ ! -x "${GATE_SCRIPT}" ]]; then
  echo "ERROR: gate script not executable: ${GATE_SCRIPT}" >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Locate the source bundle
# ---------------------------------------------------------------------------

if [[ -n "${PIN}" ]]; then
  if [[ ! -d "${PIN}" ]]; then
    echo "ERROR: pinned replay run dir not found: ${PIN}" >&2
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
    echo "ERROR: could not auto-detect a previous gate bundle under ${ARTIFACT_ROOT}" >&2
    exit 1
  fi
fi

echo "replay source bundle: ${source_bundle}"

# ---------------------------------------------------------------------------
# Validate the source bundle
# ---------------------------------------------------------------------------

source_manifest="${source_bundle}/run_manifest.json"
source_corpus="${source_bundle}/scenario_corpus.json"

for f in "${source_manifest}" "${source_corpus}" \
         "${source_bundle}/events.jsonl" \
         "${source_bundle}/summary.md"; do
  if [[ ! -f "${f}" ]]; then
    echo "ERROR: source bundle missing required artifact: ${f}" >&2
    exit 2
  fi
done

if ! jq -e '.schema_version == "franken-engine.rgc-capability-typed-compile-time.manifest.v1"' \
      "${source_manifest}" >/dev/null; then
  echo "ERROR: source manifest schema mismatch: ${source_manifest}" >&2
  exit 2
fi

source_verdict="$(jq -r '.verdict' "${source_manifest}")"
source_scenario_count="$(jq -r '.scenario_count' "${source_manifest}")"

echo "source verdict=${source_verdict} scenarios=${source_scenario_count}"

# ---------------------------------------------------------------------------
# Re-run the gate to the replay dir
# ---------------------------------------------------------------------------

replay_run_dir="${REPLAY_DIR}/replay_run"
mkdir -p "${replay_run_dir}"

# Tell the gate to write directly into our dir.
if ! RGC_CAPABILITY_TYPED_COMPILE_TIME_REPLAY_RUN_DIR="${replay_run_dir}" \
     "${GATE_SCRIPT}" "${mode}" "${replay_run_dir}" \
     >"${REPLAY_DIR}/replay_stdout.log" 2>"${REPLAY_DIR}/replay_stderr.log"; then
  echo "WARNING: replay gate run exited non-zero — comparison still proceeds" >&2
fi

replay_manifest="${replay_run_dir}/run_manifest.json"
if [[ ! -f "${replay_manifest}" ]]; then
  echo "ERROR: replay gate did not produce a manifest at ${replay_manifest}" >&2
  exit 2
fi

replay_verdict="$(jq -r '.verdict' "${replay_manifest}")"
replay_scenario_count="$(jq -r '.scenario_count' "${replay_manifest}")"

echo "replay verdict=${replay_verdict} scenarios=${replay_scenario_count}"

# ---------------------------------------------------------------------------
# Compare verdicts and scenario sets
# ---------------------------------------------------------------------------

comparison_report="${REPLAY_DIR}/comparison_report.json"
exit_code=0

# Scenario-set diff (semantic, not byte-identical).
if ! diff -q <(jq -S '.expected_scenarios' "${source_corpus}") \
             <(jq -S '.expected_scenarios' "${replay_run_dir}/scenario_corpus.json") >/dev/null; then
  echo "DIFF: scenario corpus mismatch" >&2
  exit_code=4
fi

if [[ "${source_verdict}" != "${replay_verdict}" ]]; then
  echo "DIFF: verdict mismatch (source=${source_verdict} replay=${replay_verdict})" >&2
  if [[ "${exit_code}" -eq 0 ]]; then
    exit_code=3
  fi
fi

jq -n \
  --arg schema_version "franken-engine.rgc-capability-typed-compile-time.replay-report.v1" \
  --arg replay_ts "${REPLAY_TS}" \
  --arg mode "${mode}" \
  --arg source_bundle "${source_bundle}" \
  --arg replay_bundle "${replay_run_dir}" \
  --arg source_verdict "${source_verdict}" \
  --arg replay_verdict "${replay_verdict}" \
  --argjson source_scenario_count "${source_scenario_count}" \
  --argjson replay_scenario_count "${replay_scenario_count}" \
  --argjson exit_code "${exit_code}" \
  '{
    schema_version: $schema_version,
    replay_ts: $replay_ts,
    mode: $mode,
    source_bundle: $source_bundle,
    replay_bundle: $replay_bundle,
    source_verdict: $source_verdict,
    replay_verdict: $replay_verdict,
    source_scenario_count: $source_scenario_count,
    replay_scenario_count: $replay_scenario_count,
    verdict_match: ($source_verdict == $replay_verdict),
    scenario_count_match: ($source_scenario_count == $replay_scenario_count),
    exit_code: $exit_code
  }' >"${comparison_report}"

{
  printf -- '# RGC capability-typed compile-time gate replay — %s\n\n' "${REPLAY_TS}"
  printf -- '- Mode: `%s`\n' "${mode}"
  printf -- '- Source bundle: `%s`\n' "${source_bundle}"
  printf -- '- Replay bundle: `%s`\n' "${replay_run_dir}"
  printf -- '- Source verdict: `%s`\n' "${source_verdict}"
  printf -- '- Replay verdict: `%s`\n' "${replay_verdict}"
  printf -- '- Source scenarios: %s\n' "${source_scenario_count}"
  printf -- '- Replay scenarios: %s\n' "${replay_scenario_count}"
  printf -- '- Exit code: %s\n' "${exit_code}"
} >"${REPLAY_DIR}/replay_summary.md"

echo "rgc_capability_typed_compile_time_replay_report=${comparison_report}"
echo "rgc_capability_typed_compile_time_replay_summary=${REPLAY_DIR}/replay_summary.md"

exit ${exit_code}
