#!/usr/bin/env bash
# RGC production-feature-catalog replay wrapper (bd-cixqu.6.5)
#
# Re-runs the F.5 gate against the pinned-or-latest previous bundle and
# compares verdict + per-feature manifest hashes. Used by Track F's
# downstream matrix promotion (bd-cixqu.6.6) to confirm the catalog
# hasn't drifted under the operator's feet.
#
# Usage:
#   scripts/e2e/rgc_production_feature_catalog_replay.sh [ci|dev|selftest]
#   RGC_PRODUCTION_FEATURE_CATALOG_REPLAY_RUN_DIR=path \
#     scripts/e2e/rgc_production_feature_catalog_replay.sh
#
# Exit codes:
#   0  — verdict + per-feature sha256 manifest hashes match.
#   1  — no source bundle found.
#   2  — source bundle invalid.
#   3  — verdict mismatch.
#   4  — sub-bundle set mismatch (different features detected).
#   5  — manifest-hash mismatch on at least one sub-bundle (a feature
#         bundle drifted between the two runs).

set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_DIR}"

mode="${1:-ci}"

readonly GATE_NAME="rgc_production_feature_catalog"
readonly GATE_SCRIPT="${PROJECT_DIR}/scripts/run_${GATE_NAME}.sh"
readonly ARTIFACT_ROOT="${RGC_PRODUCTION_FEATURE_CATALOG_ARTIFACT_ROOT:-artifacts/${GATE_NAME}}"
readonly REPLAY_TS="$(date -u +%Y%m%dT%H%M%SZ)"
readonly REPLAY_DIR_BASE="${ARTIFACT_ROOT}_replay"
readonly REPLAY_DIR="${REPLAY_DIR_BASE}/${REPLAY_TS}"
mkdir -p "${REPLAY_DIR}"

readonly PIN="${RGC_PRODUCTION_FEATURE_CATALOG_REPLAY_RUN_DIR:-}"

if [[ ! -x "${GATE_SCRIPT}" ]]; then
  echo "ERROR: gate script not executable: ${GATE_SCRIPT}" >&2
  exit 2
fi

# Locate source bundle.
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

# Validate source.
source_manifest="${source_bundle}/run_manifest.json"
source_catalog="${source_bundle}/production_feature_catalog_manifest.json"

for f in "${source_manifest}" "${source_catalog}" \
         "${source_bundle}/events.jsonl" \
         "${source_bundle}/summary.md"; do
  if [[ ! -f "${f}" ]]; then
    echo "ERROR: source bundle missing required artifact: ${f}" >&2
    exit 2
  fi
done

if ! jq -e '.schema_version == "franken-engine.rgc-production-feature-catalog.manifest.v1"' \
      "${source_manifest}" >/dev/null; then
  echo "ERROR: source manifest schema mismatch: ${source_manifest}" >&2
  exit 2
fi

source_verdict="$(jq -r '.verdict' "${source_manifest}")"
source_features="$(jq -c '[.subbundles[].feature_id] | sort' "${source_catalog}")"
source_hashes="$(jq -c '[.subbundles[] | {feature_id, sha: .manifest_sha256}] | sort_by(.feature_id)' "${source_catalog}")"

echo "source verdict=${source_verdict}"
echo "source features=${source_features}"

# Re-run gate.
replay_run_dir="${REPLAY_DIR}/replay_run"
mkdir -p "${replay_run_dir}"
if ! RGC_PRODUCTION_FEATURE_CATALOG_REPLAY_RUN_DIR="${replay_run_dir}" \
     "${GATE_SCRIPT}" "${mode}" "${replay_run_dir}" \
     >"${REPLAY_DIR}/replay_stdout.log" 2>"${REPLAY_DIR}/replay_stderr.log"; then
  echo "WARNING: replay gate exited non-zero — comparison still proceeds" >&2
fi

replay_manifest="${replay_run_dir}/run_manifest.json"
replay_catalog="${replay_run_dir}/production_feature_catalog_manifest.json"
if [[ ! -f "${replay_manifest}" || ! -f "${replay_catalog}" ]]; then
  echo "ERROR: replay gate did not emit manifest + catalog at ${replay_run_dir}" >&2
  exit 2
fi

replay_verdict="$(jq -r '.verdict' "${replay_manifest}")"
replay_features="$(jq -c '[.subbundles[].feature_id] | sort' "${replay_catalog}")"
replay_hashes="$(jq -c '[.subbundles[] | {feature_id, sha: .manifest_sha256}] | sort_by(.feature_id)' "${replay_catalog}")"

echo "replay verdict=${replay_verdict}"
echo "replay features=${replay_features}"

# Compare.
exit_code=0
if [[ "${source_features}" != "${replay_features}" ]]; then
  echo "DIFF: feature set mismatch source=${source_features} replay=${replay_features}" >&2
  exit_code=4
fi
if [[ "${source_verdict}" != "${replay_verdict}" ]]; then
  echo "DIFF: verdict mismatch source=${source_verdict} replay=${replay_verdict}" >&2
  if [[ "${exit_code}" -eq 0 ]]; then
    exit_code=3
  fi
fi
if [[ "${source_hashes}" != "${replay_hashes}" ]]; then
  echo "DIFF: per-feature manifest-hash mismatch" >&2
  echo "source: ${source_hashes}" >&2
  echo "replay: ${replay_hashes}" >&2
  if [[ "${exit_code}" -eq 0 ]]; then
    exit_code=5
  fi
fi

jq -n \
  --arg schema "franken-engine.rgc-production-feature-catalog.replay-report.v1" \
  --arg replay_ts "${REPLAY_TS}" \
  --arg mode "${mode}" \
  --arg source_bundle "${source_bundle}" \
  --arg replay_bundle "${replay_run_dir}" \
  --arg source_verdict "${source_verdict}" \
  --arg replay_verdict "${replay_verdict}" \
  --argjson source_features "${source_features}" \
  --argjson replay_features "${replay_features}" \
  --argjson source_hashes "${source_hashes}" \
  --argjson replay_hashes "${replay_hashes}" \
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
    feature_set_match: ($source_features == $replay_features),
    per_feature_hash_match: ($source_hashes == $replay_hashes),
    source_features: $source_features,
    replay_features: $replay_features,
    source_hashes: $source_hashes,
    replay_hashes: $replay_hashes,
    exit_code: $exit_code
  }' >"${REPLAY_DIR}/comparison_report.json"

{
  printf -- '# RGC production-feature-catalog replay — %s\n\n' "${REPLAY_TS}"
  printf -- '- Mode: `%s`\n' "${mode}"
  printf -- '- Source bundle: `%s`\n' "${source_bundle}"
  printf -- '- Replay bundle: `%s`\n' "${replay_run_dir}"
  printf -- '- Source verdict: `%s`\n' "${source_verdict}"
  printf -- '- Replay verdict: `%s`\n' "${replay_verdict}"
  printf -- '- Feature set match: %s\n' "$([[ "${source_features}" == "${replay_features}" ]] && echo yes || echo no)"
  printf -- '- Per-feature hash match: %s\n' "$([[ "${source_hashes}" == "${replay_hashes}" ]] && echo yes || echo no)"
  printf -- '- Exit code: %s\n' "${exit_code}"
} >"${REPLAY_DIR}/replay_summary.md"

echo "rgc_production_feature_catalog_replay_report=${REPLAY_DIR}/comparison_report.json"
echo "rgc_production_feature_catalog_replay_summary=${REPLAY_DIR}/replay_summary.md"

exit ${exit_code}
