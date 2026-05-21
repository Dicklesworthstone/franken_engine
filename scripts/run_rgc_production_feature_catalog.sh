#!/usr/bin/env bash
# RGC production-feature-catalog gate (bd-cixqu.6.5)
#
# Track F cap-stone gate. Consumes the three sub-bundles shipped by
# bd-cixqu.6.{2,3,4}:
#   - signed_ifc_declassification          (FE-CLAIM-015, F.2)
#   - deterministic_replay                 (FE-CLAIM-013, F.3)
#   - red_team_compromise_rate             (FE-CLAIM-011, F.4)
# Each lives under
# artifacts/production_feature_catalog/<feature-id>/<timestamp>/ and
# carries a `feature_catalog_manifest.json` conforming to
# `franken-engine.production-feature-catalog-bundle.v1`.
#
# This gate:
# 1. Auto-detects the latest timestamped sub-bundle per feature.
# 2. Validates each sub-bundle's manifest against the F.1 schema
#    declared in `docs/production_feature_catalog_v1.json`.
# 3. Emits a unified `production_feature_catalog_manifest.json` that
#    cross-references all three sub-bundles with sha256 content hashes
#    (so a future fleet-distribution audit can confirm the catalog the
#    fleet actually ran is the catalog the operator believes it ran).
# 4. Standard RGC artifact-bundle shape (events.jsonl, commands.txt,
#    summary.md, manifest).
#
# Usage:
#   scripts/run_rgc_production_feature_catalog.sh ci
#   scripts/run_rgc_production_feature_catalog.sh dev
#   scripts/run_rgc_production_feature_catalog.sh selftest
#
# Modes:
#   ci       — all three sub-bundles must validate; fail closed on any
#              missing / malformed manifest.
#   dev      — same as ci but reports each sub-bundle's status without
#              fail-closing when a manifest is missing (useful while
#              other agents are still producing their bundle).
#   selftest — shape-only validation against the in-tree sub-bundles
#              that exist today; does NOT require all three to be
#              present.
#
# Environment:
#   RGC_PRODUCTION_FEATURE_CATALOG_ARTIFACT_ROOT
#     Override the artifacts directory.
#   RGC_PRODUCTION_FEATURE_CATALOG_REPLAY_RUN_DIR
#     Write outputs directly to this dir (used by the replay wrapper).
#
# Artifacts:
#   artifacts/rgc_production_feature_catalog/<ts>/
#   ├── run_manifest.json
#   ├── production_feature_catalog_manifest.json  (the unified catalog)
#   ├── events.jsonl
#   ├── commands.txt
#   └── summary.md

set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_DIR}"

mode="${1:-ci}"
explicit_output_dir="${2:-}"

readonly GATE_NAME="rgc_production_feature_catalog"
readonly ARTIFACT_ROOT="${RGC_PRODUCTION_FEATURE_CATALOG_ARTIFACT_ROOT:-artifacts/${GATE_NAME}}"
readonly TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly REPLAY_PIN="${RGC_PRODUCTION_FEATURE_CATALOG_REPLAY_RUN_DIR:-}"

if [[ -n "${explicit_output_dir}" ]]; then
  RUN_DIR="${explicit_output_dir}"
elif [[ -n "${REPLAY_PIN}" ]]; then
  RUN_DIR="${REPLAY_PIN}"
else
  RUN_DIR="${ARTIFACT_ROOT}/${TIMESTAMP}"
fi
mkdir -p "${RUN_DIR}"

readonly MANIFEST_PATH="${RUN_DIR}/run_manifest.json"
readonly CATALOG_PATH="${RUN_DIR}/production_feature_catalog_manifest.json"
readonly EVENTS_PATH="${RUN_DIR}/events.jsonl"
readonly COMMANDS_PATH="${RUN_DIR}/commands.txt"
readonly SUMMARY_PATH="${RUN_DIR}/summary.md"

readonly CATALOG_BASE="artifacts/production_feature_catalog"
readonly FEATURE_IDS=(
  "signed_ifc_declassification"
  "deterministic_replay"
  "red_team_compromise_rate"
)

readonly TRACE_ID="trace-${GATE_NAME}-${TIMESTAMP}"
readonly DECISION_ID="decision-${GATE_NAME}-${TIMESTAMP}"
readonly POLICY_ID="policy-fe-claim-014-production-feature-catalog"
readonly COMPONENT="${GATE_NAME}"

printf './scripts/run_rgc_production_feature_catalog.sh %s\n' "${mode}" >"${COMMANDS_PATH}"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 2
fi

emit_event() {
  local layer="$1"
  local feature_id="$2"
  local outcome="$3"
  local detail="$4"
  jq -nc \
    --arg trace_id "${TRACE_ID}" \
    --arg decision_id "${DECISION_ID}" \
    --arg policy_id "${POLICY_ID}" \
    --arg component "${COMPONENT}" \
    --arg event "${layer}" \
    --arg outcome "${outcome}" \
    --arg feature_id "${feature_id}" \
    --arg detail "${detail}" \
    '{
      schema_version: "franken-engine.gate-event.v1",
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: $event,
      outcome: $outcome,
      feature_id: $feature_id,
      detail: $detail
    }' >>"${EVENTS_PATH}"
}

# Locate the latest timestamped sub-bundle directory for a feature.
latest_subbundle() {
  local feature_id="$1"
  local base="${CATALOG_BASE}/${feature_id}"
  if [[ ! -d "${base}" ]]; then
    return 1
  fi
  local latest
  latest="$(find "${base}" -maxdepth 1 -mindepth 1 -type d -name "*T*Z" | sort | tail -1)"
  if [[ -z "${latest}" || ! -d "${latest}" ]]; then
    return 1
  fi
  printf '%s\n' "${latest}"
}

# Validate a sub-bundle's feature_catalog_manifest.json against the F.1
# schema. Echo "ok" or an error string.
validate_subbundle_manifest() {
  local manifest_path="$1"
  if [[ ! -f "${manifest_path}" ]]; then
    echo "missing manifest"
    return 1
  fi
  if ! jq -e '
        .schema_version == "franken-engine.production-feature-catalog-bundle.v1"
        and ((.feature_id // "") | length > 0)
        and ((.source_claim // "") | length > 0)
        and ((.bundle_bead_id // "") | length > 0)
        and (.feature_state == "observed")
        and ((.verification_commands // []) | length > 0)
        and ((.evidence_bundle_references // []) | length > 0)
      ' "${manifest_path}" >/dev/null; then
    echo "manifest fails franken-engine.production-feature-catalog-bundle.v1 contract"
    return 1
  fi
  echo "ok"
}

# Build sub-bundle JSON entry for the unified catalog.
build_subbundle_entry() {
  local feature_id="$1"
  local bundle_dir="$2"
  local manifest_path="${bundle_dir}/feature_catalog_manifest.json"
  local manifest_hash
  manifest_hash="sha256:$(sha256sum "${manifest_path}" | cut -d' ' -f1)"
  jq -nc \
    --arg feature_id "${feature_id}" \
    --arg bundle_dir "${bundle_dir}" \
    --arg manifest_hash "${manifest_hash}" \
    --slurpfile manifest "${manifest_path}" \
    '{
      feature_id: $feature_id,
      bundle_dir: $bundle_dir,
      manifest_relpath: "feature_catalog_manifest.json",
      manifest_sha256: $manifest_hash,
      source_claim: ($manifest[0].source_claim // ""),
      bundle_bead_id: ($manifest[0].bundle_bead_id // ""),
      feature_title: ($manifest[0].feature_title // ""),
      feature_state: ($manifest[0].feature_state // ""),
      verification_commands: ($manifest[0].verification_commands // [])
    }'
}

# ---------------------------------------------------------------------------
# Pass 1 — detect + validate every sub-bundle
# ---------------------------------------------------------------------------

entries="[]"
present=0
missing=0
malformed=0

for feature_id in "${FEATURE_IDS[@]}"; do
  local_bundle_dir=""
  if ! local_bundle_dir="$(latest_subbundle "${feature_id}")"; then
    missing=$((missing + 1))
    emit_event "subbundle_detection" "${feature_id}" "missing" "no timestamped sub-bundle dir under ${CATALOG_BASE}/${feature_id}/"
    continue
  fi

  local_manifest_path="${local_bundle_dir}/feature_catalog_manifest.json"
  local_validation="$(validate_subbundle_manifest "${local_manifest_path}")"
  if [[ "${local_validation}" != "ok" ]]; then
    malformed=$((malformed + 1))
    emit_event "subbundle_validation" "${feature_id}" "fail" "${local_validation} at ${local_manifest_path}"
    continue
  fi
  emit_event "subbundle_validation" "${feature_id}" "pass" "${local_bundle_dir}"
  present=$((present + 1))

  entries="$(jq --argjson e "$(build_subbundle_entry "${feature_id}" "${local_bundle_dir}")" \
    '. += [$e]' <<<"${entries}")"
done

total=${#FEATURE_IDS[@]}

# ---------------------------------------------------------------------------
# Pass 2 — emit the unified catalog manifest
# ---------------------------------------------------------------------------

generated_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
source_commit="$(git rev-parse HEAD 2>/dev/null || printf 'unknown\n')"

jq -n \
  --arg schema "franken-engine.production-feature-catalog-unified-manifest.v1" \
  --arg generated_utc "${generated_utc}" \
  --arg generated_by "MossyLion (bd-cixqu.6.5)" \
  --arg source_commit "${source_commit}" \
  --arg trace_id "${TRACE_ID}" \
  --arg decision_id "${DECISION_ID}" \
  --arg policy_id "${POLICY_ID}" \
  --argjson required_feature_count "${total}" \
  --argjson present "${present}" \
  --argjson missing "${missing}" \
  --argjson malformed "${malformed}" \
  --argjson subbundles "${entries}" \
  '{
    schema_version: $schema,
    generated_utc: $generated_utc,
    freshness: { generated_utc: $generated_utc },
    generated_by: $generated_by,
    source_commit: $source_commit,
    trace_id: $trace_id,
    decision_id: $decision_id,
    policy_id: $policy_id,
    catalog_spec: "docs/production_feature_catalog_v1.json",
    catalog_owning_bead: "bd-cixqu.6.5",
    required_feature_count: $required_feature_count,
    present_count: $present,
    missing_count: $missing,
    malformed_count: $malformed,
    subbundles: $subbundles
  }' >"${CATALOG_PATH}"

# ---------------------------------------------------------------------------
# Verdict + manifest + summary
# ---------------------------------------------------------------------------

verdict="pass"
verdict_reason="all three production-feature sub-bundles present and valid"

if [[ "${missing}" -ne 0 ]] || [[ "${malformed}" -ne 0 ]]; then
  case "${mode}" in
    selftest|dev)
      verdict="degraded"
      verdict_reason="${missing} missing + ${malformed} malformed sub-bundle(s) (mode=${mode}, tolerated)"
      ;;
    *)
      verdict="fail"
      verdict_reason="${missing} missing + ${malformed} malformed sub-bundle(s)"
      ;;
  esac
fi

jq -n \
  --arg schema "franken-engine.rgc-production-feature-catalog.manifest.v1" \
  --arg run_dir "${RUN_DIR}" \
  --arg mode "${mode}" \
  --arg trace_id "${TRACE_ID}" \
  --arg decision_id "${DECISION_ID}" \
  --arg policy_id "${POLICY_ID}" \
  --arg component "${COMPONENT}" \
  --arg generated_utc "${generated_utc}" \
  --arg verdict "${verdict}" \
  --arg verdict_reason "${verdict_reason}" \
  --argjson required_feature_count "${total}" \
  --argjson present "${present}" \
  --argjson missing "${missing}" \
  --argjson malformed "${malformed}" \
  --slurpfile catalog "${CATALOG_PATH}" \
  '{
    schema_version: $schema,
    run_dir: $run_dir,
    mode: $mode,
    trace_id: $trace_id,
    decision_id: $decision_id,
    policy_id: $policy_id,
    component: $component,
    generated_utc: $generated_utc,
    freshness: { generated_utc: $generated_utc },
    verdict: $verdict,
    verdict_reason: $verdict_reason,
    required_feature_count: $required_feature_count,
    present_count: $present,
    missing_count: $missing,
    malformed_count: $malformed,
    catalog: $catalog[0],
    artifacts: {
      events_jsonl: "events.jsonl",
      commands_txt: "commands.txt",
      summary_md: "summary.md",
      catalog_manifest: "production_feature_catalog_manifest.json"
    }
  }' >"${MANIFEST_PATH}"

{
  printf -- '# RGC production-feature-catalog gate — %s\n\n' "${TIMESTAMP}"
  printf -- '- Mode: `%s`\n' "${mode}"
  printf -- '- Verdict: **%s** (%s)\n' "${verdict}" "${verdict_reason}"
  printf -- '- Required features: %d (signed_ifc_declassification, deterministic_replay, red_team_compromise_rate)\n' "${total}"
  printf -- '- Present: %d · Missing: %d · Malformed: %d\n' "${present}" "${missing}" "${malformed}"
  printf -- '\n## Per-feature status\n\n'
  printf -- '| Feature | Source Claim | Bead | Sub-bundle |\n'
  printf -- '|---|---|---|---|\n'
  jq -r '.subbundles[] | "| `\(.feature_id)` | \(.source_claim) | \(.bundle_bead_id) | `\(.bundle_dir)` |"' \
    "${CATALOG_PATH}"
  printf -- '\n## Artifacts\n\n'
  printf -- '- `run_manifest.json` — gate verdict.\n'
  printf -- '- `production_feature_catalog_manifest.json` — unified catalog (schema `franken-engine.production-feature-catalog-unified-manifest.v1`).\n'
  printf -- '- `events.jsonl` — per-feature detection + validation events.\n'
  printf -- '- `commands.txt` — shell command transcript.\n'
} >"${SUMMARY_PATH}"

echo "rgc_production_feature_catalog_manifest=${MANIFEST_PATH}"
echo "rgc_production_feature_catalog_unified=${CATALOG_PATH}"
echo "rgc_production_feature_catalog_events=${EVENTS_PATH}"
echo "rgc_production_feature_catalog_summary=${SUMMARY_PATH}"

if [[ "${verdict}" == "pass" ]] || [[ "${verdict}" == "degraded" ]]; then
  exit 0
fi
exit 1
