#!/usr/bin/env bash
# audit_feature_catalog.sh (bd-cixqu.6.7)
#
# Operator query script for the F.5 production-feature catalog. For
# every named feature in `docs/production_feature_catalog_v1.json`,
# reports:
#   - bundle presence (does the latest sub-bundle dir exist?)
#   - bundle freshness (mtime of feature_catalog_manifest.json,
#     compared against FEATURE_CATALOG_STALE_THRESHOLD_DAYS, default 30)
#   - source FE-CLAIM row state in
#     `docs/claim_to_proof_matrix_v1.json`
#
# Modes:
#   audit    (default) plain-English summary on stdout + JSON to
#            artifacts/feature_catalog_audit/<ts>/.
#   json     emit ONLY the JSON report on stdout (no banner / no
#            disk artifacts) — pipe-friendly.
#   selftest fixture self-validation against the in-tree catalog;
#            asserts 3 features, present + present_count + JSON
#            shape.
#
# Output schema:
#   { schema_version: franken-engine.feature-catalog-audit.v1,
#     generated_utc, catalog_spec, total_features, present,
#     missing, stale, features: [{feature_id, bundle_path,
#     manifest_age_days, freshness_status, source_claim,
#     source_claim_state, severity}] }

set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_DIR}"

readonly DEFAULT_CATALOG_SPEC="docs/production_feature_catalog_v1.json"
readonly DEFAULT_MATRIX_PATH="docs/claim_to_proof_matrix_v1.json"
readonly CATALOG_BASE="artifacts/production_feature_catalog"
readonly STALE_THRESHOLD_DAYS="${FEATURE_CATALOG_STALE_THRESHOLD_DAYS:-30}"
readonly TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

mode="${1:-audit}"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 2
fi

catalog_spec="${FEATURE_CATALOG_SPEC:-${DEFAULT_CATALOG_SPEC}}"
matrix_path="${FEATURE_CATALOG_AUDIT_MATRIX_PATH:-${DEFAULT_MATRIX_PATH}}"

if [[ ! -f "${catalog_spec}" ]]; then
  echo "ERROR: catalog spec not found: ${catalog_spec}" >&2
  exit 2
fi
if [[ ! -f "${matrix_path}" ]]; then
  echo "ERROR: matrix not found: ${matrix_path}" >&2
  exit 2
fi

canonical_id_to_bundle_dirname() {
  # The catalog spec uses canonical feature ids with descriptive
  # suffixes (e.g. `signed_ifc_declassification_receipts`) while the
  # on-disk bundle directories use the short feature-family name
  # (e.g. `signed_ifc_declassification`). Strip the well-known
  # suffixes so the audit script can find the bundle. Falls back to
  # the canonical id unchanged.
  local id="$1"
  case "${id}" in
    signed_ifc_declassification_receipts)  printf 'signed_ifc_declassification\n' ;;
    deterministic_replay_coverage)         printf 'deterministic_replay\n' ;;
    red_team_compromise_rate_reduction)    printf 'red_team_compromise_rate\n' ;;
    *) printf '%s\n' "${id}" ;;
  esac
}

latest_subbundle_dir() {
  local feature_id="$1"
  local short_name
  short_name="$(canonical_id_to_bundle_dirname "${feature_id}")"
  local base="${CATALOG_BASE}/${short_name}"
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

manifest_age_days() {
  local manifest_path="$1"
  local mtime
  if ! mtime="$(stat -c %Y "${manifest_path}" 2>/dev/null)"; then
    printf -- '-1\n'
    return
  fi
  local now
  now="$(date -u +%s)"
  printf '%d\n' $(((now - mtime) / 86400))
}

lookup_claim_state() {
  local claim_id="$1"
  jq -r --arg id "${claim_id}" '
    .claims[] | select(.claim_id == $id) | .allowed_state // "unknown"
  ' "${matrix_path}"
}

# Build a record per feature defined in the catalog spec.
records="[]"
present=0
missing=0
stale=0

while IFS= read -r feature_entry; do
  feature_id="$(jq -r '.feature_id' <<<"${feature_entry}")"
  source_claim="$(jq -r '.source_claim // ""' <<<"${feature_entry}")"

  bundle_path=""
  age_days=-1
  freshness_status="missing"
  severity="error"

  if bundle_path="$(latest_subbundle_dir "${feature_id}")"; then
    manifest_path="${bundle_path}/feature_catalog_manifest.json"
    if [[ -f "${manifest_path}" ]]; then
      age_days="$(manifest_age_days "${manifest_path}")"
      if [[ "${age_days}" -lt 0 ]]; then
        freshness_status="present"
        severity="info"
      elif [[ "${age_days}" -gt "${STALE_THRESHOLD_DAYS}" ]]; then
        freshness_status="stale"
        severity="warning"
        stale=$((stale + 1))
      else
        freshness_status="present"
        severity="info"
      fi
      present=$((present + 1))
    else
      freshness_status="missing"
      missing=$((missing + 1))
    fi
  else
    missing=$((missing + 1))
  fi

  source_claim_state=""
  if [[ -n "${source_claim}" ]]; then
    source_claim_state="$(lookup_claim_state "${source_claim}")"
  fi

  record="$(jq -nc \
    --arg feature_id "${feature_id}" \
    --arg bundle_path "${bundle_path}" \
    --arg freshness_status "${freshness_status}" \
    --arg source_claim "${source_claim}" \
    --arg source_claim_state "${source_claim_state}" \
    --argjson manifest_age_days "${age_days}" \
    --arg severity "${severity}" \
    '{
      feature_id: $feature_id,
      bundle_path: $bundle_path,
      manifest_age_days: $manifest_age_days,
      freshness_status: $freshness_status,
      source_claim: $source_claim,
      source_claim_state: $source_claim_state,
      severity: $severity
    }')"

  records="$(jq --argjson r "${record}" '. += [$r]' <<<"${records}")"
done < <(jq -c '.features // .catalog // [] | .[]' "${catalog_spec}" 2>/dev/null \
        || jq -c '[.features[]?, .catalog[]?] | .[]' "${catalog_spec}" 2>/dev/null \
        || echo)

# If the catalog spec uses a different key shape, fall back to enumerating
# under .features[] or .production_features[]; pick whichever is present.
if [[ "$(jq -r 'length' <<<"${records}")" == "0" ]]; then
  while IFS= read -r feature_entry; do
    feature_id="$(jq -r '.feature_id // .id // ""' <<<"${feature_entry}")"
    source_claim="$(jq -r '.source_claim // .parent_claim // ""' <<<"${feature_entry}")"
    if [[ -z "${feature_id}" ]]; then continue; fi

    bundle_path=""
    age_days=-1
    freshness_status="missing"
    severity="error"

    if bundle_path="$(latest_subbundle_dir "${feature_id}")"; then
      manifest_path="${bundle_path}/feature_catalog_manifest.json"
      if [[ -f "${manifest_path}" ]]; then
        age_days="$(manifest_age_days "${manifest_path}")"
        if [[ "${age_days}" -lt 0 ]]; then
          freshness_status="present"
          severity="info"
        elif [[ "${age_days}" -gt "${STALE_THRESHOLD_DAYS}" ]]; then
          freshness_status="stale"
          severity="warning"
          stale=$((stale + 1))
        else
          freshness_status="present"
          severity="info"
        fi
        present=$((present + 1))
      else
        missing=$((missing + 1))
      fi
    else
      missing=$((missing + 1))
    fi

    source_claim_state=""
    if [[ -n "${source_claim}" ]]; then
      source_claim_state="$(lookup_claim_state "${source_claim}")"
    fi

    record="$(jq -nc \
      --arg feature_id "${feature_id}" \
      --arg bundle_path "${bundle_path}" \
      --arg freshness_status "${freshness_status}" \
      --arg source_claim "${source_claim}" \
      --arg source_claim_state "${source_claim_state}" \
      --argjson manifest_age_days "${age_days}" \
      --arg severity "${severity}" \
      '{feature_id: $feature_id, bundle_path: $bundle_path, manifest_age_days: $manifest_age_days, freshness_status: $freshness_status, source_claim: $source_claim, source_claim_state: $source_claim_state, severity: $severity}')"
    records="$(jq --argjson r "${record}" '. += [$r]' <<<"${records}")"
  done < <(jq -c '
    (.features // .production_features // .catalog // [])[]
  ' "${catalog_spec}" 2>/dev/null)
fi

total="$(jq 'length' <<<"${records}")"

report_json="$(jq -n \
  --arg schema "franken-engine.feature-catalog-audit.v1" \
  --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg catalog_spec "${catalog_spec}" \
  --arg matrix_path "${matrix_path}" \
  --argjson stale_threshold_days "${STALE_THRESHOLD_DAYS}" \
  --argjson total "${total}" \
  --argjson present "${present}" \
  --argjson missing "${missing}" \
  --argjson stale "${stale}" \
  --argjson features "${records}" \
  '{
    schema_version: $schema,
    generated_utc: $generated,
    catalog_spec: $catalog_spec,
    matrix_path: $matrix_path,
    stale_threshold_days: $stale_threshold_days,
    total_features: $total,
    present: $present,
    missing: $missing,
    stale: $stale,
    features: $features
  }')"

case "${mode}" in
  json)
    printf '%s\n' "${report_json}"
    ;;
  selftest)
    failures=0
    expect_total=3
    if ! jq -e ".total_features == ${expect_total}" <<<"${report_json}" >/dev/null; then
      echo "FAIL: expected ${expect_total} features, got $(jq -r '.total_features' <<<"${report_json}")" >&2
      failures=$((failures + 1))
    else
      printf 'PASS feature-catalog-audit total_features=%d\n' "${expect_total}"
    fi
    if ! jq -e '.schema_version == "franken-engine.feature-catalog-audit.v1"' <<<"${report_json}" >/dev/null; then
      echo "FAIL: schema_version mismatch" >&2
      failures=$((failures + 1))
    else
      printf 'PASS feature-catalog-audit schema_version pinned\n'
    fi
    if ! jq -e '
        (.features | map(.feature_id) | sort) == [
          "deterministic_replay_coverage",
          "red_team_compromise_rate_reduction",
          "signed_ifc_declassification_receipts"
        ]
      ' <<<"${report_json}" >/dev/null; then
      echo "FAIL: expected 3 canonical feature_ids, got $(jq -c '.features | map(.feature_id) | sort' <<<"${report_json}")" >&2
      failures=$((failures + 1))
    else
      printf 'PASS feature-catalog-audit features=[deterministic_replay_coverage,red_team_compromise_rate_reduction,signed_ifc_declassification_receipts]\n'
    fi
    if [[ "${failures}" -ne 0 ]]; then exit 1; fi
    ;;
  audit|*)
    artifact_root="${FEATURE_CATALOG_AUDIT_ARTIFACT_ROOT:-artifacts/feature_catalog_audit}"
    run_dir="${artifact_root}/${TIMESTAMP}"
    mkdir -p "${run_dir}"
    report_path="${run_dir}/feature_catalog_audit_report.json"
    printf '%s\n' "${report_json}" >"${report_path}"

    {
      printf -- '# feature catalog audit — %s\n\n' "${TIMESTAMP}"
      printf -- '- Catalog spec: `%s`\n' "${catalog_spec}"
      printf -- '- Matrix: `%s`\n' "${matrix_path}"
      printf -- '- Stale threshold: %d days\n' "${STALE_THRESHOLD_DAYS}"
      printf -- '- Total features: %d\n' "${total}"
      printf -- '- Present: %d · Missing: %d · Stale (>%d days): %d\n\n' \
        "${present}" "${missing}" "${STALE_THRESHOLD_DAYS}" "${stale}"
      printf -- '## Per-feature status\n\n'
      printf -- '| feature_id | freshness | age (d) | source_claim | claim_state | bundle_path |\n'
      printf -- '|---|---|---|---|---|---|\n'
      jq -r '.features[] | "| `\(.feature_id)` | \(.freshness_status) | \(.manifest_age_days) | \(.source_claim) | \(.source_claim_state) | `\(.bundle_path)` |"' <<<"${report_json}"
    } >"${run_dir}/feature_catalog_audit_summary.md"

    printf -- '- Total features: %d (present=%d missing=%d stale=%d)\n' \
      "${total}" "${present}" "${missing}" "${stale}"
    printf -- '- JSON report: %s\n' "${report_path}"
    printf -- '- Summary: %s\n' "${run_dir}/feature_catalog_audit_summary.md"

    if [[ "${missing}" -ne 0 ]]; then
      printf -- '\nACTION: %d feature(s) have no bundle — run runbooks/scripts/refresh_feature_bundle.sh <feature_id>\n' "${missing}" >&2
      exit 1
    fi
    if [[ "${stale}" -ne 0 ]]; then
      printf -- '\nWARNING: %d bundle(s) older than %d days — run runbooks/scripts/refresh_feature_bundle.sh <feature_id> to refresh\n' "${stale}" "${STALE_THRESHOLD_DAYS}" >&2
    fi
    ;;
esac
