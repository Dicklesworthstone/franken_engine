#!/usr/bin/env bash
# audit_repro_lock_coverage.sh (bd-cixqu.4.5)
#
# Operator query script. Lists every OBSERVED claim in
# docs/claim_to_proof_matrix_v1.json and reports the status of its
# reproducibility-lock partner (present / missing / stale).
#
# Modes:
#   audit          (default) emit plain-English summary on stdout + JSON
#                  to artifacts/repro_lock_coverage_audit/<ts>/.
#   json           emit ONLY the JSON report on stdout (no banner /
#                  artifacts) — pipe-friendly for tooling.
#   selftest       run with the in-tree fixture matrix from bd-cixqu.4.3
#                  (scripts/testdata/claim_to_proof_matrix_repro_lock/
#                  claim_to_proof_matrix_fixture.json) and assert the
#                  expected with_lock=present / without_lock=missing
#                  outcomes.
#
# Output schema:
#   { schema_version: franken-engine.repro-lock-coverage-audit.v1,
#     generated_utc, matrix_path, total_observed, present, missing,
#     stale, claims: [{claim_id, artifact_path, lock_status, lock_path,
#     lock_age_days, severity}], summary: <markdown> }
#
# Background: bd-cixqu.4.3 made the claim-to-proof matrix gate
# fail-closed when an OBSERVED claim has no `repro.lock` sibling. Before
# that gate trips in production, operators want a query view that
# reports every OBSERVED claim's lock status without running the full
# gate. This is that view.

set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_DIR}"

readonly DEFAULT_MATRIX="docs/claim_to_proof_matrix_v1.json"
readonly STALE_THRESHOLD_DAYS="${REPRO_LOCK_STALE_THRESHOLD_DAYS:-30}"
readonly TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

mode="${1:-audit}"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# detect_repro_lock <artifact_path> -> echoes the lock path (or empty)
detect_repro_lock() {
  local artifact_path="$1"
  local found=""

  if [[ -z "${artifact_path}" || "${artifact_path}" == "null" ]]; then
    return 1
  fi

  if [[ -f "${artifact_path}" ]]; then
    local parent
    parent="$(dirname "${artifact_path}")"
    if [[ -f "${parent}/repro.lock" ]]; then
      printf '%s\n' "${parent}/repro.lock"
      return 0
    fi
    return 1
  fi

  if [[ -d "${artifact_path}" ]]; then
    if found="$(find "${artifact_path}" -maxdepth 4 -name "repro.lock" -type f -print -quit 2>/dev/null)" \
        && [[ -n "${found}" ]]; then
      printf '%s\n' "${found}"
      return 0
    fi
    return 1
  fi

  return 1
}

lock_age_days() {
  local lock_path="$1"
  local mtime
  if ! mtime="$(stat -c %Y "${lock_path}" 2>/dev/null)"; then
    printf -- '-1\n'
    return
  fi
  local now
  now="$(date -u +%s)"
  printf '%d\n' $(((now - mtime) / 86400))
}

# build_claim_record <matrix_json_line> -> emits one JSON object
build_claim_record() {
  local claim_json="$1"
  local claim_id artifact_path
  claim_id="$(jq -r '.claim_id' <<<"${claim_json}")"
  artifact_path="$(jq -r '.artifact_path // ""' <<<"${claim_json}")"

  local lock_status="missing"
  local lock_path=""
  local age_days=-1
  local severity="error"

  if lock_path="$(detect_repro_lock "${artifact_path}" 2>/dev/null)" \
      && [[ -n "${lock_path}" ]]; then
    age_days="$(lock_age_days "${lock_path}")"
    if [[ "${age_days}" -lt 0 ]]; then
      lock_status="present"
      severity="info"
    elif [[ "${age_days}" -gt "${STALE_THRESHOLD_DAYS}" ]]; then
      lock_status="stale"
      severity="warning"
    else
      lock_status="present"
      severity="info"
    fi
  fi

  jq -nc \
    --arg claim_id "${claim_id}" \
    --arg artifact_path "${artifact_path}" \
    --arg lock_status "${lock_status}" \
    --arg lock_path "${lock_path}" \
    --argjson lock_age_days "${age_days}" \
    --arg severity "${severity}" \
    '{
      claim_id: $claim_id,
      artifact_path: $artifact_path,
      lock_status: $lock_status,
      lock_path: $lock_path,
      lock_age_days: $lock_age_days,
      severity: $severity
    }'
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

matrix_path="${REPRO_LOCK_AUDIT_MATRIX_PATH:-${DEFAULT_MATRIX}}"
if [[ "${mode}" == "selftest" ]]; then
  matrix_path="scripts/testdata/claim_to_proof_matrix_repro_lock/claim_to_proof_matrix_fixture.json"
fi

if [[ ! -f "${matrix_path}" ]]; then
  echo "ERROR: matrix not found: ${matrix_path}" >&2
  exit 2
fi

# Stream every OBSERVED claim through build_claim_record.
records=()
while IFS= read -r line; do
  records+=("$(build_claim_record "${line}")")
done < <(jq -c '.claims[] | select(.allowed_state == "observed")' "${matrix_path}")

total=${#records[@]}
present=0
missing=0
stale=0

records_json="[]"
for r in "${records[@]}"; do
  case "$(jq -r '.lock_status' <<<"${r}")" in
    present) present=$((present + 1)) ;;
    missing) missing=$((missing + 1)) ;;
    stale)   stale=$((stale + 1)) ;;
  esac
  records_json="$(jq --argjson r "${r}" '. += [$r]' <<<"${records_json}")"
done

summary="$(printf 'Total OBSERVED claims: %d\n- present: %d\n- missing: %d\n- stale (>%d days): %d\n' \
  "${total}" "${present}" "${missing}" "${STALE_THRESHOLD_DAYS}" "${stale}")"

report_json="$(jq -n \
  --arg schema "franken-engine.repro-lock-coverage-audit.v1" \
  --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg matrix_path "${matrix_path}" \
  --arg summary "${summary}" \
  --argjson stale_threshold_days "${STALE_THRESHOLD_DAYS}" \
  --argjson total "${total}" \
  --argjson present "${present}" \
  --argjson missing "${missing}" \
  --argjson stale "${stale}" \
  --argjson claims "${records_json}" \
  '{
    schema_version: $schema,
    generated_utc: $generated,
    matrix_path: $matrix_path,
    stale_threshold_days: $stale_threshold_days,
    total_observed: $total,
    present: $present,
    missing: $missing,
    stale: $stale,
    claims: $claims,
    summary: $summary
  }')"

case "${mode}" in
  json)
    printf '%s\n' "${report_json}"
    ;;
  selftest)
    # Assert known fixture outcomes.
    with_status="$(jq -r '.claims[] | select(.claim_id == "REPRO-LOCK-WITH") | .lock_status' <<<"${report_json}")"
    without_status="$(jq -r '.claims[] | select(.claim_id == "REPRO-LOCK-WITHOUT") | .lock_status' <<<"${report_json}")"
    failures=0
    if [[ "${with_status}" != "present" ]]; then
      echo "FAIL: REPRO-LOCK-WITH lock_status=${with_status} (expected present)" >&2
      failures=$((failures + 1))
    else
      printf 'PASS audit-repro-lock REPRO-LOCK-WITH=present\n'
    fi
    if [[ "${without_status}" != "missing" ]]; then
      echo "FAIL: REPRO-LOCK-WITHOUT lock_status=${without_status} (expected missing)" >&2
      failures=$((failures + 1))
    else
      printf 'PASS audit-repro-lock REPRO-LOCK-WITHOUT=missing\n'
    fi
    if ! jq -e '.schema_version == "franken-engine.repro-lock-coverage-audit.v1"' \
        <<<"${report_json}" >/dev/null; then
      echo "FAIL: schema_version mismatch" >&2
      failures=$((failures + 1))
    else
      printf 'PASS audit-repro-lock schema_version pinned\n'
    fi
    if ! jq -e '.total_observed == 2' <<<"${report_json}" >/dev/null; then
      echo "FAIL: expected total_observed=2 in fixture matrix" >&2
      failures=$((failures + 1))
    else
      printf 'PASS audit-repro-lock total_observed=2\n'
    fi
    if [[ "${failures}" -ne 0 ]]; then
      exit 1
    fi
    ;;
  audit|*)
    artifact_root="${REPRO_LOCK_AUDIT_ARTIFACT_ROOT:-artifacts/repro_lock_coverage_audit}"
    run_dir="${artifact_root}/${TIMESTAMP}"
    mkdir -p "${run_dir}"
    report_path="${run_dir}/repro_lock_coverage_report.json"
    printf '%s\n' "${report_json}" >"${report_path}"
    {
      printf -- '# repro.lock coverage audit — %s\n\n' "${TIMESTAMP}"
      printf -- '- Matrix: `%s`\n' "${matrix_path}"
      printf -- '- Stale threshold: %d days\n' "${STALE_THRESHOLD_DAYS}"
      printf -- '- Total OBSERVED claims: %d\n' "${total}"
      printf -- '- Present: %d\n' "${present}"
      printf -- '- Missing: %d\n' "${missing}"
      printf -- '- Stale (>%d days): %d\n\n' "${STALE_THRESHOLD_DAYS}" "${stale}"
      printf '## Per-claim status\n\n'
      printf '| claim_id | lock_status | severity | artifact_path |\n'
      printf '|---|---|---|---|\n'
      jq -r '.claims[] | "| `\(.claim_id)` | \(.lock_status) | \(.severity) | `\(.artifact_path)` |"' \
        <<<"${report_json}"
    } >"${run_dir}/repro_lock_coverage_summary.md"

    printf -- '- Matrix audited: %s\n' "${matrix_path}"
    printf -- '- Total OBSERVED claims: %d (present=%d missing=%d stale=%d)\n' \
      "${total}" "${present}" "${missing}" "${stale}"
    printf -- '- JSON report: %s\n' "${report_path}"
    printf -- '- Summary: %s\n' "${run_dir}/repro_lock_coverage_summary.md"

    if [[ "${missing}" -ne 0 ]]; then
      printf -- '\nACTION: %d claim(s) have no repro.lock — run runbooks/scripts/backfill_repro_lock.sh\n' "${missing}" >&2
      exit 1
    fi
    if [[ "${stale}" -ne 0 ]]; then
      printf -- '\nWARNING: %d lock(s) older than %d days — consider regeneration\n' "${stale}" "${STALE_THRESHOLD_DAYS}" >&2
    fi
    ;;
esac
