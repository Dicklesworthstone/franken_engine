#!/usr/bin/env bash
# feature_catalog_runbook_smoke.sh (bd-cixqu.6.7)
#
# Smoke test for the bd-cixqu.6.7 operator-runbook scripts:
# `runbooks/scripts/audit_feature_catalog.sh` and
# `runbooks/scripts/refresh_feature_bundle.sh`.
#
# Asserts:
#   1. shell syntax + shellcheck clean.
#   2. audit selftest exits 0 (3 in-script PASS lines).
#   3. audit json mode emits a parseable JSON report with the
#      expected schema_version.
#   4. audit run against the real in-tree catalog produces a
#      structured summary on stdout.
#   5. refresh --list prints the canonical id -> bundle dir mapping
#      for all three features.
#   6. refresh <single-feature> exits 0 and the F.5 gate re-runs to
#      ci=pass.
#   7. refresh ALL exits 0 and re-runs F.5 ci=pass.
#   8. audit picks up the refreshed bundle (per-feature
#      manifest_age_days <= the stale threshold).

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_DIR}"

readonly AUDIT="${PROJECT_DIR}/runbooks/scripts/audit_feature_catalog.sh"
readonly REFRESH="${PROJECT_DIR}/runbooks/scripts/refresh_feature_bundle.sh"

failures=0
pass() { printf 'PASS feature-catalog-runbook %s\n' "$1"; }
fail() { printf 'FAIL feature-catalog-runbook %s\n' "$1" >&2; failures=$((failures + 1)); }

usage() {
  cat >&2 <<'EOF'
Usage: scripts/e2e/feature_catalog_runbook_smoke.sh [check|run]
EOF
}

check_syntax() {
  bash -n "${AUDIT}"
  bash -n "${REFRESH}"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x -e SC2016,SC2155,SC2034 "${AUDIT}" "${REFRESH}" "${BASH_SOURCE[0]}" >/dev/null 2>&1 \
      || fail "shellcheck reported issues"
  fi
  pass "shell syntax + shellcheck clean"
}

assertion_audit_selftest() {
  if "${AUDIT}" selftest >/dev/null 2>&1; then
    pass "audit selftest exits 0"
  else
    fail "audit selftest must exit 0"
  fi
}

assertion_audit_json_mode() {
  local out
  if ! out="$("${AUDIT}" json 2>/dev/null)"; then
    fail "audit json mode must exit 0"
    return
  fi
  if ! jq -e '.schema_version == "franken-engine.feature-catalog-audit.v1" and .total_features == 3' <<<"${out}" >/dev/null; then
    fail "audit json mode must report schema + total_features == 3"
    return
  fi
  pass "audit json mode emits 3-feature schema-valid report"
}

assertion_audit_run_summary() {
  local out
  out="$("${AUDIT}" audit 2>&1 || true)"
  if grep -q "Total features:" <<<"${out}"; then
    pass "audit run produces 'Total features:' summary line"
  else
    fail "audit run must include 'Total features:' on stdout"
  fi
}

assertion_refresh_list() {
  local out
  out="$("${REFRESH}" --list 2>&1 || true)"
  if grep -q "signed_ifc_declassification_receipts" <<<"${out}" \
      && grep -q "deterministic_replay_coverage" <<<"${out}" \
      && grep -q "red_team_compromise_rate_reduction" <<<"${out}"; then
    pass "refresh --list shows all three canonical feature ids"
  else
    fail "refresh --list must list three canonical feature ids"
  fi
}

assertion_refresh_single_feature() {
  if "${REFRESH}" signed_ifc_declassification_receipts >/dev/null 2>&1; then
    pass "refresh signed_ifc_declassification_receipts exits 0 (F.5 ci=pass)"
  else
    fail "refresh signed_ifc_declassification_receipts must exit 0"
  fi
}

assertion_refresh_all() {
  if "${REFRESH}" ALL >/dev/null 2>&1; then
    pass "refresh ALL exits 0 (F.5 ci=pass)"
  else
    fail "refresh ALL must exit 0"
  fi
}

assertion_audit_sees_refreshed_bundles() {
  local out
  out="$("${AUDIT}" json 2>/dev/null)"
  if ! jq -e '
        . as $r
        | ($r.features | length == 3)
        and ([$r.features[].freshness_status] | all(. == "present"))
        and ([$r.features[].manifest_age_days] | all(. <= ($r.stale_threshold_days // 30)))
      ' <<<"${out}" >/dev/null; then
    fail "audit must report all 3 features fresh + present after refresh"
    return
  fi
  pass "audit reports 3 fresh + present features after refresh ALL"
}

case "${1:-check}" in
  check)
    check_syntax
    ;;
  run)
    check_syntax
    assertion_audit_selftest
    assertion_audit_json_mode
    assertion_audit_run_summary
    assertion_refresh_list
    assertion_refresh_single_feature
    assertion_refresh_all
    assertion_audit_sees_refreshed_bundles
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    fail "unknown mode: ${1:-}"
    exit 64
    ;;
esac

if [[ "${failures}" -ne 0 ]]; then
  exit 1
fi
