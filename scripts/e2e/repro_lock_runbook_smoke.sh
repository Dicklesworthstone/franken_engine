#!/usr/bin/env bash
# repro_lock_runbook_smoke.sh (bd-cixqu.4.5)
#
# Smoke test for the bd-cixqu.4.5 operator-runbook scripts:
# `runbooks/scripts/audit_repro_lock_coverage.sh` and
# `runbooks/scripts/backfill_repro_lock.sh`.
#
# Asserts:
#   1.  audit selftest passes (4 in-script assertions).
#   2.  audit json mode emits a parseable JSON document with the
#       expected schema_version.
#   3.  audit run against the in-tree real matrix completes without
#       panic — outcome is reported, not asserted (the live state may
#       have missing locks; we only require well-formed output).
#   4.  backfill refuses to overwrite an existing repro.lock without
#       BACKFILL_REPRO_LOCK_OVERWRITE=1.
#   5.  backfill writes a syntactically-valid lock to a fresh
#       bundle-dir.
#   6.  backfill-generated lock passes the same schema validation
#       used by the production gate (bd-cixqu.4.3).
#   7.  audit picks up a backfilled lock as `present` on the next run.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_DIR}"

readonly AUDIT="${PROJECT_DIR}/runbooks/scripts/audit_repro_lock_coverage.sh"
readonly BACKFILL="${PROJECT_DIR}/runbooks/scripts/backfill_repro_lock.sh"

failures=0

pass() { printf 'PASS repro-lock-runbook %s\n' "$1"; }
fail() { printf 'FAIL repro-lock-runbook %s\n' "$1" >&2; failures=$((failures + 1)); }

usage() {
  cat >&2 <<'EOF'
Usage: scripts/e2e/repro_lock_runbook_smoke.sh [check|run]
EOF
}

check_syntax() {
  bash -n "${AUDIT}"
  bash -n "${BACKFILL}"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x -e SC2016,SC2155 "${AUDIT}" "${BACKFILL}" "${BASH_SOURCE[0]}" >/dev/null 2>&1 \
      || fail "shellcheck reported issues"
  fi
  pass "shell syntax + shellcheck clean"
}

assertion_1_audit_selftest() {
  if "${AUDIT}" selftest >/dev/null 2>&1; then
    pass "audit selftest exits 0"
  else
    fail "audit selftest must exit 0"
  fi
}

assertion_2_audit_json_mode() {
  local out
  if ! out="$("${AUDIT}" json 2>/dev/null)"; then
    fail "audit json mode must exit 0 on the real matrix"
    return
  fi
  if ! jq -e '.schema_version == "franken-engine.repro-lock-coverage-audit.v1"' <<<"${out}" >/dev/null; then
    fail "audit json mode must emit schema_version franken-engine.repro-lock-coverage-audit.v1"
    return
  fi
  pass "audit json mode emits schema-valid report"
}

assertion_3_audit_run_against_real_matrix() {
  # In `audit` mode, exit code 1 just means missing locks (expected on
  # some matrices). We only require well-formed output.
  local out
  out="$("${AUDIT}" audit 2>&1 || true)"
  if grep -q "Total OBSERVED claims:" <<<"${out}"; then
    pass "audit run produces a structured summary on stdout"
  else
    fail "audit run must include a 'Total OBSERVED claims:' line"
  fi
}

assertion_4_backfill_refuses_to_clobber() {
  local tmp
  tmp="$(mktemp -d)"
  printf '{"x":1}\n' >"${tmp}/run_manifest.json"
  printf 'existing-content\n' >"${tmp}/repro.lock"

  # Without BACKFILL_REPRO_LOCK_OVERWRITE=1, backfill should exit 3.
  set +e
  "${BACKFILL}" test_gate "${tmp}" "./scripts/test_gate.sh ci" >/dev/null 2>&1
  rc=$?
  set -e
  if [[ "${rc}" -eq 3 ]]; then
    pass "backfill refuses to overwrite an existing repro.lock (exit 3)"
  else
    fail "backfill should exit 3 when repro.lock exists, got ${rc}"
  fi
  # Tidy up (no rm -rf; rely on tmp dir cleanup).
  : >"${tmp}/repro.lock" 2>/dev/null || true
}

assertion_5_backfill_writes_fresh_lock() {
  local tmp
  tmp="$(mktemp -d)"
  printf '{"x":1}\n' >"${tmp}/run_manifest.json"
  set +e
  "${BACKFILL}" test_gate "${tmp}" "./scripts/test_gate.sh ci" >/dev/null 2>&1
  rc=$?
  set -e
  if [[ "${rc}" -ne 0 ]]; then
    fail "backfill exit code on fresh bundle should be 0, got ${rc}"
    return
  fi
  if [[ ! -f "${tmp}/repro.lock" ]]; then
    fail "backfill should write a repro.lock"
    return
  fi
  pass "backfill writes a fresh repro.lock to an empty bundle"
}

assertion_6_backfill_lock_schema_valid() {
  local tmp
  tmp="$(mktemp -d)"
  printf '{"x":1}\n' >"${tmp}/run_manifest.json"
  "${BACKFILL}" test_gate "${tmp}" "./scripts/test_gate.sh ci" >/dev/null 2>&1
  if jq -e '
        .schema_version == "frankenengine.reproducibility.lock.v1"
        and ((.replay.command_sequence | length) > 0)
        and ((.source_commit | length) > 0)
        and (.commands.verification == "./scripts/test_gate.sh ci")
      ' "${tmp}/repro.lock" >/dev/null; then
    pass "backfill lock matches frankenengine.reproducibility.lock.v1 schema"
  else
    fail "backfill lock failed schema validation"
  fi
}

assertion_7_audit_picks_up_backfilled_lock() {
  local tmp
  tmp="$(mktemp -d)"
  printf '{"x":1}\n' >"${tmp}/run_manifest.json"
  "${BACKFILL}" test_gate "${tmp}" "./scripts/test_gate.sh ci" >/dev/null 2>&1
  # Build a one-claim fixture matrix pointing at the tmp bundle.
  local fixture
  fixture="$(mktemp)"
  jq -n --arg ap "${tmp}" '{
    schema_version: "franken-engine.claim-to-proof-matrix.v1",
    claims: [{
      claim_id: "SMOKE-BACKFILL-OK",
      claim_scope: "fixture",
      source_path: "README.md",
      source_span: {start_line: 1, end_line: 1, must_contain: "FrankenEngine"},
      allowed_state: "observed",
      actual_wording_state: "observed",
      artifact_path: $ap,
      verification_command: "./scripts/run_claim_to_proof_matrix_gate.sh ci",
      freshness_days: 30,
      decision: "allow_observed",
      owning_bead: "bd-cixqu.4.5"
    }]
  }' >"${fixture}"

  local out
  out="$(REPRO_LOCK_AUDIT_MATRIX_PATH="${fixture}" "${AUDIT}" json 2>/dev/null)"
  if jq -e '.claims[0].lock_status == "present" and .total_observed == 1' <<<"${out}" >/dev/null; then
    pass "audit reports backfilled lock as present"
  else
    fail "audit did not detect backfilled lock as present"
  fi
}

case "${1:-check}" in
  check)
    check_syntax
    ;;
  run)
    check_syntax
    assertion_1_audit_selftest
    assertion_2_audit_json_mode
    assertion_3_audit_run_against_real_matrix
    assertion_4_backfill_refuses_to_clobber
    assertion_5_backfill_writes_fresh_lock
    assertion_6_backfill_lock_schema_valid
    assertion_7_audit_picks_up_backfilled_lock
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
