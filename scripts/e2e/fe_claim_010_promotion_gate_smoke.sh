#!/usr/bin/env bash
# bd-cixqu.5.6 — E.6 smoke wrapper for the FE-CLAIM-010 matrix-promotion gate.
#
# Asserts (without needing the Rust crate to link):
#   1. check: the gate + this wrapper parse cleanly and the gate carries the
#      fail-closed over-claim and missing-repro-lock error codes.
#   2. run:   the gate's own `selftest` proves all four decision paths —
#        - clears 3.0 + observed              -> PROMOTE_TO_OBSERVED (exit 0)
#        - parity + target                    -> STAY_TARGET        (exit 0)
#        - parity + observed (fudge)          -> fail closed        (exit 1)
#        - clears 3.0 but no repro.lock        -> fail closed        (exit 1)
#   3. run:   against the LIVE tree the gate emits a coherent decision artifact
#      whose `decision`/`matrix` pair is internally consistent (no over-claim).

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

gate_script="${root_dir}/scripts/run_fe_claim_010_promotion_gate.sh"

failures=0
record_pass() { printf 'PASS fe-claim-010-promotion %s\n' "$1"; }
record_failure() { printf 'FAIL fe-claim-010-promotion %s\n' "$1" >&2; failures=$((failures + 1)); }

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/fe_claim_010_promotion_gate_smoke.sh [check|run] [output_dir]
EOF
}

run_check() {
  bash -n "$gate_script"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$gate_script" "${BASH_SOURCE[0]}" 2>/dev/null || true
  fi

  test -x "$gate_script" || record_failure "gate script must be executable"

  grep -Fq 'FeClaim010PromotionError::ObservedWithoutClearedThreshold' "$gate_script" \
    || record_failure "gate must define the over-claim error code"
  grep -Fq 'FeClaim010PromotionError::ObservedWithoutReproLock' "$gate_script" \
    || record_failure "gate must define the missing-repro-lock error code"
  grep -Fq 'PROMOTE_TO_OBSERVED' "$gate_script" \
    || record_failure "gate must define the PROMOTE_TO_OBSERVED decision"
  grep -Fq 'STAY_TARGET' "$gate_script" \
    || record_failure "gate must define the STAY_TARGET decision"

  [[ "$failures" -eq 0 ]] && record_pass "gate-script wiring + fail-closed error codes"
}

run_smoke() {
  local output_dir="${1:-$(mktemp -d "${TMPDIR:-/tmp}/fe-claim-010-smoke.XXXXXX")}"

  # (1) The gate's own selftest must exercise every decision path and pass.
  local selftest_exit
  set +e
  "$gate_script" selftest >"${output_dir}/selftest.log" 2>&1
  selftest_exit=$?
  set -e
  if [[ "$selftest_exit" -ne 0 ]]; then
    record_failure "gate selftest must pass (exit ${selftest_exit}); see ${output_dir}/selftest.log"
  else
    record_pass "gate selftest exercised clears/parity/fudge/no-reprolock paths"
  fi
  for label in "clears-and-observed" "parity-and-target" "parity-but-observed-fudge" "clears-no-reprolock-observed"; do
    grep -Fq "PASS selftest [$label]" "${output_dir}/selftest.log" \
      || record_failure "selftest path missing or failed: $label"
  done

  # (2) Live-tree run must produce an internally consistent decision artifact.
  local live_exit
  set +e
  CLAIM_TO_PROOF_MATRIX_PATH="${CLAIM_TO_PROOF_MATRIX_PATH:-docs/claim_to_proof_matrix_v1.json}" \
    FE_CLAIM_010_PROMOTION_ARTIFACT_ROOT="${output_dir}/live" \
    "$gate_script" ci >"${output_dir}/live.log" 2>&1
  live_exit=$?
  set -e
  local report
  report="$(grep -oE 'fe_claim_010_promotion_gate_report=.*' "${output_dir}/live.log" | tail -1 | cut -d= -f2-)"
  if [[ -z "$report" || ! -f "$report" ]]; then
    record_failure "live run did not emit a usable decision artifact; see ${output_dir}/live.log"
    return
  fi
  # The live matrix must NOT over-claim: exit must be 0 and decision coherent.
  if [[ "$live_exit" -ne 0 ]]; then
    record_failure "live tree FE-CLAIM-010 matrix over-claims relative to S_B evidence (exit ${live_exit})"
  else
    record_pass "live decision artifact is internally consistent (no over-claim)"
  fi
  if ! jq -e '
    .schema_version == "franken-engine.fe-claim-010-promotion-gate.v1"
    and .claim_id == "FE-CLAIM-010"
    and (.decision == "PROMOTE_TO_OBSERVED" or .decision == "STAY_TARGET")
    and (.consistent == true)
  ' "$report" >/dev/null; then
    record_failure "live decision artifact failed schema/consistency assertion"
  else
    record_pass "live decision artifact carries valid schema + decision"
  fi
  # The gate must agree with the matrix's recorded state.
  local decision matrix_state
  decision="$(jq -r '.decision' "$report")"
  matrix_state="$(jq -r '.matrix.actual_wording_state' "$report")"
  if [[ "$decision" == "STAY_TARGET" && "$matrix_state" == "observed" ]]; then
    record_failure "STAY_TARGET decision but matrix says observed — fudge not caught"
  else
    record_pass "decision/matrix pairing honest: decision=${decision} matrix=${matrix_state}"
  fi

  printf 'fe_claim_010_promotion_gate_smoke_artifacts=%s\n' "$output_dir"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      output_dir="${2:-$(mktemp -d "${TMPDIR:-/tmp}/fe-claim-010-smoke.XXXXXX")}"
      run_smoke "$output_dir"
    fi
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
