#!/usr/bin/env bash
# bd-cixqu.7.13 — G.10 smoke wrapper for the FE-CLAIM-016..021 matrix-promotion
# umbrella gate.
#
# Asserts (without needing the Rust crate to link):
#   1. check: the gate + this wrapper parse cleanly and the gate carries the
#      fail-closed over-claim / fixture / matrix-shape error codes plus the
#      PROMOTE_ALL_TO_OBSERVED and STAY_HYPOTHESIS decisions.
#   2. run:   the gate's own `selftest` proves every decision path —
#        - six real proven proofs + observed  -> PROMOTE_ALL_TO_OBSERVED (0)
#        - no proofs + hypothesis (honest)     -> STAY_HYPOTHESIS         (0)
#        - no proofs + observed (fudge)        -> fail closed             (1)
#        - fixture proofs + observed           -> fail closed             (1)
#        - tampered proofs + observed          -> fail closed             (1)
#        - not-proven proofs + observed        -> fail closed             (1)
#        - six real proofs + hypothesis        -> advisory under-claim    (0)
#   3. run:   against the LIVE tree the gate emits a coherent decision artifact
#      whose decision/matrix pairing is internally consistent (no over-claim).

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

gate_script="${root_dir}/scripts/run_fe_claim_016_021_promotion_gate.sh"

failures=0
record_pass() { printf 'PASS fe-claim-016-021-promotion %s\n' "$1"; }
record_failure() { printf 'FAIL fe-claim-016-021-promotion %s\n' "$1" >&2; failures=$((failures + 1)); }

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/fe_claim_016_021_promotion_gate_smoke.sh [check|run] [output_dir]
EOF
}

run_check() {
  bash -n "$gate_script"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$gate_script" "${BASH_SOURCE[0]}" 2>/dev/null || true
  fi

  test -x "$gate_script" || record_failure "gate script must be executable"

  grep -Fq 'FeClaim016_021PromotionError::ObservedWithoutProvenTheorem' "$gate_script" \
    || record_failure "gate must define the over-claim error code"
  grep -Fq 'FeClaim016_021PromotionError::ObservedWithFixtureProof' "$gate_script" \
    || record_failure "gate must define the fixture-proof error code"
  grep -Fq 'FeClaim016_021PromotionError::MatrixEntryMissing' "$gate_script" \
    || record_failure "gate must define the matrix-shape error code"
  grep -Fq 'PROMOTE_ALL_TO_OBSERVED' "$gate_script" \
    || record_failure "gate must define the PROMOTE_ALL_TO_OBSERVED decision"
  grep -Fq 'STAY_HYPOTHESIS' "$gate_script" \
    || record_failure "gate must define the STAY_HYPOTHESIS decision"

  [[ "$failures" -eq 0 ]] && record_pass "gate-script wiring + fail-closed error codes"
}

run_smoke() {
  local output_dir="${1:-$(mktemp -d "${TMPDIR:-/tmp}/fe-claim-016-021-smoke.XXXXXX")}"

  # (1) The gate's own selftest must exercise every decision path and pass.
  local selftest_exit
  set +e
  "$gate_script" selftest >"${output_dir}/selftest.log" 2>&1
  selftest_exit=$?
  set -e
  if [[ "$selftest_exit" -ne 0 ]]; then
    record_failure "gate selftest must pass (exit ${selftest_exit}); see ${output_dir}/selftest.log"
  else
    record_pass "gate selftest exercised real/none/fudge/fixture/tamper/notproven/underclaim paths"
  fi
  for label in "real-and-observed" "none-and-hypothesis" "none-but-observed-fudge" \
               "fixture-but-observed" "tampered-but-observed" "notproven-but-observed" \
               "real-but-hypothesis" "fixture-error-code"; do
    grep -Fq "PASS selftest [$label]" "${output_dir}/selftest.log" \
      || record_failure "selftest path missing or failed: $label"
  done

  # (2) Live-tree run must produce an internally consistent decision artifact.
  local live_exit
  set +e
  CLAIM_TO_PROOF_MATRIX_PATH="${CLAIM_TO_PROOF_MATRIX_PATH:-docs/claim_to_proof_matrix_v1.json}" \
    FE_CLAIM_016_021_PROMOTION_ARTIFACT_ROOT="${output_dir}/live" \
    "$gate_script" ci >"${output_dir}/live.log" 2>&1
  live_exit=$?
  set -e
  local report
  report="$(grep -oE 'fe_claim_016_021_promotion_gate_report=.*' "${output_dir}/live.log" | tail -1 | cut -d= -f2-)"
  if [[ -z "$report" || ! -f "$report" ]]; then
    record_failure "live run did not emit a usable decision artifact; see ${output_dir}/live.log"
    return
  fi
  # The live matrix must NOT over-claim: exit must be 0 and decision coherent.
  if [[ "$live_exit" -ne 0 ]]; then
    record_failure "live tree FE-CLAIM-016..021 matrix over-claims relative to proof evidence (exit ${live_exit})"
  else
    record_pass "live decision artifact is internally consistent (no over-claim)"
  fi
  if ! jq -e '
    .schema_version == "franken-engine.fe-claim-016-021-promotion-gate.v1"
    and .bead_id == "bd-cixqu.7.13"
    and (.decision == "PROMOTE_ALL_TO_OBSERVED" or .decision == "STAY_HYPOTHESIS")
    and (.consistent == true)
    and (.claim_count == 6)
  ' "$report" >/dev/null; then
    record_failure "live decision artifact failed schema/consistency assertion"
  else
    record_pass "live decision artifact carries valid schema + decision over six claims"
  fi
  # No claim may over-claim in the live artifact.
  local overclaims
  overclaims="$(jq -r '[.claims[] | select(.consistency == "over_claim")] | length' "$report")"
  if [[ "$overclaims" != "0" ]]; then
    record_failure "live artifact has ${overclaims} over-claiming claim(s) — fudge not caught"
  else
    record_pass "no claim over-claims in the live artifact"
  fi
  # `verify` must accept the freshly emitted artifact.
  set +e
  "$gate_script" verify "$report" >/dev/null 2>&1
  local verify_exit=$?
  set -e
  if [[ "$verify_exit" -ne 0 ]]; then
    record_failure "gate verify rejected its own freshly emitted artifact (exit ${verify_exit})"
  else
    record_pass "gate verify accepts the live decision artifact"
  fi

  printf 'fe_claim_016_021_promotion_gate_smoke_artifacts=%s\n' "$output_dir"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      output_dir="${2:-$(mktemp -d "${TMPDIR:-/tmp}/fe-claim-016-021-smoke.XXXXXX")}"
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
