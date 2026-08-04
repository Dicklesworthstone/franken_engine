#!/usr/bin/env bash
# bd-cixqu.4.3 — negative test for the claim-to-proof matrix gate's
# fail-closed `repro.lock` check.
#
# Asserts:
#   1. The gate accepts an OBSERVED claim whose artifact directory
#      contains a `repro.lock` alongside its `run_manifest.json`.
#   2. The gate rejects an OBSERVED claim whose artifact directory has
#      NO `repro.lock` — with stable error code
#      `ClaimMatrixError::MissingReproducibilityBundle`.
#   3. Together these prove the gate is genuinely fail-closed on the
#      reproducibility-lock surface and that the rejection emits the
#      stable error code downstream structured-event consumers route
#      on.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

gate_script="${root_dir}/scripts/run_claim_to_proof_matrix_gate.sh"
fixture_root="${root_dir}/scripts/testdata/claim_to_proof_matrix_repro_lock"
matrix_json="${fixture_root}/claim_to_proof_matrix_fixture.json"

failures=0

record_pass() {
  printf 'PASS claim-to-proof-matrix-repro-lock %s\n' "$1"
}

record_failure() {
  printf 'FAIL claim-to-proof-matrix-repro-lock %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/claim_to_proof_matrix_repro_lock_smoke.sh [check|run] [output_dir]
EOF
}

# `check` mode validates fixture shape + script syntax without running cargo.
run_check() {
  bash -n "$gate_script"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$gate_script" "${BASH_SOURCE[0]}" 2>/dev/null || true
  fi

  jq empty "$matrix_json" \
    "${fixture_root}/with_lock/run_manifest.json" \
    "${fixture_root}/without_lock/run_manifest.json" >/dev/null
  jq -e '
    .schema_version == "franken-engine.claim-to-proof-matrix.v1"
    and ([.claims[].claim_id] | index("REPRO-LOCK-WITH") != null)
    and ([.claims[].claim_id] | index("REPRO-LOCK-WITHOUT") != null)
  ' "$matrix_json" >/dev/null || record_failure "fixture matrix shape"

  test -f "${fixture_root}/with_lock/repro.lock" \
    || record_failure "with_lock fixture must include repro.lock"
  test ! -f "${fixture_root}/without_lock/repro.lock" \
    || record_failure "without_lock fixture must NOT include repro.lock"

  grep -Fq 'detect_reproducibility_bundle' "$gate_script" \
    || record_failure "gate script must define detect_reproducibility_bundle"
  grep -Fq 'ClaimMatrixError::MissingReproducibilityBundle' "$gate_script" \
    || record_failure "gate script must emit the stable error code"
  # bd-sde5e.2.3: the committed (git-tracked) requirement must be wired.
  grep -Fq 'repro_lock_committed' "$gate_script" \
    || record_failure "gate script must define repro_lock_committed (bd-sde5e.2.3)"

  record_pass "fixture shape and gate-script wiring"
}

# bd-sde5e.2.3 (CEI-B.3): prove the gate requires a COMMITTED (git-tracked)
# repro.lock, not merely an on-disk one. Copies the with_lock fixture to an
# untracked temp location and asserts the same claim is now rejected, then that
# the explicit override re-accepts it.
run_committed_check() {
  local out="${1:-$(mktemp -d "${TMPDIR:-/tmp}/claim-repro-committed.XXXXXX")}"

  local untracked_root
  untracked_root="$(mktemp -d "${TMPDIR:-/tmp}/claim-repro-untracked.XXXXXX")"
  cp -r "${fixture_root}/with_lock" "${untracked_root}/with_lock"

  # Sanity: the copied lock must genuinely be untracked.
  if git ls-files --error-unmatch -- "${untracked_root}/with_lock/repro.lock" >/dev/null 2>&1; then
    record_failure "temp repro.lock unexpectedly git-tracked; cannot test committed requirement"
    return
  fi

  local variant_matrix="${out}/variant_matrix.json"
  jq --arg ap "${untracked_root}/with_lock" '
    .claims = [ .claims[] | select(.claim_id == "REPRO-LOCK-WITH") | .artifact_path = $ap ]
  ' "$matrix_json" >"$variant_matrix"

  # 1) Default: an on-disk-but-untracked lock must be REJECTED.
  set +e
  CLAIM_TO_PROOF_MATRIX_PATH="$variant_matrix" \
    CLAIM_TO_PROOF_MATRIX_ARTIFACT_ROOT="${out}/reject" \
    "$gate_script" ci >"${out}/reject.log" 2>&1
  set -e
  local report
  report="$(grep -oE 'claim_to_proof_matrix_gate_report=.*' "${out}/reject.log" | tail -1 | cut -d= -f2-)"
  if [[ -n "$report" && -f "$report" ]] && jq -e '
      .events[]
      | select(.claim_id == "REPRO-LOCK-WITH")
      | (.status == "fail")
        and (.reason | contains("ClaimMatrixError::MissingReproducibilityBundle"))
    ' "$report" >/dev/null; then
    record_pass "untracked repro.lock rejected — committed lock required (bd-sde5e.2.3)"
  else
    record_failure "untracked repro.lock was NOT rejected (report=${report:-none})"
  fi

  # 2) Explicit override: the same on-disk lock is accepted.
  set +e
  CLAIM_TO_PROOF_MATRIX_ALLOW_UNTRACKED_REPRO_LOCK=1 \
    CLAIM_TO_PROOF_MATRIX_PATH="$variant_matrix" \
    CLAIM_TO_PROOF_MATRIX_ARTIFACT_ROOT="${out}/allow" \
    "$gate_script" ci >"${out}/allow.log" 2>&1
  set -e
  local report2
  report2="$(grep -oE 'claim_to_proof_matrix_gate_report=.*' "${out}/allow.log" | tail -1 | cut -d= -f2-)"
  if [[ -n "$report2" && -f "$report2" ]] && jq -e '
      .events[] | select(.claim_id == "REPRO-LOCK-WITH") | .status == "pass"
    ' "$report2" >/dev/null; then
    record_pass "override accepts on-disk lock (CLAIM_TO_PROOF_MATRIX_ALLOW_UNTRACKED_REPRO_LOCK=1)"
  else
    record_failure "override did not accept the on-disk lock (report=${report2:-none})"
  fi
}

# `run` mode actually invokes the gate against the fixture matrix and
# asserts both the positive (with_lock) and negative (without_lock)
# outcomes show up in the report.
run_smoke() {
  local output_dir="${1:-$(mktemp -d "${TMPDIR:-/tmp}/claim-repro-lock-smoke.XXXXXX")}"
  local actual_exit

  set +e
  CLAIM_TO_PROOF_MATRIX_PATH="$matrix_json" \
    CLAIM_TO_PROOF_MATRIX_ARTIFACT_ROOT="$output_dir" \
    "$gate_script" ci >"${output_dir}/stdout.log" 2>"${output_dir}/stderr.log"
  actual_exit=$?
  set -e

  # The gate must EXIT 1 because the negative-fixture claim fails.
  if [[ "$actual_exit" -ne 1 ]]; then
    record_failure "gate must exit 1 when a negative fixture is present (got ${actual_exit})"
    return
  fi

  # Locate the most-recent report.
  local report_path
  report_path="$(grep -oE 'claim_to_proof_matrix_gate_report=.*' "${output_dir}/stdout.log" | tail -1 | cut -d= -f2-)"
  if [[ -z "$report_path" || ! -f "$report_path" ]]; then
    record_failure "gate did not emit a usable report path; stdout=${output_dir}/stdout.log"
    return
  fi

  # Positive claim: REPRO-LOCK-WITH must pass.
  if ! jq -e '
    .events[] | select(.claim_id == "REPRO-LOCK-WITH") | .status == "pass"
  ' "$report_path" >/dev/null; then
    record_failure "REPRO-LOCK-WITH must pass (has repro.lock)"
  else
    record_pass "REPRO-LOCK-WITH accepted (repro.lock present)"
  fi

  # Negative claim: REPRO-LOCK-WITHOUT must fail with the stable code.
  if ! jq -e '
    .events[]
    | select(.claim_id == "REPRO-LOCK-WITHOUT")
    | (.status == "fail")
      and (.reason | contains("ClaimMatrixError::MissingReproducibilityBundle"))
  ' "$report_path" >/dev/null; then
    record_failure "REPRO-LOCK-WITHOUT must fail with MissingReproducibilityBundle"
  else
    record_pass "REPRO-LOCK-WITHOUT rejected with MissingReproducibilityBundle"
  fi

  # The stderr log must also surface the rejection for operator triage.
  if ! grep -Fq "ClaimMatrixError::MissingReproducibilityBundle" "${output_dir}/stderr.log"; then
    record_failure "stderr did not surface the stable error code"
  else
    record_pass "stable error code surfaced on stderr"
  fi
}

case "${1:-check}" in
  check)
    run_check
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      output_dir="${2:-$(mktemp -d "${TMPDIR:-/tmp}/claim-repro-lock-smoke.XXXXXX")}"
      run_smoke "$output_dir"
      run_committed_check "$output_dir"
      printf 'claim_to_proof_matrix_repro_lock_smoke_artifacts=%s\n' "$output_dir"
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
