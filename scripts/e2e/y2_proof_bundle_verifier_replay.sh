#!/usr/bin/env bash
set -euo pipefail

# bd-cixqu.25.2 — replay wrapper for the Y.2 proof-bundle verifier gate.
#
# Re-verifies a preserved gate bundle WITHOUT regenerating it: it re-runs the
# clean-room docker verifier against the bundle's preserved valid and tampered
# proof-bundle tars and asserts the verdicts reproduce — the valid bundle still
# verifies (verdict=pass) with the SAME recheck digest recorded at gate time,
# and the tampered bundle still fails closed (verdict=fail). This proves the
# third-party verification is reproducible from the preserved trust artifacts.
#
# Usage:
#   scripts/e2e/y2_proof_bundle_verifier_replay.sh [bundle [<run_dir>]]
#
# Bundle selection (priority order):
#   1. an explicit <run_dir> argument,
#   2. $Y2_PROOF_BUNDLE_VERIFIER_REPLAY_RUN_DIR,
#   3. the latest COMPLETE bundle under artifacts/y2_proof_bundle_verifier/.
# Fails closed if no complete bundle exists or any verdict drifts.

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"
export LC_ALL=C LANG=C TZ=UTC

readonly IMAGE_TAG="frankenengine/y2-proof-bundle-verifier:bd-cixqu.25.2"
readonly DOCKER_CONTEXT="docker/y2_proof_bundle_verifier"
artifact_root="${Y2_PROOF_BUNDLE_VERIFIER_ARTIFACT_ROOT:-artifacts/y2_proof_bundle_verifier}"

arg_dir=""
case "${1:-}" in
  bundle) arg_dir="${2:-}" ;;
  "") ;;
  *) arg_dir="${1}" ;;
esac

bundle_complete() {
  local d="$1"
  [[ -f "${d}/run_manifest.json" \
     && -f "${d}/proof_bundle_valid.tar.gz" \
     && -f "${d}/verdict_valid.json" \
     && -f "${d}/proof_bundle_tampered.tar.gz" ]] \
    && jq -e '.schema_id=="franken-engine.proof-artifact-manifest.v1"' "${d}/run_manifest.json" >/dev/null 2>&1
}

run_dir=""
if [[ -n "$arg_dir" ]]; then
  run_dir="$arg_dir"
elif [[ -n "${Y2_PROOF_BUNDLE_VERIFIER_REPLAY_RUN_DIR:-}" ]]; then
  run_dir="${Y2_PROOF_BUNDLE_VERIFIER_REPLAY_RUN_DIR}"
else
  while IFS= read -r d; do
    if bundle_complete "$d"; then run_dir="$d"; break; fi
  done < <(find "$artifact_root" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | LC_ALL=C sort -r)
fi

if [[ -z "$run_dir" ]]; then
  echo "FE-Y2-REPLAY-0001: no complete y2_proof_bundle_verifier bundle found under ${artifact_root}" >&2
  exit 1
fi
if ! bundle_complete "$run_dir"; then
  echo "FE-Y2-REPLAY-0002: bundle is incomplete or wrong schema: ${run_dir}" >&2
  exit 1
fi

command -v docker >/dev/null 2>&1 || { echo "FE-Y2-REPLAY-0003: docker not found" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "FE-Y2-REPLAY-0003: docker daemon unreachable" >&2; exit 2; }

# Ensure the clean-room image exists (rebuild from the pinned context if absent).
if ! docker image inspect "${IMAGE_TAG}" >/dev/null 2>&1; then
  echo "==> verifier image absent; rebuilding from ${DOCKER_CONTEXT}"
  docker build --pull=false -t "${IMAGE_TAG}" "${DOCKER_CONTEXT}" >/dev/null
fi

echo "==> replaying Y.2 proof-bundle verifier bundle: ${run_dir}"

recorded_digest="$(jq -r '.recomputed_recheck_digest // empty' "${run_dir}/verdict_valid.json")"
mismatches=0
tmp_valid="$(mktemp)"
tmp_tampered="$(mktemp)"
trap 'rm -f "$tmp_valid" "$tmp_tampered"' EXIT

verify_tar() {
  local tar="$1" out="$2"
  local abs
  abs="$(cd "$(dirname "$tar")" && pwd)/$(basename "$tar")"
  docker run --rm --network=none -v "${abs}:/input/proof_bundle.tar.gz:ro" \
    "${IMAGE_TAG}" verify-proof-bundle /input/proof_bundle.tar.gz >"$out" 2>/dev/null
}

# 1. valid bundle must still verify (exit 0) with the recorded digest.
if verify_tar "${run_dir}/proof_bundle_valid.tar.gz" "$tmp_valid"; then
  cur_verdict="$(jq -r '.verdict' "$tmp_valid")"
  cur_digest="$(jq -r '.recomputed_recheck_digest // empty' "$tmp_valid")"
  if [[ "$cur_verdict" == "pass" ]]; then
    if [[ -n "$recorded_digest" && "$cur_digest" != "$recorded_digest" ]]; then
      echo "  DRIFT valid: recheck digest changed (recorded ${recorded_digest} -> ${cur_digest})" >&2
      mismatches=$((mismatches + 1))
    else
      echo "  OK    valid bundle verifies (verdict=pass, digest sha256:${cur_digest})"
    fi
  else
    echo "  DRIFT valid: expected verdict=pass, got ${cur_verdict}" >&2
    mismatches=$((mismatches + 1))
  fi
else
  echo "  DRIFT valid: bundle no longer verifies (non-zero exit)" >&2
  mismatches=$((mismatches + 1))
fi

# 2. tampered bundle must still fail closed (non-zero exit, verdict=fail).
if verify_tar "${run_dir}/proof_bundle_tampered.tar.gz" "$tmp_tampered"; then
  echo "  DRIFT tampered: tampered bundle verified (NOT fail-closed)" >&2
  mismatches=$((mismatches + 1))
else
  cur_verdict="$(jq -r '.verdict' "$tmp_tampered" 2>/dev/null || echo unknown)"
  if [[ "$cur_verdict" == "fail" ]]; then
    echo "  OK    tampered bundle fails closed (verdict=fail)"
  else
    echo "  DRIFT tampered: non-zero exit but verdict=${cur_verdict}" >&2
    mismatches=$((mismatches + 1))
  fi
fi

echo "==> replay mismatches=${mismatches}"
if [[ "$mismatches" -ne 0 ]]; then
  echo "FE-Y2-REPLAY-0004: ${mismatches} verdict(s) failed to reproduce" >&2
  exit 1
fi
echo "Y.2 proof-bundle verifier bundle reproduced: ${run_dir}"
