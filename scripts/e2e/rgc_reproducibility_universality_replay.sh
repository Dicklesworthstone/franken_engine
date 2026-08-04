#!/usr/bin/env bash
set -euo pipefail

# bd-cixqu.14.3 — replay wrapper for the RGC reproducibility-universality gate.
#
# Re-verifies a preserved gate bundle: for every claim-evidence repro.lock the
# bundle attested to, it re-hashes the current lock and re-derives its plan with
# the third-party verifier (--plan-only), then asserts the lock content hash,
# verdict, and command count reproduce the values recorded in the bundle's
# run_manifest.json byte-for-byte. This proves both that the corpus the bundle
# certified is unchanged and that the verifier's plan derivation is deterministic.
#
# Usage:
#   scripts/e2e/rgc_reproducibility_universality_replay.sh [bundle [<run_dir>]]
#
# Bundle selection (in priority order):
#   1. an explicit <run_dir> argument,
#   2. $RGC_REPRODUCIBILITY_UNIVERSALITY_REPLAY_RUN_DIR,
#   3. the latest COMPLETE bundle under artifacts/reproducibility_universality/.
# Fails closed if no complete bundle exists or any value drifts.

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"
export LC_ALL=C LANG=C

verifier="scripts/third_party_repro_lock_verifier.sh"
artifact_root="${RGC_REPRODUCIBILITY_UNIVERSALITY_ARTIFACT_ROOT:-artifacts/reproducibility_universality}"

# arg parsing: tolerate a leading "bundle" keyword for symmetry with peers.
arg_dir=""
case "${1:-}" in
  bundle) arg_dir="${2:-}" ;;
  "") ;;
  *) arg_dir="${1}" ;;
esac

bundle_complete() {
  local d="$1"
  [[ -f "${d}/run_manifest.json" && -f "${d}/summary.txt" && -f "${d}/events.jsonl" ]] \
    && jq -e '.schema_version=="rgc.reproducibility-universality.gate.run-manifest.v1"' "${d}/run_manifest.json" >/dev/null 2>&1
}

run_dir=""
if [[ -n "$arg_dir" ]]; then
  run_dir="$arg_dir"
elif [[ -n "${RGC_REPRODUCIBILITY_UNIVERSALITY_REPLAY_RUN_DIR:-}" ]]; then
  run_dir="${RGC_REPRODUCIBILITY_UNIVERSALITY_REPLAY_RUN_DIR}"
else
  # newest complete bundle (directory names are sortable UTC timestamps).
  while IFS= read -r d; do
    if bundle_complete "$d"; then run_dir="$d"; break; fi
  done < <(find "$artifact_root" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | LC_ALL=C sort -r)
fi

if [[ -z "$run_dir" ]]; then
  echo "FE-RGC-REPRO-UNIV-REPLAY-0001: no complete reproducibility-universality bundle found under ${artifact_root}" >&2
  exit 1
fi
if ! bundle_complete "$run_dir"; then
  echo "FE-RGC-REPRO-UNIV-REPLAY-0002: bundle is incomplete or wrong schema: ${run_dir}" >&2
  exit 1
fi

manifest="${run_dir}/run_manifest.json"
echo "==> replaying reproducibility-universality bundle: ${run_dir}"

sha256_of() {
  if [[ -f "$1" ]]; then sha256sum "$1" | awk '{print $1}'; else printf '' | sha256sum | awk '{print $1}'; fi
}

result_count="$(jq '.results | length' "$manifest")"
if [[ "$result_count" -lt 1 ]]; then
  echo "FE-RGC-REPRO-UNIV-REPLAY-0003: bundle records no per-lock results: ${run_dir}" >&2
  exit 1
fi

tmp_plan="$(mktemp)"
mismatches=0
checked=0
while IFS=$'\t' read -r claim lock recorded_sha recorded_verdict recorded_cc; do
  checked=$((checked + 1))
  if [[ ! -f "$lock" ]]; then
    echo "  DRIFT ${claim}: recorded lock no longer present: ${lock}" >&2
    mismatches=$((mismatches + 1))
    continue
  fi
  cur_sha="$(sha256_of "$lock")"
  if [[ "$cur_sha" != "$recorded_sha" ]]; then
    echo "  DRIFT ${claim}: repro.lock content hash changed (recorded ${recorded_sha} -> current ${cur_sha})" >&2
    mismatches=$((mismatches + 1))
    continue
  fi
  if bash "$verifier" --lock "$lock" --plan-only --report "$tmp_plan" >/dev/null 2>&1; then
    cur_verdict="$(jq -r '.verdict // "unknown"' "$tmp_plan")"
    cur_cc="$(jq -r '.command_count // 0' "$tmp_plan")"
  else
    cur_verdict="fail"
    cur_cc=0
  fi
  if [[ "$cur_verdict" != "$recorded_verdict" || "$cur_cc" != "$recorded_cc" ]]; then
    echo "  DRIFT ${claim}: verdict/command_count changed (recorded ${recorded_verdict}/${recorded_cc} -> current ${cur_verdict}/${cur_cc})" >&2
    mismatches=$((mismatches + 1))
    continue
  fi
  echo "  OK    ${claim}: ${cur_verdict} (${cur_cc} cmds, lock sha matches)"
done < <(jq -r '.results[] | [.claim, .lock, .lock_sha256, .verdict, (.command_count|tostring)] | @tsv' "$manifest")
rm -f "$tmp_plan"

recorded_outcome="$(jq -r '.outcome' "$manifest")"
echo "==> replay checked ${checked} locks (recorded outcome=${recorded_outcome}); mismatches=${mismatches}"

if [[ "$mismatches" -ne 0 ]]; then
  echo "FE-RGC-REPRO-UNIV-REPLAY-0004: ${mismatches} bundle value(s) failed to reproduce" >&2
  exit 1
fi
echo "reproducibility-universality bundle reproduced byte-identically: ${run_dir}"
