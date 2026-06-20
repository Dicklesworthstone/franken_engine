#!/usr/bin/env bash
# CEI D.3 (bd-sde5e.4.3): Test262 posture consistency e2e — proves the gate FAILS
# on drift.
#
# Runs scripts/run_test262_posture_consistency.sh in three states:
#   1. clean HEAD                      -> gate must PASS
#   2. posture JSON full-suite flipped -> gate must FAIL (then reverted)
#   3. matrix FE-CLAIM-TEST262 bumped to observed -> gate must FAIL (then reverted)
#
# Each tamper is applied to a backup-and-restore copy so the working tree is left
# exactly as found. A gate that passes clean AND fails on both injected drifts is
# the proof that the honest Test262 posture cannot silently regress.
#
# Exit codes:
#   0 — clean PASS + both drifts FAIL (gate is sound)
#   1 — clean run did not pass
#   2 — a drift was not caught (gate is not drift-sensitive)
#   3 — could not restore a tampered file (working tree dirty; investigate)
set -euo pipefail

export TZ=UTC LC_ALL=C LANG=C

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/../.." && pwd)"
cd "${project_dir}"

gate="${project_dir}/scripts/run_test262_posture_consistency.sh"
posture_json="docs/test262_compatibility_pass_rate_v1.json"
matrix_json="docs/claim_to_proof_matrix_v1.json"

ts="$(date -u +%Y%m%dT%H%M%SZ)"
out_dir="artifacts/test262_posture_consistency_smoke/${ts}"
mkdir -p "${out_dir}"

run_gate() {
  # run_gate <label> -> prints verdict, returns gate exit code
  local label="$1"
  "${gate}" ci "${out_dir}/${label}" >"${out_dir}/${label}.stdout" 2>"${out_dir}/${label}.stderr"
}

restore() {
  # restore <file> <backup>; hard-fail if the file does not match the backup
  local f="$1" b="$2"
  cp "$b" "$f"
  if ! cmp -s "$f" "$b"; then
    echo "ERROR: could not restore ${f}" >&2
    exit 3
  fi
}

# --- 1. clean run must PASS ---
if run_gate "clean"; then
  echo "clean: PASS"
else
  echo "ERROR: gate did not pass on clean HEAD" >&2
  cat "${out_dir}/clean.stdout" >&2 || true
  exit 1
fi

# --- 2. flip posture full_suite_claim_allowed -> true (drift) ---
bak_posture="${out_dir}/posture_backup.json"
cp "${posture_json}" "${bak_posture}"
jq '.full_suite_claim_allowed = true' "${bak_posture}" >"${posture_json}"
if run_gate "drift_full_suite"; then
  echo "ERROR: gate PASSED despite full_suite_claim_allowed=true drift" >&2
  restore "${posture_json}" "${bak_posture}"
  exit 2
else
  echo "drift_full_suite: correctly FAILED"
fi
restore "${posture_json}" "${bak_posture}"

# --- 3. bump matrix FE-CLAIM-TEST262 -> observed (over-promotion drift) ---
bak_matrix="${out_dir}/matrix_backup.json"
cp "${matrix_json}" "${bak_matrix}"
jq '(.claims[] | select(.claim_id=="FE-CLAIM-TEST262") | .allowed_state) = "observed"' \
  "${bak_matrix}" >"${matrix_json}"
if run_gate "drift_matrix_observed"; then
  echo "ERROR: gate PASSED despite FE-CLAIM-TEST262 -> observed drift" >&2
  restore "${matrix_json}" "${bak_matrix}"
  exit 2
else
  echo "drift_matrix_observed: correctly FAILED"
fi
restore "${matrix_json}" "${bak_matrix}"

echo "test262_posture_consistency_smoke=PASS (clean pass + 2 drifts caught)"
echo "smoke_out_dir=${out_dir}"
exit 0
