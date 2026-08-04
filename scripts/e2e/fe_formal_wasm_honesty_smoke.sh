#!/usr/bin/env bash
# CEI F.3 (bd-sde5e.6.3): formal+WASM honesty e2e — proves the gate FAILS on drift.
#
# Runs scripts/run_fe_formal_wasm_honesty.sh in three states:
#   1. clean HEAD                              -> gate must PASS
#   2. matrix FE-CLAIM-016 bumped to observed  -> gate must FAIL (then reverted)
#   3. WASM no-execution wording removed from the module doc -> FAIL (then reverted)
#
# Each tamper is applied to a backup-and-restore copy so the working tree is left
# exactly as found.
#
# Exit codes:
#   0 — clean PASS + both drifts FAIL
#   1 — clean run did not pass
#   2 — a drift was not caught
#   3 — could not restore a tampered file
set -euo pipefail
export TZ=UTC LC_ALL=C LANG=C

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/../.." && pwd)"
cd "${project_dir}"

gate="${project_dir}/scripts/run_fe_formal_wasm_honesty.sh"
matrix_json="docs/claim_to_proof_matrix_v1.json"
wasm_src="crates/franken-engine/src/wasm_runtime_lane.rs"

ts="$(date -u +%Y%m%dT%H%M%SZ)"
out_dir="artifacts/fe_formal_wasm_honesty_smoke/${ts}"
mkdir -p "${out_dir}"

run_gate() { "${gate}" ci "${out_dir}/$1" >"${out_dir}/$1.stdout" 2>"${out_dir}/$1.stderr"; }
restore() {
  cp "$2" "$1"
  cmp -s "$1" "$2" || { echo "ERROR: could not restore $1" >&2; exit 3; }
}

# --- 1. clean run must PASS ---
if run_gate "clean"; then
  echo "clean: PASS"
else
  echo "ERROR: gate did not pass on clean HEAD" >&2
  cat "${out_dir}/clean.stdout" >&2 || true
  exit 1
fi

# --- 2. matrix FE-CLAIM-016 -> observed (formal over-promotion) ---
bak_matrix="${out_dir}/matrix_backup.json"
cp "${matrix_json}" "${bak_matrix}"
jq '(.claims[] | select(.claim_id=="FE-CLAIM-016") | .allowed_state) = "observed"' \
  "${bak_matrix}" >"${matrix_json}"
if run_gate "drift_formal"; then
  echo "ERROR: gate PASSED despite FE-CLAIM-016 -> observed" >&2
  restore "${matrix_json}" "${bak_matrix}"; exit 2
else
  echo "drift_formal: correctly FAILED"
fi
restore "${matrix_json}" "${bak_matrix}"

# --- 3. remove the WASM no-execution wording (doc over-claim drift) ---
bak_wasm="${out_dir}/wasm_backup.rs"
cp "${wasm_src}" "${bak_wasm}"
# Strike the load-bearing honesty sentence; simulate a doc that drops the
# "does not execute" guarantee.
sed 's/non-constant WASM function does not execute here/the runtime executes arbitrary WebAssembly/' \
  "${bak_wasm}" >"${wasm_src}"
if run_gate "drift_wasm"; then
  echo "ERROR: gate PASSED despite WASM no-execution wording removed" >&2
  restore "${wasm_src}" "${bak_wasm}"; exit 2
else
  echo "drift_wasm: correctly FAILED"
fi
restore "${wasm_src}" "${bak_wasm}"

echo "fe_formal_wasm_honesty_smoke=PASS (clean pass + 2 drifts caught)"
echo "smoke_out_dir=${out_dir}"
exit 0
