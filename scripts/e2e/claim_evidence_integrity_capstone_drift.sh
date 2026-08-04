#!/usr/bin/env bash
# CEI G.3 (bd-sde5e.7.3): no-mock acceptance drill for the integrity capstone.
#
# Proves the capstone meta-gate (scripts/run_claim_evidence_integrity_capstone.sh)
# CANNOT be satisfied by fixtures: it injects a real over-promotion of each class,
# one at a time, into the *committed* CEI inputs and asserts the capstone goes red
# with the responsible sub-gate failing — then restores every touched file
# byte-for-byte (verified by sha256) and asserts the capstone is green again.
#
# Injection classes (one per sub-gate of the capstone):
#   1. claim_to_proof   matrix: a TARGETED row's actual_wording_state bumped to
#                       'observed' (actual > allowed) -> wording over-promotion.
#   2. bidirectional_lattice + merkle_ledger
#                       a committed OBSERVED receipt flipped to 'pending'
#                       (the row now asserts more than its evidence licenses, and
#                       the moved leaf diverges from the committed ledger root).
#   3. test262_posture  the posture json's full_suite_claim_allowed flipped to true.
#
# A restore trap guarantees the tree is returned to its committed state even if the
# drill aborts mid-run. Uses cp-based snapshot/restore (not `git checkout`, which is
# blocked by the destructive-command guard).
#
# Usage:  scripts/e2e/claim_evidence_integrity_capstone_drift.sh [ci]
# Honors FRANKEN_EVIDENCE_MANIFEST_BIN / FRANKEN_CLAIM_EVIDENCE_LEDGER_BIN to skip
# rebuilds in the composed sub-gates.
set -uo pipefail
export TZ=UTC LC_ALL=C LANG=C

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/../.." && pwd)"
cd "${project_dir}"

command -v jq >/dev/null 2>&1 || { echo "ERROR: jq required" >&2; exit 2; }

capstone="${project_dir}/scripts/run_claim_evidence_integrity_capstone.sh"
matrix="docs/claim_to_proof_matrix_v1.json"
posture="docs/test262_compatibility_pass_rate_v1.json"

# Pick a committed OBSERVED receipt that is currently 'passed' to flip.
receipt_manifest=""
for cand in docs/evidence/FE-CLAIM-009/manifest.json docs/evidence/FE-CLAIM-005/manifest.json; do
  if [[ -f "$cand" ]] && [[ "$(jq -r '.outputs.verification_result // ""' "$cand")" == "passed" ]]; then
    receipt_manifest="$cand"; break
  fi
done

snap_dir="$(mktemp -d)"
touched=("$matrix" "$posture")
[[ -n "$receipt_manifest" ]] && touched+=("$receipt_manifest")

snapshot() { local f; for f in "${touched[@]}"; do mkdir -p "${snap_dir}/$(dirname "$f")"; cp -p "$f" "${snap_dir}/$f"; done; }
restore()  { local f; for f in "${touched[@]}"; do cp -p "${snap_dir}/$f" "$f"; done; }
cleanup()  { restore 2>/dev/null || true; rm -rf "${snap_dir}"; }
trap cleanup EXIT
snapshot

declare -A pre_sha
for f in "${touched[@]}"; do pre_sha["$f"]="$(sha256sum "$f" | cut -d' ' -f1)"; done

drill_run_root="$(mktemp -d)"
fail=0
case_no=0

# run_capstone_into <dir> ; echoes overall verdict; sets CAP_EXIT
run_capstone_into() {
  local d="$1"
  "${capstone}" ci "$d" >"${d}.log" 2>&1
  CAP_EXIT=$?
  jq -r '.verdict' "${d}/run_manifest.json" 2>/dev/null || echo "MISSING_MANIFEST"
}

subgate_verdict() { jq -r --arg l "$2" '.subgates[] | select(.label==$l) | .verdict' "$1/run_manifest.json" 2>/dev/null; }

assert_red() {
  # assert_red <label> <expected_sub_gate>
  local label="$1" sub="$2" d v
  case_no=$((case_no+1))
  d="${drill_run_root}/case_${case_no}"
  v="$(run_capstone_into "$d")"
  if [[ "$v" == "fail" ]] && [[ "$(subgate_verdict "$d" "$sub")" == "fail" ]]; then
    echo "  PASS: injection '${label}' -> capstone RED, sub-gate '${sub}' failed"
  else
    echo "  FAIL: injection '${label}' did NOT redden the capstone as expected (verdict=${v}, ${sub}=$(subgate_verdict "$d" "$sub"))" >&2
    fail=1
  fi
}

echo "== CEI G.3 no-mock acceptance drill =="
echo "snapshot: ${snap_dir}"

# Baseline: clean tree must be GREEN.
echo "[0] baseline clean run (expect GREEN)"
base_dir="${drill_run_root}/baseline"
base_v="$(run_capstone_into "$base_dir")"
if [[ "$base_v" == "pass" ]]; then
  echo "  PASS: baseline capstone is GREEN"
else
  echo "  FAIL: baseline capstone is not green (verdict=${base_v}) — cannot run drill on an already-red tree" >&2
  echo "  (see ${base_dir}.log)"
  exit 1
fi

# Case 1 — matrix wording over-promotion (track A/C: claim_to_proof).
echo "[1] inject: matrix FE-CLAIM-023 actual_wording_state observed > allowed target"
python3 - "$matrix" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p))
for c in d["claims"]:
    if c["claim_id"]=="FE-CLAIM-023":
        c["actual_wording_state"]="observed"   # > allowed_state 'target'
json.dump(d,open(p,"w"),indent=2,ensure_ascii=False,sort_keys=True); open(p,"a").write("\n")
PY
assert_red "matrix wording over-promotion" "claim_to_proof_matrix"
restore

# Case 2 — receipt flipped to pending (track A/B lattice + B ledger).
if [[ -n "$receipt_manifest" ]]; then
  echo "[2] inject: ${receipt_manifest} verification_result passed -> pending"
  python3 - "$receipt_manifest" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p))
d.setdefault("outputs",{})["verification_result"]="pending"
json.dump(d,open(p,"w"),indent=2,sort_keys=True); open(p,"a").write("\n")
PY
  assert_red "OBSERVED receipt -> pending" "bidirectional_lattice"
  restore
else
  echo "[2] SKIP: no committed OBSERVED 'passed' receipt found to flip" >&2
fi

# Case 3 — test262 posture drift (track D).
echo "[3] inject: ${posture} full_suite_claim_allowed false -> true"
python3 - "$posture" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p))
d["full_suite_claim_allowed"]=True
json.dump(d,open(p,"w"),indent=2,sort_keys=True); open(p,"a").write("\n")
PY
assert_red "test262 posture drift" "test262_posture"
restore

# Restore + verify byte-identical.
echo "[4] verifying every touched file restored byte-for-byte"
for f in "${touched[@]}"; do
  now="$(sha256sum "$f" | cut -d' ' -f1)"
  if [[ "$now" == "${pre_sha[$f]}" ]]; then
    echo "  PASS: ${f} restored (sha256 ${now:0:12}...)"
  else
    echo "  FAIL: ${f} NOT restored (pre=${pre_sha[$f]:0:12} now=${now:0:12})" >&2
    fail=1
  fi
done

# Final clean run must be GREEN again.
echo "[5] post-drill clean run (expect GREEN)"
post_dir="${drill_run_root}/post"
post_v="$(run_capstone_into "$post_dir")"
if [[ "$post_v" == "pass" ]]; then
  echo "  PASS: capstone GREEN after restore"
else
  echo "  FAIL: capstone not green after restore (verdict=${post_v})" >&2
  fail=1
fi

rm -rf "${drill_run_root}"
if [[ "$fail" -eq 0 ]]; then
  echo "== DRILL PASSED: the capstone cannot be satisfied by fixtures =="
  exit 0
else
  echo "== DRILL FAILED ==" >&2
  exit 1
fi
