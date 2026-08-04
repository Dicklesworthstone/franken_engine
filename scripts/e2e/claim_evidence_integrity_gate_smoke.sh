#!/usr/bin/env bash
# CEI A.6 (bd-sde5e.1.6): end-to-end smoke for the claim-evidence integrity gate.
#
# Exercises the whole Track-A surface as an operator would:
#   1. run the gate (advisory ci mode) and assert it emits a COMPLETE standard
#      bundle (run_manifest.json, audit_report.txt, events.jsonl, trace_ids.json,
#      commands.txt, step_logs/) with a well-formed, schema'd manifest;
#   2. verify the manifest content hashes match the bytes on disk;
#   3. run the replay wrapper and assert it reproduces the verdict + coverage;
#   4. FAIL-CLOSED proof: an incomplete bundle (a missing artifact, i.e. a
#      fixture that pretends to be a real run) must be REJECTED by the replay
#      wrapper (exit 2) — the gate cannot be satisfied by a hollow bundle.
#
# Usage:
#   scripts/e2e/claim_evidence_integrity_gate_smoke.sh [ci|selftest]
#   FRANKEN_EVIDENCE_MANIFEST_BIN=<bin> scripts/e2e/claim_evidence_integrity_gate_smoke.sh
#
# Exit codes:
#   0  — all checks pass
#   1  — one or more checks failed
#   2  — prerequisite missing (jq, gate script)
set -euo pipefail

export TZ=UTC LC_ALL=C LANG=C

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/../.." && pwd)"
cd "${project_dir}"

gate_script="${project_dir}/scripts/run_claim_evidence_integrity.sh"
replay_script="${project_dir}/scripts/e2e/claim_evidence_integrity_replay.sh"

failures=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }
pass() { echo "ok: $*"; }

command -v jq >/dev/null 2>&1 || { echo "jq required" >&2; exit 2; }
[[ -x "${gate_script}" || -f "${gate_script}" ]] || { echo "gate script missing" >&2; exit 2; }

smoke_root="$(mktemp -d)"
export CLAIM_EVIDENCE_INTEGRITY_ARTIFACT_ROOT="${smoke_root}/artifacts/claim_evidence_integrity"

# ---------------------------------------------------------------------------
# 1. Run the gate and assert a complete bundle
# ---------------------------------------------------------------------------
gate_out="$(bash "${gate_script}" ci 2>"${smoke_root}/gate_stderr.log")" || fail "gate exited non-zero in ci mode"
run_dir="$(printf '%s\n' "${gate_out}" | sed -n 's/^claim_evidence_integrity_run_dir=//p')"
[[ -n "${run_dir}" && -d "${run_dir}" ]] || fail "gate did not report a run dir"
echo "bundle: ${run_dir}"

for art in run_manifest.json audit_report.txt events.jsonl trace_ids.json commands.txt step_logs; do
  if [[ -e "${run_dir}/${art}" ]]; then pass "bundle has ${art}"; else fail "bundle missing ${art}"; fi
done

# manifest schema + verdict
if jq -e '.schema_version == "franken-engine.claim-evidence-integrity-gate.run-manifest.v1"' \
     "${run_dir}/run_manifest.json" >/dev/null 2>&1; then
  pass "manifest schema_version"
else
  fail "manifest schema_version wrong"
fi
verdict="$(jq -r '.verdict' "${run_dir}/run_manifest.json" 2>/dev/null || echo '')"
[[ "${verdict}" == "advisory_pass" ]] && pass "advisory verdict" || fail "unexpected verdict: ${verdict}"

# events.jsonl valid JSONL with start + end markers
if jq -e . "${run_dir}/events.jsonl" >/dev/null 2>&1; then pass "events.jsonl valid JSONL"; else fail "events.jsonl invalid"; fi
grep -q '"event":"gate.start"' "${run_dir}/events.jsonl" && pass "events has gate.start" || fail "events missing gate.start"
grep -q '"event":"gate.end"' "${run_dir}/events.jsonl" && pass "events has gate.end" || fail "events missing gate.end"

# ---------------------------------------------------------------------------
# 2. Content hashes match the bytes on disk
# ---------------------------------------------------------------------------
recorded="$(jq -r '.content_hashes."audit_report.txt"' "${run_dir}/run_manifest.json")"
actual="$(sha256sum "${run_dir}/audit_report.txt" | cut -d' ' -f1)"
[[ "${recorded}" == "${actual}" ]] && pass "audit_report content hash matches" || fail "audit_report hash mismatch (manifest=${recorded} actual=${actual})"

# ---------------------------------------------------------------------------
# 3. Replay wrapper reproduces the verdict
# ---------------------------------------------------------------------------
if CLAIM_EVIDENCE_INTEGRITY_REPLAY_RUN_DIR="${run_dir}" \
   bash "${replay_script}" ci >"${smoke_root}/replay.log" 2>&1; then
  pass "replay wrapper reproduced the verdict"
else
  fail "replay wrapper failed (exit $?)"
  cat "${smoke_root}/replay.log" >&2 || true
fi

# ---------------------------------------------------------------------------
# 4. FAIL-CLOSED: an incomplete bundle must be rejected (exit 2)
# ---------------------------------------------------------------------------
hollow="${smoke_root}/hollow_bundle"
cp -r "${run_dir}" "${hollow}"
rm -f "${hollow}/events.jsonl"   # drop a required artifact -> incomplete
set +e
CLAIM_EVIDENCE_INTEGRITY_REPLAY_RUN_DIR="${hollow}" \
  bash "${replay_script}" ci >"${smoke_root}/hollow.log" 2>&1
hollow_exit=$?
set -e
if [[ "${hollow_exit}" -eq 2 ]]; then
  pass "incomplete bundle rejected (fail-closed, exit 2)"
else
  fail "incomplete bundle NOT rejected (exit ${hollow_exit}, expected 2)"
  cat "${smoke_root}/hollow.log" >&2 || true
fi

# ---------------------------------------------------------------------------
echo ""
if [[ "${failures}" -eq 0 ]]; then
  echo "SMOKE PASS: claim-evidence integrity gate e2e (bundle + replay + fail-closed)"
  exit 0
fi
echo "SMOKE FAIL: ${failures} check(s) failed"
exit 1
