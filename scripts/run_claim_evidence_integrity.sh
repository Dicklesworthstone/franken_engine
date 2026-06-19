#!/usr/bin/env bash
# CEI A.3 (bd-sde5e.1.3): claim-evidence integrity gate.
#
# Scores the live claim-to-proof matrix against the *committed* evidence
# (docs/evidence/<CLAIM>/) using the bidirectional soundness lattice
# (crates/franken-engine/src/claim_evidence_lattice.rs, CEI A.1): for every row it
# checks that the asserted state does not exceed ceiling(evidence_tier), where the
# tier is derived only from machine-checkable facts -- artifact git-tracked,
# manifest verification_result == passed AND not backfill, a committed repro.lock,
# a zero-exit receipt, and freshness within the matrix window.
#
# This is the enforcement half the historical claim-to-proof gate lacked (which
# only checked README-wording <= matrix.allowed_state, never matrix <= evidence).
#
# Modes:
#   ci          advisory (default): reports over-promoted rows, exits 0.
#   blocking    fail-closed: exits 1 if any row asserts more than its evidence
#               licenses. The G.1 meta-gate composes this once Track B has
#               re-emitted real receipts for every OBSERVED row.
#
# Honors FRANKEN_EVIDENCE_MANIFEST_BIN to skip the build (a prebuilt binary).
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
blocking_flag=""
if [[ "$mode" == "blocking" || "${CLAIM_EVIDENCE_INTEGRITY_BLOCKING:-0}" == "1" ]]; then
  blocking_flag="--blocking"
fi

artifact_root="${CLAIM_EVIDENCE_INTEGRITY_ARTIFACT_ROOT:-artifacts/claim_evidence_integrity}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
report_path="${run_dir}/audit_report.txt"
manifest_path="${run_dir}/run_manifest.json"
commands_path="${run_dir}/commands.txt"
mkdir -p "$run_dir"

# Locate or build the audit binary.
bin="${FRANKEN_EVIDENCE_MANIFEST_BIN:-}"
if [[ -z "$bin" ]]; then
  for cand in \
    "target_icydeer/debug/franken_evidence_manifest" \
    "target/debug/franken_evidence_manifest" \
    "target/release/franken_evidence_manifest"; do
    if [[ -x "$cand" ]]; then bin="$cand"; break; fi
  done
fi
if [[ -z "$bin" ]]; then
  echo "building franken_evidence_manifest ..." >&2
  cargo build -p frankenengine-engine --bin franken_evidence_manifest >&2
  bin="target/debug/franken_evidence_manifest"
fi

printf '%s audit %s\n' "$bin" "$blocking_flag" >"$commands_path"

set +e
"$bin" audit $blocking_flag | tee "$report_path"
audit_exit="${PIPESTATUS[0]}"
set -e

# Structured run manifest (content-addressed report hash for replay / drift).
report_sha="$(sha256sum "$report_path" | cut -d' ' -f1)"
coverage_line="$(grep -m1 'claim-integrity-coverage' "$report_path" || true)"
verdict="advisory_pass"
if [[ -n "$blocking_flag" ]]; then
  verdict=$([[ "$audit_exit" -eq 0 ]] && echo "pass" || echo "fail")
fi
cat >"$manifest_path" <<JSON
{
  "schema_version": "franken-engine.claim-evidence-integrity-gate.v1",
  "mode": "${mode}",
  "blocking": $([[ -n "$blocking_flag" ]] && echo true || echo false),
  "audit_exit_code": ${audit_exit},
  "verdict": "${verdict}",
  "coverage": "$(printf '%s' "$coverage_line" | sed 's/"/\\"/g')",
  "report_sha256": "${report_sha}",
  "owning_bead": "bd-sde5e.1.3"
}
JSON

echo "claim_evidence_integrity_report=${report_path}"
echo "claim_evidence_integrity_manifest=${manifest_path}"
echo "claim_evidence_integrity_verdict=${verdict}"

# Advisory mode never fails the build; blocking mode propagates the audit exit.
if [[ -n "$blocking_flag" ]]; then
  exit "$audit_exit"
fi
exit 0
