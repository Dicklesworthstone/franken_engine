#!/usr/bin/env bash
# check_dw_non_use_certificate_doc_drift.sh — DW.DOCS doc-drift guard for the
# E8 Non-Use / Non-Exfiltration Certificate surface (bd-fqlfw.8.8).
#
# Fails closed if the operator/integrator docs (the runbook, the README E8
# section, the threat-model boundary doc, and the four-act demo) quote a CLI
# surface, schema/refusal code, claim ID, gate/replay script, or explicit-flow
# wording boundary that no longer matches the shipped source of truth, or if
# banned absolute-superiority words slip into the runbook/README E8 section.
#
# Usage: scripts/check_dw_non_use_certificate_doc_drift.sh   (exit 0 = no drift, 1 = drift)
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."

RUNBOOK="runbooks/dw_non_use_certificate.md"
THREAT_DOC="docs/E8_NON_USE_CERTIFICATE_THREAT_MODEL_V1.md"
DEMO="examples/26_non_exfiltration_certificate/demo.sh"
DEMO_README="examples/26_non_exfiltration_certificate/README.md"
README="README.md"
CLI_SRC="crates/franken-engine/src/bin/frankenctl.rs"
CERT_SRC="crates/franken-engine/src/non_use_certificate.rs"
VERIFIER_SRC="crates/franken-engine/src/third_party_verifier.rs"
SUBSET_SRC="crates/franken-engine/src/e8_analyzed_subset.rs"
GATE="scripts/run_dw_non_use_certificate.sh"
REPLAY="scripts/e2e/dw_non_use_certificate_replay.sh"
MATRIX="docs/claim_to_proof_matrix_v1.json"

fail=0
note() { printf '  drift: %s\n' "$1" >&2; fail=1; }
have() { grep -qF -- "$2" "$1" 2>/dev/null; }

echo "[doc-drift] E8 Non-Use Certificate docs vs source of truth"

# 1. Required files exist.
for f in "$RUNBOOK" "$THREAT_DOC" "$DEMO" "$DEMO_README" "$README" "$CLI_SRC" \
         "$CERT_SRC" "$VERIFIER_SRC" "$SUBSET_SRC" "$GATE" "$REPLAY" "$MATRIX"; do
  [ -f "$f" ] || note "missing required file: $f"
done

# 2. Shipped CLI subcommands & flags documented in README + runbook must exist in frankenctl.rs.
for token in "frankenctl agent-sandbox" "--data-contract" "--certificate-out" \
             "frankenctl evidence init"; do
  have "$CLI_SRC" "$token" || note "CLI source no longer contains: $token"
  have "$RUNBOOK" "$token" || note "runbook no longer documents: $token"
done
have "$CLI_SRC" "E8_CERTIFIER_PRODUCER_ID" || note "CLI source no longer imports E8_CERTIFIER_PRODUCER_ID"
have "$CERT_SRC" "franken-engine.e8-certifier" || note "non_use_certificate.rs missing franken-engine.e8-certifier"
have "$RUNBOOK" "franken-engine.e8-certifier" || note "runbook missing franken-engine.e8-certifier"
for token in "frankenctl agent-sandbox" "--data-contract" "--certificate-out" \
             "runbooks/dw_non_use_certificate.md" \
             "docs/E8_NON_USE_CERTIFICATE_THREAT_MODEL_V1.md" \
             "examples/26_non_exfiltration_certificate/demo.sh"; do
  have "$README" "$token" || note "README lost E8 reference: $token"
done

# 3. Bundle filenames, schemas, and statuses documented in runbook must match non_use_certificate.rs.
for token in "non_use_certificate.json" "use_certificate.json" \
             "declassification_receipts.jsonl" "capability_trace.jsonl" \
             "repro.lock" "audit.md" \
             "franken-engine.non-use-certificate.v2" \
             "franken-engine.use-certificate.v2" \
             "franken-engine.repro-lock.v2" \
             "certified_within_analyzed_scope" "uncertified" \
             "holds_within_analyzed_scope" "unanalyzed_fail_closed"; do
  have "$CERT_SRC" "$token" || note "non_use_certificate.rs no longer contains: $token"
  have "$RUNBOOK" "$token" || note "runbook no longer documents: $token"
done
have "crates/franken-engine/src/data_contract.rs" "explicit_flow_ifc_v1" || note "data_contract.rs missing explicit_flow_ifc_v1"
have "$RUNBOOK" "explicit_flow_ifc_v1" || note "runbook missing explicit_flow_ifc_v1"

# 4. Third-party verifier entrypoint documented in runbook must exist in third_party_verifier.rs.
for token in "NonUseCertificateClaimBundle" "verify_non_use_certificate_claim"; do
  have "$VERIFIER_SRC" "$token" || note "third_party_verifier.rs missing: $token"
  have "$RUNBOOK" "$token" || note "runbook missing verifier symbol: $token"
done

# 5. Refusal codes documented in runbook + threat-model doc must exist in source/docs.
for code in "unproven_ifc_propagation" "out_of_scope_covert_channel" "out_of_scope_timing_channel"; do
  have "$THREAT_DOC" "$code" || note "threat-model doc missing refusal code: $code"
  have "$RUNBOOK" "$code" || note "runbook missing refusal code: $code"
done

# 6. Gate, replay wrapper, and demo must be executable and cross-referenced.
[ -x "$GATE" ] || note "$GATE is not executable"
[ -x "$REPLAY" ] || note "$REPLAY is not executable"
[ -x "$DEMO" ] || note "$DEMO is not executable"
have "$GATE" "DW_RUN_LOCAL" || note "gate lost DW_RUN_LOCAL fallback"
have "$RUNBOOK" "DW_RUN_LOCAL" || note "runbook lost DW_RUN_LOCAL note"
have "$RUNBOOK" "run_dw_non_use_certificate.sh" || note "runbook lost gate script reference"
have "$RUNBOOK" "dw_non_use_certificate_replay.sh" || note "runbook lost replay script reference"

# 7. Claim IDs cited in runbook must exist in claim_to_proof_matrix_v1.json.
for claim in "FE-CLAIM-004" "FE-CLAIM-004-TEE" "FE-CLAIM-006" "FE-CLAIM-013" "FE-CLAIM-015" "FE-CLAIM-016"; do
  have "$MATRIX" "$claim" || note "claim matrix missing cited claim: $claim"
  have "$RUNBOOK" "$claim" || note "runbook missing claim disclosure: $claim"
done

# 8. Bounded-wording & anti-hype invariant: explicit-flow bound required; banned superlatives forbidden in runbook.
have "$THREAT_DOC" "EXPLICIT DATA FLOWS ONLY" || note "threat-model doc lost 'EXPLICIT DATA FLOWS ONLY'"
have "$RUNBOOK" "never a noninterference proof" || note "runbook lost 'never a noninterference proof' bound"
for banned in "guarantees" "unbreakable" "category-defining"; do
  if grep -qiw "$banned" "$RUNBOOK"; then
    note "runbook contains banned claim-gate word '$banned'"
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "[doc-drift] FAIL — E8 Non-Use Certificate docs drifted from shipped surface" >&2
  exit 1
fi
echo "[doc-drift] OK — E8 Non-Use Certificate docs match shipped CLI / bundle / verifier / claim state"
