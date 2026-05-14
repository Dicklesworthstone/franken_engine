# IDEA-WIZARD-XIII Transparency-Log Decision Receipt Proof

`bd-ly6hp.2` provides the first FE-CLAIM-004 promotion proof bundle for the
decision-receipt and transparency-log subset only. It does not promote optional
TEE attestation wording.

The proof wrapper reuses the shipped signed-decision receipt example as the
receipt source:

```bash
./examples/02_signed_decision_receipt/verify.sh
```

That example already runs the `franken-decision-demo` binary through `rch` and
emits a signed receipt artifact. The wrapper then binds the receipt to a small
append-only transparency log artifact, emits inclusion and consistency proof
JSON, and records negative fixtures for tampered receipts, forked log roots,
missing signatures, and stale source revisions.

## Artifacts

The primary proof command is:

```bash
./scripts/idea_wizard_xiii_transparency_log_decision_receipt_proof.sh
```

It writes a bundle under
`artifacts/idea_wizard_xiii_transparency_log_decision_receipt_proof/<run-id>/`
with:

- `decision_receipt.json`
- `transparency_log.json`
- `inclusion_proofs.json`
- `consistency_proof.json`
- `negative_fixtures.json`
- `independent_verifier_report.json`
- `events.jsonl`
- `commands.txt`
- `run_manifest.json`
- `report.md`

The `independent_verifier_report.json` includes the fields required by the
claim-promotion contract:

- `receipt_chain_root`
- `log_root`
- `inclusion_proof_count`
- `consistency_proof_count`
- `independent_verifier_verdict`
- `tee_attestation_state`

## Promotion Boundary

This proof can support only this FE-CLAIM-004 subset:

```text
decision_receipts_plus_transparency_log_only
```

TEE remains `hypothesis` until a separate live attestation report exists. The
wrapper records `tee_attestation_state: "not_promoted"` and fails closed if a
bundle claims otherwise.

## Validation

```bash
bash -n scripts/idea_wizard_xiii_transparency_log_decision_receipt_proof.sh
bash -n scripts/e2e/idea_wizard_xiii_transparency_log_decision_receipt_proof_smoke.sh
jq empty docs/idea_wizard_xiii_transparency_log_decision_receipt_proof_v1.json
bash scripts/e2e/idea_wizard_xiii_transparency_log_decision_receipt_proof_smoke.sh check
bash scripts/e2e/idea_wizard_xiii_transparency_log_decision_receipt_proof_smoke.sh selftest
git diff --check -- docs/IDEA_WIZARD_XIII_TRANSPARENCY_LOG_DECISION_RECEIPT_PROOF.md docs/idea_wizard_xiii_transparency_log_decision_receipt_proof_v1.json scripts/idea_wizard_xiii_transparency_log_decision_receipt_proof.sh scripts/e2e/idea_wizard_xiii_transparency_log_decision_receipt_proof_smoke.sh
```
