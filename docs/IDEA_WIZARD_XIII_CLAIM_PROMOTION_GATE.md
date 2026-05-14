# IDEA-WIZARD-XIII Claim Promotion Gate

`bd-ly6hp.5` adds the live-report gate for the three README claims governed by
the XIII promotion contract:

- `FE-CLAIM-004`: cryptographic decision receipts and transparency-log proof.
- `FE-CLAIM-005`: fleet quarantine bounded convergence.
- `FE-CLAIM-006`: capability-typed runtime enforcement and ambient-authority
  rejection.

The gate consumes the proof reports produced by `bd-ly6hp.2`, `bd-ly6hp.3`, and
`bd-ly6hp.4`, then emits an operator status for each claim:

- `green`: the proof report passes for the named promotion subset.
- `degraded`: the proof report passes for the named subset, but the README must
  keep downgrade text for an unproven boundary.
- `fail_closed`: evidence is missing, stale, synthetic, invalid, non-passing, or
  the README claims more than the proof supports.

`FE-CLAIM-004` remains degraded after a passing transparency-log report because
optional TEE attestation is still not proven. `FE-CLAIM-006` remains degraded
after a passing capability-typed report because full typed TypeScript-to-IR
onboarding is not shipped. `FE-CLAIM-005` can be green only for bounded
quarantine convergence; de-escalation and recovery semantics remain explicitly
out of scope.

## Gate

```bash
./scripts/idea_wizard_xiii_claim_promotion_gate.sh \
  --transparency-report /path/to/decision_receipt_proof_report.json \
  --quarantine-report /path/to/quarantine_mesh_convergence_report.json \
  --capability-report /path/to/capability_typed_onboarding_report.json \
  --readme README.md
```

The gate writes `claim_promotion_gate_report.json`, `operator_status.json`,
`events.jsonl`, `commands.txt`, `run_manifest.json`, and `report.md`. It does
not rewrite README, mutate the claim matrix, run Cargo, run `rch`, or repair
Agent Mail state.

The composed acceptance drill is
`./scripts/idea_wizard_xiii_claim_promotion_acceptance_drill.sh`; it preserves
the three source proof reports and nests this gate inside one aggregate
operator bundle.

## Validation

```bash
bash -n scripts/idea_wizard_xiii_claim_promotion_gate.sh
bash -n scripts/e2e/idea_wizard_xiii_claim_promotion_gate_smoke.sh
jq empty docs/idea_wizard_xiii_claim_promotion_gate_v1.json
jq empty scripts/testdata/idea_wizard_xiii_claim_promotion_gate/cases.json
bash scripts/e2e/idea_wizard_xiii_claim_promotion_gate_smoke.sh check
bash scripts/e2e/idea_wizard_xiii_claim_promotion_gate_smoke.sh selftest
shellcheck -x scripts/idea_wizard_xiii_claim_promotion_gate.sh scripts/e2e/idea_wizard_xiii_claim_promotion_gate_smoke.sh
git diff --check -- docs/IDEA_WIZARD_XIII_CLAIM_PROMOTION_GATE.md docs/idea_wizard_xiii_claim_promotion_gate_v1.json scripts/idea_wizard_xiii_claim_promotion_gate.sh scripts/e2e/idea_wizard_xiii_claim_promotion_gate_smoke.sh scripts/testdata/idea_wizard_xiii_claim_promotion_gate/cases.json
```
