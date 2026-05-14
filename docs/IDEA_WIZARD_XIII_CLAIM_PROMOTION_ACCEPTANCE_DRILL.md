# IDEA-WIZARD-XIII Claim Promotion Acceptance Drill

`bd-ly6hp.6` composes the XIII proof lane into one replayable operator drill.
It consumes the three live proof reports, runs the claim-promotion gate, copies
the source inputs into the run bundle, and emits a single aggregate verdict.

The drill verifies:

- `FE-CLAIM-004` can promote only the decision-receipt transparency-log subset;
  missing TEE attestation keeps operator status degraded.
- `FE-CLAIM-005` can be green for bounded quarantine convergence only when the
  measured convergence stays within the recorded SLO; de-escalation remains out
  of scope.
- `FE-CLAIM-006` can promote only the covered
  `capability_typed_manifest_ir_hostcall_v1` subset; full typed
  TypeScript-to-IR onboarding remains degraded.
- stale, synthetic, missing, or README-overclaiming evidence fails closed.

## Drill

```bash
./scripts/idea_wizard_xiii_claim_promotion_acceptance_drill.sh \
  --transparency-report /path/to/independent_verifier_report.json \
  --quarantine-report /path/to/live_quarantine_mesh_convergence_report.json \
  --capability-report /path/to/capability_typed_onboarding_report.json \
  --readme README.md
```

The run bundle includes `aggregate_report.json`, `operator_summary.md`,
`source_inputs.json`, `commands.txt`, `events.jsonl`, `run_manifest.json`, and
the nested claim-promotion gate outputs under `gate/`.

## Validation

```bash
bash -n scripts/idea_wizard_xiii_claim_promotion_acceptance_drill.sh
bash -n scripts/e2e/idea_wizard_xiii_claim_promotion_acceptance_drill_smoke.sh
jq empty docs/idea_wizard_xiii_claim_promotion_acceptance_drill_v1.json
jq empty scripts/testdata/idea_wizard_xiii_claim_promotion_acceptance_drill/cases.json
bash scripts/e2e/idea_wizard_xiii_claim_promotion_acceptance_drill_smoke.sh check
bash scripts/e2e/idea_wizard_xiii_claim_promotion_acceptance_drill_smoke.sh selftest
shellcheck -x scripts/idea_wizard_xiii_claim_promotion_acceptance_drill.sh scripts/e2e/idea_wizard_xiii_claim_promotion_acceptance_drill_smoke.sh
git diff --check -- docs/IDEA_WIZARD_XIII_CLAIM_PROMOTION_ACCEPTANCE_DRILL.md docs/idea_wizard_xiii_claim_promotion_acceptance_drill_v1.json scripts/idea_wizard_xiii_claim_promotion_acceptance_drill.sh scripts/e2e/idea_wizard_xiii_claim_promotion_acceptance_drill_smoke.sh scripts/testdata/idea_wizard_xiii_claim_promotion_acceptance_drill/cases.json
```
