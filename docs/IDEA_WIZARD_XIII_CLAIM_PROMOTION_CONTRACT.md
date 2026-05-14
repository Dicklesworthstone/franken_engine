# IDEA-WIZARD-XIII Claim Promotion Contract

`bd-ly6hp.1` defines the promotion contract for the README claims that remain
`hypothesis` or `target` after the current claim-to-proof matrix pass:

- `FE-CLAIM-004`: cryptographic governance with transparency-log and optional
  TEE proof artifacts
- `FE-CLAIM-005`: fleet immune-system quarantine propagation with bounded
  convergence evidence
- `FE-CLAIM-006`: capability-typed execution and ambient-authority rejection

The contract is intentionally conservative. It does not promote public wording
by itself; it records the exact artifacts future beads must produce before
`docs/claim_to_proof_matrix_v1.json` can move any of these claims upward.

## Promotion Rules

All promotion candidates must provide:

- a fresh JSON proof report with `decision` or `verdict` equal to `pass`;
- `commands.txt`, `events.jsonl`, `run_manifest.json`, and a human report;
- no local heavy Cargo execution in command transcripts;
- rch-wrapped heavy Rust validation commands whenever Rust proof is required;
- negative fixtures proving stale, synthetic, missing, and tampered evidence
  fails closed.

Claim-specific requirements:

- `FE-CLAIM-004` may promote only the receipt/transparency-log subset unless a
  separate TEE report exists. Missing TEE keeps TEE wording downgraded.
- `FE-CLAIM-005` requires live runtime or CLI quarantine propagation evidence,
  including partial and total propagation failures that remain degraded.
- `FE-CLAIM-006` requires a covered source or manifest input that binds
  capabilities through runtime enforcement, plus negative ambient-authority
  rejection cases.

## Gate

The advisory gate is:

```bash
./scripts/idea_wizard_xiii_claim_promotion_contract_gate.sh
```

It validates `docs/idea_wizard_xiii_claim_promotion_contract_v1.json` against
`docs/claim_to_proof_matrix_v1.json`, emits a report bundle, and fails closed
when a claim is missing, current matrix state is stronger than the contract
allows, required artifacts are omitted, or a promotion rule lacks downgrade
language.

## Live Report Gate

`bd-ly6hp.5` adds the second-stage live report gate:

```bash
./scripts/idea_wizard_xiii_claim_promotion_gate.sh
```

It consumes the XIII proof reports from `bd-ly6hp.2`, `bd-ly6hp.3`, and
`bd-ly6hp.4`, emits per-claim `green`, `degraded`, or `fail_closed` operator
status, and rejects stale, synthetic, missing, or overclaiming README inputs
before any README wording can be promoted.

## Validation

```bash
bash -n scripts/idea_wizard_xiii_claim_promotion_contract_gate.sh
bash -n scripts/e2e/idea_wizard_xiii_claim_promotion_contract_smoke.sh
jq empty docs/idea_wizard_xiii_claim_promotion_contract_v1.json
bash scripts/e2e/idea_wizard_xiii_claim_promotion_contract_smoke.sh check
bash scripts/e2e/idea_wizard_xiii_claim_promotion_contract_smoke.sh selftest
shellcheck -x scripts/idea_wizard_xiii_claim_promotion_contract_gate.sh scripts/e2e/idea_wizard_xiii_claim_promotion_contract_smoke.sh
git diff --check -- docs/IDEA_WIZARD_XIII_CLAIM_PROMOTION_CONTRACT.md docs/idea_wizard_xiii_claim_promotion_contract_v1.json scripts/idea_wizard_xiii_claim_promotion_contract_gate.sh scripts/e2e/idea_wizard_xiii_claim_promotion_contract_smoke.sh
```
