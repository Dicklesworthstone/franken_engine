# BD-CSNQB Formal Mathematical Claims Audit

## Audit Summary

Found several claims using formal mathematical terminology without corresponding proof artifacts:

## Unsupported Formal Claims Found

### PLAN_TO_CREATE_FRANKEN_ENGINE.md

1. **Line 50**: "mathematically explicit security decisions"
   - Lacks formal mathematical specification or proof
   - Should be downgraded to TARGETED

2. **Line 588**: "proof-carrying compilation contract...machine-checkable witness...isomorphism ledger"
   - Claims formal verification of compilation correctness
   - No Lean/Coq/TLA+ proof artifacts exist
   - Should be downgraded to TARGETED or create FOLLOWUP bead

3. **Line 606**: "formal semantics with explicit monotonicity...mathematically explicit merge operators with proofs"
   - Claims formal semantics and mathematical proofs
   - No formal specification or proof files
   - Should be downgraded to TARGETED or create FOLLOWUP bead

4. **Line 631**: "mathematically equivalent fast paths...behind isomorphism proof notes"
   - Claims mathematical equivalence proofs
   - No proof artifacts exist
   - Should be downgraded to TARGETED

5. **Line 739**: "theorem-backed compiler is the only scalable route"
   - Claims theorem-backed compilation
   - No formal theorem or proof exists
   - Should be downgraded to HYPOTHESIZED

6. **Line 828**: "Policy Theorem Engine"
   - Names a component using formal theorem terminology
   - No formal theorem engine implementation with proofs
   - Should be downgraded to TARGETED

7. **Line 898**: "Policy theorem checks validate monotonic safety constraints"
   - Claims formal theorem validation
   - No formal theorem checker implementation
   - Should be downgraded to TARGETED

## Existing Claim-to-Proof Matrix Status

The current matrix in `docs/claim_to_proof_matrix_v1.json` does NOT track these formal mathematical claims from the PLAN file. All tracked claims appear to be properly categorized (most unsupported claims are marked as "target" or "hypothesis").

## Recommendations

1. **Add missing formal claims** to the claim-to-proof matrix with appropriate downgrades
2. **Downgrade language** in PLAN file to use TARGETED/HYPOTHESIZED wording
3. **Create FOLLOWUP beads** for any formal verification work that should actually be implemented

## No Formal Proof Artifacts Found

Searched for:
- Lean files (*.lean): None found
- Coq files (*.v, *.coq): None found  
- TLA+ files (*.tla): None found
- Other formal verification tool files: None found
- External paper citations with proofs: None found

## Action Required

Either provide actual formal proof artifacts OR downgrade all mathematical/theorem/proof claims to TARGETED/HYPOTHESIZED status as appropriate.