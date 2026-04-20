# Proof Sketch Template

## Policy/Protocol
- Define the policy or protocol under validation.
- State the trust boundary and attacker model assumptions.
- Name the authority, enforcement mechanism, and failure semantics.

## Claim
- State the formal claim in a precise, checkable form.
- Include scope, preconditions, and the expected security, correctness, or performance outcome.
- List explicit dependencies that must hold for the claim to remain true.

## Assumptions
- Document all environmental, protocol, and component assumptions.
- List trusted inputs, replay/reproducibility assumptions, and version constraints.
- Note any limitations, caveats, or out-of-scope behavior.

## Proof Sketch
- Give a high-level argument linking implementation facts to the claim.
- Identify key invariants, obligations, and proof obligations.
- Explain transitions between states and why they preserve required properties.

## Mechanized Proof Artifact
- Reference the exact artifact path and expected checksum/builder reproducibility inputs.
- Provide machine-checkable checks (e.g., theorem statements, regression test IDs, scripts).
- Include instructions for artifact regeneration and verification steps.

## Replication Instructions

- **Prerequisites**: Record exact `git rev`, runtime, OS image, and compiler versions.
- **Reproducibility settings**: pin `CARGO_TARGET_DIR` and run with `CARGO_INCREMENTAL=0`.
- **Procedure**: Re-run the artifact generation and verification workflow from the same commit, capturing command output and logs.
- **Validation**: Compare generated artifacts to listed expectations and note environment drift with mitigation notes.
