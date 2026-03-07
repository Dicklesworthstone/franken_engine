# RGC Claim Entitlement Algebra V1

## Purpose

`RGC-017` defines the typed vocabulary that decides what FrankenEngine is
allowed to claim today, what is still only a frontier objective, and which
evidence gaps or disqualifiers prevent stronger language.

This is the dependency-safe answer to the repo's repeated "conceptually right
but cycle-unsafe edge" problem: docs, rollout, GA, support-surface, React, and
supremacy publication logic need a common truth model that does not depend on
ad hoc prose interpretation.

## Contract Version

- `schema_version`: `franken-engine.rgc-claim-entitlement-algebra.v1`
- `contract_version`: `0.1.0`
- `bead_id`: `bd-1lsy.1.7`
- `generated_by`: `bd-1lsy.1.7`

Canonical machine-readable source:

- `docs/rgc_claim_entitlement_algebra_v1.json`

## Claim Atoms

The atom catalog defines the primitive statements the program can reason over.
This foundation intentionally includes both shipped facts and frontier-only
ambitions.

Current catalog families:

- shipped `frankenctl` command-surface atoms
- React compile and SSR support-state atoms
- V8 supremacy publication-language atoms
- rollout/doctor guidance atoms
- unsupported-surface visibility atoms
- GA evidence-package atoms

The core distinction is non-negotiable:

- `shipped_fact` means the public/operator surface can speak in present tense if
  the required evidence remains green.
- `scoped_observed` means present-tense language is allowed only within a
  bounded scope.
- `frontier_ambition` means roadmap or goal language only.
- `unsupported_surface` means the system must fail closed with guidance instead
  of pretending the surface is shipped.

## Evidence Morphisms

Evidence morphisms map concrete artifacts into claim atoms while attaching the
side constraints and disqualifier rules that keep those mappings honest.

Current foundation morphisms consume:

- docs/help surface audits
- focused `frankenctl` CLI tests
- React capability contracts
- V8 supremacy publication contracts
- runtime doctor outputs
- support-surface contracts
- GA evidence bundles
- counterexample ledgers

The morphism layer is what lets later consumers ask "which claims does this
artifact support or constrain?" without inventing custom logic in every gate.

## Side-Constraint Lattice

The side-constraint lattice describes the ordered conditions required for a
statement to move from intent-language toward stronger publishable language.

Current lattice spine:

- `constraint.intent.frontier_only`
- `constraint.publication.scoped_language`
- `constraint.surface.shipped_path`
- `constraint.evidence.reproducible`
- `constraint.quality.counterexample_free`
- `constraint.quality.user_visible_diagnostics`
- `constraint.quality.platform_verified`
- `constraint.performance.side_constraints_green`
- `constraint.publication.universal_language`

This is intentionally conservative. A claim does not climb the lattice merely
because one artifact exists; it climbs only if the stronger constraints also
hold.

## Disqualifier Rules

Disqualifiers override optimistic publication paths when active evidence says
"not yet" or "currently false."

Current rule families:

- active counterexample beats optimism
- unsupported surface beats shipped-language drift
- stale evidence forces downgrade
- missing platform verification blocks shipped support claims
- missing user-visible diagnostics blocks unsupported-surface publication
- tail or memory regressions block universal supremacy language
- docs/help contradictions block shipped CLI statements

These rules are ordered. The precedence list is machine-readable so downstream
consumers do not disagree about which blocker wins.

Scenario evaluation on top of the algebra emits four deterministic report
families for downstream gates:

- `claim_entitlement_report.json`
- `missing_evidence_cutsets.json`
- `impossibility_certificates.json`
- `claim_counterexample_ledger.json`

These outputs make the claim state explicit instead of forcing later beads to
re-derive why a statement is entitled, merely unproven, blocked by missing
evidence, or currently false under an active counterexample.

## Operator Verification

```bash
jq empty docs/rgc_claim_entitlement_algebra_v1.json
./scripts/run_rgc_claim_entitlement_algebra.sh ci
./scripts/e2e/rgc_claim_entitlement_algebra_replay.sh ci
cat artifacts/rgc_claim_entitlement_algebra/<timestamp>/claim_atom_catalog.json
cat artifacts/rgc_claim_entitlement_algebra/<timestamp>/evidence_morphism_catalog.json
cat artifacts/rgc_claim_entitlement_algebra/<timestamp>/side_constraint_lattice.json
cat artifacts/rgc_claim_entitlement_algebra/<timestamp>/disqualifier_rules.json
cat artifacts/rgc_claim_entitlement_algebra/<timestamp>/claim_entitlement_report.json
cat artifacts/rgc_claim_entitlement_algebra/<timestamp>/missing_evidence_cutsets.json
cat artifacts/rgc_claim_entitlement_algebra/<timestamp>/impossibility_certificates.json
cat artifacts/rgc_claim_entitlement_algebra/<timestamp>/claim_counterexample_ledger.json
cat artifacts/rgc_claim_entitlement_algebra/<timestamp>/run_manifest.json
cat artifacts/rgc_claim_entitlement_algebra/<timestamp>/events.jsonl
cat artifacts/rgc_claim_entitlement_algebra/<timestamp>/commands.txt
```
