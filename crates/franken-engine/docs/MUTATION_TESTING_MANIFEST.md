# FrankenEngine Mutation Testing Manifest

- **Report ID:** `FKTR-2026-006`
- **Tracking Bead:** `bd-2501`
- **Status:** Draft skeleton
- **Scope:** Mutation-testing discipline for validating that FrankenEngine tests
  detect semantic regressions instead of only executing code paths.

Mutation testing turns test adequacy into a falsifiable claim: if a small,
behavior-changing mutant survives, the relevant test or oracle is incomplete.
This manifest defines the minimum catalog, triage, filtering, baseline, and CI
gate needed before mutation scores can support publishable quality claims.

## Mutation Operators Catalog

| Operator Family | Example Mutations | Target Surfaces | Required Oracle |
| --- | --- | --- | --- |
| Boolean and branch logic | Negate condition, swap `&&`/`||`, invert guard result | Policy gates, parser validation, runtime dispatch | Expected allow/deny or parse verdict |
| Numeric boundaries | Replace `<` with `<=`, shift min/max, perturb saturating casts | Resource budgets, ring buffers, timing bounds | Boundary fixture plus invariant check |
| Error propagation | Drop `Err`, convert error to default, erase error context | CLI gates, artifact generators, replay validators | Fail-closed assertion and stable error code |
| Collection semantics | Remove first/last item, skip duplicate check, reorder stable output | Registry, corpus coverage, compatibility matrices | Deterministic ordering and count assertions |
| Capability semantics | Permit missing capability, ignore revocation, widen scope | Extension host and sandbox policy | Explicit denial and trace-field assertion |

Every operator must declare its target module class, expected mutant effect, and
known unsafe-to-run exclusions before entering automated campaigns.

## Survivor Analysis

Survivors are actionable defects unless proven equivalent.

| Survivor Field | Required Content |
| --- | --- |
| Mutant ID | Stable operator, file, span, and mutation payload identifier |
| Covered tests | Tests that executed the mutated code path |
| Observed output | Actual verdict, logs, and artifact digests under mutation |
| Expected kill reason | Test oracle or invariant that should have failed |
| Remediation owner | Test, implementation, or equivalent-mutant classification owner |

Survivor reports must distinguish unexecuted code, weak assertions, missing
edge-case fixtures, and intentional semantic latitude. Unknown survivor causes
block score promotion.

## Equivalent-Mutant Filter

Equivalent mutants are excluded only with evidence.

| Filter Rule | Evidence Required |
| --- | --- |
| Semantic no-op | Proof sketch or differential trace showing identical observable behavior |
| Dead code under current feature set | Feature matrix row and reachability explanation |
| Type-system collapse | Compiler proof that the mutation cannot alter runtime output |
| Redundant invariant | Existing stronger invariant with linked test or formal check |

Equivalent classifications must expire when the surrounding API, feature gate,
or target specification changes.

## Mutation-Score Baseline

| Target Class | Initial Baseline | Publishable Threshold | Notes |
| --- | ---: | ---: | --- |
| Parser and lowering invariants | 0.72 | 0.85 | Start with grammar and semantic-error operators |
| Baseline interpreter builtins | 0.68 | 0.80 | Require compatibility fixture kills for semantic mutants |
| Policy and capability gates | 0.91 | 0.95 | Security-critical mutants must not survive |
| Artifact and replay validators | 0.84 | 0.90 | Missing-hash and missing-signature mutants are mandatory |
| CLI fail-closed gates | 0.87 | 0.90 | Unknown-option and invalid-input mutants are required |

The baseline is measured per target class and cannot be averaged in a way that
hides a weak security-critical surface.

## CI Gate Threshold

| Gate | Threshold | Failure Behavior |
| --- | ---: | --- |
| Changed-module smoke mutation | No new surviving non-equivalent mutants | Block merge |
| Security-critical mutation lane | Score >= 0.95 and zero high-severity survivors | Block release |
| Nightly broad mutation campaign | Score does not regress by more than 0.02 | Open blocking bead |
| Publishable artifact evidence | Target-specific threshold met with signed survivor report | Block publication |

CI must publish the mutant manifest, killed/survived/equivalent counts,
survivor report, and reproduction command. A missing mutation report is a gate
failure, not a skipped quality signal.

## Replication Instructions

- **Prerequisites**: Record exact `git rev`, runtime, OS image, and compiler versions.
- **Reproducibility settings**: pin `CARGO_TARGET_DIR` and run with `CARGO_INCREMENTAL=0`.
- **Procedure**: Re-run the artifact generation and verification workflow from the same commit, capturing command output and logs.
- **Validation**: Compare generated artifacts to listed expectations and note environment drift with mitigation notes.
