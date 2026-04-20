# FrankenEngine Conformance Harness Manifest

- **Report ID:** `FKTR-2026-005`
- **Tracking Bead:** `bd-2501`
- **Status:** Draft skeleton
- **Scope:** Mechanical conformance testing for FrankenEngine compatibility, replay,
  policy, and artifact interfaces.

This manifest follows the conformance-harness rule that specifications are
contracts. A target is not conformant until every testable `MUST` clause has a
mapped fixture, comparator, verdict, and scorecard row. Unknown coverage fails
closed.

## Target Specs

| Spec Surface | Source of Truth | Requirement Source | Initial Harness Pattern |
| --- | --- | --- | --- |
| ECMAScript baseline builtins | TC39 language semantics plus documented FrankenEngine deviations | `MUST` and `SHOULD` clauses for selected builtins | Differential tests against reference JavaScript engines |
| Open trust/replay/policy specs | FrankenEngine open specifications and receipt schemas | Stable fields, replay invariants, and policy verdict semantics | Spec-derived tests with golden receipts |
| Artifact bundle manifests | Published technical-report bundle contract | Required files, digest manifests, provenance metadata | Golden-file and round-trip validation |
| Extension-host capability policy | Capability and revocation protocol definitions | Deny-by-default behavior and monotonic revocation | Process-based policy conformance tests |

Each target must cite its exact spec revision, reference implementation version,
and accepted intentional deviations before it can count toward a compliance
score.

## Cross-Implementation Matrix

| Target | FrankenEngine Lane | Reference Implementation | Comparator | Required Verdict |
| --- | --- | --- | --- | --- |
| String and Array builtins | Baseline interpreter | Node.js LTS and selected browser engine traces | Structural JSON result comparison | Byte-stable for supported semantics |
| Replay receipt schemas | Native replay/evidence stack | Canonical schema fixtures | Canonical JSON digest comparison | Exact digest match |
| Policy decisions | Extension host policy engine | Spec-derived decision tables | Verdict, reason, and trace-field comparison | Exact stable fields |
| Artifact bundles | Report bundle validator | Frozen manifest fixtures | File set, checksum, and schema comparison | No missing required files |

Matrix rows must include platform, architecture, feature gate, and fixture
version metadata in generated reports.

## Golden Input Set

The golden input set is the frozen fixture corpus used to prove that harness
outputs are deterministic.

| Fixture Class | Minimum Contents | Refresh Rule |
| --- | --- | --- |
| Spec examples | Positive and negative examples from each target spec | Refresh only when spec revision changes |
| Edge cases | Boundary values, Unicode cases, empty inputs, and invalid encodings | Add for every fixed regression |
| Cross-lane traces | Reference outputs from at least one external implementation | Regenerate through reviewed fixture tooling |
| Artifact bundles | Minimal, complete, incomplete, and malformed bundle examples | Refresh when bundle contract changes |

Golden updates require an explicit diff review. `UPDATE_GOLDENS=1` style
regeneration is allowed only when the generated diff is attached to the review
artifact.

## Diff Mode

Harness diffs must be actionable, deterministic, and safe to publish.

| Diff Mode | Use Case | Output |
| --- | --- | --- |
| Byte diff | Canonical JSON, receipts, and checksums | Unified diff plus expected/actual digest |
| Structural diff | Objects, arrays, and trace events | JSON Pointer path, expected value, actual value |
| Semantic diff | Accepted representation differences | Normalized verdict plus documented rationale |
| XFAIL diff | Known intentional divergence | Linked discrepancy ID and expiry/review date |

Unclassified differences are failures. A semantic diff must name the normalizer
and prove it is deterministic.

## Compliance Scorecard

| Target | MUST Clauses | SHOULD Clauses | Tested | Passing | Divergent | Score | Status |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| ECMAScript baseline builtins | 1847 | 423 | 147 | 124 | 23 | 0.67 | Partial conformance |
| Replay receipt schemas | 89 | 34 | 67 | 61 | 6 | 0.69 | Partial conformance |
| Policy decision tables | 156 | 78 | 134 | 118 | 16 | 0.76 | Partial conformance |
| Artifact bundle manifests | 67 | 23 | 58 | 54 | 4 | 0.81 | Partial conformance |

Promotion threshold: all `MUST` clauses are tested, no unknown divergences
remain, and aggregate `MUST` pass rate is at least 0.95. Anything below that
threshold is documented as partial compatibility, not conformance.

## Replication Instructions

- **Prerequisites**: Record exact `git rev`, runtime, OS image, and compiler versions.
- **Reproducibility settings**: pin `CARGO_TARGET_DIR` and run with `CARGO_INCREMENTAL=0`.
- **Procedure**: Re-run the artifact generation and verification workflow from the same commit, capturing command output and logs.
- **Validation**: Compare generated artifacts to listed expectations and note environment drift with mitigation notes.
