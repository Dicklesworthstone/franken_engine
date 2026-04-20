# Metamorphic Testing Manifest

## Metamorphic Relations Catalog

FrankenEngine uses metamorphic relations when exact expected output is expensive,
underspecified, or unavailable, but relationships between executions are known.
Each relation must name the transformed input, the expected relationship between
outputs, and the fault class it is intended to expose.

Initial catalog:

- Parser preservation: formatting-only input changes must preserve the canonical
  parse tree hash.
- Replay determinism: repeating a run with the same seed, policy, and artifact
  inputs must reproduce the same trace and decision identifiers.
- Policy monotonicity: removing a granted capability must not expand the set of
  allowed effects.
- Containment invariance: reordering independent extension events must not bypass
  revocation, budget, or isolation checks.
- Lowering equivalence: syntax-preserving source rewrites must produce
  semantically equivalent lowered artifacts.

## Input Transformations

Input transformations are deterministic functions over fixtures, policies, seed
schedules, or event streams. A transformation is valid only when it preserves the
preconditions declared by the target relation.

Accepted transformation families:

- Whitespace, comment, and non-semantic formatting changes.
- Stable permutation of independent records or events.
- Capability removal, policy tightening, or budget reduction.
- Seed replay with identical inputs and runtime configuration.
- Alpha-renaming or syntax-preserving source rewrites.
- Failure injection that preserves artifact identity while changing the expected
  error path.

Transformations must be recorded with a stable name, version, seed, and input
artifact hash so failed runs can be replayed without reconstructing generator
state from logs.

## Output Invariants

Output invariants compare baseline and transformed executions without relying on
a single golden answer. Every invariant must be decidable from structured
artifacts produced by the run.

Required invariant classes:

- Equality invariants for canonical hashes, deterministic identifiers, and
  replay receipts.
- Subset invariants for tightened policy decisions and reduced capability sets.
- Monotonicity invariants for risk scores, budget ceilings, and revocation
  precedence.
- Disjointness invariants for complementary policy outcomes.
- Failure-shape invariants for expected error code, event ordering, and
  fail-closed outcomes.

Invariant failures are treated as real findings unless the relation precondition
is proven invalid by the same artifact bundle.

## Seed Schedule

Metamorphic runs use explicit seed schedules instead of ambient randomness. Each
schedule must define the generator version, seed namespace, run count, and replay
command used to regenerate the transformed inputs.

Default schedule:

- `smoke`: fixed seeds `0..16` for quick pre-commit coverage.
- `nightly`: fixed seeds `0..256` plus relation-specific adversarial seeds.
- `release`: the nightly schedule plus every previously failing seed retained in
  the regression corpus.
- `incident`: the failing seed, its minimized reproducer, and one neighboring
  seed on each side when the generator supports ordered seeds.

Seed changes require a manifest update and must preserve historical failing
seeds until the associated defect and regression test are closed.

## Oracle-Free Property Coverage

Oracle-free coverage is measured by relation coverage, transformation coverage,
and fault-class coverage rather than by golden output count.

Minimum coverage expectations:

- Each high-risk subsystem has at least one equivalence or monotonicity relation.
- Each relation declares the bug classes it can detect and the classes it cannot
  detect.
- Compound checks compose at least two independent relations when runtime cost is
  acceptable.
- Mutation or fault-injection runs periodically prove that each relation catches
  a planted defect.
- Coverage reports list skipped relations, invalid preconditions, and
  inconclusive runs separately from passes.

Metamorphic test results are publishable only when the artifact bundle includes
the original input, transformed input, relation name, invariant result, seed,
structured events, and replay command.
