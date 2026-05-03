# Formal Runtime Security Model V1

This document is the current mathematical model boundary for FrankenEngine
runtime security. It is deliberately narrower than the long-term theorem-backed
vision: the shipped repository now has explicit finite algebra models and
executable invariant checks, while end-to-end machine-checked proofs for all
security decision algorithms remain hypothesis/target work in the
claim-to-proof matrix.

## Scope

The model covers two enforcement layers used by untrusted extension execution:

- IFC labels and flow authorization in `crates/franken-engine/src/ifc_artifacts.rs`.
- Runtime capability profiles in `crates/franken-engine/src/capability.rs`.

It does not claim a complete theorem proof for parser correctness, JavaScript
semantic equivalence, probabilistic guardplane optimality, TEE attestation,
transparency-log governance, or proof-carrying optimization.

## IFC Label Algebra

Let `L` be the finite built-in label set:

`Public < Internal < Confidential < Secret < TopSecret`

Custom labels extend the carrier set with an explicit non-negative level. The
runtime order `<=` is defined by `Label::level()`. A source label may flow to a
sink label when:

`source <= sink`

The runtime join and meet operations are:

- `join(a, b) = max_level(a, b)`, the least upper bound under `<=`.
- `meet(a, b) = min_level(a, b)`, the greatest lower bound under `<=`.

Executable obligations:

- Join and meet are idempotent, commutative, associative, and satisfy absorption
  over the built-in label set.
- `join(a, b)` is an upper bound for both inputs and is less than or equal to
  every other common upper bound in the built-in label set.
- `meet(a, b)` is a lower bound for both inputs and is greater than or equal to
  every other common lower bound in the built-in label set.
- Computed IR2 labels are the join of their input labels, so derived data is at
  least as sensitive as every direct input.

## IFC Flow Policy Semantics

For a policy `P`, source `s`, and sink `k`, `FlowPolicy::is_flow_allowed(s, k)`
is ordered as:

1. Explicit prohibitions deny first, even if `s <= k`.
2. Explicit allows permit named policy exceptions.
3. Lattice-legal flows permit when `s <= k`.
4. Declassification routes produce a required-declassification result.
5. All remaining flows deny.

This makes the safe default fail-closed: no route, no lattice legality, and no
explicit allow means denial.

## Capability Authority Algebra

Let `C` be the finite set of `RuntimeCapability` variants. A
`CapabilityProfile` denotes a subset of `C`.

Subsumption is set inclusion:

`A subsumes B` iff `B.capabilities subset_of A.capabilities`

Attenuation is set intersection:

`attenuate(A, B) = A intersect B`

Executable obligations:

- `FullCaps` subsumes every canonical profile.
- `ComputeOnlyCaps` is the bottom profile and grants no side effects.
- Intersections are commutative, idempotent, and never grant capabilities absent
  from either input.
- Pairwise intersections among `EngineCoreCaps`, `PolicyCaps`, and `RemoteCaps`
  are empty, preserving authority partitioning.
- Deserialization validates canonical profile definitions and rejects profile
  kind/capability smuggling.
- Unknown hostcall tags map to no typed capability and must be rejected by
  callers that require a security capability.

## Verification Commands

Focused proof-model checks:

```bash
cargo test -p frankenengine-engine --lib ifc_lattice_model -- --nocapture
cargo test -p frankenengine-engine --lib capability_profile_security_algebra -- --nocapture
```

Proof-smoke bundle with structured logging:

```bash
./scripts/e2e/runtime_security_model_proof_smoke.sh
```

The smoke script writes `manifest.json`, `commands.txt`, `events.jsonl`,
`report.json`, `report.md`, and `redaction_policy.json` using
`franken-engine.proof-artifact-manifest.v1`.

## Claim Boundary

The repository may describe the shipped runtime security layer as
mathematically explicit only when that phrase refers to the finite IFC and
capability algebra above plus the executable invariant checks. Stronger claims,
including theorem-backed security decisions or proof-carrying compilation,
remain governed by `docs/CLAIM_TO_PROOF_MATRIX_V1.md` and must stay
`hypothesis` or `target` until corresponding proof artifacts ship.
