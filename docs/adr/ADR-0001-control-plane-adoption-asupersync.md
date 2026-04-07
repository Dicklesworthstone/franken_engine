# ADR-0001: Control-Plane Primitive Adoption from `/dp/asupersync`

- Status: Accepted
- Date: 2026-02-20
- Owners: FrankenEngine maintainers + 10.11 primitive owners
- Plan references: 10.13 item 1, 10.11 ownership model
- Related beads: `bd-3vlb`, `bd-ypl4`, `bd-2fa1`

## Context

FrankenEngine must consume control-plane primitives from the canonical `/dp/asupersync`
crates and avoid local type forks. Without an explicit decision record, teams can
accidentally introduce duplicate local definitions that break determinism, evidence
linkage, and cross-repo integration.

## Decision

FrankenEngine adopts `/dp/asupersync` as the canonical source for control-plane
primitives. The listed types are imported from canonical crates and are never redefined
inside this repository.

## Exact Imported Control-Plane Surface

The approved import boundary is `crates/franken-engine/src/control_plane/mod.rs`.
RC-6.3 contract tests in
`crates/franken-engine/tests/asupersync_dependency_contracts.rs` type-check the
exact upstream API surface below and fail early if `/dp/asupersync` drifts.

### `franken-kernel` / `franken_kernel`

| Imported symbol | Kind | Current use |
| --- | --- | --- |
| `Budget` | struct | budget threading through `KernelContext` and adapter callers |
| `CapabilitySet` | trait | capability-generic `Cx` plumbing |
| `Cx` | struct | canonical execution context wrapper in `KernelContext` |
| `DecisionId` | struct | decision identity carried through adapter requests |
| `NoCaps` | struct | zero-capability default for `Cx` |
| `PolicyId` | struct | policy identity carried through adapter requests |
| `SchemaVersion` | struct | schema compatibility identity exposed by the adapter boundary |
| `TraceId` | struct | trace identity threaded through `Cx` and adapter requests |

### `franken-decision` / `franken_decision`

| Imported symbol | Kind | Current use |
| --- | --- | --- |
| `DecisionContract` | trait | contract trait re-exported from `control_plane` |
| `DecisionOutcome` | struct | result type from decision evaluation |
| `EvalContext` | struct | calibration/e-process/CI-width evaluation input |
| `FallbackPolicy` | struct | fallback thresholds for degraded decisions |
| `LossMatrix` | struct | expected-loss model for contract evaluation |
| `Posterior` | struct | posterior belief state for contract evaluation |
| `evaluate` | function | canonical evaluation engine used by `control_plane::evaluate_contract` |

### `franken-evidence` / `franken_evidence`

| Imported symbol | Kind | Current use |
| --- | --- | --- |
| `EvidenceLedger` | struct | emitted evidence entry type returned to adapter callers |
| `EvidenceLedgerBuilder` | struct | canonical builder used for adapter evidence emission |

`franken-kernel`/`franken_kernel`, `franken-decision`/`franken_decision`, and
`franken-evidence`/`franken_evidence` are all normative references. The table
above is intentionally exact rather than aspirational: if the import list
changes, this ADR and the RC-6.3 contract tests must change together.

## Version Policy

Version policy for `/dp/asupersync` imports is strict and explicit:

| Cargo package | Allowed range | Pinning policy | Upgrade gate |
| --- | --- | --- | --- |
| `franken-kernel` | `>=0.2.0, <0.3.0` | Lockfile pins exact release | 10.11 owner review + compatibility notes |
| `franken-decision` | `>=0.2.0, <0.3.0` | Lockfile pins exact release | 10.11 owner review + compatibility notes |
| `franken-evidence` | `>=0.2.0, <0.3.0` | Lockfile pins exact release | 10.11 owner review + compatibility notes |

For `0.x` crates, minor-version changes are treated as potentially breaking and require
explicit review before adoption.

## Naming Guidance

Cargo package names and Rust crate paths are both normative, but they are used in
different contexts:

| Context | Required form | Example |
| --- | --- | --- |
| `Cargo.toml` dependency keys and `package` values | Hyphenated package names | `franken-kernel`, `franken-decision`, `franken-evidence` |
| Rust source (`use`, `extern crate`) | Underscored crate paths | `franken_kernel`, `franken_decision`, `franken_evidence` |

Correct `Cargo.toml` examples:

```toml
[dependencies]
franken-kernel = "0.2"
franken-decision = "0.2"
franken-evidence = "0.2"
```

Correct Rust source examples:

```rust
use franken_kernel::{Cx, DecisionId, PolicyId, SchemaVersion};
use franken_decision::{DecisionContract, evaluate};
use franken_evidence::EvidenceLedgerBuilder;
```

Common mistakes (forbidden):

- `Cargo.toml` dependency keys like `franken_kernel = "..."` (underscored package key).
- `package = "franken_kernel"` (underscored package value).
- Rust imports like `use franken-kernel::Cx;` (hyphen in Rust path).

A lint script is provided at `scripts/check_asupersync_naming.sh` and can be wired into
CI to enforce these rules.

## Escalation Path for Missing APIs

If a required primitive is missing upstream:

1. Open an upstream issue in `/dp/asupersync` with required type/contract details.
2. Open or update a local tracking bead that links the upstream issue.
3. Use only a narrow local adapter for call-shape compatibility when unavoidable.
4. Do not fork `/dp/asupersync` crates and do not create local shadow types for
   `Cx`, `TraceId`, `DecisionId`, `PolicyId`, `SchemaVersion`, or `Budget`.
5. Merge only after 10.11 primitive-owner sign-off.

## Dependency Policy: No Local Forks

FrankenEngine must not define local substitutes for the exact imported control-plane
surface documented above. At minimum, that includes `Budget`, `CapabilitySet`,
`Cx`, `DecisionId`, `NoCaps`, `PolicyId`, `SchemaVersion`, `TraceId`,
`DecisionContract`, `DecisionOutcome`, `EvalContext`, `FallbackPolicy`,
`LossMatrix`, `Posterior`, `EvidenceLedger`, and `EvidenceLedgerBuilder`.

This policy treats all of the following as forbidden local forks:

- `struct` or `type` definitions that reuse those canonical names.
- Newtype wrappers intended to impersonate canonical primitives at integration boundaries.
- Local modules that re-export locally defined substitutes under canonical names.

Current import ownership for the enforced boundary is:

- `franken_kernel`: `Budget`, `CapabilitySet`, `Cx`, `DecisionId`, `NoCaps`, `PolicyId`, `SchemaVersion`, `TraceId`
- `franken_decision`: `DecisionContract`, `DecisionOutcome`, `EvalContext`, `FallbackPolicy`, `LossMatrix`, `Posterior`, `evaluate`
- `franken_evidence`: `EvidenceLedger`, `EvidenceLedgerBuilder`

Enforcement is provided by `scripts/check_no_local_control_plane_type_forks.sh`.
The script blocks new local definitions and supports an explicit baseline allowlist
until legacy names are migrated.

Remediation process for violations:

1. Replace local substitute types with canonical imports from `/dp/asupersync`.
2. Remove legacy allowlist entries when migration is complete.
3. Only keep allowlist entries that are explicitly tracked as migration debt.
4. Do not add new allowlist entries without an ADR amendment and linked bead.

## Non-Goals

- Re-implementing control-plane primitive semantics in `franken_engine`.
- Creating alternate local type systems for canonical control-plane identifiers.

## Consequences

- Positive: deterministic, single-source primitive vocabulary across repos.
- Positive: less drift and easier cross-repo verification for evidence and decisions.
- Cost: integration work may wait on upstream `/dp/asupersync` changes.

## Compliance Signals

- Dependency policy docs and CI checks should enforce no local forked primitive types.
- New integration code should reference this ADR and the companion naming/dependency beads.
- RC-6.3 contract tests should type-check the exact upstream re-exports and the
  `control_plane::evaluate_contract` signature under `asupersync-integration`.
