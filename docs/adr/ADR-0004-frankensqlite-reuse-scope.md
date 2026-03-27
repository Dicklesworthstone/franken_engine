# ADR-0004: `/dp/frankensqlite` as Canonical SQLite Control-Plane Persistence Substrate

- Status: Accepted
- Date: 2026-02-20
- Owners: FrankenEngine maintainers + control-plane persistence owners
- Plan references: 10.14 item 4, success criterion 13
- Related beads: `bd-3azm`, `bd-1ps3`, `bd-89l2`, `bd-30vf`

## Context

FrankenEngine follows a sibling-repo reuse-first policy and avoids parallel local
replacements when a designated substrate exists. For SQLite-backed control-plane
persistence, that substrate is `/dp/frankensqlite`.

Without a binding scope decision, local SQLite usage can drift into inconsistent
WAL/PRAGMA settings, duplicated migration logic, and fragmented persistence APIs.

## Decision

FrankenEngine declares `/dp/frankensqlite` as the canonical substrate for
SQLite-backed control-plane persistence. New control-plane persistence work must
integrate through `/dp/frankensqlite` APIs/primitives unless an explicit
exception is approved.

WAL/PRAGMA tuning and schema migration logic are owned by `/dp/frankensqlite`,
not ad hoc local persistence code.

## Scope

In scope (must use `/dp/frankensqlite`):

- replay index
- evidence index
- benchmark ledger
- policy cache
- witness stores
- lineage logs
- other durable control-plane SQLite persistence paths

Out of scope:

- Non-SQLite persistence backends.
- In-memory/transient runtime state with no control-plane durability contract.
- Non-production fixtures used only for isolated test scaffolding.

## Companion Decision: `sqlmodel_rust` Boundary

`/dp/sqlmodel_rust` is required on top of `/dp/frankensqlite` when typed models
materially improve correctness or migration safety.

Use `sqlmodel_rust` (typed model layer on frankensqlite) when one or more are true:

1. The store has multi-table relationships with non-trivial invariants.
2. The store encodes domain constraints that should be validated at typed boundaries.
3. Migration risk is high enough that compile-time model/schema alignment materially reduces defect risk.

Use raw `/dp/frankensqlite` primitives when all are true:

1. Schema is simple (key-value or append-only records).
2. Domain invariants are minimal and do not justify typed model overhead.
3. Migration patterns are straightforward and low risk.

Expected examples:

- Usually raw `/dp/frankensqlite`: replay index, benchmark ledger, policy artifact cache.
- Usually `sqlmodel_rust` over `/dp/frankensqlite`: replacement lineage log, IFC provenance index, specialization index.

## Persistence Boundary Definition

A persistence surface is treated as in-scope control-plane SQLite persistence
when all of the following are true:

1. It stores durable state in SQLite.
2. It is used by operator, policy, replay, benchmark, or evidence workflows.
3. It influences runtime governance, incident analysis, or release decisions.

If all three are true, `/dp/frankensqlite` integration is required.

## Rationale

Centralizing SQLite usage through `/dp/frankensqlite` ensures deterministic and
auditable persistence behavior, prevents conflicting storage conventions, and
keeps migration and tuning logic consolidated in one hardened substrate.

This aligns with AGENTS.md sibling reuse policy and
`docs/REPO_SPLIT_CONTRACT.md` reuse expectations.

## Exception Process

When `/dp/frankensqlite` cannot reasonably satisfy a required persistence path:

1. Open a tracking bead with explicit mismatch, expected workload, and proposed divergence.
2. Reference this ADR and describe exact scope of the raw SQLite need.
3. Document why `/dp/frankensqlite` cannot be extended in-time, plus migration-back plan.
4. Obtain maintainer approval before merge.
5. Keep exception time-bounded and review at the next integration checkpoint.

## Consequences

- Positive: consistent WAL/PRAGMA and migration behavior across control-plane stores.
- Positive: reduced duplicate persistence logic and lower long-term maintenance cost.
- Cost: some delivery cadence depends on `/dp/frankensqlite` API availability.

## Compliance Signals

- New control-plane SQLite PRs reference this ADR.
- New direct `rusqlite`/SQLite dependency additions trigger ADR/exception review.
- Storage adapter work (`bd-89l2`) and persistence inventory (`bd-1ps3`) align to this boundary.
- Every new store documents `raw frankensqlite` vs `sqlmodel_rust` choice with rationale (`bd-2d21`).

## Migration Policy (No Ad-Hoc Local SQLite Wrappers)

Effective immediately as of February 20, 2026:

- New direct SQLite wrappers (for example `rusqlite`, `sqlite3`, or local one-off
  SQLite adapter layers) are prohibited for control-plane persistence paths.
- New control-plane persistence must route through
  `crates/franken-engine/src/storage_adapter.rs` and the corresponding
  `/dp/frankensqlite` integration seam.

CI enforcement for this policy is provided by:

```bash
scripts/check_no_local_sqlite_wrappers.sh ci
```

This check fails when direct SQLite dependency or usage patterns are introduced
outside the approved storage-adapter boundary.

Exception process for this migration policy:

- Create an approved exception record under
  `docs/adr/exceptions/ADR-EXCEPTION-SQLITE-<id>.md`.
- The document must include `Status: Approved` and explicit `Scope:` lines for
  dependency/path/token exceptions.
- Exceptions are time-bounded and must include a rollback/migration-back plan.

Transition timeline:

1. By March 15, 2026: any remaining direct SQLite call sites must be inventoried
   and linked to tracked migration beads.
2. By January 31, 2027: direct wrappers must be removed or carried by renewed,
   explicitly approved exception artifacts.

## Operator Verification (Storage Adapter Contract)

For `bd-89l2` storage-adapter verification, follow these steps:

1. Run the storage adapter suite:
   ```bash
   scripts/run_storage_adapter_suite.sh ci
   ```
2. Verify that this `rch`-backed runner emits reproducibility artifacts under `artifacts/storage_adapter/<timestamp>/`:
   - `run_manifest.json`: toolchain/seed/commands/commit metadata
   - `commands.txt`: exact command list executed
3. If replay validation is required, rerun with the same `STORAGE_ADAPTER_SEED` value and compare the emitted manifest and command log.
