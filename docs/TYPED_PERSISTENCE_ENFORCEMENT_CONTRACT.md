# TYPED_PERSISTENCE_ENFORCEMENT_CONTRACT

This contract defines the required end state for `bd-gvnex` and the broader
`SQLMODEL-TYPED-P0` track. It records which FrankenEngine persistence stores
are inventory-mandated to use `sqlmodel_rust on frankensqlite`, what current
typed evidence already exists in-tree, and what future implementation beads
must enforce before the AGENTS.md deviation can be considered closed. Bead
`bd-q8x8x.5` extends the contract with rollback-sensitive fleet trust state;
`bd-q8x8x.9` adds its isolated real FrankenSQLite CAS backend.

Machine-readable contract:
`docs/typed_persistence_enforcement_contract_v1.json`.

Smoke gate:
`scripts/e2e/typed_persistence_enforcement_contract_smoke.sh`.

No-mock drill:
`scripts/e2e/typed_persistence_no_mock_drill.sh`.

Truth gate:
`scripts/e2e/typed_persistence_truth_gate.sh`.

## Stores In Scope

The enforcement contract applies only to the typed-heavy stores that the
inventory already marks `sqlmodel_rust on frankensqlite`:

- replacement lineage log
- IFC provenance index
- specialization index
- fleet trust state

These correspond to:

- `StoreKind::ReplacementLineage` -> `ReplacementLineageEntry`
- `StoreKind::IfcProvenance` -> `IfcProvenanceEntry`
- `StoreKind::SpecializationIndex` -> `SpecializationIndexEntry`
- `StoreKind::FleetTrustState` -> `FleetTrustStateEntry`

The contract does not require rewriting unrelated `raw frankensqlite` stores
such as replay index, evidence index, benchmark ledger, policy cache, or PLAS
witness storage.

## Required End State

Primary authoritative writes and reads for the four stores above must use the
typed boundary built around `TypedStoreRecord` and `TypedStorageAdapterExt`.
That means future implementation beads must treat the typed helpers as the
authoritative path for normal store mutations and lookups, not as optional
demonstration helpers.

Generic `StorageAdapter` operations for these typed-heavy stores must become non-authoritative.
They may remain available only where they are explicitly
needed for deterministic migration planning, low-level test fixtures, or
carefully bounded compatibility shims that do not bypass typed schema
validation.

Fleet trust state has a stricter mutation rule than the other typed-heavy
stores. `put_typed`, `put_typed_batch`, generic `compare_and_swap`, and delete
must all fail closed for `StoreKind::FleetTrustState`. Its only mutation path is
the specialized `FleetVerificationRegistryPersistence` revision-plus-prior-hash
CAS, guarded by an opaque transition-bound authorization token. The external
monotonic or quorum authority first prepares an authenticated old-to-new permit
without advancing. The surface persists that permit with the complete staged
snapshot, idempotently finalizes the external anchor, and only then permits live
publication. Restart can resume finalization from the authenticated persisted
permit after a lost process or response without trusting the database as
authority.
Backends without one transactional CAS must reject the operation; a read then
write emulation is forbidden.
The fleet model and its `fleet_trust_state_create_table_sql` bootstrap are
therefore excluded from the generic typed-session DDL and unit-of-work writer.
The current generic `FrankensqliteBackend` default remains fail closed. The
specialized `FleetTrustStateFrankensqliteStorageAdapter` is the only in-tree
override: it owns a private sibling-backed connection, creates only
`fleet_trust_state`, maps the exactly-one-transition registry generation to the
fixed-width durable store revision, and executes bootstrap or advance as one
affected-row-count statement predicated on both revision and snapshot hash.
Its generic put, batch, delete, query, and ordinary CAS backend operations all
reject. FrankenEngine does not set WAL, synchronous, journal, or migration
policy; opening delegates those settings to FrankenSQLite. That delegation is
not yet a production authority durability contract: the currently exposed
generic SQLModel file open uses NORMAL/deferred WAL synchronization and lacks
strict multi-process, identity-bound admission plus atomic authority-profile
initialization. Same-connection exact readback does not prove stable-media
per-commit durability. `bd-q8x8x.9.1` tracks the required sibling-owned strict
durability/open API. The real in-memory driver tests prove the statement-level
CAS, while `bd-q8x8x.9.2` tracks retained-file true subprocess crash,
simultaneous cross-process CAS, lost-response recovery, and stale/fork rollback
proof. Both blockers must close before `bd-q8x8x.9` can close.
The current adapter probes cardinality and byte lengths with `octet_length`
before selecting the complete singleton and repeats the predicates during that
selection. A sibling streaming or metadata-only bound is still required to
make hostile oversized on-disk rows a hard pre-allocation ingress guarantee;
that gap is part of `bd-q8x8x.9.1`.

Legacy `StoreRecord` inputs are allowed only for explicit lossless backfill planning
and store-specific mapping. Implicit acceptance of untyped or
partially typed envelopes is forbidden. Ambiguous legacy data must fail closed.

## Current Evidence Inputs

Current in-tree evidence that this track must build on:

- `typed_persistence_models.rs` defines `TypedStoreRecord`, typed models for
  the four stores, explicit lossless legacy mappers for pre-existing stores, and
  `plan_typed_store_backfill`; fleet schema bootstrap is isolated from its
  generic typed-session bootstrap.
- `storage_adapter.rs` maps the four store kinds to
  `sqlmodel_rust::*Entry` integration points.
- `replacement_lineage_log.rs`, `ifc_provenance_index.rs`, and
  `specialization_index.rs` already expose typed helper entrypoints alongside
  their still-generic primary paths.

This contract is intentionally truthful about the current seam: typed evidence
exists today, but end-to-end boundary enforcement is not yet complete.

## Evidence Requirements

The full track is not complete until future beads prove all of the following:

- the four primary store surfaces route normal writes through typed entries or,
  for fleet trust state, its stricter opaque-authorized revision CAS
- the four primary store surfaces route authoritative reads through typed
  lookups or typed queries
- unsupported legacy rows are rejected with deterministic fail-closed errors
- generic authority is blocked for these stores when it would bypass typed
  schema validation
- fleet live state cannot advance before its complete snapshot is durable and
  its external rollback-anchor claim is authenticated
- no-mock end-to-end proof exercises the real stores and migration-planning
  seams together

## No-Mock Drill

Run the composed typed-persistence proof with:

```bash
bash scripts/e2e/typed_persistence_no_mock_drill.sh check
bash scripts/e2e/typed_persistence_no_mock_drill.sh selftest
```

The drill is fixture-fed, proof-only, and advisory-only. It reads the checked-in
suite at `scripts/testdata/typed_persistence_no_mock_drill/cases.json` together
with the real store and guard surfaces:

- `crates/franken-engine/src/replacement_lineage_log.rs`
- `crates/franken-engine/src/ifc_provenance_index.rs`
- `crates/franken-engine/src/specialization_index.rs`
- `crates/franken-engine/src/storage_adapter.rs`
- `crates/franken-engine/src/typed_persistence_models.rs`

It covers four exact proof categories:

- healthy typed writes
- supported lossless legacy backfill planning
- unsupported legacy rejection
- generic-authority rejection

The drill does not run Cargo or RCH.
The drill does not mutate live storage.
The drill does not update, reopen, close, or reassign beads.
The drill does not release file reservations.
The drill does not send Agent Mail.
The drill does not query live Agent Mail.

Artifacts written by the drill:

- `typed_persistence_no_mock_drill_report.json`
- `case_results.jsonl`
- `commands.txt`
- `events.jsonl`
- `report.md`

## Truth Gate

Run the truth gate whenever this contract, the suite, or the drill changes:

```bash
bash scripts/e2e/typed_persistence_truth_gate.sh check
bash scripts/e2e/typed_persistence_truth_gate.sh selftest
```

The truth gate reruns the drill over the checked-in fixtures and rejects:

- forbidden wording that claims implicit legacy acceptance
- forbidden wording that restores generic authority to authoritative status
- forbidden wording that claims the drill runs Cargo or RCH
- forbidden wording that claims the drill mutates live storage, beads, reservations, or Agent Mail
- contract drift that removes one of the four proof categories

## Smoke Harness

Use the repo-local smoke harness for the full shell/docs/testdata surface:

```bash
bash scripts/e2e/typed_persistence_no_mock_drill_smoke.sh check
bash scripts/e2e/typed_persistence_no_mock_drill_smoke.sh selftest
```

## Validation

```bash
bash -n scripts/e2e/typed_persistence_enforcement_contract_smoke.sh
shellcheck -x scripts/e2e/typed_persistence_enforcement_contract_smoke.sh
jq empty docs/typed_persistence_enforcement_contract_v1.json
bash scripts/e2e/typed_persistence_enforcement_contract_smoke.sh check
bash scripts/e2e/typed_persistence_enforcement_contract_smoke.sh selftest
bash -n scripts/e2e/typed_persistence_no_mock_drill.sh scripts/e2e/typed_persistence_truth_gate.sh scripts/e2e/typed_persistence_no_mock_drill_smoke.sh
shellcheck -x scripts/e2e/typed_persistence_no_mock_drill.sh scripts/e2e/typed_persistence_truth_gate.sh scripts/e2e/typed_persistence_no_mock_drill_smoke.sh
jq empty scripts/testdata/typed_persistence_no_mock_drill/cases.json
bash scripts/e2e/typed_persistence_no_mock_drill_smoke.sh check
bash scripts/e2e/typed_persistence_no_mock_drill_smoke.sh selftest
git diff --check -- docs/TYPED_PERSISTENCE_ENFORCEMENT_CONTRACT.md docs/typed_persistence_enforcement_contract_v1.json scripts/e2e/typed_persistence_enforcement_contract_smoke.sh
```
