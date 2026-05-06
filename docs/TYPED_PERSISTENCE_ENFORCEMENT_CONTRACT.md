# TYPED_PERSISTENCE_ENFORCEMENT_CONTRACT

This contract defines the required end state for `bd-gvnex` and the broader
`SQLMODEL-TYPED-P0` track. It records which FrankenEngine persistence stores
are inventory-mandated to use `sqlmodel_rust on frankensqlite`, what current
typed evidence already exists in-tree, and what future implementation beads
must enforce before the AGENTS.md deviation can be considered closed.

Machine-readable contract:
`docs/typed_persistence_enforcement_contract_v1.json`.

Smoke gate:
`scripts/e2e/typed_persistence_enforcement_contract_smoke.sh`.

## Stores In Scope

The enforcement contract applies only to the typed-heavy stores that the
inventory already marks `sqlmodel_rust on frankensqlite`:

- replacement lineage log
- IFC provenance index
- specialization index

These correspond to:

- `StoreKind::ReplacementLineage` -> `ReplacementLineageEntry`
- `StoreKind::IfcProvenance` -> `IfcProvenanceEntry`
- `StoreKind::SpecializationIndex` -> `SpecializationIndexEntry`

The contract does not require rewriting unrelated `raw frankensqlite` stores
such as replay index, evidence index, benchmark ledger, policy cache, or PLAS
witness storage.

## Required End State

Primary authoritative writes and reads for the three stores above must use the
typed boundary built around `TypedStoreRecord` and `TypedStorageAdapterExt`.
That means future implementation beads must treat the typed helpers as the
authoritative path for normal store mutations and lookups, not as optional
demonstration helpers.

Generic `StorageAdapter` operations for these typed-heavy stores must become non-authoritative.
They may remain available only where they are explicitly
needed for deterministic migration planning, low-level test fixtures, or
carefully bounded compatibility shims that do not bypass typed schema
validation.

Legacy `StoreRecord` inputs are allowed only for explicit lossless backfill planning
and store-specific mapping. Implicit acceptance of untyped or
partially typed envelopes is forbidden. Ambiguous legacy data must fail closed.

## Current Evidence Inputs

Current in-tree evidence that this track must build on:

- `typed_persistence_models.rs` defines `TypedStoreRecord`, typed models for
  the three stores, explicit lossless legacy mappers, and
  `plan_typed_store_backfill`.
- `storage_adapter.rs` already maps the three store kinds to
  `sqlmodel_rust::*Entry` integration points.
- `replacement_lineage_log.rs`, `ifc_provenance_index.rs`, and
  `specialization_index.rs` already expose typed helper entrypoints alongside
  their still-generic primary paths.

This contract is intentionally truthful about the current seam: typed evidence
exists today, but end-to-end boundary enforcement is not yet complete.

## Evidence Requirements

The full track is not complete until future beads prove all of the following:

- the three primary store surfaces route normal writes through typed entries
- the three primary store surfaces route authoritative reads through typed
  lookups or typed queries
- unsupported legacy rows are rejected with deterministic fail-closed errors
- generic authority is blocked for these stores when it would bypass typed
  schema validation
- no-mock end-to-end proof exercises the real stores and migration-planning
  seams together

## Validation

```bash
bash -n scripts/e2e/typed_persistence_enforcement_contract_smoke.sh
shellcheck -x scripts/e2e/typed_persistence_enforcement_contract_smoke.sh
jq empty docs/typed_persistence_enforcement_contract_v1.json
bash scripts/e2e/typed_persistence_enforcement_contract_smoke.sh check
bash scripts/e2e/typed_persistence_enforcement_contract_smoke.sh selftest
git diff --check -- docs/TYPED_PERSISTENCE_ENFORCEMENT_CONTRACT.md docs/typed_persistence_enforcement_contract_v1.json scripts/e2e/typed_persistence_enforcement_contract_smoke.sh
```
