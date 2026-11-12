# Storage Adapter FRANKENSQLITE_PERSISTENCE_INVENTORY Audit Report

**Audit Date:** 2026-05-21  
**Audited By:** SapphireRaven (bd-cixqu.12.1)  
**Scope:** storage_adapter.rs + typed_persistence_models.rs vs FRANKENSQLITE_PERSISTENCE_INVENTORY.md

## Executive Summary

Audit of storage_adapter.rs and typed_persistence_models.rs against the FRANKENSQLITE_PERSISTENCE_INVENTORY reveals 4 correctly implemented sqlmodel_rust-backed typed stores, 1 inventory inconsistency, and 1 design clarity gap. No generic StoreRecord violations found.

## Typed Store Inventory Status

### ✅ CONFIRMED sqlmodel_rust-backed stores:

1. **ShadowEvidenceJournal**
   - Integration: `sqlmodel_rust::ShadowEvidenceJournalEntry`
   - Typed Model: `ShadowEvidenceJournalEntry` 
   - Inventory: "sqlmodel_rust on frankensqlite"
   - Status: ✅ CONSISTENT

2. **ReplacementLineage** 
   - Integration: `sqlmodel_rust::ReplacementLineageEntry`
   - Typed Model: `ReplacementLineageEntry`
   - Inventory: "sqlmodel_rust on frankensqlite" 
   - Status: ✅ CONSISTENT

3. **IfcProvenance**
   - Integration: `sqlmodel_rust::IfcProvenanceEntry`
   - Typed Model: `IfcProvenanceEntry`
   - Inventory: "sqlmodel_rust on frankensqlite"
   - Status: ✅ CONSISTENT

4. **SpecializationIndex**
   - Integration: `sqlmodel_rust::SpecializationIndexEntry` 
   - Typed Model: `SpecializationIndexEntry`
   - Inventory: "sqlmodel_rust on frankensqlite"
   - Status: ✅ CONSISTENT

## Issues Identified

### ✅ RESOLVED: PlasWitness Integration Point (`bd-rc-2026-11-11-epic-g2vrp.13`)

**Resolution:** Implemented `PlasWitnessEntry` (`#[sqlmodel(table = "plas_witness")]`) with `TypedStoreRecord` (`StoreKind::PlasWitness`), updated `StoreKind::PlasWitness.integration_point()` to `"sqlmodel_rust::PlasWitnessEntry"`, added `StoreKind::PlasWitness` to `is_typed_heavy_store()`, and reconciled `FRANKENSQLITE_PERSISTENCE_INVENTORY.md` + `ADR-0004`.

### ⚠️ ISSUE 2: EvidenceIndex Model/Store Naming Confusion

**Problem:** There's a disconnect between EvidenceIndex (the store) and ProofEvidenceIndexEntry (the typed model).

**Code Evidence:**
```rust
// StoreKind::EvidenceIndex uses raw frankensqlite
Self::EvidenceIndex => "frankensqlite::control_plane::evidence_index",

// But there's also ProofEvidenceIndexEntry typed model
impl TypedStoreRecord for ProofEvidenceIndexEntry {
    const STORE_KIND: StoreKind = StoreKind::EvidenceIndex;
    const MODEL_NAME: &'static str = "ProofEvidenceIndexEntry";
}
```

**Resolution Required:** Clarify whether EvidenceIndex store should use the ProofEvidenceIndexEntry typed model or remain raw frankensqlite. Current implementation suggests parallel paths.

## Generic StoreRecord Usage

### ✅ VERIFIED: No inappropriate generic StoreRecord uses

All non-typed stores correctly use raw frankensqlite integration points:
- **ReplayIndex**: `frankensqlite::control_plane::replay_index`
- **BenchmarkLedger**: `frankensqlite::benchmark::ledger`  
- **PolicyCache**: `frankensqlite::control_plane::policy_cache`

No violations of typed-heavy store policies found in generic adapter methods.

## Typed Persistence Model Coverage

### ✅ IMPLEMENTED: All required typed models exist

From typed_persistence_models.rs analysis:
- `ReplacementLineageEntry` - Complete typed boundary ✅
- `IfcProvenanceEntry` - Complete typed boundary ✅  
- `ShadowEvidenceJournalEntry` - Complete typed boundary ✅
- `SpecializationIndexEntry` - Complete typed boundary ✅
- `PlasWitnessEntry` - Complete typed boundary ✅ (`g2vrp.13`)
- `ProofEvidenceIndexEntry` - Exists with `StoreKind::EvidenceIndex` typed boundary ✅

All typed models include proper:
- `TypedStoreRecord` trait implementation
- SQLModel `#[derive(Model)]` decoration
- Validation methods and metadata extraction
- Legacy record mapping / compatibility metadata guards

## Resolution Summary (`g2vrp.13`)

1. **Resolved**: `PlasWitness` now routes through `sqlmodel_rust::PlasWitnessEntry` (`StoreKind::PlasWitness::integration_point()`, `is_typed_heavy_store()`, `typed_heavy_expected_model()`, and `typed_heavy_payload_matches_typed_model()`), matching `docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md` and `docs/adr/ADR-0004-frankensqlite-reuse-scope.md`.
2. **Legacy index compatibility**: `WitnessIndex` multi-index key prefixes (`witnesses/`, `witness_by_id/`, `witness_by_extension/`, `witness_by_capability/`, `witness_escrow_receipts/`) use explicit `mark_typed_heavy_generic_compat_metadata` compatibility envelopes and remain non-authoritative for untyped payloads.

## Audit Compliance

✅ **PASS**: Primary inventory requirement met
✅ **PASS**: No unauthorized generic StoreRecord usage
✅ **PASS**: Inventory consistency (`PlasWitness` -> `sqlmodel_rust::PlasWitnessEntry`)

**Overall Status: COMPLIANT**
