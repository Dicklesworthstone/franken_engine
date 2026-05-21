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

### ❌ ISSUE 1: PlasWitness Integration Point Mismatch

**Problem:** FRANKENSQLITE_PERSISTENCE_INVENTORY.md lists PLAS witness store as "sqlmodel_rust on frankensqlite", but storage_adapter.rs implements it as raw frankensqlite.

**Code Evidence:**
```rust
// storage_adapter.rs:75
Self::PlasWitness => "frankensqlite::analysis::plas_witness",
```

**Expected vs Actual:**
- Inventory says: "sqlmodel_rust on frankensqlite" 
- Code implements: "frankensqlite::analysis::plas_witness" (raw)
- is_typed_heavy_store(): PlasWitness NOT included

**Resolution Required:** Either update inventory to list PlasWitness as "raw frankensqlite" OR implement typed model + integration point.

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
- `ProofEvidenceIndexEntry` - Exists but store integration unclear ⚠️

All typed models include proper:
- `TypedStoreRecord` trait implementation
- SQLModel `#[derive(Model)]` decoration
- Validation methods and metadata extraction
- Legacy record mapping functions

## Recommendations

1. **Immediate**: Resolve PlasWitness inventory/code mismatch by updating FRANKENSQLITE_PERSISTENCE_INVENTORY.md model layer from "sqlmodel_rust" to "raw frankensqlite"

2. **Design clarity**: Clarify EvidenceIndex vs ProofEvidenceIndexEntry relationship - are these meant to be the same store with different access patterns?

3. **Documentation**: Add inline comments to storage_adapter.rs explaining why certain stores are typed-heavy vs raw frankensqlite

## Audit Compliance

✅ **PASS**: Primary inventory requirement met  
✅ **PASS**: No unauthorized generic StoreRecord usage  
❌ **FAIL**: Inventory consistency (PlasWitness mismatch)  
⚠️ **REVIEW**: EvidenceIndex design clarity needed

**Overall Status: SUBSTANTIALLY COMPLIANT** with 1 documentation fix required.