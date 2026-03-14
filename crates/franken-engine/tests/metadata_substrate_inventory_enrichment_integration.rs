#![forbid(unsafe_code)]

//! Enrichment integration tests for metadata_substrate_inventory module.

use std::collections::BTreeSet;

use frankenengine_engine::metadata_substrate_inventory::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn make_contract(kind: MetadataStructureKind, substrate: SubstrateKind) -> SubstrateContract {
    SubstrateContract::new(
        kind,
        substrate,
        LocalityGoal::L1Hot,
        FallbackMode::LinearScan,
        RollbackRule::Immutable,
        1024,
        500_000,
    )
}

fn make_assignment(kind: MetadataStructureKind, substrate: SubstrateKind) -> SubstrateAssignment {
    SubstrateAssignment {
        contract: make_contract(kind, substrate),
        assigned_epoch: epoch(),
        rationale: format!("test assignment for {kind}"),
        confidence_millionths: 900_000,
    }
}

// ── MetadataStructureKind ───────────────────────────────────────────────

#[test]
fn enrichment_structure_kind_copy_semantics() {
    let a = MetadataStructureKind::ShapeTable;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_structure_kind_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for v in MetadataStructureKind::ALL {
        assert!(set.insert(*v));
    }
    assert_eq!(set.len(), 10);
    for v in MetadataStructureKind::ALL {
        assert!(!set.insert(*v));
    }
}

#[test]
fn enrichment_structure_kind_debug_all_unique() {
    let debugs: BTreeSet<String> = MetadataStructureKind::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(debugs.len(), 10);
}

#[test]
fn enrichment_structure_kind_display_all_unique() {
    let displays: BTreeSet<String> = MetadataStructureKind::ALL
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(displays.len(), 10);
}

// ── SubstrateKind ───────────────────────────────────────────────────────

#[test]
fn enrichment_substrate_kind_copy_semantics() {
    let a = SubstrateKind::SwissTable;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_substrate_kind_btreeset_dedup() {
    let all = [
        SubstrateKind::FlatArray,
        SubstrateKind::SwissTable,
        SubstrateKind::ArtTree,
        SubstrateKind::HashArray,
        SubstrateKind::Swizzled,
        SubstrateKind::CacheOblivious,
        SubstrateKind::LinearProbe,
        SubstrateKind::BTreeIndex,
    ];
    let mut set = BTreeSet::new();
    for v in &all {
        assert!(set.insert(*v));
    }
    assert_eq!(set.len(), 8);
}

#[test]
fn enrichment_substrate_kind_debug_all_unique() {
    let all = [
        SubstrateKind::FlatArray,
        SubstrateKind::SwissTable,
        SubstrateKind::ArtTree,
        SubstrateKind::HashArray,
        SubstrateKind::Swizzled,
        SubstrateKind::CacheOblivious,
        SubstrateKind::LinearProbe,
        SubstrateKind::BTreeIndex,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 8);
}

#[test]
fn enrichment_substrate_kind_display_all_unique() {
    let all = [
        SubstrateKind::FlatArray,
        SubstrateKind::SwissTable,
        SubstrateKind::ArtTree,
        SubstrateKind::HashArray,
        SubstrateKind::Swizzled,
        SubstrateKind::CacheOblivious,
        SubstrateKind::LinearProbe,
        SubstrateKind::BTreeIndex,
    ];
    let displays: BTreeSet<String> = all.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 8);
}

// ── LocalityGoal ────────────────────────────────────────────────────────

#[test]
fn enrichment_locality_goal_copy_semantics() {
    let a = LocalityGoal::L1Hot;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_locality_goal_btreeset_dedup() {
    let all = [
        LocalityGoal::L1Hot,
        LocalityGoal::L2Warm,
        LocalityGoal::L3Cold,
        LocalityGoal::DramResident,
        LocalityGoal::Evictable,
    ];
    let mut set = BTreeSet::new();
    for v in &all {
        assert!(set.insert(*v));
    }
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_locality_goal_debug_all_unique() {
    let all = [
        LocalityGoal::L1Hot,
        LocalityGoal::L2Warm,
        LocalityGoal::L3Cold,
        LocalityGoal::DramResident,
        LocalityGoal::Evictable,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 5);
}

#[test]
fn enrichment_locality_goal_display_all_unique() {
    let all = [
        LocalityGoal::L1Hot,
        LocalityGoal::L2Warm,
        LocalityGoal::L3Cold,
        LocalityGoal::DramResident,
        LocalityGoal::Evictable,
    ];
    let displays: BTreeSet<String> = all.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 5);
}

// ── FallbackMode ────────────────────────────────────────────────────────

#[test]
fn enrichment_fallback_mode_copy_semantics() {
    let a = FallbackMode::Rehash;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_fallback_mode_btreeset_dedup() {
    let all = [
        FallbackMode::LinearScan,
        FallbackMode::Rehash,
        FallbackMode::Deoptimize,
        FallbackMode::Recompile,
        FallbackMode::Abstain,
    ];
    let mut set = BTreeSet::new();
    for v in &all {
        assert!(set.insert(*v));
    }
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_fallback_mode_debug_all_unique() {
    let all = [
        FallbackMode::LinearScan,
        FallbackMode::Rehash,
        FallbackMode::Deoptimize,
        FallbackMode::Recompile,
        FallbackMode::Abstain,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 5);
}

#[test]
fn enrichment_fallback_mode_display_all_unique() {
    let all = [
        FallbackMode::LinearScan,
        FallbackMode::Rehash,
        FallbackMode::Deoptimize,
        FallbackMode::Recompile,
        FallbackMode::Abstain,
    ];
    let displays: BTreeSet<String> = all.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 5);
}

// ── RollbackRule ────────────────────────────────────────────────────────

#[test]
fn enrichment_rollback_rule_copy_semantics() {
    let a = RollbackRule::EpochFenced;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_rollback_rule_btreeset_dedup() {
    let all = [
        RollbackRule::Immutable,
        RollbackRule::SnapshottedCow,
        RollbackRule::EpochFenced,
        RollbackRule::Rebuilds,
        RollbackRule::NoRollback,
    ];
    let mut set = BTreeSet::new();
    for v in &all {
        assert!(set.insert(*v));
    }
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_rollback_rule_debug_all_unique() {
    let all = [
        RollbackRule::Immutable,
        RollbackRule::SnapshottedCow,
        RollbackRule::EpochFenced,
        RollbackRule::Rebuilds,
        RollbackRule::NoRollback,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 5);
}

#[test]
fn enrichment_rollback_rule_display_all_unique() {
    let all = [
        RollbackRule::Immutable,
        RollbackRule::SnapshottedCow,
        RollbackRule::EpochFenced,
        RollbackRule::Rebuilds,
        RollbackRule::NoRollback,
    ];
    let displays: BTreeSet<String> = all.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 5);
}

// ── MetadataSubstrateSpecimenFamily ─────────────────────────────────────

#[test]
fn enrichment_specimen_family_copy_semantics() {
    let a = MetadataSubstrateSpecimenFamily::ShapeTable;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_specimen_family_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for v in MetadataSubstrateSpecimenFamily::ALL {
        assert!(set.insert(*v));
    }
    assert_eq!(set.len(), 10);
}

#[test]
fn enrichment_specimen_family_debug_all_unique() {
    let debugs: BTreeSet<String> = MetadataSubstrateSpecimenFamily::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(debugs.len(), 10);
}

#[test]
fn enrichment_specimen_family_display_all_unique() {
    let displays: BTreeSet<String> = MetadataSubstrateSpecimenFamily::ALL
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(displays.len(), 10);
}

#[test]
fn enrichment_specimen_family_bijection_with_structure_kind() {
    for kind in MetadataStructureKind::ALL {
        let family = MetadataSubstrateSpecimenFamily::from_structure_kind(*kind);
        assert_eq!(family.to_string(), kind.to_string());
    }
    // And families count matches
    assert_eq!(
        MetadataSubstrateSpecimenFamily::ALL.len(),
        MetadataStructureKind::ALL.len()
    );
}

#[test]
fn enrichment_specimen_family_serde_roundtrip() {
    for v in MetadataSubstrateSpecimenFamily::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: MetadataSubstrateSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ── SubstrateContract ───────────────────────────────────────────────────

#[test]
fn enrichment_contract_clone_independence() {
    let a = make_contract(MetadataStructureKind::ShapeTable, SubstrateKind::SwissTable);
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_contract_json_field_names() {
    let c = make_contract(MetadataStructureKind::ShapeTable, SubstrateKind::SwissTable);
    let v: serde_json::Value = serde_json::to_value(&c).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "structure_kind",
        "substrate_kind",
        "locality_goal",
        "fallback_mode",
        "rollback_rule",
        "max_entry_count",
        "expected_hot_fraction_millionths",
        "content_hash",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 8);
}

#[test]
fn enrichment_contract_debug_nonempty() {
    let c = make_contract(MetadataStructureKind::ShapeTable, SubstrateKind::SwissTable);
    let d = format!("{c:?}");
    assert!(!d.is_empty());
    assert!(d.contains("SubstrateContract"));
}

#[test]
fn enrichment_contract_display_contains_components() {
    let c = make_contract(MetadataStructureKind::StringTable, SubstrateKind::ArtTree);
    let s = c.to_string();
    assert!(s.contains("string_table"));
    assert!(s.contains("art_tree"));
    assert!(s.contains("l1_hot"));
    assert!(s.contains("linear_scan"));
    assert!(s.contains("immutable"));
}

#[test]
fn enrichment_contract_hash_changes_with_locality_goal() {
    let a = SubstrateContract::new(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
        LocalityGoal::L1Hot,
        FallbackMode::LinearScan,
        RollbackRule::Immutable,
        1024,
        500_000,
    );
    let b = SubstrateContract::new(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
        LocalityGoal::L3Cold,
        FallbackMode::LinearScan,
        RollbackRule::Immutable,
        1024,
        500_000,
    );
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_contract_hash_changes_with_max_entry_count() {
    let a = SubstrateContract::new(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
        LocalityGoal::L1Hot,
        FallbackMode::LinearScan,
        RollbackRule::Immutable,
        1024,
        500_000,
    );
    let b = SubstrateContract::new(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
        LocalityGoal::L1Hot,
        FallbackMode::LinearScan,
        RollbackRule::Immutable,
        2048,
        500_000,
    );
    assert_ne!(a.content_hash, b.content_hash);
}

// ── SubstrateAssignment ─────────────────────────────────────────────────

#[test]
fn enrichment_assignment_clone_independence() {
    let a = make_assignment(MetadataStructureKind::ShapeTable, SubstrateKind::SwissTable);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_assignment_json_field_names() {
    let a = make_assignment(MetadataStructureKind::ShapeTable, SubstrateKind::SwissTable);
    let v: serde_json::Value = serde_json::to_value(&a).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "contract",
        "assigned_epoch",
        "rationale",
        "confidence_millionths",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 4);
}

#[test]
fn enrichment_assignment_debug_nonempty() {
    let a = make_assignment(MetadataStructureKind::ShapeTable, SubstrateKind::SwissTable);
    let d = format!("{a:?}");
    assert!(!d.is_empty());
    assert!(d.contains("SubstrateAssignment"));
}

// ── InventoryEvidenceEntry ──────────────────────────────────────────────

#[test]
fn enrichment_evidence_entry_clone_independence() {
    let a = InventoryEvidenceEntry {
        family: MetadataStructureKind::ShapeTable,
        expected_substrate: SubstrateKind::SwissTable,
        expected_locality: LocalityGoal::L1Hot,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_evidence_entry_json_field_names() {
    let e = InventoryEvidenceEntry {
        family: MetadataStructureKind::ShapeTable,
        expected_substrate: SubstrateKind::SwissTable,
        expected_locality: LocalityGoal::L1Hot,
    };
    let v: serde_json::Value = serde_json::to_value(&e).unwrap();
    let obj = v.as_object().unwrap();
    for key in &["family", "expected_substrate", "expected_locality"] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 3);
}

#[test]
fn enrichment_evidence_entry_debug_nonempty() {
    let e = InventoryEvidenceEntry {
        family: MetadataStructureKind::ModuleGraph,
        expected_substrate: SubstrateKind::HashArray,
        expected_locality: LocalityGoal::L3Cold,
    };
    let d = format!("{e:?}");
    assert!(!d.is_empty());
    assert!(d.contains("InventoryEvidenceEntry"));
}

// ── InventoryCoverageReport ─────────────────────────────────────────────

#[test]
fn enrichment_coverage_report_clone_independence() {
    let inv = default_substrate_assignments(epoch());
    let a = inv.coverage_report();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_coverage_report_json_field_names() {
    let inv = default_substrate_assignments(epoch());
    let report = inv.coverage_report();
    let v: serde_json::Value = serde_json::to_value(&report).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "total_structure_kinds",
        "assigned_structure_kinds",
        "coverage_millionths",
        "missing_kinds",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 4);
}

#[test]
fn enrichment_coverage_report_debug_nonempty() {
    let inv = default_substrate_assignments(epoch());
    let report = inv.coverage_report();
    let d = format!("{report:?}");
    assert!(!d.is_empty());
    assert!(d.contains("InventoryCoverageReport"));
}

#[test]
fn enrichment_coverage_report_serde_roundtrip() {
    let inv = default_substrate_assignments(epoch());
    let report = inv.coverage_report();
    let json = serde_json::to_string(&report).unwrap();
    let back: InventoryCoverageReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ── SubstrateInventory ──────────────────────────────────────────────────

#[test]
fn enrichment_inventory_clone_independence() {
    let a = default_substrate_assignments(epoch());
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn enrichment_inventory_json_field_names() {
    let inv = SubstrateInventory::new();
    let v: serde_json::Value = serde_json::to_value(&inv).unwrap();
    let obj = v.as_object().unwrap();
    for key in &["assignments", "schema_version"] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 2);
}

#[test]
fn enrichment_inventory_debug_nonempty() {
    let inv = SubstrateInventory::new();
    let d = format!("{inv:?}");
    assert!(!d.is_empty());
    assert!(d.contains("SubstrateInventory"));
}

#[test]
fn enrichment_inventory_default_eq_new() {
    let a = SubstrateInventory::new();
    let b = SubstrateInventory::default();
    assert_eq!(a, b);
}

#[test]
fn enrichment_inventory_lookup_returns_empty_for_missing() {
    let inv = SubstrateInventory::new();
    for kind in MetadataStructureKind::ALL {
        assert!(inv.lookup(*kind).is_empty());
    }
}

#[test]
fn enrichment_inventory_content_hash_differs_empty_vs_full() {
    let empty = SubstrateInventory::new();
    let full = default_substrate_assignments(epoch());
    assert_ne!(empty.content_hash(), full.content_hash());
}

// ── default_substrate_assignments cross-cutting ─────────────────────────

#[test]
fn enrichment_default_assignments_all_hashes_unique() {
    let inv = default_substrate_assignments(epoch());
    let hashes: BTreeSet<Vec<u8>> = inv
        .assignments
        .iter()
        .map(|a| a.contract.content_hash.as_bytes().to_vec())
        .collect();
    assert_eq!(hashes.len(), 10);
}

#[test]
fn enrichment_default_assignments_hot_fraction_within_bounds() {
    let inv = default_substrate_assignments(epoch());
    for a in &inv.assignments {
        assert!(
            a.contract.expected_hot_fraction_millionths <= 1_000_000,
            "{}: hot fraction {} exceeds 100%",
            a.contract.structure_kind,
            a.contract.expected_hot_fraction_millionths,
        );
    }
}

#[test]
fn enrichment_default_assignments_confidence_within_bounds() {
    let inv = default_substrate_assignments(epoch());
    for a in &inv.assignments {
        assert!(
            a.confidence_millionths <= 1_000_000,
            "{}: confidence {} exceeds 100%",
            a.contract.structure_kind,
            a.confidence_millionths,
        );
        assert!(
            a.confidence_millionths > 0,
            "{}: confidence is zero",
            a.contract.structure_kind,
        );
    }
}

#[test]
fn enrichment_default_assignments_max_entry_count_positive() {
    let inv = default_substrate_assignments(epoch());
    for a in &inv.assignments {
        assert!(
            a.contract.max_entry_count > 0,
            "{}: max_entry_count is zero",
            a.contract.structure_kind,
        );
    }
}

// ── Coverage report edge cases ──────────────────────────────────────────

#[test]
fn enrichment_coverage_single_assignment() {
    let mut inv = SubstrateInventory::new();
    inv.add_assignment(make_assignment(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
    ));
    let report = inv.coverage_report();
    assert_eq!(report.assigned_structure_kinds, 1);
    assert_eq!(report.coverage_millionths, 100_000); // 1/10 = 10%
    assert_eq!(report.missing_kinds.len(), 9);
    assert!(
        !report
            .missing_kinds
            .contains(&MetadataStructureKind::ShapeTable)
    );
}

#[test]
fn enrichment_coverage_duplicate_kind_counts_once() {
    let mut inv = SubstrateInventory::new();
    inv.add_assignment(make_assignment(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
    ));
    inv.add_assignment(make_assignment(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::FlatArray,
    ));
    let report = inv.coverage_report();
    // Two assignments for same kind => still 1 assigned kind
    assert_eq!(report.assigned_structure_kinds, 1);
    assert_eq!(report.coverage_millionths, 100_000);
}

#[test]
fn enrichment_coverage_missing_kinds_sorted() {
    let mut inv = SubstrateInventory::new();
    inv.add_assignment(make_assignment(
        MetadataStructureKind::GcMetadata,
        SubstrateKind::CacheOblivious,
    ));
    let report = inv.coverage_report();
    // Missing kinds come from BTreeSet difference, so should be sorted
    for i in 1..report.missing_kinds.len() {
        assert!(report.missing_kinds[i] > report.missing_kinds[i - 1]);
    }
}

// ── Five-run determinism ────────────────────────────────────────────────

#[test]
fn enrichment_five_run_determinism_inventory_content_hash() {
    let hashes: Vec<_> = (0..5)
        .map(|_| default_substrate_assignments(epoch()).content_hash())
        .collect();
    for h in &hashes[1..] {
        assert_eq!(hashes[0], *h);
    }
}

#[test]
fn enrichment_five_run_determinism_contract_content_hash() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            make_contract(MetadataStructureKind::ShapeTable, SubstrateKind::SwissTable).content_hash
        })
        .collect();
    for h in &hashes[1..] {
        assert_eq!(hashes[0], *h);
    }
}

#[test]
fn enrichment_five_run_determinism_coverage_report() {
    let reports: Vec<_> = (0..5)
        .map(|_| default_substrate_assignments(epoch()).coverage_report())
        .collect();
    for r in &reports[1..] {
        assert_eq!(reports[0], *r);
    }
}

// ── Constants stability ─────────────────────────────────────────────────

#[test]
fn enrichment_constants_stable() {
    assert_eq!(
        METADATA_SUBSTRATE_SCHEMA_VERSION,
        "franken-engine.metadata-substrate-inventory.v1"
    );
    assert_eq!(METADATA_SUBSTRATE_BEAD_ID, "bd-1lsy.7.26.1");
    assert_eq!(COMPONENT, "metadata_substrate_inventory");
}
