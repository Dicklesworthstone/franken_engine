//! Integration tests for the `metadata_substrate_inventory` module.
//!
//! Covers all public enums (Display + serde roundtrip), struct construction,
//! key methods (lookup, coverage_report, content_hash), default assignments,
//! evidence entries, specimen families, and edge cases.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::metadata_substrate_inventory::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn contract(kind: MetadataStructureKind, substrate: SubstrateKind) -> SubstrateContract {
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

fn assignment(kind: MetadataStructureKind, substrate: SubstrateKind) -> SubstrateAssignment {
    SubstrateAssignment {
        contract: contract(kind, substrate),
        assigned_epoch: epoch(),
        rationale: format!("test assignment for {kind}"),
        confidence_millionths: 900_000,
    }
}

// ---------------------------------------------------------------------------
// MetadataStructureKind
// ---------------------------------------------------------------------------

#[test]
fn metadata_structure_kind_display_all_variants() {
    let expected = [
        "shape_table",
        "inline_cache_table",
        "string_table",
        "scope_chain_table",
        "module_graph",
        "prototype_chain_table",
        "type_feedback_vector",
        "compilation_cache",
        "gc_metadata",
        "allocation_site_table",
    ];
    for (kind, exp) in MetadataStructureKind::ALL.iter().zip(expected.iter()) {
        assert_eq!(kind.to_string(), *exp);
    }
}

#[test]
fn metadata_structure_kind_serde_roundtrip_all() {
    for kind in MetadataStructureKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: MetadataStructureKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn metadata_structure_kind_all_count() {
    assert_eq!(MetadataStructureKind::ALL.len(), 10);
}

#[test]
fn metadata_structure_kind_ordering_is_stable() {
    assert!(MetadataStructureKind::ShapeTable < MetadataStructureKind::InlineCacheTable);
    assert!(MetadataStructureKind::InlineCacheTable < MetadataStructureKind::AllocationSiteTable);
}

// ---------------------------------------------------------------------------
// SubstrateKind
// ---------------------------------------------------------------------------

#[test]
fn substrate_kind_display_all_variants() {
    let expected = [
        "flat_array",
        "swiss_table",
        "art_tree",
        "hash_array",
        "swizzled",
        "cache_oblivious",
        "linear_probe",
        "btree_index",
    ];
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
    for (kind, exp) in all.iter().zip(expected.iter()) {
        assert_eq!(kind.to_string(), *exp);
    }
}

#[test]
fn substrate_kind_serde_roundtrip_all() {
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
    for kind in &all {
        let json = serde_json::to_string(kind).unwrap();
        let back: SubstrateKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ---------------------------------------------------------------------------
// LocalityGoal
// ---------------------------------------------------------------------------

#[test]
fn locality_goal_display_all() {
    let expected = ["l1_hot", "l2_warm", "l3_cold", "dram_resident", "evictable"];
    let all = [
        LocalityGoal::L1Hot,
        LocalityGoal::L2Warm,
        LocalityGoal::L3Cold,
        LocalityGoal::DramResident,
        LocalityGoal::Evictable,
    ];
    for (goal, exp) in all.iter().zip(expected.iter()) {
        assert_eq!(goal.to_string(), *exp);
    }
}

#[test]
fn locality_goal_serde_roundtrip() {
    let all = [
        LocalityGoal::L1Hot,
        LocalityGoal::L2Warm,
        LocalityGoal::L3Cold,
        LocalityGoal::DramResident,
        LocalityGoal::Evictable,
    ];
    for goal in &all {
        let json = serde_json::to_string(goal).unwrap();
        let back: LocalityGoal = serde_json::from_str(&json).unwrap();
        assert_eq!(*goal, back);
    }
}

// ---------------------------------------------------------------------------
// FallbackMode
// ---------------------------------------------------------------------------

#[test]
fn fallback_mode_display_all() {
    let expected = [
        "linear_scan",
        "rehash",
        "deoptimize",
        "recompile",
        "abstain",
    ];
    let all = [
        FallbackMode::LinearScan,
        FallbackMode::Rehash,
        FallbackMode::Deoptimize,
        FallbackMode::Recompile,
        FallbackMode::Abstain,
    ];
    for (mode, exp) in all.iter().zip(expected.iter()) {
        assert_eq!(mode.to_string(), *exp);
    }
}

#[test]
fn fallback_mode_serde_roundtrip() {
    let all = [
        FallbackMode::LinearScan,
        FallbackMode::Rehash,
        FallbackMode::Deoptimize,
        FallbackMode::Recompile,
        FallbackMode::Abstain,
    ];
    for mode in &all {
        let json = serde_json::to_string(mode).unwrap();
        let back: FallbackMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, back);
    }
}

// ---------------------------------------------------------------------------
// RollbackRule
// ---------------------------------------------------------------------------

#[test]
fn rollback_rule_display_all() {
    let expected = [
        "immutable",
        "snapshotted_cow",
        "epoch_fenced",
        "rebuilds",
        "no_rollback",
    ];
    let all = [
        RollbackRule::Immutable,
        RollbackRule::SnapshottedCow,
        RollbackRule::EpochFenced,
        RollbackRule::Rebuilds,
        RollbackRule::NoRollback,
    ];
    for (rule, exp) in all.iter().zip(expected.iter()) {
        assert_eq!(rule.to_string(), *exp);
    }
}

#[test]
fn rollback_rule_serde_roundtrip() {
    let all = [
        RollbackRule::Immutable,
        RollbackRule::SnapshottedCow,
        RollbackRule::EpochFenced,
        RollbackRule::Rebuilds,
        RollbackRule::NoRollback,
    ];
    for rule in &all {
        let json = serde_json::to_string(rule).unwrap();
        let back: RollbackRule = serde_json::from_str(&json).unwrap();
        assert_eq!(*rule, back);
    }
}

// ---------------------------------------------------------------------------
// SubstrateContract
// ---------------------------------------------------------------------------

#[test]
fn substrate_contract_construction_and_fields() {
    let c = contract(MetadataStructureKind::ShapeTable, SubstrateKind::SwissTable);
    assert_eq!(c.structure_kind, MetadataStructureKind::ShapeTable);
    assert_eq!(c.substrate_kind, SubstrateKind::SwissTable);
    assert_eq!(c.locality_goal, LocalityGoal::L1Hot);
    assert_eq!(c.fallback_mode, FallbackMode::LinearScan);
    assert_eq!(c.rollback_rule, RollbackRule::Immutable);
    assert_eq!(c.max_entry_count, 1024);
    assert_eq!(c.expected_hot_fraction_millionths, 500_000);
}

#[test]
fn substrate_contract_serde_roundtrip() {
    let c = contract(
        MetadataStructureKind::InlineCacheTable,
        SubstrateKind::FlatArray,
    );
    let json = serde_json::to_string(&c).unwrap();
    let back: SubstrateContract = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn substrate_contract_content_hash_determinism() {
    let c1 = contract(MetadataStructureKind::StringTable, SubstrateKind::ArtTree);
    let c2 = contract(MetadataStructureKind::StringTable, SubstrateKind::ArtTree);
    assert_eq!(c1.content_hash, c2.content_hash);
}

#[test]
fn substrate_contract_different_params_different_hash() {
    let c1 = contract(MetadataStructureKind::ShapeTable, SubstrateKind::SwissTable);
    let c2 = contract(MetadataStructureKind::StringTable, SubstrateKind::ArtTree);
    assert_ne!(c1.content_hash, c2.content_hash);
}

#[test]
fn substrate_contract_display_contains_fields() {
    let c = contract(
        MetadataStructureKind::GcMetadata,
        SubstrateKind::CacheOblivious,
    );
    let s = c.to_string();
    assert!(s.contains("gc_metadata"));
    assert!(s.contains("cache_oblivious"));
    assert!(s.contains("l1_hot"));
    assert!(s.contains("linear_scan"));
    assert!(s.contains("immutable"));
}

// ---------------------------------------------------------------------------
// SubstrateAssignment
// ---------------------------------------------------------------------------

#[test]
fn substrate_assignment_construction() {
    let a = assignment(MetadataStructureKind::ModuleGraph, SubstrateKind::HashArray);
    assert_eq!(
        a.contract.structure_kind,
        MetadataStructureKind::ModuleGraph
    );
    assert_eq!(a.assigned_epoch, epoch());
    assert_eq!(a.confidence_millionths, 900_000);
    assert!(!a.rationale.is_empty());
}

#[test]
fn substrate_assignment_serde_roundtrip() {
    let a = assignment(
        MetadataStructureKind::ScopeChainTable,
        SubstrateKind::BTreeIndex,
    );
    let json = serde_json::to_string(&a).unwrap();
    let back: SubstrateAssignment = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn substrate_assignment_display_contains_kind() {
    let a = assignment(
        MetadataStructureKind::PrototypeChainTable,
        SubstrateKind::LinearProbe,
    );
    let s = a.to_string();
    assert!(s.contains("prototype_chain_table"));
}

// ---------------------------------------------------------------------------
// SubstrateInventory
// ---------------------------------------------------------------------------

#[test]
fn inventory_new_is_empty() {
    let inv = SubstrateInventory::new();
    assert!(inv.assignments.is_empty());
    assert_eq!(inv.schema_version, METADATA_SUBSTRATE_SCHEMA_VERSION);
}

#[test]
fn inventory_default_trait() {
    let inv = SubstrateInventory::default();
    assert!(inv.assignments.is_empty());
    assert_eq!(inv.schema_version, METADATA_SUBSTRATE_SCHEMA_VERSION);
}

#[test]
fn inventory_add_and_lookup() {
    let mut inv = SubstrateInventory::new();
    inv.add_assignment(assignment(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
    ));
    inv.add_assignment(assignment(
        MetadataStructureKind::StringTable,
        SubstrateKind::ArtTree,
    ));

    let shapes = inv.lookup(MetadataStructureKind::ShapeTable);
    assert_eq!(shapes.len(), 1);
    assert_eq!(shapes[0].contract.substrate_kind, SubstrateKind::SwissTable);

    let empty = inv.lookup(MetadataStructureKind::GcMetadata);
    assert!(empty.is_empty());
}

#[test]
fn inventory_lookup_multiple_same_kind() {
    let mut inv = SubstrateInventory::new();
    inv.add_assignment(assignment(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
    ));
    inv.add_assignment(assignment(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::FlatArray,
    ));
    let results = inv.lookup(MetadataStructureKind::ShapeTable);
    assert_eq!(results.len(), 2);
}

#[test]
fn inventory_serde_roundtrip() {
    let inv = default_substrate_assignments(epoch());
    let json = serde_json::to_string(&inv).unwrap();
    let back: SubstrateInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

#[test]
fn inventory_content_hash_determinism() {
    let inv1 = default_substrate_assignments(epoch());
    let inv2 = default_substrate_assignments(epoch());
    assert_eq!(inv1.content_hash(), inv2.content_hash());
}

#[test]
fn inventory_content_hash_changes_with_additions() {
    let inv1 = default_substrate_assignments(epoch());
    let h1 = inv1.content_hash();
    let mut inv2 = default_substrate_assignments(epoch());
    inv2.add_assignment(assignment(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::FlatArray,
    ));
    let h2 = inv2.content_hash();
    assert_ne!(h1, h2);
}

#[test]
fn inventory_display_contains_count() {
    let inv = default_substrate_assignments(epoch());
    let s = inv.to_string();
    assert!(s.contains("SubstrateInventory"));
    assert!(s.contains("10"));
}

// ---------------------------------------------------------------------------
// Coverage report
// ---------------------------------------------------------------------------

#[test]
fn coverage_report_empty_inventory() {
    let inv = SubstrateInventory::new();
    let report = inv.coverage_report();
    assert_eq!(report.total_structure_kinds, 10);
    assert_eq!(report.assigned_structure_kinds, 0);
    assert_eq!(report.coverage_millionths, 0);
    assert_eq!(report.missing_kinds.len(), 10);
}

#[test]
fn coverage_report_partial() {
    let mut inv = SubstrateInventory::new();
    inv.add_assignment(assignment(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
    ));
    inv.add_assignment(assignment(
        MetadataStructureKind::StringTable,
        SubstrateKind::ArtTree,
    ));
    let report = inv.coverage_report();
    assert_eq!(report.assigned_structure_kinds, 2);
    assert_eq!(report.coverage_millionths, 200_000);
    assert_eq!(report.missing_kinds.len(), 8);
    assert!(
        !report
            .missing_kinds
            .contains(&MetadataStructureKind::ShapeTable)
    );
}

#[test]
fn coverage_report_full() {
    let inv = default_substrate_assignments(epoch());
    let report = inv.coverage_report();
    assert_eq!(report.assigned_structure_kinds, 10);
    assert_eq!(report.coverage_millionths, 1_000_000);
    assert!(report.missing_kinds.is_empty());
}

#[test]
fn coverage_report_display() {
    let inv = default_substrate_assignments(epoch());
    let report = inv.coverage_report();
    let s = report.to_string();
    assert!(s.contains("InventoryCoverageReport"));
    assert!(s.contains("10/10"));
}

#[test]
fn coverage_report_serde_roundtrip() {
    let inv = default_substrate_assignments(epoch());
    let report = inv.coverage_report();
    let json = serde_json::to_string(&report).unwrap();
    let back: InventoryCoverageReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// default_substrate_assignments
// ---------------------------------------------------------------------------

#[test]
fn default_assignments_cover_all_kinds() {
    let inv = default_substrate_assignments(epoch());
    assert_eq!(inv.assignments.len(), 10);
    let mut seen = std::collections::BTreeSet::new();
    for a in &inv.assignments {
        seen.insert(a.contract.structure_kind);
    }
    for kind in MetadataStructureKind::ALL {
        assert!(seen.contains(kind), "Missing assignment for {kind}");
    }
}

#[test]
fn default_assignments_epoch_propagation() {
    let ep = SecurityEpoch::from_raw(42);
    let inv = default_substrate_assignments(ep);
    for a in &inv.assignments {
        assert_eq!(a.assigned_epoch, ep);
    }
}

#[test]
fn default_assignments_confidence_positive() {
    let inv = default_substrate_assignments(epoch());
    for a in &inv.assignments {
        assert!(a.confidence_millionths > 0);
    }
}

#[test]
fn default_assignments_rationale_nonempty() {
    let inv = default_substrate_assignments(epoch());
    for a in &inv.assignments {
        assert!(!a.rationale.is_empty());
    }
}

// ---------------------------------------------------------------------------
// MetadataSubstrateSpecimenFamily
// ---------------------------------------------------------------------------

#[test]
fn specimen_family_all_count() {
    assert_eq!(MetadataSubstrateSpecimenFamily::ALL.len(), 10);
}

#[test]
fn specimen_family_from_structure_kind_mapping() {
    for kind in MetadataStructureKind::ALL {
        let family = MetadataSubstrateSpecimenFamily::from_structure_kind(*kind);
        assert_eq!(family.to_string(), kind.to_string());
    }
}

#[test]
fn specimen_family_display_samples() {
    assert_eq!(
        MetadataSubstrateSpecimenFamily::ShapeTable.to_string(),
        "shape_table"
    );
    assert_eq!(
        MetadataSubstrateSpecimenFamily::GcMetadata.to_string(),
        "gc_metadata"
    );
    assert_eq!(
        MetadataSubstrateSpecimenFamily::AllocationSiteTable.to_string(),
        "allocation_site_table"
    );
}

#[test]
fn specimen_family_serde_roundtrip() {
    for fam in MetadataSubstrateSpecimenFamily::ALL {
        let json = serde_json::to_string(fam).unwrap();
        let back: MetadataSubstrateSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*fam, back);
    }
}

// ---------------------------------------------------------------------------
// InventoryEvidenceEntry
// ---------------------------------------------------------------------------

#[test]
fn evidence_entry_construction_and_display() {
    let entry = InventoryEvidenceEntry {
        family: MetadataStructureKind::ShapeTable,
        expected_substrate: SubstrateKind::SwissTable,
        expected_locality: LocalityGoal::L1Hot,
    };
    let s = entry.to_string();
    assert!(s.contains("shape_table"));
    assert!(s.contains("swiss_table"));
    assert!(s.contains("l1_hot"));
}

#[test]
fn evidence_entry_serde_roundtrip() {
    let entry = InventoryEvidenceEntry {
        family: MetadataStructureKind::ModuleGraph,
        expected_substrate: SubstrateKind::HashArray,
        expected_locality: LocalityGoal::L3Cold,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: InventoryEvidenceEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_constant() {
    assert!(METADATA_SUBSTRATE_SCHEMA_VERSION.contains("metadata-substrate-inventory"));
    assert!(METADATA_SUBSTRATE_SCHEMA_VERSION.contains(".v1"));
}

#[test]
fn bead_id_constant() {
    assert_eq!(METADATA_SUBSTRATE_BEAD_ID, "bd-1lsy.7.26.1");
}

#[test]
fn component_constant() {
    assert_eq!(COMPONENT, "metadata_substrate_inventory");
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn contract_max_entry_count_zero() {
    let c = SubstrateContract::new(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
        LocalityGoal::L1Hot,
        FallbackMode::LinearScan,
        RollbackRule::Immutable,
        0,
        0,
    );
    assert_eq!(c.max_entry_count, 0);
    assert_eq!(c.expected_hot_fraction_millionths, 0);
}

#[test]
fn contract_max_hot_fraction() {
    let c = SubstrateContract::new(
        MetadataStructureKind::InlineCacheTable,
        SubstrateKind::FlatArray,
        LocalityGoal::L1Hot,
        FallbackMode::Deoptimize,
        RollbackRule::Rebuilds,
        u64::MAX,
        1_000_000,
    );
    assert_eq!(c.expected_hot_fraction_millionths, 1_000_000);
}

#[test]
fn inventory_lookup_nonexistent_kind() {
    let mut inv = SubstrateInventory::new();
    inv.add_assignment(assignment(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
    ));
    assert!(inv.lookup(MetadataStructureKind::GcMetadata).is_empty());
}

#[test]
fn coverage_report_single_kind_partial() {
    let mut inv = SubstrateInventory::new();
    inv.add_assignment(assignment(
        MetadataStructureKind::CompilationCache,
        SubstrateKind::SwissTable,
    ));
    let report = inv.coverage_report();
    assert_eq!(report.assigned_structure_kinds, 1);
    assert_eq!(report.coverage_millionths, 100_000); // 10%
    assert_eq!(report.missing_kinds.len(), 9);
}
