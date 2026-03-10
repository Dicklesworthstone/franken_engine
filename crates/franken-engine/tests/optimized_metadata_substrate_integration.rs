//! Integration tests for the optimized metadata substrate module.
//!
//! Tests cover substrate selection, override policies, snapshot/rollback,
//! health checks, transition events, and the full lifecycle from inventory
//! to instantiation.

use frankenengine_engine::metadata_substrate_inventory::{
    FallbackMode, LocalityGoal, MetadataStructureKind, RollbackRule, SubstrateAssignment,
    SubstrateContract, SubstrateInventory, SubstrateKind,
};
use frankenengine_engine::optimized_metadata_substrate::{
    default_optimized_assignments, OverridePolicy, OverrideReason,
    SubstrateHealthCheck, SubstrateInstance, SubstrateInstanceStatus,
    SubstrateSelectionError, SubstrateSelectionReceipt, SubstrateSelector, SubstrateSnapshot,
    SubstrateTransitionEvent, SubstrateTransitionKind, COMPONENT,
    OPTIMIZED_SUBSTRATE_BEAD_ID, OPTIMIZED_SUBSTRATE_SCHEMA_VERSION,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn shape_contract() -> SubstrateContract {
    SubstrateContract::new(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
        LocalityGoal::L1Hot,
        FallbackMode::LinearScan,
        RollbackRule::SnapshottedCow,
        65536,
        850_000,
    )
}

fn shape_assignment() -> SubstrateAssignment {
    SubstrateAssignment {
        contract: shape_contract(),
        assigned_epoch: epoch(1),
        rationale: "Swiss table for L1 shape access".to_string(),
        confidence_millionths: 750_000,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_format() {
    assert!(OPTIMIZED_SUBSTRATE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(OPTIMIZED_SUBSTRATE_SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn test_bead_id_format() {
    assert!(OPTIMIZED_SUBSTRATE_BEAD_ID.starts_with("bd-"));
}

#[test]
fn test_component_name() {
    assert_eq!(COMPONENT, "optimized_metadata_substrate");
}

// ---------------------------------------------------------------------------
// SubstrateInstanceStatus
// ---------------------------------------------------------------------------

#[test]
fn test_all_instance_statuses_are_distinct() {
    let statuses: Vec<_> = SubstrateInstanceStatus::ALL.to_vec();
    for (i, a) in statuses.iter().enumerate() {
        for (j, b) in statuses.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "statuses at {i} and {j} should differ");
            }
        }
    }
}

#[test]
fn test_instance_status_display_serde_consistency() {
    for status in SubstrateInstanceStatus::ALL {
        let display = status.to_string();
        let json = serde_json::to_string(status).unwrap();
        let json_inner = json.trim_matches('"');
        assert_eq!(display, json_inner);
    }
}

// ---------------------------------------------------------------------------
// OverrideReason
// ---------------------------------------------------------------------------

#[test]
fn test_all_override_reasons_are_distinct() {
    let reasons: Vec<_> = OverrideReason::ALL.to_vec();
    for (i, a) in reasons.iter().enumerate() {
        for (j, b) in reasons.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn test_override_only_none_is_not_override() {
    for reason in OverrideReason::ALL {
        if *reason == OverrideReason::None {
            assert!(!reason.is_override());
        } else {
            assert!(reason.is_override(), "{reason} should be an override");
        }
    }
}

// ---------------------------------------------------------------------------
// OverridePolicy
// ---------------------------------------------------------------------------

#[test]
fn test_permissive_policy_permits_all_reasons() {
    let policy = OverridePolicy::permissive();
    for reason in OverrideReason::ALL {
        assert!(
            policy.is_permitted(*reason),
            "permissive should permit {reason}"
        );
    }
}

#[test]
fn test_locked_policy_denies_most_reasons() {
    let policy = OverridePolicy::locked();
    // EpochRollback and None are always permitted
    assert!(policy.is_permitted(OverrideReason::EpochRollback));
    assert!(policy.is_permitted(OverrideReason::None));
    // Others should be denied
    assert!(!policy.is_permitted(OverrideReason::OperatorDebug));
    assert!(!policy.is_permitted(OverrideReason::CorruptionDetected));
    assert!(!policy.is_permitted(OverrideReason::MemoryPressure));
}

#[test]
fn test_restrictive_allows_only_corruption_security_rollback() {
    let policy = OverridePolicy::restrictive();
    assert!(policy.is_permitted(OverrideReason::CorruptionDetected));
    assert!(policy.is_permitted(OverrideReason::SecurityVeto));
    assert!(policy.is_permitted(OverrideReason::EpochRollback));
    assert!(policy.is_permitted(OverrideReason::None));
    assert!(!policy.is_permitted(OverrideReason::OperatorDebug));
    assert!(!policy.is_permitted(OverrideReason::PortabilityFallback));
    assert!(!policy.is_permitted(OverrideReason::MemoryPressure));
    assert!(!policy.is_permitted(OverrideReason::PerformanceRegression));
}

#[test]
fn test_different_policies_have_different_hashes() {
    let p1 = OverridePolicy::permissive();
    let p2 = OverridePolicy::restrictive();
    let p3 = OverridePolicy::locked();
    assert_ne!(p1.policy_hash, p2.policy_hash);
    assert_ne!(p2.policy_hash, p3.policy_hash);
    assert_ne!(p1.policy_hash, p3.policy_hash);
}

// ---------------------------------------------------------------------------
// SubstrateSelectionReceipt
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_contract_fields_match() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(5), "test");
    assert_eq!(receipt.structure_kind, contract.structure_kind);
    assert_eq!(receipt.selected_substrate, contract.substrate_kind);
    assert_eq!(receipt.locality_goal, contract.locality_goal);
    assert_eq!(receipt.contract_substrate, contract.substrate_kind);
}

#[test]
fn test_receipt_override_preserves_contract_reference() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_override(
        &contract,
        SubstrateKind::FlatArray,
        LocalityGoal::DramResident,
        OverrideReason::OperatorDebug,
        epoch(5),
        "debug mode",
    );
    assert_eq!(receipt.contract_substrate, SubstrateKind::SwissTable);
    assert_eq!(receipt.selected_substrate, SubstrateKind::FlatArray);
    assert_ne!(receipt.contract_substrate, receipt.selected_substrate);
}

#[test]
fn test_receipt_different_epochs_different_hashes() {
    let contract = shape_contract();
    let r1 = SubstrateSelectionReceipt::from_contract(&contract, epoch(1), "test");
    let r2 = SubstrateSelectionReceipt::from_contract(&contract, epoch(2), "test");
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

// ---------------------------------------------------------------------------
// SubstrateSnapshot
// ---------------------------------------------------------------------------

#[test]
fn test_snapshot_captures_state() {
    let hash = frankenengine_engine::hash_tiers::ContentHash::compute(b"test_state");
    let snap = SubstrateSnapshot::new(
        MetadataStructureKind::StringTable,
        SubstrateKind::ArtTree,
        SubstrateInstanceStatus::Active,
        epoch(10),
        5000,
        hash,
    );
    assert_eq!(snap.entry_count, 5000);
    assert_eq!(snap.snapshot_epoch.as_u64(), 10);
}

#[test]
fn test_snapshot_different_entry_counts_different_hashes() {
    let hash = frankenengine_engine::hash_tiers::ContentHash::compute(b"s");
    let s1 = SubstrateSnapshot::new(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
        SubstrateInstanceStatus::Active,
        epoch(1),
        100,
        hash.clone(),
    );
    let s2 = SubstrateSnapshot::new(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
        SubstrateInstanceStatus::Active,
        epoch(1),
        200,
        hash,
    );
    assert_ne!(s1.snapshot_hash, s2.snapshot_hash);
}

// ---------------------------------------------------------------------------
// SubstrateInstance
// ---------------------------------------------------------------------------

#[test]
fn test_instance_starts_warming() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(1), "test");
    let instance = SubstrateInstance::from_contract(&contract, receipt);
    assert_eq!(instance.status, SubstrateInstanceStatus::Warming);
    assert!(instance.is_serving());
}

#[test]
fn test_instance_load_factor_computation() {
    let contract = shape_contract(); // max=65536
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(1), "test");
    let mut instance = SubstrateInstance::from_contract(&contract, receipt);

    // 50% load
    instance.record_entries(32768);
    assert_eq!(instance.load_factor_millionths, 500_000);

    // 100% load
    instance.record_entries(65536);
    assert_eq!(instance.load_factor_millionths, 1_000_000);

    // 0% load
    instance.record_entries(0);
    assert_eq!(instance.load_factor_millionths, 0);
}

#[test]
fn test_instance_lifecycle_warming_active_decommission() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(1), "test");
    let mut instance = SubstrateInstance::from_contract(&contract, receipt);

    assert_eq!(instance.status, SubstrateInstanceStatus::Warming);
    assert!(instance.is_serving());

    instance.activate();
    assert_eq!(instance.status, SubstrateInstanceStatus::Active);
    assert!(instance.is_serving());

    instance.decommission();
    assert_eq!(instance.status, SubstrateInstanceStatus::Decommissioned);
    assert!(!instance.is_serving());
}

#[test]
fn test_instance_fallback_sets_generic_substrate() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(1), "test");
    let mut instance = SubstrateInstance::from_contract(&contract, receipt);
    instance.activate();

    assert_eq!(instance.substrate_kind, SubstrateKind::SwissTable);
    instance.fallback(OverrideReason::CorruptionDetected);
    assert_eq!(instance.substrate_kind, SubstrateKind::FlatArray);
    assert_eq!(instance.locality_goal, LocalityGoal::DramResident);
    assert_eq!(instance.status, SubstrateInstanceStatus::FallenBack);
}

#[test]
fn test_instance_snapshot_rollback_restores_entry_count() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(1), "test");
    let mut instance = SubstrateInstance::from_contract(&contract, receipt);
    instance.activate();
    instance.record_entries(1000);

    let snapshot = instance.take_snapshot(epoch(1));
    assert_eq!(snapshot.entry_count, 1000);

    instance.record_entries(50000);
    assert_eq!(instance.entry_count, 50000);

    instance.restore_from_snapshot(&snapshot);
    assert_eq!(instance.entry_count, 1000);
    assert_eq!(instance.status, SubstrateInstanceStatus::RolledBack);
}

#[test]
fn test_instance_multiple_snapshots_selective_rollback() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(1), "test");
    let mut instance = SubstrateInstance::from_contract(&contract, receipt);
    instance.activate();

    instance.record_entries(100);
    let s1 = instance.take_snapshot(epoch(1));
    instance.record_entries(500);
    let s2 = instance.take_snapshot(epoch(2));
    instance.record_entries(1000);
    let _s3 = instance.take_snapshot(epoch(3));

    // Can rollback to any snapshot
    instance.restore_from_snapshot(&s2);
    assert_eq!(instance.entry_count, 500);

    instance.restore_from_snapshot(&s1);
    assert_eq!(instance.entry_count, 100);
}

// ---------------------------------------------------------------------------
// SubstrateSelector
// ---------------------------------------------------------------------------

#[test]
fn test_selector_instantiates_all_from_inventory() {
    let e = epoch(1);
    let inventory = default_optimized_assignments(e);
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);
    let instances = selector.instantiate_all(&inventory);

    assert_eq!(instances.len(), MetadataStructureKind::ALL.len());
    assert_eq!(selector.instances.len(), MetadataStructureKind::ALL.len());
    assert_eq!(selector.receipts.len(), MetadataStructureKind::ALL.len());
}

#[test]
fn test_selector_instance_for_returns_correct_kind() {
    let e = epoch(1);
    let inventory = default_optimized_assignments(e);
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);
    selector.instantiate_all(&inventory);

    for kind in MetadataStructureKind::ALL {
        let instance = selector.instance_for(*kind);
        assert!(instance.is_some(), "should find instance for {kind}");
        assert_eq!(instance.unwrap().structure_kind, *kind);
    }
}

#[test]
fn test_selector_override_denied_by_restrictive_policy() {
    let policy = OverridePolicy::restrictive();
    let mut selector = SubstrateSelector::new(policy, epoch(1));
    let assignment = shape_assignment();

    let result = selector.select_with_override(
        &assignment,
        SubstrateKind::FlatArray,
        LocalityGoal::DramResident,
        OverrideReason::OperatorDebug,
        "debug",
    );
    assert!(result.is_err());
    if let Err(SubstrateSelectionError::OverrideDenied {
        structure_kind,
        reason,
    }) = result
    {
        assert_eq!(structure_kind, MetadataStructureKind::ShapeTable);
        assert_eq!(reason, OverrideReason::OperatorDebug);
    }
}

#[test]
fn test_selector_override_allowed_by_permissive_policy() {
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, epoch(1));
    let assignment = shape_assignment();

    let result = selector.select_with_override(
        &assignment,
        SubstrateKind::LinearProbe,
        LocalityGoal::L2Warm,
        OverrideReason::PortabilityFallback,
        "no SIMD support",
    );
    assert!(result.is_ok());
    let instance = result.unwrap();
    assert_eq!(instance.substrate_kind, SubstrateKind::LinearProbe);
}

#[test]
fn test_selector_epoch_rollback_always_allowed() {
    let policy = OverridePolicy::locked();
    let mut selector = SubstrateSelector::new(policy, epoch(1));
    let assignment = shape_assignment();

    let result = selector.select_with_override(
        &assignment,
        SubstrateKind::FlatArray,
        LocalityGoal::DramResident,
        OverrideReason::EpochRollback,
        "epoch rollback",
    );
    assert!(result.is_ok());
}

#[test]
fn test_selector_summary_full_coverage() {
    let e = epoch(1);
    let inventory = default_optimized_assignments(e);
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);
    selector.instantiate_all(&inventory);

    let report = selector.summary_report();
    assert_eq!(report.total_instances, 10);
    assert_eq!(report.coverage_millionths, 1_000_000);
    assert_eq!(report.overridden_instances, 0);
    assert_eq!(report.fallen_back_instances, 0);
}

#[test]
fn test_selector_summary_with_override() {
    let e = epoch(1);
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);
    let assignment = shape_assignment();

    selector.select_from_contract(&assignment);
    let _ = selector.select_with_override(
        &SubstrateAssignment {
            contract: SubstrateContract::new(
                MetadataStructureKind::GcMetadata,
                SubstrateKind::CacheOblivious,
                LocalityGoal::L2Warm,
                FallbackMode::Abstain,
                RollbackRule::NoRollback,
                524288,
                500_000,
            ),
            assigned_epoch: e,
            rationale: "GC".to_string(),
            confidence_millionths: 700_000,
        },
        SubstrateKind::FlatArray,
        LocalityGoal::DramResident,
        OverrideReason::MemoryPressure,
        "low memory",
    );

    assert_eq!(selector.overridden_count(), 1);
}

// ---------------------------------------------------------------------------
// default_optimized_assignments
// ---------------------------------------------------------------------------

#[test]
fn test_default_assignments_unique_structure_kinds() {
    let inventory = default_optimized_assignments(epoch(1));
    let mut seen = std::collections::BTreeSet::new();
    for assignment in &inventory.assignments {
        assert!(
            seen.insert(assignment.contract.structure_kind),
            "duplicate assignment for {}",
            assignment.contract.structure_kind
        );
    }
}

#[test]
fn test_default_assignments_all_have_rationale() {
    let inventory = default_optimized_assignments(epoch(1));
    for assignment in &inventory.assignments {
        assert!(
            !assignment.rationale.is_empty(),
            "missing rationale for {}",
            assignment.contract.structure_kind
        );
    }
}

#[test]
fn test_default_assignments_confidence_in_range() {
    let inventory = default_optimized_assignments(epoch(1));
    for assignment in &inventory.assignments {
        assert!(
            assignment.confidence_millionths <= 1_000_000,
            "confidence out of range for {}",
            assignment.contract.structure_kind
        );
    }
}

#[test]
fn test_default_assignments_locality_distribution() {
    let inventory = default_optimized_assignments(epoch(1));
    let l1_count = inventory
        .assignments
        .iter()
        .filter(|a| a.contract.locality_goal == LocalityGoal::L1Hot)
        .count();
    let l2_count = inventory
        .assignments
        .iter()
        .filter(|a| a.contract.locality_goal == LocalityGoal::L2Warm)
        .count();
    let l3_count = inventory
        .assignments
        .iter()
        .filter(|a| a.contract.locality_goal == LocalityGoal::L3Cold)
        .count();
    // At least some L1, L2, and L3 assignments
    assert!(l1_count > 0, "should have L1 hot assignments");
    assert!(l2_count > 0, "should have L2 warm assignments");
    assert!(l3_count > 0, "should have L3 cold assignments");
}

// ---------------------------------------------------------------------------
// SubstrateHealthCheck
// ---------------------------------------------------------------------------

#[test]
fn test_health_check_all_defaults_healthy() {
    let e = epoch(1);
    let inventory = default_optimized_assignments(e);
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);
    selector.instantiate_all(&inventory);

    for instance in &selector.instances {
        let check = SubstrateHealthCheck::check(instance, e);
        assert!(check.healthy, "{} should be healthy", instance.structure_kind);
        assert!(check.serving);
        assert!(!check.overloaded);
    }
}

#[test]
fn test_health_check_overloaded_threshold() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(1), "test");
    let mut instance = SubstrateInstance::from_contract(&contract, receipt);
    instance.activate();

    // 79% load — below 80% threshold, should be healthy
    instance.record_entries(51773);
    let check = SubstrateHealthCheck::check(&instance, epoch(1));
    assert!(check.healthy);

    // 95% load — above threshold, unhealthy
    instance.record_entries(62259);
    let check = SubstrateHealthCheck::check(&instance, epoch(1));
    assert!(!check.healthy);
    assert!(check.overloaded);
}

#[test]
fn test_health_check_decommissioned_not_healthy() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(1), "test");
    let mut instance = SubstrateInstance::from_contract(&contract, receipt);
    instance.decommission();

    let check = SubstrateHealthCheck::check(&instance, epoch(1));
    assert!(!check.healthy);
    assert!(!check.serving);
}

#[test]
fn test_health_check_diagnostic_message_contains_kind() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(1), "test");
    let mut instance = SubstrateInstance::from_contract(&contract, receipt);
    instance.activate();

    let check = SubstrateHealthCheck::check(&instance, epoch(1));
    assert!(check.diagnostic.contains("shape_table"));
}

// ---------------------------------------------------------------------------
// SubstrateTransitionEvent
// ---------------------------------------------------------------------------

#[test]
fn test_transition_event_captures_from_to() {
    let event = SubstrateTransitionEvent::new(
        MetadataStructureKind::InlineCacheTable,
        SubstrateTransitionKind::Overridden,
        Some(SubstrateKind::FlatArray),
        SubstrateKind::SwissTable,
        epoch(5),
        "upgrade to Swiss table",
    );
    assert_eq!(event.from_substrate, Some(SubstrateKind::FlatArray));
    assert_eq!(event.to_substrate, SubstrateKind::SwissTable);
    assert_eq!(event.reason, "upgrade to Swiss table");
}

#[test]
fn test_transition_event_created_has_no_from() {
    let event = SubstrateTransitionEvent::new(
        MetadataStructureKind::StringTable,
        SubstrateTransitionKind::Created,
        None,
        SubstrateKind::ArtTree,
        epoch(1),
        "initial creation",
    );
    assert!(event.from_substrate.is_none());
}

#[test]
fn test_all_transition_kinds_display() {
    let kinds = [
        SubstrateTransitionKind::Created,
        SubstrateTransitionKind::Activated,
        SubstrateTransitionKind::Overridden,
        SubstrateTransitionKind::FellBack,
        SubstrateTransitionKind::RolledBack,
        SubstrateTransitionKind::Decommissioned,
        SubstrateTransitionKind::SnapshotTaken,
    ];
    for kind in kinds {
        let display = kind.to_string();
        assert!(!display.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Full lifecycle integration
// ---------------------------------------------------------------------------

#[test]
fn test_full_lifecycle_inventory_to_health() {
    let e = epoch(1);
    let inventory = default_optimized_assignments(e);
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);
    selector.instantiate_all(&inventory);

    // Activate all, populate with data
    for i in 0..selector.instances.len() {
        selector.instances[i].activate();
        selector.instances[i].record_entries(100);
    }

    // Health check all
    let checks: Vec<_> = selector
        .instances
        .iter()
        .map(|i| SubstrateHealthCheck::check(i, e))
        .collect();
    assert!(checks.iter().all(|c| c.healthy));

    // Snapshot all
    for i in 0..selector.instances.len() {
        selector.instances[i].take_snapshot(e);
    }
    assert!(selector.instances.iter().all(|i| !i.snapshots.is_empty()));
}

#[test]
fn test_override_then_snapshot_then_rollback() {
    let e = epoch(1);
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);
    let assignment = shape_assignment();

    let result = selector.select_with_override(
        &assignment,
        SubstrateKind::LinearProbe,
        LocalityGoal::L2Warm,
        OverrideReason::PortabilityFallback,
        "no SIMD",
    );
    assert!(result.is_ok());

    let instance = selector.instance_for_mut(MetadataStructureKind::ShapeTable).unwrap();
    instance.activate();
    instance.record_entries(500);
    let snapshot = instance.take_snapshot(epoch(1));

    instance.record_entries(10000);
    instance.restore_from_snapshot(&snapshot);
    assert_eq!(instance.entry_count, 500);
}

#[test]
fn test_concurrent_structures_independent_lifecycle() {
    let e = epoch(1);
    let inventory = default_optimized_assignments(e);
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);
    selector.instantiate_all(&inventory);

    // Decommission shape table
    selector.instance_for_mut(MetadataStructureKind::ShapeTable).unwrap().decommission();

    // GC metadata should still be serving
    let gc = selector.instance_for(MetadataStructureKind::GcMetadata).unwrap();
    assert!(gc.is_serving());

    // Shape table should not be serving
    let shape = selector.instance_for(MetadataStructureKind::ShapeTable).unwrap();
    assert!(!shape.is_serving());
}

#[test]
fn test_hash_determinism_across_full_pipeline() {
    let e = epoch(42);
    let inv1 = default_optimized_assignments(e);
    let inv2 = default_optimized_assignments(e);

    let policy1 = OverridePolicy::permissive();
    let policy2 = OverridePolicy::permissive();

    let mut sel1 = SubstrateSelector::new(policy1, e);
    let mut sel2 = SubstrateSelector::new(policy2, e);

    sel1.instantiate_all(&inv1);
    sel2.instantiate_all(&inv2);

    assert_eq!(sel1.selector_hash, sel2.selector_hash);
}

#[test]
fn test_serde_roundtrip_full_selector() {
    let e = epoch(1);
    let inventory = default_optimized_assignments(e);
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);
    selector.instantiate_all(&inventory);

    let json = serde_json::to_string(&selector).unwrap();
    let back: SubstrateSelector = serde_json::from_str(&json).unwrap();
    assert_eq!(selector, back);
}
