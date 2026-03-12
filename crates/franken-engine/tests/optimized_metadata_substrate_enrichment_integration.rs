//! Enrichment integration tests for the optimized metadata substrate module.
//!
//! Covers Display uniqueness, serde roundtrips, edge cases on SubstrateInstance,
//! OverridePolicy permission matrix, SubstrateSelector edge cases, health checks,
//! snapshots, transition events, summary reports, default assignments, and hash
//! determinism.

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

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::metadata_substrate_inventory::{
    FallbackMode, LocalityGoal, MetadataStructureKind, RollbackRule, SubstrateAssignment,
    SubstrateContract, SubstrateKind,
};
use frankenengine_engine::optimized_metadata_substrate::{
    OverridePolicy, OverrideReason, SubstrateHealthCheck, SubstrateInstance,
    SubstrateInstanceStatus, SubstrateSelectionError, SubstrateSelectionReceipt,
    SubstrateSelector, SubstrateSnapshot, SubstrateTransitionEvent, SubstrateTransitionKind,
    default_optimized_assignments, SelectorSummaryReport,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn epoch2() -> SecurityEpoch {
    SecurityEpoch::from_raw(2)
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
        assigned_epoch: epoch(),
        rationale: "Swiss table for L1 shape access".to_string(),
        confidence_millionths: 750_000,
    }
}

fn make_instance() -> SubstrateInstance {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(), "test");
    SubstrateInstance::from_contract(&contract, receipt)
}

// ---------------------------------------------------------------------------
// 1. Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_instance_status_display_all_unique() {
    let displays: BTreeSet<String> = SubstrateInstanceStatus::ALL
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(displays.len(), SubstrateInstanceStatus::ALL.len());
}

#[test]
fn enrichment_override_reason_display_all_unique() {
    let displays: BTreeSet<String> = OverrideReason::ALL
        .iter()
        .map(|r| r.to_string())
        .collect();
    assert_eq!(displays.len(), OverrideReason::ALL.len());
}

#[test]
fn enrichment_transition_kind_display_all_unique() {
    let kinds = [
        SubstrateTransitionKind::Created,
        SubstrateTransitionKind::Activated,
        SubstrateTransitionKind::Overridden,
        SubstrateTransitionKind::FellBack,
        SubstrateTransitionKind::RolledBack,
        SubstrateTransitionKind::Decommissioned,
        SubstrateTransitionKind::SnapshotTaken,
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), 7);
}

#[test]
fn enrichment_selection_error_display_all_unique() {
    let errors = [
        SubstrateSelectionError::OverrideDenied {
            structure_kind: MetadataStructureKind::ShapeTable,
            reason: OverrideReason::OperatorDebug,
        },
        SubstrateSelectionError::NoContractFound {
            structure_kind: MetadataStructureKind::ShapeTable,
        },
        SubstrateSelectionError::AlreadyDecommissioned {
            structure_kind: MetadataStructureKind::ShapeTable,
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_override_policy_display_non_empty() {
    let policy = OverridePolicy::permissive();
    let display = policy.to_string();
    assert!(!display.is_empty());
    assert!(display.contains("OverridePolicy"));
}

#[test]
fn enrichment_selector_summary_report_display_non_empty() {
    let e = epoch();
    let inventory = default_optimized_assignments(e);
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);
    selector.instantiate_all(&inventory);
    let report = selector.summary_report();
    let display = report.to_string();
    assert!(!display.is_empty());
    assert!(display.contains("SelectorSummary"));
}

// ---------------------------------------------------------------------------
// 2. Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_instance_status_all_variants() {
    for status in SubstrateInstanceStatus::ALL {
        let json = serde_json::to_string(status).unwrap();
        let back: SubstrateInstanceStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*status, back);
    }
}

#[test]
fn enrichment_serde_override_reason_all_variants() {
    for reason in OverrideReason::ALL {
        let json = serde_json::to_string(reason).unwrap();
        let back: OverrideReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

#[test]
fn enrichment_serde_transition_kind_all_variants() {
    let kinds = [
        SubstrateTransitionKind::Created,
        SubstrateTransitionKind::Activated,
        SubstrateTransitionKind::Overridden,
        SubstrateTransitionKind::FellBack,
        SubstrateTransitionKind::RolledBack,
        SubstrateTransitionKind::Decommissioned,
        SubstrateTransitionKind::SnapshotTaken,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let back: SubstrateTransitionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn enrichment_serde_override_policy_roundtrip() {
    for policy in [
        OverridePolicy::permissive(),
        OverridePolicy::restrictive(),
        OverridePolicy::locked(),
    ] {
        let json = serde_json::to_string(&policy).unwrap();
        let back: OverridePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }
}

#[test]
fn enrichment_serde_substrate_snapshot_roundtrip() {
    let hash = ContentHash::compute(b"snapshot_state");
    let snap = SubstrateSnapshot::new(
        MetadataStructureKind::StringTable,
        SubstrateKind::ArtTree,
        SubstrateInstanceStatus::Active,
        epoch(),
        5000,
        hash,
    );
    let json = serde_json::to_string(&snap).unwrap();
    let back: SubstrateSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, back);
}

#[test]
fn enrichment_serde_transition_event_roundtrip() {
    let event = SubstrateTransitionEvent::new(
        MetadataStructureKind::ShapeTable,
        SubstrateTransitionKind::Activated,
        Some(SubstrateKind::FlatArray),
        SubstrateKind::SwissTable,
        epoch(),
        "activated after warmup",
    );
    let json = serde_json::to_string(&event).unwrap();
    let back: SubstrateTransitionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ---------------------------------------------------------------------------
// 3. SubstrateInstance edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_instance_record_entries_zero_load_factor() {
    let mut instance = make_instance();
    instance.record_entries(0);
    assert_eq!(instance.load_factor_millionths, 0);
}

#[test]
fn enrichment_instance_record_entries_max_load_factor() {
    let mut instance = make_instance();
    // max_entry_count = 65536
    instance.record_entries(65536);
    assert_eq!(instance.load_factor_millionths, 1_000_000);
}

#[test]
fn enrichment_instance_is_serving_active() {
    let mut instance = make_instance();
    instance.activate();
    assert!(instance.is_serving());
}

#[test]
fn enrichment_instance_is_serving_warming() {
    let instance = make_instance();
    assert_eq!(instance.status, SubstrateInstanceStatus::Warming);
    assert!(instance.is_serving());
}

#[test]
fn enrichment_instance_not_serving_decommissioned() {
    let mut instance = make_instance();
    instance.decommission();
    assert!(!instance.is_serving());
}

#[test]
fn enrichment_instance_not_serving_paused_fallenback_rolledback() {
    // FallenBack
    let mut fb = make_instance();
    fb.fallback(OverrideReason::CorruptionDetected);
    assert!(!fb.is_serving());

    // RolledBack
    let mut rb = make_instance();
    rb.activate();
    rb.record_entries(100);
    let snap = rb.take_snapshot(epoch());
    rb.record_entries(500);
    rb.restore_from_snapshot(&snap);
    assert_eq!(rb.status, SubstrateInstanceStatus::RolledBack);
    assert!(!rb.is_serving());
}

#[test]
fn enrichment_instance_is_overloaded_above_threshold() {
    let mut instance = make_instance();
    instance.activate();
    // 90% load = 58982 / 65536
    instance.record_entries(58982);
    assert!(instance.is_overloaded(800_000));
}

#[test]
fn enrichment_instance_is_overloaded_below_threshold() {
    let mut instance = make_instance();
    instance.activate();
    // 50% load
    instance.record_entries(32768);
    assert!(!instance.is_overloaded(800_000));
}

#[test]
fn enrichment_instance_fallback_corruption_detected() {
    let mut instance = make_instance();
    instance.activate();
    instance.fallback(OverrideReason::CorruptionDetected);
    assert_eq!(instance.status, SubstrateInstanceStatus::FallenBack);
    assert_eq!(instance.substrate_kind, SubstrateKind::FlatArray);
    assert!(instance.selection_receipt.override_applied);
    assert_eq!(
        instance.selection_receipt.override_reason,
        OverrideReason::CorruptionDetected
    );
}

#[test]
fn enrichment_instance_fallback_memory_pressure() {
    let mut instance = make_instance();
    instance.activate();
    instance.fallback(OverrideReason::MemoryPressure);
    assert_eq!(instance.status, SubstrateInstanceStatus::FallenBack);
    assert_eq!(instance.locality_goal, LocalityGoal::DramResident);
}

#[test]
fn enrichment_instance_fallback_portability() {
    let mut instance = make_instance();
    instance.activate();
    instance.fallback(OverrideReason::PortabilityFallback);
    assert_eq!(instance.status, SubstrateInstanceStatus::FallenBack);
    assert_eq!(instance.substrate_kind, SubstrateKind::FlatArray);
}

#[test]
fn enrichment_instance_hash_changes_after_activate() {
    let instance = make_instance();
    let hash_before = instance.instance_hash;
    let mut activated = instance;
    activated.activate();
    assert_ne!(hash_before, activated.instance_hash);
}

#[test]
fn enrichment_instance_hash_changes_after_record_entries() {
    let mut instance = make_instance();
    let hash_before = instance.instance_hash;
    instance.record_entries(1000);
    assert_ne!(hash_before, instance.instance_hash);
}

// ---------------------------------------------------------------------------
// 4. OverridePolicy permission matrix
// ---------------------------------------------------------------------------

#[test]
fn enrichment_permissive_permits_all_eight_reasons() {
    let policy = OverridePolicy::permissive();
    for reason in OverrideReason::ALL {
        assert!(
            policy.is_permitted(*reason),
            "permissive should permit {reason}"
        );
    }
}

#[test]
fn enrichment_locked_denies_all_non_epoch_non_none() {
    let policy = OverridePolicy::locked();
    let denied = [
        OverrideReason::OperatorDebug,
        OverrideReason::CorruptionDetected,
        OverrideReason::PortabilityFallback,
        OverrideReason::MemoryPressure,
        OverrideReason::PerformanceRegression,
        OverrideReason::SecurityVeto,
    ];
    for reason in denied {
        assert!(
            !policy.is_permitted(reason),
            "locked should deny {reason}"
        );
    }
    // Always permitted
    assert!(policy.is_permitted(OverrideReason::EpochRollback));
    assert!(policy.is_permitted(OverrideReason::None));
}

#[test]
fn enrichment_restrictive_permits_corruption_security_rollback() {
    let policy = OverridePolicy::restrictive();
    assert!(policy.is_permitted(OverrideReason::CorruptionDetected));
    assert!(policy.is_permitted(OverrideReason::SecurityVeto));
    assert!(policy.is_permitted(OverrideReason::EpochRollback));
    assert!(policy.is_permitted(OverrideReason::None));
}

#[test]
fn enrichment_override_reason_none_is_not_override() {
    assert!(!OverrideReason::None.is_override());
}

#[test]
fn enrichment_all_non_none_reasons_are_overrides() {
    for reason in OverrideReason::ALL {
        if *reason != OverrideReason::None {
            assert!(reason.is_override(), "{reason} should be an override");
        }
    }
}

// ---------------------------------------------------------------------------
// 5. SubstrateSelector edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_empty_selector_counts() {
    let selector = SubstrateSelector::new(OverridePolicy::permissive(), epoch());
    assert_eq!(selector.active_count(), 0);
    assert_eq!(selector.overridden_count(), 0);
}

#[test]
fn enrichment_empty_selector_summary_coverage() {
    let selector = SubstrateSelector::new(OverridePolicy::permissive(), epoch());
    let report = selector.summary_report();
    assert_eq!(report.total_instances, 0);
    assert_eq!(report.coverage_millionths, 0);
}

#[test]
fn enrichment_select_with_override_returns_denied_error() {
    let policy = OverridePolicy::locked();
    let mut selector = SubstrateSelector::new(policy, epoch());
    let assignment = shape_assignment();

    let result = selector.select_with_override(
        &assignment,
        SubstrateKind::FlatArray,
        LocalityGoal::DramResident,
        OverrideReason::OperatorDebug,
        "debug",
    );
    assert!(result.is_err());
    match result {
        Err(SubstrateSelectionError::OverrideDenied {
            structure_kind,
            reason,
        }) => {
            assert_eq!(structure_kind, MetadataStructureKind::ShapeTable);
            assert_eq!(reason, OverrideReason::OperatorDebug);
        }
        _ => panic!("expected OverrideDenied"),
    }
}

#[test]
fn enrichment_instance_for_mut_allows_state_modification() {
    let e = epoch();
    let inventory = default_optimized_assignments(e);
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);
    selector.instantiate_all(&inventory);

    let instance = selector
        .instance_for_mut(MetadataStructureKind::ShapeTable)
        .unwrap();
    assert_eq!(instance.status, SubstrateInstanceStatus::Warming);
    instance.activate();
    assert_eq!(instance.status, SubstrateInstanceStatus::Active);

    // Verify the change persisted in the selector
    let instance_ref = selector
        .instance_for(MetadataStructureKind::ShapeTable)
        .unwrap();
    assert_eq!(instance_ref.status, SubstrateInstanceStatus::Active);
}

#[test]
fn enrichment_selector_hash_changes_after_adding_instance() {
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, epoch());
    let hash_before = selector.selector_hash;

    let assignment = shape_assignment();
    selector.select_from_contract(&assignment);
    assert_ne!(hash_before, selector.selector_hash);
}

// ---------------------------------------------------------------------------
// 6. SubstrateHealthCheck
// ---------------------------------------------------------------------------

#[test]
fn enrichment_health_check_active_instance_healthy_serving() {
    let mut instance = make_instance();
    instance.activate();
    instance.record_entries(100);
    let check = SubstrateHealthCheck::check(&instance, epoch());
    assert!(check.healthy);
    assert!(check.serving);
    assert!(!check.overloaded);
}

#[test]
fn enrichment_health_check_warming_instance_serving() {
    let instance = make_instance();
    assert_eq!(instance.status, SubstrateInstanceStatus::Warming);
    let check = SubstrateHealthCheck::check(&instance, epoch());
    assert!(check.serving);
    assert!(check.healthy);
}

#[test]
fn enrichment_health_check_paused_instance_not_serving() {
    // Paused is not serving; simulate by creating via fallback then manually
    // We can't directly set Paused from the public API, but the health check
    // looks at is_serving which only returns true for Active/Warming.
    // Decommissioned is also not serving, so we use that as the proxy.
    let mut instance = make_instance();
    instance.decommission();
    let check = SubstrateHealthCheck::check(&instance, epoch());
    assert!(!check.serving);
    assert!(!check.healthy);
}

#[test]
fn enrichment_health_check_load_factor_at_boundary() {
    let contract = SubstrateContract::new(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
        LocalityGoal::L1Hot,
        FallbackMode::LinearScan,
        RollbackRule::SnapshottedCow,
        1_000_000, // max = 1M so load_factor = entries directly
        850_000,
    );
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(), "test");
    let mut instance = SubstrateInstance::from_contract(&contract, receipt);
    instance.activate();

    // Exactly 800_000 entries out of 1M = 800_000 millionths
    instance.record_entries(800_000);
    assert_eq!(instance.load_factor_millionths, 800_000);

    // is_overloaded uses strictly greater than
    assert!(!instance.is_overloaded(800_000));

    // One more entry tips it over
    instance.record_entries(800_001);
    assert!(instance.is_overloaded(800_000));
}

#[test]
fn enrichment_health_check_hash_deterministic() {
    let mut instance = make_instance();
    instance.activate();
    instance.record_entries(500);

    let check1 = SubstrateHealthCheck::check(&instance, epoch());
    let check2 = SubstrateHealthCheck::check(&instance, epoch());
    assert_eq!(check1.check_hash, check2.check_hash);
}

// ---------------------------------------------------------------------------
// 7. SubstrateSnapshot
// ---------------------------------------------------------------------------

#[test]
fn enrichment_snapshot_same_state_same_epoch_same_hash() {
    let hash = ContentHash::compute(b"deterministic");
    let s1 = SubstrateSnapshot::new(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
        SubstrateInstanceStatus::Active,
        epoch(),
        1000,
        hash.clone(),
    );
    let s2 = SubstrateSnapshot::new(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
        SubstrateInstanceStatus::Active,
        epoch(),
        1000,
        hash,
    );
    assert_eq!(s1.snapshot_hash, s2.snapshot_hash);
}

#[test]
fn enrichment_snapshot_different_entry_count_different_hash() {
    let hash = ContentHash::compute(b"state");
    let s1 = SubstrateSnapshot::new(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
        SubstrateInstanceStatus::Active,
        epoch(),
        100,
        hash.clone(),
    );
    let s2 = SubstrateSnapshot::new(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
        SubstrateInstanceStatus::Active,
        epoch(),
        200,
        hash,
    );
    assert_ne!(s1.snapshot_hash, s2.snapshot_hash);
}

#[test]
fn enrichment_snapshot_serde_preserves_all_fields() {
    let hash = ContentHash::compute(b"serde_test");
    let snap = SubstrateSnapshot::new(
        MetadataStructureKind::GcMetadata,
        SubstrateKind::CacheOblivious,
        SubstrateInstanceStatus::Warming,
        epoch2(),
        42_000,
        hash,
    );
    let json = serde_json::to_string(&snap).unwrap();
    let back: SubstrateSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap.structure_kind, back.structure_kind);
    assert_eq!(snap.substrate_kind, back.substrate_kind);
    assert_eq!(snap.status, back.status);
    assert_eq!(snap.snapshot_epoch, back.snapshot_epoch);
    assert_eq!(snap.entry_count, back.entry_count);
    assert_eq!(snap.state_hash, back.state_hash);
    assert_eq!(snap.snapshot_hash, back.snapshot_hash);
}

// ---------------------------------------------------------------------------
// 8. SubstrateTransitionEvent
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transition_event_hash_deterministic() {
    let e1 = SubstrateTransitionEvent::new(
        MetadataStructureKind::StringTable,
        SubstrateTransitionKind::Created,
        None,
        SubstrateKind::ArtTree,
        epoch(),
        "initial",
    );
    let e2 = SubstrateTransitionEvent::new(
        MetadataStructureKind::StringTable,
        SubstrateTransitionKind::Created,
        None,
        SubstrateKind::ArtTree,
        epoch(),
        "initial",
    );
    assert_eq!(e1.event_hash, e2.event_hash);
}

#[test]
fn enrichment_transition_event_different_epochs_different_hash() {
    let e1 = SubstrateTransitionEvent::new(
        MetadataStructureKind::ShapeTable,
        SubstrateTransitionKind::Activated,
        None,
        SubstrateKind::SwissTable,
        epoch(),
        "activate",
    );
    let e2 = SubstrateTransitionEvent::new(
        MetadataStructureKind::ShapeTable,
        SubstrateTransitionKind::Activated,
        None,
        SubstrateKind::SwissTable,
        epoch2(),
        "activate",
    );
    assert_ne!(e1.event_hash, e2.event_hash);
}

#[test]
fn enrichment_transition_event_display_contains_kind() {
    let event = SubstrateTransitionEvent::new(
        MetadataStructureKind::InlineCacheTable,
        SubstrateTransitionKind::FellBack,
        Some(SubstrateKind::FlatArray),
        SubstrateKind::FlatArray,
        epoch(),
        "fallback",
    );
    let display = event.to_string();
    assert!(display.contains("fell_back"));
}

// ---------------------------------------------------------------------------
// 9. SelectorSummaryReport
// ---------------------------------------------------------------------------

#[test]
fn enrichment_selector_summary_report_serde_roundtrip() {
    let e = epoch();
    let inventory = default_optimized_assignments(e);
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);
    selector.instantiate_all(&inventory);
    let report = selector.summary_report();

    let json = serde_json::to_string(&report).unwrap();
    let back: SelectorSummaryReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_selector_summary_report_full_coverage_value() {
    let e = epoch();
    let inventory = default_optimized_assignments(e);
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);
    selector.instantiate_all(&inventory);

    let report = selector.summary_report();
    assert_eq!(report.coverage_millionths, 1_000_000);
    assert_eq!(report.total_instances, 10);
    assert_eq!(report.active_instances, 10); // all warming = serving
}

#[test]
fn enrichment_selector_summary_report_display_contains_key_info() {
    let e = epoch();
    let inventory = default_optimized_assignments(e);
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);
    selector.instantiate_all(&inventory);

    let report = selector.summary_report();
    let display = report.to_string();
    assert!(display.contains("total="));
    assert!(display.contains("active="));
    assert!(display.contains("coverage="));
}

// ---------------------------------------------------------------------------
// 10. default_optimized_assignments
// ---------------------------------------------------------------------------

#[test]
fn enrichment_default_assignments_has_ten_structure_kinds() {
    let inventory = default_optimized_assignments(epoch());
    assert_eq!(inventory.assignments.len(), 10);
}

#[test]
fn enrichment_default_assignments_all_substrate_kinds_non_empty() {
    let inventory = default_optimized_assignments(epoch());
    for assignment in &inventory.assignments {
        let kind_str = assignment.contract.substrate_kind.to_string();
        assert!(
            !kind_str.is_empty(),
            "substrate kind string should be non-empty for {}",
            assignment.contract.structure_kind
        );
    }
}

#[test]
fn enrichment_default_assignments_all_max_entry_count_positive() {
    let inventory = default_optimized_assignments(epoch());
    for assignment in &inventory.assignments {
        assert!(
            assignment.contract.max_entry_count > 0,
            "max_entry_count should be > 0 for {}",
            assignment.contract.structure_kind
        );
    }
}

// ---------------------------------------------------------------------------
// 11. Hash determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_override_policy_same_flags_same_hash() {
    let p1 = OverridePolicy::permissive();
    let p2 = OverridePolicy::permissive();
    assert_eq!(p1.policy_hash, p2.policy_hash);
}

#[test]
fn enrichment_receipt_hash_changes_with_different_contract() {
    let contract1 = SubstrateContract::new(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
        LocalityGoal::L1Hot,
        FallbackMode::LinearScan,
        RollbackRule::SnapshottedCow,
        65536,
        850_000,
    );
    let contract2 = SubstrateContract::new(
        MetadataStructureKind::StringTable,
        SubstrateKind::ArtTree,
        LocalityGoal::L2Warm,
        FallbackMode::Rehash,
        RollbackRule::Immutable,
        262144,
        300_000,
    );
    let r1 = SubstrateSelectionReceipt::from_contract(&contract1, epoch(), "test");
    let r2 = SubstrateSelectionReceipt::from_contract(&contract2, epoch(), "test");
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_instance_clone_has_same_hash() {
    let instance = make_instance();
    let cloned = instance.clone();
    assert_eq!(instance.instance_hash, cloned.instance_hash);
}
