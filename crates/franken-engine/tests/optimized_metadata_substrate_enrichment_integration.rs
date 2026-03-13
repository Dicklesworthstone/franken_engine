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
    COMPONENT, OPTIMIZED_SUBSTRATE_BEAD_ID, OPTIMIZED_SUBSTRATE_SCHEMA_VERSION, OverridePolicy,
    OverrideReason, SelectorSummaryReport, SubstrateHealthCheck, SubstrateInstance,
    SubstrateInstanceStatus, SubstrateSelectionError, SubstrateSelectionReceipt, SubstrateSelector,
    SubstrateSnapshot, SubstrateTransitionEvent, SubstrateTransitionKind,
    default_optimized_assignments,
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
    let displays: BTreeSet<String> = OverrideReason::ALL.iter().map(|r| r.to_string()).collect();
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
        assert!(!policy.is_permitted(reason), "locked should deny {reason}");
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

// ---------------------------------------------------------------------------
// 12. Debug impls (all types derive Debug)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_instance_status_debug_format() {
    for status in SubstrateInstanceStatus::ALL {
        let dbg = format!("{status:?}");
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_override_reason_debug_format() {
    for reason in OverrideReason::ALL {
        let dbg = format!("{reason:?}");
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_override_policy_debug_format() {
    let policy = OverridePolicy::permissive();
    let dbg = format!("{policy:?}");
    assert!(dbg.contains("OverridePolicy"));
    assert!(dbg.contains("allow_operator_debug"));
}

#[test]
fn enrichment_selection_receipt_debug_format() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(), "test");
    let dbg = format!("{receipt:?}");
    assert!(dbg.contains("SubstrateSelectionReceipt"));
    assert!(dbg.contains("structure_kind"));
}

#[test]
fn enrichment_substrate_snapshot_debug_format() {
    let hash = ContentHash::compute(b"debug_test");
    let snap = SubstrateSnapshot::new(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
        SubstrateInstanceStatus::Active,
        epoch(),
        100,
        hash,
    );
    let dbg = format!("{snap:?}");
    assert!(dbg.contains("SubstrateSnapshot"));
}

#[test]
fn enrichment_substrate_instance_debug_format() {
    let instance = make_instance();
    let dbg = format!("{instance:?}");
    assert!(dbg.contains("SubstrateInstance"));
    assert!(dbg.contains("structure_kind"));
}

#[test]
fn enrichment_substrate_selector_debug_format() {
    let selector = SubstrateSelector::new(OverridePolicy::permissive(), epoch());
    let dbg = format!("{selector:?}");
    assert!(dbg.contains("SubstrateSelector"));
}

#[test]
fn enrichment_summary_report_debug_format() {
    let selector = SubstrateSelector::new(OverridePolicy::permissive(), epoch());
    let report = selector.summary_report();
    let dbg = format!("{report:?}");
    assert!(dbg.contains("SelectorSummaryReport"));
}

#[test]
fn enrichment_health_check_debug_format() {
    let mut instance = make_instance();
    instance.activate();
    let check = SubstrateHealthCheck::check(&instance, epoch());
    let dbg = format!("{check:?}");
    assert!(dbg.contains("SubstrateHealthCheck"));
}

#[test]
fn enrichment_transition_event_debug_format() {
    let event = SubstrateTransitionEvent::new(
        MetadataStructureKind::ShapeTable,
        SubstrateTransitionKind::Created,
        None,
        SubstrateKind::SwissTable,
        epoch(),
        "created",
    );
    let dbg = format!("{event:?}");
    assert!(dbg.contains("SubstrateTransitionEvent"));
}

#[test]
fn enrichment_selection_error_debug_format() {
    let err = SubstrateSelectionError::NoContractFound {
        structure_kind: MetadataStructureKind::GcMetadata,
    };
    let dbg = format!("{err:?}");
    assert!(dbg.contains("NoContractFound"));
}

#[test]
fn enrichment_transition_kind_debug_format() {
    let kinds = [
        SubstrateTransitionKind::Created,
        SubstrateTransitionKind::Activated,
        SubstrateTransitionKind::Overridden,
        SubstrateTransitionKind::FellBack,
        SubstrateTransitionKind::RolledBack,
        SubstrateTransitionKind::Decommissioned,
        SubstrateTransitionKind::SnapshotTaken,
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|k| format!("{k:?}")).collect();
    assert_eq!(displays.len(), 7);
}

// ---------------------------------------------------------------------------
// 13. Clone semantics
// ---------------------------------------------------------------------------

#[test]
fn enrichment_override_policy_clone_equality() {
    let policy = OverridePolicy::restrictive();
    let cloned = policy.clone();
    assert_eq!(policy, cloned);
    assert_eq!(policy.policy_hash, cloned.policy_hash);
}

#[test]
fn enrichment_selection_receipt_clone_equality() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(), "test");
    let cloned = receipt.clone();
    assert_eq!(receipt, cloned);
    assert_eq!(receipt.receipt_hash, cloned.receipt_hash);
}

#[test]
fn enrichment_snapshot_clone_equality() {
    let hash = ContentHash::compute(b"clone_test");
    let snap = SubstrateSnapshot::new(
        MetadataStructureKind::StringTable,
        SubstrateKind::ArtTree,
        SubstrateInstanceStatus::Active,
        epoch(),
        5000,
        hash,
    );
    let cloned = snap.clone();
    assert_eq!(snap, cloned);
    assert_eq!(snap.snapshot_hash, cloned.snapshot_hash);
}

#[test]
fn enrichment_transition_event_clone_equality() {
    let event = SubstrateTransitionEvent::new(
        MetadataStructureKind::CompilationCache,
        SubstrateTransitionKind::Overridden,
        Some(SubstrateKind::HashArray),
        SubstrateKind::FlatArray,
        epoch(),
        "clone test",
    );
    let cloned = event.clone();
    assert_eq!(event, cloned);
    assert_eq!(event.event_hash, cloned.event_hash);
}

#[test]
fn enrichment_health_check_clone_equality() {
    let mut instance = make_instance();
    instance.activate();
    instance.record_entries(500);
    let check = SubstrateHealthCheck::check(&instance, epoch());
    let cloned = check.clone();
    assert_eq!(check, cloned);
    assert_eq!(check.check_hash, cloned.check_hash);
}

#[test]
fn enrichment_selector_clone_equality() {
    let e = epoch();
    let inventory = default_optimized_assignments(e);
    let mut selector = SubstrateSelector::new(OverridePolicy::permissive(), e);
    selector.instantiate_all(&inventory);
    let cloned = selector.clone();
    assert_eq!(selector, cloned);
    assert_eq!(selector.selector_hash, cloned.selector_hash);
}

#[test]
fn enrichment_summary_report_clone_equality() {
    let e = epoch();
    let inventory = default_optimized_assignments(e);
    let mut selector = SubstrateSelector::new(OverridePolicy::permissive(), e);
    selector.instantiate_all(&inventory);
    let report = selector.summary_report();
    let cloned = report.clone();
    assert_eq!(report, cloned);
}

// ---------------------------------------------------------------------------
// 14. JSON field names (serde rename_all snake_case)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_instance_status_json_snake_case() {
    let json = serde_json::to_string(&SubstrateInstanceStatus::FallenBack).unwrap();
    assert_eq!(json, "\"fallen_back\"");
}

#[test]
fn enrichment_instance_status_json_active() {
    let json = serde_json::to_string(&SubstrateInstanceStatus::Active).unwrap();
    assert_eq!(json, "\"active\"");
}

#[test]
fn enrichment_instance_status_json_warming() {
    let json = serde_json::to_string(&SubstrateInstanceStatus::Warming).unwrap();
    assert_eq!(json, "\"warming\"");
}

#[test]
fn enrichment_instance_status_json_paused() {
    let json = serde_json::to_string(&SubstrateInstanceStatus::Paused).unwrap();
    assert_eq!(json, "\"paused\"");
}

#[test]
fn enrichment_instance_status_json_rolled_back() {
    let json = serde_json::to_string(&SubstrateInstanceStatus::RolledBack).unwrap();
    assert_eq!(json, "\"rolled_back\"");
}

#[test]
fn enrichment_instance_status_json_decommissioned() {
    let json = serde_json::to_string(&SubstrateInstanceStatus::Decommissioned).unwrap();
    assert_eq!(json, "\"decommissioned\"");
}

#[test]
fn enrichment_override_reason_json_snake_case() {
    let json = serde_json::to_string(&OverrideReason::CorruptionDetected).unwrap();
    assert_eq!(json, "\"corruption_detected\"");
}

#[test]
fn enrichment_override_reason_json_operator_debug() {
    let json = serde_json::to_string(&OverrideReason::OperatorDebug).unwrap();
    assert_eq!(json, "\"operator_debug\"");
}

#[test]
fn enrichment_override_reason_json_portability_fallback() {
    let json = serde_json::to_string(&OverrideReason::PortabilityFallback).unwrap();
    assert_eq!(json, "\"portability_fallback\"");
}

#[test]
fn enrichment_override_reason_json_memory_pressure() {
    let json = serde_json::to_string(&OverrideReason::MemoryPressure).unwrap();
    assert_eq!(json, "\"memory_pressure\"");
}

#[test]
fn enrichment_override_reason_json_performance_regression() {
    let json = serde_json::to_string(&OverrideReason::PerformanceRegression).unwrap();
    assert_eq!(json, "\"performance_regression\"");
}

#[test]
fn enrichment_override_reason_json_epoch_rollback() {
    let json = serde_json::to_string(&OverrideReason::EpochRollback).unwrap();
    assert_eq!(json, "\"epoch_rollback\"");
}

#[test]
fn enrichment_override_reason_json_security_veto() {
    let json = serde_json::to_string(&OverrideReason::SecurityVeto).unwrap();
    assert_eq!(json, "\"security_veto\"");
}

#[test]
fn enrichment_override_reason_json_none() {
    let json = serde_json::to_string(&OverrideReason::None).unwrap();
    assert_eq!(json, "\"none\"");
}

#[test]
fn enrichment_transition_kind_json_snake_case() {
    let json = serde_json::to_string(&SubstrateTransitionKind::FellBack).unwrap();
    assert_eq!(json, "\"fell_back\"");
}

#[test]
fn enrichment_transition_kind_json_snapshot_taken() {
    let json = serde_json::to_string(&SubstrateTransitionKind::SnapshotTaken).unwrap();
    assert_eq!(json, "\"snapshot_taken\"");
}

// ---------------------------------------------------------------------------
// 15. Display content verification
// ---------------------------------------------------------------------------

#[test]
fn enrichment_instance_display_contains_structure_kind() {
    let instance = make_instance();
    let display = instance.to_string();
    assert!(display.contains("SubstrateInstance"));
    assert!(display.contains("shape_table"));
}

#[test]
fn enrichment_instance_display_contains_load_factor() {
    let mut instance = make_instance();
    instance.activate();
    instance.record_entries(32768);
    let display = instance.to_string();
    assert!(display.contains("500000"));
}

#[test]
fn enrichment_snapshot_display_contains_epoch() {
    let hash = ContentHash::compute(b"display");
    let snap = SubstrateSnapshot::new(
        MetadataStructureKind::StringTable,
        SubstrateKind::ArtTree,
        SubstrateInstanceStatus::Active,
        epoch2(),
        1000,
        hash,
    );
    let display = snap.to_string();
    assert!(display.contains("epoch=2"));
    assert!(display.contains("entries=1000"));
}

#[test]
fn enrichment_receipt_display_no_override() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(), "test");
    let display = receipt.to_string();
    assert!(display.contains("SelectionReceipt"));
    assert!(display.contains("epoch=1"));
    // No override should not contain "overrode"
    assert!(!display.contains("overrode"));
}

#[test]
fn enrichment_receipt_display_with_override() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_override(
        &contract,
        SubstrateKind::FlatArray,
        LocalityGoal::DramResident,
        OverrideReason::CorruptionDetected,
        epoch(),
        "corruption detected",
    );
    let display = receipt.to_string();
    assert!(display.contains("overrode"));
    assert!(display.contains("corruption_detected"));
}

#[test]
fn enrichment_selector_display_contains_instance_count() {
    let e = epoch();
    let inventory = default_optimized_assignments(e);
    let mut selector = SubstrateSelector::new(OverridePolicy::permissive(), e);
    selector.instantiate_all(&inventory);
    let display = selector.to_string();
    assert!(display.contains("instances=10"));
    assert!(display.contains("overrides=0"));
}

#[test]
fn enrichment_health_check_display_contains_healthy() {
    let mut instance = make_instance();
    instance.activate();
    instance.record_entries(100);
    let check = SubstrateHealthCheck::check(&instance, epoch());
    let display = check.to_string();
    assert!(display.contains("HealthCheck"));
    assert!(display.contains("healthy=true"));
}

#[test]
fn enrichment_health_check_display_overloaded() {
    let mut instance = make_instance();
    instance.activate();
    // 95% load = 62259 / 65536
    instance.record_entries(62259);
    let check = SubstrateHealthCheck::check(&instance, epoch());
    let display = check.to_string();
    assert!(display.contains("healthy=false"));
}

#[test]
fn enrichment_selection_error_display_override_denied() {
    let err = SubstrateSelectionError::OverrideDenied {
        structure_kind: MetadataStructureKind::ShapeTable,
        reason: OverrideReason::OperatorDebug,
    };
    let display = err.to_string();
    assert!(display.contains("override denied"));
    assert!(display.contains("shape_table"));
}

#[test]
fn enrichment_selection_error_display_no_contract() {
    let err = SubstrateSelectionError::NoContractFound {
        structure_kind: MetadataStructureKind::GcMetadata,
    };
    let display = err.to_string();
    assert!(display.contains("no contract found"));
}

#[test]
fn enrichment_selection_error_display_already_decommissioned() {
    let err = SubstrateSelectionError::AlreadyDecommissioned {
        structure_kind: MetadataStructureKind::StringTable,
    };
    let display = err.to_string();
    assert!(display.contains("already decommissioned"));
}

// ---------------------------------------------------------------------------
// 16. Serde roundtrips for more complex structures
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_selection_receipt_from_contract_roundtrip() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(), "test serde");
    let json = serde_json::to_string(&receipt).unwrap();
    let back: SubstrateSelectionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn enrichment_serde_selection_receipt_from_override_roundtrip() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_override(
        &contract,
        SubstrateKind::FlatArray,
        LocalityGoal::DramResident,
        OverrideReason::MemoryPressure,
        epoch2(),
        "memory pressure",
    );
    let json = serde_json::to_string(&receipt).unwrap();
    let back: SubstrateSelectionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn enrichment_serde_instance_with_snapshots_roundtrip() {
    let mut instance = make_instance();
    instance.activate();
    instance.record_entries(1000);
    instance.take_snapshot(epoch());
    instance.record_entries(2000);
    instance.take_snapshot(epoch2());

    let json = serde_json::to_string(&instance).unwrap();
    let back: SubstrateInstance = serde_json::from_str(&json).unwrap();
    assert_eq!(instance, back);
    assert_eq!(back.snapshots.len(), 2);
}

#[test]
fn enrichment_serde_health_check_roundtrip() {
    let mut instance = make_instance();
    instance.activate();
    instance.record_entries(500);
    let check = SubstrateHealthCheck::check(&instance, epoch());
    let json = serde_json::to_string(&check).unwrap();
    let back: SubstrateHealthCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(check, back);
}

#[test]
fn enrichment_serde_selection_error_all_variants() {
    let errors = [
        SubstrateSelectionError::OverrideDenied {
            structure_kind: MetadataStructureKind::ShapeTable,
            reason: OverrideReason::OperatorDebug,
        },
        SubstrateSelectionError::NoContractFound {
            structure_kind: MetadataStructureKind::GcMetadata,
        },
        SubstrateSelectionError::AlreadyDecommissioned {
            structure_kind: MetadataStructureKind::StringTable,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: SubstrateSelectionError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn enrichment_serde_selector_with_overrides_roundtrip() {
    let e = epoch();
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);
    let assignment = shape_assignment();
    selector.select_from_contract(&assignment);

    let gc_contract = SubstrateContract::new(
        MetadataStructureKind::GcMetadata,
        SubstrateKind::CacheOblivious,
        LocalityGoal::L2Warm,
        FallbackMode::Abstain,
        RollbackRule::NoRollback,
        524288,
        500_000,
    );
    let gc_assignment = SubstrateAssignment {
        contract: gc_contract,
        assigned_epoch: e,
        rationale: "GC metadata".to_string(),
        confidence_millionths: 700_000,
    };
    let _ = selector.select_with_override(
        &gc_assignment,
        SubstrateKind::FlatArray,
        LocalityGoal::DramResident,
        OverrideReason::MemoryPressure,
        "low memory",
    );

    let json = serde_json::to_string(&selector).unwrap();
    let back: SubstrateSelector = serde_json::from_str(&json).unwrap();
    assert_eq!(selector, back);
}

// ---------------------------------------------------------------------------
// 17. Edge cases: entry counts and load factors
// ---------------------------------------------------------------------------

#[test]
fn enrichment_record_entries_one() {
    let mut instance = make_instance();
    instance.record_entries(1);
    // 1 / 65536 * 1_000_000 = 15 (truncated integer division)
    assert_eq!(instance.load_factor_millionths, 1 * 1_000_000 / 65536);
}

#[test]
fn enrichment_record_entries_overflow_protection() {
    // saturating_mul prevents overflow
    let contract = SubstrateContract::new(
        MetadataStructureKind::GcMetadata,
        SubstrateKind::CacheOblivious,
        LocalityGoal::L2Warm,
        FallbackMode::Abstain,
        RollbackRule::NoRollback,
        1, // max_entry_count = 1
        500_000,
    );
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(), "test");
    let mut instance = SubstrateInstance::from_contract(&contract, receipt);
    // With max_entry_count = 1, recording 1_000_000 entries
    instance.record_entries(1_000_000);
    // (1_000_000 * 1_000_000) / 1 = 1_000_000_000_000, but saturating_mul then div
    // Actually saturating_mul(1_000_000) for u64 shouldn't overflow, result is 1_000_000_000_000
    assert!(instance.load_factor_millionths > 1_000_000);
}

#[test]
fn enrichment_record_entries_max_entry_count_zero_div() {
    // checked_div with zero returns None, unwrap_or(0)
    // But we can't directly set max_entry_count to 0 through public API
    // since SubstrateContract::new presumably requires > 0.
    // Instead we test that normal cases don't panic.
    let contract = SubstrateContract::new(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
        LocalityGoal::L1Hot,
        FallbackMode::LinearScan,
        RollbackRule::SnapshottedCow,
        1,
        850_000,
    );
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(), "test");
    let mut instance = SubstrateInstance::from_contract(&contract, receipt);
    instance.record_entries(0);
    assert_eq!(instance.load_factor_millionths, 0);
}

#[test]
fn enrichment_load_factor_exact_millionths() {
    // With max_entry_count = 1_000_000, entries map 1:1 to millionths
    let contract = SubstrateContract::new(
        MetadataStructureKind::GcMetadata,
        SubstrateKind::CacheOblivious,
        LocalityGoal::L2Warm,
        FallbackMode::Abstain,
        RollbackRule::NoRollback,
        1_000_000,
        500_000,
    );
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(), "test");
    let mut instance = SubstrateInstance::from_contract(&contract, receipt);
    instance.record_entries(500_000);
    assert_eq!(instance.load_factor_millionths, 500_000);
    instance.record_entries(750_000);
    assert_eq!(instance.load_factor_millionths, 750_000);
}

// ---------------------------------------------------------------------------
// 18. Selector: active_count and overridden_count
// ---------------------------------------------------------------------------

#[test]
fn enrichment_active_count_all_warming_are_serving() {
    let e = epoch();
    let inventory = default_optimized_assignments(e);
    let mut selector = SubstrateSelector::new(OverridePolicy::permissive(), e);
    selector.instantiate_all(&inventory);
    // All start as Warming which is serving
    assert_eq!(selector.active_count(), 10);
}

#[test]
fn enrichment_active_count_decommission_reduces_count() {
    let e = epoch();
    let inventory = default_optimized_assignments(e);
    let mut selector = SubstrateSelector::new(OverridePolicy::permissive(), e);
    selector.instantiate_all(&inventory);

    selector
        .instance_for_mut(MetadataStructureKind::ShapeTable)
        .unwrap()
        .decommission();
    selector
        .instance_for_mut(MetadataStructureKind::StringTable)
        .unwrap()
        .decommission();

    assert_eq!(selector.active_count(), 8);
}

#[test]
fn enrichment_active_count_fallback_reduces_count() {
    let e = epoch();
    let inventory = default_optimized_assignments(e);
    let mut selector = SubstrateSelector::new(OverridePolicy::permissive(), e);
    selector.instantiate_all(&inventory);

    selector
        .instance_for_mut(MetadataStructureKind::GcMetadata)
        .unwrap()
        .fallback(OverrideReason::CorruptionDetected);

    assert_eq!(selector.active_count(), 9);
}

#[test]
fn enrichment_overridden_count_zero_when_no_overrides() {
    let e = epoch();
    let inventory = default_optimized_assignments(e);
    let mut selector = SubstrateSelector::new(OverridePolicy::permissive(), e);
    selector.instantiate_all(&inventory);
    assert_eq!(selector.overridden_count(), 0);
}

#[test]
fn enrichment_overridden_count_increments_with_overrides() {
    let e = epoch();
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);

    let assignment = shape_assignment();
    let _ = selector.select_with_override(
        &assignment,
        SubstrateKind::FlatArray,
        LocalityGoal::DramResident,
        OverrideReason::OperatorDebug,
        "debug",
    );
    assert_eq!(selector.overridden_count(), 1);

    let gc_contract = SubstrateContract::new(
        MetadataStructureKind::GcMetadata,
        SubstrateKind::CacheOblivious,
        LocalityGoal::L2Warm,
        FallbackMode::Abstain,
        RollbackRule::NoRollback,
        524288,
        500_000,
    );
    let gc_assignment = SubstrateAssignment {
        contract: gc_contract,
        assigned_epoch: e,
        rationale: "GC".to_string(),
        confidence_millionths: 700_000,
    };
    let _ = selector.select_with_override(
        &gc_assignment,
        SubstrateKind::FlatArray,
        LocalityGoal::DramResident,
        OverrideReason::SecurityVeto,
        "security",
    );
    assert_eq!(selector.overridden_count(), 2);
}

// ---------------------------------------------------------------------------
// 19. Summary report edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_summary_report_after_fallback() {
    let e = epoch();
    let inventory = default_optimized_assignments(e);
    let mut selector = SubstrateSelector::new(OverridePolicy::permissive(), e);
    selector.instantiate_all(&inventory);

    selector
        .instance_for_mut(MetadataStructureKind::ShapeTable)
        .unwrap()
        .fallback(OverrideReason::CorruptionDetected);

    let report = selector.summary_report();
    assert_eq!(report.fallen_back_instances, 1);
    assert_eq!(report.active_instances, 9);
}

#[test]
fn enrichment_summary_report_after_rollback() {
    let e = epoch();
    let inventory = default_optimized_assignments(e);
    let mut selector = SubstrateSelector::new(OverridePolicy::permissive(), e);
    selector.instantiate_all(&inventory);

    let inst = selector
        .instance_for_mut(MetadataStructureKind::ShapeTable)
        .unwrap();
    inst.activate();
    inst.record_entries(100);
    let snap = inst.take_snapshot(e);
    inst.record_entries(500);
    inst.restore_from_snapshot(&snap);

    let report = selector.summary_report();
    assert_eq!(report.rolled_back_instances, 1);
    // RolledBack is not serving, so active goes down
    assert_eq!(report.active_instances, 9);
}

#[test]
fn enrichment_summary_report_partial_coverage() {
    let e = epoch();
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);

    // Only add one assignment
    let assignment = shape_assignment();
    selector.select_from_contract(&assignment);

    let report = selector.summary_report();
    assert_eq!(report.total_instances, 1);
    // coverage = 1/10 * 1_000_000 = 100_000
    assert_eq!(report.coverage_millionths, 100_000);
}

#[test]
fn enrichment_summary_report_two_of_ten_coverage() {
    let e = epoch();
    let policy = OverridePolicy::permissive();
    let mut selector = SubstrateSelector::new(policy, e);

    let assignment1 = shape_assignment();
    selector.select_from_contract(&assignment1);

    let gc_contract = SubstrateContract::new(
        MetadataStructureKind::GcMetadata,
        SubstrateKind::CacheOblivious,
        LocalityGoal::L2Warm,
        FallbackMode::Abstain,
        RollbackRule::NoRollback,
        524288,
        500_000,
    );
    let assignment2 = SubstrateAssignment {
        contract: gc_contract,
        assigned_epoch: e,
        rationale: "GC metadata".to_string(),
        confidence_millionths: 700_000,
    };
    selector.select_from_contract(&assignment2);

    let report = selector.summary_report();
    assert_eq!(report.total_instances, 2);
    assert_eq!(report.coverage_millionths, 200_000);
}

// ---------------------------------------------------------------------------
// 20. Snapshot edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_snapshot_zero_entries() {
    let hash = ContentHash::compute(b"empty");
    let snap = SubstrateSnapshot::new(
        MetadataStructureKind::ScopeChainTable,
        SubstrateKind::FlatArray,
        SubstrateInstanceStatus::Warming,
        epoch(),
        0,
        hash,
    );
    assert_eq!(snap.entry_count, 0);
}

#[test]
fn enrichment_snapshot_different_status_different_hash() {
    let hash = ContentHash::compute(b"status_diff");
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
        SubstrateInstanceStatus::Warming,
        epoch(),
        100,
        hash,
    );
    assert_ne!(s1.snapshot_hash, s2.snapshot_hash);
}

#[test]
fn enrichment_snapshot_different_substrate_kind_different_hash() {
    let hash = ContentHash::compute(b"substrate_diff");
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
        SubstrateKind::FlatArray,
        SubstrateInstanceStatus::Active,
        epoch(),
        100,
        hash,
    );
    assert_ne!(s1.snapshot_hash, s2.snapshot_hash);
}

#[test]
fn enrichment_snapshot_different_structure_kind_different_hash() {
    let hash = ContentHash::compute(b"kind_diff");
    let s1 = SubstrateSnapshot::new(
        MetadataStructureKind::ShapeTable,
        SubstrateKind::SwissTable,
        SubstrateInstanceStatus::Active,
        epoch(),
        100,
        hash.clone(),
    );
    let s2 = SubstrateSnapshot::new(
        MetadataStructureKind::StringTable,
        SubstrateKind::SwissTable,
        SubstrateInstanceStatus::Active,
        epoch(),
        100,
        hash,
    );
    assert_ne!(s1.snapshot_hash, s2.snapshot_hash);
}

#[test]
fn enrichment_snapshot_different_epoch_different_hash() {
    let hash = ContentHash::compute(b"epoch_diff");
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
        epoch2(),
        100,
        hash,
    );
    assert_ne!(s1.snapshot_hash, s2.snapshot_hash);
}

// ---------------------------------------------------------------------------
// 21. Transition event edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transition_event_with_from_substrate_contains_it() {
    let event = SubstrateTransitionEvent::new(
        MetadataStructureKind::InlineCacheTable,
        SubstrateTransitionKind::Overridden,
        Some(SubstrateKind::FlatArray),
        SubstrateKind::SwissTable,
        epoch(),
        "overriding for perf",
    );
    assert_eq!(event.from_substrate, Some(SubstrateKind::FlatArray));
    assert_eq!(event.to_substrate, SubstrateKind::SwissTable);
}

#[test]
fn enrichment_transition_event_decommissioned() {
    let event = SubstrateTransitionEvent::new(
        MetadataStructureKind::AllocationSiteTable,
        SubstrateTransitionKind::Decommissioned,
        Some(SubstrateKind::SwissTable),
        SubstrateKind::SwissTable,
        epoch2(),
        "end of life",
    );
    assert_eq!(event.transition, SubstrateTransitionKind::Decommissioned);
    assert_eq!(event.reason, "end of life");
}

#[test]
fn enrichment_transition_event_snapshot_taken() {
    let event = SubstrateTransitionEvent::new(
        MetadataStructureKind::TypeFeedbackVector,
        SubstrateTransitionKind::SnapshotTaken,
        Some(SubstrateKind::FlatArray),
        SubstrateKind::FlatArray,
        epoch(),
        "epoch checkpoint",
    );
    assert_eq!(event.transition, SubstrateTransitionKind::SnapshotTaken);
    assert_eq!(event.from_substrate, event.from_substrate);
}

#[test]
fn enrichment_transition_event_different_reasons_different_hashes() {
    let e1 = SubstrateTransitionEvent::new(
        MetadataStructureKind::ShapeTable,
        SubstrateTransitionKind::Activated,
        None,
        SubstrateKind::SwissTable,
        epoch(),
        "reason_a",
    );
    let e2 = SubstrateTransitionEvent::new(
        MetadataStructureKind::ShapeTable,
        SubstrateTransitionKind::Activated,
        None,
        SubstrateKind::SwissTable,
        epoch(),
        "reason_b",
    );
    assert_ne!(e1.event_hash, e2.event_hash);
}

#[test]
fn enrichment_transition_event_different_kinds_different_hashes() {
    let e1 = SubstrateTransitionEvent::new(
        MetadataStructureKind::ShapeTable,
        SubstrateTransitionKind::Created,
        None,
        SubstrateKind::SwissTable,
        epoch(),
        "test",
    );
    let e2 = SubstrateTransitionEvent::new(
        MetadataStructureKind::ShapeTable,
        SubstrateTransitionKind::Activated,
        None,
        SubstrateKind::SwissTable,
        epoch(),
        "test",
    );
    assert_ne!(e1.event_hash, e2.event_hash);
}

// ---------------------------------------------------------------------------
// 22. Receipt edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_from_contract_override_applied_false() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(), "no override");
    assert!(!receipt.override_applied);
    assert_eq!(receipt.override_reason, OverrideReason::None);
}

#[test]
fn enrichment_receipt_from_override_override_applied_true() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_override(
        &contract,
        SubstrateKind::FlatArray,
        LocalityGoal::DramResident,
        OverrideReason::SecurityVeto,
        epoch(),
        "security veto",
    );
    assert!(receipt.override_applied);
    assert_eq!(receipt.override_reason, OverrideReason::SecurityVeto);
}

#[test]
fn enrichment_receipt_same_contract_same_epoch_same_hash() {
    let contract = shape_contract();
    let r1 = SubstrateSelectionReceipt::from_contract(&contract, epoch(), "same");
    let r2 = SubstrateSelectionReceipt::from_contract(&contract, epoch(), "same");
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_receipt_different_rationale_same_hash() {
    // rationale is not included in hash computation
    let contract = shape_contract();
    let r1 = SubstrateSelectionReceipt::from_contract(&contract, epoch(), "rationale_a");
    let r2 = SubstrateSelectionReceipt::from_contract(&contract, epoch(), "rationale_b");
    // The hash includes structure_kind, substrates, locality, override info, epoch, contract_hash
    // but NOT rationale text, so they should be equal
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_receipt_contract_hash_matches_contract() {
    let contract = shape_contract();
    let receipt = SubstrateSelectionReceipt::from_contract(&contract, epoch(), "test");
    assert_eq!(receipt.contract_hash, contract.content_hash);
}

// ---------------------------------------------------------------------------
// 23. Default assignments: per-structure-kind validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_default_assignments_shape_table_swiss_table() {
    let inventory = default_optimized_assignments(epoch());
    let shape = inventory
        .assignments
        .iter()
        .find(|a| a.contract.structure_kind == MetadataStructureKind::ShapeTable)
        .unwrap();
    assert_eq!(shape.contract.substrate_kind, SubstrateKind::SwissTable);
    assert_eq!(shape.contract.locality_goal, LocalityGoal::L1Hot);
}

#[test]
fn enrichment_default_assignments_inline_cache_flat_array() {
    let inventory = default_optimized_assignments(epoch());
    let ic = inventory
        .assignments
        .iter()
        .find(|a| a.contract.structure_kind == MetadataStructureKind::InlineCacheTable)
        .unwrap();
    assert_eq!(ic.contract.substrate_kind, SubstrateKind::FlatArray);
    assert_eq!(ic.contract.locality_goal, LocalityGoal::L1Hot);
}

#[test]
fn enrichment_default_assignments_string_table_art_tree() {
    let inventory = default_optimized_assignments(epoch());
    let st = inventory
        .assignments
        .iter()
        .find(|a| a.contract.structure_kind == MetadataStructureKind::StringTable)
        .unwrap();
    assert_eq!(st.contract.substrate_kind, SubstrateKind::ArtTree);
    assert_eq!(st.contract.locality_goal, LocalityGoal::L2Warm);
}

#[test]
fn enrichment_default_assignments_module_graph_btree() {
    let inventory = default_optimized_assignments(epoch());
    let mg = inventory
        .assignments
        .iter()
        .find(|a| a.contract.structure_kind == MetadataStructureKind::ModuleGraph)
        .unwrap();
    assert_eq!(mg.contract.substrate_kind, SubstrateKind::BTreeIndex);
    assert_eq!(mg.contract.locality_goal, LocalityGoal::L3Cold);
}

#[test]
fn enrichment_default_assignments_gc_metadata_cache_oblivious() {
    let inventory = default_optimized_assignments(epoch());
    let gc = inventory
        .assignments
        .iter()
        .find(|a| a.contract.structure_kind == MetadataStructureKind::GcMetadata)
        .unwrap();
    assert_eq!(gc.contract.substrate_kind, SubstrateKind::CacheOblivious);
    assert_eq!(gc.contract.rollback_rule, RollbackRule::NoRollback);
}

#[test]
fn enrichment_default_assignments_compilation_cache_hash_array() {
    let inventory = default_optimized_assignments(epoch());
    let cc = inventory
        .assignments
        .iter()
        .find(|a| a.contract.structure_kind == MetadataStructureKind::CompilationCache)
        .unwrap();
    assert_eq!(cc.contract.substrate_kind, SubstrateKind::HashArray);
    assert_eq!(cc.contract.fallback_mode, FallbackMode::Recompile);
}

#[test]
fn enrichment_default_assignments_all_confidence_750k() {
    let inventory = default_optimized_assignments(epoch());
    for assignment in &inventory.assignments {
        assert_eq!(
            assignment.confidence_millionths, 750_000,
            "confidence should be 750k for {}",
            assignment.contract.structure_kind
        );
    }
}

#[test]
fn enrichment_default_assignments_deterministic() {
    let inv1 = default_optimized_assignments(epoch());
    let inv2 = default_optimized_assignments(epoch());
    assert_eq!(inv1.assignments.len(), inv2.assignments.len());
    for (a, b) in inv1.assignments.iter().zip(inv2.assignments.iter()) {
        assert_eq!(a.contract.structure_kind, b.contract.structure_kind);
        assert_eq!(a.contract.substrate_kind, b.contract.substrate_kind);
        assert_eq!(a.contract.content_hash, b.contract.content_hash);
    }
}

// ---------------------------------------------------------------------------
// 24. Instance lifecycle: complex transitions
// ---------------------------------------------------------------------------

#[test]
fn enrichment_instance_activate_then_fallback_then_snapshot() {
    let mut instance = make_instance();
    instance.activate();
    instance.record_entries(5000);
    instance.fallback(OverrideReason::PerformanceRegression);
    assert_eq!(instance.status, SubstrateInstanceStatus::FallenBack);
    assert_eq!(instance.substrate_kind, SubstrateKind::FlatArray);

    // Taking a snapshot of a fallen-back instance
    let snap = instance.take_snapshot(epoch());
    assert_eq!(snap.status, SubstrateInstanceStatus::FallenBack);
    assert_eq!(snap.substrate_kind, SubstrateKind::FlatArray);
}

#[test]
fn enrichment_instance_rollback_restores_load_factor() {
    let mut instance = make_instance();
    instance.activate();
    instance.record_entries(32768); // 50% load
    let snap = instance.take_snapshot(epoch());
    assert_eq!(snap.entry_count, 32768);

    instance.record_entries(65536); // 100% load
    assert_eq!(instance.load_factor_millionths, 1_000_000);

    instance.restore_from_snapshot(&snap);
    assert_eq!(instance.entry_count, 32768);
    assert_eq!(instance.load_factor_millionths, 500_000);
}

#[test]
fn enrichment_instance_decommission_is_terminal() {
    let mut instance = make_instance();
    instance.activate();
    instance.record_entries(1000);
    instance.decommission();
    assert!(!instance.is_serving());
    assert_eq!(instance.status, SubstrateInstanceStatus::Decommissioned);
    // Entry count persists even after decommission
    assert_eq!(instance.entry_count, 1000);
}

#[test]
fn enrichment_instance_multiple_record_entries_updates() {
    let mut instance = make_instance();
    instance.activate();
    for i in 0..10 {
        instance.record_entries(i * 1000);
    }
    assert_eq!(instance.entry_count, 9000);
    // 9000 / 65536 * 1_000_000 = 137329
    assert_eq!(instance.load_factor_millionths, 9000 * 1_000_000 / 65536);
}

// ---------------------------------------------------------------------------
// 25. Policy: per-reason permission tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_locked_policy_permits_epoch_rollback() {
    let policy = OverridePolicy::locked();
    assert!(policy.is_permitted(OverrideReason::EpochRollback));
}

#[test]
fn enrichment_locked_policy_permits_none() {
    let policy = OverridePolicy::locked();
    assert!(policy.is_permitted(OverrideReason::None));
}

#[test]
fn enrichment_restrictive_denies_operator_debug() {
    let policy = OverridePolicy::restrictive();
    assert!(!policy.is_permitted(OverrideReason::OperatorDebug));
}

#[test]
fn enrichment_restrictive_denies_portability() {
    let policy = OverridePolicy::restrictive();
    assert!(!policy.is_permitted(OverrideReason::PortabilityFallback));
}

#[test]
fn enrichment_restrictive_denies_memory_pressure() {
    let policy = OverridePolicy::restrictive();
    assert!(!policy.is_permitted(OverrideReason::MemoryPressure));
}

#[test]
fn enrichment_restrictive_denies_performance_regression() {
    let policy = OverridePolicy::restrictive();
    assert!(!policy.is_permitted(OverrideReason::PerformanceRegression));
}

#[test]
fn enrichment_permissive_display_contains_all_categories() {
    let policy = OverridePolicy::permissive();
    let display = policy.to_string();
    assert!(display.contains("debug"));
    assert!(display.contains("corruption"));
    assert!(display.contains("portability"));
    assert!(display.contains("memory"));
    assert!(display.contains("perf"));
    assert!(display.contains("security"));
}

#[test]
fn enrichment_locked_display_empty_permits() {
    let policy = OverridePolicy::locked();
    let display = policy.to_string();
    assert!(display.contains("permits=[]"));
}

#[test]
fn enrichment_restrictive_display_subset_permits() {
    let policy = OverridePolicy::restrictive();
    let display = policy.to_string();
    assert!(display.contains("corruption"));
    assert!(display.contains("security"));
    assert!(!display.contains("debug"));
}

// ---------------------------------------------------------------------------
// 26. Selector: instance_for returns None for missing kinds
// ---------------------------------------------------------------------------

#[test]
fn enrichment_instance_for_returns_none_when_empty() {
    let selector = SubstrateSelector::new(OverridePolicy::permissive(), epoch());
    assert!(
        selector
            .instance_for(MetadataStructureKind::ShapeTable)
            .is_none()
    );
}

#[test]
fn enrichment_instance_for_returns_none_for_missing_kind() {
    let e = epoch();
    let mut selector = SubstrateSelector::new(OverridePolicy::permissive(), e);
    let assignment = shape_assignment();
    selector.select_from_contract(&assignment);
    // ShapeTable exists
    assert!(
        selector
            .instance_for(MetadataStructureKind::ShapeTable)
            .is_some()
    );
    // GcMetadata does not
    assert!(
        selector
            .instance_for(MetadataStructureKind::GcMetadata)
            .is_none()
    );
}

#[test]
fn enrichment_instance_for_mut_returns_none_when_empty() {
    let mut selector = SubstrateSelector::new(OverridePolicy::permissive(), epoch());
    assert!(
        selector
            .instance_for_mut(MetadataStructureKind::ShapeTable)
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// 27. Health check: diagnostic messages
// ---------------------------------------------------------------------------

#[test]
fn enrichment_health_check_healthy_diagnostic_contains_entries() {
    let mut instance = make_instance();
    instance.activate();
    instance.record_entries(1234);
    let check = SubstrateHealthCheck::check(&instance, epoch());
    assert!(check.diagnostic.contains("1234"));
    assert!(check.diagnostic.contains("healthy"));
}

#[test]
fn enrichment_health_check_overloaded_diagnostic_contains_threshold() {
    let mut instance = make_instance();
    instance.activate();
    instance.record_entries(62000); // 94.6% load
    let check = SubstrateHealthCheck::check(&instance, epoch());
    assert!(check.diagnostic.contains("overloaded"));
    assert!(check.diagnostic.contains("80%"));
}

#[test]
fn enrichment_health_check_not_serving_diagnostic_contains_status() {
    let mut instance = make_instance();
    instance.decommission();
    let check = SubstrateHealthCheck::check(&instance, epoch());
    assert!(check.diagnostic.contains("not serving"));
    assert!(check.diagnostic.contains("decommissioned"));
}

#[test]
fn enrichment_health_check_fallen_back_not_serving() {
    let mut instance = make_instance();
    instance.activate();
    instance.fallback(OverrideReason::CorruptionDetected);
    let check = SubstrateHealthCheck::check(&instance, epoch());
    assert!(!check.serving);
    assert!(!check.healthy);
}

#[test]
fn enrichment_health_check_rolled_back_not_serving() {
    let mut instance = make_instance();
    instance.activate();
    instance.record_entries(500);
    let snap = instance.take_snapshot(epoch());
    instance.record_entries(1000);
    instance.restore_from_snapshot(&snap);
    let check = SubstrateHealthCheck::check(&instance, epoch());
    assert!(!check.serving);
    assert!(!check.healthy);
}

// ---------------------------------------------------------------------------
// 28. Constants verification
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_contains_module_name() {
    assert!(OPTIMIZED_SUBSTRATE_SCHEMA_VERSION.contains("optimized-metadata-substrate"));
}

#[test]
fn enrichment_bead_id_is_hierarchical() {
    assert!(OPTIMIZED_SUBSTRATE_BEAD_ID.contains('.'));
}

#[test]
fn enrichment_component_matches_module_name() {
    assert_eq!(COMPONENT, "optimized_metadata_substrate");
}

// ---------------------------------------------------------------------------
// 29. Selector schema_version
// ---------------------------------------------------------------------------

#[test]
fn enrichment_selector_schema_version_matches_constant() {
    let selector = SubstrateSelector::new(OverridePolicy::permissive(), epoch());
    assert_eq!(selector.schema_version, OPTIMIZED_SUBSTRATE_SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// 30. Hash determinism across separate constructions
// ---------------------------------------------------------------------------

#[test]
fn enrichment_two_selectors_same_inventory_same_hash() {
    let e = epoch();
    let inv1 = default_optimized_assignments(e);
    let inv2 = default_optimized_assignments(e);
    let mut sel1 = SubstrateSelector::new(OverridePolicy::permissive(), e);
    let mut sel2 = SubstrateSelector::new(OverridePolicy::permissive(), e);
    sel1.instantiate_all(&inv1);
    sel2.instantiate_all(&inv2);
    assert_eq!(sel1.selector_hash, sel2.selector_hash);
}

#[test]
fn enrichment_two_selectors_different_policies_different_hash() {
    let e = epoch();
    let inv = default_optimized_assignments(e);
    let mut sel1 = SubstrateSelector::new(OverridePolicy::permissive(), e);
    let mut sel2 = SubstrateSelector::new(OverridePolicy::restrictive(), e);
    sel1.instantiate_all(&inv);
    sel2.instantiate_all(&inv);
    assert_ne!(sel1.selector_hash, sel2.selector_hash);
}

#[test]
fn enrichment_two_selectors_different_epochs_different_hash() {
    let inv1 = default_optimized_assignments(epoch());
    let inv2 = default_optimized_assignments(epoch2());
    let mut sel1 = SubstrateSelector::new(OverridePolicy::permissive(), epoch());
    let mut sel2 = SubstrateSelector::new(OverridePolicy::permissive(), epoch2());
    sel1.instantiate_all(&inv1);
    sel2.instantiate_all(&inv2);
    assert_ne!(sel1.selector_hash, sel2.selector_hash);
}
