#![forbid(unsafe_code)]
//! Enrichment integration tests for `frankenlab_harness_migration`.
//!
//! Covers MigrationStatus classification, Display uniqueness, LifecycleScenarioId::ALL
//! completeness, serde roundtrips, constant values, ContainmentTestKind, registry
//! operations, and migration lifecycle transitions.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::frankenlab_harness_migration::{
    ContainmentTestEntry, ContainmentTestKind, HARNESS_MIGRATION_BEAD_ID,
    HARNESS_MIGRATION_SCHEMA_VERSION, HarnessMigrationRegistry, LifecycleScenarioId,
    MigrationStatus, ScenarioMigrationEntry,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// helpers
// ===========================================================================

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

// ===========================================================================
// MigrationStatus classification
// ===========================================================================

#[test]
fn enrichment_migration_status_is_upstream_backed_migrated() {
    assert!(MigrationStatus::Migrated.is_upstream_backed());
}

#[test]
fn enrichment_migration_status_is_upstream_backed_verified() {
    assert!(MigrationStatus::Verified.is_upstream_backed());
}

#[test]
fn enrichment_migration_status_not_upstream_backed_local_only() {
    assert!(!MigrationStatus::LocalOnly.is_upstream_backed());
}

#[test]
fn enrichment_migration_status_not_upstream_backed_in_progress() {
    assert!(!MigrationStatus::InProgress.is_upstream_backed());
}

#[test]
fn enrichment_migration_status_not_upstream_backed_deferred() {
    assert!(!MigrationStatus::Deferred.is_upstream_backed());
}

#[test]
fn enrichment_migration_status_needs_work_local_only() {
    assert!(MigrationStatus::LocalOnly.needs_work());
}

#[test]
fn enrichment_migration_status_needs_work_in_progress() {
    assert!(MigrationStatus::InProgress.needs_work());
}

#[test]
fn enrichment_migration_status_no_work_migrated() {
    assert!(!MigrationStatus::Migrated.needs_work());
}

#[test]
fn enrichment_migration_status_no_work_verified() {
    assert!(!MigrationStatus::Verified.needs_work());
}

#[test]
fn enrichment_migration_status_no_work_deferred() {
    assert!(!MigrationStatus::Deferred.needs_work());
}

// ===========================================================================
// MigrationStatus Display uniqueness
// ===========================================================================

#[test]
fn enrichment_migration_status_display_all_unique() {
    let all = [
        MigrationStatus::LocalOnly,
        MigrationStatus::InProgress,
        MigrationStatus::Migrated,
        MigrationStatus::Verified,
        MigrationStatus::Deferred,
    ];
    let set: BTreeSet<String> = all.iter().map(|s| s.to_string()).collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_migration_status_display_exact_values() {
    assert_eq!(MigrationStatus::LocalOnly.to_string(), "local_only");
    assert_eq!(MigrationStatus::InProgress.to_string(), "in_progress");
    assert_eq!(MigrationStatus::Migrated.to_string(), "migrated");
    assert_eq!(MigrationStatus::Verified.to_string(), "verified");
    assert_eq!(MigrationStatus::Deferred.to_string(), "deferred");
}

// ===========================================================================
// MigrationStatus serde roundtrips
// ===========================================================================

#[test]
fn enrichment_migration_status_serde_all_variants() {
    let all = [
        MigrationStatus::LocalOnly,
        MigrationStatus::InProgress,
        MigrationStatus::Migrated,
        MigrationStatus::Verified,
        MigrationStatus::Deferred,
    ];
    for status in &all {
        let json = serde_json::to_string(status).unwrap();
        let back: MigrationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*status, back);
    }
}

#[test]
fn enrichment_migration_status_serde_tags_distinct() {
    let all = [
        MigrationStatus::LocalOnly,
        MigrationStatus::InProgress,
        MigrationStatus::Migrated,
        MigrationStatus::Verified,
        MigrationStatus::Deferred,
    ];
    let tags: BTreeSet<String> = all
        .iter()
        .map(|s| serde_json::to_string(s).unwrap())
        .collect();
    assert_eq!(tags.len(), 5);
}

// ===========================================================================
// LifecycleScenarioId::ALL completeness
// ===========================================================================

#[test]
fn enrichment_lifecycle_scenario_id_all_has_10_entries() {
    assert_eq!(LifecycleScenarioId::ALL.len(), 10);
}

#[test]
fn enrichment_lifecycle_scenario_id_all_unique() {
    let set: BTreeSet<LifecycleScenarioId> = LifecycleScenarioId::ALL.iter().copied().collect();
    assert_eq!(set.len(), 10);
}

#[test]
fn enrichment_lifecycle_scenario_id_display_all_unique() {
    let displays: BTreeSet<String> = LifecycleScenarioId::ALL
        .iter()
        .map(|id| id.to_string())
        .collect();
    assert_eq!(displays.len(), 10);
}

#[test]
fn enrichment_lifecycle_scenario_id_serde_roundtrip_all() {
    for id in &LifecycleScenarioId::ALL {
        let json = serde_json::to_string(id).unwrap();
        let back: LifecycleScenarioId = serde_json::from_str(&json).unwrap();
        assert_eq!(*id, back);
    }
}

#[test]
fn enrichment_lifecycle_scenario_id_ord_follows_declaration() {
    for pair in LifecycleScenarioId::ALL.windows(2) {
        assert!(pair[0] < pair[1], "{:?} should be < {:?}", pair[0], pair[1]);
    }
}

// ===========================================================================
// ContainmentTestKind
// ===========================================================================

#[test]
fn enrichment_containment_test_kind_all_has_8_entries() {
    assert_eq!(ContainmentTestKind::ALL.len(), 8);
}

#[test]
fn enrichment_containment_test_kind_display_all_unique() {
    let displays: BTreeSet<String> = ContainmentTestKind::ALL
        .iter()
        .map(|k| k.to_string())
        .collect();
    assert_eq!(displays.len(), 8);
}

#[test]
fn enrichment_containment_test_kind_serde_roundtrip_all() {
    for kind in &ContainmentTestKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: ContainmentTestKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_harness_migration_schema_version_nonempty() {
    assert!(!HARNESS_MIGRATION_SCHEMA_VERSION.is_empty());
    assert!(HARNESS_MIGRATION_SCHEMA_VERSION.contains("harness-migration"));
}

#[test]
fn enrichment_harness_migration_bead_id_nonempty() {
    assert!(!HARNESS_MIGRATION_BEAD_ID.is_empty());
    assert!(HARNESS_MIGRATION_BEAD_ID.starts_with("bd-"));
}

// ===========================================================================
// ScenarioMigrationEntry
// ===========================================================================

#[test]
fn enrichment_scenario_migration_entry_local_only_defaults() {
    let entry = ScenarioMigrationEntry::local_only(LifecycleScenarioId::Startup, "test_harness");
    assert_eq!(entry.scenario_id, LifecycleScenarioId::Startup);
    assert_eq!(entry.status, MigrationStatus::LocalOnly);
    assert_eq!(entry.local_harness, "test_harness");
    assert!(entry.upstream_harness.is_none());
    assert!(entry.local_oracles.is_empty());
    assert!(entry.bridge_oracles.is_empty());
    assert!(!entry.replay_verified);
    assert!(!entry.evidence_linked);
}

#[test]
fn enrichment_scenario_migration_entry_serde_roundtrip() {
    let entry = ScenarioMigrationEntry::local_only(LifecycleScenarioId::Quarantine, "harness_q");
    let json = serde_json::to_string(&entry).unwrap();
    let back: ScenarioMigrationEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_scenario_migration_entry_total_oracles_empty() {
    let entry = ScenarioMigrationEntry::local_only(LifecycleScenarioId::Startup, "h");
    assert_eq!(entry.total_oracles(), 0);
}

#[test]
fn enrichment_scenario_migration_entry_bridge_fraction_no_oracles() {
    let entry = ScenarioMigrationEntry::local_only(LifecycleScenarioId::Startup, "h");
    assert_eq!(entry.bridge_oracle_fraction_millionths(), 0);
}

#[test]
fn enrichment_scenario_migration_entry_mark_migrated() {
    let mut entry =
        ScenarioMigrationEntry::local_only(LifecycleScenarioId::ForcedCancel, "local_h");
    entry.mark_migrated("upstream_h");
    assert_eq!(entry.status, MigrationStatus::Migrated);
    assert_eq!(entry.upstream_harness, Some("upstream_h".to_string()));
    assert!(entry.status.is_upstream_backed());
}

#[test]
fn enrichment_scenario_migration_entry_mark_verified() {
    let mut entry = ScenarioMigrationEntry::local_only(LifecycleScenarioId::Revocation, "local_h");
    entry.mark_migrated("upstream_h");
    entry.mark_verified();
    assert_eq!(entry.status, MigrationStatus::Verified);
    assert!(entry.replay_verified);
    assert!(entry.evidence_linked);
}

// ===========================================================================
// ContainmentTestEntry
// ===========================================================================

#[test]
fn enrichment_containment_test_entry_new_defaults() {
    let entry = ContainmentTestEntry::new(
        ContainmentTestKind::RegionIsolation,
        "tests/region_test.rs",
        10,
    );
    assert_eq!(entry.kind, ContainmentTestKind::RegionIsolation);
    assert_eq!(entry.status, MigrationStatus::LocalOnly);
    assert_eq!(entry.local_test_count, 10);
    assert_eq!(entry.upstream_test_count, 0);
    assert!(!entry.uses_mock_context);
    assert!(!entry.oracle_covered);
}

#[test]
fn enrichment_containment_test_entry_migration_coverage_zero() {
    let entry = ContainmentTestEntry::new(ContainmentTestKind::BudgetEnforcement, "f.rs", 5);
    assert_eq!(entry.migration_coverage_millionths(), 0);
}

#[test]
fn enrichment_containment_test_entry_fully_migrated_false_initially() {
    let entry = ContainmentTestEntry::new(ContainmentTestKind::BudgetEnforcement, "f.rs", 5);
    assert!(!entry.fully_migrated());
}

#[test]
fn enrichment_containment_test_entry_serde_roundtrip() {
    let entry = ContainmentTestEntry::new(
        ContainmentTestKind::EvidenceCompleteness,
        "tests/evidence.rs",
        20,
    );
    let json = serde_json::to_string(&entry).unwrap();
    let back: ContainmentTestEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ===========================================================================
// HarnessMigrationRegistry
// ===========================================================================

#[test]
fn enrichment_registry_new_empty() {
    let reg = HarnessMigrationRegistry::new(epoch());
    assert!(reg.scenarios.is_empty());
    assert!(reg.containment_tests.is_empty());
    assert_eq!(reg.schema_version, HARNESS_MIGRATION_SCHEMA_VERSION);
}

#[test]
fn enrichment_registry_serde_roundtrip_empty() {
    let reg = HarnessMigrationRegistry::new(epoch());
    let json = serde_json::to_string(&reg).unwrap();
    let back: HarnessMigrationRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, back);
}

#[test]
fn enrichment_registry_with_default_scenarios() {
    let reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    assert_eq!(reg.scenarios.len(), 10);
    assert_eq!(reg.containment_tests.len(), 8);
}

#[test]
fn enrichment_registry_with_default_scenarios_serde_roundtrip() {
    let reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    let json = serde_json::to_string(&reg).unwrap();
    let back: HarnessMigrationRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, back);
}

#[test]
fn enrichment_registry_scenario_lookup() {
    let reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    let entry = reg.scenario(LifecycleScenarioId::Startup);
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().scenario_id, LifecycleScenarioId::Startup);
}

#[test]
fn enrichment_registry_scenario_status_counts() {
    let reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    let counts = reg.scenario_status_counts();
    let total: usize = counts.values().sum();
    assert_eq!(total, 10);
}

#[test]
fn enrichment_registry_build_report() {
    let reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    let report = reg.build_report();
    assert_eq!(report.total_scenarios, 10);
    assert_eq!(report.total_containment_tests, 8);
}
