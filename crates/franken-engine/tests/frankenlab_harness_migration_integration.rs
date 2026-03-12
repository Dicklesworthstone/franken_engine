//! Integration tests for frankenlab_harness_migration module.

use std::collections::BTreeSet;

use frankenengine_engine::frankenlab_harness_migration::{
    ContainmentTestEntry, ContainmentTestKind, HARNESS_MIGRATION_BEAD_ID,
    HARNESS_MIGRATION_SCHEMA_VERSION, HarnessMigrationRegistry, HarnessMigrationReport,
    LifecycleScenarioId, MigrationStatus, OracleMigrationEntry, ScenarioMigrationEntry,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(400)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn integration_schema_version_present() {
    assert!(!HARNESS_MIGRATION_SCHEMA_VERSION.is_empty());
    assert!(HARNESS_MIGRATION_SCHEMA_VERSION.contains("harness-migration"));
}

#[test]
fn integration_bead_id() {
    assert_eq!(HARNESS_MIGRATION_BEAD_ID, "bd-3nr.1.4.2");
}

// ---------------------------------------------------------------------------
// MigrationStatus
// ---------------------------------------------------------------------------

#[test]
fn integration_migration_status_ordering() {
    assert!(MigrationStatus::LocalOnly < MigrationStatus::InProgress);
    assert!(MigrationStatus::InProgress < MigrationStatus::Migrated);
    assert!(MigrationStatus::Migrated < MigrationStatus::Verified);
    assert!(MigrationStatus::Verified < MigrationStatus::Deferred);
}

#[test]
fn integration_migration_status_display_coverage() {
    let statuses = [
        MigrationStatus::LocalOnly,
        MigrationStatus::InProgress,
        MigrationStatus::Migrated,
        MigrationStatus::Verified,
        MigrationStatus::Deferred,
    ];
    for s in &statuses {
        let display = s.to_string();
        assert!(!display.is_empty());
        assert!(!display.contains(char::is_uppercase));
    }
}

// ---------------------------------------------------------------------------
// LifecycleScenarioId
// ---------------------------------------------------------------------------

#[test]
fn integration_lifecycle_scenarios_cover_core_paths() {
    let all: BTreeSet<LifecycleScenarioId> = LifecycleScenarioId::ALL.iter().copied().collect();
    // Must include the 7 original lifecycle paths
    assert!(all.contains(&LifecycleScenarioId::Startup));
    assert!(all.contains(&LifecycleScenarioId::NormalShutdown));
    assert!(all.contains(&LifecycleScenarioId::ForcedCancel));
    assert!(all.contains(&LifecycleScenarioId::Quarantine));
    assert!(all.contains(&LifecycleScenarioId::Revocation));
    assert!(all.contains(&LifecycleScenarioId::DegradedMode));
    assert!(all.contains(&LifecycleScenarioId::MultiExtension));
    // Plus the 3 new correction-wave paths
    assert!(all.contains(&LifecycleScenarioId::BudgetExhaustion));
    assert!(all.contains(&LifecycleScenarioId::ChildContextPropagation));
    assert!(all.contains(&LifecycleScenarioId::EvidenceChainIntegrity));
}

#[test]
fn integration_lifecycle_scenario_serde_roundtrip() {
    for id in LifecycleScenarioId::ALL {
        let json = serde_json::to_string(&id).unwrap();
        let round: LifecycleScenarioId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, round);
    }
}

// ---------------------------------------------------------------------------
// ScenarioMigrationEntry
// ---------------------------------------------------------------------------

#[test]
fn integration_scenario_entry_oracle_progression() {
    let mut entry = ScenarioMigrationEntry::local_only(LifecycleScenarioId::Startup, "local");

    // Start with local oracles
    entry.local_oracles.insert("safety".to_owned());
    entry.local_oracles.insert("liveness".to_owned());
    assert_eq!(entry.bridge_oracle_fraction_millionths(), 0);

    // Migrate one oracle to bridge
    entry.bridge_oracles.insert("safety".to_owned());
    entry.local_oracles.remove("safety");
    assert_eq!(entry.bridge_oracle_fraction_millionths(), 500_000);

    // Migrate all
    entry.bridge_oracles.insert("liveness".to_owned());
    entry.local_oracles.clear();
    assert!(entry.all_oracles_bridged());
    assert_eq!(entry.bridge_oracle_fraction_millionths(), 1_000_000);
}

#[test]
fn integration_scenario_entry_lifecycle() {
    let mut entry =
        ScenarioMigrationEntry::local_only(LifecycleScenarioId::Quarantine, "local_harness");
    assert!(entry.status.needs_work());
    assert!(!entry.status.is_upstream_backed());

    // Progress to migrated
    entry.mark_migrated("upstream::scenario_runner");
    assert!(entry.status.is_upstream_backed());
    assert!(!entry.status.needs_work());
    assert_eq!(
        entry.upstream_harness.as_deref(),
        Some("upstream::scenario_runner")
    );

    // Progress to verified
    entry.mark_verified();
    assert_eq!(entry.status, MigrationStatus::Verified);
    assert!(entry.replay_verified);
    assert!(entry.evidence_linked);
}

// ---------------------------------------------------------------------------
// ContainmentTestKind
// ---------------------------------------------------------------------------

#[test]
fn integration_containment_test_kinds_unique() {
    let set: BTreeSet<ContainmentTestKind> = ContainmentTestKind::ALL.iter().copied().collect();
    assert_eq!(set.len(), ContainmentTestKind::ALL.len());
}

#[test]
fn integration_containment_test_display_all() {
    for kind in ContainmentTestKind::ALL {
        let s = kind.to_string();
        assert!(!s.is_empty());
    }
}

// ---------------------------------------------------------------------------
// ContainmentTestEntry
// ---------------------------------------------------------------------------

#[test]
fn integration_containment_entry_coverage_progression() {
    let mut entry =
        ContainmentTestEntry::new(ContainmentTestKind::RegionIsolation, "tests/region.rs", 20);
    assert_eq!(entry.migration_coverage_millionths(), 0);

    entry.upstream_test_count = 5;
    assert_eq!(entry.migration_coverage_millionths(), 250_000);

    entry.upstream_test_count = 10;
    assert_eq!(entry.migration_coverage_millionths(), 500_000);

    entry.upstream_test_count = 20;
    entry.status = MigrationStatus::Migrated;
    assert!(entry.fully_migrated());
    assert_eq!(entry.migration_coverage_millionths(), 1_000_000);
}

#[test]
fn integration_containment_entry_zero_local_tests() {
    let entry = ContainmentTestEntry::new(ContainmentTestKind::MockSeamAbsence, "tests/mock.rs", 0);
    assert_eq!(entry.migration_coverage_millionths(), 0);
    assert!(!entry.fully_migrated());
}

// ---------------------------------------------------------------------------
// HarnessMigrationRegistry
// ---------------------------------------------------------------------------

#[test]
fn integration_registry_default_scenarios_all_local() {
    let reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    for s in &reg.scenarios {
        assert_eq!(s.status, MigrationStatus::LocalOnly);
    }
    for t in &reg.containment_tests {
        assert_eq!(t.status, MigrationStatus::LocalOnly);
    }
}

#[test]
fn integration_registry_scenario_lookup_all() {
    let reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    for id in LifecycleScenarioId::ALL {
        assert!(
            reg.scenario(id).is_some(),
            "missing scenario entry for {:?}",
            id,
        );
    }
}

#[test]
fn integration_registry_containment_lookup_all() {
    let reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    for kind in ContainmentTestKind::ALL {
        assert!(
            reg.containment_test(kind).is_some(),
            "missing containment entry for {:?}",
            kind,
        );
    }
}

#[test]
fn integration_registry_mutable_scenario_access() {
    let mut reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    reg.scenario_mut(LifecycleScenarioId::Startup)
        .unwrap()
        .mark_migrated("upstream");
    assert_eq!(
        reg.scenario(LifecycleScenarioId::Startup).unwrap().status,
        MigrationStatus::Migrated,
    );
}

#[test]
fn integration_registry_mutable_containment_access() {
    let mut reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    {
        let test = reg
            .containment_test_mut(ContainmentTestKind::BudgetEnforcement)
            .unwrap();
        test.upstream_test_count = 30;
        test.status = MigrationStatus::Verified;
    }
    let test = reg
        .containment_test(ContainmentTestKind::BudgetEnforcement)
        .unwrap();
    assert_eq!(test.upstream_test_count, 30);
    assert!(test.fully_migrated());
}

#[test]
fn integration_registry_progress_tracks_migration() {
    let mut reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    assert_eq!(reg.scenario_migration_progress_millionths(), 0);

    // Migrate 5 of 10 scenarios
    let ids_to_migrate = [
        LifecycleScenarioId::Startup,
        LifecycleScenarioId::NormalShutdown,
        LifecycleScenarioId::ForcedCancel,
        LifecycleScenarioId::Quarantine,
        LifecycleScenarioId::Revocation,
    ];
    for id in ids_to_migrate {
        reg.scenario_mut(id).unwrap().mark_verified();
    }
    assert_eq!(reg.scenario_migration_progress_millionths(), 500_000);
}

#[test]
fn integration_registry_serde_roundtrip() {
    let mut reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    reg.scenario_mut(LifecycleScenarioId::Startup)
        .unwrap()
        .mark_migrated("upstream");
    let json = serde_json::to_string_pretty(&reg).unwrap();
    let round: HarnessMigrationRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, round);
}

// ---------------------------------------------------------------------------
// HarnessMigrationReport
// ---------------------------------------------------------------------------

#[test]
fn integration_report_initial() {
    let reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    let report = reg.build_report();

    assert!(!report.is_complete());
    assert_eq!(report.total_scenarios, 10);
    assert_eq!(report.total_containment_tests, 8);
    assert_eq!(report.scenarios_needing_work, 10);
    assert_eq!(report.containment_needing_work, 8);
    assert_eq!(report.mock_context_tests, 0);
    assert_eq!(report.oracle_covered_tests, 0);
    assert_eq!(report.replay_verified_scenarios, 0);
    assert_eq!(report.evidence_linked_scenarios, 0);
    assert_eq!(report.scenario_migration_progress_millionths, 0);
    assert_eq!(report.containment_migration_progress_millionths, 0);
}

#[test]
fn integration_report_complete() {
    let mut reg = HarnessMigrationRegistry::with_default_scenarios(epoch());

    for id in LifecycleScenarioId::ALL {
        reg.scenario_mut(id).unwrap().mark_verified();
    }
    for kind in ContainmentTestKind::ALL {
        let test = reg.containment_test_mut(kind).unwrap();
        test.status = MigrationStatus::Verified;
        test.upstream_test_count = test.local_test_count;
        test.oracle_covered = true;
    }

    let report = reg.build_report();
    assert!(report.is_complete());
    assert_eq!(report.scenarios_needing_work, 0);
    assert_eq!(report.containment_needing_work, 0);
    assert_eq!(report.oracle_covered_tests, 8);
    assert_eq!(report.replay_verified_scenarios, 10);
}

#[test]
fn integration_report_mock_context_tracking() {
    let mut reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    reg.containment_test_mut(ContainmentTestKind::RegionIsolation)
        .unwrap()
        .uses_mock_context = true;
    reg.containment_test_mut(ContainmentTestKind::BudgetEnforcement)
        .unwrap()
        .uses_mock_context = true;

    let report = reg.build_report();
    assert!(report.has_mock_context_usage());
    assert_eq!(report.mock_context_tests, 2);
}

#[test]
fn integration_report_json_roundtrip() {
    let reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    let report = reg.build_report();
    let json = serde_json::to_string_pretty(&report).unwrap();
    let round: HarnessMigrationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, round);
}

#[test]
fn integration_report_hash_deterministic() {
    let make = || {
        let reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
        reg.build_report()
    };
    let r1 = make();
    let r2 = make();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn integration_report_display() {
    let reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    let report = reg.build_report();
    let s = format!("{report}");
    assert!(s.contains("HarnessMigrationReport"));
    assert!(s.contains("complete=false"));
}

// ---------------------------------------------------------------------------
// OracleMigrationEntry
// ---------------------------------------------------------------------------

#[test]
fn integration_oracle_migration_lifecycle() {
    let mut oracle = OracleMigrationEntry::local_only("safety");
    assert!(oracle.available_locally);
    assert!(!oracle.available_via_bridge);
    assert!(!oracle.cross_validated);

    oracle.add_scenario("startup");
    oracle.add_scenario("shutdown");
    assert_eq!(oracle.used_by_scenarios.len(), 2);

    // Upgrade to bridged
    oracle.available_via_bridge = true;
    oracle.mark_cross_validated();
    assert!(oracle.cross_validated);
}

#[test]
fn integration_oracle_entry_serde_roundtrip() {
    let mut oracle = OracleMigrationEntry::bridged("liveness");
    oracle.add_scenario("startup");
    oracle.add_scenario("cancel");
    oracle.mark_cross_validated();
    let json = serde_json::to_string(&oracle).unwrap();
    let round: OracleMigrationEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(oracle, round);
}

// ---------------------------------------------------------------------------
// E2E: Full migration workflow
// ---------------------------------------------------------------------------

#[test]
fn integration_e2e_progressive_migration() {
    let mut reg = HarnessMigrationRegistry::with_default_scenarios(epoch());

    // Phase 1: Mark 3 scenarios as in-progress
    for id in [
        LifecycleScenarioId::Startup,
        LifecycleScenarioId::NormalShutdown,
        LifecycleScenarioId::ForcedCancel,
    ] {
        reg.scenario_mut(id).unwrap().status = MigrationStatus::InProgress;
    }

    let report1 = reg.build_report();
    assert_eq!(report1.scenarios_needing_work, 10); // in_progress still needs work
    assert!(!report1.is_complete());

    // Phase 2: Migrate the 3 in-progress scenarios
    for id in [
        LifecycleScenarioId::Startup,
        LifecycleScenarioId::NormalShutdown,
        LifecycleScenarioId::ForcedCancel,
    ] {
        reg.scenario_mut(id)
            .unwrap()
            .mark_migrated("upstream::runner");
    }

    let report2 = reg.build_report();
    assert_eq!(report2.scenarios_needing_work, 7);
    assert_eq!(report2.scenario_migration_progress_millionths, 300_000);

    // Phase 3: Defer remaining scenarios
    for id in LifecycleScenarioId::ALL {
        let entry = reg.scenario_mut(id).unwrap();
        if entry.status == MigrationStatus::LocalOnly {
            entry.status = MigrationStatus::Deferred;
        }
    }

    // Defer containment tests
    for kind in ContainmentTestKind::ALL {
        reg.containment_test_mut(kind).unwrap().status = MigrationStatus::Deferred;
    }

    let report3 = reg.build_report();
    assert!(report3.is_complete()); // deferred doesn't need work
}

#[test]
fn integration_e2e_containment_migration_with_oracles() {
    let mut reg = HarnessMigrationRegistry::with_default_scenarios(epoch());

    // Migrate budget enforcement tests
    let test = reg
        .containment_test_mut(ContainmentTestKind::BudgetEnforcement)
        .unwrap();
    test.upstream_test_count = 30;
    test.status = MigrationStatus::Verified;
    test.oracle_covered = true;
    test.uses_mock_context = false;

    // Migrate capability narrowing tests
    let test = reg
        .containment_test_mut(ContainmentTestKind::CapabilityNarrowing)
        .unwrap();
    test.upstream_test_count = 35;
    test.status = MigrationStatus::Verified;
    test.oracle_covered = true;

    let report = reg.build_report();
    assert_eq!(report.oracle_covered_tests, 2);
    assert!(!report.is_complete()); // other tests still local
}

// ---------------------------------------------------------------------------
// Additional enrichment tests
// ---------------------------------------------------------------------------

#[test]
fn integration_migration_status_serde_roundtrip() {
    for status in [
        MigrationStatus::LocalOnly,
        MigrationStatus::InProgress,
        MigrationStatus::Migrated,
        MigrationStatus::Verified,
        MigrationStatus::Deferred,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let round: MigrationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, round);
    }
}

#[test]
fn integration_migration_status_needs_work() {
    assert!(MigrationStatus::LocalOnly.needs_work());
    assert!(MigrationStatus::InProgress.needs_work());
    assert!(!MigrationStatus::Migrated.needs_work());
    assert!(!MigrationStatus::Verified.needs_work());
    assert!(!MigrationStatus::Deferred.needs_work());
}

#[test]
fn integration_migration_status_is_upstream_backed() {
    assert!(!MigrationStatus::LocalOnly.is_upstream_backed());
    assert!(!MigrationStatus::InProgress.is_upstream_backed());
    assert!(MigrationStatus::Migrated.is_upstream_backed());
    assert!(MigrationStatus::Verified.is_upstream_backed());
    assert!(!MigrationStatus::Deferred.is_upstream_backed());
}

#[test]
fn integration_lifecycle_scenario_all_has_ten() {
    assert_eq!(LifecycleScenarioId::ALL.len(), 10);
}

#[test]
fn integration_lifecycle_scenario_unique_labels() {
    let mut labels = BTreeSet::new();
    for id in LifecycleScenarioId::ALL {
        let s = format!("{id}");
        assert!(labels.insert(s.clone()), "duplicate: {s}");
    }
    assert_eq!(labels.len(), 10);
}

#[test]
fn integration_lifecycle_scenario_serde_roundtrip() {
    for id in LifecycleScenarioId::ALL {
        let json = serde_json::to_string(&id).unwrap();
        let round: LifecycleScenarioId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, round);
    }
}

#[test]
fn integration_containment_test_kind_all_has_eight() {
    assert_eq!(ContainmentTestKind::ALL.len(), 8);
}

#[test]
fn integration_containment_test_kind_serde_roundtrip() {
    for kind in ContainmentTestKind::ALL {
        let json = serde_json::to_string(&kind).unwrap();
        let round: ContainmentTestKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, round);
    }
}

#[test]
fn integration_containment_entry_migration_coverage_zero() {
    let entry = ContainmentTestEntry::new(
        ContainmentTestKind::BudgetEnforcement,
        "tests/budget.rs",
        10,
    );
    assert_eq!(entry.migration_coverage_millionths(), 0);
    assert!(!entry.fully_migrated());
}

#[test]
fn integration_containment_entry_fully_migrated() {
    let mut entry = ContainmentTestEntry::new(
        ContainmentTestKind::CapabilityNarrowing,
        "tests/narrowing.rs",
        10,
    );
    entry.upstream_test_count = 10;
    entry.status = MigrationStatus::Verified;
    entry.oracle_covered = true;
    assert!(entry.fully_migrated());
    assert_eq!(entry.migration_coverage_millionths(), 1_000_000);
}

#[test]
fn integration_scenario_entry_mark_migrated_then_verified() {
    let mut entry =
        ScenarioMigrationEntry::local_only(LifecycleScenarioId::Startup, "tests/startup.rs");
    assert_eq!(entry.status, MigrationStatus::LocalOnly);

    entry.mark_migrated("upstream::runner");
    assert_eq!(entry.status, MigrationStatus::Migrated);
    assert_eq!(entry.upstream_harness, "upstream::runner");

    entry.mark_verified();
    assert_eq!(entry.status, MigrationStatus::Verified);
    assert!(entry.cross_validated);
}

#[test]
fn integration_oracle_migration_entry_local_only() {
    let entry = OracleMigrationEntry::local_only("test_oracle");
    assert_eq!(entry.name, "test_oracle");
    assert!(!entry.bridged_to_upstream);
    assert!(!entry.cross_validated);
}

#[test]
fn integration_oracle_migration_entry_bridged() {
    let entry = OracleMigrationEntry::bridged("bridge_oracle");
    assert_eq!(entry.name, "bridge_oracle");
    assert!(entry.bridged_to_upstream);
    assert!(!entry.cross_validated);
}

#[test]
fn integration_oracle_migration_entry_cross_validated() {
    let mut entry = OracleMigrationEntry::bridged("val_oracle");
    entry.mark_cross_validated();
    assert!(entry.cross_validated);
}

#[test]
fn integration_registry_scenario_status_counts() {
    let reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    let counts = reg.scenario_status_counts();
    let total: usize = counts.values().sum();
    assert_eq!(total, 10);
}

#[test]
fn integration_registry_containment_status_counts() {
    let reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    let counts = reg.containment_status_counts();
    let total: usize = counts.values().sum();
    assert_eq!(total, 8);
}

#[test]
fn integration_report_serde_roundtrip() {
    let reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
    let report = reg.build_report();
    let json = serde_json::to_string(&report).unwrap();
    let round: HarnessMigrationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, round);
}

#[test]
fn integration_report_hash_deterministic() {
    let make = || {
        let reg = HarnessMigrationRegistry::with_default_scenarios(epoch());
        reg.build_report()
    };
    let r1 = make();
    let r2 = make();
    assert_eq!(r1.content_hash, r2.content_hash);
}
