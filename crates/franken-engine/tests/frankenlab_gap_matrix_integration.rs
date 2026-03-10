//! Integration tests for frankenlab_gap_matrix module.

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

use frankenengine_engine::frankenlab_gap_matrix::{
    self, GAP_MATRIX_BEAD_ID, GAP_MATRIX_SCHEMA_VERSION, GapCoverageSummary, GapMatrix,
    GapMatrixEntry, GapStatus, LabSurfaceKind, MigrationDecision, MigrationPlan,
    UpstreamCapability,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn entry(
    local: LabSurfaceKind,
    upstream: UpstreamCapability,
    status: GapStatus,
    coverage: u64,
    decision: MigrationDecision,
    confidence: u64,
) -> GapMatrixEntry {
    GapMatrixEntry {
        local_surface: local,
        upstream_capability: upstream,
        status,
        coverage_millionths: coverage,
        migration_decision: decision,
        rationale: "test rationale".to_string(),
        confidence_millionths: confidence,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_stable() {
    assert_eq!(
        GAP_MATRIX_SCHEMA_VERSION,
        "franken-engine.frankenlab-gap-matrix.v1"
    );
}

#[test]
fn test_bead_id() {
    assert_eq!(GAP_MATRIX_BEAD_ID, "bd-3nr.1.1.2");
}

// ---------------------------------------------------------------------------
// LabSurfaceKind
// ---------------------------------------------------------------------------

#[test]
fn test_lab_surface_kind_all_has_ten() {
    assert_eq!(LabSurfaceKind::ALL.len(), 10);
}

#[test]
fn test_lab_surface_kind_display() {
    assert_eq!(
        format!("{}", LabSurfaceKind::DeterministicReplay),
        "deterministic_replay"
    );
    assert_eq!(
        format!("{}", LabSurfaceKind::ScenarioRunner),
        "scenario_runner"
    );
    assert_eq!(
        format!("{}", LabSurfaceKind::ReleaseGateRunner),
        "release_gate_runner"
    );
}

#[test]
fn test_lab_surface_kind_serde_roundtrip() {
    for s in LabSurfaceKind::ALL {
        let json = serde_json::to_string(&s).unwrap();
        let back: LabSurfaceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn test_lab_surface_kind_all_variants_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for s in LabSurfaceKind::ALL {
        assert!(seen.insert(format!("{s}")), "duplicate: {s}");
    }
}

// ---------------------------------------------------------------------------
// UpstreamCapability
// ---------------------------------------------------------------------------

#[test]
fn test_upstream_capability_all_has_ten() {
    assert_eq!(UpstreamCapability::ALL.len(), 10);
}

#[test]
fn test_upstream_capability_display() {
    assert_eq!(format!("{}", UpstreamCapability::LabRuntime), "lab_runtime");
    assert_eq!(
        format!("{}", UpstreamCapability::ReleaseGating),
        "release_gating"
    );
}

#[test]
fn test_upstream_capability_serde_roundtrip() {
    for c in UpstreamCapability::ALL {
        let json = serde_json::to_string(&c).unwrap();
        let back: UpstreamCapability = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}

#[test]
fn test_upstream_capability_all_variants_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for c in UpstreamCapability::ALL {
        assert!(seen.insert(format!("{c}")), "duplicate: {c}");
    }
}

// ---------------------------------------------------------------------------
// GapStatus
// ---------------------------------------------------------------------------

#[test]
fn test_gap_status_display() {
    assert_eq!(format!("{}", GapStatus::Covered), "covered");
    assert_eq!(format!("{}", GapStatus::PartialGap), "partial_gap");
    assert_eq!(format!("{}", GapStatus::FullGap), "full_gap");
    assert_eq!(format!("{}", GapStatus::Redundant), "redundant");
}

#[test]
fn test_gap_status_serde_roundtrip() {
    for s in [
        GapStatus::Covered,
        GapStatus::PartialGap,
        GapStatus::FullGap,
        GapStatus::Redundant,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: GapStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ---------------------------------------------------------------------------
// MigrationDecision
// ---------------------------------------------------------------------------

#[test]
fn test_migration_decision_display() {
    assert_eq!(
        format!("{}", MigrationDecision::DirectAdoption),
        "direct_adoption"
    );
    assert_eq!(format!("{}", MigrationDecision::ThinBridge), "thin_bridge");
    assert_eq!(
        format!("{}", MigrationDecision::MaintainedWrapper),
        "maintained_wrapper"
    );
    assert_eq!(
        format!("{}", MigrationDecision::NoMigration),
        "no_migration"
    );
    assert_eq!(format!("{}", MigrationDecision::Deferred), "deferred");
}

#[test]
fn test_migration_decision_serde_roundtrip() {
    for d in [
        MigrationDecision::DirectAdoption,
        MigrationDecision::ThinBridge,
        MigrationDecision::MaintainedWrapper,
        MigrationDecision::NoMigration,
        MigrationDecision::Deferred,
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let back: MigrationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}

// ---------------------------------------------------------------------------
// GapMatrixEntry
// ---------------------------------------------------------------------------

#[test]
fn test_entry_display() {
    let e = entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        950_000,
        MigrationDecision::NoMigration,
        900_000,
    );
    let d = format!("{e}");
    assert!(d.contains("deterministic_replay"));
    assert!(d.contains("lab_runtime"));
    assert!(d.contains("covered"));
}

#[test]
fn test_entry_serde_roundtrip() {
    let e = entry(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::OracleDispatch,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        700_000,
    );
    let json = serde_json::to_string(&e).unwrap();
    let back: GapMatrixEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// GapMatrix — construction and basic operations
// ---------------------------------------------------------------------------

#[test]
fn test_new_matrix_is_empty() {
    let m = GapMatrix::new(test_epoch());
    assert!(m.entries.is_empty());
    assert_eq!(m.schema_version, GAP_MATRIX_SCHEMA_VERSION);
}

#[test]
fn test_add_entry() {
    let mut m = GapMatrix::new(test_epoch());
    m.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        950_000,
        MigrationDecision::NoMigration,
        900_000,
    ));
    assert_eq!(m.entries.len(), 1);
}

#[test]
fn test_lookup_found() {
    let mut m = GapMatrix::new(test_epoch());
    m.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        950_000,
        MigrationDecision::NoMigration,
        900_000,
    ));
    let found = m.lookup(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
    );
    assert!(found.is_some());
    assert_eq!(found.unwrap().status, GapStatus::Covered);
}

#[test]
fn test_lookup_not_found() {
    let m = GapMatrix::new(test_epoch());
    let found = m.lookup(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
    );
    assert!(found.is_none());
}

// ---------------------------------------------------------------------------
// coverage_summary
// ---------------------------------------------------------------------------

#[test]
fn test_coverage_summary_empty() {
    let m = GapMatrix::new(test_epoch());
    let s = m.coverage_summary();
    assert_eq!(s.total_pairs, 0);
    assert_eq!(s.overall_coverage_millionths, 0);
}

#[test]
fn test_coverage_summary_single_covered() {
    let mut m = GapMatrix::new(test_epoch());
    m.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        1_000_000,
        MigrationDecision::NoMigration,
        900_000,
    ));
    let s = m.coverage_summary();
    assert_eq!(s.total_pairs, 1);
    assert_eq!(s.covered_count, 1);
    assert_eq!(s.overall_coverage_millionths, 1_000_000);
}

#[test]
fn test_coverage_summary_mixed() {
    let mut m = GapMatrix::new(test_epoch());
    m.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        1_000_000,
        MigrationDecision::NoMigration,
        900_000,
    ));
    m.add_entry(entry(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::OracleDispatch,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        700_000,
    ));
    let s = m.coverage_summary();
    assert_eq!(s.total_pairs, 2);
    assert_eq!(s.covered_count, 1);
    assert_eq!(s.full_gap_count, 1);
    assert_eq!(s.overall_coverage_millionths, 500_000); // avg of 1M and 0
}

#[test]
fn test_coverage_summary_counts_partial_and_redundant() {
    let mut m = GapMatrix::new(test_epoch());
    m.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::PartialGap,
        500_000,
        MigrationDecision::ThinBridge,
        750_000,
    ));
    m.add_entry(entry(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::OracleDispatch,
        GapStatus::Redundant,
        1_000_000,
        MigrationDecision::NoMigration,
        800_000,
    ));
    let s = m.coverage_summary();
    assert_eq!(s.partial_gap_count, 1);
    assert_eq!(s.redundant_count, 1);
}

// ---------------------------------------------------------------------------
// migration_plan
// ---------------------------------------------------------------------------

#[test]
fn test_migration_plan_empty() {
    let m = GapMatrix::new(test_epoch());
    let plan = m.migration_plan();
    assert!(plan.adopt.is_empty());
    assert!(plan.bridge.is_empty());
    assert!(plan.wrap.is_empty());
    assert!(plan.keep.is_empty());
    assert!(plan.defer.is_empty());
}

#[test]
fn test_migration_plan_categorizes_correctly() {
    let mut m = GapMatrix::new(test_epoch());
    m.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        800_000,
    ));
    m.add_entry(entry(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::OracleDispatch,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        750_000,
    ));
    m.add_entry(entry(
        LabSurfaceKind::EvidenceChecker,
        UpstreamCapability::EvidenceReplay,
        GapStatus::Covered,
        900_000,
        MigrationDecision::MaintainedWrapper,
        850_000,
    ));
    m.add_entry(entry(
        LabSurfaceKind::VirtualTimeClock,
        UpstreamCapability::VirtualTimeControl,
        GapStatus::Covered,
        950_000,
        MigrationDecision::NoMigration,
        900_000,
    ));
    m.add_entry(entry(
        LabSurfaceKind::QuarantineHarness,
        UpstreamCapability::QuarantineOrchestration,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
    ));
    let plan = m.migration_plan();
    assert_eq!(plan.adopt.len(), 1);
    assert_eq!(plan.bridge.len(), 1);
    assert_eq!(plan.wrap.len(), 1);
    assert_eq!(plan.keep.len(), 1);
    assert_eq!(plan.defer.len(), 1);
}

#[test]
fn test_migration_plan_recommendation_adopt_only() {
    let mut m = GapMatrix::new(test_epoch());
    m.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        800_000,
    ));
    let plan = m.migration_plan();
    assert!(plan.recommendation.contains("direct adoption"));
}

#[test]
fn test_migration_plan_recommendation_deferred() {
    let mut m = GapMatrix::new(test_epoch());
    m.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
    ));
    let plan = m.migration_plan();
    assert!(plan.recommendation.contains("deferred"));
}

#[test]
fn test_migration_plan_recommendation_mixed() {
    let mut m = GapMatrix::new(test_epoch());
    m.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        800_000,
    ));
    m.add_entry(entry(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::OracleDispatch,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        750_000,
    ));
    let plan = m.migration_plan();
    assert!(plan.recommendation.contains("Mixed"));
}

// ---------------------------------------------------------------------------
// content_hash
// ---------------------------------------------------------------------------

#[test]
fn test_content_hash_deterministic() {
    let mut m1 = GapMatrix::new(test_epoch());
    m1.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        950_000,
        MigrationDecision::NoMigration,
        900_000,
    ));
    let mut m2 = GapMatrix::new(test_epoch());
    m2.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        950_000,
        MigrationDecision::NoMigration,
        900_000,
    ));
    assert_eq!(m1.content_hash(), m2.content_hash());
}

#[test]
fn test_content_hash_differs_on_status_change() {
    let mut m1 = GapMatrix::new(test_epoch());
    m1.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        950_000,
        MigrationDecision::NoMigration,
        900_000,
    ));
    let mut m2 = GapMatrix::new(test_epoch());
    m2.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::PartialGap,
        950_000,
        MigrationDecision::NoMigration,
        900_000,
    ));
    assert_ne!(m1.content_hash(), m2.content_hash());
}

// ---------------------------------------------------------------------------
// GapMatrix Display
// ---------------------------------------------------------------------------

#[test]
fn test_matrix_display() {
    let mut m = GapMatrix::new(test_epoch());
    m.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        950_000,
        MigrationDecision::NoMigration,
        900_000,
    ));
    let d = format!("{m}");
    assert!(d.contains("Frankenlab Gap Matrix"));
    assert!(d.contains("Total pairs: 1"));
}

// ---------------------------------------------------------------------------
// build_canonical_gap_matrix
// ---------------------------------------------------------------------------

#[test]
fn test_canonical_matrix_has_100_entries() {
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    assert_eq!(m.entries.len(), 100);
}

#[test]
fn test_canonical_matrix_schema_version() {
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    assert_eq!(m.schema_version, GAP_MATRIX_SCHEMA_VERSION);
}

#[test]
fn test_canonical_matrix_epoch() {
    let epoch = SecurityEpoch::from_raw(42);
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(epoch);
    assert_eq!(m.assessed_epoch, epoch);
}

#[test]
fn test_canonical_matrix_covers_all_surfaces() {
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    for surface in LabSurfaceKind::ALL {
        let count = m
            .entries
            .iter()
            .filter(|e| e.local_surface == surface)
            .count();
        assert_eq!(count, 10, "surface {surface} should have 10 entries");
    }
}

#[test]
fn test_canonical_matrix_covers_all_capabilities() {
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    for cap in UpstreamCapability::ALL {
        let count = m
            .entries
            .iter()
            .filter(|e| e.upstream_capability == cap)
            .count();
        assert_eq!(count, 10, "capability {cap} should have 10 entries");
    }
}

#[test]
fn test_canonical_matrix_has_all_status_types() {
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    assert!(m.entries.iter().any(|e| e.status == GapStatus::Covered));
    assert!(m.entries.iter().any(|e| e.status == GapStatus::PartialGap));
    assert!(m.entries.iter().any(|e| e.status == GapStatus::FullGap));
}

#[test]
fn test_canonical_matrix_has_all_decision_types() {
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    assert!(
        m.entries
            .iter()
            .any(|e| e.migration_decision == MigrationDecision::DirectAdoption)
    );
    assert!(
        m.entries
            .iter()
            .any(|e| e.migration_decision == MigrationDecision::ThinBridge)
    );
    assert!(
        m.entries
            .iter()
            .any(|e| e.migration_decision == MigrationDecision::MaintainedWrapper)
    );
    assert!(
        m.entries
            .iter()
            .any(|e| e.migration_decision == MigrationDecision::NoMigration)
    );
    assert!(
        m.entries
            .iter()
            .any(|e| e.migration_decision == MigrationDecision::Deferred)
    );
}

#[test]
fn test_canonical_matrix_all_entries_have_rationale() {
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    for e in &m.entries {
        assert!(!e.rationale.is_empty(), "entry {e} missing rationale");
    }
}

#[test]
fn test_canonical_matrix_coverage_is_valid() {
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    for e in &m.entries {
        assert!(
            e.coverage_millionths <= 1_000_000,
            "coverage > 100% for {e}"
        );
    }
}

#[test]
fn test_canonical_matrix_confidence_is_valid() {
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    for e in &m.entries {
        assert!(
            e.confidence_millionths <= 1_000_000,
            "confidence > 100% for {e}"
        );
    }
}

#[test]
fn test_canonical_matrix_deterministic() {
    let m1 = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    let m2 = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    assert_eq!(m1.content_hash(), m2.content_hash());
}

#[test]
fn test_canonical_matrix_coverage_summary() {
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    let s = m.coverage_summary();
    assert_eq!(s.total_pairs, 100);
    assert!(s.covered_count + s.partial_gap_count + s.full_gap_count + s.redundant_count == 100);
}

#[test]
fn test_canonical_matrix_migration_plan() {
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    let plan = m.migration_plan();
    let total =
        plan.adopt.len() + plan.bridge.len() + plan.wrap.len() + plan.keep.len() + plan.defer.len();
    assert_eq!(total, 100);
}

#[test]
fn test_canonical_matrix_lookup() {
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    let found = m.lookup(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
    );
    assert!(found.is_some());
}

// ---------------------------------------------------------------------------
// Serde roundtrips for complex types
// ---------------------------------------------------------------------------

#[test]
fn test_gap_matrix_serde_roundtrip() {
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    let json = serde_json::to_string(&m).unwrap();
    let back: GapMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn test_coverage_summary_serde_roundtrip() {
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    let s = m.coverage_summary();
    let json = serde_json::to_string(&s).unwrap();
    let back: GapCoverageSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn test_migration_plan_serde_roundtrip() {
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    let plan = m.migration_plan();
    let json = serde_json::to_string(&plan).unwrap();
    let back: MigrationPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(plan, back);
}

// ---------------------------------------------------------------------------
// Clone & Debug
// ---------------------------------------------------------------------------

#[test]
fn test_matrix_clone() {
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    let cloned = m.clone();
    assert_eq!(m, cloned);
}

#[test]
fn test_matrix_debug() {
    let m = frankenlab_gap_matrix::build_canonical_gap_matrix(test_epoch());
    let dbg = format!("{m:?}");
    assert!(dbg.contains("GapMatrix"));
}
