//! Enrichment integration tests for frankenlab_gap_matrix (bd-3nr.1.1.2).
//!
//! Covers areas not exercised by the base integration test file:
//! - Enum ordering (Ord) for LabSurfaceKind, UpstreamCapability, GapStatus, MigrationDecision
//! - Display string uniqueness for all enums
//! - Content hash sensitivity to each entry field
//! - Coverage summary edge cases (overflow guard, weighted average correctness)
//! - Migration plan recommendation text validation
//! - Canonical matrix row completeness (10 per surface)
//! - Canonical matrix pair uniqueness (no duplicate cells)
//! - GapMatrixEntry display format
//! - Matrix display includes epoch and schema version

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

use frankenengine_engine::frankenlab_gap_matrix::{
    GAP_MATRIX_BEAD_ID, GAP_MATRIX_SCHEMA_VERSION, GapCoverageSummary, GapMatrix, GapMatrixEntry,
    GapStatus, LabSurfaceKind, MigrationDecision, MigrationPlan, UpstreamCapability,
    build_canonical_gap_matrix,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn entry(
    local: LabSurfaceKind,
    upstream: UpstreamCapability,
    status: GapStatus,
    coverage: u64,
    decision: MigrationDecision,
) -> GapMatrixEntry {
    GapMatrixEntry {
        local_surface: local,
        upstream_capability: upstream,
        status,
        coverage_millionths: coverage,
        migration_decision: decision,
        rationale: "test rationale".into(),
        confidence_millionths: 800_000,
    }
}

// ---------------------------------------------------------------------------
// LabSurfaceKind — ordering + display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lab_surface_kind_ordering_is_deterministic() {
    let mut kinds = LabSurfaceKind::ALL.to_vec();
    let original = kinds.clone();
    kinds.sort();
    assert_eq!(kinds, original, "ALL should already be in Ord order");
}

#[test]
fn enrichment_lab_surface_kind_display_strings_unique() {
    let displays: BTreeSet<String> = LabSurfaceKind::ALL.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), LabSurfaceKind::ALL.len());
}

#[test]
fn enrichment_lab_surface_kind_display_nonempty() {
    for k in &LabSurfaceKind::ALL {
        assert!(!k.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------------
// UpstreamCapability — ordering + display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_upstream_capability_ordering_is_deterministic() {
    let mut caps = UpstreamCapability::ALL.to_vec();
    let original = caps.clone();
    caps.sort();
    assert_eq!(caps, original, "ALL should already be in Ord order");
}

#[test]
fn enrichment_upstream_capability_display_strings_unique() {
    let displays: BTreeSet<String> = UpstreamCapability::ALL
        .iter()
        .map(|c| c.to_string())
        .collect();
    assert_eq!(displays.len(), UpstreamCapability::ALL.len());
}

// ---------------------------------------------------------------------------
// GapStatus — ordering + display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gap_status_ordering() {
    assert!(GapStatus::Covered < GapStatus::PartialGap);
    assert!(GapStatus::PartialGap < GapStatus::FullGap);
    assert!(GapStatus::FullGap < GapStatus::Redundant);
}

#[test]
fn enrichment_gap_status_display_unique() {
    let all = [
        GapStatus::Covered,
        GapStatus::PartialGap,
        GapStatus::FullGap,
        GapStatus::Redundant,
    ];
    let displays: BTreeSet<String> = all.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_gap_status_serde_per_variant() {
    let all = [
        (GapStatus::Covered, "covered"),
        (GapStatus::PartialGap, "partial_gap"),
        (GapStatus::FullGap, "full_gap"),
        (GapStatus::Redundant, "redundant"),
    ];
    for (variant, expected_display) in &all {
        assert_eq!(variant.to_string(), *expected_display);
        let json = serde_json::to_string(variant).unwrap();
        let back: GapStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, back);
    }
}

// ---------------------------------------------------------------------------
// MigrationDecision — ordering + display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_migration_decision_ordering() {
    assert!(MigrationDecision::DirectAdoption < MigrationDecision::ThinBridge);
    assert!(MigrationDecision::ThinBridge < MigrationDecision::MaintainedWrapper);
    assert!(MigrationDecision::MaintainedWrapper < MigrationDecision::NoMigration);
    assert!(MigrationDecision::NoMigration < MigrationDecision::Deferred);
}

#[test]
fn enrichment_migration_decision_display_unique() {
    let all = [
        MigrationDecision::DirectAdoption,
        MigrationDecision::ThinBridge,
        MigrationDecision::MaintainedWrapper,
        MigrationDecision::NoMigration,
        MigrationDecision::Deferred,
    ];
    let displays: BTreeSet<String> = all.iter().map(|d| d.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_migration_decision_serde_per_variant() {
    let all = [
        (MigrationDecision::DirectAdoption, "direct_adoption"),
        (MigrationDecision::ThinBridge, "thin_bridge"),
        (MigrationDecision::MaintainedWrapper, "maintained_wrapper"),
        (MigrationDecision::NoMigration, "no_migration"),
        (MigrationDecision::Deferred, "deferred"),
    ];
    for (variant, expected_display) in &all {
        assert_eq!(variant.to_string(), *expected_display);
        let json = serde_json::to_string(variant).unwrap();
        let back: MigrationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, back);
    }
}

// ---------------------------------------------------------------------------
// Content hash sensitivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_content_hash_sensitive_to_coverage() {
    let mut m1 = GapMatrix::new(epoch(1));
    m1.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        900_000,
        MigrationDecision::NoMigration,
    ));
    let mut m2 = GapMatrix::new(epoch(1));
    m2.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        500_000, // different coverage
        MigrationDecision::NoMigration,
    ));
    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn enrichment_content_hash_sensitive_to_decision() {
    let mut m1 = GapMatrix::new(epoch(1));
    m1.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        900_000,
        MigrationDecision::NoMigration,
    ));
    let mut m2 = GapMatrix::new(epoch(1));
    m2.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        900_000,
        MigrationDecision::DirectAdoption,
    ));
    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn enrichment_content_hash_sensitive_to_epoch() {
    let mut m1 = GapMatrix::new(epoch(1));
    m1.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        900_000,
        MigrationDecision::NoMigration,
    ));
    let mut m2 = GapMatrix::new(epoch(2));
    m2.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        900_000,
        MigrationDecision::NoMigration,
    ));
    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn enrichment_content_hash_sensitive_to_rationale() {
    let mut m1 = GapMatrix::new(epoch(1));
    let mut e = entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        900_000,
        MigrationDecision::NoMigration,
    );
    e.rationale = "reason one".into();
    m1.add_entry(e);

    let mut m2 = GapMatrix::new(epoch(1));
    let mut e2 = entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        900_000,
        MigrationDecision::NoMigration,
    );
    e2.rationale = "reason two".into();
    m2.add_entry(e2);
    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn enrichment_content_hash_sensitive_to_confidence() {
    let mut m1 = GapMatrix::new(epoch(1));
    let mut e = entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        900_000,
        MigrationDecision::NoMigration,
    );
    e.confidence_millionths = 800_000;
    m1.add_entry(e);

    let mut m2 = GapMatrix::new(epoch(1));
    let mut e2 = entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        900_000,
        MigrationDecision::NoMigration,
    );
    e2.confidence_millionths = 600_000;
    m2.add_entry(e2);
    assert_ne!(m1.content_hash(), m2.content_hash());
}

// ---------------------------------------------------------------------------
// Coverage summary edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_coverage_summary_weighted_average_correct() {
    let mut matrix = GapMatrix::new(epoch(1));
    matrix.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        1_000_000,
        MigrationDecision::NoMigration,
    ));
    matrix.add_entry(entry(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::LabRuntime,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
    ));
    let summary = matrix.coverage_summary();
    assert_eq!(summary.total_pairs, 2);
    assert_eq!(summary.overall_coverage_millionths, 500_000); // (1_000_000 + 0) / 2
}

#[test]
fn enrichment_coverage_summary_all_redundant() {
    let mut matrix = GapMatrix::new(epoch(1));
    matrix.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Redundant,
        1_000_000,
        MigrationDecision::NoMigration,
    ));
    let summary = matrix.coverage_summary();
    assert_eq!(summary.redundant_count, 1);
    assert_eq!(summary.covered_count, 0);
    assert_eq!(summary.partial_gap_count, 0);
    assert_eq!(summary.full_gap_count, 0);
}

// ---------------------------------------------------------------------------
// Migration plan recommendation text
// ---------------------------------------------------------------------------

#[test]
fn enrichment_migration_plan_recommendation_all_adopt() {
    let mut matrix = GapMatrix::new(epoch(1));
    matrix.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
    ));
    let plan = matrix.migration_plan();
    assert!(plan.recommendation.contains("direct adoption"));
    assert_eq!(plan.adopt.len(), 1);
    assert!(plan.bridge.is_empty());
    assert!(plan.defer.is_empty());
}

#[test]
fn enrichment_migration_plan_recommendation_with_deferred() {
    let mut matrix = GapMatrix::new(epoch(1));
    matrix.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
    ));
    let plan = matrix.migration_plan();
    assert!(plan.recommendation.contains("deferred"));
    assert_eq!(plan.defer.len(), 1);
}

#[test]
fn enrichment_migration_plan_recommendation_mixed_no_defer() {
    let mut matrix = GapMatrix::new(epoch(1));
    matrix.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
    ));
    matrix.add_entry(entry(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::LabRuntime,
        GapStatus::PartialGap,
        500_000,
        MigrationDecision::ThinBridge,
    ));
    let plan = matrix.migration_plan();
    assert!(plan.recommendation.contains("Mixed strategy"));
}

// ---------------------------------------------------------------------------
// Canonical matrix invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_canonical_matrix_each_surface_has_ten_capabilities() {
    let matrix = build_canonical_gap_matrix(epoch(42));
    for surface in &LabSurfaceKind::ALL {
        let count = matrix
            .entries
            .iter()
            .filter(|e| e.local_surface == *surface)
            .count();
        assert_eq!(
            count, 10,
            "surface {:?} should have 10 capability pairs",
            surface
        );
    }
}

#[test]
fn enrichment_canonical_matrix_no_duplicate_pairs() {
    let matrix = build_canonical_gap_matrix(epoch(42));
    let mut seen = BTreeSet::new();
    for e in &matrix.entries {
        let pair = (e.local_surface, e.upstream_capability);
        assert!(
            seen.insert(pair),
            "duplicate pair: {:?}x{:?}",
            e.local_surface,
            e.upstream_capability
        );
    }
    assert_eq!(seen.len(), 100);
}

#[test]
fn enrichment_canonical_matrix_rationale_non_empty() {
    let matrix = build_canonical_gap_matrix(epoch(42));
    for e in &matrix.entries {
        assert!(
            !e.rationale.is_empty(),
            "entry {:?}x{:?} has empty rationale",
            e.local_surface,
            e.upstream_capability
        );
    }
}

#[test]
fn enrichment_canonical_matrix_coverage_at_most_one_million() {
    let matrix = build_canonical_gap_matrix(epoch(42));
    for e in &matrix.entries {
        assert!(
            e.coverage_millionths <= 1_000_000,
            "entry {:?}x{:?} coverage {} exceeds 100%",
            e.local_surface,
            e.upstream_capability,
            e.coverage_millionths
        );
    }
}

#[test]
fn enrichment_canonical_matrix_confidence_at_most_one_million() {
    let matrix = build_canonical_gap_matrix(epoch(42));
    for e in &matrix.entries {
        assert!(
            e.confidence_millionths <= 1_000_000,
            "entry {:?}x{:?} confidence {} exceeds 100%",
            e.local_surface,
            e.upstream_capability,
            e.confidence_millionths
        );
    }
}

#[test]
fn enrichment_canonical_matrix_full_gap_has_zero_coverage() {
    let matrix = build_canonical_gap_matrix(epoch(42));
    for e in &matrix.entries {
        if e.status == GapStatus::FullGap {
            assert_eq!(
                e.coverage_millionths, 0,
                "FullGap entry {:?}x{:?} should have 0 coverage",
                e.local_surface, e.upstream_capability
            );
        }
    }
}

#[test]
fn enrichment_canonical_matrix_covered_has_positive_coverage() {
    let matrix = build_canonical_gap_matrix(epoch(42));
    for e in &matrix.entries {
        if e.status == GapStatus::Covered {
            assert!(
                e.coverage_millionths > 0,
                "Covered entry {:?}x{:?} should have positive coverage",
                e.local_surface,
                e.upstream_capability
            );
        }
    }
}

#[test]
fn enrichment_canonical_matrix_migration_plan_complete() {
    let matrix = build_canonical_gap_matrix(epoch(42));
    let plan = matrix.migration_plan();
    let total =
        plan.adopt.len() + plan.bridge.len() + plan.wrap.len() + plan.keep.len() + plan.defer.len();
    assert_eq!(
        total, 100,
        "migration plan should account for all 100 pairs"
    );
}

// ---------------------------------------------------------------------------
// GapMatrixEntry display format
// ---------------------------------------------------------------------------

#[test]
fn enrichment_entry_display_contains_surface_and_capability() {
    let e = entry(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::OracleDispatch,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
    );
    let display = e.to_string();
    assert!(display.contains("scenario_runner"));
    assert!(display.contains("oracle_dispatch"));
    assert!(display.contains("full_gap"));
    assert!(display.contains("direct_adoption"));
}

// ---------------------------------------------------------------------------
// GapMatrix display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_matrix_display_includes_schema_and_epoch() {
    let matrix = build_canonical_gap_matrix(epoch(7));
    let display = matrix.to_string();
    assert!(display.contains(GAP_MATRIX_SCHEMA_VERSION));
    assert!(display.contains("epoch="));
}

// ---------------------------------------------------------------------------
// Serde roundtrips for aggregate types
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gap_coverage_summary_serde() {
    let summary = GapCoverageSummary {
        total_pairs: 100,
        covered_count: 30,
        partial_gap_count: 25,
        full_gap_count: 35,
        redundant_count: 10,
        overall_coverage_millionths: 450_000,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: GapCoverageSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn enrichment_migration_plan_serde_nonempty() {
    let plan = MigrationPlan {
        adopt: vec![(
            LabSurfaceKind::DeterministicReplay,
            UpstreamCapability::LabRuntime,
        )],
        bridge: vec![(
            LabSurfaceKind::ScenarioRunner,
            UpstreamCapability::EvidenceReplay,
        )],
        wrap: vec![(
            LabSurfaceKind::VirtualTimeClock,
            UpstreamCapability::LabRuntime,
        )],
        keep: vec![(
            LabSurfaceKind::CancellationInjector,
            UpstreamCapability::CancelInjection,
        )],
        defer: vec![(
            LabSurfaceKind::EvidenceChecker,
            UpstreamCapability::QuarantineOrchestration,
        )],
        recommendation: "Mixed strategy".into(),
    };
    let json = serde_json::to_string(&plan).unwrap();
    let back: MigrationPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(plan, back);
}

#[test]
fn enrichment_gap_matrix_entry_serde_all_fields() {
    let e = GapMatrixEntry {
        local_surface: LabSurfaceKind::QuarantineHarness,
        upstream_capability: UpstreamCapability::QuarantineOrchestration,
        status: GapStatus::PartialGap,
        coverage_millionths: 600_000,
        migration_decision: MigrationDecision::ThinBridge,
        rationale: "Quarantine harness partially covers orchestration".into(),
        confidence_millionths: 750_000,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: GapMatrixEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_non_empty() {
    assert!(!GAP_MATRIX_SCHEMA_VERSION.is_empty());
    assert!(!GAP_MATRIX_BEAD_ID.is_empty());
    assert!(GAP_MATRIX_SCHEMA_VERSION.contains("gap-matrix"));
    assert!(GAP_MATRIX_BEAD_ID.starts_with("bd-"));
}

// ---------------------------------------------------------------------------
// Lookup edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lookup_returns_none_for_empty_matrix() {
    let matrix = GapMatrix::new(epoch(1));
    assert!(
        matrix
            .lookup(
                LabSurfaceKind::DeterministicReplay,
                UpstreamCapability::LabRuntime
            )
            .is_none()
    );
}

#[test]
fn enrichment_lookup_wrong_capability_returns_none() {
    let mut matrix = GapMatrix::new(epoch(1));
    matrix.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        900_000,
        MigrationDecision::NoMigration,
    ));
    assert!(
        matrix
            .lookup(
                LabSurfaceKind::DeterministicReplay,
                UpstreamCapability::OracleDispatch
            )
            .is_none()
    );
}

#[test]
fn enrichment_lookup_wrong_surface_returns_none() {
    let mut matrix = GapMatrix::new(epoch(1));
    matrix.add_entry(entry(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        900_000,
        MigrationDecision::NoMigration,
    ));
    assert!(
        matrix
            .lookup(
                LabSurfaceKind::ScenarioRunner,
                UpstreamCapability::LabRuntime
            )
            .is_none()
    );
}
