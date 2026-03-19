#![forbid(unsafe_code)]
//! Enrichment integration tests for `frankenlab_surface_gap_matrix`.
//!
//! Tests SurfaceId::ALL completeness, Display uniqueness, source_file validity,
//! CapabilityId Display uniqueness, serde roundtrips, constant presence,
//! and gap matrix structure.

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

use frankenengine_engine::frankenlab_surface_gap_matrix::{
    CapabilityId, CoverageLevel, GapCell, GapMatrix, MigrationDecision, SurfaceAssessment,
    SurfaceId, BEAD_ID, COMPONENT, GAP_MATRIX_SCHEMA_VERSION, build_canonical_gap_matrix,
};

// ===========================================================================
// helpers
// ===========================================================================

fn cell(s: SurfaceId, c: CapabilityId, cov: CoverageLevel, n: &str) -> GapCell {
    GapCell {
        surface: s,
        capability: c,
        coverage: cov,
        notes: n.to_string(),
    }
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_constant_component_value() {
    assert_eq!(COMPONENT, "frankenlab_surface_gap_matrix");
}

#[test]
fn enrichment_constant_bead_id_nonempty() {
    assert!(!BEAD_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_constant_schema_version_nonempty() {
    assert!(!GAP_MATRIX_SCHEMA_VERSION.is_empty());
    assert!(GAP_MATRIX_SCHEMA_VERSION.contains("gap-matrix"));
}

// ===========================================================================
// SurfaceId::ALL completeness
// ===========================================================================

#[test]
fn enrichment_surface_id_all_count() {
    assert_eq!(SurfaceId::ALL.len(), 7);
}

#[test]
fn enrichment_surface_id_all_unique() {
    let set: BTreeSet<SurfaceId> = SurfaceId::ALL.iter().copied().collect();
    assert_eq!(set.len(), 7);
}

#[test]
fn enrichment_surface_id_ord_follows_declaration() {
    for pair in SurfaceId::ALL.windows(2) {
        assert!(pair[0] < pair[1], "{:?} should be < {:?}", pair[0], pair[1]);
    }
}

// ===========================================================================
// SurfaceId Display uniqueness
// ===========================================================================

#[test]
fn enrichment_surface_id_display_all_unique() {
    let displays: BTreeSet<String> = SurfaceId::ALL.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 7);
}

#[test]
fn enrichment_surface_id_display_lowercase_snake() {
    for s in &SurfaceId::ALL {
        let disp = s.to_string();
        assert!(
            disp.chars().all(|c| c.is_lowercase() || c == '_'),
            "Display for {s:?} should be lowercase snake_case, got '{disp}'"
        );
    }
}

#[test]
fn enrichment_surface_id_display_nonempty() {
    for s in &SurfaceId::ALL {
        assert!(!s.to_string().is_empty());
    }
}

// ===========================================================================
// SurfaceId::source_file()
// ===========================================================================

#[test]
fn enrichment_surface_id_source_file_starts_with_src() {
    for s in &SurfaceId::ALL {
        let f = s.source_file();
        assert!(
            f.starts_with("src/"),
            "source_file for {s:?} must start with src/, got '{f}'"
        );
    }
}

#[test]
fn enrichment_surface_id_source_file_ends_with_rs() {
    for s in &SurfaceId::ALL {
        let f = s.source_file();
        assert!(
            f.ends_with(".rs"),
            "source_file for {s:?} must end with .rs, got '{f}'"
        );
    }
}

#[test]
fn enrichment_surface_id_source_file_all_unique() {
    let files: BTreeSet<&str> = SurfaceId::ALL.iter().map(|s| s.source_file()).collect();
    assert_eq!(files.len(), 7);
}

#[test]
fn enrichment_surface_id_source_file_known_values() {
    assert_eq!(SurfaceId::LabRuntime.source_file(), "src/lab_runtime.rs");
    assert_eq!(
        SurfaceId::FrankenlabScenarios.source_file(),
        "src/frankenlab_extension_lifecycle.rs"
    );
    assert_eq!(
        SurfaceId::ReleaseGate.source_file(),
        "src/frankenlab_release_gate.rs"
    );
}

// ===========================================================================
// SurfaceId serde roundtrips
// ===========================================================================

#[test]
fn enrichment_surface_id_serde_roundtrip_all() {
    for s in &SurfaceId::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: SurfaceId = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn enrichment_surface_id_serde_tags_distinct() {
    let tags: BTreeSet<String> = SurfaceId::ALL
        .iter()
        .map(|s| serde_json::to_string(s).unwrap())
        .collect();
    assert_eq!(tags.len(), 7);
}

#[test]
fn enrichment_surface_id_serde_snake_case() {
    let json = serde_json::to_string(&SurfaceId::LabRuntime).unwrap();
    assert_eq!(json, "\"lab_runtime\"");
}

// ===========================================================================
// CapabilityId Display uniqueness
// ===========================================================================

#[test]
fn enrichment_capability_id_display_all_unique() {
    let all = [
        CapabilityId::VirtualTime,
        CapabilityId::ScheduleReplay,
        CapabilityId::FaultInjection,
        CapabilityId::CancellationInjection,
        CapabilityId::TaskLifecycle,
        CapabilityId::ExtensionLifecycle,
        CapabilityId::RaceExploration,
        CapabilityId::EvidenceChainValidation,
        CapabilityId::CrossMachineDeterminism,
        CapabilityId::NondeterminismCapture,
        CapabilityId::DivergenceDetection,
        CapabilityId::FailoverManagement,
        CapabilityId::IncidentArtifacts,
        CapabilityId::EventSimulation,
        CapabilityId::PriorityDispatch,
        CapabilityId::FailClosedGating,
        CapabilityId::ContentAddressedArtifacts,
        CapabilityId::ObligationResolution,
    ];
    let displays: BTreeSet<String> = all.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 18);
}

#[test]
fn enrichment_capability_id_display_nonempty() {
    let caps = [
        CapabilityId::VirtualTime,
        CapabilityId::ScheduleReplay,
        CapabilityId::FaultInjection,
        CapabilityId::ObligationResolution,
    ];
    for c in &caps {
        assert!(!c.to_string().is_empty());
    }
}

#[test]
fn enrichment_capability_id_serde_roundtrip_sample() {
    let caps = [
        CapabilityId::VirtualTime,
        CapabilityId::FaultInjection,
        CapabilityId::FailClosedGating,
        CapabilityId::ObligationResolution,
    ];
    for c in &caps {
        let json = serde_json::to_string(c).unwrap();
        let back: CapabilityId = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

// ===========================================================================
// CoverageLevel and MigrationDecision serde
// ===========================================================================

#[test]
fn enrichment_coverage_level_serde_roundtrip_all() {
    let all = [
        CoverageLevel::Covered,
        CoverageLevel::Partial,
        CoverageLevel::Missing,
        CoverageLevel::LocalOnly,
    ];
    for cov in &all {
        let json = serde_json::to_string(cov).unwrap();
        let back: CoverageLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(*cov, back);
    }
}

#[test]
fn enrichment_coverage_level_display_all_unique() {
    let all = [
        CoverageLevel::Covered,
        CoverageLevel::Partial,
        CoverageLevel::Missing,
        CoverageLevel::LocalOnly,
    ];
    let displays: BTreeSet<String> = all.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_migration_decision_serde_roundtrip_all() {
    let all = [
        MigrationDecision::DirectAdoption,
        MigrationDecision::ThinBridge,
        MigrationDecision::MaintainedWrapper,
    ];
    for d in &all {
        let json = serde_json::to_string(d).unwrap();
        let back: MigrationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

#[test]
fn enrichment_migration_decision_display_all_unique() {
    let all = [
        MigrationDecision::DirectAdoption,
        MigrationDecision::ThinBridge,
        MigrationDecision::MaintainedWrapper,
    ];
    let displays: BTreeSet<String> = all.iter().map(|d| d.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

// ===========================================================================
// GapCell serde and Display
// ===========================================================================

#[test]
fn enrichment_gap_cell_serde_roundtrip() {
    let c = cell(
        SurfaceId::LabRuntime,
        CapabilityId::VirtualTime,
        CoverageLevel::Covered,
        "full coverage",
    );
    let json = serde_json::to_string(&c).unwrap();
    let back: GapCell = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn enrichment_gap_cell_display_contains_surface_and_capability() {
    let c = cell(
        SurfaceId::LabRuntime,
        CapabilityId::VirtualTime,
        CoverageLevel::Covered,
        "note",
    );
    let disp = c.to_string();
    assert!(disp.contains("lab_runtime"));
    assert!(disp.contains("covered"));
}

// ===========================================================================
// SurfaceAssessment
// ===========================================================================

#[test]
fn enrichment_surface_assessment_build_and_serde() {
    let cells = vec![
        cell(
            SurfaceId::LabRuntime,
            CapabilityId::VirtualTime,
            CoverageLevel::Covered,
            "ok",
        ),
        cell(
            SurfaceId::LabRuntime,
            CapabilityId::FaultInjection,
            CoverageLevel::Missing,
            "needs work",
        ),
    ];
    let a = SurfaceAssessment::build(
        SurfaceId::LabRuntime,
        cells,
        MigrationDecision::ThinBridge,
        "rationale",
    );
    assert_eq!(a.surface, SurfaceId::LabRuntime);
    assert_eq!(a.decision, MigrationDecision::ThinBridge);
    assert_eq!(a.covered_count, 1);
    assert_eq!(a.missing_count, 1);

    let json = serde_json::to_string(&a).unwrap();
    let back: SurfaceAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

// ===========================================================================
// Canonical gap matrix
// ===========================================================================

#[test]
fn enrichment_canonical_gap_matrix_has_all_surfaces() {
    let matrix = build_canonical_gap_matrix();
    for s in &SurfaceId::ALL {
        assert!(
            matrix.for_surface(*s).is_some(),
            "canonical matrix missing surface {s:?}"
        );
    }
}

#[test]
fn enrichment_canonical_gap_matrix_serde_roundtrip() {
    let matrix = build_canonical_gap_matrix();
    let json = serde_json::to_string(&matrix).unwrap();
    let back: GapMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(matrix, back);
}

#[test]
fn enrichment_canonical_gap_matrix_deterministic() {
    let m1 = build_canonical_gap_matrix();
    let m2 = build_canonical_gap_matrix();
    assert_eq!(m1, m2);
}

// ===========================================================================
// Debug and Clone
// ===========================================================================

#[test]
fn enrichment_surface_id_debug_all_distinct() {
    let debugs: BTreeSet<String> = SurfaceId::ALL.iter().map(|s| format!("{s:?}")).collect();
    assert_eq!(debugs.len(), 7);
}

#[test]
fn enrichment_gap_cell_clone_independence() {
    let c = cell(
        SurfaceId::SimScheduler,
        CapabilityId::EventSimulation,
        CoverageLevel::Partial,
        "original",
    );
    let mut cloned = c.clone();
    cloned.notes = "modified".to_string();
    assert_eq!(c.notes, "original");
}
