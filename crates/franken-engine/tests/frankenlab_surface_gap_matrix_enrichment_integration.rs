#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for `frankenlab_surface_gap_matrix`.

use std::collections::BTreeSet;

use frankenengine_engine::frankenlab_surface_gap_matrix::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn cell(s: SurfaceId, c: CapabilityId, cov: CoverageLevel, n: &str) -> GapCell {
    GapCell { surface: s, capability: c, coverage: cov, notes: n.to_string() }
}

fn assessment(s: SurfaceId, cells: Vec<GapCell>, d: MigrationDecision) -> SurfaceAssessment {
    SurfaceAssessment::build(s, cells, d, "test rationale")
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constant_component_value() {
    assert_eq!(COMPONENT, "frankenlab_surface_gap_matrix");
}

#[test]
fn constant_bead_id_value() {
    assert_eq!(BEAD_ID, "bd-3nr.1.1.2");
}

#[test]
fn constant_schema_version_value() {
    assert_eq!(GAP_MATRIX_SCHEMA_VERSION, "franken-engine.frankenlab-gap-matrix.v1");
}

// ---------------------------------------------------------------------------
// SurfaceId
// ---------------------------------------------------------------------------

#[test]
fn surface_id_all_count() {
    assert_eq!(SurfaceId::ALL.len(), 7);
}

#[test]
fn surface_id_all_unique() {
    let mut seen = BTreeSet::new();
    for s in SurfaceId::ALL {
        assert!(seen.insert(s), "duplicate SurfaceId: {s}");
    }
}

#[test]
fn surface_id_display_distinctness() {
    let mut seen = BTreeSet::new();
    for s in SurfaceId::ALL {
        assert!(seen.insert(format!("{s}")));
    }
    assert_eq!(seen.len(), 7);
}

#[test]
fn surface_id_serde_roundtrip() {
    for s in SurfaceId::ALL {
        let json = serde_json::to_string(&s).unwrap();
        let back: SurfaceId = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn surface_id_serde_snake_case() {
    let json = serde_json::to_string(&SurfaceId::LabRuntime).unwrap();
    assert_eq!(json, "\"lab_runtime\"");
    let json = serde_json::to_string(&SurfaceId::FrankenlabScenarios).unwrap();
    assert_eq!(json, "\"frankenlab_scenarios\"");
}

#[test]
fn surface_id_source_file_all_valid() {
    for s in SurfaceId::ALL {
        let f = s.source_file();
        assert!(f.starts_with("src/"), "source_file for {s} must start with src/");
        assert!(f.ends_with(".rs"), "source_file for {s} must end with .rs");
    }
}

#[test]
fn surface_id_ordering_matches_all_array() {
    for pair in SurfaceId::ALL.windows(2) {
        assert!(pair[0] < pair[1]);
    }
}

// ---------------------------------------------------------------------------
// CapabilityId
// ---------------------------------------------------------------------------

#[test]
fn capability_id_display_all_not_empty() {
    let all = [
        CapabilityId::VirtualTime, CapabilityId::ScheduleReplay, CapabilityId::FaultInjection,
        CapabilityId::CancellationInjection, CapabilityId::TaskLifecycle,
        CapabilityId::ExtensionLifecycle, CapabilityId::RaceExploration,
        CapabilityId::EvidenceChainValidation, CapabilityId::CrossMachineDeterminism,
        CapabilityId::NondeterminismCapture, CapabilityId::DivergenceDetection,
        CapabilityId::FailoverManagement, CapabilityId::IncidentArtifacts,
        CapabilityId::EventSimulation, CapabilityId::PriorityDispatch,
        CapabilityId::FailClosedGating, CapabilityId::ContentAddressedArtifacts,
        CapabilityId::ObligationResolution,
    ];
    let mut seen = BTreeSet::new();
    for c in all {
        let s = format!("{c}");
        assert!(!s.is_empty());
        assert!(seen.insert(s.clone()), "duplicate CapabilityId display: {s}");
    }
    assert_eq!(seen.len(), 18);
}

#[test]
fn capability_id_serde_roundtrip() {
    let caps = [
        CapabilityId::VirtualTime, CapabilityId::ScheduleReplay,
        CapabilityId::FaultInjection, CapabilityId::ObligationResolution,
    ];
    for c in caps {
        let json = serde_json::to_string(&c).unwrap();
        let back: CapabilityId = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}

// ---------------------------------------------------------------------------
// CoverageLevel
// ---------------------------------------------------------------------------

#[test]
fn coverage_level_display_values() {
    assert_eq!(format!("{}", CoverageLevel::Covered), "covered");
    assert_eq!(format!("{}", CoverageLevel::Partial), "partial");
    assert_eq!(format!("{}", CoverageLevel::Missing), "missing");
    assert_eq!(format!("{}", CoverageLevel::LocalOnly), "local_only");
}

#[test]
fn coverage_level_serde_roundtrip_all() {
    for c in [CoverageLevel::Covered, CoverageLevel::Partial, CoverageLevel::Missing, CoverageLevel::LocalOnly] {
        let json = serde_json::to_string(&c).unwrap();
        let back: CoverageLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}

#[test]
fn coverage_level_ordering_chain() {
    assert!(CoverageLevel::Covered < CoverageLevel::Partial);
    assert!(CoverageLevel::Partial < CoverageLevel::Missing);
    assert!(CoverageLevel::Missing < CoverageLevel::LocalOnly);
}

// ---------------------------------------------------------------------------
// MigrationDecision
// ---------------------------------------------------------------------------

#[test]
fn migration_decision_display_values() {
    assert_eq!(format!("{}", MigrationDecision::DirectAdoption), "direct_adoption");
    assert_eq!(format!("{}", MigrationDecision::ThinBridge), "thin_bridge");
    assert_eq!(format!("{}", MigrationDecision::MaintainedWrapper), "maintained_wrapper");
}

#[test]
fn migration_decision_serde_roundtrip_all() {
    for d in [MigrationDecision::DirectAdoption, MigrationDecision::ThinBridge, MigrationDecision::MaintainedWrapper] {
        let json = serde_json::to_string(&d).unwrap();
        let back: MigrationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}

// ---------------------------------------------------------------------------
// GapCell
// ---------------------------------------------------------------------------

#[test]
fn gap_cell_serde_roundtrip() {
    let c = cell(SurfaceId::LabRuntime, CapabilityId::VirtualTime, CoverageLevel::Covered, "ok");
    let json = serde_json::to_string(&c).unwrap();
    let back: GapCell = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn gap_cell_display_contains_surface_and_coverage() {
    let c = cell(SurfaceId::ReleaseGate, CapabilityId::FailClosedGating, CoverageLevel::Partial, "note");
    let s = format!("{c}");
    assert!(s.contains("release_gate"));
    assert!(s.contains("partial"));
    assert!(s.contains("note"));
}

#[test]
fn gap_cell_json_field_names() {
    let c = cell(SurfaceId::LabRuntime, CapabilityId::VirtualTime, CoverageLevel::Covered, "test");
    let v: serde_json::Value = serde_json::to_value(&c).unwrap();
    assert_eq!(v["surface"], "lab_runtime");
    assert_eq!(v["capability"], "virtual_time");
    assert_eq!(v["coverage"], "covered");
}

// ---------------------------------------------------------------------------
// SurfaceAssessment
// ---------------------------------------------------------------------------

#[test]
fn surface_assessment_build_counts() {
    let cells = vec![
        cell(SurfaceId::LabRuntime, CapabilityId::VirtualTime, CoverageLevel::Covered, ""),
        cell(SurfaceId::LabRuntime, CapabilityId::FaultInjection, CoverageLevel::Partial, ""),
        cell(SurfaceId::LabRuntime, CapabilityId::RaceExploration, CoverageLevel::Missing, ""),
        cell(SurfaceId::LabRuntime, CapabilityId::TaskLifecycle, CoverageLevel::LocalOnly, ""),
    ];
    let a = assessment(SurfaceId::LabRuntime, cells, MigrationDecision::ThinBridge);
    assert_eq!(a.covered_count, 1);
    assert_eq!(a.partial_count, 1);
    assert_eq!(a.missing_count, 1);
    assert_eq!(a.local_only_count, 1);
}

#[test]
fn surface_assessment_coverage_rate_full() {
    let cells = vec![
        cell(SurfaceId::LabRuntime, CapabilityId::VirtualTime, CoverageLevel::Covered, ""),
    ];
    let a = assessment(SurfaceId::LabRuntime, cells, MigrationDecision::DirectAdoption);
    assert_eq!(a.coverage_rate_millionths(), 1_000_000);
}

#[test]
fn surface_assessment_coverage_rate_empty_returns_full() {
    let a = assessment(SurfaceId::LabRuntime, vec![], MigrationDecision::DirectAdoption);
    assert_eq!(a.coverage_rate_millionths(), 1_000_000);
}

#[test]
fn surface_assessment_coverage_rate_all_missing() {
    let cells = vec![
        cell(SurfaceId::LabRuntime, CapabilityId::VirtualTime, CoverageLevel::Missing, ""),
        cell(SurfaceId::LabRuntime, CapabilityId::TaskLifecycle, CoverageLevel::Missing, ""),
    ];
    let a = assessment(SurfaceId::LabRuntime, cells, MigrationDecision::ThinBridge);
    assert_eq!(a.coverage_rate_millionths(), 0);
}

#[test]
fn surface_assessment_coverage_rate_local_only_excluded_from_denominator() {
    let cells = vec![
        cell(SurfaceId::LabRuntime, CapabilityId::VirtualTime, CoverageLevel::Covered, ""),
        cell(SurfaceId::LabRuntime, CapabilityId::TaskLifecycle, CoverageLevel::LocalOnly, ""),
    ];
    let a = assessment(SurfaceId::LabRuntime, cells, MigrationDecision::MaintainedWrapper);
    assert_eq!(a.coverage_rate_millionths(), 1_000_000);
}

#[test]
fn surface_assessment_display_format() {
    let a = assessment(SurfaceId::SimScheduler, vec![], MigrationDecision::MaintainedWrapper);
    let s = format!("{a}");
    assert!(s.contains("sim_scheduler"));
    assert!(s.contains("maintained_wrapper"));
}

#[test]
fn surface_assessment_serde_roundtrip() {
    let cells = vec![cell(SurfaceId::LabRuntime, CapabilityId::VirtualTime, CoverageLevel::Covered, "ok")];
    let a = assessment(SurfaceId::LabRuntime, cells, MigrationDecision::DirectAdoption);
    let json = serde_json::to_string(&a).unwrap();
    let back: SurfaceAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

// ---------------------------------------------------------------------------
// GapMatrix
// ---------------------------------------------------------------------------

#[test]
fn gap_matrix_empty() {
    let m = GapMatrix::build(vec![]);
    assert_eq!(m.summary.total_surfaces, 0);
    assert!(!m.has_gaps());
    assert_eq!(m.schema_version, GAP_MATRIX_SCHEMA_VERSION);
}

#[test]
fn gap_matrix_for_surface_found_and_not_found() {
    let a = assessment(SurfaceId::LabRuntime, vec![], MigrationDecision::MaintainedWrapper);
    let m = GapMatrix::build(vec![a]);
    assert!(m.for_surface(SurfaceId::LabRuntime).is_some());
    assert!(m.for_surface(SurfaceId::ReleaseGate).is_none());
}

#[test]
fn gap_matrix_has_gaps_when_missing_present() {
    let cells = vec![cell(SurfaceId::LabRuntime, CapabilityId::VirtualTime, CoverageLevel::Missing, "")];
    let a = assessment(SurfaceId::LabRuntime, cells, MigrationDecision::ThinBridge);
    let m = GapMatrix::build(vec![a]);
    assert!(m.has_gaps());
}

#[test]
fn gap_matrix_no_gaps_when_all_covered_or_partial() {
    let cells = vec![
        cell(SurfaceId::LabRuntime, CapabilityId::VirtualTime, CoverageLevel::Covered, ""),
        cell(SurfaceId::LabRuntime, CapabilityId::TaskLifecycle, CoverageLevel::Partial, ""),
    ];
    let a = assessment(SurfaceId::LabRuntime, cells, MigrationDecision::ThinBridge);
    let m = GapMatrix::build(vec![a]);
    assert!(!m.has_gaps());
}

#[test]
fn gap_matrix_surfaces_with_decision_filtering() {
    let a1 = assessment(SurfaceId::LabRuntime, vec![], MigrationDecision::DirectAdoption);
    let a2 = assessment(SurfaceId::ReleaseGate, vec![], MigrationDecision::ThinBridge);
    let a3 = assessment(SurfaceId::SimScheduler, vec![], MigrationDecision::DirectAdoption);
    let m = GapMatrix::build(vec![a1, a2, a3]);
    let direct = m.surfaces_with_decision(MigrationDecision::DirectAdoption);
    assert_eq!(direct.len(), 2);
    assert!(direct.contains(&SurfaceId::LabRuntime));
    assert!(direct.contains(&SurfaceId::SimScheduler));
}

#[test]
fn gap_matrix_hash_deterministic() {
    let cells1 = vec![cell(SurfaceId::LabRuntime, CapabilityId::VirtualTime, CoverageLevel::Covered, "")];
    let cells2 = vec![cell(SurfaceId::LabRuntime, CapabilityId::VirtualTime, CoverageLevel::Covered, "")];
    let m1 = GapMatrix::build(vec![assessment(SurfaceId::LabRuntime, cells1, MigrationDecision::DirectAdoption)]);
    let m2 = GapMatrix::build(vec![assessment(SurfaceId::LabRuntime, cells2, MigrationDecision::DirectAdoption)]);
    assert_eq!(m1.matrix_hash, m2.matrix_hash);
}

#[test]
fn gap_matrix_hash_differs_with_different_coverage() {
    let cells1 = vec![cell(SurfaceId::LabRuntime, CapabilityId::VirtualTime, CoverageLevel::Covered, "")];
    let cells2 = vec![cell(SurfaceId::LabRuntime, CapabilityId::VirtualTime, CoverageLevel::Missing, "")];
    let m1 = GapMatrix::build(vec![assessment(SurfaceId::LabRuntime, cells1, MigrationDecision::DirectAdoption)]);
    let m2 = GapMatrix::build(vec![assessment(SurfaceId::LabRuntime, cells2, MigrationDecision::DirectAdoption)]);
    assert_ne!(m1.matrix_hash, m2.matrix_hash);
}

#[test]
fn gap_matrix_display_contains_schema_version() {
    let m = GapMatrix::build(vec![]);
    let s = format!("{m}");
    assert!(s.contains(GAP_MATRIX_SCHEMA_VERSION));
    assert!(s.contains("Frankenlab Surface Gap Matrix"));
}

#[test]
fn gap_matrix_serde_roundtrip() {
    let cells = vec![
        cell(SurfaceId::LabRuntime, CapabilityId::VirtualTime, CoverageLevel::Covered, "ok"),
        cell(SurfaceId::LabRuntime, CapabilityId::FaultInjection, CoverageLevel::Missing, "gap"),
    ];
    let a = assessment(SurfaceId::LabRuntime, cells, MigrationDecision::ThinBridge);
    let m = GapMatrix::build(vec![a]);
    let json = serde_json::to_string(&m).unwrap();
    let back: GapMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn gap_matrix_summary_counts() {
    let cells = vec![
        cell(SurfaceId::LabRuntime, CapabilityId::VirtualTime, CoverageLevel::Covered, ""),
        cell(SurfaceId::LabRuntime, CapabilityId::FaultInjection, CoverageLevel::Partial, ""),
        cell(SurfaceId::LabRuntime, CapabilityId::RaceExploration, CoverageLevel::Missing, ""),
        cell(SurfaceId::LabRuntime, CapabilityId::TaskLifecycle, CoverageLevel::LocalOnly, ""),
    ];
    let a = assessment(SurfaceId::LabRuntime, cells, MigrationDecision::ThinBridge);
    let m = GapMatrix::build(vec![a]);
    assert_eq!(m.summary.total_cells, 4);
    assert_eq!(m.summary.covered_cells, 1);
    assert_eq!(m.summary.partial_cells, 1);
    assert_eq!(m.summary.missing_cells, 1);
    assert_eq!(m.summary.local_only_cells, 1);
}

// ---------------------------------------------------------------------------
// build_canonical_gap_matrix
// ---------------------------------------------------------------------------

#[test]
fn canonical_matrix_seven_surfaces() {
    let m = build_canonical_gap_matrix();
    assert_eq!(m.summary.total_surfaces, 7);
}

#[test]
fn canonical_matrix_all_surfaces_present() {
    let m = build_canonical_gap_matrix();
    for s in SurfaceId::ALL {
        assert!(m.for_surface(s).is_some(), "missing surface: {s}");
    }
}

#[test]
fn canonical_matrix_decisions() {
    let m = build_canonical_gap_matrix();
    assert_eq!(m.summary.direct_adoption_count, 0);
    assert_eq!(m.summary.thin_bridge_count, 3);
    assert_eq!(m.summary.maintained_wrapper_count, 4);
}

#[test]
fn canonical_matrix_no_missing() {
    let m = build_canonical_gap_matrix();
    assert_eq!(m.summary.missing_cells, 0);
    assert!(!m.has_gaps());
}

#[test]
fn canonical_matrix_has_partial() {
    let m = build_canonical_gap_matrix();
    assert!(m.summary.partial_cells > 0);
}

#[test]
fn canonical_matrix_deterministic_hash() {
    let m1 = build_canonical_gap_matrix();
    let m2 = build_canonical_gap_matrix();
    assert_eq!(m1.matrix_hash, m2.matrix_hash);
}

#[test]
fn canonical_matrix_serde_roundtrip() {
    let m = build_canonical_gap_matrix();
    let json = serde_json::to_string(&m).unwrap();
    let back: GapMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn canonical_matrix_display_has_surface_count() {
    let m = build_canonical_gap_matrix();
    let s = format!("{m}");
    assert!(s.contains("Surfaces: 7"));
}

#[test]
fn canonical_matrix_all_assessments_have_rationale() {
    let m = build_canonical_gap_matrix();
    for a in &m.assessments {
        assert!(!a.rationale.is_empty(), "empty rationale for {}", a.surface);
    }
}

#[test]
fn canonical_matrix_all_assessments_have_cells() {
    let m = build_canonical_gap_matrix();
    for a in &m.assessments {
        assert!(!a.cells.is_empty(), "no cells for {}", a.surface);
    }
}
