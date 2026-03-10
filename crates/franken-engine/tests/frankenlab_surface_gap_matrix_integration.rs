//! Integration tests for `frankenlab_surface_gap_matrix` module.

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

use frankenengine_engine::frankenlab_surface_gap_matrix::*;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn make_cell(
    surface: SurfaceId,
    capability: CapabilityId,
    coverage: CoverageLevel,
    notes: &str,
) -> GapCell {
    GapCell {
        surface,
        capability,
        coverage,
        notes: notes.to_string(),
    }
}

fn make_assessment(
    surface: SurfaceId,
    cells: Vec<GapCell>,
    decision: MigrationDecision,
) -> SurfaceAssessment {
    SurfaceAssessment::build(surface, cells, decision, "test rationale")
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constant_component() {
    assert_eq!(COMPONENT, "frankenlab_surface_gap_matrix");
}

#[test]
fn constant_bead_id() {
    assert_eq!(BEAD_ID, "bd-3nr.1.1.2");
}

#[test]
fn constant_schema_version() {
    assert_eq!(
        GAP_MATRIX_SCHEMA_VERSION,
        "frankenengine.frankenlab-gap-matrix.v1"
    );
}

// ---------------------------------------------------------------------------
// SurfaceId
// ---------------------------------------------------------------------------

#[test]
fn surface_id_all_has_seven_variants() {
    assert_eq!(SurfaceId::ALL.len(), 7);
}

#[test]
fn surface_id_all_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for s in SurfaceId::ALL {
        assert!(seen.insert(s), "duplicate SurfaceId: {s}");
    }
}

#[test]
fn surface_id_source_file_all_start_with_src() {
    for s in SurfaceId::ALL {
        let f = s.source_file();
        assert!(
            f.starts_with("src/"),
            "source_file for {s} must start with src/"
        );
        assert!(f.ends_with(".rs"), "source_file for {s} must end with .rs");
    }
}

#[test]
fn surface_id_source_file_specific_mappings() {
    assert_eq!(SurfaceId::LabRuntime.source_file(), "src/lab_runtime.rs");
    assert_eq!(
        SurfaceId::FrankenlabScenarios.source_file(),
        "src/frankenlab_extension_lifecycle.rs"
    );
    assert_eq!(
        SurfaceId::InterleavingExplorer.source_file(),
        "src/interleaving_explorer.rs"
    );
    assert_eq!(
        SurfaceId::EvidenceReplayChecker.source_file(),
        "src/evidence_replay_checker.rs"
    );
    assert_eq!(
        SurfaceId::DeterministicReplay.source_file(),
        "src/deterministic_replay.rs"
    );
    assert_eq!(
        SurfaceId::SimScheduler.source_file(),
        "src/deterministic_sim_scheduler.rs"
    );
    assert_eq!(
        SurfaceId::ReleaseGate.source_file(),
        "src/frankenlab_release_gate.rs"
    );
}

#[test]
fn surface_id_display_all_variants() {
    assert_eq!(format!("{}", SurfaceId::LabRuntime), "lab_runtime");
    assert_eq!(
        format!("{}", SurfaceId::FrankenlabScenarios),
        "frankenlab_scenarios"
    );
    assert_eq!(
        format!("{}", SurfaceId::InterleavingExplorer),
        "interleaving_explorer"
    );
    assert_eq!(
        format!("{}", SurfaceId::EvidenceReplayChecker),
        "evidence_replay_checker"
    );
    assert_eq!(
        format!("{}", SurfaceId::DeterministicReplay),
        "deterministic_replay"
    );
    assert_eq!(format!("{}", SurfaceId::SimScheduler), "sim_scheduler");
    assert_eq!(format!("{}", SurfaceId::ReleaseGate), "release_gate");
}

#[test]
fn surface_id_serde_roundtrip_all() {
    for s in SurfaceId::ALL {
        let json = serde_json::to_string(&s).unwrap();
        let back: SurfaceId = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back, "roundtrip failed for {s}");
    }
}

#[test]
fn surface_id_serde_snake_case_rename() {
    let json = serde_json::to_string(&SurfaceId::LabRuntime).unwrap();
    assert_eq!(json, "\"lab_runtime\"");
    let json = serde_json::to_string(&SurfaceId::SimScheduler).unwrap();
    assert_eq!(json, "\"sim_scheduler\"");
}

#[test]
fn surface_id_ordering() {
    // ALL is declared in deterministic order; verify Ord agrees
    for pair in SurfaceId::ALL.windows(2) {
        assert!(pair[0] < pair[1], "{} should be < {}", pair[0], pair[1]);
    }
}

// ---------------------------------------------------------------------------
// CapabilityId
// ---------------------------------------------------------------------------

#[test]
fn capability_id_display_not_empty() {
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
    assert_eq!(all.len(), 18, "expected 18 CapabilityId variants");
    for c in all {
        let s = format!("{c}");
        assert!(
            !s.is_empty(),
            "Display for CapabilityId should not be empty"
        );
    }
}

#[test]
fn capability_id_serde_roundtrip_all() {
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
    for c in all {
        let json = serde_json::to_string(&c).unwrap();
        let back: CapabilityId = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back, "serde roundtrip failed for CapabilityId: {json}");
    }
}

#[test]
fn capability_id_display_uses_serde_snake_case() {
    // CapabilityId::Display delegates to serde_json
    let json = serde_json::to_string(&CapabilityId::VirtualTime).unwrap();
    let display = format!("{}", CapabilityId::VirtualTime);
    // Display should equal the JSON value without quotes
    assert_eq!(format!("\"{}\"", display), json);
}

// ---------------------------------------------------------------------------
// CoverageLevel
// ---------------------------------------------------------------------------

#[test]
fn coverage_level_display() {
    assert_eq!(format!("{}", CoverageLevel::Covered), "covered");
    assert_eq!(format!("{}", CoverageLevel::Partial), "partial");
    assert_eq!(format!("{}", CoverageLevel::Missing), "missing");
    assert_eq!(format!("{}", CoverageLevel::LocalOnly), "local_only");
}

#[test]
fn coverage_level_serde_roundtrip() {
    for c in [
        CoverageLevel::Covered,
        CoverageLevel::Partial,
        CoverageLevel::Missing,
        CoverageLevel::LocalOnly,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let back: CoverageLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}

#[test]
fn coverage_level_ordering() {
    assert!(CoverageLevel::Covered < CoverageLevel::Partial);
    assert!(CoverageLevel::Partial < CoverageLevel::Missing);
    assert!(CoverageLevel::Missing < CoverageLevel::LocalOnly);
}

// ---------------------------------------------------------------------------
// MigrationDecision
// ---------------------------------------------------------------------------

#[test]
fn migration_decision_display() {
    assert_eq!(
        format!("{}", MigrationDecision::DirectAdoption),
        "direct_adoption"
    );
    assert_eq!(format!("{}", MigrationDecision::ThinBridge), "thin_bridge");
    assert_eq!(
        format!("{}", MigrationDecision::MaintainedWrapper),
        "maintained_wrapper"
    );
}

#[test]
fn migration_decision_serde_roundtrip() {
    for d in [
        MigrationDecision::DirectAdoption,
        MigrationDecision::ThinBridge,
        MigrationDecision::MaintainedWrapper,
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let back: MigrationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}

#[test]
fn migration_decision_ordering() {
    assert!(MigrationDecision::DirectAdoption < MigrationDecision::ThinBridge);
    assert!(MigrationDecision::ThinBridge < MigrationDecision::MaintainedWrapper);
}

// ---------------------------------------------------------------------------
// GapCell
// ---------------------------------------------------------------------------

#[test]
fn gap_cell_construction_and_fields() {
    let c = make_cell(
        SurfaceId::LabRuntime,
        CapabilityId::VirtualTime,
        CoverageLevel::Covered,
        "fully implemented",
    );
    assert_eq!(c.surface, SurfaceId::LabRuntime);
    assert_eq!(c.capability, CapabilityId::VirtualTime);
    assert_eq!(c.coverage, CoverageLevel::Covered);
    assert_eq!(c.notes, "fully implemented");
}

#[test]
fn gap_cell_display_format() {
    let c = make_cell(
        SurfaceId::ReleaseGate,
        CapabilityId::FailClosedGating,
        CoverageLevel::Partial,
        "half done",
    );
    let s = format!("{c}");
    assert!(s.contains("release_gate"), "should contain surface display");
    assert!(s.contains("partial"), "should contain coverage display");
    assert!(s.contains("half done"), "should contain notes");
    // Format is: surface x capability: coverage -- notes
    assert!(
        s.contains("\u{d7}") || s.contains("×"),
        "should contain multiplication sign"
    );
}

#[test]
fn gap_cell_serde_roundtrip() {
    let c = make_cell(
        SurfaceId::SimScheduler,
        CapabilityId::EventSimulation,
        CoverageLevel::LocalOnly,
        "unique to local",
    );
    let json = serde_json::to_string(&c).unwrap();
    let back: GapCell = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn gap_cell_serde_json_structure() {
    let c = make_cell(
        SurfaceId::LabRuntime,
        CapabilityId::VirtualTime,
        CoverageLevel::Covered,
        "test",
    );
    let val: serde_json::Value = serde_json::to_value(&c).unwrap();
    assert_eq!(val["surface"], "lab_runtime");
    assert_eq!(val["capability"], "virtual_time");
    assert_eq!(val["coverage"], "covered");
    assert_eq!(val["notes"], "test");
}

// ---------------------------------------------------------------------------
// SurfaceAssessment
// ---------------------------------------------------------------------------

#[test]
fn surface_assessment_build_counts_correctly() {
    let cells = vec![
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::VirtualTime,
            CoverageLevel::Covered,
            "",
        ),
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::FaultInjection,
            CoverageLevel::Partial,
            "",
        ),
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::RaceExploration,
            CoverageLevel::Missing,
            "",
        ),
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::TaskLifecycle,
            CoverageLevel::LocalOnly,
            "",
        ),
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::ScheduleReplay,
            CoverageLevel::Covered,
            "",
        ),
    ];
    let a = make_assessment(SurfaceId::LabRuntime, cells, MigrationDecision::ThinBridge);
    assert_eq!(a.covered_count, 2);
    assert_eq!(a.partial_count, 1);
    assert_eq!(a.missing_count, 1);
    assert_eq!(a.local_only_count, 1);
    assert_eq!(a.cells.len(), 5);
    assert_eq!(a.decision, MigrationDecision::ThinBridge);
}

#[test]
fn surface_assessment_coverage_rate_full() {
    let cells = vec![
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::VirtualTime,
            CoverageLevel::Covered,
            "",
        ),
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::TaskLifecycle,
            CoverageLevel::Covered,
            "",
        ),
    ];
    let a = make_assessment(
        SurfaceId::LabRuntime,
        cells,
        MigrationDecision::DirectAdoption,
    );
    assert_eq!(a.coverage_rate_millionths(), 1_000_000);
}

#[test]
fn surface_assessment_coverage_rate_partial_only() {
    // 2 partial, 0 covered, 0 missing -> (0 + 2*500_000) / 2 = 500_000
    let cells = vec![
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::VirtualTime,
            CoverageLevel::Partial,
            "",
        ),
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::TaskLifecycle,
            CoverageLevel::Partial,
            "",
        ),
    ];
    let a = make_assessment(SurfaceId::LabRuntime, cells, MigrationDecision::ThinBridge);
    assert_eq!(a.coverage_rate_millionths(), 500_000);
}

#[test]
fn surface_assessment_coverage_rate_mixed() {
    // 1 covered (1_000_000) + 1 partial (500_000) = 1_500_000 / 2 = 750_000
    let cells = vec![
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::VirtualTime,
            CoverageLevel::Covered,
            "",
        ),
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::TaskLifecycle,
            CoverageLevel::Partial,
            "",
        ),
    ];
    let a = make_assessment(SurfaceId::LabRuntime, cells, MigrationDecision::ThinBridge);
    assert_eq!(a.coverage_rate_millionths(), 750_000);
}

#[test]
fn surface_assessment_coverage_rate_all_missing() {
    // 0 covered, 0 partial, 3 missing -> 0 / 3 = 0
    let cells = vec![
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::VirtualTime,
            CoverageLevel::Missing,
            "",
        ),
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::TaskLifecycle,
            CoverageLevel::Missing,
            "",
        ),
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::FaultInjection,
            CoverageLevel::Missing,
            "",
        ),
    ];
    let a = make_assessment(SurfaceId::LabRuntime, cells, MigrationDecision::ThinBridge);
    assert_eq!(a.coverage_rate_millionths(), 0);
}

#[test]
fn surface_assessment_coverage_rate_empty_cells() {
    let a = make_assessment(
        SurfaceId::LabRuntime,
        vec![],
        MigrationDecision::DirectAdoption,
    );
    // Empty -> returns 1_000_000 (100%)
    assert_eq!(a.coverage_rate_millionths(), 1_000_000);
}

#[test]
fn surface_assessment_coverage_rate_local_only_excluded() {
    // LocalOnly is NOT included in coverage rate denominator
    // 1 covered + 1 local_only -> total = covered + partial + missing = 1, covered_equiv = 1_000_000
    let cells = vec![
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::VirtualTime,
            CoverageLevel::Covered,
            "",
        ),
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::TaskLifecycle,
            CoverageLevel::LocalOnly,
            "",
        ),
    ];
    let a = make_assessment(
        SurfaceId::LabRuntime,
        cells,
        MigrationDecision::MaintainedWrapper,
    );
    assert_eq!(a.coverage_rate_millionths(), 1_000_000);
}

#[test]
fn surface_assessment_display_format() {
    let a = make_assessment(
        SurfaceId::ReleaseGate,
        vec![],
        MigrationDecision::MaintainedWrapper,
    );
    let s = format!("{a}");
    assert!(s.contains("release_gate"));
    assert!(s.contains("maintained_wrapper"));
    assert!(s.contains("covered=0"));
}

#[test]
fn surface_assessment_serde_roundtrip() {
    let cells = vec![make_cell(
        SurfaceId::SimScheduler,
        CapabilityId::EventSimulation,
        CoverageLevel::Covered,
        "sim events",
    )];
    let a = make_assessment(
        SurfaceId::SimScheduler,
        cells,
        MigrationDecision::MaintainedWrapper,
    );
    let json = serde_json::to_string(&a).unwrap();
    let back: SurfaceAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

// ---------------------------------------------------------------------------
// GapMatrix
// ---------------------------------------------------------------------------

#[test]
fn gap_matrix_build_empty() {
    let m = GapMatrix::build(vec![]);
    assert_eq!(m.summary.total_surfaces, 0);
    assert_eq!(m.summary.total_cells, 0);
    assert_eq!(m.summary.direct_adoption_count, 0);
    assert_eq!(m.summary.thin_bridge_count, 0);
    assert_eq!(m.summary.maintained_wrapper_count, 0);
    assert!(!m.has_gaps());
    assert_eq!(m.schema_version, GAP_MATRIX_SCHEMA_VERSION);
}

#[test]
fn gap_matrix_for_surface_found() {
    let a = make_assessment(
        SurfaceId::LabRuntime,
        vec![],
        MigrationDecision::MaintainedWrapper,
    );
    let m = GapMatrix::build(vec![a]);
    let found = m.for_surface(SurfaceId::LabRuntime);
    assert!(found.is_some());
    assert_eq!(found.unwrap().surface, SurfaceId::LabRuntime);
}

#[test]
fn gap_matrix_for_surface_not_found() {
    let a = make_assessment(
        SurfaceId::LabRuntime,
        vec![],
        MigrationDecision::MaintainedWrapper,
    );
    let m = GapMatrix::build(vec![a]);
    assert!(m.for_surface(SurfaceId::ReleaseGate).is_none());
}

#[test]
fn gap_matrix_has_gaps_true() {
    let cells = vec![make_cell(
        SurfaceId::LabRuntime,
        CapabilityId::VirtualTime,
        CoverageLevel::Missing,
        "gap",
    )];
    let a = make_assessment(SurfaceId::LabRuntime, cells, MigrationDecision::ThinBridge);
    let m = GapMatrix::build(vec![a]);
    assert!(m.has_gaps());
}

#[test]
fn gap_matrix_has_gaps_false_when_all_covered() {
    let cells = vec![
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::VirtualTime,
            CoverageLevel::Covered,
            "",
        ),
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::TaskLifecycle,
            CoverageLevel::Partial,
            "",
        ),
    ];
    let a = make_assessment(SurfaceId::LabRuntime, cells, MigrationDecision::ThinBridge);
    let m = GapMatrix::build(vec![a]);
    assert!(!m.has_gaps());
}

#[test]
fn gap_matrix_surfaces_with_decision_direct_adoption() {
    let a1 = make_assessment(
        SurfaceId::LabRuntime,
        vec![],
        MigrationDecision::DirectAdoption,
    );
    let a2 = make_assessment(
        SurfaceId::ReleaseGate,
        vec![],
        MigrationDecision::ThinBridge,
    );
    let a3 = make_assessment(
        SurfaceId::SimScheduler,
        vec![],
        MigrationDecision::DirectAdoption,
    );
    let m = GapMatrix::build(vec![a1, a2, a3]);
    let direct = m.surfaces_with_decision(MigrationDecision::DirectAdoption);
    assert_eq!(direct.len(), 2);
    assert!(direct.contains(&SurfaceId::LabRuntime));
    assert!(direct.contains(&SurfaceId::SimScheduler));
}

#[test]
fn gap_matrix_surfaces_with_decision_empty_result() {
    let a = make_assessment(
        SurfaceId::LabRuntime,
        vec![],
        MigrationDecision::MaintainedWrapper,
    );
    let m = GapMatrix::build(vec![a]);
    let direct = m.surfaces_with_decision(MigrationDecision::DirectAdoption);
    assert!(direct.is_empty());
}

#[test]
fn gap_matrix_summary_decision_map() {
    let a1 = make_assessment(
        SurfaceId::LabRuntime,
        vec![],
        MigrationDecision::MaintainedWrapper,
    );
    let a2 = make_assessment(
        SurfaceId::ReleaseGate,
        vec![],
        MigrationDecision::ThinBridge,
    );
    let a3 = make_assessment(
        SurfaceId::SimScheduler,
        vec![],
        MigrationDecision::ThinBridge,
    );
    let m = GapMatrix::build(vec![a1, a2, a3]);
    assert_eq!(m.summary.decisions.get("maintained_wrapper"), Some(&1));
    assert_eq!(m.summary.decisions.get("thin_bridge"), Some(&2));
    assert_eq!(m.summary.decisions.get("direct_adoption"), Some(&0));
}

#[test]
fn gap_matrix_display_format() {
    let a = make_assessment(
        SurfaceId::LabRuntime,
        vec![],
        MigrationDecision::MaintainedWrapper,
    );
    let m = GapMatrix::build(vec![a]);
    let s = format!("{m}");
    assert!(s.contains("Frankenlab Surface Gap Matrix"));
    assert!(s.contains(GAP_MATRIX_SCHEMA_VERSION));
    assert!(s.contains("Surfaces: 1"));
}

#[test]
fn gap_matrix_serde_roundtrip() {
    let cells = vec![
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::VirtualTime,
            CoverageLevel::Covered,
            "ok",
        ),
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::FaultInjection,
            CoverageLevel::Missing,
            "gap",
        ),
    ];
    let a = make_assessment(SurfaceId::LabRuntime, cells, MigrationDecision::ThinBridge);
    let m = GapMatrix::build(vec![a]);
    let json = serde_json::to_string(&m).unwrap();
    let back: GapMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn gap_matrix_hash_deterministic() {
    let cells1 = vec![make_cell(
        SurfaceId::LabRuntime,
        CapabilityId::VirtualTime,
        CoverageLevel::Covered,
        "",
    )];
    let cells2 = vec![make_cell(
        SurfaceId::LabRuntime,
        CapabilityId::VirtualTime,
        CoverageLevel::Covered,
        "",
    )];
    let m1 = GapMatrix::build(vec![make_assessment(
        SurfaceId::LabRuntime,
        cells1,
        MigrationDecision::DirectAdoption,
    )]);
    let m2 = GapMatrix::build(vec![make_assessment(
        SurfaceId::LabRuntime,
        cells2,
        MigrationDecision::DirectAdoption,
    )]);
    assert_eq!(m1.matrix_hash, m2.matrix_hash);
}

#[test]
fn gap_matrix_hash_differs_for_different_content() {
    let cells1 = vec![make_cell(
        SurfaceId::LabRuntime,
        CapabilityId::VirtualTime,
        CoverageLevel::Covered,
        "",
    )];
    let cells2 = vec![make_cell(
        SurfaceId::LabRuntime,
        CapabilityId::VirtualTime,
        CoverageLevel::Missing,
        "",
    )];
    let m1 = GapMatrix::build(vec![make_assessment(
        SurfaceId::LabRuntime,
        cells1,
        MigrationDecision::DirectAdoption,
    )]);
    let m2 = GapMatrix::build(vec![make_assessment(
        SurfaceId::LabRuntime,
        cells2,
        MigrationDecision::DirectAdoption,
    )]);
    assert_ne!(m1.matrix_hash, m2.matrix_hash);
}

#[test]
fn gap_matrix_summary_cell_counts() {
    let cells = vec![
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::VirtualTime,
            CoverageLevel::Covered,
            "",
        ),
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::FaultInjection,
            CoverageLevel::Partial,
            "",
        ),
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::RaceExploration,
            CoverageLevel::Missing,
            "",
        ),
        make_cell(
            SurfaceId::LabRuntime,
            CapabilityId::TaskLifecycle,
            CoverageLevel::LocalOnly,
            "",
        ),
    ];
    let a = make_assessment(SurfaceId::LabRuntime, cells, MigrationDecision::ThinBridge);
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
        assert!(
            m.for_surface(s).is_some(),
            "canonical matrix missing surface: {s}"
        );
    }
}

#[test]
fn canonical_matrix_hash_determinism() {
    let m1 = build_canonical_gap_matrix();
    let m2 = build_canonical_gap_matrix();
    assert_eq!(m1.matrix_hash, m2.matrix_hash);
}

#[test]
fn canonical_matrix_decisions() {
    let m = build_canonical_gap_matrix();
    assert_eq!(m.summary.direct_adoption_count, 0);
    assert_eq!(m.summary.thin_bridge_count, 3);
    assert_eq!(m.summary.maintained_wrapper_count, 4);
}

#[test]
fn canonical_matrix_no_missing_cells() {
    let m = build_canonical_gap_matrix();
    assert_eq!(m.summary.missing_cells, 0);
    assert!(!m.has_gaps());
}

#[test]
fn canonical_matrix_has_partial_cells() {
    let m = build_canonical_gap_matrix();
    assert!(m.summary.partial_cells > 0);
}

#[test]
fn canonical_matrix_covered_cells_dominate() {
    let m = build_canonical_gap_matrix();
    assert!(m.summary.covered_cells > m.summary.partial_cells);
}

#[test]
fn canonical_matrix_total_cells_above_twenty() {
    let m = build_canonical_gap_matrix();
    assert!(m.summary.total_cells > 20);
}

#[test]
fn canonical_matrix_lab_runtime_maintained_wrapper() {
    let m = build_canonical_gap_matrix();
    let a = m.for_surface(SurfaceId::LabRuntime).unwrap();
    assert_eq!(a.decision, MigrationDecision::MaintainedWrapper);
}

#[test]
fn canonical_matrix_release_gate_thin_bridge() {
    let m = build_canonical_gap_matrix();
    let a = m.for_surface(SurfaceId::ReleaseGate).unwrap();
    assert_eq!(a.decision, MigrationDecision::ThinBridge);
}

#[test]
fn canonical_matrix_serde_roundtrip() {
    let m = build_canonical_gap_matrix();
    let json = serde_json::to_string(&m).unwrap();
    let back: GapMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn canonical_matrix_display_contains_surface_count() {
    let m = build_canonical_gap_matrix();
    let s = format!("{m}");
    assert!(s.contains("Surfaces: 7"));
}

#[test]
fn canonical_matrix_display_contains_matrix_hash() {
    let m = build_canonical_gap_matrix();
    let s = format!("{m}");
    assert!(s.contains("Matrix hash:"));
}

#[test]
fn canonical_matrix_surfaces_with_thin_bridge() {
    let m = build_canonical_gap_matrix();
    let bridges = m.surfaces_with_decision(MigrationDecision::ThinBridge);
    assert_eq!(bridges.len(), 3);
    assert!(bridges.contains(&SurfaceId::FrankenlabScenarios));
    assert!(bridges.contains(&SurfaceId::EvidenceReplayChecker));
    assert!(bridges.contains(&SurfaceId::ReleaseGate));
}

#[test]
fn canonical_matrix_surfaces_with_maintained_wrapper() {
    let m = build_canonical_gap_matrix();
    let wrappers = m.surfaces_with_decision(MigrationDecision::MaintainedWrapper);
    assert_eq!(wrappers.len(), 4);
    assert!(wrappers.contains(&SurfaceId::LabRuntime));
    assert!(wrappers.contains(&SurfaceId::InterleavingExplorer));
    assert!(wrappers.contains(&SurfaceId::DeterministicReplay));
    assert!(wrappers.contains(&SurfaceId::SimScheduler));
}

#[test]
fn canonical_matrix_no_direct_adoption() {
    let m = build_canonical_gap_matrix();
    let direct = m.surfaces_with_decision(MigrationDecision::DirectAdoption);
    assert!(direct.is_empty());
}

#[test]
fn canonical_matrix_lab_runtime_cells_not_empty() {
    let m = build_canonical_gap_matrix();
    let a = m.for_surface(SurfaceId::LabRuntime).unwrap();
    assert!(!a.cells.is_empty());
    assert!(a.covered_count > 0);
}

#[test]
fn canonical_matrix_all_assessments_have_rationale() {
    let m = build_canonical_gap_matrix();
    for a in &m.assessments {
        assert!(
            !a.rationale.is_empty(),
            "assessment for {} has empty rationale",
            a.surface
        );
    }
}
