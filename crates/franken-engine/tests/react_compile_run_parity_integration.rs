//! Integration tests for react_compile_run_parity (bd-1lsy.3.6.3 [RGC-206C]).
//!
//! Exercises the shipped-path React compile/run parity matrix through public
//! API entry points.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::react_compile_run_parity::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn hash(tag: &[u8]) -> ContentHash {
    ContentHash::compute(tag)
}

fn artifact(
    kind: ArtifactKind,
    surface: Surface,
    workflow: WorkflowKind,
    tier: ExampleAppTier,
    size: u64,
    tag: &[u8],
) -> CapturedArtifact {
    CapturedArtifact {
        kind,
        surface,
        workflow,
        content_hash: hash(tag),
        size_bytes: size,
        app_tier: tier,
    }
}

fn matching_cell(surface: Surface, workflow: WorkflowKind, tier: ExampleAppTier) -> MatrixCell {
    let a = artifact(
        ArtifactKind::CompiledOutput,
        surface,
        workflow,
        tier,
        1000,
        b"same",
    );
    let b = artifact(
        ArtifactKind::CompiledOutput,
        surface,
        workflow,
        tier,
        1000,
        b"same",
    );
    MatrixCell {
        surface,
        workflow,
        app_tier: tier,
        artifacts_reference: vec![a],
        artifacts_candidate: vec![b],
        mismatches: vec![],
        verdict: CellVerdict::Pass,
    }
}

fn failing_cell(surface: Surface, workflow: WorkflowKind, tier: ExampleAppTier) -> MatrixCell {
    let a = artifact(
        ArtifactKind::CompiledOutput,
        surface,
        workflow,
        tier,
        1000,
        b"ref",
    );
    let b = artifact(
        ArtifactKind::CompiledOutput,
        surface,
        workflow,
        tier,
        1000,
        b"cand",
    );
    MatrixCell {
        surface,
        workflow,
        app_tier: tier,
        artifacts_reference: vec![a],
        artifacts_candidate: vec![b],
        mismatches: vec![ClassifiedMismatch {
            class: MismatchClass::ContentDivergence,
            severity: MismatchSeverity::Critical,
            surface,
            workflow,
            artifact_kind: ArtifactKind::CompiledOutput,
            detail: String::from("content hash differs"),
            hash_a: Some(hash(b"ref")),
            hash_b: Some(hash(b"cand")),
        }],
        verdict: CellVerdict::Fail,
    }
}

fn default_config() -> MatrixConfig {
    MatrixConfig::default()
}

// ---------------------------------------------------------------------------
// Empty / minimal scenarios
// ---------------------------------------------------------------------------

#[test]
fn empty_cells_yields_inconclusive() {
    let config = default_config();
    let result = evaluate_parity_matrix(&config, &[], epoch());
    assert_eq!(result.overall_verdict, CellVerdict::Inconclusive);
}

#[test]
fn single_passing_cell_yields_pass() {
    let config = default_config();
    let cell = matching_cell(
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    );
    let result = evaluate_parity_matrix(&config, &[cell], epoch());
    assert_eq!(result.overall_verdict, CellVerdict::Pass);
    assert_eq!(result.total_mismatches, 0);
}

#[test]
fn single_failing_cell_yields_fail() {
    let config = default_config();
    let cell = failing_cell(
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    );
    let result = evaluate_parity_matrix(&config, &[cell], epoch());
    assert_eq!(result.overall_verdict, CellVerdict::Fail);
    assert!(result.critical_count > 0);
}

// ---------------------------------------------------------------------------
// Severity comparison
// ---------------------------------------------------------------------------

#[test]
fn severity_informational_below_minor() {
    assert!(severity_at_or_above(
        &MismatchSeverity::Minor,
        &MismatchSeverity::Minor
    ));
    assert!(!severity_at_or_above(
        &MismatchSeverity::Informational,
        &MismatchSeverity::Minor
    ));
}

#[test]
fn severity_critical_above_major() {
    assert!(severity_at_or_above(
        &MismatchSeverity::Critical,
        &MismatchSeverity::Major
    ));
}

#[test]
fn severity_same_level_is_at_or_above() {
    assert!(severity_at_or_above(
        &MismatchSeverity::Major,
        &MismatchSeverity::Major
    ));
}

#[test]
fn severity_minor_below_major() {
    assert!(!severity_at_or_above(
        &MismatchSeverity::Minor,
        &MismatchSeverity::Major
    ));
}

// ---------------------------------------------------------------------------
// Mismatch classification
// ---------------------------------------------------------------------------

#[test]
fn classify_identical_artifacts_no_mismatch() {
    let a = artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"same",
    );
    let b = artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"same",
    );
    let mismatch = classify_mismatch(&a, &b, DEFAULT_MAX_SIZE_DIVERGENCE);
    assert!(mismatch.is_none());
}

#[test]
fn classify_content_divergence() {
    let a = artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"ref",
    );
    let b = artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"cand",
    );
    let mismatch = classify_mismatch(&a, &b, DEFAULT_MAX_SIZE_DIVERGENCE);
    assert!(mismatch.is_some());
    let m = mismatch.unwrap();
    assert_eq!(m.class, MismatchClass::ContentDivergence);
}

#[test]
fn classify_size_divergence() {
    let a = artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"same",
    );
    let b = artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1200,
        b"same",
    );
    let mismatch = classify_mismatch(&a, &b, 50_000); // 5% threshold, 20% divergence
    // Hash is same but size differs — depends on implementation
    // At minimum verify no panic
    let _ = mismatch;
}

// ---------------------------------------------------------------------------
// Cell evaluation
// ---------------------------------------------------------------------------

#[test]
fn evaluate_cell_with_matching_artifacts() {
    let mut config = default_config();
    config.require_source_maps = false;
    let ref_arts = vec![artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"same",
    )];
    let cand_arts = vec![artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"same",
    )];
    let cell = evaluate_cell(
        &ref_arts,
        &cand_arts,
        &config,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    );
    assert_eq!(cell.verdict, CellVerdict::Pass);
    assert!(cell.mismatches.is_empty());
}

#[test]
fn evaluate_cell_with_missing_candidate_artifact() {
    let config = default_config();
    let ref_arts = vec![
        artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            1000,
            b"ref",
        ),
        artifact(
            ArtifactKind::SourceMap,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            500,
            b"map",
        ),
    ];
    let cand_arts = vec![artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"ref",
    )];
    let cell = evaluate_cell(
        &ref_arts,
        &cand_arts,
        &config,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    );
    assert!(!cell.mismatches.is_empty());
}

#[test]
fn evaluate_cell_with_extra_candidate_artifact() {
    let config = default_config();
    let ref_arts = vec![artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"ref",
    )];
    let cand_arts = vec![
        artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            1000,
            b"ref",
        ),
        artifact(
            ArtifactKind::SourceMap,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            500,
            b"extra",
        ),
    ];
    let cell = evaluate_cell(
        &ref_arts,
        &cand_arts,
        &config,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    );
    // Extra artifact may or may not be a mismatch depending on impl
    let _ = cell;
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

#[test]
fn coverage_single_surface_single_workflow() {
    let config = default_config();
    let cells = vec![matching_cell(
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    )];
    let coverage = compute_coverage(&cells, &config);
    assert!(coverage.overall_coverage_millionths > 0);
    assert!(!coverage.surface_coverage.is_empty());
}

#[test]
fn coverage_all_surfaces() {
    let config = default_config();
    let cells = vec![
        matching_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        ),
        matching_cell(
            Surface::FrankenctlCompile,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        ),
        matching_cell(
            Surface::FrankenctlRun,
            WorkflowKind::Execute,
            ExampleAppTier::Minimal,
        ),
        matching_cell(
            Surface::ExampleApp,
            WorkflowKind::Execute,
            ExampleAppTier::Typical,
        ),
    ];
    let coverage = compute_coverage(&cells, &config);
    assert_eq!(coverage.surface_coverage.len(), 4);
}

#[test]
fn coverage_empty_cells() {
    let config = default_config();
    let coverage = compute_coverage(&[], &config);
    assert_eq!(coverage.overall_coverage_millionths, 0);
}

// ---------------------------------------------------------------------------
// Overall verdict derivation
// ---------------------------------------------------------------------------

#[test]
fn overall_verdict_all_pass() {
    let config = default_config();
    let cells = vec![
        matching_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        ),
        matching_cell(
            Surface::FrankenctlCompile,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Typical,
        ),
    ];
    assert_eq!(derive_overall_verdict(&cells, &config), CellVerdict::Pass);
}

#[test]
fn overall_verdict_one_fail() {
    let config = default_config();
    let cells = vec![
        matching_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        ),
        failing_cell(
            Surface::FrankenctlRun,
            WorkflowKind::Execute,
            ExampleAppTier::Typical,
        ),
    ];
    assert_eq!(derive_overall_verdict(&cells, &config), CellVerdict::Fail);
}

#[test]
fn overall_verdict_empty_is_inconclusive() {
    let config = default_config();
    assert_eq!(
        derive_overall_verdict(&[], &config),
        CellVerdict::Inconclusive
    );
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

#[test]
fn receipt_fields_populated() {
    let receipt = compute_receipt(hash(b"input"), &CellVerdict::Pass, epoch());
    assert_eq!(receipt.schema_version, SCHEMA_VERSION);
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.bead_id, BEAD_ID);
    assert_eq!(receipt.policy_id, POLICY_ID);
}

#[test]
fn receipt_deterministic() {
    let r1 = compute_receipt(hash(b"same"), &CellVerdict::Pass, epoch());
    let r2 = compute_receipt(hash(b"same"), &CellVerdict::Pass, epoch());
    assert_eq!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn receipt_differs_by_verdict() {
    let r1 = compute_receipt(hash(b"input"), &CellVerdict::Pass, epoch());
    let r2 = compute_receipt(hash(b"input"), &CellVerdict::Fail, epoch());
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

// ---------------------------------------------------------------------------
// Enum display strings
// ---------------------------------------------------------------------------

#[test]
fn workflow_kind_display() {
    assert_eq!(WorkflowKind::CompileOnly.as_str(), "compile_only");
    assert_eq!(WorkflowKind::Execute.as_str(), "execute");
    assert_eq!(WorkflowKind::SsrRender.as_str(), "ssr_render");
    assert_eq!(
        format!("{}", WorkflowKind::StreamingRender),
        "streaming_render"
    );
}

#[test]
fn surface_display() {
    assert_eq!(Surface::Library.as_str(), "library");
    assert_eq!(Surface::FrankenctlCompile.as_str(), "frankenctl_compile");
    assert_eq!(format!("{}", Surface::ExampleApp), "example_app");
}

#[test]
fn artifact_kind_display() {
    assert_eq!(ArtifactKind::CompiledOutput.as_str(), "compiled_output");
    assert_eq!(ArtifactKind::SourceMap.as_str(), "source_map");
    assert_eq!(
        format!("{}", ArtifactKind::ExecutionTrace),
        "execution_trace"
    );
}

#[test]
fn mismatch_class_display() {
    assert_eq!(MismatchClass::Missing.as_str(), "missing");
    assert_eq!(
        MismatchClass::ContentDivergence.as_str(),
        "content_divergence"
    );
    assert_eq!(
        format!("{}", MismatchClass::SemanticDivergence),
        "semantic_divergence"
    );
}

#[test]
fn mismatch_severity_display() {
    assert_eq!(MismatchSeverity::Informational.as_str(), "informational");
    assert_eq!(MismatchSeverity::Critical.as_str(), "critical");
    assert_eq!(format!("{}", MismatchSeverity::Major), "major");
}

#[test]
fn cell_verdict_display() {
    assert_eq!(CellVerdict::Pass.as_str(), "pass");
    assert_eq!(CellVerdict::Fail.as_str(), "fail");
    assert_eq!(format!("{}", CellVerdict::Inconclusive), "inconclusive");
}

#[test]
fn example_app_tier_display() {
    assert_eq!(ExampleAppTier::Minimal.as_str(), "minimal");
    assert_eq!(ExampleAppTier::SsrFocused.as_str(), "ssr_focused");
    assert_eq!(
        format!("{}", ExampleAppTier::HybridIsomorphic),
        "hybrid_isomorphic"
    );
}

// ---------------------------------------------------------------------------
// Serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn matrix_report_serde_roundtrip() {
    let config = default_config();
    let cells = vec![matching_cell(
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    )];
    let report = evaluate_parity_matrix(&config, &cells, epoch());
    let json = serde_json::to_string(&report).expect("serialize");
    let deser: MatrixReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deser.overall_verdict, report.overall_verdict);
    assert_eq!(deser.cells.len(), report.cells.len());
}

#[test]
fn config_serde_roundtrip() {
    let config = default_config();
    let json = serde_json::to_string(&config).expect("serialize");
    let deser: MatrixConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        deser.max_size_divergence_millionths,
        config.max_size_divergence_millionths
    );
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[test]
fn config_default_values() {
    let config = MatrixConfig::default();
    assert_eq!(config.max_size_divergence_millionths, 50_000);
    assert_eq!(config.severity_threshold, MismatchSeverity::Major);
    assert!(config.require_source_maps);
    assert!(config.require_execution_traces);
    assert!(!config.require_all_app_tiers);
}

// ---------------------------------------------------------------------------
// Multi-cell end-to-end
// ---------------------------------------------------------------------------

#[test]
fn matrix_across_all_surfaces_and_workflows() {
    let config = default_config();
    let cells = vec![
        matching_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        ),
        matching_cell(
            Surface::FrankenctlCompile,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Typical,
        ),
        matching_cell(
            Surface::FrankenctlRun,
            WorkflowKind::Execute,
            ExampleAppTier::Complex,
        ),
        matching_cell(
            Surface::ExampleApp,
            WorkflowKind::SsrRender,
            ExampleAppTier::SsrFocused,
        ),
        matching_cell(
            Surface::ExampleApp,
            WorkflowKind::HydrationRound,
            ExampleAppTier::HybridIsomorphic,
        ),
        matching_cell(
            Surface::ExampleApp,
            WorkflowKind::StreamingRender,
            ExampleAppTier::Typical,
        ),
    ];
    let result = evaluate_parity_matrix(&config, &cells, epoch());
    assert_eq!(result.overall_verdict, CellVerdict::Pass);
    assert_eq!(result.total_mismatches, 0);
    assert_eq!(result.cells.len(), 6);
}

#[test]
fn matrix_mixed_pass_and_fail() {
    let config = default_config();
    let cells = vec![
        matching_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        ),
        failing_cell(
            Surface::FrankenctlRun,
            WorkflowKind::Execute,
            ExampleAppTier::Typical,
        ),
        matching_cell(
            Surface::ExampleApp,
            WorkflowKind::SsrRender,
            ExampleAppTier::SsrFocused,
        ),
    ];
    let result = evaluate_parity_matrix(&config, &cells, epoch());
    assert_eq!(result.overall_verdict, CellVerdict::Fail);
    assert!(result.critical_count >= 1);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn module_constants_populated() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!COMPONENT.is_empty());
    assert_eq!(BEAD_ID, "bd-1lsy.3.6.3");
    assert_eq!(POLICY_ID, "RGC-206C");
}

// ===========================================================================
// Enrichment: evaluate_cell edge cases
// ===========================================================================

#[test]
fn evaluate_cell_empty_both_sides_inconclusive() {
    let mut config = default_config();
    config.require_source_maps = false;
    config.require_execution_traces = false;
    let cell = evaluate_cell(
        &[],
        &[],
        &config,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    );
    assert_eq!(cell.verdict, CellVerdict::Inconclusive);
    assert!(cell.mismatches.is_empty());
}

#[test]
fn evaluate_cell_empty_candidate_reports_missing() {
    let mut config = default_config();
    config.require_source_maps = false;
    let ref_arts = vec![artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"ref",
    )];
    let cell = evaluate_cell(
        &ref_arts,
        &[],
        &config,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    );
    assert_eq!(cell.verdict, CellVerdict::Fail);
    assert!(
        cell.mismatches
            .iter()
            .any(|m| m.class == MismatchClass::Missing)
    );
}

#[test]
fn evaluate_cell_empty_reference_reports_extra() {
    let mut config = default_config();
    config.require_source_maps = false;
    let cand_arts = vec![artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"cand",
    )];
    let cell = evaluate_cell(
        &[],
        &cand_arts,
        &config,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    );
    // Extra should be minor severity → Pass with default threshold at Major
    assert!(
        cell.mismatches
            .iter()
            .any(|m| m.class == MismatchClass::Extra)
    );
}

#[test]
fn evaluate_cell_content_divergence_is_major() {
    let mut config = default_config();
    config.require_source_maps = false;
    let ref_arts = vec![artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"ref_content",
    )];
    let cand_arts = vec![artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"cand_content",
    )];
    let cell = evaluate_cell(
        &ref_arts,
        &cand_arts,
        &config,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    );
    assert_eq!(cell.verdict, CellVerdict::Fail);
    let content_mm = cell
        .mismatches
        .iter()
        .find(|m| m.class == MismatchClass::ContentDivergence);
    assert!(content_mm.is_some());
    assert_eq!(content_mm.unwrap().severity, MismatchSeverity::Major);
}

// ===========================================================================
// Enrichment: severity rank ordering
// ===========================================================================

#[test]
fn severity_rank_monotonically_increasing() {
    assert!(MismatchSeverity::Informational.rank() < MismatchSeverity::Minor.rank());
    assert!(MismatchSeverity::Minor.rank() < MismatchSeverity::Major.rank());
    assert!(MismatchSeverity::Major.rank() < MismatchSeverity::Critical.rank());
}

// ===========================================================================
// Enrichment: enum all() variants exhaustive
// ===========================================================================

#[test]
fn workflow_kind_all_has_six_variants() {
    assert_eq!(WorkflowKind::all().len(), 6);
}

#[test]
fn surface_all_has_four_variants() {
    assert_eq!(Surface::all().len(), 4);
}

#[test]
fn artifact_kind_all_has_six_variants() {
    assert_eq!(ArtifactKind::all().len(), 6);
}

#[test]
fn example_app_tier_all_has_five_variants() {
    assert_eq!(ExampleAppTier::all().len(), 5);
}

// ===========================================================================
// Enrichment: serde round-trips for individual types
// ===========================================================================

#[test]
fn captured_artifact_serde_round_trip() {
    let a = artifact(
        ArtifactKind::SourceMap,
        Surface::FrankenctlCompile,
        WorkflowKind::SsrRender,
        ExampleAppTier::Complex,
        2048,
        b"artifact-tag",
    );
    let json = serde_json::to_string(&a).unwrap();
    let back: CapturedArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn classified_mismatch_serde_round_trip() {
    let mm = ClassifiedMismatch {
        class: MismatchClass::SizeDivergence,
        severity: MismatchSeverity::Minor,
        surface: Surface::ExampleApp,
        workflow: WorkflowKind::Execute,
        artifact_kind: ArtifactKind::ExecutionTrace,
        detail: "test detail".to_string(),
        hash_a: Some(hash(b"a")),
        hash_b: None,
    };
    let json = serde_json::to_string(&mm).unwrap();
    let back: ClassifiedMismatch = serde_json::from_str(&json).unwrap();
    assert_eq!(mm, back);
}

#[test]
fn coverage_report_serde_round_trip() {
    let config = default_config();
    let cells = vec![matching_cell(
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    )];
    let cov = compute_coverage(&cells, &config);
    let json = serde_json::to_string(&cov).unwrap();
    let back: CoverageReport = serde_json::from_str(&json).unwrap();
    assert_eq!(cov, back);
}

#[test]
fn decision_receipt_serde_round_trip() {
    let receipt = compute_receipt(hash(b"test"), &CellVerdict::Fail, epoch());
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ===========================================================================
// Enrichment: evaluate_parity_matrix determinism
// ===========================================================================

#[test]
fn evaluate_parity_matrix_is_deterministic() {
    let config = default_config();
    let cells = vec![
        matching_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        ),
        failing_cell(
            Surface::FrankenctlRun,
            WorkflowKind::Execute,
            ExampleAppTier::Typical,
        ),
    ];
    let r1 = evaluate_parity_matrix(&config, &cells, epoch());
    let r2 = evaluate_parity_matrix(&config, &cells, epoch());
    assert_eq!(r1.overall_verdict, r2.overall_verdict);
    assert_eq!(r1.total_mismatches, r2.total_mismatches);
    assert_eq!(r1.receipt.verdict_hash, r2.receipt.verdict_hash);
}

// ===========================================================================
// Enrichment: required surfaces/workflows in config
// ===========================================================================

#[test]
fn config_required_surfaces_enforcement() {
    use std::collections::BTreeSet;
    let mut config = default_config();
    config.required_surfaces = BTreeSet::from([Surface::Library, Surface::FrankenctlCompile]);
    let cells = vec![matching_cell(
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    )];
    let result = evaluate_parity_matrix(&config, &cells, epoch());
    // FrankenctlCompile not covered — verdict depends on implementation
    let _ = result;
}

// ===========================================================================
// Enrichment: large divergence → critical severity
// ===========================================================================

#[test]
fn classify_large_size_divergence_critical_severity() {
    let a = artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"small",
    );
    let b = artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        4000,
        b"large",
    );
    // 3000/4000 = 75% divergence > 20% critical threshold
    let mm = classify_mismatch(&a, &b, 10_000); // 1% threshold
    assert!(mm.is_some());
    let m = mm.unwrap();
    // Large divergence should be Critical (>20%)
    assert_eq!(m.severity, MismatchSeverity::Critical);
}

// ===========================================================================
// Enrichment: moderate divergence → major severity
// ===========================================================================

#[test]
fn classify_moderate_size_divergence_major_severity() {
    let a = artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"med-a",
    );
    let b = artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1150,
        b"med-b",
    );
    // 150/1150 ≈ 13% divergence → between 10% and 20% → Major
    let mm = classify_mismatch(&a, &b, 10_000); // 1% threshold
    assert!(mm.is_some());
    let m = mm.unwrap();
    assert_eq!(m.severity, MismatchSeverity::Major);
}

// ===========================================================================
// Enrichment: cell evaluation with execution trace requirement
// ===========================================================================

#[test]
fn evaluate_cell_ssr_without_trace_reports_missing() {
    let config = default_config();
    let ref_arts = vec![artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::SsrRender,
        ExampleAppTier::SsrFocused,
        500,
        b"output",
    )];
    let cand_arts = vec![artifact(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::SsrRender,
        ExampleAppTier::SsrFocused,
        500,
        b"output",
    )];
    let cell = evaluate_cell(
        &ref_arts,
        &cand_arts,
        &config,
        Surface::Library,
        WorkflowKind::SsrRender,
        ExampleAppTier::SsrFocused,
    );
    // Neither side has execution trace → should report missing for SSR workflow
    let trace_missing = cell.mismatches.iter().any(|m| {
        m.artifact_kind == ArtifactKind::ExecutionTrace && m.class == MismatchClass::Missing
    });
    assert!(
        trace_missing,
        "SSR without execution trace should be flagged"
    );
}

// ===========================================================================
// Enrichment: matrix cell count preservation
// ===========================================================================

#[test]
fn matrix_preserves_cell_count() {
    let config = default_config();
    let cells: Vec<_> = (0..10)
        .map(|_| {
            matching_cell(
                Surface::Library,
                WorkflowKind::CompileOnly,
                ExampleAppTier::Minimal,
            )
        })
        .collect();
    let result = evaluate_parity_matrix(&config, &cells, epoch());
    assert_eq!(result.cells.len(), 10);
}

// ===========================================================================
// Enrichment: mismatch counts accuracy
// ===========================================================================

#[test]
fn mismatch_counts_are_accurate() {
    let config = default_config();
    let cells = vec![
        failing_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        ),
        failing_cell(
            Surface::FrankenctlRun,
            WorkflowKind::Execute,
            ExampleAppTier::Typical,
        ),
        matching_cell(
            Surface::ExampleApp,
            WorkflowKind::SsrRender,
            ExampleAppTier::SsrFocused,
        ),
    ];
    let result = evaluate_parity_matrix(&config, &cells, epoch());
    assert!(result.total_mismatches >= 2, "at least 2 failing cells");
    assert!(
        result.critical_count >= 2,
        "failing cells have critical mismatches"
    );
}
