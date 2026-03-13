//! Enrichment integration tests for react_compile_run_parity (bd-1lsy.3.6.3 [RGC-206C]).
//!
//! Deep coverage of Display uniqueness, serde roundtrips, method behavior,
//! edge cases, deterministic hash behavior, and cross-type interactions.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::react_compile_run_parity::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ep(raw: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(raw)
}

fn ch(tag: &[u8]) -> ContentHash {
    ContentHash::compute(tag)
}

fn art(
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
        content_hash: ch(tag),
        size_bytes: size,
        app_tier: tier,
    }
}

fn pass_cell(surface: Surface, workflow: WorkflowKind, tier: ExampleAppTier) -> MatrixCell {
    let a = art(
        ArtifactKind::CompiledOutput,
        surface,
        workflow,
        tier,
        500,
        b"eq",
    );
    MatrixCell {
        surface,
        workflow,
        app_tier: tier,
        artifacts_reference: vec![a.clone()],
        artifacts_candidate: vec![a],
        mismatches: vec![],
        verdict: CellVerdict::Pass,
    }
}

fn fail_cell(surface: Surface, workflow: WorkflowKind, tier: ExampleAppTier) -> MatrixCell {
    MatrixCell {
        surface,
        workflow,
        app_tier: tier,
        artifacts_reference: vec![art(
            ArtifactKind::CompiledOutput,
            surface,
            workflow,
            tier,
            500,
            b"ref-data",
        )],
        artifacts_candidate: vec![art(
            ArtifactKind::CompiledOutput,
            surface,
            workflow,
            tier,
            500,
            b"cand-data",
        )],
        mismatches: vec![ClassifiedMismatch {
            class: MismatchClass::ContentDivergence,
            severity: MismatchSeverity::Critical,
            surface,
            workflow,
            artifact_kind: ArtifactKind::CompiledOutput,
            detail: String::from("hash differs"),
            hash_a: Some(ch(b"ref-data")),
            hash_b: Some(ch(b"cand-data")),
        }],
        verdict: CellVerdict::Fail,
    }
}

fn relaxed_config() -> MatrixConfig {
    MatrixConfig {
        required_surfaces: BTreeSet::new(),
        required_workflows: BTreeSet::new(),
        max_size_divergence_millionths: DEFAULT_MAX_SIZE_DIVERGENCE,
        severity_threshold: MismatchSeverity::Major,
        require_source_maps: false,
        require_execution_traces: false,
        require_all_app_tiers: false,
    }
}

// ===========================================================================
// Display uniqueness: every variant in each enum has a unique Display string
// ===========================================================================

#[test]
fn enrichment_workflow_kind_display_all_unique() {
    let mut seen = BTreeSet::new();
    for v in WorkflowKind::all() {
        let s = format!("{v}");
        assert!(
            seen.insert(s.clone()),
            "duplicate display for WorkflowKind: {s}"
        );
    }
    assert_eq!(seen.len(), WorkflowKind::all().len());
}

#[test]
fn enrichment_surface_display_all_unique() {
    let mut seen = BTreeSet::new();
    for v in Surface::all() {
        let s = format!("{v}");
        assert!(seen.insert(s.clone()), "duplicate display for Surface: {s}");
    }
    assert_eq!(seen.len(), Surface::all().len());
}

#[test]
fn enrichment_artifact_kind_display_all_unique() {
    let mut seen = BTreeSet::new();
    for v in ArtifactKind::all() {
        let s = format!("{v}");
        assert!(
            seen.insert(s.clone()),
            "duplicate display for ArtifactKind: {s}"
        );
    }
    assert_eq!(seen.len(), ArtifactKind::all().len());
}

#[test]
fn enrichment_mismatch_class_display_all_unique() {
    let classes = [
        MismatchClass::Missing,
        MismatchClass::Extra,
        MismatchClass::ContentDivergence,
        MismatchClass::SizeDivergence,
        MismatchClass::OrderDivergence,
        MismatchClass::SemanticDivergence,
    ];
    let mut seen = BTreeSet::new();
    for v in &classes {
        let s = format!("{v}");
        assert!(
            seen.insert(s.clone()),
            "duplicate display for MismatchClass: {s}"
        );
    }
    assert_eq!(seen.len(), classes.len());
}

#[test]
fn enrichment_mismatch_severity_display_all_unique() {
    let sevs = [
        MismatchSeverity::Informational,
        MismatchSeverity::Minor,
        MismatchSeverity::Major,
        MismatchSeverity::Critical,
    ];
    let mut seen = BTreeSet::new();
    for v in &sevs {
        let s = format!("{v}");
        assert!(
            seen.insert(s.clone()),
            "duplicate display for MismatchSeverity: {s}"
        );
    }
    assert_eq!(seen.len(), sevs.len());
}

#[test]
fn enrichment_cell_verdict_display_all_unique() {
    let verdicts = [
        CellVerdict::Pass,
        CellVerdict::Fail,
        CellVerdict::Inconclusive,
    ];
    let mut seen = BTreeSet::new();
    for v in &verdicts {
        let s = format!("{v}");
        assert!(
            seen.insert(s.clone()),
            "duplicate display for CellVerdict: {s}"
        );
    }
    assert_eq!(seen.len(), verdicts.len());
}

#[test]
fn enrichment_example_app_tier_display_all_unique() {
    let mut seen = BTreeSet::new();
    for v in ExampleAppTier::all() {
        let s = format!("{v}");
        assert!(
            seen.insert(s.clone()),
            "duplicate display for ExampleAppTier: {s}"
        );
    }
    assert_eq!(seen.len(), ExampleAppTier::all().len());
}

// ===========================================================================
// Display equals as_str for all enum variants
// ===========================================================================

#[test]
fn enrichment_workflow_kind_display_matches_as_str() {
    for v in WorkflowKind::all() {
        assert_eq!(format!("{v}"), v.as_str());
    }
}

#[test]
fn enrichment_surface_display_matches_as_str() {
    for v in Surface::all() {
        assert_eq!(format!("{v}"), v.as_str());
    }
}

#[test]
fn enrichment_artifact_kind_display_matches_as_str() {
    for v in ArtifactKind::all() {
        assert_eq!(format!("{v}"), v.as_str());
    }
}

#[test]
fn enrichment_example_app_tier_display_matches_as_str() {
    for v in ExampleAppTier::all() {
        assert_eq!(format!("{v}"), v.as_str());
    }
}

// ===========================================================================
// Serde roundtrips for all individual enum variants
// ===========================================================================

#[test]
fn enrichment_serde_roundtrip_every_workflow_kind() {
    for v in WorkflowKind::all() {
        let json = serde_json::to_string(v).unwrap();
        let back: WorkflowKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
        // Serde rename_all = snake_case: JSON string should match as_str.
        let expected = format!("\"{}\"", v.as_str());
        assert_eq!(json, expected);
    }
}

#[test]
fn enrichment_serde_roundtrip_every_surface() {
    for v in Surface::all() {
        let json = serde_json::to_string(v).unwrap();
        let back: Surface = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
        let expected = format!("\"{}\"", v.as_str());
        assert_eq!(json, expected);
    }
}

#[test]
fn enrichment_serde_roundtrip_every_artifact_kind() {
    for v in ArtifactKind::all() {
        let json = serde_json::to_string(v).unwrap();
        let back: ArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_serde_roundtrip_every_mismatch_class() {
    let classes = [
        MismatchClass::Missing,
        MismatchClass::Extra,
        MismatchClass::ContentDivergence,
        MismatchClass::SizeDivergence,
        MismatchClass::OrderDivergence,
        MismatchClass::SemanticDivergence,
    ];
    for v in &classes {
        let json = serde_json::to_string(v).unwrap();
        let back: MismatchClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_serde_roundtrip_every_mismatch_severity() {
    let sevs = [
        MismatchSeverity::Informational,
        MismatchSeverity::Minor,
        MismatchSeverity::Major,
        MismatchSeverity::Critical,
    ];
    for v in &sevs {
        let json = serde_json::to_string(v).unwrap();
        let back: MismatchSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_serde_roundtrip_every_cell_verdict() {
    let verdicts = [
        CellVerdict::Pass,
        CellVerdict::Fail,
        CellVerdict::Inconclusive,
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: CellVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_serde_roundtrip_every_example_app_tier() {
    for v in ExampleAppTier::all() {
        let json = serde_json::to_string(v).unwrap();
        let back: ExampleAppTier = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_serde_roundtrip_matrix_cell() {
    let cell = pass_cell(
        Surface::FrankenctlCompile,
        WorkflowKind::SsrRender,
        ExampleAppTier::Complex,
    );
    let json = serde_json::to_string(&cell).unwrap();
    let back: MatrixCell = serde_json::from_str(&json).unwrap();
    assert_eq!(cell, back);
}

#[test]
fn enrichment_serde_roundtrip_classified_mismatch_both_hashes_none() {
    let mm = ClassifiedMismatch {
        class: MismatchClass::OrderDivergence,
        severity: MismatchSeverity::Informational,
        surface: Surface::ExampleApp,
        workflow: WorkflowKind::HydrationRound,
        artifact_kind: ArtifactKind::RenderOutput,
        detail: "order swapped".to_string(),
        hash_a: None,
        hash_b: None,
    };
    let json = serde_json::to_string(&mm).unwrap();
    let back: ClassifiedMismatch = serde_json::from_str(&json).unwrap();
    assert_eq!(mm, back);
}

#[test]
fn enrichment_serde_roundtrip_full_matrix_report() {
    let config = relaxed_config();
    let cells = vec![
        pass_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        ),
        fail_cell(
            Surface::ExampleApp,
            WorkflowKind::Execute,
            ExampleAppTier::Typical,
        ),
    ];
    let report = evaluate_parity_matrix(&config, &cells, ep(100));
    let json = serde_json::to_string(&report).unwrap();
    let back: MatrixReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_serde_roundtrip_config_with_required_sets() {
    let mut config = MatrixConfig::default();
    config.required_surfaces.insert(Surface::Library);
    config.required_surfaces.insert(Surface::FrankenctlRun);
    config.required_workflows.insert(WorkflowKind::Execute);
    config.require_all_app_tiers = true;
    let json = serde_json::to_string(&config).unwrap();
    let back: MatrixConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ===========================================================================
// Severity rank values
// ===========================================================================

#[test]
fn enrichment_severity_rank_exact_values() {
    assert_eq!(MismatchSeverity::Informational.rank(), 0);
    assert_eq!(MismatchSeverity::Minor.rank(), 1);
    assert_eq!(MismatchSeverity::Major.rank(), 2);
    assert_eq!(MismatchSeverity::Critical.rank(), 3);
}

// ===========================================================================
// severity_at_or_above exhaustive matrix
// ===========================================================================

#[test]
fn enrichment_severity_at_or_above_full_matrix() {
    let sevs = [
        MismatchSeverity::Informational,
        MismatchSeverity::Minor,
        MismatchSeverity::Major,
        MismatchSeverity::Critical,
    ];
    for (si, s) in sevs.iter().enumerate() {
        for (ti, t) in sevs.iter().enumerate() {
            let expected = si >= ti;
            assert_eq!(
                severity_at_or_above(s, t),
                expected,
                "severity_at_or_above({s}, {t}) should be {expected}"
            );
        }
    }
}

// ===========================================================================
// classify_mismatch edge cases
// ===========================================================================

#[test]
fn enrichment_classify_both_zero_size_same_hash_no_mismatch() {
    let a = art(
        ArtifactKind::Diagnostics,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        0,
        b"z",
    );
    let b = a.clone();
    assert!(classify_mismatch(&a, &b, DEFAULT_MAX_SIZE_DIVERGENCE).is_none());
}

#[test]
fn enrichment_classify_zero_vs_nonzero_size_different_hash() {
    let a = art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        0,
        b"aa",
    );
    let b = art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        100,
        b"bb",
    );
    let mm = classify_mismatch(&a, &b, DEFAULT_MAX_SIZE_DIVERGENCE);
    // Size diff is 100/100 = 100% which is > threshold. checked_div(0) for 0-max case would return None.
    // max_size = 100, divergence = 100 * 1_000_000 / 100 = 1_000_000 > 200_000 => Critical
    assert!(mm.is_some());
}

#[test]
fn enrichment_classify_same_hash_different_size_within_tolerance() {
    // Same content hash, sizes differ by 3% (within 5% threshold).
    let a = art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"same",
    );
    let b = CapturedArtifact {
        kind: ArtifactKind::CompiledOutput,
        surface: Surface::Library,
        workflow: WorkflowKind::CompileOnly,
        content_hash: ch(b"same"),
        size_bytes: 1030,
        app_tier: ExampleAppTier::Minimal,
    };
    // Hash matches but size differs. classify_mismatch checks hash == hash AND size == size first.
    // Since size differs, it proceeds. Then size divergence = 30 * 1_000_000 / 1030 = 29_126 < 50_000.
    // Content hashes are the same, so the final branch returns None.
    let mm = classify_mismatch(&a, &b, DEFAULT_MAX_SIZE_DIVERGENCE);
    assert!(mm.is_none());
}

#[test]
fn enrichment_classify_same_hash_different_size_exceeds_tolerance() {
    // Same content hash, sizes differ by 8% (above 5% threshold).
    let a = art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"same",
    );
    let b = CapturedArtifact {
        kind: ArtifactKind::CompiledOutput,
        surface: Surface::Library,
        workflow: WorkflowKind::CompileOnly,
        content_hash: ch(b"same"),
        size_bytes: 1100,
        app_tier: ExampleAppTier::Minimal,
    };
    // divergence = 100 * 1_000_000 / 1100 = 90_909 > 50_000, but <= 100_000 => Minor
    let mm = classify_mismatch(&a, &b, DEFAULT_MAX_SIZE_DIVERGENCE);
    assert!(mm.is_some());
    let m = mm.unwrap();
    assert_eq!(m.class, MismatchClass::SizeDivergence);
    assert_eq!(m.severity, MismatchSeverity::Minor);
}

#[test]
fn enrichment_classify_size_divergence_boundary_at_threshold() {
    // Exactly at threshold should NOT be classified as divergence (> not >=).
    let a = art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1_000_000,
        b"aa",
    );
    let b = art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        950_000,
        b"bb",
    );
    // divergence = 50_000 * 1_000_000 / 1_000_000 = 50_000 which equals threshold (not >) => no size divergence mismatch
    // But content hashes differ => ContentDivergence
    let mm = classify_mismatch(&a, &b, 50_000);
    assert!(mm.is_some());
    let m = mm.unwrap();
    assert_eq!(m.class, MismatchClass::ContentDivergence);
}

#[test]
fn enrichment_classify_size_divergence_just_above_threshold() {
    let a = art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1_000_000,
        b"xx",
    );
    let b = art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        949_000,
        b"yy",
    );
    // divergence = 51_000 * 1_000_000 / 1_000_000 = 51_000 > 50_000 => SizeDivergence
    let mm = classify_mismatch(&a, &b, 50_000);
    assert!(mm.is_some());
    let m = mm.unwrap();
    assert_eq!(m.class, MismatchClass::SizeDivergence);
    assert_eq!(m.severity, MismatchSeverity::Minor);
}

#[test]
fn enrichment_classify_mismatch_populates_hashes() {
    let a = art(
        ArtifactKind::SourceMap,
        Surface::FrankenctlCompile,
        WorkflowKind::Execute,
        ExampleAppTier::Typical,
        200,
        b"alpha",
    );
    let b = art(
        ArtifactKind::SourceMap,
        Surface::FrankenctlCompile,
        WorkflowKind::Execute,
        ExampleAppTier::Typical,
        200,
        b"beta",
    );
    let mm = classify_mismatch(&a, &b, DEFAULT_MAX_SIZE_DIVERGENCE).unwrap();
    assert_eq!(mm.hash_a, Some(ch(b"alpha")));
    assert_eq!(mm.hash_b, Some(ch(b"beta")));
}

#[test]
fn enrichment_classify_mismatch_preserves_surface_and_workflow() {
    let a = art(
        ArtifactKind::RenderOutput,
        Surface::ExampleApp,
        WorkflowKind::StreamingRender,
        ExampleAppTier::HybridIsomorphic,
        300,
        b"p",
    );
    let b = art(
        ArtifactKind::RenderOutput,
        Surface::ExampleApp,
        WorkflowKind::StreamingRender,
        ExampleAppTier::HybridIsomorphic,
        300,
        b"q",
    );
    let mm = classify_mismatch(&a, &b, DEFAULT_MAX_SIZE_DIVERGENCE).unwrap();
    assert_eq!(mm.surface, Surface::ExampleApp);
    assert_eq!(mm.workflow, WorkflowKind::StreamingRender);
    assert_eq!(mm.artifact_kind, ArtifactKind::RenderOutput);
}

#[test]
fn enrichment_classify_size_divergence_minor_boundary() {
    // Between 5% and 10%: Minor
    let a = art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"c1",
    );
    let b = art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        900,
        b"c2",
    );
    // divergence = 100 * 1_000_000 / 1000 = 100_000, which equals 10%. Code checks > 100_000 for Major.
    // 100_000 is NOT > 100_000, so this should be Minor.
    let mm = classify_mismatch(&a, &b, 50_000).unwrap();
    assert_eq!(mm.class, MismatchClass::SizeDivergence);
    assert_eq!(mm.severity, MismatchSeverity::Minor);
}

#[test]
fn enrichment_classify_size_divergence_major_boundary() {
    // Between 10% and 20%: Major
    let a = art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"d1",
    );
    let b = art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        800,
        b"d2",
    );
    // divergence = 200 * 1_000_000 / 1000 = 200_000. Code checks > 200_000 for Critical.
    // 200_000 is NOT > 200_000, so this should be Major.
    let mm = classify_mismatch(&a, &b, 50_000).unwrap();
    assert_eq!(mm.class, MismatchClass::SizeDivergence);
    assert_eq!(mm.severity, MismatchSeverity::Major);
}

#[test]
fn enrichment_classify_size_divergence_critical_boundary() {
    // Above 20%: Critical
    let a = art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        1000,
        b"e1",
    );
    let b = art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        790,
        b"e2",
    );
    // divergence = 210 * 1_000_000 / 1000 = 210_000 > 200_000 => Critical
    let mm = classify_mismatch(&a, &b, 50_000).unwrap();
    assert_eq!(mm.class, MismatchClass::SizeDivergence);
    assert_eq!(mm.severity, MismatchSeverity::Critical);
}

// ===========================================================================
// evaluate_cell edge cases
// ===========================================================================

#[test]
fn enrichment_evaluate_cell_multiple_kinds_matched_by_kind() {
    let config = relaxed_config();
    let ref_arts = vec![
        art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            100,
            b"co",
        ),
        art(
            ArtifactKind::SourceMap,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            50,
            b"sm",
        ),
        art(
            ArtifactKind::Diagnostics,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            30,
            b"dg",
        ),
    ];
    let cand_arts = vec![
        art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            100,
            b"co",
        ),
        art(
            ArtifactKind::SourceMap,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            50,
            b"sm",
        ),
        art(
            ArtifactKind::Diagnostics,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            30,
            b"dg",
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
    assert_eq!(cell.verdict, CellVerdict::Pass);
    assert!(cell.mismatches.is_empty());
    assert_eq!(cell.artifacts_reference.len(), 3);
    assert_eq!(cell.artifacts_candidate.len(), 3);
}

#[test]
fn enrichment_evaluate_cell_missing_reports_critical() {
    let config = relaxed_config();
    let ref_arts = vec![
        art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            100,
            b"co",
        ),
        art(
            ArtifactKind::ModuleGraph,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            80,
            b"mg",
        ),
    ];
    let cand_arts = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        100,
        b"co",
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
    let missing = cell
        .mismatches
        .iter()
        .find(|m| m.class == MismatchClass::Missing)
        .unwrap();
    assert_eq!(missing.severity, MismatchSeverity::Critical);
    assert_eq!(missing.artifact_kind, ArtifactKind::ModuleGraph);
    assert!(missing.hash_a.is_some());
    assert!(missing.hash_b.is_none());
}

#[test]
fn enrichment_evaluate_cell_extra_reports_minor() {
    let config = relaxed_config();
    let ref_arts = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        100,
        b"co",
    )];
    let cand_arts = vec![
        art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            100,
            b"co",
        ),
        art(
            ArtifactKind::Diagnostics,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            40,
            b"diag",
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
    // Extra is Minor, threshold is Major => Pass
    assert_eq!(cell.verdict, CellVerdict::Pass);
    let extra = cell
        .mismatches
        .iter()
        .find(|m| m.class == MismatchClass::Extra)
        .unwrap();
    assert_eq!(extra.severity, MismatchSeverity::Minor);
    assert!(extra.hash_a.is_none());
    assert!(extra.hash_b.is_some());
}

#[test]
fn enrichment_evaluate_cell_source_map_required_ref_has_cand_missing() {
    let mut config = relaxed_config();
    config.require_source_maps = true;
    let ref_arts = vec![
        art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            100,
            b"co",
        ),
        art(
            ArtifactKind::SourceMap,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            50,
            b"sm",
        ),
    ];
    let cand_arts = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        100,
        b"co",
    )];
    let cell = evaluate_cell(
        &ref_arts,
        &cand_arts,
        &config,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    );
    // SourceMap in ref but not cand => Missing (Critical) from matching logic
    assert_eq!(cell.verdict, CellVerdict::Fail);
    assert!(
        cell.mismatches.iter().any(
            |m| m.artifact_kind == ArtifactKind::SourceMap && m.class == MismatchClass::Missing
        )
    );
}

#[test]
fn enrichment_evaluate_cell_source_map_absent_both_sides_major() {
    let mut config = relaxed_config();
    config.require_source_maps = true;
    let ref_arts = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        100,
        b"co",
    )];
    let cand_arts = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        100,
        b"co",
    )];
    let cell = evaluate_cell(
        &ref_arts,
        &cand_arts,
        &config,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    );
    // Source maps required but absent from both => Major mismatch => Fail
    assert_eq!(cell.verdict, CellVerdict::Fail);
    let sm_missing = cell
        .mismatches
        .iter()
        .find(|m| m.artifact_kind == ArtifactKind::SourceMap && m.class == MismatchClass::Missing);
    assert!(sm_missing.is_some());
    assert_eq!(sm_missing.unwrap().severity, MismatchSeverity::Major);
}

#[test]
fn enrichment_evaluate_cell_execution_trace_required_for_hydration() {
    let config = MatrixConfig {
        require_execution_traces: true,
        require_source_maps: false,
        ..relaxed_config()
    };
    let ref_arts = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::HydrationRound,
        ExampleAppTier::Minimal,
        100,
        b"co",
    )];
    let cand_arts = ref_arts.clone();
    let cell = evaluate_cell(
        &ref_arts,
        &cand_arts,
        &config,
        Surface::Library,
        WorkflowKind::HydrationRound,
        ExampleAppTier::Minimal,
    );
    // HydrationRound requires execution trace; absent from both => Major
    assert!(
        cell.mismatches
            .iter()
            .any(|m| m.artifact_kind == ArtifactKind::ExecutionTrace)
    );
}

#[test]
fn enrichment_evaluate_cell_execution_trace_required_for_streaming() {
    let config = MatrixConfig {
        require_execution_traces: true,
        require_source_maps: false,
        ..relaxed_config()
    };
    let ref_arts = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::StreamingRender,
        ExampleAppTier::Minimal,
        100,
        b"co",
    )];
    let cand_arts = ref_arts.clone();
    let cell = evaluate_cell(
        &ref_arts,
        &cand_arts,
        &config,
        Surface::Library,
        WorkflowKind::StreamingRender,
        ExampleAppTier::Minimal,
    );
    assert!(
        cell.mismatches
            .iter()
            .any(|m| m.artifact_kind == ArtifactKind::ExecutionTrace)
    );
}

#[test]
fn enrichment_evaluate_cell_execution_trace_not_required_for_static_generation() {
    let config = MatrixConfig {
        require_execution_traces: true,
        require_source_maps: false,
        ..relaxed_config()
    };
    let ref_arts = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::StaticGeneration,
        ExampleAppTier::Minimal,
        100,
        b"co",
    )];
    let cand_arts = ref_arts.clone();
    let cell = evaluate_cell(
        &ref_arts,
        &cand_arts,
        &config,
        Surface::Library,
        WorkflowKind::StaticGeneration,
        ExampleAppTier::Minimal,
    );
    // StaticGeneration is NOT in the list requiring execution traces
    assert!(
        !cell
            .mismatches
            .iter()
            .any(|m| m.artifact_kind == ArtifactKind::ExecutionTrace)
    );
    assert_eq!(cell.verdict, CellVerdict::Pass);
}

#[test]
fn enrichment_evaluate_cell_severity_threshold_minor_fails_on_extra() {
    let config = MatrixConfig {
        severity_threshold: MismatchSeverity::Minor,
        require_source_maps: false,
        require_execution_traces: false,
        ..relaxed_config()
    };
    let cand_arts = vec![art(
        ArtifactKind::Diagnostics,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        40,
        b"diag",
    )];
    let cell = evaluate_cell(
        &[],
        &cand_arts,
        &config,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    );
    // Extra = Minor, threshold = Minor => at_or_above => Fail
    assert_eq!(cell.verdict, CellVerdict::Fail);
}

// ===========================================================================
// compute_coverage edge cases
// ===========================================================================

#[test]
fn enrichment_coverage_single_cell_partial_fractions() {
    let config = relaxed_config();
    let cells = vec![pass_cell(
        Surface::Library,
        WorkflowKind::Execute,
        ExampleAppTier::Complex,
    )];
    let cov = compute_coverage(&cells, &config);
    // Surface: 1/4 = 250_000
    let lib_cov = cov
        .surface_coverage
        .iter()
        .find(|(s, _)| *s == Surface::Library)
        .unwrap()
        .1;
    assert_eq!(lib_cov, 1_000_000);
    let fc_cov = cov
        .surface_coverage
        .iter()
        .find(|(s, _)| *s == Surface::FrankenctlCompile)
        .unwrap()
        .1;
    assert_eq!(fc_cov, 0);
    // Workflow: 1/6
    let exec_cov = cov
        .workflow_coverage
        .iter()
        .find(|(w, _)| *w == WorkflowKind::Execute)
        .unwrap()
        .1;
    assert_eq!(exec_cov, 1_000_000);
    // Tier: 1/5
    let complex_cov = cov
        .app_tier_coverage
        .iter()
        .find(|(t, _)| *t == ExampleAppTier::Complex)
        .unwrap()
        .1;
    assert_eq!(complex_cov, 1_000_000);
    // Overall = average of 250_000 + 166_666 + 200_000 = 205_555
    assert!(cov.overall_coverage_millionths > 0);
    assert!(cov.overall_coverage_millionths < 1_000_000);
}

#[test]
fn enrichment_coverage_full_matrix_all_million() {
    let config = relaxed_config();
    let mut cells = Vec::new();
    for s in Surface::all() {
        for w in WorkflowKind::all() {
            for t in ExampleAppTier::all() {
                cells.push(pass_cell(*s, *w, *t));
            }
        }
    }
    let cov = compute_coverage(&cells, &config);
    assert_eq!(cov.overall_coverage_millionths, 1_000_000);
    for (_, v) in &cov.surface_coverage {
        assert_eq!(*v, 1_000_000);
    }
    for (_, v) in &cov.workflow_coverage {
        assert_eq!(*v, 1_000_000);
    }
    for (_, v) in &cov.app_tier_coverage {
        assert_eq!(*v, 1_000_000);
    }
}

#[test]
fn enrichment_coverage_dimensions_length_matches_all() {
    let config = relaxed_config();
    let cells = vec![pass_cell(
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    )];
    let cov = compute_coverage(&cells, &config);
    assert_eq!(cov.surface_coverage.len(), Surface::all().len());
    assert_eq!(cov.workflow_coverage.len(), WorkflowKind::all().len());
    assert_eq!(cov.app_tier_coverage.len(), ExampleAppTier::all().len());
}

// ===========================================================================
// derive_overall_verdict edge cases
// ===========================================================================

#[test]
fn enrichment_overall_verdict_required_surfaces_met_pass() {
    let mut config = relaxed_config();
    config.required_surfaces.insert(Surface::Library);
    config.required_surfaces.insert(Surface::ExampleApp);
    let cells = vec![
        pass_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        ),
        pass_cell(
            Surface::ExampleApp,
            WorkflowKind::Execute,
            ExampleAppTier::Typical,
        ),
    ];
    assert_eq!(derive_overall_verdict(&cells, &config), CellVerdict::Pass);
}

#[test]
fn enrichment_overall_verdict_required_surfaces_not_met_fail() {
    let mut config = relaxed_config();
    config.required_surfaces.insert(Surface::Library);
    config.required_surfaces.insert(Surface::FrankenctlCompile);
    let cells = vec![pass_cell(
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    )];
    assert_eq!(derive_overall_verdict(&cells, &config), CellVerdict::Fail);
}

#[test]
fn enrichment_overall_verdict_required_workflows_met_pass() {
    let mut config = relaxed_config();
    config.required_workflows.insert(WorkflowKind::CompileOnly);
    config.required_workflows.insert(WorkflowKind::Execute);
    let cells = vec![
        pass_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        ),
        pass_cell(
            Surface::Library,
            WorkflowKind::Execute,
            ExampleAppTier::Typical,
        ),
    ];
    assert_eq!(derive_overall_verdict(&cells, &config), CellVerdict::Pass);
}

#[test]
fn enrichment_overall_verdict_required_workflows_not_met_fail() {
    let mut config = relaxed_config();
    config.required_workflows.insert(WorkflowKind::SsrRender);
    let cells = vec![pass_cell(
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    )];
    assert_eq!(derive_overall_verdict(&cells, &config), CellVerdict::Fail);
}

#[test]
fn enrichment_overall_verdict_require_all_app_tiers_met() {
    let mut config = relaxed_config();
    config.require_all_app_tiers = true;
    let cells: Vec<MatrixCell> = ExampleAppTier::all()
        .iter()
        .map(|t| pass_cell(Surface::Library, WorkflowKind::CompileOnly, *t))
        .collect();
    assert_eq!(derive_overall_verdict(&cells, &config), CellVerdict::Pass);
}

#[test]
fn enrichment_overall_verdict_require_all_app_tiers_missing_one() {
    let mut config = relaxed_config();
    config.require_all_app_tiers = true;
    // Skip HybridIsomorphic
    let tiers = [
        ExampleAppTier::Minimal,
        ExampleAppTier::Typical,
        ExampleAppTier::Complex,
        ExampleAppTier::SsrFocused,
    ];
    let cells: Vec<MatrixCell> = tiers
        .iter()
        .map(|t| pass_cell(Surface::Library, WorkflowKind::CompileOnly, *t))
        .collect();
    assert_eq!(derive_overall_verdict(&cells, &config), CellVerdict::Fail);
}

#[test]
fn enrichment_overall_verdict_mix_pass_and_inconclusive() {
    let config = relaxed_config();
    let cells = vec![
        pass_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        ),
        MatrixCell {
            surface: Surface::ExampleApp,
            workflow: WorkflowKind::Execute,
            app_tier: ExampleAppTier::Typical,
            artifacts_reference: vec![],
            artifacts_candidate: vec![],
            mismatches: vec![],
            verdict: CellVerdict::Inconclusive,
        },
    ];
    assert_eq!(
        derive_overall_verdict(&cells, &config),
        CellVerdict::Inconclusive
    );
}

#[test]
fn enrichment_overall_verdict_fail_overrides_everything() {
    let mut config = relaxed_config();
    config.require_all_app_tiers = true;
    let mut cells: Vec<MatrixCell> = ExampleAppTier::all()
        .iter()
        .map(|t| pass_cell(Surface::Library, WorkflowKind::CompileOnly, *t))
        .collect();
    // Inject one failing cell
    cells.push(fail_cell(
        Surface::FrankenctlRun,
        WorkflowKind::Execute,
        ExampleAppTier::Complex,
    ));
    assert_eq!(derive_overall_verdict(&cells, &config), CellVerdict::Fail);
}

// ===========================================================================
// compute_receipt determinism and field correctness
// ===========================================================================

#[test]
fn enrichment_receipt_deterministic_same_inputs() {
    let ih = ch(b"determinism-test");
    let r1 = compute_receipt(ih, &CellVerdict::Pass, ep(77));
    let r2 = compute_receipt(ih, &CellVerdict::Pass, ep(77));
    assert_eq!(r1, r2);
}

#[test]
fn enrichment_receipt_varies_with_input_hash() {
    let r1 = compute_receipt(ch(b"input-a"), &CellVerdict::Pass, ep(1));
    let r2 = compute_receipt(ch(b"input-b"), &CellVerdict::Pass, ep(1));
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn enrichment_receipt_varies_with_epoch() {
    let ih = ch(b"same-input");
    let r1 = compute_receipt(ih, &CellVerdict::Pass, ep(10));
    let r2 = compute_receipt(ih, &CellVerdict::Pass, ep(11));
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
    assert_eq!(r1.epoch, ep(10));
    assert_eq!(r2.epoch, ep(11));
}

#[test]
fn enrichment_receipt_varies_with_verdict() {
    let ih = ch(b"same-input");
    let rp = compute_receipt(ih, &CellVerdict::Pass, ep(5));
    let rf = compute_receipt(ih, &CellVerdict::Fail, ep(5));
    let ri = compute_receipt(ih, &CellVerdict::Inconclusive, ep(5));
    assert_ne!(rp.verdict_hash, rf.verdict_hash);
    assert_ne!(rp.verdict_hash, ri.verdict_hash);
    assert_ne!(rf.verdict_hash, ri.verdict_hash);
}

#[test]
fn enrichment_receipt_timestamp_is_zero() {
    let r = compute_receipt(ch(b"ts"), &CellVerdict::Pass, ep(1));
    assert_eq!(r.timestamp_micros, 0);
}

#[test]
fn enrichment_receipt_field_values() {
    let r = compute_receipt(ch(b"fv"), &CellVerdict::Fail, ep(42));
    assert_eq!(r.schema_version, SCHEMA_VERSION);
    assert_eq!(r.component, COMPONENT);
    assert_eq!(r.bead_id, BEAD_ID);
    assert_eq!(r.policy_id, POLICY_ID);
    assert_eq!(r.epoch, ep(42));
    assert_eq!(r.input_hash, ch(b"fv"));
}

// ===========================================================================
// evaluate_parity_matrix: mismatch accounting
// ===========================================================================

#[test]
fn enrichment_matrix_counts_informational_not_counted() {
    let config = relaxed_config();
    let mut cell = pass_cell(
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    );
    cell.mismatches.push(ClassifiedMismatch {
        class: MismatchClass::OrderDivergence,
        severity: MismatchSeverity::Informational,
        surface: Surface::Library,
        workflow: WorkflowKind::CompileOnly,
        artifact_kind: ArtifactKind::CompiledOutput,
        detail: "cosmetic".to_string(),
        hash_a: None,
        hash_b: None,
    });
    let report = evaluate_parity_matrix(&config, &[cell], ep(1));
    assert_eq!(report.total_mismatches, 1);
    // Informational is not counted in critical/major/minor
    assert_eq!(report.critical_count, 0);
    assert_eq!(report.major_count, 0);
    assert_eq!(report.minor_count, 0);
}

#[test]
fn enrichment_matrix_counts_all_severity_levels() {
    let config = relaxed_config();
    let mut cell = pass_cell(
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    );
    cell.verdict = CellVerdict::Fail;
    cell.mismatches.push(ClassifiedMismatch {
        class: MismatchClass::Missing,
        severity: MismatchSeverity::Critical,
        surface: Surface::Library,
        workflow: WorkflowKind::CompileOnly,
        artifact_kind: ArtifactKind::CompiledOutput,
        detail: "crit".into(),
        hash_a: None,
        hash_b: None,
    });
    cell.mismatches.push(ClassifiedMismatch {
        class: MismatchClass::SizeDivergence,
        severity: MismatchSeverity::Major,
        surface: Surface::Library,
        workflow: WorkflowKind::CompileOnly,
        artifact_kind: ArtifactKind::SourceMap,
        detail: "maj".into(),
        hash_a: None,
        hash_b: None,
    });
    cell.mismatches.push(ClassifiedMismatch {
        class: MismatchClass::Extra,
        severity: MismatchSeverity::Minor,
        surface: Surface::Library,
        workflow: WorkflowKind::CompileOnly,
        artifact_kind: ArtifactKind::Diagnostics,
        detail: "min".into(),
        hash_a: None,
        hash_b: None,
    });
    cell.mismatches.push(ClassifiedMismatch {
        class: MismatchClass::OrderDivergence,
        severity: MismatchSeverity::Informational,
        surface: Surface::Library,
        workflow: WorkflowKind::CompileOnly,
        artifact_kind: ArtifactKind::ModuleGraph,
        detail: "info".into(),
        hash_a: None,
        hash_b: None,
    });
    let report = evaluate_parity_matrix(&config, &[cell], ep(2));
    assert_eq!(report.total_mismatches, 4);
    assert_eq!(report.critical_count, 1);
    assert_eq!(report.major_count, 1);
    assert_eq!(report.minor_count, 1);
}

#[test]
fn enrichment_matrix_multi_cell_aggregation() {
    let config = relaxed_config();
    let mut c1 = pass_cell(
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    );
    c1.verdict = CellVerdict::Fail;
    c1.mismatches.push(ClassifiedMismatch {
        class: MismatchClass::Missing,
        severity: MismatchSeverity::Critical,
        surface: Surface::Library,
        workflow: WorkflowKind::CompileOnly,
        artifact_kind: ArtifactKind::CompiledOutput,
        detail: "m1".into(),
        hash_a: None,
        hash_b: None,
    });
    let mut c2 = pass_cell(
        Surface::ExampleApp,
        WorkflowKind::Execute,
        ExampleAppTier::Typical,
    );
    c2.mismatches.push(ClassifiedMismatch {
        class: MismatchClass::Extra,
        severity: MismatchSeverity::Minor,
        surface: Surface::ExampleApp,
        workflow: WorkflowKind::Execute,
        artifact_kind: ArtifactKind::Diagnostics,
        detail: "m2".into(),
        hash_a: None,
        hash_b: None,
    });
    let report = evaluate_parity_matrix(&config, &[c1, c2], ep(3));
    assert_eq!(report.total_mismatches, 2);
    assert_eq!(report.critical_count, 1);
    assert_eq!(report.minor_count, 1);
}

// ===========================================================================
// evaluate_parity_matrix: receipt integration
// ===========================================================================

#[test]
fn enrichment_matrix_receipt_epoch_propagates() {
    let config = relaxed_config();
    let cells = vec![pass_cell(
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    )];
    let report = evaluate_parity_matrix(&config, &cells, ep(999));
    assert_eq!(report.receipt.epoch, ep(999));
}

#[test]
fn enrichment_matrix_report_deterministic_across_invocations() {
    let config = relaxed_config();
    let cells = vec![
        pass_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        ),
        fail_cell(
            Surface::FrankenctlRun,
            WorkflowKind::Execute,
            ExampleAppTier::Complex,
        ),
    ];
    let r1 = evaluate_parity_matrix(&config, &cells, ep(50));
    let r2 = evaluate_parity_matrix(&config, &cells, ep(50));
    assert_eq!(r1.receipt.verdict_hash, r2.receipt.verdict_hash);
    assert_eq!(r1.receipt.input_hash, r2.receipt.input_hash);
    assert_eq!(r1.overall_verdict, r2.overall_verdict);
    assert_eq!(r1.total_mismatches, r2.total_mismatches);
}

#[test]
fn enrichment_matrix_different_configs_different_input_hash() {
    let mut config_a = relaxed_config();
    config_a.max_size_divergence_millionths = 10_000;
    let mut config_b = relaxed_config();
    config_b.max_size_divergence_millionths = 20_000;
    let cells = vec![pass_cell(
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
    )];
    let r1 = evaluate_parity_matrix(&config_a, &cells, ep(1));
    let r2 = evaluate_parity_matrix(&config_b, &cells, ep(1));
    // Different config.max_size_divergence_millionths is hashed into input_hash
    assert_ne!(r1.receipt.input_hash, r2.receipt.input_hash);
}

// ===========================================================================
// Constants validation
// ===========================================================================

#[test]
fn enrichment_constants_schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("react-compile-run-parity"));
    assert!(SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn enrichment_constants_component_matches_module_name() {
    assert_eq!(COMPONENT, "react_compile_run_parity");
}

#[test]
fn enrichment_constants_bead_and_policy_nonempty() {
    assert!(!BEAD_ID.is_empty());
    assert!(!POLICY_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(POLICY_ID.starts_with("RGC-"));
}

#[test]
fn enrichment_default_max_size_divergence_value() {
    assert_eq!(DEFAULT_MAX_SIZE_DIVERGENCE, 50_000);
}

// ===========================================================================
// MatrixConfig default validation
// ===========================================================================

#[test]
fn enrichment_matrix_config_default_empty_required_sets() {
    let config = MatrixConfig::default();
    assert!(config.required_surfaces.is_empty());
    assert!(config.required_workflows.is_empty());
}

#[test]
fn enrichment_matrix_config_default_boolean_flags() {
    let config = MatrixConfig::default();
    assert!(config.require_source_maps);
    assert!(config.require_execution_traces);
    assert!(!config.require_all_app_tiers);
}

// ===========================================================================
// Content hash determinism across classify_mismatch
// ===========================================================================

#[test]
fn enrichment_content_hash_deterministic_for_classify() {
    let a1 = art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        100,
        b"det",
    );
    let a2 = art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        WorkflowKind::CompileOnly,
        ExampleAppTier::Minimal,
        100,
        b"det",
    );
    assert!(classify_mismatch(&a1, &a2, DEFAULT_MAX_SIZE_DIVERGENCE).is_none());
}

#[test]
fn enrichment_content_hash_different_data_always_mismatches() {
    // Verify that different byte inputs always produce different hashes
    let h1 = ch(b"alpha");
    let h2 = ch(b"bravo");
    let h3 = ch(b"charlie");
    assert_ne!(h1, h2);
    assert_ne!(h2, h3);
    assert_ne!(h1, h3);
}

// ===========================================================================
// Enum ordering (Ord trait) used in BTreeSet
// ===========================================================================

#[test]
fn enrichment_surface_ord_usable_in_btreeset() {
    let mut set = BTreeSet::new();
    for s in Surface::all() {
        set.insert(*s);
    }
    assert_eq!(set.len(), Surface::all().len());
}

#[test]
fn enrichment_workflow_kind_ord_usable_in_btreeset() {
    let mut set = BTreeSet::new();
    for w in WorkflowKind::all() {
        set.insert(*w);
    }
    assert_eq!(set.len(), WorkflowKind::all().len());
}

#[test]
fn enrichment_example_app_tier_ord_usable_in_btreeset() {
    let mut set = BTreeSet::new();
    for t in ExampleAppTier::all() {
        set.insert(*t);
    }
    assert_eq!(set.len(), ExampleAppTier::all().len());
}

#[test]
fn enrichment_mismatch_severity_ord_ascending() {
    let mut sevs = [
        MismatchSeverity::Critical,
        MismatchSeverity::Informational,
        MismatchSeverity::Major,
        MismatchSeverity::Minor,
    ];
    sevs.sort();
    // Verify sorted order corresponds to rank() order
    for window in sevs.windows(2) {
        assert!(window[0].rank() <= window[1].rank());
    }
}

// ===========================================================================
// Large-scale matrix report
// ===========================================================================

#[test]
fn enrichment_matrix_report_coverage_included() {
    let config = relaxed_config();
    let cells = vec![
        pass_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        ),
        pass_cell(
            Surface::FrankenctlCompile,
            WorkflowKind::Execute,
            ExampleAppTier::Typical,
        ),
        pass_cell(
            Surface::FrankenctlRun,
            WorkflowKind::SsrRender,
            ExampleAppTier::Complex,
        ),
    ];
    let report = evaluate_parity_matrix(&config, &cells, ep(7));
    assert_eq!(report.coverage.surface_coverage.len(), Surface::all().len());
    assert_eq!(
        report.coverage.workflow_coverage.len(),
        WorkflowKind::all().len()
    );
    assert!(report.coverage.overall_coverage_millionths > 0);
}

#[test]
fn enrichment_matrix_all_surfaces_all_workflows_all_tiers_full_pass() {
    let config = relaxed_config();
    let mut cells = Vec::new();
    for s in Surface::all() {
        for w in WorkflowKind::all() {
            for t in ExampleAppTier::all() {
                cells.push(pass_cell(*s, *w, *t));
            }
        }
    }
    let report = evaluate_parity_matrix(&config, &cells, ep(1));
    assert_eq!(report.overall_verdict, CellVerdict::Pass);
    assert_eq!(report.total_mismatches, 0);
    assert_eq!(report.coverage.overall_coverage_millionths, 1_000_000);
    assert_eq!(report.cells.len(), 4 * 6 * 5); // 120 cells
}
