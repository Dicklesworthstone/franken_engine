//! Integration tests for hole_witness_generator — RGC-809B (bd-1lsy.9.9.2)
//!
//! Validates witness generation across surfaces, configurations, analysis
//! helpers, serde roundtrips, and end-to-end coverage pipelines.

use std::collections::BTreeSet;

use frankenengine_engine::hole_witness_generator::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hole(id: &str, surface: HoleSurface, persistence: u64) -> HoleReference {
    HoleReference {
        hole_id: id.to_string(),
        dimension: 1,
        persistence_millionths: persistence,
        surface,
        representative_cycle: vec!["s0".into(), "s1".into()],
        affected_programs: vec!["prog_a".into()],
    }
}

fn cfg() -> GeneratorConfig {
    GeneratorConfig::default()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn integration_schema_version() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("hole-witness"));
}

#[test]
fn integration_bead_id() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn integration_component_nonempty() {
    assert!(!COMPONENT.is_empty());
}

#[test]
fn integration_policy_id() {
    assert!(POLICY_ID.starts_with("RGC-"));
}

// ---------------------------------------------------------------------------
// WitnessProgramKind
// ---------------------------------------------------------------------------

#[test]
fn all_kinds_display_nonempty() {
    let kinds = [
        WitnessProgramKind::JavaScript,
        WitnessProgramKind::TypeScript,
        WitnessProgramKind::PackageManifest,
        WitnessProgramKind::ReactApp,
        WitnessProgramKind::ModuleResolution,
        WitnessProgramKind::AsyncGenerator,
    ];
    for k in &kinds {
        assert!(!format!("{k}").is_empty());
    }
}

#[test]
fn kind_serde_all_variants() {
    let kinds = [
        WitnessProgramKind::JavaScript,
        WitnessProgramKind::TypeScript,
        WitnessProgramKind::PackageManifest,
        WitnessProgramKind::ReactApp,
        WitnessProgramKind::ModuleResolution,
        WitnessProgramKind::AsyncGenerator,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let back: WitnessProgramKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// HoleSurface
// ---------------------------------------------------------------------------

#[test]
fn all_surfaces_display_nonempty() {
    let surfaces = [
        HoleSurface::Parser,
        HoleSurface::Lowering,
        HoleSurface::Runtime,
        HoleSurface::Module,
        HoleSurface::TypeScript,
        HoleSurface::React,
        HoleSurface::RegExp,
        HoleSurface::Stdlib,
        HoleSurface::Interop,
    ];
    for s in &surfaces {
        assert!(!format!("{s}").is_empty());
    }
}

#[test]
fn surface_serde_all_variants() {
    let surfaces = [
        HoleSurface::Parser,
        HoleSurface::Lowering,
        HoleSurface::Runtime,
        HoleSurface::Module,
        HoleSurface::TypeScript,
        HoleSurface::React,
        HoleSurface::RegExp,
        HoleSurface::Stdlib,
        HoleSurface::Interop,
    ];
    for s in &surfaces {
        let json = serde_json::to_string(s).unwrap();
        let back: HoleSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// HoleReference
// ---------------------------------------------------------------------------

#[test]
fn hole_ref_hash_varies_by_persistence() {
    let h1 = hole("h", HoleSurface::Parser, 100_000);
    let h2 = hole("h", HoleSurface::Parser, 200_000);
    assert_ne!(h1.content_hash(), h2.content_hash());
}

#[test]
fn hole_ref_hash_varies_by_surface() {
    let h1 = hole("h", HoleSurface::Parser, 100_000);
    let h2 = hole("h", HoleSurface::Runtime, 100_000);
    assert_ne!(h1.content_hash(), h2.content_hash());
}

#[test]
fn hole_ref_hash_varies_by_cycle() {
    let mut h1 = hole("h", HoleSurface::Parser, 100_000);
    let mut h2 = hole("h", HoleSurface::Parser, 100_000);
    h2.representative_cycle.push("s2".into());
    assert_ne!(h1.content_hash(), h2.content_hash());
    h1.representative_cycle.push("s2".into());
    assert_eq!(h1.content_hash(), h2.content_hash());
}

#[test]
fn hole_ref_serde_full_roundtrip() {
    let h = HoleReference {
        hole_id: "deep".into(),
        dimension: 3,
        persistence_millionths: 999_999,
        surface: HoleSurface::TypeScript,
        representative_cycle: vec!["a".into(), "b".into(), "c".into()],
        affected_programs: vec!["p1".into(), "p2".into()],
    };
    let json = serde_json::to_string(&h).unwrap();
    let back: HoleReference = serde_json::from_str(&json).unwrap();
    assert_eq!(h, back);
}

// ---------------------------------------------------------------------------
// WitnessSourceFile
// ---------------------------------------------------------------------------

#[test]
fn source_file_newlines_counted() {
    let f = WitnessSourceFile::new("x.ts", "a\nb\nc\nd");
    assert_eq!(f.line_count, 4);
}

#[test]
fn source_file_hash_varies_by_path() {
    let f1 = WitnessSourceFile::new("a.js", "x");
    let f2 = WitnessSourceFile::new("b.js", "x");
    assert_ne!(f1.content_hash(), f2.content_hash());
}

#[test]
fn source_file_hash_varies_by_content() {
    let f1 = WitnessSourceFile::new("a.js", "x");
    let f2 = WitnessSourceFile::new("a.js", "y");
    assert_ne!(f1.content_hash(), f2.content_hash());
}

// ---------------------------------------------------------------------------
// WitnessProgram
// ---------------------------------------------------------------------------

#[test]
fn witness_tags_contain_hole_and_surface() {
    let h = hole("tst", HoleSurface::Parser, 300_000);
    let batch = generate_for_hole(&h, &cfg()).unwrap();
    for w in &batch.witnesses {
        assert!(w.tags.contains("hole:tst"));
        assert!(w.tags.contains("surface:parser"));
    }
}

#[test]
fn witness_files_nonempty() {
    let h = hole("f1", HoleSurface::Runtime, 300_000);
    let batch = generate_for_hole(&h, &cfg()).unwrap();
    for w in &batch.witnesses {
        assert!(!w.files.is_empty());
        for f in &w.files {
            assert!(!f.content.is_empty());
        }
    }
}

#[test]
fn witness_serde_roundtrip() {
    let h = hole("ser", HoleSurface::Module, 400_000);
    let batch = generate_for_hole(&h, &cfg()).unwrap();
    for w in &batch.witnesses {
        let json = serde_json::to_string(w).unwrap();
        let back: WitnessProgram = serde_json::from_str(&json).unwrap();
        assert_eq!(*w, back);
    }
}

// ---------------------------------------------------------------------------
// HoleWitnessBatch
// ---------------------------------------------------------------------------

#[test]
fn batch_seal_recalculates_confidence() {
    let h = hole("bs", HoleSurface::Parser, 500_000);
    let batch = generate_for_hole(&h, &cfg()).unwrap();
    assert!(batch.has_confident_witness);
}

#[test]
fn batch_hash_deterministic() {
    let h = hole("det", HoleSurface::Parser, 500_000);
    let b1 = generate_for_hole(&h, &cfg()).unwrap();
    let b2 = generate_for_hole(&h, &cfg()).unwrap();
    assert_eq!(b1.content_hash, b2.content_hash);
}

#[test]
fn batch_serde_roundtrip() {
    let h = hole("batch_ser", HoleSurface::Lowering, 300_000);
    let batch = generate_for_hole(&h, &cfg()).unwrap();
    let json = serde_json::to_string(&batch).unwrap();
    let back: HoleWitnessBatch = serde_json::from_str(&json).unwrap();
    assert_eq!(batch, back);
}

// ---------------------------------------------------------------------------
// GeneratorConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_values() {
    let c = GeneratorConfig::default();
    assert_eq!(c.min_persistence_millionths, DEFAULT_MIN_PERSISTENCE);
    assert_eq!(c.max_witness_lines, DEFAULT_MAX_WITNESS_LINES);
    assert_eq!(c.max_witnesses_per_hole, DEFAULT_MAX_WITNESSES_PER_HOLE);
    assert_eq!(c.min_confidence_millionths, DEFAULT_MIN_CONFIDENCE);
}

#[test]
fn config_restrict_kinds() {
    let mut c = cfg();
    c.allowed_kinds.clear();
    c.allowed_kinds.insert(WitnessProgramKind::JavaScript);
    let h = hole("rk", HoleSurface::Parser, 500_000);
    let batch = generate_for_hole(&h, &c).unwrap();
    for w in &batch.witnesses {
        assert_eq!(w.kind, WitnessProgramKind::JavaScript);
    }
}

#[test]
fn config_high_persistence_threshold_filters() {
    let mut c = cfg();
    c.min_persistence_millionths = 999_999;
    let h = hole("ht", HoleSurface::Parser, 500_000);
    let batch = generate_for_hole(&h, &c).unwrap();
    assert!(batch.witnesses.is_empty());
}

// ---------------------------------------------------------------------------
// GeneratorError
// ---------------------------------------------------------------------------

#[test]
fn error_display_all_variants() {
    let errors = vec![
        GeneratorError::EmptyInput,
        GeneratorError::InvalidHoleReference("bad".into()),
        GeneratorError::UnsupportedSurface("x".into()),
        GeneratorError::GenerationFailed {
            hole_id: "h".into(),
            reason: "r".into(),
        },
        GeneratorError::InternalError("i".into()),
    ];
    for e in &errors {
        assert!(!format!("{e}").is_empty());
    }
}

#[test]
fn error_serde_all_variants() {
    let errors = vec![
        GeneratorError::EmptyInput,
        GeneratorError::InvalidHoleReference("bad".into()),
        GeneratorError::UnsupportedSurface("x".into()),
        GeneratorError::GenerationFailed {
            hole_id: "h".into(),
            reason: "r".into(),
        },
        GeneratorError::InternalError("i".into()),
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: GeneratorError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// GenerationOutcome
// ---------------------------------------------------------------------------

#[test]
fn outcome_serde_roundtrip() {
    let outcomes = [
        GenerationOutcome::Complete,
        GenerationOutcome::Partial,
        GenerationOutcome::Empty,
        GenerationOutcome::NoActionableHoles,
    ];
    for o in &outcomes {
        let json = serde_json::to_string(o).unwrap();
        let back: GenerationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, back);
    }
}

// ---------------------------------------------------------------------------
// GenerationReport
// ---------------------------------------------------------------------------

#[test]
fn report_complete_all_surfaces() {
    let surfaces = [
        HoleSurface::Parser,
        HoleSurface::Lowering,
        HoleSurface::Runtime,
        HoleSurface::Module,
        HoleSurface::React,
        HoleSurface::Interop,
        HoleSurface::RegExp,
        HoleSurface::TypeScript,
        HoleSurface::Stdlib,
    ];
    let holes: Vec<_> = surfaces
        .iter()
        .enumerate()
        .map(|(i, s)| hole(&format!("h{i}"), *s, 500_000))
        .collect();
    let report = generate_witnesses(&holes, &cfg()).unwrap();
    assert_eq!(report.holes_processed, 9);
    assert_eq!(report.outcome, GenerationOutcome::Complete);
}

#[test]
fn report_empty_when_all_below_threshold() {
    let holes = vec![
        hole("a", HoleSurface::Parser, 1),
        hole("b", HoleSurface::Runtime, 2),
    ];
    let report = generate_witnesses(&holes, &cfg()).unwrap();
    assert_eq!(report.outcome, GenerationOutcome::Empty);
    assert_eq!(report.holes_covered, 0);
}

#[test]
fn report_hash_deterministic() {
    let holes = vec![
        hole("a", HoleSurface::Parser, 300_000),
        hole("b", HoleSurface::Runtime, 300_000),
    ];
    let r1 = generate_witnesses(&holes, &cfg()).unwrap();
    let r2 = generate_witnesses(&holes, &cfg()).unwrap();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_serde_roundtrip() {
    let holes = vec![
        hole("a", HoleSurface::Parser, 300_000),
        hole("b", HoleSurface::Module, 400_000),
    ];
    let report = generate_witnesses(&holes, &cfg()).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: GenerationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn report_with_epoch() {
    let epoch = SecurityEpoch::from_raw(77);
    let holes = vec![hole("a", HoleSurface::Parser, 300_000)];
    let report = generate_witnesses_at_epoch(&holes, &cfg(), epoch).unwrap();
    assert_eq!(report.epoch, epoch);
    assert_eq!(report.epoch.as_u64(), 77);
}

// ---------------------------------------------------------------------------
// Analysis helpers
// ---------------------------------------------------------------------------

#[test]
fn collect_ids_all_prefixed() {
    let holes = vec![
        hole("a", HoleSurface::Parser, 500_000),
        hole("b", HoleSurface::Runtime, 500_000),
        hole("c", HoleSurface::Module, 500_000),
    ];
    let report = generate_witnesses(&holes, &cfg()).unwrap();
    let ids = collect_witness_ids(&report);
    assert!(ids.iter().all(|id| id.starts_with("wt-")));
    assert!(ids.len() >= 3);
}

#[test]
fn covered_surfaces_subset_of_input() {
    let holes = vec![
        hole("a", HoleSurface::Parser, 500_000),
        hole("b", HoleSurface::React, 500_000),
    ];
    let report = generate_witnesses(&holes, &cfg()).unwrap();
    let cs = covered_surfaces(&report);
    assert!(cs.contains(&HoleSurface::Parser));
    assert!(cs.contains(&HoleSurface::React));
    assert!(!cs.contains(&HoleSurface::Interop));
}

#[test]
fn surface_coverage_sums_correctly() {
    let holes = vec![
        hole("a", HoleSurface::Parser, 500_000),
        hole("b", HoleSurface::Parser, 500_000),
        hole("c", HoleSurface::Parser, 500_000),
    ];
    let report = generate_witnesses(&holes, &cfg()).unwrap();
    let cov = surface_coverage(&report);
    assert_eq!(*cov.get(&HoleSurface::Parser).unwrap(), 1_000_000);
}

#[test]
fn empty_batches_only_below_threshold() {
    let holes = vec![
        hole("a", HoleSurface::Parser, 500_000),
        hole("low1", HoleSurface::Runtime, 5),
        hole("low2", HoleSurface::Module, 10),
    ];
    let report = generate_witnesses(&holes, &cfg()).unwrap();
    let eb = empty_batches(&report);
    assert_eq!(eb.len(), 2);
}

#[test]
fn max_min_confidence_ordered() {
    let holes = vec![
        hole("a", HoleSurface::Parser, 500_000),
        hole("b", HoleSurface::Runtime, 500_000),
    ];
    let report = generate_witnesses(&holes, &cfg()).unwrap();
    assert!(max_confidence(&report) >= min_confidence(&report));
}

// ---------------------------------------------------------------------------
// ReportSummary
// ---------------------------------------------------------------------------

#[test]
fn summary_matches_report() {
    let holes = vec![
        hole("a", HoleSurface::Parser, 500_000),
        hole("b", HoleSurface::React, 500_000),
        hole("c", HoleSurface::Module, 1),
    ];
    let report = generate_witnesses(&holes, &cfg()).unwrap();
    let summary = report_summary(&report);
    assert_eq!(summary.holes_processed, report.holes_processed);
    assert_eq!(summary.holes_covered, report.holes_covered);
    assert_eq!(summary.holes_uncovered, report.holes_uncovered);
    assert_eq!(summary.total_witnesses, report.total_witnesses);
    assert_eq!(summary.coverage_millionths, report.coverage_millionths);
    assert_eq!(summary.outcome, report.outcome);
}

#[test]
fn summary_serde_roundtrip() {
    let holes = vec![hole("a", HoleSurface::Parser, 500_000)];
    let report = generate_witnesses(&holes, &cfg()).unwrap();
    let summary = report_summary(&report);
    let json = serde_json::to_string(&summary).unwrap();
    let back: ReportSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn summary_surfaces_count() {
    let holes = vec![
        hole("a", HoleSurface::Parser, 500_000),
        hole("b", HoleSurface::React, 500_000),
        hole("c", HoleSurface::Module, 500_000),
    ];
    let report = generate_witnesses(&holes, &cfg()).unwrap();
    let summary = report_summary(&report);
    assert!(summary.surfaces_covered >= 3);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn single_hole_single_surface() {
    let holes = vec![hole("only", HoleSurface::Stdlib, 300_000)];
    let report = generate_witnesses(&holes, &cfg()).unwrap();
    assert_eq!(report.holes_processed, 1);
    assert!(!report.batches.is_empty());
}

#[test]
fn high_dimension_hole_lower_confidence() {
    let mut h = hole("dim3", HoleSurface::Parser, 300_000);
    h.dimension = 3;
    let batch = generate_for_hole(&h, &cfg()).unwrap();
    // Higher dimension → lower confidence
    for w in &batch.witnesses {
        assert!(w.confidence_millionths < 800_000);
    }
}

#[test]
fn hole_no_cycle_lower_confidence() {
    let mut h = hole("nocyc", HoleSurface::Parser, 300_000);
    h.representative_cycle.clear();
    let batch = generate_for_hole(&h, &cfg()).unwrap();
    for w in &batch.witnesses {
        assert!(w.confidence_millionths < 700_000);
    }
}

#[test]
fn many_programs_boost() {
    let mut h = hole("many", HoleSurface::Parser, 300_000);
    h.affected_programs = vec!["a".into(), "b".into(), "c".into(), "d".into(), "e".into()];
    let batch = generate_for_hole(&h, &cfg()).unwrap();
    assert!(batch.has_confident_witness);
}

#[test]
fn duplicate_holes_produce_same_output() {
    let h1 = hole("dup", HoleSurface::Parser, 500_000);
    let h2 = hole("dup", HoleSurface::Parser, 500_000);
    let b1 = generate_for_hole(&h1, &cfg()).unwrap();
    let b2 = generate_for_hole(&h2, &cfg()).unwrap();
    assert_eq!(b1.content_hash, b2.content_hash);
}

#[test]
fn witness_id_format() {
    let h = hole("fmt", HoleSurface::Parser, 500_000);
    let batch = generate_for_hole(&h, &cfg()).unwrap();
    for w in &batch.witnesses {
        assert!(w.witness_id.starts_with("wt-fmt-"));
    }
}

#[test]
fn witness_description_contains_hole_info() {
    let h = hole("desc", HoleSurface::React, 500_000);
    let batch = generate_for_hole(&h, &cfg()).unwrap();
    for w in &batch.witnesses {
        assert!(w.description.contains("desc"));
        assert!(w.description.contains("react"));
    }
}

// ---------------------------------------------------------------------------
// Restricted config
// ---------------------------------------------------------------------------

#[test]
fn empty_allowed_kinds_produces_empty_batches() {
    let mut c = cfg();
    c.allowed_kinds.clear();
    let h = hole("ek", HoleSurface::Parser, 500_000);
    let batch = generate_for_hole(&h, &c).unwrap();
    assert!(batch.witnesses.is_empty());
}

#[test]
fn tiny_max_lines_filters_large_witnesses() {
    let mut c = cfg();
    c.max_witness_lines = 2; // Very restrictive
    let h = hole("tiny", HoleSurface::Parser, 500_000);
    let batch = generate_for_hole(&h, &c).unwrap();
    // Templates have >2 lines, so all filtered
    assert!(batch.witnesses.is_empty());
}

// ---------------------------------------------------------------------------
// Multiple batches
// ---------------------------------------------------------------------------

#[test]
fn ten_holes_various_surfaces() {
    let holes: Vec<_> = (0..10)
        .map(|i| {
            let surface = match i % 5 {
                0 => HoleSurface::Parser,
                1 => HoleSurface::Runtime,
                2 => HoleSurface::Module,
                3 => HoleSurface::React,
                _ => HoleSurface::Interop,
            };
            hole(&format!("h{i}"), surface, 500_000)
        })
        .collect();
    let report = generate_witnesses(&holes, &cfg()).unwrap();
    assert_eq!(report.holes_processed, 10);
    assert_eq!(report.outcome, GenerationOutcome::Complete);
}

#[test]
fn coverage_ratio_correct() {
    let holes = vec![
        hole("a", HoleSurface::Parser, 500_000),
        hole("b", HoleSurface::Parser, 500_000),
        hole("c", HoleSurface::Parser, 1), // Below threshold
        hole("d", HoleSurface::Parser, 1), // Below threshold
    ];
    let report = generate_witnesses(&holes, &cfg()).unwrap();
    assert_eq!(report.coverage_millionths, 500_000); // 2/4
}
