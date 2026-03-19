#![allow(clippy::too_many_arguments)]

//! Enrichment integration tests for `minimized_repro_extraction`.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::minimized_repro_extraction::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(99)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_are_consistent() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert_eq!(COMPONENT, "minimized_repro_extraction");
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(POLICY_ID.starts_with("RGC-"));
    assert_eq!(FIXED_ONE, 1_000_000);
    assert!(DEFAULT_MAX_REPRO_LINES > 0);
    assert!(DEFAULT_MIN_REDUCTION_RATIO > 0);
    assert!(DEFAULT_MAX_TRIAGE_LATENCY_NS > 0);
}

// ---------------------------------------------------------------------------
// FailureCategory serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn failure_category_serde_all_variants() {
    for cat in FailureCategory::all() {
        let json = serde_json::to_string(cat).unwrap();
        let back: FailureCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, back);
    }
}

#[test]
fn failure_category_display_distinct() {
    let displays: BTreeSet<String> = FailureCategory::all()
        .iter()
        .map(|c| c.to_string())
        .collect();
    assert_eq!(displays.len(), 10);
}

#[test]
fn failure_category_display_specific_values() {
    assert_eq!(FailureCategory::RenderCrash.to_string(), "render_crash");
    assert_eq!(FailureCategory::JsxTransform.to_string(), "jsx_transform");
    assert_eq!(
        FailureCategory::ConcurrentRace.to_string(),
        "concurrent_race"
    );
    assert_eq!(
        FailureCategory::ServerComponentError.to_string(),
        "server_component_error"
    );
}

#[test]
fn failure_category_ordering() {
    assert!(FailureCategory::RenderCrash < FailureCategory::HydrationMismatch);
    assert!(FailureCategory::HydrationMismatch < FailureCategory::BuildToolIntegration);
}

// ---------------------------------------------------------------------------
// MinimizationStrategy serde and display
// ---------------------------------------------------------------------------

#[test]
fn minimization_strategy_serde_all_variants() {
    let strats = [
        MinimizationStrategy::DeltaDebugging,
        MinimizationStrategy::HierarchicalReduction,
        MinimizationStrategy::DependencyStripping,
        MinimizationStrategy::StateSlicing,
        MinimizationStrategy::PropElimination,
    ];
    for s in strats {
        let json = serde_json::to_string(&s).unwrap();
        let back: MinimizationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn minimization_strategy_display_distinct() {
    let strats = [
        MinimizationStrategy::DeltaDebugging,
        MinimizationStrategy::HierarchicalReduction,
        MinimizationStrategy::DependencyStripping,
        MinimizationStrategy::StateSlicing,
        MinimizationStrategy::PropElimination,
    ];
    let displays: BTreeSet<String> = strats.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

// ---------------------------------------------------------------------------
// TriageOwner
// ---------------------------------------------------------------------------

#[test]
fn triage_owner_serde_all_variants() {
    let owners = [
        TriageOwner::EngineRuntime,
        TriageOwner::ParserCompiler,
        TriageOwner::ReactIntegration,
        TriageOwner::ModuleResolution,
        TriageOwner::BuildTooling,
        TriageOwner::ExternalUpstream,
    ];
    for o in owners {
        let json = serde_json::to_string(&o).unwrap();
        let back: TriageOwner = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }
}

#[test]
fn triage_owner_display_distinct() {
    let owners = [
        TriageOwner::EngineRuntime,
        TriageOwner::ParserCompiler,
        TriageOwner::ReactIntegration,
        TriageOwner::ModuleResolution,
        TriageOwner::BuildTooling,
        TriageOwner::ExternalUpstream,
    ];
    let displays: BTreeSet<String> = owners.iter().map(|o| o.to_string()).collect();
    assert_eq!(displays.len(), 6);
}

// ---------------------------------------------------------------------------
// TriageSeverity
// ---------------------------------------------------------------------------

#[test]
fn triage_severity_serde_roundtrip() {
    for sev in [
        TriageSeverity::Info,
        TriageSeverity::Warning,
        TriageSeverity::Error,
        TriageSeverity::Critical,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: TriageSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
    }
}

#[test]
fn triage_severity_ordering() {
    assert!(TriageSeverity::Info < TriageSeverity::Warning);
    assert!(TriageSeverity::Warning < TriageSeverity::Error);
    assert!(TriageSeverity::Error < TriageSeverity::Critical);
}

// ---------------------------------------------------------------------------
// ReproInput
// ---------------------------------------------------------------------------

#[test]
fn repro_input_hash_deterministic() {
    let a = ReproInput::new("inp-1".into(), FailureCategory::HookOrdering, 300, 12, 8);
    let b = ReproInput::new("inp-1".into(), FailureCategory::HookOrdering, 300, 12, 8);
    assert_eq!(a.input_hash, b.input_hash);
}

#[test]
fn repro_input_different_id_different_hash() {
    let a = ReproInput::new("inp-1".into(), FailureCategory::HookOrdering, 300, 12, 8);
    let b = ReproInput::new("inp-2".into(), FailureCategory::HookOrdering, 300, 12, 8);
    assert_ne!(a.input_hash, b.input_hash);
}

#[test]
fn repro_input_different_category_different_hash() {
    let a = ReproInput::new("inp-1".into(), FailureCategory::HookOrdering, 300, 12, 8);
    let b = ReproInput::new("inp-1".into(), FailureCategory::RenderCrash, 300, 12, 8);
    assert_ne!(a.input_hash, b.input_hash);
}

#[test]
fn repro_input_serde_roundtrip() {
    let input = ReproInput::new(
        "serde-test".into(),
        FailureCategory::SuspenseFailure,
        150,
        6,
        3,
    );
    let json = serde_json::to_string(&input).unwrap();
    let back: ReproInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

// ---------------------------------------------------------------------------
// MinimizedRepro
// ---------------------------------------------------------------------------

#[test]
fn minimized_repro_full_reduction() {
    let r = MinimizedRepro::new(
        "inp".into(),
        MinimizationStrategy::PropElimination,
        0,
        200,
        true,
        5_000,
    );
    assert_eq!(r.reduction_ratio_millionths, 1_000_000);
}

#[test]
fn minimized_repro_no_reduction() {
    let r = MinimizedRepro::new(
        "inp".into(),
        MinimizationStrategy::DeltaDebugging,
        100,
        100,
        true,
        5_000,
    );
    assert_eq!(r.reduction_ratio_millionths, 0);
}

#[test]
fn minimized_repro_zero_original_no_panic() {
    let r = MinimizedRepro::new(
        "inp".into(),
        MinimizationStrategy::DeltaDebugging,
        0,
        0,
        false,
        0,
    );
    assert_eq!(r.reduction_ratio_millionths, 0);
}

#[test]
fn minimized_repro_50_percent_reduction() {
    let r = MinimizedRepro::new(
        "inp".into(),
        MinimizationStrategy::HierarchicalReduction,
        50,
        100,
        true,
        10_000,
    );
    assert_eq!(r.reduction_ratio_millionths, 500_000);
}

#[test]
fn minimized_repro_hash_deterministic() {
    let a = MinimizedRepro::new(
        "x".into(),
        MinimizationStrategy::StateSlicing,
        10,
        100,
        true,
        99,
    );
    let b = MinimizedRepro::new(
        "x".into(),
        MinimizationStrategy::StateSlicing,
        10,
        100,
        true,
        99,
    );
    assert_eq!(a.repro_hash, b.repro_hash);
}

#[test]
fn minimized_repro_serde_roundtrip() {
    let r = MinimizedRepro::new(
        "inp-s".into(),
        MinimizationStrategy::DependencyStripping,
        15,
        200,
        true,
        7_000,
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: MinimizedRepro = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// TriageFinding
// ---------------------------------------------------------------------------

#[test]
fn triage_finding_serde_roundtrip_with_hash() {
    let finding = TriageFinding {
        category: FailureCategory::HydrationMismatch,
        owner: TriageOwner::ReactIntegration,
        severity: TriageSeverity::Error,
        summary: "SSR mismatch".into(),
        repro_hash: Some(ContentHash::compute(b"evidence")),
        recommended_action: "Fix useLayoutEffect".into(),
    };
    let json = serde_json::to_string(&finding).unwrap();
    let back: TriageFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, back);
}

#[test]
fn triage_finding_serde_roundtrip_without_hash() {
    let finding = TriageFinding {
        category: FailureCategory::BuildToolIntegration,
        owner: TriageOwner::BuildTooling,
        severity: TriageSeverity::Warning,
        summary: "Vite plugin fails".into(),
        repro_hash: None,
        recommended_action: "Upgrade plugin".into(),
    };
    let json = serde_json::to_string(&finding).unwrap();
    let back: TriageFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, back);
    assert!(back.repro_hash.is_none());
}

// ---------------------------------------------------------------------------
// ExtractionConfig
// ---------------------------------------------------------------------------

#[test]
fn config_strict_has_all_categories() {
    let c = ExtractionConfig::strict();
    assert_eq!(c.required_categories.len(), FailureCategory::all().len());
}

#[test]
fn config_relaxed_has_no_required_categories() {
    let c = ExtractionConfig::relaxed();
    assert!(c.required_categories.is_empty());
}

#[test]
fn config_default_equals_relaxed() {
    let def = ExtractionConfig::default();
    let rel = ExtractionConfig::relaxed();
    assert_eq!(def, rel);
}

#[test]
fn config_strict_more_restrictive_than_relaxed() {
    let strict = ExtractionConfig::strict();
    let relaxed = ExtractionConfig::relaxed();
    assert!(strict.min_reduction_ratio >= relaxed.min_reduction_ratio);
    assert!(strict.max_repro_lines <= relaxed.max_repro_lines);
}

#[test]
fn config_serde_roundtrip() {
    let c = ExtractionConfig::strict();
    let json = serde_json::to_string(&c).unwrap();
    let back: ExtractionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// ExtractionVerdict
// ---------------------------------------------------------------------------

#[test]
fn verdict_serde_all_variants() {
    for v in [
        ExtractionVerdict::Complete,
        ExtractionVerdict::PartialReduction,
        ExtractionVerdict::IncompleteCoverage,
        ExtractionVerdict::TriageLatencyExceeded,
        ExtractionVerdict::NoInputs,
        ExtractionVerdict::MultipleIssues,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: ExtractionVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn verdict_needs_attention_only_complete_false() {
    assert!(!ExtractionVerdict::Complete.needs_attention());
    assert!(ExtractionVerdict::PartialReduction.needs_attention());
    assert!(ExtractionVerdict::IncompleteCoverage.needs_attention());
    assert!(ExtractionVerdict::TriageLatencyExceeded.needs_attention());
    assert!(ExtractionVerdict::NoInputs.needs_attention());
    assert!(ExtractionVerdict::MultipleIssues.needs_attention());
}

#[test]
fn verdict_display_all_distinct() {
    let displays: BTreeSet<String> = [
        ExtractionVerdict::Complete,
        ExtractionVerdict::PartialReduction,
        ExtractionVerdict::IncompleteCoverage,
        ExtractionVerdict::TriageLatencyExceeded,
        ExtractionVerdict::NoInputs,
        ExtractionVerdict::MultipleIssues,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(displays.len(), 6);
}

// ---------------------------------------------------------------------------
// Default owner routing
// ---------------------------------------------------------------------------

#[test]
fn default_owner_covers_all_categories() {
    for cat in FailureCategory::all() {
        let owner = ExtractionEngine::default_owner(*cat);
        assert!(!owner.to_string().is_empty());
    }
}

#[test]
fn default_owner_specific_routings() {
    assert_eq!(
        ExtractionEngine::default_owner(FailureCategory::JsxTransform),
        TriageOwner::ParserCompiler
    );
    assert_eq!(
        ExtractionEngine::default_owner(FailureCategory::ModuleResolution),
        TriageOwner::ModuleResolution
    );
    assert_eq!(
        ExtractionEngine::default_owner(FailureCategory::BuildToolIntegration),
        TriageOwner::BuildTooling
    );
    assert_eq!(
        ExtractionEngine::default_owner(FailureCategory::RenderCrash),
        TriageOwner::EngineRuntime
    );
    assert_eq!(
        ExtractionEngine::default_owner(FailureCategory::ConcurrentRace),
        TriageOwner::EngineRuntime
    );
    assert_eq!(
        ExtractionEngine::default_owner(FailureCategory::HydrationMismatch),
        TriageOwner::ReactIntegration
    );
}

// ---------------------------------------------------------------------------
// ExtractionEngine evaluate
// ---------------------------------------------------------------------------

#[test]
fn engine_empty_gives_no_inputs() {
    let engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    let report = engine.evaluate(epoch());
    assert_eq!(report.verdict, ExtractionVerdict::NoInputs);
    assert!(report.inputs.is_empty());
    assert!(report.repros.is_empty());
}

#[test]
fn engine_good_repro_gives_complete() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new(
        "i1".into(),
        FailureCategory::RenderCrash,
        200,
        5,
        3,
    ));
    engine.add_repro(MinimizedRepro::new(
        "i1".into(),
        MinimizationStrategy::DeltaDebugging,
        20,
        200,
        true,
        1_000_000,
    ));
    let report = engine.evaluate(epoch());
    assert_eq!(report.verdict, ExtractionVerdict::Complete);
}

#[test]
fn engine_partial_reduction_when_ratio_below_threshold() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new(
        "i1".into(),
        FailureCategory::RenderCrash,
        200,
        5,
        3,
    ));
    engine.add_repro(MinimizedRepro::new(
        "i1".into(),
        MinimizationStrategy::DeltaDebugging,
        160,
        200,
        true,
        1_000_000,
    ));
    let report = engine.evaluate(epoch());
    assert_eq!(report.verdict, ExtractionVerdict::PartialReduction);
}

#[test]
fn engine_repro_too_large_gives_partial_reduction() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new(
        "i1".into(),
        FailureCategory::RenderCrash,
        1000,
        50,
        20,
    ));
    // reduced_lines=60 > default max_repro_lines=50
    engine.add_repro(MinimizedRepro::new(
        "i1".into(),
        MinimizationStrategy::DeltaDebugging,
        60,
        1000,
        true,
        1_000_000,
    ));
    let report = engine.evaluate(epoch());
    assert_eq!(report.verdict, ExtractionVerdict::PartialReduction);
}

#[test]
fn engine_triage_latency_exceeded() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new(
        "i1".into(),
        FailureCategory::RenderCrash,
        200,
        5,
        3,
    ));
    engine.add_repro(MinimizedRepro::new(
        "i1".into(),
        MinimizationStrategy::DeltaDebugging,
        20,
        200,
        true,
        100_000_000_000, // 100s > 60s default
    ));
    let report = engine.evaluate(epoch());
    assert_eq!(report.verdict, ExtractionVerdict::TriageLatencyExceeded);
}

#[test]
fn engine_incomplete_coverage() {
    let mut config = ExtractionConfig::relaxed();
    config
        .required_categories
        .insert(FailureCategory::HydrationMismatch);
    config
        .required_categories
        .insert(FailureCategory::JsxTransform);
    let mut engine = ExtractionEngine::new(config);
    engine.add_input(ReproInput::new(
        "i1".into(),
        FailureCategory::RenderCrash,
        200,
        5,
        3,
    ));
    let report = engine.evaluate(epoch());
    assert_eq!(report.verdict, ExtractionVerdict::IncompleteCoverage);
    assert!(
        report
            .categories_missing
            .contains(&FailureCategory::HydrationMismatch)
    );
    assert!(
        report
            .categories_missing
            .contains(&FailureCategory::JsxTransform)
    );
}

#[test]
fn engine_multiple_issues() {
    let mut config = ExtractionConfig::relaxed();
    config
        .required_categories
        .insert(FailureCategory::HydrationMismatch);
    let mut engine = ExtractionEngine::new(config);
    engine.add_input(ReproInput::new(
        "i1".into(),
        FailureCategory::RenderCrash,
        200,
        5,
        3,
    ));
    // Bad repro: too large, poor ratio
    engine.add_repro(MinimizedRepro::new(
        "i1".into(),
        MinimizationStrategy::DeltaDebugging,
        150,
        200,
        true,
        1_000_000,
    ));
    let report = engine.evaluate(epoch());
    assert_eq!(report.verdict, ExtractionVerdict::MultipleIssues);
}

// ---------------------------------------------------------------------------
// ExtractionEngine avg reduction ratio
// ---------------------------------------------------------------------------

#[test]
fn engine_avg_reduction_single_repro() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new(
        "i1".into(),
        FailureCategory::RenderCrash,
        200,
        5,
        3,
    ));
    engine.add_repro(MinimizedRepro::new(
        "i1".into(),
        MinimizationStrategy::DeltaDebugging,
        20,
        200,
        true,
        1_000_000,
    ));
    let report = engine.evaluate(epoch());
    assert_eq!(report.avg_reduction_ratio_millionths, 900_000);
}

#[test]
fn engine_avg_reduction_multiple_repros() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new(
        "i1".into(),
        FailureCategory::RenderCrash,
        200,
        5,
        3,
    ));
    engine.add_repro(MinimizedRepro::new(
        "i1".into(),
        MinimizationStrategy::DeltaDebugging,
        20,
        200,
        true,
        1_000_000,
    ));
    engine.add_repro(MinimizedRepro::new(
        "i2".into(),
        MinimizationStrategy::HierarchicalReduction,
        50,
        200,
        true,
        1_000_000,
    ));
    let report = engine.evaluate(epoch());
    // (900_000 + 750_000) / 2 = 825_000
    assert_eq!(report.avg_reduction_ratio_millionths, 825_000);
}

#[test]
fn engine_no_repros_avg_is_zero() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new(
        "i1".into(),
        FailureCategory::RenderCrash,
        200,
        5,
        3,
    ));
    let report = engine.evaluate(epoch());
    assert_eq!(report.avg_reduction_ratio_millionths, 0);
}

// ---------------------------------------------------------------------------
// Report determinism
// ---------------------------------------------------------------------------

#[test]
fn report_hash_deterministic() {
    let build = || {
        let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
        engine.add_input(ReproInput::new(
            "i1".into(),
            FailureCategory::RenderCrash,
            200,
            5,
            3,
        ));
        engine.add_repro(MinimizedRepro::new(
            "i1".into(),
            MinimizationStrategy::DeltaDebugging,
            20,
            200,
            true,
            1_000_000,
        ));
        engine.evaluate(epoch())
    };
    let r1 = build();
    let r2 = build();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_hash_changes_with_different_inputs() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new(
        "i1".into(),
        FailureCategory::RenderCrash,
        200,
        5,
        3,
    ));
    let r1 = engine.evaluate(epoch());
    engine.add_input(ReproInput::new(
        "i2".into(),
        FailureCategory::HookOrdering,
        300,
        8,
        4,
    ));
    let r2 = engine.evaluate(epoch());
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// ExtractionReport serde
// ---------------------------------------------------------------------------

#[test]
fn report_serde_roundtrip_empty() {
    let engine = ExtractionEngine::new(ExtractionConfig::default());
    let report = engine.evaluate(epoch());
    let json = serde_json::to_string(&report).unwrap();
    let back: ExtractionReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn report_serde_roundtrip_populated() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new(
        "i1".into(),
        FailureCategory::RenderCrash,
        200,
        5,
        3,
    ));
    engine.add_repro(MinimizedRepro::new(
        "i1".into(),
        MinimizationStrategy::DeltaDebugging,
        20,
        200,
        true,
        1_000_000,
    ));
    engine.add_finding(TriageFinding {
        category: FailureCategory::RenderCrash,
        owner: TriageOwner::EngineRuntime,
        severity: TriageSeverity::Critical,
        summary: "crash".into(),
        repro_hash: Some(ContentHash::compute(b"test")),
        recommended_action: "fix".into(),
    });
    let report = engine.evaluate(epoch());
    let json = serde_json::to_string(&report).unwrap();
    let back: ExtractionReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// ExtractionEngine serde
// ---------------------------------------------------------------------------

#[test]
fn engine_serde_roundtrip() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::strict());
    engine.add_input(ReproInput::new(
        "i1".into(),
        FailureCategory::SuspenseFailure,
        500,
        20,
        10,
    ));
    let json = serde_json::to_string(&engine).unwrap();
    let back: ExtractionEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(engine, back);
}

// ---------------------------------------------------------------------------
// categories_covered tracking
// ---------------------------------------------------------------------------

#[test]
fn categories_covered_deduplicates() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new(
        "i1".into(),
        FailureCategory::RenderCrash,
        200,
        5,
        3,
    ));
    engine.add_input(ReproInput::new(
        "i2".into(),
        FailureCategory::RenderCrash,
        300,
        7,
        4,
    ));
    let report = engine.evaluate(epoch());
    assert_eq!(report.categories_covered.len(), 1);
}

#[test]
fn categories_covered_tracks_multiple() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new(
        "i1".into(),
        FailureCategory::RenderCrash,
        200,
        5,
        3,
    ));
    engine.add_input(ReproInput::new(
        "i2".into(),
        FailureCategory::HookOrdering,
        300,
        8,
        4,
    ));
    engine.add_input(ReproInput::new(
        "i3".into(),
        FailureCategory::JsxTransform,
        100,
        2,
        1,
    ));
    let report = engine.evaluate(epoch());
    assert_eq!(report.categories_covered.len(), 3);
    assert!(
        report
            .categories_covered
            .contains(&FailureCategory::RenderCrash)
    );
    assert!(
        report
            .categories_covered
            .contains(&FailureCategory::HookOrdering)
    );
    assert!(
        report
            .categories_covered
            .contains(&FailureCategory::JsxTransform)
    );
}

// ---------------------------------------------------------------------------
// Report epoch
// ---------------------------------------------------------------------------

#[test]
fn report_epoch_matches_provided() {
    let engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    let ep = SecurityEpoch::from_raw(42);
    let report = engine.evaluate(ep);
    assert_eq!(report.epoch.as_u64(), 42);
}

// ---------------------------------------------------------------------------
// Strict config coverage requirement with all categories
// ---------------------------------------------------------------------------

#[test]
fn strict_config_all_categories_missing_when_empty() {
    let engine = ExtractionEngine::new(ExtractionConfig::strict());
    let report = engine.evaluate(epoch());
    // NoInputs takes precedence in single-issue case
    // But with strict config, both NoInputs and IncompleteCoverage trigger => MultipleIssues
    assert_eq!(report.verdict, ExtractionVerdict::MultipleIssues);
    assert_eq!(report.categories_missing.len(), 10);
}

#[test]
fn strict_config_partial_coverage() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::strict());
    for cat in FailureCategory::all().iter().take(5) {
        engine.add_input(ReproInput::new(format!("i-{}", cat), *cat, 100, 3, 2));
    }
    let report = engine.evaluate(epoch());
    assert_eq!(report.categories_missing.len(), 5);
}
