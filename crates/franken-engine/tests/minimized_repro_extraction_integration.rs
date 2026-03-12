// Integration tests for minimized_repro_extraction module.
//
// Covers: constants, type ordering, constructor verification, lifecycle flows,
// verdict determination, content hash determinism, and E2E scenarios.

use frankenengine_engine::minimized_repro_extraction::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_contains_module_name() {
    assert!(SCHEMA_VERSION.contains("minimized-repro-extraction"));
}

#[test]
fn test_schema_version_ends_with_v1() {
    assert!(SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn test_component_value() {
    assert_eq!(COMPONENT, "minimized_repro_extraction");
}

#[test]
fn test_bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
    assert_eq!(BEAD_ID, "bd-1lsy.5.7.3");
}

#[test]
fn test_policy_id_format() {
    assert!(POLICY_ID.starts_with("RGC-"));
    assert_eq!(POLICY_ID, "RGC-405C");
}

#[test]
fn test_fixed_one_value() {
    assert_eq!(FIXED_ONE, 1_000_000);
}

#[test]
fn test_default_constants_positive() {
    assert!(DEFAULT_MAX_REPRO_LINES > 0);
    assert!(DEFAULT_MIN_REDUCTION_RATIO > 0);
    assert!(DEFAULT_MAX_TRIAGE_LATENCY_NS > 0);
}

// ---------------------------------------------------------------------------
// FailureCategory ordering and display
// ---------------------------------------------------------------------------

#[test]
fn test_failure_category_all_returns_ten() {
    assert_eq!(FailureCategory::all().len(), 10);
}

#[test]
fn test_failure_category_ordering_first_last() {
    assert!(FailureCategory::RenderCrash < FailureCategory::BuildToolIntegration);
}

#[test]
fn test_failure_category_ordering_adjacent() {
    let all = FailureCategory::all();
    for i in 0..all.len() - 1 {
        assert!(all[i] < all[i + 1], "{:?} should be < {:?}", all[i], all[i + 1]);
    }
}

#[test]
fn test_failure_category_display_render_crash() {
    assert_eq!(FailureCategory::RenderCrash.to_string(), "render_crash");
}

#[test]
fn test_failure_category_display_hydration_mismatch() {
    assert_eq!(FailureCategory::HydrationMismatch.to_string(), "hydration_mismatch");
}

#[test]
fn test_failure_category_display_hook_ordering() {
    assert_eq!(FailureCategory::HookOrdering.to_string(), "hook_ordering");
}

#[test]
fn test_failure_category_display_build_tool_integration() {
    assert_eq!(FailureCategory::BuildToolIntegration.to_string(), "build_tool_integration");
}

#[test]
fn test_failure_category_all_unique() {
    let all = FailureCategory::all();
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(all[i], all[j]);
        }
    }
}

// ---------------------------------------------------------------------------
// MinimizationStrategy display
// ---------------------------------------------------------------------------

#[test]
fn test_minimization_strategy_display_delta_debugging() {
    assert_eq!(MinimizationStrategy::DeltaDebugging.to_string(), "delta_debugging");
}

#[test]
fn test_minimization_strategy_display_hierarchical() {
    assert_eq!(
        MinimizationStrategy::HierarchicalReduction.to_string(),
        "hierarchical_reduction"
    );
}

#[test]
fn test_minimization_strategy_display_dependency_stripping() {
    assert_eq!(
        MinimizationStrategy::DependencyStripping.to_string(),
        "dependency_stripping"
    );
}

#[test]
fn test_minimization_strategy_display_state_slicing() {
    assert_eq!(MinimizationStrategy::StateSlicing.to_string(), "state_slicing");
}

#[test]
fn test_minimization_strategy_display_prop_elimination() {
    assert_eq!(MinimizationStrategy::PropElimination.to_string(), "prop_elimination");
}

#[test]
fn test_minimization_strategy_ordering() {
    assert!(MinimizationStrategy::DeltaDebugging < MinimizationStrategy::PropElimination);
}

// ---------------------------------------------------------------------------
// ReproInput construction
// ---------------------------------------------------------------------------

#[test]
fn test_repro_input_fields_stored() {
    let inp = ReproInput::new("inp1".into(), FailureCategory::RenderCrash, 500, 10, 5);
    assert_eq!(inp.input_id, "inp1");
    assert_eq!(inp.category, FailureCategory::RenderCrash);
    assert_eq!(inp.original_lines, 500);
    assert_eq!(inp.component_count, 10);
    assert_eq!(inp.dependency_count, 5);
}

#[test]
fn test_repro_input_hash_determinism() {
    let a = ReproInput::new("inp1".into(), FailureCategory::RenderCrash, 500, 10, 5);
    let b = ReproInput::new("inp1".into(), FailureCategory::RenderCrash, 500, 10, 5);
    assert_eq!(a.input_hash, b.input_hash);
}

#[test]
fn test_repro_input_hash_differs_on_category() {
    let a = ReproInput::new("inp1".into(), FailureCategory::RenderCrash, 500, 10, 5);
    let b = ReproInput::new("inp1".into(), FailureCategory::HookOrdering, 500, 10, 5);
    assert_ne!(a.input_hash, b.input_hash);
}

#[test]
fn test_repro_input_hash_differs_on_id() {
    let a = ReproInput::new("inp1".into(), FailureCategory::RenderCrash, 500, 10, 5);
    let b = ReproInput::new("inp2".into(), FailureCategory::RenderCrash, 500, 10, 5);
    assert_ne!(a.input_hash, b.input_hash);
}

// ---------------------------------------------------------------------------
// MinimizedRepro construction
// ---------------------------------------------------------------------------

#[test]
fn test_minimized_repro_ratio_75_percent() {
    let r = MinimizedRepro::new(
        "inp1".into(), MinimizationStrategy::DeltaDebugging,
        25, 100, true, 1_000_000,
    );
    assert_eq!(r.reduction_ratio_millionths, 750_000);
    assert!(r.reproduces);
}

#[test]
fn test_minimized_repro_ratio_no_reduction() {
    let r = MinimizedRepro::new(
        "inp1".into(), MinimizationStrategy::DeltaDebugging,
        100, 100, true, 1_000_000,
    );
    assert_eq!(r.reduction_ratio_millionths, 0);
}

#[test]
fn test_minimized_repro_ratio_zero_original() {
    let r = MinimizedRepro::new(
        "inp1".into(), MinimizationStrategy::DeltaDebugging,
        0, 0, false, 0,
    );
    assert_eq!(r.reduction_ratio_millionths, 0);
}

#[test]
fn test_minimized_repro_ratio_90_percent() {
    let r = MinimizedRepro::new(
        "inp1".into(), MinimizationStrategy::HierarchicalReduction,
        10, 100, true, 500_000,
    );
    assert_eq!(r.reduction_ratio_millionths, 900_000);
}

#[test]
fn test_minimized_repro_hash_determinism() {
    let a = MinimizedRepro::new(
        "inp1".into(), MinimizationStrategy::DeltaDebugging,
        25, 100, true, 1_000_000,
    );
    let b = MinimizedRepro::new(
        "inp1".into(), MinimizationStrategy::DeltaDebugging,
        25, 100, true, 1_000_000,
    );
    assert_eq!(a.repro_hash, b.repro_hash);
}

#[test]
fn test_minimized_repro_hash_differs_on_strategy() {
    let a = MinimizedRepro::new(
        "inp1".into(), MinimizationStrategy::DeltaDebugging,
        25, 100, true, 1_000_000,
    );
    let b = MinimizedRepro::new(
        "inp1".into(), MinimizationStrategy::StateSlicing,
        25, 100, true, 1_000_000,
    );
    assert_ne!(a.repro_hash, b.repro_hash);
}

// ---------------------------------------------------------------------------
// TriageOwner and TriageSeverity
// ---------------------------------------------------------------------------

#[test]
fn test_triage_owner_display_engine_runtime() {
    assert_eq!(TriageOwner::EngineRuntime.to_string(), "engine_runtime");
}

#[test]
fn test_triage_owner_display_parser_compiler() {
    assert_eq!(TriageOwner::ParserCompiler.to_string(), "parser_compiler");
}

#[test]
fn test_triage_owner_display_build_tooling() {
    assert_eq!(TriageOwner::BuildTooling.to_string(), "build_tooling");
}

#[test]
fn test_triage_severity_ordering() {
    assert!(TriageSeverity::Info < TriageSeverity::Warning);
    assert!(TriageSeverity::Warning < TriageSeverity::Error);
    assert!(TriageSeverity::Error < TriageSeverity::Critical);
}

// ---------------------------------------------------------------------------
// Default owner routing
// ---------------------------------------------------------------------------

#[test]
fn test_default_owner_render_crash() {
    assert_eq!(
        ExtractionEngine::default_owner(FailureCategory::RenderCrash),
        TriageOwner::EngineRuntime,
    );
}

#[test]
fn test_default_owner_concurrent_race() {
    assert_eq!(
        ExtractionEngine::default_owner(FailureCategory::ConcurrentRace),
        TriageOwner::EngineRuntime,
    );
}

#[test]
fn test_default_owner_hydration_mismatch() {
    assert_eq!(
        ExtractionEngine::default_owner(FailureCategory::HydrationMismatch),
        TriageOwner::ReactIntegration,
    );
}

#[test]
fn test_default_owner_jsx_transform() {
    assert_eq!(
        ExtractionEngine::default_owner(FailureCategory::JsxTransform),
        TriageOwner::ParserCompiler,
    );
}

#[test]
fn test_default_owner_module_resolution() {
    assert_eq!(
        ExtractionEngine::default_owner(FailureCategory::ModuleResolution),
        TriageOwner::ModuleResolution,
    );
}

#[test]
fn test_default_owner_build_tool_integration() {
    assert_eq!(
        ExtractionEngine::default_owner(FailureCategory::BuildToolIntegration),
        TriageOwner::BuildTooling,
    );
}

// ---------------------------------------------------------------------------
// ExtractionConfig
// ---------------------------------------------------------------------------

#[test]
fn test_config_strict_values() {
    let c = ExtractionConfig::strict();
    assert_eq!(c.max_repro_lines, 30);
    assert_eq!(c.required_categories.len(), 10);
    assert_eq!(c.min_reduction_ratio, 700_000);
}

#[test]
fn test_config_relaxed_no_required_categories() {
    let c = ExtractionConfig::relaxed();
    assert!(c.required_categories.is_empty());
    assert_eq!(c.max_repro_lines, DEFAULT_MAX_REPRO_LINES);
}

#[test]
fn test_config_default_is_relaxed() {
    let d = ExtractionConfig::default();
    let r = ExtractionConfig::relaxed();
    assert_eq!(d, r);
}

#[test]
fn test_config_strict_tighter_than_relaxed() {
    let s = ExtractionConfig::strict();
    let r = ExtractionConfig::relaxed();
    assert!(s.max_repro_lines <= r.max_repro_lines);
    assert!(s.min_reduction_ratio >= r.min_reduction_ratio);
    assert!(s.max_triage_latency_ns <= r.max_triage_latency_ns);
}

// ---------------------------------------------------------------------------
// ExtractionVerdict
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_complete_no_attention() {
    assert!(!ExtractionVerdict::Complete.needs_attention());
}

#[test]
fn test_verdict_all_non_complete_need_attention() {
    let needing = [
        ExtractionVerdict::PartialReduction,
        ExtractionVerdict::IncompleteCoverage,
        ExtractionVerdict::TriageLatencyExceeded,
        ExtractionVerdict::NoInputs,
        ExtractionVerdict::MultipleIssues,
    ];
    for v in &needing {
        assert!(v.needs_attention(), "{:?} should need attention", v);
    }
}

#[test]
fn test_verdict_display_complete() {
    assert_eq!(ExtractionVerdict::Complete.to_string(), "complete");
}

#[test]
fn test_verdict_display_partial_reduction() {
    assert_eq!(ExtractionVerdict::PartialReduction.to_string(), "partial_reduction");
}

#[test]
fn test_verdict_display_no_inputs() {
    assert_eq!(ExtractionVerdict::NoInputs.to_string(), "no_inputs");
}

#[test]
fn test_verdict_ordering() {
    assert!(ExtractionVerdict::Complete < ExtractionVerdict::MultipleIssues);
}

// ---------------------------------------------------------------------------
// ExtractionEngine lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_engine_empty_no_inputs() {
    let engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    let report = engine.evaluate(epoch());
    assert_eq!(report.verdict, ExtractionVerdict::NoInputs);
}

#[test]
fn test_engine_with_good_repro_complete() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new("i1".into(), FailureCategory::RenderCrash, 200, 5, 3));
    engine.add_repro(MinimizedRepro::new(
        "i1".into(), MinimizationStrategy::DeltaDebugging, 20, 200, true, 1_000_000,
    ));
    let report = engine.evaluate(epoch());
    assert_eq!(report.verdict, ExtractionVerdict::Complete);
}

#[test]
fn test_engine_partial_reduction_low_ratio() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new("i1".into(), FailureCategory::RenderCrash, 200, 5, 3));
    engine.add_repro(MinimizedRepro::new(
        "i1".into(), MinimizationStrategy::DeltaDebugging, 150, 200, true, 1_000_000,
    ));
    let report = engine.evaluate(epoch());
    assert_eq!(report.verdict, ExtractionVerdict::PartialReduction);
}

#[test]
fn test_engine_partial_reduction_too_large() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new("i1".into(), FailureCategory::RenderCrash, 1000, 50, 20));
    engine.add_repro(MinimizedRepro::new(
        "i1".into(), MinimizationStrategy::DeltaDebugging, 60, 1000, true, 1_000_000,
    ));
    let report = engine.evaluate(epoch());
    assert_eq!(report.verdict, ExtractionVerdict::PartialReduction);
}

#[test]
fn test_engine_triage_latency_exceeded() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new("i1".into(), FailureCategory::RenderCrash, 200, 5, 3));
    engine.add_repro(MinimizedRepro::new(
        "i1".into(), MinimizationStrategy::DeltaDebugging, 20, 200, true,
        100_000_000_000, // 100 seconds
    ));
    let report = engine.evaluate(epoch());
    assert_eq!(report.verdict, ExtractionVerdict::TriageLatencyExceeded);
}

#[test]
fn test_engine_incomplete_coverage() {
    let mut config = ExtractionConfig::relaxed();
    config.required_categories.insert(FailureCategory::HydrationMismatch);
    let mut engine = ExtractionEngine::new(config);
    engine.add_input(ReproInput::new("i1".into(), FailureCategory::RenderCrash, 200, 5, 3));
    let report = engine.evaluate(epoch());
    assert_eq!(report.verdict, ExtractionVerdict::IncompleteCoverage);
    assert!(report.categories_missing.contains(&FailureCategory::HydrationMismatch));
}

#[test]
fn test_engine_multiple_issues() {
    let mut config = ExtractionConfig::relaxed();
    config.required_categories.insert(FailureCategory::HydrationMismatch);
    let mut engine = ExtractionEngine::new(config);
    engine.add_input(ReproInput::new("i1".into(), FailureCategory::RenderCrash, 200, 5, 3));
    engine.add_repro(MinimizedRepro::new(
        "i1".into(), MinimizationStrategy::DeltaDebugging, 150, 200, true, 1_000_000,
    ));
    let report = engine.evaluate(epoch());
    assert_eq!(report.verdict, ExtractionVerdict::MultipleIssues);
}

#[test]
fn test_engine_avg_reduction_ratio_computed() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new("i1".into(), FailureCategory::RenderCrash, 200, 5, 3));
    engine.add_repro(MinimizedRepro::new(
        "i1".into(), MinimizationStrategy::DeltaDebugging, 20, 200, true, 1_000_000,
    ));
    engine.add_repro(MinimizedRepro::new(
        "i2".into(), MinimizationStrategy::HierarchicalReduction, 50, 200, true, 1_000_000,
    ));
    let report = engine.evaluate(epoch());
    // 900_000 + 750_000 = 1_650_000 / 2 = 825_000
    assert_eq!(report.avg_reduction_ratio_millionths, 825_000);
}

#[test]
fn test_engine_categories_covered_tracking() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new("i1".into(), FailureCategory::RenderCrash, 200, 5, 3));
    engine.add_input(ReproInput::new("i2".into(), FailureCategory::HookOrdering, 300, 8, 4));
    let report = engine.evaluate(epoch());
    assert!(report.categories_covered.contains(&FailureCategory::RenderCrash));
    assert!(report.categories_covered.contains(&FailureCategory::HookOrdering));
    assert_eq!(report.categories_covered.len(), 2);
}

#[test]
fn test_engine_finding_stored() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new("i1".into(), FailureCategory::RenderCrash, 200, 5, 3));
    engine.add_finding(TriageFinding {
        category: FailureCategory::RenderCrash,
        owner: TriageOwner::EngineRuntime,
        severity: TriageSeverity::Error,
        summary: "Crash on mount".into(),
        repro_hash: None,
        recommended_action: "Fix mount lifecycle".into(),
    });
    let report = engine.evaluate(epoch());
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].severity, TriageSeverity::Error);
}

#[test]
fn test_engine_epoch_recorded() {
    let engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    let report = engine.evaluate(SecurityEpoch::from_raw(99));
    assert_eq!(report.epoch, SecurityEpoch::from_raw(99));
}

// ---------------------------------------------------------------------------
// Content hash determinism
// ---------------------------------------------------------------------------

#[test]
fn test_report_hash_deterministic_two_evaluations() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new("i1".into(), FailureCategory::RenderCrash, 200, 5, 3));
    let r1 = engine.evaluate(epoch());
    let r2 = engine.evaluate(epoch());
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn test_report_hash_changes_when_input_added() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new("i1".into(), FailureCategory::RenderCrash, 200, 5, 3));
    let r1 = engine.evaluate(epoch());
    engine.add_input(ReproInput::new("i2".into(), FailureCategory::HookOrdering, 300, 8, 4));
    let r2 = engine.evaluate(epoch());
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn test_report_hash_changes_with_epoch() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new("i1".into(), FailureCategory::RenderCrash, 200, 5, 3));
    let r1 = engine.evaluate(SecurityEpoch::from_raw(1));
    let r2 = engine.evaluate(SecurityEpoch::from_raw(2));
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// E2E scenarios
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_full_pass_multiple_categories() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new("i1".into(), FailureCategory::RenderCrash, 200, 5, 3));
    engine.add_input(ReproInput::new("i2".into(), FailureCategory::HydrationMismatch, 300, 8, 4));
    engine.add_repro(MinimizedRepro::new(
        "i1".into(), MinimizationStrategy::DeltaDebugging, 20, 200, true, 1_000_000,
    ));
    engine.add_repro(MinimizedRepro::new(
        "i2".into(), MinimizationStrategy::HierarchicalReduction, 30, 300, true, 2_000_000,
    ));
    let report = engine.evaluate(epoch());
    assert_eq!(report.verdict, ExtractionVerdict::Complete);
    assert!(report.categories_covered.len() >= 2);
}

#[test]
fn test_e2e_strict_empty_is_multiple_issues() {
    let engine = ExtractionEngine::new(ExtractionConfig::strict());
    let report = engine.evaluate(epoch());
    // NoInputs + IncompleteCoverage = MultipleIssues
    assert_eq!(report.verdict, ExtractionVerdict::MultipleIssues);
}

#[test]
fn test_e2e_all_strategies_pass() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    engine.add_input(ReproInput::new("i1".into(), FailureCategory::RenderCrash, 200, 5, 3));
    let strategies = [
        MinimizationStrategy::DeltaDebugging,
        MinimizationStrategy::HierarchicalReduction,
        MinimizationStrategy::DependencyStripping,
        MinimizationStrategy::StateSlicing,
        MinimizationStrategy::PropElimination,
    ];
    for (i, strat) in strategies.iter().enumerate() {
        engine.add_repro(MinimizedRepro::new(
            format!("i{}", i + 1), *strat, 10, 200, true, 500_000,
        ));
    }
    let report = engine.evaluate(epoch());
    assert_eq!(report.verdict, ExtractionVerdict::Complete);
    assert_eq!(report.repros.len(), 5);
}

#[test]
fn test_e2e_finding_with_repro_hash() {
    let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
    let inp = ReproInput::new("i1".into(), FailureCategory::JsxTransform, 400, 12, 6);
    engine.add_input(inp);
    let repro = MinimizedRepro::new(
        "i1".into(), MinimizationStrategy::DeltaDebugging, 15, 400, true, 1_000_000,
    );
    let hash = repro.repro_hash.clone();
    engine.add_repro(repro);
    engine.add_finding(TriageFinding {
        category: FailureCategory::JsxTransform,
        owner: TriageOwner::ParserCompiler,
        severity: TriageSeverity::Warning,
        summary: "JSX classic transform emitting invalid output".into(),
        repro_hash: Some(hash),
        recommended_action: "Check classic mode pragma handling".into(),
    });
    let report = engine.evaluate(epoch());
    assert_eq!(report.verdict, ExtractionVerdict::Complete);
    assert_eq!(report.findings.len(), 1);
    assert!(report.findings[0].repro_hash.is_some());
}

#[test]
fn test_e2e_triage_routing_all_categories() {
    for cat in FailureCategory::all() {
        let owner = ExtractionEngine::default_owner(*cat);
        // Every category must route to some owner.
        let owner_str = owner.to_string();
        assert!(!owner_str.is_empty(), "owner for {:?} should be non-empty", cat);
    }
}
