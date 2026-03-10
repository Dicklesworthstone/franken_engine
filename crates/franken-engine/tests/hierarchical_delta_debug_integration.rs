//! Integration tests for the `hierarchical_delta_debug` module.
//!
//! Exercises the public API from outside the crate: DefectClass display/serde/ord,
//! ReductionLevel display/serde/all(), ReductionStrategy display/serde,
//! ReductionConfig default/display/serde/config_hash determinism, ProgramFragment
//! new/size/mark_tested/content_hash/display/serde, StepOutcome display/serde,
//! ReductionStep content_hash/display/serde, DeltaDebugger new/fragment/try_remove/
//! reduce/build_repro/steps/summary, MinimalRepro reduction_percentage/display/serde,
//! ReductionSummary serde, ReductionEvidenceInventory from_repros,
//! DeltaDebugSpecimenFamily display/serde, delta_debug_corpus, run_delta_debug_corpus,
//! and edge cases (empty source, single-char, already minimal).

use frankenengine_engine::hierarchical_delta_debug::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn sample_program() -> &'static str {
    "function add(a, b) {\n  const result = a + b;\n  console.log(result);\n  return result;\n}\n\nfunction mul(a, b) {\n  return a * b;\n}\n\nadd(1, 2);\nmul(3, 4);"
}

fn make_repro(
    defect: DefectClass,
    original_size: u32,
    reduced_size: u32,
    ratio: u64,
    total_steps: u32,
    progress_steps: u32,
) -> MinimalRepro {
    MinimalRepro {
        repro_id: "mr-test".into(),
        schema_version: REDUCTION_SCHEMA_VERSION.to_string(),
        defect_class: defect,
        source: "x".into(),
        original_size,
        reduced_size,
        reduction_ratio_millionths: ratio,
        total_steps,
        progress_steps,
        original_fragment_count: 10,
        remaining_fragment_count: 3,
        essential_fragment_ids: vec![],
        config: ReductionConfig::default(),
        epoch: test_epoch(),
        stable: true,
    }
}

// ---------------------------------------------------------------------------
// DefectClass
// ---------------------------------------------------------------------------

#[test]
fn test_defect_class_display_crash() {
    assert_eq!(format!("{}", DefectClass::Crash), "crash");
}

#[test]
fn test_defect_class_display_wrong_output() {
    assert_eq!(format!("{}", DefectClass::WrongOutput), "wrong-output");
}

#[test]
fn test_defect_class_display_perf_regression() {
    assert_eq!(
        format!("{}", DefectClass::PerformanceRegression),
        "perf-regression"
    );
}

#[test]
fn test_defect_class_display_ifc_violation() {
    assert_eq!(format!("{}", DefectClass::IfcViolation), "ifc-violation");
}

#[test]
fn test_defect_class_display_determinism_failure() {
    assert_eq!(
        format!("{}", DefectClass::DeterminismFailure),
        "determinism-failure"
    );
}

#[test]
fn test_defect_class_display_type_unsoundness() {
    assert_eq!(
        format!("{}", DefectClass::TypeUnsoundness),
        "type-unsoundness"
    );
}

#[test]
fn test_defect_class_display_module_resolution() {
    assert_eq!(
        format!("{}", DefectClass::ModuleResolutionFailure),
        "module-resolution"
    );
}

#[test]
fn test_defect_class_display_memory_safety() {
    assert_eq!(
        format!("{}", DefectClass::MemorySafetyViolation),
        "memory-safety"
    );
}

#[test]
fn test_defect_class_display_timeout() {
    assert_eq!(format!("{}", DefectClass::Timeout), "timeout");
}

#[test]
fn test_defect_class_display_assertion_failure() {
    assert_eq!(
        format!("{}", DefectClass::AssertionFailure),
        "assertion-failure"
    );
}

#[test]
fn test_defect_class_display_custom() {
    let dc = DefectClass::Custom {
        tag: "my-bug".into(),
    };
    assert_eq!(format!("{dc}"), "custom(my-bug)");
}

#[test]
fn test_defect_class_serde_roundtrip_all_variants() {
    let variants = vec![
        DefectClass::Crash,
        DefectClass::WrongOutput,
        DefectClass::PerformanceRegression,
        DefectClass::IfcViolation,
        DefectClass::DeterminismFailure,
        DefectClass::TypeUnsoundness,
        DefectClass::ModuleResolutionFailure,
        DefectClass::MemorySafetyViolation,
        DefectClass::Timeout,
        DefectClass::AssertionFailure,
        DefectClass::Custom { tag: "fuzz".into() },
    ];
    for dc in &variants {
        let json = serde_json::to_string(dc).unwrap();
        let back: DefectClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*dc, back);
    }
}

#[test]
fn test_defect_class_ord_crash_lt_wrong_output() {
    assert!(DefectClass::Crash < DefectClass::WrongOutput);
}

#[test]
fn test_defect_class_ord_timeout_lt_assertion() {
    assert!(DefectClass::Timeout < DefectClass::AssertionFailure);
}

#[test]
fn test_defect_class_clone_eq() {
    let dc = DefectClass::IfcViolation;
    let cloned = dc.clone();
    assert_eq!(dc, cloned);
}

// ---------------------------------------------------------------------------
// ReductionLevel
// ---------------------------------------------------------------------------

#[test]
fn test_reduction_level_all_returns_five() {
    let levels = ReductionLevel::all();
    assert_eq!(levels.len(), 5);
}

#[test]
fn test_reduction_level_all_order() {
    let levels = ReductionLevel::all();
    assert_eq!(levels[0], ReductionLevel::Module);
    assert_eq!(levels[1], ReductionLevel::Declaration);
    assert_eq!(levels[2], ReductionLevel::Statement);
    assert_eq!(levels[3], ReductionLevel::Expression);
    assert_eq!(levels[4], ReductionLevel::Token);
}

#[test]
fn test_reduction_level_display_values() {
    assert_eq!(format!("{}", ReductionLevel::Module), "module");
    assert_eq!(format!("{}", ReductionLevel::Declaration), "declaration");
    assert_eq!(format!("{}", ReductionLevel::Statement), "statement");
    assert_eq!(format!("{}", ReductionLevel::Expression), "expression");
    assert_eq!(format!("{}", ReductionLevel::Token), "token");
}

#[test]
fn test_reduction_level_serde_roundtrip() {
    for level in ReductionLevel::all() {
        let json = serde_json::to_string(level).unwrap();
        let back: ReductionLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(*level, back);
    }
}

#[test]
fn test_reduction_level_ord() {
    assert!(ReductionLevel::Module < ReductionLevel::Token);
    assert!(ReductionLevel::Statement < ReductionLevel::Expression);
}

// ---------------------------------------------------------------------------
// ReductionStrategy
// ---------------------------------------------------------------------------

#[test]
fn test_reduction_strategy_display_ddmin() {
    assert_eq!(format!("{}", ReductionStrategy::DeltaDebugging), "ddmin");
}

#[test]
fn test_reduction_strategy_display_hierarchical() {
    assert_eq!(
        format!("{}", ReductionStrategy::HierarchicalDelta),
        "hierarchical"
    );
}

#[test]
fn test_reduction_strategy_display_structured() {
    assert_eq!(
        format!("{}", ReductionStrategy::StructuredReduction),
        "structured"
    );
}

#[test]
fn test_reduction_strategy_display_semantic() {
    assert_eq!(
        format!("{}", ReductionStrategy::SemanticPreserving),
        "semantic"
    );
}

#[test]
fn test_reduction_strategy_display_type_directed() {
    assert_eq!(
        format!("{}", ReductionStrategy::TypeDirected),
        "type-directed"
    );
}

#[test]
fn test_reduction_strategy_serde_roundtrip_all() {
    let strategies = vec![
        ReductionStrategy::DeltaDebugging,
        ReductionStrategy::HierarchicalDelta,
        ReductionStrategy::StructuredReduction,
        ReductionStrategy::SemanticPreserving,
        ReductionStrategy::TypeDirected,
    ];
    for s in &strategies {
        let json = serde_json::to_string(s).unwrap();
        let back: ReductionStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// ReductionConfig
// ---------------------------------------------------------------------------

#[test]
fn test_config_default_max_steps() {
    let c = ReductionConfig::default();
    assert_eq!(c.max_steps, DEFAULT_MAX_REDUCTION_STEPS);
}

#[test]
fn test_config_default_min_program_size() {
    let c = ReductionConfig::default();
    assert_eq!(c.min_program_size, DEFAULT_MIN_PROGRAM_SIZE);
}

#[test]
fn test_config_default_max_time() {
    let c = ReductionConfig::default();
    assert_eq!(c.max_time_ms, DEFAULT_MAX_REDUCTION_TIME_MS);
}

#[test]
fn test_config_default_preserve_flags() {
    let c = ReductionConfig::default();
    assert!(c.preserve_syntax);
    assert!(c.preserve_imports);
}

#[test]
fn test_config_default_strategies_non_empty() {
    let c = ReductionConfig::default();
    assert!(!c.strategies.is_empty());
}

#[test]
fn test_config_default_levels_non_empty() {
    let c = ReductionConfig::default();
    assert!(!c.levels.is_empty());
}

#[test]
fn test_config_default_emit_intermediates_false() {
    let c = ReductionConfig::default();
    assert!(!c.emit_intermediates);
}

#[test]
fn test_config_hash_deterministic() {
    let c1 = ReductionConfig::default();
    let c2 = ReductionConfig::default();
    assert_eq!(c1.config_hash(), c2.config_hash());
}

#[test]
fn test_config_hash_starts_with_rc() {
    let c = ReductionConfig::default();
    assert!(c.config_hash().starts_with("rc-"));
}

#[test]
fn test_config_hash_differs_on_max_steps() {
    let c1 = ReductionConfig::default();
    let c2 = ReductionConfig {
        max_steps: 500,
        ..ReductionConfig::default()
    };
    assert_ne!(c1.config_hash(), c2.config_hash());
}

#[test]
fn test_config_hash_differs_on_preserve_syntax() {
    let c1 = ReductionConfig::default();
    let c2 = ReductionConfig {
        preserve_syntax: false,
        ..ReductionConfig::default()
    };
    assert_ne!(c1.config_hash(), c2.config_hash());
}

#[test]
fn test_config_hash_differs_on_preserve_imports() {
    let c1 = ReductionConfig::default();
    let c2 = ReductionConfig {
        preserve_imports: false,
        ..ReductionConfig::default()
    };
    assert_ne!(c1.config_hash(), c2.config_hash());
}

#[test]
fn test_config_display_contains_keyword() {
    let c = ReductionConfig::default();
    let s = format!("{c}");
    assert!(s.contains("reduction-config"));
    assert!(s.contains("max-steps="));
}

#[test]
fn test_config_serde_roundtrip() {
    let c = ReductionConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: ReductionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn test_config_serde_custom_values() {
    let c = ReductionConfig {
        max_steps: 50,
        min_program_size: 5,
        max_time_ms: 1000,
        preserve_syntax: false,
        preserve_imports: false,
        strategies: vec![ReductionStrategy::DeltaDebugging],
        levels: vec![ReductionLevel::Statement],
        emit_intermediates: true,
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: ReductionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// ProgramFragment
// ---------------------------------------------------------------------------

#[test]
fn test_fragment_new_basic() {
    let frag = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
    assert!(frag.fragment_id.starts_with("frag-"));
    assert_eq!(frag.level, ReductionLevel::Statement);
    assert_eq!(frag.source, "let x = 1;");
    assert_eq!(frag.start_offset, 0);
    assert_eq!(frag.end_offset, 11);
    assert!(frag.included);
    assert!(!frag.tested);
    assert!(!frag.removable);
    assert!(frag.parent_id.is_none());
}

#[test]
fn test_fragment_size() {
    let frag = ProgramFragment::new(ReductionLevel::Statement, "abc", 10, 25);
    assert_eq!(frag.size(), 15);
}

#[test]
fn test_fragment_size_zero() {
    let frag = ProgramFragment::new(ReductionLevel::Token, "", 5, 5);
    assert_eq!(frag.size(), 0);
}

#[test]
fn test_fragment_mark_tested_removable() {
    let mut frag = ProgramFragment::new(ReductionLevel::Statement, "let x;", 0, 6);
    frag.mark_tested(true);
    assert!(frag.tested);
    assert!(frag.removable);
    assert!(!frag.included);
}

#[test]
fn test_fragment_mark_tested_essential() {
    let mut frag = ProgramFragment::new(ReductionLevel::Statement, "return x;", 0, 9);
    frag.mark_tested(false);
    assert!(frag.tested);
    assert!(!frag.removable);
    assert!(frag.included);
}

#[test]
fn test_fragment_id_deterministic_same_offsets() {
    let f1 = ProgramFragment::new(ReductionLevel::Statement, "aaa", 0, 11);
    let f2 = ProgramFragment::new(ReductionLevel::Statement, "bbb", 0, 11);
    // Same level and offsets produce same ID regardless of content
    assert_eq!(f1.fragment_id, f2.fragment_id);
}

#[test]
fn test_fragment_id_differs_by_level() {
    let f1 = ProgramFragment::new(ReductionLevel::Statement, "x", 0, 10);
    let f2 = ProgramFragment::new(ReductionLevel::Declaration, "x", 0, 10);
    assert_ne!(f1.fragment_id, f2.fragment_id);
}

#[test]
fn test_fragment_id_differs_by_offset() {
    let f1 = ProgramFragment::new(ReductionLevel::Statement, "x", 0, 10);
    let f2 = ProgramFragment::new(ReductionLevel::Statement, "x", 5, 15);
    assert_ne!(f1.fragment_id, f2.fragment_id);
}

#[test]
fn test_fragment_display_contains_level_and_offsets() {
    let frag = ProgramFragment::new(ReductionLevel::Declaration, "fn foo() {}", 10, 21);
    let s = format!("{frag}");
    assert!(s.contains("fragment"));
    assert!(s.contains("declaration"));
    assert!(s.contains("10-21"));
    assert!(s.contains("11B"));
}

#[test]
fn test_fragment_serde_roundtrip() {
    let frag = ProgramFragment::new(ReductionLevel::Expression, "a + b", 5, 10);
    let json = serde_json::to_string(&frag).unwrap();
    let back: ProgramFragment = serde_json::from_str(&json).unwrap();
    assert_eq!(frag, back);
}

#[test]
fn test_fragment_serde_with_parent_id() {
    let mut frag = ProgramFragment::new(ReductionLevel::Statement, "x;", 0, 2);
    frag.parent_id = Some("frag-parent".into());
    let json = serde_json::to_string(&frag).unwrap();
    let back: ProgramFragment = serde_json::from_str(&json).unwrap();
    assert_eq!(frag.parent_id, back.parent_id);
}

// ---------------------------------------------------------------------------
// StepOutcome
// ---------------------------------------------------------------------------

#[test]
fn test_step_outcome_display_all() {
    assert_eq!(
        format!("{}", StepOutcome::DefectPreserved),
        "defect-preserved"
    );
    assert_eq!(format!("{}", StepOutcome::DefectLost), "defect-lost");
    assert_eq!(format!("{}", StepOutcome::SyntaxError), "syntax-error");
    assert_eq!(format!("{}", StepOutcome::TestTimeout), "test-timeout");
    assert_eq!(format!("{}", StepOutcome::Skipped), "skipped");
}

#[test]
fn test_step_outcome_serde_roundtrip() {
    let outcomes = vec![
        StepOutcome::DefectPreserved,
        StepOutcome::DefectLost,
        StepOutcome::SyntaxError,
        StepOutcome::TestTimeout,
        StepOutcome::Skipped,
    ];
    for o in &outcomes {
        let json = serde_json::to_string(o).unwrap();
        let back: StepOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, back);
    }
}

// ---------------------------------------------------------------------------
// ReductionStep
// ---------------------------------------------------------------------------

#[test]
fn test_reduction_step_content_hash_deterministic() {
    let step = ReductionStep {
        step_number: 1,
        level: ReductionLevel::Statement,
        strategy: ReductionStrategy::DeltaDebugging,
        removed_fragment_ids: vec!["frag-abc".into()],
        outcome: StepOutcome::DefectPreserved,
        program_size_after: 50,
        progress: true,
    };
    let h1 = step.content_hash();
    let h2 = step.content_hash();
    assert_eq!(h1, h2);
    assert!(h1.starts_with("rs-"));
}

#[test]
fn test_reduction_step_content_hash_differs_by_step_number() {
    let s1 = ReductionStep {
        step_number: 1,
        level: ReductionLevel::Statement,
        strategy: ReductionStrategy::DeltaDebugging,
        removed_fragment_ids: vec![],
        outcome: StepOutcome::DefectLost,
        program_size_after: 100,
        progress: false,
    };
    let s2 = ReductionStep {
        step_number: 2,
        ..s1.clone()
    };
    assert_ne!(s1.content_hash(), s2.content_hash());
}

#[test]
fn test_reduction_step_display_format() {
    let step = ReductionStep {
        step_number: 7,
        level: ReductionLevel::Declaration,
        strategy: ReductionStrategy::HierarchicalDelta,
        removed_fragment_ids: vec!["a".into(), "b".into(), "c".into()],
        outcome: StepOutcome::DefectPreserved,
        program_size_after: 200,
        progress: true,
    };
    let s = format!("{step}");
    assert!(s.contains("step #7"));
    assert!(s.contains("declaration"));
    assert!(s.contains("hierarchical"));
    assert!(s.contains("removed=3"));
    assert!(s.contains("defect-preserved"));
}

#[test]
fn test_reduction_step_serde_roundtrip() {
    let step = ReductionStep {
        step_number: 5,
        level: ReductionLevel::Expression,
        strategy: ReductionStrategy::SemanticPreserving,
        removed_fragment_ids: vec!["frag-1".into(), "frag-2".into()],
        outcome: StepOutcome::SyntaxError,
        program_size_after: 75,
        progress: false,
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: ReductionStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, back);
}

// ---------------------------------------------------------------------------
// DeltaDebugger
// ---------------------------------------------------------------------------

#[test]
fn test_debugger_new_initial_state() {
    let debugger = DeltaDebugger::new(
        "let x = 1;",
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );
    assert_eq!(debugger.fragment_count(), 0);
    assert!(debugger.steps().is_empty());
}

#[test]
fn test_debugger_fragment_creates_fragments() {
    let mut debugger = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );
    debugger.fragment();
    assert!(debugger.fragment_count() > 0);
}

#[test]
fn test_debugger_fragment_declaration_level_non_empty() {
    let mut debugger = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );
    debugger.fragment();
    let decl_frags = debugger.fragments_at_level(ReductionLevel::Declaration);
    assert!(!decl_frags.is_empty());
}

#[test]
fn test_debugger_fragment_statement_level_non_empty() {
    let mut debugger = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );
    debugger.fragment();
    let stmt_frags = debugger.fragments_at_level(ReductionLevel::Statement);
    assert!(!stmt_frags.is_empty());
}

#[test]
fn test_debugger_fragment_statement_has_parent() {
    let mut debugger = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );
    debugger.fragment();
    let stmt_frags = debugger.fragments_at_level(ReductionLevel::Statement);
    // Statement fragments should have parent IDs linking to declaration fragments
    for frag in &stmt_frags {
        assert!(
            frag.parent_id.is_some(),
            "Statement fragment should have a parent_id"
        );
    }
}

#[test]
fn test_debugger_try_remove_defect_preserved() {
    let mut debugger = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );
    debugger.fragment();

    let decl_ids: Vec<String> = debugger
        .fragments_at_level(ReductionLevel::Declaration)
        .iter()
        .take(1)
        .map(|f| f.fragment_id.clone())
        .collect();

    if !decl_ids.is_empty() {
        let outcome = debugger.try_remove(&decl_ids, |_| StepOutcome::DefectPreserved);
        assert_eq!(outcome, StepOutcome::DefectPreserved);
        assert_eq!(debugger.steps().len(), 1);
        assert!(debugger.steps()[0].progress);
    }
}

#[test]
fn test_debugger_try_remove_defect_lost() {
    let mut debugger = DeltaDebugger::new(
        sample_program(),
        DefectClass::WrongOutput,
        ReductionConfig::default(),
        test_epoch(),
    );
    debugger.fragment();

    let decl_ids: Vec<String> = debugger
        .fragments_at_level(ReductionLevel::Declaration)
        .iter()
        .take(1)
        .map(|f| f.fragment_id.clone())
        .collect();

    if !decl_ids.is_empty() {
        let outcome = debugger.try_remove(&decl_ids, |_| StepOutcome::DefectLost);
        assert_eq!(outcome, StepOutcome::DefectLost);
        assert!(!debugger.steps()[0].progress);
    }
}

#[test]
fn test_debugger_try_remove_syntax_error_oracle() {
    let mut debugger = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );
    debugger.fragment();

    let decl_ids: Vec<String> = debugger
        .fragments_at_level(ReductionLevel::Declaration)
        .iter()
        .take(1)
        .map(|f| f.fragment_id.clone())
        .collect();

    if !decl_ids.is_empty() {
        let outcome = debugger.try_remove(&decl_ids, |_| StepOutcome::SyntaxError);
        assert_eq!(outcome, StepOutcome::SyntaxError);
        assert!(!debugger.steps()[0].progress);
    }
}

#[test]
fn test_debugger_reduce_with_bug_oracle() {
    let source =
        "line1_safe\nline2_safe\nbug_trigger\nline3_safe\nline4_safe\n\nblock2_line1\nblock2_line2";
    let mut debugger = DeltaDebugger::new(
        source,
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );

    let repro = debugger.reduce(|s| {
        if s.contains("bug") {
            StepOutcome::DefectPreserved
        } else {
            StepOutcome::DefectLost
        }
    });

    assert!(repro.source.contains("bug"));
    assert!(repro.reduced_size <= repro.original_size);
    assert!(repro.repro_id.starts_with("mr-"));
    assert!(repro.stable);
}

#[test]
fn test_debugger_reduce_preserves_essential_content() {
    let source = "import React from 'react';\n\nfunction App() {\n  return <div>Hello</div>;\n}\n\nexport default App;";
    let mut debugger = DeltaDebugger::new(
        source,
        DefectClass::WrongOutput,
        ReductionConfig::default(),
        test_epoch(),
    );

    let repro = debugger.reduce(|s| {
        if s.contains("App") {
            StepOutcome::DefectPreserved
        } else {
            StepOutcome::DefectLost
        }
    });

    assert!(repro.source.contains("App"));
}

#[test]
fn test_debugger_reduce_all_essential() {
    // Oracle always says defect lost => nothing can be removed
    let mut debugger = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );

    let repro = debugger.reduce(|_| StepOutcome::DefectLost);
    // Nothing removed, so progress_steps should be 0
    assert_eq!(repro.progress_steps, 0);
}

#[test]
fn test_debugger_reduce_all_removable() {
    // Oracle always says defect preserved => everything removable
    let mut debugger = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );

    let repro = debugger.reduce(|_| StepOutcome::DefectPreserved);
    assert!(repro.reduced_size <= repro.original_size);
    assert!(repro.progress_steps > 0);
}

#[test]
fn test_debugger_max_steps_respected() {
    let config = ReductionConfig {
        max_steps: 2,
        ..ReductionConfig::default()
    };
    let mut debugger =
        DeltaDebugger::new(sample_program(), DefectClass::Crash, config, test_epoch());

    let _repro = debugger.reduce(|_| StepOutcome::DefectLost);
    assert!(debugger.steps().len() <= 2);
}

#[test]
fn test_debugger_build_repro_without_reduction() {
    let mut debugger = DeltaDebugger::new(
        "hello world test program",
        DefectClass::Timeout,
        ReductionConfig::default(),
        test_epoch(),
    );
    debugger.fragment();
    let repro = debugger.build_repro();
    assert!(repro.repro_id.starts_with("mr-"));
    assert_eq!(repro.defect_class, DefectClass::Timeout);
    assert_eq!(repro.total_steps, 0);
    assert_eq!(repro.progress_steps, 0);
}

#[test]
fn test_debugger_steps_empty_before_reduction() {
    let debugger = DeltaDebugger::new(
        "test",
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );
    assert!(debugger.steps().is_empty());
}

#[test]
fn test_debugger_steps_populated_after_reduction() {
    let mut debugger = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );

    let _repro = debugger.reduce(|_| StepOutcome::DefectLost);
    assert!(!debugger.steps().is_empty());
}

#[test]
fn test_debugger_summary_fields() {
    let mut debugger = DeltaDebugger::new(
        sample_program(),
        DefectClass::DeterminismFailure,
        ReductionConfig::default(),
        test_epoch(),
    );

    let _repro = debugger.reduce(|s| {
        if s.contains("add") {
            StepOutcome::DefectPreserved
        } else {
            StepOutcome::DefectLost
        }
    });

    let summary = debugger.summary();
    assert_eq!(summary.defect_class, DefectClass::DeterminismFailure);
    assert_eq!(summary.original_size, sample_program().len() as u32);
    assert!(summary.total_steps > 0);
    assert!(!summary.levels_attempted.is_empty());
    assert!(!summary.strategies_used.is_empty());
}

#[test]
fn test_debugger_summary_serde_roundtrip() {
    let mut debugger = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );
    let _repro = debugger.reduce(|_| StepOutcome::DefectLost);
    let summary = debugger.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: ReductionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// MinimalRepro
// ---------------------------------------------------------------------------

#[test]
fn test_minimal_repro_reduction_percentage_75() {
    let repro = make_repro(DefectClass::Crash, 100, 25, 750_000, 10, 5);
    assert_eq!(repro.reduction_percentage(), 75);
}

#[test]
fn test_minimal_repro_reduction_percentage_zero_original() {
    let repro = make_repro(DefectClass::Crash, 0, 0, 0, 0, 0);
    assert_eq!(repro.reduction_percentage(), 0);
}

#[test]
fn test_minimal_repro_reduction_percentage_no_reduction() {
    let repro = make_repro(DefectClass::Crash, 100, 100, 0, 5, 0);
    assert_eq!(repro.reduction_percentage(), 0);
}

#[test]
fn test_minimal_repro_reduction_percentage_full_reduction() {
    let repro = make_repro(DefectClass::Crash, 100, 0, 1_000_000, 10, 10);
    assert_eq!(repro.reduction_percentage(), 100);
}

#[test]
fn test_minimal_repro_display_format() {
    let repro = make_repro(DefectClass::WrongOutput, 200, 50, 750_000, 15, 8);
    let s = format!("{repro}");
    assert!(s.contains("minimal-repro"));
    assert!(s.contains("wrong-output"));
    assert!(s.contains("200B"));
    assert!(s.contains("50B"));
}

#[test]
fn test_minimal_repro_serde_roundtrip() {
    let repro = make_repro(DefectClass::IfcViolation, 500, 100, 800_000, 20, 12);
    let json = serde_json::to_string(&repro).unwrap();
    let back: MinimalRepro = serde_json::from_str(&json).unwrap();
    assert_eq!(repro, back);
}

#[test]
fn test_minimal_repro_from_reduce_pipeline() {
    let mut debugger = DeltaDebugger::new(
        "let a = 1;\nlet b = 2;\nlet c = bug;\nlet d = 4;",
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );
    let repro = debugger.reduce(|s| {
        if s.contains("bug") {
            StepOutcome::DefectPreserved
        } else {
            StepOutcome::DefectLost
        }
    });
    assert!(repro.source.contains("bug"));
    assert_eq!(repro.schema_version, REDUCTION_SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// ReductionSummary
// ---------------------------------------------------------------------------

#[test]
fn test_reduction_summary_serde_standalone() {
    let summary = ReductionSummary {
        repro_id: "mr-standalone".into(),
        defect_class: DefectClass::MemorySafetyViolation,
        original_size: 1000,
        reduced_size: 150,
        reduction_percentage: 85,
        total_steps: 50,
        progress_steps: 20,
        levels_attempted: vec![ReductionLevel::Declaration, ReductionLevel::Statement],
        strategies_used: vec![ReductionStrategy::HierarchicalDelta],
        stable: true,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: ReductionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// ReductionEvidenceInventory
// ---------------------------------------------------------------------------

#[test]
fn test_evidence_inventory_from_empty_repros() {
    let inv = ReductionEvidenceInventory::from_repros(&[]);
    assert_eq!(inv.session_count, 0);
    assert_eq!(inv.total_steps, 0);
    assert_eq!(inv.total_progress_steps, 0);
    assert_eq!(inv.avg_reduction_millionths, 0);
    assert_eq!(inv.component, COMPONENT);
    assert_eq!(inv.schema_version, REDUCTION_SCHEMA_VERSION);
}

#[test]
fn test_evidence_inventory_from_single_repro() {
    let repro = make_repro(DefectClass::Crash, 100, 25, 750_000, 10, 5);
    let inv = ReductionEvidenceInventory::from_repros(&[repro]);
    assert_eq!(inv.session_count, 1);
    assert_eq!(inv.total_steps, 10);
    assert_eq!(inv.total_progress_steps, 5);
    assert_eq!(inv.avg_reduction_millionths, 750_000);
}

#[test]
fn test_evidence_inventory_from_multiple_repros() {
    let r1 = make_repro(DefectClass::Crash, 100, 25, 750_000, 10, 5);
    let r2 = make_repro(DefectClass::WrongOutput, 200, 100, 500_000, 20, 10);
    let inv = ReductionEvidenceInventory::from_repros(&[r1, r2]);
    assert_eq!(inv.session_count, 2);
    assert_eq!(inv.total_steps, 30);
    assert_eq!(inv.total_progress_steps, 15);
    assert_eq!(inv.avg_reduction_millionths, 625_000);
}

#[test]
fn test_evidence_inventory_serde_roundtrip() {
    let repro = make_repro(DefectClass::Timeout, 50, 10, 800_000, 8, 4);
    let inv = ReductionEvidenceInventory::from_repros(&[repro]);
    let json = serde_json::to_string(&inv).unwrap();
    let back: ReductionEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

// ---------------------------------------------------------------------------
// DeltaDebugSpecimenFamily
// ---------------------------------------------------------------------------

#[test]
fn test_specimen_family_display_all() {
    assert_eq!(
        format!("{}", DeltaDebugSpecimenFamily::SingleFile),
        "single-file"
    );
    assert_eq!(
        format!("{}", DeltaDebugSpecimenFamily::MultiStatement),
        "multi-statement"
    );
    assert_eq!(
        format!("{}", DeltaDebugSpecimenFamily::ImportDependent),
        "import-dependent"
    );
    assert_eq!(
        format!("{}", DeltaDebugSpecimenFamily::ReactComponent),
        "react-component"
    );
    assert_eq!(
        format!("{}", DeltaDebugSpecimenFamily::PerformanceLoop),
        "perf-loop"
    );
}

#[test]
fn test_specimen_family_serde_roundtrip_all() {
    let families = vec![
        DeltaDebugSpecimenFamily::SingleFile,
        DeltaDebugSpecimenFamily::MultiStatement,
        DeltaDebugSpecimenFamily::ImportDependent,
        DeltaDebugSpecimenFamily::ReactComponent,
        DeltaDebugSpecimenFamily::PerformanceLoop,
    ];
    for f in &families {
        let json = serde_json::to_string(f).unwrap();
        let back: DeltaDebugSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}

// ---------------------------------------------------------------------------
// Corpus functions
// ---------------------------------------------------------------------------

#[test]
fn test_delta_debug_corpus_non_empty() {
    let corpus = delta_debug_corpus();
    assert!(!corpus.is_empty());
    assert_eq!(corpus.len(), 5);
}

#[test]
fn test_delta_debug_corpus_all_families_present() {
    let corpus = delta_debug_corpus();
    let families: Vec<_> = corpus.iter().map(|(f, _)| f.clone()).collect();
    assert!(families.contains(&DeltaDebugSpecimenFamily::SingleFile));
    assert!(families.contains(&DeltaDebugSpecimenFamily::MultiStatement));
    assert!(families.contains(&DeltaDebugSpecimenFamily::ImportDependent));
    assert!(families.contains(&DeltaDebugSpecimenFamily::ReactComponent));
    assert!(families.contains(&DeltaDebugSpecimenFamily::PerformanceLoop));
}

#[test]
fn test_delta_debug_corpus_descriptions_non_empty() {
    let corpus = delta_debug_corpus();
    for (_, desc) in &corpus {
        assert!(!desc.is_empty());
    }
}

#[test]
fn test_run_delta_debug_corpus_all_pass() {
    let results = run_delta_debug_corpus();
    assert_eq!(results.len(), 5);
    for (_, passed) in &results {
        assert!(*passed);
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_component_constant() {
    assert_eq!(COMPONENT, "hierarchical_delta_debug");
}

#[test]
fn test_schema_version_constant() {
    assert_eq!(REDUCTION_SCHEMA_VERSION, "1.0.0");
}

#[test]
fn test_default_max_reduction_steps() {
    assert_eq!(DEFAULT_MAX_REDUCTION_STEPS, 1000);
}

#[test]
fn test_default_min_program_size() {
    assert_eq!(DEFAULT_MIN_PROGRAM_SIZE, 10);
}

#[test]
fn test_default_max_reduction_time_ms() {
    assert_eq!(DEFAULT_MAX_REDUCTION_TIME_MS, 60_000);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_edge_case_single_line_program() {
    let mut debugger = DeltaDebugger::new(
        "console.log('hello world');",
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );
    let repro = debugger.reduce(|s| {
        if s.contains("hello") {
            StepOutcome::DefectPreserved
        } else {
            StepOutcome::DefectLost
        }
    });
    assert!(repro.source.contains("hello"));
}

#[test]
fn test_edge_case_empty_source_no_fragments() {
    let mut debugger = DeltaDebugger::new(
        "",
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );
    debugger.fragment();
    assert_eq!(debugger.fragment_count(), 0);
}

#[test]
fn test_edge_case_empty_source_reduce() {
    let mut debugger = DeltaDebugger::new(
        "",
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );
    let repro = debugger.reduce(|_| StepOutcome::DefectPreserved);
    assert_eq!(repro.original_size, 0);
    assert_eq!(repro.total_steps, 0);
}

#[test]
fn test_edge_case_very_short_source_below_min() {
    // Source below min_program_size (10 bytes) -- fragments won't be created
    let mut debugger = DeltaDebugger::new(
        "abc",
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );
    debugger.fragment();
    // "abc" is 3 bytes, below DEFAULT_MIN_PROGRAM_SIZE=10
    let decl_frags = debugger.fragments_at_level(ReductionLevel::Declaration);
    assert!(decl_frags.is_empty());
}

#[test]
fn test_edge_case_already_minimal_source() {
    // Oracle says defect is always lost -- nothing can be removed
    let source = "let x = bug_trigger();";
    let mut debugger = DeltaDebugger::new(
        source,
        DefectClass::AssertionFailure,
        ReductionConfig::default(),
        test_epoch(),
    );
    let repro = debugger.reduce(|_| StepOutcome::DefectLost);
    assert_eq!(repro.progress_steps, 0);
}

#[test]
fn test_edge_case_large_multi_block_program() {
    let mut source = String::new();
    for i in 0..20 {
        source.push_str(&format!("function fn{i}() {{ return {i}; }}\n"));
        if i % 3 == 0 {
            source.push('\n');
        }
    }

    let mut debugger = DeltaDebugger::new(
        &source,
        DefectClass::PerformanceRegression,
        ReductionConfig::default(),
        test_epoch(),
    );

    let repro = debugger.reduce(|s| {
        if s.contains("fn5") {
            StepOutcome::DefectPreserved
        } else {
            StepOutcome::DefectLost
        }
    });

    assert!(repro.source.contains("fn5"));
    assert!(repro.reduced_size <= repro.original_size);
}

#[test]
fn test_edge_case_fragment_then_refragment() {
    let mut debugger = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );
    debugger.fragment();
    let count1 = debugger.fragment_count();
    // Calling fragment again should clear and re-create
    debugger.fragment();
    let count2 = debugger.fragment_count();
    assert_eq!(count1, count2);
}

#[test]
fn test_edge_case_config_single_step_budget() {
    let config = ReductionConfig {
        max_steps: 1,
        ..ReductionConfig::default()
    };
    let mut debugger =
        DeltaDebugger::new(sample_program(), DefectClass::Crash, config, test_epoch());
    let _repro = debugger.reduce(|_| StepOutcome::DefectPreserved);
    assert!(debugger.steps().len() <= 1);
}

#[test]
fn test_repro_id_deterministic_same_inputs() {
    let mut d1 = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );
    let mut d2 = DeltaDebugger::new(
        sample_program(),
        DefectClass::Crash,
        ReductionConfig::default(),
        test_epoch(),
    );

    let r1 = d1.reduce(|_| StepOutcome::DefectLost);
    let r2 = d2.reduce(|_| StepOutcome::DefectLost);
    // Same inputs and same oracle should produce same repro ID
    assert_eq!(r1.repro_id, r2.repro_id);
}
