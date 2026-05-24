//! Integration tests for G.6 feature-class translation validation (bd-cixqu.7.9).
//!
//! These exercise the public surface of `full_ir_translation_validator` that
//! extends translation validation from G.4 (pure expressions) and G.5
//! (statements + control flow) to the remaining IR feature classes:
//! try/catch/finally, async/await, generators, iterator protocol, hostcalls,
//! and IFC label propagation.

use frankenengine_engine::full_ir_translation_validator::{
    FeatureClass, FeatureClassValidationContext, FeatureOpcode, FeatureWitness,
    FullIrValidationContext, IrLevel, break_witness, generate_feature_programs,
};
use frankenengine_engine::ir_contract::IteratorCloseReason;

#[test]
fn corpus_covers_all_six_g6_subtracks_with_minimum_size() {
    let programs = generate_feature_programs();
    assert!(
        programs.len() >= 50,
        "G.6 acceptance requires >=50 generated programs, got {}",
        programs.len()
    );

    let mut counts = std::collections::BTreeMap::new();
    for w in &programs {
        *counts.entry(w.feature_class).or_insert(0usize) += 1;
    }
    for class in FeatureClass::ALL {
        assert!(
            counts.get(&class).copied().unwrap_or(0) > 0,
            "{} ({:?}) has no programs",
            class.g6_subtrack(),
            class
        );
    }
}

#[test]
fn all_well_formed_programs_validate() {
    for w in generate_feature_programs() {
        assert!(
            w.check_obligations().is_ok(),
            "program `{}` should validate, got {:?}",
            w.program_name,
            w.check_obligations()
        );
    }
}

#[test]
fn all_broken_mutants_reject() {
    for w in generate_feature_programs() {
        let broken = break_witness(&w);
        assert!(
            broken.check_obligations().is_err(),
            "broken `{}` ({:?}) must reject",
            w.program_name,
            w.feature_class
        );
    }
}

#[test]
fn try_catch_finally_obligations() {
    // Balanced try/catch/finally validates.
    let ok = FeatureWitness::new(
        "balanced",
        FeatureClass::TryCatchFinally,
        vec![
            FeatureOpcode::BeginTry {
                has_catch: true,
                has_finally: true,
            },
            FeatureOpcode::Throw,
            FeatureOpcode::EnterCatch,
            FeatureOpcode::EnterFinally,
            FeatureOpcode::EndFinally,
        ],
    );
    assert!(ok.check_obligations().is_ok());

    // Declared finally that never reaches EndFinally is rejected.
    let bad = FeatureWitness::new(
        "dangling_finally",
        FeatureClass::TryCatchFinally,
        vec![FeatureOpcode::BeginTry {
            has_catch: false,
            has_finally: true,
        }],
    );
    assert!(bad.check_obligations().is_err());
}

#[test]
fn async_await_microtask_preservation() {
    let ok = FeatureWitness::new(
        "two_awaits",
        FeatureClass::AsyncAwait,
        vec![
            FeatureOpcode::AwaitValue,
            FeatureOpcode::MicrotaskCheckpoint,
            FeatureOpcode::AwaitValue,
            FeatureOpcode::MicrotaskCheckpoint,
        ],
    );
    assert!(ok.check_obligations().is_ok());

    // Checkpoint preceding its await breaks resume ordering.
    let reordered = FeatureWitness::new(
        "reordered",
        FeatureClass::AsyncAwait,
        vec![
            FeatureOpcode::MicrotaskCheckpoint,
            FeatureOpcode::AwaitValue,
        ],
    );
    assert!(reordered.check_obligations().is_err());
}

#[test]
fn iterator_close_on_every_exit_path() {
    for reason in [
        IteratorCloseReason::Break,
        IteratorCloseReason::Return,
        IteratorCloseReason::Throw,
    ] {
        let ok = FeatureWitness::new(
            "for_of",
            FeatureClass::IteratorProtocol,
            vec![
                FeatureOpcode::ForOfInit,
                FeatureOpcode::ForOfNext,
                FeatureOpcode::IteratorClose { reason },
            ],
        );
        assert!(
            ok.check_obligations().is_ok(),
            "{reason:?} close should validate"
        );
    }

    let leak = FeatureWitness::new(
        "leak",
        FeatureClass::IteratorProtocol,
        vec![FeatureOpcode::ForOfInit, FeatureOpcode::ForOfNext],
    );
    assert!(leak.check_obligations().is_err());
}

#[test]
fn hostcall_capability_witness_required() {
    let ok = FeatureWitness::new(
        "io_read",
        FeatureClass::Hostcalls,
        vec![FeatureOpcode::HostCall {
            capability: "io.read".into(),
        }],
    );
    assert!(ok.check_obligations().is_ok());

    let stripped = FeatureWitness::new(
        "uncapped",
        FeatureClass::Hostcalls,
        vec![FeatureOpcode::HostCall {
            capability: "  ".into(),
        }],
    );
    assert!(stripped.check_obligations().is_err());
}

#[test]
fn ifc_labels_may_rise_but_not_fall() {
    let raise = FeatureWitness::new(
        "raise",
        FeatureClass::IfcLabelPropagation,
        vec![
            FeatureOpcode::IfcLabel {
                var: "x".into(),
                level: 1,
            },
            FeatureOpcode::IfcLabel {
                var: "x".into(),
                level: 3,
            },
        ],
    );
    assert!(raise.check_obligations().is_ok());

    let declassify = FeatureWitness::new(
        "declassify",
        FeatureClass::IfcLabelPropagation,
        vec![
            FeatureOpcode::IfcLabel {
                var: "x".into(),
                level: 3,
            },
            FeatureOpcode::IfcLabel {
                var: "x".into(),
                level: 0,
            },
        ],
    );
    assert!(declassify.check_obligations().is_err());
}

#[test]
fn validation_context_reports_full_breadth() {
    let mut ctx = FeatureClassValidationContext::new();
    ctx.add_standard_corpus();
    let lemmas = ctx.generate_lemmas();
    assert_eq!(lemmas, ctx.witnesses.len());

    let result = ctx.validate();
    assert!(result.all_accepted);
    assert!(result.full_breadth());
    assert_eq!(result.classes_covered.len(), 6);
    assert!(result.total_programs >= 50);
}

#[test]
fn full_pipeline_coverage_requires_feature_classes() {
    let mut ctx = FullIrValidationContext::new();
    ctx.verification_coverage.expression_coverage_percentage = 100.0;
    ctx.verification_coverage.statement_coverage_percentage = 100.0;
    ctx.verification_coverage.control_flow_coverage_percentage = 100.0;
    for level in [IrLevel::IR0, IrLevel::IR1, IrLevel::IR2, IrLevel::IR3] {
        ctx.verification_coverage.ir_levels_covered.insert(level);
    }

    // Feature classes not yet validated.
    let result = ctx.validate_full_pipeline();
    assert!(!result.complete_coverage_achieved);

    // Validate the feature-class corpus, then full coverage is reachable.
    ctx.feature_validator.add_standard_corpus();
    let feature_result = ctx.validate_feature_classes();
    assert!(feature_result.full_breadth());

    let result = ctx.validate_full_pipeline();
    assert!(result.complete_coverage_achieved);
}

#[test]
fn witnesses_round_trip_through_json() {
    // Determinism / replay: a witness corpus must serialize and deserialize
    // byte-stably (project convention: serde on all types).
    let programs = generate_feature_programs();
    let json = serde_json::to_string(&programs).expect("serialize");
    let back: Vec<FeatureWitness> = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(programs, back);
    let json2 = serde_json::to_string(&back).expect("re-serialize");
    assert_eq!(json, json2, "round-trip must be byte-stable");
}
