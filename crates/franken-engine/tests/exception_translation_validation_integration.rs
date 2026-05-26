//! Integration tests for G.6.A exception-semantics translation validation
//! (bd-cixqu.7.9.1). Exercises the public `exception_translation_validator`
//! API from outside the crate: the ≥50-program corpus validates faithfully,
//! and every "preserving-looking" semantics-breaking transform is rejected
//! (the G.6.A / G.11 negative case).

#![forbid(unsafe_code)]

use frankenengine_engine::exception_translation_validator::{
    ExcStmt, ExceptionValidationContext, ProgramCategory, SemanticsBreakingTransform, TryRegion,
    apply_transform, faithful_lower, generate_exception_test_programs, reference_trace,
    target_trace,
};

fn plain(site: u32, throws: bool) -> ExcStmt {
    ExcStmt::Plain {
        site,
        throws,
        is_await: false,
    }
}

#[test]
fn corpus_has_at_least_50_programs() {
    assert!(generate_exception_test_programs().len() >= 50);
}

#[test]
fn corpus_covers_all_required_categories() {
    use ProgramCategory::*;
    let programs = generate_exception_test_programs();
    for cat in [
        NestedTry,
        TryWithoutFinally,
        TryWithoutCatch,
        ThrowInFinally,
        ThrowInCatch,
        AwaitInTry,
        AwaitInFinally,
        TryCatchFinally,
    ] {
        assert!(
            programs.iter().any(|p| p.category == cat),
            "missing category {cat:?}"
        );
    }
}

#[test]
fn every_corpus_program_validates_under_faithful_lowering() {
    for p in generate_exception_test_programs() {
        let result = ExceptionValidationContext::faithful(p.program.clone()).validate();
        assert!(
            result.validation_successful,
            "program {} ({:?}) failed lemmas {:?}",
            p.name, p.category, result.failed_lemmas
        );
        assert!(result.flow_equivalence_proven);
        // bd-cixqu.45 diagnostic surface: an event per lemma, all verified.
        assert_eq!(result.events.len(), 5);
        assert!(result.events.iter().all(|e| e.verified));
    }
}

#[test]
fn faithful_lowering_trace_equals_reference_trace() {
    for p in generate_exception_test_programs() {
        let reference = reference_trace(&p.program);
        let target = target_trace(&faithful_lower(&p.program));
        assert_eq!(
            reference, target,
            "faithful lowering diverged for {}",
            p.name
        );
    }
}

#[test]
fn semantics_breaking_transforms_are_rejected() {
    // For each transform, find at least one corpus program where it changes
    // observable exception flow, and assert the validator rejects it.
    let transforms = [
        SemanticsBreakingTransform::DropEnterFinally,
        SemanticsBreakingTransform::DropCatchTarget,
        SemanticsBreakingTransform::DropBeginTry,
        SemanticsBreakingTransform::DropEndFinallyRethrow,
    ];
    for &tr in &transforms {
        let mut rejected_somewhere = false;
        for p in generate_exception_test_programs() {
            let lowered = faithful_lower(&p.program);
            if let Some(broken) = apply_transform(&lowered, tr) {
                let result = ExceptionValidationContext::new(p.program.clone(), broken).validate();
                if !result.validation_successful {
                    rejected_somewhere = true;
                    // A rejection must record the divergence point.
                    assert!(result.first_divergence.is_some() || !result.failed_lemmas.is_empty());
                }
            }
        }
        assert!(
            rejected_somewhere,
            "transform {tr:?} was never rejected across the corpus"
        );
    }
}

#[test]
fn dropped_finally_is_rejected_on_throwing_program() {
    // try { throw } finally { } — dropping EnterFinally means the finally never
    // runs, which the validator must reject.
    let src = vec![ExcStmt::Try(TryRegion {
        try_id: 100,
        body: vec![plain(1000, true)],
        catch_body: None,
        finally_body: Some(vec![plain(1002, false)]),
    })];
    let lowered = faithful_lower(&src);
    let broken = apply_transform(&lowered, SemanticsBreakingTransform::DropEnterFinally)
        .expect("program has a finally");
    let result = ExceptionValidationContext::new(src, broken).validate();
    assert!(!result.validation_successful);
    assert!(!result.flow_equivalence_proven);
}

#[test]
fn swallowed_exception_is_rejected() {
    // try { throw } finally { } — if EndFinally fails to re-throw the pending
    // exception it is silently swallowed; must be rejected.
    let src = vec![ExcStmt::Try(TryRegion {
        try_id: 200,
        body: vec![plain(2000, true)],
        catch_body: None,
        finally_body: Some(vec![plain(2002, false)]),
    })];
    let lowered = faithful_lower(&src);
    let broken = apply_transform(&lowered, SemanticsBreakingTransform::DropEndFinallyRethrow)
        .expect("program has a finally");
    let result = ExceptionValidationContext::new(src, broken).validate();
    assert!(!result.validation_successful);
}

#[test]
fn events_serialize_to_jsonl() {
    let p = generate_exception_test_programs()
        .into_iter()
        .find(|p| p.category == ProgramCategory::TryCatchFinally)
        .unwrap();
    let result = ExceptionValidationContext::faithful(p.program).validate();
    let jsonl = result.events_jsonl();
    assert_eq!(jsonl.lines().count(), 5);
}
