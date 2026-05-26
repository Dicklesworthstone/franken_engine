//! Integration tests for G.6.D iterator-protocol translation validation
//! (bd-cixqu.7.9.4). Exercises the public `iterator_protocol_translation_validator`
//! API from outside the crate: the ≥50-program corpus validates faithfully, and
//! every semantics-breaking transform (most importantly dropping the
//! `IteratorClose`/`.return()` on an early-exit path) is rejected.

#![forbid(unsafe_code)]

use frankenengine_engine::iterator_protocol_translation_validator::{
    IterCategory, IterSource, IterStmt, IterValidationContext, LoopExit,
    SemanticsBreakingTransform, apply_transform, faithful_lower, generate_iterator_test_programs,
    reference_trace, target_trace,
};

#[test]
fn corpus_has_at_least_50_programs() {
    assert!(generate_iterator_test_programs().len() >= 50);
}

#[test]
fn corpus_covers_all_required_categories() {
    use IterCategory::*;
    let programs = generate_iterator_test_programs();
    for cat in [
        ForOfArray,
        ForOfMap,
        ForOfSet,
        ForOfCustom,
        ForInProtoChain,
        BreakInForOf,
        ReturnInForOf,
        ThrowInForOf,
    ] {
        assert!(
            programs.iter().any(|p| p.category == cat),
            "missing category {cat:?}"
        );
    }
}

#[test]
fn every_corpus_program_validates_under_faithful_lowering() {
    for p in generate_iterator_test_programs() {
        let r = IterValidationContext::faithful(p.program.clone()).validate();
        assert!(
            r.validation_successful,
            "program {} ({:?}) failed lemmas {:?}",
            p.name, p.category, r.failed_lemmas
        );
        assert!(r.flow_equivalence_proven);
        assert_eq!(r.events.len(), 5);
        assert!(r.events.iter().all(|e| e.verified));
    }
}

#[test]
fn faithful_lowering_trace_equals_reference_trace() {
    for p in generate_iterator_test_programs() {
        assert_eq!(
            reference_trace(&p.program),
            target_trace(&faithful_lower(&p.program)),
            "faithful lowering diverged for {}",
            p.name
        );
    }
}

#[test]
fn dropping_iterator_close_on_break_is_rejected() {
    // for (x of custom) { if (...) break; } — dropping .return() leaks the
    // iterator; the validator must reject.
    let src = vec![IterStmt::ForOf {
        loop_id: 1,
        source: IterSource::Custom(5),
        exit: LoopExit::BreakAt(2),
    }];
    let lowered = faithful_lower(&src);
    let broken = apply_transform(&lowered, SemanticsBreakingTransform::DropIteratorClose)
        .expect("for-of with abrupt exit");
    let r = IterValidationContext::new(src, broken).validate();
    assert!(!r.validation_successful);
    assert!(!r.flow_equivalence_proven);
}

#[test]
fn semantics_breaking_transforms_are_rejected_across_corpus() {
    let transforms = [
        SemanticsBreakingTransform::DropIteratorClose,
        SemanticsBreakingTransform::DropGetIterator,
        SemanticsBreakingTransform::DropForInProtoKeys,
    ];
    for &tr in &transforms {
        let mut rejected = false;
        for p in generate_iterator_test_programs() {
            let lowered = faithful_lower(&p.program);
            if let Some(broken) = apply_transform(&lowered, tr) {
                let r = IterValidationContext::new(p.program.clone(), broken).validate();
                if !r.validation_successful {
                    rejected = true;
                    assert!(r.first_divergence.is_some() || !r.failed_lemmas.is_empty());
                }
            }
        }
        assert!(rejected, "transform {tr:?} never rejected across corpus");
    }
}

#[test]
fn throw_in_for_of_closes_then_propagates() {
    let src = vec![IterStmt::ForOf {
        loop_id: 9,
        source: IterSource::Custom(4),
        exit: LoopExit::ThrowAt(1, 42),
    }];
    let r = IterValidationContext::faithful(src.clone()).validate();
    assert!(r.validation_successful);
    let trace = reference_trace(&src);
    assert_eq!(trace.last().unwrap().state_after.open_iterators, 0);
}

#[test]
fn events_serialize_to_jsonl() {
    let p = generate_iterator_test_programs()
        .into_iter()
        .find(|p| p.category == IterCategory::BreakInForOf)
        .unwrap();
    let r = IterValidationContext::faithful(p.program).validate();
    assert_eq!(r.events_jsonl().lines().count(), 5);
}
