//! Integration tests for G.6.E hostcall + capability-witness translation
//! validation (bd-cixqu.7.9.5). Exercises the public
//! `hostcall_capability_translation_validator` API from outside the crate: the
//! ≥50-program corpus validates faithfully, ambient-authority hostcalls fail
//! closed, and dropping the capability witness (a membrane bypass) is rejected.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use frankenengine_engine::hostcall_capability_translation_validator::{
    Capability, HostCategory, HostFamily, HostProgram, HostStmt, HostValidationContext,
    SemanticsBreakingTransform, apply_transform, faithful_lower, generate_hostcall_test_programs,
    reference_trace, target_trace,
};

#[test]
fn corpus_has_at_least_50_programs() {
    assert!(generate_hostcall_test_programs().len() >= 50);
}

#[test]
fn corpus_covers_all_required_categories() {
    use HostCategory::*;
    let programs = generate_hostcall_test_programs();
    for cat in [
        SingleHostcall,
        NestedHostcalls,
        HostcallInAsync,
        DeclaredCapability,
        AmbientAuthorityRejection,
    ] {
        assert!(
            programs.iter().any(|p| p.category == cat),
            "missing category {cat:?}"
        );
    }
}

#[test]
fn every_corpus_program_validates_under_faithful_lowering() {
    for p in generate_hostcall_test_programs() {
        let r = HostValidationContext::faithful(p.program.clone()).validate();
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
    for p in generate_hostcall_test_programs() {
        assert_eq!(
            reference_trace(&p.program),
            target_trace(&p.program.granted, &faithful_lower(&p.program)),
            "faithful lowering diverged for {}",
            p.name
        );
    }
}

#[test]
fn dropping_capability_witness_on_ambient_hostcall_is_rejected() {
    // The security-critical case: a hostcall whose capability is NOT granted
    // must fail closed; a lowering that drops the witness would dispatch it.
    let p = HostProgram {
        granted: BTreeSet::new(),
        body: vec![HostStmt::Hostcall {
            call_id: 1,
            family: HostFamily::ProcSpawn,
            args: vec![1],
        }],
    };
    let lowered = faithful_lower(&p);
    let broken = apply_transform(&lowered, SemanticsBreakingTransform::DropCapabilityWitness)
        .expect("program has a hostcall");
    let r = HostValidationContext::new(p, broken).validate();
    assert!(
        !r.validation_successful,
        "capability bypass must be rejected"
    );
    assert!(!r.flow_equivalence_proven);
}

#[test]
fn declared_capability_hostcall_succeeds() {
    let p = HostProgram {
        granted: [Capability::NetConnect].into_iter().collect(),
        body: vec![HostStmt::Hostcall {
            call_id: 1,
            family: HostFamily::NetConnect,
            args: vec![1, 2, 3],
        }],
    };
    assert!(
        HostValidationContext::faithful(p)
            .validate()
            .validation_successful
    );
}

#[test]
fn semantics_breaking_transforms_are_rejected_across_corpus() {
    let transforms = [
        SemanticsBreakingTransform::DropCapabilityWitness,
        SemanticsBreakingTransform::DropPostCallState,
        SemanticsBreakingTransform::MutateArgs,
    ];
    for &tr in &transforms {
        let mut rejected = false;
        for p in generate_hostcall_test_programs() {
            let lowered = faithful_lower(&p.program);
            if let Some(broken) = apply_transform(&lowered, tr) {
                let r = HostValidationContext::new(p.program.clone(), broken).validate();
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
fn events_serialize_to_jsonl() {
    let p = generate_hostcall_test_programs()
        .into_iter()
        .find(|p| p.category == HostCategory::AmbientAuthorityRejection)
        .unwrap();
    let r = HostValidationContext::faithful(p.program).validate();
    assert_eq!(r.events_jsonl().lines().count(), 5);
}
