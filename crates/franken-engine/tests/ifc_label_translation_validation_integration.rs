//! Integration tests for G.6.F IFC label-propagation translation validation
//! (bd-cixqu.7.9.6). Exercises the public `ifc_label_translation_validator`
//! API from outside the crate: the >=50-program corpus validates faithfully,
//! every "preserving-looking" semantics-breaking transform is rejected (the
//! G.6.F / G.11 negative case), and the declassification-receipt discipline
//! (valid trusted receipt vs. missing / untrusted / invalid-signature) is
//! preserved across lowering.

#![forbid(unsafe_code)]

use frankenengine_engine::ifc_label_translation_validator::{
    DeclassificationReceipt, Declassify, IfcLemma, IfcStmt, IfcValidationContext, ProgramCategory,
    SecurityLabel, SemanticsBreakingTransform, TrustedAuthorizers, apply_transform, faithful_lower,
    generate_ifc_test_programs, reference_trace, target_trace,
};

fn receipt(
    contract: &str,
    authorizer: &str,
    from: SecurityLabel,
    to: SecurityLabel,
    signature_valid: bool,
) -> DeclassificationReceipt {
    DeclassificationReceipt {
        decision_contract_id: contract.to_string(),
        authorized_by: authorizer.to_string(),
        from,
        to,
        signature_valid,
    }
}

#[test]
fn corpus_has_at_least_50_programs() {
    assert!(generate_ifc_test_programs().len() >= 50);
}

#[test]
fn corpus_covers_all_required_categories() {
    use ProgramCategory::*;
    let programs = generate_ifc_test_programs();
    for cat in [
        LatticeOrdering,
        JoinIdempotence,
        JoinMultipleInputs,
        DeclassifyWithReceipt,
        DeclassifyRefusedNoReceipt,
        DeclassifyRefusedUntrusted,
        DeclassifyRefusedInvalidSignature,
        SinkFlowAllowed,
        SinkFlowViolation,
    ] {
        assert!(
            programs.iter().any(|p| p.category == cat),
            "missing category {cat:?}"
        );
    }
}

#[test]
fn every_corpus_program_validates_under_faithful_lowering() {
    for p in generate_ifc_test_programs() {
        let result =
            IfcValidationContext::faithful(p.program.clone(), p.trusted.clone()).validate();
        assert!(
            result.validation_successful,
            "program {} ({:?}) failed lemmas {:?}",
            p.name, p.category, result.failed_lemmas
        );
        assert!(result.flow_equivalence_proven);
        // bd-cixqu.45 diagnostic surface: an event per lemma, all verified.
        assert_eq!(result.events.len(), 6);
        assert!(result.failed_lemmas.is_empty());
    }
}

#[test]
fn faithful_lowering_reproduces_the_reference_trace() {
    for p in generate_ifc_test_programs() {
        let reference = reference_trace(&p.program, &p.trusted);
        let target = target_trace(&faithful_lower(&p.program), &p.trusted);
        assert_eq!(
            reference, target,
            "{} diverged under faithful lowering",
            p.name
        );
    }
}

#[test]
fn every_semantics_breaking_transform_is_rejected() {
    use SemanticsBreakingTransform::*;
    for transform in [
        DropJoinInput,
        WeakenJoinResult,
        OverclassifyJoinResult,
        ForgeDeclassification,
        SpuriousDeclassifyRefusal,
    ] {
        let mut observed_break = false;
        for p in generate_ifc_test_programs() {
            let faithful = faithful_lower(&p.program);
            let Some(mutated) = apply_transform(&faithful, transform) else {
                continue;
            };
            // Only count transforms that actually change the observable trace.
            if target_trace(&faithful, &p.trusted) == target_trace(&mutated, &p.trusted) {
                continue;
            }
            let result =
                IfcValidationContext::new(p.program.clone(), mutated, p.trusted.clone()).validate();
            assert!(
                !result.validation_successful,
                "{transform:?} on {} was not rejected",
                p.name
            );
            observed_break = true;
        }
        assert!(
            observed_break,
            "{transform:?} never broke any corpus program"
        );
    }
}

#[test]
fn declassification_with_valid_trusted_receipt_is_admitted() {
    let mut trusted = TrustedAuthorizers::new();
    trusted.trust("contract.v1", "authority.alpha");
    let program = vec![
        IfcStmt::Source {
            var: 0,
            label: SecurityLabel::Secret,
        },
        IfcStmt::Derive {
            dest: 1,
            inputs: vec![0],
            declassify: Some(Declassify {
                to: SecurityLabel::Public,
                receipt: Some(receipt(
                    "contract.v1",
                    "authority.alpha",
                    SecurityLabel::Secret,
                    SecurityLabel::Public,
                    true,
                )),
            }),
        },
    ];
    let result = IfcValidationContext::faithful(program, trusted).validate();
    assert!(result.validation_successful);
    assert!(
        result
            .verified_lemmas
            .contains(&IfcLemma::DeclassificationReceiptDiscipline)
    );
}

#[test]
fn forging_a_declassification_without_a_receipt_is_rejected() {
    // No receipt -> the faithful lowering refuses; forging the admission must
    // be caught as a receipt-discipline violation.
    let trusted = TrustedAuthorizers::new();
    let program = vec![
        IfcStmt::Source {
            var: 0,
            label: SecurityLabel::Secret,
        },
        IfcStmt::Derive {
            dest: 1,
            inputs: vec![0],
            declassify: Some(Declassify {
                to: SecurityLabel::Public,
                receipt: None,
            }),
        },
    ];
    let forged = apply_transform(
        &faithful_lower(&program),
        SemanticsBreakingTransform::ForgeDeclassification,
    )
    .expect("declassify present");
    let result = IfcValidationContext::new(program, forged, trusted).validate();
    assert!(!result.validation_successful);
    assert!(
        result
            .failed_lemmas
            .contains(&IfcLemma::DeclassificationReceiptDiscipline)
    );
    assert!(
        result
            .failed_lemmas
            .contains(&IfcLemma::LabelFlowEquivalence)
    );
}

#[test]
fn lattice_soundness_lemmas_always_verified() {
    // The lattice self-checks must hold for any program.
    let programs = generate_ifc_test_programs();
    let p = &programs[0];
    let result = IfcValidationContext::faithful(p.program.clone(), p.trusted.clone()).validate();
    assert!(
        result
            .verified_lemmas
            .contains(&IfcLemma::JoinIsLeastUpperBound)
    );
    assert!(result.verified_lemmas.contains(&IfcLemma::JoinIdempotent));
}

#[test]
fn validation_result_serializes_to_jsonl_events() {
    let programs = generate_ifc_test_programs();
    let p = &programs[0];
    let result = IfcValidationContext::faithful(p.program.clone(), p.trusted.clone()).validate();
    let jsonl = result.events_jsonl();
    assert_eq!(jsonl.lines().count(), 6);
    for line in jsonl.lines() {
        let _: serde_json::Value = serde_json::from_str(line).expect("each event is valid JSON");
    }
}
