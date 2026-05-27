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
    SecurityLabel, SemanticsBreakingTransform, TrustedAuthorizers, apply_transform,
    declassification_admitted, faithful_lower, generate_ifc_test_programs, reference_trace,
    target_trace,
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

/// bd-bg9l1.14: the translation-validator admission path must be bound to a
/// REAL receipt signature check, not a hand-set bool. Here `signature_valid` is
/// *derived* from `ifc_artifacts::DeclassificationReceipt::verify` (real ed25519
/// signature + validity-window check) and fed through both the public admission
/// function and the full faithful-lowering validation. If the runtime's real
/// receipt verification ever diverges from what the proof harness assumes, this
/// test breaks instead of staying green on a hand-set `true`.
#[test]
fn declassification_admission_is_bound_to_real_signature_verification() {
    use frankenengine_engine::ifc_artifacts::{
        DeclassificationDecision, DeclassificationReceipt as ArtifactReceipt, IfcSchemaVersion,
        Label,
    };
    use frankenengine_engine::signature_preimage::{Signature, SigningKey};

    let signing_key = SigningKey::from_bytes([7u8; 32]).expect("valid signing key bytes");
    let verification_key = signing_key.verification_key();
    let attacker_key = SigningKey::from_bytes([13u8; 32])
        .expect("valid signing key bytes")
        .verification_key();

    // A real, signable receipt authorizing a Confidential -> Internal downgrade.
    let mut artifact = ArtifactReceipt {
        receipt_id: "translation-validator-bd-bg9l1-14".to_string(),
        source_label: Label::Confidential,
        sink_clearance: Label::Internal,
        content_binding: None,
        declassification_route_ref: "route.v1".to_string(),
        decision_contract_id: "contract.v1".to_string(),
        policy_evaluation_summary: "authorized downgrade".to_string(),
        loss_assessment_milli: 100_000,
        decision: DeclassificationDecision::Allow,
        authorized_by: verification_key.clone(),
        replay_linkage: "trace.v1".to_string(),
        timestamp_ms: 1_735_689_000_000,
        not_before_ms: 0,
        not_after_ms: u64::MAX,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: Signature::from_bytes([0u8; 64]),
    };
    artifact.sign(&signing_key).expect("honest receipt signs");

    // DERIVED from real verification (signature + validity window), not hand-set.
    let honest_signature_valid = artifact.verify(&verification_key).is_ok();
    let forged_signature_valid = artifact.verify(&attacker_key).is_ok();
    assert!(honest_signature_valid, "honest receipt must verify");
    assert!(
        !forged_signature_valid,
        "verification under the wrong key must fail"
    );

    // The mirror receipt carries the derived bool; the authorizer identity is the
    // real verification key, and the trust set is keyed off that same identity.
    let authorizer = verification_key.to_hex();
    let mut trusted = TrustedAuthorizers::new();
    trusted.trust("contract.v1", &authorizer);

    let honest = receipt(
        "contract.v1",
        &authorizer,
        SecurityLabel::Secret,
        SecurityLabel::Public,
        honest_signature_valid,
    );
    let forged = receipt(
        "contract.v1",
        &authorizer,
        SecurityLabel::Secret,
        SecurityLabel::Public,
        forged_signature_valid,
    );

    // Public admission keys directly off the real verification outcome.
    assert!(
        declassification_admitted(
            Some(&honest),
            SecurityLabel::Secret,
            SecurityLabel::Public,
            &trusted
        ),
        "a genuinely-verified receipt must be admitted"
    );
    assert!(
        !declassification_admitted(
            Some(&forged),
            SecurityLabel::Secret,
            SecurityLabel::Public,
            &trusted
        ),
        "a receipt whose real signature check failed must be refused"
    );

    // End-to-end: the honest, real-verified receipt also clears the full
    // faithful-lowering validation and its receipt-discipline lemma.
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
                receipt: Some(honest),
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
