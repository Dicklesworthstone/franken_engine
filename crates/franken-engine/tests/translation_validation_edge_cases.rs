//! Integration tests for `translation_validation` — modes, verdicts,
//! receipts, promotions, quarantine, gate lifecycle, and error handling.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeMap;

use frankenengine_engine::engine_object_id::{self, ObjectDomain, SchemaId};
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::proof_schema::{
    ActivationStage, OptReceipt, OptimizationClass, RollbackToken, proof_schema_version_current,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::tee_attestation_policy::DecisionImpact;
use frankenengine_engine::translation_validation::{
    QuarantineEntry, RollbackReceipt, StagePromotion, TranslationValidationGate, ValidationEvent,
    ValidationEventType, ValidationGateError, ValidationMode, ValidationVerdict,
};

// ── helpers ──────────────────────────────────────────────────────────────

const KEY: &[u8] = b"test-signing-key-32-bytes-long!!";

fn signer_key_id() -> frankenengine_engine::engine_object_id::EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::KeyBundle,
        "test-zone",
        &SchemaId::from_definition(b"test-signer"),
        b"key-material",
    )
    .unwrap()
}

fn issuer_key_id() -> frankenengine_engine::engine_object_id::EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::KeyBundle,
        "test-zone",
        &SchemaId::from_definition(b"test-issuer"),
        b"issuer-material",
    )
    .unwrap()
}

fn opt_receipt(id: &str) -> OptReceipt {
    let mut compat = BTreeMap::new();
    compat.insert("engine_version".into(), "0.1.0".into());

    OptReceipt {
        schema_version: proof_schema_version_current(),
        optimization_id: id.to_string(),
        optimization_class: OptimizationClass::Superinstruction,
        baseline_ir_hash: ContentHash::compute(b"baseline-ir"),
        candidate_ir_hash: ContentHash::compute(b"candidate-ir"),
        translation_witness_hash: ContentHash::compute(b"witness"),
        invariance_digest: ContentHash::compute(b"invariance"),
        rollback_token_id: format!("token-{id}"),
        replay_compatibility: compat,
        policy_epoch: SecurityEpoch::from_raw(1),
        timestamp_ticks: 1000,
        signer_key_id: signer_key_id(),
        correlation_id: format!("corr-{id}"),
        decision_impact: DecisionImpact::Standard,
        attestation_bindings: None,
        signature: AuthenticityHash::compute_keyed(&[], &[]),
    }
    .sign(KEY)
}

fn rollback_token(id: &str) -> RollbackToken {
    RollbackToken {
        schema_version: proof_schema_version_current(),
        token_id: format!("token-{id}"),
        optimization_id: id.to_string(),
        baseline_snapshot_hash: ContentHash::compute(b"baseline-snapshot"),
        activation_stage: ActivationStage::Shadow,
        expiry_epoch: SecurityEpoch::from_raw(100),
        issuer_key_id: issuer_key_id(),
        issuer_signature: AuthenticityHash::compute_keyed(&[], &[]),
    }
    .sign(KEY)
}

fn pass_verdict() -> ValidationVerdict {
    ValidationVerdict::Pass {
        mode: ValidationMode::GoldenCorpusReplay {
            corpus_hash: ContentHash::compute(b"golden"),
            vector_count: 100,
        },
        evidence_hash: ContentHash::compute(b"evidence"),
    }
}

fn fail_verdict() -> ValidationVerdict {
    ValidationVerdict::Fail {
        mode: ValidationMode::DifferentialTrace {
            workload_hash: ContentHash::compute(b"workload"),
            trace_pair_count: 50,
        },
        divergence_reason: "hostcall sequence divergence at step 42".into(),
        counterexample_hash: ContentHash::compute(b"counterexample"),
    }
}

fn inconclusive_verdict() -> ValidationVerdict {
    ValidationVerdict::Inconclusive {
        mode: ValidationMode::SymbolicEquivalence {
            proof_hash: ContentHash::compute(b"proof"),
        },
        reason: "solver timeout after 30s".into(),
    }
}

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn submit_opt(gate: &mut TranslationValidationGate, id: &str, ticks: u64) {
    gate.submit(&opt_receipt(id), &rollback_token(id), KEY, epoch(), ticks)
        .unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// ValidationMode — Display, serde edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn mode_golden_corpus_display_includes_count() {
    let m = ValidationMode::GoldenCorpusReplay {
        corpus_hash: ContentHash::compute(b"c"),
        vector_count: 0,
    };
    assert!(m.to_string().contains("0 vectors"));
}

#[test]
fn mode_differential_trace_display_includes_pairs() {
    let m = ValidationMode::DifferentialTrace {
        workload_hash: ContentHash::compute(b"w"),
        trace_pair_count: 999,
    };
    assert!(m.to_string().contains("999 pairs"));
}

#[test]
fn mode_symbolic_display_no_count() {
    let m = ValidationMode::SymbolicEquivalence {
        proof_hash: ContentHash::compute(b"p"),
    };
    assert_eq!(m.to_string(), "symbolic_equivalence");
}

#[test]
fn mode_serde_all_variants() {
    let modes = [
        ValidationMode::GoldenCorpusReplay {
            corpus_hash: ContentHash::compute(b"gc"),
            vector_count: 42,
        },
        ValidationMode::SymbolicEquivalence {
            proof_hash: ContentHash::compute(b"se"),
        },
        ValidationMode::DifferentialTrace {
            workload_hash: ContentHash::compute(b"dt"),
            trace_pair_count: 7,
        },
    ];
    for m in &modes {
        let json = serde_json::to_string(m).unwrap();
        let parsed: ValidationMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*m, parsed);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ValidationVerdict — permits_activation, Display, serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn verdict_pass_permits() {
    assert!(pass_verdict().permits_activation());
}

#[test]
fn verdict_fail_denies() {
    assert!(!fail_verdict().permits_activation());
}

#[test]
fn verdict_inconclusive_denies() {
    assert!(!inconclusive_verdict().permits_activation());
}

#[test]
fn verdict_display_pass_contains_mode() {
    let s = pass_verdict().to_string();
    assert!(s.contains("PASS"));
    assert!(s.contains("100 vectors"));
}

#[test]
fn verdict_display_fail_contains_reason() {
    let s = fail_verdict().to_string();
    assert!(s.contains("FAIL"));
    assert!(s.contains("hostcall"));
}

#[test]
fn verdict_display_inconclusive_contains_reason() {
    let s = inconclusive_verdict().to_string();
    assert!(s.contains("INCONCLUSIVE"));
    assert!(s.contains("solver timeout"));
}

#[test]
fn verdict_serde_all_variants() {
    for v in [pass_verdict(), fail_verdict(), inconclusive_verdict()] {
        let json = serde_json::to_string(&v).unwrap();
        let parsed: ValidationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, parsed);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// RollbackReceipt — sign/verify/tamper/serde
// ═══════════════════════════════════════════════════════════════════════════

fn make_rollback_receipt(with_cx: bool) -> RollbackReceipt {
    RollbackReceipt {
        rollback_token_id: "token-1".into(),
        optimization_id: "opt-1".into(),
        failure_reason: "divergence".into(),
        counterexample_hash: if with_cx {
            Some(ContentHash::compute(b"cx"))
        } else {
            None
        },
        restoration_baseline_hash: ContentHash::compute(b"baseline"),
        rollback_from_stage: ActivationStage::Canary,
        timestamp_ticks: 5000,
        epoch: SecurityEpoch::from_raw(1),
        signature: AuthenticityHash::compute_keyed(&[], &[]),
    }
    .sign(KEY)
}

#[test]
fn rollback_receipt_sign_verify() {
    let r = make_rollback_receipt(true);
    assert!(r.verify_signature(KEY));
    assert!(!r.verify_signature(b"wrong-key-material!!!!!!!!!!!!!!"));
}

#[test]
fn rollback_receipt_tampered_reason_fails() {
    let mut r = make_rollback_receipt(true);
    assert!(r.verify_signature(KEY));
    r.failure_reason = "tampered".into();
    assert!(!r.verify_signature(KEY));
}

#[test]
fn rollback_receipt_tampered_epoch_fails() {
    let mut r = make_rollback_receipt(false);
    assert!(r.verify_signature(KEY));
    r.epoch = SecurityEpoch::from_raw(999);
    assert!(!r.verify_signature(KEY));
}

#[test]
fn rollback_receipt_without_counterexample_sign_verify() {
    let r = make_rollback_receipt(false);
    assert!(r.verify_signature(KEY));
    assert!(r.counterexample_hash.is_none());
}

#[test]
fn rollback_receipt_serde_with_counterexample() {
    let r = make_rollback_receipt(true);
    let json = serde_json::to_string(&r).unwrap();
    let parsed: RollbackReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, parsed);
}

#[test]
fn rollback_receipt_serde_without_counterexample() {
    let r = make_rollback_receipt(false);
    let json = serde_json::to_string(&r).unwrap();
    let parsed: RollbackReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, parsed);
    assert!(parsed.counterexample_hash.is_none());
}

#[test]
fn rollback_receipt_preimage_differs_by_stage() {
    let mut r1 = make_rollback_receipt(true);
    r1.rollback_from_stage = ActivationStage::Shadow;
    r1 = r1.sign(KEY);
    let mut r2 = make_rollback_receipt(true);
    r2.rollback_from_stage = ActivationStage::Ramp;
    r2 = r2.sign(KEY);
    assert_ne!(r1.signature, r2.signature);
}

// ═══════════════════════════════════════════════════════════════════════════
// StagePromotion — sign/verify/tamper/serde
// ═══════════════════════════════════════════════════════════════════════════

fn make_promotion(from: ActivationStage, to: ActivationStage) -> StagePromotion {
    StagePromotion {
        optimization_id: "opt-1".into(),
        from_stage: from,
        to_stage: to,
        evidence_hash: ContentHash::compute(b"evidence"),
        timestamp_ticks: 3000,
        epoch: SecurityEpoch::from_raw(1),
        signature: AuthenticityHash::compute_keyed(&[], &[]),
    }
    .sign(KEY)
}

#[test]
fn promotion_sign_verify() {
    let p = make_promotion(ActivationStage::Shadow, ActivationStage::Canary);
    assert!(p.verify_signature(KEY));
    assert!(!p.verify_signature(b"wrong-key-material!!!!!!!!!!!!!!"));
}

#[test]
fn promotion_tampered_opt_id_fails() {
    let mut p = make_promotion(ActivationStage::Shadow, ActivationStage::Canary);
    assert!(p.verify_signature(KEY));
    p.optimization_id = "tampered".into();
    assert!(!p.verify_signature(KEY));
}

#[test]
fn promotion_tampered_evidence_fails() {
    let mut p = make_promotion(ActivationStage::Shadow, ActivationStage::Canary);
    assert!(p.verify_signature(KEY));
    p.evidence_hash = ContentHash::compute(b"tampered");
    assert!(!p.verify_signature(KEY));
}

#[test]
fn promotion_serde_all_stages() {
    let transitions = [
        (ActivationStage::Shadow, ActivationStage::Canary),
        (ActivationStage::Canary, ActivationStage::Ramp),
        (ActivationStage::Ramp, ActivationStage::Default),
    ];
    for (from, to) in transitions {
        let p = make_promotion(from, to);
        let json = serde_json::to_string(&p).unwrap();
        let parsed: StagePromotion = serde_json::from_str(&json).unwrap();
        assert_eq!(p, parsed);
    }
}

#[test]
fn promotion_signature_differs_by_stages() {
    let p1 = make_promotion(ActivationStage::Shadow, ActivationStage::Canary);
    let p2 = make_promotion(ActivationStage::Canary, ActivationStage::Ramp);
    assert_ne!(p1.signature, p2.signature);
}

// ═══════════════════════════════════════════════════════════════════════════
// QuarantineEntry — serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn quarantine_entry_serde_with_counterexample() {
    let entry = QuarantineEntry {
        optimization_id: "opt-1".into(),
        reason: "divergence".into(),
        counterexample_hash: Some(ContentHash::compute(b"cx")),
        quarantined_epoch: SecurityEpoch::from_raw(5),
        quarantined_at_ticks: 9999,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let parsed: QuarantineEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, parsed);
}

#[test]
fn quarantine_entry_serde_without_counterexample() {
    let entry = QuarantineEntry {
        optimization_id: "opt-2".into(),
        reason: "inconclusive check".into(),
        counterexample_hash: None,
        quarantined_epoch: SecurityEpoch::from_raw(1),
        quarantined_at_ticks: 100,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let parsed: QuarantineEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, parsed);
    assert!(parsed.counterexample_hash.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════
// ValidationGateError — Display, std::error::Error, serde all variants
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn error_display_all_variants() {
    let errors: Vec<ValidationGateError> = vec![
        ValidationGateError::InvalidReceiptSignature {
            optimization_id: "opt-1".into(),
        },
        ValidationGateError::InvalidTokenSignature {
            token_id: "tok-1".into(),
        },
        ValidationGateError::TokenExpired {
            token_id: "tok-1".into(),
            expiry_epoch: 10,
            current_epoch: 20,
        },
        ValidationGateError::TokenReceiptMismatch {
            token_optimization_id: "opt-a".into(),
            receipt_optimization_id: "opt-b".into(),
        },
        ValidationGateError::Quarantined {
            optimization_id: "opt-1".into(),
            reason: "failed".into(),
        },
        ValidationGateError::InvalidStageTransition {
            from: ActivationStage::Shadow,
            to: ActivationStage::Default,
        },
        ValidationGateError::OptimizationNotFound {
            optimization_id: "opt-x".into(),
        },
        ValidationGateError::DuplicateSubmission {
            optimization_id: "opt-1".into(),
        },
        ValidationGateError::ActivationDenied {
            verdict: "no pass".into(),
        },
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty());
    }
}

#[test]
fn error_std_error_trait() {
    let err = ValidationGateError::ActivationDenied {
        verdict: "no pass".into(),
    };
    let _: &dyn std::error::Error = &err;
}

#[test]
fn error_serde_all_variants() {
    let errors: Vec<ValidationGateError> = vec![
        ValidationGateError::InvalidReceiptSignature {
            optimization_id: "opt-1".into(),
        },
        ValidationGateError::InvalidTokenSignature {
            token_id: "tok-1".into(),
        },
        ValidationGateError::TokenExpired {
            token_id: "tok-1".into(),
            expiry_epoch: 10,
            current_epoch: 20,
        },
        ValidationGateError::TokenReceiptMismatch {
            token_optimization_id: "opt-a".into(),
            receipt_optimization_id: "opt-b".into(),
        },
        ValidationGateError::Quarantined {
            optimization_id: "q1".into(),
            reason: "bad".into(),
        },
        ValidationGateError::InvalidStageTransition {
            from: ActivationStage::Canary,
            to: ActivationStage::Ramp,
        },
        ValidationGateError::OptimizationNotFound {
            optimization_id: "missing".into(),
        },
        ValidationGateError::DuplicateSubmission {
            optimization_id: "dup".into(),
        },
        ValidationGateError::ActivationDenied {
            verdict: "no pass".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let parsed: ValidationGateError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, parsed);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ValidationEvent & ValidationEventType — serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn event_type_serde_all_variants() {
    let types = [
        ValidationEventType::Submitted,
        ValidationEventType::Validated {
            verdict: "PASS".into(),
        },
        ValidationEventType::StagePromoted {
            from: ActivationStage::Shadow,
            to: ActivationStage::Canary,
        },
        ValidationEventType::StageDemoted {
            from: ActivationStage::Canary,
            to: ActivationStage::Shadow,
        },
        ValidationEventType::RolledBack {
            reason: "divergence".into(),
        },
        ValidationEventType::Quarantined {
            reason: "repeated failure".into(),
        },
        ValidationEventType::QuarantineLifted {
            override_reason: "policy".into(),
        },
    ];
    for t in &types {
        let json = serde_json::to_string(t).unwrap();
        let parsed: ValidationEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, parsed);
    }
}

#[test]
fn validation_event_serde() {
    let event = ValidationEvent {
        optimization_id: "opt-1".into(),
        event_type: ValidationEventType::StagePromoted {
            from: ActivationStage::Ramp,
            to: ActivationStage::Default,
        },
        timestamp_ticks: 42_000,
        epoch: SecurityEpoch::from_raw(7),
    };
    let json = serde_json::to_string(&event).unwrap();
    let parsed: ValidationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, parsed);
}

// ═══════════════════════════════════════════════════════════════════════════
// TranslationValidationGate — submit edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn gate_new_is_empty() {
    let g = TranslationValidationGate::new();
    assert_eq!(g.tracked_count(), 0);
    assert_eq!(g.quarantine_count(), 0);
    assert_eq!(g.event_count(), 0);
    assert!(g.rollback_receipts().is_empty());
}

#[test]
fn gate_submit_wrong_key_rejected() {
    let mut g = TranslationValidationGate::new();
    let result = g.submit(
        &opt_receipt("opt-1"),
        &rollback_token("opt-1"),
        b"wrong-key-material!!!!!!!!!!!!!!",
        epoch(),
        1000,
    );
    assert!(matches!(
        result,
        Err(ValidationGateError::InvalidReceiptSignature { .. })
    ));
}

#[test]
fn gate_submit_expired_token() {
    let mut g = TranslationValidationGate::new();
    let result = g.submit(
        &opt_receipt("opt-1"),
        &rollback_token("opt-1"),
        KEY,
        SecurityEpoch::from_raw(200), // past expiry of 100
        1000,
    );
    assert!(matches!(
        result,
        Err(ValidationGateError::TokenExpired { .. })
    ));
}

#[test]
fn gate_submit_mismatched_token() {
    let mut g = TranslationValidationGate::new();
    let result = g.submit(
        &opt_receipt("opt-1"),
        &rollback_token("opt-2"), // different optimization_id
        KEY,
        epoch(),
        1000,
    );
    assert!(matches!(
        result,
        Err(ValidationGateError::TokenReceiptMismatch { .. })
    ));
}

#[test]
fn gate_submit_duplicate() {
    let mut g = TranslationValidationGate::new();
    submit_opt(&mut g, "opt-1", 1000);
    let result = g.submit(
        &opt_receipt("opt-1"),
        &rollback_token("opt-1"),
        KEY,
        epoch(),
        2000,
    );
    assert!(matches!(
        result,
        Err(ValidationGateError::DuplicateSubmission { .. })
    ));
}

// ═══════════════════════════════════════════════════════════════════════════
// TranslationValidationGate — verdict + rollback
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn gate_pass_verdict_no_rollback() {
    let mut g = TranslationValidationGate::new();
    submit_opt(&mut g, "opt-1", 1000);
    let result = g
        .record_verdict("opt-1", pass_verdict(), KEY, epoch(), 2000)
        .unwrap();
    assert!(result.is_none());
    assert_eq!(g.tracked_count(), 1);
    assert_eq!(g.quarantine_count(), 0);
}

#[test]
fn gate_fail_verdict_triggers_rollback_and_quarantine() {
    let mut g = TranslationValidationGate::new();
    submit_opt(&mut g, "opt-1", 1000);
    let result = g
        .record_verdict("opt-1", fail_verdict(), KEY, epoch(), 2000)
        .unwrap();
    assert!(result.is_some());
    let receipt = result.unwrap();
    assert_eq!(receipt.optimization_id, "opt-1");
    assert!(receipt.counterexample_hash.is_some());
    assert!(receipt.verify_signature(KEY));
    assert_eq!(g.tracked_count(), 0);
    assert!(g.is_quarantined("opt-1"));
}

#[test]
fn gate_inconclusive_verdict_triggers_rollback() {
    let mut g = TranslationValidationGate::new();
    submit_opt(&mut g, "opt-1", 1000);
    let result = g
        .record_verdict("opt-1", inconclusive_verdict(), KEY, epoch(), 2000)
        .unwrap();
    assert!(result.is_some());
    let receipt = result.unwrap();
    assert!(receipt.failure_reason.contains("inconclusive"));
    assert!(receipt.counterexample_hash.is_none());
}

#[test]
fn gate_verdict_for_unknown_fails() {
    let mut g = TranslationValidationGate::new();
    let result = g.record_verdict("nonexistent", pass_verdict(), KEY, epoch(), 1000);
    assert!(matches!(
        result,
        Err(ValidationGateError::OptimizationNotFound { .. })
    ));
}

// ═══════════════════════════════════════════════════════════════════════════
// TranslationValidationGate — promote
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn gate_promote_shadow_to_canary() {
    let mut g = TranslationValidationGate::new();
    submit_opt(&mut g, "opt-1", 1000);
    g.record_verdict("opt-1", pass_verdict(), KEY, epoch(), 2000)
        .unwrap();
    let p = g
        .promote("opt-1", ContentHash::compute(b"ev"), KEY, epoch(), 3000)
        .unwrap();
    assert_eq!(p.from_stage, ActivationStage::Shadow);
    assert_eq!(p.to_stage, ActivationStage::Canary);
    assert!(p.verify_signature(KEY));
    assert_eq!(g.current_stage("opt-1"), Some(ActivationStage::Canary));
}

#[test]
fn gate_promote_without_pass_denied() {
    let mut g = TranslationValidationGate::new();
    submit_opt(&mut g, "opt-1", 1000);
    let result = g.promote("opt-1", ContentHash::compute(b"ev"), KEY, epoch(), 2000);
    assert!(matches!(
        result,
        Err(ValidationGateError::ActivationDenied { .. })
    ));
}

#[test]
fn gate_promote_full_chain_to_default() {
    let mut g = TranslationValidationGate::new();
    submit_opt(&mut g, "opt-1", 1000);

    let expected = [
        (ActivationStage::Shadow, ActivationStage::Canary),
        (ActivationStage::Canary, ActivationStage::Ramp),
        (ActivationStage::Ramp, ActivationStage::Default),
    ];

    for (i, (from, to)) in expected.iter().enumerate() {
        let t = (i as u64 + 1) * 1000 + 1000;
        g.record_verdict("opt-1", pass_verdict(), KEY, epoch(), t)
            .unwrap();
        let p = g
            .promote("opt-1", ContentHash::compute(b"ev"), KEY, epoch(), t + 500)
            .unwrap();
        assert_eq!(p.from_stage, *from);
        assert_eq!(p.to_stage, *to);
    }

    assert_eq!(g.current_stage("opt-1"), Some(ActivationStage::Default));
}

#[test]
fn gate_promote_from_default_fails() {
    let mut g = TranslationValidationGate::new();
    submit_opt(&mut g, "opt-1", 1000);

    // Fast-forward to Default
    for t in [2000u64, 3000, 4000] {
        g.record_verdict("opt-1", pass_verdict(), KEY, epoch(), t)
            .unwrap();
        g.promote("opt-1", ContentHash::compute(b"ev"), KEY, epoch(), t + 100)
            .unwrap();
    }

    g.record_verdict("opt-1", pass_verdict(), KEY, epoch(), 5000)
        .unwrap();
    let result = g.promote("opt-1", ContentHash::compute(b"ev"), KEY, epoch(), 5100);
    assert!(matches!(
        result,
        Err(ValidationGateError::InvalidStageTransition { .. })
    ));
}

// ═══════════════════════════════════════════════════════════════════════════
// TranslationValidationGate — demote
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn gate_demote_canary_to_shadow() {
    let mut g = TranslationValidationGate::new();
    submit_opt(&mut g, "opt-1", 1000);
    g.record_verdict("opt-1", pass_verdict(), KEY, epoch(), 2000)
        .unwrap();
    g.promote("opt-1", ContentHash::compute(b"ev"), KEY, epoch(), 3000)
        .unwrap();

    let d = g
        .demote(
            "opt-1",
            ActivationStage::Shadow,
            "p99 regression",
            KEY,
            epoch(),
            4000,
        )
        .unwrap();
    assert_eq!(d.from_stage, ActivationStage::Canary);
    assert_eq!(d.to_stage, ActivationStage::Shadow);
    assert!(d.verify_signature(KEY));
    assert_eq!(g.current_stage("opt-1"), Some(ActivationStage::Shadow));
}

#[test]
fn gate_demote_to_same_stage_fails() {
    let mut g = TranslationValidationGate::new();
    submit_opt(&mut g, "opt-1", 1000);
    let result = g.demote(
        "opt-1",
        ActivationStage::Shadow,
        "reason",
        KEY,
        epoch(),
        2000,
    );
    assert!(matches!(
        result,
        Err(ValidationGateError::InvalidStageTransition { .. })
    ));
}

#[test]
fn gate_demote_then_re_promote() {
    let mut g = TranslationValidationGate::new();
    submit_opt(&mut g, "opt-1", 1000);

    // Promote to Canary
    g.record_verdict("opt-1", pass_verdict(), KEY, epoch(), 2000)
        .unwrap();
    g.promote("opt-1", ContentHash::compute(b"ev"), KEY, epoch(), 3000)
        .unwrap();
    assert_eq!(g.current_stage("opt-1"), Some(ActivationStage::Canary));

    // Demote back to Shadow
    g.demote(
        "opt-1",
        ActivationStage::Shadow,
        "regression",
        KEY,
        epoch(),
        4000,
    )
    .unwrap();
    assert_eq!(g.current_stage("opt-1"), Some(ActivationStage::Shadow));

    // Re-promote to Canary
    g.record_verdict("opt-1", pass_verdict(), KEY, epoch(), 5000)
        .unwrap();
    g.promote("opt-1", ContentHash::compute(b"ev"), KEY, epoch(), 6000)
        .unwrap();
    assert_eq!(g.current_stage("opt-1"), Some(ActivationStage::Canary));

    // Should have 3 promotions in history (promote, demote, re-promote)
    let history = g.promotion_history("opt-1");
    assert_eq!(history.len(), 3);
}

// ═══════════════════════════════════════════════════════════════════════════
// TranslationValidationGate — quarantine lifecycle
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn gate_quarantine_blocks_resubmission() {
    let mut g = TranslationValidationGate::new();
    submit_opt(&mut g, "opt-1", 1000);
    g.record_verdict("opt-1", fail_verdict(), KEY, epoch(), 2000)
        .unwrap();
    assert!(g.is_quarantined("opt-1"));

    let result = g.submit(
        &opt_receipt("opt-1"),
        &rollback_token("opt-1"),
        KEY,
        epoch(),
        3000,
    );
    assert!(matches!(
        result,
        Err(ValidationGateError::Quarantined { .. })
    ));
}

#[test]
fn gate_lift_quarantine_allows_resubmission() {
    let mut g = TranslationValidationGate::new();
    submit_opt(&mut g, "opt-1", 1000);
    g.record_verdict("opt-1", fail_verdict(), KEY, epoch(), 2000)
        .unwrap();

    g.lift_quarantine("opt-1", "new evidence", epoch(), 3000)
        .unwrap();
    assert!(!g.is_quarantined("opt-1"));

    submit_opt(&mut g, "opt-1", 4000);
    assert_eq!(g.tracked_count(), 1);
}

#[test]
fn gate_lift_quarantine_for_unknown_fails() {
    let mut g = TranslationValidationGate::new();
    let result = g.lift_quarantine("nonexistent", "reason", epoch(), 1000);
    assert!(matches!(
        result,
        Err(ValidationGateError::OptimizationNotFound { .. })
    ));
}

#[test]
fn gate_quarantine_entry_accessible() {
    let mut g = TranslationValidationGate::new();
    submit_opt(&mut g, "opt-1", 1000);
    g.record_verdict("opt-1", fail_verdict(), KEY, epoch(), 2000)
        .unwrap();

    let entry = g.get_quarantine_entry("opt-1").unwrap();
    assert_eq!(entry.optimization_id, "opt-1");
    assert!(entry.counterexample_hash.is_some());
    assert_eq!(entry.quarantined_epoch, epoch());
}

// ═══════════════════════════════════════════════════════════════════════════
// TranslationValidationGate — events and receipts
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn gate_events_track_full_lifecycle() {
    let mut g = TranslationValidationGate::new();
    submit_opt(&mut g, "opt-1", 1000); // Submitted
    g.record_verdict("opt-1", pass_verdict(), KEY, epoch(), 2000)
        .unwrap(); // Validated
    g.promote("opt-1", ContentHash::compute(b"ev"), KEY, epoch(), 3000)
        .unwrap(); // StagePromoted

    let events = g.events();
    assert_eq!(events.len(), 3);
    assert!(matches!(
        events[0].event_type,
        ValidationEventType::Submitted
    ));
    assert!(matches!(
        events[1].event_type,
        ValidationEventType::Validated { .. }
    ));
    assert!(matches!(
        events[2].event_type,
        ValidationEventType::StagePromoted { .. }
    ));
}

#[test]
fn gate_rollback_receipts_accumulated() {
    let mut g = TranslationValidationGate::new();

    // First fail
    submit_opt(&mut g, "opt-1", 1000);
    g.record_verdict("opt-1", fail_verdict(), KEY, epoch(), 2000)
        .unwrap();

    // Lift and fail again
    g.lift_quarantine("opt-1", "retry", epoch(), 3000).unwrap();
    submit_opt(&mut g, "opt-1", 4000);
    g.record_verdict("opt-1", inconclusive_verdict(), KEY, epoch(), 5000)
        .unwrap();

    assert_eq!(g.rollback_receipts().len(), 2);
    for r in g.rollback_receipts() {
        assert!(r.verify_signature(KEY));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TranslationValidationGate — serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn gate_serde_roundtrip() {
    let mut g = TranslationValidationGate::new();
    submit_opt(&mut g, "opt-1", 1000);
    g.record_verdict("opt-1", pass_verdict(), KEY, epoch(), 2000)
        .unwrap();
    g.promote("opt-1", ContentHash::compute(b"ev"), KEY, epoch(), 3000)
        .unwrap();

    let json = serde_json::to_string(&g).unwrap();
    let parsed: TranslationValidationGate = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.tracked_count(), 1);
    assert_eq!(parsed.event_count(), 3);
    assert_eq!(parsed.current_stage("opt-1"), Some(ActivationStage::Canary));
}

#[test]
fn gate_deterministic_identical_operations() {
    let build = || {
        let mut g = TranslationValidationGate::new();
        submit_opt(&mut g, "opt-1", 1000);
        g.record_verdict("opt-1", pass_verdict(), KEY, epoch(), 2000)
            .unwrap();
        g.promote("opt-1", ContentHash::compute(b"ev"), KEY, epoch(), 3000)
            .unwrap();
        g
    };

    let json1 = serde_json::to_string(&build()).unwrap();
    let json2 = serde_json::to_string(&build()).unwrap();
    assert_eq!(json1, json2);
}

// ═══════════════════════════════════════════════════════════════════════════
// Full integration — multiple optimizations
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn integration_multiple_optimizations_independent() {
    let mut g = TranslationValidationGate::new();

    // Submit two optimizations
    submit_opt(&mut g, "opt-1", 1000);
    submit_opt(&mut g, "opt-2", 1000);
    assert_eq!(g.tracked_count(), 2);

    // opt-1 passes, opt-2 fails
    g.record_verdict("opt-1", pass_verdict(), KEY, epoch(), 2000)
        .unwrap();
    g.record_verdict("opt-2", fail_verdict(), KEY, epoch(), 2000)
        .unwrap();

    assert_eq!(g.tracked_count(), 1);
    assert_eq!(g.quarantine_count(), 1);
    assert_eq!(g.current_stage("opt-1"), Some(ActivationStage::Shadow));
    assert!(g.is_quarantined("opt-2"));
    assert!(g.current_stage("opt-2").is_none());
}

#[test]
fn integration_fail_quarantine_lift_succeed() {
    let mut g = TranslationValidationGate::new();

    // Submit → fail → quarantine
    submit_opt(&mut g, "opt-1", 1000);
    g.record_verdict("opt-1", fail_verdict(), KEY, epoch(), 2000)
        .unwrap();
    assert!(g.is_quarantined("opt-1"));

    // Lift quarantine
    g.lift_quarantine("opt-1", "fixed root cause", epoch(), 3000)
        .unwrap();

    // Re-submit → pass → promote through all stages
    submit_opt(&mut g, "opt-1", 4000);
    for t in [5000u64, 6000, 7000] {
        g.record_verdict("opt-1", pass_verdict(), KEY, epoch(), t)
            .unwrap();
        g.promote("opt-1", ContentHash::compute(b"ev"), KEY, epoch(), t + 100)
            .unwrap();
    }

    assert_eq!(g.current_stage("opt-1"), Some(ActivationStage::Default));
    assert!(!g.is_quarantined("opt-1"));
}
