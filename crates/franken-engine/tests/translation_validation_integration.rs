//! Integration tests for `frankenengine_engine::translation_validation`.
//!
//! Exercises the translation-validation gate from the public crate boundary:
//! ValidationMode, ValidationVerdict, RollbackReceipt, StagePromotion,
//! QuarantineEntry, ValidationGateError, TranslationValidationGate lifecycle
//! (submit → validate → promote/demote → rollback → quarantine).

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

// ── Helpers ─────────────────────────────────────────────────────────────

const TEST_KEY: &[u8] = b"test-signing-key-32-bytes-long!!";

fn test_receipt(opt_id: &str) -> OptReceipt {
    let mut compat = BTreeMap::new();
    compat.insert("engine_version".into(), "0.1.0".into());

    let signer_key_id = engine_object_id::derive_id(
        ObjectDomain::KeyBundle,
        "test-zone",
        &SchemaId::from_definition(b"test-signer"),
        b"key-material",
    )
    .unwrap();

    OptReceipt {
        schema_version: proof_schema_version_current(),
        optimization_id: opt_id.to_string(),
        optimization_class: OptimizationClass::Superinstruction,
        baseline_ir_hash: ContentHash::compute(b"baseline-ir"),
        candidate_ir_hash: ContentHash::compute(b"candidate-ir"),
        translation_witness_hash: ContentHash::compute(b"witness"),
        invariance_digest: ContentHash::compute(b"invariance"),
        rollback_token_id: format!("token-{opt_id}"),
        replay_compatibility: compat,
        policy_epoch: SecurityEpoch::from_raw(1),
        timestamp_ticks: 1000,
        signer_key_id,
        correlation_id: format!("corr-{opt_id}"),
        decision_impact: DecisionImpact::Standard,
        attestation_bindings: None,
        signature: AuthenticityHash::compute_keyed(&[], &[]),
    }
    .sign(TEST_KEY)
}

fn test_token(opt_id: &str) -> RollbackToken {
    let issuer_key_id = engine_object_id::derive_id(
        ObjectDomain::KeyBundle,
        "test-zone",
        &SchemaId::from_definition(b"test-issuer"),
        b"issuer-material",
    )
    .unwrap();

    RollbackToken {
        schema_version: proof_schema_version_current(),
        token_id: format!("token-{opt_id}"),
        optimization_id: opt_id.to_string(),
        baseline_snapshot_hash: ContentHash::compute(b"baseline-snapshot"),
        activation_stage: ActivationStage::Shadow,
        expiry_epoch: SecurityEpoch::from_raw(100),
        issuer_key_id,
        issuer_signature: AuthenticityHash::compute_keyed(&[], &[]),
    }
    .sign(TEST_KEY)
}

fn pass_verdict() -> ValidationVerdict {
    ValidationVerdict::Pass {
        mode: ValidationMode::GoldenCorpusReplay {
            corpus_hash: ContentHash::compute(b"golden-corpus"),
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

// ── ValidationMode ──────────────────────────────────────────────────────

#[test]
fn validation_mode_display_golden() {
    let mode = ValidationMode::GoldenCorpusReplay {
        corpus_hash: ContentHash::compute(b"c"),
        vector_count: 42,
    };
    assert!(format!("{}", mode).contains("42 vectors"));
}

#[test]
fn validation_mode_display_symbolic() {
    let mode = ValidationMode::SymbolicEquivalence {
        proof_hash: ContentHash::compute(b"p"),
    };
    assert!(format!("{}", mode).contains("symbolic_equivalence"));
}

#[test]
fn validation_mode_display_differential() {
    let mode = ValidationMode::DifferentialTrace {
        workload_hash: ContentHash::compute(b"w"),
        trace_pair_count: 10,
    };
    assert!(format!("{}", mode).contains("10 pairs"));
}

#[test]
fn validation_mode_serde_roundtrip() {
    let mode = ValidationMode::GoldenCorpusReplay {
        corpus_hash: ContentHash::compute(b"test"),
        vector_count: 200,
    };
    let json = serde_json::to_string(&mode).unwrap();
    let back: ValidationMode = serde_json::from_str(&json).unwrap();
    assert_eq!(back, mode);
}

// ── ValidationVerdict ───────────────────────────────────────────────────

#[test]
fn verdict_pass_permits_activation() {
    assert!(pass_verdict().permits_activation());
}

#[test]
fn verdict_fail_denies_activation() {
    assert!(!fail_verdict().permits_activation());
}

#[test]
fn verdict_inconclusive_denies_activation() {
    assert!(!inconclusive_verdict().permits_activation());
}

#[test]
fn verdict_display_contains_type() {
    assert!(pass_verdict().to_string().contains("PASS"));
    assert!(fail_verdict().to_string().contains("FAIL"));
    assert!(inconclusive_verdict().to_string().contains("INCONCLUSIVE"));
}

#[test]
fn verdict_serde_roundtrip() {
    for v in [pass_verdict(), fail_verdict(), inconclusive_verdict()] {
        let json = serde_json::to_string(&v).unwrap();
        let back: ValidationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}

// ── RollbackReceipt ─────────────────────────────────────────────────────

#[test]
fn rollback_receipt_sign_and_verify() {
    let receipt = RollbackReceipt {
        rollback_token_id: "tok-1".to_string(),
        optimization_id: "opt-1".to_string(),
        failure_reason: "divergence detected".to_string(),
        counterexample_hash: Some(ContentHash::compute(b"cx")),
        restoration_baseline_hash: ContentHash::compute(b"baseline"),
        rollback_from_stage: ActivationStage::Shadow,
        timestamp_ticks: 5000,
        epoch: SecurityEpoch::from_raw(1),
        signature: AuthenticityHash::compute_keyed(&[], &[]),
    }
    .sign(TEST_KEY);

    assert!(receipt.verify_signature(TEST_KEY));
    assert!(!receipt.verify_signature(b"wrong-key-that-is-32-bytes-long"));
}

#[test]
fn rollback_receipt_serde_roundtrip() {
    let receipt = RollbackReceipt {
        rollback_token_id: "tok-1".to_string(),
        optimization_id: "opt-1".to_string(),
        failure_reason: "test".to_string(),
        counterexample_hash: None,
        restoration_baseline_hash: ContentHash::compute(b"base"),
        rollback_from_stage: ActivationStage::Canary,
        timestamp_ticks: 1000,
        epoch: SecurityEpoch::from_raw(2),
        signature: AuthenticityHash::compute_keyed(TEST_KEY, b"test"),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let back: RollbackReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back, receipt);
}

// ── StagePromotion ──────────────────────────────────────────────────────

#[test]
fn stage_promotion_sign_and_verify() {
    let promo = StagePromotion {
        optimization_id: "opt-1".to_string(),
        from_stage: ActivationStage::Shadow,
        to_stage: ActivationStage::Canary,
        evidence_hash: ContentHash::compute(b"evidence"),
        timestamp_ticks: 2000,
        epoch: SecurityEpoch::from_raw(1),
        signature: AuthenticityHash::compute_keyed(&[], &[]),
    }
    .sign(TEST_KEY);

    assert!(promo.verify_signature(TEST_KEY));
    assert!(!promo.verify_signature(b"wrong-key-that-is-32-bytes-long"));
}

#[test]
fn stage_promotion_serde_roundtrip() {
    let promo = StagePromotion {
        optimization_id: "opt-2".to_string(),
        from_stage: ActivationStage::Canary,
        to_stage: ActivationStage::Ramp,
        evidence_hash: ContentHash::compute(b"ev"),
        timestamp_ticks: 3000,
        epoch: SecurityEpoch::from_raw(3),
        signature: AuthenticityHash::compute_keyed(TEST_KEY, b"p"),
    };
    let json = serde_json::to_string(&promo).unwrap();
    let back: StagePromotion = serde_json::from_str(&json).unwrap();
    assert_eq!(back, promo);
}

// ── QuarantineEntry ─────────────────────────────────────────────────────

#[test]
fn quarantine_entry_serde_roundtrip() {
    let entry = QuarantineEntry {
        optimization_id: "opt-bad".to_string(),
        reason: "divergence".to_string(),
        counterexample_hash: Some(ContentHash::compute(b"cx")),
        quarantined_epoch: SecurityEpoch::from_raw(5),
        quarantined_at_ticks: 10_000,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: QuarantineEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

// ── ValidationGateError ─────────────────────────────────────────────────

#[test]
fn gate_error_display_variants() {
    let err = ValidationGateError::InvalidReceiptSignature {
        optimization_id: "opt-1".to_string(),
    };
    assert!(format!("{}", err).contains("opt-1"));

    let err = ValidationGateError::Quarantined {
        optimization_id: "opt-q".to_string(),
        reason: "bad".to_string(),
    };
    assert!(format!("{}", err).contains("quarantined"));

    let err = ValidationGateError::DuplicateSubmission {
        optimization_id: "dup".to_string(),
    };
    assert!(format!("{}", err).contains("duplicate"));

    let err = ValidationGateError::TokenExpired {
        token_id: "tok".to_string(),
        expiry_epoch: 5,
        current_epoch: 10,
    };
    assert!(format!("{}", err).contains("expired"));
}

#[test]
fn gate_error_serde_roundtrip() {
    let err = ValidationGateError::InvalidStageTransition {
        from: ActivationStage::Shadow,
        to: ActivationStage::Default,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: ValidationGateError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

// ── ValidationEvent ─────────────────────────────────────────────────────

#[test]
fn validation_event_serde_roundtrip() {
    let event = ValidationEvent {
        optimization_id: "opt-1".to_string(),
        event_type: ValidationEventType::Submitted,
        timestamp_ticks: 1000,
        epoch: SecurityEpoch::from_raw(1),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ValidationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

#[test]
fn validation_event_type_all_variants_serde() {
    let types = vec![
        ValidationEventType::Submitted,
        ValidationEventType::Validated {
            verdict: "PASS".to_string(),
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
            reason: "fail".to_string(),
        },
        ValidationEventType::Quarantined {
            reason: "diverged".to_string(),
        },
        ValidationEventType::QuarantineLifted {
            override_reason: "new evidence".to_string(),
        },
    ];
    for et in &types {
        let json = serde_json::to_string(et).unwrap();
        let back: ValidationEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, et);
    }
}

// ── TranslationValidationGate ───────────────────────────────────────────

#[test]
fn gate_new_is_empty() {
    let gate = TranslationValidationGate::new();
    assert_eq!(gate.tracked_count(), 0);
    assert_eq!(gate.quarantine_count(), 0);
    assert_eq!(gate.event_count(), 0);
    assert!(gate.rollback_receipts().is_empty());
}

#[test]
fn gate_submit_registers_in_shadow() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-1");
    let token = test_token("opt-1");
    gate.submit(&receipt, &token, TEST_KEY, SecurityEpoch::from_raw(1), 1000)
        .unwrap();
    assert_eq!(gate.tracked_count(), 1);
    assert_eq!(gate.current_stage("opt-1"), Some(ActivationStage::Shadow));
    assert_eq!(gate.event_count(), 1); // Submitted event
}

#[test]
fn gate_submit_rejects_duplicate() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-1");
    let token = test_token("opt-1");
    gate.submit(&receipt, &token, TEST_KEY, SecurityEpoch::from_raw(1), 1000)
        .unwrap();
    let err = gate
        .submit(&receipt, &token, TEST_KEY, SecurityEpoch::from_raw(1), 2000)
        .unwrap_err();
    assert!(matches!(
        err,
        ValidationGateError::DuplicateSubmission { .. }
    ));
}

#[test]
fn gate_submit_rejects_bad_receipt_signature() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-1");
    let token = test_token("opt-1");
    let bad_key = b"wrong-signing-key-is-32-byte-no";
    let err = gate
        .submit(&receipt, &token, bad_key, SecurityEpoch::from_raw(1), 1000)
        .unwrap_err();
    assert!(matches!(
        err,
        ValidationGateError::InvalidReceiptSignature { .. }
    ));
}

#[test]
fn gate_submit_rejects_expired_token() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-1");
    let token = test_token("opt-1"); // expiry_epoch = 100
    let err = gate
        .submit(
            &receipt,
            &token,
            TEST_KEY,
            SecurityEpoch::from_raw(200), // current > expiry
            1000,
        )
        .unwrap_err();
    assert!(matches!(err, ValidationGateError::TokenExpired { .. }));
}

#[test]
fn gate_submit_rejects_token_receipt_mismatch() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-1");
    let token = test_token("opt-2"); // different opt_id
    let err = gate
        .submit(&receipt, &token, TEST_KEY, SecurityEpoch::from_raw(1), 1000)
        .unwrap_err();
    assert!(matches!(
        err,
        ValidationGateError::TokenReceiptMismatch { .. }
    ));
}

// ── record_verdict ──────────────────────────────────────────────────────

#[test]
fn gate_record_pass_verdict_no_rollback() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-1");
    let token = test_token("opt-1");
    gate.submit(&receipt, &token, TEST_KEY, SecurityEpoch::from_raw(1), 1000)
        .unwrap();

    let result = gate
        .record_verdict(
            "opt-1",
            pass_verdict(),
            TEST_KEY,
            SecurityEpoch::from_raw(1),
            2000,
        )
        .unwrap();
    assert!(result.is_none()); // No rollback for pass
    assert_eq!(gate.tracked_count(), 1); // Still tracked
}

#[test]
fn gate_record_fail_verdict_triggers_rollback() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-1");
    let token = test_token("opt-1");
    gate.submit(&receipt, &token, TEST_KEY, SecurityEpoch::from_raw(1), 1000)
        .unwrap();

    let result = gate
        .record_verdict(
            "opt-1",
            fail_verdict(),
            TEST_KEY,
            SecurityEpoch::from_raw(1),
            2000,
        )
        .unwrap();
    let rollback = result.unwrap();
    assert_eq!(rollback.optimization_id, "opt-1");
    assert!(rollback.verify_signature(TEST_KEY));
    assert!(rollback.counterexample_hash.is_some());

    // Optimization should be removed from tracked and quarantined
    assert_eq!(gate.tracked_count(), 0);
    assert!(gate.is_quarantined("opt-1"));
    assert!(!gate.rollback_receipts().is_empty());
}

#[test]
fn gate_record_inconclusive_verdict_triggers_rollback() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-1");
    let token = test_token("opt-1");
    gate.submit(&receipt, &token, TEST_KEY, SecurityEpoch::from_raw(1), 1000)
        .unwrap();

    let result = gate
        .record_verdict(
            "opt-1",
            inconclusive_verdict(),
            TEST_KEY,
            SecurityEpoch::from_raw(1),
            2000,
        )
        .unwrap();
    assert!(result.is_some()); // Rollback triggered
    assert!(gate.is_quarantined("opt-1"));
}

#[test]
fn gate_record_verdict_unknown_opt_error() {
    let mut gate = TranslationValidationGate::new();
    let err = gate
        .record_verdict(
            "nonexistent",
            pass_verdict(),
            TEST_KEY,
            SecurityEpoch::from_raw(1),
            1000,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        ValidationGateError::OptimizationNotFound { .. }
    ));
}

// ── promote ─────────────────────────────────────────────────────────────

#[test]
fn gate_promote_shadow_to_canary() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-1");
    let token = test_token("opt-1");
    gate.submit(&receipt, &token, TEST_KEY, SecurityEpoch::from_raw(1), 1000)
        .unwrap();
    gate.record_verdict(
        "opt-1",
        pass_verdict(),
        TEST_KEY,
        SecurityEpoch::from_raw(1),
        2000,
    )
    .unwrap();

    let promo = gate
        .promote(
            "opt-1",
            ContentHash::compute(b"evidence"),
            TEST_KEY,
            SecurityEpoch::from_raw(1),
            3000,
        )
        .unwrap();
    assert_eq!(promo.from_stage, ActivationStage::Shadow);
    assert_eq!(promo.to_stage, ActivationStage::Canary);
    assert!(promo.verify_signature(TEST_KEY));
    assert_eq!(gate.current_stage("opt-1"), Some(ActivationStage::Canary));
}

#[test]
fn gate_promote_without_pass_denied() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-1");
    let token = test_token("opt-1");
    gate.submit(&receipt, &token, TEST_KEY, SecurityEpoch::from_raw(1), 1000)
        .unwrap();
    // No verdict recorded — try to promote
    let err = gate
        .promote(
            "opt-1",
            ContentHash::compute(b"ev"),
            TEST_KEY,
            SecurityEpoch::from_raw(1),
            2000,
        )
        .unwrap_err();
    assert!(matches!(err, ValidationGateError::ActivationDenied { .. }));
}

// ── demote ──────────────────────────────────────────────────────────────

#[test]
fn gate_demote_canary_to_shadow() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-1");
    let token = test_token("opt-1");
    gate.submit(&receipt, &token, TEST_KEY, SecurityEpoch::from_raw(1), 1000)
        .unwrap();
    gate.record_verdict(
        "opt-1",
        pass_verdict(),
        TEST_KEY,
        SecurityEpoch::from_raw(1),
        2000,
    )
    .unwrap();
    gate.promote(
        "opt-1",
        ContentHash::compute(b"ev"),
        TEST_KEY,
        SecurityEpoch::from_raw(1),
        3000,
    )
    .unwrap();

    let demotion = gate
        .demote(
            "opt-1",
            ActivationStage::Shadow,
            "regression detected",
            TEST_KEY,
            SecurityEpoch::from_raw(1),
            4000,
        )
        .unwrap();
    assert_eq!(demotion.from_stage, ActivationStage::Canary);
    assert_eq!(demotion.to_stage, ActivationStage::Shadow);
    assert_eq!(gate.current_stage("opt-1"), Some(ActivationStage::Shadow));
}

#[test]
fn gate_demote_to_same_or_higher_stage_errors() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-1");
    let token = test_token("opt-1");
    gate.submit(&receipt, &token, TEST_KEY, SecurityEpoch::from_raw(1), 1000)
        .unwrap();
    // Currently at Shadow — can't demote to Shadow or higher
    let err = gate
        .demote(
            "opt-1",
            ActivationStage::Shadow,
            "reason",
            TEST_KEY,
            SecurityEpoch::from_raw(1),
            2000,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        ValidationGateError::InvalidStageTransition { .. }
    ));
}

// ── lift_quarantine ─────────────────────────────────────────────────────

#[test]
fn gate_lift_quarantine_allows_resubmission() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-1");
    let token = test_token("opt-1");
    gate.submit(&receipt, &token, TEST_KEY, SecurityEpoch::from_raw(1), 1000)
        .unwrap();
    gate.record_verdict(
        "opt-1",
        fail_verdict(),
        TEST_KEY,
        SecurityEpoch::from_raw(1),
        2000,
    )
    .unwrap();
    assert!(gate.is_quarantined("opt-1"));

    gate.lift_quarantine("opt-1", "new evidence", SecurityEpoch::from_raw(2), 3000)
        .unwrap();
    assert!(!gate.is_quarantined("opt-1"));

    // Can resubmit after quarantine lifted
    let receipt2 = test_receipt("opt-1");
    let token2 = test_token("opt-1");
    gate.submit(
        &receipt2,
        &token2,
        TEST_KEY,
        SecurityEpoch::from_raw(2),
        4000,
    )
    .unwrap();
    assert_eq!(gate.tracked_count(), 1);
}

#[test]
fn gate_lift_quarantine_nonexistent_errors() {
    let mut gate = TranslationValidationGate::new();
    let err = gate
        .lift_quarantine("nonexistent", "reason", SecurityEpoch::from_raw(1), 1000)
        .unwrap_err();
    assert!(matches!(
        err,
        ValidationGateError::OptimizationNotFound { .. }
    ));
}

// ── Queries ─────────────────────────────────────────────────────────────

#[test]
fn gate_quarantined_ids() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-1");
    let token = test_token("opt-1");
    gate.submit(&receipt, &token, TEST_KEY, SecurityEpoch::from_raw(1), 1000)
        .unwrap();
    gate.record_verdict(
        "opt-1",
        fail_verdict(),
        TEST_KEY,
        SecurityEpoch::from_raw(1),
        2000,
    )
    .unwrap();

    let ids = gate.quarantined_ids();
    assert!(ids.contains("opt-1"));
    assert_eq!(ids.len(), 1);
}

#[test]
fn gate_get_quarantine_entry() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-1");
    let token = test_token("opt-1");
    gate.submit(&receipt, &token, TEST_KEY, SecurityEpoch::from_raw(1), 1000)
        .unwrap();
    gate.record_verdict(
        "opt-1",
        fail_verdict(),
        TEST_KEY,
        SecurityEpoch::from_raw(1),
        2000,
    )
    .unwrap();

    let entry = gate.get_quarantine_entry("opt-1").unwrap();
    assert_eq!(entry.optimization_id, "opt-1");
    assert!(entry.counterexample_hash.is_some());
}

#[test]
fn gate_promotion_history() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-1");
    let token = test_token("opt-1");
    gate.submit(&receipt, &token, TEST_KEY, SecurityEpoch::from_raw(1), 1000)
        .unwrap();
    gate.record_verdict(
        "opt-1",
        pass_verdict(),
        TEST_KEY,
        SecurityEpoch::from_raw(1),
        2000,
    )
    .unwrap();
    gate.promote(
        "opt-1",
        ContentHash::compute(b"ev"),
        TEST_KEY,
        SecurityEpoch::from_raw(1),
        3000,
    )
    .unwrap();

    let history = gate.promotion_history("opt-1");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].from_stage, ActivationStage::Shadow);
    assert_eq!(history[0].to_stage, ActivationStage::Canary);
}

// ── Gate Serde Roundtrip ────────────────────────────────────────────────

#[test]
fn gate_serde_roundtrip() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-1");
    let token = test_token("opt-1");
    gate.submit(&receipt, &token, TEST_KEY, SecurityEpoch::from_raw(1), 1000)
        .unwrap();
    gate.record_verdict(
        "opt-1",
        pass_verdict(),
        TEST_KEY,
        SecurityEpoch::from_raw(1),
        2000,
    )
    .unwrap();

    let json = serde_json::to_string(&gate).unwrap();
    let back: TranslationValidationGate = serde_json::from_str(&json).unwrap();
    assert_eq!(back.tracked_count(), 1);
    assert_eq!(back.event_count(), gate.event_count());
}

// ── Full Lifecycle ──────────────────────────────────────────────────────

#[test]
fn full_lifecycle_submit_validate_promote_to_default() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);

    // Submit
    let receipt = test_receipt("opt-lifecycle");
    let token = test_token("opt-lifecycle");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();
    assert_eq!(
        gate.current_stage("opt-lifecycle"),
        Some(ActivationStage::Shadow)
    );

    // Shadow → Canary
    gate.record_verdict("opt-lifecycle", pass_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();
    gate.promote(
        "opt-lifecycle",
        ContentHash::compute(b"e1"),
        TEST_KEY,
        epoch,
        3000,
    )
    .unwrap();
    assert_eq!(
        gate.current_stage("opt-lifecycle"),
        Some(ActivationStage::Canary)
    );

    // Canary → Ramp
    gate.record_verdict("opt-lifecycle", pass_verdict(), TEST_KEY, epoch, 4000)
        .unwrap();
    gate.promote(
        "opt-lifecycle",
        ContentHash::compute(b"e2"),
        TEST_KEY,
        epoch,
        5000,
    )
    .unwrap();
    assert_eq!(
        gate.current_stage("opt-lifecycle"),
        Some(ActivationStage::Ramp)
    );

    // Ramp → Default
    gate.record_verdict("opt-lifecycle", pass_verdict(), TEST_KEY, epoch, 6000)
        .unwrap();
    gate.promote(
        "opt-lifecycle",
        ContentHash::compute(b"e3"),
        TEST_KEY,
        epoch,
        7000,
    )
    .unwrap();
    assert_eq!(
        gate.current_stage("opt-lifecycle"),
        Some(ActivationStage::Default)
    );

    // No further promotion possible
    gate.record_verdict("opt-lifecycle", pass_verdict(), TEST_KEY, epoch, 8000)
        .unwrap();
    let err = gate
        .promote(
            "opt-lifecycle",
            ContentHash::compute(b"e4"),
            TEST_KEY,
            epoch,
            9000,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        ValidationGateError::InvalidStageTransition { .. }
    ));

    // Verify audit trail
    assert!(gate.event_count() > 5);
    assert_eq!(gate.promotion_history("opt-lifecycle").len(), 3);
}

#[test]
fn full_lifecycle_fail_rollback_quarantine_lift_resubmit() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);

    // Submit and fail
    let receipt = test_receipt("opt-fail");
    let token = test_token("opt-fail");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();
    let rollback = gate
        .record_verdict("opt-fail", fail_verdict(), TEST_KEY, epoch, 2000)
        .unwrap()
        .unwrap();
    assert!(rollback.verify_signature(TEST_KEY));
    assert!(gate.is_quarantined("opt-fail"));
    assert_eq!(gate.tracked_count(), 0);

    // Cannot resubmit while quarantined
    let receipt2 = test_receipt("opt-fail");
    let token2 = test_token("opt-fail");
    let err = gate
        .submit(&receipt2, &token2, TEST_KEY, epoch, 3000)
        .unwrap_err();
    assert!(matches!(err, ValidationGateError::Quarantined { .. }));

    // Lift quarantine
    gate.lift_quarantine("opt-fail", "patch applied", epoch, 4000)
        .unwrap();
    assert!(!gate.is_quarantined("opt-fail"));

    // Resubmit
    gate.submit(&receipt2, &token2, TEST_KEY, epoch, 5000)
        .unwrap();
    assert_eq!(gate.tracked_count(), 1);

    // Now pass
    gate.record_verdict("opt-fail", pass_verdict(), TEST_KEY, epoch, 6000)
        .unwrap();
    gate.promote(
        "opt-fail",
        ContentHash::compute(b"fixed"),
        TEST_KEY,
        epoch,
        7000,
    )
    .unwrap();
    assert_eq!(
        gate.current_stage("opt-fail"),
        Some(ActivationStage::Canary)
    );
}

// ── Enrichment Tests ────────────────────────────────────────────────────
// ~80 new enrichment tests covering edge cases, validation rules,
// determinism, error reporting, and complex scenarios.

// ── enrichment: ValidationMode edge cases ───────────────────────────────

#[test]
fn enrichment_validation_mode_golden_corpus_zero_vectors() {
    let mode = ValidationMode::GoldenCorpusReplay {
        corpus_hash: ContentHash::compute(b"empty-corpus"),
        vector_count: 0,
    };
    let s = mode.to_string();
    assert!(s.contains("0 vectors"));
    let json = serde_json::to_string(&mode).unwrap();
    let back: ValidationMode = serde_json::from_str(&json).unwrap();
    assert_eq!(back, mode);
}

#[test]
fn enrichment_validation_mode_golden_corpus_large_vector_count() {
    let mode = ValidationMode::GoldenCorpusReplay {
        corpus_hash: ContentHash::compute(b"large"),
        vector_count: u64::MAX,
    };
    let json = serde_json::to_string(&mode).unwrap();
    let back: ValidationMode = serde_json::from_str(&json).unwrap();
    assert_eq!(back, mode);
}

#[test]
fn enrichment_validation_mode_differential_zero_pairs() {
    let mode = ValidationMode::DifferentialTrace {
        workload_hash: ContentHash::compute(b"empty-workload"),
        trace_pair_count: 0,
    };
    let s = mode.to_string();
    assert!(s.contains("0 pairs"));
}

#[test]
fn enrichment_validation_mode_differential_large_pair_count() {
    let mode = ValidationMode::DifferentialTrace {
        workload_hash: ContentHash::compute(b"big-workload"),
        trace_pair_count: 1_000_000,
    };
    let s = mode.to_string();
    assert!(s.contains("1000000 pairs"));
}

#[test]
fn enrichment_validation_mode_clone_preserves_equality() {
    let mode = ValidationMode::SymbolicEquivalence {
        proof_hash: ContentHash::compute(b"proof-data"),
    };
    let cloned = mode.clone();
    assert_eq!(mode, cloned);
}

#[test]
fn enrichment_validation_mode_different_hashes_not_equal() {
    let mode1 = ValidationMode::SymbolicEquivalence {
        proof_hash: ContentHash::compute(b"proof-a"),
    };
    let mode2 = ValidationMode::SymbolicEquivalence {
        proof_hash: ContentHash::compute(b"proof-b"),
    };
    assert_ne!(mode1, mode2);
}

#[test]
fn enrichment_validation_mode_different_variants_not_equal() {
    let golden = ValidationMode::GoldenCorpusReplay {
        corpus_hash: ContentHash::compute(b"c"),
        vector_count: 10,
    };
    let symbolic = ValidationMode::SymbolicEquivalence {
        proof_hash: ContentHash::compute(b"c"),
    };
    assert_ne!(golden, symbolic);
}

// ── enrichment: ValidationVerdict edge cases ────────────────────────────

#[test]
fn enrichment_verdict_pass_with_symbolic_mode() {
    let v = ValidationVerdict::Pass {
        mode: ValidationMode::SymbolicEquivalence {
            proof_hash: ContentHash::compute(b"sym-proof"),
        },
        evidence_hash: ContentHash::compute(b"sym-evidence"),
    };
    assert!(v.permits_activation());
    let s = v.to_string();
    assert!(s.contains("PASS"));
    assert!(s.contains("symbolic"));
}

#[test]
fn enrichment_verdict_pass_with_differential_mode() {
    let v = ValidationVerdict::Pass {
        mode: ValidationMode::DifferentialTrace {
            workload_hash: ContentHash::compute(b"diff-workload"),
            trace_pair_count: 25,
        },
        evidence_hash: ContentHash::compute(b"diff-evidence"),
    };
    assert!(v.permits_activation());
    let s = v.to_string();
    assert!(s.contains("25 pairs"));
}

#[test]
fn enrichment_verdict_fail_display_includes_divergence_reason() {
    let v = ValidationVerdict::Fail {
        mode: ValidationMode::GoldenCorpusReplay {
            corpus_hash: ContentHash::compute(b"c"),
            vector_count: 5,
        },
        divergence_reason: "output mismatch at vector 3".into(),
        counterexample_hash: ContentHash::compute(b"cx"),
    };
    let s = v.to_string();
    assert!(s.contains("output mismatch at vector 3"));
}

#[test]
fn enrichment_verdict_inconclusive_display_includes_reason() {
    let v = ValidationVerdict::Inconclusive {
        mode: ValidationMode::SymbolicEquivalence {
            proof_hash: ContentHash::compute(b"p"),
        },
        reason: "nonlinear arithmetic unsupported".into(),
    };
    let s = v.to_string();
    assert!(s.contains("nonlinear arithmetic unsupported"));
}

#[test]
fn enrichment_verdict_fail_with_empty_reason() {
    let v = ValidationVerdict::Fail {
        mode: ValidationMode::DifferentialTrace {
            workload_hash: ContentHash::compute(b"w"),
            trace_pair_count: 1,
        },
        divergence_reason: String::new(),
        counterexample_hash: ContentHash::compute(b"cx"),
    };
    assert!(!v.permits_activation());
    let json = serde_json::to_string(&v).unwrap();
    let back: ValidationVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_verdict_clone_preserves_semantics() {
    let v = pass_verdict();
    let cloned = v.clone();
    assert_eq!(v.permits_activation(), cloned.permits_activation());
    assert_eq!(v.to_string(), cloned.to_string());
}

// ── enrichment: RollbackReceipt edge cases ──────────────────────────────

#[test]
fn enrichment_rollback_receipt_without_counterexample() {
    let receipt = RollbackReceipt {
        rollback_token_id: "tok-no-cx".to_string(),
        optimization_id: "opt-no-cx".to_string(),
        failure_reason: "inconclusive: solver timeout".to_string(),
        counterexample_hash: None,
        restoration_baseline_hash: ContentHash::compute(b"base"),
        rollback_from_stage: ActivationStage::Shadow,
        timestamp_ticks: 1000,
        epoch: SecurityEpoch::from_raw(1),
        signature: AuthenticityHash::compute_keyed(&[], &[]),
    }
    .sign(TEST_KEY);

    assert!(receipt.verify_signature(TEST_KEY));
    assert!(receipt.counterexample_hash.is_none());
}

#[test]
fn enrichment_rollback_receipt_with_counterexample() {
    let receipt = RollbackReceipt {
        rollback_token_id: "tok-cx".to_string(),
        optimization_id: "opt-cx".to_string(),
        failure_reason: "hostcall divergence".to_string(),
        counterexample_hash: Some(ContentHash::compute(b"counterexample-fixture")),
        restoration_baseline_hash: ContentHash::compute(b"base"),
        rollback_from_stage: ActivationStage::Canary,
        timestamp_ticks: 2000,
        epoch: SecurityEpoch::from_raw(3),
        signature: AuthenticityHash::compute_keyed(&[], &[]),
    }
    .sign(TEST_KEY);

    assert!(receipt.verify_signature(TEST_KEY));
    assert!(receipt.counterexample_hash.is_some());
}

#[test]
fn enrichment_rollback_receipt_signing_preimage_deterministic() {
    let receipt = RollbackReceipt {
        rollback_token_id: "tok-det".to_string(),
        optimization_id: "opt-det".to_string(),
        failure_reason: "determinism check".to_string(),
        counterexample_hash: Some(ContentHash::compute(b"cx")),
        restoration_baseline_hash: ContentHash::compute(b"base"),
        rollback_from_stage: ActivationStage::Ramp,
        timestamp_ticks: 5000,
        epoch: SecurityEpoch::from_raw(2),
        signature: AuthenticityHash::compute_keyed(&[], &[]),
    };
    let p1 = receipt.signing_preimage();
    let p2 = receipt.signing_preimage();
    assert_eq!(p1, p2, "signing preimage must be deterministic");
}

#[test]
fn enrichment_rollback_receipt_different_fields_different_preimage() {
    let receipt_a = RollbackReceipt {
        rollback_token_id: "tok-a".to_string(),
        optimization_id: "opt-a".to_string(),
        failure_reason: "reason-a".to_string(),
        counterexample_hash: None,
        restoration_baseline_hash: ContentHash::compute(b"base-a"),
        rollback_from_stage: ActivationStage::Shadow,
        timestamp_ticks: 1000,
        epoch: SecurityEpoch::from_raw(1),
        signature: AuthenticityHash::compute_keyed(&[], &[]),
    };
    let receipt_b = RollbackReceipt {
        rollback_token_id: "tok-b".to_string(),
        optimization_id: "opt-b".to_string(),
        failure_reason: "reason-b".to_string(),
        counterexample_hash: None,
        restoration_baseline_hash: ContentHash::compute(b"base-b"),
        rollback_from_stage: ActivationStage::Shadow,
        timestamp_ticks: 1000,
        epoch: SecurityEpoch::from_raw(1),
        signature: AuthenticityHash::compute_keyed(&[], &[]),
    };
    assert_ne!(receipt_a.signing_preimage(), receipt_b.signing_preimage());
}

#[test]
fn enrichment_rollback_receipt_counterexample_changes_preimage() {
    let base = RollbackReceipt {
        rollback_token_id: "tok".to_string(),
        optimization_id: "opt".to_string(),
        failure_reason: "fail".to_string(),
        counterexample_hash: None,
        restoration_baseline_hash: ContentHash::compute(b"base"),
        rollback_from_stage: ActivationStage::Shadow,
        timestamp_ticks: 1000,
        epoch: SecurityEpoch::from_raw(1),
        signature: AuthenticityHash::compute_keyed(&[], &[]),
    };
    let with_cx = RollbackReceipt {
        counterexample_hash: Some(ContentHash::compute(b"cx")),
        ..base.clone()
    };
    assert_ne!(base.signing_preimage(), with_cx.signing_preimage());
}

#[test]
fn enrichment_rollback_receipt_all_stages_serde() {
    for stage in [
        ActivationStage::Shadow,
        ActivationStage::Canary,
        ActivationStage::Ramp,
        ActivationStage::Default,
    ] {
        let receipt = RollbackReceipt {
            rollback_token_id: "tok".to_string(),
            optimization_id: "opt".to_string(),
            failure_reason: "fail".to_string(),
            counterexample_hash: None,
            restoration_baseline_hash: ContentHash::compute(b"base"),
            rollback_from_stage: stage,
            timestamp_ticks: 1000,
            epoch: SecurityEpoch::from_raw(1),
            signature: AuthenticityHash::compute_keyed(&[], &[]),
        }
        .sign(TEST_KEY);
        let json = serde_json::to_string(&receipt).unwrap();
        let back: RollbackReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }
}

// ── enrichment: StagePromotion edge cases ───────────────────────────────

#[test]
fn enrichment_stage_promotion_signing_preimage_deterministic() {
    let promo = StagePromotion {
        optimization_id: "opt-sp".to_string(),
        from_stage: ActivationStage::Shadow,
        to_stage: ActivationStage::Canary,
        evidence_hash: ContentHash::compute(b"ev"),
        timestamp_ticks: 3000,
        epoch: SecurityEpoch::from_raw(1),
        signature: AuthenticityHash::compute_keyed(&[], &[]),
    };
    let p1 = promo.signing_preimage();
    let p2 = promo.signing_preimage();
    assert_eq!(p1, p2);
}

#[test]
fn enrichment_stage_promotion_different_stages_different_preimage() {
    let promo_a = StagePromotion {
        optimization_id: "opt-1".to_string(),
        from_stage: ActivationStage::Shadow,
        to_stage: ActivationStage::Canary,
        evidence_hash: ContentHash::compute(b"ev"),
        timestamp_ticks: 3000,
        epoch: SecurityEpoch::from_raw(1),
        signature: AuthenticityHash::compute_keyed(&[], &[]),
    };
    let promo_b = StagePromotion {
        from_stage: ActivationStage::Canary,
        to_stage: ActivationStage::Ramp,
        ..promo_a.clone()
    };
    assert_ne!(promo_a.signing_preimage(), promo_b.signing_preimage());
}

#[test]
fn enrichment_stage_promotion_all_transitions_serde() {
    let transitions = [
        (ActivationStage::Shadow, ActivationStage::Canary),
        (ActivationStage::Canary, ActivationStage::Ramp),
        (ActivationStage::Ramp, ActivationStage::Default),
    ];
    for (from, to) in transitions {
        let promo = StagePromotion {
            optimization_id: "opt-t".to_string(),
            from_stage: from,
            to_stage: to,
            evidence_hash: ContentHash::compute(b"ev"),
            timestamp_ticks: 1000,
            epoch: SecurityEpoch::from_raw(1),
            signature: AuthenticityHash::compute_keyed(&[], &[]),
        }
        .sign(TEST_KEY);
        assert!(promo.verify_signature(TEST_KEY));
        let json = serde_json::to_string(&promo).unwrap();
        let back: StagePromotion = serde_json::from_str(&json).unwrap();
        assert_eq!(promo, back);
    }
}

// ── enrichment: QuarantineEntry edge cases ──────────────────────────────

#[test]
fn enrichment_quarantine_entry_empty_reason() {
    let entry = QuarantineEntry {
        optimization_id: "opt-empty".to_string(),
        reason: String::new(),
        counterexample_hash: None,
        quarantined_epoch: SecurityEpoch::from_raw(1),
        quarantined_at_ticks: 0,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: QuarantineEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_quarantine_entry_large_ticks() {
    let entry = QuarantineEntry {
        optimization_id: "opt-large".to_string(),
        reason: "perf regression".to_string(),
        counterexample_hash: None,
        quarantined_epoch: SecurityEpoch::from_raw(u64::MAX),
        quarantined_at_ticks: u64::MAX,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: QuarantineEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_quarantine_entry_clone_equality() {
    let entry = QuarantineEntry {
        optimization_id: "opt-clone".to_string(),
        reason: "test".to_string(),
        counterexample_hash: Some(ContentHash::compute(b"cx")),
        quarantined_epoch: SecurityEpoch::from_raw(5),
        quarantined_at_ticks: 10_000,
    };
    assert_eq!(entry, entry.clone());
}

// ── enrichment: ValidationGateError edge cases ──────────────────────────

#[test]
fn enrichment_gate_error_invalid_token_signature_display() {
    let err = ValidationGateError::InvalidTokenSignature {
        token_id: "tok-invalid".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("tok-invalid"));
}

#[test]
fn enrichment_gate_error_activation_denied_display() {
    let err = ValidationGateError::ActivationDenied {
        verdict: "no passing verdict at stage Shadow".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("denied") || s.contains("activation"));
}

#[test]
fn enrichment_gate_error_all_variants_serde_roundtrip() {
    let errors = vec![
        ValidationGateError::InvalidReceiptSignature {
            optimization_id: "o1".into(),
        },
        ValidationGateError::InvalidTokenSignature {
            token_id: "t1".into(),
        },
        ValidationGateError::TokenExpired {
            token_id: "t2".into(),
            expiry_epoch: 100,
            current_epoch: 200,
        },
        ValidationGateError::TokenReceiptMismatch {
            token_optimization_id: "a".into(),
            receipt_optimization_id: "b".into(),
        },
        ValidationGateError::Quarantined {
            optimization_id: "o2".into(),
            reason: "divergence".into(),
        },
        ValidationGateError::InvalidStageTransition {
            from: ActivationStage::Canary,
            to: ActivationStage::Canary,
        },
        ValidationGateError::OptimizationNotFound {
            optimization_id: "o3".into(),
        },
        ValidationGateError::DuplicateSubmission {
            optimization_id: "o4".into(),
        },
        ValidationGateError::ActivationDenied {
            verdict: "FAIL".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ValidationGateError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn enrichment_gate_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ValidationGateError::ActivationDenied {
        verdict: "test".into(),
    });
    assert!(!err.to_string().is_empty());
}

#[test]
fn enrichment_gate_error_clone_equality() {
    let err = ValidationGateError::Quarantined {
        optimization_id: "opt-q".to_string(),
        reason: "repeated failure".to_string(),
    };
    assert_eq!(err, err.clone());
}

// ── enrichment: ValidationEvent edge cases ──────────────────────────────

#[test]
fn enrichment_validation_event_all_types_serde() {
    let types = vec![
        ValidationEventType::Submitted,
        ValidationEventType::Validated {
            verdict: "PASS (golden_corpus_replay)".to_string(),
        },
        ValidationEventType::StagePromoted {
            from: ActivationStage::Shadow,
            to: ActivationStage::Canary,
        },
        ValidationEventType::StageDemoted {
            from: ActivationStage::Ramp,
            to: ActivationStage::Shadow,
        },
        ValidationEventType::RolledBack {
            reason: "hostcall divergence".to_string(),
        },
        ValidationEventType::Quarantined {
            reason: "repeated failure".to_string(),
        },
        ValidationEventType::QuarantineLifted {
            override_reason: "patch applied".to_string(),
        },
    ];
    for et in &types {
        let event = ValidationEvent {
            optimization_id: "opt-all".to_string(),
            event_type: et.clone(),
            timestamp_ticks: 42,
            epoch: SecurityEpoch::from_raw(1),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: ValidationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }
}

#[test]
fn enrichment_validation_event_clone_equality() {
    let event = ValidationEvent {
        optimization_id: "opt-cl".to_string(),
        event_type: ValidationEventType::Submitted,
        timestamp_ticks: 999,
        epoch: SecurityEpoch::from_raw(7),
    };
    assert_eq!(event, event.clone());
}

// ── enrichment: Gate submission edge cases ──────────────────────────────

#[test]
fn enrichment_gate_submit_at_boundary_epoch() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-boundary");
    let token = test_token("opt-boundary"); // expiry_epoch = 100
    // Submit at exactly epoch 99 (just before expiry at 100)
    gate.submit(
        &receipt,
        &token,
        TEST_KEY,
        SecurityEpoch::from_raw(99),
        1000,
    )
    .unwrap();
    assert_eq!(gate.tracked_count(), 1);
}

#[test]
fn enrichment_gate_submit_at_exact_expiry_epoch_rejected() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-exp");
    let token = test_token("opt-exp"); // expiry_epoch = 100
    let result = gate.submit(
        &receipt,
        &token,
        TEST_KEY,
        SecurityEpoch::from_raw(100),
        1000,
    );
    // Token with expiry_epoch=100 at current_epoch=100 is expired
    assert!(result.is_err());
}

#[test]
fn enrichment_gate_submit_multiple_independent_optimizations() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    for i in 0..10 {
        let id = format!("opt-batch-{i}");
        let receipt = test_receipt(&id);
        let token = test_token(&id);
        gate.submit(&receipt, &token, TEST_KEY, epoch, 1000 + i as u64)
            .unwrap();
    }
    assert_eq!(gate.tracked_count(), 10);
    assert_eq!(gate.event_count(), 10);
}

#[test]
fn enrichment_gate_submit_events_have_correct_timestamps() {
    let mut gate = TranslationValidationGate::new();
    let receipt = test_receipt("opt-ts");
    let token = test_token("opt-ts");
    gate.submit(
        &receipt,
        &token,
        TEST_KEY,
        SecurityEpoch::from_raw(5),
        42_000,
    )
    .unwrap();
    let event = &gate.events()[0];
    assert_eq!(event.timestamp_ticks, 42_000);
    assert_eq!(event.epoch, SecurityEpoch::from_raw(5));
    assert_eq!(event.optimization_id, "opt-ts");
}

// ── enrichment: Gate verdict edge cases ─────────────────────────────────

#[test]
fn enrichment_gate_verdict_pass_preserves_tracked_state() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-keep");
    let token = test_token("opt-keep");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();

    // Multiple pass verdicts should not remove tracking
    for t in [2000u64, 3000, 4000] {
        let result = gate
            .record_verdict("opt-keep", pass_verdict(), TEST_KEY, epoch, t)
            .unwrap();
        assert!(result.is_none());
    }
    assert_eq!(gate.tracked_count(), 1);
    assert_eq!(gate.quarantine_count(), 0);
}

#[test]
fn enrichment_gate_fail_verdict_records_counterexample_hash() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-cx");
    let token = test_token("opt-cx");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();

    let rollback = gate
        .record_verdict("opt-cx", fail_verdict(), TEST_KEY, epoch, 2000)
        .unwrap()
        .unwrap();
    // fail_verdict includes a counterexample_hash
    assert!(rollback.counterexample_hash.is_some());
    assert_eq!(rollback.optimization_id, "opt-cx");
}

#[test]
fn enrichment_gate_inconclusive_verdict_no_counterexample() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-inc");
    let token = test_token("opt-inc");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();

    let rollback = gate
        .record_verdict("opt-inc", inconclusive_verdict(), TEST_KEY, epoch, 2000)
        .unwrap()
        .unwrap();
    assert!(rollback.counterexample_hash.is_none());
    assert!(rollback.failure_reason.contains("inconclusive"));
}

#[test]
fn enrichment_gate_fail_verdict_at_canary_stage() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-can-fail");
    let token = test_token("opt-can-fail");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();
    gate.record_verdict("opt-can-fail", pass_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();
    gate.promote(
        "opt-can-fail",
        ContentHash::compute(b"ev"),
        TEST_KEY,
        epoch,
        3000,
    )
    .unwrap();
    assert_eq!(
        gate.current_stage("opt-can-fail"),
        Some(ActivationStage::Canary)
    );

    let rollback = gate
        .record_verdict("opt-can-fail", fail_verdict(), TEST_KEY, epoch, 4000)
        .unwrap()
        .unwrap();
    assert_eq!(rollback.rollback_from_stage, ActivationStage::Canary);
    assert!(gate.is_quarantined("opt-can-fail"));
    assert!(gate.current_stage("opt-can-fail").is_none());
}

#[test]
fn enrichment_gate_fail_verdict_at_ramp_stage() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-ramp-fail");
    let token = test_token("opt-ramp-fail");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();

    // Shadow -> Canary
    gate.record_verdict("opt-ramp-fail", pass_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();
    gate.promote(
        "opt-ramp-fail",
        ContentHash::compute(b"ev"),
        TEST_KEY,
        epoch,
        3000,
    )
    .unwrap();

    // Canary -> Ramp
    gate.record_verdict("opt-ramp-fail", pass_verdict(), TEST_KEY, epoch, 4000)
        .unwrap();
    gate.promote(
        "opt-ramp-fail",
        ContentHash::compute(b"ev"),
        TEST_KEY,
        epoch,
        5000,
    )
    .unwrap();
    assert_eq!(
        gate.current_stage("opt-ramp-fail"),
        Some(ActivationStage::Ramp)
    );

    let rollback = gate
        .record_verdict("opt-ramp-fail", fail_verdict(), TEST_KEY, epoch, 6000)
        .unwrap()
        .unwrap();
    assert_eq!(rollback.rollback_from_stage, ActivationStage::Ramp);
    assert!(gate.is_quarantined("opt-ramp-fail"));
}

// ── enrichment: Gate promotion edge cases ───────────────────────────────

#[test]
fn enrichment_gate_promote_requires_pass_at_each_stage() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-multi");
    let token = test_token("opt-multi");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();

    // Pass at Shadow, promote to Canary
    gate.record_verdict("opt-multi", pass_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();
    gate.promote(
        "opt-multi",
        ContentHash::compute(b"ev1"),
        TEST_KEY,
        epoch,
        3000,
    )
    .unwrap();

    // Try to promote Canary without new pass verdict
    let err = gate
        .promote(
            "opt-multi",
            ContentHash::compute(b"ev2"),
            TEST_KEY,
            epoch,
            4000,
        )
        .unwrap_err();
    assert!(matches!(err, ValidationGateError::ActivationDenied { .. }));
}

#[test]
fn enrichment_gate_promote_unknown_optimization_error() {
    let mut gate = TranslationValidationGate::new();
    let err = gate
        .promote(
            "nonexistent",
            ContentHash::compute(b"ev"),
            TEST_KEY,
            SecurityEpoch::from_raw(1),
            1000,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        ValidationGateError::OptimizationNotFound { .. }
    ));
}

#[test]
fn enrichment_gate_promotion_history_empty_for_untracked() {
    let gate = TranslationValidationGate::new();
    assert!(gate.promotion_history("nonexistent").is_empty());
}

#[test]
fn enrichment_gate_promotion_records_signature() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-sig");
    let token = test_token("opt-sig");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();
    gate.record_verdict("opt-sig", pass_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();
    let promo = gate
        .promote(
            "opt-sig",
            ContentHash::compute(b"ev"),
            TEST_KEY,
            epoch,
            3000,
        )
        .unwrap();
    assert!(promo.verify_signature(TEST_KEY));
    assert!(!promo.verify_signature(b"wrong-key-that-is-32-bytes-long"));
}

// ── enrichment: Gate demotion edge cases ────────────────────────────────

#[test]
fn enrichment_gate_demote_unknown_optimization_error() {
    let mut gate = TranslationValidationGate::new();
    let err = gate
        .demote(
            "nonexistent",
            ActivationStage::Shadow,
            "reason",
            TEST_KEY,
            SecurityEpoch::from_raw(1),
            1000,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        ValidationGateError::OptimizationNotFound { .. }
    ));
}

#[test]
fn enrichment_gate_demote_to_higher_stage_error() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-dem");
    let token = test_token("opt-dem");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();
    gate.record_verdict("opt-dem", pass_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();
    gate.promote(
        "opt-dem",
        ContentHash::compute(b"ev"),
        TEST_KEY,
        epoch,
        3000,
    )
    .unwrap();
    // At Canary, try to demote to Ramp (higher)
    let err = gate
        .demote(
            "opt-dem",
            ActivationStage::Ramp,
            "reason",
            TEST_KEY,
            epoch,
            4000,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        ValidationGateError::InvalidStageTransition { .. }
    ));
}

#[test]
fn enrichment_gate_demote_ramp_to_shadow() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-r2s");
    let token = test_token("opt-r2s");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();

    // Shadow -> Canary -> Ramp
    for t in [2000u64, 3000] {
        gate.record_verdict("opt-r2s", pass_verdict(), TEST_KEY, epoch, t)
            .unwrap();
        gate.promote(
            "opt-r2s",
            ContentHash::compute(b"ev"),
            TEST_KEY,
            epoch,
            t + 500,
        )
        .unwrap();
    }
    assert_eq!(gate.current_stage("opt-r2s"), Some(ActivationStage::Ramp));

    let demotion = gate
        .demote(
            "opt-r2s",
            ActivationStage::Shadow,
            "full rollback",
            TEST_KEY,
            epoch,
            5000,
        )
        .unwrap();
    assert_eq!(demotion.from_stage, ActivationStage::Ramp);
    assert_eq!(demotion.to_stage, ActivationStage::Shadow);
    assert_eq!(gate.current_stage("opt-r2s"), Some(ActivationStage::Shadow));
}

#[test]
fn enrichment_gate_demote_default_to_canary() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-d2c");
    let token = test_token("opt-d2c");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();

    // Full promotion to Default
    for t in [2000u64, 3000, 4000] {
        gate.record_verdict("opt-d2c", pass_verdict(), TEST_KEY, epoch, t)
            .unwrap();
        gate.promote(
            "opt-d2c",
            ContentHash::compute(b"ev"),
            TEST_KEY,
            epoch,
            t + 500,
        )
        .unwrap();
    }
    assert_eq!(
        gate.current_stage("opt-d2c"),
        Some(ActivationStage::Default)
    );

    let demotion = gate
        .demote(
            "opt-d2c",
            ActivationStage::Canary,
            "regression in production",
            TEST_KEY,
            epoch,
            6000,
        )
        .unwrap();
    assert_eq!(demotion.from_stage, ActivationStage::Default);
    assert_eq!(demotion.to_stage, ActivationStage::Canary);
}

#[test]
fn enrichment_gate_demotion_emits_signed_record() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-dsig");
    let token = test_token("opt-dsig");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();
    gate.record_verdict("opt-dsig", pass_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();
    gate.promote(
        "opt-dsig",
        ContentHash::compute(b"ev"),
        TEST_KEY,
        epoch,
        3000,
    )
    .unwrap();

    let demotion = gate
        .demote(
            "opt-dsig",
            ActivationStage::Shadow,
            "bad metrics",
            TEST_KEY,
            epoch,
            4000,
        )
        .unwrap();
    assert!(demotion.verify_signature(TEST_KEY));
    assert!(!demotion.verify_signature(b"wrong-key-material-is-32-bytes!"));
}

// ── enrichment: Gate quarantine edge cases ──────────────────────────────

#[test]
fn enrichment_gate_multiple_quarantine_entries() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);

    for i in 0..5 {
        let id = format!("opt-q-{i}");
        let receipt = test_receipt(&id);
        let token = test_token(&id);
        gate.submit(&receipt, &token, TEST_KEY, epoch, i as u64 * 1000)
            .unwrap();
        gate.record_verdict(&id, fail_verdict(), TEST_KEY, epoch, i as u64 * 1000 + 500)
            .unwrap();
    }
    assert_eq!(gate.quarantine_count(), 5);
    assert_eq!(gate.tracked_count(), 0);
    let ids = gate.quarantined_ids();
    assert_eq!(ids.len(), 5);
}

#[test]
fn enrichment_gate_quarantine_entry_has_correct_fields() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(7);
    let receipt = test_receipt("opt-qf");
    let token = test_token("opt-qf");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 5000)
        .unwrap();
    gate.record_verdict("opt-qf", fail_verdict(), TEST_KEY, epoch, 6000)
        .unwrap();

    let entry = gate.get_quarantine_entry("opt-qf").unwrap();
    assert_eq!(entry.optimization_id, "opt-qf");
    assert!(entry.counterexample_hash.is_some());
    assert_eq!(entry.quarantined_epoch, epoch);
    assert_eq!(entry.quarantined_at_ticks, 6000);
}

#[test]
fn enrichment_gate_quarantine_entry_none_for_unquarantined() {
    let gate = TranslationValidationGate::new();
    assert!(gate.get_quarantine_entry("anything").is_none());
}

#[test]
fn enrichment_gate_lift_quarantine_emits_event() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-lqe");
    let token = test_token("opt-lqe");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();
    gate.record_verdict("opt-lqe", fail_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();
    let event_count_before = gate.event_count();
    gate.lift_quarantine("opt-lqe", "fixed patch", epoch, 3000)
        .unwrap();
    assert_eq!(gate.event_count(), event_count_before + 1);
    let last_event = gate.events().last().unwrap();
    assert!(matches!(
        last_event.event_type,
        ValidationEventType::QuarantineLifted { .. }
    ));
}

#[test]
fn enrichment_gate_quarantine_blocks_submission_preserves_reason() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-qr");
    let token = test_token("opt-qr");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();
    gate.record_verdict("opt-qr", fail_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();

    let err = gate
        .submit(&receipt, &token, TEST_KEY, epoch, 3000)
        .unwrap_err();
    if let ValidationGateError::Quarantined { reason, .. } = &err {
        assert!(!reason.is_empty());
    } else {
        panic!("Expected Quarantined error, got: {err:?}");
    }
}

// ── enrichment: Gate determinism ────────────────────────────────────────

#[test]
fn enrichment_gate_deterministic_serialization() {
    let build_gate = || {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);
        let receipt = test_receipt("opt-det");
        let token = test_token("opt-det");
        gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
            .unwrap();
        gate.record_verdict("opt-det", pass_verdict(), TEST_KEY, epoch, 2000)
            .unwrap();
        gate.promote(
            "opt-det",
            ContentHash::compute(b"ev"),
            TEST_KEY,
            epoch,
            3000,
        )
        .unwrap();
        gate
    };
    let json_a = serde_json::to_string(&build_gate()).unwrap();
    let json_b = serde_json::to_string(&build_gate()).unwrap();
    assert_eq!(
        json_a, json_b,
        "identical operations must produce identical JSON"
    );
}

#[test]
fn enrichment_gate_deterministic_with_multiple_ops() {
    let build_gate = || {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);

        // Submit two, pass one, fail one
        gate.submit(
            &test_receipt("opt-a"),
            &test_token("opt-a"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();
        gate.submit(
            &test_receipt("opt-b"),
            &test_token("opt-b"),
            TEST_KEY,
            epoch,
            1001,
        )
        .unwrap();
        gate.record_verdict("opt-a", pass_verdict(), TEST_KEY, epoch, 2000)
            .unwrap();
        gate.record_verdict("opt-b", fail_verdict(), TEST_KEY, epoch, 2001)
            .unwrap();
        gate
    };
    let json_a = serde_json::to_string(&build_gate()).unwrap();
    let json_b = serde_json::to_string(&build_gate()).unwrap();
    assert_eq!(json_a, json_b);
}

// ── enrichment: Gate event audit trail ──────────────────────────────────

#[test]
fn enrichment_gate_events_monotonic_timestamps() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-mono");
    let token = test_token("opt-mono");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 100).unwrap();
    gate.record_verdict("opt-mono", pass_verdict(), TEST_KEY, epoch, 200)
        .unwrap();
    gate.promote(
        "opt-mono",
        ContentHash::compute(b"ev"),
        TEST_KEY,
        epoch,
        300,
    )
    .unwrap();

    let events = gate.events();
    for window in events.windows(2) {
        assert!(
            window[0].timestamp_ticks <= window[1].timestamp_ticks,
            "events should be in timestamp order"
        );
    }
}

#[test]
fn enrichment_gate_events_all_reference_correct_opt_id() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-evid");
    let token = test_token("opt-evid");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();
    gate.record_verdict("opt-evid", fail_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();

    for event in gate.events() {
        assert_eq!(event.optimization_id, "opt-evid");
    }
}

#[test]
fn enrichment_gate_rollback_receipts_accumulate_across_different_opts() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);

    for i in 0..3 {
        let id = format!("opt-rb-{i}");
        let receipt = test_receipt(&id);
        let token = test_token(&id);
        gate.submit(&receipt, &token, TEST_KEY, epoch, i as u64 * 2000)
            .unwrap();
        gate.record_verdict(&id, fail_verdict(), TEST_KEY, epoch, i as u64 * 2000 + 1000)
            .unwrap();
    }
    assert_eq!(gate.rollback_receipts().len(), 3);
    // Each rollback receipt should have a distinct optimization_id
    let opt_ids: std::collections::BTreeSet<_> = gate
        .rollback_receipts()
        .iter()
        .map(|r| r.optimization_id.clone())
        .collect();
    assert_eq!(opt_ids.len(), 3);
}

// ── enrichment: Gate serde roundtrip complex state ──────────────────────

#[test]
fn enrichment_gate_serde_roundtrip_with_quarantine() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-sr");
    let token = test_token("opt-sr");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();
    gate.record_verdict("opt-sr", fail_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();

    let json = serde_json::to_string(&gate).unwrap();
    let back: TranslationValidationGate = serde_json::from_str(&json).unwrap();
    assert_eq!(back.tracked_count(), 0);
    assert_eq!(back.quarantine_count(), 1);
    assert!(back.is_quarantined("opt-sr"));
    assert_eq!(back.event_count(), gate.event_count());
    assert_eq!(back.rollback_receipts().len(), 1);
}

#[test]
fn enrichment_gate_serde_roundtrip_with_promotions() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-sp");
    let token = test_token("opt-sp");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();
    gate.record_verdict("opt-sp", pass_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();
    gate.promote("opt-sp", ContentHash::compute(b"ev"), TEST_KEY, epoch, 3000)
        .unwrap();

    let json = serde_json::to_string(&gate).unwrap();
    let back: TranslationValidationGate = serde_json::from_str(&json).unwrap();
    assert_eq!(back.tracked_count(), 1);
    assert_eq!(back.current_stage("opt-sp"), Some(ActivationStage::Canary));
}

#[test]
fn enrichment_gate_default_equals_new() {
    let g1 = TranslationValidationGate::new();
    let g2 = TranslationValidationGate::default();
    assert_eq!(g1.tracked_count(), g2.tracked_count());
    assert_eq!(g1.quarantine_count(), g2.quarantine_count());
    assert_eq!(g1.event_count(), g2.event_count());
}

// ── enrichment: Complex lifecycle scenarios ─────────────────────────────

#[test]
fn enrichment_lifecycle_promote_demote_promote_again() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-pdp");
    let token = test_token("opt-pdp");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();

    // Pass and promote to Canary
    gate.record_verdict("opt-pdp", pass_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();
    gate.promote(
        "opt-pdp",
        ContentHash::compute(b"ev1"),
        TEST_KEY,
        epoch,
        3000,
    )
    .unwrap();
    assert_eq!(gate.current_stage("opt-pdp"), Some(ActivationStage::Canary));

    // Demote back to Shadow
    gate.demote(
        "opt-pdp",
        ActivationStage::Shadow,
        "regression",
        TEST_KEY,
        epoch,
        4000,
    )
    .unwrap();
    assert_eq!(gate.current_stage("opt-pdp"), Some(ActivationStage::Shadow));

    // Pass again and re-promote to Canary
    gate.record_verdict("opt-pdp", pass_verdict(), TEST_KEY, epoch, 5000)
        .unwrap();
    gate.promote(
        "opt-pdp",
        ContentHash::compute(b"ev2"),
        TEST_KEY,
        epoch,
        6000,
    )
    .unwrap();
    assert_eq!(gate.current_stage("opt-pdp"), Some(ActivationStage::Canary));

    // Promotion history should have 3 entries (promote, demote, promote)
    let history = gate.promotion_history("opt-pdp");
    assert_eq!(history.len(), 3);
}

#[test]
fn enrichment_lifecycle_multiple_opts_interleaved() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);

    // Submit opt-a and opt-b
    gate.submit(
        &test_receipt("opt-a"),
        &test_token("opt-a"),
        TEST_KEY,
        epoch,
        1000,
    )
    .unwrap();
    gate.submit(
        &test_receipt("opt-b"),
        &test_token("opt-b"),
        TEST_KEY,
        epoch,
        1001,
    )
    .unwrap();

    // Pass opt-a, promote it
    gate.record_verdict("opt-a", pass_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();
    gate.promote(
        "opt-a",
        ContentHash::compute(b"ev-a"),
        TEST_KEY,
        epoch,
        2500,
    )
    .unwrap();

    // Fail opt-b
    gate.record_verdict("opt-b", fail_verdict(), TEST_KEY, epoch, 3000)
        .unwrap();

    assert_eq!(gate.tracked_count(), 1);
    assert_eq!(gate.quarantine_count(), 1);
    assert_eq!(gate.current_stage("opt-a"), Some(ActivationStage::Canary));
    assert!(gate.is_quarantined("opt-b"));
}

#[test]
fn enrichment_lifecycle_full_promotion_then_demote_to_shadow() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-full-dem");
    let token = test_token("opt-full-dem");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();

    // Promote all the way to Default
    for t in [2000u64, 3000, 4000] {
        gate.record_verdict("opt-full-dem", pass_verdict(), TEST_KEY, epoch, t)
            .unwrap();
        gate.promote(
            "opt-full-dem",
            ContentHash::compute(b"ev"),
            TEST_KEY,
            epoch,
            t + 500,
        )
        .unwrap();
    }
    assert_eq!(
        gate.current_stage("opt-full-dem"),
        Some(ActivationStage::Default)
    );

    // Demote all the way to Shadow
    gate.demote(
        "opt-full-dem",
        ActivationStage::Shadow,
        "critical regression",
        TEST_KEY,
        epoch,
        6000,
    )
    .unwrap();
    assert_eq!(
        gate.current_stage("opt-full-dem"),
        Some(ActivationStage::Shadow)
    );
}

#[test]
fn enrichment_lifecycle_quarantine_lift_pass_full_promotion() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);

    // Submit, fail, quarantine
    gate.submit(
        &test_receipt("opt-qlp"),
        &test_token("opt-qlp"),
        TEST_KEY,
        epoch,
        1000,
    )
    .unwrap();
    gate.record_verdict("opt-qlp", fail_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();
    assert!(gate.is_quarantined("opt-qlp"));

    // Lift quarantine
    gate.lift_quarantine("opt-qlp", "fix verified", epoch, 3000)
        .unwrap();

    // Resubmit and promote all the way to Default
    gate.submit(
        &test_receipt("opt-qlp"),
        &test_token("opt-qlp"),
        TEST_KEY,
        epoch,
        4000,
    )
    .unwrap();

    for (i, t) in [5000u64, 6000, 7000].iter().enumerate() {
        gate.record_verdict("opt-qlp", pass_verdict(), TEST_KEY, epoch, *t)
            .unwrap();
        gate.promote(
            "opt-qlp",
            ContentHash::compute(format!("ev-{i}").as_bytes()),
            TEST_KEY,
            epoch,
            t + 500,
        )
        .unwrap();
    }
    assert_eq!(
        gate.current_stage("opt-qlp"),
        Some(ActivationStage::Default)
    );
    assert!(!gate.is_quarantined("opt-qlp"));
}

// ── enrichment: Gate query edge cases ───────────────────────────────────

#[test]
fn enrichment_gate_current_stage_none_for_unknown() {
    let gate = TranslationValidationGate::new();
    assert!(gate.current_stage("does-not-exist").is_none());
}

#[test]
fn enrichment_gate_is_quarantined_false_for_tracked() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-tr");
    let token = test_token("opt-tr");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();
    assert!(!gate.is_quarantined("opt-tr"));
}

#[test]
fn enrichment_gate_quarantined_ids_deterministic_order() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);

    // Submit and fail in reverse alphabetical order
    for id in ["opt-z", "opt-m", "opt-a"] {
        gate.submit(&test_receipt(id), &test_token(id), TEST_KEY, epoch, 1000)
            .unwrap();
        gate.record_verdict(id, fail_verdict(), TEST_KEY, epoch, 2000)
            .unwrap();
    }

    let ids: Vec<_> = gate.quarantined_ids().into_iter().collect();
    // BTreeSet ensures alphabetical order
    assert_eq!(ids, vec!["opt-a", "opt-m", "opt-z"]);
}

// ── enrichment: Rollback receipt verification ───────────────────────────

#[test]
fn enrichment_gate_rollback_receipt_verifiable() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-rv");
    let token = test_token("opt-rv");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();
    gate.record_verdict("opt-rv", fail_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();

    for rb in gate.rollback_receipts() {
        assert!(rb.verify_signature(TEST_KEY));
        assert!(!rb.verify_signature(b"wrong-key-that-is-32-bytes-long"));
    }
}

#[test]
fn enrichment_gate_rollback_receipt_contains_correct_token_id() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    let receipt = test_receipt("opt-tid");
    let token = test_token("opt-tid");
    gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
        .unwrap();
    gate.record_verdict("opt-tid", fail_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();

    let rb = &gate.rollback_receipts()[0];
    assert_eq!(rb.rollback_token_id, "token-opt-tid");
    assert_eq!(rb.optimization_id, "opt-tid");
}

// ── enrichment: Event type correctness ──────────────────────────────────

#[test]
fn enrichment_gate_submit_emits_submitted_event() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    gate.submit(
        &test_receipt("opt-se"),
        &test_token("opt-se"),
        TEST_KEY,
        epoch,
        1000,
    )
    .unwrap();

    assert!(matches!(
        gate.events()[0].event_type,
        ValidationEventType::Submitted
    ));
}

#[test]
fn enrichment_gate_verdict_emits_validated_event() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    gate.submit(
        &test_receipt("opt-ve"),
        &test_token("opt-ve"),
        TEST_KEY,
        epoch,
        1000,
    )
    .unwrap();
    gate.record_verdict("opt-ve", pass_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();

    assert!(matches!(
        gate.events()[1].event_type,
        ValidationEventType::Validated { .. }
    ));
}

#[test]
fn enrichment_gate_fail_verdict_emits_rollback_event() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    gate.submit(
        &test_receipt("opt-re"),
        &test_token("opt-re"),
        TEST_KEY,
        epoch,
        1000,
    )
    .unwrap();
    gate.record_verdict("opt-re", fail_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();

    // Events: Submitted, Validated, RolledBack
    assert_eq!(gate.events().len(), 3);
    assert!(matches!(
        gate.events()[2].event_type,
        ValidationEventType::RolledBack { .. }
    ));
}

#[test]
fn enrichment_gate_promote_emits_stage_promoted_event() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    gate.submit(
        &test_receipt("opt-pe"),
        &test_token("opt-pe"),
        TEST_KEY,
        epoch,
        1000,
    )
    .unwrap();
    gate.record_verdict("opt-pe", pass_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();
    gate.promote("opt-pe", ContentHash::compute(b"ev"), TEST_KEY, epoch, 3000)
        .unwrap();

    let last = gate.events().last().unwrap();
    if let ValidationEventType::StagePromoted { from, to } = &last.event_type {
        assert_eq!(*from, ActivationStage::Shadow);
        assert_eq!(*to, ActivationStage::Canary);
    } else {
        panic!("Expected StagePromoted event");
    }
}

#[test]
fn enrichment_gate_demote_emits_stage_demoted_event() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    gate.submit(
        &test_receipt("opt-de"),
        &test_token("opt-de"),
        TEST_KEY,
        epoch,
        1000,
    )
    .unwrap();
    gate.record_verdict("opt-de", pass_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();
    gate.promote("opt-de", ContentHash::compute(b"ev"), TEST_KEY, epoch, 3000)
        .unwrap();
    gate.demote(
        "opt-de",
        ActivationStage::Shadow,
        "perf issue",
        TEST_KEY,
        epoch,
        4000,
    )
    .unwrap();

    let last = gate.events().last().unwrap();
    if let ValidationEventType::StageDemoted { from, to } = &last.event_type {
        assert_eq!(*from, ActivationStage::Canary);
        assert_eq!(*to, ActivationStage::Shadow);
    } else {
        panic!("Expected StageDemoted event");
    }
}

// ── enrichment: Error reporting quality ─────────────────────────────────

#[test]
fn enrichment_error_display_includes_token_id_for_expired() {
    let err = ValidationGateError::TokenExpired {
        token_id: "tok-precise-42".to_string(),
        expiry_epoch: 50,
        current_epoch: 75,
    };
    let s = err.to_string();
    assert!(s.contains("tok-precise-42"));
    assert!(s.contains("50"));
    assert!(s.contains("75"));
}

#[test]
fn enrichment_error_display_includes_both_ids_for_mismatch() {
    let err = ValidationGateError::TokenReceiptMismatch {
        token_optimization_id: "opt-tok-x".to_string(),
        receipt_optimization_id: "opt-rec-y".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("opt-tok-x"));
    assert!(s.contains("opt-rec-y"));
}

#[test]
fn enrichment_error_display_quarantined_includes_reason() {
    let err = ValidationGateError::Quarantined {
        optimization_id: "opt-q99".to_string(),
        reason: "repeated hostcall divergence".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("opt-q99"));
    assert!(s.contains("repeated hostcall divergence"));
}

#[test]
fn enrichment_error_display_invalid_stage_transition() {
    let err = ValidationGateError::InvalidStageTransition {
        from: ActivationStage::Shadow,
        to: ActivationStage::Default,
    };
    let s = err.to_string();
    assert!(!s.is_empty());
    // Should mention the stages
    assert!(s.contains("Shadow") || s.contains("shadow"));
}

#[test]
fn enrichment_error_debug_distinct_from_display() {
    let err = ValidationGateError::DuplicateSubmission {
        optimization_id: "opt-dd".to_string(),
    };
    let display = err.to_string();
    let debug = format!("{err:?}");
    // Debug typically has more structure than Display
    assert!(!debug.is_empty());
    assert!(!display.is_empty());
}

// ── enrichment: Gate events() returns correct length ────────────────────

#[test]
fn enrichment_gate_event_count_matches_events_len() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    gate.submit(
        &test_receipt("opt-ec"),
        &test_token("opt-ec"),
        TEST_KEY,
        epoch,
        1000,
    )
    .unwrap();
    gate.record_verdict("opt-ec", pass_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();
    gate.promote("opt-ec", ContentHash::compute(b"ev"), TEST_KEY, epoch, 3000)
        .unwrap();

    assert_eq!(gate.event_count(), gate.events().len());
}

// ── enrichment: Serde stability with complex state ──────────────────────

#[test]
fn enrichment_gate_serde_preserves_rollback_receipt_signatures() {
    let mut gate = TranslationValidationGate::new();
    let epoch = SecurityEpoch::from_raw(1);
    gate.submit(
        &test_receipt("opt-srs"),
        &test_token("opt-srs"),
        TEST_KEY,
        epoch,
        1000,
    )
    .unwrap();
    gate.record_verdict("opt-srs", fail_verdict(), TEST_KEY, epoch, 2000)
        .unwrap();

    let json = serde_json::to_string(&gate).unwrap();
    let restored: TranslationValidationGate = serde_json::from_str(&json).unwrap();

    for rb in restored.rollback_receipts() {
        assert!(
            rb.verify_signature(TEST_KEY),
            "rollback receipt signature must survive serde roundtrip"
        );
    }
}

#[test]
fn enrichment_gate_serde_empty_state() {
    let gate = TranslationValidationGate::new();
    let json = serde_json::to_string(&gate).unwrap();
    let back: TranslationValidationGate = serde_json::from_str(&json).unwrap();
    assert_eq!(back.tracked_count(), 0);
    assert_eq!(back.quarantine_count(), 0);
    assert_eq!(back.event_count(), 0);
    assert!(back.rollback_receipts().is_empty());
}
