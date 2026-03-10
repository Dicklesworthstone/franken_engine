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
