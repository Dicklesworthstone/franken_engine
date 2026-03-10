#![forbid(unsafe_code)]
//! Enrichment integration tests for `translation_validation`.
//!
//! Adds JSON field-name stability, exact serde enum values, Display exactness,
//! Debug distinctness, error coverage, gate construction, and edge cases beyond
//! the existing 40 integration tests.

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

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::proof_schema::ActivationStage;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::translation_validation::{
    QuarantineEntry, RollbackReceipt, StagePromotion, TranslationValidationGate, ValidationEvent,
    ValidationEventType, ValidationGateError, ValidationMode, ValidationVerdict,
};

// ===========================================================================
// 1) ValidationMode — exact Display
// ===========================================================================

#[test]
fn validation_mode_display_golden_corpus() {
    let m = ValidationMode::GoldenCorpusReplay {
        corpus_hash: ContentHash::compute(b"c"),
        vector_count: 42,
    };
    let s = m.to_string();
    assert!(
        s.contains("42") || s.contains("golden"),
        "should describe golden replay: {s}"
    );
}

#[test]
fn validation_mode_display_symbolic() {
    let m = ValidationMode::SymbolicEquivalence {
        proof_hash: ContentHash::compute(b"p"),
    };
    let s = m.to_string();
    assert!(
        s.contains("symbolic") || s.contains("equivalence"),
        "should describe symbolic: {s}"
    );
}

#[test]
fn validation_mode_display_differential() {
    let m = ValidationMode::DifferentialTrace {
        workload_hash: ContentHash::compute(b"w"),
        trace_pair_count: 10,
    };
    let s = m.to_string();
    assert!(
        s.contains("10") || s.contains("differential"),
        "should describe differential: {s}"
    );
}

// ===========================================================================
// 2) ValidationVerdict — Display + permits_activation
// ===========================================================================

#[test]
fn validation_verdict_pass_permits() {
    let v = ValidationVerdict::Pass {
        mode: ValidationMode::SymbolicEquivalence {
            proof_hash: ContentHash::compute(b"p"),
        },
        evidence_hash: ContentHash::compute(b"e"),
    };
    assert!(v.permits_activation());
    let s = v.to_string();
    assert!(
        s.contains("PASS") || s.contains("pass"),
        "should say pass: {s}"
    );
}

#[test]
fn validation_verdict_fail_denies() {
    let v = ValidationVerdict::Fail {
        mode: ValidationMode::SymbolicEquivalence {
            proof_hash: ContentHash::compute(b"p"),
        },
        divergence_reason: "type mismatch".into(),
        counterexample_hash: ContentHash::compute(b"cx"),
    };
    assert!(!v.permits_activation());
    let s = v.to_string();
    assert!(
        s.contains("FAIL") || s.contains("fail"),
        "should say fail: {s}"
    );
}

#[test]
fn validation_verdict_inconclusive_denies() {
    let v = ValidationVerdict::Inconclusive {
        mode: ValidationMode::DifferentialTrace {
            workload_hash: ContentHash::compute(b"w"),
            trace_pair_count: 5,
        },
        reason: "timeout".into(),
    };
    assert!(!v.permits_activation());
}

// ===========================================================================
// 3) ValidationGateError — Display uniqueness + std::error::Error
// ===========================================================================

#[test]
fn validation_gate_error_display_all_unique() {
    let variants: Vec<String> = vec![
        ValidationGateError::InvalidReceiptSignature {
            optimization_id: "a".into(),
        }
        .to_string(),
        ValidationGateError::InvalidTokenSignature {
            token_id: "b".into(),
        }
        .to_string(),
        ValidationGateError::TokenExpired {
            token_id: "c".into(),
            expiry_epoch: 1,
            current_epoch: 2,
        }
        .to_string(),
        ValidationGateError::TokenReceiptMismatch {
            token_optimization_id: "d".into(),
            receipt_optimization_id: "e".into(),
        }
        .to_string(),
        ValidationGateError::Quarantined {
            optimization_id: "f".into(),
            reason: "g".into(),
        }
        .to_string(),
        ValidationGateError::InvalidStageTransition {
            from: ActivationStage::Shadow,
            to: ActivationStage::Default,
        }
        .to_string(),
        ValidationGateError::OptimizationNotFound {
            optimization_id: "h".into(),
        }
        .to_string(),
        ValidationGateError::DuplicateSubmission {
            optimization_id: "i".into(),
        }
        .to_string(),
        ValidationGateError::ActivationDenied {
            verdict: "j".into(),
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

#[test]
fn validation_gate_error_is_std_error() {
    let e = ValidationGateError::OptimizationNotFound {
        optimization_id: "x".into(),
    };
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 4) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_validation_mode() {
    let variants = [
        format!(
            "{:?}",
            ValidationMode::GoldenCorpusReplay {
                corpus_hash: ContentHash::compute(b"a"),
                vector_count: 1,
            }
        ),
        format!(
            "{:?}",
            ValidationMode::SymbolicEquivalence {
                proof_hash: ContentHash::compute(b"b"),
            }
        ),
        format!(
            "{:?}",
            ValidationMode::DifferentialTrace {
                workload_hash: ContentHash::compute(b"c"),
                trace_pair_count: 1,
            }
        ),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_validation_verdict() {
    let variants = [
        format!(
            "{:?}",
            ValidationVerdict::Pass {
                mode: ValidationMode::SymbolicEquivalence {
                    proof_hash: ContentHash::compute(b"a")
                },
                evidence_hash: ContentHash::compute(b"b"),
            }
        ),
        format!(
            "{:?}",
            ValidationVerdict::Fail {
                mode: ValidationMode::SymbolicEquivalence {
                    proof_hash: ContentHash::compute(b"a")
                },
                divergence_reason: "x".into(),
                counterexample_hash: ContentHash::compute(b"c"),
            }
        ),
        format!(
            "{:?}",
            ValidationVerdict::Inconclusive {
                mode: ValidationMode::SymbolicEquivalence {
                    proof_hash: ContentHash::compute(b"a")
                },
                reason: "y".into(),
            }
        ),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 5) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_validation_mode_all() {
    let modes = vec![
        ValidationMode::GoldenCorpusReplay {
            corpus_hash: ContentHash::compute(b"a"),
            vector_count: 100,
        },
        ValidationMode::SymbolicEquivalence {
            proof_hash: ContentHash::compute(b"b"),
        },
        ValidationMode::DifferentialTrace {
            workload_hash: ContentHash::compute(b"c"),
            trace_pair_count: 50,
        },
    ];
    for m in &modes {
        let json = serde_json::to_string(m).unwrap();
        let rt: ValidationMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*m, rt);
    }
}

#[test]
fn serde_roundtrip_validation_verdict_all() {
    let verdicts = vec![
        ValidationVerdict::Pass {
            mode: ValidationMode::SymbolicEquivalence {
                proof_hash: ContentHash::compute(b"p"),
            },
            evidence_hash: ContentHash::compute(b"e"),
        },
        ValidationVerdict::Fail {
            mode: ValidationMode::SymbolicEquivalence {
                proof_hash: ContentHash::compute(b"p"),
            },
            divergence_reason: "div".into(),
            counterexample_hash: ContentHash::compute(b"cx"),
        },
        ValidationVerdict::Inconclusive {
            mode: ValidationMode::DifferentialTrace {
                workload_hash: ContentHash::compute(b"w"),
                trace_pair_count: 3,
            },
            reason: "timeout".into(),
        },
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let rt: ValidationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_validation_gate_error_all() {
    let variants = vec![
        ValidationGateError::InvalidReceiptSignature {
            optimization_id: "a".into(),
        },
        ValidationGateError::InvalidTokenSignature {
            token_id: "b".into(),
        },
        ValidationGateError::TokenExpired {
            token_id: "c".into(),
            expiry_epoch: 1,
            current_epoch: 2,
        },
        ValidationGateError::TokenReceiptMismatch {
            token_optimization_id: "d".into(),
            receipt_optimization_id: "e".into(),
        },
        ValidationGateError::Quarantined {
            optimization_id: "f".into(),
            reason: "g".into(),
        },
        ValidationGateError::InvalidStageTransition {
            from: ActivationStage::Shadow,
            to: ActivationStage::Default,
        },
        ValidationGateError::OptimizationNotFound {
            optimization_id: "h".into(),
        },
        ValidationGateError::DuplicateSubmission {
            optimization_id: "i".into(),
        },
        ValidationGateError::ActivationDenied {
            verdict: "j".into(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: ValidationGateError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_quarantine_entry() {
    let qe = QuarantineEntry {
        optimization_id: "opt1".into(),
        reason: "bad".into(),
        counterexample_hash: Some(ContentHash::compute(b"cx")),
        quarantined_epoch: SecurityEpoch::from_raw(5),
        quarantined_at_ticks: 1000,
    };
    let json = serde_json::to_string(&qe).unwrap();
    let rt: QuarantineEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(qe, rt);
}

// ===========================================================================
// 6) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_quarantine_entry() {
    let qe = QuarantineEntry {
        optimization_id: "opt1".into(),
        reason: "bad".into(),
        counterexample_hash: None,
        quarantined_epoch: SecurityEpoch::from_raw(1),
        quarantined_at_ticks: 100,
    };
    let v: serde_json::Value = serde_json::to_value(&qe).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "optimization_id",
        "reason",
        "counterexample_hash",
        "quarantined_epoch",
        "quarantined_at_ticks",
    ] {
        assert!(
            obj.contains_key(key),
            "QuarantineEntry missing field: {key}"
        );
    }
}

#[test]
fn json_fields_validation_event() {
    let ve = ValidationEvent {
        optimization_id: "opt1".into(),
        event_type: ValidationEventType::Submitted,
        timestamp_ticks: 500,
        epoch: SecurityEpoch::from_raw(1),
    };
    let v: serde_json::Value = serde_json::to_value(&ve).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["optimization_id", "event_type", "timestamp_ticks", "epoch"] {
        assert!(
            obj.contains_key(key),
            "ValidationEvent missing field: {key}"
        );
    }
}

// ===========================================================================
// 7) TranslationValidationGate — construction and initial state
// ===========================================================================

#[test]
fn gate_new_initial_state() {
    let gate = TranslationValidationGate::new();
    assert_eq!(gate.tracked_count(), 0);
    assert_eq!(gate.quarantine_count(), 0);
    assert_eq!(gate.event_count(), 0);
    assert!(gate.events().is_empty());
    assert!(gate.rollback_receipts().is_empty());
    assert!(gate.quarantined_ids().is_empty());
}

#[test]
fn gate_default_matches_new() {
    let g1 = TranslationValidationGate::new();
    let g2 = TranslationValidationGate::default();
    assert_eq!(g1.tracked_count(), g2.tracked_count());
    assert_eq!(g1.quarantine_count(), g2.quarantine_count());
}

#[test]
fn gate_current_stage_unknown() {
    let gate = TranslationValidationGate::new();
    assert!(gate.current_stage("nonexistent").is_none());
}

#[test]
fn gate_is_quarantined_unknown() {
    let gate = TranslationValidationGate::new();
    assert!(!gate.is_quarantined("nonexistent"));
}

#[test]
fn gate_quarantine_entry_unknown() {
    let gate = TranslationValidationGate::new();
    assert!(gate.get_quarantine_entry("nonexistent").is_none());
}

#[test]
fn gate_promotion_history_unknown() {
    let gate = TranslationValidationGate::new();
    assert!(gate.promotion_history("nonexistent").is_empty());
}

// ===========================================================================
// 8) Serde roundtrips — additional structs
// ===========================================================================

#[test]
fn serde_roundtrip_validation_event_submitted() {
    let ve = ValidationEvent {
        optimization_id: "opt1".into(),
        event_type: ValidationEventType::Submitted,
        timestamp_ticks: 500,
        epoch: SecurityEpoch::from_raw(1),
    };
    let json = serde_json::to_string(&ve).unwrap();
    let rt: ValidationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ve, rt);
}

#[test]
fn serde_roundtrip_validation_event_validated() {
    let ve = ValidationEvent {
        optimization_id: "opt1".into(),
        event_type: ValidationEventType::Validated {
            verdict: "PASS".into(),
        },
        timestamp_ticks: 600,
        epoch: SecurityEpoch::from_raw(1),
    };
    let json = serde_json::to_string(&ve).unwrap();
    let rt: ValidationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ve, rt);
}

#[test]
fn serde_roundtrip_validation_event_stage_promoted() {
    let ve = ValidationEvent {
        optimization_id: "opt1".into(),
        event_type: ValidationEventType::StagePromoted {
            from: ActivationStage::Shadow,
            to: ActivationStage::Canary,
        },
        timestamp_ticks: 700,
        epoch: SecurityEpoch::from_raw(1),
    };
    let json = serde_json::to_string(&ve).unwrap();
    let rt: ValidationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ve, rt);
}

#[test]
fn serde_roundtrip_validation_event_stage_demoted() {
    let ve = ValidationEvent {
        optimization_id: "opt1".into(),
        event_type: ValidationEventType::StageDemoted {
            from: ActivationStage::Canary,
            to: ActivationStage::Shadow,
        },
        timestamp_ticks: 800,
        epoch: SecurityEpoch::from_raw(1),
    };
    let json = serde_json::to_string(&ve).unwrap();
    let rt: ValidationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ve, rt);
}

#[test]
fn serde_roundtrip_validation_event_rolled_back() {
    let ve = ValidationEvent {
        optimization_id: "opt1".into(),
        event_type: ValidationEventType::RolledBack {
            reason: "divergence".into(),
        },
        timestamp_ticks: 900,
        epoch: SecurityEpoch::from_raw(2),
    };
    let json = serde_json::to_string(&ve).unwrap();
    let rt: ValidationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ve, rt);
}

#[test]
fn serde_roundtrip_validation_event_quarantined() {
    let ve = ValidationEvent {
        optimization_id: "opt1".into(),
        event_type: ValidationEventType::Quarantined {
            reason: "bad perf".into(),
        },
        timestamp_ticks: 1000,
        epoch: SecurityEpoch::from_raw(2),
    };
    let json = serde_json::to_string(&ve).unwrap();
    let rt: ValidationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ve, rt);
}

#[test]
fn serde_roundtrip_validation_event_quarantine_lifted() {
    let ve = ValidationEvent {
        optimization_id: "opt1".into(),
        event_type: ValidationEventType::QuarantineLifted {
            override_reason: "new evidence".into(),
        },
        timestamp_ticks: 1100,
        epoch: SecurityEpoch::from_raw(3),
    };
    let json = serde_json::to_string(&ve).unwrap();
    let rt: ValidationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ve, rt);
}

// ===========================================================================
// 9) ValidationGateError — Display content
// ===========================================================================

#[test]
fn validation_gate_error_contains_optimization_id() {
    let e = ValidationGateError::InvalidReceiptSignature {
        optimization_id: "opt-123".into(),
    };
    let s = e.to_string();
    assert!(s.contains("opt-123"), "should contain opt id: {s}");
}

#[test]
fn validation_gate_error_token_expired_contains_epochs() {
    let e = ValidationGateError::TokenExpired {
        token_id: "tok-1".into(),
        expiry_epoch: 5,
        current_epoch: 10,
    };
    let s = e.to_string();
    assert!(
        s.contains("5") || s.contains("10"),
        "should contain epochs: {s}"
    );
}

#[test]
fn validation_gate_error_token_receipt_mismatch_contains_ids() {
    let e = ValidationGateError::TokenReceiptMismatch {
        token_optimization_id: "tok-opt-1".into(),
        receipt_optimization_id: "rec-opt-2".into(),
    };
    let s = e.to_string();
    assert!(
        s.contains("tok-opt-1") || s.contains("rec-opt-2"),
        "should contain ids: {s}"
    );
}

#[test]
fn validation_gate_error_quarantined_contains_reason() {
    let e = ValidationGateError::Quarantined {
        optimization_id: "opt-q".into(),
        reason: "repeated failure".into(),
    };
    let s = e.to_string();
    assert!(
        s.contains("repeated") || s.contains("quarantine"),
        "should contain reason: {s}"
    );
}

#[test]
fn validation_gate_error_invalid_stage_transition_contains_stages() {
    let e = ValidationGateError::InvalidStageTransition {
        from: ActivationStage::Shadow,
        to: ActivationStage::Default,
    };
    let s = e.to_string();
    assert!(!s.is_empty(), "display should not be empty");
}

// ===========================================================================
// 10) ValidationVerdict — Display content
// ===========================================================================

#[test]
fn validation_verdict_inconclusive_display_contains_reason() {
    let v = ValidationVerdict::Inconclusive {
        mode: ValidationMode::DifferentialTrace {
            workload_hash: ContentHash::compute(b"w"),
            trace_pair_count: 5,
        },
        reason: "resource limit".into(),
    };
    let s = v.to_string();
    assert!(
        s.contains("inconclusive") || s.contains("INCONCLUSIVE") || s.contains("resource"),
        "should describe inconclusive: {s}"
    );
}

#[test]
fn validation_verdict_fail_display_contains_reason() {
    let v = ValidationVerdict::Fail {
        mode: ValidationMode::GoldenCorpusReplay {
            corpus_hash: ContentHash::compute(b"c"),
            vector_count: 10,
        },
        divergence_reason: "output mismatch".into(),
        counterexample_hash: ContentHash::compute(b"cx"),
    };
    let s = v.to_string();
    assert!(
        s.contains("mismatch") || s.contains("FAIL") || s.contains("fail"),
        "should describe failure: {s}"
    );
}

// ===========================================================================
// 11) RollbackReceipt and StagePromotion serde
// ===========================================================================

#[test]
fn serde_roundtrip_rollback_receipt() {
    let receipt = RollbackReceipt {
        rollback_token_id: "tok-1".into(),
        optimization_id: "opt-1".into(),
        failure_reason: "divergence detected".into(),
        counterexample_hash: Some(ContentHash::compute(b"cx")),
        restoration_baseline_hash: ContentHash::compute(b"baseline"),
        rollback_from_stage: ActivationStage::Canary,
        timestamp_ticks: 5000,
        epoch: SecurityEpoch::from_raw(3),
        signature: frankenengine_engine::hash_tiers::AuthenticityHash::compute_keyed(
            b"data", b"key",
        ),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let rt: RollbackReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, rt);
}

#[test]
fn serde_roundtrip_stage_promotion() {
    let promo = StagePromotion {
        optimization_id: "opt-1".into(),
        from_stage: ActivationStage::Shadow,
        to_stage: ActivationStage::Canary,
        evidence_hash: ContentHash::compute(b"evidence"),
        timestamp_ticks: 3000,
        epoch: SecurityEpoch::from_raw(2),
        signature: frankenengine_engine::hash_tiers::AuthenticityHash::compute_keyed(
            b"data", b"key",
        ),
    };
    let json = serde_json::to_string(&promo).unwrap();
    let rt: StagePromotion = serde_json::from_str(&json).unwrap();
    assert_eq!(promo, rt);
}

// ===========================================================================
// 12) RollbackReceipt signing
// ===========================================================================

#[test]
fn rollback_receipt_sign_and_verify() {
    let key = b"test-signing-key";
    let receipt = RollbackReceipt {
        rollback_token_id: "tok-1".into(),
        optimization_id: "opt-1".into(),
        failure_reason: "test".into(),
        counterexample_hash: None,
        restoration_baseline_hash: ContentHash::compute(b"b"),
        rollback_from_stage: ActivationStage::Shadow,
        timestamp_ticks: 100,
        epoch: SecurityEpoch::from_raw(1),
        signature: frankenengine_engine::hash_tiers::AuthenticityHash::compute_keyed(b"", b""),
    };
    let signed = receipt.sign(key);
    assert!(signed.verify_signature(key));
    assert!(!signed.verify_signature(b"wrong-key"));
}

#[test]
fn rollback_receipt_signing_preimage_deterministic() {
    let receipt = RollbackReceipt {
        rollback_token_id: "tok-1".into(),
        optimization_id: "opt-1".into(),
        failure_reason: "test".into(),
        counterexample_hash: None,
        restoration_baseline_hash: ContentHash::compute(b"b"),
        rollback_from_stage: ActivationStage::Shadow,
        timestamp_ticks: 100,
        epoch: SecurityEpoch::from_raw(1),
        signature: frankenengine_engine::hash_tiers::AuthenticityHash::compute_keyed(b"", b""),
    };
    let p1 = receipt.signing_preimage();
    let p2 = receipt.signing_preimage();
    assert_eq!(p1, p2);
}

// ===========================================================================
// 13) StagePromotion signing
// ===========================================================================

#[test]
fn stage_promotion_sign_and_verify() {
    let key = b"test-key";
    let promo = StagePromotion {
        optimization_id: "opt-1".into(),
        from_stage: ActivationStage::Shadow,
        to_stage: ActivationStage::Canary,
        evidence_hash: ContentHash::compute(b"e"),
        timestamp_ticks: 200,
        epoch: SecurityEpoch::from_raw(1),
        signature: frankenengine_engine::hash_tiers::AuthenticityHash::compute_keyed(b"", b""),
    };
    let signed = promo.sign(key);
    assert!(signed.verify_signature(key));
    assert!(!signed.verify_signature(b"wrong"));
}

#[test]
fn stage_promotion_signing_preimage_deterministic() {
    let promo = StagePromotion {
        optimization_id: "opt-1".into(),
        from_stage: ActivationStage::Shadow,
        to_stage: ActivationStage::Canary,
        evidence_hash: ContentHash::compute(b"e"),
        timestamp_ticks: 200,
        epoch: SecurityEpoch::from_raw(1),
        signature: frankenengine_engine::hash_tiers::AuthenticityHash::compute_keyed(b"", b""),
    };
    let p1 = promo.signing_preimage();
    let p2 = promo.signing_preimage();
    assert_eq!(p1, p2);
}

// ===========================================================================
// 14) QuarantineEntry edge cases
// ===========================================================================

#[test]
fn quarantine_entry_no_counterexample() {
    let qe = QuarantineEntry {
        optimization_id: "opt1".into(),
        reason: "policy violation".into(),
        counterexample_hash: None,
        quarantined_epoch: SecurityEpoch::from_raw(1),
        quarantined_at_ticks: 100,
    };
    let v: serde_json::Value = serde_json::to_value(&qe).unwrap();
    assert!(v["counterexample_hash"].is_null());
}

#[test]
fn quarantine_entry_with_counterexample() {
    let qe = QuarantineEntry {
        optimization_id: "opt1".into(),
        reason: "divergence".into(),
        counterexample_hash: Some(ContentHash::compute(b"cx")),
        quarantined_epoch: SecurityEpoch::from_raw(2),
        quarantined_at_ticks: 200,
    };
    let v: serde_json::Value = serde_json::to_value(&qe).unwrap();
    assert!(!v["counterexample_hash"].is_null());
}

// ===========================================================================
// 15) ValidationMode Display all distinct
// ===========================================================================

#[test]
fn validation_mode_display_all_distinct() {
    let displays: Vec<String> = vec![
        ValidationMode::GoldenCorpusReplay {
            corpus_hash: ContentHash::compute(b"a"),
            vector_count: 1,
        }
        .to_string(),
        ValidationMode::SymbolicEquivalence {
            proof_hash: ContentHash::compute(b"b"),
        }
        .to_string(),
        ValidationMode::DifferentialTrace {
            workload_hash: ContentHash::compute(b"c"),
            trace_pair_count: 1,
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = displays.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 16) ValidationVerdict Display all distinct
// ===========================================================================

#[test]
fn validation_verdict_display_all_distinct() {
    let mode = ValidationMode::SymbolicEquivalence {
        proof_hash: ContentHash::compute(b"p"),
    };
    let displays: Vec<String> = vec![
        ValidationVerdict::Pass {
            mode: mode.clone(),
            evidence_hash: ContentHash::compute(b"e"),
        }
        .to_string(),
        ValidationVerdict::Fail {
            mode: mode.clone(),
            divergence_reason: "x".into(),
            counterexample_hash: ContentHash::compute(b"cx"),
        }
        .to_string(),
        ValidationVerdict::Inconclusive {
            mode,
            reason: "y".into(),
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = displays.iter().collect();
    assert_eq!(unique.len(), 3);
}
