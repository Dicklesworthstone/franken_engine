#![forbid(unsafe_code)]
//! Enrichment integration tests for `receipt_verifier_pipeline`.
//!
//! Adds JSON field-name stability, serde exact tags, Debug distinctness,
//! Display exactness, error trait coverage, and edge-case validation
//! beyond the existing 37 integration tests.

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

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::mmr_proof::{MmrProof, ProofType};
use frankenengine_engine::receipt_verifier_pipeline::{
    ConsistencyProofInput, EXIT_CODE_ATTESTATION_FAILURE, EXIT_CODE_SIGNATURE_FAILURE,
    EXIT_CODE_STALE_DATA, EXIT_CODE_SUCCESS, EXIT_CODE_TRANSPARENCY_FAILURE, LayerCheck,
    LayerResult, LogOperatorKey, ReceiptVerifierCliInput, ReceiptVerifierPipelineError,
    SignedLogCheckpoint, SignerRevocationCache, UnifiedReceiptVerificationVerdict,
    VerificationFailureClass, VerifierLogEvent,
};
use frankenengine_engine::signature_preimage::{Signature, VerificationKey};

// ===========================================================================
// 1) Exit-code constants — exact values
// ===========================================================================

#[test]
fn exit_code_success_is_zero() {
    assert_eq!(EXIT_CODE_SUCCESS, 0);
}

#[test]
fn exit_code_signature_failure_is_twenty() {
    assert_eq!(EXIT_CODE_SIGNATURE_FAILURE, 20);
}

#[test]
fn exit_code_transparency_failure_is_twenty_one() {
    assert_eq!(EXIT_CODE_TRANSPARENCY_FAILURE, 21);
}

#[test]
fn exit_code_attestation_failure_is_twenty_two() {
    assert_eq!(EXIT_CODE_ATTESTATION_FAILURE, 22);
}

#[test]
fn exit_code_stale_data_is_twenty_three() {
    assert_eq!(EXIT_CODE_STALE_DATA, 23);
}

#[test]
fn exit_codes_all_distinct() {
    let codes = [
        EXIT_CODE_SUCCESS,
        EXIT_CODE_SIGNATURE_FAILURE,
        EXIT_CODE_TRANSPARENCY_FAILURE,
        EXIT_CODE_ATTESTATION_FAILURE,
        EXIT_CODE_STALE_DATA,
    ];
    let unique: BTreeSet<_> = codes.iter().collect();
    assert_eq!(unique.len(), 5);
}

// ===========================================================================
// 2) VerificationFailureClass — Display exact values
// ===========================================================================

#[test]
fn verification_failure_class_display_signature() {
    assert_eq!(VerificationFailureClass::Signature.to_string(), "signature");
}

#[test]
fn verification_failure_class_display_transparency() {
    assert_eq!(
        VerificationFailureClass::Transparency.to_string(),
        "transparency"
    );
}

#[test]
fn verification_failure_class_display_attestation() {
    assert_eq!(
        VerificationFailureClass::Attestation.to_string(),
        "attestation"
    );
}

#[test]
fn verification_failure_class_display_stale_data() {
    assert_eq!(
        VerificationFailureClass::StaleData.to_string(),
        "stale_data"
    );
}

#[test]
fn verification_failure_class_display_all_unique() {
    let displays: Vec<String> = [
        VerificationFailureClass::Signature,
        VerificationFailureClass::Transparency,
        VerificationFailureClass::Attestation,
        VerificationFailureClass::StaleData,
    ]
    .iter()
    .map(|c| c.to_string())
    .collect();
    let unique: BTreeSet<_> = displays.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 3) VerificationFailureClass — serde exact tags (snake_case)
// ===========================================================================

#[test]
fn serde_exact_verification_failure_class_tags() {
    let classes = [
        VerificationFailureClass::Signature,
        VerificationFailureClass::Transparency,
        VerificationFailureClass::Attestation,
        VerificationFailureClass::StaleData,
    ];
    let expected = [
        "\"signature\"",
        "\"transparency\"",
        "\"attestation\"",
        "\"stale_data\"",
    ];
    for (c, exp) in classes.iter().zip(expected.iter()) {
        let json = serde_json::to_string(c).unwrap();
        assert_eq!(
            json, *exp,
            "VerificationFailureClass tag mismatch for {c:?}"
        );
    }
}

// ===========================================================================
// 4) VerificationFailureClass — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_verification_failure_class() {
    let variants = [
        format!("{:?}", VerificationFailureClass::Signature),
        format!("{:?}", VerificationFailureClass::Transparency),
        format!("{:?}", VerificationFailureClass::Attestation),
        format!("{:?}", VerificationFailureClass::StaleData),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 5) ReceiptVerifierPipelineError — Display + std::error::Error
// ===========================================================================

#[test]
fn pipeline_error_display_receipt_not_found() {
    let e = ReceiptVerifierPipelineError::ReceiptNotFound {
        receipt_id: "rcpt-999".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("rcpt-999"), "should contain receipt_id: {s}");
    assert!(s.contains("not found"), "should contain 'not found': {s}");
}

#[test]
fn pipeline_error_is_std_error() {
    let e = ReceiptVerifierPipelineError::ReceiptNotFound {
        receipt_id: "x".to_string(),
    };
    let _: &dyn std::error::Error = &e;
}

#[test]
fn pipeline_error_serde_roundtrip() {
    let e = ReceiptVerifierPipelineError::ReceiptNotFound {
        receipt_id: "rcpt-42".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let rt: ReceiptVerifierPipelineError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, rt);
}

// ===========================================================================
// 6) ReceiptVerifierCliInput — default empty
// ===========================================================================

#[test]
fn cli_input_default_receipts_empty() {
    let input = ReceiptVerifierCliInput::default();
    assert!(input.receipts.is_empty());
}

#[test]
fn cli_input_serde_roundtrip_default() {
    let input = ReceiptVerifierCliInput::default();
    let json = serde_json::to_string(&input).unwrap();
    let rt: ReceiptVerifierCliInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input.receipts.len(), rt.receipts.len());
}

// ===========================================================================
// 7) JSON field-name stability — VerifierLogEvent
// ===========================================================================

#[test]
fn json_fields_verifier_log_event() {
    let ev = VerifierLogEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "pass".into(),
        error_code: None,
    };
    let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(
            obj.contains_key(key),
            "VerifierLogEvent missing field: {key}"
        );
    }
}

// ===========================================================================
// 8) JSON field-name stability — LayerCheck
// ===========================================================================

#[test]
fn json_fields_layer_check() {
    let lc = LayerCheck {
        check: "sig_valid".into(),
        outcome: "pass".into(),
        error_code: None,
        detail: "ok".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&lc).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["check", "outcome", "error_code", "detail"] {
        assert!(obj.contains_key(key), "LayerCheck missing field: {key}");
    }
}

// ===========================================================================
// 9) JSON field-name stability — LayerResult
// ===========================================================================

#[test]
fn json_fields_layer_result() {
    let lr = LayerResult {
        passed: true,
        error_code: None,
        checks: vec![],
    };
    let v: serde_json::Value = serde_json::to_value(&lr).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["passed", "error_code", "checks"] {
        assert!(obj.contains_key(key), "LayerResult missing field: {key}");
    }
}

// ===========================================================================
// 13) JSON field-name stability — UnifiedReceiptVerificationVerdict
// ===========================================================================

#[test]
fn json_fields_unified_verdict() {
    let verdict = UnifiedReceiptVerificationVerdict {
        receipt_id: "r".into(),
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        verification_timestamp_ns: 0,
        passed: true,
        failure_class: None,
        exit_code: 0,
        signature: LayerResult {
            passed: true,
            error_code: None,
            checks: vec![],
        },
        transparency: LayerResult {
            passed: true,
            error_code: None,
            checks: vec![],
        },
        attestation: LayerResult {
            passed: true,
            error_code: None,
            checks: vec![],
        },
        warnings: vec![],
        logs: vec![],
    };
    let v: serde_json::Value = serde_json::to_value(&verdict).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "receipt_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "verification_timestamp_ns",
        "passed",
        "failure_class",
        "exit_code",
        "signature",
        "transparency",
        "attestation",
        "warnings",
        "logs",
    ] {
        assert!(
            obj.contains_key(key),
            "UnifiedReceiptVerificationVerdict missing field: {key}"
        );
    }
}

// ===========================================================================
// 14) Serde roundtrips — structs
// ===========================================================================

#[test]
fn serde_roundtrip_verifier_log_event_with_error_code() {
    let ev = VerifierLogEvent {
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        component: "signature_layer".into(),
        event: "check_completed".into(),
        outcome: "fail".into(),
        error_code: Some("signer_revoked".into()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let rt: VerifierLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, rt);
}

#[test]
fn serde_roundtrip_layer_check_with_error() {
    let lc = LayerCheck {
        check: "preimage_hash_match".into(),
        outcome: "fail".into(),
        error_code: Some("preimage_hash_mismatch".into()),
        detail: "computed preimage does not match".into(),
    };
    let json = serde_json::to_string(&lc).unwrap();
    let rt: LayerCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(lc, rt);
}

#[test]
fn serde_roundtrip_layer_result_with_checks() {
    let lr = LayerResult {
        passed: false,
        error_code: Some("signer_revoked".into()),
        checks: vec![
            LayerCheck {
                check: "key_valid".into(),
                outcome: "pass".into(),
                error_code: None,
                detail: "ok".into(),
            },
            LayerCheck {
                check: "revocation_status".into(),
                outcome: "fail".into(),
                error_code: Some("signer_revoked".into()),
                detail: "signer key is revoked".into(),
            },
        ],
    };
    let json = serde_json::to_string(&lr).unwrap();
    let rt: LayerResult = serde_json::from_str(&json).unwrap();
    assert_eq!(lr, rt);
}

// ===========================================================================
// 15) VerificationFailureClass — serde roundtrip all variants
// ===========================================================================

#[test]
fn serde_roundtrip_verification_failure_class_all() {
    for c in [
        VerificationFailureClass::Signature,
        VerificationFailureClass::Transparency,
        VerificationFailureClass::Attestation,
        VerificationFailureClass::StaleData,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let rt: VerificationFailureClass = serde_json::from_str(&json).unwrap();
        assert_eq!(c, rt);
    }
}

// ===========================================================================
// 16) LayerResult — empty checks means passing
// ===========================================================================

#[test]
fn layer_result_empty_checks_can_be_passing() {
    let lr = LayerResult {
        passed: true,
        error_code: None,
        checks: vec![],
    };
    assert!(lr.passed);
    assert!(lr.error_code.is_none());
}

// ===========================================================================
// 17) UnifiedReceiptVerificationVerdict — passing verdict has no failure class
// ===========================================================================

#[test]
fn passing_verdict_no_failure_class() {
    let verdict = UnifiedReceiptVerificationVerdict {
        receipt_id: "r".into(),
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        verification_timestamp_ns: 1,
        passed: true,
        failure_class: None,
        exit_code: EXIT_CODE_SUCCESS,
        signature: LayerResult {
            passed: true,
            error_code: None,
            checks: vec![],
        },
        transparency: LayerResult {
            passed: true,
            error_code: None,
            checks: vec![],
        },
        attestation: LayerResult {
            passed: true,
            error_code: None,
            checks: vec![],
        },
        warnings: vec![],
        logs: vec![],
    };
    assert!(verdict.passed);
    assert!(verdict.failure_class.is_none());
    assert_eq!(verdict.exit_code, 0);
}

// ===========================================================================
// 19) VerifierLogEvent — error_code None vs Some
// ===========================================================================

#[test]
fn verifier_log_event_error_code_none_serializes_null() {
    let ev = VerifierLogEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "sig".into(),
        event: "check".into(),
        outcome: "pass".into(),
        error_code: None,
    };
    let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
    assert!(v["error_code"].is_null());
}

#[test]
fn verifier_log_event_error_code_some_serializes_string() {
    let ev = VerifierLogEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "sig".into(),
        event: "check".into(),
        outcome: "fail".into(),
        error_code: Some("signer_revoked".into()),
    };
    let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
    assert_eq!(v["error_code"].as_str().unwrap(), "signer_revoked");
}

// ===========================================================================
// 20) UnifiedReceiptVerificationVerdict — failing verdict carries failure class
// ===========================================================================

#[test]
fn failing_verdict_carries_signature_failure_class() {
    let verdict = UnifiedReceiptVerificationVerdict {
        receipt_id: "r-sig-fail".into(),
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        verification_timestamp_ns: 42,
        passed: false,
        failure_class: Some(VerificationFailureClass::Signature),
        exit_code: EXIT_CODE_SIGNATURE_FAILURE,
        signature: LayerResult {
            passed: false,
            error_code: Some("signer_revoked".into()),
            checks: vec![LayerCheck {
                check: "revocation_status".into(),
                outcome: "fail".into(),
                error_code: Some("signer_revoked".into()),
                detail: "key revoked".into(),
            }],
        },
        transparency: LayerResult {
            passed: true,
            error_code: None,
            checks: vec![],
        },
        attestation: LayerResult {
            passed: true,
            error_code: None,
            checks: vec![],
        },
        warnings: vec![],
        logs: vec![],
    };
    assert!(!verdict.passed);
    assert_eq!(
        verdict.failure_class,
        Some(VerificationFailureClass::Signature)
    );
    assert_eq!(verdict.exit_code, EXIT_CODE_SIGNATURE_FAILURE);
    assert!(!verdict.signature.passed);
    assert_eq!(verdict.signature.checks.len(), 1);
}

// ===========================================================================
// 21) UnifiedReceiptVerificationVerdict — full serde roundtrip with all fields populated
// ===========================================================================

#[test]
fn unified_verdict_full_serde_roundtrip() {
    let verdict = UnifiedReceiptVerificationVerdict {
        receipt_id: "rcpt-serde-full".into(),
        trace_id: "t-full".into(),
        decision_id: "d-full".into(),
        policy_id: "p-full".into(),
        verification_timestamp_ns: 1_700_000_000_000,
        passed: false,
        failure_class: Some(VerificationFailureClass::Attestation),
        exit_code: EXIT_CODE_ATTESTATION_FAILURE,
        signature: LayerResult {
            passed: true,
            error_code: None,
            checks: vec![LayerCheck {
                check: "key_valid".into(),
                outcome: "pass".into(),
                error_code: None,
                detail: "ok".into(),
            }],
        },
        transparency: LayerResult {
            passed: true,
            error_code: None,
            checks: vec![],
        },
        attestation: LayerResult {
            passed: false,
            error_code: Some("enclave_mismatch".into()),
            checks: vec![LayerCheck {
                check: "enclave_identity".into(),
                outcome: "fail".into(),
                error_code: Some("enclave_mismatch".into()),
                detail: "MRENCLAVE differs".into(),
            }],
        },
        warnings: vec!["clock skew detected".to_string()],
        logs: vec![VerifierLogEvent {
            trace_id: "t-full".into(),
            decision_id: "d-full".into(),
            policy_id: "p-full".into(),
            component: "attestation_layer".into(),
            event: "check_completed".into(),
            outcome: "fail".into(),
            error_code: Some("enclave_mismatch".into()),
        }],
    };
    let json = serde_json::to_string(&verdict).unwrap();
    let rt: UnifiedReceiptVerificationVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(verdict, rt);
}

// ===========================================================================
// 22) LayerCheck — Debug representation is distinct per field combination
// ===========================================================================

#[test]
fn layer_check_debug_repr_captures_all_fields() {
    let lc = LayerCheck {
        check: "sig_valid".into(),
        outcome: "pass".into(),
        error_code: None,
        detail: "ok".into(),
    };
    let dbg = format!("{lc:?}");
    assert!(
        dbg.contains("sig_valid"),
        "Debug should contain check name: {dbg}"
    );
    assert!(dbg.contains("pass"), "Debug should contain outcome: {dbg}");
    assert!(
        dbg.contains("None"),
        "Debug should show None error_code: {dbg}"
    );
}

// ===========================================================================
// 23) ReceiptVerifierPipelineError — all variants serde roundtrip
// ===========================================================================

#[test]
fn pipeline_error_all_variants_display_nonempty() {
    let errors = vec![ReceiptVerifierPipelineError::ReceiptNotFound {
        receipt_id: "rcpt-missing".to_string(),
    }];
    for e in &errors {
        let s = e.to_string();
        assert!(!s.is_empty(), "Display for {:?} should not be empty", e);
        // Verify std::error::Error trait
        let _: &dyn std::error::Error = e;
    }
}

// ===========================================================================
// 24) UnifiedReceiptVerificationVerdict — warnings field serialization
// ===========================================================================

#[test]
fn verdict_warnings_serialize_as_json_array() {
    let verdict = UnifiedReceiptVerificationVerdict {
        receipt_id: "r-warn".into(),
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        verification_timestamp_ns: 0,
        passed: true,
        failure_class: None,
        exit_code: EXIT_CODE_SUCCESS,
        signature: LayerResult {
            passed: true,
            error_code: None,
            checks: vec![],
        },
        transparency: LayerResult {
            passed: true,
            error_code: None,
            checks: vec![],
        },
        attestation: LayerResult {
            passed: true,
            error_code: None,
            checks: vec![],
        },
        warnings: vec!["clock-skew".to_string(), "cert-expiry-soon".to_string()],
        logs: vec![],
    };
    let v: serde_json::Value = serde_json::to_value(&verdict).unwrap();
    let warnings = v["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 2);
    assert_eq!(warnings[0].as_str().unwrap(), "clock-skew");
    assert_eq!(warnings[1].as_str().unwrap(), "cert-expiry-soon");
}

// ===========================================================================
// 25) SignerRevocationCache — JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_signer_revocation_cache() {
    let cache = SignerRevocationCache {
        signer_key_id: EngineObjectId([0x11; 32]),
        source: "offline-revocations".into(),
        is_revoked: false,
        cache_stale: true,
    };
    let v: serde_json::Value = serde_json::to_value(&cache).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["signer_key_id", "source", "is_revoked", "cache_stale"] {
        assert!(
            obj.contains_key(key),
            "SignerRevocationCache missing field: {key}"
        );
    }
    assert_eq!(
        obj.len(),
        4,
        "SignerRevocationCache should have exactly 4 fields"
    );
}

// ===========================================================================
// 26) SignedLogCheckpoint — JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_signed_log_checkpoint() {
    let ckpt = SignedLogCheckpoint {
        checkpoint_seq: 42,
        log_length: 100,
        root_hash: ContentHash::compute(b"root"),
        timestamp_ns: 1_000_000,
        operator_key_id: "op-1".into(),
        signature: Signature::from_bytes([0u8; 64]),
    };
    let v: serde_json::Value = serde_json::to_value(&ckpt).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "checkpoint_seq",
        "log_length",
        "root_hash",
        "timestamp_ns",
        "operator_key_id",
        "signature",
    ] {
        assert!(
            obj.contains_key(key),
            "SignedLogCheckpoint missing field: {key}"
        );
    }
    assert_eq!(
        obj.len(),
        6,
        "SignedLogCheckpoint should have exactly 6 fields"
    );
}

// ===========================================================================
// 27) LogOperatorKey — JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_log_operator_key() {
    let key = LogOperatorKey {
        key_id: "operator-alpha".into(),
        verification_key: VerificationKey::from_bytes([0xAA; 32]),
        revoked: false,
    };
    let v: serde_json::Value = serde_json::to_value(&key).unwrap();
    let obj = v.as_object().unwrap();
    for field in ["key_id", "verification_key", "revoked"] {
        assert!(
            obj.contains_key(field),
            "LogOperatorKey missing field: {field}"
        );
    }
    assert_eq!(obj.len(), 3, "LogOperatorKey should have exactly 3 fields");
}

// ===========================================================================
// 28) ConsistencyProofInput — JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_consistency_proof_input() {
    let proof = ConsistencyProofInput {
        from_root: ContentHash::compute(b"old-root"),
        proof: MmrProof {
            proof_type: ProofType::Consistency,
            marker_index: 3,
            proof_hashes: vec![],
            root_hash: ContentHash::compute(b"new-root"),
            stream_length: 10,
            epoch_id: 1,
        },
    };
    let v: serde_json::Value = serde_json::to_value(&proof).unwrap();
    let obj = v.as_object().unwrap();
    for field in ["from_root", "proof"] {
        assert!(
            obj.contains_key(field),
            "ConsistencyProofInput missing field: {field}"
        );
    }
    assert_eq!(
        obj.len(),
        2,
        "ConsistencyProofInput should have exactly 2 fields"
    );
}

// ===========================================================================
// 29) VerificationFailureClass — Ord produces correct BTreeSet ordering
// ===========================================================================

#[test]
fn verification_failure_class_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(VerificationFailureClass::StaleData);
    set.insert(VerificationFailureClass::Signature);
    set.insert(VerificationFailureClass::Attestation);
    set.insert(VerificationFailureClass::Transparency);

    let ordered: Vec<_> = set.into_iter().collect();
    assert_eq!(ordered[0], VerificationFailureClass::Signature);
    assert_eq!(ordered[1], VerificationFailureClass::Transparency);
    assert_eq!(ordered[2], VerificationFailureClass::Attestation);
    assert_eq!(ordered[3], VerificationFailureClass::StaleData);
}

// ===========================================================================
// 30) UnifiedReceiptVerificationVerdict — exact JSON field count
// ===========================================================================

#[test]
fn unified_verdict_has_exactly_thirteen_fields() {
    let verdict = UnifiedReceiptVerificationVerdict {
        receipt_id: "r".into(),
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        verification_timestamp_ns: 0,
        passed: true,
        failure_class: None,
        exit_code: 0,
        signature: LayerResult {
            passed: true,
            error_code: None,
            checks: vec![],
        },
        transparency: LayerResult {
            passed: true,
            error_code: None,
            checks: vec![],
        },
        attestation: LayerResult {
            passed: true,
            error_code: None,
            checks: vec![],
        },
        warnings: vec![],
        logs: vec![],
    };
    let v: serde_json::Value = serde_json::to_value(&verdict).unwrap();
    let obj = v.as_object().unwrap();
    assert_eq!(
        obj.len(),
        13,
        "UnifiedReceiptVerificationVerdict should have exactly 13 fields"
    );
}

// ===========================================================================
// 31) ReceiptVerifierPipelineError — Debug contains receipt_id
// ===========================================================================

#[test]
fn pipeline_error_debug_contains_receipt_id() {
    let e = ReceiptVerifierPipelineError::ReceiptNotFound {
        receipt_id: "rcpt-debug-test".to_string(),
    };
    let dbg = format!("{e:?}");
    assert!(
        dbg.contains("rcpt-debug-test"),
        "Debug should contain receipt_id: {dbg}"
    );
    assert!(
        dbg.contains("ReceiptNotFound"),
        "Debug should contain variant name: {dbg}"
    );
}

// ===========================================================================
// 32) LayerResult — mixed pass/fail checks preserve order
// ===========================================================================

#[test]
fn layer_result_mixed_checks_preserve_order() {
    let lr = LayerResult {
        passed: false,
        error_code: Some("second_check_error".into()),
        checks: vec![
            LayerCheck {
                check: "first_check".into(),
                outcome: "pass".into(),
                error_code: None,
                detail: "ok".into(),
            },
            LayerCheck {
                check: "second_check".into(),
                outcome: "fail".into(),
                error_code: Some("second_check_error".into()),
                detail: "bad".into(),
            },
            LayerCheck {
                check: "third_check".into(),
                outcome: "pass".into(),
                error_code: None,
                detail: "recovered".into(),
            },
        ],
    };
    // Verify ordering is preserved through serde
    let json = serde_json::to_string(&lr).unwrap();
    let rt: LayerResult = serde_json::from_str(&json).unwrap();
    assert_eq!(rt.checks.len(), 3);
    assert_eq!(rt.checks[0].check, "first_check");
    assert_eq!(rt.checks[0].outcome, "pass");
    assert_eq!(rt.checks[1].check, "second_check");
    assert_eq!(rt.checks[1].outcome, "fail");
    assert_eq!(rt.checks[2].check, "third_check");
    assert_eq!(rt.checks[2].outcome, "pass");
    assert!(!rt.passed);
    assert_eq!(rt.error_code.as_deref(), Some("second_check_error"));
}

// ===========================================================================
// 33) LayerCheck — clone produces independent value
// ===========================================================================

#[test]
fn layer_check_clone_independence() {
    let original = LayerCheck {
        check: "sig_valid".into(),
        outcome: "pass".into(),
        error_code: None,
        detail: "ok".into(),
    };
    let mut cloned = original.clone();
    cloned.outcome = "fail".into();
    cloned.error_code = Some("mutated".into());
    // Original unchanged
    assert_eq!(original.outcome, "pass");
    assert!(original.error_code.is_none());
    // Clone is different
    assert_eq!(cloned.outcome, "fail");
    assert_eq!(cloned.error_code.as_deref(), Some("mutated"));
}

// ===========================================================================
// 34) VerifierLogEvent — exact field count stability
// ===========================================================================

#[test]
fn verifier_log_event_has_exactly_seven_fields() {
    let ev = VerifierLogEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "pass".into(),
        error_code: None,
    };
    let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
    let obj = v.as_object().unwrap();
    assert_eq!(
        obj.len(),
        7,
        "VerifierLogEvent should have exactly 7 fields"
    );
}

// ===========================================================================
// 35) LayerCheck — exact field count stability
// ===========================================================================

#[test]
fn layer_check_has_exactly_four_fields() {
    let lc = LayerCheck {
        check: "test".into(),
        outcome: "pass".into(),
        error_code: None,
        detail: "ok".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&lc).unwrap();
    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 4, "LayerCheck should have exactly 4 fields");
}

// ===========================================================================
// 36) LayerResult — exact field count stability
// ===========================================================================

#[test]
fn layer_result_has_exactly_three_fields() {
    let lr = LayerResult {
        passed: true,
        error_code: None,
        checks: vec![],
    };
    let v: serde_json::Value = serde_json::to_value(&lr).unwrap();
    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 3, "LayerResult should have exactly 3 fields");
}
