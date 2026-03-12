//! Integration tests for `frankenengine_engine::receipt_verifier_pipeline`.
//!
//! Exercises the unified deterministic receipt verifier pipeline from the
//! public crate boundary: VerifierLogEvent, VerificationFailureClass,
//! LayerCheck, LayerResult, SignerRevocationCache, SignedLogCheckpoint,
//! LogOperatorKey, ConsistencyProofInput, ReceiptVerifierPipelineError,
//! ReceiptVerifierCliInput, UnifiedReceiptVerificationRequest,
//! UnifiedReceiptVerificationVerdict, verify_receipt_by_id,
//! verify_receipt_request, render_verdict_summary.

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

use frankenengine_engine::attested_execution_cell::{
    SoftwareTrustRoot, TrustLevel, TrustRootBackend,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::mmr_proof::MerkleMountainRange;
use frankenengine_engine::proof_schema::{
    proof_schema_version_current, AttestationValidityWindow, OptReceipt, OptimizationClass,
    ReceiptAttestationBindings,
};
use frankenengine_engine::receipt_verifier_pipeline::{
    render_verdict_summary, verify_receipt_by_id, verify_receipt_request, AttestationLayerInput,
    ConsistencyProofInput, LayerCheck, LayerResult, LogOperatorKey, ReceiptVerifierCliInput,
    ReceiptVerifierPipelineError, SignatureLayerInput, SignedLogCheckpoint, SignerRevocationCache,
    TransparencyLayerInput, UnifiedReceiptVerificationRequest, UnifiedReceiptVerificationVerdict,
    VerificationFailureClass, VerifierLogEvent, EXIT_CODE_ATTESTATION_FAILURE,
    EXIT_CODE_SIGNATURE_FAILURE, EXIT_CODE_STALE_DATA, EXIT_CODE_SUCCESS,
    EXIT_CODE_TRANSPARENCY_FAILURE,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{sign_preimage, Signature, SigningKey};
use frankenengine_engine::tee_attestation_policy::{
    AttestationFreshnessWindow, DecisionImpact, MeasurementAlgorithm,
    MeasurementDigest as PolicyMeasurementDigest, PlatformTrustRoot, RevocationFallback,
    RevocationProbeStatus, RevocationSource, RevocationSourceType, TeeAttestationPolicy,
    TeePlatform, TrustRootPinning, TrustRootSource,
};

// ── Constants ───────────────────────────────────────────────────────────

#[test]
fn exit_code_constants_are_distinct() {
    let codes = [
        EXIT_CODE_SUCCESS,
        EXIT_CODE_SIGNATURE_FAILURE,
        EXIT_CODE_TRANSPARENCY_FAILURE,
        EXIT_CODE_ATTESTATION_FAILURE,
        EXIT_CODE_STALE_DATA,
    ];
    for (i, a) in codes.iter().enumerate() {
        for b in &codes[i + 1..] {
            assert_ne!(a, b, "exit codes must be distinct");
        }
    }
    assert_eq!(EXIT_CODE_SUCCESS, 0);
}

// ── VerificationFailureClass ────────────────────────────────────────────

#[test]
fn failure_class_display() {
    assert_eq!(VerificationFailureClass::Signature.to_string(), "signature");
    assert_eq!(
        VerificationFailureClass::Transparency.to_string(),
        "transparency"
    );
    assert_eq!(
        VerificationFailureClass::Attestation.to_string(),
        "attestation"
    );
    assert_eq!(
        VerificationFailureClass::StaleData.to_string(),
        "stale_data"
    );
}

#[test]
fn failure_class_serde_roundtrip() {
    for class in [
        VerificationFailureClass::Signature,
        VerificationFailureClass::Transparency,
        VerificationFailureClass::Attestation,
        VerificationFailureClass::StaleData,
    ] {
        let json = serde_json::to_string(&class).unwrap();
        let back: VerificationFailureClass = serde_json::from_str(&json).unwrap();
        assert_eq!(back, class);
    }
}

// ── VerifierLogEvent ────────────────────────────────────────────────────

#[test]
fn verifier_log_event_serde_roundtrip() {
    let event = VerifierLogEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: "receipt_verifier_pipeline".to_string(),
        event: "test_event".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: VerifierLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

#[test]
fn verifier_log_event_serde_with_error_code() {
    let event = VerifierLogEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: "test".to_string(),
        event: "signature_failed".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("signature_invalid".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("signature_invalid"));
    let back: VerifierLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.error_code.as_deref(), Some("signature_invalid"));
}

// ── LayerCheck ──────────────────────────────────────────────────────────

#[test]
fn layer_check_serde_roundtrip() {
    let check = LayerCheck {
        check: "receipt_signature_valid".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        detail: "signature verified".to_string(),
    };
    let json = serde_json::to_string(&check).unwrap();
    let back: LayerCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(back, check);
}

// ── LayerResult ─────────────────────────────────────────────────────────

#[test]
fn layer_result_serde_roundtrip() {
    let result = LayerResult {
        passed: true,
        error_code: None,
        checks: vec![LayerCheck {
            check: "test_check".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            detail: "all good".to_string(),
        }],
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: LayerResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, result);
}

// ── SignerRevocationCache ───────────────────────────────────────────────

#[test]
fn signer_revocation_cache_serde_roundtrip() {
    let cache = SignerRevocationCache {
        signer_key_id: EngineObjectId([0x11; 32]),
        source: "offline-revocations".to_string(),
        is_revoked: false,
        cache_stale: false,
    };
    let json = serde_json::to_string(&cache).unwrap();
    let back: SignerRevocationCache = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cache);
}

// ── SignedLogCheckpoint ─────────────────────────────────────────────────

#[test]
fn signed_log_checkpoint_serde_roundtrip() {
    let checkpoint = SignedLogCheckpoint {
        checkpoint_seq: 1,
        log_length: 100,
        root_hash: ContentHash::compute(b"root"),
        timestamp_ns: 1_000_000_000,
        operator_key_id: "op-1".to_string(),
        signature: Signature::from_bytes([0x42; 64]),
    };
    let json = serde_json::to_string(&checkpoint).unwrap();
    let back: SignedLogCheckpoint = serde_json::from_str(&json).unwrap();
    assert_eq!(back, checkpoint);
}

// ── LogOperatorKey ──────────────────────────────────────────────────────

#[test]
fn log_operator_key_serde_roundtrip() {
    let key = LogOperatorKey {
        key_id: "op-1".to_string(),
        verification_key: SigningKey::from_bytes([9u8; 32]).verification_key(),
        revoked: false,
    };
    let json = serde_json::to_string(&key).unwrap();
    let back: LogOperatorKey = serde_json::from_str(&json).unwrap();
    assert_eq!(back, key);
}

// ── ConsistencyProofInput ───────────────────────────────────────────────

#[test]
fn consistency_proof_input_serde_roundtrip() {
    let proof_input = ConsistencyProofInput {
        from_root: ContentHash::compute(b"old-root"),
        proof: {
            let mut mmr = MerkleMountainRange::new(1);
            mmr.append(ContentHash::compute(b"leaf0"));
            mmr.append(ContentHash::compute(b"leaf1"));
            mmr.consistency_proof(1).expect("consistency proof")
        },
    };
    let json = serde_json::to_string(&proof_input).unwrap();
    let back: ConsistencyProofInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back, proof_input);
}

// ── ReceiptVerifierPipelineError ────────────────────────────────────────

#[test]
fn pipeline_error_display() {
    let err = ReceiptVerifierPipelineError::ReceiptNotFound {
        receipt_id: "rcpt-404".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("rcpt-404"));
    assert!(msg.contains("not found"));
}

#[test]
fn pipeline_error_serde_roundtrip() {
    let err = ReceiptVerifierPipelineError::ReceiptNotFound {
        receipt_id: "rcpt-404".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: ReceiptVerifierPipelineError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

// ── ReceiptVerifierCliInput ─────────────────────────────────────────────

#[test]
fn cli_input_default_is_empty() {
    let input = ReceiptVerifierCliInput::default();
    assert!(input.receipts.is_empty());
}

#[test]
fn cli_input_serde_roundtrip() {
    let input = ReceiptVerifierCliInput::default();
    let json = serde_json::to_string(&input).unwrap();
    let back: ReceiptVerifierCliInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back.receipts.len(), 0);
}

// ── Fixture builder ─────────────────────────────────────────────────────

/// Replicate the private `checkpoint_preimage` function from the module.
fn checkpoint_preimage(checkpoint: &SignedLogCheckpoint) -> Vec<u8> {
    let domain = b"FrankenEngine.ReceiptTransparencyCheckpoint.v1";
    let mut preimage = Vec::new();
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&checkpoint.checkpoint_seq.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(&checkpoint.log_length.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(checkpoint.root_hash.as_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(&checkpoint.timestamp_ns.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(checkpoint.operator_key_id.as_bytes());
    preimage
}

/// Compute the attestation quote digest the same way the module does.
fn attestation_quote_digest(
    quote: &frankenengine_engine::attested_execution_cell::AttestationQuote,
) -> ContentHash {
    let bytes = serde_json::to_vec(quote).expect("quote serialize");
    ContentHash::compute(&bytes)
}

fn digest_hex(byte: u8, byte_len: usize) -> String {
    let mut out = String::with_capacity(byte_len * 2);
    for _ in 0..byte_len {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn sample_policy(
    policy_epoch: SecurityEpoch,
    intel_digest_hex: String,
    trust_root_id: &str,
) -> TeeAttestationPolicy {
    let mut approved_measurements = BTreeMap::new();
    approved_measurements.insert(
        TeePlatform::IntelSgx,
        vec![PolicyMeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: intel_digest_hex,
        }],
    );
    approved_measurements.insert(
        TeePlatform::ArmTrustZone,
        vec![PolicyMeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: digest_hex(0x22, 32),
        }],
    );
    approved_measurements.insert(
        TeePlatform::ArmCca,
        vec![PolicyMeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: digest_hex(0x44, 32),
        }],
    );
    approved_measurements.insert(
        TeePlatform::AmdSev,
        vec![PolicyMeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: digest_hex(0x33, 48),
        }],
    );

    TeeAttestationPolicy {
        schema_version: 1,
        policy_epoch,
        approved_measurements,
        freshness_window: AttestationFreshnessWindow {
            standard_max_age_secs: 120,
            high_impact_max_age_secs: 30,
        },
        revocation_sources: vec![
            RevocationSource {
                source_id: "intel_pcs".to_string(),
                source_type: RevocationSourceType::IntelPcs,
                endpoint: "https://intel.example/pcs".to_string(),
                on_unavailable: RevocationFallback::TryNextSource,
            },
            RevocationSource {
                source_id: "internal_ledger".to_string(),
                source_type: RevocationSourceType::InternalLedger,
                endpoint: "sqlite://revocations".to_string(),
                on_unavailable: RevocationFallback::FailClosed,
            },
        ],
        platform_trust_roots: vec![
            PlatformTrustRoot {
                root_id: trust_root_id.to_string(),
                platform: TeePlatform::IntelSgx,
                trust_anchor_pem: "-----BEGIN KEY-----intel-----END KEY-----".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(1),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            PlatformTrustRoot {
                root_id: "arm-root".to_string(),
                platform: TeePlatform::ArmTrustZone,
                trust_anchor_pem: "-----BEGIN KEY-----arm-----END KEY-----".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(1),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            PlatformTrustRoot {
                root_id: "cca-root".to_string(),
                platform: TeePlatform::ArmCca,
                trust_anchor_pem: "-----BEGIN KEY-----cca-----END KEY-----".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(1),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            PlatformTrustRoot {
                root_id: "amd-root".to_string(),
                platform: TeePlatform::AmdSev,
                trust_anchor_pem: "-----BEGIN KEY-----amd-----END KEY-----".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(1),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
        ],
    }
}

/// Build a fully valid verification request that passes all three layers.
fn build_valid_fixture() -> (String, UnifiedReceiptVerificationRequest) {
    let receipt_id = "rcpt-001".to_string();
    let signer_key_id = EngineObjectId([0x44; 32]);
    let signer_key_bytes = vec![0x55; 32];

    let software_root = SoftwareTrustRoot::new("root-1", 7);
    let measurement = software_root.measure(
        b"code-v1",
        b"cfg-v1",
        b"policy-v1",
        b"schema-v1",
        "runtime-v1",
    );
    let nonce = [7u8; 32];
    let mut cell_attestation_quote =
        software_root.attest(&measurement, nonce, 30_000_000_000, 10_000_000_000);
    cell_attestation_quote.trust_level = TrustLevel::SoftwareOnly;

    let measurement_zone = "measurement-zone-test".to_string();
    let measurement_id = measurement
        .derive_id(&measurement_zone)
        .expect("measurement ID");
    let quote_digest = attestation_quote_digest(&cell_attestation_quote);

    let mut replay_compatibility = BTreeMap::new();
    replay_compatibility.insert("arch".to_string(), "x86_64".to_string());
    replay_compatibility.insert("engine".to_string(), "franken-v1".to_string());

    let bindings = ReceiptAttestationBindings {
        quote_digest,
        measurement_id,
        attested_signer_key_id: signer_key_id.clone(),
        nonce,
        validity_window: AttestationValidityWindow {
            start_timestamp_ticks: 100,
            end_timestamp_ticks: 2_000,
        },
    };

    let unsigned_receipt = OptReceipt {
        schema_version: proof_schema_version_current(),
        optimization_id: "opt-01".to_string(),
        optimization_class: OptimizationClass::Superinstruction,
        baseline_ir_hash: ContentHash::compute(b"baseline"),
        candidate_ir_hash: ContentHash::compute(b"candidate"),
        translation_witness_hash: ContentHash::compute(b"translation"),
        invariance_digest: ContentHash::compute(b"invariance"),
        rollback_token_id: "rollback-01".to_string(),
        replay_compatibility,
        policy_epoch: SecurityEpoch::from_raw(5),
        timestamp_ticks: 1_000,
        signer_key_id: signer_key_id.clone(),
        correlation_id: "corr-01".to_string(),
        decision_impact: DecisionImpact::HighImpact,
        attestation_bindings: Some(bindings),
        signature: AuthenticityHash::compute_keyed(b"placeholder", b"placeholder"),
    };
    let receipt = unsigned_receipt.sign(&signer_key_bytes);
    let expected_preimage_hash = ContentHash::compute(&receipt.signing_preimage());

    let receipt_leaf_hash = ContentHash::compute(&receipt.signing_preimage());
    let leaf0 = ContentHash::compute(b"leaf0");
    let leaf1 = ContentHash::compute(b"leaf1");

    let mut old_mmr = MerkleMountainRange::new(5);
    old_mmr.append(leaf0.clone());
    old_mmr.append(leaf1.clone());
    let old_root = old_mmr.root_hash().expect("old root");

    let mut mmr = MerkleMountainRange::new(5);
    mmr.append(leaf0);
    mmr.append(leaf1);
    mmr.append(receipt_leaf_hash.clone());
    let inclusion_proof = mmr.inclusion_proof(2).expect("inclusion proof");
    let consistency_proof = mmr.consistency_proof(2).expect("consistency proof");
    let current_root = mmr.root_hash().expect("root");

    let operator_signing_key = SigningKey::from_bytes([9u8; 32]);
    let operator_verification_key = operator_signing_key.verification_key();

    // Build checkpoint — need to sign it properly.
    let unsigned_checkpoint = SignedLogCheckpoint {
        checkpoint_seq: 1,
        log_length: inclusion_proof.stream_length,
        root_hash: current_root,
        timestamp_ns: 20_000_000_000,
        operator_key_id: "operator-1".to_string(),
        signature: Signature::from_bytes([0u8; 64]),
    };
    let cp_preimage = checkpoint_preimage(&unsigned_checkpoint);
    let cp_sig = sign_preimage(&operator_signing_key, &cp_preimage).expect("checkpoint sign");
    let checkpoint = SignedLogCheckpoint {
        signature: cp_sig,
        ..unsigned_checkpoint
    };

    let measurement_digest_hex = measurement.composite_hash().to_hex();
    let policy = sample_policy(SecurityEpoch::from_raw(5), measurement_digest_hex, "root-1");

    let mut revocation_observations = BTreeMap::new();
    revocation_observations.insert("intel_pcs".to_string(), RevocationProbeStatus::Good);
    revocation_observations.insert(
        "internal_ledger".to_string(),
        RevocationProbeStatus::Unavailable,
    );
    let policy_quote = frankenengine_engine::tee_attestation_policy::AttestationQuote {
        platform: TeePlatform::IntelSgx,
        measurement: PolicyMeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: measurement.composite_hash().to_hex(),
        },
        quote_age_secs: 10,
        trust_root_id: "root-1".to_string(),
        revocation_observations,
    };

    let request = UnifiedReceiptVerificationRequest {
        trace_id: "trace-verify-01".to_string(),
        decision_id: "decision-verify-01".to_string(),
        policy_id: "policy-verify-01".to_string(),
        verification_timestamp_ns: 20_000_000_000,
        receipt,
        signature: SignatureLayerInput {
            expected_preimage_hash,
            signing_key_bytes: signer_key_bytes,
            signer_revocation: SignerRevocationCache {
                signer_key_id,
                source: "offline-signer-revocations".to_string(),
                is_revoked: false,
                cache_stale: false,
            },
        },
        transparency: TransparencyLayerInput {
            leaf_hash: receipt_leaf_hash,
            leaf_index: 2,
            inclusion_proof,
            consistency_proofs: vec![ConsistencyProofInput {
                from_root: old_root,
                proof: consistency_proof,
            }],
            checkpoint,
            operator_keys: vec![LogOperatorKey {
                key_id: "operator-1".to_string(),
                verification_key: operator_verification_key,
                revoked: false,
            }],
            cache_stale: false,
        },
        attestation: AttestationLayerInput {
            attestation_quote: cell_attestation_quote,
            policy_quote,
            policy,
            decision_impact: DecisionImpact::HighImpact,
            runtime_epoch: SecurityEpoch::from_raw(5),
            verification_time_ns: 20_000_000_000,
            measurement_zone,
            trust_roots: vec![software_root.clone()],
            policy_cache_stale: false,
            revocation_cache_stale: false,
        },
    };

    (receipt_id, request)
}

// ── verify_receipt_by_id ────────────────────────────────────────────────

#[test]
fn verify_receipt_by_id_not_found() {
    let input = ReceiptVerifierCliInput::default();
    let result = verify_receipt_by_id(&input, "nonexistent");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("nonexistent"));
}

#[test]
fn verify_receipt_by_id_found_and_verified() {
    let (receipt_id, request) = build_valid_fixture();
    let mut input = ReceiptVerifierCliInput::default();
    input.receipts.insert(receipt_id.clone(), request);
    let result = verify_receipt_by_id(&input, &receipt_id);
    assert!(result.is_ok());
    let verdict = result.unwrap();
    assert!(verdict.passed);
    assert_eq!(verdict.exit_code, EXIT_CODE_SUCCESS);
}

// ── verify_receipt_request — full pass ──────────────────────────────────

#[test]
fn valid_request_passes_all_layers() {
    let (receipt_id, request) = build_valid_fixture();
    let verdict = verify_receipt_request(&receipt_id, &request);

    assert!(verdict.passed);
    assert_eq!(verdict.failure_class, None);
    assert_eq!(verdict.exit_code, EXIT_CODE_SUCCESS);
    assert!(verdict.signature.passed);
    assert!(verdict.transparency.passed);
    assert!(verdict.attestation.passed);
    assert!(verdict.warnings.is_empty());
    assert_eq!(verdict.logs.len(), 4);
}

#[test]
fn valid_request_logs_have_correct_trace_ids() {
    let (receipt_id, request) = build_valid_fixture();
    let verdict = verify_receipt_request(&receipt_id, &request);
    for log in &verdict.logs {
        assert_eq!(log.trace_id, "trace-verify-01");
        assert_eq!(log.decision_id, "decision-verify-01");
        assert_eq!(log.policy_id, "policy-verify-01");
    }
}

// ── Signature layer failures ────────────────────────────────────────────

#[test]
fn revoked_signer_fails_signature_layer() {
    let (receipt_id, mut request) = build_valid_fixture();
    request.signature.signer_revocation.is_revoked = true;
    let verdict = verify_receipt_request(&receipt_id, &request);

    assert!(!verdict.passed);
    assert_eq!(
        verdict.failure_class,
        Some(VerificationFailureClass::Signature)
    );
    assert_eq!(verdict.exit_code, EXIT_CODE_SIGNATURE_FAILURE);
    assert!(!verdict.signature.passed);
}

#[test]
fn wrong_preimage_fails_signature_layer() {
    let (receipt_id, mut request) = build_valid_fixture();
    request.signature.expected_preimage_hash = ContentHash::compute(b"wrong-preimage");
    let verdict = verify_receipt_request(&receipt_id, &request);

    assert!(!verdict.passed);
    assert_eq!(
        verdict.failure_class,
        Some(VerificationFailureClass::Signature)
    );
    assert!(!verdict.signature.passed);
    assert!(verdict
        .signature
        .checks
        .iter()
        .any(|c| c.check == "canonical_preimage_hash_matches" && c.outcome == "fail"));
}

#[test]
fn wrong_signing_key_fails_signature_verification() {
    let (receipt_id, mut request) = build_valid_fixture();
    request.signature.signing_key_bytes = vec![0xAA; 32];
    let verdict = verify_receipt_request(&receipt_id, &request);

    assert!(!verdict.passed);
    assert!(!verdict.signature.passed);
    assert!(verdict
        .signature
        .checks
        .iter()
        .any(|c| c.check == "receipt_signature_valid" && c.outcome == "fail"));
}

#[test]
fn empty_revocation_source_fails_signature_layer() {
    let (receipt_id, mut request) = build_valid_fixture();
    request.signature.signer_revocation.source = "".to_string();
    let verdict = verify_receipt_request(&receipt_id, &request);

    assert!(!verdict.passed);
    assert!(!verdict.signature.passed);
    assert!(verdict
        .signature
        .checks
        .iter()
        .any(|c| c.check == "revocation_source_present" && c.outcome == "fail"));
}

#[test]
fn mismatched_signer_key_id_fails_signature_layer() {
    let (receipt_id, mut request) = build_valid_fixture();
    request.signature.signer_revocation.signer_key_id = EngineObjectId([0xFF; 32]);
    let verdict = verify_receipt_request(&receipt_id, &request);

    assert!(!verdict.passed);
    assert!(!verdict.signature.passed);
    assert!(verdict
        .signature
        .checks
        .iter()
        .any(|c| c.check == "signer_key_id_matches_receipt" && c.outcome == "fail"));
}

// ── Transparency layer failures ─────────────────────────────────────────

#[test]
fn missing_operator_key_fails_transparency() {
    let (receipt_id, mut request) = build_valid_fixture();
    request.transparency.operator_keys.clear();
    let verdict = verify_receipt_request(&receipt_id, &request);

    assert!(!verdict.passed);
    assert_eq!(
        verdict.failure_class,
        Some(VerificationFailureClass::Transparency)
    );
    assert!(!verdict.transparency.passed);
}

#[test]
fn revoked_operator_key_fails_transparency() {
    let (receipt_id, mut request) = build_valid_fixture();
    request.transparency.operator_keys[0].revoked = true;
    let verdict = verify_receipt_request(&receipt_id, &request);

    assert!(!verdict.passed);
    assert!(!verdict.transparency.passed);
    assert!(verdict
        .transparency
        .checks
        .iter()
        .any(|c| c.check == "checkpoint_operator_key_not_revoked" && c.outcome == "fail"));
}

// ── Stale cache warnings ────────────────────────────────────────────────

#[test]
fn stale_signature_cache_produces_warning() {
    let (receipt_id, mut request) = build_valid_fixture();
    request.signature.signer_revocation.cache_stale = true;
    let verdict = verify_receipt_request(&receipt_id, &request);

    // Signature layer still passes but we get a stale data warning.
    assert!(verdict.signature.passed);
    assert!(verdict
        .warnings
        .contains(&"signature_revocation_cache_stale".to_string()));
    assert_eq!(
        verdict.failure_class,
        Some(VerificationFailureClass::StaleData)
    );
    assert_eq!(verdict.exit_code, EXIT_CODE_STALE_DATA);
}

#[test]
fn stale_transparency_cache_produces_warning() {
    let (receipt_id, mut request) = build_valid_fixture();
    request.transparency.cache_stale = true;
    let verdict = verify_receipt_request(&receipt_id, &request);

    assert!(verdict
        .warnings
        .contains(&"transparency_cache_stale".to_string()));
}

#[test]
fn stale_attestation_policy_cache_produces_warning() {
    let (receipt_id, mut request) = build_valid_fixture();
    request.attestation.policy_cache_stale = true;
    let verdict = verify_receipt_request(&receipt_id, &request);

    assert!(verdict
        .warnings
        .contains(&"attestation_policy_cache_stale".to_string()));
}

#[test]
fn stale_attestation_revocation_cache_produces_warning() {
    let (receipt_id, mut request) = build_valid_fixture();
    request.attestation.revocation_cache_stale = true;
    let verdict = verify_receipt_request(&receipt_id, &request);

    assert!(verdict
        .warnings
        .contains(&"attestation_revocation_cache_stale".to_string()));
}

// ── render_verdict_summary ──────────────────────────────────────────────

#[test]
fn render_verdict_summary_passing() {
    let (receipt_id, request) = build_valid_fixture();
    let verdict = verify_receipt_request(&receipt_id, &request);
    let summary = render_verdict_summary(&verdict);

    assert!(summary.contains("receipt=rcpt-001"));
    assert!(summary.contains("passed=true"));
    assert!(summary.contains("exit_code=0"));
    assert!(summary.contains("failure_class=none"));
    assert!(summary.contains("warnings=0"));
}

#[test]
fn render_verdict_summary_failing() {
    let (receipt_id, mut request) = build_valid_fixture();
    request.signature.signer_revocation.is_revoked = true;
    let verdict = verify_receipt_request(&receipt_id, &request);
    let summary = render_verdict_summary(&verdict);

    assert!(summary.contains("passed=false"));
    assert!(summary.contains("failure_class=signature"));
    assert!(summary.contains(&format!("exit_code={EXIT_CODE_SIGNATURE_FAILURE}")));
}

// ── UnifiedReceiptVerificationVerdict serde ──────────────────────────────

#[test]
fn verdict_serde_roundtrip() {
    let (receipt_id, request) = build_valid_fixture();
    let verdict = verify_receipt_request(&receipt_id, &request);
    let json = serde_json::to_string(&verdict).unwrap();
    let back: UnifiedReceiptVerificationVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back.passed, verdict.passed);
    assert_eq!(back.exit_code, verdict.exit_code);
    assert_eq!(back.failure_class, verdict.failure_class);
    assert_eq!(back.receipt_id, verdict.receipt_id);
    assert_eq!(back.warnings.len(), verdict.warnings.len());
    assert_eq!(back.logs.len(), verdict.logs.len());
}

// ── Full lifecycle ──────────────────────────────────────────────────────

#[test]
fn full_lifecycle_verify_and_render() {
    let (receipt_id, request) = build_valid_fixture();
    let mut input = ReceiptVerifierCliInput::default();
    input.receipts.insert(receipt_id.clone(), request);

    let verdict = verify_receipt_by_id(&input, &receipt_id).expect("verify");
    assert!(verdict.passed);

    let summary = render_verdict_summary(&verdict);
    assert!(summary.contains("passed=true"));
    assert!(summary.contains("exit_code=0"));
}

#[test]
fn full_lifecycle_multiple_receipts() {
    let (receipt_id_1, request_1) = build_valid_fixture();
    let (_, mut request_2) = build_valid_fixture();
    request_2.signature.signer_revocation.is_revoked = true;
    let receipt_id_2 = "rcpt-002".to_string();

    let mut input = ReceiptVerifierCliInput::default();
    input.receipts.insert(receipt_id_1.clone(), request_1);
    input.receipts.insert(receipt_id_2.clone(), request_2);

    let v1 = verify_receipt_by_id(&input, &receipt_id_1).expect("v1");
    assert!(v1.passed);

    let v2 = verify_receipt_by_id(&input, &receipt_id_2).expect("v2");
    assert!(!v2.passed);
    assert_eq!(v2.failure_class, Some(VerificationFailureClass::Signature));
}

// ── Attestation layer edge cases ────────────────────────────────────────

#[test]
fn missing_attestation_bindings_fails() {
    let (receipt_id, mut request) = build_valid_fixture();
    let signer_key_bytes = request.signature.signing_key_bytes.clone();
    let receipt = request.receipt.clone();
    // Rebuild receipt without attestation bindings.
    let receipt = OptReceipt {
        attestation_bindings: None,
        signature: AuthenticityHash::compute_keyed(b"placeholder", b"placeholder"),
        ..receipt
    }
    .sign(&signer_key_bytes);
    request.signature.expected_preimage_hash = ContentHash::compute(&receipt.signing_preimage());
    request.receipt = receipt;
    let verdict = verify_receipt_request(&receipt_id, &request);

    assert!(!verdict.attestation.passed);
    assert!(verdict
        .attestation
        .checks
        .iter()
        .any(|c| c.check == "receipt_has_attestation_bindings" && c.outcome == "fail"));
}

// ── Deterministic verdict ───────────────────────────────────────────────

#[test]
fn deterministic_verdicts_for_same_input() {
    let (receipt_id, request) = build_valid_fixture();
    let v1 = verify_receipt_request(&receipt_id, &request);
    let v2 = verify_receipt_request(&receipt_id, &request);

    assert_eq!(
        serde_json::to_string(&v1).unwrap(),
        serde_json::to_string(&v2).unwrap()
    );
}
