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
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::attested_execution_cell::{
    SoftwareTrustRoot, TrustLevel, TrustRootBackend,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::mmr_proof::MerkleMountainRange;
use frankenengine_engine::proof_schema::{
    AttestationValidityWindow, OptReceipt, OptimizationClass, ReceiptAttestationBindings,
    proof_schema_version_current,
};
use frankenengine_engine::receipt_verifier_pipeline::{
    AttestationLayerInput, ConsistencyProofInput, EXIT_CODE_ATTESTATION_FAILURE,
    EXIT_CODE_SIGNATURE_FAILURE, EXIT_CODE_STALE_DATA, EXIT_CODE_SUCCESS,
    EXIT_CODE_TRANSPARENCY_FAILURE, LayerCheck, LayerResult, LogOperatorKey,
    ReceiptVerifierCliInput, ReceiptVerifierPipelineError, SignatureLayerInput,
    SignedLogCheckpoint, SignerRevocationCache, TransparencyLayerInput,
    UnifiedReceiptVerificationRequest, UnifiedReceiptVerificationVerdict, VerificationFailureClass,
    VerifierLogEvent, render_verdict_summary, verify_receipt_by_id, verify_receipt_request,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{Signature, SigningKey, sign_preimage};
use frankenengine_engine::tee_attestation_policy::{
    AttestationFreshnessWindow, AttestationQuote as PolicyAttestationQuote, DecisionImpact,
    MeasurementAlgorithm, MeasurementDigest, PlatformTrustRoot, RevocationFallback,
    RevocationProbeStatus, RevocationSource, RevocationSourceType, TeeAttestationPolicy,
    TeePlatform, TrustRootPinning, TrustRootSource,
};

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
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: intel_digest_hex,
        }],
    );
    approved_measurements.insert(
        TeePlatform::ArmTrustZone,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: digest_hex(0x22, 32),
        }],
    );
    approved_measurements.insert(
        TeePlatform::ArmCca,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: digest_hex(0x44, 32),
        }],
    );
    approved_measurements.insert(
        TeePlatform::AmdSev,
        vec![MeasurementDigest {
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

fn build_cli_input(wrong_signature_key: bool) -> ReceiptVerifierCliInput {
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
    let mut attestation_quote =
        software_root.attest(&measurement, nonce, 30_000_000_000, 10_000_000_000);
    attestation_quote.trust_level = TrustLevel::SoftwareOnly;

    let measurement_zone = "measurement-zone-test".to_string();
    let measurement_id = measurement
        .derive_id(&measurement_zone)
        .expect("measurement ID");
    let quote_digest =
        ContentHash::compute(&serde_json::to_vec(&attestation_quote).expect("quote json"));

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
    old_mmr.append(leaf0);
    old_mmr.append(leaf1);
    let old_root = old_mmr.root_hash().expect("old root");

    let mut mmr = MerkleMountainRange::new(5);
    mmr.append(leaf0);
    mmr.append(leaf1);
    mmr.append(receipt_leaf_hash);
    let inclusion_proof = mmr.inclusion_proof(2).expect("inclusion");
    let consistency_proof = mmr.consistency_proof(2).expect("consistency");
    let current_root = mmr.root_hash().expect("root");

    let operator_signing_key = SigningKey::from_bytes([9u8; 32]);
    let operator_verification_key = operator_signing_key.verification_key();
    let checkpoint_stub = SignedLogCheckpoint {
        checkpoint_seq: 1,
        log_length: inclusion_proof.stream_length,
        root_hash: current_root,
        timestamp_ns: 20_000_000_000,
        operator_key_id: "operator-1".to_string(),
        signature: Signature::from_bytes([0u8; 64]),
    };
    let mut checkpoint = checkpoint_stub.clone();
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"FrankenEngine.ReceiptTransparencyCheckpoint.v1");
    preimage.extend_from_slice(&checkpoint_stub.checkpoint_seq.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(&checkpoint_stub.log_length.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(checkpoint_stub.root_hash.as_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(&checkpoint_stub.timestamp_ns.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(checkpoint_stub.operator_key_id.as_bytes());
    checkpoint.signature = sign_preimage(&operator_signing_key, &preimage).expect("checkpoint sig");

    let measurement_digest_hex = measurement.composite_hash().to_hex();
    let policy = sample_policy(SecurityEpoch::from_raw(5), measurement_digest_hex, "root-1");
    let mut revocation_observations = BTreeMap::new();
    revocation_observations.insert("intel_pcs".to_string(), RevocationProbeStatus::Good);
    revocation_observations.insert(
        "internal_ledger".to_string(),
        RevocationProbeStatus::Unavailable,
    );
    let policy_quote = PolicyAttestationQuote {
        platform: TeePlatform::IntelSgx,
        measurement: MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: measurement.composite_hash().to_hex(),
        },
        quote_age_secs: 10,
        trust_root_id: "root-1".to_string(),
        revocation_observations,
    };

    let mut receipts = BTreeMap::new();
    receipts.insert(
        receipt_id,
        UnifiedReceiptVerificationRequest {
            trace_id: "trace-verify-01".to_string(),
            decision_id: "decision-verify-01".to_string(),
            policy_id: "policy-verify-01".to_string(),
            verification_timestamp_ns: 20_000_000_000,
            receipt,
            signature: SignatureLayerInput {
                expected_preimage_hash,
                signing_key_bytes: if wrong_signature_key {
                    vec![1u8; 32]
                } else {
                    signer_key_bytes
                },
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
                attestation_quote,
                policy_quote,
                policy,
                decision_impact: DecisionImpact::HighImpact,
                runtime_epoch: SecurityEpoch::from_raw(5),
                verification_time_ns: 20_000_000_000,
                measurement_zone,
                trust_roots: vec![software_root],
                policy_cache_stale: false,
                revocation_cache_stale: false,
            },
        },
    );

    ReceiptVerifierCliInput { receipts }
}

fn write_input_file(input: &ReceiptVerifierCliInput) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    path.push(format!(
        "receipt_verifier_pipeline_test_{}_{}.json",
        std::process::id(),
        nonce
    ));
    fs::write(
        &path,
        serde_json::to_vec_pretty(input).expect("input serialization"),
    )
    .expect("input write");
    path
}

#[test]
fn franken_verify_receipt_command_succeeds_for_valid_input() {
    let input = build_cli_input(false);
    let input_path = write_input_file(&input);

    let output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "receipt",
            "rcpt-001",
            "--input",
            input_path.to_str().expect("utf8 path"),
            "--summary",
        ])
        .output()
        .expect("command executes");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("receipt=rcpt-001"));
    assert!(stdout.contains("passed=true"));
    assert!(stdout.contains("exit_code=0"));

    let _ = fs::remove_file(input_path);
}

#[test]
fn franken_verify_receipt_command_returns_signature_failure_exit_code() {
    let input = build_cli_input(true);
    let input_path = write_input_file(&input);

    let output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "receipt",
            "rcpt-001",
            "--input",
            input_path.to_str().expect("utf8 path"),
            "--summary",
        ])
        .output()
        .expect("command executes");

    assert_eq!(output.status.code(), Some(20));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("passed=false"));
    assert!(stdout.contains("failure_class=signature"));

    let _ = fs::remove_file(input_path);
}

// ===========================================================================
// Enrichment: PearlTower 2026-03-04 — library-level tests
// ===========================================================================

/// Build a valid (receipt_id, request) that passes all 3 verification layers.
///
/// The existing `build_cli_input` uses `RevocationProbeStatus::Unavailable` for
/// `internal_ledger` (whose policy is `FailClosed`), which causes the attestation
/// layer to fail. This helper mirrors the unit-test `build_valid_fixture` by
/// using `RevocationProbeStatus::Good` for all sources.
fn build_valid_request() -> (String, UnifiedReceiptVerificationRequest) {
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
    let mut attestation_quote =
        software_root.attest(&measurement, nonce, 30_000_000_000, 10_000_000_000);
    attestation_quote.trust_level = TrustLevel::SoftwareOnly;

    let measurement_zone = "measurement-zone-test".to_string();
    let measurement_id = measurement
        .derive_id(&measurement_zone)
        .expect("measurement ID");
    let quote_digest =
        ContentHash::compute(&serde_json::to_vec(&attestation_quote).expect("quote json"));

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
    old_mmr.append(leaf0);
    old_mmr.append(leaf1);
    let old_root = old_mmr.root_hash().expect("old root");

    let mut mmr = MerkleMountainRange::new(5);
    mmr.append(leaf0);
    mmr.append(leaf1);
    mmr.append(receipt_leaf_hash);
    let inclusion_proof = mmr.inclusion_proof(2).expect("inclusion");
    let consistency_proof = mmr.consistency_proof(2).expect("consistency");

    let operator_signing_key = SigningKey::from_bytes([9u8; 32]);
    let operator_verification_key = operator_signing_key.verification_key();
    let checkpoint_stub = SignedLogCheckpoint {
        checkpoint_seq: 1,
        log_length: inclusion_proof.stream_length,
        root_hash: mmr.root_hash().expect("root"),
        timestamp_ns: 20_000_000_000,
        operator_key_id: "operator-1".to_string(),
        signature: Signature::from_bytes([0u8; 64]),
    };
    let mut checkpoint = checkpoint_stub.clone();
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"FrankenEngine.ReceiptTransparencyCheckpoint.v1");
    preimage.extend_from_slice(&checkpoint_stub.checkpoint_seq.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(&checkpoint_stub.log_length.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(checkpoint_stub.root_hash.as_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(&checkpoint_stub.timestamp_ns.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(checkpoint_stub.operator_key_id.as_bytes());
    checkpoint.signature = sign_preimage(&operator_signing_key, &preimage).expect("checkpoint sig");

    let measurement_digest_hex = measurement.composite_hash().to_hex();
    let policy = sample_policy(SecurityEpoch::from_raw(5), measurement_digest_hex, "root-1");

    // Key difference from build_cli_input: ALL revocation probes return Good
    let mut revocation_observations = BTreeMap::new();
    revocation_observations.insert("intel_pcs".to_string(), RevocationProbeStatus::Good);
    revocation_observations.insert("internal_ledger".to_string(), RevocationProbeStatus::Good);

    let policy_quote = PolicyAttestationQuote {
        platform: TeePlatform::IntelSgx,
        measurement: MeasurementDigest {
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
            attestation_quote,
            policy_quote,
            policy,
            decision_impact: DecisionImpact::HighImpact,
            runtime_epoch: SecurityEpoch::from_raw(5),
            verification_time_ns: 20_000_000_000,
            measurement_zone,
            trust_roots: vec![software_root],
            policy_cache_stale: false,
            revocation_cache_stale: false,
        },
    };

    (receipt_id, request)
}

// -- verify_receipt_request: valid case --

#[test]
fn pipeline_passes_for_valid_request() {
    let (receipt_id, request) = build_valid_request();
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(verdict.passed);
    assert_eq!(verdict.failure_class, None);
    assert_eq!(verdict.exit_code, EXIT_CODE_SUCCESS);
    assert!(verdict.signature.passed);
    assert!(verdict.transparency.passed);
    assert!(verdict.attestation.passed);
    assert!(verdict.warnings.is_empty());
}

#[test]
fn verdict_propagates_request_ids() {
    let (receipt_id, request) = build_valid_request();
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert_eq!(verdict.receipt_id, receipt_id);
    assert_eq!(verdict.trace_id, request.trace_id);
    assert_eq!(verdict.decision_id, request.decision_id);
    assert_eq!(verdict.policy_id, request.policy_id);
    assert_eq!(
        verdict.verification_timestamp_ns,
        request.verification_timestamp_ns
    );
}

#[test]
fn verdict_always_has_four_log_entries() {
    let (receipt_id, request) = build_valid_request();
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert_eq!(verdict.logs.len(), 4);
}

#[test]
fn verdict_logs_have_correct_component() {
    let (receipt_id, request) = build_valid_request();
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(
        verdict
            .logs
            .iter()
            .all(|log| log.component == "receipt_verifier_pipeline")
    );
}

#[test]
fn verdict_logs_include_completion_event() {
    let (receipt_id, request) = build_valid_request();
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(
        verdict
            .logs
            .iter()
            .any(|log| log.event == "receipt_verification_complete")
    );
}

#[test]
fn verdict_passing_has_pass_completion_outcome() {
    let (receipt_id, request) = build_valid_request();
    let verdict = verify_receipt_request(&receipt_id, &request);
    let complete = verdict
        .logs
        .iter()
        .find(|log| log.event == "receipt_verification_complete")
        .unwrap();
    assert_eq!(complete.outcome, "pass");
    assert!(complete.error_code.is_none());
}

// -- verify_receipt_by_id --

#[test]
fn by_id_lookup_returns_verdict_when_present() {
    let (receipt_id, request) = build_valid_request();
    let mut input = ReceiptVerifierCliInput::default();
    input.receipts.insert(receipt_id.clone(), request);
    let verdict = verify_receipt_by_id(&input, &receipt_id).unwrap();
    assert!(verdict.passed);
    assert_eq!(verdict.receipt_id, receipt_id);
}

#[test]
fn by_id_lookup_returns_error_when_missing() {
    let input = build_cli_input(false);
    let error = verify_receipt_by_id(&input, "missing").expect_err("missing receipt");
    assert_eq!(
        error,
        ReceiptVerifierPipelineError::ReceiptNotFound {
            receipt_id: "missing".to_string()
        }
    );
}

// -- render_verdict_summary --

#[test]
fn render_verdict_summary_passing() {
    let (receipt_id, request) = build_valid_request();
    let verdict = verify_receipt_request(&receipt_id, &request);
    let summary = render_verdict_summary(&verdict);
    assert!(summary.contains("passed=true"));
    assert!(summary.contains("exit_code=0"));
    assert!(summary.contains("failure_class=none"));
    assert!(summary.contains("warnings=0"));
}

#[test]
fn render_verdict_summary_failing() {
    let (receipt_id, mut request) = build_valid_request();
    request.signature.signing_key_bytes = vec![1u8; 32];
    let verdict = verify_receipt_request(&receipt_id, &request);
    let summary = render_verdict_summary(&verdict);
    assert!(summary.contains("passed=false"));
    assert!(summary.contains("failure_class=signature"));
}

#[test]
fn render_verdict_summary_stale_data() {
    let (receipt_id, mut request) = build_valid_request();
    request.attestation.revocation_cache_stale = true;
    let verdict = verify_receipt_request(&receipt_id, &request);
    let summary = render_verdict_summary(&verdict);
    assert!(summary.contains("passed=false"));
    assert!(summary.contains("failure_class=stale_data"));
    assert!(summary.contains("warnings=1"));
}

// -- VerificationFailureClass --

#[test]
fn failure_class_display_all_variants() {
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
fn failure_class_display_uniqueness() {
    use std::collections::BTreeSet;
    let displays: BTreeSet<String> = [
        VerificationFailureClass::Signature,
        VerificationFailureClass::Transparency,
        VerificationFailureClass::Attestation,
        VerificationFailureClass::StaleData,
    ]
    .iter()
    .map(|c| c.to_string())
    .collect();
    assert_eq!(displays.len(), 4);
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
        assert_eq!(class, back);
    }
}

#[test]
fn failure_class_ordering() {
    assert!(VerificationFailureClass::Signature < VerificationFailureClass::Transparency);
    assert!(VerificationFailureClass::Transparency < VerificationFailureClass::Attestation);
    assert!(VerificationFailureClass::Attestation < VerificationFailureClass::StaleData);
}

#[test]
fn failure_class_display_matches_serde_key() {
    for variant in [
        VerificationFailureClass::Signature,
        VerificationFailureClass::Transparency,
        VerificationFailureClass::Attestation,
        VerificationFailureClass::StaleData,
    ] {
        let display = variant.to_string();
        let json = serde_json::to_string(&variant).unwrap();
        let serde_key = json.trim_matches('"');
        assert_eq!(display, serde_key);
    }
}

// -- Exit code constants --

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
        for (j, b) in codes.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

// -- ReceiptVerifierPipelineError --

#[test]
fn pipeline_error_display() {
    let e = ReceiptVerifierPipelineError::ReceiptNotFound {
        receipt_id: "rcpt-x".to_string(),
    };
    assert_eq!(
        e.to_string(),
        "receipt 'rcpt-x' not found in verifier input"
    );
}

#[test]
fn pipeline_error_serde_roundtrip() {
    let e = ReceiptVerifierPipelineError::ReceiptNotFound {
        receipt_id: "x".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ReceiptVerifierPipelineError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// -- VerifierLogEvent serde --

#[test]
fn verifier_log_event_serde_roundtrip() {
    let e = VerifierLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: VerifierLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn verifier_log_event_with_error_code_serde_roundtrip() {
    let e = VerifierLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("err-1".to_string()),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: VerifierLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// -- LayerCheck serde --

#[test]
fn layer_check_serde_roundtrip() {
    let check = LayerCheck {
        check: "test_check".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        detail: "detail".to_string(),
    };
    let json = serde_json::to_string(&check).unwrap();
    let back: LayerCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(check, back);
}

#[test]
fn layer_check_with_error_code_serde_roundtrip() {
    let check = LayerCheck {
        check: "some_check".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("some_error".to_string()),
        detail: "a detail".to_string(),
    };
    let json = serde_json::to_string(&check).unwrap();
    let back: LayerCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(check, back);
}

// -- LayerResult serde --

#[test]
fn layer_result_serde_roundtrip() {
    let r = LayerResult {
        passed: true,
        error_code: None,
        checks: vec![LayerCheck {
            check: "c1".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            detail: "d1".to_string(),
        }],
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: LayerResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// -- UnifiedReceiptVerificationVerdict serde --

#[test]
fn verdict_serde_roundtrip() {
    let (receipt_id, request) = build_valid_request();
    let verdict = verify_receipt_request(&receipt_id, &request);
    let json = serde_json::to_string(&verdict).unwrap();
    let back: UnifiedReceiptVerificationVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(verdict, back);
}

// -- Signature failure modes --

#[test]
fn signature_wrong_key_fails() {
    let (receipt_id, mut request) = build_valid_request();
    request.signature.signing_key_bytes = vec![1u8; 32];
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert_eq!(
        verdict.failure_class,
        Some(VerificationFailureClass::Signature)
    );
    assert_eq!(verdict.exit_code, EXIT_CODE_SIGNATURE_FAILURE);
}

#[test]
fn signature_revoked_signer_fails() {
    let (receipt_id, mut request) = build_valid_request();
    request.signature.signer_revocation.is_revoked = true;
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert!(
        verdict
            .signature
            .checks
            .iter()
            .any(|c| c.check == "signer_not_revoked" && c.outcome == "fail")
    );
}

#[test]
fn signature_empty_revocation_source_fails() {
    let (receipt_id, mut request) = build_valid_request();
    request.signature.signer_revocation.source = "".to_string();
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert!(
        verdict
            .signature
            .checks
            .iter()
            .any(|c| c.check == "revocation_source_present" && c.outcome == "fail")
    );
}

#[test]
fn signature_signer_key_id_mismatch_fails() {
    let (receipt_id, mut request) = build_valid_request();
    request.signature.signer_revocation.signer_key_id = EngineObjectId([0xAA; 32]);
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert!(
        verdict
            .signature
            .checks
            .iter()
            .any(|c| c.check == "signer_key_id_matches_receipt" && c.outcome == "fail")
    );
}

#[test]
fn signature_preimage_hash_mismatch_fails() {
    let (receipt_id, mut request) = build_valid_request();
    request.signature.expected_preimage_hash = ContentHash::compute(b"wrong");
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert!(
        verdict
            .signature
            .checks
            .iter()
            .any(|c| c.check == "canonical_preimage_hash_matches" && c.outcome == "fail")
    );
}

// -- Transparency failure modes --

#[test]
fn transparency_tampered_leaf_fails() {
    let (receipt_id, mut request) = build_valid_request();
    request.transparency.leaf_hash = ContentHash::compute(b"tampered");
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert_eq!(
        verdict.failure_class,
        Some(VerificationFailureClass::Transparency)
    );
    assert_eq!(verdict.exit_code, EXIT_CODE_TRANSPARENCY_FAILURE);
}

#[test]
fn transparency_operator_key_revoked_fails() {
    let (receipt_id, mut request) = build_valid_request();
    request.transparency.operator_keys[0].revoked = true;
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert!(
        verdict
            .transparency
            .checks
            .iter()
            .any(|c| c.check == "checkpoint_operator_key_not_revoked" && c.outcome == "fail")
    );
}

#[test]
fn transparency_operator_key_missing_fails() {
    let (receipt_id, mut request) = build_valid_request();
    request.transparency.operator_keys.clear();
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert!(
        verdict
            .transparency
            .checks
            .iter()
            .any(|c| c.check == "checkpoint_operator_key_found" && c.outcome == "fail")
    );
}

#[test]
fn transparency_root_mismatch_fails() {
    let (receipt_id, mut request) = build_valid_request();
    request.transparency.inclusion_proof.root_hash = ContentHash::compute(b"wrong-root");
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert!(
        verdict
            .transparency
            .checks
            .iter()
            .any(|c| c.check == "inclusion_root_matches_checkpoint_root" && c.outcome == "fail")
    );
}

#[test]
fn transparency_log_length_mismatch_fails() {
    let (receipt_id, mut request) = build_valid_request();
    request.transparency.inclusion_proof.stream_length = 999;
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert!(verdict.transparency.checks.iter().any(|c| c.check
        == "checkpoint_log_length_matches_inclusion_stream_length"
        && c.outcome == "fail"));
}

// -- Attestation failure modes --

#[test]
fn attestation_quote_age_mismatch_fails() {
    let (receipt_id, mut request) = build_valid_request();
    request.attestation.policy_quote.quote_age_secs = 999_999;
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert_eq!(
        verdict.failure_class,
        Some(VerificationFailureClass::Attestation)
    );
    assert_eq!(verdict.exit_code, EXIT_CODE_ATTESTATION_FAILURE);
}

#[test]
fn attestation_nonce_mismatch_fails() {
    let (receipt_id, mut request) = build_valid_request();
    if let Some(ref mut bindings) = request.receipt.attestation_bindings {
        bindings.nonce = [0xFF; 32];
    }
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert!(
        verdict
            .attestation
            .checks
            .iter()
            .any(|c| c.check == "quote_nonce_matches_binding" && c.outcome == "fail")
    );
}

#[test]
fn attestation_trust_root_missing_fails() {
    let (receipt_id, mut request) = build_valid_request();
    request.attestation.trust_roots.clear();
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert!(
        verdict
            .attestation
            .checks
            .iter()
            .any(|c| c.check == "quote_trust_root_available" && c.outcome == "fail")
    );
}

#[test]
fn attestation_policy_trust_root_mismatch_fails() {
    let (receipt_id, mut request) = build_valid_request();
    request.attestation.policy_quote.trust_root_id = "wrong-root".to_string();
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert!(verdict.attestation.checks.iter().any(|c| c.check
        == "policy_quote_trust_root_matches_attested_signer"
        && c.outcome == "fail"));
}

#[test]
fn attestation_measurement_mismatch_fails() {
    let (receipt_id, mut request) = build_valid_request();
    request.attestation.policy_quote.measurement.digest_hex = "aa".repeat(32);
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert!(verdict.attestation.checks.iter().any(|c| c.check
        == "policy_quote_measurement_matches_attested_measurement"
        && c.outcome == "fail"));
}

// -- Stale cache warnings --

#[test]
fn signature_revocation_cache_stale_warning() {
    let (receipt_id, mut request) = build_valid_request();
    request.signature.signer_revocation.cache_stale = true;
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert_eq!(
        verdict.failure_class,
        Some(VerificationFailureClass::StaleData)
    );
    assert!(
        verdict
            .warnings
            .contains(&"signature_revocation_cache_stale".to_string())
    );
}

#[test]
fn transparency_cache_stale_warning() {
    let (receipt_id, mut request) = build_valid_request();
    request.transparency.cache_stale = true;
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert!(
        verdict
            .warnings
            .contains(&"transparency_cache_stale".to_string())
    );
}

#[test]
fn attestation_policy_cache_stale_warning() {
    let (receipt_id, mut request) = build_valid_request();
    request.attestation.policy_cache_stale = true;
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert!(!verdict.passed);
    assert_eq!(
        verdict.failure_class,
        Some(VerificationFailureClass::StaleData)
    );
    assert_eq!(verdict.exit_code, EXIT_CODE_STALE_DATA);
}

#[test]
fn multiple_stale_caches_accumulate() {
    let (receipt_id, mut request) = build_valid_request();
    request.signature.signer_revocation.cache_stale = true;
    request.transparency.cache_stale = true;
    request.attestation.policy_cache_stale = true;
    request.attestation.revocation_cache_stale = true;
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert_eq!(verdict.warnings.len(), 4);
}

// -- Priority of failure classes --

#[test]
fn signature_failure_takes_priority_over_stale() {
    let (receipt_id, mut request) = build_valid_request();
    request.signature.signing_key_bytes = vec![1u8; 32];
    request.attestation.policy_cache_stale = true;
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert_eq!(
        verdict.failure_class,
        Some(VerificationFailureClass::Signature)
    );
}

#[test]
fn transparency_failure_takes_priority_over_attestation() {
    let (receipt_id, mut request) = build_valid_request();
    request.transparency.leaf_hash = ContentHash::compute(b"tampered");
    request.attestation.policy_quote.quote_age_secs = 999_999;
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert_eq!(
        verdict.failure_class,
        Some(VerificationFailureClass::Transparency)
    );
}

#[test]
fn attestation_failure_takes_priority_over_stale() {
    let (receipt_id, mut request) = build_valid_request();
    request.attestation.policy_quote.quote_age_secs = 999_999;
    request.signature.signer_revocation.cache_stale = true;
    let verdict = verify_receipt_request(&receipt_id, &request);
    assert_eq!(
        verdict.failure_class,
        Some(VerificationFailureClass::Attestation)
    );
}

// -- Verdict completion event outcomes --

#[test]
fn verdict_hard_failure_has_fail_completion_outcome() {
    let (receipt_id, mut request) = build_valid_request();
    request.signature.signing_key_bytes = vec![1u8; 32];
    let verdict = verify_receipt_request(&receipt_id, &request);
    let complete = verdict
        .logs
        .iter()
        .find(|log| log.event == "receipt_verification_complete")
        .unwrap();
    assert_eq!(complete.outcome, "fail");
    assert_eq!(complete.error_code.as_deref(), Some("signature"));
}

#[test]
fn verdict_stale_has_warn_completion_outcome() {
    let (receipt_id, mut request) = build_valid_request();
    request.attestation.policy_cache_stale = true;
    let verdict = verify_receipt_request(&receipt_id, &request);
    let complete = verdict
        .logs
        .iter()
        .find(|log| log.event == "receipt_verification_complete")
        .unwrap();
    assert_eq!(complete.outcome, "warn");
    assert_eq!(complete.error_code.as_deref(), Some("stale_data"));
}

// -- JSON field name contracts --

#[test]
fn verifier_log_event_json_field_names() {
    let e = VerifierLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&e).unwrap();
    for field in &[
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(
            json.contains(field),
            "VerifierLogEvent JSON missing field: {field}"
        );
    }
}

#[test]
fn verdict_json_field_names() {
    let (receipt_id, request) = build_valid_request();
    let verdict = verify_receipt_request(&receipt_id, &request);
    let json = serde_json::to_string(&verdict).unwrap();
    for field in &[
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
        assert!(json.contains(field), "Verdict JSON missing field: {field}");
    }
}

#[test]
fn layer_result_json_field_names() {
    let r = LayerResult {
        passed: true,
        error_code: None,
        checks: vec![],
    };
    let json = serde_json::to_string(&r).unwrap();
    for field in &["passed", "error_code", "checks"] {
        assert!(
            json.contains(field),
            "LayerResult JSON missing field: {field}"
        );
    }
}

// -- Serde roundtrips for input types --

#[test]
fn signer_revocation_cache_serde_roundtrip() {
    let cache = SignerRevocationCache {
        signer_key_id: EngineObjectId([0xAA; 32]),
        source: "offline-ledger".to_string(),
        is_revoked: false,
        cache_stale: true,
    };
    let json = serde_json::to_string(&cache).unwrap();
    let back: SignerRevocationCache = serde_json::from_str(&json).unwrap();
    assert_eq!(cache, back);
}

#[test]
fn log_operator_key_serde_roundtrip() {
    let key = LogOperatorKey {
        key_id: "op-key-1".to_string(),
        verification_key: SigningKey::from_bytes([3u8; 32]).verification_key(),
        revoked: false,
    };
    let json = serde_json::to_string(&key).unwrap();
    let back: LogOperatorKey = serde_json::from_str(&json).unwrap();
    assert_eq!(key, back);
}

#[test]
fn signed_log_checkpoint_serde_roundtrip() {
    let checkpoint = SignedLogCheckpoint {
        checkpoint_seq: 42,
        log_length: 100,
        root_hash: ContentHash::compute(b"root"),
        timestamp_ns: 5_000_000_000,
        operator_key_id: "op-1".to_string(),
        signature: Signature::from_bytes([0u8; 64]),
    };
    let json = serde_json::to_string(&checkpoint).unwrap();
    let back: SignedLogCheckpoint = serde_json::from_str(&json).unwrap();
    assert_eq!(checkpoint, back);
}

#[test]
fn signature_layer_input_serde_roundtrip() {
    let input = SignatureLayerInput {
        expected_preimage_hash: ContentHash::compute(b"preimage"),
        signing_key_bytes: vec![0x55; 32],
        signer_revocation: SignerRevocationCache {
            signer_key_id: EngineObjectId([0x44; 32]),
            source: "offline".to_string(),
            is_revoked: false,
            cache_stale: false,
        },
    };
    let json = serde_json::to_string(&input).unwrap();
    let back: SignatureLayerInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn receipt_verifier_cli_input_default_is_empty() {
    let input = ReceiptVerifierCliInput::default();
    assert!(input.receipts.is_empty());
}

// -- Clone independence --

#[test]
fn signer_revocation_cache_clone_independence() {
    let original = SignerRevocationCache {
        signer_key_id: EngineObjectId([0xAA; 32]),
        source: "src".to_string(),
        is_revoked: false,
        cache_stale: false,
    };
    let mut cloned = original.clone();
    cloned.is_revoked = true;
    cloned.source = "mutated".to_string();
    assert!(!original.is_revoked);
    assert_eq!(original.source, "src");
}

#[test]
fn log_operator_key_clone_independence() {
    let original = LogOperatorKey {
        key_id: "op-1".to_string(),
        verification_key: SigningKey::from_bytes([3u8; 32]).verification_key(),
        revoked: false,
    };
    let mut cloned = original.clone();
    cloned.key_id = "mutated".to_string();
    cloned.revoked = true;
    assert_eq!(original.key_id, "op-1");
    assert!(!original.revoked);
}

#[test]
fn verifier_log_event_clone_independence() {
    let original = VerifierLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let mut cloned = original.clone();
    cloned.outcome = "fail".to_string();
    cloned.error_code = Some("err".to_string());
    assert_eq!(original.outcome, "pass");
    assert!(original.error_code.is_none());
}
