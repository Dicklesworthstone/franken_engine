//! In-tree cargo companion for the FE-CLAIM-004 signed-decision-receipt gate
//! (`scripts/run_rgc_signed_decision_receipt.sh`, bd-cixqu.1.4).
//!
//! The gate's `ci` mode validates the FE-CLAIM-004 proof *surface* (it does not
//! invoke cargo). This test is the runnable proof that the foundational A.1
//! artifact — the cryptographically signed decision receipt — round-trips and
//! fails closed under tampering, and that the unified verifier surface is
//! fail-closed by default. Callers run it via rch:
//!
//! ```text
//! cargo test --test rgc_signed_decision_receipt
//! ```

use std::collections::BTreeMap;

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::proof_schema::{
    OptReceipt, OptimizationClass, proof_schema_version_current,
};
use frankenengine_engine::receipt_verifier_pipeline::{
    ReceiptVerifierCliInput, verify_receipt_by_id,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::tee_attestation_policy::DecisionImpact;

const SIGNER_KEY: &[u8] = &[0x5Au8; 32];
const WRONG_KEY: &[u8] = &[0xA5u8; 32];

/// Builds an unsigned A.1 decision receipt with deterministic fields.
fn unsigned_receipt() -> OptReceipt {
    let mut replay_compatibility = BTreeMap::new();
    replay_compatibility.insert("arch".to_string(), "x86_64".to_string());
    replay_compatibility.insert("engine".to_string(), "franken-v1".to_string());

    OptReceipt {
        schema_version: proof_schema_version_current(),
        optimization_id: "opt-rgc-001".to_string(),
        optimization_class: OptimizationClass::Superinstruction,
        baseline_ir_hash: ContentHash::compute(b"baseline-ir"),
        candidate_ir_hash: ContentHash::compute(b"candidate-ir"),
        translation_witness_hash: ContentHash::compute(b"translation-witness"),
        invariance_digest: ContentHash::compute(b"invariance"),
        rollback_token_id: "rollback-rgc-001".to_string(),
        replay_compatibility,
        policy_epoch: SecurityEpoch::from_raw(5),
        timestamp_ticks: 1_000,
        signer_key_id: EngineObjectId([0x44; 32]),
        correlation_id: "corr-rgc-001".to_string(),
        decision_impact: DecisionImpact::HighImpact,
        attestation_bindings: None,
        signature: AuthenticityHash::compute_keyed(b"placeholder", b"placeholder"),
    }
}

fn signed_receipt() -> OptReceipt {
    unsigned_receipt().sign(SIGNER_KEY)
}

#[test]
fn valid_receipt_verifies_with_signing_key() {
    let receipt = signed_receipt();
    assert!(
        receipt.verify_signature(SIGNER_KEY),
        "freshly signed receipt must verify under its signing key"
    );
}

#[test]
fn wrong_key_is_rejected() {
    let receipt = signed_receipt();
    assert!(
        !receipt.verify_signature(WRONG_KEY),
        "receipt must not verify under a different key (fail closed)"
    );
}

#[test]
fn tampered_optimization_id_breaks_signature() {
    let mut receipt = signed_receipt();
    receipt.optimization_id = "opt-tampered".to_string();
    assert!(
        !receipt.verify_signature(SIGNER_KEY),
        "mutating a signed field must invalidate the signature"
    );
}

#[test]
fn tampered_candidate_ir_breaks_signature() {
    let mut receipt = signed_receipt();
    receipt.candidate_ir_hash = ContentHash::compute(b"swapped-candidate");
    assert!(!receipt.verify_signature(SIGNER_KEY));
}

#[test]
fn tampered_policy_epoch_breaks_signature() {
    let mut receipt = signed_receipt();
    receipt.policy_epoch = SecurityEpoch::from_raw(99);
    assert!(!receipt.verify_signature(SIGNER_KEY));
}

#[test]
fn signing_preimage_excludes_signature_field() {
    // Two receipts identical except for the signature field must share a
    // preimage — the signature is computed over the unsigned view.
    let signed = signed_receipt();
    let mut other = signed.clone();
    other.signature = AuthenticityHash::compute_keyed(b"different", b"different");
    assert_eq!(
        signed.signing_preimage(),
        other.signing_preimage(),
        "signature field must be excluded from the signing preimage"
    );
}

#[test]
fn preimage_is_deterministic() {
    let a = unsigned_receipt().signing_preimage();
    let b = unsigned_receipt().signing_preimage();
    assert_eq!(a, b, "preimage construction must be deterministic");
}

#[test]
fn distinct_correlation_ids_yield_distinct_preimage() {
    let base = unsigned_receipt();
    let mut other = unsigned_receipt();
    other.correlation_id = "corr-rgc-002".to_string();
    assert_ne!(base.signing_preimage(), other.signing_preimage());
}

#[test]
fn signed_receipt_serde_roundtrip_preserves_verification() {
    let receipt = signed_receipt();
    let json = serde_json::to_string(&receipt).expect("serialize signed receipt");
    let restored: OptReceipt = serde_json::from_str(&json).expect("deserialize signed receipt");
    assert!(
        restored.verify_signature(SIGNER_KEY),
        "signature must survive a serde round-trip"
    );
    assert_eq!(receipt.signing_preimage(), restored.signing_preimage());
}

#[test]
fn unified_verifier_is_fail_closed_for_unknown_receipt() {
    // The gate's transparency/attestation layers build on the unified verifier;
    // an empty input must never silently "pass" — it errors.
    let input = ReceiptVerifierCliInput::default();
    let result = verify_receipt_by_id(&input, "rcpt-does-not-exist");
    assert!(
        result.is_err(),
        "verifier must fail closed when the receipt id is absent"
    );
    let err = result.unwrap_err();
    assert!(err.to_string().contains("rcpt-does-not-exist"));
}
