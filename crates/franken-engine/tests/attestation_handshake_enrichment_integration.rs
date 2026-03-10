#![forbid(unsafe_code)]
//! Enrichment integration tests for `attestation_handshake`.
//!
//! Adds exact Display values, Debug distinctness, error Display exact messages,
//! JSON field-name stability, serde exact enum values, CellAuthorization.authorizes(),
//! CellHandshakeClient canonical_bytes, check_authorization error paths,
//! challenge validity edge cases, revoke_authorization false on unknown cell,
//! and additional serde roundtrips beyond the existing 26 integration tests.

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

use frankenengine_engine::attestation_handshake::{
    CellAuthorization, CellHandshakeClient, HandshakeError, HandshakeEvent, HandshakeOutcome,
    PolicyPlaneVerifier, ReattestationTrigger,
};
use frankenengine_engine::attested_execution_cell::{
    CellFunction, MeasurementDigest, SoftwareTrustRoot, TrustRootBackend,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn signing_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(13);
    }
    key
}

fn trust_root() -> SoftwareTrustRoot {
    SoftwareTrustRoot::new("test-key-1", 12345)
}

fn measurement(root: &SoftwareTrustRoot) -> MeasurementDigest {
    root.measure(
        b"cell-code-v1",
        b"cell-config-v1",
        b"cell-policy-v1",
        b"evidence-schema-v1",
        "1.0.0",
    )
}

fn verifier() -> PolicyPlaneVerifier {
    PolicyPlaneVerifier::new(signing_key(), 1, epoch(42), "production")
}

fn client(cell_id: &str) -> CellHandshakeClient {
    let mut caps = BTreeSet::new();
    caps.insert("sign_receipts".to_string());
    caps.insert("emit_evidence".to_string());
    CellHandshakeClient {
        cell_id: cell_id.to_string(),
        cell_function: CellFunction::DecisionReceiptSigner,
        public_key: vec![1, 2, 3, 4, 5, 6, 7, 8],
        capabilities: caps,
    }
}

fn full_handshake(
    v: &mut PolicyPlaneVerifier,
    c: &CellHandshakeClient,
    root: &SoftwareTrustRoot,
    m: &MeasurementDigest,
    ts: u64,
) -> Result<CellAuthorization, HandshakeError> {
    let nonce = [42u8; 32];
    let challenge = v.generate_challenge(nonce, ts, 10_000_000)?;
    let response = c.respond(&challenge, m, root, 10_000_000, ts);
    v.verify_and_authorize(&challenge, &response, root, ts)
}

// ===========================================================================
// 1. HandshakeOutcome — Display exact values
// ===========================================================================

#[test]
fn handshake_outcome_display_exact() {
    assert_eq!(HandshakeOutcome::Authorized.to_string(), "authorized");
    assert_eq!(
        HandshakeOutcome::ChallengeTimeout.to_string(),
        "challenge-timeout"
    );
    assert_eq!(
        HandshakeOutcome::MeasurementRejected.to_string(),
        "measurement-rejected"
    );
    assert_eq!(HandshakeOutcome::QuoteFailed.to_string(), "quote-failed");
    assert_eq!(
        HandshakeOutcome::KeyBindingFailed.to_string(),
        "key-binding-failed"
    );
    assert_eq!(
        HandshakeOutcome::SignatureFailed.to_string(),
        "signature-failed"
    );
}

// ===========================================================================
// 2. Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_handshake_outcome() {
    let variants = [
        HandshakeOutcome::Authorized,
        HandshakeOutcome::ChallengeTimeout,
        HandshakeOutcome::MeasurementRejected,
        HandshakeOutcome::QuoteFailed,
        HandshakeOutcome::KeyBindingFailed,
        HandshakeOutcome::SignatureFailed,
    ];
    let strings: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(strings.len(), variants.len());
}

#[test]
fn debug_distinct_reattestation_trigger() {
    let variants = [
        ReattestationTrigger::Periodic,
        ReattestationTrigger::PolicyChange,
        ReattestationTrigger::EpochTransition,
        ReattestationTrigger::TrustRootUpdate,
        ReattestationTrigger::Manual,
    ];
    let strings: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(strings.len(), variants.len());
}

// ===========================================================================
// 3. HandshakeError — Display exact messages
// ===========================================================================

#[test]
fn error_display_challenge_expired() {
    let e = HandshakeError::ChallengeExpired {
        challenge_timestamp_ns: 100,
        deadline_ns: 50,
        current_ns: 200,
    };
    assert_eq!(
        e.to_string(),
        "challenge expired (current: 200, deadline: 50)"
    );
}

#[test]
fn error_display_challenge_signature_invalid() {
    assert_eq!(
        HandshakeError::ChallengeSignatureInvalid.to_string(),
        "challenge signature invalid"
    );
}

#[test]
fn error_display_measurement_not_approved() {
    let h = ContentHash::compute(b"test");
    let e = HandshakeError::MeasurementNotApproved {
        measurement_hash: h.clone(),
    };
    let s = e.to_string();
    assert!(s.starts_with("measurement not approved: "), "got: {s}");
}

#[test]
fn error_display_quote_verification_failed() {
    let e = HandshakeError::QuoteVerificationFailed {
        result: "expired cert".into(),
    };
    assert_eq!(e.to_string(), "quote verification failed: expired cert");
}

#[test]
fn error_display_nonce_mismatch() {
    assert_eq!(HandshakeError::NonceMismatch.to_string(), "nonce mismatch");
}

#[test]
fn error_display_key_binding_invalid() {
    assert_eq!(
        HandshakeError::KeyBindingInvalid.to_string(),
        "key binding proof invalid"
    );
}

#[test]
fn error_display_response_signature_invalid() {
    assert_eq!(
        HandshakeError::ResponseSignatureInvalid.to_string(),
        "response signature invalid"
    );
}

#[test]
fn error_display_authorization_expired() {
    let e = HandshakeError::AuthorizationExpired {
        issued_at_ns: 100,
        validity_window_ns: 50,
        current_ns: 200,
    };
    assert_eq!(e.to_string(), "authorization expired at 200");
}

#[test]
fn error_display_authorization_signature_invalid() {
    assert_eq!(
        HandshakeError::AuthorizationSignatureInvalid.to_string(),
        "authorization signature invalid"
    );
}

#[test]
fn error_display_operation_not_authorized() {
    let e = HandshakeError::OperationNotAuthorized {
        operation: "admin_delete".into(),
    };
    assert_eq!(e.to_string(), "operation not authorized: admin_delete");
}

#[test]
fn error_display_cell_not_found() {
    let e = HandshakeError::CellNotFound {
        cell_id: "cell-99".into(),
    };
    assert_eq!(e.to_string(), "cell not found: cell-99");
}

#[test]
fn error_display_reattestation_required() {
    let e = HandshakeError::ReattestationRequired {
        reason: "epoch change".into(),
    };
    assert_eq!(e.to_string(), "re-attestation required: epoch change");
}

#[test]
fn error_display_id_derivation() {
    let e = HandshakeError::IdDerivation("bad input".into());
    assert_eq!(e.to_string(), "id derivation: bad input");
}

// ===========================================================================
// 4. Serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_handshake_outcome() {
    assert_eq!(
        serde_json::to_string(&HandshakeOutcome::Authorized).unwrap(),
        "\"Authorized\""
    );
    assert_eq!(
        serde_json::to_string(&HandshakeOutcome::ChallengeTimeout).unwrap(),
        "\"ChallengeTimeout\""
    );
    assert_eq!(
        serde_json::to_string(&HandshakeOutcome::MeasurementRejected).unwrap(),
        "\"MeasurementRejected\""
    );
    assert_eq!(
        serde_json::to_string(&HandshakeOutcome::QuoteFailed).unwrap(),
        "\"QuoteFailed\""
    );
    assert_eq!(
        serde_json::to_string(&HandshakeOutcome::KeyBindingFailed).unwrap(),
        "\"KeyBindingFailed\""
    );
    assert_eq!(
        serde_json::to_string(&HandshakeOutcome::SignatureFailed).unwrap(),
        "\"SignatureFailed\""
    );
}

#[test]
fn serde_exact_reattestation_trigger() {
    assert_eq!(
        serde_json::to_string(&ReattestationTrigger::Periodic).unwrap(),
        "\"Periodic\""
    );
    assert_eq!(
        serde_json::to_string(&ReattestationTrigger::PolicyChange).unwrap(),
        "\"PolicyChange\""
    );
    assert_eq!(
        serde_json::to_string(&ReattestationTrigger::EpochTransition).unwrap(),
        "\"EpochTransition\""
    );
    assert_eq!(
        serde_json::to_string(&ReattestationTrigger::TrustRootUpdate).unwrap(),
        "\"TrustRootUpdate\""
    );
    assert_eq!(
        serde_json::to_string(&ReattestationTrigger::Manual).unwrap(),
        "\"Manual\""
    );
}

// ===========================================================================
// 5. JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_attestation_challenge() {
    let v = verifier();
    let c = v.generate_challenge([1u8; 32], 1000, 5000).unwrap();
    let json = serde_json::to_string(&c).unwrap();
    for field in [
        "challenge_id",
        "nonce",
        "approved_measurements",
        "policy_version",
        "challenge_timestamp_ns",
        "epoch",
        "response_deadline_ns",
        "policy_plane_signature",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_cell_authorization() {
    let mut v = verifier();
    let r = trust_root();
    let m = measurement(&r);
    v.approve_measurement(m.composite_hash());
    let c = client("cell-1");
    let auth = full_handshake(&mut v, &c, &r, &m, 1000).unwrap();
    let json = serde_json::to_string(&auth).unwrap();
    for field in [
        "authorization_id",
        "cell_id",
        "authorized_operations",
        "epoch",
        "issued_at_ns",
        "validity_window_ns",
        "policy_version",
        "verified_measurement",
        "authorization_signature",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_handshake_event() {
    let event = HandshakeEvent {
        seq: 0,
        timestamp_ns: 1000,
        epoch: epoch(1),
        cell_id: "c".into(),
        outcome: HandshakeOutcome::Authorized,
        measurement_hash: None,
        policy_version: 1,
        trust_level: None,
        failure_reason: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    for field in [
        "seq",
        "timestamp_ns",
        "epoch",
        "cell_id",
        "outcome",
        "measurement_hash",
        "policy_version",
        "trust_level",
        "failure_reason",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

// ===========================================================================
// 6. CellAuthorization.authorizes() edge cases
// ===========================================================================

#[test]
fn authorization_authorizes_claimed_ops() {
    let mut v = verifier();
    let r = trust_root();
    let m = measurement(&r);
    v.approve_measurement(m.composite_hash());
    let c = client("cell-1");
    let auth = full_handshake(&mut v, &c, &r, &m, 1000).unwrap();

    assert!(auth.authorizes("sign_receipts"));
    assert!(auth.authorizes("emit_evidence"));
    assert!(!auth.authorizes("admin_delete"));
    assert!(!auth.authorizes(""));
}

// ===========================================================================
// 7. check_authorization error paths
// ===========================================================================

#[test]
fn check_authorization_cell_not_found() {
    let v = verifier();
    match v.check_authorization("unknown-cell", "op", 1000) {
        Err(HandshakeError::CellNotFound { cell_id }) => {
            assert_eq!(cell_id, "unknown-cell");
        }
        other => panic!("expected CellNotFound, got {other:?}"),
    }
}

#[test]
fn check_authorization_expired() {
    let mut v = verifier();
    v.set_authorization_window(1000);
    let r = trust_root();
    let m = measurement(&r);
    v.approve_measurement(m.composite_hash());
    let c = client("cell-1");
    full_handshake(&mut v, &c, &r, &m, 1000).unwrap();

    // At t=2001, expired (1000 + 1000 = 2000)
    match v.check_authorization("cell-1", "sign_receipts", 2001) {
        Err(HandshakeError::AuthorizationExpired { .. }) => {}
        other => panic!("expected AuthorizationExpired, got {other:?}"),
    }
}

#[test]
fn check_authorization_operation_not_authorized() {
    let mut v = verifier();
    let r = trust_root();
    let m = measurement(&r);
    v.approve_measurement(m.composite_hash());
    let c = client("cell-1");
    full_handshake(&mut v, &c, &r, &m, 1000).unwrap();

    match v.check_authorization("cell-1", "admin_delete", 1000) {
        Err(HandshakeError::OperationNotAuthorized { operation }) => {
            assert_eq!(operation, "admin_delete");
        }
        other => panic!("expected OperationNotAuthorized, got {other:?}"),
    }
}

// ===========================================================================
// 8. revoke_authorization — false for unknown cell
// ===========================================================================

#[test]
fn revoke_unknown_cell_returns_false() {
    let mut v = verifier();
    assert!(!v.revoke_authorization("nonexistent"));
}

// ===========================================================================
// 9. revoke_all_authorizations on empty
// ===========================================================================

#[test]
fn revoke_all_empty_returns_zero() {
    let mut v = verifier();
    assert_eq!(v.revoke_all_authorizations(), 0);
}

// ===========================================================================
// 10. Challenge before issuance time is invalid
// ===========================================================================

#[test]
fn challenge_before_issuance_is_invalid() {
    let v = verifier();
    let challenge = v.generate_challenge([1u8; 32], 5000, 1000).unwrap();
    // Before issuance
    assert!(!challenge.is_valid_at(4999));
    // At issuance
    assert!(challenge.is_valid_at(5000));
}

// ===========================================================================
// 11. PolicyPlaneVerifier serde roundtrip
// ===========================================================================

#[test]
fn policy_plane_verifier_serde_roundtrip() {
    let mut v = verifier();
    let r = trust_root();
    let m = measurement(&r);
    v.approve_measurement(m.composite_hash());
    let c = client("cell-1");
    full_handshake(&mut v, &c, &r, &m, 1000).unwrap();

    let json = serde_json::to_string(&v).unwrap();
    let back: PolicyPlaneVerifier = serde_json::from_str(&json).unwrap();
    assert_eq!(back.authorization_count(), 1);
    assert_eq!(back.policy_version(), 1);
    assert_eq!(back.events().len(), 1);
}

// ===========================================================================
// 12. HandshakeEvent serde with success
// ===========================================================================

#[test]
fn handshake_event_success_serde_roundtrip() {
    let mut v = verifier();
    let r = trust_root();
    let m = measurement(&r);
    v.approve_measurement(m.composite_hash());
    let c = client("cell-1");
    full_handshake(&mut v, &c, &r, &m, 1000).unwrap();

    let event = &v.events()[0];
    let json = serde_json::to_string(event).unwrap();
    let back: HandshakeEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, *event);
    assert_eq!(back.outcome, HandshakeOutcome::Authorized);
    assert!(back.measurement_hash.is_some());
    assert!(back.trust_level.is_some());
    assert!(back.failure_reason.is_none());
}

// ===========================================================================
// 13. Challenge has approved measurements
// ===========================================================================

#[test]
fn challenge_carries_approved_measurements() {
    let mut v = verifier();
    let h1 = ContentHash::compute(b"measure-1");
    let h2 = ContentHash::compute(b"measure-2");
    v.approve_measurement(h1.clone());
    v.approve_measurement(h2.clone());

    let challenge = v.generate_challenge([1u8; 32], 1000, 5000).unwrap();
    assert!(challenge.approved_measurements.contains(&h1));
    assert!(challenge.approved_measurements.contains(&h2));
    assert_eq!(challenge.approved_measurements.len(), 2);
}

// ===========================================================================
// 14. Measurement not approved — handshake rejection
// ===========================================================================

#[test]
fn handshake_rejects_unapproved_measurement() {
    let mut v = verifier();
    // Don't approve any measurements
    let r = trust_root();
    let m = measurement(&r);
    let c = client("cell-1");

    match full_handshake(&mut v, &c, &r, &m, 1000) {
        Err(HandshakeError::MeasurementNotApproved { .. }) => {}
        other => panic!("expected MeasurementNotApproved, got {other:?}"),
    }
}

// ===========================================================================
// 15. Challenge expired — handshake rejection
// ===========================================================================

#[test]
fn handshake_rejects_expired_challenge() {
    let mut v = verifier();
    let r = trust_root();
    let m = measurement(&r);
    v.approve_measurement(m.composite_hash());
    let c = client("cell-1");

    let nonce = [42u8; 32];
    let challenge = v.generate_challenge(nonce, 1000, 500).unwrap();
    let response = c.respond(&challenge, &m, &r, 10_000_000, 2000);
    // current_ns=2000, deadline=1000+500=1500 → expired
    match v.verify_and_authorize(&challenge, &response, &r, 2000) {
        Err(HandshakeError::ChallengeExpired {
            current_ns: 2000, ..
        }) => {}
        other => panic!("expected ChallengeExpired, got {other:?}"),
    }
}

// ===========================================================================
// 16. Re-handshake replaces previous authorization
// ===========================================================================

#[test]
fn rehandshake_replaces_authorization() {
    let mut v = verifier();
    let r = trust_root();
    let m = measurement(&r);
    v.approve_measurement(m.composite_hash());
    let c = client("cell-1");

    let auth1 = full_handshake(&mut v, &c, &r, &m, 1000).unwrap();
    assert_eq!(v.authorization_count(), 1);

    let auth2 = full_handshake(&mut v, &c, &r, &m, 2000).unwrap();
    assert_eq!(v.authorization_count(), 1); // still 1, replaced

    // auth2 has later timestamp
    assert!(auth2.issued_at_ns > auth1.issued_at_ns);
}

// ===========================================================================
// 17. Event tracking — failure events have reason
// ===========================================================================

#[test]
fn failure_events_carry_reason() {
    let mut v = verifier();
    let r = trust_root();
    let m = measurement(&r);
    // No approved measurement → failure
    let c = client("cell-1");
    let _ = full_handshake(&mut v, &c, &r, &m, 1000);

    assert_eq!(v.events().len(), 1);
    let ev = &v.events()[0];
    assert_ne!(ev.outcome, HandshakeOutcome::Authorized);
    assert!(ev.failure_reason.is_some());
    assert!(!ev.failure_reason.as_ref().unwrap().is_empty());
}

// ===========================================================================
// 18. cells_needing_reattestation — empty when no authorizations
// ===========================================================================

#[test]
fn no_cells_needing_reattestation_when_empty() {
    let v = verifier();
    assert!(v.cells_needing_reattestation(999_999_999).is_empty());
}

// ===========================================================================
// 19. authorized_cells — empty initially
// ===========================================================================

#[test]
fn authorized_cells_empty_initially() {
    let v = verifier();
    assert!(v.authorized_cells().is_empty());
    assert_eq!(v.authorization_count(), 0);
}

// ===========================================================================
// 20. valid_authorizations_at — empty initially
// ===========================================================================

#[test]
fn valid_authorizations_at_empty_initially() {
    let v = verifier();
    assert!(v.valid_authorizations_at(0).is_empty());
}

// ===========================================================================
// 21. Nonce mismatch produces failure event
// ===========================================================================

#[test]
fn nonce_mismatch_rejection() {
    let mut v = verifier();
    let r = trust_root();
    let m = measurement(&r);
    v.approve_measurement(m.composite_hash());
    let c = client("cell-1");

    // Create challenge with one nonce
    let challenge = v.generate_challenge([1u8; 32], 1000, 10_000_000).unwrap();

    // Create a different challenge to get a response with different nonce
    let other_challenge = v.generate_challenge([2u8; 32], 1000, 10_000_000).unwrap();
    let response = c.respond(&other_challenge, &m, &r, 10_000_000, 1000);

    // Verify with mismatched nonce
    match v.verify_and_authorize(&challenge, &response, &r, 1000) {
        Err(HandshakeError::NonceMismatch) => {}
        other => panic!("expected NonceMismatch, got {other:?}"),
    }
}

// ===========================================================================
// 22. Serde roundtrip for ReattestationTrigger verified exact
// ===========================================================================

#[test]
fn reattestation_trigger_serde_exact_values() {
    // Already tested in existing tests but here we verify exact JSON strings
    assert_eq!(
        serde_json::to_string(&ReattestationTrigger::Periodic).unwrap(),
        "\"Periodic\""
    );
    assert_eq!(
        serde_json::to_string(&ReattestationTrigger::Manual).unwrap(),
        "\"Manual\""
    );
}

// ===========================================================================
// 23. CellHandshakeClient respond produces valid canonical bytes
// ===========================================================================

#[test]
fn client_response_has_nonempty_fields() {
    let r = trust_root();
    let m = measurement(&r);
    let c = client("cell-1");
    let v = verifier();
    let challenge = v.generate_challenge([1u8; 32], 1000, 10_000).unwrap();
    let response = c.respond(&challenge, &m, &r, 10_000, 1000);

    assert_eq!(response.cell_id, "cell-1");
    assert!(!response.signer_public_key.is_empty());
    assert!(!response.key_binding_proof.is_empty());
    assert!(!response.response_signature.is_empty());
    assert!(!response.canonical_bytes().is_empty());
    assert_eq!(response.response_timestamp_ns, 1000);
    assert_eq!(response.cell_function, CellFunction::DecisionReceiptSigner);
}

// ===========================================================================
// 24. Authorization canonical_bytes deterministic
// ===========================================================================

#[test]
fn authorization_canonical_bytes_deterministic() {
    let mut v = verifier();
    let r = trust_root();
    let m = measurement(&r);
    v.approve_measurement(m.composite_hash());
    let c = client("cell-1");
    let auth = full_handshake(&mut v, &c, &r, &m, 1000).unwrap();

    let bytes1 = auth.canonical_bytes();
    let bytes2 = auth.canonical_bytes();
    assert_eq!(bytes1, bytes2);
    assert!(!bytes1.is_empty());
}

// ===========================================================================
// 25. Challenge canonical_bytes deterministic
// ===========================================================================

#[test]
fn challenge_canonical_bytes_deterministic() {
    let v = verifier();
    let c1 = v.generate_challenge([1u8; 32], 1000, 5000).unwrap();
    let c2 = v.generate_challenge([1u8; 32], 1000, 5000).unwrap();
    assert_eq!(c1.canonical_bytes(), c2.canonical_bytes());
}

// ===========================================================================
// 26. Events carry epoch and policy_version
// ===========================================================================

#[test]
fn events_carry_epoch_and_policy_version() {
    let mut v = verifier();
    let r = trust_root();
    let m = measurement(&r);
    v.approve_measurement(m.composite_hash());
    let c = client("cell-1");
    full_handshake(&mut v, &c, &r, &m, 1000).unwrap();

    let ev = &v.events()[0];
    assert_eq!(ev.epoch, epoch(42));
    assert_eq!(ev.policy_version, 1);
    assert_eq!(ev.cell_id, "cell-1");
}
