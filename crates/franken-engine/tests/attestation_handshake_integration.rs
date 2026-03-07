//! Integration tests for the `attestation_handshake` module.
//!
//! Covers the full mutual attestation protocol, serde roundtrips for all
//! types, re-attestation lifecycle, multi-cell scenarios, and adversarial
//! rejection paths that complement the inline unit tests.

use std::collections::BTreeSet;

use frankenengine_engine::attestation_handshake::{
    AttestationChallenge, AttestationResponse, CellAuthorization, CellHandshakeClient,
    HandshakeError, HandshakeEvent, HandshakeOutcome, PolicyPlaneVerifier, ReattestationTrigger,
};
use frankenengine_engine::attested_execution_cell::{
    CellFunction, MeasurementDigest, SoftwareTrustRoot, TrustRootBackend,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn test_signing_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(13);
    }
    key
}

fn test_trust_root() -> SoftwareTrustRoot {
    SoftwareTrustRoot::new("test-key-1", 12345)
}

fn test_measurement(root: &SoftwareTrustRoot) -> MeasurementDigest {
    root.measure(
        b"cell-code-v1",
        b"cell-config-v1",
        b"cell-policy-v1",
        b"evidence-schema-v1",
        "1.0.0",
    )
}

fn test_verifier() -> PolicyPlaneVerifier {
    PolicyPlaneVerifier::new(test_signing_key(), 1, epoch(42), "production")
}

fn test_client(cell_id: &str) -> CellHandshakeClient {
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

fn do_full_handshake(
    verifier: &mut PolicyPlaneVerifier,
    client: &CellHandshakeClient,
    root: &SoftwareTrustRoot,
    measurement: &MeasurementDigest,
    timestamp_ns: u64,
) -> Result<CellAuthorization, HandshakeError> {
    let nonce = [42u8; 32];
    let challenge = verifier.generate_challenge(nonce, timestamp_ns, 10_000_000)?;
    let response = client.respond(&challenge, measurement, root, 10_000_000, timestamp_ns);
    verifier.verify_and_authorize(&challenge, &response, root, timestamp_ns)
}

// ---------------------------------------------------------------------------
// HandshakeError serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn handshake_error_serde_roundtrip_all_variants() {
    let errors = [
        HandshakeError::ChallengeExpired {
            challenge_timestamp_ns: 100,
            deadline_ns: 50,
            current_ns: 200,
        },
        HandshakeError::ChallengeSignatureInvalid,
        HandshakeError::MeasurementNotApproved {
            measurement_hash: ContentHash::compute(b"test"),
        },
        HandshakeError::QuoteVerificationFailed {
            result: "expired".to_string(),
        },
        HandshakeError::NonceMismatch,
        HandshakeError::KeyBindingInvalid,
        HandshakeError::ResponseSignatureInvalid,
        HandshakeError::AuthorizationExpired {
            issued_at_ns: 100,
            validity_window_ns: 50,
            current_ns: 200,
        },
        HandshakeError::AuthorizationSignatureInvalid,
        HandshakeError::OperationNotAuthorized {
            operation: "admin".to_string(),
        },
        HandshakeError::CellNotFound {
            cell_id: "cell-99".to_string(),
        },
        HandshakeError::ReattestationRequired {
            reason: "policy change".to_string(),
        },
        HandshakeError::IdDerivation("bad id".to_string()),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: HandshakeError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn handshake_error_implements_std_error() {
    let err = HandshakeError::NonceMismatch;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn handshake_error_display_all_non_empty() {
    let errors = [
        HandshakeError::ChallengeExpired {
            challenge_timestamp_ns: 1,
            deadline_ns: 2,
            current_ns: 3,
        },
        HandshakeError::ChallengeSignatureInvalid,
        HandshakeError::MeasurementNotApproved {
            measurement_hash: ContentHash::compute(b"x"),
        },
        HandshakeError::QuoteVerificationFailed { result: "r".into() },
        HandshakeError::NonceMismatch,
        HandshakeError::KeyBindingInvalid,
        HandshakeError::ResponseSignatureInvalid,
        HandshakeError::AuthorizationExpired {
            issued_at_ns: 1,
            validity_window_ns: 2,
            current_ns: 3,
        },
        HandshakeError::AuthorizationSignatureInvalid,
        HandshakeError::OperationNotAuthorized {
            operation: "op".into(),
        },
        HandshakeError::CellNotFound {
            cell_id: "c".into(),
        },
        HandshakeError::ReattestationRequired { reason: "r".into() },
        HandshakeError::IdDerivation("i".into()),
    ];
    for err in &errors {
        assert!(!err.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------------
// HandshakeOutcome serde
// ---------------------------------------------------------------------------

#[test]
fn handshake_outcome_serde_roundtrip_all_variants() {
    let outcomes = [
        HandshakeOutcome::Authorized,
        HandshakeOutcome::ChallengeTimeout,
        HandshakeOutcome::MeasurementRejected,
        HandshakeOutcome::QuoteFailed,
        HandshakeOutcome::KeyBindingFailed,
        HandshakeOutcome::SignatureFailed,
    ];
    for o in &outcomes {
        let json = serde_json::to_string(o).unwrap();
        let back: HandshakeOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, back);
    }
}

// ---------------------------------------------------------------------------
// ReattestationTrigger serde
// ---------------------------------------------------------------------------

#[test]
fn reattestation_trigger_serde_roundtrip_all_variants() {
    let triggers = [
        ReattestationTrigger::Periodic,
        ReattestationTrigger::PolicyChange,
        ReattestationTrigger::EpochTransition,
        ReattestationTrigger::TrustRootUpdate,
        ReattestationTrigger::Manual,
    ];
    for t in &triggers {
        let json = serde_json::to_string(t).unwrap();
        let back: ReattestationTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

#[test]
fn reattestation_trigger_display_all_variants() {
    assert_eq!(ReattestationTrigger::Periodic.to_string(), "periodic");
    assert_eq!(
        ReattestationTrigger::PolicyChange.to_string(),
        "policy-change"
    );
    assert_eq!(
        ReattestationTrigger::EpochTransition.to_string(),
        "epoch-transition"
    );
    assert_eq!(
        ReattestationTrigger::TrustRootUpdate.to_string(),
        "trust-root-update"
    );
    assert_eq!(ReattestationTrigger::Manual.to_string(), "manual");
}

// ---------------------------------------------------------------------------
// AttestationChallenge
// ---------------------------------------------------------------------------

#[test]
fn challenge_canonical_bytes_differ_with_different_nonces() {
    let verifier = test_verifier();
    let c1 = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
    let c2 = verifier.generate_challenge([2u8; 32], 1000, 500).unwrap();
    assert_ne!(c1.canonical_bytes(), c2.canonical_bytes());
}

#[test]
fn challenge_canonical_bytes_differ_with_different_timestamps() {
    let verifier = test_verifier();
    let c1 = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
    let c2 = verifier.generate_challenge([1u8; 32], 2000, 500).unwrap();
    assert_ne!(c1.canonical_bytes(), c2.canonical_bytes());
}

#[test]
fn challenge_is_valid_at_boundary() {
    let verifier = test_verifier();
    let challenge = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
    // Exactly at deadline: 1000 + 500 = 1500 → valid.
    assert!(challenge.is_valid_at(1500));
    // One past: 1501 → invalid.
    assert!(!challenge.is_valid_at(1501));
    // At issuance: valid.
    assert!(challenge.is_valid_at(1000));
}

#[test]
fn challenge_serde_roundtrip() {
    let verifier = test_verifier();
    let challenge = verifier.generate_challenge([0xAB; 32], 5000, 2000).unwrap();
    let json = serde_json::to_string(&challenge).unwrap();
    let back: AttestationChallenge = serde_json::from_str(&json).unwrap();
    assert_eq!(challenge, back);
}

// ---------------------------------------------------------------------------
// CellAuthorization
// ---------------------------------------------------------------------------

#[test]
fn authorization_canonical_bytes_differ_with_different_operations() {
    let mut verifier = test_verifier();
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let client1 = test_client("cell-001");
    let auth1 = do_full_handshake(&mut verifier, &client1, &root, &measurement, 1000).unwrap();

    let mut client2 = test_client("cell-002");
    client2.capabilities = ["different_op".to_string()].into_iter().collect();
    let auth2 = do_full_handshake(&mut verifier, &client2, &root, &measurement, 2000).unwrap();

    assert_ne!(auth1.canonical_bytes(), auth2.canonical_bytes());
}

#[test]
fn authorization_is_valid_at_boundary() {
    let mut verifier = test_verifier();
    verifier.set_authorization_window(1000);
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let client = test_client("cell-001");
    let auth = do_full_handshake(&mut verifier, &client, &root, &measurement, 5000).unwrap();

    assert!(auth.is_valid_at(5000));
    assert!(auth.is_valid_at(6000)); // 5000 + 1000 = 6000 → valid.
    assert!(!auth.is_valid_at(6001));
}

#[test]
fn authorization_serde_roundtrip() {
    let mut verifier = test_verifier();
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let client = test_client("cell-001");
    let auth = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

    let json = serde_json::to_string(&auth).unwrap();
    let back: CellAuthorization = serde_json::from_str(&json).unwrap();
    assert_eq!(auth, back);
}

// ---------------------------------------------------------------------------
// Multi-cell handshake
// ---------------------------------------------------------------------------

#[test]
fn multiple_cells_authorized_independently() {
    let mut verifier = test_verifier();
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let client1 = test_client("cell-001");
    let client2 = test_client("cell-002");
    let client3 = test_client("cell-003");

    do_full_handshake(&mut verifier, &client1, &root, &measurement, 1000).unwrap();
    do_full_handshake(&mut verifier, &client2, &root, &measurement, 2000).unwrap();
    do_full_handshake(&mut verifier, &client3, &root, &measurement, 3000).unwrap();

    assert_eq!(verifier.authorization_count(), 3);

    let cells = verifier.authorized_cells();
    assert_eq!(cells.len(), 3);
    assert!(cells.contains(&"cell-001"));
    assert!(cells.contains(&"cell-002"));
    assert!(cells.contains(&"cell-003"));
}

#[test]
fn revoke_one_cell_leaves_others() {
    let mut verifier = test_verifier();
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let client1 = test_client("cell-001");
    let client2 = test_client("cell-002");

    do_full_handshake(&mut verifier, &client1, &root, &measurement, 1000).unwrap();
    do_full_handshake(&mut verifier, &client2, &root, &measurement, 2000).unwrap();

    assert!(verifier.revoke_authorization("cell-001"));
    assert_eq!(verifier.authorization_count(), 1);
    assert!(
        verifier
            .check_authorization("cell-002", "sign_receipts", 3000)
            .is_ok()
    );
    assert!(
        verifier
            .check_authorization("cell-001", "sign_receipts", 3000)
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// Full lifecycle: challenge → authorize → expire → reattestation
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_with_reattestation() {
    let mut verifier = test_verifier();
    verifier.set_authorization_window(5000);
    verifier.set_reattestation_interval(3000);
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let client = test_client("cell-001");

    // Initial handshake at t=1000.
    do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

    // At t=2000, no reattestation needed.
    assert!(verifier.cells_needing_reattestation(2000).is_empty());

    // At t=4000, reattestation needed (age=3000 >= interval=3000).
    let needing = verifier.cells_needing_reattestation(4000);
    assert_eq!(needing.len(), 1);
    assert_eq!(needing[0], "cell-001");

    // Re-handshake at t=4000.
    do_full_handshake(&mut verifier, &client, &root, &measurement, 4000).unwrap();

    // Authorization refreshed, not needing reattestation at t=5000.
    assert!(verifier.cells_needing_reattestation(5000).is_empty());

    // At t=7000, needs again (age=3000 >= interval=3000).
    assert_eq!(verifier.cells_needing_reattestation(7000).len(), 1);

    // Events: 2 successful handshakes.
    let success_events: Vec<_> = verifier
        .events()
        .iter()
        .filter(|e| e.outcome == HandshakeOutcome::Authorized)
        .collect();
    assert_eq!(success_events.len(), 2);
}

// ---------------------------------------------------------------------------
// Policy version and epoch management
// ---------------------------------------------------------------------------

#[test]
fn bump_policy_version_increments() {
    let mut verifier = test_verifier();
    assert_eq!(verifier.policy_version(), 1);
    assert_eq!(verifier.bump_policy_version(), 2);
    assert_eq!(verifier.bump_policy_version(), 3);
    assert_eq!(verifier.policy_version(), 3);
}

#[test]
fn advance_epoch_updates_verifier() {
    let mut verifier = test_verifier();
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let client = test_client("cell-001");
    do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

    // Advance epoch.
    verifier.advance_epoch(epoch(43));

    // New challenge should use the new epoch.
    let challenge = verifier.generate_challenge([1u8; 32], 2000, 1000).unwrap();
    assert_eq!(challenge.epoch, epoch(43));
}

// ---------------------------------------------------------------------------
// valid_authorizations_at
// ---------------------------------------------------------------------------

#[test]
fn valid_authorizations_at_filters_by_time() {
    let mut verifier = test_verifier();
    verifier.set_authorization_window(1000);
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let client1 = test_client("cell-001");
    let client2 = test_client("cell-002");

    do_full_handshake(&mut verifier, &client1, &root, &measurement, 1000).unwrap();
    do_full_handshake(&mut verifier, &client2, &root, &measurement, 1500).unwrap();

    // At t=1800, both valid.
    assert_eq!(verifier.valid_authorizations_at(1800).len(), 2);

    // At t=2100, cell-001 expired (1000+1000=2000), cell-002 still valid.
    assert_eq!(verifier.valid_authorizations_at(2100).len(), 1);

    // At t=2600, both expired.
    assert_eq!(verifier.valid_authorizations_at(2600).len(), 0);
}

// ---------------------------------------------------------------------------
// Event tracking
// ---------------------------------------------------------------------------

#[test]
fn events_track_both_successes_and_failures() {
    let mut verifier = test_verifier();
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    // No approved measurements → failure.

    let client = test_client("cell-001");
    let _ = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000);
    assert_eq!(verifier.events().len(), 1);
    assert_eq!(
        verifier.events()[0].outcome,
        HandshakeOutcome::MeasurementRejected
    );
    assert!(verifier.events()[0].failure_reason.is_some());

    // Now approve and retry.
    verifier.approve_measurement(measurement.composite_hash());
    do_full_handshake(&mut verifier, &client, &root, &measurement, 2000).unwrap();
    assert_eq!(verifier.events().len(), 2);
    assert_eq!(verifier.events()[1].outcome, HandshakeOutcome::Authorized);
    assert!(verifier.events()[1].failure_reason.is_none());
}

#[test]
fn event_sequence_numbers_are_monotonic() {
    let mut verifier = test_verifier();
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    for i in 0..5u64 {
        let client = test_client(&format!("cell-{i:03}"));
        do_full_handshake(&mut verifier, &client, &root, &measurement, 1000 + i * 1000).unwrap();
    }

    let events = verifier.events();
    assert_eq!(events.len(), 5);
    for (i, event) in events.iter().enumerate() {
        assert_eq!(event.seq, i as u64);
    }
}

// ---------------------------------------------------------------------------
// HandshakeEvent serde
// ---------------------------------------------------------------------------

#[test]
fn handshake_event_with_failure_serde_roundtrip() {
    let event = HandshakeEvent {
        seq: 3,
        timestamp_ns: 5000,
        epoch: epoch(42),
        cell_id: "cell-001".to_string(),
        outcome: HandshakeOutcome::MeasurementRejected,
        measurement_hash: Some(ContentHash::compute(b"bad-measurement")),
        policy_version: 2,
        trust_level: None,
        failure_reason: Some("measurement not in approved set".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: HandshakeEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ---------------------------------------------------------------------------
// AttestationResponse serde
// ---------------------------------------------------------------------------

#[test]
fn attestation_response_serde_roundtrip() {
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    let client = test_client("cell-001");
    let verifier = test_verifier();
    let challenge = verifier
        .generate_challenge([1u8; 32], 1000, 10_000)
        .unwrap();
    let response = client.respond(&challenge, &measurement, &root, 10_000, 1000);

    let json = serde_json::to_string(&response).unwrap();
    let back: AttestationResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, back);
}

#[test]
fn attestation_response_canonical_bytes_deterministic() {
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    let client = test_client("cell-001");
    let verifier = test_verifier();
    let challenge = verifier
        .generate_challenge([1u8; 32], 1000, 10_000)
        .unwrap();
    let r1 = client.respond(&challenge, &measurement, &root, 10_000, 1000);
    let r2 = client.respond(&challenge, &measurement, &root, 10_000, 1000);
    assert_eq!(r1.canonical_bytes(), r2.canonical_bytes());
}

// ---------------------------------------------------------------------------
// Stress test
// ---------------------------------------------------------------------------

#[test]
fn stress_many_cells_handshake_and_reattestation() {
    let mut verifier = test_verifier();
    verifier.set_reattestation_interval(5000);
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let n = 20;
    for i in 0..n {
        let client = test_client(&format!("cell-{i:03}"));
        do_full_handshake(&mut verifier, &client, &root, &measurement, 1000 + i * 100).unwrap();
    }

    assert_eq!(verifier.authorization_count(), n as usize);
    assert_eq!(verifier.events().len(), n as usize);

    // At t=8000, all cells have age >= 5000 (latest: t=2900, age=5100).
    let needing = verifier.cells_needing_reattestation(8000);
    assert_eq!(needing.len(), n as usize);

    // Revoke all.
    let revoked = verifier.revoke_all_authorizations();
    assert_eq!(revoked, n as usize);
    assert_eq!(verifier.authorization_count(), 0);
}

// ---------------------------------------------------------------------------
// Approved measurement management
// ---------------------------------------------------------------------------

#[test]
fn approve_multiple_measurements() {
    let mut verifier = test_verifier();
    let root = test_trust_root();

    let m1 = root.measure(
        b"code-v1",
        b"config-v1",
        b"policy-v1",
        b"schema-v1",
        "1.0.0",
    );
    let m2 = root.measure(
        b"code-v2",
        b"config-v2",
        b"policy-v2",
        b"schema-v2",
        "2.0.0",
    );

    verifier.approve_measurement(m1.composite_hash());
    verifier.approve_measurement(m2.composite_hash());

    // Both measurements should be accepted.
    let client = test_client("cell-001");
    do_full_handshake(&mut verifier, &client, &root, &m1, 1000).unwrap();

    let client2 = test_client("cell-002");
    do_full_handshake(&mut verifier, &client2, &root, &m2, 2000).unwrap();

    assert_eq!(verifier.authorization_count(), 2);
}

// ---------------------------------------------------------------------------
// Authorization operations check
// ---------------------------------------------------------------------------

#[test]
fn authorization_authorizes_claimed_capabilities() {
    let mut verifier = test_verifier();
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let client = test_client("cell-001");
    let auth = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

    assert!(auth.authorizes("sign_receipts"));
    assert!(auth.authorizes("emit_evidence"));
    assert!(!auth.authorizes("admin_override"));
}

#[test]
fn check_authorization_rejects_unauthorized_operation() {
    let mut verifier = test_verifier();
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let client = test_client("cell-001");
    do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

    let err = verifier
        .check_authorization("cell-001", "admin_override", 1000)
        .expect_err("should reject");
    assert!(matches!(err, HandshakeError::OperationNotAuthorized { .. }));
}

#[test]
fn check_authorization_rejects_unknown_cell() {
    let verifier = test_verifier();
    let err = verifier
        .check_authorization("nonexistent-cell", "sign_receipts", 1000)
        .expect_err("should fail");
    assert!(matches!(err, HandshakeError::CellNotFound { .. }));
}

#[test]
fn check_authorization_rejects_expired_authorization() {
    let mut verifier = test_verifier();
    verifier.set_authorization_window(500);
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let client = test_client("cell-001");
    do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

    let err = verifier
        .check_authorization("cell-001", "sign_receipts", 2000)
        .expect_err("should be expired");
    assert!(matches!(err, HandshakeError::AuthorizationExpired { .. }));
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

#[test]
fn revoke_nonexistent_cell_returns_false() {
    let mut verifier = test_verifier();
    assert!(!verifier.revoke_authorization("no-such-cell"));
}

#[test]
fn revoke_all_on_empty_returns_zero() {
    let mut verifier = test_verifier();
    assert_eq!(verifier.revoke_all_authorizations(), 0);
}

// ---------------------------------------------------------------------------
// Handshake failure: unapproved measurement
// ---------------------------------------------------------------------------

#[test]
fn handshake_fails_for_unapproved_measurement() {
    let mut verifier = test_verifier();
    // Don't approve any measurements
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    let client = test_client("cell-001");

    let err = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000)
        .expect_err("should reject");
    assert!(matches!(err, HandshakeError::MeasurementNotApproved { .. }));
}

#[test]
fn handshake_rejects_tampered_challenge_signature() {
    let mut verifier = test_verifier();
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let mut challenge = verifier
        .generate_challenge([1u8; 32], 1000, 10_000)
        .expect("challenge");
    challenge.policy_plane_signature = vec![0xCA, 0xFE];

    let client = test_client("cell-001");
    let response = client.respond(&challenge, &measurement, &root, 10_000, 1000);

    let err = verifier
        .verify_and_authorize(&challenge, &response, &root, 1000)
        .expect_err("tampered challenge should be rejected");
    assert!(matches!(err, HandshakeError::ChallengeSignatureInvalid));
}

#[test]
fn handshake_rejects_tampered_quote_after_response_signing() {
    let mut verifier = test_verifier();
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let challenge = verifier
        .generate_challenge([1u8; 32], 1000, 10_000)
        .expect("challenge");
    let client = test_client("cell-001");
    let mut response = client.respond(&challenge, &measurement, &root, 10_000, 1000);
    response.attestation_quote.issued_at_ns = 999;

    let err = verifier
        .verify_and_authorize(&challenge, &response, &root, 1000)
        .expect_err("tampered quote should break the response signature");
    assert!(matches!(err, HandshakeError::ResponseSignatureInvalid));
}

#[test]
fn authorization_tampering_is_rejected() {
    let mut verifier = test_verifier();
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let client = test_client("cell-001");
    do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).expect("handshake");

    let mut verifier_json = serde_json::to_value(&verifier).expect("serialize verifier");
    verifier_json["active_authorizations"]["cell-001"]["authorized_operations"]
        .as_array_mut()
        .expect("authorization operations array")
        .push(serde_json::Value::String("admin_override".to_string()));

    let tampered_verifier: PolicyPlaneVerifier =
        serde_json::from_value(verifier_json).expect("deserialize tampered verifier");
    let err = tampered_verifier
        .check_authorization("cell-001", "admin_override", 2000)
        .expect_err("tampered authorization should be rejected");
    assert!(matches!(err, HandshakeError::AuthorizationSignatureInvalid));
}

// ---------------------------------------------------------------------------
// HandshakeOutcome display
// ---------------------------------------------------------------------------

#[test]
fn handshake_outcome_display_all_non_empty() {
    for outcome in [
        HandshakeOutcome::Authorized,
        HandshakeOutcome::ChallengeTimeout,
        HandshakeOutcome::MeasurementRejected,
        HandshakeOutcome::QuoteFailed,
        HandshakeOutcome::KeyBindingFailed,
        HandshakeOutcome::SignatureFailed,
    ] {
        assert!(!outcome.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Challenge determinism
// ---------------------------------------------------------------------------

#[test]
fn challenge_canonical_bytes_deterministic() {
    let verifier = test_verifier();
    let c1 = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
    let c2 = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
    assert_eq!(c1.canonical_bytes(), c2.canonical_bytes());
}

// ---------------------------------------------------------------------------
// CellAuthorization canonical bytes
// ---------------------------------------------------------------------------

#[test]
fn authorization_canonical_bytes_deterministic() {
    let mut verifier = test_verifier();
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let client = test_client("cell-001");
    let auth1 = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();
    let bytes1 = auth1.canonical_bytes();

    // Re-handshake same cell overwrites authorization
    let auth2 = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();
    let bytes2 = auth2.canonical_bytes();

    // Same inputs should produce same canonical bytes
    assert_eq!(bytes1, bytes2);
}

// ---------------------------------------------------------------------------
// Event HandshakeEvent serde with success
// ---------------------------------------------------------------------------

#[test]
fn handshake_event_success_serde_roundtrip() {
    let mut verifier = test_verifier();
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let client = test_client("cell-001");
    do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

    let event = &verifier.events()[0];
    let json = serde_json::to_string(event).expect("serialize");
    let recovered: HandshakeEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(*event, recovered);
    assert_eq!(event.outcome, HandshakeOutcome::Authorized);
}

// ---------------------------------------------------------------------------
// Verifier serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn verifier_serde_roundtrip() {
    let mut verifier = test_verifier();
    let root = test_trust_root();
    let measurement = test_measurement(&root);
    verifier.approve_measurement(measurement.composite_hash());

    let client = test_client("cell-001");
    do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

    let json = serde_json::to_string(&verifier).expect("serialize");
    let recovered: PolicyPlaneVerifier = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.authorization_count(), 1);
    assert_eq!(recovered.policy_version(), verifier.policy_version());
}

// ---------------------------------------------------------------------------
// ReattestationTrigger serde (additional)
// ---------------------------------------------------------------------------

#[test]
fn reattestation_trigger_debug_distinct() {
    let triggers = [
        ReattestationTrigger::Periodic,
        ReattestationTrigger::PolicyChange,
        ReattestationTrigger::EpochTransition,
        ReattestationTrigger::TrustRootUpdate,
        ReattestationTrigger::Manual,
    ];
    let debug_strs: std::collections::BTreeSet<_> =
        triggers.iter().map(|t| format!("{t:?}")).collect();
    assert_eq!(debug_strs.len(), 5);
}
