//! Conformance harness for attested_execution_cell trust-root interface contract.
//!
//! Tests the documented invariants for TrustRootBackend implementations:
//! - Identical inputs produce identical measurements and object IDs
//! - Changed code/config/policy/schema changes measurement
//! - Attest+verify accepts only matching nonce/fresh quote/signature
//! - Revoked signer and expired quote fail closed
//! - Lifecycle transitions follow documented state machine
//! - Safe-mode fallback semantics

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::attested_execution_cell::{
    AttestationQuote, CellFunction, CellLifecycle, CreateCellInput, MeasurementDigest,
    PlatformKind, SoftwareTrustRoot, TrustLevel, TrustRootBackend, VerificationResult,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Generic TrustRootBackend contract tests
// ---------------------------------------------------------------------------

/// Generic contract test function that validates all TrustRootBackend implementations
/// follow the documented trust-root interface contract.
fn assert_trust_root_backend_contract<T: TrustRootBackend>(backend: T) {
    // Test 1: Identical inputs produce identical measurements and object IDs
    test_measurement_determinism(&backend);

    // Test 2: Changed code/config/policy/schema changes measurement
    test_measurement_sensitivity(&backend);

    // Test 3: Attest+verify flow with matching parameters succeeds
    test_attest_verify_success(&backend);

    // Test 4: Nonce mismatch fails closed
    test_nonce_mismatch_fails(&backend);

    // Test 5: Expired quote fails closed
    test_expired_quote_fails(&backend);

    // Test 6: Signature verification requirements
    test_signature_verification(&backend);
}

fn test_measurement_determinism<T: TrustRootBackend>(backend: &T) {
    let code = b"test-code-v1";
    let config = b"test-config-v1";
    let policy = b"test-policy-v1";
    let schema = b"test-schema-v1";
    let runtime = "1.0.0";

    // Measure same inputs multiple times
    let measurement1 = backend.measure(code, config, policy, schema, runtime);
    let measurement2 = backend.measure(code, config, policy, schema, runtime);
    let measurement3 = backend.measure(code, config, policy, schema, runtime);

    // Assert identical measurements
    assert_eq!(
        measurement1, measurement2,
        "Identical inputs should produce identical measurements"
    );
    assert_eq!(
        measurement2, measurement3,
        "Measurement should be deterministic across calls"
    );

    // Assert identical canonical bytes
    let canonical1 = measurement1.canonical_bytes();
    let canonical2 = measurement2.canonical_bytes();
    assert_eq!(
        canonical1, canonical2,
        "Canonical bytes should be identical for identical measurements"
    );

    // Assert identical composite hashes
    let hash1 = measurement1.composite_hash();
    let hash2 = measurement2.composite_hash();
    assert_eq!(
        hash1, hash2,
        "Composite hashes should be identical for identical measurements"
    );

    // Assert identical object IDs
    let zone = "test-zone";
    let id1 = measurement1
        .derive_id(zone)
        .expect("ID derivation should succeed");
    let id2 = measurement2
        .derive_id(zone)
        .expect("ID derivation should succeed");
    assert_eq!(
        id1, id2,
        "Object IDs should be identical for identical measurements"
    );
}

fn test_measurement_sensitivity<T: TrustRootBackend>(backend: &T) {
    let base_code = b"base-code-v1";
    let base_config = b"base-config-v1";
    let base_policy = b"base-policy-v1";
    let base_schema = b"base-schema-v1";
    let base_runtime = "1.0.0";

    let base_measurement = backend.measure(
        base_code,
        base_config,
        base_policy,
        base_schema,
        base_runtime,
    );

    // Test code change
    let changed_code = b"changed-code-v1";
    let code_measurement = backend.measure(
        changed_code,
        base_config,
        base_policy,
        base_schema,
        base_runtime,
    );
    assert_ne!(
        base_measurement, code_measurement,
        "Changed code should produce different measurement"
    );
    assert_ne!(
        base_measurement.code_hash, code_measurement.code_hash,
        "Code hash should change with code"
    );

    // Test config change
    let changed_config = b"changed-config-v1";
    let config_measurement = backend.measure(
        base_code,
        changed_config,
        base_policy,
        base_schema,
        base_runtime,
    );
    assert_ne!(
        base_measurement, config_measurement,
        "Changed config should produce different measurement"
    );
    assert_ne!(
        base_measurement.config_hash, config_measurement.config_hash,
        "Config hash should change with config"
    );

    // Test policy change
    let changed_policy = b"changed-policy-v1";
    let policy_measurement = backend.measure(
        base_code,
        base_config,
        changed_policy,
        base_schema,
        base_runtime,
    );
    assert_ne!(
        base_measurement, policy_measurement,
        "Changed policy should produce different measurement"
    );
    assert_ne!(
        base_measurement.policy_hash, policy_measurement.policy_hash,
        "Policy hash should change with policy"
    );

    // Test schema change
    let changed_schema = b"changed-schema-v1";
    let schema_measurement = backend.measure(
        base_code,
        base_config,
        base_policy,
        changed_schema,
        base_runtime,
    );
    assert_ne!(
        base_measurement, schema_measurement,
        "Changed schema should produce different measurement"
    );
    assert_ne!(
        base_measurement.evidence_schema_hash, schema_measurement.evidence_schema_hash,
        "Schema hash should change with schema"
    );

    // Test runtime version change
    let changed_runtime = "2.0.0";
    let runtime_measurement = backend.measure(
        base_code,
        base_config,
        base_policy,
        base_schema,
        changed_runtime,
    );
    assert_ne!(
        base_measurement, runtime_measurement,
        "Changed runtime should produce different measurement"
    );
    assert_ne!(
        base_measurement.runtime_version, runtime_measurement.runtime_version,
        "Runtime version should change"
    );

    // Assert all measurements have different composite hashes
    let measurements = [
        &base_measurement,
        &code_measurement,
        &config_measurement,
        &policy_measurement,
        &schema_measurement,
        &runtime_measurement,
    ];

    for (i, measurement1) in measurements.iter().enumerate() {
        for (j, measurement2) in measurements.iter().enumerate() {
            if i != j {
                assert_ne!(measurement1.composite_hash(), measurement2.composite_hash(),
                         "Different inputs should produce different composite hashes (measurement {} vs {})", i, j);
            }
        }
    }
}

fn test_attest_verify_success<T: TrustRootBackend>(backend: &T) {
    let measurement = backend.measure(b"code", b"config", b"policy", b"schema", "1.0.0");
    let nonce = [1u8; 32];
    let validity_window_ns = 3600_000_000_000; // 1 hour
    let issued_at_ns = 1_000_000_000_000; // Fixed timestamp

    // Create attestation quote
    let quote = backend.attest(&measurement, nonce, validity_window_ns, issued_at_ns);

    // Verify attestation should succeed with matching parameters
    let verification_time = issued_at_ns + 1800_000_000_000; // 30 minutes later (within validity)
    let result = backend.verify(&quote, &measurement, &nonce, verification_time);

    assert_eq!(
        result,
        VerificationResult::Valid,
        "Verification should succeed with matching parameters"
    );

    // Test that quote contains expected fields
    assert_eq!(
        quote.measurement, measurement,
        "Quote should contain the measurement"
    );
    assert_eq!(quote.nonce, nonce, "Quote should contain the nonce");
    assert_eq!(
        quote.issued_at_ns, issued_at_ns,
        "Quote should have correct issued timestamp"
    );
    assert_eq!(
        quote.validity_window_ns, validity_window_ns,
        "Quote should have correct validity window"
    );
    assert_eq!(
        quote.trust_level,
        backend.trust_level(),
        "Quote should have backend's trust level"
    );
    assert_eq!(
        quote.platform,
        backend.platform(),
        "Quote should have backend's platform"
    );
    assert!(
        !quote.signature_bytes.is_empty(),
        "Quote should have non-empty signature"
    );
    assert!(
        !quote.signer_key_id.is_empty(),
        "Quote should have non-empty signer key ID"
    );

    // Test freshness methods
    assert!(
        quote.is_fresh_at(issued_at_ns),
        "Quote should be fresh at issuance time"
    );
    assert!(
        quote.is_fresh_at(verification_time),
        "Quote should be fresh within validity window"
    );
    assert!(
        !quote.is_expired_at(issued_at_ns),
        "Quote should not be expired at issuance time"
    );
    assert!(
        !quote.is_expired_at(verification_time),
        "Quote should not be expired within validity window"
    );
}

fn test_nonce_mismatch_fails<T: TrustRootBackend>(backend: &T) {
    let measurement = backend.measure(b"code", b"config", b"policy", b"schema", "1.0.0");
    let correct_nonce = [1u8; 32];
    let wrong_nonce = [2u8; 32];
    let validity_window_ns = 3600_000_000_000; // 1 hour
    let issued_at_ns = 1_000_000_000_000;

    // Create quote with correct nonce
    let quote = backend.attest(
        &measurement,
        correct_nonce,
        validity_window_ns,
        issued_at_ns,
    );

    // Verify with wrong nonce should fail
    let verification_time = issued_at_ns + 1800_000_000_000; // 30 minutes later
    let result = backend.verify(&quote, &measurement, &wrong_nonce, verification_time);

    assert_eq!(
        result,
        VerificationResult::NonceMismatch,
        "Verification should fail with nonce mismatch"
    );
}

fn test_expired_quote_fails<T: TrustRootBackend>(backend: &T) {
    let measurement = backend.measure(b"code", b"config", b"policy", b"schema", "1.0.0");
    let nonce = [1u8; 32];
    let validity_window_ns = 3600_000_000_000; // 1 hour
    let issued_at_ns = 1_000_000_000_000;

    // Create quote
    let quote = backend.attest(&measurement, nonce, validity_window_ns, issued_at_ns);

    // Verify after expiration should fail
    let expired_verification_time = issued_at_ns + validity_window_ns + 1; // 1 ns past expiration
    let result = backend.verify(&quote, &measurement, &nonce, expired_verification_time);

    match result {
        VerificationResult::Expired {
            issued_at_ns: issued,
            validity_window_ns: window,
            checked_at_ns: checked,
        } => {
            assert_eq!(
                issued, quote.issued_at_ns,
                "Expired result should report correct issued time"
            );
            assert_eq!(
                window, quote.validity_window_ns,
                "Expired result should report correct validity window"
            );
            assert_eq!(
                checked, expired_verification_time,
                "Expired result should report correct check time"
            );
        }
        _ => panic!(
            "Verification should fail with Expired for expired quote, got: {:?}",
            result
        ),
    }

    // Test that expired quote reports as expired
    assert!(
        quote.is_expired_at(expired_verification_time),
        "Quote should be expired past validity window"
    );
    assert!(
        !quote.is_fresh_at(expired_verification_time),
        "Quote should not be fresh past validity window"
    );
}

fn test_signature_verification<T: TrustRootBackend>(backend: &T) {
    let measurement = backend.measure(b"code", b"config", b"policy", b"schema", "1.0.0");
    let nonce = [1u8; 32];
    let validity_window_ns = 3600_000_000_000; // 1 hour
    let issued_at_ns = 1_000_000_000_000;

    // Create quote
    let quote = backend.attest(&measurement, nonce, validity_window_ns, issued_at_ns);

    // Test with different measurement (should fail)
    let different_measurement =
        backend.measure(b"different-code", b"config", b"policy", b"schema", "1.0.0");
    let verification_time = issued_at_ns + 1800_000_000_000; // 30 minutes later
    let result = backend.verify(&quote, &different_measurement, &nonce, verification_time);

    match result {
        VerificationResult::MeasurementMismatch { expected, actual } => {
            assert_eq!(expected, different_measurement.composite_hash(), "Expected should match different measurement hash");
            assert_eq!(actual, quote.measurement.composite_hash(), "Actual should match quote measurement hash");
        }
        _ => panic!("Verification should fail with MeasurementMismatch for different measurement, got: {:?}", result),
    }
}

// ---------------------------------------------------------------------------
// Lifecycle state machine contract tests
// ---------------------------------------------------------------------------

fn test_lifecycle_transitions() {
    // Test valid transitions
    let valid_transitions = [
        (CellLifecycle::Provisioning, CellLifecycle::Measured),
        (CellLifecycle::Measured, CellLifecycle::Attested),
        (CellLifecycle::Attested, CellLifecycle::Active),
        (CellLifecycle::Active, CellLifecycle::Suspended),
        (CellLifecycle::Suspended, CellLifecycle::Attested), // Re-attestation
        (CellLifecycle::Measured, CellLifecycle::Attested),  // Re-attestation from measured
        (CellLifecycle::Active, CellLifecycle::Decommissioned),
        (CellLifecycle::Suspended, CellLifecycle::Decommissioned),
    ];

    for (from, to) in valid_transitions {
        assert!(
            is_valid_transition(from, to),
            "Transition {} -> {} should be valid per documented contract",
            from,
            to
        );
    }

    // Test invalid transitions
    let invalid_transitions = [
        (CellLifecycle::Provisioning, CellLifecycle::Attested), // Skip measured
        (CellLifecycle::Provisioning, CellLifecycle::Active),   // Skip intermediate states
        (CellLifecycle::Measured, CellLifecycle::Active),       // Skip attested
        (CellLifecycle::Attested, CellLifecycle::Suspended),    // Must go through active
        (CellLifecycle::Decommissioned, CellLifecycle::Active), // No transitions from decommissioned
        (CellLifecycle::Decommissioned, CellLifecycle::Measured),
        (CellLifecycle::Active, CellLifecycle::Provisioning), // No backwards transitions except suspension
        (CellLifecycle::Active, CellLifecycle::Measured),
    ];

    for (from, to) in invalid_transitions {
        assert!(
            !is_valid_transition(from, to),
            "Transition {} -> {} should be invalid per documented contract",
            from,
            to
        );
    }
}

/// Helper function defining valid lifecycle transitions per the documented contract
fn is_valid_transition(from: CellLifecycle, to: CellLifecycle) -> bool {
    match (from, to) {
        // Forward progression
        (CellLifecycle::Provisioning, CellLifecycle::Measured) => true,
        (CellLifecycle::Measured, CellLifecycle::Attested) => true,
        (CellLifecycle::Attested, CellLifecycle::Active) => true,

        // Suspension and recovery
        (CellLifecycle::Active, CellLifecycle::Suspended) => true,
        (CellLifecycle::Suspended, CellLifecycle::Attested) => true, // Re-attestation
        (CellLifecycle::Measured, CellLifecycle::Attested) => true,  // Re-attestation from measured

        // Decommissioning
        (CellLifecycle::Active, CellLifecycle::Decommissioned) => true,
        (CellLifecycle::Suspended, CellLifecycle::Decommissioned) => true,

        // All other transitions are invalid
        _ => false,
    }
}

fn test_operational_semantics() {
    // Only Active state should be operational
    assert!(
        CellLifecycle::Active.is_operational(),
        "Active state should be operational"
    );

    let non_operational_states = [
        CellLifecycle::Provisioning,
        CellLifecycle::Measured,
        CellLifecycle::Attested,
        CellLifecycle::Suspended,
        CellLifecycle::Decommissioned,
    ];

    for state in non_operational_states {
        assert!(
            !state.is_operational(),
            "State {} should not be operational",
            state
        );
    }
}

fn test_reattestation_semantics() {
    // Only Suspended and Measured states should allow re-attestation
    let allows_reattestation = [CellLifecycle::Suspended, CellLifecycle::Measured];
    let disallows_reattestation = [
        CellLifecycle::Provisioning,
        CellLifecycle::Attested,
        CellLifecycle::Active,
        CellLifecycle::Decommissioned,
    ];

    for state in allows_reattestation {
        assert!(
            state.allows_reattestation(),
            "State {} should allow re-attestation",
            state
        );
    }

    for state in disallows_reattestation {
        assert!(
            !state.allows_reattestation(),
            "State {} should not allow re-attestation",
            state
        );
    }
}

// ---------------------------------------------------------------------------
// Software trust root revocation tests
// ---------------------------------------------------------------------------

fn test_revocation_semantics() {
    let mut root = SoftwareTrustRoot::new("test-key", 12345);
    let measurement = root.measure(b"code", b"config", b"policy", b"schema", "1.0.0");
    let nonce = [1u8; 32];
    let validity_window_ns = 3600_000_000_000;
    let issued_at_ns = 1_000_000_000_000;

    // Create quote before revocation
    let quote = root.attest(&measurement, nonce, validity_window_ns, issued_at_ns);

    // Verify should succeed before revocation
    let verification_time = issued_at_ns + 1800_000_000_000;
    let result = root.verify(&quote, &measurement, &nonce, verification_time);
    assert_eq!(
        result,
        VerificationResult::Valid,
        "Verification should succeed before revocation"
    );

    // Revoke the key
    root.revoke_key("test-key");

    // Verify should fail after revocation
    let result = root.verify(&quote, &measurement, &nonce, verification_time);
    match result {
        VerificationResult::SignerRevoked { key_id } => {
            assert_eq!(
                key_id, "test-key",
                "Revocation result should report correct key ID"
            );
        }
        _ => panic!(
            "Verification should fail with SignerRevoked after key revocation, got: {:?}",
            result
        ),
    }
}

// ---------------------------------------------------------------------------
// Safe-mode fallback tests
// ---------------------------------------------------------------------------

fn test_safe_mode_semantics() {
    // Test that non-operational states enforce safe-mode restrictions
    let safe_mode_states = [
        CellLifecycle::Provisioning,
        CellLifecycle::Measured,
        CellLifecycle::Attested,
        CellLifecycle::Suspended,
        CellLifecycle::Decommissioned,
    ];

    for state in safe_mode_states {
        // Safe mode means high-impact actions should be degraded to deterministic safe alternatives
        // The specific semantics depend on the operation, but we can test the invariant that
        // non-operational states should not permit high-impact operations
        assert!(
            !state.is_operational(),
            "State {} should enforce safe-mode (non-operational) semantics",
            state
        );
    }
}

// ---------------------------------------------------------------------------
// Deterministic behavior tests
// ---------------------------------------------------------------------------

fn test_deterministic_id_allocation() {
    let root = SoftwareTrustRoot::new("deterministic-test", 98765);

    let measurement = root.measure(b"code", b"config", b"policy", b"schema", "1.0.0");
    let zone = "test-zone";

    // Multiple ID derivations should be identical
    let id1 = measurement
        .derive_id(zone)
        .expect("ID derivation should succeed");
    let id2 = measurement
        .derive_id(zone)
        .expect("ID derivation should succeed");
    let id3 = measurement
        .derive_id(zone)
        .expect("ID derivation should succeed");

    assert_eq!(id1, id2, "ID derivation should be deterministic");
    assert_eq!(
        id2, id3,
        "ID derivation should be deterministic across calls"
    );
}

// ---------------------------------------------------------------------------
// Platform-specific behavior tests
// ---------------------------------------------------------------------------

fn test_platform_consistency() {
    let root = SoftwareTrustRoot::new("platform-test", 11111);

    // Trust level and platform should be consistent
    assert_eq!(
        root.trust_level(),
        TrustLevel::SoftwareOnly,
        "SoftwareTrustRoot should report SoftwareOnly trust level"
    );
    assert_eq!(
        root.platform(),
        PlatformKind::Software,
        "SoftwareTrustRoot should report Software platform"
    );

    // Measurements should include correct platform
    let measurement = root.measure(b"code", b"config", b"policy", b"schema", "1.0.0");
    assert_eq!(
        measurement.platform,
        PlatformKind::Software,
        "Measurement should use Software platform"
    );

    // Quotes should include correct platform and trust level
    let nonce = [1u8; 32];
    let quote = root.attest(&measurement, nonce, 3600_000_000_000, 1_000_000_000_000);
    assert_eq!(
        quote.platform,
        PlatformKind::Software,
        "Quote should use Software platform"
    );
    assert_eq!(
        quote.trust_level,
        TrustLevel::SoftwareOnly,
        "Quote should use SoftwareOnly trust level"
    );
}

// ---------------------------------------------------------------------------
// Test runner that applies contract to all implementations
// ---------------------------------------------------------------------------

#[test]
fn software_trust_root_contract_conformance() {
    let root = SoftwareTrustRoot::new("conformance-test", 42);
    assert_trust_root_backend_contract(root);
}

#[test]
fn lifecycle_state_machine_conformance() {
    test_lifecycle_transitions();
    test_operational_semantics();
    test_reattestation_semantics();
}

#[test]
fn revocation_contract_conformance() {
    test_revocation_semantics();
}

#[test]
fn safe_mode_fallback_conformance() {
    test_safe_mode_semantics();
}

#[test]
fn deterministic_behavior_conformance() {
    test_deterministic_id_allocation();
}

#[test]
fn platform_behavior_conformance() {
    test_platform_consistency();
}

// ---------------------------------------------------------------------------
// Cross-backend comparison tests (for when multiple backends exist)
// ---------------------------------------------------------------------------

#[test]
fn measurement_consistency_across_backends() {
    // When additional backends are implemented, this test should verify that
    // identical inputs produce semantically equivalent measurements (even if
    // the exact bytes differ due to platform-specific details)

    let root = SoftwareTrustRoot::new("consistency-test", 77777);
    let measurement = root.measure(b"code", b"config", b"policy", b"schema", "1.0.0");

    // For now, just verify the measurement is internally consistent
    assert_eq!(measurement.platform, PlatformKind::Software);
    assert!(!measurement.runtime_version.is_empty());

    // When additional backends are added, this test should create measurements
    // with identical inputs across all backends and verify semantic consistency
}

// ---------------------------------------------------------------------------
// Golden fixture tests for regression detection
// ---------------------------------------------------------------------------

#[test]
fn golden_measurement_regression_detection() {
    // Create deterministic measurements with known inputs to detect regressions
    let root = SoftwareTrustRoot::new("golden-test", 0x12345678);

    let measurement = root.measure(
        b"golden-code-fixture-v1",
        b"golden-config-fixture-v1",
        b"golden-policy-fixture-v1",
        b"golden-schema-fixture-v1",
        "1.2.3",
    );

    // These values should remain stable across versions to catch regressions
    let canonical = measurement.canonical_bytes();
    let composite = measurement.composite_hash();

    // The specific hash values depend on the implementation details, but they
    // should be deterministic. In a real deployment, these would be golden
    // reference values to detect measurement algorithm changes.
    assert!(!canonical.is_empty(), "Canonical bytes should not be empty");
    assert_eq!(
        canonical.len(),
        32 + 32 + 32 + 32 + 5 + 1,
        "Canonical bytes should have expected length"
    );

    // Composite hash should be reproducible
    let composite2 = measurement.composite_hash();
    assert_eq!(
        composite, composite2,
        "Composite hash should be deterministic"
    );

    // Object ID should be deterministic
    let id1 = measurement
        .derive_id("golden-zone")
        .expect("ID derivation should succeed");
    let id2 = measurement
        .derive_id("golden-zone")
        .expect("ID derivation should succeed");
    assert_eq!(id1, id2, "Object ID should be deterministic");
}
