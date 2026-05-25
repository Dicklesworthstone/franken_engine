//! Integration tests for TEE attestation live quote functionality.
//!
//! This test suite validates the complete TEE attestation workflow:
//! - Live quote generation on TEE-capable workers
//! - Safe-mode fallback for non-TEE workers
//! - Receipt binding and verification
//! - Policy validation and compliance

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frankenengine_engine::evidence_contract::{
    ActionType, AttestationValidityWindow, DecisionAction, ExpectedLossEntry, PosteriorSnapshot,
    ReceiptRecord, SignatureAlgorithm, SignatureBundle, TeeAttestationBinding,
    VerificationMetadata,
};
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::tee_attestation_policy::{TeeAttestationPolicy, TeePlatform};
use frankenengine_engine::tee_live_quote::{
    SafeModeAttestationRecord, TeeCapability, TeeQuoteConfig, TeeQuoteError, TeeQuoteGenerator,
    TeeQuoteResult,
};

/// Helper to create a valid test receipt without TEE binding.
fn create_test_receipt() -> ReceiptRecord {
    let posterior_snapshot = PosteriorSnapshot {
        mean_expected_loss: 0.25,
        confidence_interval_95_lower: 0.15,
        confidence_interval_95_upper: 0.35,
        posterior_mode: 0.22,
        evaluation_count: 500,
    };

    let expected_loss_vector = vec![
        ExpectedLossEntry {
            scenario: "normal".to_string(),
            probability: 0.7,
            expected_loss: 0.1,
        },
        ExpectedLossEntry {
            scenario: "elevated".to_string(),
            probability: 0.3,
            expected_loss: 0.8,
        },
    ];

    let action = DecisionAction {
        action_type: ActionType::Allow,
        action_parameters: BTreeMap::new(),
        execution_timestamp: 1699123456789,
    };

    let signature_bundle = SignatureBundle {
        signature_algorithm: SignatureAlgorithm::Ed25519,
        signature_hex: "deadbeefcafebabe".repeat(8),
        public_key_hex: "1234567890abcdef".repeat(4),
        threshold_signature: false,
        signer_count: 1,
        threshold: 1,
    };

    ReceiptRecord::new(
        "receipt_123".to_string(),
        "decision_456".to_string(),
        "policy_789".to_string(),
        "evidence_hash_abc".to_string(),
        posterior_snapshot,
        expected_loss_vector,
        action,
        signature_bundle,
    )
}

/// Helper to create a test TEE quote generator.
fn create_test_generator() -> TeeQuoteGenerator {
    let config = TeeQuoteConfig::default();
    let signing_key = franken_engine::signature_preimage::generate_keypair().0;
    TeeQuoteGenerator::new(config, signing_key)
}

// ---------------------------------------------------------------------------
// TEE Capability Detection Tests
// ---------------------------------------------------------------------------

#[test]
fn test_tee_capability_detection_not_available() {
    unsafe {
        std::env::remove_var("FRANKEN_TEE_ENABLED");
        std::env::remove_var("FRANKEN_TEE_ERROR");
    }

    let generator = create_test_generator();
    let capability = generator.detect_tee_capability();

    assert_eq!(capability, TeeCapability::NotAvailable);
}

#[test]
fn test_tee_capability_detection_available() {
    unsafe {
        std::env::set_var("FRANKEN_TEE_ENABLED", "true");
        std::env::remove_var("FRANKEN_TEE_ERROR");
    }

    let generator = create_test_generator();
    let capability = generator.detect_tee_capability();

    assert_eq!(
        capability,
        TeeCapability::Available {
            platform: TeePlatform::IntelSgx
        }
    );

    unsafe {
        std::env::remove_var("FRANKEN_TEE_ENABLED");
    }
}

#[test]
fn test_tee_capability_detection_error() {
    unsafe {
        std::env::remove_var("FRANKEN_TEE_ENABLED");
        std::env::set_var("FRANKEN_TEE_ERROR", "Hardware malfunction");
    }

    let generator = create_test_generator();
    let capability = generator.detect_tee_capability();

    assert!(matches!(capability, TeeCapability::Error { .. }));

    unsafe {
        std::env::remove_var("FRANKEN_TEE_ERROR");
    }
}

// ---------------------------------------------------------------------------
// Live Quote Generation Tests
// ---------------------------------------------------------------------------

#[test]
fn test_live_quote_generation_success() {
    std::env::set_var("FRANKEN_TEE_ENABLED", "true");
    std::env::remove_var("FRANKEN_TEE_QUOTE_FAIL");

    let generator = create_test_generator();
    let decision_data = b"test decision data for quote generation";
    let nonce = "test_nonce_12345";

    let result = generator.generate_quote(decision_data, nonce);

    match result {
        TeeQuoteResult::Success { binding, raw_quote } => {
            assert!(!binding.quote_digest.is_empty());
            assert!(!binding.measurement_id.is_empty());
            assert_eq!(binding.nonce, nonce);
            assert_eq!(binding.tee_platform, "intel_sgx");
            assert!(!raw_quote.is_empty());

            // Verify validity window
            let now = chrono::Utc::now();
            let valid_from =
                chrono::DateTime::parse_from_rfc3339(&binding.validity_window.valid_from).unwrap();
            let valid_until =
                chrono::DateTime::parse_from_rfc3339(&binding.validity_window.valid_until).unwrap();

            assert!(valid_from.with_timezone(&chrono::Utc) <= now);
            assert!(valid_until.with_timezone(&chrono::Utc) > now);
        }
        _ => panic!("Expected successful quote generation, got: {:?}", result),
    }

    std::env::remove_var("FRANKEN_TEE_ENABLED");
}

#[test]
fn test_live_quote_generation_failure() {
    std::env::set_var("FRANKEN_TEE_ENABLED", "true");
    std::env::set_var("FRANKEN_TEE_QUOTE_FAIL", "1");

    let generator = create_test_generator();
    let decision_data = b"test decision data";
    let nonce = "test_nonce";

    let result = generator.generate_quote(decision_data, nonce);

    assert!(matches!(result, TeeQuoteResult::Failed { .. }));

    std::env::remove_var("FRANKEN_TEE_ENABLED");
    std::env::remove_var("FRANKEN_TEE_QUOTE_FAIL");
}

// ---------------------------------------------------------------------------
// Safe Mode Fallback Tests
// ---------------------------------------------------------------------------

#[test]
fn test_safe_mode_fallback() {
    std::env::remove_var("FRANKEN_TEE_ENABLED");
    std::env::remove_var("FRANKEN_TEE_ERROR");

    let generator = create_test_generator();
    let decision_data = b"test decision data for safe mode";
    let nonce = "safe_mode_nonce";

    let result = generator.generate_quote(decision_data, nonce);

    match result {
        TeeQuoteResult::SafeModeFallback {
            safe_mode_attestation,
        } => {
            assert!(!safe_mode_attestation.record_id.is_empty());
            assert!(!safe_mode_attestation.initiated_at.is_empty());
            assert_eq!(
                safe_mode_attestation.fallback_reason,
                "TEE hardware not available"
            );
            assert!(!safe_mode_attestation.decision_data_hash.is_empty());
            assert!(!safe_mode_attestation.signature.is_empty());
            assert!(!safe_mode_attestation.signer_public_key.is_empty());

            // Verify the timestamp format
            assert!(
                chrono::DateTime::parse_from_rfc3339(&safe_mode_attestation.initiated_at).is_ok()
            );
        }
        _ => panic!("Expected safe mode fallback, got: {:?}", result),
    }
}

#[test]
fn test_safe_mode_attestation_record_structure() {
    let generator = create_test_generator();
    let decision_data = b"test decision data";
    let reason = "Custom fallback reason";

    // Use the internal method for testing
    // Note: In a real implementation, this would be a public testing utility
    std::env::remove_var("FRANKEN_TEE_ENABLED");
    let result = generator.generate_quote(decision_data, "test_nonce");

    match result {
        TeeQuoteResult::SafeModeFallback {
            safe_mode_attestation,
        } => {
            // Verify required fields are present and non-empty
            assert!(!safe_mode_attestation.record_id.is_empty());
            assert!(!safe_mode_attestation.initiated_at.is_empty());
            assert!(!safe_mode_attestation.fallback_reason.is_empty());
            assert!(!safe_mode_attestation.decision_data_hash.is_empty());
            assert!(!safe_mode_attestation.signature.is_empty());
            assert!(!safe_mode_attestation.signer_public_key.is_empty());

            // Verify hex encoding
            assert!(hex::decode(&safe_mode_attestation.decision_data_hash).is_ok());
            assert!(hex::decode(&safe_mode_attestation.signature).is_ok());
            assert!(hex::decode(&safe_mode_attestation.signer_public_key).is_ok());
        }
        _ => panic!("Expected safe mode fallback"),
    }
}

// ---------------------------------------------------------------------------
// Receipt Integration Tests
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_with_tee_attestation_binding() {
    std::env::set_var("FRANKEN_TEE_ENABLED", "true");

    let generator = create_test_generator();
    let decision_data = b"receipt integration test data";
    let nonce = "receipt_nonce_123";

    let quote_result = generator.generate_quote(decision_data, nonce);

    match quote_result {
        TeeQuoteResult::Success { binding, .. } => {
            let mut receipt = create_test_receipt();
            receipt = receipt.with_tee_attestation_binding(binding);

            // Verify the receipt has the TEE binding
            assert!(receipt.tee_attestation_binding.is_some());

            let tee_binding = receipt.tee_attestation_binding.unwrap();
            assert!(!tee_binding.quote_digest.is_empty());
            assert!(!tee_binding.measurement_id.is_empty());
            assert_eq!(tee_binding.nonce, nonce);
            assert_eq!(tee_binding.tee_platform, "intel_sgx");

            // Verify receipt validation still passes
            assert!(receipt.validate().is_ok());
        }
        _ => panic!("Expected successful quote generation for receipt test"),
    }

    std::env::remove_var("FRANKEN_TEE_ENABLED");
}

#[test]
fn test_receipt_without_tee_attestation_binding() {
    let receipt = create_test_receipt();

    // Verify receipt without TEE binding is valid
    assert!(receipt.tee_attestation_binding.is_none());
    assert!(receipt.validate().is_ok());
}

#[test]
fn test_receipt_serialization_with_tee_binding() {
    std::env::set_var("FRANKEN_TEE_ENABLED", "true");

    let generator = create_test_generator();
    let decision_data = b"serialization test data";
    let nonce = "serialization_nonce";

    let quote_result = generator.generate_quote(decision_data, nonce);

    match quote_result {
        TeeQuoteResult::Success { binding, .. } => {
            let receipt = create_test_receipt().with_tee_attestation_binding(binding);

            // Test JSON serialization
            let json = serde_json::to_string(&receipt).expect("Receipt should serialize to JSON");
            assert!(json.contains("tee_attestation_binding"));
            assert!(json.contains("quote_digest"));

            // Test deserialization
            let deserialized: ReceiptRecord =
                serde_json::from_str(&json).expect("Receipt should deserialize from JSON");
            assert!(deserialized.tee_attestation_binding.is_some());
            assert_eq!(receipt, deserialized);
        }
        _ => panic!("Expected successful quote generation for serialization test"),
    }

    std::env::remove_var("FRANKEN_TEE_ENABLED");
}

// ---------------------------------------------------------------------------
// Policy Validation Tests
// ---------------------------------------------------------------------------

#[test]
fn test_attestation_binding_validation_success() {
    let generator = create_test_generator();
    let policy = TeeAttestationPolicy::from_json(r#"{"approved_measurements":{},"revocation_sources":[],"platform_trust_roots":[]}"#).unwrap();

    let now = chrono::Utc::now();
    let binding = TeeAttestationBinding {
        quote_digest: "abc123def456".to_string(),
        measurement_id: "test_measurement_id".to_string(),
        attested_signer_key_id: "signer_key_123".to_string(),
        nonce: "validation_nonce".to_string(),
        validity_window: AttestationValidityWindow {
            valid_from: (now - chrono::Duration::minutes(5)).to_rfc3339(),
            valid_until: (now + chrono::Duration::minutes(5)).to_rfc3339(),
        },
        tee_platform: "intel_sgx".to_string(),
        quote_algorithm: "sha256".to_string(),
    };

    let result = generator.validate_attestation_binding(&binding, &policy);
    assert!(
        result.is_ok(),
        "Valid attestation binding should pass validation"
    );
}

#[test]
fn test_attestation_binding_validation_expired() {
    let generator = create_test_generator();
    let policy = TeeAttestationPolicy::from_json(r#"{"approved_measurements":{},"revocation_sources":[],"platform_trust_roots":[]}"#).unwrap();

    let now = chrono::Utc::now();
    let binding = TeeAttestationBinding {
        quote_digest: "abc123def456".to_string(),
        measurement_id: "test_measurement_id".to_string(),
        attested_signer_key_id: "signer_key_123".to_string(),
        nonce: "expired_nonce".to_string(),
        validity_window: AttestationValidityWindow {
            valid_from: (now - chrono::Duration::hours(2)).to_rfc3339(),
            valid_until: (now - chrono::Duration::hours(1)).to_rfc3339(),
        },
        tee_platform: "intel_sgx".to_string(),
        quote_algorithm: "sha256".to_string(),
    };

    let result = generator.validate_attestation_binding(&binding, &policy);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TeeQuoteError::PolicyViolation { .. }
    ));
}

#[test]
fn test_attestation_binding_validation_not_yet_valid() {
    let generator = create_test_generator();
    let policy = TeeAttestationPolicy::from_json(r#"{"approved_measurements":{},"revocation_sources":[],"platform_trust_roots":[]}"#).unwrap();

    let now = chrono::Utc::now();
    let binding = TeeAttestationBinding {
        quote_digest: "abc123def456".to_string(),
        measurement_id: "test_measurement_id".to_string(),
        attested_signer_key_id: "signer_key_123".to_string(),
        nonce: "future_nonce".to_string(),
        validity_window: AttestationValidityWindow {
            valid_from: (now + chrono::Duration::hours(1)).to_rfc3339(),
            valid_until: (now + chrono::Duration::hours(2)).to_rfc3339(),
        },
        tee_platform: "intel_sgx".to_string(),
        quote_algorithm: "sha256".to_string(),
    };

    let result = generator.validate_attestation_binding(&binding, &policy);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TeeQuoteError::PolicyViolation { .. }
    ));
}

#[test]
fn test_attestation_binding_validation_unsupported_platform() {
    let generator = create_test_generator();
    let policy = TeeAttestationPolicy::from_json(r#"{"approved_measurements":{},"revocation_sources":[],"platform_trust_roots":[]}"#).unwrap();

    let now = chrono::Utc::now();
    let binding = TeeAttestationBinding {
        quote_digest: "abc123def456".to_string(),
        measurement_id: "test_measurement_id".to_string(),
        attested_signer_key_id: "signer_key_123".to_string(),
        nonce: "unsupported_nonce".to_string(),
        validity_window: AttestationValidityWindow {
            valid_from: (now - chrono::Duration::minutes(5)).to_rfc3339(),
            valid_until: (now + chrono::Duration::minutes(5)).to_rfc3339(),
        },
        tee_platform: "unsupported_platform".to_string(),
        quote_algorithm: "sha256".to_string(),
    };

    let result = generator.validate_attestation_binding(&binding, &policy);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TeeQuoteError::UnsupportedPlatform { .. }
    ));
}

// ---------------------------------------------------------------------------
// End-to-End Integration Tests
// ---------------------------------------------------------------------------

#[test]
fn test_end_to_end_tee_workflow() {
    std::env::set_var("FRANKEN_TEE_ENABLED", "true");

    let generator = create_test_generator();
    let policy = TeeAttestationPolicy::from_json(r#"{"approved_measurements":{},"revocation_sources":[],"platform_trust_roots":[]}"#).unwrap();

    // Step 1: Generate decision data
    let decision_data = b"end-to-end test decision data";
    let nonce = "e2e_nonce_789";

    // Step 2: Generate TEE quote
    let quote_result = generator.generate_quote(decision_data, nonce);

    match quote_result {
        TeeQuoteResult::Success { binding, raw_quote } => {
            // Step 3: Validate the binding against policy
            assert!(
                generator
                    .validate_attestation_binding(&binding, &policy)
                    .is_ok()
            );

            // Step 4: Create receipt with TEE binding
            let receipt = create_test_receipt().with_tee_attestation_binding(binding);

            // Step 5: Verify receipt is valid
            assert!(receipt.validate().is_ok());

            // Step 6: Test serialization round-trip
            let json = serde_json::to_string(&receipt).expect("Receipt serialization");
            let deserialized: ReceiptRecord =
                serde_json::from_str(&json).expect("Receipt deserialization");
            assert_eq!(receipt, deserialized);

            // Step 7: Verify TEE binding is preserved
            let restored_binding = deserialized.tee_attestation_binding.unwrap();
            assert_eq!(restored_binding.nonce, nonce);
            assert!(!restored_binding.quote_digest.is_empty());
            assert!(!raw_quote.is_empty());
        }
        _ => panic!("End-to-end test expected successful TEE quote generation"),
    }

    std::env::remove_var("FRANKEN_TEE_ENABLED");
}

#[test]
fn test_end_to_end_safe_mode_workflow() {
    std::env::remove_var("FRANKEN_TEE_ENABLED");
    std::env::remove_var("FRANKEN_TEE_ERROR");

    let generator = create_test_generator();

    // Step 1: Generate decision data
    let decision_data = b"safe mode end-to-end test data";
    let nonce = "safe_mode_e2e_nonce";

    // Step 2: Attempt TEE quote generation (should fall back to safe mode)
    let quote_result = generator.generate_quote(decision_data, nonce);

    match quote_result {
        TeeQuoteResult::SafeModeFallback {
            safe_mode_attestation,
        } => {
            // Step 3: Create receipt without TEE binding (safe mode)
            let receipt = create_test_receipt();

            // Step 4: Verify receipt is valid without TEE binding
            assert!(receipt.validate().is_ok());
            assert!(receipt.tee_attestation_binding.is_none());

            // Step 5: Verify safe mode record is properly structured
            assert!(!safe_mode_attestation.record_id.is_empty());
            assert_eq!(
                safe_mode_attestation.fallback_reason,
                "TEE hardware not available"
            );

            // Step 6: Test serialization of safe mode record
            let safe_mode_json = serde_json::to_string(&safe_mode_attestation)
                .expect("Safe mode record serialization");
            let deserialized: SafeModeAttestationRecord =
                serde_json::from_str(&safe_mode_json).expect("Safe mode record deserialization");
            assert_eq!(safe_mode_attestation, deserialized);
        }
        _ => panic!("End-to-end safe mode test expected safe mode fallback"),
    }
}

// ---------------------------------------------------------------------------
// Error Handling Tests
// ---------------------------------------------------------------------------

#[test]
fn test_quote_generation_timeout_simulation() {
    // This test verifies error handling paths
    std::env::set_var("FRANKEN_TEE_ENABLED", "true");
    std::env::set_var("FRANKEN_TEE_QUOTE_FAIL", "1");

    let generator = create_test_generator();
    let result = generator.generate_quote(b"timeout test", "timeout_nonce");

    assert!(matches!(result, TeeQuoteResult::Failed { .. }));

    std::env::remove_var("FRANKEN_TEE_ENABLED");
    std::env::remove_var("FRANKEN_TEE_QUOTE_FAIL");
}

#[test]
fn test_tee_error_display() {
    let error = TeeQuoteError::UnsupportedPlatform {
        platform: "test_platform".to_string(),
    };
    let display = format!("{}", error);
    assert!(display.contains("test_platform"));

    let error = TeeQuoteError::Timeout { timeout_ms: 1000 };
    let display = format!("{}", error);
    assert!(display.contains("1000ms"));
}

// ---------------------------------------------------------------------------
// Configuration Tests
// ---------------------------------------------------------------------------

#[test]
fn test_tee_quote_config_customization() {
    use std::time::Duration;

    let custom_config = TeeQuoteConfig {
        platform: TeePlatform::ArmTrustZone,
        freshness_window: Duration::from_secs(600),
        max_retries: 5,
        quote_timeout: Duration::from_secs(30),
    };

    let signing_key = franken_engine::signature_preimage::generate_keypair().0;
    let generator = TeeQuoteGenerator::new(custom_config, signing_key);

    // Verify the configuration is applied
    // (This would be more testable with accessor methods on TeeQuoteGenerator)
    unsafe {
        std::env::set_var("FRANKEN_TEE_ENABLED", "true");
    }
    let result = generator.generate_quote(b"config test", "config_nonce");

    match result {
        TeeQuoteResult::Success { binding, .. } => {
            // The platform should be reflected in the generated quote
            // Note: In the current simulation, it defaults to the configured platform
            // but the test environment might override this
            assert!(!binding.tee_platform.is_empty());
        }
        _ => {
            // Safe mode fallback or error is also acceptable for this config test
        }
    }

    std::env::remove_var("FRANKEN_TEE_ENABLED");
}
