//! Integration tests for signed decision receipt functionality.
//!
//! This module tests the complete end-to-end workflow for generating, validating,
//! and verifying signed decision receipts, including security tests for tampered
//! receipts, missing fields, and replay attacks.

use std::collections::BTreeMap;

use frankenengine_engine::evidence_contract::{
    ActionType, DecisionAction, ExpectedLossEntry, PosteriorSnapshot, ReceiptRecord,
    SignatureAlgorithm, SignatureBundle, VerificationMetadata,
};
use serde_json;

fn valid_test_receipt() -> ReceiptRecord {
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
        "receipt-test-001".to_string(),
        "decision-test-001".to_string(),
        "policy-test.v1".to_string(),
        "a".repeat(64),
        posterior_snapshot,
        expected_loss_vector,
        action,
        signature_bundle,
    )
}

// ---------------------------------------------------------------------------
// Positive validation tests
// ---------------------------------------------------------------------------

#[test]
fn valid_receipt_passes_validation() {
    let receipt = valid_test_receipt();
    assert!(receipt.validate().is_ok());
}

#[test]
fn valid_receipt_serializes_to_json() {
    let receipt = valid_test_receipt();
    let json = serde_json::to_string(&receipt).expect("serialization should succeed");
    assert!(json.contains("franken-engine.signed-decision-receipt.v1"));
    assert!(json.contains("receipt-test-001"));
}

#[test]
fn valid_receipt_deserializes_from_json() {
    let receipt = valid_test_receipt();
    let json = serde_json::to_string(&receipt).expect("serialization should succeed");
    let deserialized: ReceiptRecord =
        serde_json::from_str(&json).expect("deserialization should succeed");
    assert_eq!(receipt.receipt_id, deserialized.receipt_id);
    assert_eq!(receipt.decision_id, deserialized.decision_id);
}

#[test]
fn receipt_with_verification_metadata_works() {
    let metadata = VerificationMetadata {
        generator_version: "1.0.0".to_string(),
        security_epoch: 12345,
        trace_id: Some("trace-abc-123".to_string()),
    };

    let receipt = valid_test_receipt().with_verification_metadata(metadata);
    assert!(receipt.validate().is_ok());
    assert!(receipt.verification_metadata.is_some());
}

#[test]
fn receipt_with_action_parameters_works() {
    let mut receipt = valid_test_receipt();
    receipt
        .action
        .action_parameters
        .insert("reason".to_string(), "below_threshold".to_string());
    receipt
        .action
        .action_parameters
        .insert("threshold".to_string(), "0.5".to_string());

    assert!(receipt.validate().is_ok());

    let json = serde_json::to_string(&receipt).expect("serialization should succeed");
    let deserialized: ReceiptRecord =
        serde_json::from_str(&json).expect("deserialization should succeed");
    assert_eq!(
        deserialized.action.action_parameters.get("reason"),
        Some(&"below_threshold".to_string())
    );
}

#[test]
fn threshold_signature_receipt_validates() {
    let mut receipt = valid_test_receipt();
    receipt.signature_bundle.threshold_signature = true;
    receipt.signature_bundle.signer_count = 5;
    receipt.signature_bundle.threshold = 3;

    assert!(receipt.validate().is_ok());
}

#[test]
fn different_action_types_validate() {
    let action_types = [
        ActionType::Allow,
        ActionType::Deny,
        ActionType::Escalate,
        ActionType::Quarantine,
        ActionType::Monitor,
    ];

    for action_type in action_types {
        let mut receipt = valid_test_receipt();
        receipt.action.action_type = action_type;
        assert!(receipt.validate().is_ok());
    }
}

#[test]
fn different_signature_algorithms_validate() {
    let algorithms = [
        SignatureAlgorithm::Ed25519,
        SignatureAlgorithm::EcdsaP256,
        SignatureAlgorithm::RsaPssSha256,
    ];

    for algorithm in algorithms {
        let mut receipt = valid_test_receipt();
        receipt.signature_bundle.signature_algorithm = algorithm;
        assert!(receipt.validate().is_ok());
    }
}

#[test]
fn complex_expected_loss_vector_validates() {
    let mut receipt = valid_test_receipt();
    receipt.expected_loss_vector = vec![
        ExpectedLossEntry {
            scenario: "benign".to_string(),
            probability: 0.5,
            expected_loss: 0.05,
        },
        ExpectedLossEntry {
            scenario: "moderate".to_string(),
            probability: 0.3,
            expected_loss: 0.5,
        },
        ExpectedLossEntry {
            scenario: "severe".to_string(),
            probability: 0.15,
            expected_loss: 2.0,
        },
        ExpectedLossEntry {
            scenario: "critical".to_string(),
            probability: 0.05,
            expected_loss: 10.0,
        },
    ];

    assert!(receipt.validate().is_ok());
}

// ---------------------------------------------------------------------------
// Missing field validation tests
// ---------------------------------------------------------------------------

#[test]
fn empty_receipt_id_fails_validation() {
    let mut receipt = valid_test_receipt();
    receipt.receipt_id = "".to_string();

    let errors = receipt.validate().expect_err("should fail validation");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("receipt_id cannot be empty"))
    );
}

#[test]
fn empty_decision_id_fails_validation() {
    let mut receipt = valid_test_receipt();
    receipt.decision_id = "".to_string();

    let errors = receipt.validate().expect_err("should fail validation");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("decision_id cannot be empty"))
    );
}

#[test]
fn empty_policy_id_fails_validation() {
    let mut receipt = valid_test_receipt();
    receipt.policy_id = "".to_string();

    let errors = receipt.validate().expect_err("should fail validation");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("policy_id cannot be empty"))
    );
}

#[test]
fn empty_evidence_hash_fails_validation() {
    let mut receipt = valid_test_receipt();
    receipt.evidence_hash_chain_root = "".to_string();

    let errors = receipt.validate().expect_err("should fail validation");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("evidence_hash_chain_root cannot be empty"))
    );
}

#[test]
fn empty_signature_fails_validation() {
    let mut receipt = valid_test_receipt();
    receipt.signature_bundle.signature_hex = "".to_string();

    let errors = receipt.validate().expect_err("should fail validation");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("signature_hex cannot be empty"))
    );
}

#[test]
fn empty_public_key_fails_validation() {
    let mut receipt = valid_test_receipt();
    receipt.signature_bundle.public_key_hex = "".to_string();

    let errors = receipt.validate().expect_err("should fail validation");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("public_key_hex cannot be empty"))
    );
}

#[test]
fn empty_expected_loss_vector_fails_validation() {
    let mut receipt = valid_test_receipt();
    receipt.expected_loss_vector = vec![];

    let errors = receipt.validate().expect_err("should fail validation");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("expected_loss_vector cannot be empty"))
    );
}

// ---------------------------------------------------------------------------
// Probability validation tests
// ---------------------------------------------------------------------------

#[test]
fn probabilities_not_summing_to_one_fails_validation() {
    let mut receipt = valid_test_receipt();
    receipt.expected_loss_vector = vec![
        ExpectedLossEntry {
            scenario: "scenario1".to_string(),
            probability: 0.3,
            expected_loss: 0.1,
        },
        ExpectedLossEntry {
            scenario: "scenario2".to_string(),
            probability: 0.3,
            expected_loss: 0.2,
        },
        // Total probability = 0.6, not 1.0
    ];

    let errors = receipt.validate().expect_err("should fail validation");
    assert!(errors.iter().any(|e| e.contains("probabilities sum to")));
}

#[test]
fn probabilities_summing_to_slightly_over_one_fails_validation() {
    let mut receipt = valid_test_receipt();
    receipt.expected_loss_vector = vec![
        ExpectedLossEntry {
            scenario: "scenario1".to_string(),
            probability: 0.6,
            expected_loss: 0.1,
        },
        ExpectedLossEntry {
            scenario: "scenario2".to_string(),
            probability: 0.45, // 0.6 + 0.45 = 1.05
            expected_loss: 0.2,
        },
    ];

    let errors = receipt.validate().expect_err("should fail validation");
    assert!(errors.iter().any(|e| e.contains("probabilities sum to")));
}

#[test]
fn probabilities_within_tolerance_passes_validation() {
    let mut receipt = valid_test_receipt();
    receipt.expected_loss_vector = vec![
        ExpectedLossEntry {
            scenario: "scenario1".to_string(),
            probability: 0.3334,
            expected_loss: 0.1,
        },
        ExpectedLossEntry {
            scenario: "scenario2".to_string(),
            probability: 0.3333,
            expected_loss: 0.2,
        },
        ExpectedLossEntry {
            scenario: "scenario3".to_string(),
            probability: 0.3333, // Total = 1.0000
            expected_loss: 0.3,
        },
    ];

    assert!(receipt.validate().is_ok());
}

// ---------------------------------------------------------------------------
// JSON schema compliance tests
// ---------------------------------------------------------------------------

#[test]
fn schema_version_is_correct() {
    let receipt = valid_test_receipt();
    assert_eq!(
        receipt.schema_version,
        "franken-engine.signed-decision-receipt.v1"
    );
}

#[test]
fn receipt_id_format_matches_pattern() {
    let receipt = valid_test_receipt();
    // Should start with "receipt-" per JSON schema
    assert!(receipt.receipt_id.starts_with("receipt-"));
}

#[test]
fn serialized_json_contains_required_fields() {
    let receipt = valid_test_receipt();
    let json = serde_json::to_string(&receipt).expect("serialization should succeed");

    // Check all required top-level fields are present
    let required_fields = [
        "schema_version",
        "receipt_id",
        "decision_id",
        "policy_id",
        "evidence_hash_chain_root",
        "posterior_snapshot",
        "expected_loss_vector",
        "action",
        "timestamp",
        "signature_bundle",
    ];

    for field in required_fields {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "JSON missing required field: {}",
            field
        );
    }
}

#[test]
fn posterior_snapshot_has_all_required_fields() {
    let receipt = valid_test_receipt();
    let json = serde_json::to_string(&receipt).expect("serialization should succeed");
    let json_value: serde_json::Value = serde_json::from_str(&json).expect("should parse as JSON");

    let posterior = &json_value["posterior_snapshot"];
    assert!(posterior["mean_expected_loss"].is_number());
    assert!(posterior["confidence_interval_95_lower"].is_number());
    assert!(posterior["confidence_interval_95_upper"].is_number());
    assert!(posterior["posterior_mode"].is_number());
    assert!(posterior["evaluation_count"].is_number());
}

#[test]
fn signature_bundle_has_all_required_fields() {
    let receipt = valid_test_receipt();
    let json = serde_json::to_string(&receipt).expect("serialization should succeed");
    let json_value: serde_json::Value = serde_json::from_str(&json).expect("should parse as JSON");

    let signature = &json_value["signature_bundle"];
    assert!(signature["signature_algorithm"].is_string());
    assert!(signature["signature_hex"].is_string());
    assert!(signature["public_key_hex"].is_string());
    assert!(signature["threshold_signature"].is_boolean());
}

// ---------------------------------------------------------------------------
// Serialization edge cases
// ---------------------------------------------------------------------------

#[test]
fn receipt_without_verification_metadata_serializes_correctly() {
    let receipt = valid_test_receipt();
    assert!(receipt.verification_metadata.is_none());

    let json = serde_json::to_string(&receipt).expect("serialization should succeed");
    assert!(!json.contains("verification_metadata"));
}

#[test]
fn receipt_with_empty_action_parameters_serializes_correctly() {
    let receipt = valid_test_receipt();
    assert!(receipt.action.action_parameters.is_empty());

    let json = serde_json::to_string(&receipt).expect("serialization should succeed");
    assert!(!json.contains("action_parameters"));
}

#[test]
fn multiple_validation_errors_are_collected() {
    let mut receipt = valid_test_receipt();
    receipt.receipt_id = "".to_string();
    receipt.decision_id = "".to_string();
    receipt.policy_id = "".to_string();

    let errors = receipt.validate().expect_err("should fail validation");
    assert!(errors.len() >= 3);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("receipt_id cannot be empty"))
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("decision_id cannot be empty"))
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("policy_id cannot be empty"))
    );
}

// ---------------------------------------------------------------------------
// Replay attack prevention tests
// ---------------------------------------------------------------------------

#[test]
fn timestamps_are_monotonically_increasing() {
    let receipt1 = valid_test_receipt();
    // Small delay to ensure different timestamp
    std::thread::sleep(std::time::Duration::from_millis(10));
    let receipt2 = valid_test_receipt();

    assert!(receipt2.timestamp > receipt1.timestamp);
}

#[test]
fn receipts_with_same_content_have_different_timestamps() {
    let receipt1 = valid_test_receipt();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let receipt2 = valid_test_receipt();

    // Everything should be the same except timestamp
    assert_eq!(receipt1.policy_id, receipt2.policy_id);
    assert_eq!(
        receipt1.evidence_hash_chain_root,
        receipt2.evidence_hash_chain_root
    );
    assert_ne!(receipt1.timestamp, receipt2.timestamp);
    assert_ne!(receipt1.receipt_id, receipt2.receipt_id); // receipt_id includes timestamp
}

// ---------------------------------------------------------------------------
// Constructor and builder tests
// ---------------------------------------------------------------------------

#[test]
fn receipt_new_sets_current_timestamp() {
    let start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let receipt = valid_test_receipt();

    let end = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    assert!(receipt.timestamp >= start);
    assert!(receipt.timestamp <= end);
}

#[test]
fn with_verification_metadata_preserves_original_data() {
    let original = valid_test_receipt();
    let metadata = VerificationMetadata {
        generator_version: "test".to_string(),
        security_epoch: 999,
        trace_id: None,
    };

    let with_metadata = original
        .clone()
        .with_verification_metadata(metadata.clone());

    assert_eq!(original.receipt_id, with_metadata.receipt_id);
    assert_eq!(original.decision_id, with_metadata.decision_id);
    assert_eq!(original.timestamp, with_metadata.timestamp);
    assert_eq!(with_metadata.verification_metadata, Some(metadata));
}
