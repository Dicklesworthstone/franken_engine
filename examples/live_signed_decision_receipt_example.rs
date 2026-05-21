//! Live example of generating a signed decision receipt.
//!
//! This example demonstrates the complete workflow for generating an externally-verifiable
//! receipt artifact that bundles all required decision components into a standalone JSON
//! document with cryptographic signatures.
//!
//! Usage:
//!   cargo run --example live_signed_decision_receipt_example
//!
//! Output:
//!   - Prints the generated receipt to stdout as JSON
//!   - Writes receipt artifact to artifacts/signed_decision_receipt/<timestamp>/receipt.json

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use frankenengine_engine::evidence_contract::{
    ActionType, DecisionAction, ExpectedLossEntry, PosteriorSnapshot, ReceiptRecord,
    SignatureAlgorithm, SignatureBundle, VerificationMetadata,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("FrankenEngine Live Signed Decision Receipt Example");
    println!("=================================================");

    // Generate a realistic decision scenario
    let receipt = generate_sample_receipt();

    // Validate the receipt
    if let Err(errors) = receipt.validate() {
        eprintln!("Receipt validation failed:");
        for error in errors {
            eprintln!("  - {}", error);
        }
        std::process::exit(1);
    }

    // Serialize to JSON
    let receipt_json = serde_json::to_string_pretty(&receipt)?;

    println!("Generated receipt:");
    println!("{}", receipt_json);

    // Create output directory
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let output_dir = format!("artifacts/signed_decision_receipt/{}", timestamp);
    fs::create_dir_all(&output_dir)?;

    // Write receipt artifact
    let receipt_path = format!("{}/receipt.json", output_dir);
    fs::write(&receipt_path, &receipt_json)?;

    println!("\nReceipt artifact written to: {}", receipt_path);

    // Write run manifest
    let manifest = serde_json::json!({
        "run_id": format!("receipt-example-{}", timestamp),
        "timestamp": timestamp,
        "example": "live_signed_decision_receipt_example",
        "artifacts": [
            {
                "path": "receipt.json",
                "type": "signed_decision_receipt",
                "schema_version": "franken-engine.signed-decision-receipt.v1"
            }
        ],
        "verification_command": format!("frankenctl verify receipt --input {} --receipt-id {}",
                                      receipt_path, receipt.receipt_id)
    });

    let manifest_path = format!("{}/run_manifest.json", output_dir);
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;

    println!("Run manifest written to: {}", manifest_path);

    println!("\nTo verify this receipt:");
    println!("  frankenctl verify receipt --input {} --receipt-id {}",
             receipt_path, receipt.receipt_id);

    Ok(())
}

/// Generate a sample receipt for demonstration purposes.
fn generate_sample_receipt() -> ReceiptRecord {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Create a realistic posterior snapshot
    let posterior_snapshot = PosteriorSnapshot {
        mean_expected_loss: 0.15,
        confidence_interval_95_lower: 0.08,
        confidence_interval_95_upper: 0.22,
        posterior_mode: 0.12,
        evaluation_count: 1000,
    };

    // Create expected loss vector for different scenarios
    let expected_loss_vector = vec![
        ExpectedLossEntry {
            scenario: "benign_operation".to_string(),
            probability: 0.85,
            expected_loss: 0.05,
        },
        ExpectedLossEntry {
            scenario: "moderate_risk".to_string(),
            probability: 0.12,
            expected_loss: 0.8,
        },
        ExpectedLossEntry {
            scenario: "high_risk".to_string(),
            probability: 0.03,
            expected_loss: 2.5,
        },
    ];

    // Create decision action with parameters
    let mut action_parameters = BTreeMap::new();
    action_parameters.insert("reason".to_string(), "expected_loss_below_threshold".to_string());
    action_parameters.insert("threshold".to_string(), "0.5".to_string());

    let action = DecisionAction {
        action_type: ActionType::Allow,
        action_parameters,
        execution_timestamp: timestamp,
    };

    // Create signature bundle (using mock values for demonstration)
    let signature_bundle = SignatureBundle {
        signature_algorithm: SignatureAlgorithm::Ed25519,
        signature_hex: generate_mock_signature(),
        public_key_hex: generate_mock_public_key(),
        threshold_signature: false,
        signer_count: 1,
        threshold: 1,
    };

    // Create verification metadata
    let verification_metadata = VerificationMetadata {
        generator_version: env!("CARGO_PKG_VERSION").to_string(),
        security_epoch: compute_current_security_epoch(),
        trace_id: Some(format!("trace-{}", timestamp)),
    };

    // Generate receipt
    ReceiptRecord::new(
        format!("receipt-example-{}", timestamp),
        format!("decision-{}", timestamp),
        "policy-standard-risk-assessment.v2".to_string(),
        generate_mock_evidence_hash(),
        posterior_snapshot,
        expected_loss_vector,
        action,
        signature_bundle,
    )
    .with_verification_metadata(verification_metadata)
}

/// Generate a mock signature for demonstration purposes.
///
/// In a real implementation, this would use the actual signing primitives
/// from signature_preimage.rs and threshold_signing.rs.
fn generate_mock_signature() -> String {
    // Ed25519 signatures are 64 bytes = 128 hex characters
    "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456789012345678901234567890abcdef1234567890abcdef1234567890abcdef".to_string()
}

/// Generate a mock public key for demonstration purposes.
fn generate_mock_public_key() -> String {
    // Ed25519 public keys are 32 bytes = 64 hex characters
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string()
}

/// Generate a mock evidence hash chain root.
fn generate_mock_evidence_hash() -> String {
    // SHA-256 hash = 64 hex characters
    format!(
        "{}{}",
        "deadbeefcafebabe1234567890abcdef",
        "fedcba0987654321beefdaedabefaced"
    )
}

/// Compute the current security epoch.
///
/// In a real implementation, this would use the actual security epoch
/// from the security_epoch.rs module.
fn compute_current_security_epoch() -> u64 {
    // Simple mock: use days since epoch
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86400 // seconds per day
}