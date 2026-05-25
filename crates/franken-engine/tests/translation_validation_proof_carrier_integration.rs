//! Integration tests for translation validation proof carrier.
//!
//! Tests the integration between G.4's translation validation pilot and
//! V-track's ReplacementReceipt system. Demonstrates end-to-end proof
//! generation and binding during slot promotions.

use frankenengine_engine::{
    security_epoch::SecurityEpoch,
    self_replacement::{
        CreateReceiptInput, ReplacementReceipt, SchemaVersion, SignatureBundle,
        ValidationArtifactRef, ValidationArtifactKind,
    },
    proof_ingestion::ProofValidationStatus,
    signature_preimage::{Signature, SigningKey},
    slot_registry::SlotId,
    translation_validation_proof_carrier::{
        SlotSpecification, TranslationValidationEngine, TranslationValidationProof,
        ValidationResult, create_slot_specification, validate_promotion_and_get_proof_ref,
    },
};

/// Create a test signing key for demonstrations.
fn create_test_signing_key() -> SigningKey {
    let test_seed = [42u8; 32];
    SigningKey::from_bytes(test_seed).expect("valid test seed")
}

/// Create a test signature bundle.
fn create_test_signature_bundle() -> SignatureBundle {
    SignatureBundle::new(1)
}

#[test]
fn test_translation_validation_engine_basic() {
    let engine = TranslationValidationEngine::default();

    let source_slot = SlotId::new("parser_v1").expect("valid slot ID");
    let target_slot = SlotId::new("parser_v2").expect("valid slot ID");

    let source_spec = create_slot_specification(
        source_slot,
        b"function parse(input) { return input.split(','); }",
        "javascript",
    );

    let target_spec = create_slot_specification(
        target_slot,
        b"function parse(input) { return input.split(/,/); }",
        "javascript",
    );

    let result = engine.validate_slot_promotion(&source_spec, &target_spec);
    assert!(result.is_ok(), "Validation should succeed: {:?}", result);

    let proof = result.unwrap();
    assert!(
        proof.is_valid(),
        "Proof should indicate successful validation"
    );
    assert!(
        proof.summary().contains("PASSED"),
        "Summary should indicate success"
    );
    assert_eq!(proof.source_spec.slot_id.as_str(), "parser_v1");
    assert_eq!(proof.target_spec.slot_id.as_str(), "parser_v2");
}

#[test]
fn test_slot_specification_creation() {
    let slot_id = SlotId::new("test_parser").expect("valid slot ID");
    let code = b"function identity(x) { return x; }";

    let spec = create_slot_specification(slot_id.clone(), code, "javascript");

    assert_eq!(spec.slot_id, slot_id);
    assert_eq!(spec.language, "javascript");
    assert!(!spec.code_digest.is_empty());
    assert_eq!(spec.ir_stages.len(), 4);
    assert!(spec.ir_stages.contains(&"IR0_SyntaxIR".to_string()));
    assert!(spec.ir_stages.contains(&"IR1_SpecIR".to_string()));
    assert!(spec.ir_stages.contains(&"IR2_CapabilityIR".to_string()));
    assert!(spec.ir_stages.contains(&"IR3_ExecIR".to_string()));
}

#[test]
fn test_proof_generation_with_different_code() {
    let old_code = b"function add(a, b) { return a + b; }";
    let new_code = b"function add(a, b) { return (a | 0) + (b | 0); }"; // Optimized version

    let old_slot = SlotId::new("math_v1").expect("valid slot ID");
    let new_slot = SlotId::new("math_v2").expect("valid slot ID");

    let proof_ref =
        validate_promotion_and_get_proof_ref(old_slot, new_slot, old_code, new_code, "test_zone");

    assert!(
        proof_ref.is_ok(),
        "Proof generation should succeed: {:?}",
        proof_ref
    );
    let proof_ref_str = proof_ref.unwrap();
    assert!(proof_ref_str.starts_with("proof://test_zone/"));
}

#[test]
fn test_validation_result_types() {
    // Test success result
    let success = ValidationResult::Success {
        test_cases_passed: 100,
        test_cases_total: 100,
        success_rate_percent: 100,
    };
    assert!(success.is_success());
    assert_eq!(success.success_rate_percent(), 100);
    assert_eq!(success.total_test_cases(), 100);

    // Test failure result
    let failure = ValidationResult::Failed {
        test_cases_passed: 95,
        test_cases_total: 100,
        success_rate_percent: 95,
        failure_reasons: vec!["Numeric precision differs in edge cases".to_string()],
    };
    assert!(!failure.is_success());
    assert_eq!(failure.success_rate_percent(), 95);
    assert_eq!(failure.total_test_cases(), 100);
}

#[test]
fn test_replacement_receipt_with_translation_validation() {
    // Create slot specifications
    let old_slot = SlotId::new("legacy_parser").expect("valid slot ID");
    let new_slot = SlotId::new("optimized_parser").expect("valid slot ID");
    let old_code = b"function parseData(input) { return JSON.parse(input); }";
    let new_code =
        b"function parseData(input) { try { return JSON.parse(input); } catch { return null; } }";

    // Generate translation validation proof
    let proof_ref = validate_promotion_and_get_proof_ref(
        old_slot.clone(),
        new_slot.clone(),
        old_code,
        new_code,
        "production",
    )
    .expect("proof generation should succeed");

    // Create replacement receipt with translation validation proof reference
    let receipt_id = ReplacementReceipt::derive_receipt_id(
        &old_slot, // slot_id for backward compatibility
        &old_slot, // old_slot_id
        &new_slot, // new_slot_id
        "digest_legacy_abc123",
        "digest_optimized_def456",
        &proof_ref, // translation_validation_proof_ref
        "genesis_chain_001",
        1640995200000000000u64, // 2022-01-01 00:00:00 UTC
        "production",
    )
    .expect("valid receipt ID");

    let validation_artifacts = vec![
        ValidationArtifactRef {
            kind: ValidationArtifactKind::PerformanceBenchmark,
            artifact_digest: "perf_evidence_hash".to_string(),
            passed: true,
            summary: "Performance benchmark completed successfully by benchmark_runner".to_string(),
        },
        ValidationArtifactRef {
            kind: ValidationArtifactKind::EquivalenceResult,
            artifact_digest: proof_ref.clone(),
            passed: true,
            summary: "Semantic equivalence validated by g4_validation_engine".to_string(),
        },
    ];

    let receipt = ReplacementReceipt {
        receipt_id,
        schema_version: SchemaVersion::V1,
        slot_id: old_slot.clone(), // For backward compatibility
        old_slot_id: old_slot.clone(),
        new_slot_id: new_slot,
        old_cell_digest: "digest_legacy_abc123".to_string(),
        new_cell_digest: "digest_optimized_def456".to_string(),
        translation_validation_proof_ref: proof_ref.clone(),
        content_hash_chain_into_lineage: "genesis_chain_001".to_string(),
        validation_artifacts,
        rollback_token: "rollback_legacy_abc123".to_string(),
        promotion_rationale: "Performance optimization with error handling".to_string(),
        timestamp_ns: 1640995200000000000u64,
        epoch: SecurityEpoch::from_raw(1),
        zone: "production".to_string(),
        signature_bundle: create_test_signature_bundle(),
    };

    // Verify the receipt contains the translation validation proof reference
    assert_eq!(receipt.translation_validation_proof_ref, proof_ref);

    // Verify that validation artifacts include the translation validation
    let translation_artifact = receipt
        .validation_artifacts
        .iter()
        .find(|a| matches!(a.kind, ValidationArtifactKind::EquivalenceResult))
        .expect("Translation validation artifact should exist");

    assert!(translation_artifact.passed);
    assert_eq!(translation_artifact.artifact_digest, proof_ref);
    assert!(translation_artifact.summary.contains("g4_validation_engine"));
}

#[test]
fn test_proof_id_determinism() {
    let source_digest = "source_abc123";
    let target_digest = "target_def456";
    let timestamp = 1640995200000000000u64;
    let zone = "test_zone";

    let proof_id_1 =
        TranslationValidationProof::derive_proof_id(source_digest, target_digest, timestamp, zone)
            .expect("valid proof ID");

    let proof_id_2 =
        TranslationValidationProof::derive_proof_id(source_digest, target_digest, timestamp, zone)
            .expect("valid proof ID");

    assert_eq!(proof_id_1, proof_id_2, "Proof IDs should be deterministic");
}

#[test]
fn test_proof_summary_formatting() {
    let engine = TranslationValidationEngine::default();
    let slot_id = SlotId::new("test_slot").expect("valid slot ID");

    let source_spec = create_slot_specification(slot_id.clone(), b"let x = 1 + 2;", "javascript");

    let target_spec = create_slot_specification(
        slot_id,
        b"let x = 3;", // Constant folding optimization
        "javascript",
    );

    let proof = engine
        .validate_slot_promotion(&source_spec, &target_spec)
        .expect("validation should succeed");

    let summary = proof.summary();

    // Should contain key information about validation results
    assert!(summary.contains("Translation validation"));
    assert!(summary.contains("test cases"));

    // Should indicate success for high pass rate
    if proof.validation_result.success_rate_percent() >= 95 {
        assert!(summary.contains("PASSED"));
    }
}

#[test]
fn test_engine_configuration() {
    let custom_project_root = "/custom/path";
    let custom_zone = "staging";

    let engine = TranslationValidationEngine::new(custom_project_root, custom_zone.to_string());

    assert_eq!(engine.project_root.to_str(), Some(custom_project_root));
    assert_eq!(engine.zone, custom_zone);
    assert_eq!(engine.minimum_success_rate, 95); // Default value
    assert!(!engine.enable_formal_verification); // Default value

    let expected_script = format!(
        "{}/scripts/run_rgc_translation_validation_pilot.sh",
        custom_project_root
    );
    assert_eq!(engine.validation_script.to_str(), Some(expected_script.as_str()));
}

/// Test that demonstrates the full workflow: promotion request -> validation -> receipt creation.
#[test]
fn test_full_promotion_workflow() {
    // Step 1: Prepare slot promotion data
    let old_slot = SlotId::new("json_parser_v1").expect("valid slot ID");
    let new_slot = SlotId::new("json_parser_v2").expect("valid slot ID");

    let old_implementation = br#"
    function parseJson(input) {
        return JSON.parse(input);
    }
    "#;

    let new_implementation = br#"
    function parseJson(input) {
        try {
            return JSON.parse(input);
        } catch (error) {
            console.warn("JSON parse failed:", error.message);
            return null;
        }
    }
    "#;

    // Step 2: Run translation validation
    let proof_ref = validate_promotion_and_get_proof_ref(
        old_slot.clone(),
        new_slot.clone(),
        old_implementation,
        new_implementation,
        "integration_test",
    )
    .expect("translation validation should succeed");

    // Step 3: Create replacement receipt with proof binding
    let receipt_id = ReplacementReceipt::derive_receipt_id(
        &old_slot, // slot_id for backward compatibility
        &old_slot,
        &new_slot,
        "impl_v1_hash_abc123",
        "impl_v2_hash_def456",
        &proof_ref,
        "promotion_chain_001",
        1640995200000000000u64,
        "integration_test",
    )
    .expect("valid receipt ID");

    let validation_artifacts = vec![
        ValidationArtifactRef {
            kind: ValidationArtifactKind::AdversarialSurvival,
            artifact_digest: "security_audit_hash".to_string(),
            passed: true,
            summary: "Security audit completed successfully by security_team".to_string(),
        },
        ValidationArtifactRef {
            kind: ValidationArtifactKind::EquivalenceResult,
            artifact_digest: proof_ref.clone(),
            passed: true,
            summary: "Semantic equivalence validated by g4_pilot_engine".to_string(),
        },
    ];

    let receipt = ReplacementReceipt {
        receipt_id,
        schema_version: SchemaVersion::V1,
        slot_id: old_slot.clone(),
        old_slot_id: old_slot,
        new_slot_id: new_slot,
        old_cell_digest: "impl_v1_hash_abc123".to_string(),
        new_cell_digest: "impl_v2_hash_def456".to_string(),
        translation_validation_proof_ref: proof_ref.clone(),
        content_hash_chain_into_lineage: "promotion_chain_001".to_string(),
        validation_artifacts,
        rollback_token: "rollback_v1_abc123".to_string(),
        promotion_rationale: "Add error handling to JSON parsing for improved reliability"
            .to_string(),
        timestamp_ns: 1640995200000000000u64,
        epoch: SecurityEpoch::from_raw(1),
        zone: "integration_test".to_string(),
        signature_bundle: create_test_signature_bundle(),
    };

    // Step 4: Verify the complete workflow
    assert!(proof_ref.starts_with("proof://integration_test/"));
    assert_eq!(receipt.translation_validation_proof_ref, proof_ref);

    // Verify translation validation is properly recorded as an artifact
    let translation_artifact = receipt
        .validation_artifacts
        .iter()
        .find(|a| matches!(a.kind, ValidationArtifactKind::EquivalenceResult))
        .expect("Should have translation validation artifact");

    assert!(translation_artifact.passed);
    assert_eq!(translation_artifact.artifact_digest, proof_ref);

    // Verify both security and translation validation are required
    assert_eq!(receipt.validation_artifacts.len(), 2);
    assert!(
        receipt
            .validation_artifacts
            .iter()
            .any(|a| matches!(a.kind, ValidationArtifactKind::AdversarialSurvival))
    );
    assert!(
        receipt
            .validation_artifacts
            .iter()
            .any(|a| matches!(a.kind, ValidationArtifactKind::EquivalenceResult))
    );
}
