//! Integration tests for the translation validation proof carrier.
//!
//! These tests pin the **fail-closed** contract between G.4's translation
//! validation pilot and V-track's `ReplacementReceipt` system: absent a genuine
//! per-slot validation engine the carrier must NOT fabricate a passing proof,
//! and must refuse to hand a promotion a proof reference it cannot stand behind.
//! See `bd-4uyi7` (reality-check: fabricated validation backing a constitutional
//! self-replacement receipt).

use frankenengine_engine::{
    security_epoch::SecurityEpoch,
    self_replacement::{
        ReplacementReceipt, SchemaVersion, SignatureBundle, ValidationArtifactKind,
        ValidationArtifactRef,
    },
    slot_registry::SlotId,
    translation_validation_proof_carrier::{
        TranslationValidationEngine, TranslationValidationError, TranslationValidationProof,
        ValidationResult, create_slot_specification, validate_promotion_and_get_proof_ref,
    },
};

/// Create a test signature bundle.
fn create_test_signature_bundle() -> SignatureBundle {
    SignatureBundle::new(1)
}

#[test]
fn test_default_engine_is_fail_closed() {
    // The default engine has no real per-slot validation pipeline wired, so it
    // must emit an UNPROVEN result rather than fabricating a passing proof.
    let engine = TranslationValidationEngine::default();

    let source_slot = SlotId::new("parser-v1").expect("valid slot ID");
    let target_slot = SlotId::new("parser-v2").expect("valid slot ID");

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

    let proof = engine
        .validate_slot_promotion(&source_spec, &target_spec)
        .expect("a (fail-closed) proof artifact is still produced");

    assert!(
        !proof.is_valid(),
        "fail-closed default must not fabricate a valid proof"
    );
    assert!(matches!(
        proof.validation_result,
        ValidationResult::Error { .. }
    ));
    assert!(proof.summary().contains("ERROR"));
    assert_eq!(proof.source_spec.slot_id.as_str(), "parser-v1");
    assert_eq!(proof.target_spec.slot_id.as_str(), "parser-v2");
    // The witness/digest are no longer fabricated placeholders.
    assert!(proof.transformation_witness.is_empty());
    assert_ne!(proof.test_case_digest, "synthetic_test_digest");
}

#[test]
fn test_slot_specification_creation() {
    let slot_id = SlotId::new("test-parser").expect("valid slot ID");
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
fn test_promotion_helper_refuses_unproven_reference() {
    // `validate_promotion_and_get_proof_ref` must fail closed: with no genuine
    // validation it returns ValidationNotProven instead of minting a reference
    // that would otherwise be folded into a constitutional receipt.
    let old_code = b"function add(a, b) { return a + b; }";
    let new_code = b"function add(a, b) { return (a | 0) + (b | 0); }";

    let old_slot = SlotId::new("math-v1").expect("valid slot ID");
    let new_slot = SlotId::new("math-v2").expect("valid slot ID");

    let result =
        validate_promotion_and_get_proof_ref(old_slot, new_slot, old_code, new_code, "test_zone");

    match result {
        Err(TranslationValidationError::ValidationNotProven(_)) => {}
        other => panic!(
            "expected ValidationNotProven (fail-closed), got {:?}",
            other
        ),
    }
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
fn test_store_and_retrieve_proof_round_trip() {
    // store_proof / retrieve_proof genuinely persist and read back a proof —
    // they no longer fabricate a reference / always return ProofNotFound.
    let engine = TranslationValidationEngine::default();

    let slot_id = SlotId::new("rt-slot").expect("valid slot ID");
    let proof = TranslationValidationProof {
        proof_id: frankenengine_engine::engine_object_id::EngineObjectId([9u8; 32]),
        source_spec: create_slot_specification(slot_id.clone(), b"old", "javascript"),
        target_spec: create_slot_specification(slot_id, b"new", "javascript"),
        validation_result: ValidationResult::Error {
            error_message: "fail-closed unproven".to_string(),
            error_code:
                frankenengine_engine::translation_validation_proof_carrier::ValidationErrorCode::InternalError,
        },
        validation_logs: vec!["fail-closed".to_string()],
        formal_proof_ref: None,
        transformation_witness: Vec::new(),
        test_case_digest: "integration_rt_digest".to_string(),
        validation_timestamp_ns: 7,
        security_epoch: SecurityEpoch::from_raw(1),
        zone: "default".to_string(),
    };

    let proof_ref = engine.store_proof(&proof).expect("store should persist");
    assert!(proof_ref.starts_with("proof://default/"));

    let retrieved = engine
        .retrieve_proof(&proof_ref)
        .expect("retrieve should read the proof back");
    assert_eq!(retrieved.proof_id, proof.proof_id);
    assert_eq!(retrieved.test_case_digest, proof.test_case_digest);
    assert_eq!(retrieved.validation_result, proof.validation_result);

    // An unknown reference is genuinely not found (not a hard-coded error).
    assert!(matches!(
        engine.retrieve_proof("proof://default/0000000000000000"),
        Err(TranslationValidationError::ProofNotFound(_))
    ));
}

#[test]
fn test_receipt_records_unproven_equivalence_honestly() {
    // When validation is unproven, the convenience producer refuses a ref, and
    // any receipt assembled for audit must record the equivalence artifact as
    // NOT passed — never a fabricated `passed: true`.
    let engine = TranslationValidationEngine::default();

    let old_slot = SlotId::new("legacy-parser").expect("valid slot ID");
    let new_slot = SlotId::new("optimized-parser").expect("valid slot ID");
    let old_code = b"function parseData(input) { return JSON.parse(input); }";
    let new_code =
        b"function parseData(input) { try { return JSON.parse(input); } catch { return null; } }";

    // The producer fails closed.
    let refused = validate_promotion_and_get_proof_ref(
        old_slot.clone(),
        new_slot.clone(),
        old_code,
        new_code,
        "production",
    );
    assert!(matches!(
        refused,
        Err(TranslationValidationError::ValidationNotProven(_))
    ));

    // A proof artifact is still produced (unproven) and is genuinely storable.
    let source_spec = create_slot_specification(old_slot.clone(), old_code, "javascript");
    let target_spec = create_slot_specification(new_slot.clone(), new_code, "javascript");
    let proof = engine
        .validate_slot_promotion(&source_spec, &target_spec)
        .expect("unproven proof artifact");
    assert!(!proof.is_valid());
    let proof_ref = engine.store_proof(&proof).expect("store proof");

    let receipt_id = ReplacementReceipt::derive_receipt_id(
        &old_slot,
        &old_slot,
        &new_slot,
        "digest_legacy_abc123",
        "digest_optimized_def456",
        &proof_ref,
        "genesis_chain_001",
        1640995200000000000u64,
        "production",
    )
    .expect("valid receipt ID");

    // The equivalence artifact honestly reflects proof.is_valid() (= false).
    let validation_artifacts = vec![
        ValidationArtifactRef {
            kind: ValidationArtifactKind::PerformanceBenchmark,
            artifact_digest: "perf_evidence_hash".to_string(),
            passed: true,
            summary: "Performance benchmark completed successfully".to_string(),
        },
        ValidationArtifactRef {
            kind: ValidationArtifactKind::EquivalenceResult,
            artifact_digest: proof_ref.clone(),
            passed: proof.is_valid(),
            summary: format!("translation validation UNPROVEN: {}", proof.summary()),
        },
    ];

    let receipt = ReplacementReceipt {
        receipt_id,
        schema_version: SchemaVersion::V1,
        slot_id: old_slot.clone(),
        old_slot_id: old_slot,
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

    assert_eq!(receipt.translation_validation_proof_ref, proof_ref);

    let translation_artifact = receipt
        .validation_artifacts
        .iter()
        .find(|a| matches!(a.kind, ValidationArtifactKind::EquivalenceResult))
        .expect("translation validation artifact should exist");

    assert!(
        !translation_artifact.passed,
        "an unproven equivalence must not be recorded as passed"
    );
    assert_eq!(translation_artifact.artifact_digest, proof_ref);
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
fn test_proof_summary_formatting_for_unproven() {
    let engine = TranslationValidationEngine::default();
    let slot_id = SlotId::new("test-slot").expect("valid slot ID");

    let source_spec = create_slot_specification(slot_id.clone(), b"let x = 1 + 2;", "javascript");
    let target_spec = create_slot_specification(slot_id, b"let x = 3;", "javascript");

    let proof = engine
        .validate_slot_promotion(&source_spec, &target_spec)
        .expect("proof artifact");

    let summary = proof.summary();
    // Fail-closed default summarises as an ERROR, never a fabricated PASS.
    assert!(summary.contains("Translation validation"));
    assert!(summary.contains("ERROR"));
    assert!(!summary.contains("PASSED"));
}

#[test]
fn test_engine_configuration() {
    use frankenengine_engine::translation_validation_proof_carrier::ValidationExecutionMode;

    let custom_project_root = "/custom/path";
    let custom_zone = "staging";

    let engine = TranslationValidationEngine::new(custom_project_root, custom_zone.to_string());

    assert_eq!(engine.project_root.to_str(), Some(custom_project_root));
    assert_eq!(engine.zone, custom_zone);
    assert_eq!(engine.minimum_success_rate, 95); // Default value
    assert!(!engine.enable_formal_verification); // Default value
    // Fail-closed is the safe default execution mode.
    assert_eq!(engine.execution_mode, ValidationExecutionMode::FailClosed);

    let expected_script = format!(
        "{}/scripts/run_rgc_translation_validation_pilot.sh",
        custom_project_root
    );
    assert_eq!(
        engine.validation_script.to_str(),
        Some(expected_script.as_str())
    );
}

/// Full workflow: a fail-closed validation must block the promotion path from
/// obtaining a proof reference, so a constitutional receipt cannot silently
/// carry a fabricated equivalence proof.
#[test]
fn test_full_promotion_workflow_blocks_on_unproven() {
    let old_slot = SlotId::new("json-parser-v1").expect("valid slot ID");
    let new_slot = SlotId::new("json-parser-v2").expect("valid slot ID");

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

    let proof_ref = validate_promotion_and_get_proof_ref(
        old_slot,
        new_slot,
        old_implementation,
        new_implementation,
        "integration_test",
    );

    // The promotion cannot proceed with a fabricated proof: it is refused.
    match proof_ref {
        Err(TranslationValidationError::ValidationNotProven(summary)) => {
            assert!(summary.contains("ERROR") || summary.contains("Translation validation"));
        }
        other => panic!("expected fail-closed ValidationNotProven, got {:?}", other),
    }
}
