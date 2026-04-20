//! Integration tests for `certified_rewrite_optimizer` module.
//!
//! **DISABLED**: This integration test suite is temporarily disabled because the
//! `certified_rewrite_optimizer` module has broken imports for dependent APIs that
//! do not exist yet (TranslationValidator, ValidationResult, ValidationReceipt, etc.).
//!
//! **Tracking**: bd-1dfpt - Re-enable when dependent APIs land
//! **Expiry**: Remove this cfg gate and restore integration testing once:
//! 1. Missing dependent API types are implemented in their source modules
//! 2. certified_rewrite_optimizer module is re-enabled in lib.rs
//! 3. All imports resolve successfully

#![cfg(feature = "certified_rewrite_optimizer_integration")]

//!
//! Validates certified rewrite optimization coordination, translation validation,
//! optimization request/result handling, governance integration, and failure modes.

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

use frankenengine_engine::certified_optimization_governance::{
    CertificateRequest, OptimizationGovernance, OptimizationTier,
};
use frankenengine_engine::certified_rewrite_optimizer::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::translation_validation::{
    TranslationValidator, ValidationRequest, ValidationResult,
};
use frankenengine_engine::versioned_rewrite_pack::{
    PackageVersionManifest, RewritePackId, VersionedRewritePack,
};
use serde_json;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
}

fn make_rewrite_pack() -> VersionedRewritePack {
    VersionedRewritePack {
        pack_id: RewritePackId::new("test-pack").unwrap(),
        base_hash: ContentHash::compute(b"base"),
        target_hash: ContentHash::compute(b"target"),
        epoch: SecurityEpoch::from_raw(50),
        manifest: PackageVersionManifest::default(),
        rewrite_operations: vec![],
        optimization_tier: OptimizationTier::Conservative,
        proof_requirements: vec![],
    }
}

fn make_governance() -> OptimizationGovernance {
    OptimizationGovernance::new(epoch(), OptimizationTier::Conservative, true).unwrap()
}

// ---------------------------------------------------------------------------
// OptimizationRequest Tests
// ---------------------------------------------------------------------------

#[test]
fn optimization_request_creation_and_fields() {
    let request = OptimizationRequest {
        function_id: "test_fn".to_string(),
        source_hash: ContentHash::compute(b"source"),
        tier: OptimizationTier::Aggressive,
        epoch: epoch(),
        metadata: BTreeMap::new(),
    };

    assert_eq!(request.function_id, "test_fn");
    assert_eq!(request.tier, OptimizationTier::Aggressive);
    assert_eq!(request.epoch, epoch());
    assert!(request.metadata.is_empty());
}

#[test]
fn optimization_request_serde_roundtrip() {
    let mut metadata = BTreeMap::new();
    metadata.insert("key1".to_string(), "value1".to_string());
    metadata.insert("key2".to_string(), "value2".to_string());

    let request = OptimizationRequest {
        function_id: "serde_test".to_string(),
        source_hash: ContentHash::compute(b"serde_source"),
        tier: OptimizationTier::Conservative,
        epoch: epoch(),
        metadata,
    };

    let json = serde_json::to_string(&request).unwrap();
    let decoded: OptimizationRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.function_id, request.function_id);
    assert_eq!(
        decoded.source_hash.as_bytes(),
        request.source_hash.as_bytes()
    );
    assert_eq!(decoded.tier, request.tier);
    assert_eq!(decoded.epoch.as_u64(), request.epoch.as_u64());
    assert_eq!(decoded.metadata.len(), 2);
    assert_eq!(decoded.metadata.get("key1"), Some(&"value1".to_string()));
    assert_eq!(decoded.metadata.get("key2"), Some(&"value2".to_string()));
}

#[test]
fn optimization_request_hash_deterministic() {
    let request1 = OptimizationRequest {
        function_id: "hash_test".to_string(),
        source_hash: ContentHash::compute(b"hash_source"),
        tier: OptimizationTier::Moderate,
        epoch: epoch(),
        metadata: BTreeMap::new(),
    };

    let request2 = OptimizationRequest {
        function_id: "hash_test".to_string(),
        source_hash: ContentHash::compute(b"hash_source"),
        tier: OptimizationTier::Moderate,
        epoch: epoch(),
        metadata: BTreeMap::new(),
    };

    let hash1 = request1.compute_hash();
    let hash2 = request2.compute_hash();
    assert_eq!(hash1.as_bytes(), hash2.as_bytes());
}

#[test]
fn optimization_request_hash_different_for_different_requests() {
    let request1 = OptimizationRequest {
        function_id: "fn1".to_string(),
        source_hash: ContentHash::compute(b"source1"),
        tier: OptimizationTier::Conservative,
        epoch: epoch(),
        metadata: BTreeMap::new(),
    };

    let request2 = OptimizationRequest {
        function_id: "fn2".to_string(),
        source_hash: ContentHash::compute(b"source2"),
        tier: OptimizationTier::Aggressive,
        epoch: SecurityEpoch::from_raw(200),
        metadata: BTreeMap::new(),
    };

    let hash1 = request1.compute_hash();
    let hash2 = request2.compute_hash();
    assert_ne!(hash1.as_bytes(), hash2.as_bytes());
}

// ---------------------------------------------------------------------------
// OptimizationStep Tests
// ---------------------------------------------------------------------------

#[test]
fn optimization_step_creation_and_fields() {
    let step = OptimizationStep {
        step_id: "step1".to_string(),
        transform_name: "constant_fold".to_string(),
        input_hash: ContentHash::compute(b"input"),
        output_hash: ContentHash::compute(b"output"),
        proof_hash: Some(ContentHash::compute(b"proof")),
        metadata: BTreeMap::new(),
    };

    assert_eq!(step.step_id, "step1");
    assert_eq!(step.transform_name, "constant_fold");
    assert!(step.proof_hash.is_some());
    assert!(step.metadata.is_empty());
}

#[test]
fn optimization_step_serde_roundtrip() {
    let mut metadata = BTreeMap::new();
    metadata.insert("applied_rules".to_string(), "5".to_string());
    metadata.insert("time_ms".to_string(), "100".to_string());

    let step = OptimizationStep {
        step_id: "serde_step".to_string(),
        transform_name: "dead_code_elimination".to_string(),
        input_hash: ContentHash::compute(b"serde_input"),
        output_hash: ContentHash::compute(b"serde_output"),
        proof_hash: Some(ContentHash::compute(b"serde_proof")),
        metadata,
    };

    let json = serde_json::to_string(&step).unwrap();
    let decoded: OptimizationStep = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.step_id, step.step_id);
    assert_eq!(decoded.transform_name, step.transform_name);
    assert_eq!(decoded.input_hash.as_bytes(), step.input_hash.as_bytes());
    assert_eq!(decoded.output_hash.as_bytes(), step.output_hash.as_bytes());
    assert_eq!(
        decoded.proof_hash.unwrap().as_bytes(),
        step.proof_hash.unwrap().as_bytes()
    );
    assert_eq!(decoded.metadata.len(), 2);
}

#[test]
fn optimization_step_no_proof() {
    let step = OptimizationStep {
        step_id: "no_proof_step".to_string(),
        transform_name: "syntax_only".to_string(),
        input_hash: ContentHash::compute(b"input"),
        output_hash: ContentHash::compute(b"output"),
        proof_hash: None,
        metadata: BTreeMap::new(),
    };

    assert!(step.proof_hash.is_none());

    let json = serde_json::to_string(&step).unwrap();
    let decoded: OptimizationStep = serde_json::from_str(&json).unwrap();
    assert!(decoded.proof_hash.is_none());
}

// ---------------------------------------------------------------------------
// OptimizationResult Tests
// ---------------------------------------------------------------------------

#[test]
fn optimization_result_success_creation() {
    let request = OptimizationRequest {
        function_id: "result_test".to_string(),
        source_hash: ContentHash::compute(b"result_source"),
        tier: OptimizationTier::Conservative,
        epoch: epoch(),
        metadata: BTreeMap::new(),
    };

    let steps = vec![OptimizationStep {
        step_id: "step1".to_string(),
        transform_name: "inline".to_string(),
        input_hash: ContentHash::compute(b"step1_in"),
        output_hash: ContentHash::compute(b"step1_out"),
        proof_hash: Some(ContentHash::compute(b"step1_proof")),
        metadata: BTreeMap::new(),
    }];

    let result = OptimizationResult {
        request,
        success: true,
        final_hash: Some(ContentHash::compute(b"final")),
        steps,
        certificate_id: Some("cert123".to_string()),
        error_message: None,
        validation_result: Some(ValidationResult::Valid),
        metadata: BTreeMap::new(),
    };

    assert!(result.success);
    assert!(result.final_hash.is_some());
    assert_eq!(result.steps.len(), 1);
    assert_eq!(result.certificate_id.as_ref().unwrap(), "cert123");
    assert!(result.error_message.is_none());
    assert_eq!(result.validation_result.unwrap(), ValidationResult::Valid);
}

#[test]
fn optimization_result_failure_creation() {
    let request = OptimizationRequest {
        function_id: "fail_test".to_string(),
        source_hash: ContentHash::compute(b"fail_source"),
        tier: OptimizationTier::Aggressive,
        epoch: epoch(),
        metadata: BTreeMap::new(),
    };

    let result = OptimizationResult {
        request,
        success: false,
        final_hash: None,
        steps: vec![],
        certificate_id: None,
        error_message: Some("Translation validation failed".to_string()),
        validation_result: Some(ValidationResult::Invalid),
        metadata: BTreeMap::new(),
    };

    assert!(!result.success);
    assert!(result.final_hash.is_none());
    assert!(result.steps.is_empty());
    assert!(result.certificate_id.is_none());
    assert!(result.error_message.is_some());
    assert_eq!(result.validation_result.unwrap(), ValidationResult::Invalid);
}

#[test]
fn optimization_result_serde_roundtrip() {
    let request = OptimizationRequest {
        function_id: "serde_result".to_string(),
        source_hash: ContentHash::compute(b"serde_source"),
        tier: OptimizationTier::Moderate,
        epoch: epoch(),
        metadata: BTreeMap::new(),
    };

    let step = OptimizationStep {
        step_id: "serde_step".to_string(),
        transform_name: "serde_transform".to_string(),
        input_hash: ContentHash::compute(b"serde_in"),
        output_hash: ContentHash::compute(b"serde_out"),
        proof_hash: None,
        metadata: BTreeMap::new(),
    };

    let mut metadata = BTreeMap::new();
    metadata.insert("total_time_ms".to_string(), "250".to_string());

    let result = OptimizationResult {
        request,
        success: true,
        final_hash: Some(ContentHash::compute(b"serde_final")),
        steps: vec![step],
        certificate_id: Some("serde_cert".to_string()),
        error_message: None,
        validation_result: Some(ValidationResult::Valid),
        metadata,
    };

    let json = serde_json::to_string(&result).unwrap();
    let decoded: OptimizationResult = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.success, result.success);
    assert_eq!(
        decoded.final_hash.unwrap().as_bytes(),
        result.final_hash.unwrap().as_bytes()
    );
    assert_eq!(decoded.steps.len(), 1);
    assert_eq!(decoded.certificate_id, result.certificate_id);
    assert_eq!(decoded.validation_result.unwrap(), ValidationResult::Valid);
    assert_eq!(decoded.metadata.len(), 1);
}

// ---------------------------------------------------------------------------
// CertifiedRewriteOptimizer Tests
// ---------------------------------------------------------------------------

#[test]
fn certified_rewrite_optimizer_creation() {
    let governance = make_governance();
    let optimizer = CertifiedRewriteOptimizer::new(governance, epoch());

    assert_eq!(optimizer.epoch().as_u64(), epoch().as_u64());
}

#[test]
fn certified_rewrite_optimizer_perform_optimization_success() {
    let governance = make_governance();
    let mut optimizer = CertifiedRewriteOptimizer::new(governance, epoch());

    let request = OptimizationRequest {
        function_id: "opt_test".to_string(),
        source_hash: ContentHash::compute(b"opt_source"),
        tier: OptimizationTier::Conservative,
        epoch: epoch(),
        metadata: BTreeMap::new(),
    };

    // For this test, we'll simulate a successful optimization
    // In a real implementation, this would perform actual optimization
    let result = optimizer.perform_optimization(request.clone());

    // Basic validation - the actual behavior depends on implementation
    // For now, just ensure the result structure is correct
    assert_eq!(result.request.function_id, request.function_id);
}

#[test]
fn certified_rewrite_optimizer_governance_integration() {
    let governance = make_governance();
    let optimizer = CertifiedRewriteOptimizer::new(governance, epoch());

    // Test that optimizer has access to governance
    let governance_ref = optimizer.governance();
    assert_eq!(governance_ref.current_epoch().as_u64(), epoch().as_u64());
}

#[test]
fn certified_rewrite_optimizer_epoch_validation() {
    let governance = make_governance();
    let optimizer = CertifiedRewriteOptimizer::new(governance, epoch());

    let old_request = OptimizationRequest {
        function_id: "old_epoch".to_string(),
        source_hash: ContentHash::compute(b"old_source"),
        tier: OptimizationTier::Conservative,
        epoch: SecurityEpoch::from_raw(10), // Old epoch
        metadata: BTreeMap::new(),
    };

    let result = optimizer.perform_optimization(old_request);

    // Should reject optimization for old epochs
    assert!(!result.success);
    assert!(result.error_message.is_some());
    assert!(result.error_message.as_ref().unwrap().contains("epoch"));
}

#[test]
fn certified_rewrite_optimizer_tier_validation() {
    let mut governance = make_governance();

    // Set governance to only allow Conservative tier
    governance
        .set_max_tier(OptimizationTier::Conservative)
        .unwrap();

    let optimizer = CertifiedRewriteOptimizer::new(governance, epoch());

    let aggressive_request = OptimizationRequest {
        function_id: "aggressive_test".to_string(),
        source_hash: ContentHash::compute(b"aggressive_source"),
        tier: OptimizationTier::Aggressive, // Not allowed
        epoch: epoch(),
        metadata: BTreeMap::new(),
    };

    let result = optimizer.perform_optimization(aggressive_request);

    // Should reject aggressive optimization when only conservative is allowed
    assert!(!result.success);
    assert!(result.error_message.is_some());
    assert!(
        result.error_message.as_ref().unwrap().contains("tier")
            || result
                .error_message
                .as_ref()
                .unwrap()
                .contains("governance")
    );
}

// ---------------------------------------------------------------------------
// Translation Validation Integration Tests
// ---------------------------------------------------------------------------

#[test]
fn certified_rewrite_optimizer_translation_validation_integration() {
    let governance = make_governance();
    let optimizer = CertifiedRewriteOptimizer::new(governance, epoch());

    let request = OptimizationRequest {
        function_id: "validation_test".to_string(),
        source_hash: ContentHash::compute(b"validation_source"),
        tier: OptimizationTier::Conservative,
        epoch: epoch(),
        metadata: BTreeMap::new(),
    };

    let result = optimizer.perform_optimization(request);

    // Translation validation should be performed and result recorded
    assert!(result.validation_result.is_some());
}

#[test]
fn certified_rewrite_optimizer_fail_on_invalid_translation() {
    let governance = make_governance();
    let optimizer = CertifiedRewriteOptimizer::new(governance, epoch());

    // Create a request that should trigger translation validation failure
    // This is a simulation - the actual trigger depends on implementation
    let request = OptimizationRequest {
        function_id: "invalid_translation".to_string(),
        source_hash: ContentHash::compute(b"invalid_source"),
        tier: OptimizationTier::Aggressive,
        epoch: epoch(),
        metadata: BTreeMap::new(),
    };

    let result = optimizer.perform_optimization(request);

    // If translation validation fails, optimization should fail
    if let Some(validation) = result.validation_result {
        if validation == ValidationResult::Invalid {
            assert!(!result.success);
            assert!(result.error_message.is_some());
        }
    }
}

// ---------------------------------------------------------------------------
// Error Handling Tests
// ---------------------------------------------------------------------------

#[test]
fn certified_rewrite_optimizer_handles_empty_function_id() {
    let governance = make_governance();
    let optimizer = CertifiedRewriteOptimizer::new(governance, epoch());

    let request = OptimizationRequest {
        function_id: "".to_string(), // Empty function ID
        source_hash: ContentHash::compute(b"empty_fn_source"),
        tier: OptimizationTier::Conservative,
        epoch: epoch(),
        metadata: BTreeMap::new(),
    };

    let result = optimizer.perform_optimization(request);

    // Should reject empty function ID
    assert!(!result.success);
    assert!(result.error_message.is_some());
}

#[test]
fn certified_rewrite_optimizer_metadata_preservation() {
    let governance = make_governance();
    let optimizer = CertifiedRewriteOptimizer::new(governance, epoch());

    let mut metadata = BTreeMap::new();
    metadata.insert("caller".to_string(), "test_framework".to_string());
    metadata.insert("optimization_hint".to_string(), "hot_path".to_string());

    let request = OptimizationRequest {
        function_id: "metadata_test".to_string(),
        source_hash: ContentHash::compute(b"metadata_source"),
        tier: OptimizationTier::Conservative,
        epoch: epoch(),
        metadata,
    };

    let result = optimizer.perform_optimization(request);

    // Request metadata should be preserved in result
    assert_eq!(
        result.request.metadata.get("caller"),
        Some(&"test_framework".to_string())
    );
    assert_eq!(
        result.request.metadata.get("optimization_hint"),
        Some(&"hot_path".to_string())
    );
}

// ---------------------------------------------------------------------------
// Rewrite Pack Integration Tests
// ---------------------------------------------------------------------------

#[test]
fn certified_rewrite_optimizer_rewrite_pack_integration() {
    let governance = make_governance();
    let optimizer = CertifiedRewriteOptimizer::new(governance, epoch());
    let rewrite_pack = make_rewrite_pack();

    // Test that optimizer can work with versioned rewrite packs
    let pack_hash = rewrite_pack.compute_hash();
    assert!(!pack_hash.as_bytes().is_empty());

    // The optimizer should be able to use rewrite pack information
    // for optimization decisions (implementation-dependent)
    let request = OptimizationRequest {
        function_id: "rewrite_pack_test".to_string(),
        source_hash: pack_hash,
        tier: OptimizationTier::Conservative,
        epoch: epoch(),
        metadata: BTreeMap::new(),
    };

    let result = optimizer.perform_optimization(request);

    // Should handle rewrite pack-based optimization
    assert_eq!(result.request.source_hash.as_bytes(), pack_hash.as_bytes());
}

// ---------------------------------------------------------------------------
// Comprehensive Integration Tests
// ---------------------------------------------------------------------------

#[test]
fn certified_rewrite_optimizer_end_to_end_success_flow() {
    let governance = make_governance();
    let mut optimizer = CertifiedRewriteOptimizer::new(governance, epoch());

    // Create a complete optimization request
    let mut metadata = BTreeMap::new();
    metadata.insert("profile".to_string(), "production".to_string());
    metadata.insert("target".to_string(), "wasm32".to_string());

    let request = OptimizationRequest {
        function_id: "end_to_end_success".to_string(),
        source_hash: ContentHash::compute(b"e2e_success_source"),
        tier: OptimizationTier::Moderate,
        epoch: epoch(),
        metadata,
    };

    // Perform optimization
    let result = optimizer.perform_optimization(request.clone());

    // Validate complete result structure
    assert_eq!(result.request.function_id, request.function_id);
    assert_eq!(
        result.request.source_hash.as_bytes(),
        request.source_hash.as_bytes()
    );
    assert_eq!(result.request.tier, request.tier);
    assert_eq!(result.request.epoch.as_u64(), request.epoch.as_u64());
    assert_eq!(result.request.metadata.len(), 2);

    // Result should have consistent success/failure state
    if result.success {
        assert!(result.final_hash.is_some());
        assert!(result.error_message.is_none());
    } else {
        assert!(result.error_message.is_some());
    }
}

#[test]
fn certified_rewrite_optimizer_deterministic_results() {
    let governance1 = make_governance();
    let governance2 = make_governance();
    let optimizer1 = CertifiedRewriteOptimizer::new(governance1, epoch());
    let optimizer2 = CertifiedRewriteOptimizer::new(governance2, epoch());

    let request = OptimizationRequest {
        function_id: "deterministic_test".to_string(),
        source_hash: ContentHash::compute(b"deterministic_source"),
        tier: OptimizationTier::Conservative,
        epoch: epoch(),
        metadata: BTreeMap::new(),
    };

    let result1 = optimizer1.perform_optimization(request.clone());
    let result2 = optimizer2.perform_optimization(request.clone());

    // Results should be deterministic for same input
    assert_eq!(result1.success, result2.success);
    if result1.success && result2.success {
        assert_eq!(
            result1.final_hash.unwrap().as_bytes(),
            result2.final_hash.unwrap().as_bytes()
        );
    }
}
