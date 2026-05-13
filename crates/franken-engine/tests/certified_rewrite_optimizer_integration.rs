//! Integration coverage for the public certified rewrite optimizer boundary.
//!
//! Tracks bd-mw20e.1: the optimizer module is re-enabled, so this file now
//! exercises the live crate API instead of the old waiver text.

#![forbid(unsafe_code)]

use frankenengine_engine::certified_optimization_governance::OptimizationTier;
use frankenengine_engine::certified_rewrite_optimizer::{
    BEAD_ID, COMPONENT, CertifiedOptimizerError, CertifiedRewriteOptimizer, OptimizationRequest,
    RewriteRuleId, SCHEMA_VERSION, TranslationValidator, ValidationReceipt, ValidationResult,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::translation_validation::ValidationMode;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(607)
}

#[test]
fn public_optimizer_api_is_reenabled() {
    let optimizer = CertifiedRewriteOptimizer::new(epoch());
    assert_eq!(optimizer.security_epoch, epoch());
    assert!(optimizer.rewrite_packs.is_empty());

    let rule_id: RewriteRuleId = "identity_add_zero".to_string();
    assert_eq!(rule_id.as_str(), "identity_add_zero");

    let validator_type = std::any::type_name::<TranslationValidator>();
    assert!(validator_type.contains("TranslationValidationGate"));
    let _validator = TranslationValidator::new();

    let receipt = ValidationReceipt::new(format!("{COMPONENT}:integration-receipt"), true);
    let validation = ValidationResult::success(receipt);
    assert!(validation.is_valid());
    assert!(
        validation
            .receipt()
            .expect("validation result should carry a receipt")
            .validation_passed()
    );

    let tier_names: Vec<_> = OptimizationTier::ALL
        .iter()
        .map(|tier| tier.as_str())
        .collect();
    assert_eq!(
        tier_names.as_slice(),
        ["baseline", "standard", "aggressive", "speculative"]
    );

    let contract_id = format!("{SCHEMA_VERSION}:{COMPONENT}:{BEAD_ID}");
    assert!(contract_id.contains("certified-rewrite-optimizer"));
    assert!(contract_id.contains("certified_rewrite_optimizer"));
}

#[test]
fn public_optimizer_applies_validated_builtin_rewrite() {
    let mut optimizer = CertifiedRewriteOptimizer::new(epoch());
    let request = OptimizationRequest::new(
        "integration-identity-add-zero".to_string(),
        epoch(),
        OptimizationTier::Standard,
        "x + 0".to_string(),
    )
    .with_validation_mode(ValidationMode::SymbolicEquivalence {
        proof_hash: ContentHash::compute(b"integration-proof"),
    });

    let result = optimizer
        .optimize(request)
        .expect("enabled optimizer should run a supported built-in rewrite");

    assert!(result.success);
    assert_eq!(result.optimized_program.as_deref(), Some("x"));
    assert_eq!(result.optimization_steps.len(), 1);
    assert!(result.all_steps_validated());
    assert!(result.all_steps_certified());
    assert!(result.errors.is_empty());
    assert!(result.rollback_records.is_empty());
    assert_eq!(result.metrics.steps_performed, 1);
    assert_eq!(result.metrics.steps_validated, 1);
    assert_eq!(result.metrics.steps_certified, 1);

    let step = result
        .optimization_steps
        .first()
        .expect("supported rewrite should produce one step");
    assert_eq!(step.before_program, "x + 0");
    assert_eq!(step.after_program, "x");
    assert!(
        step.validation_receipt
            .as_ref()
            .expect("validated step should include a receipt")
            .validation_passed()
    );
    assert!(
        step.optimization_certificate.is_some(),
        "validated built-in rewrites should receive a certificate"
    );
}

#[test]
fn optimizer_rejects_tampered_request_hash_fail_closed() {
    let mut optimizer = CertifiedRewriteOptimizer::new(epoch());
    let mut request = OptimizationRequest::new(
        "integration-tampered-hash".to_string(),
        epoch(),
        OptimizationTier::Standard,
        "x + 0".to_string(),
    );
    request.input_program = "y + 0".to_string();

    let err = optimizer
        .optimize(request)
        .expect_err("tampered input hash must fail request validation");

    match err {
        CertifiedOptimizerError::InvalidRequest { reason, .. } => {
            assert!(reason.contains("input_hash"));
        }
        other => panic!("expected invalid request error, got {other:?}"),
    }
}
