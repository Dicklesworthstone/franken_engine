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
        "2 + 0".to_string(),
    )
    .with_validation_mode(ValidationMode::SymbolicEquivalence {
        proof_hash: ContentHash::compute(b"integration-proof"),
    });

    let result = optimizer
        .optimize(request)
        .expect("enabled optimizer should run a supported built-in rewrite");

    assert!(result.success);
    assert_eq!(result.optimized_program.as_deref(), Some("2"));
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
    assert_eq!(step.before_program, "2 + 0");
    assert_eq!(step.after_program, "2");
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

#[test]
fn unknown_or_effectful_operands_remain_on_baseline() {
    for input in [
        "x + 0",
        "0 + x",
        "x * 1",
        "x * 0",
        "0 * x",
        "effect() * 0",
        "object.value * 0",
        "missing * 0",
        "'5' + 0",
        "1n * 0",
        "Infinity * 0",
        "(effect(), 1) * 0",
        "1; effect() * 0",
    ] {
        let mut optimizer = CertifiedRewriteOptimizer::new(epoch());
        let request = OptimizationRequest::new(
            format!("unsafe-identity:{input}"),
            epoch(),
            OptimizationTier::Standard,
            input.to_string(),
        );
        let result = optimizer.optimize(request).expect("baseline fallback");
        assert!(result.success);
        assert_eq!(result.optimized_program.as_deref(), Some(input));
        assert!(result.optimization_steps.is_empty(), "{input}");
        assert_eq!(result.metrics.steps_certified, 0);
        assert!(!result.all_steps_certified());
    }
}

#[test]
fn public_optimizer_preserves_number_semantics() {
    for (input, output) in [
        ("5 / 2", "2.5"),
        ("-3 * 0", "-0"),
        ("-0 + 0", "0"),
        ("(1 + 2) * 3", "9"),
        ("1 + 2 * 3", "7"),
        ("0.1 + 0.2", "0.30000000000000004"),
        ("9007199254740993 - 9007199254740992", "0"),
    ] {
        let mut optimizer = CertifiedRewriteOptimizer::new(epoch());
        let request = OptimizationRequest::new(
            format!("number-semantics:{input}"),
            epoch(),
            OptimizationTier::Standard,
            input.to_string(),
        );
        let result = optimizer.optimize(request).expect("pure Number rewrite");
        assert!(result.success);
        assert_eq!(result.optimized_program.as_deref(), Some(output));
        assert_eq!(result.optimization_steps.len(), 1);
        assert!(result.all_steps_validated());
        assert!(result.all_steps_certified());
    }
}

#[test]
fn requests_cannot_cross_security_epochs() {
    for request_epoch in [SecurityEpoch::from_raw(606), SecurityEpoch::from_raw(608)] {
        let mut optimizer = CertifiedRewriteOptimizer::new(epoch());
        let request = OptimizationRequest::new(
            "cross-epoch".to_string(),
            request_epoch,
            OptimizationTier::Standard,
            "2 + 3".to_string(),
        );
        let error = optimizer.optimize(request).expect_err("epoch mismatch");
        assert!(matches!(
            error,
            CertifiedOptimizerError::InvalidRequest { reason, .. }
                if reason.contains("security_epoch")
        ));
    }
}

#[test]
fn required_certificate_failure_aborts_optimization() {
    let exhausted = SecurityEpoch::from_raw(u64::MAX);
    let mut optimizer = CertifiedRewriteOptimizer::new(exhausted);
    let request = OptimizationRequest::new(
        "required-certificate".to_string(),
        exhausted,
        OptimizationTier::Standard,
        "2 + 3".to_string(),
    );
    let error = optimizer.optimize(request).expect_err("certificate cannot expire");
    match error {
        CertifiedOptimizerError::CertificationFailed {
            request_id,
            step_number,
            reason,
        } => {
            assert_eq!(request_id, "required-certificate");
            assert_eq!(step_number, 0);
            assert!(reason.contains("epoch exhaustion"));
        }
        other => panic!("expected certification failure, got {other:?}"),
    }
}

#[test]
fn optional_proofs_do_not_fabricate_certificates() {
    let exhausted = SecurityEpoch::from_raw(u64::MAX);
    let mut optimizer = CertifiedRewriteOptimizer::new(exhausted);
    let request = OptimizationRequest::new(
        "optional-certificate".to_string(),
        exhausted,
        OptimizationTier::Standard,
        "2 + 3".to_string(),
    )
    .with_formal_proofs(false);
    let result = optimizer.optimize(request).expect("explicitly optional proof");
    assert_eq!(result.optimized_program.as_deref(), Some("5"));
    assert!(result.all_steps_validated());
    assert!(!result.all_steps_certified());
    assert_eq!(result.metrics.steps_certified, 0);
}

#[test]
fn invalid_or_missing_receipt_cannot_authorize_activation() {
    let invalid = ValidationReceipt::new("failed-receipt".to_string(), false);
    assert!(!ValidationResult::success(invalid).is_valid());

    let valid = ValidationResult::success(ValidationReceipt::new("valid".to_string(), true));
    let mut encoded = serde_json::to_value(valid).expect("encode result");
    encoded["receipt"] = serde_json::Value::Null;
    let forged: ValidationResult = serde_json::from_value(encoded).expect("decode result");
    assert!(!forged.is_valid());
}

#[test]
fn evidence_binds_the_complete_validation_mode() {
    let hash_a = ContentHash::compute(b"artifact-a");
    let hash_b = ContentHash::compute(b"artifact-b");
    for (mode_a, mode_b) in [
        (
            ValidationMode::GoldenCorpusReplay { corpus_hash: hash_a, vector_count: 5 },
            ValidationMode::GoldenCorpusReplay { corpus_hash: hash_b, vector_count: 5 },
        ),
        (
            ValidationMode::SymbolicEquivalence { proof_hash: hash_a },
            ValidationMode::SymbolicEquivalence { proof_hash: hash_b },
        ),
        (
            ValidationMode::DifferentialTrace { workload_hash: hash_a, trace_pair_count: 5 },
            ValidationMode::DifferentialTrace { workload_hash: hash_b, trace_pair_count: 5 },
        ),
    ] {
        let receipt_for = |mode: ValidationMode| {
            let mut optimizer = CertifiedRewriteOptimizer::new(epoch());
            let request = OptimizationRequest::new(
                "mode-binding".to_string(),
                epoch(),
                OptimizationTier::Standard,
                "2 + 3".to_string(),
            )
            .with_validation_mode(mode);
            optimizer
                .optimize(request)
                .expect("valid request")
                .optimization_steps[0]
                .validation_receipt
                .clone()
                .expect("receipt")
        };
        let receipt_a = receipt_for(mode_a.clone());
        let receipt_b = receipt_for(mode_b);
        assert_ne!(receipt_a.receipt_id, receipt_b.receipt_id);
        assert_eq!(receipt_a.before_hash, receipt_b.before_hash);
        assert_eq!(receipt_a.after_hash, receipt_b.after_hash);
        assert_eq!(receipt_a, receipt_for(mode_a));
    }
}

#[test]
fn certificate_witnesses_are_bound_to_the_issuing_epoch() {
    let certificate_for = |epoch: SecurityEpoch| {
        let mut optimizer = CertifiedRewriteOptimizer::new(epoch);
        let request = OptimizationRequest::new(
            "certificate-epoch-binding".to_string(),
            epoch,
            OptimizationTier::Standard,
            "2 + 3".to_string(),
        );
        optimizer
            .optimize(request)
            .expect("valid request")
            .optimization_steps[0]
            .optimization_certificate
            .clone()
            .expect("certificate")
    };
    let first = certificate_for(epoch());
    let second = certificate_for(epoch().next());
    assert_ne!(first.cert_id, second.cert_id);
    assert_ne!(first.proof_hash, second.proof_hash);
    assert_eq!(first.issued_epoch, epoch());
    assert_eq!(first.expiry_epoch, epoch().next());
}
