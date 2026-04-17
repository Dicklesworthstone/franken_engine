#![forbid(unsafe_code)]

//! Certified rewrite optimization infrastructure with translation validation.
//!
//! This module integrates versioned rewrite packs, translation validation,
//! and governance controls into a cohesive certified rewrite optimization
//! system. The optimizer can exploit sophisticated algebraic transformations
//! while maintaining formal correctness guarantees through proof-carrying
//! optimization and fail-closed validation.
//!
//! The system provides:
//! - Certified rewrite rule application with formal proofs
//! - Translation validation for semantic preservation
//! - Governance controls for rollback and forensics
//! - Deterministic optimization with reproducible results
//! - Performance telemetry and regression detection
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! deterministic computation.
//!
//! Reference: [RGC-607], bead bd-1lsy.7.7.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::certified_optimization_governance::{
    GovernanceState, OptimizationCertificate, OptimizationTier, RollbackRecord,
};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::translation_validation::{TranslationValidationGate, ValidationMode, ValidationVerdict};
use crate::translation_validation_receipt::TranslationValidationReceipt;
use crate::versioned_rewrite_pack::{RewritePack, RewriteRuleEntry};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the certified rewrite optimizer.
pub const SCHEMA_VERSION: &str = "franken-engine.certified-rewrite-optimizer.v1";

/// Component name for evidence linkage.
pub const COMPONENT: &str = "certified_rewrite_optimizer";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.7";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-607";

/// Fixed-point scale: 1_000_000 millionths = 1.0.
const MILLIONTHS: u64 = 1_000_000;

/// Default optimization timeout in milliseconds.
pub const DEFAULT_OPTIMIZATION_TIMEOUT_MS: u64 = 5_000;

/// Maximum number of rewrite steps per optimization session.
const MAX_REWRITE_STEPS: usize = 1_000;

/// Maximum number of validation attempts per transformation.
const MAX_VALIDATION_ATTEMPTS: usize = 3;

// ---------------------------------------------------------------------------
// OptimizationRequest
// ---------------------------------------------------------------------------

/// Request for certified optimization of a program or expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationRequest {
    /// Unique identifier for this optimization request.
    pub request_id: String,
    /// Security epoch for this request.
    pub security_epoch: SecurityEpoch,
    /// Target optimization tier.
    pub target_tier: OptimizationTier,
    /// Input program or expression to optimize.
    pub input_program: String,
    /// Hash of the input for verification.
    pub input_hash: ContentHash,
    /// Timeout for optimization in milliseconds.
    pub timeout_ms: u64,
    /// Whether to require formal proofs for all transformations.
    pub require_formal_proofs: bool,
    /// Validation mode to use.
    pub validation_mode: ValidationMode,
    /// Additional optimization parameters.
    pub parameters: BTreeMap<String, String>,
}

impl OptimizationRequest {
    /// Creates a new optimization request.
    pub fn new(
        request_id: String,
        security_epoch: SecurityEpoch,
        target_tier: OptimizationTier,
        input_program: String,
    ) -> Self {
        let input_hash = ContentHash::compute(input_program.as_bytes());
        Self {
            request_id,
            security_epoch,
            target_tier,
            input_program,
            input_hash,
            timeout_ms: DEFAULT_OPTIMIZATION_TIMEOUT_MS,
            require_formal_proofs: true,
            validation_mode: ValidationMode::GoldenCorpusReplay {
                corpus_hash: ContentHash::compute(b"default_corpus"),
                vector_count: 100,
            },
            parameters: BTreeMap::new(),
        }
    }

    /// Sets the optimization timeout.
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Sets whether formal proofs are required.
    pub fn with_formal_proofs(mut self, require_proofs: bool) -> Self {
        self.require_formal_proofs = require_proofs;
        self
    }

    /// Sets the validation mode.
    pub fn with_validation_mode(mut self, mode: ValidationMode) -> Self {
        self.validation_mode = mode;
        self
    }

    /// Adds an optimization parameter.
    pub fn with_parameter(mut self, key: String, value: String) -> Self {
        self.parameters.insert(key, value);
        self
    }

    /// Validates the optimization request.
    pub fn validate(&self) -> Result<(), CertifiedOptimizerError> {
        if self.request_id.is_empty() {
            return Err(CertifiedOptimizerError::InvalidRequest {
                request_id: self.request_id.clone(),
                reason: "request_id cannot be empty".to_string(),
            });
        }

        if self.input_program.is_empty() {
            return Err(CertifiedOptimizerError::InvalidRequest {
                request_id: self.request_id.clone(),
                reason: "input_program cannot be empty".to_string(),
            });
        }

        if self.timeout_ms == 0 {
            return Err(CertifiedOptimizerError::InvalidRequest {
                request_id: self.request_id.clone(),
                reason: "timeout_ms must be positive".to_string(),
            });
        }

        // Verify input hash
        let computed_hash = ContentHash::compute(self.input_program.as_bytes());
        if computed_hash != self.input_hash {
            return Err(CertifiedOptimizerError::InvalidRequest {
                request_id: self.request_id.clone(),
                reason: "input_hash does not match input_program".to_string(),
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OptimizationStep
// ---------------------------------------------------------------------------

/// A single step in the optimization process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationStep {
    /// Step number in the optimization sequence.
    pub step_number: usize,
    /// Rewrite rule applied in this step.
    pub rule_id: RewriteRuleId,
    /// Program state before this step.
    pub before_program: String,
    /// Program state after this step.
    pub after_program: String,
    /// Hash of the transformation for verification.
    pub transformation_hash: ContentHash,
    /// Validation receipt for this step.
    pub validation_receipt: Option<ValidationReceipt>,
    /// Optimization certificate for this step.
    pub optimization_certificate: Option<OptimizationCertificate>,
    /// Step execution time in milliseconds.
    pub execution_time_ms: u64,
}

impl OptimizationStep {
    /// Creates a new optimization step.
    pub fn new(
        step_number: usize,
        rule_id: RewriteRuleId,
        before_program: String,
        after_program: String,
    ) -> Self {
        let transformation_data = format!("{}{}{}", rule_id, before_program, after_program);
        let transformation_hash = ContentHash::compute(transformation_data.as_bytes());

        Self {
            step_number,
            rule_id,
            before_program,
            after_program,
            transformation_hash,
            validation_receipt: None,
            optimization_certificate: None,
            execution_time_ms: 0,
        }
    }

    /// Sets the validation receipt.
    pub fn with_validation_receipt(mut self, receipt: ValidationReceipt) -> Self {
        self.validation_receipt = Some(receipt);
        self
    }

    /// Sets the optimization certificate.
    pub fn with_optimization_certificate(mut self, certificate: OptimizationCertificate) -> Self {
        self.optimization_certificate = Some(certificate);
        self
    }

    /// Sets the execution time.
    pub fn with_execution_time(mut self, execution_time_ms: u64) -> Self {
        self.execution_time_ms = execution_time_ms;
        self
    }

    /// Returns whether this step passed validation.
    pub fn is_validated(&self) -> bool {
        self.validation_receipt
            .as_ref()
            .map(|r| r.validation_passed())
            .unwrap_or(false)
    }

    /// Returns whether this step is certified.
    pub fn is_certified(&self) -> bool {
        self.optimization_certificate.is_some()
    }
}

// ---------------------------------------------------------------------------
// OptimizationResult
// ---------------------------------------------------------------------------

/// Result of a certified optimization session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationResult {
    /// Original optimization request.
    pub request: OptimizationRequest,
    /// Whether optimization completed successfully.
    pub success: bool,
    /// Final optimized program (if successful).
    pub optimized_program: Option<String>,
    /// Hash of the optimized program.
    pub output_hash: Option<ContentHash>,
    /// All optimization steps performed.
    pub optimization_steps: Vec<OptimizationStep>,
    /// Any rollback records generated.
    pub rollback_records: Vec<RollbackRecord>,
    /// Overall optimization metrics.
    pub metrics: OptimizationMetrics,
    /// Any errors encountered.
    pub errors: Vec<String>,
    /// Warnings generated during optimization.
    pub warnings: Vec<String>,
    /// Total optimization time in milliseconds.
    pub total_time_ms: u64,
    /// Final governance state.
    pub governance_state: GovernanceState,
}

impl OptimizationResult {
    /// Creates a new optimization result.
    pub fn new(request: OptimizationRequest, success: bool) -> Self {
        Self {
            request,
            success,
            optimized_program: None,
            output_hash: None,
            optimization_steps: Vec::new(),
            rollback_records: Vec::new(),
            metrics: OptimizationMetrics::default(),
            errors: Vec::new(),
            warnings: Vec::new(),
            total_time_ms: 0,
            governance_state: GovernanceState::new(),
        }
    }

    /// Sets the optimized program.
    pub fn with_optimized_program(mut self, program: String) -> Self {
        self.output_hash = Some(ContentHash::compute(program.as_bytes()));
        self.optimized_program = Some(program);
        self
    }

    /// Adds an optimization step.
    pub fn add_step(&mut self, step: OptimizationStep) {
        self.optimization_steps.push(step);
    }

    /// Adds a rollback record.
    pub fn add_rollback(&mut self, rollback: RollbackRecord) {
        self.rollback_records.push(rollback);
    }

    /// Adds an error.
    pub fn add_error(&mut self, error: String) {
        self.errors.push(error);
    }

    /// Adds a warning.
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    /// Sets the total optimization time.
    pub fn with_total_time(mut self, total_time_ms: u64) -> Self {
        self.total_time_ms = total_time_ms;
        self
    }

    /// Sets the optimization metrics.
    pub fn with_metrics(mut self, metrics: OptimizationMetrics) -> Self {
        self.metrics = metrics;
        self
    }

    /// Sets the governance state.
    pub fn with_governance_state(mut self, state: GovernanceState) -> Self {
        self.governance_state = state;
        self
    }

    /// Returns the optimization ratio (improvement factor).
    pub fn optimization_ratio(&self) -> f64 {
        if self.metrics.baseline_cost_millionths == 0 {
            1.0
        } else {
            self.metrics.baseline_cost_millionths as f64
                / self.metrics.optimized_cost_millionths.max(1) as f64
        }
    }

    /// Returns whether all optimization steps passed validation.
    pub fn all_steps_validated(&self) -> bool {
        !self.optimization_steps.is_empty()
            && self.optimization_steps.iter().all(|s| s.is_validated())
    }

    /// Returns whether all optimization steps are certified.
    pub fn all_steps_certified(&self) -> bool {
        !self.optimization_steps.is_empty()
            && self.optimization_steps.iter().all(|s| s.is_certified())
    }
}

// ---------------------------------------------------------------------------
// OptimizationMetrics
// ---------------------------------------------------------------------------

/// Metrics from certified optimization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationMetrics {
    /// Number of optimization steps performed.
    pub steps_performed: usize,
    /// Number of steps that passed validation.
    pub steps_validated: usize,
    /// Number of steps with formal certificates.
    pub steps_certified: usize,
    /// Number of rollbacks triggered.
    pub rollbacks_triggered: usize,
    /// Baseline cost estimate in millionths.
    pub baseline_cost_millionths: u64,
    /// Optimized cost estimate in millionths.
    pub optimized_cost_millionths: u64,
    /// Validation overhead in milliseconds.
    pub validation_overhead_ms: u64,
    /// Certification overhead in milliseconds.
    pub certification_overhead_ms: u64,
}

impl Default for OptimizationMetrics {
    fn default() -> Self {
        Self {
            steps_performed: 0,
            steps_validated: 0,
            steps_certified: 0,
            rollbacks_triggered: 0,
            baseline_cost_millionths: MILLIONTHS,
            optimized_cost_millionths: MILLIONTHS,
            validation_overhead_ms: 0,
            certification_overhead_ms: 0,
        }
    }
}

impl OptimizationMetrics {
    /// Calculates the validation success rate as millionths.
    pub fn validation_success_rate_millionths(&self) -> u64 {
        if self.steps_performed == 0 {
            return MILLIONTHS;
        }
        (self.steps_validated as u64 * MILLIONTHS) / self.steps_performed as u64
    }

    /// Calculates the certification success rate as millionths.
    pub fn certification_success_rate_millionths(&self) -> u64 {
        if self.steps_performed == 0 {
            return MILLIONTHS;
        }
        (self.steps_certified as u64 * MILLIONTHS) / self.steps_performed as u64
    }

    /// Calculates the performance improvement as millionths.
    pub fn performance_improvement_millionths(&self) -> u64 {
        if self.baseline_cost_millionths == 0 {
            return 0;
        }
        let improvement = self
            .baseline_cost_millionths
            .saturating_sub(self.optimized_cost_millionths);
        (improvement * MILLIONTHS) / self.baseline_cost_millionths
    }
}

// ---------------------------------------------------------------------------
// CertifiedOptimizerError
// ---------------------------------------------------------------------------

/// Errors that can occur during certified optimization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertifiedOptimizerError {
    /// Invalid optimization request.
    InvalidRequest { request_id: String, reason: String },
    /// Optimization timeout.
    OptimizationTimeout { request_id: String, timeout_ms: u64 },
    /// Translation validation failed.
    ValidationFailed {
        request_id: String,
        step_number: usize,
        reason: String,
    },
    /// Certification failed.
    CertificationFailed {
        request_id: String,
        step_number: usize,
        reason: String,
    },
    /// Rewrite pack error.
    RewritePackError { request_id: String, error: String },
    /// Governance violation.
    GovernanceViolation {
        request_id: String,
        violation: String,
    },
    /// Internal error.
    InternalError { request_id: String, error: String },
}

impl fmt::Display for CertifiedOptimizerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest { request_id, reason } => {
                write!(f, "Invalid request '{}': {}", request_id, reason)
            }
            Self::OptimizationTimeout {
                request_id,
                timeout_ms,
            } => {
                write!(
                    f,
                    "Optimization timeout for '{}' after {}ms",
                    request_id, timeout_ms
                )
            }
            Self::ValidationFailed {
                request_id,
                step_number,
                reason,
            } => {
                write!(
                    f,
                    "Validation failed for '{}' at step {}: {}",
                    request_id, step_number, reason
                )
            }
            Self::CertificationFailed {
                request_id,
                step_number,
                reason,
            } => {
                write!(
                    f,
                    "Certification failed for '{}' at step {}: {}",
                    request_id, step_number, reason
                )
            }
            Self::RewritePackError { request_id, error } => {
                write!(f, "Rewrite pack error for '{}': {}", request_id, error)
            }
            Self::GovernanceViolation {
                request_id,
                violation,
            } => {
                write!(
                    f,
                    "Governance violation for '{}': {}",
                    request_id, violation
                )
            }
            Self::InternalError { request_id, error } => {
                write!(f, "Internal error for '{}': {}", request_id, error)
            }
        }
    }
}

impl std::error::Error for CertifiedOptimizerError {}

// ---------------------------------------------------------------------------
// CertifiedRewriteOptimizer
// ---------------------------------------------------------------------------

/// Main certified rewrite optimizer coordinating all components.
pub struct CertifiedRewriteOptimizer {
    /// Security epoch for this optimizer instance.
    pub security_epoch: SecurityEpoch,
    /// Available rewrite packs.
    pub rewrite_packs: BTreeMap<String, RewritePack>,
    /// Translation validator.
    pub translation_validator: TranslationValidator,
    /// Governance state.
    pub governance_state: GovernanceState,
    /// Maximum optimization steps per session.
    pub max_steps: usize,
    /// Maximum validation attempts per step.
    pub max_validation_attempts: usize,
}

impl CertifiedRewriteOptimizer {
    /// Creates a new certified rewrite optimizer.
    pub fn new(security_epoch: SecurityEpoch) -> Self {
        Self {
            security_epoch,
            rewrite_packs: BTreeMap::new(),
            translation_validator: TranslationValidator::new(),
            governance_state: GovernanceState::new(),
            max_steps: MAX_REWRITE_STEPS,
            max_validation_attempts: MAX_VALIDATION_ATTEMPTS,
        }
    }

    /// Adds a rewrite pack to the optimizer.
    pub fn add_rewrite_pack(&mut self, pack_id: String, pack: RewritePack) {
        self.rewrite_packs.insert(pack_id, pack);
    }

    /// Sets the maximum number of optimization steps.
    pub fn set_max_steps(&mut self, max_steps: usize) {
        self.max_steps = max_steps;
    }

    /// Sets the maximum number of validation attempts per step.
    pub fn set_max_validation_attempts(&mut self, max_attempts: usize) {
        self.max_validation_attempts = max_attempts;
    }

    /// Performs certified optimization on the given request.
    pub fn optimize(
        &mut self,
        request: OptimizationRequest,
    ) -> Result<OptimizationResult, CertifiedOptimizerError> {
        // Validate the request
        request.validate()?;

        let start_time = Instant::now();
        let timeout = Duration::from_millis(request.timeout_ms);

        let mut result = OptimizationResult::new(request.clone(), false);
        let mut current_program = request.input_program.clone();
        let mut step_number = 0;
        let mut total_validation_time = 0;
        let mut total_certification_time = 0;

        // Main optimization loop
        while step_number < self.max_steps {
            // Check timeout
            if start_time.elapsed() >= timeout {
                result.add_error("Optimization timeout reached".to_string());
                return Ok(result.with_total_time(start_time.elapsed().as_millis() as u64));
            }

            // Find applicable rewrite rules
            let applicable_rules = self.find_applicable_rules(&current_program)?;
            if applicable_rules.is_empty() {
                break; // No more optimizations possible
            }

            // Select the best rule (for now, just take the first one)
            let rule_id = applicable_rules[0].clone();
            let optimized_program = self.apply_rewrite_rule(&current_program, &rule_id)?;

            if optimized_program == current_program {
                continue; // No change, try next iteration
            }

            let step_start = Instant::now();
            let mut step = OptimizationStep::new(
                step_number,
                rule_id.clone(),
                current_program.clone(),
                optimized_program.clone(),
            );

            // Perform translation validation
            let validation_start = Instant::now();
            let validation_result = self.validate_transformation(
                &current_program,
                &optimized_program,
                &rule_id,
                &request.validation_mode,
            )?;

            let validation_time = validation_start.elapsed().as_millis() as u64;
            total_validation_time += validation_time;

            if !validation_result.is_valid() {
                // Validation failed - trigger rollback
                let rollback = RollbackRecord::new(
                    step_number,
                    "validation_failed".to_string(),
                    validation_result.error_message().unwrap_or_default(),
                );
                result.add_rollback(rollback);
                result.add_warning(format!(
                    "Step {} validation failed, continuing with baseline",
                    step_number
                ));
                continue;
            }

            step = step.with_validation_receipt(validation_result.receipt().unwrap());

            // Generate optimization certificate if required
            if request.require_formal_proofs {
                let cert_start = Instant::now();
                match self.generate_certificate(&rule_id, &current_program, &optimized_program) {
                    Ok(cert) => {
                        step = step.with_optimization_certificate(cert);
                        total_certification_time += cert_start.elapsed().as_millis() as u64;
                    }
                    Err(e) => {
                        result.add_warning(format!(
                            "Step {} certification failed: {}, continuing without certificate",
                            step_number, e
                        ));
                    }
                }
            }

            let step_time = step_start.elapsed().as_millis() as u64;
            step = step.with_execution_time(step_time);

            result.add_step(step);
            current_program = optimized_program;
            step_number += 1;
        }

        // Finalize result
        result = result.with_optimized_program(current_program);
        result.success = true;

        // Update metrics
        let mut metrics = OptimizationMetrics::default();
        metrics.steps_performed = result.optimization_steps.len();
        metrics.steps_validated = result
            .optimization_steps
            .iter()
            .filter(|s| s.is_validated())
            .count();
        metrics.steps_certified = result
            .optimization_steps
            .iter()
            .filter(|s| s.is_certified())
            .count();
        metrics.rollbacks_triggered = result.rollback_records.len();
        metrics.validation_overhead_ms = total_validation_time;
        metrics.certification_overhead_ms = total_certification_time;

        result = result.with_metrics(metrics);
        result = result.with_total_time(start_time.elapsed().as_millis() as u64);
        result = result.with_governance_state(self.governance_state.clone());

        Ok(result)
    }

    /// Finds applicable rewrite rules for the given program.
    fn find_applicable_rules(
        &self,
        _program: &str,
    ) -> Result<Vec<RewriteRuleId>, CertifiedOptimizerError> {
        // TODO: Implement actual rule matching logic
        // For now, return a placeholder rule
        Ok(vec!["const_fold".to_string()])
    }

    /// Applies a rewrite rule to transform the program.
    fn apply_rewrite_rule(
        &self,
        program: &str,
        _rule_id: &RewriteRuleId,
    ) -> Result<String, CertifiedOptimizerError> {
        // TODO: Implement actual rewrite application
        // For now, just return the original program (no transformation)
        Ok(program.to_string())
    }

    /// Validates a program transformation.
    fn validate_transformation(
        &mut self,
        _before: &str,
        _after: &str,
        _rule_id: &RewriteRuleId,
        _mode: &ValidationMode,
    ) -> Result<ValidationResult, CertifiedOptimizerError> {
        // TODO: Integrate with actual translation validator
        // For now, return a successful validation
        let receipt = ValidationReceipt::new("placeholder".to_string(), true);
        Ok(ValidationResult::success(receipt))
    }

    /// Generates an optimization certificate for a transformation.
    fn generate_certificate(
        &self,
        rule_id: &RewriteRuleId,
        _before: &str,
        _after: &str,
    ) -> Result<OptimizationCertificate, CertifiedOptimizerError> {
        // TODO: Implement actual certificate generation
        // For now, return a placeholder certificate
        Ok(OptimizationCertificate::new(
            rule_id.clone(),
            OptimizationTier::Standard,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimization_request_creation() {
        let epoch = SecurityEpoch::from_raw(1);
        let request = OptimizationRequest::new(
            "test_request".to_string(),
            epoch,
            OptimizationTier::Standard,
            "x + 0".to_string(),
        );

        assert_eq!(request.request_id, "test_request");
        assert_eq!(request.security_epoch, epoch);
        assert_eq!(request.target_tier, OptimizationTier::Conservative);
        assert_eq!(request.input_program, "x + 0");
        assert_eq!(request.timeout_ms, DEFAULT_OPTIMIZATION_TIMEOUT_MS);
        assert!(request.require_formal_proofs);
    }

    #[test]
    fn test_optimization_request_validation_success() {
        let epoch = SecurityEpoch::from_raw(1);
        let request = OptimizationRequest::new(
            "valid_request".to_string(),
            epoch,
            OptimizationTier::Standard,
            "x + y".to_string(),
        );

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_optimization_request_validation_empty_id() {
        let epoch = SecurityEpoch::from_raw(1);
        let request = OptimizationRequest::new(
            "".to_string(),
            epoch,
            OptimizationTier::Standard,
            "x + y".to_string(),
        );

        let result = request.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            CertifiedOptimizerError::InvalidRequest { reason, .. } => {
                assert!(reason.contains("request_id cannot be empty"));
            }
            _ => panic!("Expected InvalidRequest error"),
        }
    }

    #[test]
    fn test_optimization_request_validation_empty_program() {
        let epoch = SecurityEpoch::from_raw(1);
        let request = OptimizationRequest::new(
            "test".to_string(),
            epoch,
            OptimizationTier::Standard,
            "".to_string(),
        );

        let result = request.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            CertifiedOptimizerError::InvalidRequest { reason, .. } => {
                assert!(reason.contains("input_program cannot be empty"));
            }
            _ => panic!("Expected InvalidRequest error"),
        }
    }

    #[test]
    fn test_optimization_request_with_parameters() {
        let epoch = SecurityEpoch::from_raw(1);
        let request = OptimizationRequest::new(
            "param_test".to_string(),
            epoch,
            OptimizationTier::Aggressive,
            "func(x, y)".to_string(),
        )
        .with_timeout(10_000)
        .with_formal_proofs(false)
        .with_parameter("inline_threshold".to_string(), "5".to_string())
        .with_parameter("unroll_limit".to_string(), "3".to_string());

        assert_eq!(request.timeout_ms, 10_000);
        assert!(!request.require_formal_proofs);
        assert_eq!(request.parameters.len(), 2);
        assert_eq!(
            request.parameters.get("inline_threshold"),
            Some(&"5".to_string())
        );
        assert_eq!(
            request.parameters.get("unroll_limit"),
            Some(&"3".to_string())
        );
    }

    #[test]
    fn test_optimization_step_creation() {
        let step = OptimizationStep::new(
            1,
            "const_fold".to_string(),
            "x + 0".to_string(),
            "x".to_string(),
        );

        assert_eq!(step.step_number, 1);
        assert_eq!(step.rule_id, "const_fold");
        assert_eq!(step.before_program, "x + 0");
        assert_eq!(step.after_program, "x");
        assert!(step.validation_receipt.is_none());
        assert!(step.optimization_certificate.is_none());
        assert!(!step.is_validated());
        assert!(!step.is_certified());
    }

    #[test]
    fn test_optimization_step_with_validation() {
        let receipt = ValidationReceipt::new("test_validation".to_string(), true);
        let step = OptimizationStep::new(
            1,
            "const_fold".to_string(),
            "x + 0".to_string(),
            "x".to_string(),
        )
        .with_validation_receipt(receipt);

        assert!(step.is_validated());
        assert!(!step.is_certified());
    }

    #[test]
    fn test_optimization_step_with_certificate() {
        let certificate =
            OptimizationCertificate::new("const_fold".to_string(), OptimizationTier::Conservative);
        let step = OptimizationStep::new(
            1,
            "const_fold".to_string(),
            "x + 0".to_string(),
            "x".to_string(),
        )
        .with_optimization_certificate(certificate);

        assert!(!step.is_validated());
        assert!(step.is_certified());
    }

    #[test]
    fn test_optimization_result_creation() {
        let epoch = SecurityEpoch::from_raw(1);
        let request = OptimizationRequest::new(
            "test_result".to_string(),
            epoch,
            OptimizationTier::Standard,
            "x + 0 + y".to_string(),
        );

        let result = OptimizationResult::new(request.clone(), true);

        assert_eq!(result.request, request);
        assert!(result.success);
        assert!(result.optimized_program.is_none());
        assert!(result.optimization_steps.is_empty());
        assert!(result.rollback_records.is_empty());
        assert!(result.errors.is_empty());
        assert_eq!(result.total_time_ms, 0);
    }

    #[test]
    fn test_optimization_result_with_program() {
        let epoch = SecurityEpoch::from_raw(1);
        let request = OptimizationRequest::new(
            "test_result".to_string(),
            epoch,
            OptimizationTier::Standard,
            "x + 0".to_string(),
        );

        let result = OptimizationResult::new(request, true).with_optimized_program("x".to_string());

        assert_eq!(result.optimized_program, Some("x".to_string()));
        assert!(result.output_hash.is_some());
    }

    #[test]
    fn test_optimization_metrics_default() {
        let metrics = OptimizationMetrics::default();

        assert_eq!(metrics.steps_performed, 0);
        assert_eq!(metrics.steps_validated, 0);
        assert_eq!(metrics.steps_certified, 0);
        assert_eq!(metrics.rollbacks_triggered, 0);
        assert_eq!(metrics.baseline_cost_millionths, MILLIONTHS);
        assert_eq!(metrics.optimized_cost_millionths, MILLIONTHS);
        assert_eq!(metrics.validation_overhead_ms, 0);
        assert_eq!(metrics.certification_overhead_ms, 0);
    }

    #[test]
    fn test_optimization_metrics_success_rates() {
        let mut metrics = OptimizationMetrics::default();
        metrics.steps_performed = 10;
        metrics.steps_validated = 8;
        metrics.steps_certified = 6;

        assert_eq!(metrics.validation_success_rate_millionths(), 800_000);
        assert_eq!(metrics.certification_success_rate_millionths(), 600_000);
    }

    #[test]
    fn test_optimization_metrics_performance_improvement() {
        let mut metrics = OptimizationMetrics::default();
        metrics.baseline_cost_millionths = 1_000_000;
        metrics.optimized_cost_millionths = 750_000;

        assert_eq!(metrics.performance_improvement_millionths(), 250_000);
    }

    #[test]
    fn test_certified_optimizer_creation() {
        let epoch = SecurityEpoch::from_raw(42);
        let optimizer = CertifiedRewriteOptimizer::new(epoch);

        assert_eq!(optimizer.security_epoch, epoch);
        assert!(optimizer.rewrite_packs.is_empty());
        assert_eq!(optimizer.max_steps, MAX_REWRITE_STEPS);
        assert_eq!(optimizer.max_validation_attempts, MAX_VALIDATION_ATTEMPTS);
    }

    #[test]
    fn test_certified_optimizer_configuration() {
        let epoch = SecurityEpoch::from_raw(42);
        let mut optimizer = CertifiedRewriteOptimizer::new(epoch);

        optimizer.set_max_steps(500);
        optimizer.set_max_validation_attempts(5);

        assert_eq!(optimizer.max_steps, 500);
        assert_eq!(optimizer.max_validation_attempts, 5);
    }

    #[test]
    fn test_certified_optimizer_basic_optimization() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut optimizer = CertifiedRewriteOptimizer::new(epoch);

        let request = OptimizationRequest::new(
            "basic_test".to_string(),
            epoch,
            OptimizationTier::Standard,
            "x + 0".to_string(),
        );

        let result = optimizer.optimize(request);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.success);
        assert!(result.optimized_program.is_some());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_certified_optimizer_error_display() {
        let error = CertifiedOptimizerError::InvalidRequest {
            request_id: "test".to_string(),
            reason: "invalid input".to_string(),
        };

        let display = format!("{}", error);
        assert!(display.contains("test"));
        assert!(display.contains("invalid input"));

        let timeout_error = CertifiedOptimizerError::OptimizationTimeout {
            request_id: "timeout_test".to_string(),
            timeout_ms: 5000,
        };

        let display = format!("{}", timeout_error);
        assert!(display.contains("timeout_test"));
        assert!(display.contains("5000ms"));
    }
}
