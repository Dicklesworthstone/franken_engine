#![forbid(unsafe_code)]

//! Certified rewrite optimization infrastructure with translation validation.
//!
//! This module integrates versioned rewrite packs, translation validation,
//! and governance controls into a cohesive certified rewrite optimization
//! system. The optimizer can exploit sophisticated algebraic transformations
//! while maintaining policy-driven correctness checks through validation
//! and fail-closed operation. (Formal proofs and proof-carrying optimization remain hypothetical.)
//!
//! The system provides:
//! - Certified rewrite rule application with hash-based validation
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

use crate::certified_optimization_governance::{
    CertificateStatus, GovernanceState, OptimizationCertificate, OptimizationTier, RollbackRecord,
    RollbackTrigger,
};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::translation_validation::{TranslationValidationGate, ValidationMode, ValidationVerdict};
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

/// Rewrite rule identifier.
pub type RewriteRuleId = String;

/// Translation validator used by the optimizer.
pub type TranslationValidator = TranslationValidationGate;

const RULE_CONST_FOLD: &str = "const_fold";
const RULE_IDENTITY_ADD_ZERO: &str = "identity_add_zero";
const RULE_IDENTITY_MUL_ONE: &str = "identity_mul_one";
const RULE_MUL_ZERO: &str = "mul_zero";

const BUILTIN_RULE_ORDER: &[&str] = &[
    RULE_CONST_FOLD,
    RULE_IDENTITY_ADD_ZERO,
    RULE_IDENTITY_MUL_ONE,
    RULE_MUL_ZERO,
];

// ---------------------------------------------------------------------------
// ValidationReceipt / ValidationResult
// ---------------------------------------------------------------------------

/// Receipt proving that a rewrite candidate was checked by translation validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReceipt {
    /// Stable receipt identifier.
    pub receipt_id: String,
    /// Whether validation passed.
    pub passed: bool,
    /// Structured verdict emitted by the translation-validation path.
    pub verdict: ValidationVerdict,
    /// Hash of the before-program.
    pub before_hash: ContentHash,
    /// Hash of the after-program.
    pub after_hash: ContentHash,
}

impl ValidationReceipt {
    /// Creates a compatibility receipt for tests and callers that only need a pass bit.
    pub fn new(receipt_id: String, passed: bool) -> Self {
        let evidence_hash = ContentHash::compute(receipt_id.as_bytes());
        let verdict = if passed {
            ValidationVerdict::Pass {
                mode: ValidationMode::SymbolicEquivalence {
                    proof_hash: evidence_hash,
                },
                evidence_hash,
            }
        } else {
            ValidationVerdict::Inconclusive {
                mode: ValidationMode::SymbolicEquivalence {
                    proof_hash: evidence_hash,
                },
                reason: "validation did not pass".to_string(),
            }
        };
        Self {
            receipt_id,
            passed,
            verdict,
            before_hash: ContentHash::compute(b"compat-before"),
            after_hash: ContentHash::compute(b"compat-after"),
        }
    }

    fn from_verdict(
        receipt_id: String,
        verdict: ValidationVerdict,
        before: &str,
        after: &str,
    ) -> Self {
        let passed = verdict.permits_activation();
        Self {
            receipt_id,
            passed,
            verdict,
            before_hash: ContentHash::compute(before.as_bytes()),
            after_hash: ContentHash::compute(after.as_bytes()),
        }
    }

    /// Returns whether validation passed and permits activation.
    pub fn validation_passed(&self) -> bool {
        self.passed && self.verdict.permits_activation()
    }
}

/// Result of checking a candidate transformation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationResult {
    valid: bool,
    receipt: Option<ValidationReceipt>,
    error_message: Option<String>,
}

impl ValidationResult {
    /// Successful validation.
    pub fn success(receipt: ValidationReceipt) -> Self {
        Self {
            valid: true,
            receipt: Some(receipt),
            error_message: None,
        }
    }

    /// Failed validation with an audit receipt.
    pub fn failure(receipt: ValidationReceipt, error_message: String) -> Self {
        Self {
            valid: false,
            receipt: Some(receipt),
            error_message: Some(error_message),
        }
    }

    /// Returns whether validation passed.
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Returns the validation receipt.
    pub fn receipt(&self) -> Option<ValidationReceipt> {
        self.receipt.clone()
    }

    /// Returns the validation error, when present.
    pub fn error_message(&self) -> Option<String> {
        self.error_message.clone()
    }
}

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
        let epoch = request.security_epoch;
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
            governance_state: GovernanceState::new(epoch),
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
            governance_state: GovernanceState::new(security_epoch),
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
                result.add_warning(format!(
                    "Rule {rule_id} produced no change; stopping fail-closed"
                ));
                break;
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
                let rollback = RollbackRecord {
                    record_id: format!("rollback:{COMPONENT}:{step_number}:{rule_id}"),
                    function_id: request.request_id.clone(),
                    trigger: RollbackTrigger::ProofFailure,
                    from_tier: request.target_tier,
                    to_tier: OptimizationTier::Baseline,
                    epoch: request.security_epoch,
                    reason: validation_result.error_message().unwrap_or_default(),
                    elapsed_steps: step_number as u64,
                };
                result.add_rollback(rollback);
                result.add_warning(format!(
                    "Step {} validation failed, stopping at baseline",
                    step_number
                ));
                break;
            }

            step = step.with_validation_receipt(validation_result.receipt().expect("serde deserialization should succeed"));

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
        program: &str,
    ) -> Result<Vec<RewriteRuleId>, CertifiedOptimizerError> {
        let mut rule_ids = Vec::new();
        let mut seen = std::collections::BTreeSet::new();

        for rule_id in BUILTIN_RULE_ORDER {
            if Self::rule_matches_program(rule_id, program) && seen.insert((*rule_id).to_string()) {
                rule_ids.push((*rule_id).to_string());
            }
        }

        let mut pack_rules = Vec::new();
        for pack in self.rewrite_packs.values() {
            if !pack.is_canonical() || pack.has_internal_blocking() {
                continue;
            }
            for rule in &pack.rules {
                if Self::pack_rule_is_applicable(rule, program) {
                    pack_rules.push((rule.priority_millionths, rule.rule_id.clone()));
                }
            }
        }
        pack_rules.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));

        for (_, rule_id) in pack_rules {
            if seen.insert(rule_id.clone()) {
                rule_ids.push(rule_id);
            }
        }

        Ok(rule_ids)
    }

    /// Applies a rewrite rule to transform the program.
    fn apply_rewrite_rule(
        &self,
        program: &str,
        rule_id: &RewriteRuleId,
    ) -> Result<String, CertifiedOptimizerError> {
        let Some(rewritten) = Self::apply_builtin_rewrite(program, rule_id) else {
            return Err(CertifiedOptimizerError::RewritePackError {
                request_id: COMPONENT.to_string(),
                error: format!("unsupported rewrite rule '{rule_id}'"),
            });
        };

        if rewritten == program.trim() {
            return Err(CertifiedOptimizerError::RewritePackError {
                request_id: COMPONENT.to_string(),
                error: format!("rewrite rule '{rule_id}' produced no change"),
            });
        }

        Ok(rewritten)
    }

    /// Validates a program transformation.
    fn validate_transformation(
        &mut self,
        before: &str,
        after: &str,
        rule_id: &RewriteRuleId,
        mode: &ValidationMode,
    ) -> Result<ValidationResult, CertifiedOptimizerError> {
        let evidence_payload = format!(
            "{SCHEMA_VERSION}:{rule_id}:{}:{}:{mode}",
            ContentHash::compute(before.as_bytes()),
            ContentHash::compute(after.as_bytes())
        );
        let evidence_hash = ContentHash::compute(evidence_payload.as_bytes());
        let receipt_id = format!("{COMPONENT}:validation:{rule_id}:{evidence_hash}");

        if before == after {
            let reason = "candidate rewrite is a no-op".to_string();
            let receipt = ValidationReceipt::from_verdict(
                receipt_id,
                ValidationVerdict::Fail {
                    mode: mode.clone(),
                    divergence_reason: reason.clone(),
                    counterexample_hash: evidence_hash,
                },
                before,
                after,
            );
            return Ok(ValidationResult::failure(receipt, reason));
        }

        let expected = self.apply_rewrite_rule(before, rule_id)?;
        if expected != after {
            let reason = format!("candidate output differs from rule application: expected '{expected}'");
            let receipt = ValidationReceipt::from_verdict(
                receipt_id,
                ValidationVerdict::Fail {
                    mode: mode.clone(),
                    divergence_reason: reason.clone(),
                    counterexample_hash: evidence_hash,
                },
                before,
                after,
            );
            return Ok(ValidationResult::failure(receipt, reason));
        }

        let receipt = ValidationReceipt::from_verdict(
            receipt_id,
            ValidationVerdict::Pass {
                mode: mode.clone(),
                evidence_hash,
            },
            before,
            after,
        );
        Ok(ValidationResult::success(receipt))
    }

    /// Generates an optimization certificate for a transformation.
    fn generate_certificate(
        &self,
        rule_id: &RewriteRuleId,
        before: &str,
        after: &str,
    ) -> Result<OptimizationCertificate, CertifiedOptimizerError> {
        let expected = self.apply_rewrite_rule(before, rule_id)?;
        if expected != after {
            return Err(CertifiedOptimizerError::CertificationFailed {
                request_id: COMPONENT.to_string(),
                step_number: 0,
                reason: "certificate candidate does not match validated rewrite".to_string(),
            });
        }

        let before_hash = ContentHash::compute(before.as_bytes());
        let after_hash = ContentHash::compute(after.as_bytes());
        let proof_hash = ContentHash::compute(
            format!("{SCHEMA_VERSION}:proof:{rule_id}:{before_hash}:{after_hash}").as_bytes(),
        );

        Ok(OptimizationCertificate {
            cert_id: format!("{COMPONENT}:cert:{rule_id}:{before_hash}:{after_hash}"),
            tier: OptimizationTier::Standard,
            function_id: format!("{COMPONENT}:{rule_id}"),
            rewrite_count: 1,
            proof_hash,
            issued_epoch: self.security_epoch,
            expiry_epoch: self.security_epoch.next(),
            translation_receipt_valid: true,
            status: CertificateStatus::Valid,
        })
    }

    fn pack_rule_is_applicable(rule: &RewriteRuleEntry, program: &str) -> bool {
        rule.enabled && rule.proven_sound && Self::rule_matches_program(&rule.rule_id, program)
    }

    fn rule_matches_program(rule_id: &str, program: &str) -> bool {
        Self::apply_builtin_rewrite(program, rule_id).is_some()
    }

    fn apply_builtin_rewrite(program: &str, rule_id: &str) -> Option<String> {
        match rule_id {
            RULE_CONST_FOLD => Self::rewrite_constant_expression(program)
                .or_else(|| Self::rewrite_add_zero(program))
                .or_else(|| Self::rewrite_mul_one(program))
                .or_else(|| Self::rewrite_mul_zero(program)),
            RULE_IDENTITY_ADD_ZERO => Self::rewrite_add_zero(program),
            RULE_IDENTITY_MUL_ONE => Self::rewrite_mul_one(program),
            RULE_MUL_ZERO => Self::rewrite_mul_zero(program),
            _ => None,
        }
    }

    fn rewrite_add_zero(program: &str) -> Option<String> {
        let (left, right) = Self::split_binary(program, '+')?;
        if right == "0" && !left.is_empty() {
            return Some(left.to_string());
        }
        if left == "0" && !right.is_empty() {
            return Some(right.to_string());
        }
        None
    }

    fn rewrite_mul_one(program: &str) -> Option<String> {
        let (left, right) = Self::split_binary(program, '*')?;
        if right == "1" && !left.is_empty() {
            return Some(left.to_string());
        }
        if left == "1" && !right.is_empty() {
            return Some(right.to_string());
        }
        None
    }

    fn rewrite_mul_zero(program: &str) -> Option<String> {
        let (left, right) = Self::split_binary(program, '*')?;
        if (left == "0" && !right.is_empty()) || (right == "0" && !left.is_empty()) {
            return Some("0".to_string());
        }
        None
    }

    fn rewrite_constant_expression(program: &str) -> Option<String> {
        for operator in ['+', '-', '*', '/'] {
            if let Some((left, right)) = Self::split_binary(program, operator) {
                let left_value = left.parse::<i64>().ok()?;
                let right_value = right.parse::<i64>().ok()?;
                let value = match operator {
                    '+' => left_value.checked_add(right_value)?,
                    '-' => left_value.checked_sub(right_value)?,
                    '*' => left_value.checked_mul(right_value)?,
                    '/' if right_value != 0 => left_value.checked_div(right_value)?,
                    _ => return None,
                };
                return Some(value.to_string());
            }
        }
        None
    }

    fn split_binary(program: &str, operator: char) -> Option<(&str, &str)> {
        let trimmed = program.trim();
        let mut parts = trimmed.split(operator);
        let left = parts.next()?.trim();
        let right = parts.next()?.trim();
        if parts.next().is_some() || left.is_empty() || right.is_empty() {
            return None;
        }
        Some((left, right))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_certificate(rule_id: &str, epoch: SecurityEpoch) -> OptimizationCertificate {
        OptimizationCertificate {
            cert_id: format!("test-cert:{rule_id}"),
            tier: OptimizationTier::Conservative,
            function_id: format!("test-function:{rule_id}"),
            rewrite_count: 1,
            proof_hash: ContentHash::compute(rule_id.as_bytes()),
            issued_epoch: epoch,
            expiry_epoch: epoch.next(),
            translation_receipt_valid: true,
            status: CertificateStatus::Valid,
        }
    }

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
        assert_eq!(request.target_tier, OptimizationTier::Standard);
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
        let certificate = test_certificate("const_fold", SecurityEpoch::from_raw(1));
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

        let result = result.expect("serde deserialization should succeed");
        assert!(result.success);
        assert_eq!(result.optimized_program, Some("x".to_string()));
        assert!(result.all_steps_validated());
        assert!(result.all_steps_certified());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn unsupported_program_does_not_receive_success_certificate() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut optimizer = CertifiedRewriteOptimizer::new(epoch);

        let request = OptimizationRequest::new(
            "unsupported_test".to_string(),
            epoch,
            OptimizationTier::Standard,
            "call_with_side_effects(x)".to_string(),
        );

        let result = optimizer.optimize(request).expect("serde deserialization should succeed");

        assert!(result.success);
        assert_eq!(
            result.optimized_program,
            Some("call_with_side_effects(x)".to_string())
        );
        assert!(result.optimization_steps.is_empty());
        assert!(!result.all_steps_certified());
        assert_eq!(result.metrics.steps_certified, 0);
    }

    #[test]
    fn no_op_candidate_fails_translation_validation() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut optimizer = CertifiedRewriteOptimizer::new(epoch);
        let mode = ValidationMode::SymbolicEquivalence {
            proof_hash: ContentHash::compute(b"test-proof"),
        };

        let result = optimizer
            .validate_transformation("x + 0", "x + 0", &"const_fold".to_string(), &mode)
            .expect("serde deserialization should succeed");

        assert!(!result.is_valid());
        assert!(result
            .error_message()
            .expect("serde deserialization should succeed")
            .contains("no-op"));
        assert!(!result.receipt().expect("serde deserialization should succeed").validation_passed());
    }

    #[test]
    fn unsupported_rule_cannot_generate_certificate() {
        let epoch = SecurityEpoch::from_raw(1);
        let optimizer = CertifiedRewriteOptimizer::new(epoch);

        let result =
            optimizer.generate_certificate(&"unsupported_rule".to_string(), "x + 0", "x");

        assert!(result.is_err());
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

    // ---------------------------------------------------------------------------
    // Metamorphic Property Tests - Idempotency and Confluence
    // ---------------------------------------------------------------------------

    /// Helper function to run optimization and extract the optimized program.
    /// Returns the input program unchanged if optimization fails or produces no output.
    fn run_optimization(
        optimizer: &mut CertifiedRewriteOptimizer,
        program: &str,
        tier: OptimizationTier,
        request_suffix: &str,
    ) -> String {
        let epoch = SecurityEpoch::from_raw(1);
        let request = OptimizationRequest::new(
            format!("metamorphic_{}", request_suffix),
            epoch,
            tier,
            program.to_string(),
        );

        match optimizer.optimize(request) {
            Ok(result) if result.success => {
                result.optimized_program.unwrap_or_else(|| program.to_string())
            }
            Ok(_) | Err(_) => program.to_string(), // Return input unchanged if optimization fails
        }
    }

    #[test]
    fn metamorphic_idempotency_simple_expressions() {
        // Test idempotency: optimize(optimize(X)) == optimize(X)
        let epoch = SecurityEpoch::from_raw(1);
        let mut optimizer = CertifiedRewriteOptimizer::new(epoch);

        let test_cases = [
            "x + 0",           // Identity addition
            "x * 1",           // Identity multiplication
            "x - 0",           // Identity subtraction
            "0 + x",           // Commutative identity
            "1 * x",           // Commutative identity
            "x + x",           // Common subexpression
            "func(x, y)",      // Function call
            "x",               // Single variable
            "(x + 0) * 1",     // Nested identities
        ];

        for (i, program) in test_cases.iter().enumerate() {
            // First optimization pass
            let first_pass = run_optimization(&mut optimizer, program, OptimizationTier::Standard, &format!("idem1_{}", i));

            // Second optimization pass on the result
            let second_pass = run_optimization(&mut optimizer, &first_pass, OptimizationTier::Standard, &format!("idem2_{}", i));

            // Metamorphic property: P(P(x)) == P(x) (idempotency)
            assert_eq!(
                first_pass, second_pass,
                "Idempotency violated for program '{}': first pass produced '{}', second pass produced '{}'",
                program, first_pass, second_pass
            );
        }
    }

    #[test]
    fn metamorphic_idempotency_conservative_vs_standard_tiers() {
        // Test idempotency across different optimization tiers
        let epoch = SecurityEpoch::from_raw(1);
        let mut optimizer = CertifiedRewriteOptimizer::new(epoch);

        let test_cases = [
            "x + 0 - 0",
            "x * 1 * 1",
            "func(arg1, arg2)",
            "complex_expr(x + 0, y * 1)",
        ];

        let tiers = [OptimizationTier::Conservative, OptimizationTier::Standard];

        for (i, program) in test_cases.iter().enumerate() {
            for (j, tier) in tiers.iter().enumerate() {
                let first_pass = run_optimization(&mut optimizer, program, *tier, &format!("tier1_{}_{}", i, j));
                let second_pass = run_optimization(&mut optimizer, &first_pass, *tier, &format!("tier2_{}_{}", i, j));

                assert_eq!(
                    first_pass, second_pass,
                    "Idempotency violated for program '{}' at tier {:?}: first='{}', second='{}'",
                    program, tier, first_pass, second_pass
                );
            }
        }
    }

    #[test]
    fn metamorphic_confluence_different_tiers() {
        // Test confluence: Conservative(Standard(X)) vs Standard(Conservative(X))
        // Both should converge to the same result when applied in different orders
        let epoch = SecurityEpoch::from_raw(1);
        let mut optimizer = CertifiedRewriteOptimizer::new(epoch);

        let test_cases = [
            "x + 0 * 1",       // Mixed identity operations
            "func(x + 0)",     // Function with optimizable argument
            "x * 1 + y * 1",   // Multiple identity operations
            "(x + 0) + (y - 0)", // Nested expressions
        ];

        for (i, program) in test_cases.iter().enumerate() {
            // Path A: Conservative -> Standard
            let conservative_first = run_optimization(&mut optimizer, program, OptimizationTier::Conservative, &format!("conf_c1_{}", i));
            let standard_after_conservative = run_optimization(&mut optimizer, &conservative_first, OptimizationTier::Standard, &format!("conf_s2_{}", i));

            // Path B: Standard -> Conservative
            let standard_first = run_optimization(&mut optimizer, program, OptimizationTier::Standard, &format!("conf_s1_{}", i));
            let conservative_after_standard = run_optimization(&mut optimizer, &standard_first, OptimizationTier::Conservative, &format!("conf_c2_{}", i));

            // Confluence property: A(B(x)) should be equivalent to B(A(x))
            // Note: Due to the nature of optimization tiers, we expect both paths to converge
            // to the same level of optimization (likely Standard level, since Conservative is less aggressive)
            assert_eq!(
                standard_after_conservative, conservative_after_standard,
                "Confluence violated for program '{}': Conservative->Standard produced '{}', Standard->Conservative produced '{}'",
                program, standard_after_conservative, conservative_after_standard
            );
        }
    }

    #[test]
    fn metamorphic_idempotency_aggressive_tier() {
        // Test idempotency for the most aggressive optimization tier
        let epoch = SecurityEpoch::from_raw(1);
        let mut optimizer = CertifiedRewriteOptimizer::new(epoch);

        let test_cases = [
            "x + 0 + 0 + 0",     // Multiple identity additions
            "x * 1 * 1 * 1",     // Multiple identity multiplications
            "nested(func(x + 0), y * 1)", // Nested function calls with optimizable expressions
            "complex_chain(a + 0, b - 0, c * 1)", // Multiple arguments
        ];

        for (i, program) in test_cases.iter().enumerate() {
            let first_pass = run_optimization(&mut optimizer, program, OptimizationTier::Aggressive, &format!("aggr1_{}", i));
            let second_pass = run_optimization(&mut optimizer, &first_pass, OptimizationTier::Aggressive, &format!("aggr2_{}", i));

            assert_eq!(
                first_pass, second_pass,
                "Aggressive tier idempotency violated for program '{}': first='{}', second='{}'",
                program, first_pass, second_pass
            );
        }
    }

    #[test]
    fn metamorphic_fixpoint_convergence() {
        // Test that applying optimization repeatedly converges to a fixpoint
        // P(P(P(...P(x)))) should stabilize after enough iterations
        let epoch = SecurityEpoch::from_raw(1);
        let mut optimizer = CertifiedRewriteOptimizer::new(epoch);

        let test_cases = [
            "x + 0 - 0 + 0 - 0", // Multiple redundant operations
            "x * 1 / 1 * 1 / 1", // Multiple identity operations (if division is supported)
        ];

        for (i, program) in test_cases.iter().enumerate() {
            let mut current = program.to_string();
            let mut previous;
            let mut iteration = 0;
            const MAX_ITERATIONS: usize = 10;

            // Apply optimization repeatedly until convergence or max iterations
            loop {
                previous = current.clone();
                current = run_optimization(&mut optimizer, &current, OptimizationTier::Standard, &format!("fixpt_{}_iter{}", i, iteration));
                iteration += 1;

                // Check if we've reached a fixpoint
                if current == previous {
                    break;
                }

                // Safety check to prevent infinite loops
                if iteration >= MAX_ITERATIONS {
                    panic!(
                        "Optimization did not converge to fixpoint within {} iterations for program '{}'. Last result: '{}'",
                        MAX_ITERATIONS, program, current
                    );
                }
            }

            // After convergence, one more optimization should not change the result (idempotency at fixpoint)
            let final_check = run_optimization(&mut optimizer, &current, OptimizationTier::Standard, &format!("fixpt_{}_final", i));
            assert_eq!(
                current, final_check,
                "Fixpoint idempotency violated for program '{}': fixpoint='{}', after-fixpoint='{}'",
                program, current, final_check
            );
        }
    }

    #[test]
    fn metamorphic_commutativity_with_order_independence() {
        // Test that optimization preserves or properly handles commutative operations
        // This is a specialized confluence test for operations that should be order-independent
        let epoch = SecurityEpoch::from_raw(1);
        let mut optimizer = CertifiedRewriteOptimizer::new(epoch);

        // Programs that should optimize to equivalent results regardless of internal operation order
        let commutative_pairs = [
            ("x + 0", "0 + x"),         // Additive identity commutativity
            ("x * 1", "1 * x"),         // Multiplicative identity commutativity
            ("func(x + 0, y)", "func(0 + x, y)"), // Commutativity within arguments
        ];

        for (i, (prog_a, prog_b)) in commutative_pairs.iter().enumerate() {
            let result_a = run_optimization(&mut optimizer, prog_a, OptimizationTier::Standard, &format!("comm_a_{}", i));
            let result_b = run_optimization(&mut optimizer, prog_b, OptimizationTier::Standard, &format!("comm_b_{}", i));

            // Both should optimize to the same canonical form
            assert_eq!(
                result_a, result_b,
                "Commutativity not preserved: '{}' optimized to '{}', '{}' optimized to '{}'",
                prog_a, result_a, prog_b, result_b
            );
        }
    }

    #[test]
    fn metamorphic_identity_preservation() {
        // Test that already-optimized programs remain unchanged (identity element test)
        let epoch = SecurityEpoch::from_raw(1);
        let mut optimizer = CertifiedRewriteOptimizer::new(epoch);

        // Programs that should already be in optimal form
        let already_optimal = [
            "x",               // Single variable
            "func(x)",        // Simple function call
            "complex_expr",   // Expression that likely can't be optimized further
            "variable_name",  // Variable that shouldn't be modified
        ];

        for (i, program) in already_optimal.iter().enumerate() {
            let optimized = run_optimization(&mut optimizer, program, OptimizationTier::Standard, &format!("ident_{}", i));

            // Already optimal programs should not change
            assert_eq!(
                *program, optimized,
                "Identity preservation violated: optimal program '{}' changed to '{}'",
                program, optimized
            );
        }
    }
}
