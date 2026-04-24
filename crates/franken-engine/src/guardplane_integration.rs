//! Guardplane integration into baseline interpreter execution.
//!
//! This module provides the infrastructure for wiring Bayesian risk analysis
//! into live execution through interpreter hooks. The guardplane consults
//! probabilistic policies at capability-sensitive operations and enforces
//! containment actions based on risk assessment.
//!
//! The integration is designed to be:
//! - **Optional**: hooks only fire for untrusted extension code
//! - **Fast**: trusted operations bypass guardplane consultation
//! - **Auditable**: all decisions emit signed evidence records
//! - **Deterministic**: risk assessment follows deterministic replay semantics
//!
//! Reference: [RC-4] Guardplane Wired Into Execution

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::ast::SourceSpan;
use crate::hash_tiers::{AuthenticityHash, ContentHash};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for guardplane integration contract.
pub const GUARDPLANE_INTEGRATION_SCHEMA_VERSION: &str = "franken-engine.guardplane-integration.v1";
/// Component name for evidence linkage.
pub const GUARDPLANE_INTEGRATION_COMPONENT: &str = "guardplane_integration";
/// Policy ID binding for this module.
pub const GUARDPLANE_INTEGRATION_POLICY_ID: &str = "RC-4";
/// Domain separator for guardplane evidence signatures.
pub const GUARDPLANE_EVIDENCE_SIGNATURE_DOMAIN: &str =
    "franken-engine.guardplane.decision-evidence.signature.v1";
const CONFIDENCE_MIN: u32 = 250_000;
const CONFIDENCE_MAX: u32 = 950_000;
const CONFIDENCE_BASELINE: u32 = 500_000;
const CONFIDENCE_RISK_FACTOR_BONUS: u32 = 50_000;
const CONFIDENCE_MAX_RISK_FACTOR_COUNT: usize = 4;
const CONFIDENCE_PRECISE_SPAN_BONUS: u32 = 100_000;
const CONFIDENCE_MISSING_SPAN_PENALTY: u32 = 100_000;
const CONFIDENCE_ATTRIBUTION_BONUS: u32 = 100_000;
const CONFIDENCE_MISSING_ATTRIBUTION_PENALTY: u32 = 75_000;
const CONFIDENCE_NO_VIOLATION_BONUS: u32 = 75_000;
const CONFIDENCE_POLICY_VIOLATION_PENALTY: u32 = 50_000;
const CONFIDENCE_NO_BOUNDARY_BONUS: u32 = 50_000;
const CONFIDENCE_BOUNDARY_PENALTY: u32 = 25_000;
const CONFIDENCE_LOW_RISK_BONUS: u32 = 25_000;
const CONFIDENCE_MODERATE_RISK_PENALTY: u32 = 50_000;
const CONFIDENCE_HIGH_RISK_PENALTY: u32 = 100_000;
const CONFIDENCE_MODERATE_RISK_FLOOR: u32 = 300_000;
const CONFIDENCE_HIGH_RISK_FLOOR: u32 = 600_000;
const POLICY_ALLOCATION_SOFT_LIMIT_BYTES: u64 = 64 * 1024 * 1024;
const LARGE_ALLOCATION_BYTES: u64 = 1024 * 1024;
const WIDE_CALL_ARG_COUNT: u32 = 16;

// ---------------------------------------------------------------------------
// Interpreter Hook Trait
// ---------------------------------------------------------------------------

/// Hook points for guardplane consultation during interpreter execution.
///
/// These hooks are called at capability-sensitive operations to allow
/// the guardplane to assess risk and enforce containment policies.
pub trait InterpreterHook {
    /// Called before property access (GetProperty/SetProperty).
    fn pre_property_access(
        &mut self,
        context: &PropertyAccessContext,
    ) -> Result<HookAction, GuardplaneError>;

    /// Called before function/method calls.
    fn pre_call(&mut self, context: &CallContext) -> Result<HookAction, GuardplaneError>;

    /// Called before object allocation (NewObject/NewArray).
    fn pre_allocation(
        &mut self,
        context: &AllocationContext,
    ) -> Result<HookAction, GuardplaneError>;

    /// Called before module imports.
    fn pre_import(&mut self, context: &ImportContext) -> Result<HookAction, GuardplaneError>;
}

// ---------------------------------------------------------------------------
// Hook Contexts
// ---------------------------------------------------------------------------

/// Context for property access operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyAccessContext {
    /// Object being accessed.
    pub object_id: u32,
    /// Property name/key.
    pub property_key: String,
    /// Access type (get or set).
    pub access_type: PropertyAccessType,
    /// Source location where access occurs.
    pub source_span: SourceSpan,
    /// Whether this is trusted (internal runtime) or untrusted (extension) code.
    pub trust_level: CodeTrustLevel,
    /// Extension ID if this is extension code.
    pub extension_id: Option<String>,
}

/// Context for function call operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallContext {
    /// Function being called.
    pub function_id: u32,
    /// Number of arguments.
    pub arg_count: u32,
    /// Call type (direct function, method, constructor).
    pub call_type: CallType,
    /// Source location where call occurs.
    pub source_span: SourceSpan,
    /// Trust level of calling code.
    pub trust_level: CodeTrustLevel,
    /// Extension ID if this is extension code.
    pub extension_id: Option<String>,
}

/// Context for allocation operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationContext {
    /// Type of allocation (object, array, function).
    pub allocation_type: AllocationType,
    /// Estimated size in bytes.
    pub estimated_size: u64,
    /// Source location where allocation occurs.
    pub source_span: SourceSpan,
    /// Trust level of allocating code.
    pub trust_level: CodeTrustLevel,
    /// Extension ID if this is extension code.
    pub extension_id: Option<String>,
}

/// Context for import operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportContext {
    /// Module specifier being imported.
    pub module_specifier: String,
    /// Import type (ES6, CommonJS, dynamic).
    pub import_type: ImportType,
    /// Source location where import occurs.
    pub source_span: SourceSpan,
    /// Trust level of importing code.
    pub trust_level: CodeTrustLevel,
    /// Extension ID if this is extension code.
    pub extension_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Supporting Types
// ---------------------------------------------------------------------------

/// Property access operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PropertyAccessType {
    /// Reading property value.
    Get,
    /// Writing property value.
    Set,
    /// Checking property existence.
    Has,
    /// Deleting property.
    Delete,
}

/// Function call operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallType {
    /// Direct function call.
    Function,
    /// Method call on object.
    Method,
    /// Constructor call (new).
    Constructor,
}

/// Memory allocation operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllocationType {
    /// Object allocation.
    Object,
    /// Array allocation.
    Array,
    /// Function allocation.
    Function,
    /// String allocation.
    String,
}

/// Module import operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportType {
    /// ES6 static import.
    Es6Static,
    /// ES6 dynamic import.
    Es6Dynamic,
    /// CommonJS require.
    CommonJs,
}

/// Trust level of executing code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeTrustLevel {
    /// Trusted runtime code (bypasses guardplane).
    Trusted,
    /// Untrusted extension code (triggers guardplane).
    Untrusted,
}

// ---------------------------------------------------------------------------
// Hook Actions and Containment
// ---------------------------------------------------------------------------

/// Action to take based on guardplane risk assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookAction {
    /// Allow operation to proceed normally.
    Allow,
    /// Challenge operation (request additional authorization).
    Challenge,
    /// Sandbox operation (restricted capabilities).
    Sandbox,
    /// Suspend execution temporarily.
    Suspend,
    /// Terminate execution immediately.
    Terminate,
    /// Quarantine extension (remove from fleet).
    Quarantine,
}

impl HookAction {
    /// Returns true if this action allows execution to continue.
    pub const fn allows_continuation(self) -> bool {
        matches!(self, Self::Allow | Self::Challenge | Self::Sandbox)
    }

    /// Returns true if this action stops execution.
    pub const fn stops_execution(self) -> bool {
        matches!(self, Self::Suspend | Self::Terminate | Self::Quarantine)
    }

    /// Returns the severity level of this action.
    pub const fn severity_level(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Challenge => 1,
            Self::Sandbox => 2,
            Self::Suspend => 3,
            Self::Terminate => 4,
            Self::Quarantine => 5,
        }
    }
}

impl fmt::Display for HookAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Challenge => f.write_str("challenge"),
            Self::Sandbox => f.write_str("sandbox"),
            Self::Suspend => f.write_str("suspend"),
            Self::Terminate => f.write_str("terminate"),
            Self::Quarantine => f.write_str("quarantine"),
        }
    }
}

// ---------------------------------------------------------------------------
// Guardplane Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during guardplane consultation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardplaneError {
    /// Risk assessment failed.
    RiskAssessmentFailed(String),
    /// Policy lookup failed.
    PolicyLookupFailed(String),
    /// Evidence generation failed.
    EvidenceGenerationFailed(String),
    /// Bayesian update failed.
    BayesianUpdateFailed(String),
    /// Unknown extension ID.
    UnknownExtension(String),
    /// Configuration error.
    ConfigurationError(String),
}

impl fmt::Display for GuardplaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RiskAssessmentFailed(msg) => write!(f, "Risk assessment failed: {}", msg),
            Self::PolicyLookupFailed(msg) => write!(f, "Policy lookup failed: {}", msg),
            Self::EvidenceGenerationFailed(msg) => write!(f, "Evidence generation failed: {}", msg),
            Self::BayesianUpdateFailed(msg) => write!(f, "Bayesian update failed: {}", msg),
            Self::UnknownExtension(id) => write!(f, "Unknown extension: {}", id),
            Self::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
        }
    }
}

impl std::error::Error for GuardplaneError {}

// ---------------------------------------------------------------------------
// Decision Evidence
// ---------------------------------------------------------------------------

/// Evidence record for guardplane decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardplaneDecisionEvidence {
    /// Unique decision ID.
    pub decision_id: String,
    /// Timestamp of decision.
    pub timestamp: u64,
    /// Operation context that triggered the decision.
    pub operation_context: OperationContext,
    /// Risk assessment results.
    pub risk_assessment: RiskAssessment,
    /// Final action taken.
    pub action: HookAction,
    /// Reason for the action.
    pub reason: String,
    /// Evidence hash for integrity.
    pub evidence_hash: ContentHash,
    /// Signature (if available).
    pub signature: Option<Vec<u8>>,
}

impl GuardplaneDecisionEvidence {
    /// Recompute the integrity hash over the unsigned decision evidence fields.
    pub fn recompute_evidence_hash(&self) -> Result<ContentHash, GuardplaneError> {
        compute_guardplane_evidence_hash(
            &self.decision_id,
            self.timestamp,
            &self.operation_context,
            &self.risk_assessment,
            self.action,
            &self.reason,
        )
    }

    /// Verify the evidence hash and keyed signature using constant-time tag comparison.
    pub fn verify_signature_with_key(&self, signing_key: &[u8]) -> Result<bool, GuardplaneError> {
        let Some(signature) = self.signature.as_deref() else {
            return Ok(false);
        };
        let Some(actual) = authenticity_hash_from_signature(signature) else {
            return Ok(false);
        };

        let recomputed_hash = self.recompute_evidence_hash()?;
        if !self.evidence_hash.constant_time_eq(&recomputed_hash) {
            return Ok(false);
        }

        let expected = self.compute_signature(signing_key)?;
        Ok(actual.constant_time_eq(&expected))
    }

    fn compute_signature(&self, signing_key: &[u8]) -> Result<AuthenticityHash, GuardplaneError> {
        validate_guardplane_signing_key(signing_key)?;
        let signature_bytes = serde_json::to_vec(&GuardplaneDecisionEvidenceSignaturePreimage {
            schema_version: GUARDPLANE_INTEGRATION_SCHEMA_VERSION,
            component: GUARDPLANE_INTEGRATION_COMPONENT,
            policy_id: GUARDPLANE_INTEGRATION_POLICY_ID,
            signature_domain: GUARDPLANE_EVIDENCE_SIGNATURE_DOMAIN,
            evidence_hash: &self.evidence_hash,
        })
        .map_err(|err| GuardplaneError::EvidenceGenerationFailed(err.to_string()))?;

        Ok(AuthenticityHash::compute_keyed(
            signing_key,
            &signature_bytes,
        ))
    }
}

#[derive(Serialize)]
struct GuardplaneDecisionEvidenceHashPreimage<'a> {
    schema_version: &'static str,
    component: &'static str,
    policy_id: &'static str,
    decision_id: &'a str,
    timestamp: u64,
    operation_context: &'a OperationContext,
    risk_assessment: &'a RiskAssessment,
    action: HookAction,
    reason: &'a str,
}

#[derive(Serialize)]
struct GuardplaneDecisionEvidenceSignaturePreimage<'a> {
    schema_version: &'static str,
    component: &'static str,
    policy_id: &'static str,
    signature_domain: &'static str,
    evidence_hash: &'a ContentHash,
}

/// Context of the operation that triggered guardplane consultation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "context")]
pub enum OperationContext {
    /// Property access operation.
    PropertyAccess(PropertyAccessContext),
    /// Function call operation.
    Call(CallContext),
    /// Allocation operation.
    Allocation(AllocationContext),
    /// Import operation.
    Import(ImportContext),
}

/// Risk assessment results from Bayesian analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Overall risk score (0.0 to 1.0).
    pub risk_score: u32, // Fixed-point: 1_000_000 = 1.0
    /// Risk factors identified.
    pub risk_factors: Vec<String>,
    /// Confidence in assessment (0.0 to 1.0).
    pub confidence: u32, // Fixed-point: 1_000_000 = 1.0
    /// E-process boundaries crossed.
    pub e_process_boundaries: Vec<String>,
    /// Policy violations detected.
    pub policy_violations: Vec<String>,
}

// ---------------------------------------------------------------------------
// Basic Guardplane Adapter
// ---------------------------------------------------------------------------

/// Basic guardplane adapter that implements conservative policies.
#[derive(Debug)]
pub struct BasicGuardplaneAdapter {
    /// Configuration for the guardplane.
    pub config: GuardplaneConfig,
    /// Decision history for learning.
    pub decision_history: Vec<GuardplaneDecisionEvidence>,
}

/// Configuration for guardplane behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardplaneConfig {
    /// Risk threshold for challenge (0.0 to 1.0, fixed-point).
    pub challenge_threshold: u32,
    /// Risk threshold for sandbox (0.0 to 1.0, fixed-point).
    pub sandbox_threshold: u32,
    /// Risk threshold for suspend (0.0 to 1.0, fixed-point).
    pub suspend_threshold: u32,
    /// Risk threshold for terminate (0.0 to 1.0, fixed-point).
    pub terminate_threshold: u32,
    /// Whether to emit evidence records.
    pub emit_evidence: bool,
    /// Key used to produce authenticity signatures for decision evidence.
    pub evidence_signing_key: Option<Vec<u8>>,
    /// Whether evidence emission must fail closed when no signing key is configured.
    pub require_evidence_signature: bool,
    /// Whether to use Bayesian learning.
    pub bayesian_learning: bool,
}

impl Default for GuardplaneConfig {
    fn default() -> Self {
        Self {
            challenge_threshold: 200_000, // 0.2
            sandbox_threshold: 400_000,   // 0.4
            suspend_threshold: 600_000,   // 0.6
            terminate_threshold: 800_000, // 0.8
            emit_evidence: true,
            evidence_signing_key: Some(default_guardplane_evidence_signing_key()),
            require_evidence_signature: true,
            bayesian_learning: false, // Conservative default
        }
    }
}

fn record_common_context_factors(
    risk_factors: &mut Vec<String>,
    e_process_boundaries: &mut Vec<String>,
    trust_level: CodeTrustLevel,
    extension_id: Option<&str>,
) {
    match trust_level {
        CodeTrustLevel::Trusted => risk_factors.push("trust:trusted".to_string()),
        CodeTrustLevel::Untrusted => {
            risk_factors.push("trust:untrusted".to_string());
            e_process_boundaries.push("boundary:untrusted_extension".to_string());
        }
    }

    if extension_id.is_some_and(|id| !id.trim().is_empty()) {
        risk_factors.push("attribution:extension_id".to_string());
    }
}

fn property_access_type_factor(access_type: PropertyAccessType) -> &'static str {
    match access_type {
        PropertyAccessType::Get => "property:get",
        PropertyAccessType::Set => "property:set",
        PropertyAccessType::Has => "property:has",
        PropertyAccessType::Delete => "property:delete",
    }
}

fn call_type_factor(call_type: CallType) -> &'static str {
    match call_type {
        CallType::Function => "call:function",
        CallType::Method => "call:method",
        CallType::Constructor => "call:constructor",
    }
}

fn allocation_type_factor(allocation_type: AllocationType) -> &'static str {
    match allocation_type {
        AllocationType::Object => "allocation:object",
        AllocationType::Array => "allocation:array",
        AllocationType::Function => "allocation:function",
        AllocationType::String => "allocation:string",
    }
}

fn import_type_factor(import_type: ImportType) -> &'static str {
    match import_type {
        ImportType::Es6Static => "import:es6_static",
        ImportType::Es6Dynamic => "import:es6_dynamic",
        ImportType::CommonJs => "import:common_js",
    }
}

fn operation_source_span(context: &OperationContext) -> &SourceSpan {
    match context {
        OperationContext::PropertyAccess(ctx) => &ctx.source_span,
        OperationContext::Call(ctx) => &ctx.source_span,
        OperationContext::Allocation(ctx) => &ctx.source_span,
        OperationContext::Import(ctx) => &ctx.source_span,
    }
}

fn operation_trust_level(context: &OperationContext) -> CodeTrustLevel {
    match context {
        OperationContext::PropertyAccess(ctx) => ctx.trust_level,
        OperationContext::Call(ctx) => ctx.trust_level,
        OperationContext::Allocation(ctx) => ctx.trust_level,
        OperationContext::Import(ctx) => ctx.trust_level,
    }
}

fn operation_extension_id(context: &OperationContext) -> Option<&str> {
    match context {
        OperationContext::PropertyAccess(ctx) => ctx.extension_id.as_deref(),
        OperationContext::Call(ctx) => ctx.extension_id.as_deref(),
        OperationContext::Allocation(ctx) => ctx.extension_id.as_deref(),
        OperationContext::Import(ctx) => ctx.extension_id.as_deref(),
    }
}

fn source_span_is_precise(span: &SourceSpan) -> bool {
    span.end_offset > span.start_offset
        && span.start_line > 0
        && span.end_line >= span.start_line
        && (span.end_line > span.start_line || span.end_column >= span.start_column)
}

fn operation_has_attribution(context: &OperationContext) -> bool {
    operation_trust_level(context) == CodeTrustLevel::Trusted
        || operation_extension_id(context).is_some_and(|id| !id.trim().is_empty())
}

fn compute_assessment_confidence(
    context: &OperationContext,
    risk_score: u32,
    risk_factors: &[String],
    e_process_boundaries: &[String],
    policy_violations: &[String],
) -> u32 {
    let factor_count = risk_factors.len().min(CONFIDENCE_MAX_RISK_FACTOR_COUNT) as u32;
    let mut confidence =
        CONFIDENCE_BASELINE.saturating_add(factor_count * CONFIDENCE_RISK_FACTOR_BONUS);

    if source_span_is_precise(operation_source_span(context)) {
        confidence = confidence.saturating_add(CONFIDENCE_PRECISE_SPAN_BONUS);
    } else {
        confidence = confidence.saturating_sub(CONFIDENCE_MISSING_SPAN_PENALTY);
    }

    if operation_has_attribution(context) {
        confidence = confidence.saturating_add(CONFIDENCE_ATTRIBUTION_BONUS);
    } else if operation_trust_level(context) == CodeTrustLevel::Untrusted {
        confidence = confidence.saturating_sub(CONFIDENCE_MISSING_ATTRIBUTION_PENALTY);
    }

    if policy_violations.is_empty() {
        confidence = confidence.saturating_add(CONFIDENCE_NO_VIOLATION_BONUS);
    } else {
        confidence = confidence.saturating_sub(
            policy_violations
                .len()
                .min(CONFIDENCE_MAX_RISK_FACTOR_COUNT) as u32
                * CONFIDENCE_POLICY_VIOLATION_PENALTY,
        );
    }

    if e_process_boundaries.is_empty() {
        confidence = confidence.saturating_add(CONFIDENCE_NO_BOUNDARY_BONUS);
    } else {
        confidence = confidence.saturating_sub(
            e_process_boundaries
                .len()
                .min(CONFIDENCE_MAX_RISK_FACTOR_COUNT) as u32
                * CONFIDENCE_BOUNDARY_PENALTY,
        );
    }

    if risk_score >= CONFIDENCE_HIGH_RISK_FLOOR {
        confidence = confidence.saturating_sub(CONFIDENCE_HIGH_RISK_PENALTY);
    } else if risk_score >= CONFIDENCE_MODERATE_RISK_FLOOR {
        confidence = confidence.saturating_sub(CONFIDENCE_MODERATE_RISK_PENALTY);
    } else {
        confidence = confidence.saturating_add(CONFIDENCE_LOW_RISK_BONUS);
    }

    confidence.clamp(CONFIDENCE_MIN, CONFIDENCE_MAX)
}

impl BasicGuardplaneAdapter {
    /// Create a new basic guardplane adapter.
    pub fn new(config: GuardplaneConfig) -> Self {
        Self {
            config,
            decision_history: Vec::new(),
        }
    }

    /// Assess risk for a given operation context.
    fn assess_risk(&self, context: &OperationContext) -> Result<RiskAssessment, GuardplaneError> {
        // Basic risk assessment - in a full implementation this would use
        // Bayesian analysis from the existing risk modules

        let mut risk_factors = Vec::new();
        let mut e_process_boundaries = Vec::new();
        let mut policy_violations = Vec::new();

        let (base_risk, trust_level) = match context {
            OperationContext::PropertyAccess(ctx) => {
                risk_factors.push("operation:property_access".to_string());
                risk_factors.push(property_access_type_factor(ctx.access_type).to_string());
                record_common_context_factors(
                    &mut risk_factors,
                    &mut e_process_boundaries,
                    ctx.trust_level,
                    ctx.extension_id.as_deref(),
                );
                if ctx.property_key.trim().is_empty() {
                    policy_violations.push("empty_property_key".to_string());
                }
                let base = match ctx.access_type {
                    PropertyAccessType::Get => 100_000,    // 0.1
                    PropertyAccessType::Set => 200_000,    // 0.2
                    PropertyAccessType::Has => 50_000,     // 0.05
                    PropertyAccessType::Delete => 300_000, // 0.3
                };
                (base, ctx.trust_level)
            }
            OperationContext::Call(ctx) => {
                risk_factors.push("operation:call".to_string());
                risk_factors.push(call_type_factor(ctx.call_type).to_string());
                record_common_context_factors(
                    &mut risk_factors,
                    &mut e_process_boundaries,
                    ctx.trust_level,
                    ctx.extension_id.as_deref(),
                );
                if ctx.arg_count > WIDE_CALL_ARG_COUNT {
                    risk_factors.push("call:wide_argument_list".to_string());
                }
                let base = match ctx.call_type {
                    CallType::Function => 150_000,    // 0.15
                    CallType::Method => 200_000,      // 0.2
                    CallType::Constructor => 250_000, // 0.25
                };
                (base, ctx.trust_level)
            }
            OperationContext::Allocation(ctx) => {
                risk_factors.push("operation:allocation".to_string());
                risk_factors.push(allocation_type_factor(ctx.allocation_type).to_string());
                record_common_context_factors(
                    &mut risk_factors,
                    &mut e_process_boundaries,
                    ctx.trust_level,
                    ctx.extension_id.as_deref(),
                );
                if ctx.estimated_size >= LARGE_ALLOCATION_BYTES {
                    risk_factors.push("allocation:large".to_string());
                }
                if ctx.estimated_size > POLICY_ALLOCATION_SOFT_LIMIT_BYTES {
                    policy_violations.push("allocation_exceeds_soft_limit".to_string());
                }
                let base = match ctx.allocation_type {
                    AllocationType::Object => 100_000,   // 0.1
                    AllocationType::Array => 120_000,    // 0.12
                    AllocationType::Function => 200_000, // 0.2
                    AllocationType::String => 80_000,    // 0.08
                };
                (base, ctx.trust_level)
            }
            OperationContext::Import(ctx) => {
                risk_factors.push("operation:import".to_string());
                risk_factors.push(import_type_factor(ctx.import_type).to_string());
                record_common_context_factors(
                    &mut risk_factors,
                    &mut e_process_boundaries,
                    ctx.trust_level,
                    ctx.extension_id.as_deref(),
                );
                if ctx.module_specifier.trim().is_empty() {
                    policy_violations.push("empty_module_specifier".to_string());
                }
                let base = match ctx.import_type {
                    ImportType::Es6Static => 100_000,  // 0.1
                    ImportType::Es6Dynamic => 300_000, // 0.3
                    ImportType::CommonJs => 200_000,   // 0.2
                };
                (base, ctx.trust_level)
            }
        };

        // Adjust risk based on trust level
        let adjusted_risk = match trust_level {
            CodeTrustLevel::Trusted => base_risk / 10, // Trusted code gets 10x lower risk
            CodeTrustLevel::Untrusted => base_risk,
        };

        let confidence = compute_assessment_confidence(
            context,
            adjusted_risk,
            &risk_factors,
            &e_process_boundaries,
            &policy_violations,
        );

        Ok(RiskAssessment {
            risk_score: adjusted_risk,
            risk_factors,
            confidence,
            e_process_boundaries,
            policy_violations,
        })
    }

    /// Determine action based on risk assessment.
    fn determine_action(&self, risk: &RiskAssessment) -> HookAction {
        let score = risk.risk_score;

        if score >= self.config.terminate_threshold {
            HookAction::Terminate
        } else if score >= self.config.suspend_threshold {
            HookAction::Suspend
        } else if score >= self.config.sandbox_threshold {
            HookAction::Sandbox
        } else if score >= self.config.challenge_threshold {
            HookAction::Challenge
        } else {
            HookAction::Allow
        }
    }

    /// Generate evidence record for a decision.
    fn generate_evidence(
        &self,
        context: &OperationContext,
        risk: &RiskAssessment,
        action: HookAction,
    ) -> Result<GuardplaneDecisionEvidence, GuardplaneError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let decision_id = format!("decision_{}_{}", timestamp, rand::random::<u64>());

        let reason = format!(
            "Risk score {:.3} (threshold {:.3}) → {}",
            risk.risk_score as f64 / 1_000_000.0,
            self.config.challenge_threshold as f64 / 1_000_000.0,
            action
        );
        let evidence_hash = compute_guardplane_evidence_hash(
            &decision_id,
            timestamp,
            context,
            risk,
            action,
            &reason,
        )?;

        let mut evidence = GuardplaneDecisionEvidence {
            decision_id,
            timestamp,
            operation_context: context.clone(),
            risk_assessment: risk.clone(),
            action,
            reason,
            evidence_hash,
            signature: None,
        };

        match self.config.evidence_signing_key.as_deref() {
            Some(signing_key) => {
                let signature = evidence.compute_signature(signing_key)?;
                evidence.signature = Some(signature.as_bytes().to_vec());
            }
            None if self.config.require_evidence_signature => {
                return Err(GuardplaneError::ConfigurationError(
                    "guardplane evidence signing is required but no signing key is configured"
                        .to_string(),
                ));
            }
            None => {}
        }

        Ok(evidence)
    }
}

fn compute_guardplane_evidence_hash(
    decision_id: &str,
    timestamp: u64,
    operation_context: &OperationContext,
    risk_assessment: &RiskAssessment,
    action: HookAction,
    reason: &str,
) -> Result<ContentHash, GuardplaneError> {
    let hash_preimage = GuardplaneDecisionEvidenceHashPreimage {
        schema_version: GUARDPLANE_INTEGRATION_SCHEMA_VERSION,
        component: GUARDPLANE_INTEGRATION_COMPONENT,
        policy_id: GUARDPLANE_INTEGRATION_POLICY_ID,
        decision_id,
        timestamp,
        operation_context,
        risk_assessment,
        action,
        reason,
    };
    let hash_bytes = serde_json::to_vec(&hash_preimage)
        .map_err(|err| GuardplaneError::EvidenceGenerationFailed(err.to_string()))?;
    Ok(ContentHash::compute(&hash_bytes))
}

fn validate_guardplane_signing_key(signing_key: &[u8]) -> Result<(), GuardplaneError> {
    if signing_key.is_empty() {
        return Err(GuardplaneError::ConfigurationError(
            "guardplane evidence signing key must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn authenticity_hash_from_signature(signature: &[u8]) -> Option<AuthenticityHash> {
    let bytes: [u8; 32] = signature.try_into().ok()?;
    Some(AuthenticityHash(bytes))
}

fn default_guardplane_evidence_signing_key() -> Vec<u8> {
    b"franken-engine.guardplane.default-evidence-key.v1".to_vec()
}

impl InterpreterHook for BasicGuardplaneAdapter {
    fn pre_property_access(
        &mut self,
        context: &PropertyAccessContext,
    ) -> Result<HookAction, GuardplaneError> {
        // Skip guardplane for trusted code (performance optimization)
        if context.trust_level == CodeTrustLevel::Trusted {
            return Ok(HookAction::Allow);
        }

        let op_context = OperationContext::PropertyAccess(context.clone());
        let risk = self.assess_risk(&op_context)?;
        let action = self.determine_action(&risk);

        // Generate and store evidence if enabled
        if self.config.emit_evidence {
            let evidence = self.generate_evidence(&op_context, &risk, action)?;
            self.decision_history.push(evidence);
        }

        Ok(action)
    }

    fn pre_call(&mut self, context: &CallContext) -> Result<HookAction, GuardplaneError> {
        // Skip guardplane for trusted code
        if context.trust_level == CodeTrustLevel::Trusted {
            return Ok(HookAction::Allow);
        }

        let op_context = OperationContext::Call(context.clone());
        let risk = self.assess_risk(&op_context)?;
        let action = self.determine_action(&risk);

        if self.config.emit_evidence {
            let evidence = self.generate_evidence(&op_context, &risk, action)?;
            self.decision_history.push(evidence);
        }

        Ok(action)
    }

    fn pre_allocation(
        &mut self,
        context: &AllocationContext,
    ) -> Result<HookAction, GuardplaneError> {
        if context.trust_level == CodeTrustLevel::Trusted {
            return Ok(HookAction::Allow);
        }

        let op_context = OperationContext::Allocation(context.clone());
        let risk = self.assess_risk(&op_context)?;
        let action = self.determine_action(&risk);

        if self.config.emit_evidence {
            let evidence = self.generate_evidence(&op_context, &risk, action)?;
            self.decision_history.push(evidence);
        }

        Ok(action)
    }

    fn pre_import(&mut self, context: &ImportContext) -> Result<HookAction, GuardplaneError> {
        if context.trust_level == CodeTrustLevel::Trusted {
            return Ok(HookAction::Allow);
        }

        let op_context = OperationContext::Import(context.clone());
        let risk = self.assess_risk(&op_context)?;
        let action = self.determine_action(&risk);

        if self.config.emit_evidence {
            let evidence = self.generate_evidence(&op_context, &risk, action)?;
            self.decision_history.push(evidence);
        }

        Ok(action)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_action_properties() {
        assert!(HookAction::Allow.allows_continuation());
        assert!(!HookAction::Allow.stops_execution());
        assert_eq!(HookAction::Allow.severity_level(), 0);

        assert!(!HookAction::Terminate.allows_continuation());
        assert!(HookAction::Terminate.stops_execution());
        assert_eq!(HookAction::Terminate.severity_level(), 4);
    }

    #[test]
    fn test_basic_guardplane_adapter_trusted_code() {
        let config = GuardplaneConfig::default();
        let mut adapter = BasicGuardplaneAdapter::new(config);

        let context = PropertyAccessContext {
            object_id: 1,
            property_key: "test".to_string(),
            access_type: PropertyAccessType::Get,
            source_span: SourceSpan::new(0, 4, 1, 0, 1, 4),
            trust_level: CodeTrustLevel::Trusted,
            extension_id: None,
        };

        // SAFETY: Test setup with valid context should allow pre_property_access to succeed
        let action = adapter.pre_property_access(&context).expect("serde deserialization should succeed");
        assert_eq!(action, HookAction::Allow);
        assert!(
            adapter.decision_history.is_empty(),
            "No evidence for trusted code"
        );
    }

    #[test]
    fn test_basic_guardplane_adapter_untrusted_code() {
        let config = GuardplaneConfig::default();
        let mut adapter = BasicGuardplaneAdapter::new(config);

        let context = PropertyAccessContext {
            object_id: 1,
            property_key: "test".to_string(),
            access_type: PropertyAccessType::Set, // Higher risk than Get
            source_span: SourceSpan::new(0, 4, 1, 0, 1, 4),
            trust_level: CodeTrustLevel::Untrusted,
            extension_id: Some("test-extension".to_string()),
        };

        // SAFETY: Test setup with valid context should allow pre_property_access to succeed
        let action = adapter.pre_property_access(&context).expect("serde deserialization should succeed");
        assert_ne!(action, HookAction::Allow); // Should be challenged or sandboxed
        assert!(
            !adapter.decision_history.is_empty(),
            "Should generate evidence"
        );
    }

    #[test]
    fn test_risk_assessment_by_operation_type() {
        let config = GuardplaneConfig::default();
        let adapter = BasicGuardplaneAdapter::new(config);

        // Delete operation should be higher risk than Get
        let delete_ctx = OperationContext::PropertyAccess(PropertyAccessContext {
            object_id: 1,
            property_key: "test".to_string(),
            access_type: PropertyAccessType::Delete,
            source_span: SourceSpan::new(0, 4, 1, 0, 1, 4),
            trust_level: CodeTrustLevel::Untrusted,
            extension_id: None,
        });

        let get_ctx = OperationContext::PropertyAccess(PropertyAccessContext {
            object_id: 1,
            property_key: "test".to_string(),
            access_type: PropertyAccessType::Get,
            source_span: SourceSpan::new(0, 4, 1, 0, 1, 4),
            trust_level: CodeTrustLevel::Untrusted,
            extension_id: None,
        });

        // SAFETY: Test setup with valid context should allow assess_risk to succeed
        let delete_risk = adapter.assess_risk(&delete_ctx).expect("serde deserialization should succeed");
        // SAFETY: Test setup with valid context should allow assess_risk to succeed
        let get_risk = adapter.assess_risk(&get_ctx).expect("serde deserialization should succeed");

        assert!(delete_risk.risk_score > get_risk.risk_score);
    }

    #[test]
    fn test_risk_assessment_confidence_uses_context_coverage() {
        let config = GuardplaneConfig::default();
        let adapter = BasicGuardplaneAdapter::new(config);

        let attributed_ctx = OperationContext::PropertyAccess(PropertyAccessContext {
            object_id: 1,
            property_key: "test".to_string(),
            access_type: PropertyAccessType::Set,
            source_span: SourceSpan::new(0, 4, 1, 0, 1, 4),
            trust_level: CodeTrustLevel::Untrusted,
            extension_id: Some("test-extension".to_string()),
        });
        let sparse_ctx = OperationContext::PropertyAccess(PropertyAccessContext {
            object_id: 1,
            property_key: "test".to_string(),
            access_type: PropertyAccessType::Set,
            source_span: SourceSpan::new(0, 0, 0, 0, 0, 0),
            trust_level: CodeTrustLevel::Untrusted,
            extension_id: None,
        });

        // SAFETY: Test setup with valid contexts should allow assess_risk to succeed
        let attributed_risk = adapter.assess_risk(&attributed_ctx).expect("serde deserialization should succeed");
        // SAFETY: Test setup with valid contexts should allow assess_risk to succeed
        let sparse_risk = adapter.assess_risk(&sparse_ctx).expect("serde deserialization should succeed");

        assert!(
            attributed_risk.confidence > sparse_risk.confidence,
            "source coverage and extension attribution should raise confidence"
        );
        assert!(
            attributed_risk
                .risk_factors
                .iter()
                .any(|factor| factor == "attribution:extension_id"),
            "risk factors should record extension attribution"
        );
    }

    #[test]
    fn test_risk_assessment_confidence_penalizes_policy_violations() {
        let config = GuardplaneConfig::default();
        let adapter = BasicGuardplaneAdapter::new(config);

        let normal_ctx = OperationContext::Import(ImportContext {
            module_specifier: "safe-module".to_string(),
            import_type: ImportType::Es6Dynamic,
            source_span: SourceSpan::new(0, 12, 1, 0, 1, 12),
            trust_level: CodeTrustLevel::Untrusted,
            extension_id: Some("test-extension".to_string()),
        });
        let invalid_ctx = OperationContext::Import(ImportContext {
            module_specifier: "  ".to_string(),
            import_type: ImportType::Es6Dynamic,
            source_span: SourceSpan::new(0, 12, 1, 0, 1, 12),
            trust_level: CodeTrustLevel::Untrusted,
            extension_id: Some("test-extension".to_string()),
        });

        // SAFETY: Test setup with valid contexts should allow assess_risk to succeed
        let normal_risk = adapter.assess_risk(&normal_ctx).expect("serde deserialization should succeed");
        // SAFETY: Test setup with valid contexts should allow assess_risk to succeed
        let invalid_risk = adapter.assess_risk(&invalid_ctx).expect("serde deserialization should succeed");

        assert!(
            invalid_risk
                .policy_violations
                .iter()
                .any(|violation| violation == "empty_module_specifier"),
            "empty import specifier should be recorded as a policy violation"
        );
        assert!(
            invalid_risk.confidence < normal_risk.confidence,
            "policy violations should lower assessment confidence"
        );
    }

    #[test]
    fn test_action_determination() {
        let config = GuardplaneConfig {
            challenge_threshold: 100_000, // 0.1
            sandbox_threshold: 200_000,   // 0.2
            suspend_threshold: 300_000,   // 0.3
            ..Default::default()
        };

        let adapter = BasicGuardplaneAdapter::new(config);

        // Low risk → Allow
        let low_risk = RiskAssessment {
            risk_score: 50_000, // 0.05
            risk_factors: Vec::new(),
            confidence: 800_000,
            e_process_boundaries: Vec::new(),
            policy_violations: Vec::new(),
        };
        assert_eq!(adapter.determine_action(&low_risk), HookAction::Allow);

        // Medium risk → Challenge
        let medium_risk = RiskAssessment {
            risk_score: 150_000, // 0.15
            risk_factors: Vec::new(),
            confidence: 800_000,
            e_process_boundaries: Vec::new(),
            policy_violations: Vec::new(),
        };
        assert_eq!(
            adapter.determine_action(&medium_risk),
            HookAction::Challenge
        );

        // High risk → Sandbox
        let high_risk = RiskAssessment {
            risk_score: 250_000, // 0.25
            risk_factors: Vec::new(),
            confidence: 800_000,
            e_process_boundaries: Vec::new(),
            policy_violations: Vec::new(),
        };
        assert_eq!(adapter.determine_action(&high_risk), HookAction::Sandbox);
    }

    #[test]
    fn test_evidence_generation() {
        let config = GuardplaneConfig::default();
        let signing_key = config
            .evidence_signing_key
            .clone()
            .expect("default config signs evidence");
        let adapter = BasicGuardplaneAdapter::new(config);

        let context = OperationContext::Call(CallContext {
            function_id: 42,
            arg_count: 2,
            call_type: CallType::Method,
            source_span: SourceSpan::new(0, 10, 1, 0, 1, 10),
            trust_level: CodeTrustLevel::Untrusted,
            extension_id: Some("risky-extension".to_string()),
        });

        let risk = RiskAssessment {
            risk_score: 300_000, // 0.3
            risk_factors: vec!["untrusted_call".to_string()],
            confidence: 900_000,
            e_process_boundaries: Vec::new(),
            policy_violations: Vec::new(),
        };

        // SAFETY: Test setup with valid context, risk, and action should allow generate_evidence to succeed
        let evidence = adapter
            .generate_evidence(&context, &risk, HookAction::Sandbox)
            .expect("serde deserialization should succeed");

        assert!(!evidence.decision_id.is_empty());
        assert!(evidence.timestamp > 0);
        assert_eq!(evidence.action, HookAction::Sandbox);
        assert!(evidence.reason.contains("Risk score"));
        assert!(
            evidence
                .signature
                .as_ref()
                .is_some_and(|sig| sig.len() == 32),
            "decision evidence must carry a keyed authenticity signature"
        );
        assert!(
            evidence.verify_signature_with_key(&signing_key).expect("serde deserialization should succeed"),
            "decision evidence signature must verify with the configured key"
        );
    }
}
