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

use serde::{Deserialize, Serialize};

use crate::ast::SourceSpan;
use crate::eprocess_guardrail::{
    EProcessGuardrail, ExpectedLossMatrix, GuardrailRegistry, ThresholdLikelihoodRatio,
};
use crate::evidence_ledger::{
    EvidenceSignatureEnvelope, EvidenceSigningAuthority, EvidenceTrustRegistry,
    LabEvidenceAuthority, RuntimeEvidenceAuthority,
};
use crate::hash_tiers::ContentHash;
use crate::martingale_decision_ledger::StoppingThreshold;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for guardplane integration contract.
pub const GUARDPLANE_INTEGRATION_SCHEMA_VERSION: &str = "franken-engine.guardplane-integration.v2";
/// Component name for evidence linkage.
pub const GUARDPLANE_INTEGRATION_COMPONENT: &str = "guardplane_integration";
/// Policy ID binding for this module.
pub const GUARDPLANE_INTEGRATION_POLICY_ID: &str = "RC-4";
/// Canonical producer ID for guardplane decision evidence.
pub const GUARDPLANE_EVIDENCE_PRODUCER_ID: &str = "franken-engine.guardplane";
/// Domain separator for guardplane evidence signatures.
pub const GUARDPLANE_EVIDENCE_SIGNATURE_DOMAIN: &str =
    "franken-engine.guardplane.decision-evidence.signature.v2";
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
const RISK_SCORE_MAX: u32 = 1_000_000;
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

fn stricter_guardplane_action(left: HookAction, right: HookAction) -> HookAction {
    if left.severity_level() >= right.severity_level() {
        left
    } else {
        right
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
    /// Evidence authenticity verification failed.
    EvidenceVerificationFailed(String),
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
            Self::EvidenceVerificationFailed(msg) => {
                write!(f, "Evidence verification failed: {}", msg)
            }
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
    /// Unique decision ID, deterministically derived from the canonical
    /// content of this evidence record. Format: `decision_<seq>_<hex>` where
    /// `<seq>` is the issuing adapter's per-adapter sequence number and
    /// `<hex>` is the 16-hex-digit prefix of the SHA-256 content hash over
    /// the canonical preimage (excluding decision_id itself). Two replays
    /// of byte-identical evidence inputs produce byte-identical decision_ids.
    /// bd-jn3uv: prior to this format the decision_id contained a
    /// `rand::random::<u64>()` suffix which made the chain unreplayable.
    pub decision_id: String,
    /// Logical decision sequence (NOT a wall-clock timestamp). Monotonically
    /// increasing per `BasicGuardplaneAdapter` instance. Filled by the
    /// adapter's `decision_sequence` counter at evidence-generation time so
    /// the evidence chain replays byte-identically. bd-jn3uv: prior to this
    /// the field stored `SystemTime::now().as_secs()` which made the
    /// evidence_hash wall-clock-dependent. Operators who need wall-time
    /// correlation should use the separately bound
    /// [`crate::security_epoch::SecurityEpoch`] rather than this field.
    pub timestamp: u64,
    /// Runtime security epoch bound into both the evidence hash and signature
    /// envelope. This is distinct from `timestamp`, which is a replay-stable
    /// per-adapter decision sequence.
    pub security_epoch: SecurityEpoch,
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
    /// Provenance-bound signature envelope (if evidence signing is enabled).
    /// Verifiers must authenticate this against an externally supplied trust
    /// registry; the claimant's embedded verification key is not a trust root.
    pub signature: Option<EvidenceSignatureEnvelope>,
}

impl GuardplaneDecisionEvidence {
    /// Recompute the integrity hash over the unsigned decision evidence fields.
    pub fn recompute_evidence_hash(&self) -> Result<ContentHash, GuardplaneError> {
        compute_guardplane_evidence_hash(
            &self.decision_id,
            self.timestamp,
            self.security_epoch,
            &self.operation_context,
            &self.risk_assessment,
            self.action,
            &self.reason,
        )
    }

    /// Verify integrity and producer authenticity through an externally
    /// populated production runtime trust registry.
    pub fn verify_runtime_signature(
        &self,
        trust_registry: &EvidenceTrustRegistry,
    ) -> Result<(), GuardplaneError> {
        trust_registry
            .ensure_runtime_scope()
            .map_err(|error| GuardplaneError::EvidenceVerificationFailed(error.to_string()))?;
        self.verify_signature_with_registry(trust_registry)
    }

    /// Verify an explicitly lab-scoped fixture. A runtime trust registry is
    /// rejected here just as a lab registry is rejected by
    /// [`Self::verify_runtime_signature`].
    pub fn verify_signature_for_lab(
        &self,
        trust_registry: &EvidenceTrustRegistry,
    ) -> Result<(), GuardplaneError> {
        trust_registry
            .ensure_lab_scope()
            .map_err(|error| GuardplaneError::EvidenceVerificationFailed(error.to_string()))?;
        self.verify_signature_with_registry(trust_registry)
    }

    fn verify_signature_with_registry(
        &self,
        trust_registry: &EvidenceTrustRegistry,
    ) -> Result<(), GuardplaneError> {
        let signature = self.signature.as_ref().ok_or_else(|| {
            GuardplaneError::EvidenceVerificationFailed(
                "guardplane decision evidence has no signature envelope".to_string(),
            )
        })?;
        if signature.producer_id != GUARDPLANE_EVIDENCE_PRODUCER_ID {
            return Err(GuardplaneError::EvidenceVerificationFailed(format!(
                "guardplane decision evidence producer must be {GUARDPLANE_EVIDENCE_PRODUCER_ID}, got {}",
                signature.producer_id
            )));
        }
        let recomputed_hash = self.recompute_evidence_hash()?;
        if !self.evidence_hash.constant_time_eq(&recomputed_hash) {
            return Err(GuardplaneError::EvidenceVerificationFailed(
                "guardplane decision evidence hash mismatch".to_string(),
            ));
        }
        trust_registry
            .verify_detached(signature, &self.signature_payload()?, self.security_epoch)
            .map_err(|error| GuardplaneError::EvidenceVerificationFailed(error.to_string()))
    }

    fn signature_payload(&self) -> Result<Vec<u8>, GuardplaneError> {
        serde_json::to_vec(&GuardplaneDecisionEvidenceSignaturePayload {
            schema_version: GUARDPLANE_INTEGRATION_SCHEMA_VERSION,
            component: GUARDPLANE_INTEGRATION_COMPONENT,
            policy_id: GUARDPLANE_INTEGRATION_POLICY_ID,
            signature_domain: GUARDPLANE_EVIDENCE_SIGNATURE_DOMAIN,
            evidence_hash: &self.evidence_hash,
        })
        .map_err(|err| GuardplaneError::EvidenceGenerationFailed(err.to_string()))
    }
}

#[derive(Serialize)]
struct GuardplaneDecisionEvidenceHashPreimage<'a> {
    schema_version: &'static str,
    component: &'static str,
    policy_id: &'static str,
    decision_id: &'a str,
    timestamp: u64,
    security_epoch: SecurityEpoch,
    operation_context: &'a OperationContext,
    risk_assessment: &'a RiskAssessment,
    action: HookAction,
    reason: &'a str,
}

#[derive(Serialize)]
struct GuardplaneDecisionEvidenceSignaturePayload<'a> {
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
    /// Unified substrate from AA.1/AA.2 for martingale-based decisions
    pub unified_guardrail_registry: GuardrailRegistry,
    /// Monotonic per-adapter counter feeding the deterministic decision_id
    /// (and the `timestamp` field, which is now interpreted as a logical
    /// decision sequence — see [`GuardplaneDecisionEvidence::timestamp`]).
    /// bd-jn3uv: prior to this counter the evidence chain stamped
    /// `SystemTime::now().as_secs()` and a `rand::random::<u64>()` suffix,
    /// which made the chain unreplayable; the counter restores the
    /// "deterministic replay" property the module-level docstring asserts.
    decision_sequence: u64,
    /// Non-serializable signing capability supplied by the composition root.
    evidence_signing_authority: Option<EvidenceSigningAuthority>,
    /// Runtime epoch bound into every emitted evidence record and envelope.
    evidence_epoch: SecurityEpoch,
}

/// Configuration for guardplane behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Whether evidence emission must fail closed when no signing authority is configured.
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
    /// Create an adapter without a signing authority.
    ///
    /// This succeeds only when evidence emission is disabled or unsigned
    /// evidence is explicitly permitted. The default configuration therefore
    /// fails closed; production composition roots must use
    /// [`Self::new_with_runtime_authority`].
    pub fn new(config: GuardplaneConfig) -> Result<Self, GuardplaneError> {
        Self::new_with_authority(config, None, SecurityEpoch::GENESIS)
    }

    /// Create a production adapter with a runtime-owned signing authority.
    pub fn new_with_runtime_authority(
        config: GuardplaneConfig,
        authority: RuntimeEvidenceAuthority,
        evidence_epoch: SecurityEpoch,
    ) -> Result<Self, GuardplaneError> {
        Self::new_with_authority(
            config,
            Some(EvidenceSigningAuthority::Runtime(authority)),
            evidence_epoch,
        )
    }

    /// Create an explicitly lab-scoped adapter with deterministic fixture
    /// authority. Lab provenance is signature-bound and cannot be authorized
    /// by a production runtime trust registry.
    pub fn new_for_lab(
        config: GuardplaneConfig,
        authority: LabEvidenceAuthority,
        evidence_epoch: SecurityEpoch,
    ) -> Result<Self, GuardplaneError> {
        Self::new_with_authority(
            config,
            Some(EvidenceSigningAuthority::Lab(authority)),
            evidence_epoch,
        )
    }

    fn new_with_authority(
        config: GuardplaneConfig,
        evidence_signing_authority: Option<EvidenceSigningAuthority>,
        evidence_epoch: SecurityEpoch,
    ) -> Result<Self, GuardplaneError> {
        let thresholds = [
            ("challenge_threshold", config.challenge_threshold),
            ("sandbox_threshold", config.sandbox_threshold),
            ("suspend_threshold", config.suspend_threshold),
            ("terminate_threshold", config.terminate_threshold),
        ];
        if let Some((name, value)) = thresholds.iter().find(|(_, value)| *value > RISK_SCORE_MAX) {
            return Err(GuardplaneError::ConfigurationError(format!(
                "{name} must be within [0, {RISK_SCORE_MAX}], got {value}"
            )));
        }
        if !thresholds.windows(2).all(|pair| pair[0].1 <= pair[1].1) {
            return Err(GuardplaneError::ConfigurationError(
                "guardplane thresholds must satisfy challenge <= sandbox <= suspend <= terminate"
                    .to_string(),
            ));
        }

        if config.emit_evidence
            && config.require_evidence_signature
            && evidence_signing_authority.is_none()
        {
            return Err(GuardplaneError::ConfigurationError(
                "guardplane evidence signing is required but no runtime authority is configured"
                    .to_string(),
            ));
        }

        if let Some(authority) = evidence_signing_authority.as_ref() {
            let identity = authority.verification_identity();
            if identity.producer_id != GUARDPLANE_EVIDENCE_PRODUCER_ID {
                return Err(GuardplaneError::ConfigurationError(format!(
                    "guardplane evidence authority producer must be {GUARDPLANE_EVIDENCE_PRODUCER_ID}, got {}",
                    identity.producer_id
                )));
            }
            if identity.key_provenance.activation_epoch.as_u64() > evidence_epoch.as_u64() {
                return Err(GuardplaneError::ConfigurationError(format!(
                    "guardplane evidence key {} activates at epoch {}, after adapter epoch {}",
                    identity.key_provenance.key_id,
                    identity.key_provenance.activation_epoch.as_u64(),
                    evidence_epoch.as_u64()
                )));
            }
        }

        let mut unified_guardrail_registry = GuardrailRegistry::new();

        // Create expected-loss matrix for integration decisions
        let mut action_losses = std::collections::BTreeMap::new();
        action_losses.insert("allow".to_string(), 100_000); // 0.1 loss for allow
        action_losses.insert("challenge".to_string(), 300_000); // 0.3 loss for challenge
        action_losses.insert("sandbox".to_string(), 600_000); // 0.6 loss for sandbox
        action_losses.insert("deny".to_string(), 900_000); // 0.9 loss for deny

        let expected_loss_matrix = ExpectedLossMatrix::new(
            action_losses,
            500_000, // Block actions with loss >= 0.5
        );

        // Create stopping threshold for integration decisions
        let stopping_threshold = StoppingThreshold::try_from_log_millionths(2_996_000)
            .unwrap_or_else(|_| StoppingThreshold::try_from_log_millionths(1_000_000).unwrap());

        // Create unified guardrail for integration
        let unified_guardrail = EProcessGuardrail::new(
            "guardplane-integration",
            "integration-decisions",
            "unified guardplane integration decisions",
            stopping_threshold,
            expected_loss_matrix,
            evidence_epoch,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: config.challenge_threshold as i64,
                high_ratio_millionths: 3_000_000, // 3.0 ratio when above threshold
                low_ratio_millionths: 300_000,    // 0.3 ratio when below threshold
            }),
        );
        unified_guardrail_registry.add(unified_guardrail);

        Ok(Self {
            config,
            decision_history: Vec::new(),
            unified_guardrail_registry,
            decision_sequence: 0,
            evidence_signing_authority,
            evidence_epoch,
        })
    }

    fn unified_action_for_observation(
        &mut self,
        observation_millionths: i64,
        containment_action: HookAction,
    ) -> HookAction {
        let guardrail_errors = self
            .unified_guardrail_registry
            .update_stream("integration-decisions", observation_millionths);
        if !guardrail_errors.is_empty()
            || !self.unified_guardrail_registry.blocked_actions().is_empty()
        {
            containment_action
        } else {
            HookAction::Allow
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
    ///
    /// bd-jn3uv: the timestamp + decision_id are now derived from a
    /// deterministic monotonic counter (`self.decision_sequence`) and the
    /// canonical content hash of the evidence body, rather than
    /// `SystemTime::now()` and `rand::random::<u64>()`. This restores the
    /// "deterministic replay" property the module asserts: two byte-identical
    /// (context, risk, action) inputs to the same adapter produce
    /// byte-identical evidence records and (if signed) byte-identical
    /// signatures, so the audit chain re-verifies under replay.
    fn generate_evidence(
        &mut self,
        context: &OperationContext,
        risk: &RiskAssessment,
        action: HookAction,
    ) -> Result<GuardplaneDecisionEvidence, GuardplaneError> {
        let sequence = self.decision_sequence;
        let next_sequence = sequence.checked_add(1).ok_or_else(|| {
            GuardplaneError::EvidenceGenerationFailed(
                "guardplane decision sequence exhausted".to_string(),
            )
        })?;
        let timestamp = sequence;

        let reason = format!(
            "Risk score {} (threshold {}) → {}",
            format_millionths_three_decimals(risk.risk_score),
            format_millionths_three_decimals(self.config.challenge_threshold),
            action
        );

        // decision_id is the content-hash prefix of the canonical preimage
        // (excluding decision_id itself, since it is being derived). This is
        // the bd-jn3uv fix: replaces `format!("decision_{}_{}", timestamp,
        // rand::random::<u64>())` with a deterministic hash so two replays
        // produce the same decision_id.
        let decision_id = derive_deterministic_decision_id(
            sequence,
            timestamp,
            self.evidence_epoch,
            context,
            risk,
            action,
            &reason,
        )?;

        let evidence_hash = compute_guardplane_evidence_hash(
            &decision_id,
            timestamp,
            self.evidence_epoch,
            context,
            risk,
            action,
            &reason,
        )?;

        let mut evidence = GuardplaneDecisionEvidence {
            decision_id,
            timestamp,
            security_epoch: self.evidence_epoch,
            operation_context: context.clone(),
            risk_assessment: risk.clone(),
            action,
            reason,
            evidence_hash,
            signature: None,
        };

        match self.evidence_signing_authority.as_ref() {
            Some(authority) => {
                evidence.signature = Some(
                    authority
                        .sign_detached(&evidence.signature_payload()?, self.evidence_epoch)
                        .map_err(|error| {
                            GuardplaneError::EvidenceGenerationFailed(error.to_string())
                        })?,
                );
            }
            None if self.config.require_evidence_signature => {
                return Err(GuardplaneError::ConfigurationError(
                    "guardplane evidence signing is required but no signing authority is configured"
                        .to_string(),
                ));
            }
            None => {}
        }

        // Commit the sequence only after every fallible evidence operation has
        // succeeded. A missing or failed signer cannot create a hidden gap.
        self.decision_sequence = next_sequence;
        Ok(evidence)
    }
}

fn format_millionths_three_decimals(value: u32) -> String {
    // Round fixed-point millionths to three decimal places using integers so
    // signed evidence never depends on platform floating-point formatting.
    let rounded_thousandths = (u64::from(value) + 500) / 1_000;
    format!(
        "{}.{:03}",
        rounded_thousandths / 1_000,
        rounded_thousandths % 1_000
    )
}

/// bd-jn3uv: deterministic decision_id derivation.
///
/// The decision_id is `decision_<seq>_<16-hex-prefix>` where the prefix is a
/// SHA-256 content hash over the canonical preimage *excluding* decision_id
/// itself (since decision_id is what we are deriving). This replaces the
/// previous `format!("decision_{}_{}", SystemTime::now().as_secs(),
/// rand::random::<u64>())` construction, which made decision_ids unique only
/// to the wall-clock instant of generation and broke the chain's replay
/// determinism contract.
///
/// Sequence number is included BOTH as a prefix and inside the hash so two
/// records with otherwise-identical canonical bodies but emitted at
/// different sequence positions get distinct decision_ids; without the
/// sequence, idempotent retries would produce the same decision_id (which
/// callers may or may not want — this construction prefers explicit
/// monotonic identity).
fn derive_deterministic_decision_id(
    sequence: u64,
    timestamp: u64,
    security_epoch: SecurityEpoch,
    operation_context: &OperationContext,
    risk_assessment: &RiskAssessment,
    action: HookAction,
    reason: &str,
) -> Result<String, GuardplaneError> {
    // Compute the same preimage shape compute_guardplane_evidence_hash uses,
    // but with a SENTINEL decision_id placeholder. The result is just used to
    // derive a hex digest; the sentinel ensures no field-boundary collision
    // with a real decision_id.
    const DECISION_ID_DERIVATION_SENTINEL: &str = "<bd-jn3uv:deriving-decision-id>";
    let hash = compute_guardplane_evidence_hash(
        DECISION_ID_DERIVATION_SENTINEL,
        timestamp,
        security_epoch,
        operation_context,
        risk_assessment,
        action,
        reason,
    )?;
    let hex_prefix = &hash.to_hex()[..16];
    Ok(format!("decision_{sequence}_{hex_prefix}"))
}

fn compute_guardplane_evidence_hash(
    decision_id: &str,
    timestamp: u64,
    security_epoch: SecurityEpoch,
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
        security_epoch,
        operation_context,
        risk_assessment,
        action,
        reason,
    };
    let hash_bytes = serde_json::to_vec(&hash_preimage)
        .map_err(|err| GuardplaneError::EvidenceGenerationFailed(err.to_string()))?;
    Ok(ContentHash::compute(&hash_bytes))
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
        let legacy_action = self.determine_action(&risk);

        let unified_action =
            self.unified_action_for_observation(i64::from(risk.risk_score), HookAction::Terminate);
        let final_action = stricter_guardplane_action(legacy_action, unified_action);

        // Generate and store evidence if enabled
        if self.config.emit_evidence {
            let evidence = self.generate_evidence(&op_context, &risk, final_action)?;
            self.decision_history.push(evidence);
        }

        Ok(final_action)
    }

    fn pre_call(&mut self, context: &CallContext) -> Result<HookAction, GuardplaneError> {
        // Skip guardplane for trusted code
        if context.trust_level == CodeTrustLevel::Trusted {
            return Ok(HookAction::Allow);
        }

        let op_context = OperationContext::Call(context.clone());
        let risk = self.assess_risk(&op_context)?;
        let legacy_action = self.determine_action(&risk);

        let unified_action =
            self.unified_action_for_observation(i64::from(risk.risk_score), HookAction::Terminate);
        let final_action = stricter_guardplane_action(legacy_action, unified_action);

        if self.config.emit_evidence {
            let evidence = self.generate_evidence(&op_context, &risk, final_action)?;
            self.decision_history.push(evidence);
        }

        Ok(final_action)
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
        let legacy_action = self.determine_action(&risk);

        let unified_action =
            self.unified_action_for_observation(i64::from(risk.risk_score), HookAction::Terminate);
        let final_action = stricter_guardplane_action(legacy_action, unified_action);

        if self.config.emit_evidence {
            let evidence = self.generate_evidence(&op_context, &risk, final_action)?;
            self.decision_history.push(evidence);
        }

        Ok(final_action)
    }

    fn pre_import(&mut self, context: &ImportContext) -> Result<HookAction, GuardplaneError> {
        if context.trust_level == CodeTrustLevel::Trusted {
            return Ok(HookAction::Allow);
        }

        let op_context = OperationContext::Import(context.clone());
        let risk = self.assess_risk(&op_context)?;

        // Legacy decision path (maintained for compatibility)
        let legacy_action = self.determine_action(&risk);

        let unified_action =
            self.unified_action_for_observation(i64::from(risk.risk_score), HookAction::Quarantine);
        let final_action = stricter_guardplane_action(legacy_action, unified_action);

        if self.config.emit_evidence {
            let evidence = self.generate_evidence(&op_context, &risk, final_action)?;
            self.decision_history.push(evidence);
        }

        Ok(final_action)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const LAB_FIXTURE_ID: &str = "guardplane-integration-unit-tests";

    fn lab_authority() -> LabEvidenceAuthority {
        LabEvidenceAuthority::deterministic_fixture(
            GUARDPLANE_EVIDENCE_PRODUCER_ID,
            LAB_FIXTURE_ID,
            SecurityEpoch::GENESIS,
        )
        .expect("built-in guardplane lab authority must be valid")
    }

    fn lab_adapter(config: GuardplaneConfig) -> BasicGuardplaneAdapter {
        BasicGuardplaneAdapter::new_for_lab(config, lab_authority(), SecurityEpoch::GENESIS)
            .expect("lab guardplane adapter must be valid")
    }

    fn lab_trust_registry() -> EvidenceTrustRegistry {
        EvidenceTrustRegistry::from_lab_identities(
            SecurityEpoch::GENESIS,
            [lab_authority().verification_identity()],
        )
        .expect("lab guardplane trust registry must be valid")
    }

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
    fn construction_rejects_out_of_range_thresholds() {
        let error = BasicGuardplaneAdapter::new(GuardplaneConfig {
            challenge_threshold: RISK_SCORE_MAX + 1,
            emit_evidence: false,
            ..GuardplaneConfig::default()
        })
        .expect_err("out-of-range risk thresholds must fail closed");

        assert!(matches!(
            error,
            GuardplaneError::ConfigurationError(detail)
                if detail.contains("challenge_threshold must be within")
        ));
    }

    #[test]
    fn construction_rejects_inverted_threshold_order() {
        let error = BasicGuardplaneAdapter::new(GuardplaneConfig {
            challenge_threshold: 400_000,
            sandbox_threshold: 300_000,
            emit_evidence: false,
            ..GuardplaneConfig::default()
        })
        .expect_err("inverted containment thresholds must fail closed");

        assert!(matches!(
            error,
            GuardplaneError::ConfigurationError(detail)
                if detail.contains("challenge <= sandbox <= suspend <= terminate")
        ));
    }

    #[test]
    fn signed_reason_fixed_point_formatting_is_deterministic() {
        assert_eq!(format_millionths_three_decimals(0), "0.000");
        assert_eq!(format_millionths_three_decimals(999_499), "0.999");
        assert_eq!(format_millionths_three_decimals(999_500), "1.000");
        assert_eq!(format_millionths_three_decimals(1_234_499), "1.234");
        assert_eq!(format_millionths_three_decimals(1_234_500), "1.235");
    }

    #[test]
    fn stricter_action_combination_preserves_quarantine() {
        assert_eq!(
            stricter_guardplane_action(HookAction::Quarantine, HookAction::Terminate),
            HookAction::Quarantine
        );
        assert_eq!(
            stricter_guardplane_action(HookAction::Terminate, HookAction::Quarantine),
            HookAction::Quarantine
        );
    }

    #[test]
    fn unified_guardrail_terminal_policy_is_reachable() {
        let mut adapter = lab_adapter(GuardplaneConfig::default());

        assert_eq!(
            adapter.unified_action_for_observation(1_000_000, HookAction::Terminate),
            HookAction::Allow
        );
        assert_eq!(
            adapter.unified_action_for_observation(1_000_000, HookAction::Terminate),
            HookAction::Allow
        );
        assert_eq!(
            adapter.unified_action_for_observation(1_000_000, HookAction::Terminate),
            HookAction::Terminate
        );
        assert!(
            !adapter
                .unified_guardrail_registry
                .blocked_actions()
                .is_empty(),
            "a stopped guardrail must expose its terminal action policy"
        );
    }

    #[test]
    fn unified_guardrail_uses_the_adapter_evidence_epoch() {
        let epoch = SecurityEpoch::from_raw(7);
        let adapter = BasicGuardplaneAdapter::new_for_lab(
            GuardplaneConfig::default(),
            lab_authority(),
            epoch,
        )
        .expect("lab adapter should accept a later evidence epoch");

        assert_eq!(
            adapter
                .unified_guardrail_registry
                .get("guardplane-integration")
                .expect("integration guardrail should be registered")
                .config_epoch(),
            epoch
        );
    }

    #[test]
    fn test_basic_guardplane_adapter_trusted_code() {
        let config = GuardplaneConfig::default();
        let mut adapter = lab_adapter(config);

        let context = PropertyAccessContext {
            object_id: 1,
            property_key: "test".to_string(),
            access_type: PropertyAccessType::Get,
            source_span: SourceSpan::new(0, 4, 1, 0, 1, 4),
            trust_level: CodeTrustLevel::Trusted,
            extension_id: None,
        };

        // SAFETY: Test setup with valid context should allow pre_property_access to succeed
        let action = adapter
            .pre_property_access(&context)
            .expect("operation should succeed for valid inputs");
        assert_eq!(action, HookAction::Allow);
        assert!(
            adapter.decision_history.is_empty(),
            "No evidence for trusted code"
        );
    }

    #[test]
    fn test_basic_guardplane_adapter_untrusted_code() {
        let config = GuardplaneConfig::default();
        let mut adapter = lab_adapter(config);

        let context = PropertyAccessContext {
            object_id: 1,
            property_key: "test".to_string(),
            access_type: PropertyAccessType::Set, // Higher risk than Get
            source_span: SourceSpan::new(0, 4, 1, 0, 1, 4),
            trust_level: CodeTrustLevel::Untrusted,
            extension_id: Some("test-extension".to_string()),
        };

        // SAFETY: Test setup with valid context should allow pre_property_access to succeed
        let action = adapter
            .pre_property_access(&context)
            .expect("operation should succeed for valid inputs");
        assert_ne!(action, HookAction::Allow); // Should be challenged or sandboxed
        assert!(
            !adapter.decision_history.is_empty(),
            "Should generate evidence"
        );
    }

    #[test]
    fn test_risk_assessment_by_operation_type() {
        let config = GuardplaneConfig::default();
        let adapter = lab_adapter(config);

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
        let delete_risk = adapter
            .assess_risk(&delete_ctx)
            .expect("operation should succeed for valid inputs");
        // SAFETY: Test setup with valid context should allow assess_risk to succeed
        let get_risk = adapter
            .assess_risk(&get_ctx)
            .expect("operation should succeed for valid inputs");

        assert!(delete_risk.risk_score > get_risk.risk_score);
    }

    #[test]
    fn test_risk_assessment_confidence_uses_context_coverage() {
        let config = GuardplaneConfig::default();
        let adapter = lab_adapter(config);

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
        let attributed_risk = adapter
            .assess_risk(&attributed_ctx)
            .expect("operation should succeed for valid inputs");
        // SAFETY: Test setup with valid contexts should allow assess_risk to succeed
        let sparse_risk = adapter
            .assess_risk(&sparse_ctx)
            .expect("operation should succeed for valid inputs");

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
        let adapter = lab_adapter(config);

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
        let normal_risk = adapter
            .assess_risk(&normal_ctx)
            .expect("operation should succeed for valid inputs");
        // SAFETY: Test setup with valid contexts should allow assess_risk to succeed
        let invalid_risk = adapter
            .assess_risk(&invalid_ctx)
            .expect("operation should succeed for valid inputs");

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

        let adapter = lab_adapter(config);

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
        assert!(matches!(
            adapter.determine_action(&medium_risk),
            HookAction::Challenge
        ));

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
        let mut adapter = lab_adapter(config);

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
            .expect("operation should succeed for valid inputs");

        assert!(!evidence.decision_id.is_empty());
        // bd-jn3uv: timestamp is now a logical sequence number starting at 0,
        // not a wall-clock seconds count. First evidence record has timestamp 0.
        // Asserting decision_id shape covers the determinism contract better.
        assert!(
            evidence.decision_id.starts_with("decision_0_"),
            "first evidence in an adapter must be decision_0_<hex>, got {}",
            evidence.decision_id
        );
        assert_eq!(evidence.action, HookAction::Sandbox);
        assert!(evidence.reason.contains("Risk score"));
        assert!(
            evidence
                .signature
                .as_ref()
                .is_some_and(|envelope| !envelope.signature.is_sentinel()),
            "decision evidence must carry a provenance-bound signature"
        );
        evidence
            .verify_signature_for_lab(&lab_trust_registry())
            .expect("decision evidence must verify through external lab trust");
    }

    // -----------------------------------------------------------------------
    // bd-jn3uv: deterministic replay regression tests
    //
    // Asserts the contract from the module-level docstring ("Deterministic:
    // risk assessment follows deterministic replay semantics") at the
    // evidence-generation layer specifically. Two BasicGuardplaneAdapter
    // instances fed byte-identical (context, risk, action) sequences must
    // produce byte-identical evidence records — including decision_id,
    // timestamp, evidence_hash, and signature. The previous SystemTime +
    // rand::random construction made this assertion impossible.
    // -----------------------------------------------------------------------

    fn deterministic_test_context() -> OperationContext {
        OperationContext::Call(CallContext {
            function_id: 7,
            arg_count: 1,
            call_type: CallType::Function,
            source_span: SourceSpan::new(0, 8, 1, 0, 1, 8),
            trust_level: CodeTrustLevel::Untrusted,
            extension_id: Some("ext-jn3uv".to_string()),
        })
    }

    fn deterministic_test_risk() -> RiskAssessment {
        RiskAssessment {
            risk_score: 500_000,
            risk_factors: vec!["jn3uv-test".to_string()],
            confidence: 950_000,
            e_process_boundaries: Vec::new(),
            policy_violations: Vec::new(),
        }
    }

    #[test]
    fn evidence_sequence_starts_at_zero_and_increments() {
        let mut adapter = lab_adapter(GuardplaneConfig::default());
        let context = deterministic_test_context();
        let risk = deterministic_test_risk();

        let first = adapter
            .generate_evidence(&context, &risk, HookAction::Allow)
            .expect("first generate_evidence");
        let second = adapter
            .generate_evidence(&context, &risk, HookAction::Allow)
            .expect("second generate_evidence");
        let third = adapter
            .generate_evidence(&context, &risk, HookAction::Allow)
            .expect("third generate_evidence");

        assert_eq!(first.timestamp, 0, "first sequence is 0");
        assert_eq!(second.timestamp, 1, "second sequence is 1");
        assert_eq!(third.timestamp, 2, "third sequence is 2");
        assert!(first.decision_id.starts_with("decision_0_"));
        assert!(second.decision_id.starts_with("decision_1_"));
        assert!(third.decision_id.starts_with("decision_2_"));
    }

    #[test]
    fn two_adapters_with_identical_input_streams_produce_byte_identical_evidence() {
        // bd-jn3uv core regression: this assertion was impossible under the
        // previous SystemTime + rand::random construction. If it ever fails
        // again, the wall-clock dependence has crept back.
        let config = GuardplaneConfig::default();
        let mut adapter_a = lab_adapter(config.clone());
        let mut adapter_b = lab_adapter(config);
        let context = deterministic_test_context();
        let risk = deterministic_test_risk();

        for action in [
            HookAction::Allow,
            HookAction::Challenge,
            HookAction::Sandbox,
        ] {
            let ev_a = adapter_a
                .generate_evidence(&context, &risk, action)
                .expect("adapter_a generate_evidence");
            let ev_b = adapter_b
                .generate_evidence(&context, &risk, action)
                .expect("adapter_b generate_evidence");
            assert_eq!(
                ev_a, ev_b,
                "two adapters fed identical input streams must produce identical evidence; \\
                 divergence here means bd-jn3uv has regressed and the chain is no longer replayable"
            );
        }
    }

    #[test]
    fn evidence_decision_id_is_a_deterministic_content_hash() {
        // The decision_id format is `decision_<seq>_<16-hex>` where the
        // hex digits are a SHA-256-prefix of the canonical evidence body.
        // Distinct (context, risk, action) tuples at the same sequence
        // position must produce distinct hex tails — otherwise the
        // attacker can collide two different decisions under the same id.
        let mut adapter = lab_adapter(GuardplaneConfig::default());
        let context = deterministic_test_context();
        let risk = deterministic_test_risk();

        let mut adapter_b = lab_adapter(GuardplaneConfig::default());
        let alt_risk = RiskAssessment {
            risk_score: risk.risk_score + 1,
            ..risk.clone()
        };

        let ev_a = adapter
            .generate_evidence(&context, &risk, HookAction::Allow)
            .expect("evidence a");
        let ev_b = adapter_b
            .generate_evidence(&context, &alt_risk, HookAction::Allow)
            .expect("evidence b");

        assert_eq!(ev_a.timestamp, 0);
        assert_eq!(ev_b.timestamp, 0);
        assert_ne!(
            ev_a.decision_id, ev_b.decision_id,
            "decision_id must depend on the canonical body; \\
             two decisions differing in risk_score must get different decision_ids"
        );
        assert_ne!(
            ev_a.evidence_hash, ev_b.evidence_hash,
            "evidence_hash must depend on the canonical body"
        );
    }

    #[test]
    fn evidence_sequence_exhaustion_fails_closed_without_duplicate_id() {
        let mut adapter = lab_adapter(GuardplaneConfig::default());
        adapter.decision_sequence = u64::MAX - 1;
        let context = deterministic_test_context();
        let risk = deterministic_test_risk();

        let final_evidence = adapter
            .generate_evidence(&context, &risk, HookAction::Allow)
            .expect("the final non-overflowing sequence should be usable");
        assert_eq!(final_evidence.timestamp, u64::MAX - 1);
        let expected_prefix = format!("decision_{}_", u64::MAX - 1);
        assert!(final_evidence.decision_id.starts_with(&expected_prefix));

        let error = adapter
            .generate_evidence(&context, &risk, HookAction::Allow)
            .expect_err("sequence exhaustion must not reuse the final decision id");
        assert!(matches!(
            error,
            GuardplaneError::EvidenceGenerationFailed(message)
                if message.contains("sequence exhausted")
        ));
        assert_eq!(adapter.decision_sequence, u64::MAX);
    }

    #[test]
    fn evidence_no_longer_calls_systemtime_or_rand() {
        // Architectural regression guard: this test is more of a code-shape
        // assertion than a behavior test. If a future refactor reintroduces a
        // wall-clock or randomness call in evidence generation, the module
        // re-introduces `use std::time::...` or `use rand::...`. Both were
        // intentionally removed by bd-jn3uv. We assert their absence here so a
        // code-review reviewer is forced to confront the deterministic-replay
        // contract.
        //
        // Two subtleties this guard MUST handle, because `include_str!` pulls
        // in this very file (bd-o4cbn.3.3.* gate fix):
        //   1. Doc/line comments here describe the *removed* historical
        //      construction, so we scan code lines only (full-line comments
        //      stripped) to avoid matching that prose.
        //   2. The forbidden needles are assembled by concatenation so neither
        //      this `contains` call nor the failure messages embed the literal
        //      pattern verbatim (which would make the guard match itself and
        //      fail unconditionally).
        const MODULE_SOURCE: &str = include_str!("guardplane_integration.rs");
        let code_only: String = MODULE_SOURCE
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let systemtime_now_call = ["SystemTime", "::now()"].concat();
        let rand_random_call = ["rand", "::random"].concat();
        assert!(
            !code_only.contains(&systemtime_now_call),
            "bd-jn3uv: evidence generation must not call the wall-clock now() — \\
             if you reintroduce it, you must also reintroduce a deterministic-clock \\
             alternative for the replay path"
        );
        assert!(
            !code_only.contains(&rand_random_call),
            "bd-jn3uv: evidence generation must not call the rand crate — \\
             decision_id is now a deterministic content hash"
        );
    }
}
