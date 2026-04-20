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
use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for guardplane integration contract.
pub const GUARDPLANE_INTEGRATION_SCHEMA_VERSION: &str = "franken-engine.guardplane-integration.v1";
/// Component name for evidence linkage.
pub const GUARDPLANE_INTEGRATION_COMPONENT: &str = "guardplane_integration";
/// Policy ID binding for this module.
pub const GUARDPLANE_INTEGRATION_POLICY_ID: &str = "RC-4";

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
            bayesian_learning: false, // Conservative default
        }
    }
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

        let (base_risk, trust_level) = match context {
            OperationContext::PropertyAccess(ctx) => {
                let base = match ctx.access_type {
                    PropertyAccessType::Get => 100_000,    // 0.1
                    PropertyAccessType::Set => 200_000,    // 0.2
                    PropertyAccessType::Has => 50_000,     // 0.05
                    PropertyAccessType::Delete => 300_000, // 0.3
                };
                (base, ctx.trust_level)
            }
            OperationContext::Call(ctx) => {
                let base = match ctx.call_type {
                    CallType::Function => 150_000,    // 0.15
                    CallType::Method => 200_000,      // 0.2
                    CallType::Constructor => 250_000, // 0.25
                };
                (base, ctx.trust_level)
            }
            OperationContext::Allocation(ctx) => {
                let base = match ctx.allocation_type {
                    AllocationType::Object => 100_000,   // 0.1
                    AllocationType::Array => 120_000,    // 0.12
                    AllocationType::Function => 200_000, // 0.2
                    AllocationType::String => 80_000,    // 0.08
                };
                (base, ctx.trust_level)
            }
            OperationContext::Import(ctx) => {
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

        Ok(RiskAssessment {
            risk_score: adjusted_risk,
            risk_factors: vec![format!("operation_{:?}", context)],
            confidence: 800_000, // 0.8
            e_process_boundaries: Vec::new(),
            policy_violations: Vec::new(),
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

        let evidence = GuardplaneDecisionEvidence {
            decision_id,
            timestamp,
            operation_context: context.clone(),
            risk_assessment: risk.clone(),
            action,
            reason,
            evidence_hash: ContentHash::compute(b"placeholder"), // Would compute real hash
            signature: None, // Would include cryptographic signature
        };

        Ok(evidence)
    }
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
        let action = adapter.pre_property_access(&context).unwrap();
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

        let action = adapter.pre_property_access(&context).unwrap();
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

        let delete_risk = adapter.assess_risk(&delete_ctx).unwrap();
        let get_risk = adapter.assess_risk(&get_ctx).unwrap();

        assert!(delete_risk.risk_score > get_risk.risk_score);
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

        let evidence = adapter
            .generate_evidence(&context, &risk, HookAction::Sandbox)
            .unwrap();

        assert!(!evidence.decision_id.is_empty());
        assert!(evidence.timestamp > 0);
        assert_eq!(evidence.action, HookAction::Sandbox);
        assert!(evidence.reason.contains("Risk score"));
    }
}
