//! Operator-facing diagnostic contract: stable error codes, severity levels,
//! remediation guidance, and evidence/replay linkage.
//!
//! Bead: bd-3nr.1.3.3 [10.13X.C3]
//!
//! This module defines the external contract for how corrected control-plane
//! semantics become user-facing and operator-facing outputs. Every internal
//! failure class (cancellation, budget exhaustion, capability denial, policy
//! denial, panic-class, compatibility drift) maps to a stable diagnostic with
//! actionable remediation, replay links, and evidence references.
//!
//! The contract ensures that release gates, dashboards, CI, and operator
//! tooling all consume the same vocabulary.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const SCHEMA_VERSION: &str = "franken-engine.operator-diagnostic-contract.v1";
pub const BEAD_ID: &str = "bd-3nr.1.3.3";
pub const POLICY_ID: &str = "10.13X.C3";
pub const COMPONENT: &str = "operator_diagnostic_contract";

// ---------------------------------------------------------------------------
// InternalFailureKind
// ---------------------------------------------------------------------------

/// Internal failure kinds that must be distinguishable through the diagnostic
/// pipeline until the intended policy edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InternalFailureKind {
    /// Operation was cancelled by the control plane.
    Cancellation,
    /// Budget exhausted before operation completed.
    BudgetExhaustion,
    /// Capability denied: caller lacks required capability.
    CapabilityDenial,
    /// Policy denied: guardplane decision rejected the operation.
    PolicyDenial,
    /// Panic-class failure: unrecoverable internal error.
    PanicClass,
    /// Compatibility/version drift between components.
    CompatibilityDrift,
    /// Domain-specific logic error (not a bug, but a user-correctable issue).
    DomainError,
    /// Infrastructure failure (network, disk, etc.).
    InfrastructureFailure,
    /// Unknown or unclassified internal failure.
    Unknown,
}

impl InternalFailureKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancellation => "cancellation",
            Self::BudgetExhaustion => "budget_exhaustion",
            Self::CapabilityDenial => "capability_denial",
            Self::PolicyDenial => "policy_denial",
            Self::PanicClass => "panic_class",
            Self::CompatibilityDrift => "compatibility_drift",
            Self::DomainError => "domain_error",
            Self::InfrastructureFailure => "infrastructure_failure",
            Self::Unknown => "unknown",
        }
    }

    /// Stable error code prefix for this failure kind.
    #[must_use]
    pub const fn error_code_prefix(self) -> &'static str {
        match self {
            Self::Cancellation => "FE-CANCEL",
            Self::BudgetExhaustion => "FE-BUDGET",
            Self::CapabilityDenial => "FE-CAPABILITY",
            Self::PolicyDenial => "FE-POLICY",
            Self::PanicClass => "FE-PANIC",
            Self::CompatibilityDrift => "FE-COMPAT",
            Self::DomainError => "FE-DOMAIN",
            Self::InfrastructureFailure => "FE-INFRA",
            Self::Unknown => "FE-UNKNOWN",
        }
    }

    /// All known failure kinds.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Cancellation,
            Self::BudgetExhaustion,
            Self::CapabilityDenial,
            Self::PolicyDenial,
            Self::PanicClass,
            Self::CompatibilityDrift,
            Self::DomainError,
            Self::InfrastructureFailure,
            Self::Unknown,
        ]
    }
}

impl fmt::Display for InternalFailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DiagnosticSeverity
// ---------------------------------------------------------------------------

/// Stable severity levels for operator diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    /// System cannot continue. Immediate operator action required.
    Fatal,
    /// Operation failed. Operator should investigate.
    Error,
    /// Operation succeeded with degradation. Operator should be aware.
    Warning,
    /// Informational diagnostic for audit trail.
    Info,
}

impl DiagnosticSeverity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fatal => "fatal",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }

    /// Numeric weight (higher = more severe).
    #[must_use]
    pub const fn weight(self) -> u32 {
        match self {
            Self::Fatal => 4,
            Self::Error => 3,
            Self::Warning => 2,
            Self::Info => 1,
        }
    }
}

impl fmt::Display for DiagnosticSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// UserImpact / OperatorImpact
// ---------------------------------------------------------------------------

/// Impact on the end user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserImpact {
    /// Request/operation failed with error visible to user.
    OperationFailed,
    /// Request succeeded but with degraded quality.
    DegradedQuality,
    /// No direct user impact.
    None,
}

impl UserImpact {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OperationFailed => "operation_failed",
            Self::DegradedQuality => "degraded_quality",
            Self::None => "none",
        }
    }
}

impl fmt::Display for UserImpact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Impact on the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorImpact {
    /// Requires immediate manual intervention.
    ImmediateAction,
    /// Should be investigated during next triage cycle.
    TriageRequired,
    /// Informational only, no action needed.
    InformationalOnly,
}

impl OperatorImpact {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ImmediateAction => "immediate_action",
            Self::TriageRequired => "triage_required",
            Self::InformationalOnly => "informational_only",
        }
    }
}

impl fmt::Display for OperatorImpact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// NextAction
// ---------------------------------------------------------------------------

/// Recommended next action for the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextAction {
    /// Retry the operation (transient failure).
    Retry,
    /// Increase budget allocation and retry.
    IncreaseBudget,
    /// Grant the required capability and retry.
    GrantCapability,
    /// Update the policy configuration.
    UpdatePolicy,
    /// Upgrade to a compatible version.
    UpgradeVersion,
    /// File a bug report with evidence bundle.
    FileBugReport,
    /// No action needed.
    NoAction,
    /// Investigate the infrastructure failure.
    InvestigateInfra,
}

impl NextAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Retry => "retry",
            Self::IncreaseBudget => "increase_budget",
            Self::GrantCapability => "grant_capability",
            Self::UpdatePolicy => "update_policy",
            Self::UpgradeVersion => "upgrade_version",
            Self::FileBugReport => "file_bug_report",
            Self::NoAction => "no_action",
            Self::InvestigateInfra => "investigate_infra",
        }
    }
}

impl fmt::Display for NextAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// PolicyMapping
// ---------------------------------------------------------------------------

/// Maps an internal failure kind to its external diagnostic contract.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PolicyMapping {
    /// Internal failure kind.
    pub failure_kind: InternalFailureKind,
    /// Stable error code for this mapping.
    pub error_code: String,
    /// Severity level.
    pub severity: DiagnosticSeverity,
    /// User impact.
    pub user_impact: UserImpact,
    /// Operator impact.
    pub operator_impact: OperatorImpact,
    /// Recommended next action.
    pub next_action: NextAction,
    /// Human-readable description.
    pub description: String,
    /// Remediation guidance.
    pub remediation: String,
    /// Whether an evidence reference is attached.
    pub has_evidence_ref: bool,
    /// Whether a replay reference is attached.
    pub has_replay_ref: bool,
}

// ---------------------------------------------------------------------------
// DiagnosticEntry
// ---------------------------------------------------------------------------

/// A concrete diagnostic emitted at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticEntry {
    /// Stable error code.
    pub error_code: String,
    /// Failure kind.
    pub failure_kind: InternalFailureKind,
    /// Severity.
    pub severity: DiagnosticSeverity,
    /// User impact.
    pub user_impact: UserImpact,
    /// Operator impact.
    pub operator_impact: OperatorImpact,
    /// Recommended next action.
    pub next_action: NextAction,
    /// Human-readable message.
    pub message: String,
    /// Remediation guidance.
    pub remediation: String,
    /// Evidence reference (trace/receipt/bundle ID).
    pub evidence_ref: Option<String>,
    /// Replay reference (command to reproduce).
    pub replay_ref: Option<String>,
    /// Structured context for dashboard/gate consumption.
    pub context: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// BoundaryPolicyMappingContract
// ---------------------------------------------------------------------------

/// The complete contract mapping internal failure kinds to external diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryPolicyMappingContract {
    /// Schema version.
    pub schema_version: String,
    /// Bead identifier.
    pub bead_id: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Component name.
    pub component: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Per-failure-kind mappings.
    pub mappings: BTreeMap<String, PolicyMapping>,
    /// Content hash for integrity.
    pub content_hash: ContentHash,
}

impl BoundaryPolicyMappingContract {
    /// Build the canonical contract with default mappings.
    #[must_use]
    pub fn canonical(epoch: SecurityEpoch) -> Self {
        let mut mappings = BTreeMap::new();
        for mapping in default_policy_mappings() {
            mappings.insert(mapping.failure_kind.as_str().to_string(), mapping);
        }
        let content_hash = compute_mappings_hash(&mappings);
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            policy_id: POLICY_ID.to_string(),
            component: COMPONENT.to_string(),
            epoch,
            mappings,
            content_hash,
        }
    }

    /// Look up the mapping for a failure kind.
    #[must_use]
    pub fn mapping_for(&self, kind: InternalFailureKind) -> Option<&PolicyMapping> {
        self.mappings.get(kind.as_str())
    }

    /// Verify the content hash.
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        let expected = compute_mappings_hash(&self.mappings);
        self.content_hash == expected
    }

    /// Emit a diagnostic entry for a given failure.
    #[must_use]
    pub fn emit_diagnostic(
        &self,
        kind: InternalFailureKind,
        message: &str,
        evidence_ref: Option<&str>,
        replay_ref: Option<&str>,
        context: BTreeMap<String, String>,
    ) -> DiagnosticEntry {
        match self.mapping_for(kind) {
            Some(mapping) => DiagnosticEntry {
                error_code: mapping.error_code.clone(),
                failure_kind: kind,
                severity: mapping.severity,
                user_impact: mapping.user_impact,
                operator_impact: mapping.operator_impact,
                next_action: mapping.next_action,
                message: message.to_string(),
                remediation: mapping.remediation.clone(),
                evidence_ref: evidence_ref.map(|s| s.to_string()),
                replay_ref: replay_ref.map(|s| s.to_string()),
                context,
            },
            None => DiagnosticEntry {
                error_code: format!("{}-UNMAPPED", kind.error_code_prefix()),
                failure_kind: kind,
                severity: DiagnosticSeverity::Error,
                user_impact: UserImpact::OperationFailed,
                operator_impact: OperatorImpact::TriageRequired,
                next_action: NextAction::FileBugReport,
                message: message.to_string(),
                remediation: "This failure kind has no mapped diagnostic. File a bug report."
                    .to_string(),
                evidence_ref: evidence_ref.map(|s| s.to_string()),
                replay_ref: replay_ref.map(|s| s.to_string()),
                context,
            },
        }
    }

    /// Count of failure kinds covered by this contract.
    #[must_use]
    pub fn coverage_count(&self) -> usize {
        self.mappings.len()
    }

    /// Count of failure kinds with evidence references.
    #[must_use]
    pub fn evidence_linked_count(&self) -> usize {
        self.mappings
            .values()
            .filter(|m| m.has_evidence_ref)
            .count()
    }
}

// ---------------------------------------------------------------------------
// DiagnosticEvent
// ---------------------------------------------------------------------------

/// Structured event emitted during diagnostic evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticEvent {
    /// Schema version.
    pub schema_version: String,
    /// Trace identifier.
    pub trace_id: String,
    /// Decision identifier.
    pub decision_id: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Component name.
    pub component: String,
    /// Event kind.
    pub event: String,
    /// Outcome.
    pub outcome: String,
    /// Error code.
    pub error_code: Option<String>,
    /// Deterministic seed.
    pub seed: String,
    /// Scenario identifier.
    pub scenario_id: String,
    /// Failure kind.
    pub failure_kind: String,
    /// Severity.
    pub severity: String,
    /// Next action.
    pub next_action: String,
}

/// Build a diagnostic event.
#[must_use]
pub fn build_diagnostic_event(
    trace_id: &str,
    decision_id: &str,
    scenario_id: &str,
    entry: &DiagnosticEntry,
) -> DiagnosticEvent {
    DiagnosticEvent {
        schema_version: SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: "diagnostic_emitted".to_string(),
        outcome: entry.severity.as_str().to_string(),
        error_code: Some(entry.error_code.clone()),
        seed: "operator-diagnostic-contract-v1".to_string(),
        scenario_id: scenario_id.to_string(),
        failure_kind: entry.failure_kind.as_str().to_string(),
        severity: entry.severity.as_str().to_string(),
        next_action: entry.next_action.as_str().to_string(),
    }
}

// ---------------------------------------------------------------------------
// Default mappings
// ---------------------------------------------------------------------------

fn default_policy_mappings() -> Vec<PolicyMapping> {
    vec![
        PolicyMapping {
            failure_kind: InternalFailureKind::Cancellation,
            error_code: "FE-CANCEL-001".to_string(),
            severity: DiagnosticSeverity::Warning,
            user_impact: UserImpact::OperationFailed,
            operator_impact: OperatorImpact::InformationalOnly,
            next_action: NextAction::Retry,
            description: "Operation cancelled by control plane".to_string(),
            remediation: "Retry the operation. If cancellation persists, check control-plane configuration and load.".to_string(),
            has_evidence_ref: true,
            has_replay_ref: true,
        },
        PolicyMapping {
            failure_kind: InternalFailureKind::BudgetExhaustion,
            error_code: "FE-BUDGET-001".to_string(),
            severity: DiagnosticSeverity::Error,
            user_impact: UserImpact::OperationFailed,
            operator_impact: OperatorImpact::TriageRequired,
            next_action: NextAction::IncreaseBudget,
            description: "Budget exhausted before operation completed".to_string(),
            remediation: "Increase cell_close_budget_ms in orchestrator config. Review budget propagation matrix for tightening opportunities.".to_string(),
            has_evidence_ref: true,
            has_replay_ref: true,
        },
        PolicyMapping {
            failure_kind: InternalFailureKind::CapabilityDenial,
            error_code: "FE-CAPABILITY-001".to_string(),
            severity: DiagnosticSeverity::Error,
            user_impact: UserImpact::OperationFailed,
            operator_impact: OperatorImpact::TriageRequired,
            next_action: NextAction::GrantCapability,
            description: "Caller lacks required capability".to_string(),
            remediation: "Grant the required capability to the extension. Check capability_typed_extension_contract for required profiles.".to_string(),
            has_evidence_ref: true,
            has_replay_ref: false,
        },
        PolicyMapping {
            failure_kind: InternalFailureKind::PolicyDenial,
            error_code: "FE-POLICY-001".to_string(),
            severity: DiagnosticSeverity::Warning,
            user_impact: UserImpact::OperationFailed,
            operator_impact: OperatorImpact::TriageRequired,
            next_action: NextAction::UpdatePolicy,
            description: "Guardplane policy denied the operation".to_string(),
            remediation: "Review the guardplane loss matrix and posterior. Adjust policy thresholds if the denial is overly conservative.".to_string(),
            has_evidence_ref: true,
            has_replay_ref: true,
        },
        PolicyMapping {
            failure_kind: InternalFailureKind::PanicClass,
            error_code: "FE-PANIC-001".to_string(),
            severity: DiagnosticSeverity::Fatal,
            user_impact: UserImpact::OperationFailed,
            operator_impact: OperatorImpact::ImmediateAction,
            next_action: NextAction::FileBugReport,
            description: "Unrecoverable internal error".to_string(),
            remediation: "File a bug report with the evidence bundle attached. This is an engine bug that needs immediate investigation.".to_string(),
            has_evidence_ref: true,
            has_replay_ref: true,
        },
        PolicyMapping {
            failure_kind: InternalFailureKind::CompatibilityDrift,
            error_code: "FE-COMPAT-001".to_string(),
            severity: DiagnosticSeverity::Warning,
            user_impact: UserImpact::DegradedQuality,
            operator_impact: OperatorImpact::TriageRequired,
            next_action: NextAction::UpgradeVersion,
            description: "Component version incompatibility detected".to_string(),
            remediation: "Upgrade mismatched components to compatible versions. Check cross-repo contract tests.".to_string(),
            has_evidence_ref: true,
            has_replay_ref: false,
        },
        PolicyMapping {
            failure_kind: InternalFailureKind::DomainError,
            error_code: "FE-DOMAIN-001".to_string(),
            severity: DiagnosticSeverity::Info,
            user_impact: UserImpact::OperationFailed,
            operator_impact: OperatorImpact::InformationalOnly,
            next_action: NextAction::NoAction,
            description: "Domain-specific logic error".to_string(),
            remediation: "Review the input for correctness. This is typically a user-correctable issue, not an engine bug.".to_string(),
            has_evidence_ref: false,
            has_replay_ref: false,
        },
        PolicyMapping {
            failure_kind: InternalFailureKind::InfrastructureFailure,
            error_code: "FE-INFRA-001".to_string(),
            severity: DiagnosticSeverity::Error,
            user_impact: UserImpact::OperationFailed,
            operator_impact: OperatorImpact::ImmediateAction,
            next_action: NextAction::InvestigateInfra,
            description: "Infrastructure failure (network, disk, etc.)".to_string(),
            remediation: "Check disk space, network connectivity, and system resources. Retry after resolving infrastructure issues.".to_string(),
            has_evidence_ref: true,
            has_replay_ref: false,
        },
        PolicyMapping {
            failure_kind: InternalFailureKind::Unknown,
            error_code: "FE-UNKNOWN-001".to_string(),
            severity: DiagnosticSeverity::Error,
            user_impact: UserImpact::OperationFailed,
            operator_impact: OperatorImpact::TriageRequired,
            next_action: NextAction::FileBugReport,
            description: "Unclassified internal failure".to_string(),
            remediation: "File a bug report with evidence bundle. This failure needs classification.".to_string(),
            has_evidence_ref: true,
            has_replay_ref: true,
        },
    ]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn compute_mappings_hash(mappings: &BTreeMap<String, PolicyMapping>) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_VERSION.as_bytes());
    for (key, mapping) in mappings {
        hasher.update(key.as_bytes());
        hasher.update(mapping.error_code.as_bytes());
        hasher.update(mapping.severity.as_str().as_bytes());
        hasher.update(mapping.user_impact.as_str().as_bytes());
        hasher.update(mapping.operator_impact.as_str().as_bytes());
        hasher.update(mapping.next_action.as_str().as_bytes());
    }
    let digest = hasher.finalize();
    ContentHash::from_bytes(digest.into())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn canonical_contract_covers_all_failure_kinds() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        for kind in InternalFailureKind::all() {
            assert!(
                contract.mapping_for(*kind).is_some(),
                "missing mapping for {kind}"
            );
        }
    }

    #[test]
    fn canonical_contract_integrity() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        assert!(contract.verify_integrity());
    }

    #[test]
    fn tampered_contract_fails_integrity() {
        let mut contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        contract.content_hash = ContentHash::compute(b"tampered");
        assert!(!contract.verify_integrity());
    }

    #[test]
    fn failure_kind_as_str_unique() {
        let mut seen = BTreeSet::new();
        for kind in InternalFailureKind::all() {
            assert!(seen.insert(kind.as_str()), "duplicate as_str for {kind:?}");
        }
    }

    #[test]
    fn failure_kind_error_code_prefix_unique() {
        let mut seen = BTreeSet::new();
        for kind in InternalFailureKind::all() {
            assert!(
                seen.insert(kind.error_code_prefix()),
                "duplicate prefix for {kind:?}"
            );
        }
    }

    #[test]
    fn failure_kind_display_matches_as_str() {
        for kind in InternalFailureKind::all() {
            assert_eq!(kind.to_string(), kind.as_str());
        }
    }

    #[test]
    fn severity_weight_ordering() {
        assert!(DiagnosticSeverity::Fatal.weight() > DiagnosticSeverity::Error.weight());
        assert!(DiagnosticSeverity::Error.weight() > DiagnosticSeverity::Warning.weight());
        assert!(DiagnosticSeverity::Warning.weight() > DiagnosticSeverity::Info.weight());
    }

    #[test]
    fn severity_display() {
        assert_eq!(DiagnosticSeverity::Fatal.to_string(), "fatal");
        assert_eq!(DiagnosticSeverity::Info.to_string(), "info");
    }

    #[test]
    fn user_impact_display() {
        assert_eq!(UserImpact::OperationFailed.to_string(), "operation_failed");
        assert_eq!(UserImpact::None.to_string(), "none");
    }

    #[test]
    fn operator_impact_display() {
        assert_eq!(
            OperatorImpact::ImmediateAction.to_string(),
            "immediate_action"
        );
    }

    #[test]
    fn next_action_display() {
        assert_eq!(NextAction::Retry.to_string(), "retry");
        assert_eq!(NextAction::FileBugReport.to_string(), "file_bug_report");
    }

    #[test]
    fn emit_diagnostic_for_budget_exhaustion() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let diag = contract.emit_diagnostic(
            InternalFailureKind::BudgetExhaustion,
            "cell close budget exhausted at 5ms remaining",
            Some("evidence-12345"),
            Some("frankenctl replay run --trace ./artifacts/trace-id.json --mode strict"),
            BTreeMap::new(),
        );
        assert_eq!(diag.error_code, "FE-BUDGET-001");
        assert_eq!(diag.severity, DiagnosticSeverity::Error);
        assert_eq!(diag.next_action, NextAction::IncreaseBudget);
        assert!(diag.evidence_ref.is_some());
        assert!(diag.replay_ref.is_some());
    }

    #[test]
    fn emit_diagnostic_for_panic_class() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let diag = contract.emit_diagnostic(
            InternalFailureKind::PanicClass,
            "interpreter panicked on invalid instruction",
            Some("evidence-99"),
            None,
            BTreeMap::new(),
        );
        assert_eq!(diag.severity, DiagnosticSeverity::Fatal);
        assert_eq!(diag.operator_impact, OperatorImpact::ImmediateAction);
        assert_eq!(diag.next_action, NextAction::FileBugReport);
    }

    #[test]
    fn emit_diagnostic_for_unknown_has_fallback() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let diag = contract.emit_diagnostic(
            InternalFailureKind::Unknown,
            "something went wrong",
            None,
            None,
            BTreeMap::new(),
        );
        assert!(diag.error_code.starts_with("FE-UNKNOWN"));
        assert_eq!(diag.severity, DiagnosticSeverity::Error);
    }

    #[test]
    fn diagnostic_event_structure() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let diag = contract.emit_diagnostic(
            InternalFailureKind::Cancellation,
            "cancelled",
            None,
            None,
            BTreeMap::new(),
        );
        let event = build_diagnostic_event("trace-001", "decision-001", "scenario-001", &diag);
        assert_eq!(event.component, COMPONENT);
        assert_eq!(event.failure_kind, "cancellation");
        assert_eq!(event.severity, "warning");
        assert_eq!(event.next_action, "retry");
    }

    #[test]
    fn coverage_count_matches_all() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        assert_eq!(contract.coverage_count(), InternalFailureKind::all().len());
    }

    #[test]
    fn evidence_linked_count() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let count = contract.evidence_linked_count();
        assert!(count > 0);
        assert!(count <= contract.coverage_count());
    }

    #[test]
    fn contract_serde_roundtrip() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let json = serde_json::to_string_pretty(&contract).unwrap();
        let parsed: BoundaryPolicyMappingContract = serde_json::from_str(&json).unwrap();
        assert_eq!(contract, parsed);
    }

    #[test]
    fn diagnostic_entry_serde_roundtrip() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let diag = contract.emit_diagnostic(
            InternalFailureKind::BudgetExhaustion,
            "test message",
            Some("ev-ref"),
            Some("replay-ref"),
            BTreeMap::from([("key".to_string(), "value".to_string())]),
        );
        let json = serde_json::to_string(&diag).unwrap();
        let parsed: DiagnosticEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(diag, parsed);
    }

    #[test]
    fn diagnostic_context_propagated() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let ctx = BTreeMap::from([
            ("budget_remaining_ms".to_string(), "5".to_string()),
            ("cell_id".to_string(), "cell-42".to_string()),
        ]);
        let diag = contract.emit_diagnostic(
            InternalFailureKind::BudgetExhaustion,
            "exhausted",
            None,
            None,
            ctx.clone(),
        );
        assert_eq!(diag.context, ctx);
    }

    #[test]
    fn schema_constants_non_empty() {
        assert!(!SCHEMA_VERSION.is_empty());
        assert!(!BEAD_ID.is_empty());
        assert!(!POLICY_ID.is_empty());
        assert!(!COMPONENT.is_empty());
    }

    #[test]
    fn deterministic_contract_builds() {
        let c1 = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let c2 = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        assert_eq!(c1.content_hash, c2.content_hash);
        assert_eq!(c1.mappings.len(), c2.mappings.len());
    }

    #[test]
    fn panic_class_is_fatal_severity() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let mapping = contract
            .mapping_for(InternalFailureKind::PanicClass)
            .unwrap();
        assert_eq!(mapping.severity, DiagnosticSeverity::Fatal);
    }

    #[test]
    fn domain_error_is_info_severity() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let mapping = contract
            .mapping_for(InternalFailureKind::DomainError)
            .unwrap();
        assert_eq!(mapping.severity, DiagnosticSeverity::Info);
    }

    // -- Exhaustive enum serde round-trips --

    #[test]
    fn all_failure_kinds_serde_round_trip() {
        for kind in InternalFailureKind::all() {
            let json = serde_json::to_string(kind).unwrap();
            let back: InternalFailureKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn all_severity_levels_serde_round_trip() {
        for sev in [
            DiagnosticSeverity::Fatal,
            DiagnosticSeverity::Error,
            DiagnosticSeverity::Warning,
            DiagnosticSeverity::Info,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let back: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, back);
        }
    }

    #[test]
    fn all_user_impacts_serde_round_trip() {
        for impact in [
            UserImpact::OperationFailed,
            UserImpact::DegradedQuality,
            UserImpact::None,
        ] {
            let json = serde_json::to_string(&impact).unwrap();
            let back: UserImpact = serde_json::from_str(&json).unwrap();
            assert_eq!(impact, back);
        }
    }

    #[test]
    fn all_operator_impacts_serde_round_trip() {
        for impact in [
            OperatorImpact::ImmediateAction,
            OperatorImpact::TriageRequired,
            OperatorImpact::InformationalOnly,
        ] {
            let json = serde_json::to_string(&impact).unwrap();
            let back: OperatorImpact = serde_json::from_str(&json).unwrap();
            assert_eq!(impact, back);
        }
    }

    #[test]
    fn all_next_actions_serde_round_trip() {
        for action in [
            NextAction::Retry,
            NextAction::IncreaseBudget,
            NextAction::GrantCapability,
            NextAction::UpdatePolicy,
            NextAction::UpgradeVersion,
            NextAction::FileBugReport,
            NextAction::NoAction,
            NextAction::InvestigateInfra,
        ] {
            let json = serde_json::to_string(&action).unwrap();
            let back: NextAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, back);
        }
    }

    // -- Error code prefix structure --

    #[test]
    fn all_error_code_prefixes_start_with_fe() {
        for kind in InternalFailureKind::all() {
            assert!(
                kind.error_code_prefix().starts_with("FE-"),
                "prefix for {kind:?} must start with FE-"
            );
        }
    }

    #[test]
    fn all_error_codes_in_contract_start_with_prefix() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        for kind in InternalFailureKind::all() {
            let mapping = contract.mapping_for(*kind).unwrap();
            assert!(
                mapping.error_code.starts_with(kind.error_code_prefix()),
                "error code {} should start with prefix {} for {:?}",
                mapping.error_code,
                kind.error_code_prefix(),
                kind,
            );
        }
    }

    // -- Diagnostic emission for all failure kinds --

    #[test]
    fn emit_diagnostic_for_every_failure_kind() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        for kind in InternalFailureKind::all() {
            let diag = contract.emit_diagnostic(
                *kind,
                &format!("test message for {kind}"),
                Some("evidence-test"),
                Some("replay-test"),
                BTreeMap::new(),
            );
            assert_eq!(diag.failure_kind, *kind);
            assert!(!diag.error_code.is_empty());
            assert!(!diag.message.is_empty());
            assert!(!diag.remediation.is_empty());
        }
    }

    // -- Cancellation has correct mappings --

    #[test]
    fn cancellation_is_warning_with_retry() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let mapping = contract
            .mapping_for(InternalFailureKind::Cancellation)
            .unwrap();
        assert_eq!(mapping.severity, DiagnosticSeverity::Warning);
        assert_eq!(mapping.next_action, NextAction::Retry);
        assert_eq!(mapping.operator_impact, OperatorImpact::InformationalOnly);
    }

    // -- Infrastructure failure is error with immediate action --

    #[test]
    fn infra_failure_is_error_with_immediate_action() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let mapping = contract
            .mapping_for(InternalFailureKind::InfrastructureFailure)
            .unwrap();
        assert_eq!(mapping.severity, DiagnosticSeverity::Error);
        assert_eq!(mapping.operator_impact, OperatorImpact::ImmediateAction);
        assert_eq!(mapping.next_action, NextAction::InvestigateInfra);
    }

    // -- Diagnostic event serde --

    #[test]
    fn diagnostic_event_serde_round_trip() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let diag = contract.emit_diagnostic(
            InternalFailureKind::PolicyDenial,
            "policy blocked",
            None,
            None,
            BTreeMap::new(),
        );
        let event = build_diagnostic_event("t-1", "d-1", "s-1", &diag);
        let json = serde_json::to_string(&event).unwrap();
        let back: DiagnosticEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.trace_id, back.trace_id);
        assert_eq!(event.failure_kind, back.failure_kind);
        assert_eq!(event.severity, back.severity);
    }

    // -- Epoch variation does not affect mappings --

    #[test]
    fn different_epochs_produce_same_mappings() {
        let c1 = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let c2 = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(42));
        assert_eq!(c1.mappings, c2.mappings);
        assert_eq!(c1.content_hash, c2.content_hash);
    }

    // -- Severity ordering exhaustive --

    #[test]
    fn severity_ordering_matches_weight() {
        let severities = [
            DiagnosticSeverity::Info,
            DiagnosticSeverity::Warning,
            DiagnosticSeverity::Error,
            DiagnosticSeverity::Fatal,
        ];
        for window in severities.windows(2) {
            assert!(
                window[0].weight() < window[1].weight(),
                "{:?} should have lower weight than {:?}",
                window[0],
                window[1],
            );
        }
    }

    // -- Contract schema version --

    #[test]
    fn contract_has_correct_schema_version() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        assert_eq!(contract.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn contract_has_correct_bead_id() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        assert_eq!(contract.bead_id, BEAD_ID);
    }

    // -- No evidence/replay for domain error --

    #[test]
    fn domain_error_has_no_evidence_or_replay_ref() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let mapping = contract
            .mapping_for(InternalFailureKind::DomainError)
            .unwrap();
        assert!(!mapping.has_evidence_ref);
        assert!(!mapping.has_replay_ref);
    }

    // -- Panic class has both evidence and replay --

    #[test]
    fn panic_class_has_evidence_and_replay() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let mapping = contract
            .mapping_for(InternalFailureKind::PanicClass)
            .unwrap();
        assert!(mapping.has_evidence_ref);
        assert!(mapping.has_replay_ref);
    }

    // -- Policy mapping serde --

    #[test]
    fn policy_mapping_serde_round_trip() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let mapping = contract
            .mapping_for(InternalFailureKind::BudgetExhaustion)
            .unwrap();
        let json = serde_json::to_string(mapping).unwrap();
        let back: PolicyMapping = serde_json::from_str(&json).unwrap();
        assert_eq!(*mapping, back);
    }

    // -- Diagnostic with context --

    #[test]
    fn diagnostic_context_keys_preserved() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        let mut ctx = BTreeMap::new();
        ctx.insert("extension_id".to_string(), "ext-123".to_string());
        ctx.insert("capability".to_string(), "FsWrite".to_string());
        ctx.insert("operation".to_string(), "file_create".to_string());

        let diag = contract.emit_diagnostic(
            InternalFailureKind::CapabilityDenial,
            "denied FsWrite",
            None,
            None,
            ctx,
        );

        assert_eq!(diag.context.len(), 3);
        assert_eq!(diag.context["extension_id"], "ext-123");
        assert_eq!(diag.context["capability"], "FsWrite");
    }

    // -- All failure kinds have non-empty descriptions --

    #[test]
    fn all_mappings_have_non_empty_descriptions() {
        let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
        for kind in InternalFailureKind::all() {
            let mapping = contract.mapping_for(*kind).unwrap();
            assert!(
                !mapping.description.is_empty(),
                "mapping for {kind:?} must have a description"
            );
            assert!(
                !mapping.remediation.is_empty(),
                "mapping for {kind:?} must have remediation guidance"
            );
        }
    }
}
