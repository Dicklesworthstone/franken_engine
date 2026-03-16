//! User/operator-facing policy mappings, diagnostics, and remediation contracts
//! for corrected control-plane semantics.
//!
//! Translates internal budget-propagation violations, capability-narrowing
//! violations, and outcome-propagation anomalies into actionable operator
//! output: structured error codes, severity levels, remediation guidance,
//! and evidence links.
//!
//! Key responsibilities:
//! - Map internal control-plane errors to stable, versioned error codes
//! - Assign severity levels for dashboard and alerting integration
//! - Emit structured remediation guidance per error class
//! - Link diagnostics to evidence artifacts for auditing
//! - Gate release decisions on diagnostic severity thresholds
//!
//! Plan references: Section 10.13X.C3, bd-3nr.1.3.3.
//! Dependencies: budget_propagation_contract, outcome_capability_narrowing.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::budget_propagation_contract::BudgetBoundaryKind;
use crate::budget_propagation_contract::BudgetPropagationError;
use crate::hash_tiers::ContentHash;
use crate::outcome_capability_narrowing::NarrowingViolation;
#[cfg(test)]
use crate::outcome_capability_narrowing::{BoundaryOutcome, CapabilityToken};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Error code prefix for control-plane diagnostics.
const ERROR_PREFIX: &str = "CP";

/// Current diagnostic schema version.
const DIAGNOSTIC_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// DiagnosticSeverity
// ---------------------------------------------------------------------------

/// Severity level for control-plane diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    /// Informational: no action required.
    Info,
    /// Warning: operator should review.
    Warning,
    /// Error: must be addressed before release.
    Error,
    /// Critical: blocks all releases; immediate action required.
    Critical,
}

impl DiagnosticSeverity {
    /// Human-readable label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }

    /// Numeric severity for comparison (higher = more severe).
    pub fn level(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Warning => 1,
            Self::Error => 2,
            Self::Critical => 3,
        }
    }

    /// Whether this severity blocks releases.
    pub fn is_release_blocking(self) -> bool {
        matches!(self, Self::Error | Self::Critical)
    }
}

// ---------------------------------------------------------------------------
// DiagnosticCategory
// ---------------------------------------------------------------------------

/// Category of control-plane diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCategory {
    /// Budget propagation issue.
    BudgetPropagation,
    /// Capability narrowing issue.
    CapabilityNarrowing,
    /// Outcome propagation issue.
    OutcomePropagation,
    /// Mock seam leakage.
    MockSeamLeakage,
    /// Context threading issue.
    ContextThreading,
}

impl DiagnosticCategory {
    /// Human-readable label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BudgetPropagation => "budget_propagation",
            Self::CapabilityNarrowing => "capability_narrowing",
            Self::OutcomePropagation => "outcome_propagation",
            Self::MockSeamLeakage => "mock_seam_leakage",
            Self::ContextThreading => "context_threading",
        }
    }
}

// ---------------------------------------------------------------------------
// DiagnosticErrorCode
// ---------------------------------------------------------------------------

/// Structured error code for control-plane diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DiagnosticErrorCode {
    /// The code string (e.g., "CP-BUDGET-001").
    pub code: String,
    /// Category of the diagnostic.
    pub category: DiagnosticCategory,
    /// Severity level.
    pub severity: DiagnosticSeverity,
}

impl DiagnosticErrorCode {
    /// Create a budget propagation error code.
    fn budget(suffix: &str, severity: DiagnosticSeverity) -> Self {
        Self {
            code: format!("{}-BUDGET-{}", ERROR_PREFIX, suffix),
            category: DiagnosticCategory::BudgetPropagation,
            severity,
        }
    }

    /// Create a capability narrowing error code.
    fn capability(suffix: &str, severity: DiagnosticSeverity) -> Self {
        Self {
            code: format!("{}-CAP-{}", ERROR_PREFIX, suffix),
            category: DiagnosticCategory::CapabilityNarrowing,
            severity,
        }
    }

    /// Create an outcome propagation error code.
    fn outcome(suffix: &str, severity: DiagnosticSeverity) -> Self {
        Self {
            code: format!("{}-OUTCOME-{}", ERROR_PREFIX, suffix),
            category: DiagnosticCategory::OutcomePropagation,
            severity,
        }
    }

    /// Create a mock seam leakage error code.
    #[allow(dead_code)]
    fn mock_seam(suffix: &str, severity: DiagnosticSeverity) -> Self {
        Self {
            code: format!("{}-MOCK-{}", ERROR_PREFIX, suffix),
            category: DiagnosticCategory::MockSeamLeakage,
            severity,
        }
    }
}

impl std::fmt::Display for DiagnosticErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code)
    }
}

// ---------------------------------------------------------------------------
// RemediationGuidance
// ---------------------------------------------------------------------------

/// Structured remediation guidance for an operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationGuidance {
    /// Short summary of the issue.
    pub summary: String,
    /// Detailed explanation of the issue.
    pub detail: String,
    /// Concrete steps to remediate.
    pub steps: Vec<String>,
    /// Links to relevant documentation.
    pub doc_refs: Vec<String>,
    /// Whether automated remediation is available.
    pub auto_remediable: bool,
}

// ---------------------------------------------------------------------------
// ControlPlaneDiagnostic
// ---------------------------------------------------------------------------

/// A single control-plane diagnostic entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneDiagnostic {
    /// Error code.
    pub error_code: DiagnosticErrorCode,
    /// Human-readable message.
    pub message: String,
    /// Remediation guidance.
    pub remediation: RemediationGuidance,
    /// Related trace IDs for evidence linkage.
    pub trace_ids: Vec<String>,
    /// Related boundary label.
    pub boundary_label: Option<String>,
    /// Additional context key-value pairs.
    pub context: BTreeMap<String, String>,
    /// Monotonic sequence number.
    pub sequence: u64,
}

// ---------------------------------------------------------------------------
// DiagnosticEmitter
// ---------------------------------------------------------------------------

/// Emits structured diagnostics from control-plane validation results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticEmitter {
    diagnostics: Vec<ControlPlaneDiagnostic>,
    sequence_counter: u64,
    epoch: SecurityEpoch,
    schema_version: u32,
}

impl DiagnosticEmitter {
    /// Create a new emitter.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            diagnostics: Vec::new(),
            sequence_counter: 0,
            epoch,
            schema_version: DIAGNOSTIC_SCHEMA_VERSION,
        }
    }

    /// Create with default epoch.
    pub fn with_defaults() -> Self {
        Self::new(SecurityEpoch::from_raw(1))
    }

    /// Emit a diagnostic from a budget propagation error.
    pub fn emit_budget_error(&mut self, error: &BudgetPropagationError, trace_id: &str) {
        let (code, message, remediation) = match error {
            BudgetPropagationError::InsufficientBudget {
                boundary,
                derived_ms,
                minimum_ms,
                parent_remaining_ms,
            } => (
                DiagnosticErrorCode::budget("001", DiagnosticSeverity::Error),
                format!(
                    "Insufficient budget at {}: derived {}ms < minimum {}ms (parent has {}ms)",
                    boundary.as_str(),
                    derived_ms,
                    minimum_ms,
                    parent_remaining_ms
                ),
                RemediationGuidance {
                    summary:
                        "Child budget derivation produced a budget below the required minimum."
                            .to_owned(),
                    detail: format!(
                        "At boundary '{}', the derived budget of {}ms is below the configured \
                         minimum of {}ms. The parent has {}ms remaining.",
                        boundary.as_str(),
                        derived_ms,
                        minimum_ms,
                        parent_remaining_ms
                    ),
                    steps: vec![
                        "Increase the parent budget allocation".to_owned(),
                        "Lower the minimum child budget requirement".to_owned(),
                        "Review the derivation fraction in BudgetPropagationPolicy".to_owned(),
                    ],
                    doc_refs: vec!["docs/BUDGET_PROPAGATION.md".to_owned()],
                    auto_remediable: false,
                },
            ),
            BudgetPropagationError::NoRuleForBoundary { boundary } => (
                DiagnosticErrorCode::budget("002", DiagnosticSeverity::Critical),
                format!("No propagation rule for boundary '{}'", boundary.as_str()),
                RemediationGuidance {
                    summary:
                        "Budget propagation failed because no rule is configured for this boundary."
                            .to_owned(),
                    detail: format!(
                        "The BudgetPropagationPolicy has no ChildBudgetRule for boundary '{}'. \
                         With fail_closed_on_missing_rule=true, this is a hard failure.",
                        boundary.as_str()
                    ),
                    steps: vec![
                        "Add a ChildBudgetRule for this boundary kind to the policy".to_owned(),
                        "Or set fail_closed_on_missing_rule=false to allow fallback".to_owned(),
                    ],
                    doc_refs: vec!["docs/BUDGET_PROPAGATION.md".to_owned()],
                    auto_remediable: false,
                },
            ),
            BudgetPropagationError::ParentExhausted {
                boundary,
                parent_remaining_ms,
            } => (
                DiagnosticErrorCode::budget("003", DiagnosticSeverity::Error),
                format!(
                    "Parent budget exhausted at {}: {}ms remaining",
                    boundary.as_str(),
                    parent_remaining_ms
                ),
                RemediationGuidance {
                    summary: "Parent budget was already exhausted before child derivation."
                        .to_owned(),
                    detail: "The parent context has zero budget remaining, so no child \
                             budget can be derived."
                        .to_owned(),
                    steps: vec![
                        "Increase the initial orchestrator budget".to_owned(),
                        "Reduce the number of child cells spawned".to_owned(),
                        "Review budget consumption in earlier pipeline stages".to_owned(),
                    ],
                    doc_refs: vec!["docs/BUDGET_PROPAGATION.md".to_owned()],
                    auto_remediable: false,
                },
            ),
            BudgetPropagationError::CleanupExceedsParent {
                cleanup_total_ms,
                parent_remaining_ms,
            } => (
                DiagnosticErrorCode::budget("004", DiagnosticSeverity::Warning),
                format!(
                    "Cleanup budget {}ms exceeds parent {}ms",
                    cleanup_total_ms, parent_remaining_ms
                ),
                RemediationGuidance {
                    summary: "Cleanup budget allocation exceeds parent remaining.".to_owned(),
                    detail: format!(
                        "The cleanup phase requested {}ms but the parent only has {}ms. \
                         The cleanup will be capped.",
                        cleanup_total_ms, parent_remaining_ms
                    ),
                    steps: vec![
                        "Increase the parent budget".to_owned(),
                        "Reduce cleanup budget fractions".to_owned(),
                    ],
                    doc_refs: vec!["docs/BUDGET_PROPAGATION.md".to_owned()],
                    auto_remediable: true,
                },
            ),
            BudgetPropagationError::ChildExceedsParent {
                child_ms,
                parent_ms,
            } => (
                DiagnosticErrorCode::budget("005", DiagnosticSeverity::Critical),
                format!("Child budget {}ms exceeds parent {}ms", child_ms, parent_ms),
                RemediationGuidance {
                    summary: "Invariant violation: child budget exceeds parent.".to_owned(),
                    detail: format!(
                        "A child budget of {}ms was derived from a parent with only {}ms. \
                         This is an invariant violation in the derivation strategy.",
                        child_ms, parent_ms
                    ),
                    steps: vec![
                        "This is a bug in the BudgetDerivationStrategy implementation".to_owned(),
                        "File a bug report with the strategy configuration".to_owned(),
                    ],
                    doc_refs: vec!["docs/BUDGET_PROPAGATION.md".to_owned()],
                    auto_remediable: false,
                },
            ),
        };

        self.sequence_counter += 1;
        self.diagnostics.push(ControlPlaneDiagnostic {
            error_code: code,
            message,
            remediation,
            trace_ids: vec![trace_id.to_owned()],
            boundary_label: None,
            context: BTreeMap::new(),
            sequence: self.sequence_counter,
        });
    }

    /// Emit a diagnostic from a capability narrowing violation.
    pub fn emit_narrowing_violation(&mut self, violation: &NarrowingViolation, trace_id: &str) {
        let (code, message, remediation) = match violation {
            NarrowingViolation::CapabilityWidening {
                boundary_label,
                widened_tokens,
            } => {
                let token_names: Vec<&str> = widened_tokens.iter().map(|t| t.as_str()).collect();
                (
                    DiagnosticErrorCode::capability("001", DiagnosticSeverity::Critical),
                    format!(
                        "Capability widening at '{}': [{}]",
                        boundary_label,
                        token_names.join(", ")
                    ),
                    RemediationGuidance {
                        summary: "Child context has wider capabilities than parent.".to_owned(),
                        detail: format!(
                            "At boundary '{}', the child context was granted capabilities \
                             not present in the parent: [{}]. This violates monotonic \
                             capability narrowing.",
                            boundary_label,
                            token_names.join(", ")
                        ),
                        steps: vec![
                            "Ensure child capability grants are subsets of parent grants"
                                .to_owned(),
                            "Use CapabilityGrant::intersect() to enforce narrowing".to_owned(),
                            "Review the boundary's capability mapping".to_owned(),
                        ],
                        doc_refs: vec!["docs/CAPABILITY_NARROWING.md".to_owned()],
                        auto_remediable: false,
                    },
                )
            }
            NarrowingViolation::OutcomeUpgrade {
                boundary_label,
                child_outcome,
                propagated_outcome,
            } => (
                DiagnosticErrorCode::outcome("001", DiagnosticSeverity::Error),
                format!(
                    "Outcome upgrade at '{}': {} -> {}",
                    boundary_label,
                    child_outcome.as_str(),
                    propagated_outcome.as_str()
                ),
                RemediationGuidance {
                    summary: "Outcome severity decreased across boundary.".to_owned(),
                    detail: format!(
                        "At boundary '{}', outcome '{}' was mapped to '{}' which has \
                         lower severity. This may mask failures.",
                        boundary_label,
                        child_outcome.as_str(),
                        propagated_outcome.as_str()
                    ),
                    steps: vec![
                        "Review the OutcomePropagationRule for this boundary".to_owned(),
                        "Consider using Preserve or EscalateToMostSevere rules".to_owned(),
                    ],
                    doc_refs: vec!["docs/OUTCOME_PROPAGATION.md".to_owned()],
                    auto_remediable: false,
                },
            ),
            NarrowingViolation::UnknownOutcomeNotFailClosed { boundary_label } => (
                DiagnosticErrorCode::outcome("002", DiagnosticSeverity::Critical),
                format!("Unknown outcome not fail-closed at '{}'", boundary_label),
                RemediationGuidance {
                    summary: "Unknown/external outcome not mapped to Failure.".to_owned(),
                    detail: format!(
                        "At boundary '{}', an unrecognized outcome was not mapped to the \
                         fail-closed Failure variant.",
                        boundary_label
                    ),
                    steps: vec![
                        "Ensure all unknown outcomes map to BoundaryOutcome::Failure".to_owned(),
                        "Add explicit handling for the new outcome variant".to_owned(),
                    ],
                    doc_refs: vec!["docs/OUTCOME_PROPAGATION.md".to_owned()],
                    auto_remediable: false,
                },
            ),
        };

        self.sequence_counter += 1;
        self.diagnostics.push(ControlPlaneDiagnostic {
            error_code: code,
            message,
            remediation,
            trace_ids: vec![trace_id.to_owned()],
            boundary_label: match violation {
                NarrowingViolation::CapabilityWidening { boundary_label, .. }
                | NarrowingViolation::OutcomeUpgrade { boundary_label, .. }
                | NarrowingViolation::UnknownOutcomeNotFailClosed { boundary_label } => {
                    Some(boundary_label.clone())
                }
            },
            context: BTreeMap::new(),
            sequence: self.sequence_counter,
        });
    }

    /// Return all recorded diagnostics.
    pub fn diagnostics(&self) -> &[ControlPlaneDiagnostic] {
        &self.diagnostics
    }

    /// Return diagnostics at or above the given severity.
    pub fn diagnostics_at_severity(
        &self,
        min_severity: DiagnosticSeverity,
    ) -> Vec<&ControlPlaneDiagnostic> {
        self.diagnostics
            .iter()
            .filter(|d| d.error_code.severity.level() >= min_severity.level())
            .collect()
    }

    /// Whether any release-blocking diagnostics exist.
    pub fn has_release_blockers(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.error_code.severity.is_release_blocking())
    }

    /// Maximum severity across all diagnostics.
    pub fn max_severity(&self) -> Option<DiagnosticSeverity> {
        self.diagnostics.iter().map(|d| d.error_code.severity).max()
    }

    /// Build a summary report.
    pub fn build_report(&self) -> DiagnosticReport {
        let mut severity_counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut category_counts: BTreeMap<String, u64> = BTreeMap::new();

        for d in &self.diagnostics {
            *severity_counts
                .entry(d.error_code.severity.as_str().to_owned())
                .or_insert(0) += 1;
            *category_counts
                .entry(d.error_code.category.as_str().to_owned())
                .or_insert(0) += 1;
        }

        let release_blocked = self.has_release_blockers();
        let max_severity = self.max_severity();

        let content = format!(
            "diagnostics={},release_blocked={},max_severity={},schema={}",
            self.diagnostics.len(),
            release_blocked,
            max_severity.map_or("none", |s| s.as_str()),
            self.schema_version,
        );
        let content_hash = ContentHash::compute(content.as_bytes());

        DiagnosticReport {
            total_diagnostics: self.diagnostics.len() as u64,
            severity_counts,
            category_counts,
            release_blocked,
            max_severity,
            content_hash,
            epoch: self.epoch,
            schema_version: self.schema_version,
        }
    }
}

// ---------------------------------------------------------------------------
// DiagnosticReport
// ---------------------------------------------------------------------------

/// Summary report of control-plane diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticReport {
    /// Total diagnostics emitted.
    pub total_diagnostics: u64,
    /// Counts by severity.
    pub severity_counts: BTreeMap<String, u64>,
    /// Counts by category.
    pub category_counts: BTreeMap<String, u64>,
    /// Whether any diagnostic blocks release.
    pub release_blocked: bool,
    /// Maximum severity encountered.
    pub max_severity: Option<DiagnosticSeverity>,
    /// Content hash of the report data.
    pub content_hash: ContentHash,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Schema version.
    pub schema_version: u32,
}

impl DiagnosticReport {
    /// Whether the report indicates no issues.
    pub fn is_clean(&self) -> bool {
        self.total_diagnostics == 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn test_severity_ordering() {
        assert!(DiagnosticSeverity::Info.level() < DiagnosticSeverity::Warning.level());
        assert!(DiagnosticSeverity::Warning.level() < DiagnosticSeverity::Error.level());
        assert!(DiagnosticSeverity::Error.level() < DiagnosticSeverity::Critical.level());
    }

    #[test]
    fn test_severity_release_blocking() {
        assert!(!DiagnosticSeverity::Info.is_release_blocking());
        assert!(!DiagnosticSeverity::Warning.is_release_blocking());
        assert!(DiagnosticSeverity::Error.is_release_blocking());
        assert!(DiagnosticSeverity::Critical.is_release_blocking());
    }

    #[test]
    fn test_severity_as_str() {
        assert_eq!(DiagnosticSeverity::Info.as_str(), "info");
        assert_eq!(DiagnosticSeverity::Warning.as_str(), "warning");
        assert_eq!(DiagnosticSeverity::Error.as_str(), "error");
        assert_eq!(DiagnosticSeverity::Critical.as_str(), "critical");
    }

    #[test]
    fn test_category_as_str() {
        assert_eq!(
            DiagnosticCategory::BudgetPropagation.as_str(),
            "budget_propagation"
        );
        assert_eq!(
            DiagnosticCategory::CapabilityNarrowing.as_str(),
            "capability_narrowing"
        );
    }

    #[test]
    fn test_error_code_display() {
        let code = DiagnosticErrorCode::budget("001", DiagnosticSeverity::Error);
        assert_eq!(code.to_string(), "CP-BUDGET-001");
    }

    #[test]
    fn test_emitter_budget_insufficient() {
        let mut emitter = DiagnosticEmitter::with_defaults();
        let err = BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 5,
            minimum_ms: 10,
            parent_remaining_ms: 20,
        };
        emitter.emit_budget_error(&err, "trace-123");

        assert_eq!(emitter.diagnostics().len(), 1);
        let diag = &emitter.diagnostics()[0];
        assert_eq!(diag.error_code.code, "CP-BUDGET-001");
        assert_eq!(diag.error_code.severity, DiagnosticSeverity::Error);
        assert!(diag.message.contains("5ms"));
    }

    #[test]
    fn test_emitter_budget_no_rule() {
        let mut emitter = DiagnosticEmitter::with_defaults();
        let err = BudgetPropagationError::NoRuleForBoundary {
            boundary: BudgetBoundaryKind::OrchestratorToCellClose,
        };
        emitter.emit_budget_error(&err, "trace-456");

        let diag = &emitter.diagnostics()[0];
        assert_eq!(diag.error_code.code, "CP-BUDGET-002");
        assert_eq!(diag.error_code.severity, DiagnosticSeverity::Critical);
    }

    #[test]
    fn test_emitter_budget_exhausted() {
        let mut emitter = DiagnosticEmitter::with_defaults();
        let err = BudgetPropagationError::ParentExhausted {
            boundary: BudgetBoundaryKind::ParentToChildSession,
            parent_remaining_ms: 0,
        };
        emitter.emit_budget_error(&err, "trace-789");

        let diag = &emitter.diagnostics()[0];
        assert_eq!(diag.error_code.code, "CP-BUDGET-003");
    }

    #[test]
    fn test_emitter_capability_widening() {
        let mut emitter = DiagnosticEmitter::with_defaults();
        let violation = NarrowingViolation::CapabilityWidening {
            boundary_label: "spawn_ext".to_owned(),
            widened_tokens: {
                let mut s = BTreeSet::new();
                s.insert(CapabilityToken::NetworkAccess);
                s
            },
        };
        emitter.emit_narrowing_violation(&violation, "trace-abc");

        let diag = &emitter.diagnostics()[0];
        assert_eq!(diag.error_code.code, "CP-CAP-001");
        assert_eq!(diag.error_code.severity, DiagnosticSeverity::Critical);
        assert!(diag.message.contains("network"));
    }

    #[test]
    fn test_emitter_outcome_upgrade() {
        let mut emitter = DiagnosticEmitter::with_defaults();
        let violation = NarrowingViolation::OutcomeUpgrade {
            boundary_label: "cell_close".to_owned(),
            child_outcome: BoundaryOutcome::Timeout,
            propagated_outcome: BoundaryOutcome::Failure,
        };
        emitter.emit_narrowing_violation(&violation, "trace-def");

        let diag = &emitter.diagnostics()[0];
        assert_eq!(diag.error_code.code, "CP-OUTCOME-001");
        assert_eq!(diag.error_code.severity, DiagnosticSeverity::Error);
    }

    #[test]
    fn test_emitter_unknown_outcome() {
        let mut emitter = DiagnosticEmitter::with_defaults();
        let violation = NarrowingViolation::UnknownOutcomeNotFailClosed {
            boundary_label: "external".to_owned(),
        };
        emitter.emit_narrowing_violation(&violation, "trace-ghi");

        let diag = &emitter.diagnostics()[0];
        assert_eq!(diag.error_code.code, "CP-OUTCOME-002");
        assert_eq!(diag.error_code.severity, DiagnosticSeverity::Critical);
    }

    #[test]
    fn test_has_release_blockers() {
        let mut emitter = DiagnosticEmitter::with_defaults();

        // Info only: no blocker
        let err = BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 200,
            parent_remaining_ms: 100,
        };
        emitter.emit_budget_error(&err, "trace");
        assert!(!emitter.has_release_blockers()); // Warning level

        // Add Error: now blocked
        let err2 = BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 1,
            minimum_ms: 10,
            parent_remaining_ms: 5,
        };
        emitter.emit_budget_error(&err2, "trace2");
        assert!(emitter.has_release_blockers());
    }

    #[test]
    fn test_max_severity() {
        let emitter = DiagnosticEmitter::with_defaults();
        assert_eq!(emitter.max_severity(), None);

        let mut emitter2 = DiagnosticEmitter::with_defaults();
        let err = BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 200,
            parent_remaining_ms: 100,
        };
        emitter2.emit_budget_error(&err, "trace");
        assert_eq!(emitter2.max_severity(), Some(DiagnosticSeverity::Warning));
    }

    #[test]
    fn test_diagnostics_at_severity() {
        let mut emitter = DiagnosticEmitter::with_defaults();

        // Warning
        let err1 = BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 200,
            parent_remaining_ms: 100,
        };
        emitter.emit_budget_error(&err1, "trace1");

        // Error
        let err2 = BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 1,
            minimum_ms: 10,
            parent_remaining_ms: 5,
        };
        emitter.emit_budget_error(&err2, "trace2");

        // Critical
        let err3 = BudgetPropagationError::NoRuleForBoundary {
            boundary: BudgetBoundaryKind::OrchestratorToCellClose,
        };
        emitter.emit_budget_error(&err3, "trace3");

        let errors = emitter.diagnostics_at_severity(DiagnosticSeverity::Error);
        assert_eq!(errors.len(), 2); // Error + Critical
    }

    #[test]
    fn test_report_clean() {
        let emitter = DiagnosticEmitter::with_defaults();
        let report = emitter.build_report();
        assert!(report.is_clean());
        assert!(!report.release_blocked);
        assert_eq!(report.max_severity, None);
    }

    #[test]
    fn test_report_with_issues() {
        let mut emitter = DiagnosticEmitter::with_defaults();
        let err = BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 1,
            minimum_ms: 10,
            parent_remaining_ms: 5,
        };
        emitter.emit_budget_error(&err, "trace");

        let report = emitter.build_report();
        assert!(!report.is_clean());
        assert!(report.release_blocked);
        assert_eq!(report.max_severity, Some(DiagnosticSeverity::Error));
        assert_eq!(*report.severity_counts.get("error").unwrap(), 1);
        assert_eq!(
            *report.category_counts.get("budget_propagation").unwrap(),
            1
        );
    }

    #[test]
    fn test_report_serde_roundtrip() {
        let mut emitter = DiagnosticEmitter::with_defaults();
        let err = BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 1,
            minimum_ms: 10,
            parent_remaining_ms: 5,
        };
        emitter.emit_budget_error(&err, "trace");

        let report = emitter.build_report();
        let json = serde_json::to_string(&report).unwrap();
        let round: DiagnosticReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, round);
    }

    #[test]
    fn test_report_hash_deterministic() {
        let make_report = || {
            let mut e = DiagnosticEmitter::with_defaults();
            let err = BudgetPropagationError::ParentExhausted {
                boundary: BudgetBoundaryKind::ParentToChildSession,
                parent_remaining_ms: 0,
            };
            e.emit_budget_error(&err, "trace");
            e.build_report()
        };

        let r1 = make_report();
        let r2 = make_report();
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_diagnostic_serde_roundtrip() {
        let mut emitter = DiagnosticEmitter::with_defaults();
        let err = BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 1,
            minimum_ms: 10,
            parent_remaining_ms: 5,
        };
        emitter.emit_budget_error(&err, "trace");

        let diag = &emitter.diagnostics()[0];
        let json = serde_json::to_string(diag).unwrap();
        let round: ControlPlaneDiagnostic = serde_json::from_str(&json).unwrap();
        assert_eq!(*diag, round);
    }

    #[test]
    fn test_severity_serde_roundtrip() {
        for sev in [
            DiagnosticSeverity::Info,
            DiagnosticSeverity::Warning,
            DiagnosticSeverity::Error,
            DiagnosticSeverity::Critical,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let round: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, round);
        }
    }

    #[test]
    fn test_remediation_guidance_serde_roundtrip() {
        let guidance = RemediationGuidance {
            summary: "test summary".to_owned(),
            detail: "test detail".to_owned(),
            steps: vec!["step 1".to_owned(), "step 2".to_owned()],
            doc_refs: vec!["docs/TEST.md".to_owned()],
            auto_remediable: true,
        };
        let json = serde_json::to_string(&guidance).unwrap();
        let round: RemediationGuidance = serde_json::from_str(&json).unwrap();
        assert_eq!(guidance, round);
    }

    #[test]
    fn test_sequence_monotonic() {
        let mut emitter = DiagnosticEmitter::with_defaults();
        for i in 0..5 {
            let err = BudgetPropagationError::ParentExhausted {
                boundary: BudgetBoundaryKind::ParentToChildExtension,
                parent_remaining_ms: 0,
            };
            emitter.emit_budget_error(&err, &format!("trace-{}", i));
        }

        let seqs: Vec<u64> = emitter.diagnostics().iter().map(|d| d.sequence).collect();
        for i in 1..seqs.len() {
            assert!(seqs[i] > seqs[i - 1], "sequence not monotonic");
        }
    }

    #[test]
    fn test_severity_as_str_matches_serde() {
        for sev in [
            DiagnosticSeverity::Info,
            DiagnosticSeverity::Warning,
            DiagnosticSeverity::Error,
            DiagnosticSeverity::Critical,
        ] {
            let json: String = serde_json::from_str(&serde_json::to_string(&sev).unwrap()).unwrap();
            assert_eq!(json, sev.as_str());
        }
    }

    #[test]
    fn test_category_serde_roundtrip() {
        for cat in [
            DiagnosticCategory::BudgetPropagation,
            DiagnosticCategory::CapabilityNarrowing,
            DiagnosticCategory::OutcomePropagation,
            DiagnosticCategory::MockSeamLeakage,
            DiagnosticCategory::ContextThreading,
        ] {
            let json = serde_json::to_string(&cat).unwrap();
            let back: DiagnosticCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(back, cat);
        }
    }

    #[test]
    fn test_category_as_str_distinct() {
        let strs: BTreeSet<&str> = [
            DiagnosticCategory::BudgetPropagation,
            DiagnosticCategory::CapabilityNarrowing,
            DiagnosticCategory::OutcomePropagation,
            DiagnosticCategory::MockSeamLeakage,
            DiagnosticCategory::ContextThreading,
        ]
        .iter()
        .map(|c| c.as_str())
        .collect();
        assert_eq!(strs.len(), 5);
    }

    #[test]
    fn test_error_code_budget_format() {
        let code = DiagnosticErrorCode::budget("042", DiagnosticSeverity::Warning);
        assert!(code.code.starts_with("CP-BUDGET-"));
        assert_eq!(code.category, DiagnosticCategory::BudgetPropagation);
    }

    #[test]
    fn test_error_code_capability_format() {
        let code = DiagnosticErrorCode::capability("007", DiagnosticSeverity::Critical);
        assert!(code.code.starts_with("CP-CAP-"));
        assert_eq!(code.category, DiagnosticCategory::CapabilityNarrowing);
    }

    #[test]
    fn test_error_code_outcome_format() {
        let code = DiagnosticErrorCode::outcome("003", DiagnosticSeverity::Error);
        assert!(code.code.starts_with("CP-OUTCOME-"));
        assert_eq!(code.category, DiagnosticCategory::OutcomePropagation);
    }

    #[test]
    fn test_error_code_mock_seam_format() {
        let code = DiagnosticErrorCode::mock_seam("001", DiagnosticSeverity::Info);
        assert!(code.code.starts_with("CP-MOCK-"));
        assert_eq!(code.category, DiagnosticCategory::MockSeamLeakage);
    }

    #[test]
    fn test_error_code_serde_roundtrip() {
        let code = DiagnosticErrorCode::budget("001", DiagnosticSeverity::Error);
        let json = serde_json::to_string(&code).unwrap();
        let back: DiagnosticErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, back);
    }

    #[test]
    fn test_emitter_starts_empty() {
        let emitter = DiagnosticEmitter::with_defaults();
        assert!(emitter.diagnostics().is_empty());
        assert_eq!(emitter.max_severity(), None);
        assert!(!emitter.has_release_blockers());
    }

    #[test]
    fn test_emitter_new_with_custom_epoch() {
        let emitter = DiagnosticEmitter::new(SecurityEpoch::from_raw(42));
        let report = emitter.build_report();
        assert_eq!(report.epoch, SecurityEpoch::from_raw(42));
    }

    #[test]
    fn test_emitter_budget_child_exceeds_parent() {
        let mut emitter = DiagnosticEmitter::with_defaults();
        let err = BudgetPropagationError::ChildExceedsParent {
            child_ms: 100,
            parent_ms: 50,
        };
        emitter.emit_budget_error(&err, "trace-child-exceeds");

        let diag = &emitter.diagnostics()[0];
        assert_eq!(diag.error_code.code, "CP-BUDGET-005");
        assert_eq!(diag.error_code.severity, DiagnosticSeverity::Critical);
        assert!(diag.message.contains("100ms"));
        assert!(diag.message.contains("50ms"));
    }

    #[test]
    fn test_diagnostics_trace_ids_populated() {
        let mut emitter = DiagnosticEmitter::with_defaults();
        let err = BudgetPropagationError::ParentExhausted {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            parent_remaining_ms: 0,
        };
        emitter.emit_budget_error(&err, "trace-populated");

        let diag = &emitter.diagnostics()[0];
        assert_eq!(diag.trace_ids, vec!["trace-populated"]);
    }

    #[test]
    fn test_narrowing_violation_boundary_label_propagated() {
        let mut emitter = DiagnosticEmitter::with_defaults();
        let violation = NarrowingViolation::UnknownOutcomeNotFailClosed {
            boundary_label: "my_boundary".to_owned(),
        };
        emitter.emit_narrowing_violation(&violation, "trace-boundary");

        let diag = &emitter.diagnostics()[0];
        assert_eq!(diag.boundary_label.as_deref(), Some("my_boundary"));
    }

    #[test]
    fn test_report_schema_version_matches_constant() {
        let emitter = DiagnosticEmitter::with_defaults();
        let report = emitter.build_report();
        assert_eq!(report.schema_version, DIAGNOSTIC_SCHEMA_VERSION);
    }

    #[test]
    fn test_report_content_hash_changes_with_data() {
        let clean_report = DiagnosticEmitter::with_defaults().build_report();

        let mut emitter = DiagnosticEmitter::with_defaults();
        let err = BudgetPropagationError::ParentExhausted {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            parent_remaining_ms: 0,
        };
        emitter.emit_budget_error(&err, "trace");
        let dirty_report = emitter.build_report();

        assert_ne!(clean_report.content_hash, dirty_report.content_hash);
    }

    #[test]
    fn test_diagnostics_at_severity_info_returns_all() {
        let mut emitter = DiagnosticEmitter::with_defaults();
        let err = BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 200,
            parent_remaining_ms: 100,
        };
        emitter.emit_budget_error(&err, "trace1");
        let err2 = BudgetPropagationError::NoRuleForBoundary {
            boundary: BudgetBoundaryKind::OrchestratorToCellClose,
        };
        emitter.emit_budget_error(&err2, "trace2");

        let all = emitter.diagnostics_at_severity(DiagnosticSeverity::Info);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_diagnostics_at_severity_critical_filters_lower() {
        let mut emitter = DiagnosticEmitter::with_defaults();
        let err = BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 200,
            parent_remaining_ms: 100,
        };
        emitter.emit_budget_error(&err, "trace1"); // Warning
        let err2 = BudgetPropagationError::NoRuleForBoundary {
            boundary: BudgetBoundaryKind::OrchestratorToCellClose,
        };
        emitter.emit_budget_error(&err2, "trace2"); // Critical

        let critical_only = emitter.diagnostics_at_severity(DiagnosticSeverity::Critical);
        assert_eq!(critical_only.len(), 1);
        assert_eq!(
            critical_only[0].error_code.severity,
            DiagnosticSeverity::Critical
        );
    }

    #[test]
    fn test_emitter_serde_roundtrip() {
        let mut emitter = DiagnosticEmitter::with_defaults();
        let err = BudgetPropagationError::ParentExhausted {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            parent_remaining_ms: 0,
        };
        emitter.emit_budget_error(&err, "trace-serde");

        let json = serde_json::to_string(&emitter).unwrap();
        let back: DiagnosticEmitter = serde_json::from_str(&json).unwrap();
        assert_eq!(emitter.diagnostics().len(), back.diagnostics().len());
    }

    #[test]
    fn test_remediation_always_has_steps() {
        let mut emitter = DiagnosticEmitter::with_defaults();
        for boundary in [
            BudgetBoundaryKind::ParentToChildExtension,
            BudgetBoundaryKind::ParentToChildSession,
            BudgetBoundaryKind::OrchestratorToCellClose,
        ] {
            let err = BudgetPropagationError::InsufficientBudget {
                boundary,
                derived_ms: 1,
                minimum_ms: 10,
                parent_remaining_ms: 5,
            };
            emitter.emit_budget_error(&err, "trace");
        }
        for diag in emitter.diagnostics() {
            assert!(
                !diag.remediation.steps.is_empty(),
                "diagnostic {} should have remediation steps",
                diag.error_code.code
            );
            assert!(
                !diag.remediation.summary.is_empty(),
                "diagnostic {} should have summary",
                diag.error_code.code
            );
            assert!(
                !diag.remediation.doc_refs.is_empty(),
                "diagnostic {} should have doc_refs",
                diag.error_code.code
            );
        }
    }
}
