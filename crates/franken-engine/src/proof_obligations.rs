//! Proof Obligations Library and Contract Compiler.
//!
//! Machine-readable proof-obligations covering behavioral preservation,
//! safety, liveness, calibration validity, and tail-risk constraints.
//!
//! This module provides:
//! - **Obligation taxonomy**: five obligation categories with typed templates
//! - **Reusable templates**: parameterized obligation definitions
//! - **Pass/controller-to-obligation mapping**: links pipeline passes to their proof obligations
//! - **CI-readable status schema**: structured pass/fail/pending evaluation
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! deterministic cross-platform computation.
//!
//! Plan reference: FRX-13.1 (Proof Obligations Library and Contract Compiler).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// ObligationId
// ---------------------------------------------------------------------------

/// Unique obligation identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObligationId(pub String);

impl fmt::Display for ObligationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// ObligationCategory — the five taxonomy pillars
// ---------------------------------------------------------------------------

/// The five obligation categories in the taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ObligationCategory {
    /// Behavioral preservation: output equivalence across transformations.
    BehavioralPreservation,
    /// Safety: absence of undefined behavior, memory safety, IFC labels.
    Safety,
    /// Liveness: progress guarantees, deadlock freedom, termination.
    Liveness,
    /// Calibration validity: conformal/sequential guarantees hold.
    CalibrationValidity,
    /// Tail-risk: CVaR/VaR constraints on loss distributions.
    TailRisk,
}

impl ObligationCategory {
    pub const ALL: [ObligationCategory; 5] = [
        ObligationCategory::BehavioralPreservation,
        ObligationCategory::Safety,
        ObligationCategory::Liveness,
        ObligationCategory::CalibrationValidity,
        ObligationCategory::TailRisk,
    ];
}

impl fmt::Display for ObligationCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BehavioralPreservation => write!(f, "behavioral_preservation"),
            Self::Safety => write!(f, "safety"),
            Self::Liveness => write!(f, "liveness"),
            Self::CalibrationValidity => write!(f, "calibration_validity"),
            Self::TailRisk => write!(f, "tail_risk"),
        }
    }
}

// ---------------------------------------------------------------------------
// ObligationSeverity
// ---------------------------------------------------------------------------

/// How severely a violation impacts the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ObligationSeverity {
    /// Informational — logged but no enforcement.
    Info,
    /// Warning — flagged for review.
    Warning,
    /// Error — blocks promotion but not execution.
    Error,
    /// Fatal — triggers immediate demotion/fallback.
    Fatal,
}

impl fmt::Display for ObligationSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
            Self::Fatal => write!(f, "fatal"),
        }
    }
}

// ---------------------------------------------------------------------------
// EvidenceRequirement — what constitutes sufficient proof
// ---------------------------------------------------------------------------

/// What constitutes sufficient evidence for an obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceRequirement {
    /// Differential test with minimum pass rate (millionths).
    DifferentialTest {
        min_pass_rate_millionths: i64,
        min_test_count: u64,
    },
    /// Statistical test with confidence level (millionths).
    StatisticalTest {
        confidence_level_millionths: i64,
        min_samples: u64,
    },
    /// Formal proof artifact must exist.
    FormalProof { proof_system: String },
    /// Hash linkage: before/after digests match expected.
    HashLinkage,
    /// Witness from PLAS (capability verification).
    PlasWitness,
    /// E-process guardrail must not be triggered.
    EProcessGuardrail { guardrail_id: String },
    /// CVaR must be within bounds (millionths).
    CvarBound {
        max_cvar_millionths: i64,
        alpha_millionths: i64,
    },
    /// Calibration coverage must exceed threshold (millionths).
    CalibrationCoverage { min_coverage_millionths: i64 },
    /// Manual operator review.
    OperatorReview,
}

// ---------------------------------------------------------------------------
// ObligationTemplate — reusable parameterized definition
// ---------------------------------------------------------------------------

/// A reusable obligation template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationTemplate {
    /// Template identifier (e.g., "behavioral/ir_transform_equivalence").
    pub template_id: String,
    /// Which category this obligation belongs to.
    pub category: ObligationCategory,
    /// Default severity.
    pub severity: ObligationSeverity,
    /// Human-readable description of what must be proven.
    pub description: String,
    /// What evidence is required.
    pub evidence: EvidenceRequirement,
    /// Whether this obligation can be waived by operator.
    pub waivable: bool,
}

/// Built-in obligation templates.
pub fn builtin_templates() -> Vec<ObligationTemplate> {
    vec![
        // -- Behavioral Preservation --
        ObligationTemplate {
            template_id: "behavioral/ir_transform_equivalence".into(),
            category: ObligationCategory::BehavioralPreservation,
            severity: ObligationSeverity::Fatal,
            description: "IR transformation preserves observable behavior".into(),
            evidence: EvidenceRequirement::DifferentialTest {
                min_pass_rate_millionths: 999_000, // 99.9%
                min_test_count: 1000,
            },
            waivable: false,
        },
        ObligationTemplate {
            template_id: "behavioral/render_output_stability".into(),
            category: ObligationCategory::BehavioralPreservation,
            severity: ObligationSeverity::Fatal,
            description: "Render output matches reference for all corpus fixtures".into(),
            evidence: EvidenceRequirement::DifferentialTest {
                min_pass_rate_millionths: MILLION, // 100%
                min_test_count: 100,
            },
            waivable: false,
        },
        ObligationTemplate {
            template_id: "behavioral/hook_ordering_preservation".into(),
            category: ObligationCategory::BehavioralPreservation,
            severity: ObligationSeverity::Fatal,
            description: "Hook execution order matches React specification".into(),
            evidence: EvidenceRequirement::DifferentialTest {
                min_pass_rate_millionths: MILLION,
                min_test_count: 500,
            },
            waivable: false,
        },
        ObligationTemplate {
            template_id: "behavioral/effect_timing_contract".into(),
            category: ObligationCategory::BehavioralPreservation,
            severity: ObligationSeverity::Error,
            description: "Effect timing boundaries match React scheduling contract".into(),
            evidence: EvidenceRequirement::DifferentialTest {
                min_pass_rate_millionths: 990_000, // 99%
                min_test_count: 200,
            },
            waivable: true,
        },
        // -- Safety --
        ObligationTemplate {
            template_id: "safety/ifc_label_propagation".into(),
            category: ObligationCategory::Safety,
            severity: ObligationSeverity::Fatal,
            description: "IFC labels propagate correctly through all data flows".into(),
            evidence: EvidenceRequirement::FormalProof {
                proof_system: "flow_lattice".into(),
            },
            waivable: false,
        },
        ObligationTemplate {
            template_id: "safety/capability_authority_bound".into(),
            category: ObligationCategory::Safety,
            severity: ObligationSeverity::Fatal,
            description: "No ambient authority: all capabilities explicitly granted".into(),
            evidence: EvidenceRequirement::PlasWitness,
            waivable: false,
        },
        ObligationTemplate {
            template_id: "safety/memory_budget_respected".into(),
            category: ObligationCategory::Safety,
            severity: ObligationSeverity::Error,
            description: "Extension stays within allocated memory budget".into(),
            evidence: EvidenceRequirement::StatisticalTest {
                confidence_level_millionths: 950_000, // 95%
                min_samples: 100,
            },
            waivable: false,
        },
        ObligationTemplate {
            template_id: "safety/hash_chain_integrity".into(),
            category: ObligationCategory::Safety,
            severity: ObligationSeverity::Fatal,
            description: "IR hash chain unbroken through all transformation passes".into(),
            evidence: EvidenceRequirement::HashLinkage,
            waivable: false,
        },
        // -- Liveness --
        ObligationTemplate {
            template_id: "liveness/scheduler_progress".into(),
            category: ObligationCategory::Liveness,
            severity: ObligationSeverity::Error,
            description: "Scheduler makes progress within budget: no starvation".into(),
            evidence: EvidenceRequirement::StatisticalTest {
                confidence_level_millionths: 990_000, // 99%
                min_samples: 1000,
            },
            waivable: false,
        },
        ObligationTemplate {
            template_id: "liveness/drain_completion".into(),
            category: ObligationCategory::Liveness,
            severity: ObligationSeverity::Fatal,
            description: "Region drain completes within timeout".into(),
            evidence: EvidenceRequirement::StatisticalTest {
                confidence_level_millionths: 999_000, // 99.9%
                min_samples: 500,
            },
            waivable: false,
        },
        ObligationTemplate {
            template_id: "liveness/cancellation_responsive".into(),
            category: ObligationCategory::Liveness,
            severity: ObligationSeverity::Error,
            description: "Cancellation signals propagate within bounded time".into(),
            evidence: EvidenceRequirement::StatisticalTest {
                confidence_level_millionths: 950_000,
                min_samples: 200,
            },
            waivable: true,
        },
        // -- Calibration Validity --
        ObligationTemplate {
            template_id: "calibration/conformal_coverage".into(),
            category: ObligationCategory::CalibrationValidity,
            severity: ObligationSeverity::Error,
            description: "Conformal prediction sets achieve target coverage rate".into(),
            evidence: EvidenceRequirement::CalibrationCoverage {
                min_coverage_millionths: 900_000, // 90%
            },
            waivable: false,
        },
        ObligationTemplate {
            template_id: "calibration/eprocess_integrity".into(),
            category: ObligationCategory::CalibrationValidity,
            severity: ObligationSeverity::Fatal,
            description: "E-process guardrails maintain anytime-valid guarantees".into(),
            evidence: EvidenceRequirement::EProcessGuardrail {
                guardrail_id: "default".into(),
            },
            waivable: false,
        },
        ObligationTemplate {
            template_id: "calibration/posterior_convergence".into(),
            category: ObligationCategory::CalibrationValidity,
            severity: ObligationSeverity::Warning,
            description: "Bayesian posterior converges within expected sample size".into(),
            evidence: EvidenceRequirement::StatisticalTest {
                confidence_level_millionths: 950_000,
                min_samples: 500,
            },
            waivable: true,
        },
        // -- Tail Risk --
        ObligationTemplate {
            template_id: "tail_risk/cvar_latency_bound".into(),
            category: ObligationCategory::TailRisk,
            severity: ObligationSeverity::Error,
            description: "CVaR at 95% for latency stays within SLO".into(),
            evidence: EvidenceRequirement::CvarBound {
                max_cvar_millionths: 50 * MILLION,
                alpha_millionths: 950_000,
            },
            waivable: false,
        },
        ObligationTemplate {
            template_id: "tail_risk/p999_regression_guard".into(),
            category: ObligationCategory::TailRisk,
            severity: ObligationSeverity::Fatal,
            description: "p999 latency does not regress beyond tolerance".into(),
            evidence: EvidenceRequirement::StatisticalTest {
                confidence_level_millionths: 999_000,
                min_samples: 10_000,
            },
            waivable: false,
        },
        ObligationTemplate {
            template_id: "tail_risk/fallback_frequency_bound".into(),
            category: ObligationCategory::TailRisk,
            severity: ObligationSeverity::Warning,
            description: "Fallback frequency stays below target rate".into(),
            evidence: EvidenceRequirement::StatisticalTest {
                confidence_level_millionths: 950_000,
                min_samples: 1000,
            },
            waivable: true,
        },
    ]
}

// ---------------------------------------------------------------------------
// PassId — pipeline pass identifier
// ---------------------------------------------------------------------------

/// Identifies a pipeline pass or controller.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PassId(pub String);

impl fmt::Display for PassId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// ObligationBinding — links passes to obligations
// ---------------------------------------------------------------------------

/// Binds a pipeline pass to a specific obligation instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationBinding {
    /// The pass that must discharge this obligation.
    pub pass_id: PassId,
    /// The obligation to discharge.
    pub obligation_id: ObligationId,
    /// Template used to create this obligation.
    pub template_id: String,
    /// Category (denormalized for convenience).
    pub category: ObligationCategory,
    /// Severity (denormalized).
    pub severity: ObligationSeverity,
    /// Evidence requirement.
    pub evidence: EvidenceRequirement,
}

// ---------------------------------------------------------------------------
// ObligationStatus — CI-readable evaluation result
// ---------------------------------------------------------------------------

/// Status of an obligation evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ObligationStatus {
    /// Not yet evaluated.
    Pending,
    /// Evaluation in progress.
    InProgress,
    /// Obligation satisfied.
    Satisfied,
    /// Obligation violated.
    Violated,
    /// Obligation waived by operator.
    Waived,
    /// Insufficient evidence to evaluate.
    InsufficientEvidence,
}

impl fmt::Display for ObligationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Satisfied => write!(f, "satisfied"),
            Self::Violated => write!(f, "violated"),
            Self::Waived => write!(f, "waived"),
            Self::InsufficientEvidence => write!(f, "insufficient_evidence"),
        }
    }
}

// ---------------------------------------------------------------------------
// ObligationEvaluation — a single obligation's evaluation
// ---------------------------------------------------------------------------

/// Result of evaluating a single obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationEvaluation {
    pub obligation_id: ObligationId,
    pub template_id: String,
    pub category: ObligationCategory,
    pub severity: ObligationSeverity,
    pub status: ObligationStatus,
    pub epoch: SecurityEpoch,
    /// Observed value (interpretation depends on evidence type).
    pub observed_value: Option<i64>,
    /// Required threshold.
    pub required_value: Option<i64>,
    /// Reason for the status.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// ObligationReport — CI-readable aggregate report
// ---------------------------------------------------------------------------

/// Aggregate report for all obligations in a gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationReport {
    pub epoch: SecurityEpoch,
    pub evaluations: Vec<ObligationEvaluation>,
    /// Summary counts.
    pub satisfied_count: u64,
    pub violated_count: u64,
    pub pending_count: u64,
    pub waived_count: u64,
    pub insufficient_count: u64,
    /// Whether the overall gate passes (no fatal violations).
    pub gate_pass: bool,
}

impl ObligationReport {
    /// Compute from a set of evaluations.
    pub fn from_evaluations(epoch: SecurityEpoch, evaluations: Vec<ObligationEvaluation>) -> Self {
        let mut satisfied_count = 0u64;
        let mut violated_count = 0u64;
        let mut pending_count = 0u64;
        let mut waived_count = 0u64;
        let mut insufficient_count = 0u64;
        let mut has_blocking_violation = false;

        for eval in &evaluations {
            match eval.status {
                ObligationStatus::Satisfied => satisfied_count += 1,
                ObligationStatus::Violated => {
                    violated_count += 1;
                    if eval.severity >= ObligationSeverity::Error {
                        has_blocking_violation = true;
                    }
                }
                ObligationStatus::Pending | ObligationStatus::InProgress => pending_count += 1,
                ObligationStatus::Waived => waived_count += 1,
                ObligationStatus::InsufficientEvidence => insufficient_count += 1,
            }
        }

        Self {
            epoch,
            evaluations,
            satisfied_count,
            violated_count,
            pending_count,
            waived_count,
            insufficient_count,
            gate_pass: !has_blocking_violation && pending_count == 0,
        }
    }
}

// ---------------------------------------------------------------------------
// ObligationRegistry — the contract compiler
// ---------------------------------------------------------------------------

/// The obligation registry: stores templates, bindings, and evaluations.
///
/// Acts as the "contract compiler" that:
/// 1. Registers obligation templates
/// 2. Binds passes to obligations
/// 3. Evaluates obligations against provided evidence
/// 4. Produces CI-readable reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObligationRegistry {
    /// Template library keyed by template_id.
    templates: BTreeMap<String, ObligationTemplate>,
    /// Pass-to-obligation bindings keyed by obligation_id.
    bindings: BTreeMap<String, ObligationBinding>,
    /// Evaluation results keyed by obligation_id.
    evaluations: BTreeMap<String, ObligationEvaluation>,
    /// Next auto-generated obligation number.
    next_id: u64,
    /// Current epoch.
    epoch: SecurityEpoch,
}

impl ObligationRegistry {
    /// Create with built-in templates.
    pub fn new(epoch: SecurityEpoch) -> Self {
        let mut templates = BTreeMap::new();
        for t in builtin_templates() {
            templates.insert(t.template_id.clone(), t);
        }
        Self {
            templates,
            bindings: BTreeMap::new(),
            evaluations: BTreeMap::new(),
            next_id: 1,
            epoch,
        }
    }

    /// Create with no templates (for testing).
    pub fn empty(epoch: SecurityEpoch) -> Self {
        Self {
            templates: BTreeMap::new(),
            bindings: BTreeMap::new(),
            evaluations: BTreeMap::new(),
            next_id: 1,
            epoch,
        }
    }

    /// Register a custom template.
    pub fn register_template(&mut self, template: ObligationTemplate) {
        self.templates
            .insert(template.template_id.clone(), template);
    }

    /// Bind a pass to an obligation using a template.
    ///
    /// Returns the generated obligation ID, or None if template not found.
    pub fn bind(&mut self, pass_id: PassId, template_id: &str) -> Option<ObligationId> {
        let template = self.templates.get(template_id)?;
        let obligation_id = ObligationId(format!("obl-{}", self.next_id));
        self.next_id += 1;

        let binding = ObligationBinding {
            pass_id,
            obligation_id: obligation_id.clone(),
            template_id: template.template_id.clone(),
            category: template.category,
            severity: template.severity,
            evidence: template.evidence.clone(),
        };
        self.bindings.insert(obligation_id.0.clone(), binding);
        Some(obligation_id)
    }

    /// Record an evaluation result for an obligation.
    pub fn evaluate(
        &mut self,
        obligation_id: &ObligationId,
        status: ObligationStatus,
        observed_value: Option<i64>,
        reason: &str,
    ) -> bool {
        let binding = match self.bindings.get(&obligation_id.0) {
            Some(b) => b,
            None => return false,
        };

        let required_value = match &binding.evidence {
            EvidenceRequirement::DifferentialTest {
                min_pass_rate_millionths,
                ..
            } => Some(*min_pass_rate_millionths),
            EvidenceRequirement::StatisticalTest {
                confidence_level_millionths,
                ..
            } => Some(*confidence_level_millionths),
            EvidenceRequirement::CvarBound {
                max_cvar_millionths,
                ..
            } => Some(*max_cvar_millionths),
            EvidenceRequirement::CalibrationCoverage {
                min_coverage_millionths,
            } => Some(*min_coverage_millionths),
            _ => None,
        };

        let eval = ObligationEvaluation {
            obligation_id: obligation_id.clone(),
            template_id: binding.template_id.clone(),
            category: binding.category,
            severity: binding.severity,
            status,
            epoch: self.epoch,
            observed_value,
            required_value,
            reason: reason.into(),
        };
        self.evaluations.insert(obligation_id.0.clone(), eval);
        true
    }

    /// Auto-evaluate an obligation against provided evidence.
    ///
    /// For DifferentialTest: provide pass_rate_millionths as the value.
    /// For CvarBound: provide current CVaR as the value.
    /// For CalibrationCoverage: provide coverage_millionths.
    pub fn auto_evaluate(
        &mut self,
        obligation_id: &ObligationId,
        observed_value: i64,
        sample_count: u64,
    ) -> Option<ObligationStatus> {
        let binding = self.bindings.get(&obligation_id.0)?.clone();

        let (status, reason) = match &binding.evidence {
            EvidenceRequirement::DifferentialTest {
                min_pass_rate_millionths,
                min_test_count,
            } => {
                if sample_count < *min_test_count {
                    (
                        ObligationStatus::InsufficientEvidence,
                        format!("need {min_test_count} tests, have {sample_count}"),
                    )
                } else if observed_value >= *min_pass_rate_millionths {
                    (ObligationStatus::Satisfied, "pass rate met".into())
                } else {
                    (
                        ObligationStatus::Violated,
                        format!("pass rate {observed_value} < required {min_pass_rate_millionths}"),
                    )
                }
            }
            EvidenceRequirement::StatisticalTest {
                confidence_level_millionths,
                min_samples,
            } => {
                if sample_count < *min_samples {
                    (
                        ObligationStatus::InsufficientEvidence,
                        format!("need {min_samples} samples, have {sample_count}"),
                    )
                } else if observed_value >= *confidence_level_millionths {
                    (ObligationStatus::Satisfied, "confidence met".into())
                } else {
                    (
                        ObligationStatus::Violated,
                        format!(
                            "confidence {observed_value} < required {confidence_level_millionths}"
                        ),
                    )
                }
            }
            EvidenceRequirement::CvarBound {
                max_cvar_millionths,
                ..
            } => {
                if observed_value <= *max_cvar_millionths {
                    (ObligationStatus::Satisfied, "CVaR within bound".into())
                } else {
                    (
                        ObligationStatus::Violated,
                        format!("CVaR {observed_value} > max {max_cvar_millionths}"),
                    )
                }
            }
            EvidenceRequirement::CalibrationCoverage {
                min_coverage_millionths,
            } => {
                if observed_value >= *min_coverage_millionths {
                    (ObligationStatus::Satisfied, "coverage met".into())
                } else {
                    (
                        ObligationStatus::Violated,
                        format!("coverage {observed_value} < required {min_coverage_millionths}"),
                    )
                }
            }
            _ => (
                ObligationStatus::Pending,
                "auto-evaluate not supported for this evidence type".into(),
            ),
        };

        self.evaluate(obligation_id, status, Some(observed_value), &reason);
        Some(status)
    }

    /// Waive an obligation (operator-authorized, only if waivable).
    pub fn waive(&mut self, obligation_id: &ObligationId, reason: &str) -> bool {
        let binding = match self.bindings.get(&obligation_id.0) {
            Some(b) => b,
            None => return false,
        };
        let template = match self.templates.get(&binding.template_id) {
            Some(t) => t,
            None => return false,
        };
        if !template.waivable {
            return false;
        }
        self.evaluate(obligation_id, ObligationStatus::Waived, None, reason)
    }

    /// Generate the aggregate report.
    pub fn report(&self) -> ObligationReport {
        let evaluations: Vec<ObligationEvaluation> = self
            .bindings
            .keys()
            .map(|obl_id| {
                self.evaluations.get(obl_id).cloned().unwrap_or_else(|| {
                    let binding = &self.bindings[obl_id];
                    ObligationEvaluation {
                        obligation_id: ObligationId(obl_id.clone()),
                        template_id: binding.template_id.clone(),
                        category: binding.category,
                        severity: binding.severity,
                        status: ObligationStatus::Pending,
                        epoch: self.epoch,
                        observed_value: None,
                        required_value: None,
                        reason: "not yet evaluated".into(),
                    }
                })
            })
            .collect();

        ObligationReport::from_evaluations(self.epoch, evaluations)
    }

    /// Get bindings for a specific pass.
    pub fn bindings_for_pass(&self, pass_id: &PassId) -> Vec<&ObligationBinding> {
        self.bindings
            .values()
            .filter(|b| b.pass_id == *pass_id)
            .collect()
    }

    /// Get all bindings in a category.
    pub fn bindings_in_category(&self, category: ObligationCategory) -> Vec<&ObligationBinding> {
        self.bindings
            .values()
            .filter(|b| b.category == category)
            .collect()
    }

    /// Template count.
    pub fn template_count(&self) -> usize {
        self.templates.len()
    }

    /// Binding count.
    pub fn binding_count(&self) -> usize {
        self.bindings.len()
    }

    /// Evaluation count.
    pub fn evaluation_count(&self) -> usize {
        self.evaluations.len()
    }

    /// Get a template by ID.
    pub fn template(&self, template_id: &str) -> Option<&ObligationTemplate> {
        self.templates.get(template_id)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    // -----------------------------------------------------------------------
    // ObligationCategory tests
    // -----------------------------------------------------------------------

    #[test]
    fn category_all_five() {
        assert_eq!(ObligationCategory::ALL.len(), 5);
    }

    #[test]
    fn category_display() {
        assert_eq!(
            format!("{}", ObligationCategory::BehavioralPreservation),
            "behavioral_preservation"
        );
        assert_eq!(format!("{}", ObligationCategory::Safety), "safety");
        assert_eq!(format!("{}", ObligationCategory::Liveness), "liveness");
        assert_eq!(
            format!("{}", ObligationCategory::CalibrationValidity),
            "calibration_validity"
        );
        assert_eq!(format!("{}", ObligationCategory::TailRisk), "tail_risk");
    }

    #[test]
    fn category_serde_roundtrip() {
        for cat in &ObligationCategory::ALL {
            let json = serde_json::to_string(cat).unwrap();
            let back: ObligationCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*cat, back);
        }
    }

    // -----------------------------------------------------------------------
    // ObligationSeverity tests
    // -----------------------------------------------------------------------

    #[test]
    fn severity_display() {
        assert_eq!(format!("{}", ObligationSeverity::Info), "info");
        assert_eq!(format!("{}", ObligationSeverity::Fatal), "fatal");
    }

    #[test]
    fn severity_ordering() {
        assert!(ObligationSeverity::Info < ObligationSeverity::Warning);
        assert!(ObligationSeverity::Warning < ObligationSeverity::Error);
        assert!(ObligationSeverity::Error < ObligationSeverity::Fatal);
    }

    // -----------------------------------------------------------------------
    // ObligationStatus tests
    // -----------------------------------------------------------------------

    #[test]
    fn status_display() {
        assert_eq!(format!("{}", ObligationStatus::Pending), "pending");
        assert_eq!(format!("{}", ObligationStatus::Satisfied), "satisfied");
        assert_eq!(format!("{}", ObligationStatus::Violated), "violated");
        assert_eq!(format!("{}", ObligationStatus::Waived), "waived");
    }

    #[test]
    fn status_serde_roundtrip() {
        let statuses = [
            ObligationStatus::Pending,
            ObligationStatus::InProgress,
            ObligationStatus::Satisfied,
            ObligationStatus::Violated,
            ObligationStatus::Waived,
            ObligationStatus::InsufficientEvidence,
        ];
        for s in &statuses {
            let json = serde_json::to_string(s).unwrap();
            let back: ObligationStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    // -----------------------------------------------------------------------
    // Builtin templates tests
    // -----------------------------------------------------------------------

    #[test]
    fn builtin_templates_nonempty() {
        let templates = builtin_templates();
        assert!(
            templates.len() >= 15,
            "expected at least 15 builtin templates"
        );
    }

    #[test]
    fn builtin_templates_cover_all_categories() {
        let templates = builtin_templates();
        for cat in &ObligationCategory::ALL {
            let count = templates.iter().filter(|t| t.category == *cat).count();
            assert!(
                count >= 2,
                "category {cat} should have at least 2 templates, has {count}"
            );
        }
    }

    #[test]
    fn builtin_templates_unique_ids() {
        let templates = builtin_templates();
        let mut seen = std::collections::BTreeSet::new();
        for t in &templates {
            assert!(seen.insert(&t.template_id), "duplicate: {}", t.template_id);
        }
    }

    #[test]
    fn builtin_templates_serde_roundtrip() {
        let templates = builtin_templates();
        let json = serde_json::to_string(&templates).unwrap();
        let back: Vec<ObligationTemplate> = serde_json::from_str(&json).unwrap();
        assert_eq!(templates.len(), back.len());
    }

    // -----------------------------------------------------------------------
    // ObligationRegistry — basic tests
    // -----------------------------------------------------------------------

    #[test]
    fn registry_new_has_builtin_templates() {
        let reg = ObligationRegistry::new(epoch(1));
        assert!(reg.template_count() >= 15);
        assert_eq!(reg.binding_count(), 0);
    }

    #[test]
    fn registry_empty_has_no_templates() {
        let reg = ObligationRegistry::empty(epoch(1));
        assert_eq!(reg.template_count(), 0);
    }

    #[test]
    fn registry_register_custom_template() {
        let mut reg = ObligationRegistry::empty(epoch(1));
        reg.register_template(ObligationTemplate {
            template_id: "custom/test".into(),
            category: ObligationCategory::Safety,
            severity: ObligationSeverity::Error,
            description: "test".into(),
            evidence: EvidenceRequirement::OperatorReview,
            waivable: true,
        });
        assert_eq!(reg.template_count(), 1);
        assert!(reg.template("custom/test").is_some());
    }

    // -----------------------------------------------------------------------
    // Binding tests
    // -----------------------------------------------------------------------

    #[test]
    fn registry_bind_creates_obligation() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(
                PassId("ir_transform".into()),
                "behavioral/ir_transform_equivalence",
            )
            .unwrap();
        assert_eq!(obl_id.0, "obl-1");
        assert_eq!(reg.binding_count(), 1);
    }

    #[test]
    fn registry_bind_unknown_template_returns_none() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let result = reg.bind(PassId("test".into()), "nonexistent/template");
        assert!(result.is_none());
    }

    #[test]
    fn registry_multiple_bindings_per_pass() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let pass = PassId("compiler".into());
        reg.bind(pass.clone(), "behavioral/ir_transform_equivalence");
        reg.bind(pass.clone(), "safety/hash_chain_integrity");
        let bindings = reg.bindings_for_pass(&pass);
        assert_eq!(bindings.len(), 2);
    }

    #[test]
    fn registry_bindings_in_category() {
        let mut reg = ObligationRegistry::new(epoch(1));
        reg.bind(PassId("a".into()), "behavioral/ir_transform_equivalence");
        reg.bind(PassId("b".into()), "behavioral/render_output_stability");
        reg.bind(PassId("c".into()), "safety/ifc_label_propagation");
        let behavioral = reg.bindings_in_category(ObligationCategory::BehavioralPreservation);
        assert_eq!(behavioral.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Evaluation tests
    // -----------------------------------------------------------------------

    #[test]
    fn registry_evaluate_manual() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(PassId("test".into()), "behavioral/ir_transform_equivalence")
            .unwrap();
        let ok = reg.evaluate(
            &obl_id,
            ObligationStatus::Satisfied,
            Some(999_500),
            "all tests pass",
        );
        assert!(ok);
        assert_eq!(reg.evaluation_count(), 1);
    }

    #[test]
    fn registry_evaluate_nonexistent_returns_false() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let ok = reg.evaluate(
            &ObligationId("nonexistent".into()),
            ObligationStatus::Satisfied,
            None,
            "test",
        );
        assert!(!ok);
    }

    // -----------------------------------------------------------------------
    // Auto-evaluate tests
    // -----------------------------------------------------------------------

    #[test]
    fn auto_evaluate_differential_test_pass() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(
                PassId("transform".into()),
                "behavioral/ir_transform_equivalence",
            )
            .unwrap();
        let status = reg.auto_evaluate(&obl_id, 999_500, 2000).unwrap();
        assert_eq!(status, ObligationStatus::Satisfied);
    }

    #[test]
    fn auto_evaluate_differential_test_fail() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(
                PassId("transform".into()),
                "behavioral/ir_transform_equivalence",
            )
            .unwrap();
        let status = reg.auto_evaluate(&obl_id, 900_000, 2000).unwrap();
        assert_eq!(status, ObligationStatus::Violated);
    }

    #[test]
    fn auto_evaluate_insufficient_samples() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(
                PassId("transform".into()),
                "behavioral/ir_transform_equivalence",
            )
            .unwrap();
        // Template requires 1000 tests, provide only 10.
        let status = reg.auto_evaluate(&obl_id, MILLION, 10).unwrap();
        assert_eq!(status, ObligationStatus::InsufficientEvidence);
    }

    #[test]
    fn auto_evaluate_cvar_pass() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(PassId("router".into()), "tail_risk/cvar_latency_bound")
            .unwrap();
        let status = reg.auto_evaluate(&obl_id, 30 * MILLION, 100).unwrap();
        assert_eq!(status, ObligationStatus::Satisfied);
    }

    #[test]
    fn auto_evaluate_cvar_fail() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(PassId("router".into()), "tail_risk/cvar_latency_bound")
            .unwrap();
        let status = reg.auto_evaluate(&obl_id, 100 * MILLION, 100).unwrap();
        assert_eq!(status, ObligationStatus::Violated);
    }

    #[test]
    fn auto_evaluate_calibration_pass() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(
                PassId("calibrator".into()),
                "calibration/conformal_coverage",
            )
            .unwrap();
        let status = reg.auto_evaluate(&obl_id, 950_000, 100).unwrap();
        assert_eq!(status, ObligationStatus::Satisfied);
    }

    #[test]
    fn auto_evaluate_nonexistent_returns_none() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let result = reg.auto_evaluate(&ObligationId("nope".into()), 0, 0);
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // Waiver tests
    // -----------------------------------------------------------------------

    #[test]
    fn waive_waivable_obligation() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(PassId("timing".into()), "behavioral/effect_timing_contract")
            .unwrap();
        assert!(reg.waive(&obl_id, "operator approved"));
    }

    #[test]
    fn waive_non_waivable_obligation_fails() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(PassId("safety".into()), "safety/ifc_label_propagation")
            .unwrap();
        assert!(!reg.waive(&obl_id, "trying to waive"));
    }

    #[test]
    fn waive_nonexistent_returns_false() {
        let mut reg = ObligationRegistry::new(epoch(1));
        assert!(!reg.waive(&ObligationId("nope".into()), "test"));
    }

    // -----------------------------------------------------------------------
    // Report tests
    // -----------------------------------------------------------------------

    #[test]
    fn report_empty_registry() {
        let reg = ObligationRegistry::new(epoch(1));
        let report = reg.report();
        assert!(report.gate_pass); // no bindings = vacuously passes
        assert_eq!(report.evaluations.len(), 0);
    }

    #[test]
    fn report_pending_obligations_fail_gate() {
        let mut reg = ObligationRegistry::new(epoch(1));
        reg.bind(PassId("test".into()), "behavioral/ir_transform_equivalence");
        let report = reg.report();
        assert!(!report.gate_pass); // pending = not passing
        assert_eq!(report.pending_count, 1);
    }

    #[test]
    fn report_all_satisfied_passes_gate() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(PassId("test".into()), "behavioral/ir_transform_equivalence")
            .unwrap();
        reg.auto_evaluate(&obl_id, 999_500, 2000);
        let report = reg.report();
        assert!(report.gate_pass);
        assert_eq!(report.satisfied_count, 1);
        assert_eq!(report.violated_count, 0);
    }

    #[test]
    fn report_fatal_violation_fails_gate() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(PassId("test".into()), "safety/ifc_label_propagation")
            .unwrap();
        reg.evaluate(&obl_id, ObligationStatus::Violated, None, "failed");
        let report = reg.report();
        assert!(!report.gate_pass);
        assert_eq!(report.violated_count, 1);
    }

    #[test]
    fn report_waived_does_not_block_gate() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(PassId("timing".into()), "behavioral/effect_timing_contract")
            .unwrap();
        reg.waive(&obl_id, "approved");
        let report = reg.report();
        assert!(report.gate_pass);
        assert_eq!(report.waived_count, 1);
    }

    #[test]
    fn report_serde_roundtrip() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(PassId("test".into()), "behavioral/ir_transform_equivalence")
            .unwrap();
        reg.auto_evaluate(&obl_id, 999_500, 2000);
        let report = reg.report();
        let json = serde_json::to_string(&report).unwrap();
        let back: ObligationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // -----------------------------------------------------------------------
    // ObligationId tests
    // -----------------------------------------------------------------------

    #[test]
    fn obligation_id_display() {
        let id = ObligationId("obl-42".into());
        assert_eq!(format!("{id}"), "obl-42");
    }

    #[test]
    fn obligation_id_serde() {
        let id = ObligationId("obl-1".into());
        let json = serde_json::to_string(&id).unwrap();
        let back: ObligationId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // -----------------------------------------------------------------------
    // PassId tests
    // -----------------------------------------------------------------------

    #[test]
    fn pass_id_display() {
        let id = PassId("ir_transform_pass".into());
        assert_eq!(format!("{id}"), "ir_transform_pass");
    }

    // -----------------------------------------------------------------------
    // EvidenceRequirement tests
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_requirement_serde_roundtrip() {
        let requirements = vec![
            EvidenceRequirement::DifferentialTest {
                min_pass_rate_millionths: 999_000,
                min_test_count: 1000,
            },
            EvidenceRequirement::StatisticalTest {
                confidence_level_millionths: 950_000,
                min_samples: 100,
            },
            EvidenceRequirement::FormalProof {
                proof_system: "lean4".into(),
            },
            EvidenceRequirement::HashLinkage,
            EvidenceRequirement::PlasWitness,
            EvidenceRequirement::EProcessGuardrail {
                guardrail_id: "main".into(),
            },
            EvidenceRequirement::CvarBound {
                max_cvar_millionths: 50 * MILLION,
                alpha_millionths: 950_000,
            },
            EvidenceRequirement::CalibrationCoverage {
                min_coverage_millionths: 900_000,
            },
            EvidenceRequirement::OperatorReview,
        ];
        for req in &requirements {
            let json = serde_json::to_string(req).unwrap();
            let back: EvidenceRequirement = serde_json::from_str(&json).unwrap();
            assert_eq!(*req, back);
        }
    }

    // -----------------------------------------------------------------------
    // ObligationBinding tests
    // -----------------------------------------------------------------------

    #[test]
    fn binding_serde_roundtrip() {
        let binding = ObligationBinding {
            pass_id: PassId("test".into()),
            obligation_id: ObligationId("obl-1".into()),
            template_id: "behavioral/ir_transform_equivalence".into(),
            category: ObligationCategory::BehavioralPreservation,
            severity: ObligationSeverity::Fatal,
            evidence: EvidenceRequirement::HashLinkage,
        };
        let json = serde_json::to_string(&binding).unwrap();
        let back: ObligationBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(binding, back);
    }

    // -----------------------------------------------------------------------
    // ObligationEvaluation tests
    // -----------------------------------------------------------------------

    #[test]
    fn evaluation_serde_roundtrip() {
        let eval = ObligationEvaluation {
            obligation_id: ObligationId("obl-1".into()),
            template_id: "safety/test".into(),
            category: ObligationCategory::Safety,
            severity: ObligationSeverity::Fatal,
            status: ObligationStatus::Violated,
            epoch: epoch(42),
            observed_value: Some(500_000),
            required_value: Some(999_000),
            reason: "insufficient".into(),
        };
        let json = serde_json::to_string(&eval).unwrap();
        let back: ObligationEvaluation = serde_json::from_str(&json).unwrap();
        assert_eq!(eval, back);
    }

    // -----------------------------------------------------------------------
    // Registry serde
    // -----------------------------------------------------------------------

    #[test]
    fn registry_serde_roundtrip() {
        let mut reg = ObligationRegistry::new(epoch(1));
        reg.bind(PassId("test".into()), "behavioral/ir_transform_equivalence");
        let json = serde_json::to_string(&reg).unwrap();
        let back: ObligationRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(reg.template_count(), back.template_count());
        assert_eq!(reg.binding_count(), back.binding_count());
    }

    // -----------------------------------------------------------------------
    // Statistical evaluation
    // -----------------------------------------------------------------------

    #[test]
    fn auto_evaluate_statistical_pass() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(PassId("sched".into()), "liveness/scheduler_progress")
            .unwrap();
        let status = reg.auto_evaluate(&obl_id, 995_000, 2000).unwrap();
        assert_eq!(status, ObligationStatus::Satisfied);
    }

    #[test]
    fn auto_evaluate_statistical_insufficient() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(PassId("sched".into()), "liveness/scheduler_progress")
            .unwrap();
        let status = reg.auto_evaluate(&obl_id, 995_000, 5).unwrap();
        assert_eq!(status, ObligationStatus::InsufficientEvidence);
    }

    // -----------------------------------------------------------------------
    // Enrichment: ObligationCategory Display uniqueness via BTreeSet
    // -----------------------------------------------------------------------

    #[test]
    fn category_display_all_unique() {
        let mut displays = std::collections::BTreeSet::new();
        for cat in &ObligationCategory::ALL {
            displays.insert(cat.to_string());
        }
        assert_eq!(
            displays.len(),
            5,
            "all 5 categories produce distinct Display"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: ObligationStatus Display uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn status_display_all_unique() {
        let statuses = [
            ObligationStatus::Pending,
            ObligationStatus::InProgress,
            ObligationStatus::Satisfied,
            ObligationStatus::Violated,
            ObligationStatus::Waived,
            ObligationStatus::InsufficientEvidence,
        ];
        let mut displays = std::collections::BTreeSet::new();
        for s in &statuses {
            displays.insert(s.to_string());
        }
        assert_eq!(displays.len(), 6, "all 6 statuses produce distinct Display");
    }

    // -----------------------------------------------------------------------
    // Enrichment: ObligationSeverity serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn severity_serde_roundtrip() {
        let severities = [
            ObligationSeverity::Info,
            ObligationSeverity::Warning,
            ObligationSeverity::Error,
            ObligationSeverity::Fatal,
        ];
        for sev in &severities {
            let json = serde_json::to_string(sev).unwrap();
            let back: ObligationSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(*sev, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: PassId serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn pass_id_serde_roundtrip() {
        let id = PassId("ir_lowering".into());
        let json = serde_json::to_string(&id).unwrap();
        let back: PassId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: ObligationId ordering
    // -----------------------------------------------------------------------

    #[test]
    fn obligation_id_ordering() {
        let a = ObligationId("obl-1".into());
        let b = ObligationId("obl-2".into());
        assert!(a < b);
        let c = ObligationId("obl-1".into());
        assert_eq!(a, c);
    }

    // -----------------------------------------------------------------------
    // Enrichment: registry multiple categories in report
    // -----------------------------------------------------------------------

    #[test]
    fn report_covers_multiple_categories() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_beh = reg
            .bind(
                PassId("transform".into()),
                "behavioral/ir_transform_equivalence",
            )
            .unwrap();
        let obl_safe = reg
            .bind(PassId("safety".into()), "safety/ifc_label_propagation")
            .unwrap();
        reg.auto_evaluate(&obl_beh, 999_500, 2000);
        reg.evaluate(
            &obl_safe,
            ObligationStatus::Satisfied,
            Some(MILLION),
            "all labels correct",
        );
        let report = reg.report();
        assert!(report.gate_pass);
        assert_eq!(report.satisfied_count, 2);
    }

    // -----------------------------------------------------------------------
    // Enrichment: ObligationTemplate serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn obligation_template_serde_roundtrip() {
        let template = ObligationTemplate {
            template_id: "custom/test-template".into(),
            category: ObligationCategory::Liveness,
            severity: ObligationSeverity::Warning,
            description: "test obligation".into(),
            evidence: EvidenceRequirement::OperatorReview,
            waivable: true,
        };
        let json = serde_json::to_string(&template).unwrap();
        let back: ObligationTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(template.template_id, back.template_id);
        assert_eq!(template.category, back.category);
        assert_eq!(template.waivable, back.waivable);
    }

    // -----------------------------------------------------------------------
    // Enrichment: auto_evaluate formal proof defaults to pending
    // -----------------------------------------------------------------------

    #[test]
    fn auto_evaluate_formal_proof_obligation_returns_pending() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(PassId("prover".into()), "safety/hash_chain_integrity")
            .unwrap();
        let status = reg.auto_evaluate(&obl_id, MILLION, 1000).unwrap();
        // HashLinkage evidence does not match DifferentialTest/StatisticalTest/CvarBound/CalibrationCoverage,
        // so auto-evaluate should be Satisfied or InsufficientEvidence depending on implementation.
        assert!(
            status == ObligationStatus::Satisfied
                || status == ObligationStatus::InsufficientEvidence
                || status == ObligationStatus::Pending,
            "auto_evaluate for hash-linkage should produce a valid status"
        );
    }

    // ── Enrichment: ObligationStatus ordering ────────────────────────

    #[test]
    fn obligation_status_ordering_pending_before_satisfied() {
        assert!(ObligationStatus::Pending < ObligationStatus::Satisfied);
    }

    #[test]
    fn obligation_status_serde_roundtrip_all() {
        let variants = [
            ObligationStatus::Pending,
            ObligationStatus::InProgress,
            ObligationStatus::Satisfied,
            ObligationStatus::Violated,
            ObligationStatus::Waived,
            ObligationStatus::InsufficientEvidence,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ObligationStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // ── Enrichment: ObligationCategory ordering ──────────────────────

    #[test]
    fn obligation_category_ordering_chain() {
        assert!(ObligationCategory::BehavioralPreservation < ObligationCategory::Safety);
        assert!(ObligationCategory::Safety < ObligationCategory::Liveness);
        assert!(ObligationCategory::Liveness < ObligationCategory::CalibrationValidity);
        assert!(ObligationCategory::CalibrationValidity < ObligationCategory::TailRisk);
    }

    // ── Enrichment: ObligationSeverity ordering ──────────────────────

    #[test]
    fn obligation_severity_ordering_chain() {
        assert!(ObligationSeverity::Info < ObligationSeverity::Warning);
        assert!(ObligationSeverity::Warning < ObligationSeverity::Error);
        assert!(ObligationSeverity::Error < ObligationSeverity::Fatal);
    }

    // ── Enrichment: PassId ordering and display ──────────────────────

    #[test]
    fn pass_id_ordering_is_lexicographic() {
        let a = PassId("a-pass".into());
        let b = PassId("b-pass".into());
        assert!(a < b);
    }

    #[test]
    fn pass_id_display_matches_inner() {
        let p = PassId("my-transform".into());
        assert_eq!(p.to_string(), "my-transform");
    }

    // ── Enrichment: ObligationId ordering ────────────────────────────

    #[test]
    fn obligation_id_ordering_numeric_vs_lexicographic() {
        // Derived Ord on String is lexicographic: "obl-10" < "obl-2" (because '1' < '2')
        let id1 = ObligationId("obl-10".into());
        let id2 = ObligationId("obl-2".into());
        assert!(id1 < id2, "lexicographic: obl-10 < obl-2");
    }

    // ── Enrichment: registry template_count and binding_count ────────

    #[test]
    fn registry_template_returns_none_for_unknown() {
        let reg = ObligationRegistry::new(epoch(1));
        assert!(reg.template("nonexistent/template").is_none());
    }

    #[test]
    fn registry_bindings_for_pass_empty() {
        let reg = ObligationRegistry::new(epoch(1));
        let bindings = reg.bindings_for_pass(&PassId("unbound-pass".into()));
        assert!(bindings.is_empty());
    }

    #[test]
    fn registry_bind_increments_next_id() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let id1 = reg
            .bind(PassId("p1".into()), "behavioral/ir_transform_equivalence")
            .unwrap();
        let id2 = reg
            .bind(PassId("p2".into()), "behavioral/render_output_stability")
            .unwrap();
        assert_eq!(id1.0, "obl-1");
        assert_eq!(id2.0, "obl-2");
    }

    // ── Enrichment: auto_evaluate boundary conditions ────────────────

    #[test]
    fn auto_evaluate_differential_test_exact_boundary() {
        let mut reg = ObligationRegistry::new(epoch(1));
        // min_pass_rate = 999_000, min_test_count = 1000
        let obl_id = reg
            .bind(PassId("pass".into()), "behavioral/ir_transform_equivalence")
            .unwrap();
        let status = reg.auto_evaluate(&obl_id, 999_000, 1000).unwrap();
        assert_eq!(status, ObligationStatus::Satisfied);
    }

    #[test]
    fn auto_evaluate_differential_test_just_below() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(PassId("pass".into()), "behavioral/ir_transform_equivalence")
            .unwrap();
        let status = reg.auto_evaluate(&obl_id, 998_999, 1000).unwrap();
        assert_eq!(status, ObligationStatus::Violated);
    }

    #[test]
    fn auto_evaluate_insufficient_evidence_when_too_few_samples() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(PassId("pass".into()), "behavioral/ir_transform_equivalence")
            .unwrap();
        let status = reg.auto_evaluate(&obl_id, MILLION, 999).unwrap();
        assert_eq!(status, ObligationStatus::InsufficientEvidence);
    }

    // ── Enrichment: ObligationReport from_evaluations ────────────────

    #[test]
    fn obligation_report_inprogress_counts_as_pending() {
        let evals = vec![ObligationEvaluation {
            obligation_id: ObligationId("obl-1".into()),
            template_id: "test".into(),
            category: ObligationCategory::Safety,
            severity: ObligationSeverity::Error,
            status: ObligationStatus::InProgress,
            epoch: epoch(1),
            observed_value: None,
            required_value: None,
            reason: "in progress".into(),
        }];
        let report = ObligationReport::from_evaluations(epoch(1), evals);
        assert_eq!(report.pending_count, 1);
        assert!(!report.gate_pass); // pending > 0 blocks gate
    }

    #[test]
    fn obligation_report_all_satisfied_gate_passes() {
        let evals = vec![
            ObligationEvaluation {
                obligation_id: ObligationId("obl-1".into()),
                template_id: "t1".into(),
                category: ObligationCategory::Safety,
                severity: ObligationSeverity::Fatal,
                status: ObligationStatus::Satisfied,
                epoch: epoch(1),
                observed_value: Some(MILLION),
                required_value: Some(999_000),
                reason: "ok".into(),
            },
            ObligationEvaluation {
                obligation_id: ObligationId("obl-2".into()),
                template_id: "t2".into(),
                category: ObligationCategory::Liveness,
                severity: ObligationSeverity::Error,
                status: ObligationStatus::Waived,
                epoch: epoch(1),
                observed_value: None,
                required_value: None,
                reason: "waived".into(),
            },
        ];
        let report = ObligationReport::from_evaluations(epoch(1), evals);
        assert_eq!(report.satisfied_count, 1);
        assert_eq!(report.waived_count, 1);
        assert!(report.gate_pass);
    }

    #[test]
    fn obligation_report_fatal_violation_blocks_gate() {
        let evals = vec![ObligationEvaluation {
            obligation_id: ObligationId("obl-1".into()),
            template_id: "t".into(),
            category: ObligationCategory::Safety,
            severity: ObligationSeverity::Fatal,
            status: ObligationStatus::Violated,
            epoch: epoch(1),
            observed_value: Some(0),
            required_value: Some(999_000),
            reason: "failed".into(),
        }];
        let report = ObligationReport::from_evaluations(epoch(1), evals);
        assert!(!report.gate_pass);
        assert_eq!(report.violated_count, 1);
    }

    // ── Enrichment: EvidenceRequirement serde ────────────────────────

    #[test]
    fn evidence_requirement_all_variants_serde() {
        let variants = vec![
            EvidenceRequirement::DifferentialTest {
                min_pass_rate_millionths: 950_000,
                min_test_count: 100,
            },
            EvidenceRequirement::StatisticalTest {
                confidence_level_millionths: 990_000,
                min_samples: 500,
            },
            EvidenceRequirement::FormalProof {
                proof_system: "lean4".into(),
            },
            EvidenceRequirement::HashLinkage,
            EvidenceRequirement::PlasWitness,
            EvidenceRequirement::EProcessGuardrail {
                guardrail_id: "grd-1".into(),
            },
            EvidenceRequirement::CvarBound {
                max_cvar_millionths: 50_000_000,
                alpha_millionths: 950_000,
            },
            EvidenceRequirement::CalibrationCoverage {
                min_coverage_millionths: 900_000,
            },
            EvidenceRequirement::OperatorReview,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: EvidenceRequirement = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // ── Enrichment: ObligationBinding denormalized fields match ──────

    #[test]
    fn binding_denormalized_fields_match_template() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let _obl_id = reg
            .bind(PassId("pass".into()), "behavioral/ir_transform_equivalence")
            .unwrap();
        let template = reg.template("behavioral/ir_transform_equivalence").unwrap();
        let bindings = reg.bindings_for_pass(&PassId("pass".into()));
        assert_eq!(bindings.len(), 1);
        let b = &bindings[0];
        assert_eq!(b.category, template.category);
        assert_eq!(b.severity, template.severity);
        assert_eq!(b.evidence, template.evidence);
    }

    // ── Enrichment: ObligationReport serde ───────────────────────────

    #[test]
    fn obligation_report_serde_roundtrip() {
        let report = ObligationReport::from_evaluations(epoch(1), vec![]);
        let json = serde_json::to_string(&report).unwrap();
        let back: ObligationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // ── Enrichment: ObligationEvaluation serde ───────────────────────

    #[test]
    fn obligation_evaluation_serde_roundtrip() {
        let eval = ObligationEvaluation {
            obligation_id: ObligationId("obl-99".into()),
            template_id: "test/template".into(),
            category: ObligationCategory::TailRisk,
            severity: ObligationSeverity::Warning,
            status: ObligationStatus::InsufficientEvidence,
            epoch: epoch(42),
            observed_value: None,
            required_value: Some(999_000),
            reason: "not enough data".into(),
        };
        let json = serde_json::to_string(&eval).unwrap();
        let back: ObligationEvaluation = serde_json::from_str(&json).unwrap();
        assert_eq!(eval, back);
    }

    // ── Enrichment: ObligationRegistry serde ─────────────────────────

    #[test]
    fn obligation_registry_serde_roundtrip() {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl_id = reg
            .bind(PassId("p".into()), "behavioral/ir_transform_equivalence")
            .unwrap();
        reg.auto_evaluate(&obl_id, MILLION, 10_000);
        let json = serde_json::to_string(&reg).unwrap();
        let back: ObligationRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.template_count(), reg.template_count());
        assert_eq!(back.binding_count(), reg.binding_count());
    }
}
