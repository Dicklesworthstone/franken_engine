#![forbid(unsafe_code)]

//! Hindsight escalation bundle: escalates from minimal hindsight traces
//! to full replay bundles on declared triggers.
//!
//! Bead: bd-1lsy.9.11.3 [RGC-811C]
//!
//! The engine keeps routine boundary-capture logging cheap by recording
//! only minimal redacted digests (`hindsight_boundary_capture`). When
//! anomalies, regressions, or user-visible failures are detected, this
//! module escalates to a full replay bundle that captures enough evidence
//! for deep diagnosis.
//!
//! # Design decisions
//!
//! - A trigger taxonomy classifies *why* escalation fires. Each trigger
//!   carries a severity and a rationale so operators can audit the
//!   decision chain.
//! - Escalation is deliberate and deterministic: the runtime never
//!   silently switches observability regimes without recording why.
//! - Each escalation produces an `EscalationReceipt` linking the trigger,
//!   the bundle, and the epoch.
//! - Bundles carry redaction metadata so that privacy rules from
//!   `hindsight_boundary_capture` are preserved even in escalated state.
//! - All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::hindsight_boundary_capture::{BoundaryClass, RedactionTreatment};
use crate::runtime_config::GatesConfig;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the escalation bundle module.
pub const ESCALATION_SCHEMA_VERSION: &str = "franken-engine.hindsight-escalation-bundle.v1";

/// Bead identifier for this module.
pub const ESCALATION_BEAD_ID: &str = "bd-1lsy.9.11.3";

/// Component name.
pub const COMPONENT: &str = "hindsight_escalation_bundle";

/// One million — the unit for fixed-point millionths arithmetic.
const MILLION: u64 = 1_000_000;

/// Default cost budget for escalation (millionths of the per-run budget).
const DEFAULT_COST_BUDGET_MILLIONTHS: u64 = 100_000;

// ---------------------------------------------------------------------------
// EscalationTriggerKind
// ---------------------------------------------------------------------------

/// Taxonomy of events that can trigger escalation from minimal traces
/// to full replay bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationTriggerKind {
    /// An anomaly was detected in runtime behavior.
    AnomalyDetected,
    /// A performance or correctness regression was observed.
    RegressionObserved,
    /// A user-visible failure occurred.
    UserVisibleFailure,
    /// A policy violation was detected by the guard plane.
    PolicyViolation,
    /// Replay divergence between reference and candidate engines.
    ReplayDivergence,
    /// Resource exhaustion (memory, CPU budget, etc.) was observed.
    ResourceExhaustion,
    /// Operator explicitly requested escalation.
    OperatorRequest,
}

impl EscalationTriggerKind {
    /// All trigger kinds in canonical order.
    pub const ALL: &[Self] = &[
        Self::AnomalyDetected,
        Self::RegressionObserved,
        Self::UserVisibleFailure,
        Self::PolicyViolation,
        Self::ReplayDivergence,
        Self::ResourceExhaustion,
        Self::OperatorRequest,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnomalyDetected => "anomaly_detected",
            Self::RegressionObserved => "regression_observed",
            Self::UserVisibleFailure => "user_visible_failure",
            Self::PolicyViolation => "policy_violation",
            Self::ReplayDivergence => "replay_divergence",
            Self::ResourceExhaustion => "resource_exhaustion",
            Self::OperatorRequest => "operator_request",
        }
    }
}

impl fmt::Display for EscalationTriggerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// TriggerSeverity
// ---------------------------------------------------------------------------

/// Severity level of an escalation trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerSeverity {
    /// Advisory — might warrant deeper investigation.
    Advisory,
    /// Warning — likely warrants escalation.
    Warning,
    /// Critical — must escalate immediately.
    Critical,
    /// Emergency — halt-level escalation with full capture.
    Emergency,
}

impl TriggerSeverity {
    pub const ALL: &[Self] = &[
        Self::Advisory,
        Self::Warning,
        Self::Critical,
        Self::Emergency,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Emergency => "emergency",
        }
    }

    /// Cost multiplier for this severity (millionths).
    /// Higher severity means more resources can be spent on capture.
    pub const fn cost_multiplier_millionths(self) -> u64 {
        match self {
            Self::Advisory => 250_000,
            Self::Warning => 500_000,
            Self::Critical => 750_000,
            Self::Emergency => MILLION,
        }
    }

    /// Whether this severity automatically triggers escalation.
    pub const fn auto_escalate(self) -> bool {
        matches!(self, Self::Critical | Self::Emergency)
    }
}

impl fmt::Display for TriggerSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// EscalationTrigger
// ---------------------------------------------------------------------------

/// A concrete trigger event that may cause escalation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationTrigger {
    /// Unique trigger identifier.
    pub trigger_id: String,
    /// What kind of trigger this is.
    pub kind: EscalationTriggerKind,
    /// How severe this trigger is.
    pub severity: TriggerSeverity,
    /// Human-readable description of the trigger event.
    pub description: String,
    /// Which boundary classes are relevant to this trigger.
    pub relevant_boundaries: Vec<BoundaryClass>,
    /// The specific component or subsystem that fired the trigger.
    pub source_component: String,
    /// Epoch when this trigger was fired.
    pub trigger_epoch: SecurityEpoch,
    /// Content hash of this trigger.
    pub trigger_hash: ContentHash,
}

impl EscalationTrigger {
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.trigger_id.as_bytes());
        data.extend_from_slice(self.kind.as_str().as_bytes());
        data.extend_from_slice(self.severity.as_str().as_bytes());
        data.extend_from_slice(self.description.as_bytes());
        let mut sorted_boundaries: Vec<_> = self.relevant_boundaries.iter().collect();
        sorted_boundaries.sort_by_key(|b| b.as_str());
        for boundary in &sorted_boundaries {
            data.extend_from_slice(boundary.as_str().as_bytes());
        }
        data.extend_from_slice(self.source_component.as_bytes());
        data.extend_from_slice(&self.trigger_epoch.as_u64().to_le_bytes());
        self.trigger_hash = ContentHash::compute(&data);
    }
}

// ---------------------------------------------------------------------------
// BundleContentKind
// ---------------------------------------------------------------------------

/// Types of content that can be included in an escalation bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleContentKind {
    /// Full boundary capture records (unredacted where policy allows).
    FullBoundaryCapture,
    /// Decision receipt chain from the evidence ledger.
    DecisionReceiptChain,
    /// Engine state snapshot at the point of the trigger.
    StateSnapshot,
    /// Execution trace with instruction-level detail.
    ExecutionTrace,
    /// Memory heap profile at the trigger point.
    HeapProfile,
    /// Policy evaluation log covering the trigger window.
    PolicyEvaluationLog,
    /// Differential replay inputs for reproduction.
    ReplayInputs,
}

impl BundleContentKind {
    pub const ALL: &[Self] = &[
        Self::FullBoundaryCapture,
        Self::DecisionReceiptChain,
        Self::StateSnapshot,
        Self::ExecutionTrace,
        Self::HeapProfile,
        Self::PolicyEvaluationLog,
        Self::ReplayInputs,
    ];

    /// Base cost of including this content kind (millionths).
    pub const fn base_cost_millionths(self) -> u64 {
        match self {
            Self::FullBoundaryCapture => 50_000,
            Self::DecisionReceiptChain => 30_000,
            Self::StateSnapshot => 80_000,
            Self::ExecutionTrace => 120_000,
            Self::HeapProfile => 100_000,
            Self::PolicyEvaluationLog => 40_000,
            Self::ReplayInputs => 60_000,
        }
    }
}

impl fmt::Display for BundleContentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::FullBoundaryCapture => "full_boundary_capture",
            Self::DecisionReceiptChain => "decision_receipt_chain",
            Self::StateSnapshot => "state_snapshot",
            Self::ExecutionTrace => "execution_trace",
            Self::HeapProfile => "heap_profile",
            Self::PolicyEvaluationLog => "policy_evaluation_log",
            Self::ReplayInputs => "replay_inputs",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// BundleContentEntry
// ---------------------------------------------------------------------------

/// A single content entry in an escalation bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleContentEntry {
    /// What kind of content this is.
    pub kind: BundleContentKind,
    /// Digest of the content payload.
    pub content_digest: ContentHash,
    /// Redaction treatment applied to this entry.
    pub redaction: RedactionTreatment,
    /// Size in bytes (estimated or actual).
    pub size_bytes: u64,
    /// Whether this entry was fully captured or truncated.
    pub complete: bool,
}

// ---------------------------------------------------------------------------
// EscalationBundle
// ---------------------------------------------------------------------------

/// A full replay bundle produced by escalation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationBundle {
    /// Unique bundle identifier.
    pub bundle_id: String,
    /// The trigger that caused this escalation.
    pub trigger_id: String,
    /// Content entries in this bundle.
    pub entries: Vec<BundleContentEntry>,
    /// Which boundary classes are covered.
    pub covered_boundaries: BTreeSet<BoundaryClass>,
    /// Total estimated cost of this bundle (millionths).
    pub total_cost_millionths: u64,
    /// Epoch when this bundle was created.
    pub bundle_epoch: SecurityEpoch,
    /// Content hash of this bundle.
    pub bundle_hash: ContentHash,
}

impl EscalationBundle {
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.bundle_id.as_bytes());
        data.extend_from_slice(self.trigger_id.as_bytes());
        let mut sorted_entries: Vec<_> = self.entries.iter().collect();
        sorted_entries.sort_by_key(|e| &e.content_digest);
        for entry in &sorted_entries {
            data.extend_from_slice(entry.kind.to_string().as_bytes());
            data.extend_from_slice(entry.content_digest.as_bytes());
            data.extend_from_slice(match entry.redaction {
                RedactionTreatment::Plaintext => b"plaintext",
                RedactionTreatment::DigestOnly => b"digest_only",
                RedactionTreatment::Omit => b"omit",
            });
            data.extend_from_slice(&entry.size_bytes.to_le_bytes());
            data.extend_from_slice(if entry.complete { b"1" } else { b"0" });
        }
        let mut sorted_boundaries: Vec<_> = self.covered_boundaries.iter().collect();
        sorted_boundaries.sort_by_key(|b| b.as_str());
        for boundary in &sorted_boundaries {
            data.extend_from_slice(boundary.as_str().as_bytes());
        }
        data.extend_from_slice(&self.total_cost_millionths.to_le_bytes());
        data.extend_from_slice(&self.bundle_epoch.as_u64().to_le_bytes());
        self.bundle_hash = ContentHash::compute(&data);
    }
}

// ---------------------------------------------------------------------------
// EscalationDecision
// ---------------------------------------------------------------------------

/// Whether to escalate, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationDecision {
    /// Escalate: produce a full replay bundle.
    Escalate,
    /// Suppress: the trigger does not warrant escalation.
    Suppress,
    /// Defer: hold the trigger for later batch processing.
    Defer,
}

impl EscalationDecision {
    pub const ALL: &[Self] = &[Self::Escalate, Self::Suppress, Self::Defer];
}

impl fmt::Display for EscalationDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Escalate => "escalate",
            Self::Suppress => "suppress",
            Self::Defer => "defer",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// EscalationReceipt
// ---------------------------------------------------------------------------

/// Record of an escalation decision and its outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationReceipt {
    /// Unique receipt identifier.
    pub receipt_id: String,
    /// The trigger that initiated escalation.
    pub trigger_id: String,
    /// What decision was made.
    pub decision: EscalationDecision,
    /// If escalated, the bundle identifier.
    pub bundle_id: Option<String>,
    /// Rationale for the decision.
    pub rationale: String,
    /// Cost budget at the time of the decision (millionths).
    pub cost_budget_millionths: u64,
    /// Actual cost consumed (millionths).
    pub cost_consumed_millionths: u64,
    /// Epoch when this receipt was created.
    pub receipt_epoch: SecurityEpoch,
    /// Content hash of this receipt.
    pub receipt_hash: ContentHash,
}

impl EscalationReceipt {
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.receipt_id.as_bytes());
        data.extend_from_slice(self.trigger_id.as_bytes());
        data.extend_from_slice(self.decision.to_string().as_bytes());
        if let Some(ref bundle_id) = self.bundle_id {
            data.extend_from_slice(bundle_id.as_bytes());
        }
        data.extend_from_slice(self.rationale.as_bytes());
        data.extend_from_slice(&self.cost_budget_millionths.to_le_bytes());
        data.extend_from_slice(&self.cost_consumed_millionths.to_le_bytes());
        data.extend_from_slice(&self.receipt_epoch.as_u64().to_le_bytes());
        self.receipt_hash = ContentHash::compute(&data);
    }
}

// ---------------------------------------------------------------------------
// EscalationPolicy
// ---------------------------------------------------------------------------

/// Configuration for the escalation decision engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationPolicy {
    /// Maximum cost budget per escalation window (millionths).
    pub cost_budget_millionths: u64,
    /// Trigger kinds that always escalate regardless of budget.
    pub always_escalate: BTreeSet<EscalationTriggerKind>,
    /// Trigger kinds that are always suppressed.
    pub always_suppress: BTreeSet<EscalationTriggerKind>,
    /// Minimum severity to auto-escalate.
    pub auto_escalate_threshold: TriggerSeverity,
    /// Content kinds to include at each severity level.
    pub advisory_content: Vec<BundleContentKind>,
    pub warning_content: Vec<BundleContentKind>,
    pub critical_content: Vec<BundleContentKind>,
    pub emergency_content: Vec<BundleContentKind>,
}

impl Default for EscalationPolicy {
    fn default() -> Self {
        Self {
            cost_budget_millionths: DEFAULT_COST_BUDGET_MILLIONTHS,
            always_escalate: BTreeSet::from([
                EscalationTriggerKind::UserVisibleFailure,
                EscalationTriggerKind::PolicyViolation,
            ]),
            always_suppress: BTreeSet::new(),
            auto_escalate_threshold: TriggerSeverity::Critical,
            advisory_content: vec![
                BundleContentKind::FullBoundaryCapture,
                BundleContentKind::DecisionReceiptChain,
            ],
            warning_content: vec![
                BundleContentKind::FullBoundaryCapture,
                BundleContentKind::DecisionReceiptChain,
                BundleContentKind::PolicyEvaluationLog,
                BundleContentKind::ReplayInputs,
            ],
            critical_content: vec![
                BundleContentKind::FullBoundaryCapture,
                BundleContentKind::DecisionReceiptChain,
                BundleContentKind::StateSnapshot,
                BundleContentKind::ExecutionTrace,
                BundleContentKind::PolicyEvaluationLog,
                BundleContentKind::ReplayInputs,
            ],
            emergency_content: BundleContentKind::ALL.to_vec(),
        }
    }
}

impl EscalationPolicy {
    /// Create a policy with the cost budget from a [`GatesConfig`], keeping
    /// all other fields at their defaults.
    pub fn with_gates_config(config: &GatesConfig) -> Self {
        Self {
            cost_budget_millionths: config.escalation_cost_budget_millionths,
            ..Self::default()
        }
    }

    /// Get the content kinds for a given severity level.
    pub fn content_for_severity(&self, severity: TriggerSeverity) -> &[BundleContentKind] {
        match severity {
            TriggerSeverity::Advisory => &self.advisory_content,
            TriggerSeverity::Warning => &self.warning_content,
            TriggerSeverity::Critical => &self.critical_content,
            TriggerSeverity::Emergency => &self.emergency_content,
        }
    }
}

// ---------------------------------------------------------------------------
// EscalationPipeline
// ---------------------------------------------------------------------------

/// Orchestrates escalation decisions for a stream of triggers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationPipeline {
    /// Schema version.
    pub schema_version: String,
    /// Bead identifier.
    pub bead_id: String,
    /// The escalation policy in effect.
    pub policy: EscalationPolicy,
    /// All triggers processed so far.
    pub triggers: Vec<EscalationTrigger>,
    /// All receipts generated.
    pub receipts: Vec<EscalationReceipt>,
    /// All bundles produced.
    pub bundles: Vec<EscalationBundle>,
    /// Remaining cost budget (millionths).
    pub remaining_budget_millionths: u64,
    /// Epoch of pipeline creation.
    pub pipeline_epoch: SecurityEpoch,
    /// Content hash of the pipeline.
    pub pipeline_hash: ContentHash,
}

impl EscalationPipeline {
    /// Create a new pipeline with the given policy.
    pub fn new(policy: EscalationPolicy, epoch: SecurityEpoch) -> Self {
        let budget = policy.cost_budget_millionths;
        let mut pipeline = Self {
            schema_version: ESCALATION_SCHEMA_VERSION.to_string(),
            bead_id: ESCALATION_BEAD_ID.to_string(),
            policy,
            triggers: Vec::new(),
            receipts: Vec::new(),
            bundles: Vec::new(),
            remaining_budget_millionths: budget,
            pipeline_epoch: epoch,
            pipeline_hash: ContentHash::compute(b"escalation_pipeline"),
        };
        pipeline.recompute_hash();
        pipeline
    }

    /// Process a trigger and decide whether to escalate.
    pub fn process_trigger(&mut self, mut trigger: EscalationTrigger) -> &EscalationReceipt {
        trigger.recompute_hash();
        let trigger_id = trigger.trigger_id.clone();
        let severity = trigger.severity;
        let kind = trigger.kind;
        let relevant_boundaries = trigger.relevant_boundaries.clone();
        self.triggers.push(trigger);

        // Decide whether to escalate
        let (decision, rationale) = self.decide(&trigger_id, kind, severity);
        let budget_before = self.remaining_budget_millionths;

        let (bundle_id, cost_consumed) = if decision == EscalationDecision::Escalate {
            let bundle = self.build_bundle(&trigger_id, severity, &relevant_boundaries);
            let cost = bundle.total_cost_millionths;
            let bid = bundle.bundle_id.clone();
            self.bundles.push(bundle);
            self.remaining_budget_millionths =
                self.remaining_budget_millionths.saturating_sub(cost);
            (Some(bid), cost)
        } else {
            (None, 0)
        };

        let mut receipt = EscalationReceipt {
            receipt_id: format!("receipt-{trigger_id}"),
            trigger_id,
            decision,
            bundle_id,
            rationale,
            cost_budget_millionths: budget_before,
            cost_consumed_millionths: cost_consumed,
            receipt_epoch: self.pipeline_epoch,
            receipt_hash: ContentHash::compute(b"escalation_receipt"),
        };
        receipt.recompute_hash();
        self.receipts.push(receipt);
        self.recompute_hash();
        self.receipts.last().expect("just pushed")
    }

    /// Get all escalated receipts.
    pub fn escalated_receipts(&self) -> Vec<&EscalationReceipt> {
        self.receipts
            .iter()
            .filter(|r| r.decision == EscalationDecision::Escalate)
            .collect()
    }

    /// Get all suppressed receipts.
    pub fn suppressed_receipts(&self) -> Vec<&EscalationReceipt> {
        self.receipts
            .iter()
            .filter(|r| r.decision == EscalationDecision::Suppress)
            .collect()
    }

    /// Get all deferred receipts.
    pub fn deferred_receipts(&self) -> Vec<&EscalationReceipt> {
        self.receipts
            .iter()
            .filter(|r| r.decision == EscalationDecision::Defer)
            .collect()
    }

    /// Get the bundle for a specific trigger.
    pub fn bundle_for_trigger(&self, trigger_id: &str) -> Option<&EscalationBundle> {
        self.bundles.iter().find(|b| b.trigger_id == trigger_id)
    }

    /// Generate a summary report.
    pub fn summary_report(&self) -> EscalationSummary {
        let total_triggers = self.triggers.len();
        let escalated = self.escalated_receipts().len();
        let suppressed = self.suppressed_receipts().len();
        let deferred = self.deferred_receipts().len();
        let total_bundles = self.bundles.len();
        let total_cost: u64 = self.bundles.iter().map(|b| b.total_cost_millionths).sum();

        let budget_utilization_millionths = total_cost
            .saturating_mul(MILLION)
            .checked_div(self.policy.cost_budget_millionths)
            .unwrap_or(0);

        let mut by_kind = Vec::new();
        for kind in EscalationTriggerKind::ALL {
            let count = self.triggers.iter().filter(|t| t.kind == *kind).count();
            if count > 0 {
                by_kind.push((*kind, count));
            }
        }

        let mut by_severity = Vec::new();
        for severity in TriggerSeverity::ALL {
            let count = self
                .triggers
                .iter()
                .filter(|t| t.severity == *severity)
                .count();
            if count > 0 {
                by_severity.push((*severity, count));
            }
        }

        let mut hash_data = Vec::new();
        hash_data.extend_from_slice(&(total_triggers as u64).to_le_bytes());
        hash_data.extend_from_slice(&(escalated as u64).to_le_bytes());
        hash_data.extend_from_slice(&(suppressed as u64).to_le_bytes());
        hash_data.extend_from_slice(&(deferred as u64).to_le_bytes());
        hash_data.extend_from_slice(&(total_bundles as u64).to_le_bytes());
        hash_data.extend_from_slice(&total_cost.to_le_bytes());
        hash_data.extend_from_slice(&budget_utilization_millionths.to_le_bytes());
        hash_data.extend_from_slice(&self.remaining_budget_millionths.to_le_bytes());
        // by_kind and by_severity are built from sorted ALL arrays, so iteration order is stable.
        for (kind, count) in &by_kind {
            hash_data.extend_from_slice(format!("{kind:?}").as_bytes());
            hash_data.extend_from_slice(&(*count as u64).to_le_bytes());
        }
        for (severity, count) in &by_severity {
            hash_data.extend_from_slice(format!("{severity:?}").as_bytes());
            hash_data.extend_from_slice(&(*count as u64).to_le_bytes());
        }
        hash_data.extend_from_slice(&self.pipeline_epoch.as_u64().to_le_bytes());

        EscalationSummary {
            total_triggers,
            escalated_count: escalated,
            suppressed_count: suppressed,
            deferred_count: deferred,
            total_bundles,
            total_cost_millionths: total_cost,
            budget_utilization_millionths,
            remaining_budget_millionths: self.remaining_budget_millionths,
            triggers_by_kind: by_kind,
            triggers_by_severity: by_severity,
            pipeline_epoch: self.pipeline_epoch,
            summary_hash: ContentHash::compute(&hash_data),
        }
    }

    /// Decide whether to escalate for a given trigger.
    fn decide(
        &self,
        _trigger_id: &str,
        kind: EscalationTriggerKind,
        severity: TriggerSeverity,
    ) -> (EscalationDecision, String) {
        // Always-suppress overrides everything
        if self.policy.always_suppress.contains(&kind) {
            return (
                EscalationDecision::Suppress,
                format!("{kind} is in always-suppress list"),
            );
        }

        // Always-escalate overrides budget checks
        if self.policy.always_escalate.contains(&kind) {
            return (
                EscalationDecision::Escalate,
                format!("{kind} is in always-escalate list"),
            );
        }

        // Auto-escalate based on severity threshold
        if severity >= self.policy.auto_escalate_threshold {
            if self.remaining_budget_millionths > 0 {
                return (
                    EscalationDecision::Escalate,
                    format!("{severity} severity meets auto-escalate threshold"),
                );
            }
            return (
                EscalationDecision::Defer,
                format!("{severity} severity meets threshold but budget exhausted — deferred"),
            );
        }

        // Below threshold: defer unless budget is generous.
        // Estimate cost using severity-adjusted costs (matching build_bundle).
        let content = self.policy.content_for_severity(severity);
        let estimated_cost: u64 = content
            .iter()
            .map(|c| {
                c.base_cost_millionths()
                    .saturating_mul(severity.cost_multiplier_millionths())
                    / MILLION
            })
            .sum();
        if estimated_cost <= self.remaining_budget_millionths {
            (
                EscalationDecision::Escalate,
                format!(
                    "{severity} trigger within budget (cost: {estimated_cost}, remaining: {})",
                    self.remaining_budget_millionths
                ),
            )
        } else {
            (
                EscalationDecision::Defer,
                format!(
                    "{severity} trigger exceeds budget (cost: {estimated_cost}, remaining: {})",
                    self.remaining_budget_millionths
                ),
            )
        }
    }

    /// Build a bundle for an escalation.
    fn build_bundle(
        &self,
        trigger_id: &str,
        severity: TriggerSeverity,
        relevant_boundaries: &[BoundaryClass],
    ) -> EscalationBundle {
        let content_kinds = self.policy.content_for_severity(severity);
        let mut entries = Vec::new();
        let mut total_cost = 0_u64;

        for kind in content_kinds {
            let base_cost = kind.base_cost_millionths();
            let adjusted_cost =
                base_cost.saturating_mul(severity.cost_multiplier_millionths()) / MILLION;

            let redaction = match kind {
                BundleContentKind::FullBoundaryCapture
                | BundleContentKind::StateSnapshot
                | BundleContentKind::HeapProfile => {
                    if severity == TriggerSeverity::Emergency {
                        RedactionTreatment::Plaintext
                    } else {
                        RedactionTreatment::DigestOnly
                    }
                }
                _ => RedactionTreatment::Plaintext,
            };

            let content_digest = ContentHash::compute(format!("{trigger_id}-{kind}").as_bytes());

            entries.push(BundleContentEntry {
                kind: *kind,
                content_digest,
                redaction,
                size_bytes: adjusted_cost * 1024, // rough estimate
                complete: true,
            });
            total_cost = total_cost.saturating_add(adjusted_cost);
        }

        let covered: BTreeSet<BoundaryClass> = relevant_boundaries.iter().copied().collect();

        let mut bundle = EscalationBundle {
            bundle_id: format!("bundle-{trigger_id}"),
            trigger_id: trigger_id.to_string(),
            entries,
            covered_boundaries: covered,
            total_cost_millionths: total_cost,
            bundle_epoch: self.pipeline_epoch,
            bundle_hash: ContentHash::compute(b"escalation_bundle"),
        };
        bundle.recompute_hash();
        bundle
    }

    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.schema_version.as_bytes());
        data.extend_from_slice(self.bead_id.as_bytes());
        for trigger in &self.triggers {
            data.extend_from_slice(trigger.trigger_hash.as_bytes());
        }
        for receipt in &self.receipts {
            data.extend_from_slice(receipt.receipt_hash.as_bytes());
        }
        for bundle in &self.bundles {
            data.extend_from_slice(bundle.bundle_hash.as_bytes());
        }
        data.extend_from_slice(&self.remaining_budget_millionths.to_le_bytes());
        data.extend_from_slice(&self.pipeline_epoch.as_u64().to_le_bytes());
        self.pipeline_hash = ContentHash::compute(&data);
    }
}

// ---------------------------------------------------------------------------
// EscalationSummary
// ---------------------------------------------------------------------------

/// Summary report of escalation pipeline activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationSummary {
    pub total_triggers: usize,
    pub escalated_count: usize,
    pub suppressed_count: usize,
    pub deferred_count: usize,
    pub total_bundles: usize,
    pub total_cost_millionths: u64,
    pub budget_utilization_millionths: u64,
    pub remaining_budget_millionths: u64,
    pub triggers_by_kind: Vec<(EscalationTriggerKind, usize)>,
    pub triggers_by_severity: Vec<(TriggerSeverity, usize)>,
    pub pipeline_epoch: SecurityEpoch,
    pub summary_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// EscalationError
// ---------------------------------------------------------------------------

/// Errors from escalation operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationError {
    /// Trigger not found.
    TriggerNotFound { trigger_id: String },
    /// Bundle not found.
    BundleNotFound { bundle_id: String },
    /// Budget exhausted.
    BudgetExhausted { remaining: u64, required: u64 },
    /// Policy configuration invalid.
    InvalidPolicy { detail: String },
}

impl fmt::Display for EscalationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TriggerNotFound { trigger_id } => {
                write!(f, "trigger not found: {trigger_id}")
            }
            Self::BundleNotFound { bundle_id } => {
                write!(f, "bundle not found: {bundle_id}")
            }
            Self::BudgetExhausted {
                remaining,
                required,
            } => {
                write!(
                    f,
                    "budget exhausted: remaining={remaining}, required={required}"
                )
            }
            Self::InvalidPolicy { detail } => {
                write!(f, "invalid policy: {detail}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(100)
    }

    fn test_trigger(
        id: &str,
        kind: EscalationTriggerKind,
        severity: TriggerSeverity,
    ) -> EscalationTrigger {
        EscalationTrigger {
            trigger_id: id.to_string(),
            kind,
            severity,
            description: format!("test trigger {id}"),
            relevant_boundaries: vec![BoundaryClass::ClockRead, BoundaryClass::NetworkResponse],
            source_component: "test_component".to_string(),
            trigger_epoch: test_epoch(),
            trigger_hash: ContentHash::compute(b"placeholder"),
        }
    }

    // --- EscalationTriggerKind tests ---

    #[test]
    fn trigger_kind_all_count() {
        assert_eq!(EscalationTriggerKind::ALL.len(), 7);
    }

    #[test]
    fn trigger_kind_display() {
        assert_eq!(
            EscalationTriggerKind::AnomalyDetected.to_string(),
            "anomaly_detected"
        );
        assert_eq!(
            EscalationTriggerKind::AnomalyDetected.as_str(),
            "anomaly_detected"
        );
        assert_eq!(
            EscalationTriggerKind::RegressionObserved.to_string(),
            "regression_observed"
        );
        assert_eq!(
            EscalationTriggerKind::RegressionObserved.as_str(),
            "regression_observed"
        );
        assert_eq!(
            EscalationTriggerKind::UserVisibleFailure.to_string(),
            "user_visible_failure"
        );
        assert_eq!(
            EscalationTriggerKind::UserVisibleFailure.as_str(),
            "user_visible_failure"
        );
        assert_eq!(
            EscalationTriggerKind::PolicyViolation.to_string(),
            "policy_violation"
        );
        assert_eq!(
            EscalationTriggerKind::PolicyViolation.as_str(),
            "policy_violation"
        );
        assert_eq!(
            EscalationTriggerKind::ReplayDivergence.to_string(),
            "replay_divergence"
        );
        assert_eq!(
            EscalationTriggerKind::ReplayDivergence.as_str(),
            "replay_divergence"
        );
        assert_eq!(
            EscalationTriggerKind::ResourceExhaustion.to_string(),
            "resource_exhaustion"
        );
        assert_eq!(
            EscalationTriggerKind::ResourceExhaustion.as_str(),
            "resource_exhaustion"
        );
        assert_eq!(
            EscalationTriggerKind::OperatorRequest.to_string(),
            "operator_request"
        );
        assert_eq!(
            EscalationTriggerKind::OperatorRequest.as_str(),
            "operator_request"
        );
    }

    #[test]
    fn trigger_kind_as_str_matches_display() {
        for kind in EscalationTriggerKind::ALL {
            assert_eq!(kind.as_str(), kind.to_string());
        }
    }

    #[test]
    fn trigger_kind_serde_roundtrip() {
        for kind in EscalationTriggerKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: EscalationTriggerKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn trigger_kind_ordering() {
        assert!(EscalationTriggerKind::AnomalyDetected < EscalationTriggerKind::OperatorRequest);
    }

    // --- TriggerSeverity tests ---

    #[test]
    fn severity_all_count() {
        assert_eq!(TriggerSeverity::ALL.len(), 4);
    }

    #[test]
    fn severity_display() {
        assert_eq!(TriggerSeverity::Advisory.to_string(), "advisory");
        assert_eq!(TriggerSeverity::Advisory.as_str(), "advisory");
        assert_eq!(TriggerSeverity::Warning.to_string(), "warning");
        assert_eq!(TriggerSeverity::Warning.as_str(), "warning");
        assert_eq!(TriggerSeverity::Critical.to_string(), "critical");
        assert_eq!(TriggerSeverity::Critical.as_str(), "critical");
        assert_eq!(TriggerSeverity::Emergency.to_string(), "emergency");
        assert_eq!(TriggerSeverity::Emergency.as_str(), "emergency");
    }

    #[test]
    fn severity_as_str_matches_display() {
        for severity in TriggerSeverity::ALL {
            assert_eq!(severity.as_str(), severity.to_string());
        }
    }

    #[test]
    fn severity_auto_escalate() {
        assert!(!TriggerSeverity::Advisory.auto_escalate());
        assert!(!TriggerSeverity::Warning.auto_escalate());
        assert!(TriggerSeverity::Critical.auto_escalate());
        assert!(TriggerSeverity::Emergency.auto_escalate());
    }

    #[test]
    fn severity_cost_multiplier_ordering() {
        assert!(
            TriggerSeverity::Advisory.cost_multiplier_millionths()
                < TriggerSeverity::Warning.cost_multiplier_millionths()
        );
        assert!(
            TriggerSeverity::Warning.cost_multiplier_millionths()
                < TriggerSeverity::Critical.cost_multiplier_millionths()
        );
        assert!(
            TriggerSeverity::Critical.cost_multiplier_millionths()
                < TriggerSeverity::Emergency.cost_multiplier_millionths()
        );
    }

    #[test]
    fn severity_serde_roundtrip() {
        for sev in TriggerSeverity::ALL {
            let json = serde_json::to_string(sev).unwrap();
            let back: TriggerSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(*sev, back);
        }
    }

    // --- BundleContentKind tests ---

    #[test]
    fn content_kind_all_count() {
        assert_eq!(BundleContentKind::ALL.len(), 7);
    }

    #[test]
    fn content_kind_display() {
        assert_eq!(
            BundleContentKind::FullBoundaryCapture.to_string(),
            "full_boundary_capture"
        );
        assert_eq!(
            BundleContentKind::ExecutionTrace.to_string(),
            "execution_trace"
        );
        assert_eq!(BundleContentKind::ReplayInputs.to_string(), "replay_inputs");
    }

    #[test]
    fn content_kind_base_cost_nonzero() {
        for kind in BundleContentKind::ALL {
            assert!(kind.base_cost_millionths() > 0);
        }
    }

    #[test]
    fn content_kind_serde_roundtrip() {
        for kind in BundleContentKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: BundleContentKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    // --- EscalationTrigger tests ---

    #[test]
    fn trigger_hash_deterministic() {
        let mut t1 = test_trigger(
            "t-1",
            EscalationTriggerKind::AnomalyDetected,
            TriggerSeverity::Warning,
        );
        t1.recompute_hash();
        let h1 = t1.trigger_hash;
        t1.recompute_hash();
        assert_eq!(h1, t1.trigger_hash);
    }

    #[test]
    fn trigger_different_kinds_different_hashes() {
        let mk = |kind| {
            let mut t = test_trigger("t-1", kind, TriggerSeverity::Warning);
            t.recompute_hash();
            t.trigger_hash
        };
        let h1 = mk(EscalationTriggerKind::AnomalyDetected);
        let h2 = mk(EscalationTriggerKind::PolicyViolation);
        assert_ne!(h1, h2);
    }

    #[test]
    fn trigger_serde_roundtrip() {
        let mut t = test_trigger(
            "t-1",
            EscalationTriggerKind::ReplayDivergence,
            TriggerSeverity::Critical,
        );
        t.recompute_hash();
        let json = serde_json::to_string(&t).unwrap();
        let back: EscalationTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    // --- EscalationBundle tests ---

    #[test]
    fn bundle_hash_deterministic() {
        let mut b = EscalationBundle {
            bundle_id: "b-1".to_string(),
            trigger_id: "t-1".to_string(),
            entries: vec![BundleContentEntry {
                kind: BundleContentKind::FullBoundaryCapture,
                content_digest: ContentHash::compute(b"content"),
                redaction: RedactionTreatment::DigestOnly,
                size_bytes: 1024,
                complete: true,
            }],
            covered_boundaries: BTreeSet::from([BoundaryClass::ClockRead]),
            total_cost_millionths: 50_000,
            bundle_epoch: test_epoch(),
            bundle_hash: ContentHash::compute(b"placeholder"),
        };
        b.recompute_hash();
        let h1 = b.bundle_hash;
        b.recompute_hash();
        assert_eq!(h1, b.bundle_hash);
    }

    #[test]
    fn bundle_hash_changes_when_redaction_changes() {
        let mut plain = EscalationBundle {
            bundle_id: "b-1".to_string(),
            trigger_id: "t-1".to_string(),
            entries: vec![BundleContentEntry {
                kind: BundleContentKind::FullBoundaryCapture,
                content_digest: ContentHash::compute(b"content"),
                redaction: RedactionTreatment::Plaintext,
                size_bytes: 1024,
                complete: true,
            }],
            covered_boundaries: BTreeSet::from([BoundaryClass::ClockRead]),
            total_cost_millionths: 50_000,
            bundle_epoch: test_epoch(),
            bundle_hash: ContentHash::compute(b"placeholder"),
        };
        plain.recompute_hash();

        let mut digest_only = plain.clone();
        digest_only.entries[0].redaction = RedactionTreatment::DigestOnly;
        digest_only.recompute_hash();

        assert_ne!(plain.bundle_hash, digest_only.bundle_hash);
    }

    #[test]
    fn bundle_hash_changes_when_completeness_changes() {
        let mut complete = EscalationBundle {
            bundle_id: "b-1".to_string(),
            trigger_id: "t-1".to_string(),
            entries: vec![BundleContentEntry {
                kind: BundleContentKind::FullBoundaryCapture,
                content_digest: ContentHash::compute(b"content"),
                redaction: RedactionTreatment::DigestOnly,
                size_bytes: 1024,
                complete: true,
            }],
            covered_boundaries: BTreeSet::from([BoundaryClass::ClockRead]),
            total_cost_millionths: 50_000,
            bundle_epoch: test_epoch(),
            bundle_hash: ContentHash::compute(b"placeholder"),
        };
        complete.recompute_hash();

        let mut truncated = complete.clone();
        truncated.entries[0].complete = false;
        truncated.recompute_hash();

        assert_ne!(complete.bundle_hash, truncated.bundle_hash);
    }

    #[test]
    fn bundle_serde_roundtrip() {
        let mut b = EscalationBundle {
            bundle_id: "b-1".to_string(),
            trigger_id: "t-1".to_string(),
            entries: Vec::new(),
            covered_boundaries: BTreeSet::new(),
            total_cost_millionths: 0,
            bundle_epoch: test_epoch(),
            bundle_hash: ContentHash::compute(b"placeholder"),
        };
        b.recompute_hash();
        let json = serde_json::to_string(&b).unwrap();
        let back: EscalationBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
    }

    // --- EscalationDecision tests ---

    #[test]
    fn decision_all_count() {
        assert_eq!(EscalationDecision::ALL.len(), 3);
    }

    #[test]
    fn decision_display() {
        assert_eq!(EscalationDecision::Escalate.to_string(), "escalate");
        assert_eq!(EscalationDecision::Suppress.to_string(), "suppress");
        assert_eq!(EscalationDecision::Defer.to_string(), "defer");
    }

    #[test]
    fn decision_serde_roundtrip() {
        for d in EscalationDecision::ALL {
            let json = serde_json::to_string(d).unwrap();
            let back: EscalationDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(*d, back);
        }
    }

    // --- EscalationReceipt tests ---

    #[test]
    fn receipt_hash_deterministic() {
        let mut r = EscalationReceipt {
            receipt_id: "r-1".to_string(),
            trigger_id: "t-1".to_string(),
            decision: EscalationDecision::Escalate,
            bundle_id: Some("b-1".to_string()),
            rationale: "auto-escalated".to_string(),
            cost_budget_millionths: 100_000,
            cost_consumed_millionths: 50_000,
            receipt_epoch: test_epoch(),
            receipt_hash: ContentHash::compute(b"placeholder"),
        };
        r.recompute_hash();
        let h1 = r.receipt_hash;
        r.recompute_hash();
        assert_eq!(h1, r.receipt_hash);
    }

    #[test]
    fn receipt_with_without_bundle_different_hash() {
        let mk = |bundle_id: Option<String>| {
            let mut r = EscalationReceipt {
                receipt_id: "r-1".to_string(),
                trigger_id: "t-1".to_string(),
                decision: EscalationDecision::Escalate,
                bundle_id,
                rationale: "test".to_string(),
                cost_budget_millionths: 100_000,
                cost_consumed_millionths: 50_000,
                receipt_epoch: test_epoch(),
                receipt_hash: ContentHash::compute(b"placeholder"),
            };
            r.recompute_hash();
            r.receipt_hash
        };
        let h1 = mk(None);
        let h2 = mk(Some("b-1".to_string()));
        assert_ne!(h1, h2);
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let mut r = EscalationReceipt {
            receipt_id: "r-1".to_string(),
            trigger_id: "t-1".to_string(),
            decision: EscalationDecision::Suppress,
            bundle_id: None,
            rationale: "suppressed".to_string(),
            cost_budget_millionths: 100_000,
            cost_consumed_millionths: 0,
            receipt_epoch: test_epoch(),
            receipt_hash: ContentHash::compute(b"placeholder"),
        };
        r.recompute_hash();
        let json = serde_json::to_string(&r).unwrap();
        let back: EscalationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- EscalationPolicy tests ---

    #[test]
    fn policy_default_has_always_escalate() {
        let policy = EscalationPolicy::default();
        assert!(
            policy
                .always_escalate
                .contains(&EscalationTriggerKind::UserVisibleFailure)
        );
        assert!(
            policy
                .always_escalate
                .contains(&EscalationTriggerKind::PolicyViolation)
        );
    }

    #[test]
    fn policy_content_for_severity_emergency_has_all() {
        let policy = EscalationPolicy::default();
        assert_eq!(
            policy
                .content_for_severity(TriggerSeverity::Emergency)
                .len(),
            7
        );
    }

    #[test]
    fn policy_content_advisory_subset_of_critical() {
        let policy = EscalationPolicy::default();
        let advisory: BTreeSet<_> = policy
            .content_for_severity(TriggerSeverity::Advisory)
            .iter()
            .collect();
        let critical: BTreeSet<_> = policy
            .content_for_severity(TriggerSeverity::Critical)
            .iter()
            .collect();
        assert!(advisory.is_subset(&critical));
    }

    // --- EscalationPipeline tests ---

    #[test]
    fn pipeline_new_is_empty() {
        let pipeline = EscalationPipeline::new(EscalationPolicy::default(), test_epoch());
        assert!(pipeline.triggers.is_empty());
        assert!(pipeline.receipts.is_empty());
        assert!(pipeline.bundles.is_empty());
    }

    #[test]
    fn pipeline_process_user_visible_failure_escalates() {
        let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), test_epoch());
        let trigger = test_trigger(
            "t-uvf",
            EscalationTriggerKind::UserVisibleFailure,
            TriggerSeverity::Critical,
        );
        let receipt = pipeline.process_trigger(trigger);
        assert_eq!(receipt.decision, EscalationDecision::Escalate);
        assert!(receipt.bundle_id.is_some());
    }

    #[test]
    fn pipeline_process_policy_violation_escalates() {
        let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), test_epoch());
        let trigger = test_trigger(
            "t-pv",
            EscalationTriggerKind::PolicyViolation,
            TriggerSeverity::Warning,
        );
        let receipt = pipeline.process_trigger(trigger);
        assert_eq!(receipt.decision, EscalationDecision::Escalate);
    }

    #[test]
    fn pipeline_always_suppress() {
        let mut policy = EscalationPolicy::default();
        policy
            .always_suppress
            .insert(EscalationTriggerKind::AnomalyDetected);
        let mut pipeline = EscalationPipeline::new(policy, test_epoch());
        let trigger = test_trigger(
            "t-supp",
            EscalationTriggerKind::AnomalyDetected,
            TriggerSeverity::Emergency,
        );
        let receipt = pipeline.process_trigger(trigger);
        assert_eq!(receipt.decision, EscalationDecision::Suppress);
    }

    #[test]
    fn pipeline_critical_auto_escalates() {
        let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), test_epoch());
        let trigger = test_trigger(
            "t-crit",
            EscalationTriggerKind::ResourceExhaustion,
            TriggerSeverity::Critical,
        );
        let receipt = pipeline.process_trigger(trigger);
        assert_eq!(receipt.decision, EscalationDecision::Escalate);
    }

    #[test]
    fn pipeline_advisory_within_budget_escalates() {
        let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), test_epoch());
        let trigger = test_trigger(
            "t-adv",
            EscalationTriggerKind::AnomalyDetected,
            TriggerSeverity::Advisory,
        );
        let receipt = pipeline.process_trigger(trigger);
        // Advisory should escalate if within budget
        assert_eq!(receipt.decision, EscalationDecision::Escalate);
    }

    #[test]
    fn pipeline_budget_depletes() {
        let policy = EscalationPolicy {
            cost_budget_millionths: 10_000, // very small budget
            ..Default::default()
        };
        let mut pipeline = EscalationPipeline::new(policy, test_epoch());

        // First trigger should escalate and consume budget
        let t1 = test_trigger(
            "t-b1",
            EscalationTriggerKind::ResourceExhaustion,
            TriggerSeverity::Critical,
        );
        pipeline.process_trigger(t1);

        // Budget should be depleted
        let remaining = pipeline.remaining_budget_millionths;
        // Depending on costs, budget may or may not be zero
        assert!(remaining < pipeline.policy.cost_budget_millionths || remaining == 0);
    }

    #[test]
    fn pipeline_receipt_preserves_budget_before_for_forced_auto_escalation() {
        let mut policy = EscalationPolicy {
            cost_budget_millionths: 1,
            ..Default::default()
        };
        policy.always_escalate.clear();
        let mut pipeline = EscalationPipeline::new(policy, test_epoch());

        let receipt = pipeline.process_trigger(test_trigger(
            "t-budget-before",
            EscalationTriggerKind::ResourceExhaustion,
            TriggerSeverity::Critical,
        ));

        assert_eq!(receipt.decision, EscalationDecision::Escalate);
        assert_eq!(receipt.cost_budget_millionths, 1);
        assert!(receipt.cost_consumed_millionths > receipt.cost_budget_millionths);
        assert_eq!(pipeline.remaining_budget_millionths, 0);
    }

    #[test]
    fn pipeline_escalated_receipts() {
        let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), test_epoch());
        pipeline.process_trigger(test_trigger(
            "t-1",
            EscalationTriggerKind::UserVisibleFailure,
            TriggerSeverity::Critical,
        ));
        pipeline.process_trigger(test_trigger(
            "t-2",
            EscalationTriggerKind::AnomalyDetected,
            TriggerSeverity::Advisory,
        ));
        assert!(!pipeline.escalated_receipts().is_empty());
    }

    #[test]
    fn pipeline_bundle_for_trigger() {
        let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), test_epoch());
        pipeline.process_trigger(test_trigger(
            "t-bf",
            EscalationTriggerKind::UserVisibleFailure,
            TriggerSeverity::Critical,
        ));
        let bundle = pipeline.bundle_for_trigger("t-bf");
        assert!(bundle.is_some());
        assert_eq!(bundle.unwrap().trigger_id, "t-bf");
    }

    #[test]
    fn pipeline_bundle_has_entries() {
        let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), test_epoch());
        pipeline.process_trigger(test_trigger(
            "t-ent",
            EscalationTriggerKind::PolicyViolation,
            TriggerSeverity::Critical,
        ));
        let bundle = pipeline.bundle_for_trigger("t-ent").unwrap();
        assert!(!bundle.entries.is_empty());
        assert!(bundle.total_cost_millionths > 0);
    }

    #[test]
    fn pipeline_emergency_gets_all_content() {
        let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), test_epoch());
        pipeline.process_trigger(test_trigger(
            "t-emg",
            EscalationTriggerKind::UserVisibleFailure,
            TriggerSeverity::Emergency,
        ));
        let bundle = pipeline.bundle_for_trigger("t-emg").unwrap();
        assert_eq!(bundle.entries.len(), BundleContentKind::ALL.len());
    }

    #[test]
    fn pipeline_summary_report() {
        let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), test_epoch());
        for (i, kind) in EscalationTriggerKind::ALL.iter().enumerate() {
            pipeline.process_trigger(test_trigger(
                &format!("t-sum-{i}"),
                *kind,
                TriggerSeverity::Warning,
            ));
        }
        let summary = pipeline.summary_report();
        assert_eq!(summary.total_triggers, 7);
        assert_eq!(
            summary.escalated_count + summary.suppressed_count + summary.deferred_count,
            7
        );
    }

    #[test]
    fn pipeline_hash_changes() {
        let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), test_epoch());
        let h1 = pipeline.pipeline_hash;
        pipeline.process_trigger(test_trigger(
            "t-hc",
            EscalationTriggerKind::AnomalyDetected,
            TriggerSeverity::Warning,
        ));
        assert_ne!(h1, pipeline.pipeline_hash);
    }

    #[test]
    fn pipeline_serde_roundtrip() {
        let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), test_epoch());
        pipeline.process_trigger(test_trigger(
            "t-serde",
            EscalationTriggerKind::ReplayDivergence,
            TriggerSeverity::Critical,
        ));
        let json = serde_json::to_string(&pipeline).unwrap();
        let back: EscalationPipeline = serde_json::from_str(&json).unwrap();
        assert_eq!(pipeline, back);
    }

    // --- Error display tests ---

    #[test]
    fn error_display() {
        let e = EscalationError::TriggerNotFound {
            trigger_id: "t-1".to_string(),
        };
        assert!(e.to_string().contains("t-1"));

        let e = EscalationError::BundleNotFound {
            bundle_id: "b-1".to_string(),
        };
        assert!(e.to_string().contains("b-1"));

        let e = EscalationError::BudgetExhausted {
            remaining: 0,
            required: 50_000,
        };
        assert!(e.to_string().contains("50000"));

        let e = EscalationError::InvalidPolicy {
            detail: "bad".to_string(),
        };
        assert!(e.to_string().contains("bad"));
    }

    #[test]
    fn error_serde_roundtrip() {
        for err in [
            EscalationError::TriggerNotFound {
                trigger_id: "t".to_string(),
            },
            EscalationError::BundleNotFound {
                bundle_id: "b".to_string(),
            },
            EscalationError::BudgetExhausted {
                remaining: 0,
                required: 100,
            },
            EscalationError::InvalidPolicy {
                detail: "x".to_string(),
            },
        ] {
            let json = serde_json::to_string(&err).unwrap();
            let back: EscalationError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, back);
        }
    }

    // --- Determinism tests ---

    #[test]
    fn deterministic_pipeline_same_triggers() {
        let policy = EscalationPolicy::default();
        let mut p1 = EscalationPipeline::new(policy.clone(), test_epoch());
        let mut p2 = EscalationPipeline::new(policy, test_epoch());

        let triggers = vec![
            test_trigger(
                "t-a",
                EscalationTriggerKind::AnomalyDetected,
                TriggerSeverity::Warning,
            ),
            test_trigger(
                "t-b",
                EscalationTriggerKind::PolicyViolation,
                TriggerSeverity::Critical,
            ),
        ];

        for t in &triggers {
            p1.process_trigger(t.clone());
        }
        for t in &triggers {
            p2.process_trigger(t.clone());
        }

        assert_eq!(p1.pipeline_hash, p2.pipeline_hash);
    }

    // --- Content redaction tests ---

    #[test]
    fn emergency_redaction_is_plaintext() {
        let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), test_epoch());
        pipeline.process_trigger(test_trigger(
            "t-red",
            EscalationTriggerKind::UserVisibleFailure,
            TriggerSeverity::Emergency,
        ));
        let bundle = pipeline.bundle_for_trigger("t-red").unwrap();
        // In emergency, boundary capture and state snapshot should be plaintext
        for entry in &bundle.entries {
            if matches!(
                entry.kind,
                BundleContentKind::FullBoundaryCapture
                    | BundleContentKind::StateSnapshot
                    | BundleContentKind::HeapProfile
            ) {
                assert_eq!(entry.redaction, RedactionTreatment::Plaintext);
            }
        }
    }

    #[test]
    fn non_emergency_redaction_is_digest_for_sensitive() {
        let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), test_epoch());
        pipeline.process_trigger(test_trigger(
            "t-nered",
            EscalationTriggerKind::UserVisibleFailure,
            TriggerSeverity::Critical,
        ));
        let bundle = pipeline.bundle_for_trigger("t-nered").unwrap();
        for entry in &bundle.entries {
            if entry.kind == BundleContentKind::FullBoundaryCapture {
                assert_eq!(entry.redaction, RedactionTreatment::DigestOnly);
            }
        }
    }
}
