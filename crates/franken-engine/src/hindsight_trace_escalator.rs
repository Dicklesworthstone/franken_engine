#![forbid(unsafe_code)]

//! Hindsight trace escalation from minimal traces to full replay bundles.
//!
//! Bead: bd-1lsy.9.11.3 [RGC-811C]
//!
//! Defines the trigger taxonomy, escalation bundles, and support-facing outputs
//! so the engine keeps routine logging cheap while collecting deep evidence when
//! anomalies, regressions, or user-visible failures justify it.
//!
//! Key design:
//! - Trigger taxonomy: typed escalation triggers with severity and category
//! - Escalation levels: Minimal → Extended → Full → Forensic
//! - Bundle manifests: what evidence is collected at each level
//! - Deterministic escalation decisions with content-addressed receipts
//! - Support-facing outputs for triage and bug reports
//!
//! The runtime never silently switches observability regimes without recording why.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

pub const ESCALATION_SCHEMA_VERSION: &str = "franken-engine.hindsight-trace-escalator.v1";
pub const ESCALATION_BEAD_ID: &str = "bd-1lsy.9.11.3";

// ---------------------------------------------------------------------------
// Escalation level
// ---------------------------------------------------------------------------

/// Progressive escalation levels for trace collection depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationLevel {
    /// Minimal: lightweight counters and decision hashes only.
    Minimal,
    /// Extended: add decision logs, boundary snapshots, timing traces.
    Extended,
    /// Full: add complete replay inputs, IR snapshots, controller state.
    Full,
    /// Forensic: add raw memory/register dumps and step-by-step execution logs.
    Forensic,
}

impl EscalationLevel {
    /// Numeric depth for ordering (higher = more data).
    pub fn depth(self) -> u32 {
        match self {
            Self::Minimal => 0,
            Self::Extended => 1,
            Self::Full => 2,
            Self::Forensic => 3,
        }
    }
}

impl fmt::Display for EscalationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Minimal => "minimal",
            Self::Extended => "extended",
            Self::Full => "full",
            Self::Forensic => "forensic",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Trigger category
// ---------------------------------------------------------------------------

/// Category of escalation trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerCategory {
    /// Performance anomaly: tail latency spike, throughput drop, etc.
    PerformanceAnomaly,
    /// Security event: containment action, quarantine, revocation.
    SecurityEvent,
    /// Correctness failure: assertion, invariant violation, miscompile.
    CorrectnessFailure,
    /// User-visible error: crash, hang, wrong output.
    UserVisibleError,
    /// Regression: benchmark regression, parity drift.
    Regression,
    /// Operator request: explicit escalation via CLI or API.
    OperatorRequest,
    /// Resource exhaustion: OOM, budget exceeded, queue overflow.
    ResourceExhaustion,
    /// Determinism violation: replay mismatch, nondeterministic boundary.
    DeterminismViolation,
}

impl fmt::Display for TriggerCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::PerformanceAnomaly => "performance_anomaly",
            Self::SecurityEvent => "security_event",
            Self::CorrectnessFailure => "correctness_failure",
            Self::UserVisibleError => "user_visible_error",
            Self::Regression => "regression",
            Self::OperatorRequest => "operator_request",
            Self::ResourceExhaustion => "resource_exhaustion",
            Self::DeterminismViolation => "determinism_violation",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Trigger severity
// ---------------------------------------------------------------------------

/// How urgently evidence must be captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerSeverity {
    /// Informational: capture for trend analysis.
    Info,
    /// Warning: something is degraded but recoverable.
    Warning,
    /// Critical: immediate evidence capture required.
    Critical,
    /// Fatal: system cannot continue; capture everything possible.
    Fatal,
}

impl TriggerSeverity {
    /// Map severity to minimum escalation level.
    pub fn minimum_escalation(self) -> EscalationLevel {
        match self {
            Self::Info => EscalationLevel::Extended,
            Self::Warning => EscalationLevel::Extended,
            Self::Critical => EscalationLevel::Full,
            Self::Fatal => EscalationLevel::Forensic,
        }
    }
}

impl fmt::Display for TriggerSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Fatal => "fatal",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Escalation trigger
// ---------------------------------------------------------------------------

/// A typed escalation trigger with context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationTrigger {
    /// Unique trigger identifier.
    pub trigger_id: String,
    /// Category of this trigger.
    pub category: TriggerCategory,
    /// Severity assessment.
    pub severity: TriggerSeverity,
    /// Human-readable description.
    pub description: String,
    /// Source component that raised the trigger.
    pub source_component: String,
    /// Security epoch when triggered.
    pub epoch: SecurityEpoch,
    /// Optional correlation ID for grouping related triggers.
    pub correlation_id: Option<String>,
    /// Additional structured metadata.
    pub metadata: BTreeMap<String, String>,
}

impl EscalationTrigger {
    pub fn new(
        trigger_id: impl Into<String>,
        category: TriggerCategory,
        severity: TriggerSeverity,
        description: impl Into<String>,
        source_component: impl Into<String>,
        epoch: SecurityEpoch,
    ) -> Self {
        Self {
            trigger_id: trigger_id.into(),
            category,
            severity,
            description: description.into(),
            source_component: source_component.into(),
            epoch,
            correlation_id: None,
            metadata: BTreeMap::new(),
        }
    }

    /// Content hash for deduplication and replay verification.
    pub fn content_hash(&self) -> String {
        let input = format!(
            "{}:{}:{}:{}:{}:{}",
            self.trigger_id,
            self.category,
            self.severity,
            self.source_component,
            self.epoch.as_u64(),
            self.correlation_id.as_deref().unwrap_or("none"),
        );
        hex_encode(ContentHash::compute(input.as_bytes()).as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Bundle artifact spec
// ---------------------------------------------------------------------------

/// What to include in an escalation bundle at a given level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleArtifactSpec {
    /// Human-readable label for this artifact class.
    pub label: String,
    /// File extension or format identifier.
    pub format: String,
    /// Minimum escalation level for inclusion.
    pub min_level: EscalationLevel,
    /// Whether this artifact is required (vs optional).
    pub required: bool,
    /// Estimated size in bytes (0 if unknown).
    pub estimated_bytes: u64,
}

/// Standard artifact specs for escalation bundles.
pub fn standard_artifact_specs() -> Vec<BundleArtifactSpec> {
    vec![
        BundleArtifactSpec {
            label: "decision_hashes".into(),
            format: "jsonl".into(),
            min_level: EscalationLevel::Minimal,
            required: true,
            estimated_bytes: 4096,
        },
        BundleArtifactSpec {
            label: "counter_snapshot".into(),
            format: "json".into(),
            min_level: EscalationLevel::Minimal,
            required: true,
            estimated_bytes: 2048,
        },
        BundleArtifactSpec {
            label: "decision_log".into(),
            format: "jsonl".into(),
            min_level: EscalationLevel::Extended,
            required: true,
            estimated_bytes: 65536,
        },
        BundleArtifactSpec {
            label: "boundary_snapshots".into(),
            format: "jsonl".into(),
            min_level: EscalationLevel::Extended,
            required: true,
            estimated_bytes: 32768,
        },
        BundleArtifactSpec {
            label: "timing_trace".into(),
            format: "jsonl".into(),
            min_level: EscalationLevel::Extended,
            required: false,
            estimated_bytes: 131072,
        },
        BundleArtifactSpec {
            label: "replay_inputs".into(),
            format: "bin".into(),
            min_level: EscalationLevel::Full,
            required: true,
            estimated_bytes: 524288,
        },
        BundleArtifactSpec {
            label: "ir_snapshots".into(),
            format: "json".into(),
            min_level: EscalationLevel::Full,
            required: true,
            estimated_bytes: 262144,
        },
        BundleArtifactSpec {
            label: "controller_state".into(),
            format: "json".into(),
            min_level: EscalationLevel::Full,
            required: false,
            estimated_bytes: 16384,
        },
        BundleArtifactSpec {
            label: "execution_step_log".into(),
            format: "jsonl".into(),
            min_level: EscalationLevel::Forensic,
            required: true,
            estimated_bytes: 4_194_304,
        },
        BundleArtifactSpec {
            label: "memory_dump".into(),
            format: "bin".into(),
            min_level: EscalationLevel::Forensic,
            required: false,
            estimated_bytes: 16_777_216,
        },
    ]
}

// ---------------------------------------------------------------------------
// Escalation policy
// ---------------------------------------------------------------------------

/// Policy governing when and how escalation happens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Default escalation level (usually Minimal).
    pub default_level: EscalationLevel,
    /// Per-category overrides.
    pub category_overrides: BTreeMap<String, EscalationLevel>,
    /// Per-severity minimum levels.
    pub severity_minimums: BTreeMap<String, EscalationLevel>,
    /// Maximum number of active escalations (prevents resource exhaustion).
    pub max_active_escalations: u64,
    /// Cooldown in epochs between escalations for the same correlation ID.
    pub cooldown_epochs: u64,
    /// Whether forensic level is allowed (may be disabled for privacy).
    pub allow_forensic: bool,
    /// Artifact specs to use.
    pub artifact_specs: Vec<BundleArtifactSpec>,
}

impl Default for EscalationPolicy {
    fn default() -> Self {
        Self {
            schema_version: ESCALATION_SCHEMA_VERSION.into(),
            policy_id: "default".into(),
            default_level: EscalationLevel::Minimal,
            category_overrides: BTreeMap::new(),
            severity_minimums: BTreeMap::new(),
            max_active_escalations: 10,
            cooldown_epochs: 5,
            allow_forensic: false,
            artifact_specs: standard_artifact_specs(),
        }
    }
}

impl EscalationPolicy {
    /// Determine the escalation level for a given trigger.
    pub fn resolve_level(&self, trigger: &EscalationTrigger) -> EscalationLevel {
        let severity_min = trigger.severity.minimum_escalation();
        let category_override = self
            .category_overrides
            .get(&trigger.category.to_string())
            .copied()
            .unwrap_or(self.default_level);

        // Take the maximum of severity minimum and category override.
        let resolved = if severity_min.depth() > category_override.depth() {
            severity_min
        } else {
            category_override
        };

        // Clamp to Full if forensic is disallowed.
        if resolved == EscalationLevel::Forensic && !self.allow_forensic {
            EscalationLevel::Full
        } else {
            resolved
        }
    }

    /// Get artifact specs for a given escalation level.
    pub fn artifacts_for_level(&self, level: EscalationLevel) -> Vec<&BundleArtifactSpec> {
        self.artifact_specs
            .iter()
            .filter(|spec| spec.min_level.depth() <= level.depth())
            .collect()
    }

    /// Estimate total bundle size in bytes for a level.
    pub fn estimate_bundle_size(&self, level: EscalationLevel) -> u64 {
        self.artifacts_for_level(level)
            .iter()
            .map(|spec| spec.estimated_bytes)
            .sum()
    }

    /// Content hash for change detection.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.schema_version.as_bytes());
        hasher.update(self.policy_id.as_bytes());
        hasher.update(&(self.default_level.depth()).to_le_bytes());
        hasher.update(&self.max_active_escalations.to_le_bytes());
        hasher.update(&self.cooldown_epochs.to_le_bytes());
        hasher.update(&[u8::from(self.allow_forensic)]);
        for (k, v) in &self.category_overrides {
            hasher.update(k.as_bytes());
            hasher.update(&v.depth().to_le_bytes());
        }
        hex_encode(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// Escalation decision
// ---------------------------------------------------------------------------

/// Why an escalation was allowed or suppressed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationVerdict {
    /// Escalation approved at the determined level.
    Approved { level: EscalationLevel },
    /// Suppressed: too many active escalations.
    SuppressedCapacity {
        active_count: u64,
        max_allowed: u64,
    },
    /// Suppressed: cooldown not expired for this correlation ID.
    SuppressedCooldown {
        correlation_id: String,
        epochs_remaining: u64,
    },
    /// Suppressed: no escalation above minimal (trigger not significant enough).
    SuppressedBelowThreshold,
}

impl fmt::Display for EscalationVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approved { level } => write!(f, "approved({level})"),
            Self::SuppressedCapacity {
                active_count,
                max_allowed,
            } => write!(f, "suppressed_capacity({active_count}/{max_allowed})"),
            Self::SuppressedCooldown {
                correlation_id, ..
            } => write!(f, "suppressed_cooldown({correlation_id})"),
            Self::SuppressedBelowThreshold => write!(f, "suppressed_below_threshold"),
        }
    }
}

/// Full escalation decision record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationDecision {
    pub schema_version: String,
    pub trigger: EscalationTrigger,
    pub resolved_level: EscalationLevel,
    pub verdict: EscalationVerdict,
    pub artifacts_included: Vec<String>,
    pub estimated_bundle_bytes: u64,
    pub decision_hash: String,
}

// ---------------------------------------------------------------------------
// Escalation state
// ---------------------------------------------------------------------------

/// Tracked state for the escalator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalatorState {
    /// Number of currently active escalations.
    pub active_escalations: u64,
    /// Cooldown tracker: correlation_id -> epoch when cooldown expires.
    pub cooldowns: BTreeMap<String, u64>,
    /// Total escalations ever approved.
    pub total_approved: u64,
    /// Total escalations suppressed.
    pub total_suppressed: u64,
    /// Per-category counts.
    pub category_counts: BTreeMap<String, u64>,
    /// Per-level counts.
    pub level_counts: BTreeMap<String, u64>,
    /// Current security epoch.
    pub current_epoch: SecurityEpoch,
}

impl EscalatorState {
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            active_escalations: 0,
            cooldowns: BTreeMap::new(),
            total_approved: 0,
            total_suppressed: 0,
            category_counts: BTreeMap::new(),
            level_counts: BTreeMap::new(),
            current_epoch: epoch,
        }
    }
}

// ---------------------------------------------------------------------------
// Escalator
// ---------------------------------------------------------------------------

/// The hindsight trace escalator evaluates triggers and decides escalation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HindsightTraceEscalator {
    pub policy: EscalationPolicy,
    pub state: EscalatorState,
    /// Decision log for audit.
    pub decision_log: Vec<EscalationDecision>,
    /// Maximum log entries.
    pub max_log_entries: usize,
}

impl HindsightTraceEscalator {
    pub fn new(policy: EscalationPolicy, epoch: SecurityEpoch) -> Self {
        Self {
            policy,
            state: EscalatorState::new(epoch),
            decision_log: Vec::new(),
            max_log_entries: 500,
        }
    }

    /// Advance the epoch and expire cooldowns.
    pub fn advance_epoch(&mut self, new_epoch: SecurityEpoch) {
        self.state.current_epoch = new_epoch;
        let current = new_epoch.as_u64();
        self.state.cooldowns.retain(|_, expires| *expires > current);
    }

    /// Evaluate a trigger and decide whether to escalate.
    pub fn evaluate(&mut self, trigger: EscalationTrigger) -> EscalationDecision {
        let resolved_level = self.policy.resolve_level(&trigger);

        // Check if escalation is above minimal.
        if resolved_level == EscalationLevel::Minimal {
            self.state.total_suppressed += 1;
            return self.make_decision(
                trigger,
                resolved_level,
                EscalationVerdict::SuppressedBelowThreshold,
            );
        }

        // Check capacity.
        if self.state.active_escalations >= self.policy.max_active_escalations {
            self.state.total_suppressed += 1;
            return self.make_decision(
                trigger,
                resolved_level,
                EscalationVerdict::SuppressedCapacity {
                    active_count: self.state.active_escalations,
                    max_allowed: self.policy.max_active_escalations,
                },
            );
        }

        // Check cooldown.
        if let Some(correlation_id) = &trigger.correlation_id.clone() {
            if let Some(&expires) = self.state.cooldowns.get(correlation_id) {
                let current = self.state.current_epoch.as_u64();
                if current < expires {
                    self.state.total_suppressed += 1;
                    return self.make_decision(
                        trigger,
                        resolved_level,
                        EscalationVerdict::SuppressedCooldown {
                            correlation_id: correlation_id.clone(),
                            epochs_remaining: expires - current,
                        },
                    );
                }
            }
        }

        // Approve escalation.
        self.state.active_escalations += 1;
        self.state.total_approved += 1;
        *self
            .state
            .category_counts
            .entry(trigger.category.to_string())
            .or_insert(0) += 1;
        *self
            .state
            .level_counts
            .entry(resolved_level.to_string())
            .or_insert(0) += 1;

        // Set cooldown for correlation ID.
        if let Some(correlation_id) = &trigger.correlation_id {
            let expires = self.state.current_epoch.as_u64() + self.policy.cooldown_epochs;
            self.state
                .cooldowns
                .insert(correlation_id.clone(), expires);
        }

        self.make_decision(
            trigger,
            resolved_level,
            EscalationVerdict::Approved {
                level: resolved_level,
            },
        )
    }

    /// Mark an escalation as completed (frees capacity).
    pub fn complete_escalation(&mut self) {
        if self.state.active_escalations > 0 {
            self.state.active_escalations -= 1;
        }
    }

    /// Get the current state summary.
    pub fn summary(&self) -> EscalatorSummary {
        EscalatorSummary {
            schema_version: ESCALATION_SCHEMA_VERSION.into(),
            active_escalations: self.state.active_escalations,
            total_approved: self.state.total_approved,
            total_suppressed: self.state.total_suppressed,
            category_counts: self.state.category_counts.clone(),
            level_counts: self.state.level_counts.clone(),
            cooldown_count: self.state.cooldowns.len() as u64,
            policy_hash: self.policy.content_hash(),
            epoch: self.state.current_epoch,
        }
    }

    fn make_decision(
        &mut self,
        trigger: EscalationTrigger,
        resolved_level: EscalationLevel,
        verdict: EscalationVerdict,
    ) -> EscalationDecision {
        let artifacts_included: Vec<String> =
            if matches!(verdict, EscalationVerdict::Approved { .. }) {
                self.policy
                    .artifacts_for_level(resolved_level)
                    .iter()
                    .map(|s| s.label.clone())
                    .collect()
            } else {
                Vec::new()
            };
        let estimated_bundle_bytes =
            if matches!(verdict, EscalationVerdict::Approved { .. }) {
                self.policy.estimate_bundle_size(resolved_level)
            } else {
                0
            };

        let hash_input = format!(
            "{}:{}:{}:{}:{}",
            trigger.content_hash(),
            resolved_level,
            verdict,
            artifacts_included.len(),
            estimated_bundle_bytes,
        );
        let decision_hash = hex_encode(ContentHash::compute(hash_input.as_bytes()).as_bytes());

        let decision = EscalationDecision {
            schema_version: ESCALATION_SCHEMA_VERSION.into(),
            trigger,
            resolved_level,
            verdict,
            artifacts_included,
            estimated_bundle_bytes,
            decision_hash,
        };

        // Bounded log.
        if self.decision_log.len() >= self.max_log_entries {
            self.decision_log.remove(0);
        }
        self.decision_log.push(decision.clone());

        decision
    }
}

/// Summary for operator dashboards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalatorSummary {
    pub schema_version: String,
    pub active_escalations: u64,
    pub total_approved: u64,
    pub total_suppressed: u64,
    pub category_counts: BTreeMap<String, u64>,
    pub level_counts: BTreeMap<String, u64>,
    pub cooldown_count: u64,
    pub policy_hash: String,
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// Support bundle manifest
// ---------------------------------------------------------------------------

/// Manifest for a completed support bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportBundleManifest {
    pub schema_version: String,
    pub bead_id: String,
    pub bundle_id: String,
    pub trigger_id: String,
    pub escalation_level: EscalationLevel,
    pub artifacts: Vec<SupportBundleArtifact>,
    pub total_bytes: u64,
    pub epoch: SecurityEpoch,
    pub manifest_hash: String,
}

/// One artifact within a support bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportBundleArtifact {
    pub label: String,
    pub format: String,
    pub path: String,
    pub bytes: u64,
    pub content_hash: String,
}

impl SupportBundleManifest {
    /// Create a manifest from escalation decision and collected artifacts.
    pub fn from_decision(
        decision: &EscalationDecision,
        bundle_id: impl Into<String>,
        artifacts: Vec<SupportBundleArtifact>,
    ) -> Self {
        let total_bytes: u64 = artifacts.iter().map(|a| a.bytes).sum();
        let bundle_id = bundle_id.into();
        let hash_input = format!(
            "{}:{}:{}:{}:{}",
            ESCALATION_SCHEMA_VERSION,
            bundle_id,
            decision.trigger.trigger_id,
            decision.resolved_level,
            total_bytes,
        );
        let manifest_hash = hex_encode(ContentHash::compute(hash_input.as_bytes()).as_bytes());
        Self {
            schema_version: ESCALATION_SCHEMA_VERSION.into(),
            bead_id: ESCALATION_BEAD_ID.into(),
            bundle_id,
            trigger_id: decision.trigger.trigger_id.clone(),
            escalation_level: decision.resolved_level,
            artifacts,
            total_bytes,
            epoch: decision.trigger.epoch,
            manifest_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
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
        category: TriggerCategory,
        severity: TriggerSeverity,
    ) -> EscalationTrigger {
        EscalationTrigger::new(
            "trigger-001",
            category,
            severity,
            "test trigger",
            "test_component",
            test_epoch(),
        )
    }

    #[test]
    fn escalation_level_ordering() {
        assert!(EscalationLevel::Minimal < EscalationLevel::Extended);
        assert!(EscalationLevel::Extended < EscalationLevel::Full);
        assert!(EscalationLevel::Full < EscalationLevel::Forensic);
    }

    #[test]
    fn escalation_level_depth() {
        assert_eq!(EscalationLevel::Minimal.depth(), 0);
        assert_eq!(EscalationLevel::Extended.depth(), 1);
        assert_eq!(EscalationLevel::Full.depth(), 2);
        assert_eq!(EscalationLevel::Forensic.depth(), 3);
    }

    #[test]
    fn escalation_level_display() {
        assert_eq!(EscalationLevel::Minimal.to_string(), "minimal");
        assert_eq!(EscalationLevel::Extended.to_string(), "extended");
        assert_eq!(EscalationLevel::Full.to_string(), "full");
        assert_eq!(EscalationLevel::Forensic.to_string(), "forensic");
    }

    #[test]
    fn trigger_category_display() {
        assert_eq!(
            TriggerCategory::SecurityEvent.to_string(),
            "security_event"
        );
        assert_eq!(
            TriggerCategory::CorrectnessFailure.to_string(),
            "correctness_failure"
        );
        assert_eq!(
            TriggerCategory::DeterminismViolation.to_string(),
            "determinism_violation"
        );
    }

    #[test]
    fn trigger_severity_minimum_escalation() {
        assert_eq!(
            TriggerSeverity::Info.minimum_escalation(),
            EscalationLevel::Extended
        );
        assert_eq!(
            TriggerSeverity::Warning.minimum_escalation(),
            EscalationLevel::Extended
        );
        assert_eq!(
            TriggerSeverity::Critical.minimum_escalation(),
            EscalationLevel::Full
        );
        assert_eq!(
            TriggerSeverity::Fatal.minimum_escalation(),
            EscalationLevel::Forensic
        );
    }

    #[test]
    fn trigger_content_hash_deterministic() {
        let t1 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
        let t2 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
        assert_eq!(t1.content_hash(), t2.content_hash());
    }

    #[test]
    fn trigger_content_hash_changes_with_category() {
        let t1 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
        let t2 = test_trigger(TriggerCategory::SecurityEvent, TriggerSeverity::Warning);
        assert_ne!(t1.content_hash(), t2.content_hash());
    }

    #[test]
    fn standard_artifact_specs_has_all_levels() {
        let specs = standard_artifact_specs();
        let levels: BTreeSet<_> = specs.iter().map(|s| s.min_level).collect();
        assert!(levels.contains(&EscalationLevel::Minimal));
        assert!(levels.contains(&EscalationLevel::Extended));
        assert!(levels.contains(&EscalationLevel::Full));
        assert!(levels.contains(&EscalationLevel::Forensic));
    }

    #[test]
    fn policy_resolve_level_defaults_to_severity() {
        let policy = EscalationPolicy::default();
        let trigger = test_trigger(TriggerCategory::Regression, TriggerSeverity::Critical);
        assert_eq!(policy.resolve_level(&trigger), EscalationLevel::Full);
    }

    #[test]
    fn policy_resolve_level_category_override() {
        let mut policy = EscalationPolicy::default();
        policy.category_overrides.insert(
            TriggerCategory::Regression.to_string(),
            EscalationLevel::Forensic,
        );
        policy.allow_forensic = true;
        let trigger = test_trigger(TriggerCategory::Regression, TriggerSeverity::Info);
        assert_eq!(policy.resolve_level(&trigger), EscalationLevel::Forensic);
    }

    #[test]
    fn policy_resolve_level_clamps_forensic_when_disallowed() {
        let mut policy = EscalationPolicy::default();
        policy.allow_forensic = false;
        let trigger = test_trigger(TriggerCategory::SecurityEvent, TriggerSeverity::Fatal);
        assert_eq!(policy.resolve_level(&trigger), EscalationLevel::Full);
    }

    #[test]
    fn policy_artifacts_for_level() {
        let policy = EscalationPolicy::default();
        let minimal = policy.artifacts_for_level(EscalationLevel::Minimal);
        let full = policy.artifacts_for_level(EscalationLevel::Full);
        assert!(minimal.len() < full.len());
    }

    #[test]
    fn policy_estimate_bundle_size() {
        let policy = EscalationPolicy::default();
        let minimal_size = policy.estimate_bundle_size(EscalationLevel::Minimal);
        let full_size = policy.estimate_bundle_size(EscalationLevel::Full);
        assert!(minimal_size < full_size);
        assert!(minimal_size > 0);
    }

    #[test]
    fn policy_content_hash_deterministic() {
        let p1 = EscalationPolicy::default();
        let p2 = EscalationPolicy::default();
        assert_eq!(p1.content_hash(), p2.content_hash());
    }

    #[test]
    fn escalator_approve_basic() {
        let policy = EscalationPolicy::default();
        let mut escalator = HindsightTraceEscalator::new(policy, test_epoch());
        let trigger =
            test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
        let decision = escalator.evaluate(trigger);
        assert!(matches!(
            decision.verdict,
            EscalationVerdict::Approved { .. }
        ));
        assert_eq!(escalator.state.total_approved, 1);
        assert_eq!(escalator.state.active_escalations, 1);
    }

    #[test]
    fn escalator_suppress_capacity() {
        let mut policy = EscalationPolicy::default();
        policy.max_active_escalations = 1;
        let mut escalator = HindsightTraceEscalator::new(policy, test_epoch());
        // First trigger approved.
        let t1 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
        let d1 = escalator.evaluate(t1);
        assert!(matches!(d1.verdict, EscalationVerdict::Approved { .. }));
        // Second trigger suppressed.
        let t2 = EscalationTrigger::new(
            "trigger-002",
            TriggerCategory::SecurityEvent,
            TriggerSeverity::Warning,
            "another trigger",
            "other_component",
            test_epoch(),
        );
        let d2 = escalator.evaluate(t2);
        assert!(matches!(
            d2.verdict,
            EscalationVerdict::SuppressedCapacity { .. }
        ));
    }

    #[test]
    fn escalator_suppress_cooldown() {
        let mut policy = EscalationPolicy::default();
        policy.cooldown_epochs = 5;
        let mut escalator = HindsightTraceEscalator::new(policy, test_epoch());
        let mut t1 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
        t1.correlation_id = Some("corr-1".into());
        let d1 = escalator.evaluate(t1);
        assert!(matches!(d1.verdict, EscalationVerdict::Approved { .. }));
        // Complete the first escalation to free capacity.
        escalator.complete_escalation();
        // Second trigger with same correlation ID should be cooled down.
        let mut t2 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
        t2.trigger_id = "trigger-002".into();
        t2.correlation_id = Some("corr-1".into());
        let d2 = escalator.evaluate(t2);
        assert!(matches!(
            d2.verdict,
            EscalationVerdict::SuppressedCooldown { .. }
        ));
    }

    #[test]
    fn escalator_cooldown_expires() {
        let mut policy = EscalationPolicy::default();
        policy.cooldown_epochs = 3;
        let mut escalator = HindsightTraceEscalator::new(policy, test_epoch());
        let mut t1 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
        t1.correlation_id = Some("corr-1".into());
        escalator.evaluate(t1);
        escalator.complete_escalation();
        // Advance epoch past cooldown.
        escalator.advance_epoch(SecurityEpoch::from_raw(200));
        let mut t2 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
        t2.trigger_id = "trigger-003".into();
        t2.correlation_id = Some("corr-1".into());
        t2.epoch = SecurityEpoch::from_raw(200);
        let d2 = escalator.evaluate(t2);
        assert!(matches!(d2.verdict, EscalationVerdict::Approved { .. }));
    }

    #[test]
    fn escalator_complete_frees_capacity() {
        let mut policy = EscalationPolicy::default();
        policy.max_active_escalations = 1;
        let mut escalator = HindsightTraceEscalator::new(policy, test_epoch());
        let t1 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
        escalator.evaluate(t1);
        assert_eq!(escalator.state.active_escalations, 1);
        escalator.complete_escalation();
        assert_eq!(escalator.state.active_escalations, 0);
        // Now a new trigger should be approved.
        let t2 = EscalationTrigger::new(
            "trigger-002",
            TriggerCategory::SecurityEvent,
            TriggerSeverity::Critical,
            "security trigger",
            "security",
            test_epoch(),
        );
        let d2 = escalator.evaluate(t2);
        assert!(matches!(d2.verdict, EscalationVerdict::Approved { .. }));
    }

    #[test]
    fn escalator_summary() {
        let policy = EscalationPolicy::default();
        let mut escalator = HindsightTraceEscalator::new(policy, test_epoch());
        let t = test_trigger(TriggerCategory::Regression, TriggerSeverity::Critical);
        escalator.evaluate(t);
        let summary = escalator.summary();
        assert_eq!(summary.total_approved, 1);
        assert_eq!(summary.active_escalations, 1);
        assert!(!summary.policy_hash.is_empty());
    }

    #[test]
    fn escalator_decision_log_bounded() {
        let policy = EscalationPolicy::default();
        let mut escalator = HindsightTraceEscalator::new(policy, test_epoch());
        escalator.max_log_entries = 3;
        for i in 0..10 {
            let t = EscalationTrigger::new(
                format!("trigger-{i:03}"),
                TriggerCategory::PerformanceAnomaly,
                TriggerSeverity::Warning,
                "perf anomaly",
                "profiler",
                test_epoch(),
            );
            escalator.evaluate(t);
            escalator.complete_escalation();
        }
        assert!(escalator.decision_log.len() <= 3);
    }

    #[test]
    fn decision_hash_deterministic() {
        let policy = EscalationPolicy::default();
        let mut e1 = HindsightTraceEscalator::new(policy.clone(), test_epoch());
        let mut e2 = HindsightTraceEscalator::new(policy, test_epoch());
        let t1 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
        let t2 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
        let d1 = e1.evaluate(t1);
        let d2 = e2.evaluate(t2);
        assert_eq!(d1.decision_hash, d2.decision_hash);
    }

    #[test]
    fn approved_decision_includes_artifacts() {
        let policy = EscalationPolicy::default();
        let mut escalator = HindsightTraceEscalator::new(policy, test_epoch());
        let t = test_trigger(TriggerCategory::SecurityEvent, TriggerSeverity::Critical);
        let d = escalator.evaluate(t);
        assert!(!d.artifacts_included.is_empty());
        assert!(d.estimated_bundle_bytes > 0);
    }

    #[test]
    fn suppressed_decision_has_no_artifacts() {
        let mut policy = EscalationPolicy::default();
        policy.max_active_escalations = 0;
        let mut escalator = HindsightTraceEscalator::new(policy, test_epoch());
        let t = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
        let d = escalator.evaluate(t);
        assert!(d.artifacts_included.is_empty());
        assert_eq!(d.estimated_bundle_bytes, 0);
    }

    #[test]
    fn support_bundle_manifest_from_decision() {
        let policy = EscalationPolicy::default();
        let mut escalator = HindsightTraceEscalator::new(policy, test_epoch());
        let t = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
        let decision = escalator.evaluate(t);
        let artifacts = vec![SupportBundleArtifact {
            label: "decision_log".into(),
            format: "jsonl".into(),
            path: "/tmp/bundle/decisions.jsonl".into(),
            bytes: 4096,
            content_hash: "abc123".into(),
        }];
        let manifest =
            SupportBundleManifest::from_decision(&decision, "bundle-001", artifacts);
        assert_eq!(manifest.bead_id, ESCALATION_BEAD_ID);
        assert_eq!(manifest.total_bytes, 4096);
        assert!(!manifest.manifest_hash.is_empty());
    }

    #[test]
    fn escalation_verdict_display() {
        assert_eq!(
            EscalationVerdict::Approved {
                level: EscalationLevel::Full
            }
            .to_string(),
            "approved(full)"
        );
        assert_eq!(
            EscalationVerdict::SuppressedBelowThreshold.to_string(),
            "suppressed_below_threshold"
        );
    }

    #[test]
    fn trigger_serde_roundtrip() {
        let mut t = test_trigger(TriggerCategory::SecurityEvent, TriggerSeverity::Critical);
        t.correlation_id = Some("corr-42".into());
        t.metadata.insert("key".into(), "value".into());
        let json = serde_json::to_string(&t).unwrap();
        let back: EscalationTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn escalation_policy_serde_roundtrip() {
        let policy = EscalationPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let back: EscalationPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn escalation_decision_serde_roundtrip() {
        let policy = EscalationPolicy::default();
        let mut escalator = HindsightTraceEscalator::new(policy, test_epoch());
        let t = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
        let d = escalator.evaluate(t);
        let json = serde_json::to_string(&d).unwrap();
        let back: EscalationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn escalator_summary_serde_roundtrip() {
        let policy = EscalationPolicy::default();
        let escalator = HindsightTraceEscalator::new(policy, test_epoch());
        let summary = escalator.summary();
        let json = serde_json::to_string(&summary).unwrap();
        let back: EscalatorSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    #[test]
    fn support_bundle_manifest_serde_roundtrip() {
        let manifest = SupportBundleManifest {
            schema_version: ESCALATION_SCHEMA_VERSION.into(),
            bead_id: ESCALATION_BEAD_ID.into(),
            bundle_id: "test-bundle".into(),
            trigger_id: "test-trigger".into(),
            escalation_level: EscalationLevel::Full,
            artifacts: vec![],
            total_bytes: 0,
            epoch: test_epoch(),
            manifest_hash: "hash".into(),
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let back: SupportBundleManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    #[test]
    fn category_counts_tracked() {
        let policy = EscalationPolicy::default();
        let mut escalator = HindsightTraceEscalator::new(policy, test_epoch());
        let t1 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
        escalator.evaluate(t1);
        escalator.complete_escalation();
        let t2 = EscalationTrigger::new(
            "trigger-002",
            TriggerCategory::Regression,
            TriggerSeverity::Critical,
            "another regression",
            "bench",
            test_epoch(),
        );
        escalator.evaluate(t2);
        assert_eq!(
            escalator.state.category_counts.get("regression"),
            Some(&2)
        );
    }

    #[test]
    fn escalator_state_new() {
        let state = EscalatorState::new(test_epoch());
        assert_eq!(state.active_escalations, 0);
        assert_eq!(state.total_approved, 0);
        assert_eq!(state.total_suppressed, 0);
        assert!(state.cooldowns.is_empty());
    }
}
