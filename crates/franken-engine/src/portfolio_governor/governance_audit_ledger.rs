//! Governance audit ledger for moonshot portfolio decisions.
//!
//! This module provides an append-only, hash-linked governance ledger for
//! automatic and human-override portfolio decisions. Entries are signed and can
//! be queried by moonshot, actor, decision type, time range, and override
//! status.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::portfolio_governor::{GovernorDecision, GovernorDecisionKind, Scorecard};
use frankenengine_engine::seqlock_fastpath::{
    FastPathTelemetry, RetryBudgetPolicy, SnapshotFastPath,
};

/// Decision classes captured by the governance ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GovernanceDecisionType {
    Promote,
    Hold,
    Kill,
    Pause,
    Resume,
    Override,
}

impl fmt::Display for GovernanceDecisionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Promote => write!(f, "promote"),
            Self::Hold => write!(f, "hold"),
            Self::Kill => write!(f, "kill"),
            Self::Pause => write!(f, "pause"),
            Self::Resume => write!(f, "resume"),
            Self::Override => write!(f, "override"),
        }
    }
}

/// Actor type responsible for a governance decision.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GovernanceActor {
    System(String),
    Human(String),
}

impl GovernanceActor {
    pub fn actor_id(&self) -> &str {
        match self {
            Self::System(id) | Self::Human(id) => id,
        }
    }

    pub fn is_human(&self) -> bool {
        matches!(self, Self::Human(_))
    }
}

/// Structured rationale attached to each governance decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceRationale {
    pub summary: String,
    pub passed_criteria: Vec<String>,
    pub failed_criteria: Vec<String>,
    pub confidence_millionths: u64,
    pub risk_of_harm_millionths: u64,
    pub bypassed_risk_criteria: Vec<String>,
    pub acknowledged_bypass: bool,
}

impl GovernanceRationale {
    pub fn for_automatic_decision(
        summary: impl Into<String>,
        confidence_millionths: u64,
        risk_of_harm_millionths: u64,
        passed_criteria: Vec<String>,
        failed_criteria: Vec<String>,
    ) -> Self {
        Self {
            summary: summary.into(),
            passed_criteria,
            failed_criteria,
            confidence_millionths,
            risk_of_harm_millionths,
            bypassed_risk_criteria: Vec::new(),
            acknowledged_bypass: false,
        }
    }
}

/// Scorecard snapshot embedded in the governance ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScorecardSnapshot {
    pub ev_millionths: i64,
    pub confidence_millionths: u64,
    pub risk_of_harm_millionths: u64,
    pub implementation_friction_millionths: u64,
    pub cross_initiative_interference_millionths: u64,
    pub operational_burden_millionths: u64,
}

impl From<&Scorecard> for ScorecardSnapshot {
    fn from(scorecard: &Scorecard) -> Self {
        Self {
            ev_millionths: scorecard.ev_millionths,
            confidence_millionths: scorecard.confidence_millionths,
            risk_of_harm_millionths: scorecard.risk_of_harm_millionths,
            implementation_friction_millionths: scorecard.implementation_friction_millionths,
            cross_initiative_interference_millionths: scorecard
                .cross_initiative_interference_millionths,
            operational_burden_millionths: scorecard.operational_burden_millionths,
        }
    }
}

/// Input payload used when appending a new governance ledger entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceLedgerInput {
    pub decision_id: String,
    pub moonshot_id: String,
    pub decision_type: GovernanceDecisionType,
    pub actor: GovernanceActor,
    pub rationale: GovernanceRationale,
    pub scorecard_snapshot: ScorecardSnapshot,
    pub artifact_references: Vec<String>,
    pub timestamp_ns: u64,
    pub moonshot_started_at_ns: Option<u64>,
}

/// Hash-chained governance ledger entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceLedgerEntry {
    pub sequence: u64,
    pub decision_id: String,
    pub moonshot_id: String,
    pub decision_type: GovernanceDecisionType,
    pub actor: GovernanceActor,
    pub rationale: GovernanceRationale,
    pub scorecard_snapshot: ScorecardSnapshot,
    pub artifact_references: Vec<String>,
    pub timestamp_ns: u64,
    pub moonshot_started_at_ns: Option<u64>,
    pub is_override: bool,
    pub previous_hash: Option<String>,
    pub entry_hash: String,
    pub signature: String,
}

/// Signed checkpoint for efficient consistency verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceLedgerCheckpoint {
    pub checkpoint_id: String,
    pub sequence: u64,
    pub entry_count: usize,
    pub head_hash: String,
    pub timestamp_ns: u64,
    pub signature: String,
}

/// Ledger configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceLedgerConfig {
    pub checkpoint_interval: usize,
    pub signer_key: Vec<u8>,
    pub policy_id: String,
}

impl Default for GovernanceLedgerConfig {
    fn default() -> Self {
        Self {
            checkpoint_interval: 64,
            signer_key: b"governance-ledger-default".to_vec(),
            policy_id: "moonshot-governor-policy-v1".to_string(),
        }
    }
}

/// Stable structured event emitted by governance ledger operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub timestamp_ns: u64,
}

/// Query filters for ledger entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceLedgerQuery {
    pub moonshot_id: Option<String>,
    pub decision_types: Option<BTreeSet<GovernanceDecisionType>>,
    pub actor_id: Option<String>,
    pub start_time_ns: Option<u64>,
    pub end_time_ns: Option<u64>,
    pub override_only: Option<bool>,
}

impl GovernanceLedgerQuery {
    pub fn all() -> Self {
        Self {
            moonshot_id: None,
            decision_types: None,
            actor_id: None,
            start_time_ns: None,
            end_time_ns: None,
            override_only: None,
        }
    }
}

/// Aggregate governance reporting metrics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceReport {
    pub total_decisions: usize,
    pub override_count: usize,
    pub kill_count: usize,
    pub override_frequency_millionths: u64,
    pub kill_rate_millionths: u64,
    pub mean_time_to_decision_ns: Option<u64>,
    pub portfolio_health_trend: Vec<PortfolioHealthPoint>,
}

/// Time-window aggregate point for portfolio health trend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortfolioHealthPoint {
    pub window_start_ns: u64,
    pub window_end_ns: u64,
    pub decision_count: usize,
    pub promote_count: usize,
    pub hold_count: usize,
    pub kill_count: usize,
    pub override_count: usize,
    pub avg_confidence_millionths: u64,
    pub avg_risk_millionths: u64,
}

/// Governance ledger errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceLedgerError {
    InvalidConfig { reason: String },
    InvalidInput { field: String, reason: String },
    DuplicateDecisionId { decision_id: String },
    OutOfOrderTimestamp { previous_ns: u64, new_ns: u64 },
    SerializationFailed { reason: String },
    HashChainMismatch { sequence: u64 },
    SignatureMismatch { sequence: u64 },
    EntryHashMismatch { sequence: u64 },
    EmptyLedger,
}

impl GovernanceLedgerError {
    fn serialization(reason: impl Into<String>) -> Self {
        Self::SerializationFailed {
            reason: reason.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "FE-GOV-LED-0001",
            Self::InvalidInput { .. } => "FE-GOV-LED-0002",
            Self::DuplicateDecisionId { .. } => "FE-GOV-LED-0003",
            Self::OutOfOrderTimestamp { .. } => "FE-GOV-LED-0004",
            Self::SerializationFailed { .. } => "FE-GOV-LED-0005",
            Self::HashChainMismatch { .. } => "FE-GOV-LED-0006",
            Self::SignatureMismatch { .. } => "FE-GOV-LED-0007",
            Self::EntryHashMismatch { .. } => "FE-GOV-LED-0008",
            Self::EmptyLedger => "FE-GOV-LED-0009",
        }
    }
}

impl fmt::Display for GovernanceLedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { reason } => write!(f, "invalid ledger config: {reason}"),
            Self::InvalidInput { field, reason } => {
                write!(f, "invalid ledger input field '{field}': {reason}")
            }
            Self::DuplicateDecisionId { decision_id } => {
                write!(f, "duplicate decision_id in ledger: {decision_id}")
            }
            Self::OutOfOrderTimestamp {
                previous_ns,
                new_ns,
            } => write!(
                f,
                "out-of-order ledger timestamp: previous={previous_ns}, new={new_ns}"
            ),
            Self::SerializationFailed { reason } => write!(f, "serialization failed: {reason}"),
            Self::HashChainMismatch { sequence } => {
                write!(f, "hash chain mismatch at sequence {sequence}")
            }
            Self::SignatureMismatch { sequence } => {
                write!(f, "signature mismatch at sequence {sequence}")
            }
            Self::EntryHashMismatch { sequence } => {
                write!(f, "entry hash mismatch at sequence {sequence}")
            }
            Self::EmptyLedger => write!(f, "ledger is empty"),
        }
    }
}

impl std::error::Error for GovernanceLedgerError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GovernanceLedgerHeadView {
    entries: Vec<GovernanceLedgerEntry>,
    latest_checkpoint: Option<GovernanceLedgerCheckpoint>,
}

/// Append-only governance audit ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceAuditLedger {
    pub config: GovernanceLedgerConfig,
    entries: Vec<GovernanceLedgerEntry>,
    checkpoints: Vec<GovernanceLedgerCheckpoint>,
    events: Vec<GovernanceLogEvent>,
    #[serde(skip, default = "governance_head_view_fastpath")]
    head_view_fastpath: SnapshotFastPath<GovernanceLedgerHeadView>,
}

impl GovernanceAuditLedger {
    pub fn new(config: GovernanceLedgerConfig) -> Result<Self, GovernanceLedgerError> {
        if config.checkpoint_interval == 0 {
            return Err(GovernanceLedgerError::InvalidConfig {
                reason: "checkpoint_interval must be >= 1".to_string(),
            });
        }
        if config.signer_key.is_empty() {
            return Err(GovernanceLedgerError::InvalidConfig {
                reason: "signer_key must not be empty".to_string(),
            });
        }
        if config.policy_id.trim().is_empty() {
            return Err(GovernanceLedgerError::InvalidConfig {
                reason: "policy_id must not be empty".to_string(),
            });
        }
        Ok(Self {
            config,
            entries: Vec::new(),
            checkpoints: Vec::new(),
            events: Vec::new(),
            head_view_fastpath: governance_head_view_fastpath(),
        })
    }

    pub fn entries(&self) -> &[GovernanceLedgerEntry] {
        &self.entries
    }

    pub fn checkpoints(&self) -> &[GovernanceLedgerCheckpoint] {
        &self.checkpoints
    }

    pub fn events(&self) -> &[GovernanceLogEvent] {
        &self.events
    }

    pub fn append_governor_decision(
        &mut self,
        decision: &GovernorDecision,
        actor: GovernanceActor,
        artifact_references: Vec<String>,
        moonshot_started_at_ns: Option<u64>,
    ) -> Result<GovernanceLedgerEntry, GovernanceLedgerError> {
        let decision_type = match decision.kind {
            GovernorDecisionKind::Promote { .. } => GovernanceDecisionType::Promote,
            GovernorDecisionKind::Hold { .. } => GovernanceDecisionType::Hold,
            GovernorDecisionKind::Kill { .. } => GovernanceDecisionType::Kill,
            GovernorDecisionKind::Pause { .. } => GovernanceDecisionType::Pause,
            GovernorDecisionKind::Resume => GovernanceDecisionType::Resume,
        };
        let rationale = GovernanceRationale::for_automatic_decision(
            decision.rationale.clone(),
            decision.scorecard.confidence_millionths,
            decision.scorecard.risk_of_harm_millionths,
            Vec::new(),
            Vec::new(),
        );
        self.append(GovernanceLedgerInput {
            decision_id: decision.decision_id.clone(),
            moonshot_id: decision.moonshot_id.clone(),
            decision_type,
            actor,
            rationale,
            scorecard_snapshot: ScorecardSnapshot::from(&decision.scorecard),
            artifact_references,
            timestamp_ns: decision.timestamp_ns,
            moonshot_started_at_ns,
        })
    }

    pub fn append(
        &mut self,
        mut input: GovernanceLedgerInput,
    ) -> Result<GovernanceLedgerEntry, GovernanceLedgerError> {
        if let Err(err) = self.validate_input(&input) {
            let decision_id = if input.decision_id.trim().is_empty() {
                "unknown-decision".to_string()
            } else {
                input.decision_id.clone()
            };
            self.record_event(
                &decision_id,
                "append_decision",
                "rejected",
                Some(err.code()),
                input.timestamp_ns,
            );
            return Err(err);
        }

        if self
            .entries
            .iter()
            .any(|entry| entry.decision_id == input.decision_id)
        {
            let err = GovernanceLedgerError::DuplicateDecisionId {
                decision_id: input.decision_id,
            };
            self.record_event(
                "duplicate-decision",
                "append_decision",
                "rejected",
                Some(err.code()),
                input.timestamp_ns,
            );
            return Err(err);
        }

        if let Some(last) = self.entries.last()
            && input.timestamp_ns < last.timestamp_ns
        {
            let err = GovernanceLedgerError::OutOfOrderTimestamp {
                previous_ns: last.timestamp_ns,
                new_ns: input.timestamp_ns,
            };
            self.record_event(
                &input.decision_id,
                "append_decision",
                "rejected",
                Some(err.code()),
                input.timestamp_ns,
            );
            return Err(err);
        }

        input.artifact_references.sort();
        input.artifact_references.dedup();

        let sequence = self.entries.len() as u64 + 1;
        let previous_hash = self.entries.last().map(|entry| entry.entry_hash.clone());
        let is_override = input.decision_type == GovernanceDecisionType::Override;

        let preimage = match entry_preimage(sequence, &input, previous_hash.as_deref()) {
            Ok(preimage) => preimage,
            Err(err) => {
                self.record_event(
                    &input.decision_id,
                    "append_decision",
                    "error",
                    Some(err.code()),
                    input.timestamp_ns,
                );
                return Err(err);
            }
        };
        let entry_hash = ContentHash::compute(&preimage).to_hex();
        let signature =
            AuthenticityHash::compute_keyed(&preimage, &self.config.signer_key).to_hex();

        let entry = GovernanceLedgerEntry {
            sequence,
            decision_id: input.decision_id,
            moonshot_id: input.moonshot_id,
            decision_type: input.decision_type,
            actor: input.actor,
            rationale: input.rationale,
            scorecard_snapshot: input.scorecard_snapshot,
            artifact_references: input.artifact_references,
            timestamp_ns: input.timestamp_ns,
            moonshot_started_at_ns: input.moonshot_started_at_ns,
            is_override,
            previous_hash,
            entry_hash,
            signature,
        };

        self.entries.push(entry.clone());
        if self
            .entries
            .len()
            .is_multiple_of(self.config.checkpoint_interval)
        {
            let checkpoint = match self.create_checkpoint(entry.timestamp_ns) {
                Ok(checkpoint) => checkpoint,
                Err(err) => {
                    let _ = self.entries.pop();
                    self.record_event(
                        &entry.decision_id,
                        "checkpoint_create",
                        "error",
                        Some(err.code()),
                        entry.timestamp_ns,
                    );
                    return Err(err);
                }
            };
            self.checkpoints.push(checkpoint);
            self.record_event(
                &entry.decision_id,
                "checkpoint_create",
                "success",
                None,
                entry.timestamp_ns,
            );
        }
        self.record_event(
            &entry.decision_id,
            "append_decision",
            "success",
            None,
            entry.timestamp_ns,
        );
        self.publish_head_view_fastpath();
        Ok(entry)
    }

    pub fn verify_chain(&self) -> Result<(), GovernanceLedgerError> {
        for (idx, entry) in self.entries.iter().enumerate() {
            let expected_prev = if idx == 0 {
                None
            } else {
                Some(self.entries[idx - 1].entry_hash.as_str())
            };
            if entry.previous_hash.as_deref() != expected_prev {
                return Err(GovernanceLedgerError::HashChainMismatch {
                    sequence: entry.sequence,
                });
            }

            let input = GovernanceLedgerInput {
                decision_id: entry.decision_id.clone(),
                moonshot_id: entry.moonshot_id.clone(),
                decision_type: entry.decision_type,
                actor: entry.actor.clone(),
                rationale: entry.rationale.clone(),
                scorecard_snapshot: entry.scorecard_snapshot.clone(),
                artifact_references: entry.artifact_references.clone(),
                timestamp_ns: entry.timestamp_ns,
                moonshot_started_at_ns: entry.moonshot_started_at_ns,
            };
            let preimage = entry_preimage(entry.sequence, &input, entry.previous_hash.as_deref())?;
            let recomputed_hash = ContentHash::compute(&preimage).to_hex();
            if recomputed_hash != entry.entry_hash {
                return Err(GovernanceLedgerError::EntryHashMismatch {
                    sequence: entry.sequence,
                });
            }
            let recomputed_signature =
                AuthenticityHash::compute_keyed(&preimage, &self.config.signer_key).to_hex();
            if recomputed_signature != entry.signature {
                return Err(GovernanceLedgerError::SignatureMismatch {
                    sequence: entry.sequence,
                });
            }
        }

        for checkpoint in &self.checkpoints {
            let preimage = checkpoint_preimage(
                checkpoint.sequence,
                checkpoint.entry_count,
                &checkpoint.head_hash,
                checkpoint.timestamp_ns,
            )?;
            let signature =
                AuthenticityHash::compute_keyed(&preimage, &self.config.signer_key).to_hex();
            if signature != checkpoint.signature {
                return Err(GovernanceLedgerError::SignatureMismatch {
                    sequence: checkpoint.sequence,
                });
            }
        }

        Ok(())
    }

    pub fn query(&self, query: &GovernanceLedgerQuery) -> Vec<GovernanceLedgerEntry> {
        if !self.head_view_fastpath.is_initialized() {
            self.head_view_fastpath
                .seed_if_uninitialized(self.baseline_head_view());
        }
        self.head_view_fastpath
            .read_clone_or_else(|| self.baseline_head_view())
            .value
            .entries
            .into_iter()
            .filter(|entry| {
                query
                    .moonshot_id
                    .as_ref()
                    .is_none_or(|moonshot_id| &entry.moonshot_id == moonshot_id)
            })
            .filter(|entry| {
                query
                    .decision_types
                    .as_ref()
                    .is_none_or(|types| types.contains(&entry.decision_type))
            })
            .filter(|entry| {
                query
                    .actor_id
                    .as_ref()
                    .is_none_or(|actor_id| entry.actor.actor_id() == actor_id)
            })
            .filter(|entry| {
                query
                    .start_time_ns
                    .is_none_or(|start| entry.timestamp_ns >= start)
            })
            .filter(|entry| {
                query
                    .end_time_ns
                    .is_none_or(|end| entry.timestamp_ns <= end)
            })
            .filter(|entry| {
                query
                    .override_only
                    .is_none_or(|only| entry.is_override == only)
            })
            .collect()
    }

    pub fn governance_report(
        &self,
        start_time_ns: u64,
        end_time_ns: u64,
        window_ns: u64,
    ) -> Result<GovernanceReport, GovernanceLedgerError> {
        if end_time_ns < start_time_ns {
            return Err(GovernanceLedgerError::InvalidInput {
                field: "end_time_ns".to_string(),
                reason: "must be >= start_time_ns".to_string(),
            });
        }
        if window_ns == 0 {
            return Err(GovernanceLedgerError::InvalidInput {
                field: "window_ns".to_string(),
                reason: "must be >= 1".to_string(),
            });
        }

        let filtered: Vec<&GovernanceLedgerEntry> = self
            .entries
            .iter()
            .filter(|entry| {
                entry.timestamp_ns >= start_time_ns && entry.timestamp_ns <= end_time_ns
            })
            .collect();
        let total = filtered.len();
        let override_count = filtered.iter().filter(|entry| entry.is_override).count();
        let kill_count = filtered
            .iter()
            .filter(|entry| entry.decision_type == GovernanceDecisionType::Kill)
            .count();
        let override_frequency = ratio_millionths(override_count, total);
        let kill_rate = ratio_millionths(kill_count, total);

        let mut decision_latencies = Vec::new();
        for entry in &filtered {
            if let Some(started_at) = entry.moonshot_started_at_ns
                && entry.timestamp_ns >= started_at
            {
                decision_latencies.push(entry.timestamp_ns - started_at);
            }
        }
        let mean_time_to_decision_ns = if decision_latencies.is_empty() {
            None
        } else {
            let sum: u128 = decision_latencies.iter().map(|v| *v as u128).sum();
            Some((sum / decision_latencies.len() as u128) as u64)
        };

        let mut buckets: BTreeMap<u64, WindowAccumulator> = BTreeMap::new();
        for entry in filtered {
            let bucket_start =
                start_time_ns + ((entry.timestamp_ns - start_time_ns) / window_ns) * window_ns;
            let bucket = buckets.entry(bucket_start).or_default();
            bucket.decision_count += 1;
            bucket.sum_confidence += entry.rationale.confidence_millionths as u128;
            bucket.sum_risk += entry.rationale.risk_of_harm_millionths as u128;
            match entry.decision_type {
                GovernanceDecisionType::Promote => bucket.promote_count += 1,
                GovernanceDecisionType::Hold => bucket.hold_count += 1,
                GovernanceDecisionType::Kill => bucket.kill_count += 1,
                _ => {}
            }
            if entry.is_override {
                bucket.override_count += 1;
            }
        }

        let mut trend = Vec::new();
        for (bucket_start, bucket) in buckets {
            let avg_confidence = if bucket.decision_count == 0 {
                0
            } else {
                (bucket.sum_confidence / bucket.decision_count as u128) as u64
            };
            let avg_risk = if bucket.decision_count == 0 {
                0
            } else {
                (bucket.sum_risk / bucket.decision_count as u128) as u64
            };
            trend.push(PortfolioHealthPoint {
                window_start_ns: bucket_start,
                window_end_ns: bucket_start.saturating_add(window_ns.saturating_sub(1)),
                decision_count: bucket.decision_count,
                promote_count: bucket.promote_count,
                hold_count: bucket.hold_count,
                kill_count: bucket.kill_count,
                override_count: bucket.override_count,
                avg_confidence_millionths: avg_confidence,
                avg_risk_millionths: avg_risk,
            });
        }

        Ok(GovernanceReport {
            total_decisions: total,
            override_count,
            kill_count,
            override_frequency_millionths: override_frequency,
            kill_rate_millionths: kill_rate,
            mean_time_to_decision_ns,
            portfolio_health_trend: trend,
        })
    }

    pub fn latest_checkpoint(&self) -> Option<&GovernanceLedgerCheckpoint> {
        self.checkpoints.last()
    }

    pub fn latest_checkpoint_view(&self) -> Option<GovernanceLedgerCheckpoint> {
        if !self.head_view_fastpath.is_initialized() {
            self.head_view_fastpath
                .seed_if_uninitialized(self.baseline_head_view());
        }
        self.head_view_fastpath
            .read_clone_or_else(|| self.baseline_head_view())
            .value
            .latest_checkpoint
    }

    pub fn head_view_fastpath_policy(&self) -> RetryBudgetPolicy {
        self.head_view_fastpath.policy()
    }

    pub fn head_view_fastpath_telemetry(&self) -> FastPathTelemetry {
        self.head_view_fastpath.telemetry()
    }

    pub fn latest_entry(&self) -> Option<&GovernanceLedgerEntry> {
        self.entries.last()
    }

    fn create_checkpoint(
        &self,
        timestamp_ns: u64,
    ) -> Result<GovernanceLedgerCheckpoint, GovernanceLedgerError> {
        let last = self
            .entries
            .last()
            .ok_or(GovernanceLedgerError::EmptyLedger)?;
        let sequence = last.sequence;
        let entry_count = self.entries.len();
        let head_hash = last.entry_hash.clone();
        let preimage = checkpoint_preimage(sequence, entry_count, &head_hash, timestamp_ns)?;
        let checkpoint_id = ContentHash::compute(&preimage).to_hex();
        let signature =
            AuthenticityHash::compute_keyed(&preimage, &self.config.signer_key).to_hex();
        Ok(GovernanceLedgerCheckpoint {
            checkpoint_id,
            sequence,
            entry_count,
            head_hash,
            timestamp_ns,
            signature,
        })
    }

    fn baseline_head_view(&self) -> GovernanceLedgerHeadView {
        GovernanceLedgerHeadView {
            entries: self.entries.clone(),
            latest_checkpoint: self.checkpoints.last().cloned(),
        }
    }

    fn publish_head_view_fastpath(&self) {
        self.head_view_fastpath.publish(self.baseline_head_view());
    }

    fn validate_input(&self, input: &GovernanceLedgerInput) -> Result<(), GovernanceLedgerError> {
        if input.decision_id.trim().is_empty() {
            return Err(GovernanceLedgerError::InvalidInput {
                field: "decision_id".to_string(),
                reason: "must not be empty".to_string(),
            });
        }
        if input.moonshot_id.trim().is_empty() {
            return Err(GovernanceLedgerError::InvalidInput {
                field: "moonshot_id".to_string(),
                reason: "must not be empty".to_string(),
            });
        }
        if input.actor.actor_id().trim().is_empty() {
            return Err(GovernanceLedgerError::InvalidInput {
                field: "actor".to_string(),
                reason: "actor identifier must not be empty".to_string(),
            });
        }
        if input.rationale.summary.trim().is_empty() {
            return Err(GovernanceLedgerError::InvalidInput {
                field: "rationale.summary".to_string(),
                reason: "must not be empty".to_string(),
            });
        }
        if input.rationale.confidence_millionths > 1_000_000 {
            return Err(GovernanceLedgerError::InvalidInput {
                field: "rationale.confidence_millionths".to_string(),
                reason: "must be within 0..=1_000_000".to_string(),
            });
        }
        if input.rationale.risk_of_harm_millionths > 1_000_000 {
            return Err(GovernanceLedgerError::InvalidInput {
                field: "rationale.risk_of_harm_millionths".to_string(),
                reason: "must be within 0..=1_000_000".to_string(),
            });
        }

        if input.decision_type == GovernanceDecisionType::Override {
            if !input.actor.is_human() {
                return Err(GovernanceLedgerError::InvalidInput {
                    field: "actor".to_string(),
                    reason: "override decisions must be attributed to a human actor".to_string(),
                });
            }
            if input.rationale.bypassed_risk_criteria.is_empty() {
                return Err(GovernanceLedgerError::InvalidInput {
                    field: "rationale.bypassed_risk_criteria".to_string(),
                    reason: "override decisions must include bypassed risk criteria".to_string(),
                });
            }
            if !input.rationale.acknowledged_bypass {
                return Err(GovernanceLedgerError::InvalidInput {
                    field: "rationale.acknowledged_bypass".to_string(),
                    reason: "override decisions must acknowledge bypass".to_string(),
                });
            }
        }
        Ok(())
    }

    fn record_event(
        &mut self,
        decision_id: &str,
        event: &str,
        outcome: &str,
        error_code: Option<&str>,
        timestamp_ns: u64,
    ) {
        self.events.push(GovernanceLogEvent {
            trace_id: format!("trace:{decision_id}"),
            decision_id: decision_id.to_string(),
            policy_id: self.config.policy_id.clone(),
            component: "governance_audit_ledger".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(str::to_string),
            timestamp_ns,
        });
    }
}

fn governance_head_view_fastpath() -> SnapshotFastPath<GovernanceLedgerHeadView> {
    SnapshotFastPath::new(RetryBudgetPolicy::new(4, 1))
}

#[derive(Debug, Default)]
struct WindowAccumulator {
    decision_count: usize,
    promote_count: usize,
    hold_count: usize,
    kill_count: usize,
    override_count: usize,
    sum_confidence: u128,
    sum_risk: u128,
}

fn ratio_millionths(part: usize, total: usize) -> u64 {
    if total == 0 {
        return 0;
    }
    ((part as u128 * 1_000_000u128) / total as u128) as u64
}

fn entry_preimage(
    sequence: u64,
    input: &GovernanceLedgerInput,
    previous_hash: Option<&str>,
) -> Result<Vec<u8>, GovernanceLedgerError> {
    #[derive(Serialize)]
    struct EntryPreimage<'a> {
        sequence: u64,
        previous_hash: Option<&'a str>,
        decision_id: &'a str,
        moonshot_id: &'a str,
        decision_type: GovernanceDecisionType,
        actor: &'a GovernanceActor,
        rationale: &'a GovernanceRationale,
        scorecard_snapshot: &'a ScorecardSnapshot,
        artifact_references: &'a [String],
        timestamp_ns: u64,
        moonshot_started_at_ns: Option<u64>,
    }

    serde_json::to_vec(&EntryPreimage {
        sequence,
        previous_hash,
        decision_id: &input.decision_id,
        moonshot_id: &input.moonshot_id,
        decision_type: input.decision_type,
        actor: &input.actor,
        rationale: &input.rationale,
        scorecard_snapshot: &input.scorecard_snapshot,
        artifact_references: &input.artifact_references,
        timestamp_ns: input.timestamp_ns,
        moonshot_started_at_ns: input.moonshot_started_at_ns,
    })
    .map_err(|err| GovernanceLedgerError::serialization(err.to_string()))
}

fn checkpoint_preimage(
    sequence: u64,
    entry_count: usize,
    head_hash: &str,
    timestamp_ns: u64,
) -> Result<Vec<u8>, GovernanceLedgerError> {
    #[derive(Serialize)]
    struct CheckpointPreimage<'a> {
        sequence: u64,
        entry_count: usize,
        head_hash: &'a str,
        timestamp_ns: u64,
    }

    serde_json::to_vec(&CheckpointPreimage {
        sequence,
        entry_count,
        head_hash,
        timestamp_ns,
    })
    .map_err(|err| GovernanceLedgerError::serialization(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moonshot_contract::MoonshotStage;
    use crate::security_epoch::SecurityEpoch;

    fn sample_scorecard() -> Scorecard {
        Scorecard {
            moonshot_id: "moon-1".to_string(),
            ev_millionths: 800_000,
            confidence_millionths: 820_000,
            risk_of_harm_millionths: 110_000,
            implementation_friction_millionths: 120_000,
            cross_initiative_interference_millionths: 80_000,
            operational_burden_millionths: 250_000,
            computed_at_ns: 100,
            epoch: SecurityEpoch::from_raw(7),
        }
    }

    fn automatic_input(
        decision_id: &str,
        moonshot_id: &str,
        decision_type: GovernanceDecisionType,
        timestamp_ns: u64,
    ) -> GovernanceLedgerInput {
        GovernanceLedgerInput {
            decision_id: decision_id.to_string(),
            moonshot_id: moonshot_id.to_string(),
            decision_type,
            actor: GovernanceActor::System("governor".to_string()),
            rationale: GovernanceRationale::for_automatic_decision(
                "automatic gate decision",
                800_000,
                120_000,
                vec!["artifact_obligations_met".to_string()],
                vec![],
            ),
            scorecard_snapshot: ScorecardSnapshot::from(&sample_scorecard()),
            artifact_references: vec!["artifact://scorecard/1".to_string()],
            timestamp_ns,
            moonshot_started_at_ns: Some(1),
        }
    }

    fn override_input(decision_id: &str, timestamp_ns: u64) -> GovernanceLedgerInput {
        GovernanceLedgerInput {
            decision_id: decision_id.to_string(),
            moonshot_id: "moon-1".to_string(),
            decision_type: GovernanceDecisionType::Override,
            actor: GovernanceActor::Human("operator-1".to_string()),
            rationale: GovernanceRationale {
                summary: "override promotion due external incident context".to_string(),
                passed_criteria: vec!["artifact_obligations_met".to_string()],
                failed_criteria: vec!["risk_threshold".to_string()],
                confidence_millionths: 700_000,
                risk_of_harm_millionths: 250_000,
                bypassed_risk_criteria: vec!["risk_of_harm <= 200_000".to_string()],
                acknowledged_bypass: true,
            },
            scorecard_snapshot: ScorecardSnapshot::from(&sample_scorecard()),
            artifact_references: vec!["artifact://override/1".to_string()],
            timestamp_ns,
            moonshot_started_at_ns: Some(1),
        }
    }

    fn ledger() -> GovernanceAuditLedger {
        GovernanceAuditLedger::new(GovernanceLedgerConfig {
            checkpoint_interval: 2,
            signer_key: b"ledger-test-key".to_vec(),
            policy_id: "moonshot-governor-policy-test".to_string(),
        })
        .expect("ledger")
    }

    #[test]
    fn append_entries_and_verify_chain() {
        let mut ledger = ledger();
        ledger
            .append(automatic_input(
                "decision-1",
                "moon-1",
                GovernanceDecisionType::Promote,
                10,
            ))
            .expect("append decision-1");
        ledger
            .append(automatic_input(
                "decision-2",
                "moon-1",
                GovernanceDecisionType::Hold,
                20,
            ))
            .expect("append decision-2");
        ledger.verify_chain().expect("chain verifies");
        assert_eq!(ledger.entries().len(), 2);
        assert_eq!(ledger.checkpoints().len(), 1);
        assert_eq!(ledger.events().len(), 3);
        let append_event = ledger
            .events()
            .iter()
            .find(|event| event.event == "append_decision" && event.outcome == "success")
            .expect("append event");
        assert_eq!(append_event.policy_id, "moonshot-governor-policy-test");
        assert_eq!(append_event.component, "governance_audit_ledger");
        assert!(append_event.error_code.is_none());
    }

    #[test]
    fn tamper_detection_catches_hash_mismatch() {
        let mut ledger = ledger();
        ledger
            .append(automatic_input(
                "decision-1",
                "moon-1",
                GovernanceDecisionType::Promote,
                10,
            ))
            .expect("append");
        ledger.entries[0].rationale.summary = "tampered".to_string();
        let err = ledger.verify_chain().expect_err("must fail");
        assert!(matches!(
            err,
            GovernanceLedgerError::EntryHashMismatch { .. }
        ));
    }

    #[test]
    fn duplicate_decision_id_rejected() {
        let mut ledger = ledger();
        ledger
            .append(automatic_input(
                "decision-1",
                "moon-1",
                GovernanceDecisionType::Promote,
                10,
            ))
            .expect("append");
        let err = ledger
            .append(automatic_input(
                "decision-1",
                "moon-1",
                GovernanceDecisionType::Hold,
                11,
            ))
            .expect_err("duplicate rejected");
        assert!(matches!(
            err,
            GovernanceLedgerError::DuplicateDecisionId { .. }
        ));
    }

    #[test]
    fn override_requires_human_actor_and_acknowledgement() {
        let mut ledger = ledger();
        let mut input = override_input("decision-ovr", 10);
        input.actor = GovernanceActor::System("governor".to_string());
        let err = ledger.append(input).expect_err("override must be human");
        assert!(matches!(err, GovernanceLedgerError::InvalidInput { .. }));

        let mut input2 = override_input("decision-ovr-2", 11);
        input2.rationale.acknowledged_bypass = false;
        let err = ledger
            .append(input2)
            .expect_err("override must acknowledge bypass");
        assert!(matches!(err, GovernanceLedgerError::InvalidInput { .. }));
    }

    #[test]
    fn query_filters_by_actor_type_and_override() {
        let mut ledger = ledger();
        ledger
            .append(automatic_input(
                "decision-1",
                "moon-1",
                GovernanceDecisionType::Promote,
                10,
            ))
            .expect("append promote");
        ledger
            .append(override_input("decision-2", 20))
            .expect("append override");

        let q = GovernanceLedgerQuery {
            moonshot_id: Some("moon-1".to_string()),
            decision_types: None,
            actor_id: Some("operator-1".to_string()),
            start_time_ns: None,
            end_time_ns: None,
            override_only: Some(true),
        };
        let rows = ledger.query(&q);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].decision_id, "decision-2");
        assert!(rows[0].is_override);
    }

    #[test]
    fn governance_report_computes_override_frequency_kill_rate_and_trend() {
        let mut ledger = ledger();
        ledger
            .append(automatic_input(
                "decision-1",
                "moon-1",
                GovernanceDecisionType::Promote,
                10,
            ))
            .expect("append promote");
        ledger
            .append(automatic_input(
                "decision-2",
                "moon-1",
                GovernanceDecisionType::Kill,
                20,
            ))
            .expect("append kill");
        ledger
            .append(override_input("decision-3", 30))
            .expect("append override");

        let report = ledger
            .governance_report(0, 100, 25)
            .expect("report generation");
        assert_eq!(report.total_decisions, 3);
        assert_eq!(report.override_count, 1);
        assert_eq!(report.kill_count, 1);
        assert_eq!(report.override_frequency_millionths, 333_333);
        assert_eq!(report.kill_rate_millionths, 333_333);
        assert_eq!(report.mean_time_to_decision_ns, Some(19));
        assert!(!report.portfolio_health_trend.is_empty());
    }

    #[test]
    fn append_governor_decision_maps_decision_types() {
        let mut ledger = ledger();
        let decision = GovernorDecision {
            decision_id: "gov-1".to_string(),
            moonshot_id: "moon-1".to_string(),
            kind: GovernorDecisionKind::Promote {
                from: MoonshotStage::Research,
                to: MoonshotStage::Shadow,
            },
            scorecard: sample_scorecard(),
            timestamp_ns: 50,
            epoch: SecurityEpoch::from_raw(7),
            rationale: "all stage gates met".to_string(),
        };
        let row = ledger
            .append_governor_decision(
                &decision,
                GovernanceActor::System("governor".to_string()),
                vec!["artifact://scorecard/gov-1".to_string()],
                Some(1),
            )
            .expect("append governor decision");
        assert_eq!(row.decision_type, GovernanceDecisionType::Promote);
        assert_eq!(row.actor.actor_id(), "governor");
    }

    #[test]
    fn checkpoint_signature_verifies() {
        let mut ledger = ledger();
        ledger
            .append(automatic_input(
                "decision-1",
                "moon-1",
                GovernanceDecisionType::Promote,
                10,
            ))
            .expect("append #1");
        ledger
            .append(automatic_input(
                "decision-2",
                "moon-1",
                GovernanceDecisionType::Hold,
                20,
            ))
            .expect("append #2");
        let checkpoint = ledger.latest_checkpoint().expect("checkpoint").clone();
        assert_eq!(checkpoint.entry_count, 2);
        ledger.verify_chain().expect("checkpoint signature valid");
    }

    #[test]
    fn report_validation_rejects_invalid_windows() {
        let ledger = ledger();
        let err = ledger
            .governance_report(100, 50, 10)
            .expect_err("invalid end window");
        assert!(matches!(err, GovernanceLedgerError::InvalidInput { .. }));

        let err = ledger
            .governance_report(0, 50, 0)
            .expect_err("invalid window size");
        assert!(matches!(err, GovernanceLedgerError::InvalidInput { .. }));
    }

    #[test]
    fn rejected_append_emits_structured_error_event() {
        let mut ledger = ledger();
        let mut invalid = override_input("bad-override", 10);
        invalid.rationale.acknowledged_bypass = false;
        let err = ledger
            .append(invalid)
            .expect_err("invalid override must fail");
        assert_eq!(err.code(), "FE-GOV-LED-0002");

        let event = ledger.events().last().expect("error event");
        assert_eq!(event.trace_id, "trace:bad-override");
        assert_eq!(event.decision_id, "bad-override");
        assert_eq!(event.policy_id, "moonshot-governor-policy-test");
        assert_eq!(event.component, "governance_audit_ledger");
        assert_eq!(event.event, "append_decision");
        assert_eq!(event.outcome, "rejected");
        assert_eq!(event.error_code.as_deref(), Some("FE-GOV-LED-0002"));
    }

    // -- GovernanceDecisionType Display all 6 variants --

    #[test]
    fn governance_decision_type_display() {
        assert_eq!(GovernanceDecisionType::Promote.to_string(), "promote");
        assert_eq!(GovernanceDecisionType::Hold.to_string(), "hold");
        assert_eq!(GovernanceDecisionType::Kill.to_string(), "kill");
        assert_eq!(GovernanceDecisionType::Pause.to_string(), "pause");
        assert_eq!(GovernanceDecisionType::Resume.to_string(), "resume");
        assert_eq!(GovernanceDecisionType::Override.to_string(), "override");
    }

    // -- GovernanceActor --

    #[test]
    fn governance_actor_system_accessors() {
        let actor = GovernanceActor::System("gov-engine".to_string());
        assert_eq!(actor.actor_id(), "gov-engine");
        assert!(!actor.is_human());
    }

    #[test]
    fn governance_actor_human_accessors() {
        let actor = GovernanceActor::Human("operator-1".to_string());
        assert_eq!(actor.actor_id(), "operator-1");
        assert!(actor.is_human());
    }

    // -- Config validation --

    #[test]
    fn config_rejects_zero_checkpoint_interval() {
        let err = GovernanceAuditLedger::new(GovernanceLedgerConfig {
            checkpoint_interval: 0,
            signer_key: b"key".to_vec(),
            policy_id: "policy".to_string(),
        })
        .unwrap_err();
        assert!(matches!(err, GovernanceLedgerError::InvalidConfig { .. }));
    }

    #[test]
    fn config_rejects_empty_signer_key() {
        let err = GovernanceAuditLedger::new(GovernanceLedgerConfig {
            checkpoint_interval: 1,
            signer_key: vec![],
            policy_id: "policy".to_string(),
        })
        .unwrap_err();
        assert!(matches!(err, GovernanceLedgerError::InvalidConfig { .. }));
    }

    #[test]
    fn config_rejects_empty_policy_id() {
        let err = GovernanceAuditLedger::new(GovernanceLedgerConfig {
            checkpoint_interval: 1,
            signer_key: b"key".to_vec(),
            policy_id: "  ".to_string(),
        })
        .unwrap_err();
        assert!(matches!(err, GovernanceLedgerError::InvalidConfig { .. }));
    }

    #[test]
    fn config_default_values() {
        let config = GovernanceLedgerConfig::default();
        assert_eq!(config.checkpoint_interval, 64);
        assert!(!config.signer_key.is_empty());
        assert!(!config.policy_id.is_empty());
    }

    // -- Input validation --

    #[test]
    fn append_rejects_empty_decision_id() {
        let mut ledger = ledger();
        let mut input = automatic_input("d", "moon-1", GovernanceDecisionType::Promote, 10);
        input.decision_id = "  ".to_string();
        let err = ledger.append(input).unwrap_err();
        assert!(matches!(
            err,
            GovernanceLedgerError::InvalidInput { field, .. } if field == "decision_id"
        ));
    }

    #[test]
    fn append_rejects_empty_moonshot_id() {
        let mut ledger = ledger();
        let mut input = automatic_input("d", "moon-1", GovernanceDecisionType::Promote, 10);
        input.moonshot_id = "".to_string();
        let err = ledger.append(input).unwrap_err();
        assert!(matches!(
            err,
            GovernanceLedgerError::InvalidInput { field, .. } if field == "moonshot_id"
        ));
    }

    #[test]
    fn append_rejects_empty_actor_id() {
        let mut ledger = ledger();
        let mut input = automatic_input("d", "moon-1", GovernanceDecisionType::Promote, 10);
        input.actor = GovernanceActor::System("".to_string());
        let err = ledger.append(input).unwrap_err();
        assert!(matches!(
            err,
            GovernanceLedgerError::InvalidInput { field, .. } if field == "actor"
        ));
    }

    #[test]
    fn append_rejects_confidence_over_million() {
        let mut ledger = ledger();
        let mut input = automatic_input("d", "moon-1", GovernanceDecisionType::Promote, 10);
        input.rationale.confidence_millionths = 1_000_001;
        let err = ledger.append(input).unwrap_err();
        assert!(matches!(err, GovernanceLedgerError::InvalidInput { .. }));
    }

    #[test]
    fn append_rejects_risk_over_million() {
        let mut ledger = ledger();
        let mut input = automatic_input("d", "moon-1", GovernanceDecisionType::Promote, 10);
        input.rationale.risk_of_harm_millionths = 1_000_001;
        let err = ledger.append(input).unwrap_err();
        assert!(matches!(err, GovernanceLedgerError::InvalidInput { .. }));
    }

    // -- Out of order timestamp --

    #[test]
    fn append_rejects_out_of_order_timestamp() {
        let mut ledger = ledger();
        ledger
            .append(automatic_input(
                "d-1",
                "moon-1",
                GovernanceDecisionType::Promote,
                100,
            ))
            .unwrap();
        let err = ledger
            .append(automatic_input(
                "d-2",
                "moon-1",
                GovernanceDecisionType::Hold,
                50,
            ))
            .unwrap_err();
        assert!(matches!(
            err,
            GovernanceLedgerError::OutOfOrderTimestamp { .. }
        ));
    }

    // -- Hash chain links --

    #[test]
    fn first_entry_has_no_previous_hash() {
        let mut ledger = ledger();
        let entry = ledger
            .append(automatic_input(
                "d-1",
                "moon-1",
                GovernanceDecisionType::Promote,
                10,
            ))
            .unwrap();
        assert!(entry.previous_hash.is_none());
    }

    #[test]
    fn second_entry_has_previous_hash() {
        let mut ledger = ledger();
        let e1 = ledger
            .append(automatic_input(
                "d-1",
                "moon-1",
                GovernanceDecisionType::Promote,
                10,
            ))
            .unwrap();
        let e2 = ledger
            .append(automatic_input(
                "d-2",
                "moon-1",
                GovernanceDecisionType::Hold,
                20,
            ))
            .unwrap();
        assert_eq!(e2.previous_hash.as_deref(), Some(e1.entry_hash.as_str()));
    }

    // -- Override flag --

    #[test]
    fn override_entry_has_is_override_true() {
        let mut ledger = ledger();
        let entry = ledger.append(override_input("ovr-1", 10)).unwrap();
        assert!(entry.is_override);
    }

    #[test]
    fn non_override_entry_has_is_override_false() {
        let mut ledger = ledger();
        let entry = ledger
            .append(automatic_input(
                "d-1",
                "moon-1",
                GovernanceDecisionType::Promote,
                10,
            ))
            .unwrap();
        assert!(!entry.is_override);
    }

    // -- GovernanceLedgerError Display and code --

    #[test]
    fn governance_ledger_error_display_all_variants() {
        let errors: Vec<GovernanceLedgerError> = vec![
            GovernanceLedgerError::InvalidConfig {
                reason: "bad".to_string(),
            },
            GovernanceLedgerError::InvalidInput {
                field: "f".to_string(),
                reason: "r".to_string(),
            },
            GovernanceLedgerError::DuplicateDecisionId {
                decision_id: "d".to_string(),
            },
            GovernanceLedgerError::OutOfOrderTimestamp {
                previous_ns: 100,
                new_ns: 50,
            },
            GovernanceLedgerError::SerializationFailed {
                reason: "json".to_string(),
            },
            GovernanceLedgerError::HashChainMismatch { sequence: 3 },
            GovernanceLedgerError::SignatureMismatch { sequence: 4 },
            GovernanceLedgerError::EntryHashMismatch { sequence: 5 },
            GovernanceLedgerError::EmptyLedger,
        ];
        for err in &errors {
            assert!(!err.to_string().is_empty());
            assert!(err.code().starts_with("FE-GOV-LED-"));
        }
    }

    #[test]
    fn governance_ledger_error_codes_are_unique() {
        let errors: Vec<GovernanceLedgerError> = vec![
            GovernanceLedgerError::InvalidConfig {
                reason: "".to_string(),
            },
            GovernanceLedgerError::InvalidInput {
                field: "".to_string(),
                reason: "".to_string(),
            },
            GovernanceLedgerError::DuplicateDecisionId {
                decision_id: "".to_string(),
            },
            GovernanceLedgerError::OutOfOrderTimestamp {
                previous_ns: 0,
                new_ns: 0,
            },
            GovernanceLedgerError::SerializationFailed {
                reason: "".to_string(),
            },
            GovernanceLedgerError::HashChainMismatch { sequence: 0 },
            GovernanceLedgerError::SignatureMismatch { sequence: 0 },
            GovernanceLedgerError::EntryHashMismatch { sequence: 0 },
            GovernanceLedgerError::EmptyLedger,
        ];
        let codes: BTreeSet<&str> = errors.iter().map(|e| e.code()).collect();
        assert_eq!(codes.len(), errors.len());
    }

    // -- Query filters --

    #[test]
    fn query_all_returns_everything() {
        let mut ledger = ledger();
        ledger
            .append(automatic_input(
                "d-1",
                "moon-1",
                GovernanceDecisionType::Promote,
                10,
            ))
            .unwrap();
        ledger
            .append(automatic_input(
                "d-2",
                "moon-2",
                GovernanceDecisionType::Kill,
                20,
            ))
            .unwrap();
        let results = ledger.query(&GovernanceLedgerQuery::all());
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn query_by_decision_type() {
        let mut ledger = ledger();
        ledger
            .append(automatic_input(
                "d-1",
                "moon-1",
                GovernanceDecisionType::Promote,
                10,
            ))
            .unwrap();
        ledger
            .append(automatic_input(
                "d-2",
                "moon-1",
                GovernanceDecisionType::Kill,
                20,
            ))
            .unwrap();
        let q = GovernanceLedgerQuery {
            decision_types: Some(BTreeSet::from([GovernanceDecisionType::Kill])),
            ..GovernanceLedgerQuery::all()
        };
        let results = ledger.query(&q);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision_type, GovernanceDecisionType::Kill);
    }

    #[test]
    fn query_by_time_range() {
        let mut ledger = ledger();
        ledger
            .append(automatic_input(
                "d-1",
                "moon-1",
                GovernanceDecisionType::Promote,
                10,
            ))
            .unwrap();
        ledger
            .append(automatic_input(
                "d-2",
                "moon-1",
                GovernanceDecisionType::Hold,
                100,
            ))
            .unwrap();
        let q = GovernanceLedgerQuery {
            start_time_ns: Some(50),
            ..GovernanceLedgerQuery::all()
        };
        let results = ledger.query(&q);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision_id, "d-2");
    }

    // -- Serde roundtrips --

    #[test]
    fn governance_decision_type_serde_roundtrip() {
        for dt in [
            GovernanceDecisionType::Promote,
            GovernanceDecisionType::Hold,
            GovernanceDecisionType::Kill,
            GovernanceDecisionType::Pause,
            GovernanceDecisionType::Resume,
            GovernanceDecisionType::Override,
        ] {
            let json = serde_json::to_value(dt).unwrap();
            let back: GovernanceDecisionType = serde_json::from_value(json).unwrap();
            assert_eq!(dt, back);
        }
    }

    #[test]
    fn governance_actor_serde_roundtrip() {
        for actor in [
            GovernanceActor::System("gov".to_string()),
            GovernanceActor::Human("operator".to_string()),
        ] {
            let json = serde_json::to_string(&actor).unwrap();
            let back: GovernanceActor = serde_json::from_str(&json).unwrap();
            assert_eq!(actor, back);
        }
    }

    #[test]
    fn governance_ledger_error_serde_roundtrip() {
        let errors: Vec<GovernanceLedgerError> = vec![
            GovernanceLedgerError::InvalidConfig {
                reason: "bad".to_string(),
            },
            GovernanceLedgerError::DuplicateDecisionId {
                decision_id: "d".to_string(),
            },
            GovernanceLedgerError::EmptyLedger,
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let back: GovernanceLedgerError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, back);
        }
    }

    #[test]
    fn governance_rationale_serde_roundtrip() {
        let r = GovernanceRationale::for_automatic_decision(
            "test summary",
            800_000,
            100_000,
            vec!["criterion-a".to_string()],
            vec!["criterion-b".to_string()],
        );
        let json = serde_json::to_string(&r).unwrap();
        let back: GovernanceRationale = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn governance_ledger_entry_serde_roundtrip() {
        let mut ledger = ledger();
        let entry = ledger
            .append(automatic_input(
                "d-1",
                "moon-1",
                GovernanceDecisionType::Promote,
                10,
            ))
            .unwrap();
        let json = serde_json::to_string(&entry).unwrap();
        let back: GovernanceLedgerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    // -- latest_entry / latest_checkpoint --

    #[test]
    fn latest_entry_and_checkpoint_on_empty_ledger() {
        let ledger = ledger();
        assert!(ledger.latest_entry().is_none());
        assert!(ledger.latest_checkpoint().is_none());
    }

    // -- Artifact references are sorted and deduped --

    #[test]
    fn artifact_references_sorted_and_deduped() {
        let mut ledger = ledger();
        let mut input = automatic_input("d-1", "moon-1", GovernanceDecisionType::Promote, 10);
        input.artifact_references = vec![
            "z-ref".to_string(),
            "a-ref".to_string(),
            "a-ref".to_string(),
        ];
        let entry = ledger.append(input).unwrap();
        assert_eq!(entry.artifact_references, vec!["a-ref", "z-ref"]);
    }

    // -- Sequence numbering --

    #[test]
    fn sequence_numbers_are_monotonic() {
        let mut ledger = ledger();
        for i in 1..=5 {
            let entry = ledger
                .append(automatic_input(
                    &format!("d-{i}"),
                    "moon-1",
                    GovernanceDecisionType::Promote,
                    i * 10,
                ))
                .unwrap();
            assert_eq!(entry.sequence, i);
        }
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn governance_decision_type_display_all_distinct() {
        let variants = [
            GovernanceDecisionType::Promote,
            GovernanceDecisionType::Hold,
            GovernanceDecisionType::Kill,
            GovernanceDecisionType::Pause,
            GovernanceDecisionType::Resume,
            GovernanceDecisionType::Override,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn scorecard_snapshot_serde_roundtrip() {
        let snap = ScorecardSnapshot {
            ev_millionths: -500_000,
            confidence_millionths: 800_000,
            risk_of_harm_millionths: 100_000,
            implementation_friction_millionths: 200_000,
            cross_initiative_interference_millionths: 50_000,
            operational_burden_millionths: 75_000,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: ScorecardSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn governance_ledger_config_default_serde_stable() {
        let config = GovernanceLedgerConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: GovernanceLedgerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn governance_ledger_query_serde_roundtrip() {
        let mut types = BTreeSet::new();
        types.insert(GovernanceDecisionType::Kill);
        types.insert(GovernanceDecisionType::Override);
        let query = GovernanceLedgerQuery {
            moonshot_id: Some("moon-1".into()),
            decision_types: Some(types),
            actor_id: Some("admin".into()),
            start_time_ns: Some(100),
            end_time_ns: Some(900),
            override_only: Some(true),
        };
        let json = serde_json::to_string(&query).unwrap();
        let back: GovernanceLedgerQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(query, back);
    }

    #[test]
    fn governance_report_serde_roundtrip() {
        let report = GovernanceReport {
            total_decisions: 10,
            override_count: 2,
            kill_count: 1,
            override_frequency_millionths: 200_000,
            kill_rate_millionths: 100_000,
            mean_time_to_decision_ns: Some(5_000_000),
            portfolio_health_trend: vec![PortfolioHealthPoint {
                window_start_ns: 0,
                window_end_ns: 1000,
                decision_count: 3,
                promote_count: 2,
                hold_count: 0,
                kill_count: 1,
                override_count: 0,
                avg_confidence_millionths: 750_000,
                avg_risk_millionths: 150_000,
            }],
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: GovernanceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn portfolio_health_point_serde_roundtrip() {
        let point = PortfolioHealthPoint {
            window_start_ns: 100,
            window_end_ns: 200,
            decision_count: 5,
            promote_count: 3,
            hold_count: 1,
            kill_count: 1,
            override_count: 0,
            avg_confidence_millionths: 900_000,
            avg_risk_millionths: 50_000,
        };
        let json = serde_json::to_string(&point).unwrap();
        let back: PortfolioHealthPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(point, back);
    }

    #[test]
    fn governance_ledger_checkpoint_serde_roundtrip() {
        let cp = GovernanceLedgerCheckpoint {
            checkpoint_id: "cp-1".into(),
            sequence: 64,
            entry_count: 64,
            head_hash: "abc123".into(),
            timestamp_ns: 9999,
            signature: "sig".into(),
        };
        let json = serde_json::to_string(&cp).unwrap();
        let back: GovernanceLedgerCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(cp, back);
    }

    #[test]
    fn governance_log_event_serde_roundtrip() {
        let event = GovernanceLogEvent {
            trace_id: "t-1".into(),
            decision_id: "d-1".into(),
            policy_id: "pol".into(),
            component: "ledger".into(),
            event: "append".into(),
            outcome: "ok".into(),
            error_code: None,
            timestamp_ns: 42,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: GovernanceLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn governance_ledger_error_is_std_error() {
        let err = GovernanceLedgerError::EmptyLedger;
        let boxed: Box<dyn std::error::Error> = Box::new(err);
        assert!(!boxed.to_string().is_empty());
    }

    #[test]
    fn governance_ledger_query_all_returns_none_filters() {
        let q = GovernanceLedgerQuery::all();
        assert!(q.moonshot_id.is_none());
        assert!(q.decision_types.is_none());
        assert!(q.actor_id.is_none());
        assert!(q.start_time_ns.is_none());
        assert!(q.end_time_ns.is_none());
        assert!(q.override_only.is_none());
    }

    // -- Enrichment: PearlTower 2026-02-27 --

    #[test]
    fn enrichment_governance_rationale_clone_equality() {
        let r = GovernanceRationale {
            summary: "manual override due to incident".to_string(),
            passed_criteria: vec!["crit-a".to_string(), "crit-b".to_string()],
            failed_criteria: vec!["crit-c".to_string()],
            confidence_millionths: 750_000,
            risk_of_harm_millionths: 200_000,
            bypassed_risk_criteria: vec!["risk-1".to_string()],
            acknowledged_bypass: true,
        };
        let cloned = r.clone();
        assert_eq!(r, cloned);
        assert_eq!(r.summary, cloned.summary);
        assert_eq!(r.bypassed_risk_criteria, cloned.bypassed_risk_criteria);
        assert_eq!(r.acknowledged_bypass, cloned.acknowledged_bypass);
    }

    #[test]
    fn enrichment_scorecard_snapshot_clone_equality() {
        let snap = ScorecardSnapshot {
            ev_millionths: -1_000_000,
            confidence_millionths: 0,
            risk_of_harm_millionths: 1_000_000,
            implementation_friction_millionths: 500_000,
            cross_initiative_interference_millionths: 999_999,
            operational_burden_millionths: 1,
        };
        let cloned = snap.clone();
        assert_eq!(snap, cloned);
    }

    #[test]
    fn enrichment_governance_ledger_entry_clone_equality() {
        let mut ledger = ledger();
        let entry = ledger
            .append(automatic_input(
                "ce-1",
                "moon-1",
                GovernanceDecisionType::Promote,
                10,
            ))
            .unwrap();
        let cloned = entry.clone();
        assert_eq!(entry, cloned);
        assert_eq!(entry.entry_hash, cloned.entry_hash);
        assert_eq!(entry.signature, cloned.signature);
        assert_eq!(entry.sequence, cloned.sequence);
    }

    #[test]
    fn enrichment_governance_log_event_clone_equality() {
        let event = GovernanceLogEvent {
            trace_id: "t-99".into(),
            decision_id: "d-99".into(),
            policy_id: "pol-1".into(),
            component: "governance_audit_ledger".into(),
            event: "append_decision".into(),
            outcome: "success".into(),
            error_code: Some("FE-GOV-LED-0001".into()),
            timestamp_ns: 42_000,
        };
        let cloned = event.clone();
        assert_eq!(event, cloned);
        assert_eq!(event.error_code, cloned.error_code);
    }

    #[test]
    fn enrichment_governance_ledger_config_clone_equality() {
        let config = GovernanceLedgerConfig {
            checkpoint_interval: 128,
            signer_key: b"custom-signing-key-bytes".to_vec(),
            policy_id: "my-policy-v2".to_string(),
        };
        let cloned = config.clone();
        assert_eq!(config, cloned);
        assert_eq!(config.signer_key, cloned.signer_key);
    }

    #[test]
    fn enrichment_entry_json_has_required_fields() {
        let mut ledger = ledger();
        let entry = ledger
            .append(automatic_input(
                "json-1",
                "moon-1",
                GovernanceDecisionType::Kill,
                50,
            ))
            .unwrap();
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"sequence\""));
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"moonshot_id\""));
        assert!(json.contains("\"decision_type\""));
        assert!(json.contains("\"entry_hash\""));
        assert!(json.contains("\"signature\""));
        assert!(json.contains("\"is_override\""));
        assert!(json.contains("\"previous_hash\""));
    }

    #[test]
    fn enrichment_rationale_json_has_required_fields() {
        let r = GovernanceRationale::for_automatic_decision(
            "auto decision",
            900_000,
            50_000,
            vec!["pass-1".to_string()],
            vec!["fail-1".to_string()],
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"summary\""));
        assert!(json.contains("\"passed_criteria\""));
        assert!(json.contains("\"failed_criteria\""));
        assert!(json.contains("\"confidence_millionths\""));
        assert!(json.contains("\"risk_of_harm_millionths\""));
        assert!(json.contains("\"bypassed_risk_criteria\""));
        assert!(json.contains("\"acknowledged_bypass\""));
    }

    #[test]
    fn enrichment_checkpoint_json_has_required_fields() {
        let cp = GovernanceLedgerCheckpoint {
            checkpoint_id: "cp-json".into(),
            sequence: 2,
            entry_count: 2,
            head_hash: "deadbeef".into(),
            timestamp_ns: 1000,
            signature: "sig-abc".into(),
        };
        let json = serde_json::to_string(&cp).unwrap();
        assert!(json.contains("\"checkpoint_id\""));
        assert!(json.contains("\"head_hash\""));
        assert!(json.contains("\"entry_count\""));
        assert!(json.contains("\"signature\""));
    }

    #[test]
    fn enrichment_full_ledger_serde_roundtrip() {
        let mut ledger = ledger();
        ledger
            .append(automatic_input(
                "rt-1",
                "moon-1",
                GovernanceDecisionType::Promote,
                10,
            ))
            .unwrap();
        ledger
            .append(automatic_input(
                "rt-2",
                "moon-1",
                GovernanceDecisionType::Hold,
                20,
            ))
            .unwrap();
        ledger.append(override_input("rt-3", 30)).unwrap();
        let json = serde_json::to_string(&ledger).unwrap();
        let back: GovernanceAuditLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(ledger, back);
        assert_eq!(back.entries().len(), 3);
        assert_eq!(back.checkpoints().len(), 1);
        assert!(back.events().len() >= 3);
    }

    #[test]
    fn enrichment_error_display_strings_all_unique() {
        let errors: Vec<GovernanceLedgerError> = vec![
            GovernanceLedgerError::InvalidConfig {
                reason: "x".to_string(),
            },
            GovernanceLedgerError::InvalidInput {
                field: "f".to_string(),
                reason: "r".to_string(),
            },
            GovernanceLedgerError::DuplicateDecisionId {
                decision_id: "d".to_string(),
            },
            GovernanceLedgerError::OutOfOrderTimestamp {
                previous_ns: 100,
                new_ns: 50,
            },
            GovernanceLedgerError::SerializationFailed {
                reason: "json".to_string(),
            },
            GovernanceLedgerError::HashChainMismatch { sequence: 1 },
            GovernanceLedgerError::SignatureMismatch { sequence: 2 },
            GovernanceLedgerError::EntryHashMismatch { sequence: 3 },
            GovernanceLedgerError::EmptyLedger,
        ];
        let display_strings: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(display_strings.len(), errors.len());
    }

    #[test]
    fn enrichment_boundary_confidence_and_risk_at_exact_million() {
        let mut ledger = ledger();
        let mut input =
            automatic_input("boundary-1", "moon-1", GovernanceDecisionType::Promote, 10);
        input.rationale.confidence_millionths = 1_000_000;
        input.rationale.risk_of_harm_millionths = 1_000_000;
        let entry = ledger.append(input).unwrap();
        assert_eq!(entry.rationale.confidence_millionths, 1_000_000);
        assert_eq!(entry.rationale.risk_of_harm_millionths, 1_000_000);

        // Zero boundary
        let mut input2 = automatic_input("boundary-2", "moon-1", GovernanceDecisionType::Hold, 20);
        input2.rationale.confidence_millionths = 0;
        input2.rationale.risk_of_harm_millionths = 0;
        let entry2 = ledger.append(input2).unwrap();
        assert_eq!(entry2.rationale.confidence_millionths, 0);
        assert_eq!(entry2.rationale.risk_of_harm_millionths, 0);
    }

    #[test]
    fn enrichment_governance_decision_type_ord_and_error_source() {
        // Verify Ord derivation works for GovernanceDecisionType
        let mut types = vec![
            GovernanceDecisionType::Override,
            GovernanceDecisionType::Promote,
            GovernanceDecisionType::Kill,
            GovernanceDecisionType::Hold,
            GovernanceDecisionType::Resume,
            GovernanceDecisionType::Pause,
        ];
        types.sort();
        // Just confirm sort does not panic and first < last
        assert!(types[0] <= types[types.len() - 1]);

        // Verify std::error::Error source() returns None (no nested cause)
        let err = GovernanceLedgerError::InvalidConfig {
            reason: "test".to_string(),
        };
        let std_err: &dyn std::error::Error = &err;
        assert!(std_err.source().is_none());
    }
}
