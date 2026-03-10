#![forbid(unsafe_code)]

//! Law promotion lifecycle: orchestrates the end-to-end flow from
//! proof/refutation pipeline results to durable runtime asset promotion,
//! with lifecycle management (revocation, supersession, expiration).
//!
//! Bead: bd-1lsy.9.10.3 [RGC-810C]
//!
//! This module connects the `law_proof_refutation` pipeline output
//! to the `law_promotion_pack` pipeline, handling the conversion of
//! accepted candidates into `AcceptedLaw` instances, routing them to
//! appropriate promotion targets based on candidate kind and strength,
//! and managing the full lifecycle (promote → revoke/supersede/expire).
//!
//! # Design decisions
//!
//! - Routing is deterministic: `Invariant` laws go to all four targets,
//!   `SideCondition` laws go to rewrite packs and support atlases,
//!   and `NormalForm` laws go to synthesis lanes and frontier ledgers.
//! - Lifecycle events are content-addressed and create audit records.
//! - Revocation and supersession propagate to all promotion receipts
//!   for the affected law.
//! - Expiration is epoch-based with a configurable window.
//! - All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::law_mining::{CandidateKind, LawCandidate};
use crate::law_promotion_pack::{
    AcceptedLaw, LawStrength, PromotionPipeline, PromotionTarget,
};
use crate::law_proof_refutation::{ProofCampaignResult, ProofRefutationPipeline, ProofVerdict};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the law promotion lifecycle module.
pub const LAW_PROMOTION_LIFECYCLE_SCHEMA_VERSION: &str =
    "franken-engine.law-promotion-lifecycle.v1";

/// Bead identifier for this module.
pub const LAW_PROMOTION_LIFECYCLE_BEAD_ID: &str = "bd-1lsy.9.10.3";

/// Component name.
pub const COMPONENT: &str = "law_promotion_lifecycle";

/// One million — the unit for fixed-point millionths arithmetic.
const MILLION: u64 = 1_000_000;

/// Default expiration window (10 epochs).
const DEFAULT_EXPIRATION_WINDOW: u64 = 10;

/// Default minimum strength for auto-promotion.
const DEFAULT_MIN_AUTO_STRENGTH: LawStrength = LawStrength::Conditional;

/// Default minimum confidence for auto-promotion (millionths).
const DEFAULT_MIN_AUTO_CONFIDENCE_MILLIONTHS: u64 = 800_000;

// ---------------------------------------------------------------------------
// LifecycleEventKind
// ---------------------------------------------------------------------------

/// Kind of lifecycle event applied to a promoted law.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleEventKind {
    /// Law was promoted into one or more target assets.
    Promoted,
    /// Law was revoked due to regression or new counterexample.
    Revoked,
    /// Law was superseded by a stronger or more general law.
    Superseded,
    /// Law expired because its epoch window lapsed.
    Expired,
    /// Promotion was attempted but routing policy refused it.
    Refused,
}

impl LifecycleEventKind {
    /// All event kinds in canonical order.
    pub const ALL: &[Self] = &[
        Self::Promoted,
        Self::Revoked,
        Self::Superseded,
        Self::Expired,
        Self::Refused,
    ];

    /// Whether this event terminates the law's active lifecycle.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked | Self::Superseded | Self::Expired)
    }
}

impl fmt::Display for LifecycleEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Promoted => "promoted",
            Self::Revoked => "revoked",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Refused => "refused",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// RefusalReason
// ---------------------------------------------------------------------------

/// Why a law was refused for promotion.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// Strength is below the minimum threshold.
    InsufficientStrength {
        actual: LawStrength,
        minimum: LawStrength,
    },
    /// Confidence is below the minimum threshold.
    InsufficientConfidence {
        actual_millionths: u64,
        minimum_millionths: u64,
    },
    /// Law was already revoked.
    PreviouslyRevoked { law_id: String },
    /// Law is a duplicate of an already-promoted law.
    DuplicateLaw { existing_law_id: String },
    /// No valid promotion targets for this candidate kind.
    NoValidTargets { kind: CandidateKind },
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientStrength { actual, minimum } => {
                write!(f, "strength {actual} below minimum {minimum}")
            }
            Self::InsufficientConfidence {
                actual_millionths,
                minimum_millionths,
            } => write!(
                f,
                "confidence {actual_millionths} below minimum {minimum_millionths}"
            ),
            Self::PreviouslyRevoked { law_id } => {
                write!(f, "law {law_id} was previously revoked")
            }
            Self::DuplicateLaw { existing_law_id } => {
                write!(f, "duplicate of existing law {existing_law_id}")
            }
            Self::NoValidTargets { kind } => {
                write!(f, "no valid targets for candidate kind {kind:?}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// LifecycleEvent
// ---------------------------------------------------------------------------

/// A lifecycle event recording a state transition for a promoted law.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleEvent {
    /// Unique event ID.
    pub event_id: String,
    /// The law this event applies to.
    pub law_id: String,
    /// Kind of event.
    pub kind: LifecycleEventKind,
    /// Targets affected by this event.
    pub affected_targets: Vec<PromotionTarget>,
    /// Human-readable rationale.
    pub rationale: String,
    /// If superseded, the ID of the superseding law.
    pub superseding_law_id: Option<String>,
    /// If refused, the reason.
    pub refusal_reason: Option<RefusalReason>,
    /// Epoch when this event occurred.
    pub event_epoch: SecurityEpoch,
    /// Content hash.
    pub event_hash: ContentHash,
}

impl LifecycleEvent {
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.event_id.as_bytes());
        data.extend_from_slice(self.law_id.as_bytes());
        data.extend_from_slice(format!("{:?}", self.kind).as_bytes());
        for target in &self.affected_targets {
            data.extend_from_slice(format!("{target:?}").as_bytes());
        }
        data.extend_from_slice(self.rationale.as_bytes());
        if let Some(ref sid) = self.superseding_law_id {
            data.extend_from_slice(sid.as_bytes());
        }
        if let Some(ref reason) = self.refusal_reason {
            data.extend_from_slice(reason.to_string().as_bytes());
        }
        data.extend_from_slice(&self.event_epoch.as_u64().to_le_bytes());
        self.event_hash = ContentHash::compute(&data);
    }
}

impl fmt::Display for LifecycleEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LifecycleEvent({} law={} kind={} targets={})",
            self.event_id,
            self.law_id,
            self.kind,
            self.affected_targets.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// LifecycleConfig
// ---------------------------------------------------------------------------

/// Configuration for the law promotion lifecycle pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleConfig {
    /// Minimum strength required for auto-promotion.
    pub min_auto_strength: LawStrength,
    /// Minimum confidence for auto-promotion (millionths).
    pub min_auto_confidence_millionths: u64,
    /// Epoch window after which a promotion expires.
    pub expiration_window_epochs: u64,
    /// Whether to auto-route based on candidate kind.
    pub auto_route_by_kind: bool,
    /// Whether to allow promotion of heuristic-strength laws.
    pub allow_heuristic: bool,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            min_auto_strength: DEFAULT_MIN_AUTO_STRENGTH,
            min_auto_confidence_millionths: DEFAULT_MIN_AUTO_CONFIDENCE_MILLIONTHS,
            expiration_window_epochs: DEFAULT_EXPIRATION_WINDOW,
            auto_route_by_kind: true,
            allow_heuristic: false,
        }
    }
}

// ---------------------------------------------------------------------------
// RoutingDecision
// ---------------------------------------------------------------------------

/// The result of routing an accepted law to promotion targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingDecision {
    /// The law being routed.
    pub law_id: String,
    /// Candidate kind that drove the routing.
    pub candidate_kind: CandidateKind,
    /// Targets selected for this law.
    pub selected_targets: Vec<PromotionTarget>,
    /// Priority score for this law (millionths).
    pub priority_millionths: u64,
    /// Content hash.
    pub decision_hash: ContentHash,
}

impl RoutingDecision {
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.law_id.as_bytes());
        data.extend_from_slice(format!("{:?}", self.candidate_kind).as_bytes());
        for target in &self.selected_targets {
            data.extend_from_slice(format!("{target:?}").as_bytes());
        }
        data.extend_from_slice(&self.priority_millionths.to_le_bytes());
        self.decision_hash = ContentHash::compute(&data);
    }
}

impl fmt::Display for RoutingDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RoutingDecision(law={} kind={:?} targets={})",
            self.law_id,
            self.candidate_kind,
            self.selected_targets.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// LifecycleError
// ---------------------------------------------------------------------------

/// Errors from the lifecycle pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleError {
    /// Law not found in the pipeline.
    LawNotFound { law_id: String },
    /// Law already promoted.
    AlreadyPromoted { law_id: String },
    /// Law already revoked.
    AlreadyRevoked { law_id: String },
    /// Invalid configuration.
    InvalidConfig { detail: String },
    /// Promotion pipeline error.
    PromotionError { detail: String },
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LawNotFound { law_id } => write!(f, "law not found: {law_id}"),
            Self::AlreadyPromoted { law_id } => write!(f, "already promoted: {law_id}"),
            Self::AlreadyRevoked { law_id } => write!(f, "already revoked: {law_id}"),
            Self::InvalidConfig { detail } => write!(f, "invalid config: {detail}"),
            Self::PromotionError { detail } => write!(f, "promotion error: {detail}"),
        }
    }
}

// ---------------------------------------------------------------------------
// LifecycleSummary
// ---------------------------------------------------------------------------

/// Summary of lifecycle pipeline execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleSummary {
    /// Total accepted laws considered.
    pub total_accepted: usize,
    /// Laws successfully promoted.
    pub promoted_count: usize,
    /// Laws refused for promotion.
    pub refused_count: usize,
    /// Laws revoked during this lifecycle run.
    pub revoked_count: usize,
    /// Laws superseded during this lifecycle run.
    pub superseded_count: usize,
    /// Laws expired during this lifecycle run.
    pub expired_count: usize,
    /// Total promotion receipts issued.
    pub total_receipts: usize,
    /// Breakdown by promotion target.
    pub receipts_by_target: Vec<TargetBreakdown>,
    /// Mean promotion priority across promoted laws (millionths).
    pub mean_priority_millionths: u64,
}

/// Breakdown of receipts per promotion target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetBreakdown {
    /// The promotion target.
    pub target: PromotionTarget,
    /// Number of receipts for this target.
    pub receipt_count: usize,
    /// Number of currently active receipts.
    pub active_count: usize,
}

// ---------------------------------------------------------------------------
// LifecyclePipeline
// ---------------------------------------------------------------------------

/// Orchestrates the full law promotion lifecycle from proof results
/// through promotion, revocation, supersession, and expiration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecyclePipeline {
    /// Schema version.
    pub schema_version: String,
    /// Bead identifier.
    pub bead_id: String,
    /// Configuration.
    pub config: LifecycleConfig,
    /// Accepted laws converted from proof results.
    pub accepted_laws: Vec<AcceptedLaw>,
    /// Routing decisions for each accepted law.
    pub routing_decisions: Vec<RoutingDecision>,
    /// Lifecycle events (audit log).
    pub lifecycle_events: Vec<LifecycleEvent>,
    /// The underlying promotion pipeline.
    pub promotion_pipeline: PromotionPipeline,
    /// IDs of revoked laws.
    pub revoked_law_ids: BTreeSet<String>,
    /// IDs of superseded laws.
    pub superseded_law_ids: BTreeSet<String>,
    /// IDs of expired laws.
    pub expired_law_ids: BTreeSet<String>,
    /// Current epoch.
    pub pipeline_epoch: SecurityEpoch,
    /// Content hash.
    pub pipeline_hash: ContentHash,
}

impl LifecyclePipeline {
    /// Create a new lifecycle pipeline.
    pub fn new(config: LifecycleConfig, epoch: SecurityEpoch) -> Self {
        let mut pipeline = Self {
            schema_version: LAW_PROMOTION_LIFECYCLE_SCHEMA_VERSION.to_string(),
            bead_id: LAW_PROMOTION_LIFECYCLE_BEAD_ID.to_string(),
            config,
            accepted_laws: Vec::new(),
            routing_decisions: Vec::new(),
            lifecycle_events: Vec::new(),
            promotion_pipeline: PromotionPipeline::new("lifecycle-auto", epoch),
            revoked_law_ids: BTreeSet::new(),
            superseded_law_ids: BTreeSet::new(),
            expired_law_ids: BTreeSet::new(),
            pipeline_epoch: epoch,
            pipeline_hash: ContentHash::compute(b"lifecycle_pipeline"),
        };
        pipeline.recompute_hash();
        pipeline
    }

    /// Convert a proof campaign result and its original candidate into an
    /// `AcceptedLaw`, or return a refusal reason.
    pub fn convert_to_accepted_law(
        &self,
        candidate: &LawCandidate,
        result: &ProofCampaignResult,
    ) -> Result<AcceptedLaw, RefusalReason> {
        if !result.accepted {
            return Err(RefusalReason::InsufficientConfidence {
                actual_millionths: result.aggregate_confidence_millionths,
                minimum_millionths: self.config.min_auto_confidence_millionths,
            });
        }

        let strength = verdict_to_strength(result);

        if !self.config.allow_heuristic && strength == LawStrength::Heuristic {
            return Err(RefusalReason::InsufficientStrength {
                actual: strength,
                minimum: self.config.min_auto_strength,
            });
        }

        if strength < self.config.min_auto_strength {
            return Err(RefusalReason::InsufficientStrength {
                actual: strength,
                minimum: self.config.min_auto_strength,
            });
        }

        // Check for duplicates
        for existing in &self.accepted_laws {
            if existing.candidate_id == candidate.candidate_id {
                return Err(RefusalReason::DuplicateLaw {
                    existing_law_id: existing.law_id.clone(),
                });
            }
        }

        // Check for revoked
        let law_id = format!("law-{}", candidate.candidate_id);
        if self.revoked_law_ids.contains(&law_id) {
            return Err(RefusalReason::PreviouslyRevoked {
                law_id: law_id.clone(),
            });
        }

        let evidence_ids: Vec<String> = result
            .attempts
            .iter()
            .map(|a| a.attempt_id.clone())
            .collect();

        Ok(AcceptedLaw::new(
            &law_id,
            &candidate.candidate_id,
            &candidate.statement,
            strength,
            candidate
                .supporting_source_ids
                .iter()
                .cloned()
                .collect(),
            candidate.rank_millionths,
            self.pipeline_epoch,
            evidence_ids,
        ))
    }

    /// Route an accepted law to promotion targets based on its candidate kind.
    pub fn route_law(
        &self,
        law: &AcceptedLaw,
        candidate_kind: CandidateKind,
    ) -> RoutingDecision {
        let selected_targets = if self.config.auto_route_by_kind {
            targets_for_kind(candidate_kind)
        } else {
            PromotionTarget::ALL.to_vec()
        };

        let mut decision = RoutingDecision {
            law_id: law.law_id.clone(),
            candidate_kind,
            selected_targets,
            priority_millionths: law.promotion_priority_millionths(),
            decision_hash: ContentHash::compute(b"routing_decision"),
        };
        decision.recompute_hash();
        decision
    }

    /// Promote a single accepted law through the full lifecycle.
    /// Returns the lifecycle event (Promoted or Refused).
    pub fn promote_law(
        &mut self,
        candidate: &LawCandidate,
        result: &ProofCampaignResult,
    ) -> LifecycleEvent {
        let event_id = format!("evt-{}-{}", self.lifecycle_events.len(), candidate.candidate_id);

        match self.convert_to_accepted_law(candidate, result) {
            Ok(law) => {
                let routing = self.route_law(&law, candidate.kind);
                let targets = routing.selected_targets.clone();

                // Execute promotions via the underlying pipeline
                for target in &targets {
                    match target {
                        PromotionTarget::RewritePack => {
                            let pattern = format!("match:{}", law.statement);
                            let replacement = format!("opt:{}", law.statement);
                            self.promotion_pipeline.promote_to_rewrite(
                                &law,
                                &pattern,
                                &replacement,
                                "auto-guard",
                                law.promotion_priority_millionths(),
                            );
                        }
                        PromotionTarget::SynthesisLane => {
                            let template = format!("synth:{}", law.statement);
                            self.promotion_pipeline.promote_to_synthesis(
                                &law,
                                &template,
                                vec!["param0".to_string()],
                                "expected-pattern",
                            );
                        }
                        PromotionTarget::SupportAtlas => {
                            let domain = format!("domain:{}", law.candidate_id);
                            self.promotion_pipeline.promote_to_atlas(
                                &law,
                                &domain,
                                law.promotion_priority_millionths(),
                            );
                        }
                        PromotionTarget::FrontierLedger => {
                            let region = format!("frontier:{}", law.candidate_id);
                            self.promotion_pipeline.promote_to_frontier(
                                &law,
                                &region,
                                law.promotion_priority_millionths(),
                            );
                        }
                    }
                }

                self.routing_decisions.push(routing);
                self.accepted_laws.push(law.clone());

                let mut event = LifecycleEvent {
                    event_id,
                    law_id: law.law_id.clone(),
                    kind: LifecycleEventKind::Promoted,
                    affected_targets: targets,
                    rationale: format!(
                        "auto-promoted with priority {}",
                        law.promotion_priority_millionths()
                    ),
                    superseding_law_id: None,
                    refusal_reason: None,
                    event_epoch: self.pipeline_epoch,
                    event_hash: ContentHash::compute(b"event"),
                };
                event.recompute_hash();
                self.lifecycle_events.push(event.clone());
                self.recompute_hash();
                event
            }
            Err(reason) => {
                let mut event = LifecycleEvent {
                    event_id,
                    law_id: format!("law-{}", candidate.candidate_id),
                    kind: LifecycleEventKind::Refused,
                    affected_targets: Vec::new(),
                    rationale: format!("refused: {reason}"),
                    superseding_law_id: None,
                    refusal_reason: Some(reason),
                    event_epoch: self.pipeline_epoch,
                    event_hash: ContentHash::compute(b"event"),
                };
                event.recompute_hash();
                self.lifecycle_events.push(event.clone());
                self.recompute_hash();
                event
            }
        }
    }

    /// Promote all accepted candidates from a proof/refutation pipeline
    /// and their original candidates.
    pub fn promote_batch(
        &mut self,
        candidates: &[LawCandidate],
        pipeline: &ProofRefutationPipeline,
    ) {
        for candidate in candidates {
            if let Some(result) = pipeline.result_for(&candidate.candidate_id) {
                self.promote_law(candidate, result);
            }
        }
        self.recompute_hash();
    }

    /// Revoke a promoted law, marking all its receipts as revoked.
    pub fn revoke_law(&mut self, law_id: &str, reason: &str) -> Option<LifecycleEvent> {
        if !self.accepted_laws.iter().any(|l| l.law_id == law_id) {
            return None;
        }
        if self.revoked_law_ids.contains(law_id) {
            return None;
        }

        self.revoked_law_ids.insert(law_id.to_string());

        // Update all receipts for this law
        let affected_targets: Vec<PromotionTarget> = self
            .promotion_pipeline
            .receipts
            .iter()
            .filter(|r| r.law_id == law_id && r.status.is_active())
            .map(|r| r.target)
            .collect();

        for receipt in &mut self.promotion_pipeline.receipts {
            if receipt.law_id == law_id && receipt.status.is_active() {
                receipt.revoke(reason);
            }
        }

        let event_id = format!("evt-{}-revoke-{law_id}", self.lifecycle_events.len());
        let mut event = LifecycleEvent {
            event_id,
            law_id: law_id.to_string(),
            kind: LifecycleEventKind::Revoked,
            affected_targets,
            rationale: format!("revoked: {reason}"),
            superseding_law_id: None,
            refusal_reason: None,
            event_epoch: self.pipeline_epoch,
            event_hash: ContentHash::compute(b"event"),
        };
        event.recompute_hash();
        self.lifecycle_events.push(event.clone());
        self.recompute_hash();
        Some(event)
    }

    /// Supersede a law with a stronger law.
    pub fn supersede_law(
        &mut self,
        old_law_id: &str,
        new_law_id: &str,
        reason: &str,
    ) -> Option<LifecycleEvent> {
        if !self.accepted_laws.iter().any(|l| l.law_id == old_law_id) {
            return None;
        }
        if self.superseded_law_ids.contains(old_law_id) {
            return None;
        }

        self.superseded_law_ids.insert(old_law_id.to_string());

        let affected_targets: Vec<PromotionTarget> = self
            .promotion_pipeline
            .receipts
            .iter()
            .filter(|r| r.law_id == old_law_id && r.status.is_active())
            .map(|r| r.target)
            .collect();

        for receipt in &mut self.promotion_pipeline.receipts {
            if receipt.law_id == old_law_id && receipt.status.is_active() {
                receipt.supersede(new_law_id);
            }
        }

        let event_id = format!("evt-{}-supersede-{old_law_id}", self.lifecycle_events.len());
        let mut event = LifecycleEvent {
            event_id,
            law_id: old_law_id.to_string(),
            kind: LifecycleEventKind::Superseded,
            affected_targets,
            rationale: format!("superseded by {new_law_id}: {reason}"),
            superseding_law_id: Some(new_law_id.to_string()),
            refusal_reason: None,
            event_epoch: self.pipeline_epoch,
            event_hash: ContentHash::compute(b"event"),
        };
        event.recompute_hash();
        self.lifecycle_events.push(event.clone());
        self.recompute_hash();
        Some(event)
    }

    /// Expire laws whose acceptance epoch is older than the expiration window.
    pub fn expire_stale_laws(&mut self, current_epoch: SecurityEpoch) -> Vec<LifecycleEvent> {
        let mut events = Vec::new();
        let window = self.config.expiration_window_epochs;

        let expired_ids: Vec<String> = self
            .accepted_laws
            .iter()
            .filter(|law| {
                let age = current_epoch.as_u64().saturating_sub(law.accepted_epoch.as_u64());
                age > window
                    && !self.revoked_law_ids.contains(&law.law_id)
                    && !self.superseded_law_ids.contains(&law.law_id)
                    && !self.expired_law_ids.contains(&law.law_id)
            })
            .map(|law| law.law_id.clone())
            .collect();

        for law_id in &expired_ids {
            self.expired_law_ids.insert(law_id.clone());

            let affected_targets: Vec<PromotionTarget> = self
                .promotion_pipeline
                .receipts
                .iter()
                .filter(|r| r.law_id == *law_id && r.status.is_active())
                .map(|r| r.target)
                .collect();

            for receipt in &mut self.promotion_pipeline.receipts {
                if receipt.law_id == *law_id && receipt.status.is_active() {
                    receipt.revoke("epoch expired");
                }
            }

            let event_id = format!("evt-{}-expire-{law_id}", self.lifecycle_events.len());
            let mut event = LifecycleEvent {
                event_id,
                law_id: law_id.clone(),
                kind: LifecycleEventKind::Expired,
                affected_targets,
                rationale: format!("expired after {window} epochs"),
                superseding_law_id: None,
                refusal_reason: None,
                event_epoch: current_epoch,
                event_hash: ContentHash::compute(b"event"),
            };
            event.recompute_hash();
            events.push(event.clone());
            self.lifecycle_events.push(event);
        }

        self.recompute_hash();
        events
    }

    /// Get all currently active law IDs (promoted and not revoked/superseded/expired).
    pub fn active_law_ids(&self) -> Vec<&str> {
        self.accepted_laws
            .iter()
            .filter(|law| {
                !self.revoked_law_ids.contains(&law.law_id)
                    && !self.superseded_law_ids.contains(&law.law_id)
                    && !self.expired_law_ids.contains(&law.law_id)
            })
            .map(|law| law.law_id.as_str())
            .collect()
    }

    /// Get events for a specific law.
    pub fn events_for(&self, law_id: &str) -> Vec<&LifecycleEvent> {
        self.lifecycle_events
            .iter()
            .filter(|e| e.law_id == law_id)
            .collect()
    }

    /// Get the routing decision for a specific law.
    pub fn routing_for(&self, law_id: &str) -> Option<&RoutingDecision> {
        self.routing_decisions
            .iter()
            .find(|r| r.law_id == law_id)
    }

    /// Generate a summary report of the lifecycle pipeline.
    pub fn summary_report(&self) -> LifecycleSummary {
        let promoted_count = self
            .lifecycle_events
            .iter()
            .filter(|e| e.kind == LifecycleEventKind::Promoted)
            .count();
        let refused_count = self
            .lifecycle_events
            .iter()
            .filter(|e| e.kind == LifecycleEventKind::Refused)
            .count();
        let revoked_count = self.revoked_law_ids.len();
        let superseded_count = self.superseded_law_ids.len();
        let expired_count = self.expired_law_ids.len();

        let total_receipts = self.promotion_pipeline.receipts.len();

        let mut receipts_by_target = Vec::new();
        for target in PromotionTarget::ALL {
            let receipt_count = self
                .promotion_pipeline
                .receipts
                .iter()
                .filter(|r| r.target == *target)
                .count();
            let active_count = self
                .promotion_pipeline
                .receipts
                .iter()
                .filter(|r| r.target == *target && r.status.is_active())
                .count();
            receipts_by_target.push(TargetBreakdown {
                target: *target,
                receipt_count,
                active_count,
            });
        }

        let priorities: Vec<u64> = self
            .accepted_laws
            .iter()
            .filter(|l| !self.revoked_law_ids.contains(&l.law_id))
            .map(|l| l.promotion_priority_millionths())
            .collect();
        let mean_priority_millionths = if priorities.is_empty() {
            0
        } else {
            priorities.iter().sum::<u64>().checked_div(priorities.len() as u64).unwrap_or(0)
        };

        LifecycleSummary {
            total_accepted: self.accepted_laws.len(),
            promoted_count,
            refused_count,
            revoked_count,
            superseded_count,
            expired_count,
            total_receipts,
            receipts_by_target,
            mean_priority_millionths,
        }
    }

    /// Recompute the content hash.
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.schema_version.as_bytes());
        data.extend_from_slice(self.bead_id.as_bytes());
        for law in &self.accepted_laws {
            data.extend_from_slice(law.law_hash.as_bytes());
        }
        for decision in &self.routing_decisions {
            data.extend_from_slice(decision.decision_hash.as_bytes());
        }
        for event in &self.lifecycle_events {
            data.extend_from_slice(event.event_hash.as_bytes());
        }
        data.extend_from_slice(self.promotion_pipeline.pipeline_hash.as_bytes());
        for id in &self.revoked_law_ids {
            data.extend_from_slice(id.as_bytes());
        }
        for id in &self.superseded_law_ids {
            data.extend_from_slice(id.as_bytes());
        }
        for id in &self.expired_law_ids {
            data.extend_from_slice(id.as_bytes());
        }
        data.extend_from_slice(&self.pipeline_epoch.as_u64().to_le_bytes());
        self.pipeline_hash = ContentHash::compute(&data);
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Map a proof verdict + confidence to a law strength tier.
fn verdict_to_strength(result: &ProofCampaignResult) -> LawStrength {
    match result.final_verdict {
        ProofVerdict::Proved => {
            if result.aggregate_confidence_millionths >= 950_000 {
                LawStrength::Proved
            } else if result.aggregate_confidence_millionths >= 800_000 {
                LawStrength::Empirical
            } else {
                LawStrength::Conditional
            }
        }
        ProofVerdict::Inconclusive => {
            if result.aggregate_confidence_millionths >= 600_000 {
                LawStrength::Conditional
            } else {
                LawStrength::Heuristic
            }
        }
        ProofVerdict::Refuted => LawStrength::Heuristic,
    }
}

/// Determine which promotion targets are appropriate for a given candidate kind.
fn targets_for_kind(kind: CandidateKind) -> Vec<PromotionTarget> {
    match kind {
        CandidateKind::Invariant => PromotionTarget::ALL.to_vec(),
        CandidateKind::SideCondition => vec![
            PromotionTarget::RewritePack,
            PromotionTarget::SupportAtlas,
        ],
        CandidateKind::NormalForm => vec![
            PromotionTarget::SynthesisLane,
            PromotionTarget::FrontierLedger,
        ],
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::law_mining::LawCandidate;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn test_candidate(id: &str, kind: CandidateKind) -> LawCandidate {
        let mut c = LawCandidate {
            candidate_id: id.to_string(),
            kind,
            statement: format!("law-statement-{id}"),
            rank_millionths: 750_000,
            ranking_rationale: format!("rationale-{id}"),
            scope_hypothesis_id: format!("scope-{id}"),
            provenance_id: format!("prov-{id}"),
            supporting_source_ids: vec![format!("src-{id}")],
            candidate_hash: ContentHash::compute(b"placeholder"),
        };
        c.recompute_hash();
        c
    }

    fn accepted_result(candidate_id: &str, kind: CandidateKind) -> ProofCampaignResult {
        let mut r = ProofCampaignResult {
            candidate_id: candidate_id.to_string(),
            candidate_kind: kind,
            final_verdict: ProofVerdict::Proved,
            aggregate_confidence_millionths: 950_000,
            attempts: Vec::new(),
            refutation_witness_ids: Vec::new(),
            accepted: true,
            rationale: "proved with high confidence".to_string(),
            campaign_epoch: epoch(10),
            result_hash: ContentHash::compute(b"result"),
        };
        r.recompute_hash();
        r
    }

    fn rejected_result(candidate_id: &str, kind: CandidateKind) -> ProofCampaignResult {
        let mut r = ProofCampaignResult {
            candidate_id: candidate_id.to_string(),
            candidate_kind: kind,
            final_verdict: ProofVerdict::Refuted,
            aggregate_confidence_millionths: 200_000,
            attempts: Vec::new(),
            refutation_witness_ids: Vec::new(),
            accepted: false,
            rationale: "refuted by counterexample".to_string(),
            campaign_epoch: epoch(10),
            result_hash: ContentHash::compute(b"result"),
        };
        r.recompute_hash();
        r
    }

    // -----------------------------------------------------------------------
    // LifecycleEventKind tests
    // -----------------------------------------------------------------------

    #[test]
    fn event_kind_all_unique() {
        let mut seen = BTreeSet::new();
        for k in LifecycleEventKind::ALL {
            assert!(seen.insert(k.to_string()), "duplicate kind: {k}");
        }
    }

    #[test]
    fn event_kind_display_matches_serde() {
        for k in LifecycleEventKind::ALL {
            let json = serde_json::to_string(k).unwrap();
            let display = k.to_string();
            assert_eq!(json, format!("\"{display}\""));
        }
    }

    #[test]
    fn event_kind_terminal() {
        assert!(!LifecycleEventKind::Promoted.is_terminal());
        assert!(LifecycleEventKind::Revoked.is_terminal());
        assert!(LifecycleEventKind::Superseded.is_terminal());
        assert!(LifecycleEventKind::Expired.is_terminal());
        assert!(!LifecycleEventKind::Refused.is_terminal());
    }

    // -----------------------------------------------------------------------
    // RefusalReason tests
    // -----------------------------------------------------------------------

    #[test]
    fn refusal_reason_display_unique() {
        let reasons = vec![
            RefusalReason::InsufficientStrength {
                actual: LawStrength::Heuristic,
                minimum: LawStrength::Conditional,
            },
            RefusalReason::InsufficientConfidence {
                actual_millionths: 500_000,
                minimum_millionths: 800_000,
            },
            RefusalReason::PreviouslyRevoked {
                law_id: "law-1".to_string(),
            },
            RefusalReason::DuplicateLaw {
                existing_law_id: "law-2".to_string(),
            },
            RefusalReason::NoValidTargets {
                kind: CandidateKind::Invariant,
            },
        ];
        let displays: Vec<_> = reasons.iter().map(|r| r.to_string()).collect();
        let unique: BTreeSet<_> = displays.iter().collect();
        assert_eq!(displays.len(), unique.len());
    }

    #[test]
    fn refusal_reason_serde_roundtrip() {
        let reasons = vec![
            RefusalReason::InsufficientStrength {
                actual: LawStrength::Heuristic,
                minimum: LawStrength::Conditional,
            },
            RefusalReason::PreviouslyRevoked {
                law_id: "law-1".to_string(),
            },
        ];
        for r in &reasons {
            let json = serde_json::to_string(r).unwrap();
            let back: RefusalReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*r, back);
        }
    }

    // -----------------------------------------------------------------------
    // LifecycleError tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_unique() {
        let errors = vec![
            LifecycleError::LawNotFound {
                law_id: "a".to_string(),
            },
            LifecycleError::AlreadyPromoted {
                law_id: "b".to_string(),
            },
            LifecycleError::AlreadyRevoked {
                law_id: "c".to_string(),
            },
            LifecycleError::InvalidConfig {
                detail: "d".to_string(),
            },
            LifecycleError::PromotionError {
                detail: "e".to_string(),
            },
        ];
        let displays: Vec<_> = errors.iter().map(|e| e.to_string()).collect();
        let unique: BTreeSet<_> = displays.iter().collect();
        assert_eq!(displays.len(), unique.len());
    }

    #[test]
    fn error_serde_roundtrip() {
        for err in [
            LifecycleError::LawNotFound {
                law_id: "x".to_string(),
            },
            LifecycleError::AlreadyPromoted {
                law_id: "y".to_string(),
            },
            LifecycleError::InvalidConfig {
                detail: "z".to_string(),
            },
        ] {
            let json = serde_json::to_string(&err).unwrap();
            let back: LifecycleError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, back);
        }
    }

    // -----------------------------------------------------------------------
    // verdict_to_strength tests
    // -----------------------------------------------------------------------

    #[test]
    fn verdict_strength_proved_high_confidence() {
        let r = accepted_result("c1", CandidateKind::Invariant);
        assert_eq!(verdict_to_strength(&r), LawStrength::Proved);
    }

    #[test]
    fn verdict_strength_proved_medium_confidence() {
        let mut r = accepted_result("c1", CandidateKind::Invariant);
        r.aggregate_confidence_millionths = 850_000;
        assert_eq!(verdict_to_strength(&r), LawStrength::Empirical);
    }

    #[test]
    fn verdict_strength_proved_low_confidence() {
        let mut r = accepted_result("c1", CandidateKind::Invariant);
        r.aggregate_confidence_millionths = 700_000;
        assert_eq!(verdict_to_strength(&r), LawStrength::Conditional);
    }

    #[test]
    fn verdict_strength_inconclusive_high() {
        let mut r = accepted_result("c1", CandidateKind::Invariant);
        r.final_verdict = ProofVerdict::Inconclusive;
        r.aggregate_confidence_millionths = 650_000;
        assert_eq!(verdict_to_strength(&r), LawStrength::Conditional);
    }

    #[test]
    fn verdict_strength_inconclusive_low() {
        let mut r = accepted_result("c1", CandidateKind::Invariant);
        r.final_verdict = ProofVerdict::Inconclusive;
        r.aggregate_confidence_millionths = 400_000;
        assert_eq!(verdict_to_strength(&r), LawStrength::Heuristic);
    }

    #[test]
    fn verdict_strength_refuted() {
        let r = rejected_result("c1", CandidateKind::Invariant);
        assert_eq!(verdict_to_strength(&r), LawStrength::Heuristic);
    }

    // -----------------------------------------------------------------------
    // targets_for_kind tests
    // -----------------------------------------------------------------------

    #[test]
    fn routing_invariant_all_targets() {
        let targets = targets_for_kind(CandidateKind::Invariant);
        assert_eq!(targets.len(), 4);
    }

    #[test]
    fn routing_side_condition_rewrite_and_atlas() {
        let targets = targets_for_kind(CandidateKind::SideCondition);
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&PromotionTarget::RewritePack));
        assert!(targets.contains(&PromotionTarget::SupportAtlas));
    }

    #[test]
    fn routing_normal_form_synthesis_and_frontier() {
        let targets = targets_for_kind(CandidateKind::NormalForm);
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&PromotionTarget::SynthesisLane));
        assert!(targets.contains(&PromotionTarget::FrontierLedger));
    }

    // -----------------------------------------------------------------------
    // LifecycleConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn config_default_values() {
        let config = LifecycleConfig::default();
        assert_eq!(config.min_auto_strength, LawStrength::Conditional);
        assert_eq!(config.min_auto_confidence_millionths, 800_000);
        assert_eq!(config.expiration_window_epochs, 10);
        assert!(config.auto_route_by_kind);
        assert!(!config.allow_heuristic);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = LifecycleConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: LifecycleConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // -----------------------------------------------------------------------
    // LifecyclePipeline tests
    // -----------------------------------------------------------------------

    #[test]
    fn pipeline_new_empty() {
        let p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        assert!(p.accepted_laws.is_empty());
        assert!(p.routing_decisions.is_empty());
        assert!(p.lifecycle_events.is_empty());
        assert!(p.revoked_law_ids.is_empty());
    }

    #[test]
    fn pipeline_promote_single_invariant() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let c = test_candidate("inv-1", CandidateKind::Invariant);
        let r = accepted_result("inv-1", CandidateKind::Invariant);

        let event = p.promote_law(&c, &r);
        assert_eq!(event.kind, LifecycleEventKind::Promoted);
        assert_eq!(event.affected_targets.len(), 4); // Invariant → all targets
        assert_eq!(p.accepted_laws.len(), 1);
        assert_eq!(p.promotion_pipeline.receipts.len(), 4);
    }

    #[test]
    fn pipeline_promote_side_condition() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let c = test_candidate("sc-1", CandidateKind::SideCondition);
        let r = accepted_result("sc-1", CandidateKind::SideCondition);

        let event = p.promote_law(&c, &r);
        assert_eq!(event.kind, LifecycleEventKind::Promoted);
        assert_eq!(event.affected_targets.len(), 2); // SideCondition → rewrite + atlas
    }

    #[test]
    fn pipeline_promote_normal_form() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let c = test_candidate("nf-1", CandidateKind::NormalForm);
        let r = accepted_result("nf-1", CandidateKind::NormalForm);

        let event = p.promote_law(&c, &r);
        assert_eq!(event.kind, LifecycleEventKind::Promoted);
        assert_eq!(event.affected_targets.len(), 2); // NormalForm → synthesis + frontier
    }

    #[test]
    fn pipeline_refuse_rejected_candidate() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let c = test_candidate("rej-1", CandidateKind::Invariant);
        let r = rejected_result("rej-1", CandidateKind::Invariant);

        let event = p.promote_law(&c, &r);
        assert_eq!(event.kind, LifecycleEventKind::Refused);
        assert!(event.refusal_reason.is_some());
        assert!(p.accepted_laws.is_empty());
    }

    #[test]
    fn pipeline_refuse_heuristic_when_not_allowed() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let c = test_candidate("heur-1", CandidateKind::Invariant);
        let mut r = accepted_result("heur-1", CandidateKind::Invariant);
        // Set confidence so strength maps to Heuristic
        r.final_verdict = ProofVerdict::Inconclusive;
        r.aggregate_confidence_millionths = 400_000;

        let event = p.promote_law(&c, &r);
        assert_eq!(event.kind, LifecycleEventKind::Refused);
    }

    #[test]
    fn pipeline_refuse_duplicate() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let c = test_candidate("dup-1", CandidateKind::Invariant);
        let r = accepted_result("dup-1", CandidateKind::Invariant);

        let e1 = p.promote_law(&c, &r);
        assert_eq!(e1.kind, LifecycleEventKind::Promoted);

        let e2 = p.promote_law(&c, &r);
        assert_eq!(e2.kind, LifecycleEventKind::Refused);
    }

    #[test]
    fn pipeline_revoke_law() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let c = test_candidate("rev-1", CandidateKind::Invariant);
        let r = accepted_result("rev-1", CandidateKind::Invariant);
        p.promote_law(&c, &r);

        let event = p.revoke_law("law-rev-1", "regression found");
        assert!(event.is_some());
        let event = event.unwrap();
        assert_eq!(event.kind, LifecycleEventKind::Revoked);
        assert!(p.revoked_law_ids.contains("law-rev-1"));
        assert!(p.active_law_ids().is_empty());
    }

    #[test]
    fn pipeline_revoke_nonexistent_returns_none() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        assert!(p.revoke_law("nonexistent", "test").is_none());
    }

    #[test]
    fn pipeline_revoke_idempotent() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let c = test_candidate("idem-1", CandidateKind::Invariant);
        let r = accepted_result("idem-1", CandidateKind::Invariant);
        p.promote_law(&c, &r);

        assert!(p.revoke_law("law-idem-1", "first").is_some());
        assert!(p.revoke_law("law-idem-1", "second").is_none());
    }

    #[test]
    fn pipeline_supersede_law() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let c1 = test_candidate("sup-old", CandidateKind::Invariant);
        let r1 = accepted_result("sup-old", CandidateKind::Invariant);
        p.promote_law(&c1, &r1);

        let event = p.supersede_law("law-sup-old", "law-sup-new", "stronger law");
        assert!(event.is_some());
        let event = event.unwrap();
        assert_eq!(event.kind, LifecycleEventKind::Superseded);
        assert_eq!(event.superseding_law_id.as_deref(), Some("law-sup-new"));
        assert!(p.superseded_law_ids.contains("law-sup-old"));
    }

    #[test]
    fn pipeline_expire_stale_laws() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(5));
        let c = test_candidate("exp-1", CandidateKind::Invariant);
        let r = accepted_result("exp-1", CandidateKind::Invariant);
        p.promote_law(&c, &r);

        // Epoch 5 + window 10 → expires after epoch 15
        let events = p.expire_stale_laws(epoch(16));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, LifecycleEventKind::Expired);
        assert!(p.expired_law_ids.contains("law-exp-1"));
    }

    #[test]
    fn pipeline_no_expire_within_window() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let c = test_candidate("noexp-1", CandidateKind::Invariant);
        let r = accepted_result("noexp-1", CandidateKind::Invariant);
        p.promote_law(&c, &r);

        let events = p.expire_stale_laws(epoch(15));
        assert!(events.is_empty());
    }

    #[test]
    fn pipeline_active_law_ids() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        for i in 0..5 {
            let c = test_candidate(&format!("act-{i}"), CandidateKind::Invariant);
            let r = accepted_result(&format!("act-{i}"), CandidateKind::Invariant);
            p.promote_law(&c, &r);
        }
        assert_eq!(p.active_law_ids().len(), 5);

        p.revoke_law("law-act-2", "test");
        assert_eq!(p.active_law_ids().len(), 4);
    }

    #[test]
    fn pipeline_events_for_law() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let c = test_candidate("evf-1", CandidateKind::Invariant);
        let r = accepted_result("evf-1", CandidateKind::Invariant);
        p.promote_law(&c, &r);
        p.revoke_law("law-evf-1", "regression");

        let events = p.events_for("law-evf-1");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, LifecycleEventKind::Promoted);
        assert_eq!(events[1].kind, LifecycleEventKind::Revoked);
    }

    #[test]
    fn pipeline_routing_for_law() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let c = test_candidate("rt-1", CandidateKind::SideCondition);
        let r = accepted_result("rt-1", CandidateKind::SideCondition);
        p.promote_law(&c, &r);

        let routing = p.routing_for("law-rt-1");
        assert!(routing.is_some());
        let routing = routing.unwrap();
        assert_eq!(routing.selected_targets.len(), 2);
    }

    #[test]
    fn pipeline_summary_report() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        for i in 0..6 {
            let kind = match i % 3 {
                0 => CandidateKind::Invariant,
                1 => CandidateKind::SideCondition,
                _ => CandidateKind::NormalForm,
            };
            let c = test_candidate(&format!("sum-{i}"), kind);
            let r = accepted_result(&format!("sum-{i}"), kind);
            p.promote_law(&c, &r);
        }
        p.revoke_law("law-sum-0", "test revoke");

        let summary = p.summary_report();
        assert_eq!(summary.total_accepted, 6);
        assert_eq!(summary.promoted_count, 6);
        assert_eq!(summary.revoked_count, 1);
        assert_eq!(summary.refused_count, 0);
        assert!(summary.mean_priority_millionths > 0);
        assert_eq!(summary.receipts_by_target.len(), 4);
    }

    #[test]
    fn pipeline_serde_roundtrip() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let c = test_candidate("serde-1", CandidateKind::Invariant);
        let r = accepted_result("serde-1", CandidateKind::Invariant);
        p.promote_law(&c, &r);

        let json = serde_json::to_string(&p).unwrap();
        let back: LifecyclePipeline = serde_json::from_str(&json).unwrap();
        assert_eq!(p.pipeline_hash, back.pipeline_hash);
    }

    #[test]
    fn pipeline_deterministic() {
        let mut p1 = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let mut p2 = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));

        for i in 0..3 {
            let c = test_candidate(&format!("det-{i}"), CandidateKind::Invariant);
            let r = accepted_result(&format!("det-{i}"), CandidateKind::Invariant);
            p1.promote_law(&c, &r);
            p2.promote_law(&c, &r);
        }

        assert_eq!(p1.pipeline_hash, p2.pipeline_hash);
    }

    #[test]
    fn pipeline_mixed_accepted_and_rejected() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let c1 = test_candidate("mix-acc", CandidateKind::Invariant);
        let r1 = accepted_result("mix-acc", CandidateKind::Invariant);
        let c2 = test_candidate("mix-rej", CandidateKind::SideCondition);
        let r2 = rejected_result("mix-rej", CandidateKind::SideCondition);

        let e1 = p.promote_law(&c1, &r1);
        let e2 = p.promote_law(&c2, &r2);

        assert_eq!(e1.kind, LifecycleEventKind::Promoted);
        assert_eq!(e2.kind, LifecycleEventKind::Refused);
        assert_eq!(p.accepted_laws.len(), 1);
        assert_eq!(p.lifecycle_events.len(), 2);
    }

    #[test]
    fn pipeline_refuse_revoked_law() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let c = test_candidate("rr-1", CandidateKind::Invariant);
        let r = accepted_result("rr-1", CandidateKind::Invariant);
        p.promote_law(&c, &r);
        p.revoke_law("law-rr-1", "bad");

        // Try to re-promote the same candidate — should be refused as previously revoked
        // Need a new candidate with same candidate_id but different path
        // The duplicate check fires first since accepted_laws still contains it
        let e = p.promote_law(&c, &r);
        assert_eq!(e.kind, LifecycleEventKind::Refused);
    }

    #[test]
    fn pipeline_auto_route_disabled() {
        let config = LifecycleConfig {
            auto_route_by_kind: false,
            ..LifecycleConfig::default()
        };
        let mut p = LifecyclePipeline::new(config, epoch(10));
        let c = test_candidate("ar-1", CandidateKind::SideCondition);
        let r = accepted_result("ar-1", CandidateKind::SideCondition);

        let event = p.promote_law(&c, &r);
        assert_eq!(event.kind, LifecycleEventKind::Promoted);
        // With auto-route disabled, all targets should be selected
        assert_eq!(event.affected_targets.len(), 4);
    }

    #[test]
    fn pipeline_allow_heuristic() {
        let config = LifecycleConfig {
            allow_heuristic: true,
            min_auto_strength: LawStrength::Heuristic,
            ..LifecycleConfig::default()
        };
        let mut p = LifecyclePipeline::new(config, epoch(10));
        let c = test_candidate("heur-ok", CandidateKind::Invariant);
        let mut r = accepted_result("heur-ok", CandidateKind::Invariant);
        r.final_verdict = ProofVerdict::Inconclusive;
        r.aggregate_confidence_millionths = 400_000;

        let event = p.promote_law(&c, &r);
        assert_eq!(event.kind, LifecycleEventKind::Promoted);
    }

    #[test]
    fn lifecycle_event_display() {
        let mut event = LifecycleEvent {
            event_id: "evt-0".to_string(),
            law_id: "law-1".to_string(),
            kind: LifecycleEventKind::Promoted,
            affected_targets: vec![PromotionTarget::RewritePack],
            rationale: "test".to_string(),
            superseding_law_id: None,
            refusal_reason: None,
            event_epoch: epoch(10),
            event_hash: ContentHash::compute(b"test"),
        };
        event.recompute_hash();
        let display = event.to_string();
        assert!(display.contains("evt-0"));
        assert!(display.contains("law-1"));
    }

    #[test]
    fn routing_decision_display() {
        let mut rd = RoutingDecision {
            law_id: "law-1".to_string(),
            candidate_kind: CandidateKind::Invariant,
            selected_targets: PromotionTarget::ALL.to_vec(),
            priority_millionths: 800_000,
            decision_hash: ContentHash::compute(b"test"),
        };
        rd.recompute_hash();
        let display = rd.to_string();
        assert!(display.contains("law-1"));
    }

    #[test]
    fn target_breakdown_receipts() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let c = test_candidate("tb-1", CandidateKind::Invariant);
        let r = accepted_result("tb-1", CandidateKind::Invariant);
        p.promote_law(&c, &r);

        let summary = p.summary_report();
        let total: usize = summary.receipts_by_target.iter().map(|t| t.receipt_count).sum();
        assert_eq!(total, 4); // Invariant → 4 targets
    }

    #[test]
    fn supersede_then_expire_independent() {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(5));
        for i in 0..3 {
            let c = test_candidate(&format!("se-{i}"), CandidateKind::Invariant);
            let r = accepted_result(&format!("se-{i}"), CandidateKind::Invariant);
            p.promote_law(&c, &r);
        }

        p.supersede_law("law-se-0", "law-se-new", "better");
        let expired = p.expire_stale_laws(epoch(16));
        // se-0 was already superseded, so should not also expire
        assert_eq!(expired.len(), 2); // se-1 and se-2 expire
        assert!(!p.expired_law_ids.contains("law-se-0"));
    }

    #[test]
    fn pipeline_batch_promotion() {
        let candidates: Vec<LawCandidate> = (0..4)
            .map(|i| test_candidate(&format!("batch-{i}"), CandidateKind::Invariant))
            .collect();

        let config = crate::law_proof_refutation::ProofCampaignConfig::default();
        let mut proof_pipeline = ProofRefutationPipeline::new(config, epoch(10));
        for c in &candidates {
            proof_pipeline.run_campaign(c);
        }

        let mut lc = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        lc.promote_batch(&candidates, &proof_pipeline);

        // Some should be promoted, some might be refused depending on
        // the deterministic proof simulation
        assert!(!lc.lifecycle_events.is_empty());
    }
}
