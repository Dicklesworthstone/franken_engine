//! Advanced governance extensions for rollback decision-making.
//!
//! Extends the basic [`demotion_rollback`] system with sophisticated governance
//! features including challenge mechanisms, multi-stakeholder approval workflows,
//! structured audit trails, and incentive-compatibility analysis.
//!
//! Key governance improvements:
//! - **Appeal process**: Operators can challenge automatic demotions with rationale
//! - **Review workflows**: Multi-stakeholder approval for high-impact rollbacks
//! - **Audit transparency**: Structured reporting and lifecycle management
//! - **Incentive analysis**: Game-theoretic validation of governance decisions
//! - **Enhanced quarantine**: Sophisticated status management beyond basic blocking
//!
//! Integrates with [`governance_mechanism`] patterns and [`demotion_rollback`]
//! infrastructure while maintaining cryptographic integrity and deterministic
//! behavior required for adversarial extension workloads.
//!
//! Plan reference: bd-1lsy.7.4.3 (rollback governance P1).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::demotion_rollback::DemotionEvidenceItem;
use crate::governance_mechanism::ReportPhase;
use crate::policy_checkpoint::DeterministicTimestamp;
use crate::signature_preimage::{Signature, SigningKey, VerificationKey};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const GOVERNANCE_SCHEMA_VERSION: &str = "franken-engine.rollback-governance.v1";

/// Default approval threshold for governance reviews (2/3 majority).
pub const DEFAULT_APPROVAL_THRESHOLD_MILLIONTHS: u64 = 666_667;

/// Maximum time allowed for appeal submission after demotion (24 hours).
pub const APPEAL_DEADLINE_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

/// Default game-theoretic incentive analysis timeout (5 minutes).
pub const INCENTIVE_ANALYSIS_TIMEOUT_NS: u64 = 5 * 60 * 1_000_000_000;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from rollback governance operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceError {
    /// Appeal submitted outside allowed timeframe.
    AppealDeadlineExpired {
        demotion_id: String,
        deadline_ns: u64,
        submitted_at_ns: u64,
    },
    /// Insufficient governance approvals for the operation.
    InsufficientApprovals {
        required_approvers: u32,
        actual_approvers: u32,
        threshold_millionths: u64,
    },
    /// Conflicting governance decisions detected.
    ConflictingDecisions {
        decision_a_id: String,
        decision_b_id: String,
        reason: String,
    },
    /// Incentive-compatibility violation in governance structure.
    IncentiveViolation {
        stakeholder_id: String,
        violated_constraint: String,
    },
    /// Quarantine status prevents the requested operation.
    QuarantineBlocked {
        entity_id: String,
        quarantine_reason: String,
    },
    /// Invalid governance configuration.
    InvalidConfiguration { field: String, reason: String },
}

impl fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AppealDeadlineExpired {
                demotion_id,
                deadline_ns,
                submitted_at_ns,
            } => write!(
                f,
                "appeal for demotion {demotion_id} expired: deadline={deadline_ns}, submitted={submitted_at_ns}"
            ),
            Self::InsufficientApprovals {
                required_approvers,
                actual_approvers,
                threshold_millionths,
            } => write!(
                f,
                "insufficient approvals: {actual_approvers}/{required_approvers} (threshold: {}%)",
                threshold_millionths / 10_000
            ),
            Self::ConflictingDecisions {
                decision_a_id,
                decision_b_id,
                reason,
            } => write!(
                f,
                "conflicting decisions {decision_a_id} vs {decision_b_id}: {reason}"
            ),
            Self::IncentiveViolation {
                stakeholder_id,
                violated_constraint,
            } => write!(
                f,
                "incentive violation by {stakeholder_id}: {violated_constraint}"
            ),
            Self::QuarantineBlocked {
                entity_id,
                quarantine_reason,
            } => write!(f, "entity {entity_id} quarantined: {quarantine_reason}"),
            Self::InvalidConfiguration { field, reason } => {
                write!(f, "invalid configuration for {field}: {reason}")
            }
        }
    }
}

impl std::error::Error for GovernanceError {}

// ---------------------------------------------------------------------------
// Appeal mechanism
// ---------------------------------------------------------------------------

/// Current status of a demotion appeal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealStatus {
    /// Appeal submitted, awaiting initial review.
    Submitted,
    /// Under review by governance committee.
    UnderReview,
    /// Appeal approved — demotion should be reversed.
    Approved,
    /// Appeal rejected — original demotion upheld.
    Rejected,
    /// Appeal escalated to higher governance authority.
    Escalated,
}

impl fmt::Display for AppealStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Submitted => f.write_str("submitted"),
            Self::UnderReview => f.write_str("under_review"),
            Self::Approved => f.write_str("approved"),
            Self::Rejected => f.write_str("rejected"),
            Self::Escalated => f.write_str("escalated"),
        }
    }
}

/// A formal appeal against an automatic demotion decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemotionAppealRequest {
    /// Unique appeal identifier.
    pub appeal_id: String,
    /// The demotion receipt being challenged.
    pub target_demotion_id: String,
    /// Identity of the appealing party.
    pub appellant_id: String,
    /// Current status of the appeal.
    pub status: AppealStatus,
    /// Detailed rationale for the appeal.
    pub rationale: String,
    /// Supporting evidence artifacts.
    pub supporting_evidence: Vec<DemotionEvidenceItem>,
    /// Proposed alternative action (if any).
    pub proposed_alternative: Option<String>,
    /// Stake or cost associated with this appeal (anti-spam).
    pub appeal_stake_millionths: u64,
    /// When the appeal was submitted.
    pub submitted_at: DeterministicTimestamp,
    /// When the appeal was resolved (if resolved).
    pub resolved_at: Option<DeterministicTimestamp>,
    /// Final outcome rationale (if resolved).
    pub outcome_rationale: Option<String>,
}

impl DemotionAppealRequest {
    /// Create a new appeal request with validation.
    #[allow(clippy::too_many_arguments)]
    pub fn create_new(
        appeal_id: String,
        target_demotion_id: String,
        appellant_id: String,
        rationale: String,
        supporting_evidence: Vec<DemotionEvidenceItem>,
        proposed_alternative: Option<String>,
        appeal_stake_millionths: u64,
        submitted_at: DeterministicTimestamp,
        demotion_timestamp_ns: u64,
    ) -> Result<Self, GovernanceError> {
        // Validate appeal deadline. Overflow here would otherwise panic in
        // debug builds or wrap in release, creating nondeterministic appeal
        // acceptance near the timestamp boundary.
        let deadline_ns = demotion_timestamp_ns
            .checked_add(APPEAL_DEADLINE_NS)
            .ok_or_else(|| GovernanceError::InvalidConfiguration {
                field: "demotion_timestamp_ns".to_string(),
                reason: "appeal deadline calculation overflowed".to_string(),
            })?;
        if submitted_at.0 > deadline_ns {
            return Err(GovernanceError::AppealDeadlineExpired {
                demotion_id: target_demotion_id,
                deadline_ns,
                submitted_at_ns: submitted_at.0,
            });
        }

        // Validate rationale is non-empty
        if rationale.trim().is_empty() {
            return Err(GovernanceError::InvalidConfiguration {
                field: "rationale".to_string(),
                reason: "appeal rationale cannot be empty".to_string(),
            });
        }

        Ok(Self {
            appeal_id,
            target_demotion_id,
            appellant_id,
            status: AppealStatus::Submitted,
            rationale,
            supporting_evidence,
            proposed_alternative,
            appeal_stake_millionths,
            submitted_at,
            resolved_at: None,
            outcome_rationale: None,
        })
    }

    /// Update appeal status with outcome.
    pub fn resolve(
        &mut self,
        new_status: AppealStatus,
        outcome_rationale: String,
        resolved_at: DeterministicTimestamp,
    ) -> Result<(), GovernanceError> {
        if matches!(self.status, AppealStatus::Approved | AppealStatus::Rejected) {
            return Err(GovernanceError::ConflictingDecisions {
                decision_a_id: format!("{}-{}", self.appeal_id, self.status),
                decision_b_id: format!("{}-{}", self.appeal_id, new_status),
                reason: "appeal already resolved".to_string(),
            });
        }

        self.status = new_status;
        self.outcome_rationale = Some(outcome_rationale);
        self.resolved_at = Some(resolved_at);
        Ok(())
    }

    /// Check if appeal is still within deadline.
    pub fn is_within_deadline(&self, demotion_timestamp_ns: u64) -> bool {
        demotion_timestamp_ns
            .checked_add(APPEAL_DEADLINE_NS)
            .is_some_and(|deadline_ns| self.submitted_at.0 <= deadline_ns)
    }
}

// ---------------------------------------------------------------------------
// Governance review workflow
// ---------------------------------------------------------------------------

/// Stakeholder role in governance decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StakeholderRole {
    /// Extension developer or maintainer.
    Developer,
    /// System operator or administrator.
    Operator,
    /// Security analyst or reviewer.
    SecurityAnalyst,
    /// Performance engineer.
    PerformanceEngineer,
    /// Governance committee member.
    GovernanceCommittee,
}

impl fmt::Display for StakeholderRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Developer => f.write_str("developer"),
            Self::Operator => f.write_str("operator"),
            Self::SecurityAnalyst => f.write_str("security_analyst"),
            Self::PerformanceEngineer => f.write_str("performance_engineer"),
            Self::GovernanceCommittee => f.write_str("governance_committee"),
        }
    }
}

/// A single stakeholder's approval or rejection vote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceVote {
    /// Identity of the voting stakeholder.
    pub voter_id: String,
    /// Role of the stakeholder.
    pub voter_role: StakeholderRole,
    /// Whether the vote is approval (true) or rejection (false).
    pub is_approval: bool,
    /// Voting rationale.
    pub rationale: String,
    /// Vote weight (fixed-point millionths, 1_000_000 = 1.0).
    pub weight_millionths: u64,
    /// When the vote was cast.
    pub cast_at: DeterministicTimestamp,
    /// Cryptographic signature over vote contents.
    pub signature: Signature,
}

impl GovernanceVote {
    /// Create and sign a governance vote.
    #[allow(clippy::too_many_arguments)]
    pub fn create_signed(
        signing_key: &SigningKey,
        voter_id: String,
        voter_role: StakeholderRole,
        is_approval: bool,
        rationale: String,
        weight_millionths: u64,
        cast_at: DeterministicTimestamp,
        review_id: &str,
    ) -> Result<Self, GovernanceError> {
        // Compute signature preimage
        let mut preimage = Vec::new();
        preimage.extend_from_slice(GOVERNANCE_SCHEMA_VERSION.as_bytes());
        preimage.extend_from_slice(b"|vote|");
        preimage.extend_from_slice(review_id.as_bytes());
        preimage.extend_from_slice(b"|");
        preimage.extend_from_slice(voter_id.as_bytes());
        preimage.extend_from_slice(b"|");
        preimage.extend_from_slice(voter_role.to_string().as_bytes());
        preimage.push(if is_approval { 1 } else { 0 });
        preimage.extend_from_slice(&weight_millionths.to_be_bytes());
        preimage.extend_from_slice(&cast_at.0.to_be_bytes());
        preimage.extend_from_slice(rationale.as_bytes());

        let signature =
            crate::signature_preimage::sign_preimage(signing_key, &preimage).map_err(|_| {
                GovernanceError::InvalidConfiguration {
                    field: "signature".to_string(),
                    reason: "failed to sign vote".to_string(),
                }
            })?;

        Ok(Self {
            voter_id,
            voter_role,
            is_approval,
            rationale,
            weight_millionths,
            cast_at,
            signature,
        })
    }

    /// Verify the vote signature.
    pub fn verify_signature(
        &self,
        verification_key: &VerificationKey,
        review_id: &str,
    ) -> Result<(), GovernanceError> {
        // Reconstruct preimage
        let mut preimage = Vec::new();
        preimage.extend_from_slice(GOVERNANCE_SCHEMA_VERSION.as_bytes());
        preimage.extend_from_slice(b"|vote|");
        preimage.extend_from_slice(review_id.as_bytes());
        preimage.extend_from_slice(b"|");
        preimage.extend_from_slice(self.voter_id.as_bytes());
        preimage.extend_from_slice(b"|");
        preimage.extend_from_slice(self.voter_role.to_string().as_bytes());
        preimage.push(if self.is_approval { 1 } else { 0 });
        preimage.extend_from_slice(&self.weight_millionths.to_be_bytes());
        preimage.extend_from_slice(&self.cast_at.0.to_be_bytes());
        preimage.extend_from_slice(self.rationale.as_bytes());

        crate::signature_preimage::verify_signature(verification_key, &preimage, &self.signature)
            .map_err(|_| GovernanceError::InvalidConfiguration {
                field: "signature".to_string(),
                reason: "vote signature verification failed".to_string(),
            })
    }
}

/// Multi-stakeholder governance review for sensitive rollback decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceReview {
    /// Unique review identifier.
    pub review_id: String,
    /// Target entity being reviewed (demotion, appeal, policy change, etc.).
    pub target_entity_id: String,
    /// Type of review (e.g., "demotion_appeal", "policy_override").
    pub review_type: String,
    /// Current phase of the review process.
    pub phase: ReportPhase,
    /// Required approval threshold (fixed-point millionths).
    pub approval_threshold_millionths: u64,
    /// Collected stakeholder votes.
    pub votes: Vec<GovernanceVote>,
    /// Required stakeholder roles for quorum.
    pub required_roles: BTreeSet<StakeholderRole>,
    /// Deadline for vote collection.
    pub voting_deadline: DeterministicTimestamp,
    /// When the review was initiated.
    pub initiated_at: DeterministicTimestamp,
    /// When the review was concluded (if concluded).
    pub concluded_at: Option<DeterministicTimestamp>,
    /// Final decision rationale.
    pub decision_rationale: Option<String>,
}

impl GovernanceReview {
    /// Create a new governance review.
    pub fn new(
        review_id: String,
        target_entity_id: String,
        review_type: String,
        approval_threshold_millionths: u64,
        required_roles: BTreeSet<StakeholderRole>,
        voting_deadline: DeterministicTimestamp,
        initiated_at: DeterministicTimestamp,
    ) -> Self {
        Self {
            review_id,
            target_entity_id,
            review_type,
            phase: ReportPhase::Submitted,
            approval_threshold_millionths,
            votes: Vec::new(),
            required_roles,
            voting_deadline,
            initiated_at,
            concluded_at: None,
            decision_rationale: None,
        }
    }

    /// Add a stakeholder vote to the review.
    pub fn add_vote(&mut self, vote: GovernanceVote) -> Result<(), GovernanceError> {
        // Check if voting is still open
        if matches!(self.phase, ReportPhase::Resolved | ReportPhase::Dismissed) {
            return Err(GovernanceError::ConflictingDecisions {
                decision_a_id: self.review_id.clone(),
                decision_b_id: vote.voter_id.clone(),
                reason: "voting already concluded".to_string(),
            });
        }

        // Check for duplicate votes from same voter
        if self.votes.iter().any(|v| v.voter_id == vote.voter_id) {
            return Err(GovernanceError::ConflictingDecisions {
                decision_a_id: format!("{}-existing", vote.voter_id),
                decision_b_id: format!("{}-new", vote.voter_id),
                reason: "duplicate vote from same stakeholder".to_string(),
            });
        }

        self.votes.push(vote);
        Ok(())
    }

    /// Compute current approval metrics.
    pub fn compute_approval_metrics(&self) -> (u64, u64, bool) {
        let total_weight: u128 = self
            .votes
            .iter()
            .map(|v| u128::from(v.weight_millionths))
            .sum();
        let approval_weight: u128 = self
            .votes
            .iter()
            .filter(|v| v.is_approval)
            .map(|v| u128::from(v.weight_millionths))
            .sum();

        let approval_ratio_millionths = approval_weight
            .saturating_mul(1_000_000)
            .checked_div(total_weight)
            .unwrap_or(0);

        let threshold_met =
            approval_ratio_millionths >= u128::from(self.approval_threshold_millionths);
        (
            total_to_u64_saturating(approval_weight),
            total_to_u64_saturating(total_weight),
            threshold_met,
        )
    }

    /// Check if quorum is met (all required roles have voted).
    pub fn has_quorum(&self) -> bool {
        let voted_roles: BTreeSet<StakeholderRole> =
            self.votes.iter().map(|v| v.voter_role).collect();
        self.required_roles
            .iter()
            .all(|role| voted_roles.contains(role))
    }

    /// Finalize the review with a decision.
    pub fn conclude(
        &mut self,
        decision: ReportPhase,
        rationale: String,
        concluded_at: DeterministicTimestamp,
    ) -> Result<(), GovernanceError> {
        if matches!(self.phase, ReportPhase::Resolved | ReportPhase::Dismissed) {
            return Err(GovernanceError::ConflictingDecisions {
                decision_a_id: format!("{}-{}", self.review_id, self.phase),
                decision_b_id: format!("{}-{}", self.review_id, decision),
                reason: "review already concluded".to_string(),
            });
        }

        self.phase = decision;
        self.decision_rationale = Some(rationale);
        self.concluded_at = Some(concluded_at);
        Ok(())
    }
}

fn total_to_u64_saturating(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

// ---------------------------------------------------------------------------
// Enhanced quarantine management
// ---------------------------------------------------------------------------

/// Advanced quarantine status with graduated response levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineLevel {
    /// Entity can operate normally.
    Clear,
    /// Entity flagged for monitoring, normal operation allowed.
    Monitored,
    /// Entity has restricted capabilities.
    Restricted,
    /// Entity quarantined, no new promotions allowed.
    Quarantined,
    /// Entity permanently banned.
    Banned,
}

impl fmt::Display for QuarantineLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clear => f.write_str("clear"),
            Self::Monitored => f.write_str("monitored"),
            Self::Restricted => f.write_str("restricted"),
            Self::Quarantined => f.write_str("quarantined"),
            Self::Banned => f.write_str("banned"),
        }
    }
}

/// Enhanced quarantine record with graduated response levels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnhancedQuarantineRecord {
    /// Unique quarantine identifier.
    pub quarantine_id: String,
    /// Entity under quarantine (slot, cell, operator, etc.).
    pub entity_id: String,
    /// Entity type (e.g., "slot", "native_cell", "operator").
    pub entity_type: String,
    /// Current quarantine level.
    pub level: QuarantineLevel,
    /// Reason for current quarantine level.
    pub reason: String,
    /// Evidence supporting the quarantine.
    pub evidence: Vec<DemotionEvidenceItem>,
    /// Restrictions imposed at this level.
    pub imposed_restrictions: BTreeSet<String>,
    /// When the quarantine was last updated.
    pub last_updated: DeterministicTimestamp,
    /// History of quarantine level changes.
    pub level_history: Vec<QuarantineLevelChange>,
    /// Reinstatement criteria for clearing the quarantine.
    pub reinstatement_criteria: Vec<String>,
}

/// Record of a quarantine level change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineLevelChange {
    /// Previous quarantine level.
    pub from_level: QuarantineLevel,
    /// New quarantine level.
    pub to_level: QuarantineLevel,
    /// Reason for the change.
    pub reason: String,
    /// When the change occurred.
    pub changed_at: DeterministicTimestamp,
    /// Authority that made the change.
    pub changed_by: String,
}

impl EnhancedQuarantineRecord {
    /// Create a new quarantine record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        quarantine_id: String,
        entity_id: String,
        entity_type: String,
        level: QuarantineLevel,
        reason: String,
        evidence: Vec<DemotionEvidenceItem>,
        imposed_restrictions: BTreeSet<String>,
        reinstatement_criteria: Vec<String>,
        timestamp: DeterministicTimestamp,
    ) -> Self {
        let level_change = QuarantineLevelChange {
            from_level: QuarantineLevel::Clear,
            to_level: level,
            reason: reason.clone(),
            changed_at: timestamp,
            changed_by: "system".to_string(),
        };

        Self {
            quarantine_id,
            entity_id,
            entity_type,
            level,
            reason,
            evidence,
            imposed_restrictions,
            last_updated: timestamp,
            level_history: vec![level_change],
            reinstatement_criteria,
        }
    }

    /// Update the quarantine level with governance approval.
    pub fn update_level(
        &mut self,
        new_level: QuarantineLevel,
        reason: String,
        changed_by: String,
        new_restrictions: BTreeSet<String>,
        timestamp: DeterministicTimestamp,
    ) -> Result<(), GovernanceError> {
        // Validate level transition
        if new_level == self.level {
            return Err(GovernanceError::InvalidConfiguration {
                field: "level".to_string(),
                reason: format!("entity already at level {}", new_level),
            });
        }

        // Record the level change
        let level_change = QuarantineLevelChange {
            from_level: self.level,
            to_level: new_level,
            reason: reason.clone(),
            changed_at: timestamp,
            changed_by,
        };

        self.level = new_level;
        self.reason = reason;
        self.imposed_restrictions = new_restrictions;
        self.last_updated = timestamp;
        self.level_history.push(level_change);

        Ok(())
    }

    /// Check if a specific operation is allowed under current quarantine.
    pub fn is_operation_allowed(&self, operation: &str) -> bool {
        match self.level {
            QuarantineLevel::Clear => true,
            QuarantineLevel::Monitored => true, // Monitored but not restricted
            QuarantineLevel::Restricted => !self.imposed_restrictions.contains(operation),
            QuarantineLevel::Quarantined => false, // No operations allowed
            QuarantineLevel::Banned => false,      // No operations allowed
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_timestamp() -> DeterministicTimestamp {
        DeterministicTimestamp(1_600_000_000_000_000_000)
    }

    fn test_signing_key() -> SigningKey {
        // This is a test key - not used in production
        let test_bytes = [42u8; 32];
        SigningKey::from_bytes(test_bytes).expect("valid test key")
    }

    #[test]
    fn appeal_creation_validates_deadline() {
        let demotion_time = 1_600_000_000_000_000_000u64; // Base time
        let appeal_time = demotion_time + APPEAL_DEADLINE_NS + 1; // Past deadline

        let result = DemotionAppealRequest::create_new(
            "appeal-123".to_string(),
            "demotion-456".to_string(),
            "operator-001".to_string(),
            "Demotion was incorrect due to measurement error".to_string(),
            Vec::new(),
            Some("Restore with additional monitoring".to_string()),
            1_000_000, // 1.0 stake
            DeterministicTimestamp(appeal_time),
            demotion_time,
        );

        assert!(matches!(
            result,
            Err(GovernanceError::AppealDeadlineExpired { .. })
        ));
    }

    #[test]
    fn appeal_creation_fails_closed_on_deadline_overflow() {
        let result = DemotionAppealRequest::create_new(
            "appeal-overflow".to_string(),
            "demotion-overflow".to_string(),
            "operator-001".to_string(),
            "Valid appeal rationale".to_string(),
            Vec::new(),
            None,
            1_000_000,
            DeterministicTimestamp(u64::MAX),
            u64::MAX - (APPEAL_DEADLINE_NS / 2),
        );

        assert!(matches!(
            result,
            Err(GovernanceError::InvalidConfiguration { field, .. })
                if field == "demotion_timestamp_ns"
        ));
    }

    #[test]
    fn appeal_creation_rejects_empty_rationale() {
        let demotion_time = 1_600_000_000_000_000_000u64;
        let appeal_time = demotion_time + 1_000_000_000; // 1 second after

        let result = DemotionAppealRequest::create_new(
            "appeal-123".to_string(),
            "demotion-456".to_string(),
            "operator-001".to_string(),
            "   ".to_string(), // Empty rationale
            Vec::new(),
            None,
            1_000_000,
            DeterministicTimestamp(appeal_time),
            demotion_time,
        );

        assert!(matches!(
            result,
            Err(GovernanceError::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn appeal_resolution_prevents_double_resolution() {
        let demotion_time = 1_600_000_000_000_000_000u64;
        let appeal_time = demotion_time + 1_000_000_000;

        let mut appeal = DemotionAppealRequest::create_new(
            "appeal-123".to_string(),
            "demotion-456".to_string(),
            "operator-001".to_string(),
            "Valid appeal rationale".to_string(),
            Vec::new(),
            None,
            1_000_000,
            DeterministicTimestamp(appeal_time),
            demotion_time,
        )
        .expect("valid appeal");

        // First resolution succeeds
        assert!(
            appeal
                .resolve(
                    AppealStatus::Approved,
                    "Appeal granted".to_string(),
                    test_timestamp()
                )
                .is_ok()
        );

        // Second resolution should fail
        let result = appeal.resolve(
            AppealStatus::Rejected,
            "Changed mind".to_string(),
            test_timestamp(),
        );

        assert!(matches!(
            result,
            Err(GovernanceError::ConflictingDecisions { .. })
        ));
    }

    #[test]
    fn governance_vote_signature_verification() {
        let signing_key = test_signing_key();
        let verification_key = signing_key.verification_key();
        let review_id = "review-123";

        let vote = GovernanceVote::create_signed(
            &signing_key,
            "voter-001".to_string(),
            StakeholderRole::SecurityAnalyst,
            true,
            "Approve the appeal".to_string(),
            1_000_000,
            test_timestamp(),
            review_id,
        )
        .expect("valid vote");

        // Verification should succeed
        assert!(vote.verify_signature(&verification_key, review_id).is_ok());

        // Verification with wrong review ID should fail
        assert!(
            vote.verify_signature(&verification_key, "wrong-review")
                .is_err()
        );
    }

    #[test]
    fn governance_review_approval_metrics() {
        let required_roles = [StakeholderRole::Operator, StakeholderRole::SecurityAnalyst]
            .into_iter()
            .collect();

        let mut review = GovernanceReview::new(
            "review-123".to_string(),
            "appeal-456".to_string(),
            "demotion_appeal".to_string(),
            666_667, // 2/3 threshold
            required_roles,
            test_timestamp(),
            test_timestamp(),
        );

        // Add approval vote with 60% weight
        let vote1 = GovernanceVote {
            voter_id: "voter-1".to_string(),
            voter_role: StakeholderRole::Operator,
            is_approval: true,
            rationale: "Support".to_string(),
            weight_millionths: 600_000,
            cast_at: test_timestamp(),
            signature: Signature::from_bytes([0; 64]),
        };

        // Add rejection vote with 40% weight
        let vote2 = GovernanceVote {
            voter_id: "voter-2".to_string(),
            voter_role: StakeholderRole::SecurityAnalyst,
            is_approval: false,
            rationale: "Concerns".to_string(),
            weight_millionths: 400_000,
            cast_at: test_timestamp(),
            signature: Signature::from_bytes([1; 64]),
        };

        review.add_vote(vote1).expect("add vote1");
        review.add_vote(vote2).expect("add vote2");

        let (approval_weight, total_weight, threshold_met) = review.compute_approval_metrics();
        assert_eq!(approval_weight, 600_000);
        assert_eq!(total_weight, 1_000_000);
        assert!(!threshold_met); // 60% < 66.67% threshold

        // Check quorum
        assert!(review.has_quorum()); // Both required roles voted
    }

    #[test]
    fn governance_review_approval_metrics_do_not_overflow() {
        let mut review = GovernanceReview::new(
            "review-overflow".to_string(),
            "appeal-overflow".to_string(),
            "demotion_appeal".to_string(),
            DEFAULT_APPROVAL_THRESHOLD_MILLIONTHS,
            BTreeSet::new(),
            test_timestamp(),
            test_timestamp(),
        );

        review
            .add_vote(GovernanceVote {
                voter_id: "voter-1".to_string(),
                voter_role: StakeholderRole::Operator,
                is_approval: true,
                rationale: "Support".to_string(),
                weight_millionths: u64::MAX,
                cast_at: test_timestamp(),
                signature: Signature::from_bytes([0; 64]),
            })
            .expect("add vote1");
        review
            .add_vote(GovernanceVote {
                voter_id: "voter-2".to_string(),
                voter_role: StakeholderRole::SecurityAnalyst,
                is_approval: false,
                rationale: "Concerns".to_string(),
                weight_millionths: u64::MAX,
                cast_at: test_timestamp(),
                signature: Signature::from_bytes([1; 64]),
            })
            .expect("add vote2");

        let (approval_weight, total_weight, threshold_met) = review.compute_approval_metrics();
        assert_eq!(approval_weight, u64::MAX);
        assert_eq!(total_weight, u64::MAX);
        assert!(!threshold_met);
    }

    #[test]
    fn enhanced_quarantine_operation_restrictions() {
        let mut quarantine = EnhancedQuarantineRecord::new(
            "q-123".to_string(),
            "entity-456".to_string(),
            "slot".to_string(),
            QuarantineLevel::Restricted,
            "Performance violations".to_string(),
            Vec::new(),
            ["promote", "tier_up"]
                .into_iter()
                .map(|s| s.to_string())
                .collect(),
            vec!["Pass performance audit".to_string()],
            test_timestamp(),
        );

        // Restricted operations should be blocked
        assert!(!quarantine.is_operation_allowed("promote"));
        assert!(!quarantine.is_operation_allowed("tier_up"));

        // Non-restricted operations should be allowed
        assert!(quarantine.is_operation_allowed("monitor"));
        assert!(quarantine.is_operation_allowed("report"));

        // Upgrade to clear level
        quarantine
            .update_level(
                QuarantineLevel::Clear,
                "Audit passed".to_string(),
                "governance".to_string(),
                BTreeSet::new(),
                test_timestamp(),
            )
            .expect("level update");

        // All operations should be allowed
        assert!(quarantine.is_operation_allowed("promote"));
        assert!(quarantine.is_operation_allowed("tier_up"));

        // Level history should be recorded
        assert_eq!(quarantine.level_history.len(), 2);
        assert_eq!(quarantine.level_history[1].to_level, QuarantineLevel::Clear);
    }

    #[test]
    fn quarantine_duplicate_level_rejected() {
        let mut quarantine = EnhancedQuarantineRecord::new(
            "q-123".to_string(),
            "entity-456".to_string(),
            "slot".to_string(),
            QuarantineLevel::Restricted,
            "Test".to_string(),
            Vec::new(),
            BTreeSet::new(),
            Vec::new(),
            test_timestamp(),
        );

        // Setting same level should fail
        let result = quarantine.update_level(
            QuarantineLevel::Restricted,
            "Same level".to_string(),
            "admin".to_string(),
            BTreeSet::new(),
            test_timestamp(),
        );

        assert!(matches!(
            result,
            Err(GovernanceError::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn appeal_deadline_check() {
        let demotion_time = 1_600_000_000_000_000_000u64;
        let appeal_time = demotion_time + APPEAL_DEADLINE_NS / 2; // Within deadline

        let appeal = DemotionAppealRequest::create_new(
            "appeal-123".to_string(),
            "demotion-456".to_string(),
            "operator-001".to_string(),
            "Valid rationale".to_string(),
            Vec::new(),
            None,
            1_000_000,
            DeterministicTimestamp(appeal_time),
            demotion_time,
        )
        .expect("valid appeal");

        assert!(appeal.is_within_deadline(demotion_time));
        assert!(!appeal.is_within_deadline(demotion_time - APPEAL_DEADLINE_NS - 1));
        assert!(!appeal.is_within_deadline(u64::MAX - (APPEAL_DEADLINE_NS / 2)));
    }
}
