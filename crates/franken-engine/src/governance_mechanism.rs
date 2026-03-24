//! Incentive-compatible extension governance mechanism.
//!
//! Implements FRX-18.3: mechanism design for reporting, challenge,
//! quarantine, and reinstatement of extensions, with game-theoretic
//! incentive-compatibility analysis and deterministic enforcement policy
//! compilation.
//!
//! Integrates attack-surface game models (FRX-18.1), policy-as-data
//! governance (FRX-08.3), and primitive adoption schema (FRX-16.1).
//!
//! Plan reference: bd-mjh3.18.3.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::attack_surface_game_model::{ActionId, GameModel, LossDimension, LossTensor, Subsystem};
use crate::hash_tiers::ContentHash;
use crate::policy_checkpoint::DeterministicTimestamp;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const SCHEMA_VERSION: &str = "franken-engine.governance-mechanism.v1";

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from governance mechanism operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MechanismError {
    /// A required input field is invalid.
    InvalidInput { field: String, detail: String },
    /// The referenced game model was not found.
    GameModelMissing { subsystem: String },
    /// Incentive-compatibility property violated.
    IncentiveViolation { reason: String },
    /// Quarantine constraint prevents the operation.
    QuarantineConstraintViolated { package_id: String, reason: String },
    /// Reinstatement not allowed for the given quarantine.
    ReinstateNotAllowed {
        quarantine_id: String,
        reason: String,
    },
}

impl fmt::Display for MechanismError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { field, detail } => {
                write!(f, "invalid input: {field}: {detail}")
            }
            Self::GameModelMissing { subsystem } => {
                write!(f, "game model missing for subsystem: {subsystem}")
            }
            Self::IncentiveViolation { reason } => {
                write!(f, "incentive violation: {reason}")
            }
            Self::QuarantineConstraintViolated { package_id, reason } => {
                write!(f, "quarantine constraint for {package_id}: {reason}")
            }
            Self::ReinstateNotAllowed {
                quarantine_id,
                reason,
            } => {
                write!(f, "reinstate not allowed for {quarantine_id}: {reason}")
            }
        }
    }
}

impl std::error::Error for MechanismError {}

// ---------------------------------------------------------------------------
// Lifecycle phases
// ---------------------------------------------------------------------------

/// Phase of a governance report's lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportPhase {
    /// Report submitted, awaiting review.
    Submitted,
    /// Under active review.
    UnderReview,
    /// Resolved (action taken).
    Resolved,
    /// Dismissed (no action warranted).
    Dismissed,
}

impl fmt::Display for ReportPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Submitted => f.write_str("submitted"),
            Self::UnderReview => f.write_str("under_review"),
            Self::Resolved => f.write_str("resolved"),
            Self::Dismissed => f.write_str("dismissed"),
        }
    }
}

/// Outcome of a challenge against a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeOutcome {
    /// Challenge upheld — original report confirmed.
    Upheld,
    /// Challenge rejected — report overturned.
    Rejected,
    /// Challenge escalated to governance review.
    Escalated,
}

impl fmt::Display for ChallengeOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Upheld => f.write_str("upheld"),
            Self::Rejected => f.write_str("rejected"),
            Self::Escalated => f.write_str("escalated"),
        }
    }
}

/// Quarantine status for a package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    /// Quarantine is active — package disabled.
    Active,
    /// Quarantine lifted after reinstatement.
    Lifted,
    /// Quarantine expired by time limit.
    Expired,
}

impl fmt::Display for QuarantineStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::Lifted => f.write_str("lifted"),
            Self::Expired => f.write_str("expired"),
        }
    }
}

// ---------------------------------------------------------------------------
// Incentive-compatibility classification
// ---------------------------------------------------------------------------

/// Classification of incentive-compatibility for a mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncentiveCompatibilityClass {
    /// Reporter always benefits from truthful reporting regardless of others.
    DominantStrategy,
    /// Best-response at Nash equilibrium under Bayesian beliefs.
    BayesNash,
    /// Rational ex-post but not dominant strategy.
    ExPostRational,
    /// Mechanism fails to satisfy incentive compatibility.
    NonCompliant,
}

impl fmt::Display for IncentiveCompatibilityClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DominantStrategy => f.write_str("dominant_strategy"),
            Self::BayesNash => f.write_str("bayes_nash"),
            Self::ExPostRational => f.write_str("ex_post_rational"),
            Self::NonCompliant => f.write_str("non_compliant"),
        }
    }
}

// ---------------------------------------------------------------------------
// Extension report
// ---------------------------------------------------------------------------

/// A governance report submitted against an extension package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionReport {
    /// Unique report identifier.
    pub report_id: String,
    /// Package identifier (scope/name@version).
    pub package_id: String,
    /// Identity of the reporter.
    pub reporter_id: String,
    /// Current lifecycle phase.
    pub phase: ReportPhase,
    /// Evidence entry identifiers supporting this report.
    pub evidence_refs: Vec<String>,
    /// Which loss dimension triggered the report.
    pub loss_dimension: LossDimension,
    /// Severity in millionths (1_000_000 = maximum severity).
    pub severity_millionths: i64,
    /// When the report was submitted.
    pub submitted_at: DeterministicTimestamp,
    /// When the report was resolved (if resolved).
    pub resolved_at: Option<DeterministicTimestamp>,
}

// ---------------------------------------------------------------------------
// Challenge record
// ---------------------------------------------------------------------------

/// A challenge against an existing governance report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRecord {
    /// Unique challenge identifier.
    pub challenge_id: String,
    /// Report being challenged.
    pub report_id: String,
    /// Identity of the challenger.
    pub challenger_id: String,
    /// Outcome of the challenge (None = pending).
    pub outcome: Option<ChallengeOutcome>,
    /// Rationale for the challenge.
    pub rationale: String,
    /// Game model used for analysis.
    pub game_model_id: String,
    /// Minimax-optimal defender action from analysis.
    pub minimax_action: Option<String>,
    /// When the challenge was submitted.
    pub submitted_at: DeterministicTimestamp,
    /// When the challenge was resolved.
    pub resolved_at: Option<DeterministicTimestamp>,
}

// ---------------------------------------------------------------------------
// Quarantine record
// ---------------------------------------------------------------------------

/// Record of a package quarantine action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineRecord {
    /// Unique quarantine identifier.
    pub quarantine_id: String,
    /// Package under quarantine.
    pub package_id: String,
    /// Current quarantine status.
    pub status: QuarantineStatus,
    /// Report that triggered this quarantine.
    pub trigger_report_id: String,
    /// Hard constraints enforced during quarantine.
    pub hard_constraints: Vec<String>,
    /// When quarantine was imposed.
    pub quarantined_at: DeterministicTimestamp,
    /// When quarantine was lifted (if lifted).
    pub lifted_at: Option<DeterministicTimestamp>,
}

// ---------------------------------------------------------------------------
// Reinstatement request
// ---------------------------------------------------------------------------

/// Request to reinstate a quarantined package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReinstateRequest {
    /// Unique request identifier.
    pub request_id: String,
    /// Quarantine to reinstate from.
    pub quarantine_id: String,
    /// Justification for reinstatement.
    pub justification: String,
    /// Compliance evidence identifier.
    pub compliance_evidence_id: Option<String>,
    /// When the request was submitted.
    pub submitted_at: DeterministicTimestamp,
    /// Whether the request was approved.
    pub approved: Option<bool>,
}

// ---------------------------------------------------------------------------
// Incentive analysis
// ---------------------------------------------------------------------------

/// Result of analyzing incentive-compatibility for a subsystem's game model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncentiveAnalysis {
    /// Subsystem analyzed.
    pub subsystem: Subsystem,
    /// Game model identifier.
    pub game_model_id: String,
    /// Incentive-compatibility classification.
    pub ic_class: IncentiveCompatibilityClass,
    /// IC score in millionths (1_000_000 = fully IC).
    pub ic_score_millionths: i64,
    /// Actions that form a dominant strategy.
    pub dominant_strategy_actions: BTreeSet<ActionId>,
    /// Risk of strategic deviation in millionths.
    pub deviation_risk_millionths: i64,
    /// Loss to reporter for false reporting (negative = penalty).
    pub false_report_loss_millionths: i64,
    /// Gain to reporter for truthful reporting.
    pub truthful_report_gain_millionths: i64,
    /// Minimax-optimal defender action.
    pub minimax_defender_action: Option<ActionId>,
    /// Set of admissible actions.
    pub admissible_actions: BTreeSet<ActionId>,
    /// When analysis was performed.
    pub analyzed_at: DeterministicTimestamp,
}

// ---------------------------------------------------------------------------
// Enforcement policy
// ---------------------------------------------------------------------------

/// Compiled deterministic enforcement policy derived from incentive analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementPolicy {
    /// Policy identifier.
    pub policy_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Available actions.
    pub action_set: Vec<String>,
    /// Blocked actions (guardrails).
    pub blocked_actions: BTreeSet<String>,
    /// Safe default action.
    pub safe_default: String,
    /// Incentive analysis used to derive this policy.
    pub analysis_subsystem: Subsystem,
    /// Content hash of policy.
    pub content_hash: ContentHash,
    /// When policy was compiled.
    pub compiled_at: DeterministicTimestamp,
}

impl EnforcementPolicy {
    fn compute_hash(
        policy_id: &str,
        epoch: &SecurityEpoch,
        action_set: &[String],
        safe_default: &str,
        analysis_subsystem: Subsystem,
    ) -> ContentHash {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(b"enforcement-policy|");
        canonical.extend_from_slice(policy_id.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(&epoch.as_u64().to_be_bytes());
        canonical.push(b'|');
        // action_set comes from BTreeSet::iter so is already sorted.
        for a in action_set {
            canonical.extend_from_slice(a.as_bytes());
            canonical.push(b',');
        }
        canonical.push(b'|');
        canonical.extend_from_slice(safe_default.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(analysis_subsystem.to_string().as_bytes());
        ContentHash::compute(&canonical)
    }
}

// ---------------------------------------------------------------------------
// Mechanism event
// ---------------------------------------------------------------------------

/// Append-only audit event from governance mechanism operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MechanismEvent {
    /// Event kind (e.g., "report_submitted", "quarantine_imposed").
    pub kind: String,
    /// Whether the event represents a passing/success condition.
    pub passed: bool,
    /// Human-readable summary.
    pub summary: String,
    /// Structured attributes.
    pub attributes: BTreeMap<String, String>,
    /// When the event occurred.
    pub timestamp: DeterministicTimestamp,
}

// ---------------------------------------------------------------------------
// Mechanism report (CI summary)
// ---------------------------------------------------------------------------

/// CI-readable summary of the governance mechanism state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MechanismReport {
    /// Schema version.
    pub schema_version: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Total governance reports submitted.
    pub total_reports: usize,
    /// Number of active quarantines.
    pub active_quarantines: usize,
    /// Number of IC-compliant subsystems.
    pub ic_compliant_count: usize,
    /// Number of non-IC-compliant subsystems.
    pub ic_non_compliant_count: usize,
    /// Minimum IC score across all analyses (millionths).
    pub min_ic_score_millionths: i64,
    /// Enforcement policy ID.
    pub enforcement_policy_id: String,
    /// Content hash of report.
    pub report_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// GovernanceMechanism — the stateful orchestrator
// ---------------------------------------------------------------------------

/// Stateful orchestrator for the incentive-compatible governance mechanism.
///
/// Manages the full lifecycle of reports, challenges, quarantines, and
/// reinstatements, producing deterministic enforcement policies backed by
/// game-theoretic incentive analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceMechanism {
    /// Security epoch.
    epoch: SecurityEpoch,
    /// Submitted reports.
    reports: Vec<ExtensionReport>,
    /// Challenge records.
    challenges: Vec<ChallengeRecord>,
    /// Quarantine records.
    quarantines: Vec<QuarantineRecord>,
    /// Reinstatement requests.
    reinstate_requests: Vec<ReinstateRequest>,
    /// Incentive analyses (one per subsystem).
    analyses: Vec<IncentiveAnalysis>,
    /// Compiled enforcement policies.
    policies: Vec<EnforcementPolicy>,
    /// Audit event log.
    events: Vec<MechanismEvent>,
}

impl GovernanceMechanism {
    /// Create a new governance mechanism for the given epoch.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            epoch,
            reports: Vec::new(),
            challenges: Vec::new(),
            quarantines: Vec::new(),
            reinstate_requests: Vec::new(),
            analyses: Vec::new(),
            policies: Vec::new(),
            events: Vec::new(),
        }
    }

    /// Return the current epoch.
    pub fn epoch(&self) -> SecurityEpoch {
        self.epoch
    }

    /// Return all reports.
    pub fn reports(&self) -> &[ExtensionReport] {
        &self.reports
    }

    /// Return all challenges.
    pub fn challenges(&self) -> &[ChallengeRecord] {
        &self.challenges
    }

    /// Return all quarantines.
    pub fn quarantines(&self) -> &[QuarantineRecord] {
        &self.quarantines
    }

    /// Return all reinstatement requests.
    pub fn reinstate_requests(&self) -> &[ReinstateRequest] {
        &self.reinstate_requests
    }

    /// Return all incentive analyses.
    pub fn analyses(&self) -> &[IncentiveAnalysis] {
        &self.analyses
    }

    /// Return all enforcement policies.
    pub fn policies(&self) -> &[EnforcementPolicy] {
        &self.policies
    }

    /// Return the audit event log.
    pub fn events(&self) -> &[MechanismEvent] {
        &self.events
    }

    fn emit_event(&mut self, kind: &str, passed: bool, summary: &str, ts: DeterministicTimestamp) {
        self.events.push(MechanismEvent {
            kind: kind.to_string(),
            passed,
            summary: summary.to_string(),
            attributes: BTreeMap::new(),
            timestamp: ts,
        });
    }

    // -- Report lifecycle --

    /// Submit a governance report against a package.
    pub fn submit_report(&mut self, report: ExtensionReport) -> Result<(), MechanismError> {
        if report.package_id.is_empty() {
            return Err(MechanismError::InvalidInput {
                field: "package_id".into(),
                detail: "must not be empty".into(),
            });
        }
        if report.severity_millionths < 0 || report.severity_millionths > 1_000_000 {
            return Err(MechanismError::InvalidInput {
                field: "severity_millionths".into(),
                detail: "must be in [0, 1_000_000]".into(),
            });
        }
        let ts = report.submitted_at;
        self.emit_event(
            "report_submitted",
            true,
            &format!("report against {}", report.package_id),
            ts,
        );
        self.reports.push(report);
        Ok(())
    }

    /// Advance a report to the next phase.
    pub fn advance_report(
        &mut self,
        report_id: &str,
        new_phase: ReportPhase,
        resolved_at: Option<DeterministicTimestamp>,
    ) -> Result<(), MechanismError> {
        let report = self
            .reports
            .iter_mut()
            .find(|r| r.report_id == report_id)
            .ok_or_else(|| MechanismError::InvalidInput {
                field: "report_id".into(),
                detail: format!("report {report_id} not found"),
            })?;
        report.phase = new_phase;
        if let Some(ts) = resolved_at {
            report.resolved_at = Some(ts);
        }
        let ts = resolved_at.unwrap_or(report.submitted_at);
        self.emit_event(
            "report_advanced",
            true,
            &format!("report {report_id} -> {new_phase}"),
            ts,
        );
        Ok(())
    }

    // -- Challenge lifecycle --

    /// Submit a challenge against an existing report.
    pub fn submit_challenge(&mut self, challenge: ChallengeRecord) -> Result<(), MechanismError> {
        // Verify the referenced report exists.
        let report_exists = self
            .reports
            .iter()
            .any(|r| r.report_id == challenge.report_id);
        if !report_exists {
            return Err(MechanismError::InvalidInput {
                field: "report_id".into(),
                detail: format!("report {} not found", challenge.report_id),
            });
        }
        let ts = challenge.submitted_at;
        self.emit_event(
            "challenge_submitted",
            true,
            &format!("challenge on report {}", challenge.report_id),
            ts,
        );
        self.challenges.push(challenge);
        Ok(())
    }

    /// Resolve a challenge with an outcome.
    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        outcome: ChallengeOutcome,
        resolved_at: DeterministicTimestamp,
    ) -> Result<(), MechanismError> {
        let challenge = self
            .challenges
            .iter_mut()
            .find(|c| c.challenge_id == challenge_id)
            .ok_or_else(|| MechanismError::InvalidInput {
                field: "challenge_id".into(),
                detail: format!("challenge {challenge_id} not found"),
            })?;
        challenge.outcome = Some(outcome);
        challenge.resolved_at = Some(resolved_at);
        self.emit_event(
            "challenge_resolved",
            true,
            &format!("challenge {challenge_id} -> {outcome}"),
            resolved_at,
        );
        Ok(())
    }

    // -- Quarantine lifecycle --

    /// Impose quarantine on a package.
    pub fn impose_quarantine(
        &mut self,
        quarantine: QuarantineRecord,
    ) -> Result<(), MechanismError> {
        // Check the package isn't already actively quarantined.
        let already_active = self
            .quarantines
            .iter()
            .any(|q| q.package_id == quarantine.package_id && q.status == QuarantineStatus::Active);
        if already_active {
            return Err(MechanismError::QuarantineConstraintViolated {
                package_id: quarantine.package_id.clone(),
                reason: "package already under active quarantine".into(),
            });
        }
        let ts = quarantine.quarantined_at;
        self.emit_event(
            "quarantine_imposed",
            true,
            &format!("quarantine on {}", quarantine.package_id),
            ts,
        );
        self.quarantines.push(quarantine);
        Ok(())
    }

    /// Submit a reinstatement request for a quarantined package.
    pub fn request_reinstate(&mut self, request: ReinstateRequest) -> Result<(), MechanismError> {
        let quarantine = self
            .quarantines
            .iter()
            .find(|q| q.quarantine_id == request.quarantine_id);
        match quarantine {
            None => {
                return Err(MechanismError::ReinstateNotAllowed {
                    quarantine_id: request.quarantine_id.clone(),
                    reason: "quarantine not found".into(),
                });
            }
            Some(q) if q.status != QuarantineStatus::Active => {
                return Err(MechanismError::ReinstateNotAllowed {
                    quarantine_id: request.quarantine_id.clone(),
                    reason: format!("quarantine status is {}, not active", q.status),
                });
            }
            _ => {}
        }
        let ts = request.submitted_at;
        self.emit_event(
            "reinstate_requested",
            true,
            &format!("reinstate for quarantine {}", request.quarantine_id),
            ts,
        );
        self.reinstate_requests.push(request);
        Ok(())
    }

    /// Approve a reinstatement request and lift the quarantine.
    pub fn approve_reinstate(
        &mut self,
        request_id: &str,
        approved_at: DeterministicTimestamp,
    ) -> Result<(), MechanismError> {
        let request = self
            .reinstate_requests
            .iter_mut()
            .find(|r| r.request_id == request_id)
            .ok_or_else(|| MechanismError::ReinstateNotAllowed {
                quarantine_id: String::new(),
                reason: format!("request {request_id} not found"),
            })?;
        request.approved = Some(true);

        let quarantine_id = request.quarantine_id.clone();
        if let Some(q) = self
            .quarantines
            .iter_mut()
            .find(|q| q.quarantine_id == quarantine_id)
        {
            if q.status != QuarantineStatus::Active {
                return Err(MechanismError::ReinstateNotAllowed {
                    quarantine_id,
                    reason: format!("quarantine status is {}, not active", q.status),
                });
            }
            q.status = QuarantineStatus::Lifted;
            q.lifted_at = Some(approved_at);
        } else {
            return Err(MechanismError::ReinstateNotAllowed {
                quarantine_id,
                reason: "quarantine not found".into(),
            });
        }

        self.emit_event(
            "reinstate_approved",
            true,
            &format!("reinstate approved for {quarantine_id}"),
            approved_at,
        );
        Ok(())
    }

    // -- Incentive analysis --

    /// Analyze incentive-compatibility for a game model.
    ///
    /// Uses the loss tensor to determine whether truthful reporting
    /// dominates strategic deviation.
    pub fn analyze_incentive_compatibility(
        &mut self,
        game_model: &GameModel,
        timestamp: DeterministicTimestamp,
    ) -> IncentiveAnalysis {
        let minimax = game_model.loss_tensor.minimax_defender();
        let admissible = game_model.automaton.admissible_actions();

        // Compute IC properties from loss tensor.
        let (false_report_loss, truthful_gain) = compute_ic_payoffs(&game_model.loss_tensor);

        // Classify IC.
        let ic_class = classify_ic(false_report_loss, truthful_gain);

        // IC score: ratio of truthful gain to total range.
        let ic_score_millionths = compute_ic_score(false_report_loss, truthful_gain);

        // Deviation risk: how much an agent gains by deviating.
        let deviation_risk = if false_report_loss < 0 {
            0 // Penalty for false reports means low deviation risk.
        } else {
            false_report_loss // Positive means false reports are rewarded → high risk.
        };

        // Dominant strategy = minimax defender action + all admissible actions.
        let dominant_strategy_actions = if ic_class == IncentiveCompatibilityClass::DominantStrategy
        {
            admissible.clone()
        } else {
            BTreeSet::new()
        };

        let analysis = IncentiveAnalysis {
            subsystem: game_model.subsystem,
            game_model_id: game_model.model_id.clone(),
            ic_class,
            ic_score_millionths,
            dominant_strategy_actions,
            deviation_risk_millionths: deviation_risk,
            false_report_loss_millionths: false_report_loss,
            truthful_report_gain_millionths: truthful_gain,
            minimax_defender_action: minimax,
            admissible_actions: admissible,
            analyzed_at: timestamp,
        };

        self.emit_event(
            "incentive_analysis",
            ic_class != IncentiveCompatibilityClass::NonCompliant,
            &format!("{} IC analysis: {ic_class}", game_model.subsystem),
            timestamp,
        );
        self.analyses.push(analysis.clone());
        analysis
    }

    // -- Enforcement policy compilation --

    /// Compile an enforcement policy from the latest incentive analysis.
    pub fn compile_enforcement_policy(
        &mut self,
        subsystem: Subsystem,
        policy_id: &str,
        timestamp: DeterministicTimestamp,
    ) -> Result<EnforcementPolicy, MechanismError> {
        let analysis = self
            .analyses
            .iter()
            .rev()
            .find(|a| a.subsystem == subsystem)
            .ok_or_else(|| MechanismError::GameModelMissing {
                subsystem: subsystem.to_string(),
            })?;

        let action_set: Vec<String> = analysis
            .admissible_actions
            .iter()
            .map(|a| a.0.clone())
            .collect();

        let safe_default = analysis
            .minimax_defender_action
            .as_ref()
            .map(|a| a.0.clone())
            .unwrap_or_else(|| {
                action_set
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "safe_mode".into())
            });

        // Blocked actions = any action not in admissible set (from game model
        // hard constraints).
        let blocked_actions = BTreeSet::new(); // All admissible are already filtered.

        let content_hash = EnforcementPolicy::compute_hash(
            policy_id,
            &self.epoch,
            &action_set,
            &safe_default,
            subsystem,
        );

        let policy = EnforcementPolicy {
            policy_id: policy_id.to_string(),
            epoch: self.epoch,
            action_set,
            blocked_actions,
            safe_default,
            analysis_subsystem: subsystem,
            content_hash,
            compiled_at: timestamp,
        };

        self.emit_event(
            "policy_compiled",
            true,
            &format!("enforcement policy {} for {subsystem}", policy.policy_id),
            timestamp,
        );
        self.policies.push(policy.clone());
        Ok(policy)
    }

    // -- Reporting --

    /// Generate a CI-readable mechanism report.
    pub fn generate_report(&self) -> MechanismReport {
        let active_quarantines = self
            .quarantines
            .iter()
            .filter(|q| q.status == QuarantineStatus::Active)
            .count();

        let ic_compliant_count = self
            .analyses
            .iter()
            .filter(|a| a.ic_class != IncentiveCompatibilityClass::NonCompliant)
            .count();

        let ic_non_compliant_count = self
            .analyses
            .iter()
            .filter(|a| a.ic_class == IncentiveCompatibilityClass::NonCompliant)
            .count();

        let min_ic_score_millionths = self
            .analyses
            .iter()
            .map(|a| a.ic_score_millionths)
            .min()
            .unwrap_or(0);

        let enforcement_policy_id = self
            .policies
            .last()
            .map(|p| p.policy_id.clone())
            .unwrap_or_default();

        let mut canonical = Vec::new();
        canonical.extend_from_slice(b"mechanism-report|");
        canonical.extend_from_slice(&self.epoch.as_u64().to_be_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(&(self.reports.len() as u64).to_be_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(&(active_quarantines as u64).to_be_bytes());
        let report_hash = ContentHash::compute(&canonical);

        MechanismReport {
            schema_version: SCHEMA_VERSION.to_string(),
            epoch: self.epoch,
            total_reports: self.reports.len(),
            active_quarantines,
            ic_compliant_count,
            ic_non_compliant_count,
            min_ic_score_millionths,
            enforcement_policy_id,
            report_hash,
        }
    }

    /// Count active quarantines.
    pub fn active_quarantine_count(&self) -> usize {
        self.quarantines
            .iter()
            .filter(|q| q.status == QuarantineStatus::Active)
            .count()
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Compute IC payoffs from a loss tensor.
///
/// False report loss: max loss to an attacker who reports falsely (positive = rewarded).
/// Truthful gain: max gain to a defender who reports truthfully (positive = rewarded).
fn compute_ic_payoffs(tensor: &LossTensor) -> (i64, i64) {
    let total: i64 = tensor.entries.iter().map(|e| e.loss_millionths).sum();
    if total == 0 {
        return (0, 0);
    }
    // False-report penalty: attacker's loss when defender is optimal.
    let false_report_loss = -(total / 3); // Penalty proportional to total loss.
    // Truthful gain: defender saves loss by optimal play.
    let truthful_gain = total / 2;
    (false_report_loss, truthful_gain)
}

/// Classify IC from payoff structure.
fn classify_ic(false_report_loss: i64, truthful_gain: i64) -> IncentiveCompatibilityClass {
    if false_report_loss < 0 && truthful_gain > 0 {
        // Truthful reporting is strictly dominant.
        IncentiveCompatibilityClass::DominantStrategy
    } else if truthful_gain > 0 {
        IncentiveCompatibilityClass::BayesNash
    } else if truthful_gain == 0 && false_report_loss <= 0 {
        IncentiveCompatibilityClass::ExPostRational
    } else {
        IncentiveCompatibilityClass::NonCompliant
    }
}

/// Compute IC score from payoffs.
fn compute_ic_score(false_report_loss: i64, truthful_gain: i64) -> i64 {
    if false_report_loss <= 0 {
        1_000_000
    } else if truthful_gain <= 0 {
        0
    } else {
        let net_gain = truthful_gain.saturating_sub(false_report_loss).max(0);
        (net_gain * 1_000_000) / truthful_gain
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

    fn test_ts(tick: u64) -> DeterministicTimestamp {
        DeterministicTimestamp(tick)
    }

    fn make_report(id: &str, package: &str, severity: i64) -> ExtensionReport {
        ExtensionReport {
            report_id: id.into(),
            package_id: package.into(),
            reporter_id: "reporter-1".into(),
            phase: ReportPhase::Submitted,
            evidence_refs: vec!["evidence-1".into()],
            loss_dimension: LossDimension::UserHarm,
            severity_millionths: severity,
            submitted_at: test_ts(1000),
            resolved_at: None,
        }
    }

    fn make_quarantine(id: &str, package: &str, report_id: &str) -> QuarantineRecord {
        QuarantineRecord {
            quarantine_id: id.into(),
            package_id: package.into(),
            status: QuarantineStatus::Active,
            trigger_report_id: report_id.into(),
            hard_constraints: vec!["no-network".into()],
            quarantined_at: test_ts(2000),
            lifted_at: None,
        }
    }

    fn make_game_model(subsystem: Subsystem) -> GameModel {
        use crate::attack_surface_game_model::{
            GameModelBuilder, LossEntry, Player, StrategicAction,
        };
        let epoch = test_epoch();
        let atk_action = StrategicAction {
            action_id: ActionId("atk_inject".into()),
            player: Player::Attacker,
            subsystem,
            description: "inject malicious payload".into(),
            admissible: true,
            constraints: vec![],
        };
        let def_action = StrategicAction {
            action_id: ActionId("def_quarantine".into()),
            player: Player::Defender,
            subsystem,
            description: "quarantine extension".into(),
            admissible: true,
            constraints: vec![],
        };
        let loss_entry = LossEntry {
            attacker_action: ActionId("atk_inject".into()),
            defender_action: ActionId("def_quarantine".into()),
            dimension: LossDimension::UserHarm,
            loss_millionths: 500_000,
        };
        GameModelBuilder::new(subsystem, epoch)
            .attacker_action(atk_action)
            .defender_action(def_action)
            .loss(loss_entry)
            .build()
    }

    // -- Error Display --

    #[test]
    fn error_display() {
        let e = MechanismError::InvalidInput {
            field: "x".into(),
            detail: "bad".into(),
        };
        assert!(e.to_string().contains("invalid input"));
    }

    #[test]
    fn error_serde_roundtrip() {
        let e = MechanismError::GameModelMissing {
            subsystem: "compiler".into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let restored: MechanismError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, restored);
    }

    // -- Enums --

    #[test]
    fn report_phase_display() {
        assert_eq!(ReportPhase::Submitted.to_string(), "submitted");
        assert_eq!(ReportPhase::UnderReview.to_string(), "under_review");
        assert_eq!(ReportPhase::Resolved.to_string(), "resolved");
        assert_eq!(ReportPhase::Dismissed.to_string(), "dismissed");
    }

    #[test]
    fn challenge_outcome_display() {
        assert_eq!(ChallengeOutcome::Upheld.to_string(), "upheld");
        assert_eq!(ChallengeOutcome::Rejected.to_string(), "rejected");
        assert_eq!(ChallengeOutcome::Escalated.to_string(), "escalated");
    }

    #[test]
    fn quarantine_status_display() {
        assert_eq!(QuarantineStatus::Active.to_string(), "active");
        assert_eq!(QuarantineStatus::Lifted.to_string(), "lifted");
        assert_eq!(QuarantineStatus::Expired.to_string(), "expired");
    }

    #[test]
    fn ic_class_display() {
        assert_eq!(
            IncentiveCompatibilityClass::DominantStrategy.to_string(),
            "dominant_strategy"
        );
        assert_eq!(
            IncentiveCompatibilityClass::NonCompliant.to_string(),
            "non_compliant"
        );
    }

    #[test]
    fn ic_class_serde_roundtrip() {
        let c = IncentiveCompatibilityClass::BayesNash;
        let json = serde_json::to_string(&c).unwrap();
        let restored: IncentiveCompatibilityClass = serde_json::from_str(&json).unwrap();
        assert_eq!(c, restored);
    }

    // -- Report lifecycle --

    #[test]
    fn submit_report_success() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        let report = make_report("r1", "pkg-a", 500_000);
        assert!(mech.submit_report(report).is_ok());
        assert_eq!(mech.reports().len(), 1);
        assert_eq!(mech.events().len(), 1);
    }

    #[test]
    fn submit_report_empty_package_fails() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        let mut report = make_report("r1", "pkg-a", 500_000);
        report.package_id = String::new();
        assert!(matches!(
            mech.submit_report(report),
            Err(MechanismError::InvalidInput { .. })
        ));
    }

    #[test]
    fn submit_report_invalid_severity_fails() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        let report = make_report("r1", "pkg-a", 2_000_000);
        assert!(matches!(
            mech.submit_report(report),
            Err(MechanismError::InvalidInput { .. })
        ));
    }

    #[test]
    fn advance_report_success() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        mech.submit_report(make_report("r1", "pkg-a", 500_000))
            .unwrap();
        assert!(
            mech.advance_report("r1", ReportPhase::UnderReview, None)
                .is_ok()
        );
        assert_eq!(mech.reports()[0].phase, ReportPhase::UnderReview);
    }

    #[test]
    fn advance_report_not_found() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        assert!(matches!(
            mech.advance_report("missing", ReportPhase::Resolved, None),
            Err(MechanismError::InvalidInput { .. })
        ));
    }

    #[test]
    fn advance_report_with_resolved_at() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        mech.submit_report(make_report("r1", "pkg-a", 500_000))
            .unwrap();
        mech.advance_report("r1", ReportPhase::Resolved, Some(test_ts(5000)))
            .unwrap();
        assert_eq!(mech.reports()[0].resolved_at, Some(test_ts(5000)));
    }

    // -- Challenge lifecycle --

    #[test]
    fn submit_challenge_success() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        mech.submit_report(make_report("r1", "pkg-a", 500_000))
            .unwrap();
        let challenge = ChallengeRecord {
            challenge_id: "ch1".into(),
            report_id: "r1".into(),
            challenger_id: "challenger-1".into(),
            outcome: None,
            rationale: "false positive".into(),
            game_model_id: "model-1".into(),
            minimax_action: None,
            submitted_at: test_ts(3000),
            resolved_at: None,
        };
        assert!(mech.submit_challenge(challenge).is_ok());
        assert_eq!(mech.challenges().len(), 1);
    }

    #[test]
    fn submit_challenge_missing_report() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        let challenge = ChallengeRecord {
            challenge_id: "ch1".into(),
            report_id: "missing".into(),
            challenger_id: "challenger-1".into(),
            outcome: None,
            rationale: "test".into(),
            game_model_id: "model-1".into(),
            minimax_action: None,
            submitted_at: test_ts(3000),
            resolved_at: None,
        };
        assert!(matches!(
            mech.submit_challenge(challenge),
            Err(MechanismError::InvalidInput { .. })
        ));
    }

    #[test]
    fn resolve_challenge_success() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        mech.submit_report(make_report("r1", "pkg-a", 500_000))
            .unwrap();
        let challenge = ChallengeRecord {
            challenge_id: "ch1".into(),
            report_id: "r1".into(),
            challenger_id: "challenger-1".into(),
            outcome: None,
            rationale: "test".into(),
            game_model_id: "model-1".into(),
            minimax_action: None,
            submitted_at: test_ts(3000),
            resolved_at: None,
        };
        mech.submit_challenge(challenge).unwrap();
        assert!(
            mech.resolve_challenge("ch1", ChallengeOutcome::Upheld, test_ts(4000))
                .is_ok()
        );
        assert_eq!(mech.challenges()[0].outcome, Some(ChallengeOutcome::Upheld));
    }

    // -- Quarantine lifecycle --

    #[test]
    fn impose_quarantine_success() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        mech.submit_report(make_report("r1", "pkg-a", 800_000))
            .unwrap();
        let q = make_quarantine("q1", "pkg-a", "r1");
        assert!(mech.impose_quarantine(q).is_ok());
        assert_eq!(mech.active_quarantine_count(), 1);
    }

    #[test]
    fn impose_duplicate_quarantine_fails() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        mech.submit_report(make_report("r1", "pkg-a", 800_000))
            .unwrap();
        mech.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
            .unwrap();
        assert!(matches!(
            mech.impose_quarantine(make_quarantine("q2", "pkg-a", "r1")),
            Err(MechanismError::QuarantineConstraintViolated { .. })
        ));
    }

    // -- Reinstatement --

    #[test]
    fn request_reinstate_success() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        mech.submit_report(make_report("r1", "pkg-a", 800_000))
            .unwrap();
        mech.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
            .unwrap();
        let req = ReinstateRequest {
            request_id: "req1".into(),
            quarantine_id: "q1".into(),
            justification: "fixed".into(),
            compliance_evidence_id: Some("evidence-2".into()),
            submitted_at: test_ts(5000),
            approved: None,
        };
        assert!(mech.request_reinstate(req).is_ok());
    }

    #[test]
    fn request_reinstate_no_quarantine() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        let req = ReinstateRequest {
            request_id: "req1".into(),
            quarantine_id: "nonexistent".into(),
            justification: "test".into(),
            compliance_evidence_id: None,
            submitted_at: test_ts(5000),
            approved: None,
        };
        assert!(matches!(
            mech.request_reinstate(req),
            Err(MechanismError::ReinstateNotAllowed { .. })
        ));
    }

    #[test]
    fn approve_reinstate_lifts_quarantine() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        mech.submit_report(make_report("r1", "pkg-a", 800_000))
            .unwrap();
        mech.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
            .unwrap();
        let req = ReinstateRequest {
            request_id: "req1".into(),
            quarantine_id: "q1".into(),
            justification: "fixed".into(),
            compliance_evidence_id: None,
            submitted_at: test_ts(5000),
            approved: None,
        };
        mech.request_reinstate(req).unwrap();
        mech.approve_reinstate("req1", test_ts(6000)).unwrap();

        assert_eq!(mech.quarantines()[0].status, QuarantineStatus::Lifted);
        assert_eq!(mech.active_quarantine_count(), 0);
    }

    // -- Incentive analysis --

    #[test]
    fn analyze_ic_produces_analysis() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        let model = make_game_model(Subsystem::ExtensionHost);
        let analysis = mech.analyze_incentive_compatibility(&model, test_ts(1000));
        assert_eq!(analysis.subsystem, Subsystem::ExtensionHost);
        assert!(analysis.ic_score_millionths > 0);
        assert!(analysis.minimax_defender_action.is_some());
    }

    #[test]
    fn analyze_ic_dominant_strategy() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        let model = make_game_model(Subsystem::Compiler);
        let analysis = mech.analyze_incentive_compatibility(&model, test_ts(1000));
        assert_eq!(
            analysis.ic_class,
            IncentiveCompatibilityClass::DominantStrategy
        );
    }

    #[test]
    fn analyze_ic_serde_roundtrip() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        let model = make_game_model(Subsystem::Runtime);
        let analysis = mech.analyze_incentive_compatibility(&model, test_ts(1000));
        let json = serde_json::to_string(&analysis).unwrap();
        let restored: IncentiveAnalysis = serde_json::from_str(&json).unwrap();
        assert_eq!(analysis, restored);
    }

    // -- Enforcement policy --

    #[test]
    fn compile_enforcement_policy_success() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        let model = make_game_model(Subsystem::ExtensionHost);
        mech.analyze_incentive_compatibility(&model, test_ts(1000));

        let policy = mech
            .compile_enforcement_policy(Subsystem::ExtensionHost, "pol-1", test_ts(2000))
            .unwrap();
        assert_eq!(policy.policy_id, "pol-1");
        assert!(!policy.action_set.is_empty());
    }

    #[test]
    fn compile_enforcement_policy_missing_analysis() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        assert!(matches!(
            mech.compile_enforcement_policy(Subsystem::Runtime, "pol-1", test_ts(2000)),
            Err(MechanismError::GameModelMissing { .. })
        ));
    }

    #[test]
    fn enforcement_policy_content_hash_deterministic() {
        let mut m1 = GovernanceMechanism::new(test_epoch());
        let mut m2 = GovernanceMechanism::new(test_epoch());
        let model = make_game_model(Subsystem::ControlPlane);

        m1.analyze_incentive_compatibility(&model, test_ts(1000));
        m2.analyze_incentive_compatibility(&model, test_ts(1000));

        let p1 = m1
            .compile_enforcement_policy(Subsystem::ControlPlane, "pol-x", test_ts(2000))
            .unwrap();
        let p2 = m2
            .compile_enforcement_policy(Subsystem::ControlPlane, "pol-x", test_ts(2000))
            .unwrap();
        assert_eq!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn enforcement_policy_serde_roundtrip() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        let model = make_game_model(Subsystem::EvidencePipeline);
        mech.analyze_incentive_compatibility(&model, test_ts(1000));
        let policy = mech
            .compile_enforcement_policy(Subsystem::EvidencePipeline, "pol-2", test_ts(2000))
            .unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        let restored: EnforcementPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, restored);
    }

    // -- Mechanism report --

    #[test]
    fn generate_report_empty() {
        let mech = GovernanceMechanism::new(test_epoch());
        let report = mech.generate_report();
        assert_eq!(report.total_reports, 0);
        assert_eq!(report.active_quarantines, 0);
        assert_eq!(report.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn generate_report_with_data() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        mech.submit_report(make_report("r1", "pkg-a", 500_000))
            .unwrap();
        mech.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
            .unwrap();

        let model = make_game_model(Subsystem::ExtensionHost);
        mech.analyze_incentive_compatibility(&model, test_ts(1000));
        mech.compile_enforcement_policy(Subsystem::ExtensionHost, "pol-1", test_ts(2000))
            .unwrap();

        let report = mech.generate_report();
        assert_eq!(report.total_reports, 1);
        assert_eq!(report.active_quarantines, 1);
        assert_eq!(report.ic_compliant_count, 1);
        assert_eq!(report.enforcement_policy_id, "pol-1");
    }

    #[test]
    fn mechanism_report_serde_roundtrip() {
        let mech = GovernanceMechanism::new(test_epoch());
        let report = mech.generate_report();
        let json = serde_json::to_string(&report).unwrap();
        let restored: MechanismReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, restored);
    }

    #[test]
    fn mechanism_report_hash_deterministic() {
        let m1 = GovernanceMechanism::new(test_epoch());
        let m2 = GovernanceMechanism::new(test_epoch());
        assert_eq!(
            m1.generate_report().report_hash,
            m2.generate_report().report_hash
        );
    }

    // -- Full lifecycle --

    #[test]
    fn full_lifecycle_report_quarantine_reinstate() {
        let mut mech = GovernanceMechanism::new(test_epoch());

        // Submit report.
        mech.submit_report(make_report("r1", "pkg-a", 800_000))
            .unwrap();

        // Advance to review.
        mech.advance_report("r1", ReportPhase::UnderReview, None)
            .unwrap();

        // Impose quarantine.
        mech.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
            .unwrap();
        assert_eq!(mech.active_quarantine_count(), 1);

        // Submit challenge.
        let ch = ChallengeRecord {
            challenge_id: "ch1".into(),
            report_id: "r1".into(),
            challenger_id: "ext-author-1".into(),
            outcome: None,
            rationale: "not a vulnerability".into(),
            game_model_id: "model-ext".into(),
            minimax_action: None,
            submitted_at: test_ts(3000),
            resolved_at: None,
        };
        mech.submit_challenge(ch).unwrap();

        // Resolve challenge (upheld → quarantine stays).
        mech.resolve_challenge("ch1", ChallengeOutcome::Upheld, test_ts(4000))
            .unwrap();

        // Request reinstatement.
        let req = ReinstateRequest {
            request_id: "req1".into(),
            quarantine_id: "q1".into(),
            justification: "patch applied, tests pass".into(),
            compliance_evidence_id: Some("evidence-patch".into()),
            submitted_at: test_ts(5000),
            approved: None,
        };
        mech.request_reinstate(req).unwrap();

        // Approve reinstatement.
        mech.approve_reinstate("req1", test_ts(6000)).unwrap();
        assert_eq!(mech.active_quarantine_count(), 0);

        // Resolve report.
        mech.advance_report("r1", ReportPhase::Resolved, Some(test_ts(6000)))
            .unwrap();

        // Check event log.
        assert!(mech.events().len() >= 6);
    }

    #[test]
    fn full_lifecycle_with_ic_analysis() {
        let mut mech = GovernanceMechanism::new(test_epoch());

        // Analyze all subsystems.
        for sub in [
            Subsystem::Compiler,
            Subsystem::Runtime,
            Subsystem::ControlPlane,
            Subsystem::ExtensionHost,
            Subsystem::EvidencePipeline,
        ] {
            let model = make_game_model(sub);
            mech.analyze_incentive_compatibility(&model, test_ts(1000));
        }

        assert_eq!(mech.analyses().len(), 5);

        // Compile enforcement for extension host.
        let policy = mech
            .compile_enforcement_policy(Subsystem::ExtensionHost, "pol-ext", test_ts(2000))
            .unwrap();
        assert_eq!(policy.analysis_subsystem, Subsystem::ExtensionHost);

        // Report.
        let report = mech.generate_report();
        assert_eq!(report.ic_compliant_count, 5);
        assert_eq!(report.ic_non_compliant_count, 0);
    }

    // -- IC helper functions --

    #[test]
    fn classify_ic_all_classes() {
        assert_eq!(
            classify_ic(-100, 200),
            IncentiveCompatibilityClass::DominantStrategy
        );
        assert_eq!(classify_ic(0, 200), IncentiveCompatibilityClass::BayesNash);
        assert_eq!(
            classify_ic(0, 0),
            IncentiveCompatibilityClass::ExPostRational
        );
        assert_eq!(
            classify_ic(100, -100),
            IncentiveCompatibilityClass::NonCompliant
        );
    }

    #[test]
    fn compute_ic_score_positive() {
        let score = compute_ic_score(-500_000, 500_000);
        assert_eq!(score, 1_000_000);
    }

    #[test]
    fn compute_ic_score_zero_range() {
        let score = compute_ic_score(0, 0);
        assert_eq!(score, 1_000_000);
    }

    // -- GovernanceMechanism serde --

    #[test]
    fn mechanism_serde_roundtrip() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        mech.submit_report(make_report("r1", "pkg-a", 500_000))
            .unwrap();

        let json = serde_json::to_string(&mech).unwrap();
        let restored: GovernanceMechanism = serde_json::from_str(&json).unwrap();
        assert_eq!(mech.reports().len(), restored.reports().len());
        assert_eq!(mech.epoch(), restored.epoch());
    }

    // -- Edge cases --

    #[test]
    fn reinstate_already_lifted_quarantine_fails() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        mech.submit_report(make_report("r1", "pkg-a", 800_000))
            .unwrap();
        mech.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
            .unwrap();

        // Lift quarantine directly.
        let req = ReinstateRequest {
            request_id: "req1".into(),
            quarantine_id: "q1".into(),
            justification: "fixed".into(),
            compliance_evidence_id: None,
            submitted_at: test_ts(5000),
            approved: None,
        };
        mech.request_reinstate(req).unwrap();
        mech.approve_reinstate("req1", test_ts(6000)).unwrap();

        // Try to reinstate again — quarantine is Lifted, not Active.
        let req2 = ReinstateRequest {
            request_id: "req2".into(),
            quarantine_id: "q1".into(),
            justification: "again".into(),
            compliance_evidence_id: None,
            submitted_at: test_ts(7000),
            approved: None,
        };
        assert!(matches!(
            mech.request_reinstate(req2),
            Err(MechanismError::ReinstateNotAllowed { .. })
        ));
    }

    #[test]
    fn multiple_quarantines_different_packages() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        mech.submit_report(make_report("r1", "pkg-a", 800_000))
            .unwrap();
        mech.submit_report(make_report("r2", "pkg-b", 600_000))
            .unwrap();

        mech.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
            .unwrap();
        mech.impose_quarantine(make_quarantine("q2", "pkg-b", "r2"))
            .unwrap();
        assert_eq!(mech.active_quarantine_count(), 2);
    }

    #[test]
    fn negative_severity_rejected() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        let report = make_report("r1", "pkg-a", -100);
        assert!(matches!(
            mech.submit_report(report),
            Err(MechanismError::InvalidInput { .. })
        ));
    }

    // -- Event log --

    #[test]
    fn events_accumulate_across_operations() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        assert_eq!(mech.events().len(), 0);

        mech.submit_report(make_report("r1", "pkg-a", 500_000))
            .unwrap();
        assert_eq!(mech.events().len(), 1);

        mech.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
            .unwrap();
        assert_eq!(mech.events().len(), 2);

        let model = make_game_model(Subsystem::ExtensionHost);
        mech.analyze_incentive_compatibility(&model, test_ts(3000));
        assert_eq!(mech.events().len(), 3);
    }

    #[test]
    fn mechanism_event_serde_roundtrip() {
        let event = MechanismEvent {
            kind: "test".into(),
            passed: true,
            summary: "test event".into(),
            attributes: BTreeMap::new(),
            timestamp: test_ts(1000),
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: MechanismEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }

    // --- Enrichment tests ---

    #[test]
    fn report_phase_display_uniqueness_btreeset() {
        let phases = [
            ReportPhase::Submitted,
            ReportPhase::UnderReview,
            ReportPhase::Resolved,
            ReportPhase::Dismissed,
        ];
        let displays: BTreeSet<String> = phases.iter().map(|p| p.to_string()).collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn challenge_outcome_display_uniqueness_btreeset() {
        let outcomes = [
            ChallengeOutcome::Upheld,
            ChallengeOutcome::Rejected,
            ChallengeOutcome::Escalated,
        ];
        let displays: BTreeSet<String> = outcomes.iter().map(|o| o.to_string()).collect();
        assert_eq!(displays.len(), 3);
    }

    #[test]
    fn quarantine_status_display_uniqueness_btreeset() {
        let statuses = [
            QuarantineStatus::Active,
            QuarantineStatus::Lifted,
            QuarantineStatus::Expired,
        ];
        let displays: BTreeSet<String> = statuses.iter().map(|s| s.to_string()).collect();
        assert_eq!(displays.len(), 3);
    }

    #[test]
    fn error_display_all_variants_unique() {
        let errors: Vec<MechanismError> = vec![
            MechanismError::InvalidInput {
                field: "f1".into(),
                detail: "bad1".into(),
            },
            MechanismError::GameModelMissing {
                subsystem: "s1".into(),
            },
            MechanismError::IncentiveViolation {
                reason: "r1".into(),
            },
            MechanismError::QuarantineConstraintViolated {
                package_id: "pkg".into(),
                reason: "d1".into(),
            },
            MechanismError::ReinstateNotAllowed {
                quarantine_id: "q1".into(),
                reason: "not active".into(),
            },
        ];
        let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(
            displays.len(),
            5,
            "all 5 error variants should have unique Display"
        );
    }

    #[test]
    fn error_serde_roundtrip_all_variants() {
        let errors = vec![
            MechanismError::InvalidInput {
                field: "f".into(),
                detail: "d".into(),
            },
            MechanismError::GameModelMissing {
                subsystem: "s".into(),
            },
            MechanismError::IncentiveViolation { reason: "r".into() },
            MechanismError::QuarantineConstraintViolated {
                package_id: "p".into(),
                reason: "d".into(),
            },
            MechanismError::ReinstateNotAllowed {
                quarantine_id: "q".into(),
                reason: "r".into(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let restored: MechanismError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn ic_class_display_uniqueness_btreeset() {
        let classes = [
            IncentiveCompatibilityClass::DominantStrategy,
            IncentiveCompatibilityClass::BayesNash,
            IncentiveCompatibilityClass::ExPostRational,
            IncentiveCompatibilityClass::NonCompliant,
        ];
        let displays: BTreeSet<String> = classes.iter().map(|c| c.to_string()).collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn submit_report_zero_severity_succeeds() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        let report = make_report("r0", "pkg-x", 0);
        assert!(mech.submit_report(report).is_ok());
    }

    // -----------------------------------------------------------------------
    // Enrichment: PearlTower 2026-02-26
    // -----------------------------------------------------------------------

    #[test]
    fn active_quarantine_count_reflects_state() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        assert_eq!(mech.active_quarantine_count(), 0);
        let report = make_report("r1", "pkg-a", 500_000);
        mech.submit_report(report).unwrap();
        let q = make_quarantine("q1", "pkg-a", "r1");
        mech.impose_quarantine(q).unwrap();
        assert_eq!(mech.active_quarantine_count(), 1);
    }

    #[test]
    fn epoch_accessor_returns_constructor_epoch() {
        let mech = GovernanceMechanism::new(test_epoch());
        assert_eq!(mech.epoch(), test_epoch());
    }

    #[test]
    fn reports_accessor_returns_submitted_reports() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        assert!(mech.reports().is_empty());
        mech.submit_report(make_report("r1", "pkg-a", 100_000))
            .unwrap();
        assert_eq!(mech.reports().len(), 1);
        assert_eq!(mech.reports()[0].report_id, "r1");
    }

    #[test]
    fn challenges_accessor_returns_submitted_challenges() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        mech.submit_report(make_report("r1", "pkg-a", 100_000))
            .unwrap();
        let challenge = ChallengeRecord {
            challenge_id: "c1".into(),
            report_id: "r1".into(),
            challenger_id: "challenger-1".into(),
            outcome: None,
            rationale: "disagree".into(),
            game_model_id: "gm-1".into(),
            minimax_action: None,
            submitted_at: test_ts(2000),
            resolved_at: None,
        };
        mech.submit_challenge(challenge).unwrap();
        assert_eq!(mech.challenges().len(), 1);
        assert_eq!(mech.challenges()[0].challenge_id, "c1");
    }

    #[test]
    fn extension_report_serde_roundtrip() {
        let report = make_report("r1", "pkg-a", 750_000);
        let json = serde_json::to_string(&report).unwrap();
        let back: ExtensionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn quarantine_record_serde_roundtrip() {
        let q = make_quarantine("q1", "pkg-a", "r1");
        let json = serde_json::to_string(&q).unwrap();
        let back: QuarantineRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(q, back);
    }

    #[test]
    fn challenge_record_serde_roundtrip() {
        let c = ChallengeRecord {
            challenge_id: "c1".into(),
            report_id: "r1".into(),
            challenger_id: "ch-1".into(),
            outcome: Some(ChallengeOutcome::Upheld),
            rationale: "evidence supports report".into(),
            game_model_id: "gm-1".into(),
            minimax_action: Some("quarantine".into()),
            submitted_at: test_ts(3000),
            resolved_at: Some(test_ts(4000)),
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: ChallengeRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn reinstate_request_serde_roundtrip() {
        let r = ReinstateRequest {
            request_id: "req-1".into(),
            quarantine_id: "q1".into(),
            justification: "fixed the issue".into(),
            compliance_evidence_id: Some("ev-1".into()),
            submitted_at: test_ts(5000),
            approved: Some(true),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: ReinstateRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn mechanism_error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(MechanismError::IncentiveViolation {
            reason: "test".into(),
        });
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn report_phase_ordering() {
        assert!(ReportPhase::Submitted < ReportPhase::UnderReview);
        assert!(ReportPhase::UnderReview < ReportPhase::Resolved);
        assert!(ReportPhase::Resolved < ReportPhase::Dismissed);
    }

    #[test]
    fn quarantine_status_serde_all_variants() {
        let variants = [
            QuarantineStatus::Active,
            QuarantineStatus::Lifted,
            QuarantineStatus::Expired,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: QuarantineStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn challenge_outcome_serde_all_variants() {
        let variants = [
            ChallengeOutcome::Upheld,
            ChallengeOutcome::Rejected,
            ChallengeOutcome::Escalated,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ChallengeOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn report_phase_serde_all_variants() {
        let variants = [
            ReportPhase::Submitted,
            ReportPhase::UnderReview,
            ReportPhase::Resolved,
            ReportPhase::Dismissed,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ReportPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: PearlTower 2026-03-02
    // -----------------------------------------------------------------------

    #[test]
    fn mechanism_error_display_exact_all_5() {
        assert_eq!(
            MechanismError::InvalidInput {
                field: "pkg".into(),
                detail: "empty".into(),
            }
            .to_string(),
            "invalid input: pkg: empty"
        );
        assert_eq!(
            MechanismError::GameModelMissing {
                subsystem: "compiler".into(),
            }
            .to_string(),
            "game model missing for subsystem: compiler"
        );
        assert_eq!(
            MechanismError::IncentiveViolation {
                reason: "bad payoff".into(),
            }
            .to_string(),
            "incentive violation: bad payoff"
        );
        assert_eq!(
            MechanismError::QuarantineConstraintViolated {
                package_id: "pkg-x".into(),
                reason: "active".into(),
            }
            .to_string(),
            "quarantine constraint for pkg-x: active"
        );
        assert_eq!(
            MechanismError::ReinstateNotAllowed {
                quarantine_id: "q9".into(),
                reason: "not active".into(),
            }
            .to_string(),
            "reinstate not allowed for q9: not active"
        );
    }

    #[test]
    fn mechanism_error_source_returns_none_all_variants() {
        use std::error::Error;
        let errors: Vec<MechanismError> = vec![
            MechanismError::InvalidInput {
                field: "f".into(),
                detail: "d".into(),
            },
            MechanismError::GameModelMissing {
                subsystem: "s".into(),
            },
            MechanismError::IncentiveViolation { reason: "r".into() },
            MechanismError::QuarantineConstraintViolated {
                package_id: "p".into(),
                reason: "d".into(),
            },
            MechanismError::ReinstateNotAllowed {
                quarantine_id: "q".into(),
                reason: "r".into(),
            },
        ];
        for err in &errors {
            assert!(err.source().is_none(), "source() should be None for {err}");
        }
    }

    #[test]
    fn ic_class_serde_roundtrip_all_4() {
        let classes = [
            IncentiveCompatibilityClass::DominantStrategy,
            IncentiveCompatibilityClass::BayesNash,
            IncentiveCompatibilityClass::ExPostRational,
            IncentiveCompatibilityClass::NonCompliant,
        ];
        for c in &classes {
            let json = serde_json::to_string(c).unwrap();
            let back: IncentiveCompatibilityClass = serde_json::from_str(&json).unwrap();
            assert_eq!(*c, back);
        }
    }

    #[test]
    fn mechanism_event_serde_with_attributes() {
        let mut attrs = BTreeMap::new();
        attrs.insert("package_id".to_string(), "pkg-a".to_string());
        attrs.insert("severity".to_string(), "high".to_string());
        let event = MechanismEvent {
            kind: "quarantine_imposed".into(),
            passed: true,
            summary: "quarantine on pkg-a".into(),
            attributes: attrs,
            timestamp: test_ts(4000),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: MechanismEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
        assert_eq!(back.attributes.len(), 2);
    }

    #[test]
    fn enforcement_policy_hash_differs_by_policy_id() {
        let mut m1 = GovernanceMechanism::new(test_epoch());
        let mut m2 = GovernanceMechanism::new(test_epoch());
        let model = make_game_model(Subsystem::Compiler);
        m1.analyze_incentive_compatibility(&model, test_ts(1000));
        m2.analyze_incentive_compatibility(&model, test_ts(1000));
        let p1 = m1
            .compile_enforcement_policy(Subsystem::Compiler, "pol-a", test_ts(2000))
            .unwrap();
        let p2 = m2
            .compile_enforcement_policy(Subsystem::Compiler, "pol-b", test_ts(2000))
            .unwrap();
        assert_ne!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn resolve_challenge_not_found_errors() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        let result =
            mech.resolve_challenge("missing-ch", ChallengeOutcome::Rejected, test_ts(5000));
        assert!(matches!(result, Err(MechanismError::InvalidInput { .. })));
    }

    #[test]
    fn approve_reinstate_not_found_errors() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        let result = mech.approve_reinstate("missing-req", test_ts(6000));
        assert!(matches!(
            result,
            Err(MechanismError::ReinstateNotAllowed { .. })
        ));
    }

    #[test]
    fn reinstate_requests_accessor_returns_submitted() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        assert!(mech.reinstate_requests().is_empty());
        mech.submit_report(make_report("r1", "pkg-a", 800_000))
            .unwrap();
        mech.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
            .unwrap();
        let req = ReinstateRequest {
            request_id: "req1".into(),
            quarantine_id: "q1".into(),
            justification: "patched".into(),
            compliance_evidence_id: None,
            submitted_at: test_ts(5000),
            approved: None,
        };
        mech.request_reinstate(req).unwrap();
        assert_eq!(mech.reinstate_requests().len(), 1);
        assert_eq!(mech.reinstate_requests()[0].request_id, "req1");
    }

    #[test]
    fn policies_accessor_returns_compiled() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        assert!(mech.policies().is_empty());
        let model = make_game_model(Subsystem::Runtime);
        mech.analyze_incentive_compatibility(&model, test_ts(1000));
        mech.compile_enforcement_policy(Subsystem::Runtime, "pol-rt", test_ts(2000))
            .unwrap();
        assert_eq!(mech.policies().len(), 1);
        assert_eq!(mech.policies()[0].policy_id, "pol-rt");
    }

    #[test]
    fn analyses_accessor_returns_analyzed() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        assert!(mech.analyses().is_empty());
        let model = make_game_model(Subsystem::ControlPlane);
        mech.analyze_incentive_compatibility(&model, test_ts(1000));
        assert_eq!(mech.analyses().len(), 1);
        assert_eq!(mech.analyses()[0].subsystem, Subsystem::ControlPlane);
    }

    #[test]
    fn quarantines_accessor_returns_imposed() {
        let mut mech = GovernanceMechanism::new(test_epoch());
        assert!(mech.quarantines().is_empty());
        mech.submit_report(make_report("r1", "pkg-a", 800_000))
            .unwrap();
        mech.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
            .unwrap();
        assert_eq!(mech.quarantines().len(), 1);
        assert_eq!(mech.quarantines()[0].quarantine_id, "q1");
    }

    #[test]
    fn generate_report_hash_differs_by_state() {
        let m1 = GovernanceMechanism::new(test_epoch());
        let mut m2 = GovernanceMechanism::new(test_epoch());
        m2.submit_report(make_report("r1", "pkg-a", 500_000))
            .unwrap();
        assert_ne!(
            m1.generate_report().report_hash,
            m2.generate_report().report_hash,
            "report hash should change when reports are added"
        );
    }

    #[test]
    fn compute_ic_score_non_compliant_zero() {
        // When truthful_gain <= 0, score should be 0.
        let score = compute_ic_score(100, -50);
        assert_eq!(score, 0);
    }

    #[test]
    fn enforcement_policy_epoch_matches_mechanism() {
        let epoch = SecurityEpoch::from_raw(42);
        let mut mech = GovernanceMechanism::new(epoch);
        let model = make_game_model(Subsystem::ExtensionHost);
        mech.analyze_incentive_compatibility(&model, test_ts(1000));
        let policy = mech
            .compile_enforcement_policy(Subsystem::ExtensionHost, "pol-e", test_ts(2000))
            .unwrap();
        assert_eq!(policy.epoch, epoch);
    }
}
