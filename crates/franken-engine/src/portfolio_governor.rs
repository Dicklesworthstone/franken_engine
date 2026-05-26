//! Portfolio governor scoring engine for moonshot lifecycle management.
//!
//! Computes rolling scorecards for moonshot initiatives and automates
//! stage-gate transitions based on pre-declared metric and artifact
//! thresholds.  Implements kill-switch, pause, and portfolio-level
//! optimization for risk-adjusted expected-value ranking.
//!
//! Fixed-point millionths (1_000_000 = 1.0) for all fractional values.
//!
//! All collections use `BTreeMap`/`BTreeSet` for deterministic iteration.
//!
//! Plan references: Section 10.15, subsection 9I.3 (Moonshot Portfolio
//! Governor), item 2 of 3.

pub mod governance_audit_ledger;

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use self::governance_audit_ledger::{
    GovernanceActor, GovernanceAuditLedger, GovernanceLedgerConfig,
};
use crate::moonshot_contract::{ArtifactType, MetricDirection, MoonshotContract, MoonshotStage};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Scorecard — rolling scorecard for a moonshot initiative
// ---------------------------------------------------------------------------

/// Rolling scorecard dimensions for a moonshot initiative.
///
/// All fractional fields are in millionths (1_000_000 = 1.0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scorecard {
    /// Moonshot contract identifier.
    pub moonshot_id: String,
    /// Expected value (risk-adjusted) in millionths.
    pub ev_millionths: i64,
    /// Confidence in the EV estimate (0..1_000_000).
    pub confidence_millionths: u64,
    /// Risk-of-harm probability (0..1_000_000).
    pub risk_of_harm_millionths: u64,
    /// Implementation friction indicator (0..1_000_000).
    pub implementation_friction_millionths: u64,
    /// Cross-initiative interference risk (0..1_000_000).
    pub cross_initiative_interference_millionths: u64,
    /// Operational burden estimate (0..1_000_000).
    pub operational_burden_millionths: u64,
    /// Timestamp when this scorecard was computed (nanoseconds).
    pub computed_at_ns: u64,
    /// Security epoch at computation time.
    pub epoch: SecurityEpoch,
}

impl Scorecard {
    /// Compute a risk-adjusted EV score for portfolio ranking.
    ///
    /// risk_adjusted_ev = ev * confidence / 1M - risk_of_harm * 2
    ///                  - interference - friction - burden
    ///
    /// Uses i128 intermediates to prevent overflow.
    pub fn risk_adjusted_ev(&self) -> i64 {
        let ev = self.ev_millionths as i128;
        let conf = self.confidence_millionths as i128;
        let risk = self.risk_of_harm_millionths as i128;
        let interference = self.cross_initiative_interference_millionths as i128;
        let friction = self.implementation_friction_millionths as i128;
        let burden = self.operational_burden_millionths as i128;
        let one_million = 1_000_000i128;

        let adjusted = ev * conf / one_million - risk * 2 - interference - friction - burden;
        adjusted.clamp(i64::MIN as i128, i64::MAX as i128) as i64
    }
}

// ---------------------------------------------------------------------------
// ArtifactEvidence — submitted artifacts for gate evaluation
// ---------------------------------------------------------------------------

/// Evidence of a completed artifact for gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactEvidence {
    /// Artifact identifier.
    pub artifact_id: String,
    /// Obligation this artifact fulfills.
    pub obligation_id: String,
    /// Type of artifact.
    pub artifact_type: ArtifactType,
    /// Submission timestamp (nanoseconds).
    pub submitted_at_ns: u64,
    /// Content hash for integrity verification.
    pub content_hash: String,
}

// ---------------------------------------------------------------------------
// MetricObservation — observed metric values
// ---------------------------------------------------------------------------

/// A single metric observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricObservation {
    /// Metric identifier (matches `TargetMetric::metric_id`).
    pub metric_id: String,
    /// Observed value in millionths.
    pub value_millionths: i64,
    /// Observation timestamp (nanoseconds).
    pub observed_at_ns: u64,
}

// ---------------------------------------------------------------------------
// GovernorDecision — governance decisions with rationale
// ---------------------------------------------------------------------------

/// Kind of governance decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernorDecisionKind {
    /// Promote to next stage.
    Promote {
        from: MoonshotStage,
        to: MoonshotStage,
    },
    /// Hold at current stage (insufficient signal).
    Hold { reason: String },
    /// Kill the moonshot (criteria triggered).
    Kill { triggered_criteria: Vec<String> },
    /// Pause for resource reallocation.
    Pause { reason: String },
    /// Resume from pause.
    Resume,
}

impl fmt::Display for GovernorDecisionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Promote { from, to } => write!(f, "promote({from}->{to})"),
            Self::Hold { reason } => write!(f, "hold({reason})"),
            Self::Kill { .. } => write!(f, "kill"),
            Self::Pause { reason } => write!(f, "pause({reason})"),
            Self::Resume => write!(f, "resume"),
        }
    }
}

/// A signed governance decision with full rationale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernorDecision {
    /// Unique decision identifier.
    pub decision_id: String,
    /// Moonshot contract identifier.
    pub moonshot_id: String,
    /// Decision type.
    pub kind: GovernorDecisionKind,
    /// Scorecard at decision time.
    pub scorecard: Scorecard,
    /// Decision timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Human-readable rationale.
    pub rationale: String,
}

// ---------------------------------------------------------------------------
// GovernorConfig — scoring and gate configuration
// ---------------------------------------------------------------------------

/// Configuration for the portfolio governor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernorConfig {
    /// Minimum confidence for automatic promotion (millionths, 0..1M).
    pub promotion_confidence_threshold_millionths: u64,
    /// Maximum tolerable risk for promotion (millionths, 0..1M).
    pub promotion_risk_threshold_millionths: u64,
    /// Confidence below which the governor issues a "hold" (millionths).
    pub hold_confidence_below_millionths: u64,
    /// Default scoring cadence (nanoseconds).
    pub scoring_cadence_ns: u64,
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            promotion_confidence_threshold_millionths: 750_000, // 0.75
            promotion_risk_threshold_millionths: 200_000,       // 0.20
            hold_confidence_below_millionths: 500_000,          // 0.50
            scoring_cadence_ns: 604_800_000_000_000,            // 7 days
        }
    }
}

// ---------------------------------------------------------------------------
// MoonshotStatus — runtime status of a moonshot
// ---------------------------------------------------------------------------

/// Runtime status of a moonshot initiative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoonshotStatus {
    /// Active and progressing.
    Active,
    /// Temporarily paused for resource reallocation.
    Paused { reason: String, paused_at_ns: u64 },
    /// Killed by governance decision.
    Killed { reason: String, killed_at_ns: u64 },
    /// Successfully completed (reached production).
    Completed { completed_at_ns: u64 },
}

impl fmt::Display for MoonshotStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Paused { .. } => write!(f, "paused"),
            Self::Killed { .. } => write!(f, "killed"),
            Self::Completed { .. } => write!(f, "completed"),
        }
    }
}

// ---------------------------------------------------------------------------
// MoonshotState — full runtime state for a tracked moonshot
// ---------------------------------------------------------------------------

/// Full runtime state for a tracked moonshot initiative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoonshotState {
    /// The governing contract.
    pub contract: MoonshotContract,
    /// Current runtime status.
    pub status: MoonshotStatus,
    /// History of computed scorecards.
    pub scorecard_history: Vec<Scorecard>,
    /// Submitted artifact evidence.
    pub completed_artifacts: Vec<ArtifactEvidence>,
    /// Metric observation history.
    pub metric_history: Vec<MetricObservation>,
    /// All governance decisions for this moonshot.
    pub decisions: Vec<GovernorDecision>,
    /// When the moonshot was registered (nanoseconds).
    pub started_at_ns: u64,
    /// Budget consumed so far (millionths, 0..1M).
    pub budget_spent_fraction_millionths: u64,
}

impl MoonshotState {
    /// Get the latest value for a specific metric.
    pub fn latest_metric(&self, metric_id: &str) -> Option<&MetricObservation> {
        self.metric_history
            .iter()
            .rev()
            .find(|m| m.metric_id == metric_id)
    }

    /// Get all completed obligation IDs.
    pub fn completed_obligation_ids(&self) -> Vec<String> {
        self.completed_artifacts
            .iter()
            .map(|a| a.obligation_id.clone())
            .collect()
    }

    /// Build a metric snapshot from latest observations.
    pub fn metric_snapshot(&self) -> BTreeMap<String, i64> {
        let mut snapshot = BTreeMap::new();
        for obs in &self.metric_history {
            snapshot.insert(obs.metric_id.clone(), obs.value_millionths);
        }
        snapshot
    }

    /// Whether this moonshot can accept new operations.
    pub fn is_active(&self) -> bool {
        matches!(self.status, MoonshotStatus::Active)
    }
}

// ---------------------------------------------------------------------------
// PortfolioGovernor — the scoring engine
// ---------------------------------------------------------------------------

/// Portfolio governor scoring engine.
///
/// Manages a set of moonshot initiatives, computes rolling scorecards,
/// and automates stage-gate decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortfolioGovernor {
    /// Governor configuration.
    pub config: GovernorConfig,
    /// Tracked moonshots keyed by contract ID.
    pub moonshots: BTreeMap<String, MoonshotState>,
    /// Current security epoch.
    pub epoch: SecurityEpoch,
    /// Monotonic decision counter.
    decision_counter: u64,
    /// Optional append-only governance audit ledger for decision artifacts.
    governance_ledger: Option<GovernanceAuditLedger>,
    /// System actor identifier used for automatic decisions.
    governance_actor_id: String,
}

impl PortfolioGovernor {
    /// Create a new governor with the given configuration and epoch.
    pub fn new(config: GovernorConfig, epoch: SecurityEpoch) -> Self {
        Self {
            config,
            moonshots: BTreeMap::new(),
            epoch,
            decision_counter: 0,
            governance_ledger: None,
            governance_actor_id: "portfolio-governor".to_string(),
        }
    }

    /// Enable append-only governance ledger recording for automatic decisions.
    pub fn enable_governance_audit_ledger(
        &mut self,
        config: GovernanceLedgerConfig,
        actor_id: impl Into<String>,
    ) -> Result<(), GovernorError> {
        let actor_id = actor_id.into();
        if actor_id.trim().is_empty() {
            return Err(GovernorError::InvalidGovernanceActor { actor_id });
        }

        let ledger =
            GovernanceAuditLedger::new(config).map_err(|err| GovernorError::LedgerConfig {
                reason: err.to_string(),
            })?;
        self.governance_actor_id = actor_id;
        self.governance_ledger = Some(ledger);
        Ok(())
    }

    /// Access the configured governance audit ledger, if enabled.
    pub fn governance_audit_ledger(&self) -> Option<&GovernanceAuditLedger> {
        self.governance_ledger.as_ref()
    }

    /// Register a new moonshot initiative.
    pub fn register_moonshot(
        &mut self,
        contract: MoonshotContract,
        now_ns: u64,
    ) -> Result<(), GovernorError> {
        contract
            .validate()
            .map_err(|e| GovernorError::InvalidContract {
                reason: e.to_string(),
            })?;

        if self.moonshots.contains_key(&contract.contract_id) {
            return Err(GovernorError::AlreadyRegistered {
                id: contract.contract_id.clone(),
            });
        }

        let id = contract.contract_id.clone();
        let state = MoonshotState {
            contract,
            status: MoonshotStatus::Active,
            scorecard_history: Vec::new(),
            completed_artifacts: Vec::new(),
            metric_history: Vec::new(),
            decisions: Vec::new(),
            started_at_ns: now_ns,
            budget_spent_fraction_millionths: 0,
        };
        self.moonshots.insert(id, state);
        Ok(())
    }

    /// Submit artifact evidence for a moonshot.
    pub fn submit_artifact(
        &mut self,
        moonshot_id: &str,
        evidence: ArtifactEvidence,
    ) -> Result<(), GovernorError> {
        let state =
            self.moonshots
                .get_mut(moonshot_id)
                .ok_or_else(|| GovernorError::MoonshotNotFound {
                    id: moonshot_id.into(),
                })?;

        if !state.is_active() {
            return Err(GovernorError::MoonshotNotActive {
                id: moonshot_id.into(),
            });
        }

        state.completed_artifacts.push(evidence);
        Ok(())
    }

    /// Record a metric observation for a moonshot.
    pub fn record_metric(
        &mut self,
        moonshot_id: &str,
        observation: MetricObservation,
    ) -> Result<(), GovernorError> {
        let state =
            self.moonshots
                .get_mut(moonshot_id)
                .ok_or_else(|| GovernorError::MoonshotNotFound {
                    id: moonshot_id.into(),
                })?;

        if !state.is_active() {
            return Err(GovernorError::MoonshotNotActive {
                id: moonshot_id.into(),
            });
        }

        state.metric_history.push(observation);
        Ok(())
    }

    /// Update budget consumption for a moonshot.
    pub fn update_budget(
        &mut self,
        moonshot_id: &str,
        budget_spent_fraction_millionths: u64,
    ) -> Result<(), GovernorError> {
        let state =
            self.moonshots
                .get_mut(moonshot_id)
                .ok_or_else(|| GovernorError::MoonshotNotFound {
                    id: moonshot_id.into(),
                })?;

        if !state.is_active() {
            return Err(GovernorError::MoonshotNotActive {
                id: moonshot_id.into(),
            });
        }

        state.budget_spent_fraction_millionths = budget_spent_fraction_millionths;
        Ok(())
    }

    /// Compute a scorecard for a moonshot.
    ///
    /// Scoring dimensions:
    /// - `ev_millionths`: from the contract's EV model (point estimate only).
    /// - `confidence_millionths`: based on metric observation count and
    ///   recency.
    /// - `risk_of_harm_millionths`: based on risk budget consumption.
    /// - `implementation_friction_millionths`: based on artifact completion
    ///   rate.
    /// - `cross_initiative_interference_millionths`: based on active
    ///   moonshot count.
    /// - `operational_burden_millionths`: based on budget consumption rate.
    pub fn compute_scorecard(
        &self,
        moonshot_id: &str,
        now_ns: u64,
    ) -> Result<Scorecard, GovernorError> {
        let state =
            self.moonshots
                .get(moonshot_id)
                .ok_or_else(|| GovernorError::MoonshotNotFound {
                    id: moonshot_id.into(),
                })?;

        // EV from contract model.
        let ev = state.contract.ev_model.net_ev_point_estimate().unwrap_or(0);

        // Confidence: based on metric count scaled to a reasonable cap.
        let metric_count = state.metric_history.len() as u64;
        let confidence = (metric_count * 100_000).min(1_000_000);

        // Risk: derived from budget consumption rate and stage progress.
        let risk = self.compute_risk_score(state);

        // Friction: inverse of artifact completion rate.
        let friction = self.compute_friction_score(state);

        // Interference: proportional to active moonshot count.
        let active_count = self.moonshots.values().filter(|s| s.is_active()).count() as u64;
        let interference = if active_count > 1 {
            ((active_count - 1) * 50_000).min(500_000)
        } else {
            0
        };

        // Burden: based on budget consumption rate.
        let burden = state.budget_spent_fraction_millionths;

        Ok(Scorecard {
            moonshot_id: moonshot_id.into(),
            ev_millionths: ev,
            confidence_millionths: confidence,
            risk_of_harm_millionths: risk,
            implementation_friction_millionths: friction,
            cross_initiative_interference_millionths: interference,
            operational_burden_millionths: burden,
            computed_at_ns: now_ns,
            epoch: self.epoch,
        })
    }

    /// Evaluate the stage gate for a moonshot and produce a governance
    /// decision.
    ///
    /// Returns `Promote` if all obligations are met, metrics pass
    /// thresholds, confidence is high enough, and risk is acceptable.
    /// Returns `Hold` if the signal is ambiguous.
    /// Returns `Kill` if kill criteria are triggered.
    pub fn evaluate_gate(
        &mut self,
        moonshot_id: &str,
        now_ns: u64,
    ) -> Result<GovernorDecision, GovernorError> {
        // First check kill criteria.
        if let Some(kill_decision) = self.check_kill_criteria(moonshot_id, now_ns)? {
            return Ok(kill_decision);
        }

        let scorecard = self.compute_scorecard(moonshot_id, now_ns)?;

        let state =
            self.moonshots
                .get(moonshot_id)
                .ok_or_else(|| GovernorError::MoonshotNotFound {
                    id: moonshot_id.into(),
                })?;

        let current_stage = state.contract.current_stage;

        // Check if already at production (completed).
        if current_stage == MoonshotStage::Production {
            let decision = self.make_decision(
                moonshot_id,
                GovernorDecisionKind::Hold {
                    reason: "already at production stage".into(),
                },
                scorecard,
                now_ns,
                "Moonshot is already at production stage; no further promotion possible.",
            )?;
            return Ok(decision);
        }

        // Check artifact obligations for current stage.
        let obligation_ids = state.completed_obligation_ids();
        let obligations_met = state
            .contract
            .stage_obligations_met(current_stage, &obligation_ids);

        if !obligations_met {
            let decision = self.make_decision(
                moonshot_id,
                GovernorDecisionKind::Hold {
                    reason: "artifact obligations not met".into(),
                },
                scorecard,
                now_ns,
                "Stage artifact obligations are incomplete; cannot promote.",
            )?;
            return Ok(decision);
        }

        // Check confidence threshold.
        if scorecard.confidence_millionths < self.config.hold_confidence_below_millionths {
            let decision = self.make_decision(
                moonshot_id,
                GovernorDecisionKind::Hold {
                    reason: "insufficient confidence".into(),
                },
                scorecard,
                now_ns,
                "Confidence is below the hold threshold; need more evidence.",
            )?;
            return Ok(decision);
        }

        // Check risk threshold.
        if scorecard.risk_of_harm_millionths > self.config.promotion_risk_threshold_millionths {
            let decision = self.make_decision(
                moonshot_id,
                GovernorDecisionKind::Hold {
                    reason: "risk too high".into(),
                },
                scorecard,
                now_ns,
                "Risk-of-harm exceeds promotion threshold.",
            )?;
            return Ok(decision);
        }

        // Check promotion confidence.
        if scorecard.confidence_millionths < self.config.promotion_confidence_threshold_millionths {
            let decision = self.make_decision(
                moonshot_id,
                GovernorDecisionKind::Hold {
                    reason: "confidence below promotion threshold".into(),
                },
                scorecard,
                now_ns,
                "Confidence is above hold but below promotion threshold.",
            )?;
            return Ok(decision);
        }

        // All checks pass — promote.
        let next_stage = next_stage(current_stage).ok_or(GovernorError::InvalidTransition {
            from: current_stage,
            to: current_stage,
        })?;

        let decision = self.make_decision(
            moonshot_id,
            GovernorDecisionKind::Promote {
                from: current_stage,
                to: next_stage,
            },
            scorecard,
            now_ns,
            &format!("All gate criteria met; promoting from {current_stage} to {next_stage}."),
        )?;

        // Apply the promotion.
        let state = self
            .moonshots
            .get_mut(moonshot_id)
            .expect("operation should succeed for valid inputs");
        state.contract.current_stage = next_stage;

        // If promoted to Production, mark completed.
        if next_stage == MoonshotStage::Production {
            state.status = MoonshotStatus::Completed {
                completed_at_ns: now_ns,
            };
        }

        Ok(decision)
    }

    /// Check if any kill criteria are triggered for a moonshot.
    pub fn check_kill_criteria(
        &mut self,
        moonshot_id: &str,
        now_ns: u64,
    ) -> Result<Option<GovernorDecision>, GovernorError> {
        let scorecard = self.compute_scorecard(moonshot_id, now_ns)?;

        let state =
            self.moonshots
                .get(moonshot_id)
                .ok_or_else(|| GovernorError::MoonshotNotFound {
                    id: moonshot_id.into(),
                })?;

        if !state.is_active() {
            return Ok(None);
        }

        let elapsed_ns = now_ns.saturating_sub(state.started_at_ns);
        let metrics = state.metric_snapshot();

        let triggered = state.contract.check_kill_criteria(
            &metrics,
            elapsed_ns,
            state.budget_spent_fraction_millionths,
        );

        if triggered.is_empty() {
            return Ok(None);
        }

        let criterion_ids: Vec<String> = triggered.iter().map(|c| c.criterion_id.clone()).collect();

        let rationale = format!("Kill criteria triggered: {}", criterion_ids.join(", "));

        let decision = self.make_decision(
            moonshot_id,
            GovernorDecisionKind::Kill {
                triggered_criteria: criterion_ids,
            },
            scorecard,
            now_ns,
            &rationale,
        )?;

        // Apply the kill.
        let state = self
            .moonshots
            .get_mut(moonshot_id)
            .expect("operation should succeed for valid inputs");
        state.status = MoonshotStatus::Killed {
            reason: rationale,
            killed_at_ns: now_ns,
        };

        Ok(Some(decision))
    }

    /// Pause a moonshot for temporary resource reallocation.
    pub fn pause_moonshot(
        &mut self,
        moonshot_id: &str,
        reason: &str,
        now_ns: u64,
    ) -> Result<GovernorDecision, GovernorError> {
        let scorecard = self.compute_scorecard(moonshot_id, now_ns)?;

        let state =
            self.moonshots
                .get_mut(moonshot_id)
                .ok_or_else(|| GovernorError::MoonshotNotFound {
                    id: moonshot_id.into(),
                })?;

        if !state.is_active() {
            return Err(GovernorError::MoonshotNotActive {
                id: moonshot_id.into(),
            });
        }

        state.status = MoonshotStatus::Paused {
            reason: reason.into(),
            paused_at_ns: now_ns,
        };

        let decision = self.make_decision(
            moonshot_id,
            GovernorDecisionKind::Pause {
                reason: reason.into(),
            },
            scorecard,
            now_ns,
            &format!("Paused: {reason}"),
        )?;

        Ok(decision)
    }

    /// Resume a paused moonshot.
    pub fn resume_moonshot(
        &mut self,
        moonshot_id: &str,
        now_ns: u64,
    ) -> Result<GovernorDecision, GovernorError> {
        let scorecard = self.compute_scorecard(moonshot_id, now_ns)?;

        let state =
            self.moonshots
                .get_mut(moonshot_id)
                .ok_or_else(|| GovernorError::MoonshotNotFound {
                    id: moonshot_id.into(),
                })?;

        if !matches!(state.status, MoonshotStatus::Paused { .. }) {
            return Err(GovernorError::NotPaused {
                id: moonshot_id.into(),
            });
        }

        state.status = MoonshotStatus::Active;

        let decision = self.make_decision(
            moonshot_id,
            GovernorDecisionKind::Resume,
            scorecard,
            now_ns,
            "Resumed from pause.",
        )?;

        Ok(decision)
    }

    /// Rank all active moonshots by risk-adjusted EV (descending).
    ///
    /// Returns a list of (moonshot_id, risk_adjusted_ev) pairs sorted
    /// from highest to lowest.
    pub fn rank_portfolio(&self, now_ns: u64) -> Vec<(String, i64)> {
        let mut rankings: Vec<(String, i64)> = self
            .moonshots
            .iter()
            .filter(|(_, s)| s.is_active())
            .filter_map(|(id, _)| {
                self.compute_scorecard(id, now_ns)
                    .ok()
                    .map(|sc| (id.clone(), sc.risk_adjusted_ev()))
            })
            .collect();

        rankings.sort_by_key(|(_, ev)| std::cmp::Reverse(*ev));
        rankings
    }

    /// Get the latest scorecard for a moonshot (if any).
    pub fn latest_scorecard(&self, moonshot_id: &str) -> Option<&Scorecard> {
        self.moonshots
            .get(moonshot_id)
            .and_then(|s| s.scorecard_history.last())
    }

    /// Get all decisions for a moonshot.
    pub fn decisions(&self, moonshot_id: &str) -> Option<&[GovernorDecision]> {
        self.moonshots
            .get(moonshot_id)
            .map(|s| s.decisions.as_slice())
    }

    // -- Internal helpers --

    fn make_decision(
        &mut self,
        moonshot_id: &str,
        kind: GovernorDecisionKind,
        scorecard: Scorecard,
        now_ns: u64,
        rationale: &str,
    ) -> Result<GovernorDecision, GovernorError> {
        self.decision_counter += 1;
        let decision = GovernorDecision {
            decision_id: format!("gov-{}", self.decision_counter),
            moonshot_id: moonshot_id.into(),
            kind,
            scorecard: scorecard.clone(),
            timestamp_ns: now_ns,
            epoch: self.epoch,
            rationale: rationale.into(),
        };

        if let Some(ledger) = self.governance_ledger.as_mut() {
            let (artifact_references, moonshot_started_at_ns) = self
                .moonshots
                .get(moonshot_id)
                .map(|state| {
                    (
                        state
                            .completed_artifacts
                            .iter()
                            .map(|artifact| {
                                format!(
                                    "artifact://{}/{}",
                                    artifact.artifact_id, artifact.content_hash
                                )
                            })
                            .collect(),
                        Some(state.started_at_ns),
                    )
                })
                .unwrap_or_else(|| (Vec::new(), None));

            ledger
                .append_governor_decision(
                    &decision,
                    GovernanceActor::System(self.governance_actor_id.clone()),
                    artifact_references,
                    moonshot_started_at_ns,
                )
                .map_err(|err| GovernorError::LedgerWriteFailed {
                    decision_id: decision.decision_id.clone(),
                    reason: err.to_string(),
                })?;
        }

        if let Some(state) = self.moonshots.get_mut(moonshot_id) {
            state.scorecard_history.push(scorecard);
            state.decisions.push(decision.clone());
        }

        Ok(decision)
    }

    fn compute_risk_score(&self, state: &MoonshotState) -> u64 {
        // Risk increases with budget consumption.
        let budget_risk = state.budget_spent_fraction_millionths / 2;

        // Risk increases if metric targets are not being met.
        let mut metric_risk: u64 = 0;
        let metrics = state.metric_snapshot();
        for target in &state.contract.target_metrics {
            if let Some(&current) = metrics.get(&target.metric_id) {
                let missing = match target.direction {
                    MetricDirection::HigherIsBetter => current < target.threshold_millionths,
                    MetricDirection::LowerIsBetter => current > target.threshold_millionths,
                };
                if missing {
                    metric_risk = metric_risk.saturating_add(100_000);
                }
            }
        }

        (budget_risk + metric_risk).min(1_000_000)
    }

    fn compute_friction_score(&self, state: &MoonshotState) -> u64 {
        let total_obligations = state.contract.artifact_obligations.len() as u64;
        if total_obligations == 0 {
            return 0;
        }
        let completed = state
            .completed_obligation_ids()
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len() as u64;
        let completion_rate = completed * 1_000_000 / total_obligations;
        // Friction is inverse of completion: high completion = low friction.
        1_000_000u64.saturating_sub(completion_rate)
    }
}

/// Get the next stage after the given one.
fn next_stage(stage: MoonshotStage) -> Option<MoonshotStage> {
    match stage {
        MoonshotStage::Research => Some(MoonshotStage::Shadow),
        MoonshotStage::Shadow => Some(MoonshotStage::Canary),
        MoonshotStage::Canary => Some(MoonshotStage::Production),
        MoonshotStage::Production => None,
    }
}

// ---------------------------------------------------------------------------
// GovernorError — errors from governor operations
// ---------------------------------------------------------------------------

/// Errors from portfolio governor operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernorError {
    /// Moonshot not found in the portfolio.
    MoonshotNotFound { id: String },
    /// Moonshot is not in an active state.
    MoonshotNotActive { id: String },
    /// Contract validation failed.
    InvalidContract { reason: String },
    /// Stage transition is invalid.
    InvalidTransition {
        from: MoonshotStage,
        to: MoonshotStage,
    },
    /// Moonshot is already registered.
    AlreadyRegistered { id: String },
    /// Moonshot is not in paused state.
    NotPaused { id: String },
    /// Governance ledger configuration is invalid.
    LedgerConfig { reason: String },
    /// A decision could not be persisted in the governance ledger.
    LedgerWriteFailed { decision_id: String, reason: String },
    /// Governance actor identifier is invalid.
    InvalidGovernanceActor { actor_id: String },
}

impl fmt::Display for GovernorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MoonshotNotFound { id } => write!(f, "moonshot not found: {id}"),
            Self::MoonshotNotActive { id } => {
                write!(f, "moonshot not active: {id}")
            }
            Self::InvalidContract { reason } => {
                write!(f, "invalid contract: {reason}")
            }
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid transition: {from} -> {to}")
            }
            Self::AlreadyRegistered { id } => {
                write!(f, "already registered: {id}")
            }
            Self::NotPaused { id } => write!(f, "not paused: {id}"),
            Self::LedgerConfig { reason } => {
                write!(f, "invalid governance ledger config: {reason}")
            }
            Self::LedgerWriteFailed {
                decision_id,
                reason,
            } => {
                write!(
                    f,
                    "failed to persist decision {decision_id} in ledger: {reason}"
                )
            }
            Self::InvalidGovernanceActor { actor_id } => {
                write!(f, "invalid governance actor identifier: {actor_id}")
            }
        }
    }
}

impl std::error::Error for GovernorError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moonshot_contract::*;

    // -- Test helpers --

    fn test_hypothesis() -> Hypothesis {
        Hypothesis {
            problem: "Detection latency too high".into(),
            mechanism: "Fleet evidence sharing".into(),
            expected_outcome: "50% latency reduction".into(),
            falsification_criteria: vec!["No improvement in 90 days".into()],
        }
    }

    fn test_metrics() -> Vec<TargetMetric> {
        vec![TargetMetric {
            metric_id: "latency_p50".into(),
            description: "Median latency".into(),
            threshold_millionths: 250_000_000,
            direction: MetricDirection::LowerIsBetter,
            measurement_method: MeasurementMethod::FleetTelemetry,
            evaluation_cadence_ns: 86_400_000_000_000,
        }]
    }

    fn test_ev_model() -> EvModel {
        let mut params = BTreeMap::new();
        params.insert("value".into(), 600_000i64);
        EvModel {
            success_distribution: DistributionType::PointEstimate,
            distribution_params: params,
            cost_millionths: 500_000,
            benefit_on_success_millionths: 5_000_000,
            harm_on_failure_millionths: -200_000,
        }
    }

    fn test_risk_budget() -> RiskBudget {
        let mut caps = BTreeMap::new();
        caps.insert(RiskDimension::SecurityRegression, 50_000u64);
        RiskBudget {
            dimension_caps: caps,
        }
    }

    fn test_obligations() -> Vec<ArtifactObligation> {
        vec![
            ArtifactObligation {
                obligation_id: "proof-research".into(),
                required_at_stage: MoonshotStage::Research,
                artifact_type: ArtifactType::Proof,
                description: "Proof of concept".into(),
                blocking: true,
            },
            ArtifactObligation {
                obligation_id: "bench-shadow".into(),
                required_at_stage: MoonshotStage::Shadow,
                artifact_type: ArtifactType::BenchmarkResult,
                description: "Shadow benchmarks".into(),
                blocking: true,
            },
        ]
    }

    fn test_kill_criteria() -> Vec<KillCriterion> {
        vec![
            KillCriterion {
                criterion_id: "time-kill".into(),
                trigger: KillTrigger::TimeExpiry,
                condition: "180 days without promotion".into(),
                threshold_millionths: None,
                max_duration_ns: Some(15_552_000_000_000_000),
            },
            KillCriterion {
                criterion_id: "budget-kill".into(),
                trigger: KillTrigger::BudgetExhaustedNoSignal,
                condition: "Budget exhausted without signal".into(),
                threshold_millionths: None,
                max_duration_ns: None,
            },
        ]
    }

    fn test_rollback() -> RollbackPlan {
        RollbackPlan {
            steps: vec![RollbackStep {
                step_number: 1,
                description: "Revert to previous policy".into(),
                verification: "frankenctl verify".into(),
            }],
            artifact_references: vec!["checkpoint-1".into()],
            expected_state_after_rollback: "Pre-moonshot state".into(),
        }
    }

    fn test_contract() -> MoonshotContract {
        MoonshotContract {
            contract_id: "mc-test-001".into(),
            version: ContractVersion { major: 1, minor: 0 },
            hypothesis: test_hypothesis(),
            target_metrics: test_metrics(),
            ev_model: test_ev_model(),
            risk_budget: test_risk_budget(),
            artifact_obligations: test_obligations(),
            kill_criteria: test_kill_criteria(),
            rollback_plan: test_rollback(),
            current_stage: MoonshotStage::Research,
            epoch: SecurityEpoch::from_raw(1),
            governance_signature: Some("sig:gov".into()),
            metadata: BTreeMap::new(),
        }
    }

    fn test_governor() -> PortfolioGovernor {
        PortfolioGovernor::new(GovernorConfig::default(), SecurityEpoch::from_raw(1))
    }

    fn register_test_moonshot(gov: &mut PortfolioGovernor) {
        gov.register_moonshot(test_contract(), 1_000_000_000)
            .expect("operation should succeed for valid inputs");
    }

    // -- Registration tests --

    #[test]
    fn register_moonshot_ok() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        assert_eq!(gov.moonshots.len(), 1);
        assert!(gov.moonshots.contains_key("mc-test-001"));
    }

    #[test]
    fn register_duplicate_fails() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        let err = gov
            .register_moonshot(test_contract(), 2_000_000_000)
            .unwrap_err();
        assert!(matches!(err, GovernorError::AlreadyRegistered { .. }));
    }

    #[test]
    fn register_invalid_contract_fails() {
        let mut gov = test_governor();
        let mut c = test_contract();
        c.contract_id = String::new();
        let err = gov.register_moonshot(c, 1_000_000_000).unwrap_err();
        assert!(matches!(err, GovernorError::InvalidContract { .. }));
    }

    // -- Artifact submission tests --

    #[test]
    fn submit_artifact_ok() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        let evidence = ArtifactEvidence {
            artifact_id: "art-001".into(),
            obligation_id: "proof-research".into(),
            artifact_type: ArtifactType::Proof,
            submitted_at_ns: 2_000_000_000,
            content_hash: "hash-abc".into(),
        };
        gov.submit_artifact("mc-test-001", evidence)
            .expect("operation should succeed for valid inputs");
        assert_eq!(gov.moonshots["mc-test-001"].completed_artifacts.len(), 1);
    }

    #[test]
    fn submit_artifact_not_found() {
        let mut gov = test_governor();
        let evidence = ArtifactEvidence {
            artifact_id: "art-001".into(),
            obligation_id: "x".into(),
            artifact_type: ArtifactType::Proof,
            submitted_at_ns: 0,
            content_hash: "hash".into(),
        };
        let err = gov.submit_artifact("nonexistent", evidence).unwrap_err();
        assert!(matches!(err, GovernorError::MoonshotNotFound { .. }));
    }

    // -- Metric recording tests --

    #[test]
    fn record_metric_ok() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        let obs = MetricObservation {
            metric_id: "latency_p50".into(),
            value_millionths: 200_000_000,
            observed_at_ns: 3_000_000_000,
        };
        gov.record_metric("mc-test-001", obs)
            .expect("operation should succeed for valid inputs");
        assert_eq!(gov.moonshots["mc-test-001"].metric_history.len(), 1);
    }

    #[test]
    fn record_metric_not_active() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        gov.moonshots
            .get_mut("mc-test-001")
            .expect("operation should succeed for valid inputs")
            .status = MoonshotStatus::Killed {
            reason: "test".into(),
            killed_at_ns: 0,
        };
        let obs = MetricObservation {
            metric_id: "x".into(),
            value_millionths: 0,
            observed_at_ns: 0,
        };
        let err = gov.record_metric("mc-test-001", obs).unwrap_err();
        assert!(matches!(err, GovernorError::MoonshotNotActive { .. }));
    }

    // -- Scorecard tests --

    #[test]
    fn compute_scorecard_ok() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        let sc = gov
            .compute_scorecard("mc-test-001", 5_000_000_000)
            .expect("operation should succeed for valid inputs");
        assert_eq!(sc.moonshot_id, "mc-test-001");
        assert!(sc.ev_millionths > 0);
        assert_eq!(sc.confidence_millionths, 0); // no metrics yet
    }

    #[test]
    fn compute_scorecard_with_metrics() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        // Add 10 metric observations to build confidence.
        for i in 0..10 {
            gov.record_metric(
                "mc-test-001",
                MetricObservation {
                    metric_id: "latency_p50".into(),
                    value_millionths: 200_000_000,
                    observed_at_ns: (i + 1) * 1_000_000_000,
                },
            )
            .expect("operation should succeed for valid inputs");
        }
        let sc = gov
            .compute_scorecard("mc-test-001", 11_000_000_000)
            .expect("operation should succeed for valid inputs");
        assert_eq!(sc.confidence_millionths, 1_000_000); // 10 * 100_000 = 1M
    }

    #[test]
    fn scorecard_risk_adjusted_ev() {
        let sc = Scorecard {
            moonshot_id: "test".into(),
            ev_millionths: 2_000_000,
            confidence_millionths: 800_000,
            risk_of_harm_millionths: 100_000,
            implementation_friction_millionths: 50_000,
            cross_initiative_interference_millionths: 30_000,
            operational_burden_millionths: 20_000,
            computed_at_ns: 0,
            epoch: SecurityEpoch::from_raw(1),
        };
        // ev * conf / 1M - risk*2 - interference - friction - burden
        // = 2M * 800K / 1M - 200K - 30K - 50K - 20K
        // = 1_600_000 - 300_000 = 1_300_000
        assert_eq!(sc.risk_adjusted_ev(), 1_300_000);
    }

    #[test]
    fn scorecard_not_found() {
        let gov = test_governor();
        let err = gov.compute_scorecard("nonexistent", 0).unwrap_err();
        assert!(matches!(err, GovernorError::MoonshotNotFound { .. }));
    }

    // -- Gate evaluation tests --

    #[test]
    fn gate_hold_insufficient_artifacts() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        // Add enough metrics for confidence but no artifacts.
        for i in 0..10 {
            gov.record_metric(
                "mc-test-001",
                MetricObservation {
                    metric_id: "latency_p50".into(),
                    value_millionths: 200_000_000,
                    observed_at_ns: (i + 1) * 1_000_000_000,
                },
            )
            .expect("operation should succeed for valid inputs");
        }
        let decision = gov
            .evaluate_gate("mc-test-001", 11_000_000_000)
            .expect("operation should succeed for valid inputs");
        assert!(matches!(decision.kind, GovernorDecisionKind::Hold { .. }));
        assert!(decision.rationale.contains("obligation"));
    }

    #[test]
    fn gate_hold_insufficient_confidence() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        // Submit required artifact.
        gov.submit_artifact(
            "mc-test-001",
            ArtifactEvidence {
                artifact_id: "art-1".into(),
                obligation_id: "proof-research".into(),
                artifact_type: ArtifactType::Proof,
                submitted_at_ns: 1_000_000_000,
                content_hash: "hash-1".into(),
            },
        )
        .expect("operation should succeed for valid inputs");
        // Only 2 metrics = 200_000 confidence (below 500K hold threshold).
        for i in 0..2 {
            gov.record_metric(
                "mc-test-001",
                MetricObservation {
                    metric_id: "latency_p50".into(),
                    value_millionths: 200_000_000,
                    observed_at_ns: (i + 1) * 1_000_000_000,
                },
            )
            .expect("operation should succeed for valid inputs");
        }
        let decision = gov
            .evaluate_gate("mc-test-001", 3_000_000_000)
            .expect("operation should succeed for valid inputs");
        assert!(matches!(decision.kind, GovernorDecisionKind::Hold { .. }));
        assert!(decision.rationale.contains("Confidence"));
    }

    #[test]
    fn gate_promote_all_criteria_met() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        // Submit required artifact.
        gov.submit_artifact(
            "mc-test-001",
            ArtifactEvidence {
                artifact_id: "art-1".into(),
                obligation_id: "proof-research".into(),
                artifact_type: ArtifactType::Proof,
                submitted_at_ns: 1_000_000_000,
                content_hash: "hash-1".into(),
            },
        )
        .expect("operation should succeed for valid inputs");
        // Add 8 metrics for high confidence (800K > 750K threshold).
        for i in 0..8 {
            gov.record_metric(
                "mc-test-001",
                MetricObservation {
                    metric_id: "latency_p50".into(),
                    value_millionths: 200_000_000, // below 250M threshold = good
                    observed_at_ns: (i + 1) * 1_000_000_000,
                },
            )
            .expect("operation should succeed for valid inputs");
        }
        let decision = gov
            .evaluate_gate("mc-test-001", 9_000_000_000)
            .expect("operation should succeed for valid inputs");
        assert!(matches!(
            decision.kind,
            GovernorDecisionKind::Promote {
                from: MoonshotStage::Research,
                to: MoonshotStage::Shadow
            }
        ));
        // Contract stage should be updated.
        assert_eq!(
            gov.moonshots["mc-test-001"].contract.current_stage,
            MoonshotStage::Shadow
        );
    }

    #[test]
    fn gate_hold_at_production() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        gov.moonshots
            .get_mut("mc-test-001")
            .expect("operation should succeed for valid inputs")
            .contract
            .current_stage = MoonshotStage::Production;
        let decision = gov
            .evaluate_gate("mc-test-001", 1_000_000_000)
            .expect("operation should succeed for valid inputs");
        assert!(matches!(decision.kind, GovernorDecisionKind::Hold { .. }));
        assert!(decision.rationale.contains("production"));
    }

    // -- Kill criteria tests --

    #[test]
    fn kill_criteria_time_expiry() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        // Evaluate gate after 200 days (> 180 day limit).
        let elapsed = 17_280_000_000_000_000u64; // 200 days in ns
        let now = gov.moonshots["mc-test-001"].started_at_ns + elapsed;
        let decision = gov
            .check_kill_criteria("mc-test-001", now)
            .expect("operation should succeed for valid inputs")
            .expect("should trigger kill");
        assert!(matches!(decision.kind, GovernorDecisionKind::Kill { .. }));
        assert!(matches!(
            gov.moonshots["mc-test-001"].status,
            MoonshotStatus::Killed { .. }
        ));
    }

    #[test]
    fn kill_criteria_budget_exhausted() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        // Set high budget consumption with metrics above threshold (bad).
        gov.update_budget("mc-test-001", 950_000)
            .expect("operation should succeed for valid inputs");
        gov.record_metric(
            "mc-test-001",
            MetricObservation {
                metric_id: "latency_p50".into(),
                value_millionths: 300_000_000, // 300ms > 250ms threshold
                observed_at_ns: 2_000_000_000,
            },
        )
        .expect("operation should succeed for valid inputs");
        let decision = gov
            .check_kill_criteria("mc-test-001", 3_000_000_000)
            .expect("operation should succeed for valid inputs")
            .expect("should trigger kill");
        assert!(matches!(decision.kind, GovernorDecisionKind::Kill { .. }));
    }

    #[test]
    fn no_kill_when_under_thresholds() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        let result = gov
            .check_kill_criteria("mc-test-001", 2_000_000_000)
            .expect("operation should succeed for valid inputs");
        assert!(result.is_none());
    }

    // -- Pause/resume tests --

    #[test]
    fn pause_and_resume() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        let pd = gov
            .pause_moonshot("mc-test-001", "resource reallocation", 2_000_000_000)
            .expect("operation should succeed for valid inputs");
        assert!(matches!(pd.kind, GovernorDecisionKind::Pause { .. }));
        assert!(matches!(
            gov.moonshots["mc-test-001"].status,
            MoonshotStatus::Paused { .. }
        ));

        let rd = gov
            .resume_moonshot("mc-test-001", 3_000_000_000)
            .expect("operation should succeed for valid inputs");
        assert!(matches!(rd.kind, GovernorDecisionKind::Resume));
        assert!(gov.moonshots["mc-test-001"].is_active());
    }

    #[test]
    fn pause_not_active_fails() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        gov.moonshots
            .get_mut("mc-test-001")
            .expect("operation should succeed for valid inputs")
            .status = MoonshotStatus::Killed {
            reason: "test".into(),
            killed_at_ns: 0,
        };
        let err = gov.pause_moonshot("mc-test-001", "test", 0).unwrap_err();
        assert!(matches!(err, GovernorError::MoonshotNotActive { .. }));
    }

    #[test]
    fn resume_not_paused_fails() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        let err = gov.resume_moonshot("mc-test-001", 0).unwrap_err();
        assert!(matches!(err, GovernorError::NotPaused { .. }));
    }

    // -- Portfolio ranking tests --

    #[test]
    fn rank_portfolio_single() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        let rankings = gov.rank_portfolio(5_000_000_000);
        assert_eq!(rankings.len(), 1);
        assert_eq!(rankings[0].0, "mc-test-001");
    }

    #[test]
    fn rank_portfolio_multiple() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);

        // Register a second moonshot with different EV.
        let mut c2 = test_contract();
        c2.contract_id = "mc-test-002".into();
        c2.ev_model.benefit_on_success_millionths = 10_000_000; // higher benefit
        gov.register_moonshot(c2, 1_000_000_000)
            .expect("operation should succeed for valid inputs");

        // Add metrics to both so confidence is non-zero (EV * conf / 1M).
        for id in ["mc-test-001", "mc-test-002"] {
            for i in 0..10 {
                gov.record_metric(
                    id,
                    MetricObservation {
                        metric_id: "latency_p50".into(),
                        value_millionths: 200_000_000,
                        observed_at_ns: (i + 1) * 1_000_000_000,
                    },
                )
                .expect("operation should succeed for valid inputs");
            }
        }

        let rankings = gov.rank_portfolio(12_000_000_000);
        assert_eq!(rankings.len(), 2);
        // mc-test-002 should rank higher due to higher benefit.
        assert_eq!(rankings[0].0, "mc-test-002");
        assert!(rankings[0].1 > rankings[1].1);
    }

    #[test]
    fn rank_portfolio_excludes_killed() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        gov.moonshots
            .get_mut("mc-test-001")
            .expect("operation should succeed for valid inputs")
            .status = MoonshotStatus::Killed {
            reason: "test".into(),
            killed_at_ns: 0,
        };
        let rankings = gov.rank_portfolio(5_000_000_000);
        assert!(rankings.is_empty());
    }

    // -- Budget tests --

    #[test]
    fn update_budget_ok() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        gov.update_budget("mc-test-001", 500_000)
            .expect("operation should succeed for valid inputs");
        assert_eq!(
            gov.moonshots["mc-test-001"].budget_spent_fraction_millionths,
            500_000
        );
    }

    #[test]
    fn update_budget_not_found() {
        let mut gov = test_governor();
        let err = gov.update_budget("nonexistent", 0).unwrap_err();
        assert!(matches!(err, GovernorError::MoonshotNotFound { .. }));
    }

    // -- Decision tracking tests --

    #[test]
    fn decisions_tracked() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        gov.evaluate_gate("mc-test-001", 2_000_000_000)
            .expect("operation should succeed for valid inputs");
        let decisions = gov
            .decisions("mc-test-001")
            .expect("operation should succeed for valid inputs");
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].decision_id, "gov-1");
    }

    #[test]
    fn automatic_decisions_are_persisted_when_governance_ledger_enabled() {
        let mut gov = test_governor();
        gov.enable_governance_audit_ledger(
            GovernanceLedgerConfig {
                checkpoint_interval: 2,
                signer_key: b"governor-ledger-test-key".to_vec(),
                policy_id: "moonshot-governor-policy-test".to_string(),
            },
            "moonshot-governor-system",
        )
        .expect("enable ledger");
        register_test_moonshot(&mut gov);

        gov.evaluate_gate("mc-test-001", 2_000_000_000)
            .expect("operation should succeed for valid inputs");
        let ledger = gov.governance_audit_ledger().expect("ledger configured");
        assert_eq!(ledger.entries().len(), 1);
        assert_eq!(ledger.entries()[0].decision_id, "gov-1");
        assert_eq!(
            ledger.entries()[0].actor.actor_id(),
            "moonshot-governor-system"
        );
        assert_eq!(ledger.events().len(), 1);
        assert_eq!(ledger.events()[0].event, "append_decision");
        assert_eq!(ledger.events()[0].outcome, "success");
    }

    #[test]
    fn enable_governance_ledger_rejects_empty_actor_identifier() {
        let mut gov = test_governor();
        let err = gov
            .enable_governance_audit_ledger(GovernanceLedgerConfig::default(), "")
            .expect_err("must reject empty actor identifier");
        assert!(matches!(err, GovernorError::InvalidGovernanceActor { .. }));
    }

    #[test]
    fn decisions_not_found() {
        let gov = test_governor();
        assert!(gov.decisions("nonexistent").is_none());
    }

    // -- Full lifecycle test --

    #[test]
    fn full_lifecycle_research_to_shadow() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);

        // Step 1: Submit required research artifact.
        gov.submit_artifact(
            "mc-test-001",
            ArtifactEvidence {
                artifact_id: "art-proof".into(),
                obligation_id: "proof-research".into(),
                artifact_type: ArtifactType::Proof,
                submitted_at_ns: 2_000_000_000,
                content_hash: "hash-proof".into(),
            },
        )
        .expect("operation should succeed for valid inputs");

        // Step 2: Record enough metrics with good values.
        for i in 0..8 {
            gov.record_metric(
                "mc-test-001",
                MetricObservation {
                    metric_id: "latency_p50".into(),
                    value_millionths: 200_000_000,
                    observed_at_ns: (i + 3) * 1_000_000_000,
                },
            )
            .expect("operation should succeed for valid inputs");
        }

        // Step 3: Evaluate gate — should promote.
        let decision = gov
            .evaluate_gate("mc-test-001", 12_000_000_000)
            .expect("operation should succeed for valid inputs");
        assert!(matches!(
            decision.kind,
            GovernorDecisionKind::Promote {
                from: MoonshotStage::Research,
                to: MoonshotStage::Shadow
            }
        ));
        assert_eq!(
            gov.moonshots["mc-test-001"].contract.current_stage,
            MoonshotStage::Shadow
        );

        // Step 4: Verify scorecard was recorded.
        assert_eq!(gov.moonshots["mc-test-001"].scorecard_history.len(), 1);
    }

    // -- Serialization tests --

    #[test]
    fn governor_serde_round_trip() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        let json = serde_json::to_string(&gov).expect("serialize derived Serialize");
        let decoded: PortfolioGovernor =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(gov, decoded);
    }

    #[test]
    fn scorecard_serde_round_trip() {
        let sc = Scorecard {
            moonshot_id: "test".into(),
            ev_millionths: 1_000_000,
            confidence_millionths: 800_000,
            risk_of_harm_millionths: 50_000,
            implementation_friction_millionths: 100_000,
            cross_initiative_interference_millionths: 0,
            operational_burden_millionths: 200_000,
            computed_at_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
        };
        let json = serde_json::to_string(&sc).expect("serialize derived Serialize");
        let decoded: Scorecard = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(sc, decoded);
    }

    #[test]
    fn decision_serde_round_trip() {
        let d = GovernorDecision {
            decision_id: "gov-1".into(),
            moonshot_id: "mc-001".into(),
            kind: GovernorDecisionKind::Promote {
                from: MoonshotStage::Research,
                to: MoonshotStage::Shadow,
            },
            scorecard: Scorecard {
                moonshot_id: "mc-001".into(),
                ev_millionths: 1_000_000,
                confidence_millionths: 800_000,
                risk_of_harm_millionths: 50_000,
                implementation_friction_millionths: 0,
                cross_initiative_interference_millionths: 0,
                operational_burden_millionths: 0,
                computed_at_ns: 0,
                epoch: SecurityEpoch::from_raw(1),
            },
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            rationale: "All criteria met".into(),
        };
        let json = serde_json::to_string(&d).expect("serialize derived Serialize");
        let decoded: GovernorDecision =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(d, decoded);
    }

    // -- Error display tests --

    #[test]
    fn error_display() {
        assert_eq!(
            GovernorError::MoonshotNotFound { id: "x".into() }.to_string(),
            "moonshot not found: x"
        );
        assert_eq!(
            GovernorError::AlreadyRegistered { id: "y".into() }.to_string(),
            "already registered: y"
        );
        assert_eq!(
            GovernorError::NotPaused { id: "z".into() }.to_string(),
            "not paused: z"
        );
    }

    #[test]
    fn error_serde_round_trip() {
        let err = GovernorError::InvalidContract {
            reason: "test".into(),
        };
        let json = serde_json::to_string(&err).expect("serialize derived Serialize");
        let decoded: GovernorError =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(err, decoded);
    }

    // -- Decision kind display tests --

    #[test]
    fn decision_kind_display() {
        assert_eq!(
            GovernorDecisionKind::Promote {
                from: MoonshotStage::Research,
                to: MoonshotStage::Shadow
            }
            .to_string(),
            "promote(research->shadow)"
        );
        assert_eq!(
            GovernorDecisionKind::Kill {
                triggered_criteria: vec!["a".into()]
            }
            .to_string(),
            "kill"
        );
        assert_eq!(GovernorDecisionKind::Resume.to_string(), "resume");
    }

    // -- MoonshotStatus display test --

    #[test]
    fn moonshot_status_display() {
        assert_eq!(MoonshotStatus::Active.to_string(), "active");
        assert_eq!(
            MoonshotStatus::Paused {
                reason: "test".into(),
                paused_at_ns: 0
            }
            .to_string(),
            "paused"
        );
        assert_eq!(
            MoonshotStatus::Killed {
                reason: "test".into(),
                killed_at_ns: 0
            }
            .to_string(),
            "killed"
        );
        assert_eq!(
            MoonshotStatus::Completed { completed_at_ns: 0 }.to_string(),
            "completed"
        );
    }

    // -- Default config test --

    #[test]
    fn default_config() {
        let cfg = GovernorConfig::default();
        assert_eq!(cfg.promotion_confidence_threshold_millionths, 750_000);
        assert_eq!(cfg.promotion_risk_threshold_millionths, 200_000);
        assert_eq!(cfg.hold_confidence_below_millionths, 500_000);
        assert!(cfg.scoring_cadence_ns > 0);
    }

    // -- Deterministic serialization test --

    #[test]
    fn deterministic_serialization() {
        let mut g1 = test_governor();
        register_test_moonshot(&mut g1);
        let mut g2 = test_governor();
        register_test_moonshot(&mut g2);
        assert_eq!(
            serde_json::to_string(&g1).expect("serialize derived Serialize"),
            serde_json::to_string(&g2).expect("serialize derived Serialize")
        );
    }

    // -- Latest scorecard test --

    #[test]
    fn latest_scorecard_none_initially() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        assert!(gov.latest_scorecard("mc-test-001").is_none());
    }

    #[test]
    fn latest_scorecard_after_evaluation() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        gov.evaluate_gate("mc-test-001", 2_000_000_000)
            .expect("operation should succeed for valid inputs");
        let sc = gov
            .latest_scorecard("mc-test-001")
            .expect("operation should succeed for valid inputs");
        assert_eq!(sc.moonshot_id, "mc-test-001");
    }

    // -- MoonshotState helper tests --

    #[test]
    fn moonshot_state_latest_metric() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        gov.record_metric(
            "mc-test-001",
            MetricObservation {
                metric_id: "latency_p50".into(),
                value_millionths: 200_000_000,
                observed_at_ns: 1_000_000_000,
            },
        )
        .expect("operation should succeed for valid inputs");
        gov.record_metric(
            "mc-test-001",
            MetricObservation {
                metric_id: "latency_p50".into(),
                value_millionths: 180_000_000,
                observed_at_ns: 2_000_000_000,
            },
        )
        .expect("operation should succeed for valid inputs");
        let latest = gov.moonshots["mc-test-001"]
            .latest_metric("latency_p50")
            .expect("operation should succeed for valid inputs");
        assert_eq!(latest.value_millionths, 180_000_000);
    }

    // -- Friction score tests --

    #[test]
    fn friction_decreases_with_artifacts() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        let sc1 = gov
            .compute_scorecard("mc-test-001", 1_000_000_000)
            .expect("operation should succeed for valid inputs");
        // Submit one of two obligations.
        gov.submit_artifact(
            "mc-test-001",
            ArtifactEvidence {
                artifact_id: "art-1".into(),
                obligation_id: "proof-research".into(),
                artifact_type: ArtifactType::Proof,
                submitted_at_ns: 2_000_000_000,
                content_hash: "hash".into(),
            },
        )
        .expect("operation should succeed for valid inputs");
        let sc2 = gov
            .compute_scorecard("mc-test-001", 3_000_000_000)
            .expect("operation should succeed for valid inputs");
        assert!(sc2.implementation_friction_millionths < sc1.implementation_friction_millionths);
    }

    // -- Enrichment: error trait --

    #[test]
    fn governor_error_is_std_error() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(GovernorError::MoonshotNotFound {
                id: "m".to_string(),
            }),
            Box::new(GovernorError::MoonshotNotActive {
                id: "m".to_string(),
            }),
            Box::new(GovernorError::InvalidContract {
                reason: "r".to_string(),
            }),
            Box::new(GovernorError::AlreadyRegistered {
                id: "m".to_string(),
            }),
            Box::new(GovernorError::NotPaused {
                id: "m".to_string(),
            }),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }

    // -- Enrichment: serde roundtrips --

    #[test]
    fn artifact_evidence_serde_roundtrip_enrichment() {
        let ae = ArtifactEvidence {
            artifact_id: "art-1".to_string(),
            obligation_id: "obl-1".to_string(),
            artifact_type: ArtifactType::Proof,
            submitted_at_ns: 1_000_000_000,
            content_hash: "sha256:abc".to_string(),
        };
        let json = serde_json::to_string(&ae).expect("serialize derived Serialize");
        let restored: ArtifactEvidence =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(ae, restored);
    }

    #[test]
    fn metric_observation_serde_roundtrip() {
        let mo = MetricObservation {
            metric_id: "latency_p99".to_string(),
            value_millionths: 500_000,
            observed_at_ns: 2_000_000_000,
        };
        let json = serde_json::to_string(&mo).expect("serialize derived Serialize");
        let restored: MetricObservation =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(mo, restored);
    }

    #[test]
    fn governor_config_serde_roundtrip() {
        let cfg = GovernorConfig::default();
        let json = serde_json::to_string(&cfg).expect("serialize derived Serialize");
        let restored: GovernorConfig =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(cfg, restored);
    }

    #[test]
    fn moonshot_status_serde_roundtrip() {
        let statuses = vec![
            MoonshotStatus::Active,
            MoonshotStatus::Paused {
                reason: "review".to_string(),
                paused_at_ns: 1_000,
            },
            MoonshotStatus::Killed {
                reason: "budget".to_string(),
                killed_at_ns: 2_000,
            },
            MoonshotStatus::Completed {
                completed_at_ns: 3_000,
            },
        ];
        for s in &statuses {
            let json = serde_json::to_string(s).expect("serialize derived Serialize");
            let restored: MoonshotStatus =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*s, restored);
        }
    }

    #[test]
    fn decision_kind_serde_roundtrip() {
        let kinds = vec![
            GovernorDecisionKind::Promote {
                from: MoonshotStage::Research,
                to: MoonshotStage::Shadow,
            },
            GovernorDecisionKind::Hold {
                reason: "low confidence".to_string(),
            },
            GovernorDecisionKind::Kill {
                triggered_criteria: vec!["budget".to_string()],
            },
            GovernorDecisionKind::Pause {
                reason: "review".to_string(),
            },
            GovernorDecisionKind::Resume,
        ];
        for k in &kinds {
            let json = serde_json::to_string(k).expect("serialize derived Serialize");
            let restored: GovernorDecisionKind =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*k, restored);
        }
    }

    // -- Enrichment: Scorecard risk_adjusted_ev computation --

    #[test]
    fn scorecard_risk_adjusted_ev_positive() {
        let sc = Scorecard {
            moonshot_id: "m".into(),
            ev_millionths: 2_000_000,
            confidence_millionths: 800_000,
            risk_of_harm_millionths: 100_000,
            implementation_friction_millionths: 50_000,
            cross_initiative_interference_millionths: 30_000,
            operational_burden_millionths: 20_000,
            computed_at_ns: 0,
            epoch: SecurityEpoch::GENESIS,
        };
        // ev * conf / 1M - risk*2 - interference - friction - burden
        // 2M * 0.8 - 200k - 30k - 50k - 20k = 1.6M - 300k = 1_300_000
        assert_eq!(sc.risk_adjusted_ev(), 1_300_000);
    }

    #[test]
    fn scorecard_risk_adjusted_ev_negative() {
        let sc = Scorecard {
            moonshot_id: "m".into(),
            ev_millionths: 100_000,
            confidence_millionths: 100_000,
            risk_of_harm_millionths: 500_000,
            implementation_friction_millionths: 200_000,
            cross_initiative_interference_millionths: 100_000,
            operational_burden_millionths: 100_000,
            computed_at_ns: 0,
            epoch: SecurityEpoch::GENESIS,
        };
        // 100k * 100k / 1M - 1M - 100k - 200k - 100k = 10k - 1.4M < 0
        assert!(sc.risk_adjusted_ev() < 0);
    }

    #[test]
    fn scorecard_risk_adjusted_ev_zero_confidence() {
        let sc = Scorecard {
            moonshot_id: "m".into(),
            ev_millionths: 5_000_000,
            confidence_millionths: 0,
            risk_of_harm_millionths: 0,
            implementation_friction_millionths: 0,
            cross_initiative_interference_millionths: 0,
            operational_burden_millionths: 0,
            computed_at_ns: 0,
            epoch: SecurityEpoch::GENESIS,
        };
        assert_eq!(sc.risk_adjusted_ev(), 0);
    }

    // -- Enrichment: MoonshotState helpers --

    #[test]
    fn moonshot_state_completed_obligation_ids() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        gov.submit_artifact(
            "mc-test-001",
            ArtifactEvidence {
                artifact_id: "art-1".into(),
                obligation_id: "proof-research".into(),
                artifact_type: ArtifactType::Proof,
                submitted_at_ns: 1_000,
                content_hash: "h".into(),
            },
        )
        .expect("operation should succeed for valid inputs");
        let ids = gov.moonshots["mc-test-001"].completed_obligation_ids();
        assert_eq!(ids, vec!["proof-research".to_string()]);
    }

    #[test]
    fn moonshot_state_metric_snapshot() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        gov.record_metric(
            "mc-test-001",
            MetricObservation {
                metric_id: "latency_p50".into(),
                value_millionths: 200_000_000,
                observed_at_ns: 1_000,
            },
        )
        .expect("operation should succeed for valid inputs");
        gov.record_metric(
            "mc-test-001",
            MetricObservation {
                metric_id: "throughput".into(),
                value_millionths: 500_000,
                observed_at_ns: 2_000,
            },
        )
        .expect("operation should succeed for valid inputs");
        let snapshot = gov.moonshots["mc-test-001"].metric_snapshot();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot["throughput"], 500_000);
    }

    #[test]
    fn moonshot_state_is_active_variants() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        assert!(gov.moonshots["mc-test-001"].is_active());

        gov.moonshots
            .get_mut("mc-test-001")
            .expect("operation should succeed for valid inputs")
            .status = MoonshotStatus::Paused {
            reason: "test".into(),
            paused_at_ns: 0,
        };
        assert!(!gov.moonshots["mc-test-001"].is_active());

        gov.moonshots
            .get_mut("mc-test-001")
            .expect("operation should succeed for valid inputs")
            .status = MoonshotStatus::Killed {
            reason: "test".into(),
            killed_at_ns: 0,
        };
        assert!(!gov.moonshots["mc-test-001"].is_active());

        gov.moonshots
            .get_mut("mc-test-001")
            .expect("operation should succeed for valid inputs")
            .status = MoonshotStatus::Completed { completed_at_ns: 0 };
        assert!(!gov.moonshots["mc-test-001"].is_active());
    }

    // -- Enrichment: GovernorError serde all variants --

    #[test]
    fn governor_error_serde_all_variants() {
        let errors = vec![
            GovernorError::MoonshotNotFound { id: "m".into() },
            GovernorError::MoonshotNotActive { id: "m".into() },
            GovernorError::InvalidContract { reason: "r".into() },
            GovernorError::InvalidTransition {
                from: MoonshotStage::Research,
                to: MoonshotStage::Research,
            },
            GovernorError::AlreadyRegistered { id: "m".into() },
            GovernorError::NotPaused { id: "m".into() },
            GovernorError::LedgerConfig { reason: "r".into() },
            GovernorError::LedgerWriteFailed {
                decision_id: "d".into(),
                reason: "r".into(),
            },
            GovernorError::InvalidGovernanceActor {
                actor_id: "a".into(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize derived Serialize");
            let back: GovernorError =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*err, back);
        }
    }

    // -- Enrichment: GovernorError Display all variants distinct --

    #[test]
    fn governor_error_display_all_distinct() {
        let errors = vec![
            GovernorError::MoonshotNotFound { id: "m1".into() },
            GovernorError::MoonshotNotActive { id: "m2".into() },
            GovernorError::InvalidContract {
                reason: "r1".into(),
            },
            GovernorError::InvalidTransition {
                from: MoonshotStage::Research,
                to: MoonshotStage::Shadow,
            },
            GovernorError::AlreadyRegistered { id: "m3".into() },
            GovernorError::NotPaused { id: "m4".into() },
            GovernorError::LedgerConfig {
                reason: "r2".into(),
            },
            GovernorError::LedgerWriteFailed {
                decision_id: "d1".into(),
                reason: "r3".into(),
            },
            GovernorError::InvalidGovernanceActor {
                actor_id: "a1".into(),
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for err in &errors {
            displays.insert(err.to_string());
        }
        assert_eq!(displays.len(), errors.len());
    }

    // -- Enrichment: GovernorDecisionKind Display all variants --

    #[test]
    fn decision_kind_display_hold_and_pause() {
        assert_eq!(
            GovernorDecisionKind::Hold {
                reason: "low signal".into()
            }
            .to_string(),
            "hold(low signal)"
        );
        assert_eq!(
            GovernorDecisionKind::Pause {
                reason: "resources".into()
            }
            .to_string(),
            "pause(resources)"
        );
    }

    // -- Enrichment: submit_artifact / record_metric on non-active --

    #[test]
    fn submit_artifact_not_active_fails() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        gov.moonshots
            .get_mut("mc-test-001")
            .expect("operation should succeed for valid inputs")
            .status = MoonshotStatus::Killed {
            reason: "test".into(),
            killed_at_ns: 0,
        };
        let err = gov
            .submit_artifact(
                "mc-test-001",
                ArtifactEvidence {
                    artifact_id: "a".into(),
                    obligation_id: "o".into(),
                    artifact_type: ArtifactType::Proof,
                    submitted_at_ns: 0,
                    content_hash: "h".into(),
                },
            )
            .unwrap_err();
        assert!(matches!(err, GovernorError::MoonshotNotActive { .. }));
    }

    #[test]
    fn record_metric_not_active_fails() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        gov.moonshots
            .get_mut("mc-test-001")
            .expect("operation should succeed for valid inputs")
            .status = MoonshotStatus::Killed {
            reason: "test".into(),
            killed_at_ns: 0,
        };
        let err = gov
            .record_metric(
                "mc-test-001",
                MetricObservation {
                    metric_id: "m".into(),
                    value_millionths: 0,
                    observed_at_ns: 0,
                },
            )
            .unwrap_err();
        assert!(matches!(err, GovernorError::MoonshotNotActive { .. }));
    }

    // -- Enrichment: update_budget not active --

    #[test]
    fn update_budget_not_active_fails() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        gov.moonshots
            .get_mut("mc-test-001")
            .expect("operation should succeed for valid inputs")
            .status = MoonshotStatus::Killed {
            reason: "test".into(),
            killed_at_ns: 0,
        };
        let err = gov.update_budget("mc-test-001", 0).unwrap_err();
        assert!(matches!(err, GovernorError::MoonshotNotActive { .. }));
    }

    // -- Enrichment: register_moonshot duplicate --

    #[test]
    fn register_duplicate_moonshot_fails() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        let err = gov
            .register_moonshot(test_contract(), 2_000_000_000)
            .unwrap_err();
        assert!(matches!(err, GovernorError::AlreadyRegistered { .. }));
    }

    // -- Enrichment: governance_audit_ledger accessor --

    #[test]
    fn governance_audit_ledger_none_by_default() {
        let gov = test_governor();
        assert!(gov.governance_audit_ledger().is_none());
    }

    // -- Enrichment: MoonshotState serde roundtrip --

    #[test]
    fn moonshot_state_serde_roundtrip() {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        let state = &gov.moonshots["mc-test-001"];
        let json = serde_json::to_string(state).expect("serialize derived Serialize");
        let back: MoonshotState =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(*state, back);
    }

    // ── Enrichment: serde roundtrip tests ────────────────────────────

    #[test]
    fn governor_config_serde_roundtrip_default() {
        let cfg = GovernorConfig::default();
        let json = serde_json::to_string(&cfg).expect("serialize derived Serialize");
        let back: GovernorConfig =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, cfg);
    }

    #[test]
    fn governor_config_serde_roundtrip_custom() {
        let cfg = GovernorConfig {
            promotion_confidence_threshold_millionths: 800_000,
            promotion_risk_threshold_millionths: 100_000,
            hold_confidence_below_millionths: 400_000,
            scoring_cadence_ns: 1_000_000_000,
        };
        let json = serde_json::to_string(&cfg).expect("serialize derived Serialize");
        let back: GovernorConfig =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, cfg);
    }

    #[test]
    fn artifact_evidence_serde_roundtrip() {
        let ev = ArtifactEvidence {
            artifact_id: "art-001".to_string(),
            obligation_id: "obl-perf".to_string(),
            artifact_type: ArtifactType::Proof,
            submitted_at_ns: 1_000_000,
            content_hash: "abc123".to_string(),
        };
        let json = serde_json::to_string(&ev).expect("serialize derived Serialize");
        let back: ArtifactEvidence =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, ev);
    }

    #[test]
    fn metric_observation_serde_roundtrip_enrichment() {
        let obs = MetricObservation {
            metric_id: "throughput".to_string(),
            value_millionths: 950_000,
            observed_at_ns: 2_000_000,
        };
        let json = serde_json::to_string(&obs).expect("serialize derived Serialize");
        let back: MetricObservation =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, obs);
    }

    // ── Enrichment: edge case tests ──────────────────────────────────

    #[test]
    fn scorecard_zero_confidence() {
        let scorecard = Scorecard {
            moonshot_id: "mc-test-001".to_string(),
            ev_millionths: 0,
            confidence_millionths: 0,
            risk_of_harm_millionths: 0,
            implementation_friction_millionths: 0,
            cross_initiative_interference_millionths: 0,
            operational_burden_millionths: 0,
            computed_at_ns: 500_000,
            epoch: SecurityEpoch::from_raw(1),
        };
        let json = serde_json::to_string(&scorecard).expect("serialize derived Serialize");
        let back: Scorecard = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, scorecard);
        assert_eq!(back.confidence_millionths, 0);
    }
}
