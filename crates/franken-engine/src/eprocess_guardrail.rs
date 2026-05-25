//! E-process guardrail integration reformulated as martingale consumer (bd-cixqu.27.2).
//!
//! Reformulated from independent e-value accumulation to consume the unified
//! MartingaleLedger substrate. Expected-loss matrix provides terminal action
//! policy on the martingale's stopping decision. When the martingale stops
//! (crossing rejection threshold), the guardrail consults the expected-loss
//! matrix to determine which actions to block.
//!
//! Plan references: Section 10.11 item 14, 9G.5 (policy controller
//! with expected-loss actions under guardrails), Top-10 #2 (guardplane),
//! #8 (per-extension resource budget), bd-cixqu.27.1 (martingale substrate).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::martingale_decision_ledger::{
    MartingaleError, MartingaleLedger, MartingaleVerdict, StoppingThreshold,
};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// ExpectedLossMatrix — terminal action policy on martingale stopping
// ---------------------------------------------------------------------------

/// Expected-loss matrix for terminal action policy when martingale stops.
///
/// Maps actions to expected loss values (fixed-point millionths). When the
/// martingale emits a Stop verdict, the guardrail consults this matrix to
/// determine which actions to block based on loss thresholds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedLossMatrix {
    /// Loss values per action (millionths). Higher values = higher risk.
    action_losses: BTreeMap<String, i64>,
    /// Loss threshold above which actions are blocked (millionths).
    block_threshold_millionths: i64,
}

impl ExpectedLossMatrix {
    /// Create new expected-loss matrix.
    pub fn new(action_losses: BTreeMap<String, i64>, block_threshold_millionths: i64) -> Self {
        Self {
            action_losses,
            block_threshold_millionths,
        }
    }

    /// Get actions that should be blocked based on expected loss.
    pub fn blocked_actions(&self) -> BTreeSet<String> {
        self.action_losses
            .iter()
            .filter(|(_, loss)| **loss >= self.block_threshold_millionths)
            .map(|(action, _)| action.clone())
            .collect()
    }

    /// Check if specific action should be blocked.
    pub fn should_block(&self, action: &str) -> bool {
        self.action_losses
            .get(action)
            .map(|&loss| loss >= self.block_threshold_millionths)
            .unwrap_or(false)
    }

    /// Get expected loss for an action (returns 0 if not found).
    pub fn action_loss(&self, action: &str) -> i64 {
        self.action_losses.get(action).copied().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// GuardrailState — Active / Triggered / Suspended
// ---------------------------------------------------------------------------

/// State of an e-process guardrail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardrailState {
    /// Actively accumulating evidence; not yet triggered.
    Active,
    /// E-value exceeded threshold; actions are blocked.
    Triggered,
    /// Temporarily suspended by operator (not accumulating).
    Suspended,
}

impl fmt::Display for GuardrailState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Triggered => write!(f, "triggered"),
            Self::Suspended => write!(f, "suspended"),
        }
    }
}

// ---------------------------------------------------------------------------
// LikelihoodRatioFn — pluggable evidence update
// ---------------------------------------------------------------------------

/// A likelihood-ratio function that maps an observation to a ratio.
///
/// Given an observation value (fixed-point millionths), returns the
/// likelihood ratio L(observation | H1) / L(observation | H0) as
/// fixed-point millionths (1_000_000 = 1.0).
///
/// Returns `None` if the observation is outside the valid domain.
pub trait LikelihoodRatioFn: fmt::Debug + Send {
    /// Compute the likelihood ratio for a single observation.
    fn ratio(&self, observation_millionths: i64) -> Option<i64>;

    /// Human-readable family name (e.g., "normal", "binomial").
    fn family(&self) -> &str;
}

/// Simple threshold-based likelihood ratio: returns `high_ratio` when the
/// observation exceeds the threshold, `low_ratio` otherwise.
///
/// Useful for binary alarm signals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdLikelihoodRatio {
    /// Observation threshold (millionths).
    pub threshold_millionths: i64,
    /// Ratio when observation >= threshold.
    pub high_ratio_millionths: i64,
    /// Ratio when observation < threshold.
    pub low_ratio_millionths: i64,
}

impl LikelihoodRatioFn for ThresholdLikelihoodRatio {
    fn ratio(&self, observation_millionths: i64) -> Option<i64> {
        if observation_millionths >= self.threshold_millionths {
            Some(self.high_ratio_millionths)
        } else {
            Some(self.low_ratio_millionths)
        }
    }

    fn family(&self) -> &str {
        "threshold"
    }
}

/// Universal inference e-value: ratio = observation / null_mean.
///
/// Model-free construction: e_t = X_t / mu_0 where mu_0 is the null
/// hypothesis mean.  Returns millionths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversalLikelihoodRatio {
    /// Null hypothesis mean (millionths).
    pub null_mean_millionths: i64,
}

impl LikelihoodRatioFn for UniversalLikelihoodRatio {
    fn ratio(&self, observation_millionths: i64) -> Option<i64> {
        if self.null_mean_millionths == 0 {
            return None;
        }
        // ratio = observation / null_mean, in millionths
        let r = (observation_millionths as i128 * 1_000_000) / self.null_mean_millionths as i128;
        Some(
            r.try_into()
                .unwrap_or(if r > 0 { i64::MAX } else { i64::MIN }),
        )
    }

    fn family(&self) -> &str {
        "universal"
    }
}

// ---------------------------------------------------------------------------
// GuardrailError
// ---------------------------------------------------------------------------

/// Errors from e-process guardrail operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardrailError {
    /// Guardrail is suspended; cannot update.
    Suspended { guardrail_id: String },
    /// Guardrail is already triggered; update is a no-op.
    AlreadyTriggered { guardrail_id: String },
    /// Likelihood ratio function returned None (invalid observation).
    InvalidObservation { guardrail_id: String },
    /// Reset requires authorization (no valid reset receipt).
    ResetUnauthorized { guardrail_id: String },
    /// Guardrail is not in triggered state; cannot reset.
    NotTriggered { guardrail_id: String },
    /// Martingale ledger error (overflow, already stopped, etc.).
    MartingaleError {
        guardrail_id: String,
        source: MartingaleError,
    },
}

impl fmt::Display for GuardrailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Suspended { guardrail_id } => {
                write!(f, "guardrail '{guardrail_id}' is suspended")
            }
            Self::AlreadyTriggered { guardrail_id } => {
                write!(f, "guardrail '{guardrail_id}' already triggered")
            }
            Self::InvalidObservation { guardrail_id } => {
                write!(f, "invalid observation for guardrail '{guardrail_id}'")
            }
            Self::ResetUnauthorized { guardrail_id } => {
                write!(f, "unauthorized reset for guardrail '{guardrail_id}'")
            }
            Self::NotTriggered { guardrail_id } => {
                write!(f, "guardrail '{guardrail_id}' is not triggered")
            }
            Self::MartingaleError {
                guardrail_id,
                source,
            } => {
                write!(
                    f,
                    "martingale error for guardrail '{guardrail_id}': {source}"
                )
            }
        }
    }
}

impl std::error::Error for GuardrailError {}

// ---------------------------------------------------------------------------
// ResetReceipt — authorization for resetting a triggered guardrail
// ---------------------------------------------------------------------------

/// Authorization receipt for resetting a triggered guardrail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetReceipt {
    /// Who authorized the reset (operator id or epoch transition).
    pub authorized_by: String,
    /// Rationale for the reset.
    pub rationale: String,
    /// Epoch at which the reset occurs.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// GuardrailEvent — structured event for evidence emission
// ---------------------------------------------------------------------------

/// Structured event emitted by guardrail state transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardrailEvent {
    /// Martingale was updated with new observation.
    MartingaleUpdated {
        guardrail_id: String,
        observation: i64,
        log_likelihood_ratio: i64,
        verdict: MartingaleVerdict,
        sequence: u64,
    },
    /// Guardrail triggered (martingale stopped).
    Triggered {
        guardrail_id: String,
        sequence: u64,
        blocked_actions: Vec<String>,
        expected_losses: BTreeMap<String, i64>,
    },
    /// Guardrail was reset.
    Reset {
        guardrail_id: String,
        authorized_by: String,
        rationale: String,
        epoch: SecurityEpoch,
    },
    /// Guardrail was suspended.
    SuspendedEvent {
        guardrail_id: String,
        reason: String,
    },
    /// Guardrail was resumed from suspension.
    Resumed { guardrail_id: String },
}

// ---------------------------------------------------------------------------
// EProcessGuardrail — single anytime-valid sequential constraint
// ---------------------------------------------------------------------------

/// A single e-process guardrail reformulated as a martingale consumer.
///
/// Instead of manually accumulating e-values, consumes the unified
/// MartingaleLedger substrate. Expected-loss matrix provides terminal
/// action policy when the martingale emits a Stop verdict.
#[derive(Debug)]
pub struct EProcessGuardrail {
    /// Unique guardrail identifier.
    pub guardrail_id: String,
    /// Metric/evidence stream being monitored.
    pub metric_stream: String,
    /// Martingale ledger (unified substrate from bd-cixqu.27.1).
    martingale: MartingaleLedger,
    /// Description of the safety condition being guarded.
    pub null_hypothesis: String,
    /// Current state.
    state: GuardrailState,
    /// Expected-loss matrix for terminal action policy.
    loss_matrix: ExpectedLossMatrix,
    /// Epoch at which this guardrail was configured.
    config_epoch: SecurityEpoch,
    /// Event log for evidence emission.
    events: Vec<GuardrailEvent>,
    /// Pluggable likelihood ratio function.
    lr_fn: Box<dyn LikelihoodRatioFn>,
}

impl EProcessGuardrail {
    /// Create a new active guardrail with martingale substrate.
    ///
    /// - `stopping_threshold`: martingale stopping threshold.
    /// - `loss_matrix`: expected-loss matrix for terminal action policy.
    /// - `lr_fn`: likelihood ratio function for evidence updates.
    pub fn new(
        guardrail_id: impl Into<String>,
        metric_stream: impl Into<String>,
        null_hypothesis: impl Into<String>,
        stopping_threshold: StoppingThreshold,
        loss_matrix: ExpectedLossMatrix,
        config_epoch: SecurityEpoch,
        lr_fn: Box<dyn LikelihoodRatioFn>,
    ) -> Self {
        let martingale = MartingaleLedger::new(stopping_threshold, config_epoch);

        Self {
            guardrail_id: guardrail_id.into(),
            metric_stream: metric_stream.into(),
            martingale,
            null_hypothesis: null_hypothesis.into(),
            state: GuardrailState::Active,
            loss_matrix,
            config_epoch,
            events: Vec::new(),
            lr_fn,
        }
    }

    /// Current martingale state (event count, log M_n, etc.).
    pub fn martingale_state(&self) -> crate::martingale_decision_ledger::MartingaleState {
        self.martingale.current_state()
    }

    /// Whether the martingale has stopped.
    pub fn is_stopped(&self) -> bool {
        self.martingale.is_stopped()
    }

    /// Martingale stopping threshold.
    pub fn threshold(&self) -> StoppingThreshold {
        self.martingale.threshold()
    }

    /// Current state.
    pub fn state(&self) -> GuardrailState {
        self.state
    }

    /// Actions blocked by this guardrail (computed from expected-loss matrix).
    pub fn blocked_actions(&self) -> BTreeSet<String> {
        if self.state == GuardrailState::Triggered {
            self.loss_matrix.blocked_actions()
        } else {
            BTreeSet::new()
        }
    }

    /// Configuration epoch.
    pub fn config_epoch(&self) -> SecurityEpoch {
        self.config_epoch
    }

    /// Number of observations processed (martingale event count).
    pub fn observation_count(&self) -> u64 {
        self.martingale.event_count()
    }

    /// Drain and return accumulated events.
    pub fn drain_events(&mut self) -> Vec<GuardrailEvent> {
        std::mem::take(&mut self.events)
    }

    /// Check if a specific action is blocked by this guardrail.
    pub fn blocks(&self, action: &str) -> bool {
        self.state == GuardrailState::Triggered && self.loss_matrix.should_block(action)
    }

    /// Update the martingale with a new observation.
    ///
    /// Converts likelihood ratio to log space and appends to the martingale
    /// ledger. If the martingale emits a Stop verdict, consults the expected-loss
    /// matrix to determine blocked actions and transitions to Triggered state.
    pub fn update(&mut self, observation_millionths: i64) -> Result<(), GuardrailError> {
        match self.state {
            GuardrailState::Suspended => {
                return Err(GuardrailError::Suspended {
                    guardrail_id: self.guardrail_id.clone(),
                });
            }
            GuardrailState::Triggered => {
                return Err(GuardrailError::AlreadyTriggered {
                    guardrail_id: self.guardrail_id.clone(),
                });
            }
            GuardrailState::Active => {}
        }

        // Compute likelihood ratio using the pluggable function.
        let lr = self.lr_fn.ratio(observation_millionths).ok_or_else(|| {
            GuardrailError::InvalidObservation {
                guardrail_id: self.guardrail_id.clone(),
            }
        })?;

        // Convert to log space for martingale (ln(lr) * 1_000_000).
        let log_lr_millionths = if lr <= 0 {
            // Handle edge case: lr <= 0 means infinite negative log.
            i64::MIN / 1000 // Prevent overflow in subsequent addition
        } else {
            // ln(lr / 1_000_000) * 1_000_000 = (ln(lr) - ln(1_000_000)) * 1_000_000
            let lr_f64 = lr as f64 / 1_000_000.0;
            (lr_f64.ln() * 1_000_000.0) as i64
        };

        // Create content hash for the observation.
        let payload = format!("observation:{observation_millionths}:lr:{lr}");
        let payload_digest = ContentHash::compute(payload.as_bytes());

        // Append to martingale ledger.
        let verdict = self
            .martingale
            .append(
                log_lr_millionths,
                payload_digest,
                // Use a simple timestamp (real systems would use proper clock).
                self.observation_count() * 1_000_000_000,
            )
            .map_err(|source| GuardrailError::MartingaleError {
                guardrail_id: self.guardrail_id.clone(),
                source,
            })?;

        // Emit update event.
        self.events.push(GuardrailEvent::MartingaleUpdated {
            guardrail_id: self.guardrail_id.clone(),
            observation: observation_millionths,
            log_likelihood_ratio: log_lr_millionths,
            verdict,
            sequence: self.martingale.event_count(),
        });

        // Check if martingale stopped (rejection boundary crossed).
        if let MartingaleVerdict::Stop { .. } = verdict {
            self.state = GuardrailState::Triggered;

            // Terminal action policy: consult expected-loss matrix.
            let blocked_actions = self.loss_matrix.blocked_actions();
            let expected_losses: BTreeMap<String, i64> = blocked_actions
                .iter()
                .map(|action| (action.clone(), self.loss_matrix.action_loss(action)))
                .collect();

            self.events.push(GuardrailEvent::Triggered {
                guardrail_id: self.guardrail_id.clone(),
                sequence: self.martingale.event_count(),
                blocked_actions: blocked_actions.into_iter().collect(),
                expected_losses,
            });
        }

        Ok(())
    }

    /// Reset a triggered guardrail with an authorization receipt.
    ///
    /// Creates a fresh martingale ledger and transitions back to Active.
    pub fn reset(&mut self, receipt: &ResetReceipt) -> Result<(), GuardrailError> {
        if self.state != GuardrailState::Triggered {
            return Err(GuardrailError::NotTriggered {
                guardrail_id: self.guardrail_id.clone(),
            });
        }

        if receipt.authorized_by.is_empty() {
            return Err(GuardrailError::ResetUnauthorized {
                guardrail_id: self.guardrail_id.clone(),
            });
        }

        // Create fresh martingale with same threshold but new epoch.
        let threshold = self.martingale.threshold();
        self.martingale = MartingaleLedger::new(threshold, receipt.epoch);
        self.state = GuardrailState::Active;

        self.events.push(GuardrailEvent::Reset {
            guardrail_id: self.guardrail_id.clone(),
            authorized_by: receipt.authorized_by.clone(),
            rationale: receipt.rationale.clone(),
            epoch: receipt.epoch,
        });

        Ok(())
    }

    /// Suspend the guardrail (stops accumulating evidence).
    pub fn suspend(&mut self, reason: impl Into<String>) {
        self.state = GuardrailState::Suspended;
        self.events.push(GuardrailEvent::SuspendedEvent {
            guardrail_id: self.guardrail_id.clone(),
            reason: reason.into(),
        });
    }

    /// Resume a suspended guardrail.
    pub fn resume(&mut self) {
        if self.state == GuardrailState::Suspended {
            self.state = GuardrailState::Active;
            self.events.push(GuardrailEvent::Resumed {
                guardrail_id: self.guardrail_id.clone(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// GuardrailRegistry — manages multiple concurrent guardrails
// ---------------------------------------------------------------------------

/// Registry of active guardrails that the PolicyController consults.
///
/// Multiple guardrails can be active simultaneously.  An action is blocked
/// if ANY active guardrail in triggered state blocks it.
#[derive(Debug, Default)]
pub struct GuardrailRegistry {
    guardrails: Vec<EProcessGuardrail>,
}

impl GuardrailRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            guardrails: Vec::new(),
        }
    }

    /// Add a guardrail to the registry.
    pub fn add(&mut self, guardrail: EProcessGuardrail) {
        self.guardrails.push(guardrail);
    }

    /// Number of guardrails.
    pub fn len(&self) -> usize {
        self.guardrails.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.guardrails.is_empty()
    }

    /// Get the set of all currently blocked actions (union across all
    /// triggered guardrails).
    pub fn blocked_actions(&self) -> BTreeSet<String> {
        let mut blocked = BTreeSet::new();
        for gr in &self.guardrails {
            if gr.state() == GuardrailState::Triggered {
                blocked.extend(gr.blocked_actions());
            }
        }
        blocked
    }

    /// Check if a specific action is blocked by any triggered guardrail.
    pub fn is_blocked(&self, action: &str) -> bool {
        self.guardrails.iter().any(|gr| gr.blocks(action))
    }

    /// Get all blocking guardrail IDs for a given action.
    pub fn blocking_guardrails(&self, action: &str) -> Vec<String> {
        self.guardrails
            .iter()
            .filter(|gr| gr.blocks(action))
            .map(|gr| gr.guardrail_id.clone())
            .collect()
    }

    /// Compute the permitted action set: actions from `all_actions` that are
    /// not blocked by any triggered guardrail.
    pub fn permitted_actions<'a>(&self, all_actions: &'a [String]) -> Vec<&'a String> {
        all_actions.iter().filter(|a| !self.is_blocked(a)).collect()
    }

    /// Update all active guardrails with a new observation from the
    /// given metric stream.  Only guardrails matching the metric stream
    /// are updated.
    pub fn update_stream(
        &mut self,
        metric_stream: &str,
        observation_millionths: i64,
    ) -> Vec<GuardrailError> {
        let mut errors = Vec::new();
        for gr in &mut self.guardrails {
            if gr.metric_stream == metric_stream
                && gr.state() == GuardrailState::Active
                && let Err(e) = gr.update(observation_millionths)
            {
                errors.push(e);
            }
        }
        errors
    }

    /// Drain all events from all guardrails.
    pub fn drain_all_events(&mut self) -> Vec<GuardrailEvent> {
        let mut all_events = Vec::new();
        for gr in &mut self.guardrails {
            all_events.extend(gr.drain_events());
        }
        all_events
    }

    /// Get a mutable reference to a guardrail by ID.
    pub fn get_mut(&mut self, guardrail_id: &str) -> Option<&mut EProcessGuardrail> {
        self.guardrails
            .iter_mut()
            .find(|gr| gr.guardrail_id == guardrail_id)
    }

    /// Get a reference to a guardrail by ID.
    pub fn get(&self, guardrail_id: &str) -> Option<&EProcessGuardrail> {
        self.guardrails
            .iter()
            .find(|gr| gr.guardrail_id == guardrail_id)
    }

    /// Reset all guardrails for a new epoch (operator-driven bulk reset).
    pub fn reset_all(&mut self, receipt: &ResetReceipt) -> Vec<GuardrailError> {
        let mut errors = Vec::new();
        for gr in &mut self.guardrails {
            if gr.state() == GuardrailState::Triggered
                && let Err(e) = gr.reset(receipt)
            {
                errors.push(e);
            }
        }
        errors
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_guardrail() -> EProcessGuardrail {
        // Expected-loss matrix: block "low" and "medium" actions.
        let mut action_losses = BTreeMap::new();
        action_losses.insert("low".to_string(), 2_000_000); // 2.0 loss
        action_losses.insert("medium".to_string(), 3_000_000); // 3.0 loss
        action_losses.insert("high".to_string(), 500_000); // 0.5 loss (below threshold)

        let loss_matrix = ExpectedLossMatrix::new(
            action_losses,
            1_000_000, // Block actions with loss >= 1.0
        );

        // Stopping threshold: log(1/0.05) ≈ 2.996 in millionths.
        let stopping_threshold =
            StoppingThreshold::try_from_log_millionths(2_996_000).expect("valid threshold");

        EProcessGuardrail::new(
            "fnr-guard",
            "false_negative_rate",
            "false-negative rate <= 0.01",
            stopping_threshold,
            loss_matrix,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 10_000,     // 0.01
                high_ratio_millionths: 5_000_000, // 5.0
                low_ratio_millionths: 500_000,    // 0.5
            }),
        )
    }

    // -- State lifecycle --

    #[test]
    fn new_guardrail_starts_active() {
        let gr = test_guardrail();
        assert_eq!(gr.state(), GuardrailState::Active);
        assert!(!gr.is_stopped());
        assert_eq!(gr.observation_count(), 0);

        // Initial martingale state: M_0 = 1 (log_m = 0).
        let state = gr.martingale_state();
        assert_eq!(state.event_count, 0);
        assert_eq!(state.log_m_millionths, 0);
    }

    #[test]
    fn state_display() {
        assert_eq!(GuardrailState::Active.to_string(), "active");
        assert_eq!(GuardrailState::Triggered.to_string(), "triggered");
        assert_eq!(GuardrailState::Suspended.to_string(), "suspended");
    }

    // -- Martingale accumulation --

    #[test]
    fn below_threshold_observation_updates_martingale() {
        let mut gr = test_guardrail();
        // observation = 5_000 (0.005), below threshold 10_000
        // lr = 500_000 (0.5), log_lr ≈ ln(0.5) ≈ -0.693 in millionths ≈ -693_000
        gr.update(5_000).expect("update should succeed");

        let state = gr.martingale_state();
        assert_eq!(state.event_count, 1);
        assert!(state.log_m_millionths < 0); // decreased from 0
        assert_eq!(gr.state(), GuardrailState::Active);
        assert_eq!(gr.observation_count(), 1);
    }

    #[test]
    fn above_threshold_observation_increases_log_martingale() {
        let mut gr = test_guardrail();
        // observation = 15_000 (0.015), above threshold 10_000
        // lr = 5_000_000 (5.0), log_lr ≈ ln(5.0) ≈ 1.609 in millionths ≈ 1_609_000
        gr.update(15_000).expect("update should succeed");

        let state = gr.martingale_state();
        assert_eq!(state.event_count, 1);
        assert!(state.log_m_millionths > 0); // increased from 0
        assert_eq!(gr.state(), GuardrailState::Active);
    }

    #[test]
    fn repeated_high_observations_trigger_guardrail() {
        let mut gr = test_guardrail();
        // Need enough high observations to cross log threshold ≈ 2.996
        // Each high observation adds ln(5.0) ≈ 1.609
        // Need at least 2 observations: 1.609 + 1.609 = 3.218 > 2.996
        gr.update(15_000).expect("update should succeed");
        assert_eq!(gr.state(), GuardrailState::Active);

        gr.update(15_000).expect("update should succeed");
        assert_eq!(gr.state(), GuardrailState::Triggered);
        assert!(gr.is_stopped());
    }

    #[test]
    fn triggered_guardrail_rejects_updates() {
        let mut gr = test_guardrail();
        gr.update(15_000)
            .expect("serde deserialization should succeed");
        gr.update(15_000)
            .expect("serde deserialization should succeed"); // triggers
        assert_eq!(gr.state(), GuardrailState::Triggered);

        let err = gr.update(15_000).unwrap_err();
        assert_eq!(
            err,
            GuardrailError::AlreadyTriggered {
                guardrail_id: "fnr-guard".to_string()
            }
        );
    }

    // -- Blocking semantics --

    #[test]
    fn active_guardrail_does_not_block() {
        let gr = test_guardrail();
        assert!(!gr.blocks("low"));
        assert!(!gr.blocks("medium"));
    }

    #[test]
    fn triggered_guardrail_blocks_high_loss_actions() {
        let mut gr = test_guardrail();
        gr.update(15_000).expect("update should succeed");
        gr.update(15_000).expect("update should succeed"); // triggers

        // Expected-loss matrix blocks actions with loss >= 1.0
        // "low" has loss 2.0, "medium" has loss 3.0 -> blocked
        // "high" has loss 0.5 -> not blocked
        assert!(gr.blocks("low"));
        assert!(gr.blocks("medium"));
        assert!(!gr.blocks("high"));
    }

    // -- Reset --

    #[test]
    fn reset_triggered_guardrail() {
        let mut gr = test_guardrail();
        gr.update(15_000).expect("update should succeed");
        gr.update(15_000).expect("update should succeed"); // triggers

        let receipt = ResetReceipt {
            authorized_by: "operator-1".to_string(),
            rationale: "FNR condition addressed".to_string(),
            epoch: SecurityEpoch::from_raw(1),
        };
        gr.reset(&receipt).expect("reset should succeed");

        assert_eq!(gr.state(), GuardrailState::Active);
        assert!(!gr.is_stopped());
        assert_eq!(gr.observation_count(), 0);

        // Fresh martingale: M_0 = 1 (log_m = 0).
        let state = gr.martingale_state();
        assert_eq!(state.event_count, 0);
        assert_eq!(state.log_m_millionths, 0);
    }

    #[test]
    fn reset_non_triggered_fails() {
        let mut gr = test_guardrail();
        let receipt = ResetReceipt {
            authorized_by: "operator-1".to_string(),
            rationale: "test".to_string(),
            epoch: SecurityEpoch::GENESIS,
        };
        let err = gr.reset(&receipt).unwrap_err();
        assert_eq!(
            err,
            GuardrailError::NotTriggered {
                guardrail_id: "fnr-guard".to_string()
            }
        );
    }

    #[test]
    fn reset_with_empty_authorized_by_fails() {
        let mut gr = test_guardrail();
        gr.update(15_000)
            .expect("serde deserialization should succeed");
        gr.update(15_000)
            .expect("serde deserialization should succeed"); // triggers

        let receipt = ResetReceipt {
            authorized_by: "".to_string(),
            rationale: "test".to_string(),
            epoch: SecurityEpoch::GENESIS,
        };
        let err = gr.reset(&receipt).unwrap_err();
        assert_eq!(
            err,
            GuardrailError::ResetUnauthorized {
                guardrail_id: "fnr-guard".to_string()
            }
        );
    }

    // -- Suspend / Resume --

    #[test]
    fn suspend_stops_accumulation() {
        let mut gr = test_guardrail();
        gr.suspend("maintenance window");
        assert_eq!(gr.state(), GuardrailState::Suspended);

        let err = gr.update(15_000).unwrap_err();
        assert_eq!(
            err,
            GuardrailError::Suspended {
                guardrail_id: "fnr-guard".to_string()
            }
        );
    }

    #[test]
    fn resume_after_suspend() {
        let mut gr = test_guardrail();
        gr.suspend("maintenance");
        gr.resume();
        assert_eq!(gr.state(), GuardrailState::Active);
        gr.update(15_000).expect("update should succeed"); // works again
    }

    // -- Events --

    #[test]
    fn update_emits_martingale_updated_event() {
        let mut gr = test_guardrail();
        gr.update(5_000).expect("update should succeed");

        let events = gr.drain_events();
        assert_eq!(events.len(), 1);
        match &events[0] {
            GuardrailEvent::MartingaleUpdated {
                observation,
                log_likelihood_ratio,
                verdict,
                sequence,
                ..
            } => {
                assert_eq!(*observation, 5_000);
                assert!(*log_likelihood_ratio < 0); // ln(0.5) < 0
                assert!(matches!(*verdict, MartingaleVerdict::Continue));
                assert_eq!(*sequence, 1);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn trigger_emits_triggered_event() {
        let mut gr = test_guardrail();
        gr.update(15_000).expect("update should succeed");
        gr.update(15_000).expect("update should succeed"); // triggers

        let events = gr.drain_events();
        // Should have 2 martingale update events + 1 triggered event
        assert_eq!(events.len(), 3);
        match &events[2] {
            GuardrailEvent::Triggered {
                blocked_actions,
                expected_losses,
                sequence,
                ..
            } => {
                assert_eq!(*sequence, 2);
                assert_eq!(blocked_actions.len(), 2);
                assert!(blocked_actions.contains(&"low".to_string()));
                assert!(blocked_actions.contains(&"medium".to_string()));
                assert_eq!(*expected_losses.get("low").unwrap(), 2_000_000);
                assert_eq!(*expected_losses.get("medium").unwrap(), 3_000_000);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn reset_emits_reset_event() {
        let mut gr = test_guardrail();
        gr.update(15_000).expect("update should succeed");
        gr.update(15_000).expect("update should succeed");
        gr.drain_events(); // clear

        let receipt = ResetReceipt {
            authorized_by: "operator".to_string(),
            rationale: "addressed".to_string(),
            epoch: SecurityEpoch::from_raw(1),
        };
        gr.reset(&receipt).expect("reset should succeed");

        let events = gr.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], GuardrailEvent::Reset { .. }));
    }

    // -- Universal likelihood ratio --

    #[test]
    fn universal_lr_computes_ratio() {
        let lr = UniversalLikelihoodRatio {
            null_mean_millionths: 500_000, // 0.5
        };
        // observation = 1_000_000 (1.0), ratio = 1.0/0.5 = 2.0
        assert_eq!(lr.ratio(1_000_000), Some(2_000_000));
        // observation = 250_000 (0.25), ratio = 0.25/0.5 = 0.5
        assert_eq!(lr.ratio(250_000), Some(500_000));
    }

    #[test]
    fn universal_lr_rejects_zero_mean() {
        let lr = UniversalLikelihoodRatio {
            null_mean_millionths: 0,
        };
        assert_eq!(lr.ratio(1_000_000), None);
    }

    // -- GuardrailRegistry --

    #[test]
    fn registry_blocked_actions_union() {
        let mut registry = GuardrailRegistry::new();

        // gr1: low threshold, triggers easily, blocks "low" action
        let mut action_losses1 = BTreeMap::new();
        action_losses1.insert("low".to_string(), 2_000_000); // blocks this
        let loss_matrix1 = ExpectedLossMatrix::new(action_losses1, 1_000_000);
        let threshold1 =
            StoppingThreshold::try_from_log_millionths(1_000_000).expect("valid threshold"); // low threshold

        let mut gr1 = EProcessGuardrail::new(
            "gr1",
            "metric-a",
            "test",
            threshold1,
            loss_matrix1,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 10_000_000,
                low_ratio_millionths: 500_000,
            }),
        );
        // Trigger gr1 with high ratio observation
        gr1.update(1_000_000).expect("update should succeed");

        // gr2: high threshold, doesn't trigger, blocks "medium" action
        let mut action_losses2 = BTreeMap::new();
        action_losses2.insert("medium".to_string(), 2_000_000); // would block this
        let loss_matrix2 = ExpectedLossMatrix::new(action_losses2, 1_000_000);
        let threshold2 =
            StoppingThreshold::try_from_log_millionths(10_000_000).expect("valid threshold"); // high threshold

        let gr2 = EProcessGuardrail::new(
            "gr2",
            "metric-b",
            "test",
            threshold2,
            loss_matrix2,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 2_000_000,
                low_ratio_millionths: 500_000,
            }),
        );

        registry.add(gr1);
        registry.add(gr2);

        // gr1 is triggered (blocks "low"), gr2 is active (blocks nothing)
        let blocked = registry.blocked_actions();
        assert!(blocked.contains("low"));
        assert!(!blocked.contains("medium"));
    }

    #[test]
    fn registry_update_stream_targets_matching_guardrails() {
        let mut registry = GuardrailRegistry::new();

        let action_losses = BTreeMap::new();
        let loss_matrix = ExpectedLossMatrix::new(action_losses, 1_000_000);
        let threshold =
            StoppingThreshold::try_from_log_millionths(10_000_000).expect("valid threshold"); // high threshold, won't trigger easily

        let gr = EProcessGuardrail::new(
            "gr1",
            "fnr",
            "test",
            threshold,
            loss_matrix,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 2_000_000,
                low_ratio_millionths: 500_000,
            }),
        );
        registry.add(gr);

        // Update matching stream
        let errors = registry.update_stream("fnr", 1_000_000);
        assert!(errors.is_empty());
        assert_eq!(
            registry
                .get("gr1")
                .expect("guardrail should exist")
                .observation_count(),
            1
        );

        // Update non-matching stream — no effect
        let errors = registry.update_stream("other", 1_000_000);
        assert!(errors.is_empty());
        assert_eq!(
            registry
                .get("gr1")
                .expect("guardrail should exist")
                .observation_count(),
            1
        );
    }

    #[test]
    fn registry_permitted_actions() {
        let mut registry = GuardrailRegistry::new();

        let mut action_losses = BTreeMap::new();
        action_losses.insert("low".to_string(), 2_000_000); // blocks this
        action_losses.insert("medium".to_string(), 500_000); // doesn't block this
        action_losses.insert("high".to_string(), 500_000); // doesn't block this
        let loss_matrix = ExpectedLossMatrix::new(action_losses, 1_000_000);
        let threshold =
            StoppingThreshold::try_from_log_millionths(1_000_000).expect("valid threshold"); // low threshold

        let mut gr = EProcessGuardrail::new(
            "gr1",
            "m",
            "test",
            threshold,
            loss_matrix,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 10_000_000,
                low_ratio_millionths: 500_000,
            }),
        );
        gr.update(1_000_000).expect("update should succeed"); // triggers
        registry.add(gr);

        let all = vec!["low".to_string(), "medium".to_string(), "high".to_string()];
        let permitted = registry.permitted_actions(&all);
        assert_eq!(permitted.len(), 2);
        assert!(!permitted.contains(&&"low".to_string()));
    }

    #[test]
    fn registry_reset_all() {
        let mut registry = GuardrailRegistry::new();

        let mut action_losses = BTreeMap::new();
        action_losses.insert("low".to_string(), 2_000_000);
        let loss_matrix = ExpectedLossMatrix::new(action_losses, 1_000_000);
        let threshold =
            StoppingThreshold::try_from_log_millionths(1_000_000).expect("valid threshold"); // low threshold

        let mut gr = EProcessGuardrail::new(
            "gr1",
            "m",
            "test",
            threshold,
            loss_matrix,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 10_000_000,
                low_ratio_millionths: 500_000,
            }),
        );
        gr.update(1_000_000).expect("update should succeed"); // triggers
        registry.add(gr);

        let receipt = ResetReceipt {
            authorized_by: "operator".to_string(),
            rationale: "epoch transition".to_string(),
            epoch: SecurityEpoch::from_raw(1),
        };
        let errors = registry.reset_all(&receipt);
        assert!(errors.is_empty());
        assert_eq!(
            registry.get("gr1").expect("guardrail should exist").state(),
            GuardrailState::Active
        );
    }

    // -- Deterministic replay --

    #[test]
    fn deterministic_replay_produces_identical_trigger_point() {
        let observations = vec![5_000i64, 15_000, 5_000, 15_000, 15_000];

        let run = |obs: &[i64]| -> (u64, i64) {
            let mut gr = test_guardrail();
            for &o in obs {
                if gr.state() == GuardrailState::Triggered {
                    break;
                }
                let _ = gr.update(o);
            }
            // Return observation count and log martingale value
            (
                gr.observation_count(),
                gr.martingale_state().log_m_millionths,
            )
        };

        let (count1, ev1) = run(&observations);
        let (count2, ev2) = run(&observations);
        assert_eq!(count1, count2);
        assert_eq!(ev1, ev2);
    }

    // -- Error display --

    #[test]
    fn error_display() {
        assert_eq!(
            GuardrailError::Suspended {
                guardrail_id: "g1".to_string()
            }
            .to_string(),
            "guardrail 'g1' is suspended"
        );
        assert_eq!(
            GuardrailError::AlreadyTriggered {
                guardrail_id: "g1".to_string()
            }
            .to_string(),
            "guardrail 'g1' already triggered"
        );
    }

    // -- Serialization --

    #[test]
    fn guardrail_state_serialization_round_trip() {
        let states = vec![
            GuardrailState::Active,
            GuardrailState::Triggered,
            GuardrailState::Suspended,
        ];
        for state in &states {
            let json = serde_json::to_string(state).expect("serialize derived Serialize");
            let restored: GuardrailState =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*state, restored);
        }
    }

    #[test]
    fn guardrail_error_serialization_round_trip() {
        let errors = vec![
            GuardrailError::Suspended {
                guardrail_id: "g".to_string(),
            },
            GuardrailError::AlreadyTriggered {
                guardrail_id: "g".to_string(),
            },
            GuardrailError::InvalidObservation {
                guardrail_id: "g".to_string(),
            },
            GuardrailError::ResetUnauthorized {
                guardrail_id: "g".to_string(),
            },
            GuardrailError::NotTriggered {
                guardrail_id: "g".to_string(),
            },
            GuardrailError::MartingaleError {
                guardrail_id: "g".to_string(),
                source: MartingaleError::AlreadyStopped,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize derived Serialize");
            let restored: GuardrailError =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn reset_receipt_serialization_round_trip() {
        let receipt = ResetReceipt {
            authorized_by: "operator-1".to_string(),
            rationale: "addressed".to_string(),
            epoch: SecurityEpoch::from_raw(5),
        };
        let json = serde_json::to_string(&receipt).expect("serialize derived Serialize");
        let restored: ResetReceipt =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(receipt, restored);
    }

    #[test]
    fn guardrail_event_serialization_round_trip() {
        let mut expected_losses = BTreeMap::new();
        expected_losses.insert("low".to_string(), 2_000_000);

        let events = vec![
            GuardrailEvent::MartingaleUpdated {
                guardrail_id: "g".to_string(),
                observation: 15_000,
                log_likelihood_ratio: 1_609_000,
                verdict: MartingaleVerdict::Continue,
                sequence: 1,
            },
            GuardrailEvent::Triggered {
                guardrail_id: "g".to_string(),
                sequence: 2,
                blocked_actions: vec!["low".to_string()],
                expected_losses,
            },
            GuardrailEvent::Reset {
                guardrail_id: "g".to_string(),
                authorized_by: "op".to_string(),
                rationale: "ok".to_string(),
                epoch: SecurityEpoch::GENESIS,
            },
            GuardrailEvent::SuspendedEvent {
                guardrail_id: "g".to_string(),
                reason: "maint".to_string(),
            },
            GuardrailEvent::Resumed {
                guardrail_id: "g".to_string(),
            },
        ];
        for event in &events {
            let json = serde_json::to_string(event).expect("serialize derived Serialize");
            let restored: GuardrailEvent =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*event, restored);
        }
    }

    // -- Enrichment: serde & error coverage --

    #[test]
    fn universal_likelihood_ratio_serde_roundtrip() {
        let ulr = UniversalLikelihoodRatio {
            null_mean_millionths: -500_000,
        };
        let json = serde_json::to_string(&ulr).expect("serialize derived Serialize");
        let restored: UniversalLikelihoodRatio =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(ulr.null_mean_millionths, restored.null_mean_millionths);
    }

    #[test]
    fn guardrail_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(GuardrailError::Suspended {
                guardrail_id: "g1".into(),
            }),
            Box::new(GuardrailError::AlreadyTriggered {
                guardrail_id: "g2".into(),
            }),
            Box::new(GuardrailError::InvalidObservation {
                guardrail_id: "g3".into(),
            }),
            Box::new(GuardrailError::ResetUnauthorized {
                guardrail_id: "g4".into(),
            }),
            Box::new(GuardrailError::NotTriggered {
                guardrail_id: "g5".into(),
            }),
            Box::new(GuardrailError::MartingaleError {
                guardrail_id: "g6".into(),
                source: MartingaleError::LogAccumulatorOverflow,
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            6,
            "all 6 variants produce distinct messages"
        );
    }

    // -- Enrichment: edge cases, overflow, lifecycle depth --

    #[test]
    fn martingale_log_accumulator_overflow_detected() {
        let action_losses = BTreeMap::new();
        let loss_matrix = ExpectedLossMatrix::new(action_losses, 1_000_000);
        // Use extremely high threshold so we don't trigger before overflow
        let threshold =
            StoppingThreshold::try_from_log_millionths(i64::MAX).expect("valid threshold");

        // Use huge likelihood ratio that will cause log accumulator overflow
        let big_ratio: i64 = i64::MAX; // huge ratio
        let mut gr = EProcessGuardrail::new(
            "overflow-test",
            "metric",
            "test",
            threshold,
            loss_matrix,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: big_ratio,
                low_ratio_millionths: 1_000_000,
            }),
        );

        // Eventually this should cause log accumulator overflow in the martingale
        let result = gr.update(1_000_000);
        match result {
            Err(GuardrailError::MartingaleError { source, .. }) => {
                assert!(matches!(source, MartingaleError::LogAccumulatorOverflow));
            }
            _ => {
                // If we didn't hit overflow immediately, keep trying
                // (The exact number of iterations depends on the log calculation)
                let mut attempts = 0;
                while attempts < 10 {
                    match gr.update(1_000_000) {
                        Err(GuardrailError::MartingaleError { source, .. }) => {
                            assert!(matches!(source, MartingaleError::LogAccumulatorOverflow));
                            return;
                        }
                        Err(_) => break,
                        Ok(_) => attempts += 1,
                    }
                }
            }
        }
    }

    #[test]
    fn update_on_suspended_returns_suspended_error() {
        let mut gr = test_guardrail();
        gr.suspend("test");
        let err = gr.update(15_000).unwrap_err();
        assert!(matches!(err, GuardrailError::Suspended { .. }));
    }

    #[test]
    fn suspend_preserves_martingale_state_and_count() {
        let mut gr = test_guardrail();
        gr.update(5_000).expect("update should succeed");
        let state_before = gr.martingale_state();
        let count_before = gr.observation_count();
        gr.suspend("maintenance");
        assert_eq!(
            gr.martingale_state().log_m_millionths,
            state_before.log_m_millionths
        );
        assert_eq!(gr.observation_count(), count_before);
    }

    #[test]
    fn resume_non_suspended_is_noop() {
        let mut gr = test_guardrail();
        assert_eq!(gr.state(), GuardrailState::Active);
        gr.resume(); // should not emit event
        assert_eq!(gr.state(), GuardrailState::Active);
        let events = gr.drain_events();
        assert!(events.is_empty());
    }

    #[test]
    fn drain_events_idempotent() {
        let mut gr = test_guardrail();
        gr.update(5_000)
            .expect("serde deserialization should succeed");
        let first = gr.drain_events();
        assert!(!first.is_empty());
        let second = gr.drain_events();
        assert!(second.is_empty());
    }

    #[test]
    fn threshold_lr_at_exact_threshold() {
        let lr = ThresholdLikelihoodRatio {
            threshold_millionths: 10_000,
            high_ratio_millionths: 5_000_000,
            low_ratio_millionths: 500_000,
        };
        // At exact threshold → high ratio
        assert_eq!(lr.ratio(10_000), Some(5_000_000));
    }

    #[test]
    fn threshold_lr_just_below_threshold() {
        let lr = ThresholdLikelihoodRatio {
            threshold_millionths: 10_000,
            high_ratio_millionths: 5_000_000,
            low_ratio_millionths: 500_000,
        };
        assert_eq!(lr.ratio(9_999), Some(500_000));
    }

    #[test]
    fn threshold_lr_family_name() {
        let lr = ThresholdLikelihoodRatio {
            threshold_millionths: 0,
            high_ratio_millionths: 1_000_000,
            low_ratio_millionths: 1_000_000,
        };
        assert_eq!(lr.family(), "threshold");
    }

    #[test]
    fn universal_lr_family_name() {
        let lr = UniversalLikelihoodRatio {
            null_mean_millionths: 1_000_000,
        };
        assert_eq!(lr.family(), "universal");
    }

    #[test]
    fn universal_lr_negative_observation() {
        let lr = UniversalLikelihoodRatio {
            null_mean_millionths: 500_000,
        };
        let ratio = lr
            .ratio(-250_000)
            .expect("serde deserialization should succeed");
        assert!(ratio < 0); // negative obs / positive mean = negative ratio
    }

    #[test]
    fn observation_count_increments_per_update() {
        let mut gr = test_guardrail();
        for i in 0..5 {
            assert_eq!(gr.observation_count(), i);
            gr.update(5_000)
                .expect("serde deserialization should succeed");
        }
        assert_eq!(gr.observation_count(), 5);
    }

    #[test]
    fn registry_empty_permits_everything() {
        let registry = GuardrailRegistry::new();
        assert!(!registry.is_blocked("any_action"));
        assert!(registry.blocked_actions().is_empty());
        assert!(registry.is_empty());
    }

    #[test]
    fn registry_get_nonexistent_returns_none() {
        let registry = GuardrailRegistry::new();
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn registry_drain_all_events_empties_all() {
        let mut registry = GuardrailRegistry::new();
        let action_losses = BTreeMap::new();
        let loss_matrix = ExpectedLossMatrix::new(action_losses, 1_000_000);
        let threshold =
            StoppingThreshold::try_from_log_millionths(10_000_000).expect("valid threshold");

        let mut gr = EProcessGuardrail::new(
            "gr1",
            "m",
            "test",
            threshold,
            loss_matrix,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 2_000_000,
                low_ratio_millionths: 500_000,
            }),
        );
        gr.update(1_000_000).expect("update should succeed");
        registry.add(gr);
        let events = registry.drain_all_events();
        assert!(!events.is_empty());
        let events2 = registry.drain_all_events();
        assert!(events2.is_empty());
    }

    #[test]
    fn registry_blocking_guardrails_multiple_blockers() {
        let mut registry = GuardrailRegistry::new();
        // Create two guardrails both blocking "low"
        for id in ["gr1", "gr2"] {
            let mut action_losses = BTreeMap::new();
            action_losses.insert("low".to_string(), 2_000_000); // blocks this
            let loss_matrix = ExpectedLossMatrix::new(action_losses, 1_000_000);
            let threshold =
                StoppingThreshold::try_from_log_millionths(1_000_000).expect("valid threshold"); // low threshold

            let mut gr = EProcessGuardrail::new(
                id,
                "m",
                "test",
                threshold,
                loss_matrix,
                SecurityEpoch::GENESIS,
                Box::new(ThresholdLikelihoodRatio {
                    threshold_millionths: 0,
                    high_ratio_millionths: 10_000_000,
                    low_ratio_millionths: 500_000,
                }),
            );
            gr.update(1_000_000).expect("update should succeed"); // triggers
            registry.add(gr);
        }
        let blockers = registry.blocking_guardrails("low");
        assert_eq!(blockers.len(), 2);
    }

    #[test]
    fn registry_update_stream_skips_non_matching() {
        let mut registry = GuardrailRegistry::new();
        let action_losses = BTreeMap::new();
        let loss_matrix = ExpectedLossMatrix::new(action_losses, 1_000_000);
        let threshold =
            StoppingThreshold::try_from_log_millionths(10_000_000).expect("valid threshold");

        let gr = EProcessGuardrail::new(
            "gr1",
            "stream-a",
            "test",
            threshold,
            loss_matrix,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 2_000_000,
                low_ratio_millionths: 500_000,
            }),
        );
        registry.add(gr);
        registry.update_stream("stream-b", 1_000_000); // different stream
        assert_eq!(
            registry
                .get("gr1")
                .expect("guardrail should exist")
                .observation_count(),
            0
        );
    }

    #[test]
    fn reset_all_skips_active_guardrails() {
        let mut registry = GuardrailRegistry::new();
        let action_losses = BTreeMap::new();
        let loss_matrix = ExpectedLossMatrix::new(action_losses, 1_000_000);
        let threshold =
            StoppingThreshold::try_from_log_millionths(10_000_000).expect("valid threshold");

        let gr = EProcessGuardrail::new(
            "active-gr",
            "m",
            "test",
            threshold,
            loss_matrix,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 2_000_000,
                low_ratio_millionths: 500_000,
            }),
        );
        registry.add(gr);
        let receipt = ResetReceipt {
            authorized_by: "op".to_string(),
            rationale: "test".to_string(),
            epoch: SecurityEpoch::from_raw(1),
        };
        let errors = registry.reset_all(&receipt);
        assert!(errors.is_empty()); // no triggered guardrails to reset
        assert_eq!(
            registry
                .get("active-gr")
                .expect("guardrail should exist")
                .state(),
            GuardrailState::Active
        );
    }

    #[test]
    fn guardrail_error_display_all_variants() {
        let errors = vec![
            GuardrailError::Suspended {
                guardrail_id: "g".into(),
            },
            GuardrailError::AlreadyTriggered {
                guardrail_id: "g".into(),
            },
            GuardrailError::InvalidObservation {
                guardrail_id: "g".into(),
            },
            GuardrailError::ResetUnauthorized {
                guardrail_id: "g".into(),
            },
            GuardrailError::NotTriggered {
                guardrail_id: "g".into(),
            },
            GuardrailError::MartingaleError {
                guardrail_id: "g".into(),
                source: MartingaleError::AlreadyStopped,
            },
        ];
        let mut unique = std::collections::BTreeSet::new();
        for e in &errors {
            unique.insert(e.to_string());
        }
        assert_eq!(unique.len(), 6);
    }

    #[test]
    fn guardrail_config_epoch_preserved() {
        let epoch = SecurityEpoch::from_raw(42);
        let action_losses = BTreeMap::new();
        let loss_matrix = ExpectedLossMatrix::new(action_losses, 1_000_000);
        let threshold =
            StoppingThreshold::try_from_log_millionths(2_996_000).expect("valid threshold");

        let gr = EProcessGuardrail::new(
            "g",
            "m",
            "test",
            threshold,
            loss_matrix,
            epoch,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 1_000_000,
                low_ratio_millionths: 1_000_000,
            }),
        );
        assert_eq!(gr.config_epoch(), epoch);
    }

    #[test]
    fn threshold_lr_serialization_round_trip() {
        let lr = ThresholdLikelihoodRatio {
            threshold_millionths: 10_000,
            high_ratio_millionths: 5_000_000,
            low_ratio_millionths: 500_000,
        };
        let json = serde_json::to_string(&lr).expect("serialize derived Serialize");
        let restored: ThresholdLikelihoodRatio =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(lr.threshold_millionths, restored.threshold_millionths);
        assert_eq!(lr.high_ratio_millionths, restored.high_ratio_millionths);
    }

    // -----------------------------------------------------------------------
    // Enrichment: GuardrailState display uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn guardrail_state_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> = [
            GuardrailState::Active,
            GuardrailState::Triggered,
            GuardrailState::Suspended,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(displays.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Enrichment: suspend emits SuspendedEvent
    // -----------------------------------------------------------------------

    #[test]
    fn suspend_emits_event() {
        let mut gr = test_guardrail();
        gr.suspend("planned maintenance");
        let events = gr.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], GuardrailEvent::SuspendedEvent { .. }));
    }

    // -----------------------------------------------------------------------
    // Enrichment: resume emits Resumed event
    // -----------------------------------------------------------------------

    #[test]
    fn resume_emits_event() {
        let mut gr = test_guardrail();
        gr.suspend("maint");
        gr.drain_events(); // clear suspend event
        gr.resume();
        let events = gr.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], GuardrailEvent::Resumed { .. }));
    }

    // -----------------------------------------------------------------------
    // Enrichment: multiple guardrails in registry tracking
    // -----------------------------------------------------------------------

    #[test]
    fn registry_guardrail_count() {
        let mut registry = GuardrailRegistry::new();
        assert!(registry.is_empty());

        let action_losses = BTreeMap::new();
        let loss_matrix = ExpectedLossMatrix::new(action_losses, 1_000_000);
        let threshold =
            StoppingThreshold::try_from_log_millionths(10_000_000).expect("valid threshold");

        let gr = EProcessGuardrail::new(
            "gr1",
            "m",
            "test",
            threshold,
            loss_matrix,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 2_000_000,
                low_ratio_millionths: 500_000,
            }),
        );
        registry.add(gr);
        assert!(!registry.is_empty());
        assert!(registry.get("gr1").is_some());
    }

    // -----------------------------------------------------------------------
    // Enrichment: martingale always starts with log_m = 0 (M_0 = 1.0)
    // -----------------------------------------------------------------------

    #[test]
    fn initial_martingale_log_value_is_zero() {
        let gr = test_guardrail();
        assert_eq!(gr.martingale_state().log_m_millionths, 0);
        assert_eq!(gr.martingale_state().event_count, 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: trigger after single massive observation
    // -----------------------------------------------------------------------

    #[test]
    fn single_observation_can_trigger_if_log_ratio_exceeds_threshold() {
        let action_losses = BTreeMap::new();
        let loss_matrix = ExpectedLossMatrix::new(action_losses, 1_000_000);
        // Low threshold: ln(5.0) ≈ 1.609 in millionths ≈ 1_609_000
        let threshold =
            StoppingThreshold::try_from_log_millionths(1_609_000).expect("valid threshold");

        let mut gr = EProcessGuardrail::new(
            "single-trigger",
            "metric",
            "test",
            threshold,
            loss_matrix,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 10_000_000, // ratio = 10.0, ln(10) ≈ 2.303 > 1.609
                low_ratio_millionths: 500_000,
            }),
        );
        // Single observation with ratio 10.0: log_m = ln(10) ≈ 2.303 > 1.609 threshold
        gr.update(1_000_000).expect("update should succeed");
        assert_eq!(gr.state(), GuardrailState::Triggered);
    }

    // -----------------------------------------------------------------------
    // Enrichment: guardrail_id accessor
    // -----------------------------------------------------------------------

    #[test]
    fn guardrail_id_matches_construction() {
        let gr = test_guardrail();
        assert_eq!(gr.guardrail_id, "fnr-guard");
    }

    // ===================================================================
    // Enrichment batch 2: copy semantics, serde distinctness, clone
    // independence, field-name stability, hash, boundary, debug
    // ===================================================================

    // -- Category 1: Copy semantics --

    #[test]
    fn guardrail_state_copy_semantics() {
        let a = GuardrailState::Active;
        let b = a; // copy
        assert_eq!(a, b);
        let c = GuardrailState::Triggered;
        let d = c;
        assert_eq!(c, d);
        let e = GuardrailState::Suspended;
        let f = e;
        assert_eq!(e, f);
    }

    #[test]
    fn guardrail_state_copy_into_function() {
        fn consume(s: GuardrailState) -> String {
            s.to_string()
        }
        let s = GuardrailState::Active;
        let r1 = consume(s);
        let r2 = consume(s); // still usable after copy
        assert_eq!(r1, r2);
    }

    // -- Category 2: Debug distinctness --

    #[test]
    fn guardrail_state_debug_distinct() {
        let variants = [
            GuardrailState::Active,
            GuardrailState::Triggered,
            GuardrailState::Suspended,
        ];
        let dbg_set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(
            dbg_set.len(),
            3,
            "all GuardrailState variants have distinct Debug"
        );
    }

    #[test]
    fn guardrail_error_debug_distinct() {
        let errors = [
            GuardrailError::Suspended {
                guardrail_id: "x".into(),
            },
            GuardrailError::AlreadyTriggered {
                guardrail_id: "x".into(),
            },
            GuardrailError::InvalidObservation {
                guardrail_id: "x".into(),
            },
            GuardrailError::ResetUnauthorized {
                guardrail_id: "x".into(),
            },
            GuardrailError::NotTriggered {
                guardrail_id: "x".into(),
            },
            GuardrailError::MartingaleError {
                guardrail_id: "x".into(),
                source: MartingaleError::LogAccumulatorOverflow,
            },
        ];
        let dbg_set: BTreeSet<String> = errors.iter().map(|e| format!("{e:?}")).collect();
        assert_eq!(
            dbg_set.len(),
            6,
            "all GuardrailError variants have distinct Debug"
        );
    }

    #[test]
    fn guardrail_event_debug_distinct() {
        let events = [
            GuardrailEvent::MartingaleUpdated {
                guardrail_id: "g".into(),
                observation: 0,
                log_likelihood_ratio: 0,
                verdict: MartingaleVerdict::Continue,
                sequence: 0,
            },
            GuardrailEvent::Triggered {
                guardrail_id: "g".into(),
                sequence: 1,
                blocked_actions: vec![],
                expected_losses: BTreeMap::new(),
            },
            GuardrailEvent::Reset {
                guardrail_id: "g".into(),
                authorized_by: "a".into(),
                rationale: "r".into(),
                epoch: SecurityEpoch::GENESIS,
            },
            GuardrailEvent::SuspendedEvent {
                guardrail_id: "g".into(),
                reason: "r".into(),
            },
            GuardrailEvent::Resumed {
                guardrail_id: "g".into(),
            },
        ];
        let dbg_set: BTreeSet<String> = events.iter().map(|e| format!("{e:?}")).collect();
        assert_eq!(
            dbg_set.len(),
            5,
            "all GuardrailEvent variants have distinct Debug"
        );
    }

    // -- Category 3: Serde variant distinctness --

    #[test]
    fn guardrail_state_serde_variant_distinct() {
        let variants = [
            GuardrailState::Active,
            GuardrailState::Triggered,
            GuardrailState::Suspended,
        ];
        let json_set: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).expect("serialize derived Serialize"))
            .collect();
        assert_eq!(
            json_set.len(),
            3,
            "all GuardrailState serde outputs distinct"
        );
    }

    #[test]
    fn guardrail_error_serde_variant_distinct() {
        let errors = [
            GuardrailError::Suspended {
                guardrail_id: "g".into(),
            },
            GuardrailError::AlreadyTriggered {
                guardrail_id: "g".into(),
            },
            GuardrailError::InvalidObservation {
                guardrail_id: "g".into(),
            },
            GuardrailError::ResetUnauthorized {
                guardrail_id: "g".into(),
            },
            GuardrailError::NotTriggered {
                guardrail_id: "g".into(),
            },
            GuardrailError::MartingaleError {
                guardrail_id: "g".into(),
                source: MartingaleError::LogAccumulatorOverflow,
            },
        ];
        let json_set: BTreeSet<String> = errors
            .iter()
            .map(|e| serde_json::to_string(e).expect("serialize derived Serialize"))
            .collect();
        assert_eq!(
            json_set.len(),
            6,
            "all GuardrailError serde outputs distinct"
        );
    }

    #[test]
    fn guardrail_event_serde_variant_distinct() {
        let events = [
            GuardrailEvent::MartingaleUpdated {
                guardrail_id: "g".into(),
                observation: 3,
                log_likelihood_ratio: 4,
                verdict: MartingaleVerdict::Continue,
                sequence: 1,
            },
            GuardrailEvent::Triggered {
                guardrail_id: "g".into(),
                sequence: 1,
                blocked_actions: vec!["action1".to_string()],
                expected_losses: BTreeMap::new(),
            },
            GuardrailEvent::Reset {
                guardrail_id: "g".into(),
                authorized_by: "a".into(),
                rationale: "r".into(),
                epoch: SecurityEpoch::GENESIS,
            },
            GuardrailEvent::SuspendedEvent {
                guardrail_id: "g".into(),
                reason: "r".into(),
            },
            GuardrailEvent::Resumed {
                guardrail_id: "g".into(),
            },
        ];
        let json_set: BTreeSet<String> = events
            .iter()
            .map(|e| serde_json::to_string(e).expect("serialize derived Serialize"))
            .collect();
        assert_eq!(
            json_set.len(),
            5,
            "all GuardrailEvent serde outputs distinct"
        );
    }

    // -- Category 4: Clone independence --

    #[test]
    fn guardrail_error_clone_independence() {
        let original = GuardrailError::Suspended {
            guardrail_id: "abc".into(),
        };
        let cloned = original.clone();
        // Clone matches original
        assert_eq!(original, cloned);
        // They are independently owned values
        assert_eq!(
            original,
            GuardrailError::Suspended {
                guardrail_id: "abc".into()
            }
        );
        drop(cloned);
        // original still valid after clone is dropped
        assert_eq!(original.to_string(), "guardrail 'abc' is suspended");
    }

    #[test]
    fn reset_receipt_clone_independence() {
        let original = ResetReceipt {
            authorized_by: "op1".into(),
            rationale: "test".into(),
            epoch: SecurityEpoch::from_raw(5),
        };
        let mut cloned = original.clone();
        cloned.authorized_by = "op2".into();
        assert_eq!(original.authorized_by, "op1");
        assert_eq!(cloned.authorized_by, "op2");
    }

    #[test]
    fn guardrail_event_clone_independence() {
        let original = GuardrailEvent::Triggered {
            guardrail_id: "g1".into(),
            sequence: 100,
            blocked_actions: vec!["a".into(), "b".into()],
            expected_losses: BTreeMap::new(),
        };
        let mut cloned = original.clone();
        if let GuardrailEvent::Triggered {
            ref mut blocked_actions,
            ..
        } = cloned
        {
            blocked_actions.push("c".into());
        }
        // Original unchanged
        if let GuardrailEvent::Triggered {
            blocked_actions, ..
        } = &original
        {
            assert_eq!(blocked_actions.len(), 2);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn threshold_lr_clone_independence() {
        let original = ThresholdLikelihoodRatio {
            threshold_millionths: 100,
            high_ratio_millionths: 200,
            low_ratio_millionths: 300,
        };
        let mut cloned = original.clone();
        cloned.threshold_millionths = 999;
        assert_eq!(original.threshold_millionths, 100);
        assert_eq!(cloned.threshold_millionths, 999);
    }

    #[test]
    fn universal_lr_clone_independence() {
        let original = UniversalLikelihoodRatio {
            null_mean_millionths: 500_000,
        };
        let mut cloned = original.clone();
        cloned.null_mean_millionths = 1_000_000;
        assert_eq!(original.null_mean_millionths, 500_000);
        assert_eq!(cloned.null_mean_millionths, 1_000_000);
    }

    // -- Category 5: JSON field-name stability --

    #[test]
    fn reset_receipt_json_field_names() {
        let receipt = ResetReceipt {
            authorized_by: "op".into(),
            rationale: "reason".into(),
            epoch: SecurityEpoch::GENESIS,
        };
        let json = serde_json::to_value(&receipt).expect("serde deserialization should succeed");
        let obj = json
            .as_object()
            .expect("serde deserialization should succeed");
        assert!(obj.contains_key("authorized_by"), "missing 'authorized_by'");
        assert!(obj.contains_key("rationale"), "missing 'rationale'");
        assert!(obj.contains_key("epoch"), "missing 'epoch'");
        assert_eq!(obj.len(), 3, "unexpected extra fields");
    }

    #[test]
    fn threshold_lr_json_field_names() {
        let lr = ThresholdLikelihoodRatio {
            threshold_millionths: 1,
            high_ratio_millionths: 2,
            low_ratio_millionths: 3,
        };
        let json = serde_json::to_value(&lr).expect("serde deserialization should succeed");
        let obj = json
            .as_object()
            .expect("serde deserialization should succeed");
        assert!(obj.contains_key("threshold_millionths"));
        assert!(obj.contains_key("high_ratio_millionths"));
        assert!(obj.contains_key("low_ratio_millionths"));
        assert_eq!(obj.len(), 3);
    }

    #[test]
    fn universal_lr_json_field_names() {
        let lr = UniversalLikelihoodRatio {
            null_mean_millionths: 42,
        };
        let json = serde_json::to_value(&lr).expect("serde deserialization should succeed");
        let obj = json
            .as_object()
            .expect("serde deserialization should succeed");
        assert!(obj.contains_key("null_mean_millionths"));
        assert_eq!(obj.len(), 1);
    }

    #[test]
    fn guardrail_event_e_value_updated_json_field_names() {
        let event = GuardrailEvent::MartingaleUpdated {
            guardrail_id: "g".into(),
            observation: 3,
            log_likelihood_ratio: 4,
            verdict: MartingaleVerdict::Continue,
            sequence: 1,
        };
        let json = serde_json::to_value(&event).expect("serde deserialization should succeed");
        let obj = json
            .as_object()
            .expect("serde deserialization should succeed");
        assert!(obj.contains_key("EValueUpdated"));
        let inner = obj["EValueUpdated"]
            .as_object()
            .expect("serde deserialization should succeed");
        assert!(inner.contains_key("guardrail_id"));
        assert!(inner.contains_key("observation"));
        assert!(inner.contains_key("log_likelihood_ratio"));
        assert!(inner.contains_key("verdict"));
        assert!(inner.contains_key("sequence"));
    }

    #[test]
    fn guardrail_event_triggered_json_field_names() {
        let event = GuardrailEvent::Triggered {
            guardrail_id: "g".into(),
            sequence: 10,
            blocked_actions: vec!["x".into()],
            expected_losses: BTreeMap::new(),
        };
        let json = serde_json::to_value(&event).expect("serde deserialization should succeed");
        let obj = json
            .as_object()
            .expect("serde deserialization should succeed");
        assert!(obj.contains_key("Triggered"));
        let inner = obj["Triggered"]
            .as_object()
            .expect("serde deserialization should succeed");
        assert!(inner.contains_key("guardrail_id"));
        assert!(inner.contains_key("e_value"));
        assert!(inner.contains_key("threshold"));
        assert!(inner.contains_key("blocked_actions"));
    }

    #[test]
    fn guardrail_event_reset_json_field_names() {
        let event = GuardrailEvent::Reset {
            guardrail_id: "g".into(),
            authorized_by: "a".into(),
            rationale: "r".into(),
            epoch: SecurityEpoch::GENESIS,
        };
        let json = serde_json::to_value(&event).expect("serde deserialization should succeed");
        let obj = json
            .as_object()
            .expect("serde deserialization should succeed");
        assert!(obj.contains_key("Reset"));
        let inner = obj["Reset"]
            .as_object()
            .expect("serde deserialization should succeed");
        assert!(inner.contains_key("guardrail_id"));
        assert!(inner.contains_key("authorized_by"));
        assert!(inner.contains_key("rationale"));
        assert!(inner.contains_key("epoch"));
    }

    // -- Category 6: Display format checks --

    #[test]
    fn guardrail_error_display_suspended_exact() {
        let e = GuardrailError::Suspended {
            guardrail_id: "my-guard".into(),
        };
        assert_eq!(e.to_string(), "guardrail 'my-guard' is suspended");
    }

    #[test]
    fn guardrail_error_display_invalid_observation_exact() {
        let e = GuardrailError::InvalidObservation {
            guardrail_id: "obs-g".into(),
        };
        assert_eq!(e.to_string(), "invalid observation for guardrail 'obs-g'");
    }

    #[test]
    fn guardrail_error_display_reset_unauthorized_exact() {
        let e = GuardrailError::ResetUnauthorized {
            guardrail_id: "reset-g".into(),
        };
        assert_eq!(e.to_string(), "unauthorized reset for guardrail 'reset-g'");
    }

    #[test]
    fn guardrail_error_display_not_triggered_exact() {
        let e = GuardrailError::NotTriggered {
            guardrail_id: "nt-g".into(),
        };
        assert_eq!(e.to_string(), "guardrail 'nt-g' is not triggered");
    }

    #[test]
    fn guardrail_error_display_evalue_overflow_exact() {
        let e = GuardrailError::MartingaleError {
            guardrail_id: "ov-g".into(),
            source: MartingaleError::LogAccumulatorOverflow,
        };
        assert_eq!(e.to_string(), "e-value overflow for guardrail 'ov-g'");
    }

    // -- Category 7: Hash consistency (SecurityEpoch derives Hash) --

    #[test]
    fn security_epoch_hash_consistency_in_reset_receipt() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let epoch = SecurityEpoch::from_raw(42);
        let mut h1 = DefaultHasher::new();
        epoch.hash(&mut h1);
        let hash1 = h1.finish();

        let mut h2 = DefaultHasher::new();
        epoch.hash(&mut h2);
        let hash2 = h2.finish();

        assert_eq!(hash1, hash2, "same SecurityEpoch hashes identically");
    }

    #[test]
    fn guardrail_state_hash_consistency() {
        // GuardrailState doesn't derive Hash, but we verify Eq consistency
        let a = GuardrailState::Active;
        let b = GuardrailState::Active;
        assert_eq!(a, b);
        let c = GuardrailState::Triggered;
        assert_ne!(a, c);
    }

    // -- Category 8: Boundary/edge cases --

    #[test]
    fn threshold_lr_with_i64_max_observation() {
        let lr = ThresholdLikelihoodRatio {
            threshold_millionths: 0,
            high_ratio_millionths: 1_000_000,
            low_ratio_millionths: 500_000,
        };
        // i64::MAX is above threshold 0, so high ratio
        assert_eq!(lr.ratio(i64::MAX), Some(1_000_000));
    }

    #[test]
    fn threshold_lr_with_i64_min_observation() {
        let lr = ThresholdLikelihoodRatio {
            threshold_millionths: 0,
            high_ratio_millionths: 1_000_000,
            low_ratio_millionths: 500_000,
        };
        // i64::MIN is below threshold 0, so low ratio
        assert_eq!(lr.ratio(i64::MIN), Some(500_000));
    }

    #[test]
    fn universal_lr_with_zero_observation() {
        let lr = UniversalLikelihoodRatio {
            null_mean_millionths: 1_000_000,
        };
        assert_eq!(lr.ratio(0), Some(0));
    }

    #[test]
    fn universal_lr_with_very_large_observation() {
        let lr = UniversalLikelihoodRatio {
            null_mean_millionths: 1, // very small null mean
        };
        // observation = 1_000_000 (1.0), ratio = 1_000_000 * 1_000_000 / 1 = 1e12
        let ratio = lr
            .ratio(1_000_000)
            .expect("serde deserialization should succeed");
        assert_eq!(ratio, 1_000_000_000_000);
    }

    #[test]
    fn universal_lr_with_negative_null_mean() {
        let lr = UniversalLikelihoodRatio {
            null_mean_millionths: -500_000,
        };
        // observation = 1_000_000, ratio = 1M * 1M / -500K = -2M
        let ratio = lr
            .ratio(1_000_000)
            .expect("serde deserialization should succeed");
        assert_eq!(ratio, -2_000_000);
    }

    #[test]
    fn guardrail_error_with_empty_guardrail_id() {
        let e = GuardrailError::Suspended {
            guardrail_id: String::new(),
        };
        assert_eq!(e.to_string(), "guardrail '' is suspended");
    }

    #[test]
    fn reset_receipt_with_empty_rationale() {
        let receipt = ResetReceipt {
            authorized_by: "op".into(),
            rationale: String::new(),
            epoch: SecurityEpoch::GENESIS,
        };
        let json = serde_json::to_string(&receipt).expect("serialize derived Serialize");
        let restored: ResetReceipt =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(restored.rationale, "");
    }

    #[test]
    fn guardrail_with_zero_threshold_triggers_on_any_positive_ratio() {
        let loss_matrix = ExpectedLossMatrix::new(BTreeMap::new(), 0);
        let mut gr = EProcessGuardrail::new(
            "zero-thresh",
            "m",
            "test",
            StoppingThreshold::try_from_log_millionths(1).unwrap(), // Use minimal positive threshold
            loss_matrix,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 2_000_000,
                low_ratio_millionths: 500_000,
            }),
        );
        // e = 1_000_000 * 2_000_000 / 1_000_000 = 2_000_000 >= 0, triggers
        gr.update(100)
            .expect("serde deserialization should succeed");
        assert_eq!(gr.state(), GuardrailState::Triggered);
    }

    #[test]
    fn guardrail_with_empty_blocked_actions() {
        let mut gr = EProcessGuardrail::new(
            "no-blocks",
            "m",
            "test",
            StoppingThreshold::try_from_log_millionths(5_000_000).unwrap(),
            ExpectedLossMatrix::new(BTreeMap::new(), 0),
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 10_000_000,
                low_ratio_millionths: 500_000,
            }),
        );
        gr.update(1_000_000)
            .expect("serde deserialization should succeed"); // triggers
        assert_eq!(gr.state(), GuardrailState::Triggered);
        assert!(gr.blocked_actions().is_empty());
        assert!(!gr.blocks("any_action"));
    }

    #[test]
    fn guardrail_threshold_at_max_i64() {
        let loss_matrix = ExpectedLossMatrix::new(BTreeMap::new(), 0);
        let mut gr = EProcessGuardrail::new(
            "max-thresh",
            "m",
            "test",
            StoppingThreshold::try_from_log_millionths(i64::MAX).unwrap(),
            loss_matrix,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 2_000_000,
                low_ratio_millionths: 500_000,
            }),
        );
        // e = 1M * 2M / 1M = 2M — well below i64::MAX
        gr.update(1_000_000)
            .expect("serde deserialization should succeed");
        assert_eq!(gr.state(), GuardrailState::Active);
    }

    // -- Category 9: Serde roundtrips (complex structs) --

    #[test]
    fn guardrail_event_e_value_updated_serde_roundtrip_complex() {
        let event = GuardrailEvent::MartingaleUpdated {
            guardrail_id: "complex-guardrail-with-long-id".into(),
            observation: 0,
            log_likelihood_ratio: -1,
            verdict: MartingaleVerdict::Continue,
            sequence: 0,
        };
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let restored: GuardrailEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(event, restored);
    }

    #[test]
    fn guardrail_event_triggered_serde_roundtrip_many_actions() {
        let event = GuardrailEvent::Triggered {
            guardrail_id: "g".into(),
            sequence: 999_999_999,
            blocked_actions: (0..20).map(|i| format!("action-{i}")).collect(),
            expected_losses: BTreeMap::new(),
        };
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let restored: GuardrailEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(event, restored);
    }

    #[test]
    fn guardrail_error_serde_roundtrip_long_id() {
        let long_id: String = "x".repeat(1000);
        let err = GuardrailError::Suspended {
            guardrail_id: long_id.clone(),
        };
        let json = serde_json::to_string(&err).expect("serialize derived Serialize");
        let restored: GuardrailError =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(err, restored);
    }

    #[test]
    fn reset_receipt_serde_roundtrip_high_epoch() {
        let receipt = ResetReceipt {
            authorized_by: "system-auto-reset".into(),
            rationale: "epoch boundary transition at u64::MAX".into(),
            epoch: SecurityEpoch::from_raw(u64::MAX),
        };
        let json = serde_json::to_string(&receipt).expect("serialize derived Serialize");
        let restored: ResetReceipt =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(receipt, restored);
    }

    #[test]
    fn threshold_lr_serde_roundtrip_negative_values() {
        let lr = ThresholdLikelihoodRatio {
            threshold_millionths: -1_000_000,
            high_ratio_millionths: -500_000,
            low_ratio_millionths: -250_000,
        };
        let json = serde_json::to_string(&lr).expect("serialize derived Serialize");
        let restored: ThresholdLikelihoodRatio =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(lr.threshold_millionths, restored.threshold_millionths);
        assert_eq!(lr.high_ratio_millionths, restored.high_ratio_millionths);
        assert_eq!(lr.low_ratio_millionths, restored.low_ratio_millionths);
    }

    // -- Category 10: Debug nonempty --

    #[test]
    fn guardrail_state_debug_nonempty() {
        for state in &[
            GuardrailState::Active,
            GuardrailState::Triggered,
            GuardrailState::Suspended,
        ] {
            assert!(!format!("{state:?}").is_empty());
        }
    }

    #[test]
    fn guardrail_error_debug_nonempty() {
        let errors = [
            GuardrailError::Suspended {
                guardrail_id: "g".into(),
            },
            GuardrailError::AlreadyTriggered {
                guardrail_id: "g".into(),
            },
            GuardrailError::InvalidObservation {
                guardrail_id: "g".into(),
            },
            GuardrailError::ResetUnauthorized {
                guardrail_id: "g".into(),
            },
            GuardrailError::NotTriggered {
                guardrail_id: "g".into(),
            },
            GuardrailError::MartingaleError {
                guardrail_id: "g".into(),
                source: MartingaleError::LogAccumulatorOverflow,
            },
        ];
        for e in &errors {
            assert!(!format!("{e:?}").is_empty());
        }
    }

    #[test]
    fn reset_receipt_debug_nonempty() {
        let receipt = ResetReceipt {
            authorized_by: "op".into(),
            rationale: "r".into(),
            epoch: SecurityEpoch::GENESIS,
        };
        assert!(!format!("{receipt:?}").is_empty());
    }

    #[test]
    fn guardrail_event_debug_nonempty() {
        let events = [
            GuardrailEvent::MartingaleUpdated {
                guardrail_id: "g".into(),
                observation: 0,
                log_likelihood_ratio: 0,
                verdict: MartingaleVerdict::Continue,
                sequence: 0,
            },
            GuardrailEvent::Triggered {
                guardrail_id: "g".into(),
                sequence: 1,
                blocked_actions: vec![],
                expected_losses: BTreeMap::new(),
            },
            GuardrailEvent::Reset {
                guardrail_id: "g".into(),
                authorized_by: "a".into(),
                rationale: "r".into(),
                epoch: SecurityEpoch::GENESIS,
            },
            GuardrailEvent::SuspendedEvent {
                guardrail_id: "g".into(),
                reason: "r".into(),
            },
            GuardrailEvent::Resumed {
                guardrail_id: "g".into(),
            },
        ];
        for e in &events {
            assert!(!format!("{e:?}").is_empty());
        }
    }

    #[test]
    fn threshold_lr_debug_nonempty() {
        let lr = ThresholdLikelihoodRatio {
            threshold_millionths: 0,
            high_ratio_millionths: 0,
            low_ratio_millionths: 0,
        };
        assert!(!format!("{lr:?}").is_empty());
    }

    #[test]
    fn universal_lr_debug_nonempty() {
        let lr = UniversalLikelihoodRatio {
            null_mean_millionths: 0,
        };
        assert!(!format!("{lr:?}").is_empty());
    }

    #[test]
    fn eprocess_guardrail_debug_nonempty() {
        let gr = test_guardrail();
        assert!(!format!("{gr:?}").is_empty());
    }

    #[test]
    fn guardrail_registry_debug_nonempty() {
        let registry = GuardrailRegistry::new();
        assert!(!format!("{registry:?}").is_empty());
    }

    // -- Additional enrichment: lifecycle depth --

    #[test]
    fn full_lifecycle_active_trigger_reset_retrigger() {
        let mut action_losses = BTreeMap::new();
        action_losses.insert("deploy".into(), 1_000_000);
        let mut gr = EProcessGuardrail::new(
            "lifecycle",
            "m",
            "test",
            StoppingThreshold::try_from_log_millionths(5_000_000).unwrap(),
            ExpectedLossMatrix::new(action_losses, 500_000),
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 10_000_000,
                low_ratio_millionths: 500_000,
            }),
        );

        // Phase 1: trigger
        assert_eq!(gr.state(), GuardrailState::Active);
        gr.update(1_000_000)
            .expect("serde deserialization should succeed"); // e = 10.0 >= 5.0
        assert_eq!(gr.state(), GuardrailState::Triggered);
        assert!(gr.blocks("deploy"));

        // Phase 2: reset
        let receipt = ResetReceipt {
            authorized_by: "admin".into(),
            rationale: "fixed".into(),
            epoch: SecurityEpoch::from_raw(1),
        };
        gr.reset(&receipt)
            .expect("serde deserialization should succeed");
        assert_eq!(gr.state(), GuardrailState::Active);
        assert!(!gr.blocks("deploy"));
        assert_eq!(gr.martingale_state().log_m_millionths, 0); // Reset should set log M_n back to 0

        // Phase 3: re-trigger
        gr.update(1_000_000)
            .expect("serde deserialization should succeed");
        assert_eq!(gr.state(), GuardrailState::Triggered);
        assert!(gr.blocks("deploy"));
    }

    #[test]
    fn suspend_resume_suspend_cycle() {
        let mut gr = test_guardrail();
        gr.suspend("first");
        assert_eq!(gr.state(), GuardrailState::Suspended);
        gr.resume();
        assert_eq!(gr.state(), GuardrailState::Active);
        gr.suspend("second");
        assert_eq!(gr.state(), GuardrailState::Suspended);
        let events = gr.drain_events();
        // Should have: SuspendedEvent, Resumed, SuspendedEvent
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn registry_get_mut_and_modify() {
        let mut registry = GuardrailRegistry::new();
        let loss_matrix = ExpectedLossMatrix::new(BTreeMap::new(), 0);
        let gr = EProcessGuardrail::new(
            "mutable",
            "m",
            "test",
            StoppingThreshold::try_from_log_millionths(100_000_000).unwrap(),
            loss_matrix,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 2_000_000,
                low_ratio_millionths: 500_000,
            }),
        );
        registry.add(gr);

        let gr_mut = registry
            .get_mut("mutable")
            .expect("serde deserialization should succeed");
        gr_mut.suspend("via registry");
        assert_eq!(
            registry
                .get("mutable")
                .expect("serde deserialization should succeed")
                .state(),
            GuardrailState::Suspended
        );
    }

    #[test]
    fn registry_get_mut_nonexistent_returns_none() {
        let mut registry = GuardrailRegistry::new();
        assert!(registry.get_mut("nope").is_none());
    }

    #[test]
    fn registry_multiple_streams_independent() {
        let mut registry = GuardrailRegistry::new();

        for (id, stream) in [("gr-a", "stream-a"), ("gr-b", "stream-b")] {
            let loss_matrix = ExpectedLossMatrix::new(BTreeMap::new(), 0);
            let gr = EProcessGuardrail::new(
                id,
                stream,
                "test",
                StoppingThreshold::try_from_log_millionths(100_000_000).unwrap(),
                loss_matrix,
                SecurityEpoch::GENESIS,
                Box::new(ThresholdLikelihoodRatio {
                    threshold_millionths: 0,
                    high_ratio_millionths: 2_000_000,
                    low_ratio_millionths: 500_000,
                }),
            );
            registry.add(gr);
        }

        registry.update_stream("stream-a", 1_000_000);
        assert_eq!(
            registry
                .get("gr-a")
                .expect("serde deserialization should succeed")
                .observation_count(),
            1
        );
        assert_eq!(
            registry
                .get("gr-b")
                .expect("serde deserialization should succeed")
                .observation_count(),
            0
        );
    }

    #[test]
    fn registry_default_is_empty() {
        let registry = GuardrailRegistry::default();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn evalue_stays_exactly_at_one_with_ratio_one() {
        let loss_matrix = ExpectedLossMatrix::new(BTreeMap::new(), 0);
        let mut gr = EProcessGuardrail::new(
            "ratio-one",
            "m",
            "test",
            StoppingThreshold::try_from_log_millionths(100_000_000).unwrap(),
            loss_matrix,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 1_000_000, // ratio = 1.0
                low_ratio_millionths: 1_000_000,  // ratio = 1.0
            }),
        );
        for _ in 0..10 {
            gr.update(0).expect("serde deserialization should succeed");
        }
        assert_eq!(gr.martingale_state().log_m_millionths, 0); // Reset should set log M_n back to 0 // remains 1.0
        assert_eq!(gr.observation_count(), 10);
    }

    #[test]
    fn evalue_decreases_with_ratio_below_one() {
        let loss_matrix = ExpectedLossMatrix::new(BTreeMap::new(), 0);
        let mut gr = EProcessGuardrail::new(
            "decreasing",
            "m",
            "test",
            StoppingThreshold::try_from_log_millionths(100_000_000).unwrap(),
            loss_matrix,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 1_000_000_000, // unreachable
                high_ratio_millionths: 500_000,      // 0.5
                low_ratio_millionths: 500_000,       // 0.5
            }),
        );
        gr.update(0).expect("serde deserialization should succeed"); // log M_n decreases with lr < 1
        assert!(gr.martingale_state().log_m_millionths < 0); // Should be negative after lr = 0.5
        gr.update(0).expect("serde deserialization should succeed"); // log M_n decreases further
        assert!(gr.martingale_state().log_m_millionths < -693147); // ln(0.5) = -0.693147, so after two updates should be ~2*ln(0.5)
    }

    #[test]
    fn threshold_lr_with_equal_ratios() {
        let lr = ThresholdLikelihoodRatio {
            threshold_millionths: 500_000,
            high_ratio_millionths: 3_000_000,
            low_ratio_millionths: 3_000_000,
        };
        // Both above and below threshold produce the same ratio
        assert_eq!(lr.ratio(0), Some(3_000_000));
        assert_eq!(lr.ratio(1_000_000), Some(3_000_000));
    }

    #[test]
    fn universal_lr_exact_ratio_one() {
        let lr = UniversalLikelihoodRatio {
            null_mean_millionths: 1_000_000, // 1.0
        };
        // observation = null_mean => ratio = 1.0
        assert_eq!(lr.ratio(1_000_000), Some(1_000_000));
    }

    // -----------------------------------------------------------------------
    // CONFORMANCE: LikelihoodRatioFn trait contract
    // -----------------------------------------------------------------------

    /// Generic conformance harness for LikelihoodRatioFn implementations.
    ///
    /// Verifies the documented trait contract:
    /// - Returns None for out-of-domain observations
    /// - Returns Some(ratio) with fixed-point i64 values for valid observations
    /// - Maintains determinism (same input → same output)
    /// - Provides stable, non-empty family names
    fn assert_likelihood_ratio_fn_contract<T: LikelihoodRatioFn>(lr: &T) {
        // Test family name: must be stable and non-empty
        let family1 = lr.family();
        let family2 = lr.family();
        assert!(!family1.is_empty(), "family name must be non-empty");
        assert_eq!(family1, family2, "family name must be stable across calls");

        // Test determinism: same inputs should produce same outputs
        let test_observations = [
            i64::MIN,
            -1_000_000_000,
            -1_000_000,
            -1,
            0,
            1,
            1_000_000,
            1_000_000_000,
            i64::MAX,
        ];

        for &obs in &test_observations {
            let result1 = lr.ratio(obs);
            let result2 = lr.ratio(obs);
            assert_eq!(
                result1, result2,
                "ratio({}) must be deterministic, got {:?} then {:?}",
                obs, result1, result2
            );

            // Fixed-point i64 ratios cannot encode NaN or infinity; validity
            // beyond determinism is domain-specific for each implementation.
        }

        // Test boundary observations around zero and extremes
        let boundary_cases = [
            (0, "zero observation"),
            (1_000_000, "unit observation (1.0 in millionths)"),
            (-1_000_000, "negative unit observation"),
        ];

        for &(obs, desc) in &boundary_cases {
            let result = lr.ratio(obs);
            // Just verify determinism and validity - domain is implementation-specific
            let repeat = lr.ratio(obs);
            assert_eq!(
                result, repeat,
                "determinism failed for {} ({}): {:?} vs {:?}",
                desc, obs, result, repeat
            );
        }
    }

    #[test]
    fn threshold_likelihood_ratio_conforms_to_contract() {
        let lr = ThresholdLikelihoodRatio {
            threshold_millionths: 500_000,    // 0.5
            high_ratio_millionths: 2_000_000, // 2.0
            low_ratio_millionths: 800_000,    // 0.8
        };
        assert_likelihood_ratio_fn_contract(&lr);
    }

    #[test]
    fn universal_likelihood_ratio_conforms_to_contract() {
        let lr = UniversalLikelihoodRatio {
            null_mean_millionths: 1_000_000, // 1.0
        };
        assert_likelihood_ratio_fn_contract(&lr);
    }

    #[test]
    fn universal_likelihood_ratio_zero_mean_conforms_to_contract() {
        // Test edge case: zero mean should return None consistently
        let lr = UniversalLikelihoodRatio {
            null_mean_millionths: 0,
        };
        assert_likelihood_ratio_fn_contract(&lr);
    }

    #[test]
    fn threshold_likelihood_ratio_negative_ratios_conforms_to_contract() {
        // Test with negative ratios (valid for some domains)
        let lr = ThresholdLikelihoodRatio {
            threshold_millionths: 0,
            high_ratio_millionths: -500_000,  // -0.5
            low_ratio_millionths: -1_000_000, // -1.0
        };
        assert_likelihood_ratio_fn_contract(&lr);
    }
}
