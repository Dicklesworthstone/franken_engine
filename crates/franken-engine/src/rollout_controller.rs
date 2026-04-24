#![forbid(unsafe_code)]

//! Deterministic staged rollout controller.
//!
//! Fractional rates use fixed-point millionths where `1_000_000` is 100%.
//! `BTreeMap` is used for guardrails and observations so replay inputs keep a
//! stable ordering across serialization and comparison.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Fixed-point scale used for fractional rollout metrics.
pub const MILLIONTHS: u32 = 1_000_000;

/// Observation key for error rate in fixed-point millionths.
pub const OBS_ERROR_RATE: &str = "error_rate_millionths";

/// Observation key for latency in milliseconds.
pub const OBS_LATENCY_MS: &str = "latency_ms";

/// Observation key for deterministic replay agreement in fixed-point millionths.
pub const OBS_DETERMINISM: &str = "determinism_millionths";

/// Shadow/canary rollout phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutPhase {
    /// New workload output is observed but not served.
    Shadow,
    /// New workload serves limited traffic.
    Canary,
    /// New workload serves all traffic.
    Active,
    /// Rollout has been stopped by a guardrail breach.
    RolledBack,
}

impl RolloutPhase {
    /// Deterministic key used in guardrail maps and serialized artifacts.
    pub const fn as_key(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Canary => "canary",
            Self::Active => "active",
            Self::RolledBack => "rolled_back",
        }
    }

    /// Next successful rollout phase.
    pub const fn next(self) -> Self {
        match self {
            Self::Shadow => Self::Canary,
            Self::Canary => Self::Active,
            Self::Active => Self::Active,
            Self::RolledBack => Self::RolledBack,
        }
    }
}

/// Per-phase rollout guardrails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseGuardrails {
    /// Maximum acceptable error rate in fixed-point millionths.
    pub max_error_rate: u32,
    /// Maximum acceptable latency in milliseconds.
    pub max_latency_ms: u32,
    /// Whether deterministic replay agreement must be exactly 100%.
    pub determinism_required: bool,
}

impl PhaseGuardrails {
    /// Create guardrails with fixed-point millionths for `max_error_rate`.
    pub const fn new(max_error_rate: u32, max_latency_ms: u32, determinism_required: bool) -> Self {
        Self {
            max_error_rate,
            max_latency_ms,
            determinism_required,
        }
    }
}

/// Guardrail breach that stopped a rollout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreachReason {
    /// Error rate exceeded the phase guardrail or was missing.
    ErrorRate,
    /// Latency exceeded the phase guardrail or was missing.
    Latency,
    /// Determinism was required but not observed at 100%.
    Determinism,
    /// Rollout phase had no configured guardrails and must fail closed.
    MissingGuardrails,
}

/// Deterministic rollout state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutController {
    /// Current rollout phase.
    pub phase: RolloutPhase,
    /// Guardrails keyed by `RolloutPhase::as_key()`.
    pub guardrails: BTreeMap<String, PhaseGuardrails>,
    /// Ordered phase history, including the initial phase.
    pub history: Vec<RolloutPhase>,
}

impl RolloutController {
    /// Create a controller with explicit phase and guardrails.
    pub fn new(phase: RolloutPhase, guardrails: BTreeMap<String, PhaseGuardrails>) -> Self {
        Self {
            phase,
            guardrails,
            history: vec![phase],
        }
    }

    /// Create a controller that starts in shadow mode.
    pub fn shadow(guardrails: BTreeMap<String, PhaseGuardrails>) -> Self {
        Self::new(RolloutPhase::Shadow, guardrails)
    }

    /// Return the current phase.
    pub const fn phase(&self) -> RolloutPhase {
        self.phase
    }

    /// Return true when rollout is serving all traffic.
    pub const fn is_active(&self) -> bool {
        matches!(self.phase, RolloutPhase::Active)
    }

    /// Return true when rollout has been stopped by a breach.
    pub const fn is_rolled_back(&self) -> bool {
        matches!(self.phase, RolloutPhase::RolledBack)
    }

    /// Try to advance the rollout by one phase.
    ///
    /// Missing error-rate or latency observations fail closed. Missing
    /// determinism only fails closed when the current phase requires
    /// deterministic replay agreement.
    pub fn try_advance(&mut self, observed: &BTreeMap<String, u32>) -> Result<(), BreachReason> {
        if self.phase == RolloutPhase::RolledBack {
            return Err(BreachReason::Determinism);
        }

        let Some(guardrails) = self.guardrails_for_current_phase() else {
            self.rollback();
            return Err(BreachReason::MissingGuardrails);
        };
        let error_rate = observed.get(OBS_ERROR_RATE).copied().unwrap_or(u32::MAX);
        if error_rate > guardrails.max_error_rate {
            self.rollback();
            return Err(BreachReason::ErrorRate);
        }

        let latency_ms = observed.get(OBS_LATENCY_MS).copied().unwrap_or(u32::MAX);
        if latency_ms > guardrails.max_latency_ms {
            self.rollback();
            return Err(BreachReason::Latency);
        }

        if guardrails.determinism_required {
            let determinism = observed.get(OBS_DETERMINISM).copied().unwrap_or(0);
            if determinism != MILLIONTHS {
                self.rollback();
                return Err(BreachReason::Determinism);
            }
        }

        let next = self.phase.next();
        if next != self.phase {
            self.phase = next;
            self.history.push(next);
        }
        Ok(())
    }

    fn guardrails_for_current_phase(&self) -> Option<&PhaseGuardrails> {
        self.guardrails.get(self.phase.as_key())
    }

    fn rollback(&mut self) {
        if self.phase != RolloutPhase::RolledBack {
            self.phase = RolloutPhase::RolledBack;
            self.history.push(RolloutPhase::RolledBack);
        }
    }
}

impl Default for RolloutController {
    fn default() -> Self {
        Self::shadow(default_guardrails())
    }
}

/// Default conservative guardrails for shadow/canary/active rollout phases.
pub fn default_guardrails() -> BTreeMap<String, PhaseGuardrails> {
    let mut guardrails = BTreeMap::new();
    guardrails.insert(
        RolloutPhase::Shadow.as_key().to_string(),
        PhaseGuardrails::new(1_000, 250, true),
    );
    guardrails.insert(
        RolloutPhase::Canary.as_key().to_string(),
        PhaseGuardrails::new(500, 200, true),
    );
    guardrails.insert(
        RolloutPhase::Active.as_key().to_string(),
        PhaseGuardrails::new(250, 175, true),
    );
    guardrails
}

/// Build deterministic observation metrics.
pub fn observations(error_rate: u32, latency_ms: u32, determinism: u32) -> BTreeMap<String, u32> {
    let mut observed = BTreeMap::new();
    observed.insert(OBS_DETERMINISM.to_string(), determinism);
    observed.insert(OBS_ERROR_RATE.to_string(), error_rate);
    observed.insert(OBS_LATENCY_MS.to_string(), latency_ms);
    observed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relaxed_guardrails() -> BTreeMap<String, PhaseGuardrails> {
        let mut guardrails = BTreeMap::new();
        guardrails.insert(
            RolloutPhase::Shadow.as_key().to_string(),
            PhaseGuardrails::new(10_000, 1_000, true),
        );
        guardrails.insert(
            RolloutPhase::Canary.as_key().to_string(),
            PhaseGuardrails::new(5_000, 800, true),
        );
        guardrails.insert(
            RolloutPhase::Active.as_key().to_string(),
            PhaseGuardrails::new(2_500, 600, true),
        );
        guardrails
    }

    fn good_observations() -> BTreeMap<String, u32> {
        observations(100, 100, MILLIONTHS)
    }

    #[test]
    fn starts_in_shadow_by_default() {
        let controller = RolloutController::default();
        assert_eq!(controller.phase, RolloutPhase::Shadow);
        assert_eq!(controller.history, vec![RolloutPhase::Shadow]);
    }

    #[test]
    fn shadow_advances_to_canary() {
        let mut controller = RolloutController::shadow(relaxed_guardrails());
        assert_eq!(controller.try_advance(&good_observations()), Ok(()));
        assert_eq!(controller.phase, RolloutPhase::Canary);
    }

    #[test]
    fn canary_advances_to_active() {
        let mut controller = RolloutController::new(RolloutPhase::Canary, relaxed_guardrails());
        assert_eq!(controller.try_advance(&good_observations()), Ok(()));
        assert_eq!(controller.phase, RolloutPhase::Active);
    }

    #[test]
    fn active_is_terminal_on_success() {
        let mut controller = RolloutController::new(RolloutPhase::Active, relaxed_guardrails());
        assert_eq!(controller.try_advance(&good_observations()), Ok(()));
        assert_eq!(controller.phase, RolloutPhase::Active);
        assert_eq!(controller.history, vec![RolloutPhase::Active]);
    }

    #[test]
    fn full_success_path_records_history() {
        let mut controller = RolloutController::shadow(relaxed_guardrails());
        controller
            .try_advance(&good_observations())
            .expect("shadow observations should pass");
        controller
            .try_advance(&good_observations())
            .expect("canary observations should pass");
        assert_eq!(
            controller.history,
            vec![
                RolloutPhase::Shadow,
                RolloutPhase::Canary,
                RolloutPhase::Active
            ]
        );
    }

    #[test]
    fn error_rate_breach_rolls_back() {
        let mut controller = RolloutController::shadow(relaxed_guardrails());
        let observed = observations(20_000, 100, MILLIONTHS);
        assert_eq!(
            controller.try_advance(&observed),
            Err(BreachReason::ErrorRate)
        );
        assert_eq!(controller.phase, RolloutPhase::RolledBack);
    }

    #[test]
    fn latency_breach_rolls_back() {
        let mut controller = RolloutController::shadow(relaxed_guardrails());
        let observed = observations(100, 2_000, MILLIONTHS);
        assert_eq!(
            controller.try_advance(&observed),
            Err(BreachReason::Latency)
        );
        assert_eq!(controller.phase, RolloutPhase::RolledBack);
    }

    #[test]
    fn determinism_breach_rolls_back() {
        let mut controller = RolloutController::shadow(relaxed_guardrails());
        let observed = observations(100, 100, MILLIONTHS - 1);
        assert_eq!(
            controller.try_advance(&observed),
            Err(BreachReason::Determinism)
        );
        assert_eq!(controller.phase, RolloutPhase::RolledBack);
    }

    #[test]
    fn determinism_above_full_score_rolls_back() {
        let mut controller = RolloutController::shadow(relaxed_guardrails());
        let observed = observations(100, 100, MILLIONTHS + 1);
        assert_eq!(
            controller.try_advance(&observed),
            Err(BreachReason::Determinism)
        );
        assert_eq!(controller.phase, RolloutPhase::RolledBack);
    }

    #[test]
    fn rolled_back_controller_does_not_advance() {
        let mut controller = RolloutController::new(RolloutPhase::RolledBack, relaxed_guardrails());
        assert_eq!(
            controller.try_advance(&good_observations()),
            Err(BreachReason::Determinism)
        );
        assert_eq!(controller.phase, RolloutPhase::RolledBack);
    }

    #[test]
    fn missing_error_rate_fails_closed() {
        let mut controller = RolloutController::shadow(relaxed_guardrails());
        let mut observed = good_observations();
        observed.remove(OBS_ERROR_RATE);
        assert_eq!(
            controller.try_advance(&observed),
            Err(BreachReason::ErrorRate)
        );
    }

    #[test]
    fn missing_latency_fails_closed() {
        let mut controller = RolloutController::shadow(relaxed_guardrails());
        let mut observed = good_observations();
        observed.remove(OBS_LATENCY_MS);
        assert_eq!(
            controller.try_advance(&observed),
            Err(BreachReason::Latency)
        );
    }

    #[test]
    fn missing_determinism_fails_when_required() {
        let mut controller = RolloutController::shadow(relaxed_guardrails());
        let mut observed = good_observations();
        observed.remove(OBS_DETERMINISM);
        assert_eq!(
            controller.try_advance(&observed),
            Err(BreachReason::Determinism)
        );
    }

    #[test]
    fn determinism_can_be_optional() {
        let mut guardrails = relaxed_guardrails();
        guardrails.insert(
            RolloutPhase::Shadow.as_key().to_string(),
            PhaseGuardrails::new(10_000, 1_000, false),
        );
        let mut controller = RolloutController::shadow(guardrails);
        let mut observed = good_observations();
        observed.remove(OBS_DETERMINISM);
        assert_eq!(controller.try_advance(&observed), Ok(()));
        assert_eq!(controller.phase, RolloutPhase::Canary);
    }

    #[test]
    fn missing_guardrails_fail_closed() {
        let mut controller = RolloutController::shadow(BTreeMap::new());
        assert_eq!(
            controller.try_advance(&good_observations()),
            Err(BreachReason::MissingGuardrails)
        );
        assert_eq!(controller.phase, RolloutPhase::RolledBack);
    }

    #[test]
    fn missing_guardrails_reject_even_zero_observations() {
        let mut controller = RolloutController::shadow(BTreeMap::new());
        let observed = observations(0, 0, MILLIONTHS);
        assert_eq!(
            controller.try_advance(&observed),
            Err(BreachReason::MissingGuardrails)
        );
        assert_eq!(controller.phase, RolloutPhase::RolledBack);
    }

    #[test]
    fn phase_keys_are_stable() {
        assert_eq!(RolloutPhase::Shadow.as_key(), "shadow");
        assert_eq!(RolloutPhase::Canary.as_key(), "canary");
        assert_eq!(RolloutPhase::Active.as_key(), "active");
        assert_eq!(RolloutPhase::RolledBack.as_key(), "rolled_back");
    }

    #[test]
    fn next_phase_is_stable() {
        assert_eq!(RolloutPhase::Shadow.next(), RolloutPhase::Canary);
        assert_eq!(RolloutPhase::Canary.next(), RolloutPhase::Active);
        assert_eq!(RolloutPhase::Active.next(), RolloutPhase::Active);
        assert_eq!(RolloutPhase::RolledBack.next(), RolloutPhase::RolledBack);
    }

    #[test]
    fn observations_are_deterministically_ordered() {
        let observed = observations(1, 2, 3);
        let keys: Vec<&str> = observed.keys().map(String::as_str).collect();
        assert_eq!(keys, vec![OBS_DETERMINISM, OBS_ERROR_RATE, OBS_LATENCY_MS]);
    }

    #[test]
    fn default_guardrails_are_deterministically_ordered() {
        let guardrails = default_guardrails();
        let keys: Vec<&str> = guardrails.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec![
                RolloutPhase::Active.as_key(),
                RolloutPhase::Canary.as_key(),
                RolloutPhase::Shadow.as_key()
            ]
        );
    }

    #[test]
    fn controller_serializes_with_stable_map_order() {
        let controller = RolloutController::shadow(relaxed_guardrails());
        let json = serde_json::to_string(&controller).expect("controller should serialize");
        let guardrails_pos = json
            .find("\"guardrails\":{")
            .expect("guardrails object should exist");
        let guardrails_json = &json[guardrails_pos..];
        let active_pos = guardrails_json
            .find("\"active\":")
            .expect("active key should exist");
        let canary_pos = guardrails_json
            .find("\"canary\":")
            .expect("canary key should exist");
        let shadow_pos = guardrails_json
            .find("\"shadow\":")
            .expect("shadow key should exist");
        assert!(active_pos < canary_pos);
        assert!(canary_pos < shadow_pos);
    }

    #[test]
    fn controller_roundtrips_through_json() {
        let mut controller = RolloutController::shadow(relaxed_guardrails());
        controller
            .try_advance(&good_observations())
            .expect("shadow observations should pass");
        let json = serde_json::to_string(&controller).expect("controller should serialize");
        let decoded: RolloutController =
            serde_json::from_str(&json).expect("controller should deserialize");
        assert_eq!(decoded, controller);
    }

    #[test]
    fn replaying_same_observations_is_deterministic() {
        let mut left = RolloutController::shadow(relaxed_guardrails());
        let mut right = RolloutController::shadow(relaxed_guardrails());
        let observed = good_observations();
        for _ in 0..3 {
            let left_result = left.try_advance(&observed);
            let right_result = right.try_advance(&observed);
            assert_eq!(left_result, right_result);
            assert_eq!(left, right);
        }
    }

    #[test]
    fn breach_history_is_replayable_after_serializing() {
        let mut controller = RolloutController::shadow(relaxed_guardrails());
        let observed = observations(100, 100, MILLIONTHS - 1);
        let result = controller.try_advance(&observed);
        let json = serde_json::to_string(&controller).expect("controller should serialize");
        let decoded: RolloutController =
            serde_json::from_str(&json).expect("controller should deserialize");
        assert_eq!(result, Err(BreachReason::Determinism));
        assert_eq!(
            decoded.history,
            vec![RolloutPhase::Shadow, RolloutPhase::RolledBack]
        );
    }

    #[test]
    fn canary_uses_canary_guardrails() {
        let mut controller = RolloutController::new(RolloutPhase::Canary, relaxed_guardrails());
        let observed = observations(7_500, 100, MILLIONTHS);
        assert_eq!(
            controller.try_advance(&observed),
            Err(BreachReason::ErrorRate)
        );
    }

    #[test]
    fn active_uses_active_guardrails() {
        let mut controller = RolloutController::new(RolloutPhase::Active, relaxed_guardrails());
        let observed = observations(3_000, 100, MILLIONTHS);
        assert_eq!(
            controller.try_advance(&observed),
            Err(BreachReason::ErrorRate)
        );
    }

    #[test]
    fn phase_guardrails_constructor_preserves_values() {
        let guardrails = PhaseGuardrails::new(42, 900, false);
        assert_eq!(guardrails.max_error_rate, 42);
        assert_eq!(guardrails.max_latency_ms, 900);
        assert!(!guardrails.determinism_required);
    }
}
