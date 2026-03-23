//! PolicyController service for expected-loss-minimizing action selection.
//!
//! A domain-generic controller that selects actions minimizing expected
//! loss under the current posterior while respecting hard guardrail
//! constraints.  Every decision emits a structured evidence entry via
//! the evidence-ledger schema (bd-33h).
//!
//! Plan references: Section 10.11 item 13, 9G.5 (policy controller
//! with expected-loss actions), Top-10 #2 (guardplane), #8 (budgets).

pub mod operator_safety_copilot;
pub mod service_endpoint_template;

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Custom serde for `BTreeMap<(String, String), i64>` as a vec of entries,
/// since JSON requires string keys and tuples cannot be serialized as keys.
mod loss_entries_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Entry {
        state: String,
        action: String,
        loss: i64,
    }

    pub fn serialize<S>(
        entries: &BTreeMap<(String, String), i64>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let vec: Vec<Entry> = entries
            .iter()
            .map(|((state, action), &loss)| Entry {
                state: state.clone(),
                action: action.clone(),
                loss,
            })
            .collect();
        vec.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<(String, String), i64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<Entry> = Vec::deserialize(deserializer)?;
        Ok(vec
            .into_iter()
            .map(|e| ((e.state, e.action), e.loss))
            .collect())
    }
}

use crate::evidence_ledger::{
    CandidateAction, ChosenAction, Constraint, DecisionType, EvidenceEntry, EvidenceEntryBuilder,
    LedgerError,
};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// LossMatrix — (state, action) -> loss mapping
// ---------------------------------------------------------------------------

/// Loss matrix mapping (state, action) pairs to scalar loss values.
///
/// Uses BTreeMap for deterministic iteration.  Loss values are stored
/// as fixed-point millionths for deterministic arithmetic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossMatrix {
    /// Mapping from (state_name, action_name) -> loss_millionths.
    #[serde(with = "loss_entries_serde")]
    entries: BTreeMap<(String, String), i64>,
}

impl LossMatrix {
    /// Create an empty loss matrix.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Set the loss for a (state, action) pair.
    pub fn set(
        &mut self,
        state: impl Into<String>,
        action: impl Into<String>,
        loss_millionths: i64,
    ) {
        self.entries
            .insert((state.into(), action.into()), loss_millionths);
    }

    /// Get the loss for a (state, action) pair.
    pub fn get(&self, state: &str, action: &str) -> Option<i64> {
        self.entries
            .get(&(state.to_string(), action.to_string()))
            .copied()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for LossMatrix {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Posterior — probability distribution over states
// ---------------------------------------------------------------------------

/// Discrete probability distribution over states.
///
/// Probabilities are stored as fixed-point millionths (1_000_000 = 1.0)
/// for deterministic computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Posterior {
    /// Mapping from state_name -> probability_millionths.
    probabilities: BTreeMap<String, i64>,
}

impl Posterior {
    /// Create from a map of state -> probability (millionths).
    pub fn new(probabilities: BTreeMap<String, i64>) -> Self {
        Self { probabilities }
    }

    /// Get probability for a state.
    pub fn probability(&self, state: &str) -> i64 {
        self.probabilities.get(state).copied().unwrap_or(0)
    }

    /// All states in deterministic order.
    pub fn states(&self) -> impl Iterator<Item = &str> {
        self.probabilities.keys().map(String::as_str)
    }
}

// ---------------------------------------------------------------------------
// Guardrail — hard constraint on action selection
// ---------------------------------------------------------------------------

/// A guardrail that can block specific actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Guardrail {
    /// Guardrail identifier.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Actions blocked by this guardrail.
    pub blocked_actions: Vec<String>,
}

impl Guardrail {
    /// Check if this guardrail blocks the given action.
    pub fn blocks(&self, action: &str) -> bool {
        self.blocked_actions.iter().any(|a| a == action)
    }
}

// ---------------------------------------------------------------------------
// ControllerConfig
// ---------------------------------------------------------------------------

/// Configuration for a PolicyController instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerConfig {
    /// Controller identifier.
    pub controller_id: String,
    /// Tuning domain (e.g., "monitoring_intensity", "resource_budget").
    pub domain: String,
    /// Available actions in deterministic order.
    pub action_set: Vec<String>,
    /// Safe default action (used when all actions are guardrail-blocked).
    pub safe_default: String,
    /// Policy identifier for evidence emission.
    pub policy_id: String,
}

// ---------------------------------------------------------------------------
// PolicyControllerError
// ---------------------------------------------------------------------------

/// Errors from policy controller operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyControllerError {
    /// No actions available (action set is empty).
    EmptyActionSet,
    /// Loss matrix has no entries for any action.
    NoLossEntries,
    /// Safe default action is not in the action set.
    SafeDefaultNotInActionSet { safe_default: String },
    /// Evidence emission failed.
    EvidenceEmissionFailed { reason: String },
}

impl fmt::Display for PolicyControllerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyActionSet => write!(f, "action set is empty"),
            Self::NoLossEntries => write!(f, "no loss entries for any action"),
            Self::SafeDefaultNotInActionSet { safe_default } => {
                write!(f, "safe default '{safe_default}' not in action set")
            }
            Self::EvidenceEmissionFailed { reason } => {
                write!(f, "evidence emission failed: {reason}")
            }
        }
    }
}

impl std::error::Error for PolicyControllerError {}

// ---------------------------------------------------------------------------
// ActionSelection — result of a decision
// ---------------------------------------------------------------------------

/// Result of an action selection decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionSelection {
    /// The selected action.
    pub action: String,
    /// Expected loss of the selected action (millionths).
    pub expected_loss: i64,
    /// Whether the selection fell back to the safe default.
    pub is_safe_default: bool,
    /// Actions that were rejected by guardrails.
    pub guardrail_rejections: Vec<(String, String)>,
    /// Decision identifier for evidence correlation.
    pub decision_id: String,
}

// ---------------------------------------------------------------------------
// PolicyController — the decision service
// ---------------------------------------------------------------------------

/// Expected-loss-minimizing policy controller.
///
/// Selects actions from a configured action set that minimize expected
/// loss under the current posterior, subject to guardrail constraints.
#[derive(Debug)]
pub struct PolicyController {
    config: ControllerConfig,
    loss_matrix: LossMatrix,
    guardrails: Vec<Guardrail>,
    decision_count: u64,
    decisions: Vec<ActionSelection>,
}

impl PolicyController {
    /// Create a new controller.
    pub fn new(
        config: ControllerConfig,
        loss_matrix: LossMatrix,
    ) -> Result<Self, PolicyControllerError> {
        if config.action_set.is_empty() {
            return Err(PolicyControllerError::EmptyActionSet);
        }
        if !config.action_set.contains(&config.safe_default) {
            return Err(PolicyControllerError::SafeDefaultNotInActionSet {
                safe_default: config.safe_default.clone(),
            });
        }
        Ok(Self {
            config,
            loss_matrix,
            guardrails: Vec::new(),
            decision_count: 0,
            decisions: Vec::new(),
        })
    }

    /// Add a guardrail.
    pub fn add_guardrail(&mut self, guardrail: Guardrail) {
        self.guardrails.push(guardrail);
    }

    /// Update the loss matrix (e.g., on epoch transition).
    pub fn update_loss_matrix(&mut self, matrix: LossMatrix) {
        self.loss_matrix = matrix;
    }

    /// Compute expected loss for a single action under the posterior.
    ///
    /// `E[L(a)] = sum_s P(s) * L(s, a)`, using fixed-point millionths.
    fn expected_loss(&self, action: &str, posterior: &Posterior) -> i64 {
        let mut total: i64 = 0;
        for state in posterior.states() {
            let prob = posterior.probability(state);
            let loss = self.loss_matrix.get(state, action).unwrap_or(0);
            // Both are in millionths; result in millionths^2, divide by 1M.
            total += (prob as i128 * loss as i128 / 1_000_000) as i64;
        }
        total
    }

    /// Select the best action given the current posterior.
    ///
    /// Returns the action with minimum expected loss that is not blocked
    /// by any guardrail.  Falls back to safe default if all actions blocked.
    pub fn select_action(
        &mut self,
        posterior: &Posterior,
        _epoch: SecurityEpoch,
        _trace_id: &str,
    ) -> Result<ActionSelection, PolicyControllerError> {
        self.decision_count = self.decision_count.saturating_add(1);
        let decision_id = format!("{}-{:06}", self.config.controller_id, self.decision_count);

        // Compute expected loss for each action.
        let mut candidates: Vec<(String, i64, bool, Option<String>)> = Vec::new();
        let mut guardrail_rejections: Vec<(String, String)> = Vec::new();

        for action in &self.config.action_set {
            let el = self.expected_loss(action, posterior);
            let mut blocked = false;
            let mut block_reason = None;

            for gr in &self.guardrails {
                if gr.blocks(action) {
                    blocked = true;
                    block_reason = Some(gr.id.clone());
                    guardrail_rejections.push((action.clone(), gr.id.clone()));
                    break;
                }
            }

            candidates.push((action.clone(), el, blocked, block_reason));
        }

        // Select: minimum expected loss among non-blocked actions.
        let best = candidates
            .iter()
            .filter(|(_, _, blocked, _)| !blocked)
            .min_by_key(|(_, el, _, _)| *el);

        let (action, expected_loss, is_safe_default) = match best {
            Some((action, el, _, _)) => (action.clone(), *el, false),
            None => {
                // All blocked — use safe default.
                let el = self.expected_loss(&self.config.safe_default, posterior);
                (self.config.safe_default.clone(), el, true)
            }
        };

        let selection = ActionSelection {
            action,
            expected_loss,
            is_safe_default,
            guardrail_rejections,
            decision_id,
        };
        self.decisions.push(selection.clone());
        Ok(selection)
    }

    /// Build an evidence entry for a completed action selection.
    pub fn build_evidence(
        &self,
        selection: &ActionSelection,
        posterior: &Posterior,
        epoch: SecurityEpoch,
        trace_id: &str,
    ) -> Result<EvidenceEntry, LedgerError> {
        let mut builder = EvidenceEntryBuilder::new(
            trace_id,
            &selection.decision_id,
            &self.config.policy_id,
            epoch,
            DecisionType::CapabilityDecision,
        );

        // Add candidates.
        for action in &self.config.action_set {
            let el = self.expected_loss(action, posterior);
            let is_rejected = selection
                .guardrail_rejections
                .iter()
                .any(|(a, _)| a == action);

            if is_rejected {
                let reason = selection
                    .guardrail_rejections
                    .iter()
                    .find(|(a, _)| a == action)
                    .map(|(_, r)| format!("blocked by guardrail: {r}"))
                    .unwrap_or_default();
                builder = builder.candidate(CandidateAction::filtered(action, el, reason));
            } else {
                builder = builder.candidate(CandidateAction::new(action, el));
            }
        }

        // Add guardrail constraints.
        for gr in &self.guardrails {
            let active = gr
                .blocked_actions
                .iter()
                .any(|a| self.config.action_set.contains(a));
            builder = builder.constraint(Constraint {
                constraint_id: gr.id.clone(),
                description: gr.description.clone(),
                active,
            });
        }

        // Chosen action.
        let rationale = if selection.is_safe_default {
            "safe default (all actions guardrail-blocked)".to_string()
        } else {
            "minimum expected loss".to_string()
        };
        builder = builder.chosen(ChosenAction {
            action_name: selection.action.clone(),
            expected_loss_millionths: selection.expected_loss,
            rationale,
        });

        builder = builder.meta("controller_id", &self.config.controller_id);
        builder = builder.meta("domain", &self.config.domain);

        builder.build()
    }

    /// Controller configuration.
    pub fn config(&self) -> &ControllerConfig {
        &self.config
    }

    /// Number of decisions made.
    pub fn decision_count(&self) -> u64 {
        self.decision_count
    }

    /// Decision history.
    pub fn decisions(&self) -> &[ActionSelection] {
        &self.decisions
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn monitoring_controller() -> PolicyController {
        let mut matrix = LossMatrix::new();
        // States: "normal", "anomalous"
        // Actions: "low", "medium", "high"
        matrix.set("normal", "low", 100_000); // low cost, normal state
        matrix.set("normal", "medium", 300_000); // medium cost
        matrix.set("normal", "high", 800_000); // high cost, wasted
        matrix.set("anomalous", "low", 5_000_000); // huge missed detection cost
        matrix.set("anomalous", "medium", 1_000_000); // moderate risk
        matrix.set("anomalous", "high", 200_000); // appropriate response

        let config = ControllerConfig {
            controller_id: "mon-ctrl".to_string(),
            domain: "monitoring_intensity".to_string(),
            action_set: vec!["low".to_string(), "medium".to_string(), "high".to_string()],
            safe_default: "high".to_string(),
            policy_id: "policy-v1".to_string(),
        };

        PolicyController::new(config, matrix).expect("create controller")
    }

    fn normal_posterior() -> Posterior {
        let mut probs = BTreeMap::new();
        probs.insert("normal".to_string(), 900_000); // 0.9
        probs.insert("anomalous".to_string(), 100_000); // 0.1
        Posterior::new(probs)
    }

    fn anomalous_posterior() -> Posterior {
        let mut probs = BTreeMap::new();
        probs.insert("normal".to_string(), 200_000); // 0.2
        probs.insert("anomalous".to_string(), 800_000); // 0.8
        Posterior::new(probs)
    }

    // -- LossMatrix --

    #[test]
    fn loss_matrix_get_set() {
        let mut m = LossMatrix::new();
        m.set("s1", "a1", 500);
        assert_eq!(m.get("s1", "a1"), Some(500));
        assert_eq!(m.get("s1", "a2"), None);
        assert_eq!(m.len(), 1);
    }

    // -- Posterior --

    #[test]
    fn posterior_returns_zero_for_unknown_state() {
        let p = Posterior::new(BTreeMap::new());
        assert_eq!(p.probability("unknown"), 0);
    }

    // -- Controller creation --

    #[test]
    fn controller_rejects_empty_action_set() {
        let config = ControllerConfig {
            controller_id: "c".to_string(),
            domain: "d".to_string(),
            action_set: vec![],
            safe_default: "x".to_string(),
            policy_id: "p".to_string(),
        };
        let err = PolicyController::new(config, LossMatrix::new()).unwrap_err();
        assert_eq!(err, PolicyControllerError::EmptyActionSet);
    }

    #[test]
    fn controller_rejects_safe_default_not_in_action_set() {
        let config = ControllerConfig {
            controller_id: "c".to_string(),
            domain: "d".to_string(),
            action_set: vec!["a".to_string()],
            safe_default: "missing".to_string(),
            policy_id: "p".to_string(),
        };
        let err = PolicyController::new(config, LossMatrix::new()).unwrap_err();
        assert!(matches!(
            err,
            PolicyControllerError::SafeDefaultNotInActionSet { .. }
        ));
    }

    // -- Action selection: normal state --

    #[test]
    fn selects_low_monitoring_in_normal_state() {
        let mut ctrl = monitoring_controller();
        let posterior = normal_posterior();
        let sel = ctrl
            .select_action(&posterior, SecurityEpoch::from_raw(1), "trace-1")
            .expect("select");

        // Expected losses (millionths):
        // low:  0.9 * 100_000 + 0.1 * 5_000_000 = 90_000 + 500_000 = 590_000
        // medium: 0.9 * 300_000 + 0.1 * 1_000_000 = 270_000 + 100_000 = 370_000
        // high: 0.9 * 800_000 + 0.1 * 200_000 = 720_000 + 20_000 = 740_000
        // Medium has lowest expected loss.
        assert_eq!(sel.action, "medium");
        assert!(!sel.is_safe_default);
    }

    // -- Action selection: anomalous state --

    #[test]
    fn selects_high_monitoring_in_anomalous_state() {
        let mut ctrl = monitoring_controller();
        let posterior = anomalous_posterior();
        let sel = ctrl
            .select_action(&posterior, SecurityEpoch::from_raw(1), "trace-2")
            .expect("select");

        // Expected losses:
        // low:  0.2 * 100_000 + 0.8 * 5_000_000 = 20_000 + 4_000_000 = 4_020_000
        // medium: 0.2 * 300_000 + 0.8 * 1_000_000 = 60_000 + 800_000 = 860_000
        // high: 0.2 * 800_000 + 0.8 * 200_000 = 160_000 + 160_000 = 320_000
        // High has lowest expected loss.
        assert_eq!(sel.action, "high");
    }

    // -- Guardrail blocking --

    #[test]
    fn guardrail_blocks_best_action_falls_to_next() {
        let mut ctrl = monitoring_controller();
        ctrl.add_guardrail(Guardrail {
            id: "cost-cap".to_string(),
            description: "cost exceeds budget".to_string(),
            blocked_actions: vec!["medium".to_string()],
        });

        let posterior = normal_posterior();
        let sel = ctrl
            .select_action(&posterior, SecurityEpoch::from_raw(1), "trace-3")
            .expect("select");

        // Medium blocked, so should pick next best (low).
        assert_ne!(sel.action, "medium");
        assert!(!sel.guardrail_rejections.is_empty());
    }

    #[test]
    fn all_blocked_falls_to_safe_default() {
        let mut ctrl = monitoring_controller();
        ctrl.add_guardrail(Guardrail {
            id: "block-all".to_string(),
            description: "block everything".to_string(),
            blocked_actions: vec!["low".to_string(), "medium".to_string(), "high".to_string()],
        });

        let posterior = normal_posterior();
        let sel = ctrl
            .select_action(&posterior, SecurityEpoch::from_raw(1), "trace-4")
            .expect("select");

        assert_eq!(sel.action, "high"); // safe default
        assert!(sel.is_safe_default);
    }

    // -- Deterministic selection --

    #[test]
    fn selection_is_deterministic() {
        let mut ctrl1 = monitoring_controller();
        let mut ctrl2 = monitoring_controller();
        let posterior = normal_posterior();
        let epoch = SecurityEpoch::from_raw(1);

        let s1 = ctrl1.select_action(&posterior, epoch, "t1").expect("s1");
        let s2 = ctrl2.select_action(&posterior, epoch, "t1").expect("s2");
        assert_eq!(s1.action, s2.action);
        assert_eq!(s1.expected_loss, s2.expected_loss);
    }

    // -- Evidence emission --

    #[test]
    fn evidence_entry_is_valid() {
        let mut ctrl = monitoring_controller();
        let posterior = normal_posterior();
        let epoch = SecurityEpoch::from_raw(1);

        let sel = ctrl
            .select_action(&posterior, epoch, "trace-ev")
            .expect("select");
        let entry = ctrl
            .build_evidence(&sel, &posterior, epoch, "trace-ev")
            .expect("evidence");

        assert_eq!(entry.decision_type, DecisionType::CapabilityDecision);
        assert_eq!(entry.candidates.len(), 3);
        assert_eq!(entry.chosen_action.action_name, sel.action);
        assert_eq!(entry.metadata["controller_id"], "mon-ctrl");
        assert_eq!(entry.metadata["domain"], "monitoring_intensity");
    }

    #[test]
    fn evidence_includes_guardrail_rejections() {
        let mut ctrl = monitoring_controller();
        ctrl.add_guardrail(Guardrail {
            id: "cost-cap".to_string(),
            description: "cost limit".to_string(),
            blocked_actions: vec!["medium".to_string()],
        });

        let posterior = normal_posterior();
        let epoch = SecurityEpoch::from_raw(1);
        let sel = ctrl.select_action(&posterior, epoch, "t").expect("select");
        let entry = ctrl
            .build_evidence(&sel, &posterior, epoch, "t")
            .expect("evidence");

        // Should have a filtered candidate for "medium".
        let medium = entry
            .candidates
            .iter()
            .find(|c| c.action_name == "medium")
            .expect("medium candidate");
        assert!(medium.filtered);
    }

    // -- Decision tracking --

    #[test]
    fn decision_count_increments() {
        let mut ctrl = monitoring_controller();
        let posterior = normal_posterior();
        let epoch = SecurityEpoch::from_raw(1);

        assert_eq!(ctrl.decision_count(), 0);
        ctrl.select_action(&posterior, epoch, "t1").unwrap();
        assert_eq!(ctrl.decision_count(), 1);
        ctrl.select_action(&posterior, epoch, "t2").unwrap();
        assert_eq!(ctrl.decision_count(), 2);
        assert_eq!(ctrl.decisions().len(), 2);
    }

    // -- Loss matrix update --

    #[test]
    fn updated_loss_matrix_changes_selection() {
        let mut ctrl = monitoring_controller();
        let posterior = normal_posterior();
        let epoch = SecurityEpoch::from_raw(1);

        let sel1 = ctrl.select_action(&posterior, epoch, "t1").expect("s1");

        // Update matrix to make "high" always cheapest.
        let mut new_matrix = LossMatrix::new();
        new_matrix.set("normal", "low", 999_000);
        new_matrix.set("normal", "medium", 999_000);
        new_matrix.set("normal", "high", 1_000);
        new_matrix.set("anomalous", "low", 999_000);
        new_matrix.set("anomalous", "medium", 999_000);
        new_matrix.set("anomalous", "high", 1_000);
        ctrl.update_loss_matrix(new_matrix);

        let sel2 = ctrl.select_action(&posterior, epoch, "t2").expect("s2");
        assert_eq!(sel2.action, "high");
        assert_ne!(sel1.action, sel2.action);
    }

    // -- Error display --

    #[test]
    fn error_display() {
        assert_eq!(
            PolicyControllerError::EmptyActionSet.to_string(),
            "action set is empty"
        );
        assert_eq!(
            PolicyControllerError::SafeDefaultNotInActionSet {
                safe_default: "x".to_string()
            }
            .to_string(),
            "safe default 'x' not in action set"
        );
    }

    // -- Serialization --

    #[test]
    fn loss_matrix_serialization_round_trip() {
        let mut m = LossMatrix::new();
        m.set("s1", "a1", 100);
        m.set("s2", "a2", 200);
        let json = serde_json::to_string(&m).expect("serialize");
        let restored: LossMatrix = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(m, restored);
    }

    #[test]
    fn action_selection_serialization_round_trip() {
        let sel = ActionSelection {
            action: "medium".to_string(),
            expected_loss: 370_000,
            is_safe_default: false,
            guardrail_rejections: vec![("low".to_string(), "cost-cap".to_string())],
            decision_id: "mon-ctrl-000001".to_string(),
        };
        let json = serde_json::to_string(&sel).expect("serialize");
        let restored: ActionSelection = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(sel, restored);
    }

    #[test]
    fn controller_config_serialization_round_trip() {
        let config = ControllerConfig {
            controller_id: "mon-ctrl".to_string(),
            domain: "monitoring".to_string(),
            action_set: vec!["low".to_string(), "high".to_string()],
            safe_default: "high".to_string(),
            policy_id: "p-1".to_string(),
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: ControllerConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
    }

    #[test]
    fn error_serialization_round_trip() {
        let errors = vec![
            PolicyControllerError::EmptyActionSet,
            PolicyControllerError::NoLossEntries,
            PolicyControllerError::SafeDefaultNotInActionSet {
                safe_default: "x".to_string(),
            },
            PolicyControllerError::EvidenceEmissionFailed {
                reason: "test".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: PolicyControllerError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -- Enrichment: serde roundtrips --

    #[test]
    fn guardrail_serde_roundtrip() {
        let g = Guardrail {
            id: "cost-cap".to_string(),
            description: "limits spending".to_string(),
            blocked_actions: vec!["expensive".to_string(), "risky".to_string()],
        };
        let json = serde_json::to_string(&g).expect("serialize");
        let restored: Guardrail = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(g, restored);
    }

    #[test]
    fn posterior_serde_roundtrip() {
        let p = normal_posterior();
        let json = serde_json::to_string(&p).expect("serialize");
        let restored: Posterior = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, restored);
    }

    // -- Enrichment: defaults --

    #[test]
    fn loss_matrix_default_is_empty() {
        let m = LossMatrix::default();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    // -- Enrichment: error Display --

    #[test]
    fn error_display_no_loss_entries() {
        let e = PolicyControllerError::NoLossEntries;
        assert_eq!(e.to_string(), "no loss entries for any action");
    }

    #[test]
    fn error_display_evidence_emission_failed() {
        let e = PolicyControllerError::EvidenceEmissionFailed {
            reason: "ledger full".to_string(),
        };
        assert!(e.to_string().contains("ledger full"));
    }

    #[test]
    fn error_is_std_error() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(PolicyControllerError::EmptyActionSet),
            Box::new(PolicyControllerError::NoLossEntries),
            Box::new(PolicyControllerError::SafeDefaultNotInActionSet {
                safe_default: "x".to_string(),
            }),
            Box::new(PolicyControllerError::EvidenceEmissionFailed {
                reason: "r".to_string(),
            }),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }

    // -- Enrichment: guardrail behavior --

    #[test]
    fn guardrail_blocks_matching_action() {
        let g = Guardrail {
            id: "g1".to_string(),
            description: "d".to_string(),
            blocked_actions: vec!["a".to_string(), "b".to_string()],
        };
        assert!(g.blocks("a"));
        assert!(g.blocks("b"));
        assert!(!g.blocks("c"));
    }

    // -- Enrichment: posterior --

    #[test]
    fn posterior_states_deterministic_order() {
        let mut probs = BTreeMap::new();
        probs.insert("z_state".to_string(), 100_000);
        probs.insert("a_state".to_string(), 900_000);
        let p = Posterior::new(probs);
        let states: Vec<&str> = p.states().collect();
        assert_eq!(states, vec!["a_state", "z_state"]);
    }

    // -- Enrichment: loss matrix --

    #[test]
    fn loss_matrix_overwrite_entry() {
        let mut m = LossMatrix::new();
        m.set("s1", "a1", 100);
        m.set("s1", "a1", 200);
        assert_eq!(m.get("s1", "a1"), Some(200));
        assert_eq!(m.len(), 1);
    }

    // ── Enrichment: controller initialization ────────────────────

    #[test]
    fn controller_valid_init_starts_at_zero_decisions() {
        let ctrl = monitoring_controller();
        assert_eq!(ctrl.decision_count(), 0);
        assert!(ctrl.decisions().is_empty());
    }

    #[test]
    fn controller_config_accessor() {
        let ctrl = monitoring_controller();
        assert_eq!(ctrl.config().controller_id, "mon-ctrl");
        assert_eq!(ctrl.config().domain, "monitoring_intensity");
        assert_eq!(ctrl.config().safe_default, "high");
    }

    // ── Enrichment: posterior ────────────────────────────────────

    #[test]
    fn posterior_known_state_returns_probability() {
        let p = normal_posterior();
        assert_eq!(p.probability("normal"), 900_000);
        assert_eq!(p.probability("anomalous"), 100_000);
    }

    #[test]
    fn posterior_states_returns_all_states() {
        let p = normal_posterior();
        let states: Vec<&str> = p.states().collect();
        assert_eq!(states.len(), 2);
        assert!(states.contains(&"normal"));
        assert!(states.contains(&"anomalous"));
    }

    #[test]
    fn posterior_empty_has_no_states() {
        let p = Posterior::new(BTreeMap::new());
        assert_eq!(p.states().count(), 0);
    }

    // ── Enrichment: loss matrix ──────────────────────────────────

    #[test]
    fn loss_matrix_multiple_entries() {
        let mut m = LossMatrix::new();
        m.set("s1", "a1", 100);
        m.set("s1", "a2", 200);
        m.set("s2", "a1", 300);
        assert_eq!(m.len(), 3);
        assert_eq!(m.get("s2", "a1"), Some(300));
        assert_eq!(m.get("s2", "a2"), None);
    }

    #[test]
    fn loss_matrix_negative_loss() {
        let mut m = LossMatrix::new();
        m.set("s", "a", -500_000);
        assert_eq!(m.get("s", "a"), Some(-500_000));
    }

    // ── Enrichment: guardrail ────────────────────────────────────

    #[test]
    fn guardrail_empty_blocked_actions_blocks_nothing() {
        let g = Guardrail {
            id: "g".to_string(),
            description: "d".to_string(),
            blocked_actions: vec![],
        };
        assert!(!g.blocks("any"));
    }

    // ── Enrichment: action selection ─────────────────────────────

    #[test]
    fn selection_expected_loss_value() {
        let mut ctrl = monitoring_controller();
        let posterior = normal_posterior();
        let sel = ctrl
            .select_action(&posterior, SecurityEpoch::from_raw(1), "t")
            .unwrap();
        // medium: 0.9*300k + 0.1*1M = 270k + 100k = 370k
        assert_eq!(sel.expected_loss, 370_000);
    }

    #[test]
    fn selection_decision_id_format() {
        let mut ctrl = monitoring_controller();
        let posterior = normal_posterior();
        let sel = ctrl
            .select_action(&posterior, SecurityEpoch::from_raw(1), "t")
            .unwrap();
        assert_eq!(sel.decision_id, "mon-ctrl-000001");
    }

    #[test]
    fn selection_decision_id_increments() {
        let mut ctrl = monitoring_controller();
        let posterior = normal_posterior();
        let epoch = SecurityEpoch::from_raw(1);
        let s1 = ctrl.select_action(&posterior, epoch, "t1").unwrap();
        let s2 = ctrl.select_action(&posterior, epoch, "t2").unwrap();
        assert_eq!(s1.decision_id, "mon-ctrl-000001");
        assert_eq!(s2.decision_id, "mon-ctrl-000002");
    }

    #[test]
    fn decisions_history_matches_selections() {
        let mut ctrl = monitoring_controller();
        let posterior = normal_posterior();
        let epoch = SecurityEpoch::from_raw(1);
        let s1 = ctrl.select_action(&posterior, epoch, "t1").unwrap();
        let s2 = ctrl.select_action(&posterior, epoch, "t2").unwrap();
        let history = ctrl.decisions();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0], s1);
        assert_eq!(history[1], s2);
    }

    // ── Enrichment: multiple guardrails ──────────────────────────

    #[test]
    fn multiple_guardrails_accumulate_rejections() {
        let mut ctrl = monitoring_controller();
        ctrl.add_guardrail(Guardrail {
            id: "g1".to_string(),
            description: "d1".to_string(),
            blocked_actions: vec!["low".to_string()],
        });
        ctrl.add_guardrail(Guardrail {
            id: "g2".to_string(),
            description: "d2".to_string(),
            blocked_actions: vec!["medium".to_string()],
        });
        let posterior = normal_posterior();
        let sel = ctrl
            .select_action(&posterior, SecurityEpoch::from_raw(1), "t")
            .unwrap();
        // Both low and medium blocked, only high left
        assert_eq!(sel.action, "high");
        assert!(!sel.is_safe_default);
        assert_eq!(sel.guardrail_rejections.len(), 2);
    }

    // ── Enrichment: evidence constraints ─────────────────────────

    #[test]
    fn evidence_constraints_match_guardrails() {
        let mut ctrl = monitoring_controller();
        ctrl.add_guardrail(Guardrail {
            id: "g1".to_string(),
            description: "blocks low".to_string(),
            blocked_actions: vec!["low".to_string()],
        });
        let posterior = normal_posterior();
        let epoch = SecurityEpoch::from_raw(1);
        let sel = ctrl.select_action(&posterior, epoch, "t").unwrap();
        let entry = ctrl.build_evidence(&sel, &posterior, epoch, "t").unwrap();
        assert_eq!(entry.constraints.len(), 1);
        assert_eq!(entry.constraints[0].constraint_id, "g1");
        assert!(entry.constraints[0].active);
    }

    #[test]
    fn evidence_safe_default_rationale() {
        let mut ctrl = monitoring_controller();
        ctrl.add_guardrail(Guardrail {
            id: "block-all".to_string(),
            description: "block everything".to_string(),
            blocked_actions: vec!["low".to_string(), "medium".to_string(), "high".to_string()],
        });
        let posterior = normal_posterior();
        let epoch = SecurityEpoch::from_raw(1);
        let sel = ctrl.select_action(&posterior, epoch, "t").unwrap();
        let entry = ctrl.build_evidence(&sel, &posterior, epoch, "t").unwrap();
        assert!(entry.chosen_action.rationale.contains("safe default"));
    }

    #[test]
    fn evidence_normal_selection_rationale() {
        let mut ctrl = monitoring_controller();
        let posterior = normal_posterior();
        let epoch = SecurityEpoch::from_raw(1);
        let sel = ctrl.select_action(&posterior, epoch, "t").unwrap();
        let entry = ctrl.build_evidence(&sel, &posterior, epoch, "t").unwrap();
        assert!(
            entry
                .chosen_action
                .rationale
                .contains("minimum expected loss")
        );
    }

    // ── Enrichment: update_loss_matrix ───────────────────────────

    #[test]
    fn update_loss_matrix_replaces_completely() {
        let mut ctrl = monitoring_controller();
        let mut new_matrix = LossMatrix::new();
        new_matrix.set("s", "low", 1);
        ctrl.update_loss_matrix(new_matrix);
        // Old entries are gone — expected loss for "medium" in state "normal" should be 0
        let mut probs = BTreeMap::new();
        probs.insert("normal".to_string(), 1_000_000);
        let p = Posterior::new(probs);
        let sel = ctrl
            .select_action(&p, SecurityEpoch::from_raw(1), "t")
            .unwrap();
        // All actions have 0 expected loss except if they have entries in new matrix
        // "low" has loss 1 for state "s" which isn't in posterior, so all are 0
        // Ties go to first in action_set order (deterministic)
        assert_eq!(sel.expected_loss, 0);
    }

    // ── Enrichment batch 2: edge cases & boundary conditions ────

    #[test]
    fn empty_posterior_gives_zero_expected_loss() {
        let mut ctrl = monitoring_controller();
        let posterior = Posterior::new(BTreeMap::new());
        let sel = ctrl
            .select_action(&posterior, SecurityEpoch::from_raw(1), "t")
            .unwrap();
        assert_eq!(sel.expected_loss, 0);
        // With zero expected loss for all, picks first in action_set order
        assert_eq!(sel.action, "low");
    }

    #[test]
    fn uniform_posterior_selects_minimum_combined_loss() {
        let mut ctrl = monitoring_controller();
        let mut probs = BTreeMap::new();
        probs.insert("normal".to_string(), 500_000); // 0.5
        probs.insert("anomalous".to_string(), 500_000); // 0.5
        let posterior = Posterior::new(probs);
        let sel = ctrl
            .select_action(&posterior, SecurityEpoch::from_raw(1), "t")
            .unwrap();
        // low:  0.5*100k + 0.5*5M = 50k + 2500k = 2550k
        // med:  0.5*300k + 0.5*1M = 150k + 500k = 650k
        // high: 0.5*800k + 0.5*200k = 400k + 100k = 500k
        assert_eq!(sel.action, "high");
        assert_eq!(sel.expected_loss, 500_000);
    }

    #[test]
    fn single_action_set_always_selected() {
        let matrix = LossMatrix::new();
        let config = ControllerConfig {
            controller_id: "c".to_string(),
            domain: "d".to_string(),
            action_set: vec!["only".to_string()],
            safe_default: "only".to_string(),
            policy_id: "p".to_string(),
        };
        let mut ctrl = PolicyController::new(config, matrix).unwrap();
        let posterior = normal_posterior();
        let sel = ctrl
            .select_action(&posterior, SecurityEpoch::from_raw(1), "t")
            .unwrap();
        assert_eq!(sel.action, "only");
        assert!(!sel.is_safe_default);
    }

    #[test]
    fn decision_id_wraps_correctly_after_many_decisions() {
        let mut ctrl = monitoring_controller();
        let posterior = normal_posterior();
        let epoch = SecurityEpoch::from_raw(1);
        for _ in 0..999_999 {
            ctrl.select_action(&posterior, epoch, "t").unwrap();
        }
        let sel = ctrl.select_action(&posterior, epoch, "t").unwrap();
        assert_eq!(sel.decision_id, "mon-ctrl-1000000");
        assert_eq!(ctrl.decision_count(), 1_000_000);
    }

    #[test]
    fn guardrail_blocking_safe_default_still_falls_through() {
        let mut ctrl = monitoring_controller();
        // Block only the safe default ("high")
        ctrl.add_guardrail(Guardrail {
            id: "block-default".to_string(),
            description: "blocks the safe default".to_string(),
            blocked_actions: vec!["high".to_string()],
        });
        let posterior = anomalous_posterior();
        let sel = ctrl
            .select_action(&posterior, SecurityEpoch::from_raw(1), "t")
            .unwrap();
        // "high" blocked, so picks next best among "low" and "medium"
        // medium: 0.2*300k + 0.8*1M = 60k + 800k = 860k
        // low:    0.2*100k + 0.8*5M = 20k + 4000k = 4020k
        assert_eq!(sel.action, "medium");
        assert!(!sel.is_safe_default);
    }

    #[test]
    fn evidence_entry_candidate_count_matches_action_set() {
        let mut ctrl = monitoring_controller();
        let posterior = normal_posterior();
        let epoch = SecurityEpoch::from_raw(1);
        let sel = ctrl.select_action(&posterior, epoch, "t").unwrap();
        let entry = ctrl.build_evidence(&sel, &posterior, epoch, "t").unwrap();
        assert_eq!(entry.candidates.len(), ctrl.config().action_set.len());
    }

    #[test]
    fn negative_loss_values_produce_correct_selection() {
        let mut matrix = LossMatrix::new();
        matrix.set("s", "good", -500_000); // reward
        matrix.set("s", "bad", 500_000); // cost
        let config = ControllerConfig {
            controller_id: "c".to_string(),
            domain: "d".to_string(),
            action_set: vec!["bad".to_string(), "good".to_string()],
            safe_default: "bad".to_string(),
            policy_id: "p".to_string(),
        };
        let mut ctrl = PolicyController::new(config, matrix).unwrap();
        let mut probs = BTreeMap::new();
        probs.insert("s".to_string(), 1_000_000);
        let posterior = Posterior::new(probs);
        let sel = ctrl
            .select_action(&posterior, SecurityEpoch::from_raw(1), "t")
            .unwrap();
        assert_eq!(sel.action, "good");
        assert_eq!(sel.expected_loss, -500_000);
    }

    #[test]
    fn evidence_guardrail_inactive_when_no_overlap() {
        let mut ctrl = monitoring_controller();
        ctrl.add_guardrail(Guardrail {
            id: "irrelevant".to_string(),
            description: "blocks nothing in action set".to_string(),
            blocked_actions: vec!["nonexistent".to_string()],
        });
        let posterior = normal_posterior();
        let epoch = SecurityEpoch::from_raw(1);
        let sel = ctrl.select_action(&posterior, epoch, "t").unwrap();
        let entry = ctrl.build_evidence(&sel, &posterior, epoch, "t").unwrap();
        // Guardrail should be present but inactive
        assert_eq!(entry.constraints.len(), 1);
        assert!(!entry.constraints[0].active);
    }

    #[test]
    fn tied_expected_loss_deterministic_winner() {
        let mut matrix = LossMatrix::new();
        matrix.set("s", "alpha", 100_000);
        matrix.set("s", "beta", 100_000);
        let config = ControllerConfig {
            controller_id: "c".to_string(),
            domain: "d".to_string(),
            action_set: vec!["alpha".to_string(), "beta".to_string()],
            safe_default: "alpha".to_string(),
            policy_id: "p".to_string(),
        };
        let mut ctrl = PolicyController::new(config, matrix).unwrap();
        let mut probs = BTreeMap::new();
        probs.insert("s".to_string(), 1_000_000);
        let posterior = Posterior::new(probs);
        let sel1 = ctrl
            .select_action(&posterior, SecurityEpoch::from_raw(1), "t1")
            .unwrap();
        // min_by_key picks first minimum — deterministic
        let mut ctrl2 = {
            let mut m = LossMatrix::new();
            m.set("s", "alpha", 100_000);
            m.set("s", "beta", 100_000);
            let c = ControllerConfig {
                controller_id: "c".to_string(),
                domain: "d".to_string(),
                action_set: vec!["alpha".to_string(), "beta".to_string()],
                safe_default: "alpha".to_string(),
                policy_id: "p".to_string(),
            };
            PolicyController::new(c, m).unwrap()
        };
        let sel2 = ctrl2
            .select_action(&posterior, SecurityEpoch::from_raw(1), "t1")
            .unwrap();
        assert_eq!(sel1.action, sel2.action);
    }

    #[test]
    fn loss_matrix_zero_values() {
        let mut m = LossMatrix::new();
        m.set("s", "a", 0);
        assert_eq!(m.get("s", "a"), Some(0));
    }

    #[test]
    fn posterior_single_state_full_probability() {
        let mut probs = BTreeMap::new();
        probs.insert("only".to_string(), 1_000_000);
        let p = Posterior::new(probs);
        assert_eq!(p.probability("only"), 1_000_000);
        assert_eq!(p.states().count(), 1);
    }

    // -- Enrichment batch 3: serde, clone, display, error paths, determinism --

    #[test]
    fn posterior_normal_serde_roundtrip() {
        let p = normal_posterior();
        let json = serde_json::to_string(&p).unwrap();
        let back: Posterior = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn loss_matrix_multi_entry_serde_roundtrip() {
        let mut m = LossMatrix::new();
        m.set("normal", "low", 100_000);
        m.set("anomalous", "high", 200_000);
        let json = serde_json::to_string(&m).unwrap();
        let back: LossMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn controller_config_serde_roundtrip() {
        let ctrl = monitoring_controller();
        let config = ctrl.config().clone();
        let json = serde_json::to_string(&config).unwrap();
        let back: ControllerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn selection_serde_roundtrip() {
        let mut ctrl = monitoring_controller();
        let posterior = normal_posterior();
        let sel = ctrl
            .select_action(&posterior, SecurityEpoch::from_raw(1), "t")
            .unwrap();
        let json = serde_json::to_string(&sel).unwrap();
        let back: ActionSelection = serde_json::from_str(&json).unwrap();
        assert_eq!(sel, back);
    }

    #[test]
    fn guardrail_with_blocked_actions_serde_roundtrip() {
        let g = Guardrail {
            id: "g1".to_string(),
            description: "desc".to_string(),
            blocked_actions: vec!["a".to_string(), "b".to_string()],
        };
        let json = serde_json::to_string(&g).unwrap();
        let back: Guardrail = serde_json::from_str(&json).unwrap();
        assert_eq!(g, back);
    }

    #[test]
    fn posterior_unknown_state_returns_zero() {
        let p = normal_posterior();
        assert_eq!(p.probability("nonexistent"), 0);
    }

    #[test]
    fn loss_matrix_get_missing_returns_none() {
        let m = LossMatrix::new();
        assert_eq!(m.get("missing_state", "missing_action"), None);
    }

    #[test]
    fn loss_matrix_empty_len_zero() {
        let m = LossMatrix::new();
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn controller_safe_default_when_all_blocked() {
        let mut ctrl = monitoring_controller();
        ctrl.add_guardrail(Guardrail {
            id: "block-all".to_string(),
            description: "blocks all actions".to_string(),
            blocked_actions: vec!["low".to_string(), "medium".to_string(), "high".to_string()],
        });
        let posterior = normal_posterior();
        let sel = ctrl
            .select_action(&posterior, SecurityEpoch::from_raw(1), "t")
            .unwrap();
        assert!(sel.is_safe_default);
        assert_eq!(sel.action, "high"); // safe_default
    }

    #[test]
    fn selection_clone_equality() {
        let mut ctrl = monitoring_controller();
        let posterior = normal_posterior();
        let sel = ctrl
            .select_action(&posterior, SecurityEpoch::from_raw(1), "t")
            .unwrap();
        let cloned = sel.clone();
        assert_eq!(sel, cloned);
    }

    #[test]
    fn controller_decisions_deterministic_across_runs() {
        let run = || {
            let mut ctrl = monitoring_controller();
            let posterior = normal_posterior();
            let epoch = SecurityEpoch::from_raw(1);
            for i in 0..5 {
                ctrl.select_action(&posterior, epoch, &format!("t{i}"))
                    .unwrap();
            }
            ctrl.decisions().to_vec()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn anomalous_posterior_selects_high() {
        let mut ctrl = monitoring_controller();
        let posterior = anomalous_posterior();
        let sel = ctrl
            .select_action(&posterior, SecurityEpoch::from_raw(1), "t")
            .unwrap();
        // high: 0.2*800k + 0.8*200k = 160k + 160k = 320k  (lowest)
        // medium: 0.2*300k + 0.8*1M = 60k + 800k = 860k
        // low: 0.2*100k + 0.8*5M = 20k + 4M = 4020k
        assert_eq!(sel.action, "high");
        assert_eq!(sel.expected_loss, 320_000);
    }

    #[test]
    fn guardrail_rejection_tuple_serde() {
        // Guardrail rejections are stored as Vec<(action, guardrail_id)>
        let rejections: Vec<(String, String)> = vec![("low".to_string(), "cost-cap".to_string())];
        let json = serde_json::to_string(&rejections).unwrap();
        let back: Vec<(String, String)> = serde_json::from_str(&json).unwrap();
        assert_eq!(rejections, back);
    }

    #[test]
    fn evidence_entry_has_chosen_action() {
        let mut ctrl = monitoring_controller();
        let posterior = normal_posterior();
        let epoch = SecurityEpoch::from_raw(1);
        let sel = ctrl.select_action(&posterior, epoch, "t").unwrap();
        let entry = ctrl.build_evidence(&sel, &posterior, epoch, "t").unwrap();
        assert!(!entry.chosen_action.action_name.is_empty());
        assert!(entry.chosen_action.expected_loss_millionths >= 0);
    }
}
