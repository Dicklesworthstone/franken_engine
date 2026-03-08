//! Route high-impact safety actions through `franken-decision` contracts.
//!
//! Every high-impact safety action in the extension-host subsystem must
//! be evaluated by a decision contract before execution.  The router
//! computes expected losses, applies fallback policies when model
//! confidence degrades, and emits evidence entries for every decision.
//!
//! # High-impact action taxonomy
//!
//! | Action                  | Default-deny rationale                     |
//! |-------------------------|--------------------------------------------|
//! | `ExtensionQuarantine`   | Isolates extension; false-allow risks leak |
//! | `CapabilityRevocation`  | Removes live permission mid-session        |
//! | `ForcedTermination`     | Kills extension; data loss possible        |
//! | `PrivilegeEscalation`   | Grants elevated permissions                |
//! | `CrossExtensionShare`   | One extension reads another's state        |
//! | `BudgetOverride`        | Extends resource limits beyond default     |
//!
//! Plan references: Section 10.13 item 9, bd-3a5e.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::control_plane::{
    ContextAdapter, DecisionContract, DecisionId, DecisionOutcome, EvalContext, EvidenceLedger,
    FallbackPolicy, LossMatrix, PolicyId, Posterior,
};

// ---------------------------------------------------------------------------
// High-impact action taxonomy
// ---------------------------------------------------------------------------

/// High-impact safety actions that require decision-contract evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SafetyAction {
    /// Isolate an extension in quarantine.
    ExtensionQuarantine,
    /// Revoke a granted capability mid-session.
    CapabilityRevocation,
    /// Forcibly terminate an extension.
    ForcedTermination,
    /// Grant elevated permissions to an extension.
    PrivilegeEscalation,
    /// Allow one extension to access another's state.
    CrossExtensionShare,
    /// Extend resource limits beyond the default budget.
    BudgetOverride,
}

impl SafetyAction {
    /// Stable string identifier for structured logging.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExtensionQuarantine => "extension_quarantine",
            Self::CapabilityRevocation => "capability_revocation",
            Self::ForcedTermination => "forced_termination",
            Self::PrivilegeEscalation => "privilege_escalation",
            Self::CrossExtensionShare => "cross_extension_share",
            Self::BudgetOverride => "budget_override",
        }
    }

    /// All safety actions in taxonomy order.
    pub fn all() -> &'static [SafetyAction] {
        &[
            Self::ExtensionQuarantine,
            Self::CapabilityRevocation,
            Self::ForcedTermination,
            Self::PrivilegeEscalation,
            Self::CrossExtensionShare,
            Self::BudgetOverride,
        ]
    }

    /// Default fallback verdict when decision evaluation fails.
    /// All high-impact actions default to deny.
    pub fn default_fallback(self) -> SafetyVerdict {
        SafetyVerdict::Deny {
            reason: format!("default-deny for {}", self.as_str()),
        }
    }
}

impl fmt::Display for SafetyAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Safety verdict
// ---------------------------------------------------------------------------

/// Verdict from a safety-action decision evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyVerdict {
    /// The action is allowed.
    Allow,
    /// The action is denied with reason.
    Deny { reason: String },
    /// The action triggered fallback (model confidence degraded).
    Fallback { reason: String },
}

impl SafetyVerdict {
    /// Whether the verdict permits execution.
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Stable string for structured logging.
    pub fn outcome_str(&self) -> &str {
        match self {
            Self::Allow => "allow",
            Self::Deny { .. } => "deny",
            Self::Fallback { .. } => "fallback",
        }
    }
}

impl fmt::Display for SafetyVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny { reason } => write!(f, "deny: {reason}"),
            Self::Fallback { reason } => write!(f, "fallback: {reason}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Safety decision request
// ---------------------------------------------------------------------------

/// Request to evaluate a high-impact safety action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SafetyDecisionRequest {
    /// The high-impact action being requested.
    pub action: SafetyAction,
    /// Extension that is the subject of the action.
    pub extension_id: String,
    /// Optional target extension (for cross-extension actions).
    pub target_extension_id: Option<String>,
    /// Decision identifier for audit linkage.
    pub decision_id: DecisionId,
    /// Policy governing this action.
    pub policy_id: PolicyId,
    /// Timestamp in milliseconds.
    pub ts_unix_ms: u64,
    /// Current calibration score (0.0–1.0).
    pub calibration_score_bps: u16,
    /// Current e-process statistic (millionths).
    pub e_process_milli: u32,
    /// Current confidence interval width (millionths).
    pub ci_width_milli: u32,
}

impl SafetyDecisionRequest {
    #[allow(clippy::cast_precision_loss)]
    fn calibration_score(&self) -> f64 {
        f64::from(self.calibration_score_bps) / 10_000.0
    }

    #[allow(clippy::cast_precision_loss)]
    fn e_process(&self) -> f64 {
        f64::from(self.e_process_milli) / 1_000.0
    }

    #[allow(clippy::cast_precision_loss)]
    fn ci_width(&self) -> f64 {
        f64::from(self.ci_width_milli) / 1_000.0
    }
}

// ---------------------------------------------------------------------------
// Safety decision result
// ---------------------------------------------------------------------------

/// Result of evaluating a safety action through the decision router.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SafetyDecisionResult {
    /// The action that was evaluated.
    pub action: SafetyAction,
    /// The verdict.
    pub verdict: SafetyVerdict,
    /// Extension subject.
    pub extension_id: String,
    /// Trace identity from Cx.
    pub trace_id: String,
    /// Decision identity for audit linkage.
    pub decision_id: String,
    /// Policy identity.
    pub policy_id: String,
    /// Expected loss of the chosen action.
    pub expected_loss_milli: u64,
    /// Whether fallback was activated.
    pub fallback_active: bool,
    /// Budget consumed by this evaluation (ms).
    pub budget_consumed_ms: u64,
    /// Sequence number within the router.
    pub sequence_number: u64,
}

// ---------------------------------------------------------------------------
// Router errors
// ---------------------------------------------------------------------------

/// Errors from safety decision routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyRouterError {
    /// Budget exhausted before evaluation; default-deny applied.
    BudgetExhausted {
        action: SafetyAction,
        requested_ms: u64,
        remaining_ms: u64,
    },
    /// No contract registered for this action.
    NoContract { action: SafetyAction },
    /// Decision contract evaluation produced an invalid action index.
    InvalidActionIndex {
        action: SafetyAction,
        index: usize,
        max: usize,
    },
}

impl fmt::Display for SafetyRouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExhausted {
                action,
                requested_ms,
                remaining_ms,
            } => write!(
                f,
                "budget exhausted for {action}: need {requested_ms}ms, have {remaining_ms}ms"
            ),
            Self::NoContract { action } => {
                write!(f, "no decision contract registered for {action}")
            }
            Self::InvalidActionIndex { action, index, max } => {
                write!(f, "invalid action index {index} (max {max}) for {action}")
            }
        }
    }
}

impl std::error::Error for SafetyRouterError {}

// ---------------------------------------------------------------------------
// Structured event
// ---------------------------------------------------------------------------

/// Structured event emitted for every safety decision evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyDecisionEvent {
    /// Monotonic sequence.
    pub seq: u64,
    /// Trace identity from the Cx.
    pub trace_id: String,
    /// Decision identity.
    pub decision_id: String,
    /// Policy identity.
    pub policy_id: String,
    /// Component name.
    pub component: String,
    /// Event type.
    pub event: String,
    /// Outcome.
    pub outcome: String,
    /// Error code if applicable.
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// SafetyContract — concrete decision contract per action type
// ---------------------------------------------------------------------------

/// A concrete decision contract for a specific safety action type.
///
/// Uses two states ("safe" / "unsafe") and two actions ("allow" / "deny").
/// The loss matrix encodes the cost of false-allow vs. false-deny:
///
/// ```text
///              allow     deny
/// safe          0.0      deny_cost
/// unsafe     allow_cost   0.0
/// ```
///
/// `allow_cost` is typically much higher than `deny_cost` for safety
/// actions (false-allow of a dangerous action is worse than false-deny).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyContract {
    action_type: SafetyAction,
    states: Vec<String>,
    actions: Vec<String>,
    loss_matrix: LossMatrix,
    fallback_policy: FallbackPolicy,
    fallback_action_index: usize,
}

impl SafetyContract {
    /// Create a safety contract with explicit loss costs.
    ///
    /// `allow_cost`: loss incurred when allowing an unsafe action.
    /// `deny_cost`: loss incurred when denying a safe action.
    pub fn new(
        action_type: SafetyAction,
        allow_cost: f64,
        deny_cost: f64,
        fallback_policy: FallbackPolicy,
    ) -> Self {
        let states = vec!["safe".to_string(), "unsafe".to_string()];
        let actions = vec!["allow".to_string(), "deny".to_string()];
        // Row-major: [safe-allow, safe-deny, unsafe-allow, unsafe-deny]
        let loss_matrix = LossMatrix::new(
            states.clone(),
            actions.clone(),
            vec![0.0, deny_cost, allow_cost, 0.0],
        )
        .expect("valid 2x2 loss matrix");

        Self {
            action_type,
            states,
            actions,
            loss_matrix,
            fallback_policy,
            fallback_action_index: 1, // deny is the fallback
        }
    }

    /// Create with default safety-biased costs.
    ///
    /// `allow_cost` = 0.9, `deny_cost` = 0.1 — strongly biased toward
    /// denying when uncertain.
    pub fn default_for(action_type: SafetyAction) -> Self {
        Self::new(action_type, 0.9, 0.1, FallbackPolicy::default())
    }

    /// The action type this contract covers.
    pub fn action_type(&self) -> SafetyAction {
        self.action_type
    }
}

impl DecisionContract for SafetyContract {
    fn name(&self) -> &str {
        self.action_type.as_str()
    }

    fn state_space(&self) -> &[String] {
        &self.states
    }

    fn action_set(&self) -> &[String] {
        &self.actions
    }

    fn loss_matrix(&self) -> &LossMatrix {
        &self.loss_matrix
    }

    fn update_posterior(&self, posterior: &mut Posterior, state_index: usize) {
        // Simple likelihood model: observation at state_index gets
        // high likelihood (0.9), other states get low (0.1).
        let likelihoods: Vec<f64> = (0..posterior.len())
            .map(|i| if i == state_index { 0.9 } else { 0.1 })
            .collect();
        posterior.bayesian_update(&likelihoods);
    }

    fn choose_action(&self, posterior: &Posterior) -> usize {
        self.loss_matrix.bayes_action(posterior)
    }

    fn fallback_action(&self) -> usize {
        self.fallback_action_index
    }

    fn fallback_policy(&self) -> &FallbackPolicy {
        &self.fallback_policy
    }
}

// ---------------------------------------------------------------------------
// SafetyDecisionRouter
// ---------------------------------------------------------------------------

/// Budget cost for evaluating a safety decision (ms).
const SAFETY_DECISION_BUDGET_COST_MS: u64 = 2;

/// Routes high-impact safety actions through decision contracts.
///
/// The router:
/// 1. Validates budget availability via `ContextAdapter`
/// 2. Evaluates the registered decision contract for the action type
/// 3. Maps the decision outcome to a `SafetyVerdict`
/// 4. Emits evidence and structured events
/// 5. Returns `default-deny` if budget is exhausted or no contract is
///    registered
#[derive(Debug)]
pub struct SafetyDecisionRouter {
    /// Registered contracts by action type.
    contracts: BTreeMap<SafetyAction, SafetyContract>,
    /// Posteriors by action type (maintained across evaluations).
    posteriors: BTreeMap<SafetyAction, Posterior>,
    /// Accumulated events.
    events: Vec<SafetyDecisionEvent>,
    /// Evidence entries emitted.
    evidence: Vec<EvidenceLedger>,
    /// Decision results.
    results: Vec<SafetyDecisionResult>,
    /// Monotonic sequence counter.
    seq: u64,
    /// Total decisions evaluated.
    decision_count: u64,
    /// Total denials.
    deny_count: u64,
    /// Total fallbacks.
    fallback_count: u64,
}

impl SafetyDecisionRouter {
    /// Create a new router with no registered contracts.
    pub fn new() -> Self {
        Self {
            contracts: BTreeMap::new(),
            posteriors: BTreeMap::new(),
            events: Vec::new(),
            evidence: Vec::new(),
            results: Vec::new(),
            seq: 0,
            decision_count: 0,
            deny_count: 0,
            fallback_count: 0,
        }
    }

    /// Register a decision contract for a specific action type.
    pub fn register(&mut self, contract: SafetyContract) {
        let action = contract.action_type();
        self.posteriors
            .insert(action, Posterior::uniform(contract.state_space().len()));
        self.contracts.insert(action, contract);
    }

    /// Register default contracts for all action types.
    pub fn register_all_defaults(&mut self) {
        for &action in SafetyAction::all() {
            self.register(SafetyContract::default_for(action));
        }
    }

    /// Evaluate a safety action through the decision router.
    ///
    /// Consumes budget from the `ContextAdapter`, evaluates the registered
    /// contract, emits evidence, and returns the verdict.  If budget is
    /// exhausted, returns default-deny without consuming budget.
    pub fn evaluate(
        &mut self,
        cx: &mut dyn ContextAdapter,
        request: &SafetyDecisionRequest,
    ) -> Result<SafetyDecisionResult, SafetyRouterError> {
        let trace_id = cx.trace_id().to_string();

        // Check contract registration.
        let contract = match self.contracts.get(&request.action) {
            Some(c) => c.clone(),
            None => {
                self.push_event(
                    &trace_id,
                    &request.decision_id.to_string(),
                    &request.policy_id.to_string(),
                    "evaluate",
                    "no_contract",
                    Some("no_contract"),
                );
                return Err(SafetyRouterError::NoContract {
                    action: request.action,
                });
            }
        };

        // Check budget.
        let remaining = cx.budget().remaining_ms();
        if let Err(_e) = cx.consume_budget(SAFETY_DECISION_BUDGET_COST_MS) {
            self.push_event(
                &trace_id,
                &request.decision_id.to_string(),
                &request.policy_id.to_string(),
                "evaluate",
                "budget_exhausted",
                Some("budget_exhausted"),
            );
            // Default-deny on budget exhaustion.
            self.deny_count += 1;
            self.decision_count += 1;
            let result = SafetyDecisionResult {
                action: request.action,
                verdict: request.action.default_fallback(),
                extension_id: request.extension_id.clone(),
                trace_id,
                decision_id: request.decision_id.to_string(),
                policy_id: request.policy_id.to_string(),
                expected_loss_milli: 0,
                fallback_active: true,
                budget_consumed_ms: 0,
                sequence_number: self.decision_count,
            };
            self.results.push(result);
            return Err(SafetyRouterError::BudgetExhausted {
                action: request.action,
                requested_ms: SAFETY_DECISION_BUDGET_COST_MS,
                remaining_ms: remaining,
            });
        }

        // Get or create posterior.
        let posterior = self
            .posteriors
            .entry(request.action)
            .or_insert_with(|| Posterior::uniform(contract.state_space().len()))
            .clone();

        // Build eval context.
        let eval_ctx = EvalContext {
            calibration_score: request.calibration_score(),
            e_process: request.e_process(),
            ci_width: request.ci_width(),
            decision_id: request.decision_id,
            trace_id: cx.trace_id(),
            ts_unix_ms: request.ts_unix_ms,
        };

        // Evaluate decision contract.
        let outcome = franken_decision::evaluate(&contract, &posterior, &eval_ctx);

        // Map outcome to verdict.
        let verdict = self.map_outcome(&outcome, request.action);

        // Emit evidence.
        let evidence = outcome.audit_entry.to_evidence_ledger();
        self.evidence.push(evidence);

        // Emit structured event.
        self.push_event(
            &trace_id,
            &request.decision_id.to_string(),
            &request.policy_id.to_string(),
            "evaluate",
            verdict.outcome_str(),
            None,
        );

        // Track stats.
        self.decision_count += 1;
        match &verdict {
            SafetyVerdict::Deny { .. } => self.deny_count += 1,
            SafetyVerdict::Fallback { .. } => self.fallback_count += 1,
            SafetyVerdict::Allow => {}
        }

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let expected_loss_milli = (outcome.expected_loss * 1_000.0) as u64;

        let result = SafetyDecisionResult {
            action: request.action,
            verdict,
            extension_id: request.extension_id.clone(),
            trace_id,
            decision_id: request.decision_id.to_string(),
            policy_id: request.policy_id.to_string(),
            expected_loss_milli,
            fallback_active: outcome.fallback_active,
            budget_consumed_ms: SAFETY_DECISION_BUDGET_COST_MS,
            sequence_number: self.decision_count,
        };
        self.results.push(result.clone());
        Ok(result)
    }

    /// Update the posterior for a given action type with an observation.
    ///
    /// `state_index`: 0 = "safe" observation, 1 = "unsafe" observation.
    pub fn observe(
        &mut self,
        action: SafetyAction,
        state_index: usize,
    ) -> Result<(), SafetyRouterError> {
        let contract = self
            .contracts
            .get(&action)
            .ok_or(SafetyRouterError::NoContract { action })?;
        let posterior = self
            .posteriors
            .entry(action)
            .or_insert_with(|| Posterior::uniform(contract.state_space().len()));
        contract.update_posterior(posterior, state_index);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Total decisions evaluated.
    pub fn decision_count(&self) -> u64 {
        self.decision_count
    }

    /// Total denials.
    pub fn deny_count(&self) -> u64 {
        self.deny_count
    }

    /// Total fallbacks.
    pub fn fallback_count(&self) -> u64 {
        self.fallback_count
    }

    /// All decision results.
    pub fn results(&self) -> &[SafetyDecisionResult] {
        &self.results
    }

    /// All emitted evidence entries.
    pub fn evidence(&self) -> &[EvidenceLedger] {
        &self.evidence
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<SafetyDecisionEvent> {
        std::mem::take(&mut self.events)
    }

    /// Number of registered contracts.
    pub fn contract_count(&self) -> usize {
        self.contracts.len()
    }

    /// Whether a contract is registered for a given action.
    pub fn has_contract(&self, action: SafetyAction) -> bool {
        self.contracts.contains_key(&action)
    }

    /// Current posterior for a given action type (if any).
    pub fn posterior(&self, action: SafetyAction) -> Option<&Posterior> {
        self.posteriors.get(&action)
    }

    /// Summary of decisions by action type.
    pub fn summary_by_action(&self) -> BTreeMap<SafetyAction, ActionSummary> {
        let mut summaries = BTreeMap::new();
        for result in &self.results {
            let entry = summaries
                .entry(result.action)
                .or_insert_with(ActionSummary::default);
            entry.total += 1;
            match &result.verdict {
                SafetyVerdict::Allow => entry.allows += 1,
                SafetyVerdict::Deny { .. } => entry.denials += 1,
                SafetyVerdict::Fallback { .. } => entry.fallbacks += 1,
            }
        }
        summaries
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn map_outcome(&self, outcome: &DecisionOutcome, action: SafetyAction) -> SafetyVerdict {
        if outcome.fallback_active {
            return SafetyVerdict::Fallback {
                reason: format!(
                    "fallback triggered for {}: model confidence degraded",
                    action.as_str()
                ),
            };
        }

        match outcome.action_name.as_str() {
            "allow" | "permit" | "continue" => SafetyVerdict::Allow,
            "deny" | "reject" | "block" | "stop" => SafetyVerdict::Deny {
                reason: format!(
                    "decision contract denied {}: expected_loss={:.3}",
                    action.as_str(),
                    outcome.expected_loss
                ),
            },
            other => SafetyVerdict::Deny {
                reason: format!("unknown action '{other}' treated as deny for {action}"),
            },
        }
    }

    fn push_event(
        &mut self,
        trace_id: &str,
        decision_id: &str,
        policy_id: &str,
        event: &str,
        outcome: &str,
        error_code: Option<&str>,
    ) {
        self.seq += 1;
        self.events.push(SafetyDecisionEvent {
            seq: self.seq,
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: policy_id.to_string(),
            component: "safety_decision_router".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(String::from),
        });
    }
}

impl Default for SafetyDecisionRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Action summary
// ---------------------------------------------------------------------------

/// Summary statistics for a single action type.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionSummary {
    pub total: u64,
    pub allows: u64,
    pub denials: u64,
    pub fallbacks: u64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::mocks::{
        MockBudget, MockCx, decision_id_from_seed, policy_id_from_seed, trace_id_from_seed,
    };

    fn test_cx(budget_ms: u64) -> MockCx {
        MockCx::new(trace_id_from_seed(1), MockBudget::new(budget_ms))
    }

    fn test_request(action: SafetyAction, seed: u64) -> SafetyDecisionRequest {
        SafetyDecisionRequest {
            action,
            extension_id: format!("ext-{seed}"),
            target_extension_id: None,
            decision_id: decision_id_from_seed(seed),
            policy_id: policy_id_from_seed(seed),
            ts_unix_ms: 1_700_000_000_000 + seed,
            calibration_score_bps: 9_400,
            e_process_milli: 110,
            ci_width_milli: 45,
        }
    }

    // -----------------------------------------------------------------------
    // SafetyAction
    // -----------------------------------------------------------------------

    #[test]
    fn safety_action_all_returns_six_variants_batch2() {
        assert_eq!(SafetyAction::all().len(), 6);
    }

    #[test]
    fn safety_action_display_matches_as_str() {
        for &action in SafetyAction::all() {
            assert_eq!(action.to_string(), action.as_str());
        }
    }

    #[test]
    fn safety_action_default_fallback_is_deny_batch2() {
        for &action in SafetyAction::all() {
            assert!(matches!(
                action.default_fallback(),
                SafetyVerdict::Deny { .. }
            ));
        }
    }

    #[test]
    fn safety_action_serde_roundtrip() {
        for &action in SafetyAction::all() {
            let json = serde_json::to_string(&action).unwrap();
            let restored: SafetyAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, restored);
        }
    }

    #[test]
    fn safety_action_ordering_is_deterministic() {
        let mut actions = SafetyAction::all().to_vec();
        actions.sort();
        assert_eq!(actions, SafetyAction::all());
    }

    // -----------------------------------------------------------------------
    // SafetyVerdict
    // -----------------------------------------------------------------------

    #[test]
    fn safety_verdict_is_allow() {
        assert!(SafetyVerdict::Allow.is_allow());
        assert!(
            !SafetyVerdict::Deny {
                reason: "x".to_string()
            }
            .is_allow()
        );
        assert!(
            !SafetyVerdict::Fallback {
                reason: "x".to_string()
            }
            .is_allow()
        );
    }

    #[test]
    fn safety_verdict_outcome_str() {
        assert_eq!(SafetyVerdict::Allow.outcome_str(), "allow");
        assert_eq!(
            SafetyVerdict::Deny {
                reason: "x".to_string()
            }
            .outcome_str(),
            "deny"
        );
        assert_eq!(
            SafetyVerdict::Fallback {
                reason: "x".to_string()
            }
            .outcome_str(),
            "fallback"
        );
    }

    #[test]
    fn safety_verdict_display() {
        assert_eq!(SafetyVerdict::Allow.to_string(), "allow");
        assert_eq!(
            SafetyVerdict::Deny {
                reason: "bad".to_string()
            }
            .to_string(),
            "deny: bad"
        );
        assert_eq!(
            SafetyVerdict::Fallback {
                reason: "drift".to_string()
            }
            .to_string(),
            "fallback: drift"
        );
    }

    #[test]
    fn safety_verdict_serde_roundtrip_batch2() {
        let verdicts = [
            SafetyVerdict::Allow,
            SafetyVerdict::Deny {
                reason: "x".to_string(),
            },
            SafetyVerdict::Fallback {
                reason: "y".to_string(),
            },
        ];
        for v in &verdicts {
            let json = serde_json::to_string(v).unwrap();
            let restored: SafetyVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, restored);
        }
    }

    // -----------------------------------------------------------------------
    // SafetyContract
    // -----------------------------------------------------------------------

    #[test]
    fn safety_contract_default_has_two_states_two_actions() {
        let c = SafetyContract::default_for(SafetyAction::ExtensionQuarantine);
        assert_eq!(c.state_space().len(), 2);
        assert_eq!(c.action_set().len(), 2);
        assert_eq!(c.state_space(), &["safe", "unsafe"]);
        assert_eq!(c.action_set(), &["allow", "deny"]);
    }

    #[test]
    fn safety_contract_name_matches_action() {
        for &action in SafetyAction::all() {
            let c = SafetyContract::default_for(action);
            assert_eq!(c.name(), action.as_str());
        }
    }

    #[test]
    fn safety_contract_fallback_is_deny() {
        let c = SafetyContract::default_for(SafetyAction::ForcedTermination);
        assert_eq!(c.fallback_action(), 1); // "deny"
    }

    #[test]
    fn safety_contract_loss_matrix_biased_toward_deny() {
        let c = SafetyContract::default_for(SafetyAction::PrivilegeEscalation);
        let lm = c.loss_matrix();
        // loss(unsafe, allow) = 0.9 >> loss(safe, deny) = 0.1
        assert!(lm.get(1, 0) > lm.get(0, 1));
    }

    #[test]
    fn safety_contract_bayes_action_with_uniform_prior_is_deny() {
        let c = SafetyContract::default_for(SafetyAction::CapabilityRevocation);
        let posterior = Posterior::uniform(2);
        // With uniform prior and asymmetric loss, Bayes action should be
        // deny because expected_loss(allow) = 0.5*0.0 + 0.5*0.9 = 0.45
        //                   expected_loss(deny) = 0.5*0.1 + 0.5*0.0 = 0.05
        let action_idx = c.choose_action(&posterior);
        assert_eq!(c.action_set()[action_idx], "deny");
    }

    #[test]
    fn safety_contract_bayes_action_with_safe_posterior_is_allow() {
        let c = SafetyContract::default_for(SafetyAction::BudgetOverride);
        // Posterior strongly favoring "safe" state.
        let posterior = Posterior::new(vec![0.99, 0.01]).unwrap();
        // expected_loss(allow) = 0.99*0.0 + 0.01*0.9 = 0.009
        // expected_loss(deny)  = 0.99*0.1 + 0.01*0.0 = 0.099
        let action_idx = c.choose_action(&posterior);
        assert_eq!(c.action_set()[action_idx], "allow");
    }

    #[test]
    fn safety_contract_update_posterior_shifts_belief() {
        let c = SafetyContract::default_for(SafetyAction::ExtensionQuarantine);
        let mut posterior = Posterior::uniform(2);
        // Observe "unsafe" (state_index=1)
        c.update_posterior(&mut posterior, 1);
        // After update, P(unsafe) should be > P(safe)
        assert!(posterior.probs()[1] > posterior.probs()[0]);
    }

    #[test]
    fn safety_contract_serde_roundtrip() {
        let c = SafetyContract::default_for(SafetyAction::CrossExtensionShare);
        let json = serde_json::to_string(&c).unwrap();
        let restored: SafetyContract = serde_json::from_str(&json).unwrap();
        assert_eq!(c.action_type(), restored.action_type());
        assert_eq!(c.name(), restored.name());
    }

    // -----------------------------------------------------------------------
    // SafetyDecisionRouter — registration
    // -----------------------------------------------------------------------

    #[test]
    fn router_starts_empty() {
        let r = SafetyDecisionRouter::new();
        assert_eq!(r.contract_count(), 0);
        assert_eq!(r.decision_count(), 0);
    }

    #[test]
    fn router_register_individual_contract() {
        let mut r = SafetyDecisionRouter::new();
        r.register(SafetyContract::default_for(
            SafetyAction::ExtensionQuarantine,
        ));
        assert_eq!(r.contract_count(), 1);
        assert!(r.has_contract(SafetyAction::ExtensionQuarantine));
        assert!(!r.has_contract(SafetyAction::ForcedTermination));
    }

    #[test]
    fn router_register_all_defaults() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        assert_eq!(r.contract_count(), 6);
        for &action in SafetyAction::all() {
            assert!(r.has_contract(action));
        }
    }

    // -----------------------------------------------------------------------
    // SafetyDecisionRouter — evaluation
    // -----------------------------------------------------------------------

    #[test]
    fn router_evaluate_with_uniform_prior_denies() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        let mut cx = test_cx(100);
        let req = test_request(SafetyAction::ExtensionQuarantine, 1);
        let result = r.evaluate(&mut cx, &req).unwrap();
        // With uniform prior and safety-biased loss, expect deny.
        assert!(
            matches!(result.verdict, SafetyVerdict::Deny { .. }),
            "expected deny with uniform prior, got {:?}",
            result.verdict
        );
        assert_eq!(result.action, SafetyAction::ExtensionQuarantine);
        assert_eq!(result.extension_id, "ext-1");
        assert_eq!(result.budget_consumed_ms, SAFETY_DECISION_BUDGET_COST_MS);
    }

    #[test]
    fn router_evaluate_with_safe_posterior_allows() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        // Force the posterior to strongly favor "safe".
        *r.posteriors.get_mut(&SafetyAction::BudgetOverride).unwrap() =
            Posterior::new(vec![0.99, 0.01]).unwrap();

        let mut cx = test_cx(100);
        let req = test_request(SafetyAction::BudgetOverride, 2);
        let result = r.evaluate(&mut cx, &req).unwrap();
        assert!(result.verdict.is_allow());
    }

    #[test]
    fn router_evaluate_emits_evidence() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        let mut cx = test_cx(100);
        let req = test_request(SafetyAction::ForcedTermination, 3);
        r.evaluate(&mut cx, &req).unwrap();
        assert_eq!(r.evidence().len(), 1);
    }

    #[test]
    fn router_evaluate_emits_event() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        let mut cx = test_cx(100);
        let req = test_request(SafetyAction::CapabilityRevocation, 4);
        r.evaluate(&mut cx, &req).unwrap();
        let events = r.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].component, "safety_decision_router");
        assert_eq!(events[0].event, "evaluate");
    }

    #[test]
    fn router_evaluate_consumes_budget() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        let mut cx = test_cx(100);
        let req = test_request(SafetyAction::PrivilegeEscalation, 5);
        r.evaluate(&mut cx, &req).unwrap();
        assert_eq!(
            cx.budget().remaining_ms(),
            100 - SAFETY_DECISION_BUDGET_COST_MS
        );
    }

    #[test]
    fn router_evaluate_budget_exhaustion_returns_default_deny() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        let mut cx = test_cx(1); // Not enough for 2ms cost.
        let req = test_request(SafetyAction::CrossExtensionShare, 6);
        let err = r.evaluate(&mut cx, &req).unwrap_err();
        assert!(matches!(err, SafetyRouterError::BudgetExhausted { .. }));
        assert_eq!(r.deny_count(), 1);
    }

    #[test]
    fn router_evaluate_no_contract_returns_error() {
        let mut r = SafetyDecisionRouter::new();
        // Don't register any contracts.
        let mut cx = test_cx(100);
        let req = test_request(SafetyAction::ForcedTermination, 7);
        let err = r.evaluate(&mut cx, &req).unwrap_err();
        assert!(matches!(err, SafetyRouterError::NoContract { .. }));
    }

    #[test]
    fn router_evaluate_trace_id_propagated() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        let mut cx = test_cx(100);
        let trace_str = cx.trace_id().to_string();
        let req = test_request(SafetyAction::ExtensionQuarantine, 8);
        let result = r.evaluate(&mut cx, &req).unwrap();
        assert_eq!(result.trace_id, trace_str);
    }

    // -----------------------------------------------------------------------
    // Posterior updates via observe
    // -----------------------------------------------------------------------

    #[test]
    fn router_observe_shifts_posterior() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        let before = r
            .posterior(SafetyAction::ExtensionQuarantine)
            .unwrap()
            .probs()
            .to_vec();
        // Observe "safe" state.
        r.observe(SafetyAction::ExtensionQuarantine, 0).unwrap();
        let after = r
            .posterior(SafetyAction::ExtensionQuarantine)
            .unwrap()
            .probs()
            .to_vec();
        // P(safe) should have increased.
        assert!(after[0] > before[0]);
    }

    #[test]
    fn router_observe_no_contract_returns_error() {
        let mut r = SafetyDecisionRouter::new();
        let err = r.observe(SafetyAction::BudgetOverride, 0).unwrap_err();
        assert!(matches!(err, SafetyRouterError::NoContract { .. }));
    }

    #[test]
    fn router_observe_then_evaluate_changes_verdict() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        // Many "safe" observations should shift posterior toward allow.
        for _ in 0..20 {
            r.observe(SafetyAction::BudgetOverride, 0).unwrap();
        }
        let mut cx = test_cx(100);
        let req = test_request(SafetyAction::BudgetOverride, 9);
        let result = r.evaluate(&mut cx, &req).unwrap();
        // After many safe observations, should allow.
        assert!(result.verdict.is_allow());
    }

    // -----------------------------------------------------------------------
    // Fallback triggering
    // -----------------------------------------------------------------------

    #[test]
    fn router_evaluate_with_low_calibration_triggers_fallback() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        // Force safe posterior so normal eval would allow.
        *r.posteriors.get_mut(&SafetyAction::BudgetOverride).unwrap() =
            Posterior::new(vec![0.99, 0.01]).unwrap();

        let mut cx = test_cx(100);
        let mut req = test_request(SafetyAction::BudgetOverride, 10);
        // Set calibration below threshold (0.7 default).
        req.calibration_score_bps = 5_000; // 0.50

        let result = r.evaluate(&mut cx, &req).unwrap();
        assert!(matches!(result.verdict, SafetyVerdict::Fallback { .. }));
        assert!(result.fallback_active);
        assert_eq!(r.fallback_count(), 1);
    }

    #[test]
    fn router_evaluate_with_high_e_process_triggers_fallback() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        *r.posteriors
            .get_mut(&SafetyAction::PrivilegeEscalation)
            .unwrap() = Posterior::new(vec![0.99, 0.01]).unwrap();

        let mut cx = test_cx(100);
        let mut req = test_request(SafetyAction::PrivilegeEscalation, 11);
        // Set e-process above threshold (20.0 default).
        req.e_process_milli = 25_000; // 25.0

        let result = r.evaluate(&mut cx, &req).unwrap();
        assert!(matches!(result.verdict, SafetyVerdict::Fallback { .. }));
    }

    // -----------------------------------------------------------------------
    // Multiple evaluations
    // -----------------------------------------------------------------------

    #[test]
    fn router_multiple_evaluations_track_stats() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        let mut cx = test_cx(100);

        for i in 0..5 {
            let req = test_request(SafetyAction::ExtensionQuarantine, i);
            let _ = r.evaluate(&mut cx, &req);
        }
        assert_eq!(r.decision_count(), 5);
        assert_eq!(r.results().len(), 5);
    }

    #[test]
    fn router_summary_by_action() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        let mut cx = test_cx(200);

        // Evaluate different actions.
        for &action in &[
            SafetyAction::ExtensionQuarantine,
            SafetyAction::ExtensionQuarantine,
            SafetyAction::ForcedTermination,
        ] {
            let req = test_request(action, 0);
            let _ = r.evaluate(&mut cx, &req);
        }
        let summary = r.summary_by_action();
        assert_eq!(summary[&SafetyAction::ExtensionQuarantine].total, 2);
        assert_eq!(summary[&SafetyAction::ForcedTermination].total, 1);
    }

    // -----------------------------------------------------------------------
    // Serde round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn safety_decision_request_serde_roundtrip() {
        let req = test_request(SafetyAction::CrossExtensionShare, 42);
        let json = serde_json::to_string(&req).unwrap();
        let restored: SafetyDecisionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, restored);
    }

    #[test]
    fn safety_decision_result_serde_roundtrip() {
        let result = SafetyDecisionResult {
            action: SafetyAction::ForcedTermination,
            verdict: SafetyVerdict::Deny {
                reason: "x".to_string(),
            },
            extension_id: "ext-1".to_string(),
            trace_id: "trace-1".to_string(),
            decision_id: "dec-1".to_string(),
            policy_id: "pol-1".to_string(),
            expected_loss_milli: 450,
            fallback_active: false,
            budget_consumed_ms: 2,
            sequence_number: 1,
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: SafetyDecisionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, restored);
    }

    #[test]
    fn safety_decision_event_serde_roundtrip() {
        let event = SafetyDecisionEvent {
            seq: 1,
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "evaluate".to_string(),
            outcome: "allow".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: SafetyDecisionEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }

    #[test]
    fn safety_router_error_serde_roundtrip() {
        let errors = [
            SafetyRouterError::BudgetExhausted {
                action: SafetyAction::BudgetOverride,
                requested_ms: 2,
                remaining_ms: 1,
            },
            SafetyRouterError::NoContract {
                action: SafetyAction::ForcedTermination,
            },
            SafetyRouterError::InvalidActionIndex {
                action: SafetyAction::PrivilegeEscalation,
                index: 5,
                max: 2,
            },
        ];
        for e in &errors {
            let json = serde_json::to_string(e).unwrap();
            let restored: SafetyRouterError = serde_json::from_str(&json).unwrap();
            assert_eq!(*e, restored);
        }
    }

    #[test]
    fn safety_router_error_display() {
        let e1 = SafetyRouterError::BudgetExhausted {
            action: SafetyAction::ExtensionQuarantine,
            requested_ms: 2,
            remaining_ms: 1,
        };
        assert!(e1.to_string().contains("budget exhausted"));

        let e2 = SafetyRouterError::NoContract {
            action: SafetyAction::ForcedTermination,
        };
        assert!(e2.to_string().contains("no decision contract"));
    }

    #[test]
    fn action_summary_serde_roundtrip() {
        let s = ActionSummary {
            total: 10,
            allows: 3,
            denials: 5,
            fallbacks: 2,
        };
        let json = serde_json::to_string(&s).unwrap();
        let restored: ActionSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, restored);
    }

    // -----------------------------------------------------------------------
    // Deterministic replay
    // -----------------------------------------------------------------------

    #[test]
    fn deterministic_replay_identical_inputs_identical_results() {
        let run = || {
            let mut r = SafetyDecisionRouter::new();
            r.register_all_defaults();
            let mut cx = test_cx(100);
            let req = test_request(SafetyAction::ExtensionQuarantine, 1);
            r.evaluate(&mut cx, &req).unwrap()
        };
        let r1 = run();
        let r2 = run();
        assert_eq!(r1, r2);
    }

    // -----------------------------------------------------------------------
    // Custom loss matrix
    // -----------------------------------------------------------------------

    #[test]
    fn custom_loss_matrix_changes_verdict() {
        // Symmetric loss = allow_cost == deny_cost.
        let contract = SafetyContract::new(
            SafetyAction::CrossExtensionShare,
            0.5,
            0.5,
            FallbackPolicy::default(),
        );
        let mut r = SafetyDecisionRouter::new();
        r.register(contract);

        // With symmetric loss and uniform prior, action with lowest
        // index wins (allow at index 0).
        let mut cx = test_cx(100);
        let req = test_request(SafetyAction::CrossExtensionShare, 20);
        let result = r.evaluate(&mut cx, &req).unwrap();
        assert!(result.verdict.is_allow());
    }

    #[test]
    fn highly_asymmetric_loss_always_denies() {
        // Very high allow_cost, very low deny_cost.
        let contract = SafetyContract::new(
            SafetyAction::ForcedTermination,
            100.0,
            0.001,
            FallbackPolicy::default(),
        );
        let mut r = SafetyDecisionRouter::new();
        r.register(contract);

        // Even with P(safe)=0.99, the high allow_cost keeps deny as
        // the Bayes-optimal action.
        *r.posteriors
            .get_mut(&SafetyAction::ForcedTermination)
            .unwrap() = Posterior::new(vec![0.99, 0.01]).unwrap();

        let mut cx = test_cx(100);
        let req = test_request(SafetyAction::ForcedTermination, 21);
        let result = r.evaluate(&mut cx, &req).unwrap();
        assert!(
            matches!(result.verdict, SafetyVerdict::Deny { .. }),
            "expected deny with highly asymmetric loss"
        );
    }

    // -----------------------------------------------------------------------
    // Evidence linking
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_emitted_for_every_decision() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        let mut cx = test_cx(200);

        for i in 0..4 {
            let action = SafetyAction::all()[i % SafetyAction::all().len()];
            let req = test_request(action, i as u64);
            let _ = r.evaluate(&mut cx, &req);
        }
        assert_eq!(r.evidence().len(), 4);
    }

    // -----------------------------------------------------------------------
    // Enrichment: SafetyAction Display uniqueness via BTreeSet
    // -----------------------------------------------------------------------

    #[test]
    fn safety_action_display_all_unique_btreeset() {
        let mut displays = std::collections::BTreeSet::new();
        for &a in SafetyAction::all() {
            displays.insert(a.to_string());
        }
        assert_eq!(
            displays.len(),
            6,
            "all 6 SafetyAction variants produce distinct Display"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: SafetyVerdict Display uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn safety_verdict_display_all_unique() {
        let verdicts = [
            SafetyVerdict::Allow,
            SafetyVerdict::Deny {
                reason: "x".to_string(),
            },
            SafetyVerdict::Fallback {
                reason: "y".to_string(),
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &verdicts {
            displays.insert(v.to_string());
        }
        assert_eq!(
            displays.len(),
            3,
            "all SafetyVerdict variants produce distinct Display"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: SafetyRouterError Display uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn safety_router_error_display_all_unique() {
        let errors = [
            SafetyRouterError::BudgetExhausted {
                action: SafetyAction::BudgetOverride,
                requested_ms: 2,
                remaining_ms: 1,
            },
            SafetyRouterError::NoContract {
                action: SafetyAction::ForcedTermination,
            },
            SafetyRouterError::InvalidActionIndex {
                action: SafetyAction::PrivilegeEscalation,
                index: 5,
                max: 2,
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for e in &errors {
            displays.insert(e.to_string());
        }
        assert_eq!(displays.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Enrichment: SafetyRouterError implements std::error::Error
    // -----------------------------------------------------------------------

    #[test]
    fn safety_router_error_implements_std_error() {
        let variants: [Box<dyn std::error::Error>; 2] = [
            Box::new(SafetyRouterError::BudgetExhausted {
                action: SafetyAction::ExtensionQuarantine,
                requested_ms: 2,
                remaining_ms: 0,
            }),
            Box::new(SafetyRouterError::NoContract {
                action: SafetyAction::ForcedTermination,
            }),
        ];
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: router drain_events resets events
    // -----------------------------------------------------------------------

    #[test]
    fn router_drain_events_clears_log() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        let mut cx = test_cx(100);
        let req = test_request(SafetyAction::ExtensionQuarantine, 1);
        r.evaluate(&mut cx, &req).unwrap();
        assert_eq!(r.drain_events().len(), 1);
        assert!(
            r.drain_events().is_empty(),
            "drain_events should clear the log"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: router sequence numbers are monotonic
    // -----------------------------------------------------------------------

    #[test]
    fn router_sequence_numbers_monotonic() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        let mut cx = test_cx(200);

        let mut last_seq = 0;
        for i in 0..5u64 {
            let req = test_request(SafetyAction::ExtensionQuarantine, i);
            let result = r.evaluate(&mut cx, &req).unwrap();
            assert!(
                result.sequence_number > last_seq,
                "sequence must be monotonically increasing"
            );
            last_seq = result.sequence_number;
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: ActionSummary default values
    // -----------------------------------------------------------------------

    #[test]
    fn action_summary_default_is_zero() {
        let s = ActionSummary::default();
        assert_eq!(s.total, 0);
        assert_eq!(s.allows, 0);
        assert_eq!(s.denials, 0);
        assert_eq!(s.fallbacks, 0);
    }

    // -- Enrichment batch 2: PearlTower 2026-02-27 --

    #[test]
    fn safety_action_all_returns_six_variants() {
        assert_eq!(SafetyAction::all().len(), 6);
    }

    #[test]
    fn safety_action_as_str_all_distinct() {
        let labels: std::collections::BTreeSet<&str> =
            SafetyAction::all().iter().map(|a| a.as_str()).collect();
        assert_eq!(labels.len(), 6);
    }

    #[test]
    fn safety_action_default_fallback_is_deny() {
        for action in SafetyAction::all() {
            let fallback = action.default_fallback();
            assert!(matches!(fallback, SafetyVerdict::Deny { .. }));
        }
    }

    #[test]
    fn safety_verdict_outcome_str_distinct() {
        let v_allow = SafetyVerdict::Allow;
        let v_deny = SafetyVerdict::Deny { reason: "r".into() };
        let v_fallback = SafetyVerdict::Fallback { reason: "r".into() };
        assert_eq!(v_allow.outcome_str(), "allow");
        assert_eq!(v_deny.outcome_str(), "deny");
        assert_eq!(v_fallback.outcome_str(), "fallback");
    }

    #[test]
    fn safety_verdict_display_contains_reason() {
        let v = SafetyVerdict::Deny {
            reason: "model degraded".into(),
        };
        assert!(v.to_string().contains("model degraded"));
    }

    #[test]
    fn safety_verdict_is_allow_only_for_allow() {
        assert!(SafetyVerdict::Allow.is_allow());
        assert!(!SafetyVerdict::Deny { reason: "r".into() }.is_allow());
        assert!(!SafetyVerdict::Fallback { reason: "r".into() }.is_allow());
    }

    #[test]
    fn safety_verdict_serde_roundtrip() {
        let verdicts = [
            SafetyVerdict::Allow,
            SafetyVerdict::Deny {
                reason: "bad".into(),
            },
            SafetyVerdict::Fallback {
                reason: "low cal".into(),
            },
        ];
        for v in &verdicts {
            let json = serde_json::to_string(v).unwrap();
            let back: SafetyVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn router_error_serde_roundtrip() {
        let errors = [
            SafetyRouterError::BudgetExhausted {
                action: SafetyAction::ForcedTermination,
                requested_ms: 100,
                remaining_ms: 50,
            },
            SafetyRouterError::NoContract {
                action: SafetyAction::BudgetOverride,
            },
            SafetyRouterError::InvalidActionIndex {
                action: SafetyAction::PrivilegeEscalation,
                index: 5,
                max: 2,
            },
        ];
        for e in &errors {
            let json = serde_json::to_string(e).unwrap();
            let back: SafetyRouterError = serde_json::from_str(&json).unwrap();
            assert_eq!(*e, back);
        }
    }

    #[test]
    fn router_error_display_all_distinct() {
        let errors = [
            SafetyRouterError::BudgetExhausted {
                action: SafetyAction::ForcedTermination,
                requested_ms: 100,
                remaining_ms: 50,
            },
            SafetyRouterError::NoContract {
                action: SafetyAction::BudgetOverride,
            },
            SafetyRouterError::InvalidActionIndex {
                action: SafetyAction::PrivilegeEscalation,
                index: 5,
                max: 2,
            },
        ];
        let displays: std::collections::BTreeSet<String> =
            errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(displays.len(), errors.len());
    }

    #[test]
    fn router_multiple_actions_track_summaries() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        let mut cx = test_cx(200);

        let actions = [
            SafetyAction::ExtensionQuarantine,
            SafetyAction::CapabilityRevocation,
            SafetyAction::ForcedTermination,
        ];
        for (i, action) in actions.iter().enumerate() {
            let req = test_request(*action, i as u64);
            r.evaluate(&mut cx, &req).unwrap();
        }

        assert_eq!(r.decision_count(), 3);
        assert_eq!(r.results().len(), 3);
    }

    #[test]
    fn router_drain_events_clears() {
        let mut r = SafetyDecisionRouter::new();
        r.register_all_defaults();
        let mut cx = test_cx(200);
        let req = test_request(SafetyAction::ExtensionQuarantine, 0);
        r.evaluate(&mut cx, &req).unwrap();

        let events = r.drain_events();
        assert!(!events.is_empty());
        assert!(r.drain_events().is_empty());
    }

    #[test]
    fn router_no_contract_returns_error() {
        let mut r = SafetyDecisionRouter::new();
        // Don't register any contracts
        let mut cx = test_cx(200);
        let req = test_request(SafetyAction::ExtensionQuarantine, 0);
        let err = r.evaluate(&mut cx, &req).unwrap_err();
        assert!(matches!(err, SafetyRouterError::NoContract { .. }));
    }

    #[test]
    fn router_has_contract_after_register() {
        let mut r = SafetyDecisionRouter::new();
        assert!(!r.has_contract(SafetyAction::ExtensionQuarantine));
        r.register_all_defaults();
        assert!(r.has_contract(SafetyAction::ExtensionQuarantine));
        assert_eq!(r.contract_count(), 6);
    }

    #[test]
    fn safety_decision_event_serde_roundtrip_batch2() {
        let event = SafetyDecisionEvent {
            seq: 1,
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "safety_decision_router".into(),
            event: "evaluation_started".into(),
            outcome: "allow".into(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: SafetyDecisionEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn action_summary_serde_roundtrip_batch2() {
        let s = ActionSummary {
            total: 10,
            allows: 5,
            denials: 3,
            fallbacks: 2,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: ActionSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn safety_action_serde_roundtrip_batch2() {
        for action in SafetyAction::all() {
            let json = serde_json::to_string(action).unwrap();
            let back: SafetyAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*action, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 3: clone equality, JSON field presence, boundary,
    // error source, Ord determinism
    // -----------------------------------------------------------------------

    #[test]
    fn safety_verdict_clone_equality() {
        let allow = SafetyVerdict::Allow;
        let allow2 = allow.clone();
        assert_eq!(allow, allow2);

        let deny = SafetyVerdict::Deny {
            reason: "test-reason".to_string(),
        };
        let deny2 = deny.clone();
        assert_eq!(deny, deny2);

        let fb = SafetyVerdict::Fallback {
            reason: "drift".to_string(),
        };
        let fb2 = fb.clone();
        assert_eq!(fb, fb2);
    }

    #[test]
    fn safety_decision_request_clone_equality() {
        let req = test_request(SafetyAction::PrivilegeEscalation, 77);
        let req2 = req.clone();
        assert_eq!(req, req2);
    }

    #[test]
    fn safety_decision_event_clone_equality() {
        let event = SafetyDecisionEvent {
            seq: 42,
            trace_id: "t-42".to_string(),
            decision_id: "d-42".to_string(),
            policy_id: "p-42".to_string(),
            component: "safety_decision_router".to_string(),
            event: "evaluate".to_string(),
            outcome: "deny".to_string(),
            error_code: Some("budget_exhausted".to_string()),
        };
        let event2 = event.clone();
        assert_eq!(event, event2);
    }

    #[test]
    fn action_summary_clone_equality() {
        let s = ActionSummary {
            total: 7,
            allows: 2,
            denials: 4,
            fallbacks: 1,
        };
        let s2 = s.clone();
        assert_eq!(s, s2);
    }

    #[test]
    fn safety_router_error_clone_equality() {
        let e = SafetyRouterError::BudgetExhausted {
            action: SafetyAction::ExtensionQuarantine,
            requested_ms: 2,
            remaining_ms: 0,
        };
        let e2 = e.clone();
        assert_eq!(e, e2);

        let e3 = SafetyRouterError::InvalidActionIndex {
            action: SafetyAction::PrivilegeEscalation,
            index: 5,
            max: 2,
        };
        let e4 = e3.clone();
        assert_eq!(e3, e4);
    }

    #[test]
    fn safety_decision_request_json_field_presence() {
        let req = test_request(SafetyAction::CrossExtensionShare, 99);
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"action\""), "missing action field");
        assert!(
            json.contains("\"extension_id\""),
            "missing extension_id field"
        );
        assert!(
            json.contains("\"calibration_score_bps\""),
            "missing calibration_score_bps field"
        );
        assert!(
            json.contains("\"e_process_milli\""),
            "missing e_process_milli field"
        );
    }

    #[test]
    fn safety_decision_result_json_field_presence() {
        let result = SafetyDecisionResult {
            action: SafetyAction::ForcedTermination,
            verdict: SafetyVerdict::Allow,
            extension_id: "ext-f".to_string(),
            trace_id: "tr-f".to_string(),
            decision_id: "dec-f".to_string(),
            policy_id: "pol-f".to_string(),
            expected_loss_milli: 123,
            fallback_active: false,
            budget_consumed_ms: 2,
            sequence_number: 5,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(
            json.contains("\"expected_loss_milli\""),
            "missing expected_loss_milli"
        );
        assert!(
            json.contains("\"fallback_active\""),
            "missing fallback_active"
        );
        assert!(
            json.contains("\"sequence_number\""),
            "missing sequence_number"
        );
    }

    #[test]
    fn safety_decision_event_json_field_presence() {
        let event = SafetyDecisionEvent {
            seq: 1,
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "evaluate".to_string(),
            outcome: "allow".to_string(),
            error_code: Some("err".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"error_code\""), "missing error_code field");
        assert!(json.contains("\"component\""), "missing component field");
        assert!(json.contains("\"seq\""), "missing seq field");
    }

    #[test]
    fn safety_router_error_source_is_none() {
        use std::error::Error;
        let errors: [SafetyRouterError; 3] = [
            SafetyRouterError::BudgetExhausted {
                action: SafetyAction::ExtensionQuarantine,
                requested_ms: 2,
                remaining_ms: 0,
            },
            SafetyRouterError::NoContract {
                action: SafetyAction::ForcedTermination,
            },
            SafetyRouterError::InvalidActionIndex {
                action: SafetyAction::PrivilegeEscalation,
                index: 5,
                max: 2,
            },
        ];
        for e in &errors {
            assert!(
                e.source().is_none(),
                "SafetyRouterError should have no source"
            );
        }
    }

    #[test]
    fn safety_action_ord_consistency() {
        let a = SafetyAction::ExtensionQuarantine;
        let b = SafetyAction::BudgetOverride;
        assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);
        assert_eq!(b.cmp(&b), std::cmp::Ordering::Equal);
        let ab = a.cmp(&b);
        let ba = b.cmp(&a);
        assert_eq!(ab, ba.reverse());
    }

    #[test]
    fn safety_decision_request_zero_boundary_roundtrip() {
        let req = SafetyDecisionRequest {
            action: SafetyAction::ExtensionQuarantine,
            extension_id: "ext-zero".to_string(),
            target_extension_id: None,
            decision_id: decision_id_from_seed(0),
            policy_id: policy_id_from_seed(0),
            ts_unix_ms: 0,
            calibration_score_bps: 0,
            e_process_milli: 0,
            ci_width_milli: 0,
        };
        let json = serde_json::to_string(&req).unwrap();
        let restored: SafetyDecisionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, restored);
    }

    #[test]
    fn router_default_trait_equivalent_to_new() {
        let r1 = SafetyDecisionRouter::new();
        let r2 = SafetyDecisionRouter::default();
        assert_eq!(r1.contract_count(), r2.contract_count());
        assert_eq!(r1.decision_count(), r2.decision_count());
        assert_eq!(r1.deny_count(), r2.deny_count());
        assert_eq!(r1.fallback_count(), r2.fallback_count());
    }
}
