//! Formal/Model-Checked Invariants for Scheduler and Reactivity Core (FRX-05.3)
//!
//! Provides automata-based state-machine models, property specifications,
//! counterexample-to-replay bridges, and composition compatibility checks
//! for formal verification of scheduler correctness.

use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use franken_engine_deterministic_derive::Deterministic;
use franken_engine_deterministic_trait::Deterministic;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

fn invariant_schema() -> SchemaId {
    SchemaId::from_definition(b"scheduler_invariants-v1")
}

// ---------------------------------------------------------------------------
// State machine model
// ---------------------------------------------------------------------------

/// A state in the scheduler state machine.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Deterministic,
)]
pub struct StateId(pub String);

impl StateId {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

/// A transition label (event/action).
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Deterministic,
)]
pub struct TransitionLabel(pub String);

impl TransitionLabel {
    pub fn new(label: impl Into<String>) -> Self {
        Self(label.into())
    }
}

/// A single transition in the automaton.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Deterministic)]
pub struct Transition {
    pub from: StateId,
    pub label: TransitionLabel,
    pub to: StateId,
    /// Guard condition description (human-readable).
    pub guard: Option<String>,
}

/// Finite-state automaton modelling scheduler lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Deterministic)]
pub struct SchedulerAutomaton {
    pub name: String,
    pub states: BTreeSet<StateId>,
    pub initial_state: StateId,
    pub accepting_states: BTreeSet<StateId>,
    pub transitions: Vec<Transition>,
    pub alphabet: BTreeSet<TransitionLabel>,
}

impl SchedulerAutomaton {
    pub fn new(name: impl Into<String>, initial_state: StateId) -> Self {
        let mut states = BTreeSet::new();
        states.insert(initial_state.clone());
        Self {
            name: name.into(),
            states,
            initial_state,
            accepting_states: BTreeSet::new(),
            transitions: Vec::new(),
            alphabet: BTreeSet::new(),
        }
    }

    /// Add a state to the automaton.
    pub fn add_state(&mut self, state: StateId) {
        self.states.insert(state);
    }

    /// Mark a state as accepting.
    pub fn add_accepting(&mut self, state: StateId) {
        self.states.insert(state.clone());
        self.accepting_states.insert(state);
    }

    /// Add a transition.
    pub fn add_transition(&mut self, transition: Transition) {
        self.states.insert(transition.from.clone());
        self.states.insert(transition.to.clone());
        self.alphabet.insert(transition.label.clone());
        self.transitions.push(transition);
    }

    /// Get all transitions from a given state.
    pub fn transitions_from(&self, state: &StateId) -> Vec<&Transition> {
        self.transitions
            .iter()
            .filter(|t| t.from == *state)
            .collect()
    }

    /// Check if a state is reachable from the initial state via BFS.
    pub fn is_reachable(&self, target: &StateId) -> bool {
        let mut visited = BTreeSet::new();
        let mut queue = vec![self.initial_state.clone()];
        while let Some(current) = queue.pop() {
            if current == *target {
                return true;
            }
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());
            for t in self.transitions_from(&current) {
                if !visited.contains(&t.to) {
                    queue.push(t.to.clone());
                }
            }
        }
        false
    }

    /// Find dead states (unreachable from initial).
    pub fn dead_states(&self) -> BTreeSet<StateId> {
        let mut reachable = BTreeSet::new();
        let mut queue = vec![self.initial_state.clone()];
        while let Some(current) = queue.pop() {
            if reachable.contains(&current) {
                continue;
            }
            reachable.insert(current.clone());
            for t in self.transitions_from(&current) {
                if !reachable.contains(&t.to) {
                    queue.push(t.to.clone());
                }
            }
        }
        self.states.difference(&reachable).cloned().collect()
    }

    /// Check determinism: no two transitions from same state share the same label.
    pub fn is_deterministic(&self) -> bool {
        for state in &self.states {
            let outgoing = self.transitions_from(state);
            let labels: BTreeSet<_> = outgoing.iter().map(|t| &t.label).collect();
            if labels.len() != outgoing.len() {
                return false;
            }
        }
        true
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!(
            "automaton-{}-states-{}-transitions-{}",
            self.name,
            self.states.len(),
            self.transitions.len()
        );
        // SAFETY: derive_id cannot fail with valid object domain, zone, schema, and data
        derive_id(
            ObjectDomain::EvidenceRecord,
            "invariants",
            &invariant_schema(),
            canonical.as_bytes(),
        )
        .expect("serde deserialization should succeed")
    }
}

// ---------------------------------------------------------------------------
// Canonical scheduler automata
// ---------------------------------------------------------------------------

/// Build the canonical scheduler lifecycle automaton.
pub fn scheduler_lifecycle_automaton() -> SchedulerAutomaton {
    let mut a = SchedulerAutomaton::new("scheduler-lifecycle", StateId::new("idle"));

    // States
    for s in &[
        "idle",
        "scheduling",
        "executing",
        "flushing",
        "safe_mode",
        "degraded",
        "halted",
        "recovering",
    ] {
        a.add_state(StateId::new(*s));
    }
    a.add_accepting(StateId::new("idle"));
    a.add_accepting(StateId::new("halted"));

    // Transitions
    let transitions = [
        ("idle", "enqueue_update", "scheduling", None),
        ("scheduling", "batch_ready", "executing", None),
        ("scheduling", "budget_exceeded", "safe_mode", None),
        ("executing", "flush_start", "flushing", None),
        ("executing", "error", "safe_mode", None),
        ("flushing", "flush_complete", "idle", None),
        ("flushing", "budget_exceeded", "degraded", None),
        (
            "safe_mode",
            "stabilise",
            "recovering",
            Some("safe_mode_duration > min_stable"),
        ),
        (
            "safe_mode",
            "escalate",
            "halted",
            Some("failover_count > max_failovers"),
        ),
        ("degraded", "stabilise", "recovering", None),
        ("degraded", "escalate", "halted", None),
        ("recovering", "recovery_complete", "idle", None),
        ("recovering", "recovery_failed", "halted", None),
        (
            "halted",
            "operator_reset",
            "idle",
            Some("operator_approval"),
        ),
    ];

    for (from, label, to, guard) in &transitions {
        a.add_transition(Transition {
            from: StateId::new(*from),
            label: TransitionLabel::new(*label),
            to: StateId::new(*to),
            guard: guard.map(|g| g.to_string()),
        });
    }

    a
}

/// Build the fallback transition automaton.
pub fn fallback_transition_automaton() -> SchedulerAutomaton {
    let mut a = SchedulerAutomaton::new("fallback-transitions", StateId::new("adaptive"));

    for s in &["adaptive", "conservative", "safe_fallback", "halted"] {
        a.add_state(StateId::new(*s));
    }
    a.add_accepting(StateId::new("adaptive"));
    a.add_accepting(StateId::new("halted"));

    let transitions = [
        ("adaptive", "change_point", "conservative", None),
        ("adaptive", "conformal_violation", "conservative", None),
        ("adaptive", "regret_exceeded", "conservative", None),
        ("adaptive", "manual_demote", "conservative", None),
        (
            "conservative",
            "promote",
            "adaptive",
            Some("stable_period > threshold"),
        ),
        ("conservative", "budget_exhausted", "safe_fallback", None),
        ("safe_fallback", "stabilise", "conservative", None),
        ("safe_fallback", "escalate", "halted", None),
        ("halted", "operator_reset", "adaptive", None),
    ];

    for (from, label, to, guard) in &transitions {
        a.add_transition(Transition {
            from: StateId::new(*from),
            label: TransitionLabel::new(*label),
            to: StateId::new(*to),
            guard: guard.map(|g| g.to_string()),
        });
    }

    a
}

// ---------------------------------------------------------------------------
// Property specifications
// ---------------------------------------------------------------------------

/// A formal property to verify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertySpec {
    pub id: String,
    pub name: String,
    pub kind: PropertyKind,
    pub description: String,
    /// LTL/CTL formula (human-readable notation).
    pub formula: String,
    /// Components this property applies to.
    pub components: Vec<String>,
}

/// Kind of formal property.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PropertyKind {
    /// Safety: something bad never happens.
    Safety,
    /// Liveness: something good eventually happens.
    Liveness,
    /// Fairness: all lanes eventually get service.
    Fairness,
    /// Determinism: same inputs produce same outputs.
    Determinism,
    /// Composition: controllers don't interfere.
    Composition,
}

impl PropertyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Safety => "safety",
            Self::Liveness => "liveness",
            Self::Fairness => "fairness",
            Self::Determinism => "determinism",
            Self::Composition => "composition",
        }
    }
}

/// Verification result for a property.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    pub property_id: String,
    pub status: VerificationStatus,
    pub counterexample: Option<Counterexample>,
    /// States explored during verification.
    pub states_explored: u64,
    /// Verification time in microseconds.
    pub verification_time_us: u64,
}

/// Status of a verification check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Property holds.
    Verified,
    /// Counterexample found.
    Violated,
    /// Verification timed out / inconclusive.
    Inconclusive,
    /// Verification not yet run.
    Pending,
}

impl VerificationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Violated => "violated",
            Self::Inconclusive => "inconclusive",
            Self::Pending => "pending",
        }
    }
}

impl VerificationResult {
    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("verification-{}-{}", self.property_id, self.status.as_str());
        // SAFETY: derive_id cannot fail with valid object domain, zone, schema, and data
        derive_id(
            ObjectDomain::EvidenceRecord,
            "invariants",
            &invariant_schema(),
            canonical.as_bytes(),
        )
        .expect("serde deserialization should succeed")
    }
}

// ---------------------------------------------------------------------------
// Counterexample and replay bridge
// ---------------------------------------------------------------------------

/// A counterexample trace that violates a property.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counterexample {
    pub property_id: String,
    pub trace: Vec<CounterexampleStep>,
    pub violation_description: String,
}

/// A single step in a counterexample trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterexampleStep {
    pub step: u64,
    pub state: StateId,
    pub action: TransitionLabel,
    pub next_state: StateId,
    /// Key state variables at this step.
    pub state_vars: BTreeMap<String, String>,
}

/// Deterministic regression fixture generated from a counterexample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionFixture {
    pub fixture_id: String,
    pub property_id: String,
    pub description: String,
    /// Sequence of actions to replay.
    pub replay_actions: Vec<TransitionLabel>,
    /// Expected final state.
    pub expected_final_state: StateId,
    /// Whether this fixture is expected to trigger the violation.
    pub expects_violation: bool,
}

impl RegressionFixture {
    /// Generate a regression fixture from a counterexample.
    pub fn from_counterexample(fixture_id: impl Into<String>, cx: &Counterexample) -> Self {
        let actions: Vec<_> = cx.trace.iter().map(|s| s.action.clone()).collect();
        let final_state = cx
            .trace
            .last()
            .map(|s| s.next_state.clone())
            .unwrap_or_else(|| StateId::new("unknown"));

        Self {
            fixture_id: fixture_id.into(),
            property_id: cx.property_id.clone(),
            description: cx.violation_description.clone(),
            replay_actions: actions,
            expected_final_state: final_state,
            expects_violation: true,
        }
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("fixture-{}", self.fixture_id);
        // SAFETY: derive_id cannot fail with valid object domain, zone, schema, and data
        derive_id(
            ObjectDomain::EvidenceRecord,
            "invariants",
            &invariant_schema(),
            canonical.as_bytes(),
        )
        .expect("serde deserialization should succeed")
    }
}

// ---------------------------------------------------------------------------
// Composition compatibility
// ---------------------------------------------------------------------------

/// A controller in the composition model.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ControllerId(pub String);

impl ControllerId {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

/// Shared resource that controllers may contend over.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SharedResource(pub String);

impl SharedResource {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

/// A potential interference between two controllers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterferenceReport {
    pub controller_a: ControllerId,
    pub controller_b: ControllerId,
    pub resource: SharedResource,
    pub severity: InterferenceSeverity,
    pub description: String,
    pub mitigation: Option<String>,
}

/// Severity of controller interference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum InterferenceSeverity {
    /// No interference: controllers are independent.
    None,
    /// Benign: interference does not affect correctness.
    Benign,
    /// Serious: may affect correctness under specific interleavings.
    Serious,
    /// Critical: always affects correctness.
    Critical,
}

impl InterferenceSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Benign => "benign",
            Self::Serious => "serious",
            Self::Critical => "critical",
        }
    }
}

/// Composition compatibility check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionCheck {
    pub controllers: Vec<ControllerId>,
    pub shared_resources: Vec<SharedResource>,
    pub interferences: Vec<InterferenceReport>,
    pub overall_compatible: bool,
}

impl CompositionCheck {
    pub fn new(controllers: Vec<ControllerId>, resources: Vec<SharedResource>) -> Self {
        Self {
            controllers,
            shared_resources: resources,
            interferences: Vec::new(),
            overall_compatible: true,
        }
    }

    pub fn add_interference(&mut self, report: InterferenceReport) {
        if report.severity == InterferenceSeverity::Critical
            || report.severity == InterferenceSeverity::Serious
        {
            self.overall_compatible = false;
        }
        self.interferences.push(report);
    }

    pub fn critical_count(&self) -> usize {
        self.interferences
            .iter()
            .filter(|r| r.severity == InterferenceSeverity::Critical)
            .count()
    }

    pub fn serious_count(&self) -> usize {
        self.interferences
            .iter()
            .filter(|r| r.severity == InterferenceSeverity::Serious)
            .count()
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let ids: Vec<_> = self.controllers.iter().map(|c| c.0.as_str()).collect();
        let canonical = format!("composition-{}", ids.join("-"));
        // SAFETY: derive_id cannot fail with valid object domain, zone, schema, and data
        derive_id(
            ObjectDomain::EvidenceRecord,
            "invariants",
            &invariant_schema(),
            canonical.as_bytes(),
        )
        .expect("serde deserialization should succeed")
    }
}

// ---------------------------------------------------------------------------
// Invariant registry
// ---------------------------------------------------------------------------

/// Registry of all formal properties and their verification status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantRegistry {
    pub properties: Vec<PropertySpec>,
    pub results: BTreeMap<String, VerificationResult>,
    pub fixtures: Vec<RegressionFixture>,
}

impl InvariantRegistry {
    pub fn new() -> Self {
        Self {
            properties: Vec::new(),
            results: BTreeMap::new(),
            fixtures: Vec::new(),
        }
    }

    /// Register a property specification.
    pub fn add_property(&mut self, spec: PropertySpec) {
        self.properties.push(spec);
    }

    /// Record a verification result.
    pub fn record_result(&mut self, result: VerificationResult) {
        if result.status == VerificationStatus::Violated {
            // Auto-generate fixture from counterexample
            if let Some(cx) = &result.counterexample {
                let fixture_id = format!("auto-{}", result.property_id);
                self.fixtures
                    .push(RegressionFixture::from_counterexample(fixture_id, cx));
            }
        }
        self.results.insert(result.property_id.clone(), result);
    }

    /// Get the result for a specific property.
    pub fn get_result(&self, property_id: &str) -> Option<&VerificationResult> {
        self.results.get(property_id)
    }

    /// Count of verified properties.
    pub fn verified_count(&self) -> usize {
        self.results
            .values()
            .filter(|r| r.status == VerificationStatus::Verified)
            .count()
    }

    /// Count of violated properties.
    pub fn violated_count(&self) -> usize {
        self.results
            .values()
            .filter(|r| r.status == VerificationStatus::Violated)
            .count()
    }

    /// Overall status: all verified, any violated, or mixed.
    pub fn overall_status(&self) -> VerificationStatus {
        if self.results.is_empty() {
            return VerificationStatus::Pending;
        }
        if self
            .results
            .values()
            .any(|r| r.status == VerificationStatus::Violated)
        {
            return VerificationStatus::Violated;
        }
        if self
            .results
            .values()
            .all(|r| r.status == VerificationStatus::Verified)
        {
            return VerificationStatus::Verified;
        }
        VerificationStatus::Inconclusive
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!(
            "registry-props-{}-results-{}-fixtures-{}",
            self.properties.len(),
            self.results.len(),
            self.fixtures.len()
        );
        // SAFETY: derive_id cannot fail with valid object domain, zone, schema, and data
        derive_id(
            ObjectDomain::EvidenceRecord,
            "invariants",
            &invariant_schema(),
            canonical.as_bytes(),
        )
        .expect("serde deserialization should succeed")
    }
}

impl Default for InvariantRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the canonical set of scheduler invariant properties.
pub fn canonical_scheduler_properties() -> Vec<PropertySpec> {
    vec![
        PropertySpec {
            id: "P-SAFETY-01".to_string(),
            name: "No-Glitch Signal Propagation".to_string(),
            kind: PropertyKind::Safety,
            description: "A derived signal is never observed in a partially-updated state during a flush cycle.".to_string(),
            formula: "G(flush_in_progress -> !partial_observation)".to_string(),
            components: vec!["signal_graph".to_string(), "scheduler".to_string()],
        },
        PropertySpec {
            id: "P-SAFETY-02".to_string(),
            name: "Effect Ordering Invariant".to_string(),
            kind: PropertyKind::Safety,
            description: "Effects execute in topological dependency order within a flush cycle.".to_string(),
            formula: "G(effect_a depends_on effect_b -> effect_b.eval_time < effect_a.eval_time)".to_string(),
            components: vec!["effect_scheduler".to_string()],
        },
        PropertySpec {
            id: "P-SAFETY-03".to_string(),
            name: "Fallback Monotonicity".to_string(),
            kind: PropertyKind::Safety,
            description: "The fallback transition sequence is monotonically degrading: adaptive -> conservative -> safe -> halted.".to_string(),
            formula: "G(severity(next_state) >= severity(current_state) || is_recovery_transition)".to_string(),
            components: vec!["hybrid_router".to_string(), "failover_controller".to_string()],
        },
        PropertySpec {
            id: "P-LIVENESS-01".to_string(),
            name: "Eventual Flush Progress".to_string(),
            kind: PropertyKind::Liveness,
            description: "If updates are enqueued, a flush eventually occurs.".to_string(),
            formula: "G(update_enqueued -> F(flush_complete))".to_string(),
            components: vec!["scheduler".to_string()],
        },
        PropertySpec {
            id: "P-LIVENESS-02".to_string(),
            name: "Recovery Eventually Completes".to_string(),
            kind: PropertyKind::Liveness,
            description: "If the system enters recovery, it eventually reaches either idle or halted.".to_string(),
            formula: "G(recovering -> F(idle || halted))".to_string(),
            components: vec!["failover_controller".to_string()],
        },
        PropertySpec {
            id: "P-FAIRNESS-01".to_string(),
            name: "Lane Selection Fairness".to_string(),
            kind: PropertyKind::Fairness,
            description: "Under adaptive policy, both lanes receive non-zero selection probability.".to_string(),
            formula: "G(adaptive_mode -> prob(js) > 0 && prob(wasm) > 0)".to_string(),
            components: vec!["hybrid_router".to_string()],
        },
        PropertySpec {
            id: "P-DETERM-01".to_string(),
            name: "Deterministic Replay Fidelity".to_string(),
            kind: PropertyKind::Determinism,
            description: "Given identical nondeterminism trace, replay produces identical state sequence.".to_string(),
            formula: "trace1 == trace2 -> state_sequence1 == state_sequence2".to_string(),
            components: vec!["replay_engine".to_string()],
        },
        PropertySpec {
            id: "P-COMP-01".to_string(),
            name: "Router-Optimizer Non-Interference".to_string(),
            kind: PropertyKind::Composition,
            description: "Router lane selection and optimizer budget allocation do not produce deadlock or livelock.".to_string(),
            formula: "!EF(deadlock || livelock)".to_string(),
            components: vec!["hybrid_router".to_string(), "opportunity_matrix".to_string()],
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- SchedulerAutomaton --

    #[test]
    fn automaton_new() {
        let a = SchedulerAutomaton::new("test", StateId::new("init"));
        assert_eq!(a.states.len(), 1);
        assert!(a.transitions.is_empty());
    }

    #[test]
    fn automaton_add_transition() {
        let mut a = SchedulerAutomaton::new("test", StateId::new("s0"));
        a.add_transition(Transition {
            from: StateId::new("s0"),
            label: TransitionLabel::new("go"),
            to: StateId::new("s1"),
            guard: None,
        });
        assert_eq!(a.states.len(), 2);
        assert_eq!(a.transitions.len(), 1);
        assert!(a.alphabet.contains(&TransitionLabel::new("go")));
    }

    #[test]
    fn automaton_transitions_from() {
        let mut a = SchedulerAutomaton::new("test", StateId::new("s0"));
        a.add_transition(Transition {
            from: StateId::new("s0"),
            label: TransitionLabel::new("a"),
            to: StateId::new("s1"),
            guard: None,
        });
        a.add_transition(Transition {
            from: StateId::new("s0"),
            label: TransitionLabel::new("b"),
            to: StateId::new("s2"),
            guard: None,
        });
        a.add_transition(Transition {
            from: StateId::new("s1"),
            label: TransitionLabel::new("c"),
            to: StateId::new("s2"),
            guard: None,
        });

        let from_s0 = a.transitions_from(&StateId::new("s0"));
        assert_eq!(from_s0.len(), 2);
    }

    #[test]
    fn automaton_reachability() {
        let mut a = SchedulerAutomaton::new("test", StateId::new("s0"));
        a.add_transition(Transition {
            from: StateId::new("s0"),
            label: TransitionLabel::new("go"),
            to: StateId::new("s1"),
            guard: None,
        });
        a.add_state(StateId::new("s_unreachable"));

        assert!(a.is_reachable(&StateId::new("s0")));
        assert!(a.is_reachable(&StateId::new("s1")));
        assert!(!a.is_reachable(&StateId::new("s_unreachable")));
    }

    #[test]
    fn automaton_dead_states() {
        let mut a = SchedulerAutomaton::new("test", StateId::new("s0"));
        a.add_transition(Transition {
            from: StateId::new("s0"),
            label: TransitionLabel::new("go"),
            to: StateId::new("s1"),
            guard: None,
        });
        a.add_state(StateId::new("dead"));
        let dead = a.dead_states();
        assert_eq!(dead.len(), 1);
        assert!(dead.contains(&StateId::new("dead")));
    }

    #[test]
    fn automaton_deterministic() {
        let mut a = SchedulerAutomaton::new("test", StateId::new("s0"));
        a.add_transition(Transition {
            from: StateId::new("s0"),
            label: TransitionLabel::new("a"),
            to: StateId::new("s1"),
            guard: None,
        });
        a.add_transition(Transition {
            from: StateId::new("s0"),
            label: TransitionLabel::new("b"),
            to: StateId::new("s2"),
            guard: None,
        });
        assert!(a.is_deterministic());
    }

    #[test]
    fn automaton_nondeterministic() {
        let mut a = SchedulerAutomaton::new("test", StateId::new("s0"));
        a.add_transition(Transition {
            from: StateId::new("s0"),
            label: TransitionLabel::new("a"),
            to: StateId::new("s1"),
            guard: None,
        });
        a.add_transition(Transition {
            from: StateId::new("s0"),
            label: TransitionLabel::new("a"),
            to: StateId::new("s2"),
            guard: None,
        });
        assert!(!a.is_deterministic());
    }

    #[test]
    fn automaton_derive_id_stable() {
        let a1 = SchedulerAutomaton::new("test", StateId::new("s0"));
        let a2 = SchedulerAutomaton::new("test", StateId::new("s0"));
        assert_eq!(a1.derive_id(), a2.derive_id());
    }

    #[test]
    fn automaton_serde_roundtrip() {
        let mut a = SchedulerAutomaton::new("test", StateId::new("s0"));
        a.add_transition(Transition {
            from: StateId::new("s0"),
            label: TransitionLabel::new("go"),
            to: StateId::new("s1"),
            guard: Some("x > 0".to_string()),
        });
        // SAFETY: SchedulerAutomaton derives Serialize and has no non-serializable fields.
        let json = serde_json::to_string(&a).expect("serialize derived Serialize");
        // SAFETY: JSON was just produced by valid SchedulerAutomaton serialization.
        let back: SchedulerAutomaton =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(a, back);
    }

    // -- Canonical automata --

    #[test]
    fn scheduler_lifecycle_no_dead_states() {
        let a = scheduler_lifecycle_automaton();
        let dead = a.dead_states();
        assert!(dead.is_empty(), "dead states found: {dead:?}");
    }

    #[test]
    fn scheduler_lifecycle_all_states_reachable() {
        let a = scheduler_lifecycle_automaton();
        for state in &a.states {
            assert!(a.is_reachable(state), "state {state:?} is unreachable");
        }
    }

    #[test]
    fn scheduler_lifecycle_is_deterministic() {
        let a = scheduler_lifecycle_automaton();
        assert!(a.is_deterministic());
    }

    #[test]
    fn scheduler_lifecycle_has_accepting_states() {
        let a = scheduler_lifecycle_automaton();
        assert!(!a.accepting_states.is_empty());
    }

    #[test]
    fn fallback_automaton_no_dead_states() {
        let a = fallback_transition_automaton();
        let dead = a.dead_states();
        assert!(dead.is_empty(), "dead states: {dead:?}");
    }

    #[test]
    fn fallback_automaton_all_reachable() {
        let a = fallback_transition_automaton();
        for state in &a.states {
            assert!(a.is_reachable(state), "state {state:?} unreachable");
        }
    }

    #[test]
    fn fallback_automaton_deterministic() {
        let a = fallback_transition_automaton();
        assert!(a.is_deterministic());
    }

    // -- PropertySpec --

    #[test]
    fn property_kind_as_str() {
        let kinds = [
            PropertyKind::Safety,
            PropertyKind::Liveness,
            PropertyKind::Fairness,
            PropertyKind::Determinism,
            PropertyKind::Composition,
        ];
        for k in &kinds {
            assert!(!k.as_str().is_empty());
        }
    }

    #[test]
    fn canonical_properties_not_empty() {
        let props = canonical_scheduler_properties();
        assert!(props.len() >= 8);
    }

    #[test]
    fn canonical_properties_all_kinds_covered() {
        let props = canonical_scheduler_properties();
        let kinds: BTreeSet<_> = props.iter().map(|p| p.kind).collect();
        assert!(kinds.contains(&PropertyKind::Safety));
        assert!(kinds.contains(&PropertyKind::Liveness));
        assert!(kinds.contains(&PropertyKind::Fairness));
        assert!(kinds.contains(&PropertyKind::Determinism));
        assert!(kinds.contains(&PropertyKind::Composition));
    }

    // -- VerificationResult --

    #[test]
    fn verification_result_derive_id() {
        let r = VerificationResult {
            property_id: "P-SAFETY-01".to_string(),
            status: VerificationStatus::Verified,
            counterexample: None,
            states_explored: 1000,
            verification_time_us: 5000,
        };
        let id1 = r.derive_id();
        let id2 = r.derive_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn verification_status_serde() {
        for s in [
            VerificationStatus::Verified,
            VerificationStatus::Violated,
            VerificationStatus::Inconclusive,
            VerificationStatus::Pending,
        ] {
            // SAFETY: VerificationStatus derives Serialize and has no non-serializable fields.
            let json = serde_json::to_string(&s).expect("serialize derived Serialize");
            // SAFETY: JSON was just produced by valid VerificationStatus serialization.
            let back: VerificationStatus =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(s, back);
        }
    }

    // -- Counterexample / RegressionFixture --

    #[test]
    fn counterexample_to_fixture() {
        let cx = Counterexample {
            property_id: "P-SAFETY-01".to_string(),
            trace: vec![
                CounterexampleStep {
                    step: 0,
                    state: StateId::new("idle"),
                    action: TransitionLabel::new("enqueue_update"),
                    next_state: StateId::new("scheduling"),
                    state_vars: BTreeMap::new(),
                },
                CounterexampleStep {
                    step: 1,
                    state: StateId::new("scheduling"),
                    action: TransitionLabel::new("budget_exceeded"),
                    next_state: StateId::new("safe_mode"),
                    state_vars: BTreeMap::new(),
                },
            ],
            violation_description: "Signal observed in partial state".to_string(),
        };

        let fixture = RegressionFixture::from_counterexample("fix-001", &cx);
        assert_eq!(fixture.property_id, "P-SAFETY-01");
        assert_eq!(fixture.replay_actions.len(), 2);
        assert_eq!(fixture.expected_final_state, StateId::new("safe_mode"));
        assert!(fixture.expects_violation);
    }

    #[test]
    fn fixture_derive_id() {
        let fixture = RegressionFixture {
            fixture_id: "fix-001".to_string(),
            property_id: "P-SAFETY-01".to_string(),
            description: "test".to_string(),
            replay_actions: vec![],
            expected_final_state: StateId::new("idle"),
            expects_violation: false,
        };
        let id1 = fixture.derive_id();
        let id2 = fixture.derive_id();
        assert_eq!(id1, id2);
    }

    // -- CompositionCheck --

    #[test]
    fn composition_check_compatible() {
        let check = CompositionCheck::new(
            vec![ControllerId::new("router"), ControllerId::new("optimizer")],
            vec![SharedResource::new("signal_graph")],
        );
        assert!(check.overall_compatible);
        assert_eq!(check.critical_count(), 0);
    }

    #[test]
    fn composition_check_interference() {
        let mut check = CompositionCheck::new(
            vec![ControllerId::new("router"), ControllerId::new("optimizer")],
            vec![SharedResource::new("lane_budget")],
        );
        check.add_interference(InterferenceReport {
            controller_a: ControllerId::new("router"),
            controller_b: ControllerId::new("optimizer"),
            resource: SharedResource::new("lane_budget"),
            severity: InterferenceSeverity::Critical,
            description: "Both controllers modify budget concurrently".to_string(),
            mitigation: Some("Add budget lock".to_string()),
        });
        assert!(!check.overall_compatible);
        assert_eq!(check.critical_count(), 1);
    }

    #[test]
    fn composition_benign_stays_compatible() {
        let mut check = CompositionCheck::new(
            vec![ControllerId::new("a"), ControllerId::new("b")],
            vec![SharedResource::new("metrics")],
        );
        check.add_interference(InterferenceReport {
            controller_a: ControllerId::new("a"),
            controller_b: ControllerId::new("b"),
            resource: SharedResource::new("metrics"),
            severity: InterferenceSeverity::Benign,
            description: "Both read metrics, no write contention".to_string(),
            mitigation: None,
        });
        assert!(check.overall_compatible);
    }

    #[test]
    fn composition_derive_id() {
        let c = CompositionCheck::new(vec![ControllerId::new("a"), ControllerId::new("b")], vec![]);
        let id1 = c.derive_id();
        let id2 = c.derive_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn interference_severity_serde() {
        for s in [
            InterferenceSeverity::None,
            InterferenceSeverity::Benign,
            InterferenceSeverity::Serious,
            InterferenceSeverity::Critical,
        ] {
            // SAFETY: to_string cannot fail on derived Serialize enum
            let json = serde_json::to_string(&s).expect("serialize derived Serialize");
            // SAFETY: from_str cannot fail on valid JSON from to_string roundtrip
            let back: InterferenceSeverity =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(s, back);
        }
    }

    // -- InvariantRegistry --

    #[test]
    fn registry_new_empty() {
        let reg = InvariantRegistry::new();
        assert_eq!(reg.verified_count(), 0);
        assert_eq!(reg.violated_count(), 0);
        assert_eq!(reg.overall_status(), VerificationStatus::Pending);
    }

    #[test]
    fn registry_all_verified() {
        let mut reg = InvariantRegistry::new();
        reg.add_property(PropertySpec {
            id: "P1".to_string(),
            name: "Test".to_string(),
            kind: PropertyKind::Safety,
            description: "test".to_string(),
            formula: "G(true)".to_string(),
            components: vec![],
        });
        reg.record_result(VerificationResult {
            property_id: "P1".to_string(),
            status: VerificationStatus::Verified,
            counterexample: None,
            states_explored: 100,
            verification_time_us: 500,
        });
        assert_eq!(reg.overall_status(), VerificationStatus::Verified);
    }

    #[test]
    fn registry_any_violated() {
        let mut reg = InvariantRegistry::new();
        reg.record_result(VerificationResult {
            property_id: "P1".to_string(),
            status: VerificationStatus::Verified,
            counterexample: None,
            states_explored: 100,
            verification_time_us: 500,
        });
        reg.record_result(VerificationResult {
            property_id: "P2".to_string(),
            status: VerificationStatus::Violated,
            counterexample: Some(Counterexample {
                property_id: "P2".to_string(),
                trace: vec![],
                violation_description: "violation".to_string(),
            }),
            states_explored: 200,
            verification_time_us: 1000,
        });
        assert_eq!(reg.overall_status(), VerificationStatus::Violated);
        assert_eq!(reg.violated_count(), 1);
        assert_eq!(reg.fixtures.len(), 1); // empty trace -> no fixture steps, but fixture still created
    }

    #[test]
    fn registry_auto_fixture_from_counterexample() {
        let mut reg = InvariantRegistry::new();
        reg.record_result(VerificationResult {
            property_id: "P3".to_string(),
            status: VerificationStatus::Violated,
            counterexample: Some(Counterexample {
                property_id: "P3".to_string(),
                trace: vec![CounterexampleStep {
                    step: 0,
                    state: StateId::new("idle"),
                    action: TransitionLabel::new("fail"),
                    next_state: StateId::new("halted"),
                    state_vars: BTreeMap::new(),
                }],
                violation_description: "test violation".to_string(),
            }),
            states_explored: 50,
            verification_time_us: 200,
        });
        assert_eq!(reg.fixtures.len(), 1);
        assert_eq!(reg.fixtures[0].property_id, "P3");
    }

    #[test]
    fn registry_derive_id_stable() {
        let r1 = InvariantRegistry::new();
        let r2 = InvariantRegistry::new();
        assert_eq!(r1.derive_id(), r2.derive_id());
    }

    #[test]
    fn registry_serde_roundtrip() {
        let mut reg = InvariantRegistry::new();
        for prop in canonical_scheduler_properties() {
            reg.add_property(prop);
        }
        // SAFETY: to_string cannot fail on derived Serialize struct
        let json = serde_json::to_string(&reg).expect("serialize derived Serialize");
        // SAFETY: from_str cannot fail on valid JSON from to_string roundtrip
        let back: InvariantRegistry =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(reg, back);
    }

    // -- E2E --

    #[test]
    fn e2e_model_check_pipeline() {
        // 1. Build canonical automata
        let lifecycle = scheduler_lifecycle_automaton();
        let fallback = fallback_transition_automaton();

        // 2. Verify structural properties
        assert!(lifecycle.dead_states().is_empty());
        assert!(lifecycle.is_deterministic());
        assert!(fallback.dead_states().is_empty());

        // 3. Build property registry
        let mut registry = InvariantRegistry::new();
        for prop in canonical_scheduler_properties() {
            registry.add_property(prop);
        }

        // 4. Simulate verification of all properties
        for prop in &registry.properties.clone() {
            registry.record_result(VerificationResult {
                property_id: prop.id.clone(),
                status: VerificationStatus::Verified,
                counterexample: None,
                states_explored: 500,
                verification_time_us: 1000,
            });
        }

        assert_eq!(registry.overall_status(), VerificationStatus::Verified);
        assert_eq!(registry.verified_count(), 8);
        assert_eq!(registry.violated_count(), 0);

        // 5. Composition check
        let mut comp = CompositionCheck::new(
            vec![
                ControllerId::new("hybrid_router"),
                ControllerId::new("failover_controller"),
                ControllerId::new("opportunity_matrix"),
            ],
            vec![
                SharedResource::new("lane_selection"),
                SharedResource::new("budget"),
            ],
        );
        comp.add_interference(InterferenceReport {
            controller_a: ControllerId::new("hybrid_router"),
            controller_b: ControllerId::new("failover_controller"),
            resource: SharedResource::new("lane_selection"),
            severity: InterferenceSeverity::Benign,
            description: "Router defers to failover during safe mode".to_string(),
            mitigation: None,
        });
        assert!(comp.overall_compatible);
    }

    // -- Enrichment: additional coverage --

    #[test]
    fn property_kind_as_str_uniqueness() {
        let kinds = [
            PropertyKind::Safety,
            PropertyKind::Liveness,
            PropertyKind::Fairness,
            PropertyKind::Determinism,
            PropertyKind::Composition,
        ];
        let strs: BTreeSet<&str> = kinds.iter().map(|k| k.as_str()).collect();
        assert_eq!(
            strs.len(),
            5,
            "all PropertyKind::as_str values must be unique"
        );
    }

    #[test]
    fn verification_status_as_str_uniqueness() {
        let statuses = [
            VerificationStatus::Verified,
            VerificationStatus::Violated,
            VerificationStatus::Inconclusive,
            VerificationStatus::Pending,
        ];
        let strs: BTreeSet<&str> = statuses.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            strs.len(),
            4,
            "all VerificationStatus::as_str values must be unique"
        );
    }

    #[test]
    fn interference_severity_as_str_uniqueness() {
        let severities = [
            InterferenceSeverity::None,
            InterferenceSeverity::Benign,
            InterferenceSeverity::Serious,
            InterferenceSeverity::Critical,
        ];
        let strs: BTreeSet<&str> = severities.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            strs.len(),
            4,
            "all InterferenceSeverity::as_str values must be unique"
        );
    }

    #[test]
    fn transitions_from_empty_state() {
        let a = SchedulerAutomaton::new("test", StateId::new("s0"));
        let from_nonexistent = a.transitions_from(&StateId::new("nonexistent"));
        assert!(from_nonexistent.is_empty());
    }

    #[test]
    fn is_reachable_initial_state_always_true() {
        let a = SchedulerAutomaton::new("test", StateId::new("init"));
        assert!(a.is_reachable(&StateId::new("init")));
    }

    #[test]
    fn state_id_serde_roundtrip() {
        let s = StateId::new("test-state");
        // SAFETY: to_string cannot fail on derived Serialize struct
        let json = serde_json::to_string(&s).expect("serialize derived Serialize");
        // SAFETY: from_str cannot fail on valid JSON from to_string roundtrip
        let back: StateId = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(s, back);
    }

    #[test]
    fn transition_label_serde_roundtrip() {
        let t = TransitionLabel::new("go");
        // SAFETY: to_string cannot fail on derived Serialize struct
        let json = serde_json::to_string(&t).expect("serialize derived Serialize");
        // SAFETY: from_str cannot fail on valid JSON from to_string roundtrip
        let back: TransitionLabel =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(t, back);
    }

    #[test]
    fn counterexample_empty_trace_fixture_unknown_state() {
        let cx = Counterexample {
            property_id: "P-EMPTY".to_string(),
            trace: vec![],
            violation_description: "empty trace".to_string(),
        };
        let fixture = RegressionFixture::from_counterexample("fix-empty", &cx);
        assert_eq!(fixture.expected_final_state, StateId::new("unknown"));
        assert!(fixture.replay_actions.is_empty());
        assert!(fixture.expects_violation);
    }

    #[test]
    fn registry_get_result_existing() {
        let mut reg = InvariantRegistry::new();
        reg.record_result(VerificationResult {
            property_id: "P1".to_string(),
            status: VerificationStatus::Verified,
            counterexample: None,
            states_explored: 100,
            verification_time_us: 500,
        });
        assert!(reg.get_result("P1").is_some());
        assert_eq!(
            // SAFETY: Test-only unwrap, verified above that get_result("P1") returns Some
            reg.get_result("P1")
                .expect("serde deserialization should succeed")
                .status,
            VerificationStatus::Verified
        );
    }

    #[test]
    fn registry_get_result_missing() {
        let reg = InvariantRegistry::new();
        assert!(reg.get_result("P-MISSING").is_none());
    }

    #[test]
    fn composition_serious_count() {
        let mut check = CompositionCheck::new(
            vec![ControllerId::new("a"), ControllerId::new("b")],
            vec![SharedResource::new("res")],
        );
        check.add_interference(InterferenceReport {
            controller_a: ControllerId::new("a"),
            controller_b: ControllerId::new("b"),
            resource: SharedResource::new("res"),
            severity: InterferenceSeverity::Serious,
            description: "May cause starvation under load".to_string(),
            mitigation: Some("Add backoff".to_string()),
        });
        assert_eq!(check.serious_count(), 1);
        assert_eq!(check.critical_count(), 0);
        assert!(!check.overall_compatible);
    }

    #[test]
    fn scheduler_lifecycle_accepting_states_are_idle_and_halted() {
        let a = scheduler_lifecycle_automaton();
        assert!(a.accepting_states.contains(&StateId::new("idle")));
        assert!(a.accepting_states.contains(&StateId::new("halted")));
        assert_eq!(a.accepting_states.len(), 2);
    }

    #[test]
    fn registry_overall_status_inconclusive_for_mixed() {
        let mut reg = InvariantRegistry::new();
        reg.record_result(VerificationResult {
            property_id: "P1".to_string(),
            status: VerificationStatus::Verified,
            counterexample: None,
            states_explored: 100,
            verification_time_us: 500,
        });
        reg.record_result(VerificationResult {
            property_id: "P2".to_string(),
            status: VerificationStatus::Inconclusive,
            counterexample: None,
            states_explored: 100,
            verification_time_us: 5000,
        });
        assert_eq!(reg.overall_status(), VerificationStatus::Inconclusive);
    }

    #[test]
    fn invariant_registry_default_is_new() {
        let default_reg = InvariantRegistry::default();
        let new_reg = InvariantRegistry::new();
        assert_eq!(default_reg, new_reg);
    }

    // -- Enrichment: ordering, serde, edge cases --

    #[test]
    fn state_id_ordering() {
        let a = StateId::new("alpha");
        let b = StateId::new("beta");
        let c = StateId::new("alpha");
        assert!(a < b);
        assert_eq!(a, c);
        assert!(b > a);
    }

    #[test]
    fn transition_label_ordering() {
        let a = TransitionLabel::new("activate");
        let b = TransitionLabel::new("deactivate");
        assert!(a < b);
    }

    #[test]
    fn transition_serde_none_guard() {
        let t = Transition {
            from: StateId::new("s0"),
            label: TransitionLabel::new("go"),
            to: StateId::new("s1"),
            guard: None,
        };
        // SAFETY: to_string cannot fail on derived Serialize struct
        let json = serde_json::to_string(&t).expect("serialize derived Serialize");
        // SAFETY: from_str cannot fail on valid JSON from to_string roundtrip
        let back: Transition = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(t, back);
        assert!(back.guard.is_none());
    }

    #[test]
    fn transition_serde_with_guard() {
        let t = Transition {
            from: StateId::new("s0"),
            label: TransitionLabel::new("go"),
            to: StateId::new("s1"),
            guard: Some("x > 0".to_string()),
        };
        // SAFETY: to_string cannot fail on derived Serialize struct
        let json = serde_json::to_string(&t).expect("serialize derived Serialize");
        // SAFETY: from_str cannot fail on valid JSON from to_string roundtrip
        let back: Transition = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(t, back);
        assert_eq!(back.guard, Some("x > 0".to_string()));
    }

    #[test]
    fn add_accepting_also_adds_to_states() {
        let mut a = SchedulerAutomaton::new("test", StateId::new("s0"));
        a.add_accepting(StateId::new("s_new"));
        assert!(a.states.contains(&StateId::new("s_new")));
        assert!(a.accepting_states.contains(&StateId::new("s_new")));
    }

    #[test]
    fn is_deterministic_no_transitions() {
        let a = SchedulerAutomaton::new("test", StateId::new("s0"));
        assert!(a.is_deterministic());
    }

    #[test]
    fn dead_states_all_reachable() {
        let mut a = SchedulerAutomaton::new("test", StateId::new("s0"));
        a.add_transition(Transition {
            from: StateId::new("s0"),
            label: TransitionLabel::new("go"),
            to: StateId::new("s1"),
            guard: None,
        });
        assert!(a.dead_states().is_empty());
    }

    #[test]
    fn automaton_derive_id_differs_by_structure() {
        let a1 = SchedulerAutomaton::new("test", StateId::new("s0"));
        let mut a2 = SchedulerAutomaton::new("test", StateId::new("s0"));
        a2.add_state(StateId::new("s1"));
        assert_ne!(a1.derive_id(), a2.derive_id());
    }

    #[test]
    fn automaton_derive_id_differs_by_name() {
        let a1 = SchedulerAutomaton::new("alpha", StateId::new("s0"));
        let a2 = SchedulerAutomaton::new("beta", StateId::new("s0"));
        assert_ne!(a1.derive_id(), a2.derive_id());
    }

    #[test]
    fn property_kind_serde_roundtrip() {
        for k in [
            PropertyKind::Safety,
            PropertyKind::Liveness,
            PropertyKind::Fairness,
            PropertyKind::Determinism,
            PropertyKind::Composition,
        ] {
            let json = serde_json::to_string(&k).expect("serialize derived Serialize");
            let back: PropertyKind =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(k, back);
        }
    }

    #[test]
    fn property_kind_as_str_values() {
        assert_eq!(PropertyKind::Safety.as_str(), "safety");
        assert_eq!(PropertyKind::Liveness.as_str(), "liveness");
        assert_eq!(PropertyKind::Fairness.as_str(), "fairness");
        assert_eq!(PropertyKind::Determinism.as_str(), "determinism");
        assert_eq!(PropertyKind::Composition.as_str(), "composition");
    }

    #[test]
    fn verification_status_as_str_values() {
        assert_eq!(VerificationStatus::Verified.as_str(), "verified");
        assert_eq!(VerificationStatus::Violated.as_str(), "violated");
        assert_eq!(VerificationStatus::Inconclusive.as_str(), "inconclusive");
        assert_eq!(VerificationStatus::Pending.as_str(), "pending");
    }

    #[test]
    fn verification_status_ordering() {
        assert!(VerificationStatus::Verified < VerificationStatus::Violated);
        assert!(VerificationStatus::Violated < VerificationStatus::Inconclusive);
        assert!(VerificationStatus::Inconclusive < VerificationStatus::Pending);
    }

    #[test]
    fn interference_severity_as_str_values() {
        assert_eq!(InterferenceSeverity::None.as_str(), "none");
        assert_eq!(InterferenceSeverity::Benign.as_str(), "benign");
        assert_eq!(InterferenceSeverity::Serious.as_str(), "serious");
        assert_eq!(InterferenceSeverity::Critical.as_str(), "critical");
    }

    #[test]
    fn interference_severity_ordering() {
        assert!(InterferenceSeverity::None < InterferenceSeverity::Benign);
        assert!(InterferenceSeverity::Benign < InterferenceSeverity::Serious);
        assert!(InterferenceSeverity::Serious < InterferenceSeverity::Critical);
    }

    #[test]
    fn verification_result_serde_roundtrip() {
        let r = VerificationResult {
            property_id: "P-SAFETY-01".to_string(),
            status: VerificationStatus::Violated,
            counterexample: Some(Counterexample {
                property_id: "P-SAFETY-01".to_string(),
                trace: vec![CounterexampleStep {
                    step: 0,
                    state: StateId::new("idle"),
                    action: TransitionLabel::new("go"),
                    next_state: StateId::new("halted"),
                    state_vars: BTreeMap::from([("x".to_string(), "1".to_string())]),
                }],
                violation_description: "test".to_string(),
            }),
            states_explored: 1000,
            verification_time_us: 5000,
        };
        let json = serde_json::to_string(&r).expect("serialize derived Serialize");
        let back: VerificationResult =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(r, back);
    }

    #[test]
    fn property_spec_serde_roundtrip() {
        let spec = PropertySpec {
            id: "P1".to_string(),
            name: "Test Prop".to_string(),
            kind: PropertyKind::Safety,
            description: "test".to_string(),
            formula: "G(true)".to_string(),
            components: vec!["scheduler".to_string()],
        };
        let json = serde_json::to_string(&spec).expect("serialize derived Serialize");
        let back: PropertySpec = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(spec, back);
    }

    #[test]
    fn counterexample_serde_roundtrip() {
        let cx = Counterexample {
            property_id: "P1".to_string(),
            trace: vec![CounterexampleStep {
                step: 0,
                state: StateId::new("a"),
                action: TransitionLabel::new("go"),
                next_state: StateId::new("b"),
                state_vars: BTreeMap::new(),
            }],
            violation_description: "test violation".to_string(),
        };
        let json = serde_json::to_string(&cx).expect("serialize derived Serialize");
        let back: Counterexample =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(cx, back);
    }

    #[test]
    fn counterexample_step_with_state_vars() {
        let step = CounterexampleStep {
            step: 3,
            state: StateId::new("executing"),
            action: TransitionLabel::new("budget_exceeded"),
            next_state: StateId::new("safe_mode"),
            state_vars: BTreeMap::from([
                ("budget_remaining".to_string(), "0".to_string()),
                ("lane_active".to_string(), "js".to_string()),
            ]),
        };
        let json = serde_json::to_string(&step).expect("serialize derived Serialize");
        let back: CounterexampleStep =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(step, back);
        assert_eq!(back.state_vars.len(), 2);
    }

    #[test]
    fn regression_fixture_serde_roundtrip() {
        let fixture = RegressionFixture {
            fixture_id: "fix-001".to_string(),
            property_id: "P1".to_string(),
            description: "test".to_string(),
            replay_actions: vec![TransitionLabel::new("go"), TransitionLabel::new("stop")],
            expected_final_state: StateId::new("halted"),
            expects_violation: true,
        };
        let json = serde_json::to_string(&fixture).expect("serialize derived Serialize");
        let back: RegressionFixture =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(fixture, back);
    }

    #[test]
    fn interference_report_serde_roundtrip() {
        let report = InterferenceReport {
            controller_a: ControllerId::new("router"),
            controller_b: ControllerId::new("optimizer"),
            resource: SharedResource::new("budget"),
            severity: InterferenceSeverity::Serious,
            description: "both modify budget".to_string(),
            mitigation: Some("add lock".to_string()),
        };
        let json = serde_json::to_string(&report).expect("serialize derived Serialize");
        let back: InterferenceReport =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(report, back);
    }

    #[test]
    fn controller_id_serde_roundtrip() {
        let id = ControllerId::new("hybrid_router");
        let json = serde_json::to_string(&id).expect("serialize derived Serialize");
        let back: ControllerId = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(id, back);
    }

    #[test]
    fn controller_id_ordering() {
        let a = ControllerId::new("alpha");
        let b = ControllerId::new("beta");
        assert!(a < b);
    }

    #[test]
    fn shared_resource_serde_roundtrip() {
        let r = SharedResource::new("signal_graph");
        let json = serde_json::to_string(&r).expect("serialize derived Serialize");
        let back: SharedResource =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(r, back);
    }

    #[test]
    fn shared_resource_ordering() {
        let a = SharedResource::new("budget");
        let b = SharedResource::new("signal_graph");
        assert!(a < b);
    }

    #[test]
    fn composition_none_severity_stays_compatible() {
        let mut check = CompositionCheck::new(
            vec![ControllerId::new("a"), ControllerId::new("b")],
            vec![SharedResource::new("res")],
        );
        check.add_interference(InterferenceReport {
            controller_a: ControllerId::new("a"),
            controller_b: ControllerId::new("b"),
            resource: SharedResource::new("res"),
            severity: InterferenceSeverity::None,
            description: "Controllers are fully independent".to_string(),
            mitigation: None,
        });
        assert!(check.overall_compatible);
        assert_eq!(check.critical_count(), 0);
        assert_eq!(check.serious_count(), 0);
    }

    #[test]
    fn composition_serde_roundtrip() {
        let mut check = CompositionCheck::new(
            vec![ControllerId::new("a"), ControllerId::new("b")],
            vec![SharedResource::new("r1")],
        );
        check.add_interference(InterferenceReport {
            controller_a: ControllerId::new("a"),
            controller_b: ControllerId::new("b"),
            resource: SharedResource::new("r1"),
            severity: InterferenceSeverity::Benign,
            description: "benign".to_string(),
            mitigation: None,
        });
        let json = serde_json::to_string(&check).expect("serialize derived Serialize");
        let back: CompositionCheck =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(check, back);
    }

    #[test]
    fn registry_overall_status_only_inconclusive() {
        let mut reg = InvariantRegistry::new();
        reg.record_result(VerificationResult {
            property_id: "P1".to_string(),
            status: VerificationStatus::Inconclusive,
            counterexample: None,
            states_explored: 1000,
            verification_time_us: 60_000_000,
        });
        assert_eq!(reg.overall_status(), VerificationStatus::Inconclusive);
    }

    #[test]
    fn registry_violated_without_counterexample_no_fixture() {
        let mut reg = InvariantRegistry::new();
        reg.record_result(VerificationResult {
            property_id: "P1".to_string(),
            status: VerificationStatus::Violated,
            counterexample: None,
            states_explored: 500,
            verification_time_us: 1000,
        });
        assert_eq!(reg.violated_count(), 1);
        assert!(reg.fixtures.is_empty(), "no fixture without counterexample");
    }

    #[test]
    fn registry_derive_id_differs_after_results() {
        let r1 = InvariantRegistry::new();
        let mut r2 = InvariantRegistry::new();
        r2.record_result(VerificationResult {
            property_id: "P1".to_string(),
            status: VerificationStatus::Verified,
            counterexample: None,
            states_explored: 100,
            verification_time_us: 500,
        });
        assert_ne!(r1.derive_id(), r2.derive_id());
    }

    #[test]
    fn fallback_automaton_accepting_states() {
        let a = fallback_transition_automaton();
        assert!(a.accepting_states.contains(&StateId::new("adaptive")));
        assert!(a.accepting_states.contains(&StateId::new("halted")));
        assert_eq!(a.accepting_states.len(), 2);
    }

    #[test]
    fn fallback_automaton_transition_count() {
        let a = fallback_transition_automaton();
        assert_eq!(a.transitions.len(), 9);
    }

    #[test]
    fn scheduler_lifecycle_transition_count() {
        let a = scheduler_lifecycle_automaton();
        assert_eq!(a.transitions.len(), 14);
    }

    #[test]
    fn scheduler_lifecycle_state_count() {
        let a = scheduler_lifecycle_automaton();
        assert_eq!(a.states.len(), 8);
    }

    #[test]
    fn fixture_derive_id_differs_by_fixture_id() {
        let f1 = RegressionFixture {
            fixture_id: "fix-001".to_string(),
            property_id: "P1".to_string(),
            description: "test".to_string(),
            replay_actions: vec![],
            expected_final_state: StateId::new("idle"),
            expects_violation: false,
        };
        let f2 = RegressionFixture {
            fixture_id: "fix-002".to_string(),
            ..f1.clone()
        };
        assert_ne!(f1.derive_id(), f2.derive_id());
    }

    #[test]
    fn verification_result_derive_id_differs_by_status() {
        let r1 = VerificationResult {
            property_id: "P1".to_string(),
            status: VerificationStatus::Verified,
            counterexample: None,
            states_explored: 100,
            verification_time_us: 500,
        };
        let r2 = VerificationResult {
            status: VerificationStatus::Violated,
            ..r1.clone()
        };
        assert_ne!(r1.derive_id(), r2.derive_id());
    }
}
