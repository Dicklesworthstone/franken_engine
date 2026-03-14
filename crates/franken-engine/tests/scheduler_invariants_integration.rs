#![forbid(unsafe_code)]
//! Integration tests for the `scheduler_invariants` module.
//!
//! Exercises scheduler automaton construction, canonical properties,
//! verification, composition checks, regression fixtures, and serde
//! round-trips from outside the crate boundary.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::scheduler_invariants::{
    CompositionCheck, ControllerId, Counterexample, CounterexampleStep, InterferenceReport,
    InterferenceSeverity, InvariantRegistry, PropertyKind, PropertySpec, RegressionFixture,
    SchedulerAutomaton, SharedResource, StateId, Transition, TransitionLabel, VerificationResult,
    VerificationStatus, canonical_scheduler_properties, fallback_transition_automaton,
    scheduler_lifecycle_automaton,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn make_state(name: &str) -> StateId {
    StateId::new(name)
}

fn make_label(name: &str) -> TransitionLabel {
    TransitionLabel::new(name)
}

fn make_transition(from: &str, label: &str, to: &str) -> Transition {
    Transition {
        from: make_state(from),
        label: make_label(label),
        to: make_state(to),
        guard: None,
    }
}

// ===========================================================================
// 1. StateId / TransitionLabel — construction, serde
// ===========================================================================

#[test]
fn state_id_construction() {
    let s = StateId::new("idle");
    assert_eq!(s.0, "idle");
}

#[test]
fn state_id_serde_round_trip() {
    let s = StateId::new("executing");
    let json = serde_json::to_string(&s).unwrap();
    let back: StateId = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

#[test]
fn transition_label_serde_round_trip() {
    let l = TransitionLabel::new("schedule");
    let json = serde_json::to_string(&l).unwrap();
    let back: TransitionLabel = serde_json::from_str(&json).unwrap();
    assert_eq!(back, l);
}

// ===========================================================================
// 2. SchedulerAutomaton — construction
// ===========================================================================

#[test]
fn automaton_new_has_initial_state() {
    let a = SchedulerAutomaton::new("test", make_state("idle"));
    assert_eq!(a.name, "test");
    assert!(a.states.contains(&make_state("idle")));
    assert_eq!(a.initial_state, make_state("idle"));
}

#[test]
fn automaton_add_states_and_transitions() {
    let mut a = SchedulerAutomaton::new("test", make_state("idle"));
    a.add_state(make_state("running"));
    a.add_accepting(make_state("idle"));
    a.add_transition(make_transition("idle", "start", "running"));
    a.add_transition(make_transition("running", "stop", "idle"));

    assert!(a.states.contains(&make_state("running")));
    assert!(a.accepting_states.contains(&make_state("idle")));
    assert_eq!(a.transitions.len(), 2);
}

#[test]
fn automaton_transitions_from() {
    let mut a = SchedulerAutomaton::new("test", make_state("idle"));
    a.add_state(make_state("running"));
    a.add_state(make_state("done"));
    a.add_transition(make_transition("idle", "start", "running"));
    a.add_transition(make_transition("idle", "skip", "done"));
    a.add_transition(make_transition("running", "stop", "idle"));

    let from_idle = a.transitions_from(&make_state("idle"));
    assert_eq!(from_idle.len(), 2);

    let from_running = a.transitions_from(&make_state("running"));
    assert_eq!(from_running.len(), 1);
}

// ===========================================================================
// 3. SchedulerAutomaton — reachability and dead states
// ===========================================================================

#[test]
fn automaton_reachability() {
    let mut a = SchedulerAutomaton::new("test", make_state("a"));
    a.add_state(make_state("b"));
    a.add_state(make_state("c"));
    a.add_state(make_state("orphan"));
    a.add_transition(make_transition("a", "go", "b"));
    a.add_transition(make_transition("b", "go", "c"));

    assert!(a.is_reachable(&make_state("a")));
    assert!(a.is_reachable(&make_state("b")));
    assert!(a.is_reachable(&make_state("c")));
    assert!(!a.is_reachable(&make_state("orphan")));
}

#[test]
fn automaton_dead_states() {
    let mut a = SchedulerAutomaton::new("test", make_state("a"));
    a.add_state(make_state("b"));
    a.add_state(make_state("dead"));
    a.add_transition(make_transition("a", "go", "b"));

    let dead = a.dead_states();
    assert!(dead.contains(&make_state("dead")));
    assert!(!dead.contains(&make_state("a")));
    assert!(!dead.contains(&make_state("b")));
}

// ===========================================================================
// 4. SchedulerAutomaton — determinism check
// ===========================================================================

#[test]
fn automaton_deterministic() {
    let mut a = SchedulerAutomaton::new("test", make_state("a"));
    a.add_state(make_state("b"));
    a.add_transition(make_transition("a", "go", "b"));
    assert!(a.is_deterministic());
}

#[test]
fn automaton_nondeterministic() {
    let mut a = SchedulerAutomaton::new("test", make_state("a"));
    a.add_state(make_state("b"));
    a.add_state(make_state("c"));
    // Same label from same state to different targets
    a.add_transition(make_transition("a", "go", "b"));
    a.add_transition(make_transition("a", "go", "c"));
    assert!(!a.is_deterministic());
}

// ===========================================================================
// 5. SchedulerAutomaton — derive_id, serde
// ===========================================================================

#[test]
fn automaton_derive_id_deterministic() {
    let a1 = scheduler_lifecycle_automaton();
    let a2 = scheduler_lifecycle_automaton();
    assert_eq!(a1.derive_id(), a2.derive_id());
}

#[test]
fn automaton_serde_round_trip() {
    let a = scheduler_lifecycle_automaton();
    let json = serde_json::to_string(&a).unwrap();
    let back: SchedulerAutomaton = serde_json::from_str(&json).unwrap();
    assert_eq!(back, a);
}

// ===========================================================================
// 6. Canonical automatons
// ===========================================================================

#[test]
fn scheduler_lifecycle_has_expected_states() {
    let a = scheduler_lifecycle_automaton();
    assert!(a.states.contains(&make_state("idle")));
    assert!(a.states.contains(&make_state("executing")));
    assert!(a.states.contains(&make_state("halted")));
    assert_eq!(a.initial_state, make_state("idle"));
    assert!(!a.transitions.is_empty());
}

#[test]
fn scheduler_lifecycle_is_deterministic() {
    assert!(scheduler_lifecycle_automaton().is_deterministic());
}

#[test]
fn fallback_transition_has_expected_states() {
    let a = fallback_transition_automaton();
    assert!(a.states.contains(&make_state("adaptive")));
    assert!(a.states.contains(&make_state("halted")));
    assert!(!a.transitions.is_empty());
}

#[test]
fn fallback_transition_is_deterministic() {
    assert!(fallback_transition_automaton().is_deterministic());
}

// ===========================================================================
// 7. PropertyKind / VerificationStatus — as_str, serde
// ===========================================================================

#[test]
fn property_kind_as_str() {
    assert_eq!(PropertyKind::Safety.as_str(), "safety");
    assert_eq!(PropertyKind::Liveness.as_str(), "liveness");
    assert_eq!(PropertyKind::Fairness.as_str(), "fairness");
    assert_eq!(PropertyKind::Determinism.as_str(), "determinism");
    assert_eq!(PropertyKind::Composition.as_str(), "composition");
}

#[test]
fn property_kind_serde_round_trip() {
    for k in [
        PropertyKind::Safety,
        PropertyKind::Liveness,
        PropertyKind::Fairness,
        PropertyKind::Determinism,
        PropertyKind::Composition,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: PropertyKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }
}

#[test]
fn verification_status_as_str() {
    assert_eq!(VerificationStatus::Verified.as_str(), "verified");
    assert_eq!(VerificationStatus::Violated.as_str(), "violated");
    assert_eq!(VerificationStatus::Inconclusive.as_str(), "inconclusive");
    assert_eq!(VerificationStatus::Pending.as_str(), "pending");
}

#[test]
fn verification_status_serde_round_trip() {
    for s in [
        VerificationStatus::Verified,
        VerificationStatus::Violated,
        VerificationStatus::Inconclusive,
        VerificationStatus::Pending,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: VerificationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

// ===========================================================================
// 8. InterferenceSeverity — as_str, serde
// ===========================================================================

#[test]
fn interference_severity_as_str() {
    assert_eq!(InterferenceSeverity::None.as_str(), "none");
    assert_eq!(InterferenceSeverity::Benign.as_str(), "benign");
    assert_eq!(InterferenceSeverity::Serious.as_str(), "serious");
    assert_eq!(InterferenceSeverity::Critical.as_str(), "critical");
}

#[test]
fn interference_severity_serde_round_trip() {
    for s in [
        InterferenceSeverity::None,
        InterferenceSeverity::Benign,
        InterferenceSeverity::Serious,
        InterferenceSeverity::Critical,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: InterferenceSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

// ===========================================================================
// 9. Canonical properties
// ===========================================================================

#[test]
fn canonical_properties_nonempty() {
    let props = canonical_scheduler_properties();
    assert!(!props.is_empty());
}

#[test]
fn canonical_properties_unique_ids() {
    let props = canonical_scheduler_properties();
    let mut seen = BTreeSet::new();
    for p in &props {
        assert!(seen.insert(&p.id), "duplicate property id: {}", p.id);
    }
}

#[test]
fn canonical_properties_covers_multiple_kinds() {
    let props = canonical_scheduler_properties();
    let kinds: BTreeSet<_> = props.iter().map(|p| p.kind).collect();
    assert!(
        kinds.len() >= 3,
        "should cover at least 3 property kinds, got {}",
        kinds.len()
    );
}

// ===========================================================================
// 10. InvariantRegistry
// ===========================================================================

#[test]
fn registry_new_is_empty() {
    let reg = InvariantRegistry::new();
    assert!(reg.properties.is_empty());
    assert!(reg.results.is_empty());
    assert!(reg.fixtures.is_empty());
    assert_eq!(reg.verified_count(), 0);
    assert_eq!(reg.violated_count(), 0);
}

#[test]
fn registry_add_property_and_result() {
    let mut reg = InvariantRegistry::new();
    let prop = PropertySpec {
        id: "p-1".into(),
        name: "no deadlock".into(),
        kind: PropertyKind::Safety,
        description: "system never deadlocks".into(),
        formula: "AG(!deadlock)".into(),
        components: vec!["scheduler".into()],
    };
    reg.add_property(prop);
    assert_eq!(reg.properties.len(), 1);

    let result = VerificationResult {
        property_id: "p-1".into(),
        status: VerificationStatus::Verified,
        counterexample: None,
        states_explored: 100,
        verification_time_us: 500,
    };
    reg.record_result(result);
    assert_eq!(reg.verified_count(), 1);
    assert_eq!(reg.violated_count(), 0);
    assert_eq!(reg.overall_status(), VerificationStatus::Verified);
}

#[test]
fn registry_overall_status_violated_if_any_violated() {
    let mut reg = InvariantRegistry::new();
    reg.record_result(VerificationResult {
        property_id: "p-1".into(),
        status: VerificationStatus::Verified,
        counterexample: None,
        states_explored: 50,
        verification_time_us: 100,
    });
    reg.record_result(VerificationResult {
        property_id: "p-2".into(),
        status: VerificationStatus::Violated,
        counterexample: None,
        states_explored: 30,
        verification_time_us: 200,
    });
    assert_eq!(reg.overall_status(), VerificationStatus::Violated);
}

#[test]
fn registry_get_result() {
    let mut reg = InvariantRegistry::new();
    let result = VerificationResult {
        property_id: "p-1".into(),
        status: VerificationStatus::Verified,
        counterexample: None,
        states_explored: 100,
        verification_time_us: 500,
    };
    reg.record_result(result.clone());
    let got = reg.get_result("p-1").unwrap();
    assert_eq!(got.status, VerificationStatus::Verified);
    assert!(reg.get_result("p-nonexistent").is_none());
}

#[test]
fn registry_serde_round_trip() {
    let mut reg = InvariantRegistry::new();
    reg.add_property(PropertySpec {
        id: "p-1".into(),
        name: "test".into(),
        kind: PropertyKind::Safety,
        description: "desc".into(),
        formula: "AG(true)".into(),
        components: vec!["a".into()],
    });
    reg.record_result(VerificationResult {
        property_id: "p-1".into(),
        status: VerificationStatus::Verified,
        counterexample: None,
        states_explored: 100,
        verification_time_us: 500,
    });
    let json = serde_json::to_string(&reg).unwrap();
    let back: InvariantRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, reg);
}

// ===========================================================================
// 11. CompositionCheck
// ===========================================================================

#[test]
fn composition_check_new_is_compatible() {
    let check = CompositionCheck::new(
        vec![ControllerId::new("c1"), ControllerId::new("c2")],
        vec![SharedResource::new("r1")],
    );
    assert!(check.overall_compatible);
    assert!(check.interferences.is_empty());
}

#[test]
fn composition_check_add_interference() {
    let mut check = CompositionCheck::new(
        vec![ControllerId::new("c1"), ControllerId::new("c2")],
        vec![SharedResource::new("lane_budget")],
    );
    check.add_interference(InterferenceReport {
        controller_a: ControllerId::new("c1"),
        controller_b: ControllerId::new("c2"),
        resource: SharedResource::new("lane_budget"),
        severity: InterferenceSeverity::Critical,
        description: "conflicting budget claims".into(),
        mitigation: Some("use priority ordering".into()),
    });
    assert!(!check.overall_compatible);
    assert_eq!(check.critical_count(), 1);
    assert_eq!(check.serious_count(), 0);
}

#[test]
fn composition_check_serde_round_trip() {
    let check = CompositionCheck::new(
        vec![ControllerId::new("c1")],
        vec![SharedResource::new("r1")],
    );
    let json = serde_json::to_string(&check).unwrap();
    let back: CompositionCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(back, check);
}

// ===========================================================================
// 12. RegressionFixture
// ===========================================================================

#[test]
fn regression_fixture_from_counterexample() {
    let cx = Counterexample {
        property_id: "p-1".into(),
        trace: vec![CounterexampleStep {
            step: 0,
            state: make_state("idle"),
            action: make_label("schedule"),
            next_state: make_state("executing"),
            state_vars: BTreeMap::new(),
        }],
        violation_description: "deadlock found".into(),
    };
    let fixture = RegressionFixture::from_counterexample("fix-1", &cx);
    assert_eq!(fixture.fixture_id, "fix-1");
    assert_eq!(fixture.property_id, "p-1");
    assert!(fixture.expects_violation);
    assert_eq!(fixture.replay_actions.len(), 1);
}

#[test]
fn regression_fixture_serde_round_trip() {
    let fixture = RegressionFixture {
        fixture_id: "fix-1".into(),
        property_id: "p-1".into(),
        description: "deadlock regression".into(),
        replay_actions: vec![make_label("schedule"), make_label("execute")],
        expected_final_state: make_state("idle"),
        expects_violation: false,
    };
    let json = serde_json::to_string(&fixture).unwrap();
    let back: RegressionFixture = serde_json::from_str(&json).unwrap();
    assert_eq!(back, fixture);
}

// ===========================================================================
// 13. Transition serde
// ===========================================================================

#[test]
fn transition_serde_round_trip() {
    let t = Transition {
        from: make_state("idle"),
        label: make_label("start"),
        to: make_state("running"),
        guard: Some("budget > 0".into()),
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: Transition = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

// ===========================================================================
// 14. VerificationResult — derive_id, serde
// ===========================================================================

#[test]
fn verification_result_derive_id_deterministic() {
    let r1 = VerificationResult {
        property_id: "p-1".into(),
        status: VerificationStatus::Verified,
        counterexample: None,
        states_explored: 100,
        verification_time_us: 500,
    };
    let r2 = r1.clone();
    assert_eq!(r1.derive_id(), r2.derive_id());
}

#[test]
fn verification_result_serde_round_trip() {
    let r = VerificationResult {
        property_id: "p-1".into(),
        status: VerificationStatus::Violated,
        counterexample: Some(Counterexample {
            property_id: "p-1".into(),
            trace: vec![],
            violation_description: "found issue".into(),
        }),
        states_explored: 50,
        verification_time_us: 200,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: VerificationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

// ===========================================================================
// 15. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_verify_canonical_properties() {
    let automaton = scheduler_lifecycle_automaton();
    let properties = canonical_scheduler_properties();

    let mut registry = InvariantRegistry::new();

    // Register all canonical properties
    for prop in &properties {
        registry.add_property(prop.clone());
    }

    // Simulate verification of each property
    for prop in &properties {
        let result = VerificationResult {
            property_id: prop.id.clone(),
            status: VerificationStatus::Verified,
            counterexample: None,
            states_explored: automaton.states.len() as u64 * 10,
            verification_time_us: 100,
        };
        registry.record_result(result);
    }

    assert_eq!(registry.overall_status(), VerificationStatus::Verified);
    assert_eq!(registry.verified_count(), properties.len());
    assert_eq!(registry.violated_count(), 0);

    // Serde round-trip the whole registry
    let json = serde_json::to_string(&registry).unwrap();
    let back: InvariantRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.verified_count(), registry.verified_count());
}

#[test]
fn full_lifecycle_composition_with_interference() {
    let mut check = CompositionCheck::new(
        vec![
            ControllerId::new("adaptive_controller"),
            ControllerId::new("safe_mode_controller"),
        ],
        vec![
            SharedResource::new("lane_budget"),
            SharedResource::new("evidence_channel"),
        ],
    );

    // No interference on evidence_channel
    // But lane_budget has serious interference
    check.add_interference(InterferenceReport {
        controller_a: ControllerId::new("adaptive_controller"),
        controller_b: ControllerId::new("safe_mode_controller"),
        resource: SharedResource::new("lane_budget"),
        severity: InterferenceSeverity::Serious,
        description: "both controllers modify lane budget".into(),
        mitigation: Some("use priority arbitration".into()),
    });

    assert!(!check.overall_compatible);
    assert_eq!(check.serious_count(), 1);
    assert_eq!(check.critical_count(), 0);

    // Derive deterministic ID
    let id1 = check.derive_id();
    let id2 = check.derive_id();
    assert_eq!(id1, id2);
}

// ===========================================================================
// 16. StateId / TransitionLabel — Clone, Debug, Ord
// ===========================================================================

#[test]
fn test_state_id_clone_and_debug() {
    let s = StateId::new("scheduling");
    let cloned = s.clone();
    assert_eq!(s, cloned);
    let debug = format!("{cloned:?}");
    assert!(debug.contains("scheduling"));
}

#[test]
fn test_transition_label_clone_and_debug() {
    let l = TransitionLabel::new("enqueue_update");
    let cloned = l.clone();
    assert_eq!(l, cloned);
    let debug = format!("{cloned:?}");
    assert!(debug.contains("enqueue_update"));
}

#[test]
fn test_state_id_ordering() {
    let a = StateId::new("a_state");
    let b = StateId::new("b_state");
    assert!(a < b);
    assert!(b > a);
    assert_eq!(a, StateId::new("a_state"));
}

#[test]
fn test_transition_label_ordering() {
    let x = TransitionLabel::new("alpha");
    let y = TransitionLabel::new("beta");
    assert!(x < y);
    assert_eq!(x, TransitionLabel::new("alpha"));
}

// ===========================================================================
// 17. Transition — guard roundtrip, Debug, Clone
// ===========================================================================

#[test]
fn test_transition_with_no_guard_serde() {
    let t = make_transition("idle", "start", "running");
    assert!(t.guard.is_none());
    let json = serde_json::to_string(&t).unwrap();
    let back: Transition = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
    assert!(back.guard.is_none());
}

#[test]
fn test_transition_debug_contains_fields() {
    let t = Transition {
        from: make_state("idle"),
        label: make_label("start"),
        to: make_state("executing"),
        guard: Some("budget_ok".into()),
    };
    let debug = format!("{t:?}");
    assert!(debug.contains("idle"));
    assert!(debug.contains("start"));
    assert!(debug.contains("executing"));
    assert!(debug.contains("budget_ok"));
}

#[test]
fn test_transition_clone_equality() {
    let t = Transition {
        from: make_state("a"),
        label: make_label("go"),
        to: make_state("b"),
        guard: Some("cond".into()),
    };
    assert_eq!(t.clone(), t);
}

// ===========================================================================
// 18. SchedulerAutomaton — alphabet population
// ===========================================================================

#[test]
fn test_automaton_alphabet_populated_on_add_transition() {
    let mut a = SchedulerAutomaton::new("alph_test", make_state("s0"));
    a.add_transition(make_transition("s0", "fire", "s1"));
    a.add_transition(make_transition("s1", "reset", "s0"));
    assert!(a.alphabet.contains(&make_label("fire")));
    assert!(a.alphabet.contains(&make_label("reset")));
    assert_eq!(a.alphabet.len(), 2);
}

#[test]
fn test_automaton_add_state_does_not_affect_alphabet() {
    let mut a = SchedulerAutomaton::new("alph_test2", make_state("s0"));
    a.add_state(make_state("orphan"));
    assert!(a.alphabet.is_empty());
}

// ===========================================================================
// 19. SchedulerAutomaton — initial state always reachable
// ===========================================================================

#[test]
fn test_automaton_initial_state_always_reachable() {
    let a = SchedulerAutomaton::new("lone", make_state("only"));
    assert!(a.is_reachable(&make_state("only")));
}

#[test]
fn test_automaton_single_state_no_dead_states_when_accepting() {
    let mut a = SchedulerAutomaton::new("single", make_state("s0"));
    a.add_accepting(make_state("s0"));
    assert!(a.dead_states().is_empty());
    assert!(a.accepting_states.contains(&make_state("s0")));
}

// ===========================================================================
// 20. SchedulerAutomaton — derive_id changes with name
// ===========================================================================

#[test]
fn test_automaton_derive_id_differs_by_name() {
    let a1 = SchedulerAutomaton::new("name-a", make_state("s0"));
    let a2 = SchedulerAutomaton::new("name-b", make_state("s0"));
    assert_ne!(a1.derive_id(), a2.derive_id());
}

// ===========================================================================
// 21. PropertySpec — Clone, Debug, serde
// ===========================================================================

#[test]
fn test_property_spec_serde_round_trip() {
    let p = PropertySpec {
        id: "P-TEST-01".into(),
        name: "my prop".into(),
        kind: PropertyKind::Fairness,
        description: "some fairness property".into(),
        formula: "G(fair)".into(),
        components: vec!["comp_a".into(), "comp_b".into()],
    };
    let json = serde_json::to_string(&p).unwrap();
    let back: PropertySpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back, p);
}

#[test]
fn test_property_spec_debug_contains_id() {
    let p = PropertySpec {
        id: "P-DBG-01".into(),
        name: "dbg prop".into(),
        kind: PropertyKind::Determinism,
        description: "desc".into(),
        formula: "F(x)".into(),
        components: vec![],
    };
    let debug = format!("{p:?}");
    assert!(debug.contains("P-DBG-01"));
}

// ===========================================================================
// 22. InvariantRegistry — Default impl, derive_id, fixture auto-generation
// ===========================================================================

#[test]
fn test_registry_default_matches_new() {
    let via_default = InvariantRegistry::default();
    let via_new = InvariantRegistry::new();
    assert_eq!(via_default, via_new);
}

#[test]
fn test_registry_derive_id_deterministic() {
    let reg1 = InvariantRegistry::new();
    let reg2 = InvariantRegistry::new();
    assert_eq!(reg1.derive_id(), reg2.derive_id());
}

#[test]
fn test_registry_auto_fixture_on_violated_with_counterexample() {
    let mut reg = InvariantRegistry::new();
    let cx = Counterexample {
        property_id: "P-VIO-01".into(),
        trace: vec![CounterexampleStep {
            step: 0,
            state: make_state("idle"),
            action: make_label("enqueue_update"),
            next_state: make_state("scheduling"),
            state_vars: BTreeMap::new(),
        }],
        violation_description: "liveness violation".into(),
    };
    reg.record_result(VerificationResult {
        property_id: "P-VIO-01".into(),
        status: VerificationStatus::Violated,
        counterexample: Some(cx),
        states_explored: 10,
        verification_time_us: 50,
    });
    assert_eq!(reg.violated_count(), 1);
    assert_eq!(reg.fixtures.len(), 1);
    assert_eq!(reg.fixtures[0].property_id, "P-VIO-01");
    assert!(reg.fixtures[0].expects_violation);
}

#[test]
fn test_registry_no_fixture_on_violated_without_counterexample() {
    let mut reg = InvariantRegistry::new();
    reg.record_result(VerificationResult {
        property_id: "P-VIO-02".into(),
        status: VerificationStatus::Violated,
        counterexample: None,
        states_explored: 5,
        verification_time_us: 20,
    });
    assert_eq!(reg.violated_count(), 1);
    assert!(reg.fixtures.is_empty());
}

#[test]
fn test_registry_overall_status_inconclusive_with_pending() {
    let mut reg = InvariantRegistry::new();
    reg.record_result(VerificationResult {
        property_id: "p-a".into(),
        status: VerificationStatus::Verified,
        counterexample: None,
        states_explored: 10,
        verification_time_us: 10,
    });
    reg.record_result(VerificationResult {
        property_id: "p-b".into(),
        status: VerificationStatus::Pending,
        counterexample: None,
        states_explored: 0,
        verification_time_us: 0,
    });
    assert_eq!(reg.overall_status(), VerificationStatus::Inconclusive);
}

#[test]
fn test_registry_overall_status_pending_when_empty() {
    let reg = InvariantRegistry::new();
    assert_eq!(reg.overall_status(), VerificationStatus::Pending);
}

// ===========================================================================
// 23. CompositionCheck — benign interference keeps compatible flag
// ===========================================================================

#[test]
fn test_composition_benign_interference_stays_compatible() {
    let mut check = CompositionCheck::new(
        vec![ControllerId::new("ctrl_a"), ControllerId::new("ctrl_b")],
        vec![SharedResource::new("metrics_channel")],
    );
    check.add_interference(InterferenceReport {
        controller_a: ControllerId::new("ctrl_a"),
        controller_b: ControllerId::new("ctrl_b"),
        resource: SharedResource::new("metrics_channel"),
        severity: InterferenceSeverity::Benign,
        description: "read-only overlap".into(),
        mitigation: None,
    });
    assert!(check.overall_compatible);
    assert_eq!(check.critical_count(), 0);
    assert_eq!(check.serious_count(), 0);
    assert_eq!(check.interferences.len(), 1);
}

#[test]
fn test_composition_none_interference_stays_compatible() {
    let mut check = CompositionCheck::new(
        vec![ControllerId::new("ctrl_x")],
        vec![SharedResource::new("res_x")],
    );
    check.add_interference(InterferenceReport {
        controller_a: ControllerId::new("ctrl_x"),
        controller_b: ControllerId::new("ctrl_x"),
        resource: SharedResource::new("res_x"),
        severity: InterferenceSeverity::None,
        description: "no actual interference".into(),
        mitigation: None,
    });
    assert!(check.overall_compatible);
}

// ===========================================================================
// 24. ControllerId / SharedResource — Debug, Clone, serde
// ===========================================================================

#[test]
fn test_controller_id_debug_clone_serde() {
    let c = ControllerId::new("adaptive_controller");
    let cloned = c.clone();
    assert_eq!(c, cloned);
    let json = serde_json::to_string(&c).unwrap();
    let back: ControllerId = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
    let debug = format!("{c:?}");
    assert!(debug.contains("adaptive_controller"));
}

#[test]
fn test_shared_resource_debug_clone_serde() {
    let r = SharedResource::new("lane_budget");
    let cloned = r.clone();
    assert_eq!(r, cloned);
    let json = serde_json::to_string(&r).unwrap();
    let back: SharedResource = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
    let debug = format!("{r:?}");
    assert!(debug.contains("lane_budget"));
}

// ===========================================================================
// 25. RegressionFixture — empty trace yields unknown final state
// ===========================================================================

#[test]
fn test_regression_fixture_empty_trace_yields_unknown_state() {
    let cx = Counterexample {
        property_id: "P-EMPTY".into(),
        trace: vec![],
        violation_description: "empty trace violation".into(),
    };
    let fixture = RegressionFixture::from_counterexample("fix-empty", &cx);
    assert_eq!(fixture.expected_final_state, StateId::new("unknown"));
    assert!(fixture.replay_actions.is_empty());
    assert!(fixture.expects_violation);
}

#[test]
fn test_regression_fixture_multistep_trace() {
    let cx = Counterexample {
        property_id: "P-MULTI".into(),
        trace: vec![
            CounterexampleStep {
                step: 0,
                state: make_state("idle"),
                action: make_label("enqueue_update"),
                next_state: make_state("scheduling"),
                state_vars: BTreeMap::new(),
            },
            CounterexampleStep {
                step: 1,
                state: make_state("scheduling"),
                action: make_label("batch_ready"),
                next_state: make_state("executing"),
                state_vars: BTreeMap::new(),
            },
        ],
        violation_description: "multi-step violation".into(),
    };
    let fixture = RegressionFixture::from_counterexample("fix-multi", &cx);
    assert_eq!(fixture.replay_actions.len(), 2);
    assert_eq!(fixture.expected_final_state, make_state("executing"));
    assert_eq!(fixture.replay_actions[0], make_label("enqueue_update"));
    assert_eq!(fixture.replay_actions[1], make_label("batch_ready"));
}

// ===========================================================================
// 26. CounterexampleStep — state_vars serde
// ===========================================================================

#[test]
fn test_counterexample_step_with_state_vars_serde() {
    let mut vars = BTreeMap::new();
    vars.insert("budget".to_string(), "1000".to_string());
    vars.insert("lane".to_string(), "js".to_string());
    let step = CounterexampleStep {
        step: 3,
        state: make_state("executing"),
        action: make_label("flush_start"),
        next_state: make_state("flushing"),
        state_vars: vars,
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: CounterexampleStep = serde_json::from_str(&json).unwrap();
    assert_eq!(back, step);
    assert_eq!(back.state_vars.get("budget").unwrap(), "1000");
    assert_eq!(back.state_vars.get("lane").unwrap(), "js");
}

// ===========================================================================
// 27. Fallback automaton — all states reachable
// ===========================================================================

#[test]
fn test_fallback_automaton_all_states_reachable() {
    let a = fallback_transition_automaton();
    for state in &a.states {
        assert!(
            a.is_reachable(state),
            "state {state:?} is unreachable in fallback automaton"
        );
    }
}

#[test]
fn test_fallback_automaton_no_dead_states() {
    let a = fallback_transition_automaton();
    let dead = a.dead_states();
    assert!(dead.is_empty(), "unexpected dead states: {dead:?}");
}

// ===========================================================================
// 28. Canonical properties — specific IDs present
// ===========================================================================

#[test]
fn test_canonical_properties_contain_safety_and_liveness() {
    let props = canonical_scheduler_properties();
    let ids: BTreeSet<&str> = props.iter().map(|p| p.id.as_str()).collect();
    assert!(ids.contains("P-SAFETY-01"), "missing P-SAFETY-01");
    assert!(ids.contains("P-LIVENESS-01"), "missing P-LIVENESS-01");
    assert!(ids.contains("P-FAIRNESS-01"), "missing P-FAIRNESS-01");
    assert!(ids.contains("P-DETERM-01"), "missing P-DETERM-01");
    assert!(ids.contains("P-COMP-01"), "missing P-COMP-01");
}

#[test]
fn test_canonical_properties_all_have_nonempty_formula() {
    for prop in canonical_scheduler_properties() {
        assert!(!prop.formula.is_empty(), "empty formula for {}", prop.id);
        assert!(!prop.components.is_empty(), "no components for {}", prop.id);
    }
}

// ===========================================================================
// 29. VerificationResult — inconclusive status in registry
// ===========================================================================

#[test]
fn test_registry_inconclusive_result_not_counted_as_verified_or_violated() {
    let mut reg = InvariantRegistry::new();
    reg.record_result(VerificationResult {
        property_id: "p-inc".into(),
        status: VerificationStatus::Inconclusive,
        counterexample: None,
        states_explored: 1_000_000,
        verification_time_us: 999_999,
    });
    assert_eq!(reg.verified_count(), 0);
    assert_eq!(reg.violated_count(), 0);
    assert_eq!(reg.overall_status(), VerificationStatus::Inconclusive);
}

// ===========================================================================
// 30. VerificationResult — derive_id differs by status
// ===========================================================================

#[test]
fn test_verification_result_derive_id_differs_by_status() {
    let base = VerificationResult {
        property_id: "p-x".into(),
        status: VerificationStatus::Verified,
        counterexample: None,
        states_explored: 10,
        verification_time_us: 10,
    };
    let violated = VerificationResult {
        status: VerificationStatus::Violated,
        ..base.clone()
    };
    assert_ne!(base.derive_id(), violated.derive_id());
}
