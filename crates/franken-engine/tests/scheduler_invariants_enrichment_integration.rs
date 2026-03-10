//! Enrichment integration tests for `scheduler_invariants` (FRX-05.3).
//!
//! Covers: JSON field-name stability, serde roundtrips, as_str exact values,
//! Debug distinctness, automaton structural properties, canonical automata,
//! property specifications, counterexample-to-fixture bridge, composition
//! compatibility checks, and invariant registry lifecycle.

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

use frankenengine_engine::scheduler_invariants::*;
use std::collections::{BTreeMap, BTreeSet};

// ── PropertyKind ─────────────────────────────────────────────────────────

#[test]
fn property_kind_as_str_exact_all_variants() {
    assert_eq!(PropertyKind::Safety.as_str(), "safety");
    assert_eq!(PropertyKind::Liveness.as_str(), "liveness");
    assert_eq!(PropertyKind::Fairness.as_str(), "fairness");
    assert_eq!(PropertyKind::Determinism.as_str(), "determinism");
    assert_eq!(PropertyKind::Composition.as_str(), "composition");
}

#[test]
fn property_kind_debug_distinct() {
    let variants = [
        PropertyKind::Safety,
        PropertyKind::Liveness,
        PropertyKind::Fairness,
        PropertyKind::Determinism,
        PropertyKind::Composition,
    ];
    let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(set.len(), variants.len());
}

#[test]
fn property_kind_serde_roundtrip_all() {
    for k in [
        PropertyKind::Safety,
        PropertyKind::Liveness,
        PropertyKind::Fairness,
        PropertyKind::Determinism,
        PropertyKind::Composition,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: PropertyKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back);
    }
}

#[test]
fn property_kind_as_str_unique() {
    let kinds = [
        PropertyKind::Safety,
        PropertyKind::Liveness,
        PropertyKind::Fairness,
        PropertyKind::Determinism,
        PropertyKind::Composition,
    ];
    let set: BTreeSet<&str> = kinds.iter().map(|k| k.as_str()).collect();
    assert_eq!(set.len(), 5);
}

// ── VerificationStatus ───────────────────────────────────────────────────

#[test]
fn verification_status_as_str_exact_all_variants() {
    assert_eq!(VerificationStatus::Verified.as_str(), "verified");
    assert_eq!(VerificationStatus::Violated.as_str(), "violated");
    assert_eq!(VerificationStatus::Inconclusive.as_str(), "inconclusive");
    assert_eq!(VerificationStatus::Pending.as_str(), "pending");
}

#[test]
fn verification_status_debug_distinct() {
    let variants = [
        VerificationStatus::Verified,
        VerificationStatus::Violated,
        VerificationStatus::Inconclusive,
        VerificationStatus::Pending,
    ];
    let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(set.len(), variants.len());
}

#[test]
fn verification_status_serde_roundtrip_all() {
    for s in [
        VerificationStatus::Verified,
        VerificationStatus::Violated,
        VerificationStatus::Inconclusive,
        VerificationStatus::Pending,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: VerificationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn verification_status_ordering() {
    assert!(VerificationStatus::Verified < VerificationStatus::Violated);
    assert!(VerificationStatus::Violated < VerificationStatus::Inconclusive);
    assert!(VerificationStatus::Inconclusive < VerificationStatus::Pending);
}

// ── InterferenceSeverity ─────────────────────────────────────────────────

#[test]
fn interference_severity_as_str_exact_all_variants() {
    assert_eq!(InterferenceSeverity::None.as_str(), "none");
    assert_eq!(InterferenceSeverity::Benign.as_str(), "benign");
    assert_eq!(InterferenceSeverity::Serious.as_str(), "serious");
    assert_eq!(InterferenceSeverity::Critical.as_str(), "critical");
}

#[test]
fn interference_severity_debug_distinct() {
    let variants = [
        InterferenceSeverity::None,
        InterferenceSeverity::Benign,
        InterferenceSeverity::Serious,
        InterferenceSeverity::Critical,
    ];
    let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(set.len(), variants.len());
}

#[test]
fn interference_severity_serde_roundtrip_all() {
    for s in [
        InterferenceSeverity::None,
        InterferenceSeverity::Benign,
        InterferenceSeverity::Serious,
        InterferenceSeverity::Critical,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: InterferenceSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn interference_severity_ordering() {
    assert!(InterferenceSeverity::None < InterferenceSeverity::Benign);
    assert!(InterferenceSeverity::Benign < InterferenceSeverity::Serious);
    assert!(InterferenceSeverity::Serious < InterferenceSeverity::Critical);
}

// ── StateId / TransitionLabel constructors ───────────────────────────────

#[test]
fn state_id_new_and_serde_roundtrip() {
    let s = StateId::new("idle");
    assert_eq!(s.0, "idle");
    let json = serde_json::to_string(&s).unwrap();
    let back: StateId = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn transition_label_new_and_serde_roundtrip() {
    let t = TransitionLabel::new("enqueue_update");
    assert_eq!(t.0, "enqueue_update");
    let json = serde_json::to_string(&t).unwrap();
    let back: TransitionLabel = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn controller_id_new_and_serde_roundtrip() {
    let c = ControllerId::new("hybrid_router");
    assert_eq!(c.0, "hybrid_router");
    let json = serde_json::to_string(&c).unwrap();
    let back: ControllerId = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn shared_resource_new_and_serde_roundtrip() {
    let r = SharedResource::new("signal_graph");
    assert_eq!(r.0, "signal_graph");
    let json = serde_json::to_string(&r).unwrap();
    let back: SharedResource = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ── JSON field-name stability ────────────────────────────────────────────

#[test]
fn transition_json_fields() {
    let t = Transition {
        from: StateId::new("s0"),
        label: TransitionLabel::new("go"),
        to: StateId::new("s1"),
        guard: Some("x > 0".into()),
    };
    let json = serde_json::to_value(&t).unwrap();
    let obj = json.as_object().unwrap();
    for key in &["from", "label", "to", "guard"] {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }
}

#[test]
fn property_spec_json_fields() {
    let spec = PropertySpec {
        id: "P1".into(),
        name: "Test".into(),
        kind: PropertyKind::Safety,
        description: "desc".into(),
        formula: "G(true)".into(),
        components: vec!["scheduler".into()],
    };
    let json = serde_json::to_value(&spec).unwrap();
    let obj = json.as_object().unwrap();
    for key in &["id", "name", "kind", "description", "formula", "components"] {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }
}

#[test]
fn verification_result_json_fields() {
    let r = VerificationResult {
        property_id: "P1".into(),
        status: VerificationStatus::Verified,
        counterexample: None,
        states_explored: 100,
        verification_time_us: 500,
    };
    let json = serde_json::to_value(&r).unwrap();
    let obj = json.as_object().unwrap();
    for key in &[
        "property_id",
        "status",
        "counterexample",
        "states_explored",
        "verification_time_us",
    ] {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }
}

#[test]
fn counterexample_step_json_fields() {
    let step = CounterexampleStep {
        step: 0,
        state: StateId::new("idle"),
        action: TransitionLabel::new("go"),
        next_state: StateId::new("halted"),
        state_vars: BTreeMap::new(),
    };
    let json = serde_json::to_value(&step).unwrap();
    let obj = json.as_object().unwrap();
    for key in &["step", "state", "action", "next_state", "state_vars"] {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }
}

#[test]
fn regression_fixture_json_fields() {
    let f = RegressionFixture {
        fixture_id: "fix-1".into(),
        property_id: "P1".into(),
        description: "d".into(),
        replay_actions: vec![],
        expected_final_state: StateId::new("idle"),
        expects_violation: false,
    };
    let json = serde_json::to_value(&f).unwrap();
    let obj = json.as_object().unwrap();
    for key in &[
        "fixture_id",
        "property_id",
        "description",
        "replay_actions",
        "expected_final_state",
        "expects_violation",
    ] {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }
}

#[test]
fn interference_report_json_fields() {
    let r = InterferenceReport {
        controller_a: ControllerId::new("a"),
        controller_b: ControllerId::new("b"),
        resource: SharedResource::new("r"),
        severity: InterferenceSeverity::Benign,
        description: "d".into(),
        mitigation: None,
    };
    let json = serde_json::to_value(&r).unwrap();
    let obj = json.as_object().unwrap();
    for key in &[
        "controller_a",
        "controller_b",
        "resource",
        "severity",
        "description",
        "mitigation",
    ] {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }
}

#[test]
fn composition_check_json_fields() {
    let c = CompositionCheck::new(vec![ControllerId::new("a")], vec![SharedResource::new("r")]);
    let json = serde_json::to_value(&c).unwrap();
    let obj = json.as_object().unwrap();
    for key in &[
        "controllers",
        "shared_resources",
        "interferences",
        "overall_compatible",
    ] {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }
}

// ── serde roundtrips ─────────────────────────────────────────────────────

#[test]
fn transition_serde_roundtrip() {
    let t = Transition {
        from: StateId::new("s0"),
        label: TransitionLabel::new("go"),
        to: StateId::new("s1"),
        guard: Some("x > 0".into()),
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: Transition = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn property_spec_serde_roundtrip() {
    let spec = PropertySpec {
        id: "P1".into(),
        name: "Test".into(),
        kind: PropertyKind::Safety,
        description: "d".into(),
        formula: "G(true)".into(),
        components: vec!["scheduler".into()],
    };
    let json = serde_json::to_string(&spec).unwrap();
    let back: PropertySpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, back);
}

#[test]
fn verification_result_serde_roundtrip_with_counterexample() {
    let r = VerificationResult {
        property_id: "P1".into(),
        status: VerificationStatus::Violated,
        counterexample: Some(Counterexample {
            property_id: "P1".into(),
            trace: vec![CounterexampleStep {
                step: 0,
                state: StateId::new("idle"),
                action: TransitionLabel::new("go"),
                next_state: StateId::new("halted"),
                state_vars: BTreeMap::from([("x".into(), "1".into())]),
            }],
            violation_description: "test".into(),
        }),
        states_explored: 1000,
        verification_time_us: 5000,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: VerificationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn regression_fixture_serde_roundtrip() {
    let f = RegressionFixture {
        fixture_id: "fix-1".into(),
        property_id: "P1".into(),
        description: "d".into(),
        replay_actions: vec![TransitionLabel::new("go"), TransitionLabel::new("stop")],
        expected_final_state: StateId::new("halted"),
        expects_violation: true,
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: RegressionFixture = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

#[test]
fn interference_report_serde_roundtrip() {
    let r = InterferenceReport {
        controller_a: ControllerId::new("router"),
        controller_b: ControllerId::new("optimizer"),
        resource: SharedResource::new("budget"),
        severity: InterferenceSeverity::Serious,
        description: "contention".into(),
        mitigation: Some("add lock".into()),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: InterferenceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn composition_check_serde_roundtrip() {
    let mut c = CompositionCheck::new(
        vec![ControllerId::new("a"), ControllerId::new("b")],
        vec![SharedResource::new("r")],
    );
    c.add_interference(InterferenceReport {
        controller_a: ControllerId::new("a"),
        controller_b: ControllerId::new("b"),
        resource: SharedResource::new("r"),
        severity: InterferenceSeverity::Benign,
        description: "benign".into(),
        mitigation: None,
    });
    let json = serde_json::to_string(&c).unwrap();
    let back: CompositionCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ── SchedulerAutomaton ───────────────────────────────────────────────────

#[test]
fn automaton_new_initial_state_in_states() {
    let a = SchedulerAutomaton::new("test", StateId::new("init"));
    assert_eq!(a.states.len(), 1);
    assert!(a.states.contains(&StateId::new("init")));
    assert_eq!(a.initial_state, StateId::new("init"));
    assert!(a.transitions.is_empty());
    assert!(a.alphabet.is_empty());
    assert!(a.accepting_states.is_empty());
}

#[test]
fn automaton_add_state_increases_count() {
    let mut a = SchedulerAutomaton::new("test", StateId::new("s0"));
    a.add_state(StateId::new("s1"));
    assert_eq!(a.states.len(), 2);
}

#[test]
fn automaton_add_accepting_also_adds_state() {
    let mut a = SchedulerAutomaton::new("test", StateId::new("s0"));
    a.add_accepting(StateId::new("s_accept"));
    assert!(a.states.contains(&StateId::new("s_accept")));
    assert!(a.accepting_states.contains(&StateId::new("s_accept")));
}

#[test]
fn automaton_add_transition_updates_states_and_alphabet() {
    let mut a = SchedulerAutomaton::new("test", StateId::new("s0"));
    a.add_transition(Transition {
        from: StateId::new("s0"),
        label: TransitionLabel::new("go"),
        to: StateId::new("s1"),
        guard: None,
    });
    assert!(a.states.contains(&StateId::new("s1")));
    assert!(a.alphabet.contains(&TransitionLabel::new("go")));
    assert_eq!(a.transitions.len(), 1);
}

#[test]
fn automaton_transitions_from_correct() {
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
    assert_eq!(a.transitions_from(&StateId::new("s0")).len(), 2);
    assert_eq!(a.transitions_from(&StateId::new("s1")).len(), 1);
    assert_eq!(a.transitions_from(&StateId::new("s2")).len(), 0);
}

#[test]
fn automaton_is_reachable_correct() {
    let mut a = SchedulerAutomaton::new("test", StateId::new("s0"));
    a.add_transition(Transition {
        from: StateId::new("s0"),
        label: TransitionLabel::new("go"),
        to: StateId::new("s1"),
        guard: None,
    });
    a.add_state(StateId::new("unreachable"));
    assert!(a.is_reachable(&StateId::new("s0")));
    assert!(a.is_reachable(&StateId::new("s1")));
    assert!(!a.is_reachable(&StateId::new("unreachable")));
}

#[test]
fn automaton_dead_states_correct() {
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
fn automaton_is_deterministic_true() {
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
fn automaton_is_deterministic_false() {
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
fn automaton_derive_id_deterministic() {
    let a1 = SchedulerAutomaton::new("test", StateId::new("s0"));
    let a2 = SchedulerAutomaton::new("test", StateId::new("s0"));
    assert_eq!(a1.derive_id(), a2.derive_id());
}

#[test]
fn automaton_derive_id_differs_by_name() {
    let a1 = SchedulerAutomaton::new("alpha", StateId::new("s0"));
    let a2 = SchedulerAutomaton::new("beta", StateId::new("s0"));
    assert_ne!(a1.derive_id(), a2.derive_id());
}

#[test]
fn automaton_serde_roundtrip() {
    let mut a = SchedulerAutomaton::new("test", StateId::new("s0"));
    a.add_transition(Transition {
        from: StateId::new("s0"),
        label: TransitionLabel::new("go"),
        to: StateId::new("s1"),
        guard: Some("x > 0".into()),
    });
    a.add_accepting(StateId::new("s1"));
    let json = serde_json::to_string(&a).unwrap();
    let back: SchedulerAutomaton = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

// ── canonical automata ───────────────────────────────────────────────────

#[test]
fn scheduler_lifecycle_8_states_14_transitions() {
    let a = scheduler_lifecycle_automaton();
    assert_eq!(a.states.len(), 8);
    assert_eq!(a.transitions.len(), 14);
}

#[test]
fn scheduler_lifecycle_no_dead_states() {
    let a = scheduler_lifecycle_automaton();
    assert!(a.dead_states().is_empty());
}

#[test]
fn scheduler_lifecycle_all_reachable() {
    let a = scheduler_lifecycle_automaton();
    for state in &a.states {
        assert!(a.is_reachable(state), "unreachable: {state:?}");
    }
}

#[test]
fn scheduler_lifecycle_is_deterministic() {
    assert!(scheduler_lifecycle_automaton().is_deterministic());
}

#[test]
fn scheduler_lifecycle_accepting_idle_and_halted() {
    let a = scheduler_lifecycle_automaton();
    assert_eq!(a.accepting_states.len(), 2);
    assert!(a.accepting_states.contains(&StateId::new("idle")));
    assert!(a.accepting_states.contains(&StateId::new("halted")));
}

#[test]
fn scheduler_lifecycle_initial_is_idle() {
    assert_eq!(
        scheduler_lifecycle_automaton().initial_state,
        StateId::new("idle")
    );
}

#[test]
fn fallback_automaton_4_states_9_transitions() {
    let a = fallback_transition_automaton();
    assert_eq!(a.states.len(), 4);
    assert_eq!(a.transitions.len(), 9);
}

#[test]
fn fallback_automaton_no_dead_states() {
    assert!(fallback_transition_automaton().dead_states().is_empty());
}

#[test]
fn fallback_automaton_all_reachable() {
    let a = fallback_transition_automaton();
    for state in &a.states {
        assert!(a.is_reachable(state), "unreachable: {state:?}");
    }
}

#[test]
fn fallback_automaton_is_deterministic() {
    assert!(fallback_transition_automaton().is_deterministic());
}

#[test]
fn fallback_automaton_accepting_adaptive_and_halted() {
    let a = fallback_transition_automaton();
    assert_eq!(a.accepting_states.len(), 2);
    assert!(a.accepting_states.contains(&StateId::new("adaptive")));
    assert!(a.accepting_states.contains(&StateId::new("halted")));
}

#[test]
fn fallback_automaton_initial_is_adaptive() {
    assert_eq!(
        fallback_transition_automaton().initial_state,
        StateId::new("adaptive")
    );
}

// ── canonical_scheduler_properties ───────────────────────────────────────

#[test]
fn canonical_properties_count_8() {
    assert_eq!(canonical_scheduler_properties().len(), 8);
}

#[test]
fn canonical_properties_unique_ids() {
    let props = canonical_scheduler_properties();
    let ids: BTreeSet<&str> = props.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids.len(), 8);
}

#[test]
fn canonical_properties_cover_all_kinds() {
    let props = canonical_scheduler_properties();
    let kinds: BTreeSet<PropertyKind> = props.iter().map(|p| p.kind).collect();
    assert!(kinds.contains(&PropertyKind::Safety));
    assert!(kinds.contains(&PropertyKind::Liveness));
    assert!(kinds.contains(&PropertyKind::Fairness));
    assert!(kinds.contains(&PropertyKind::Determinism));
    assert!(kinds.contains(&PropertyKind::Composition));
}

#[test]
fn canonical_properties_all_have_formulas() {
    for prop in canonical_scheduler_properties() {
        assert!(!prop.formula.is_empty(), "empty formula for {}", prop.id);
    }
}

#[test]
fn canonical_properties_all_have_components() {
    for prop in canonical_scheduler_properties() {
        assert!(!prop.components.is_empty(), "no components for {}", prop.id);
    }
}

// ── RegressionFixture::from_counterexample ───────────────────────────────

#[test]
fn fixture_from_counterexample_copies_fields() {
    let cx = Counterexample {
        property_id: "P-SAFETY-01".into(),
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
        violation_description: "partial state".into(),
    };
    let fix = RegressionFixture::from_counterexample("fix-1", &cx);
    assert_eq!(fix.fixture_id, "fix-1");
    assert_eq!(fix.property_id, "P-SAFETY-01");
    assert_eq!(fix.replay_actions.len(), 2);
    assert_eq!(fix.expected_final_state, StateId::new("safe_mode"));
    assert!(fix.expects_violation);
}

#[test]
fn fixture_from_empty_counterexample_uses_unknown() {
    let cx = Counterexample {
        property_id: "P-EMPTY".into(),
        trace: vec![],
        violation_description: "empty".into(),
    };
    let fix = RegressionFixture::from_counterexample("fix-e", &cx);
    assert_eq!(fix.expected_final_state, StateId::new("unknown"));
    assert!(fix.replay_actions.is_empty());
}

#[test]
fn fixture_derive_id_deterministic() {
    let f1 = RegressionFixture {
        fixture_id: "fix-1".into(),
        property_id: "P1".into(),
        description: "d".into(),
        replay_actions: vec![],
        expected_final_state: StateId::new("idle"),
        expects_violation: false,
    };
    let f2 = f1.clone();
    assert_eq!(f1.derive_id(), f2.derive_id());
}

// ── CompositionCheck ─────────────────────────────────────────────────────

#[test]
fn composition_new_is_compatible() {
    let c = CompositionCheck::new(
        vec![ControllerId::new("a"), ControllerId::new("b")],
        vec![SharedResource::new("r")],
    );
    assert!(c.overall_compatible);
    assert_eq!(c.critical_count(), 0);
    assert_eq!(c.serious_count(), 0);
    assert!(c.interferences.is_empty());
}

#[test]
fn composition_benign_stays_compatible() {
    let mut c = CompositionCheck::new(
        vec![ControllerId::new("a"), ControllerId::new("b")],
        vec![SharedResource::new("r")],
    );
    c.add_interference(InterferenceReport {
        controller_a: ControllerId::new("a"),
        controller_b: ControllerId::new("b"),
        resource: SharedResource::new("r"),
        severity: InterferenceSeverity::Benign,
        description: "d".into(),
        mitigation: None,
    });
    assert!(c.overall_compatible);
}

#[test]
fn composition_none_stays_compatible() {
    let mut c = CompositionCheck::new(
        vec![ControllerId::new("a"), ControllerId::new("b")],
        vec![SharedResource::new("r")],
    );
    c.add_interference(InterferenceReport {
        controller_a: ControllerId::new("a"),
        controller_b: ControllerId::new("b"),
        resource: SharedResource::new("r"),
        severity: InterferenceSeverity::None,
        description: "d".into(),
        mitigation: None,
    });
    assert!(c.overall_compatible);
}

#[test]
fn composition_serious_makes_incompatible() {
    let mut c = CompositionCheck::new(
        vec![ControllerId::new("a"), ControllerId::new("b")],
        vec![SharedResource::new("r")],
    );
    c.add_interference(InterferenceReport {
        controller_a: ControllerId::new("a"),
        controller_b: ControllerId::new("b"),
        resource: SharedResource::new("r"),
        severity: InterferenceSeverity::Serious,
        description: "d".into(),
        mitigation: None,
    });
    assert!(!c.overall_compatible);
    assert_eq!(c.serious_count(), 1);
    assert_eq!(c.critical_count(), 0);
}

#[test]
fn composition_critical_makes_incompatible() {
    let mut c = CompositionCheck::new(
        vec![ControllerId::new("a"), ControllerId::new("b")],
        vec![SharedResource::new("r")],
    );
    c.add_interference(InterferenceReport {
        controller_a: ControllerId::new("a"),
        controller_b: ControllerId::new("b"),
        resource: SharedResource::new("r"),
        severity: InterferenceSeverity::Critical,
        description: "d".into(),
        mitigation: Some("fix".into()),
    });
    assert!(!c.overall_compatible);
    assert_eq!(c.critical_count(), 1);
}

#[test]
fn composition_derive_id_deterministic() {
    let c1 = CompositionCheck::new(vec![ControllerId::new("a"), ControllerId::new("b")], vec![]);
    let c2 = CompositionCheck::new(vec![ControllerId::new("a"), ControllerId::new("b")], vec![]);
    assert_eq!(c1.derive_id(), c2.derive_id());
}

// ── InvariantRegistry ────────────────────────────────────────────────────

#[test]
fn registry_new_is_empty() {
    let reg = InvariantRegistry::new();
    assert_eq!(reg.verified_count(), 0);
    assert_eq!(reg.violated_count(), 0);
    assert_eq!(reg.overall_status(), VerificationStatus::Pending);
    assert!(reg.properties.is_empty());
    assert!(reg.results.is_empty());
    assert!(reg.fixtures.is_empty());
}

#[test]
fn registry_default_equals_new() {
    assert_eq!(InvariantRegistry::default(), InvariantRegistry::new());
}

#[test]
fn registry_all_verified_status() {
    let mut reg = InvariantRegistry::new();
    reg.record_result(VerificationResult {
        property_id: "P1".into(),
        status: VerificationStatus::Verified,
        counterexample: None,
        states_explored: 100,
        verification_time_us: 500,
    });
    assert_eq!(reg.overall_status(), VerificationStatus::Verified);
    assert_eq!(reg.verified_count(), 1);
}

#[test]
fn registry_any_violated_status() {
    let mut reg = InvariantRegistry::new();
    reg.record_result(VerificationResult {
        property_id: "P1".into(),
        status: VerificationStatus::Verified,
        counterexample: None,
        states_explored: 100,
        verification_time_us: 500,
    });
    reg.record_result(VerificationResult {
        property_id: "P2".into(),
        status: VerificationStatus::Violated,
        counterexample: None,
        states_explored: 200,
        verification_time_us: 1000,
    });
    assert_eq!(reg.overall_status(), VerificationStatus::Violated);
}

#[test]
fn registry_mixed_status_is_inconclusive() {
    let mut reg = InvariantRegistry::new();
    reg.record_result(VerificationResult {
        property_id: "P1".into(),
        status: VerificationStatus::Verified,
        counterexample: None,
        states_explored: 100,
        verification_time_us: 500,
    });
    reg.record_result(VerificationResult {
        property_id: "P2".into(),
        status: VerificationStatus::Inconclusive,
        counterexample: None,
        states_explored: 100,
        verification_time_us: 5000,
    });
    assert_eq!(reg.overall_status(), VerificationStatus::Inconclusive);
}

#[test]
fn registry_auto_fixture_from_violated_with_counterexample() {
    let mut reg = InvariantRegistry::new();
    reg.record_result(VerificationResult {
        property_id: "P3".into(),
        status: VerificationStatus::Violated,
        counterexample: Some(Counterexample {
            property_id: "P3".into(),
            trace: vec![CounterexampleStep {
                step: 0,
                state: StateId::new("idle"),
                action: TransitionLabel::new("fail"),
                next_state: StateId::new("halted"),
                state_vars: BTreeMap::new(),
            }],
            violation_description: "test".into(),
        }),
        states_explored: 50,
        verification_time_us: 200,
    });
    assert_eq!(reg.fixtures.len(), 1);
    assert_eq!(reg.fixtures[0].property_id, "P3");
}

#[test]
fn registry_no_fixture_without_counterexample() {
    let mut reg = InvariantRegistry::new();
    reg.record_result(VerificationResult {
        property_id: "P4".into(),
        status: VerificationStatus::Violated,
        counterexample: None,
        states_explored: 50,
        verification_time_us: 200,
    });
    assert!(reg.fixtures.is_empty());
}

#[test]
fn registry_get_result_existing() {
    let mut reg = InvariantRegistry::new();
    reg.record_result(VerificationResult {
        property_id: "P1".into(),
        status: VerificationStatus::Verified,
        counterexample: None,
        states_explored: 100,
        verification_time_us: 500,
    });
    let r = reg.get_result("P1").unwrap();
    assert_eq!(r.status, VerificationStatus::Verified);
}

#[test]
fn registry_get_result_missing() {
    let reg = InvariantRegistry::new();
    assert!(reg.get_result("P-MISSING").is_none());
}

#[test]
fn registry_derive_id_deterministic() {
    let r1 = InvariantRegistry::new();
    let r2 = InvariantRegistry::new();
    assert_eq!(r1.derive_id(), r2.derive_id());
}

#[test]
fn registry_derive_id_changes_after_result() {
    let r1 = InvariantRegistry::new();
    let mut r2 = InvariantRegistry::new();
    r2.record_result(VerificationResult {
        property_id: "P1".into(),
        status: VerificationStatus::Verified,
        counterexample: None,
        states_explored: 100,
        verification_time_us: 500,
    });
    assert_ne!(r1.derive_id(), r2.derive_id());
}

#[test]
fn registry_serde_roundtrip() {
    let mut reg = InvariantRegistry::new();
    for prop in canonical_scheduler_properties() {
        reg.add_property(prop);
    }
    let json = serde_json::to_string(&reg).unwrap();
    let back: InvariantRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, back);
}

// ── VerificationResult::derive_id ────────────────────────────────────────

#[test]
fn verification_result_derive_id_deterministic() {
    let r = VerificationResult {
        property_id: "P-SAFETY-01".into(),
        status: VerificationStatus::Verified,
        counterexample: None,
        states_explored: 1000,
        verification_time_us: 5000,
    };
    assert_eq!(r.derive_id(), r.derive_id());
}
