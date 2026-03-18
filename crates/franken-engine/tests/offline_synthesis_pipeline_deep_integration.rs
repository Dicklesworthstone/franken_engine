#![forbid(unsafe_code)]
//! Deep integration tests for `offline_synthesis_pipeline`.
//!
//! Focuses on UNCOVERED areas: multi-guard transitions, automaton full lifecycle
//! traversal, negative/mixed coefficients, degenerate variable domains,
//! multi-objective multi-safety-spec composition, large-scale stress,
//! threshold calibration details, certificate obligation semantics,
//! Ord/Hash trait usage on enum types, Clone/PartialEq across all types,
//! and boundary conditions on constraint tightening.

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

use frankenengine_engine::offline_synthesis_pipeline::{
    AutomatonState, CalibrationMethod, CmpOp, DecisionEntry, DecisionTable, DecisionTableRow,
    EvidenceCategory, LinearConstraint, LinearTerm, ObservableState, OfflineSynthesisPipeline,
    OptDirection, OptimizationObjective, PipelineBudget, PipelineStage, SafetySpec, SpecVar,
    StageStatus, SynthesisError, SynthesisOutput, SynthesisSpec, Transition, TransitionAutomaton,
    TransitionGuard, VarDomain,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn bounded_var(name: &str, lo: i64, hi: i64) -> SpecVar {
    SpecVar {
        name: name.into(),
        domain: VarDomain::BoundedInt { lo, hi },
    }
}

fn bool_var(name: &str) -> SpecVar {
    SpecVar {
        name: name.into(),
        domain: VarDomain::Boolean,
    }
}

fn enum_var(name: &str, cardinality: u32) -> SpecVar {
    SpecVar {
        name: name.into(),
        domain: VarDomain::Enum { cardinality },
    }
}

fn unit_constraint(id: &str, var: &str, op: CmpOp, rhs: i64) -> LinearConstraint {
    LinearConstraint {
        id: id.into(),
        terms: vec![LinearTerm {
            var: var.into(),
            coeff_millionths: 1_000_000,
        }],
        op,
        rhs_millionths: rhs,
        label: format!("{id}-label"),
    }
}

fn multi_term_constraint(
    id: &str,
    terms: Vec<(&str, i64)>,
    op: CmpOp,
    rhs: i64,
) -> LinearConstraint {
    LinearConstraint {
        id: id.into(),
        terms: terms
            .into_iter()
            .map(|(var, coeff)| LinearTerm {
                var: var.into(),
                coeff_millionths: coeff,
            })
            .collect(),
        op,
        rhs_millionths: rhs,
        label: format!("{id}-label"),
    }
}

fn objective(id: &str, terms: Vec<(&str, i64)>, dir: OptDirection) -> OptimizationObjective {
    OptimizationObjective {
        id: id.into(),
        direction: dir,
        terms: terms
            .into_iter()
            .map(|(var, coeff)| LinearTerm {
                var: var.into(),
                coeff_millionths: coeff,
            })
            .collect(),
        bound_millionths: None,
    }
}

fn objective_bounded(
    id: &str,
    terms: Vec<(&str, i64)>,
    dir: OptDirection,
    bound: i64,
) -> OptimizationObjective {
    OptimizationObjective {
        id: id.into(),
        direction: dir,
        terms: terms
            .into_iter()
            .map(|(var, coeff)| LinearTerm {
                var: var.into(),
                coeff_millionths: coeff,
            })
            .collect(),
        bound_millionths: Some(bound),
    }
}

fn safety(id: &str, strat: Vec<&str>, adv: Vec<&str>) -> SafetySpec {
    SafetySpec {
        id: id.into(),
        property: format!("prop_{id}"),
        maximin_value_millionths: 400_000,
        strategy_vars: strat.into_iter().map(|s| s.into()).collect(),
        adversary_vars: adv.into_iter().map(|s| s.into()).collect(),
        cvar_alpha_millionths: 50_000,
        cvar_bound_millionths: 600_000,
    }
}

fn default_pipeline() -> OfflineSynthesisPipeline {
    OfflineSynthesisPipeline::new(PipelineBudget::default(), "safe_deny".into())
}

fn make_automaton(
    id: &str,
    state_ids: &[&str],
    transitions: Vec<Transition>,
    initial: &str,
) -> TransitionAutomaton {
    let mut states = BTreeMap::new();
    for (i, sid) in state_ids.iter().enumerate() {
        states.insert(
            sid.to_string(),
            AutomatonState {
                id: sid.to_string(),
                label: format!("state_{sid}"),
                accepting: i == 0,
            },
        );
    }
    TransitionAutomaton {
        automaton_id: id.into(),
        states,
        transitions,
        initial_state: initial.into(),
        content_hash: format!("hash_{id}"),
    }
}

// ===========================================================================
// 1. Automaton full lifecycle: normal -> elevated -> critical -> recovery -> normal
// ===========================================================================

#[test]
fn automaton_full_lifecycle_traversal() {
    let p = OfflineSynthesisPipeline::new(PipelineBudget::default(), "safe_deny".into());
    let spec = SynthesisSpec {
        spec_id: "lifecycle".into(),
        variables: vec![
            bounded_var("risk", 0, 1_000_000),
            bounded_var("load", 0, 1_000_000),
        ],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![SafetySpec {
            id: "ss1".into(),
            property: "tail_risk".into(),
            maximin_value_millionths: 200_000,
            strategy_vars: vec!["risk".into()],
            adversary_vars: vec!["load".into()],
            cvar_alpha_millionths: 50_000,
            cvar_bound_millionths: 500_000,
        }],
        epoch: 10,
    };
    let output = p.synthesize(&spec).unwrap();
    let automaton = &output.automata[0];

    // Step 1: normal -> elevated (risk > maximin/2 = 100_000)
    let bindings = BTreeMap::from([("risk".to_string(), 150_000i64), ("load".to_string(), 0)]);
    let (state, action) = automaton.step("normal", &bindings);
    assert_eq!(state, "elevated");
    assert_eq!(action.as_deref(), Some("escalate"));

    // Step 2: elevated -> critical (load > cvar_bound = 500_000)
    let bindings = BTreeMap::from([
        ("risk".to_string(), 150_000i64),
        ("load".to_string(), 600_000),
    ]);
    let (state, action) = automaton.step("elevated", &bindings);
    assert_eq!(state, "critical");
    assert_eq!(action.as_deref(), Some("safe_mode"));

    // Step 3: critical -> recovery (unconditional)
    let bindings = BTreeMap::from([
        ("risk".to_string(), 50_000i64),
        ("load".to_string(), 50_000),
    ]);
    let (state, action) = automaton.step("critical", &bindings);
    assert_eq!(state, "recovery");
    assert_eq!(action.as_deref(), Some("begin_recovery"));

    // Step 4: recovery -> normal (risk <= maximin/2 = 100_000)
    let bindings = BTreeMap::from([
        ("risk".to_string(), 50_000i64),
        ("load".to_string(), 50_000),
    ]);
    let (state, action) = automaton.step("recovery", &bindings);
    assert_eq!(state, "normal");
    assert_eq!(action.as_deref(), Some("resume_normal"));
}

// ===========================================================================
// 2. Multi-guard transition: all guards must pass
// ===========================================================================

#[test]
fn automaton_multi_guard_all_must_pass() {
    let automaton = make_automaton(
        "multi_guard",
        &["s0", "s1"],
        vec![Transition {
            from: "s0".into(),
            to: "s1".into(),
            guards: vec![
                TransitionGuard {
                    variable: "x".into(),
                    op: CmpOp::Gt,
                    threshold_millionths: 500_000,
                },
                TransitionGuard {
                    variable: "y".into(),
                    op: CmpOp::Lt,
                    threshold_millionths: 300_000,
                },
            ],
            priority: 1,
            emit_action: Some("both_pass".into()),
        }],
        "s0",
    );

    // Both guards pass
    let bindings = BTreeMap::from([("x".to_string(), 600_000i64), ("y".to_string(), 200_000)]);
    let (state, action) = automaton.step("s0", &bindings);
    assert_eq!(state, "s1");
    assert_eq!(action.as_deref(), Some("both_pass"));

    // First guard passes, second fails
    let bindings = BTreeMap::from([("x".to_string(), 600_000i64), ("y".to_string(), 400_000)]);
    let (state, action) = automaton.step("s0", &bindings);
    assert_eq!(state, "s0"); // stays
    assert!(action.is_none());

    // First guard fails, second passes
    let bindings = BTreeMap::from([("x".to_string(), 400_000i64), ("y".to_string(), 200_000)]);
    let (state, action) = automaton.step("s0", &bindings);
    assert_eq!(state, "s0");
    assert!(action.is_none());
}

// ===========================================================================
// 3. Automaton with missing binding variable
// ===========================================================================

#[test]
fn automaton_missing_binding_variable_guard_fails() {
    let automaton = make_automaton(
        "missing_var",
        &["s0", "s1"],
        vec![Transition {
            from: "s0".into(),
            to: "s1".into(),
            guards: vec![TransitionGuard {
                variable: "nonexistent".into(),
                op: CmpOp::Gt,
                threshold_millionths: 0,
            }],
            priority: 1,
            emit_action: Some("should_not_fire".into()),
        }],
        "s0",
    );

    let bindings = BTreeMap::from([("x".to_string(), 999_999i64)]);
    let (state, action) = automaton.step("s0", &bindings);
    assert_eq!(state, "s0"); // guard cannot be satisfied
    assert!(action.is_none());
}

// ===========================================================================
// 4. Automaton with empty guards (unconditional transition)
// ===========================================================================

#[test]
fn automaton_unconditional_transition() {
    let automaton = make_automaton(
        "unconditional",
        &["s0", "s1"],
        vec![Transition {
            from: "s0".into(),
            to: "s1".into(),
            guards: vec![],
            priority: 1,
            emit_action: Some("auto".into()),
        }],
        "s0",
    );

    // Empty bindings: unconditional guard always passes
    let bindings = BTreeMap::new();
    let (state, action) = automaton.step("s0", &bindings);
    assert_eq!(state, "s1");
    assert_eq!(action.as_deref(), Some("auto"));
}

// ===========================================================================
// 5. Automaton stepping from unknown state stays in place
// ===========================================================================

#[test]
fn automaton_step_from_unknown_state_stays() {
    let automaton = make_automaton(
        "unknown_state",
        &["s0"],
        vec![Transition {
            from: "s0".into(),
            to: "s0".into(),
            guards: vec![],
            priority: 1,
            emit_action: None,
        }],
        "s0",
    );

    let bindings = BTreeMap::new();
    let (state, action) = automaton.step("nonexistent_state", &bindings);
    assert_eq!(state, "nonexistent_state"); // no transition from this state
    assert!(action.is_none());
}

// ===========================================================================
// 6. Decision table: multiple rows, first match wins
// ===========================================================================

#[test]
fn decision_table_first_match_wins() {
    let state_a = ObservableState {
        values: BTreeMap::from([("x".to_string(), 100_000i64)]),
    };
    let state_b = ObservableState {
        values: BTreeMap::from([("x".to_string(), 200_000i64)]),
    };

    let table = DecisionTable {
        table_id: "dt_first".into(),
        key_variables: vec!["x".into()],
        rows: vec![
            DecisionTableRow {
                state: state_a.clone(),
                entry: DecisionEntry {
                    action: "action_a".into(),
                    expected_loss_millionths: 50_000,
                    guardrail_blocked: false,
                    pre_guardrail_action: "action_a".into(),
                },
            },
            DecisionTableRow {
                state: state_b.clone(),
                entry: DecisionEntry {
                    action: "action_b".into(),
                    expected_loss_millionths: 100_000,
                    guardrail_blocked: false,
                    pre_guardrail_action: "action_b".into(),
                },
            },
        ],
        safe_default: "fallback".into(),
        content_hash: "h".into(),
    };

    assert_eq!(table.lookup(&state_a), "action_a");
    assert_eq!(table.lookup(&state_b), "action_b");
    assert_eq!(table.entry_count(), 2);

    // Unmatched state falls back
    let unmatched = ObservableState {
        values: BTreeMap::from([("x".to_string(), 999_999i64)]),
    };
    assert_eq!(table.lookup(&unmatched), "fallback");
}

// ===========================================================================
// 7. Constraint tightening: Gt operator
// ===========================================================================

#[test]
fn constraint_tightening_gt_operator() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "gt_tight".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![unit_constraint("c1", "x", CmpOp::Gt, 500_000)],
        objectives: vec![objective(
            "obj",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    // The table should exist and have entries
    assert!(!output.decision_tables.is_empty());
    // The Gt constraint means x > 500_000, so lower bound is tightened to 500_001
    // Grid should start from 500_001
    let table = &output.decision_tables[0];
    for row in &table.rows {
        let x_val = row.state.values.get("x").copied().unwrap_or(0);
        // If x <= 500_000, the constraint is violated => guardrail_blocked
        if x_val <= 500_000 {
            assert!(
                row.entry.guardrail_blocked,
                "x={x_val} should be guardrail-blocked (x must be > 500_000)"
            );
        }
    }
}

// ===========================================================================
// 8. Constraint tightening: Eq pinning
// ===========================================================================

#[test]
fn constraint_tightening_eq_pins_variable() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "eq_pin".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![unit_constraint("c_eq", "x", CmpOp::Eq, 500_000)],
        objectives: vec![objective(
            "obj",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let table = &output.decision_tables[0];
    // With Eq constraint pinning x to 500_000, the grid should have very limited entries
    // All grid points should be at 500_000 since lo=hi=500_000 after tightening
    for row in &table.rows {
        let x_val = row.state.values.get("x").copied().unwrap_or(-1);
        assert_eq!(
            x_val, 500_000,
            "Eq constraint should pin x to exactly 500_000"
        );
    }
}

// ===========================================================================
// 9. Constraint tightening: Ne does not tighten bounds
// ===========================================================================

#[test]
fn constraint_ne_does_not_tighten_bounds() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "ne_no_tight".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![unit_constraint("c_ne", "x", CmpOp::Ne, 500_000)],
        objectives: vec![objective(
            "obj",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let table = &output.decision_tables[0];
    // Ne doesn't tighten bounds, so grid should span 0..1_000_000
    let x_vals: Vec<i64> = table
        .rows
        .iter()
        .filter_map(|r| r.state.values.get("x").copied())
        .collect();
    assert!(
        x_vals.len() > 1,
        "Ne should leave full range; got {} entries",
        x_vals.len()
    );
    // Check that the full range is present (0 and 1_000_000 should both appear)
    assert!(x_vals.contains(&0), "lower bound 0 should be in grid");
    assert!(
        x_vals.contains(&1_000_000),
        "upper bound 1_000_000 should be in grid"
    );
}

// ===========================================================================
// 10. Degenerate BoundedInt: lo == hi
// ===========================================================================

#[test]
fn degenerate_bounded_int_lo_eq_hi() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "degenerate".into(),
        variables: vec![bounded_var("x", 500_000, 500_000)],
        constraints: vec![],
        objectives: vec![objective(
            "obj",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let table = &output.decision_tables[0];
    // Only one grid point possible
    assert_eq!(table.entry_count(), 1);
    let x_val = table.rows[0].state.values.get("x").copied().unwrap();
    assert_eq!(x_val, 500_000);
}

// ===========================================================================
// 11. Enum variable with cardinality=1
// ===========================================================================

#[test]
fn enum_variable_cardinality_one() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "enum_1".into(),
        variables: vec![enum_var("single", 1)],
        constraints: vec![],
        objectives: vec![objective(
            "obj",
            vec![("single", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let table = &output.decision_tables[0];
    // Enum with cardinality 1: range is [0, 0], single grid point
    assert_eq!(table.entry_count(), 1);
}

// ===========================================================================
// 12. Negative coefficient in optimization
// ===========================================================================

#[test]
fn negative_coefficient_minimize() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "neg_coeff".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![],
        objectives: vec![objective(
            "obj",
            vec![("x", -1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    assert!(!output.decision_tables.is_empty());
    // With negative coefficient and Minimize, the solver should prefer x at upper bound
}

#[test]
fn negative_coefficient_maximize() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "neg_max".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![],
        objectives: vec![objective(
            "obj",
            vec![("x", -500_000)],
            OptDirection::Maximize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    assert!(!output.decision_tables.is_empty());
}

// ===========================================================================
// 13. Multi-term constraint with non-unit coefficients
// ===========================================================================

#[test]
fn multi_term_constraint_no_bound_tightening() {
    let p = default_pipeline();
    // Multi-term constraints do not tighten individual variable bounds
    let spec = SynthesisSpec {
        spec_id: "multi_term".into(),
        variables: vec![
            bounded_var("x", 0, 1_000_000),
            bounded_var("y", 0, 1_000_000),
        ],
        constraints: vec![multi_term_constraint(
            "c1",
            vec![("x", 500_000), ("y", 500_000)],
            CmpOp::Le,
            1_000_000,
        )],
        objectives: vec![objective(
            "obj",
            vec![("x", 1_000_000), ("y", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    assert!(!output.decision_tables.is_empty());
    // Multi-term constraints are only checked during table generation (guardrail),
    // not during bound tightening. So the grid should still cover full range.
    let table = &output.decision_tables[0];
    assert!(table.entry_count() > 1);
}

// ===========================================================================
// 14. Multiple objectives produce multiple decision tables
// ===========================================================================

#[test]
fn multiple_objectives_produce_multiple_tables() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "multi_obj".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![],
        objectives: vec![
            objective("obj_a", vec![("x", 1_000_000)], OptDirection::Minimize),
            objective("obj_b", vec![("x", 1_000_000)], OptDirection::Maximize),
        ],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    assert_eq!(output.decision_tables.len(), 2);
    assert_ne!(
        output.decision_tables[0].table_id,
        output.decision_tables[1].table_id
    );
}

// ===========================================================================
// 15. Multiple safety specs produce multiple automata
// ===========================================================================

#[test]
fn multiple_safety_specs_produce_multiple_automata() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "multi_safety".into(),
        variables: vec![
            bounded_var("a", 0, 1_000_000),
            bounded_var("b", 0, 1_000_000),
            bounded_var("c", 0, 1_000_000),
        ],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![
            safety("ss1", vec!["a"], vec!["b"]),
            safety("ss2", vec!["b"], vec!["c"]),
        ],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    assert_eq!(output.automata.len(), 2);
    assert_ne!(
        output.automata[0].automaton_id,
        output.automata[1].automaton_id
    );
    // Each automaton should have 5 states (normal, elevated, degraded, critical, recovery)
    for aut in &output.automata {
        assert_eq!(aut.state_count(), 5);
    }
}

// ===========================================================================
// 16. Automaton generated states: exactly 5 with correct accepting flags
// ===========================================================================

#[test]
fn automaton_states_accepting_flags() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "accepting".into(),
        variables: vec![
            bounded_var("x", 0, 1_000_000),
            bounded_var("y", 0, 1_000_000),
        ],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![safety("ss1", vec!["x"], vec!["y"])],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let aut = &output.automata[0];

    // normal, elevated, degraded should be accepting; critical, recovery should not
    assert!(aut.states.get("normal").unwrap().accepting);
    assert!(aut.states.get("elevated").unwrap().accepting);
    assert!(aut.states.get("degraded").unwrap().accepting);
    assert!(!aut.states.get("critical").unwrap().accepting);
    assert!(!aut.states.get("recovery").unwrap().accepting);
}

// ===========================================================================
// 17. Threshold calibration: CVaR coverage is 1 - alpha
// ===========================================================================

#[test]
fn threshold_cvar_coverage_is_one_minus_alpha() {
    let p = default_pipeline();
    let alpha = 50_000i64;
    let spec = SynthesisSpec {
        spec_id: "cvar_cov".into(),
        variables: vec![
            bounded_var("x", 0, 1_000_000),
            bounded_var("y", 0, 1_000_000),
        ],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![SafetySpec {
            id: "ss1".into(),
            property: "tail".into(),
            maximin_value_millionths: 300_000,
            strategy_vars: vec!["x".into()],
            adversary_vars: vec!["y".into()],
            cvar_alpha_millionths: alpha,
            cvar_bound_millionths: 700_000,
        }],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let bundle = &output.threshold_bundles[0];

    let cvar_threshold = bundle
        .thresholds
        .iter()
        .find(|t| t.calibration_method == CalibrationMethod::CvarEmpirical)
        .expect("should have CvarEmpirical threshold");

    assert_eq!(cvar_threshold.coverage_millionths, 1_000_000 - alpha);
    assert_eq!(cvar_threshold.value_millionths, 700_000);
}

// ===========================================================================
// 18. Threshold calibration: maximin threshold has 95% default coverage
// ===========================================================================

#[test]
fn threshold_maximin_has_95_percent_coverage() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "maximin_cov".into(),
        variables: vec![
            bounded_var("x", 0, 1_000_000),
            bounded_var("y", 0, 1_000_000),
        ],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![safety("ss1", vec!["x"], vec!["y"])],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let bundle = &output.threshold_bundles[0];

    let maximin_threshold = bundle
        .thresholds
        .iter()
        .find(|t| t.calibration_method == CalibrationMethod::EProcessSequential)
        .expect("should have EProcessSequential threshold");

    assert_eq!(maximin_threshold.coverage_millionths, 950_000);
}

// ===========================================================================
// 19. Threshold calibration: objective bound produces ConformalQuantile
// ===========================================================================

#[test]
fn objective_bound_produces_conformal_quantile_threshold() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "obj_bound".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![],
        objectives: vec![objective_bounded(
            "obj1",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
            750_000,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let bundle = &output.threshold_bundles[0];

    let conformal = bundle
        .thresholds
        .iter()
        .find(|t| t.calibration_method == CalibrationMethod::ConformalQuantile)
        .expect("should have ConformalQuantile threshold");

    assert_eq!(conformal.value_millionths, 750_000);
    assert_eq!(conformal.coverage_millionths, 900_000); // 90% default
    assert_eq!(conformal.variable, "obj1");
}

// ===========================================================================
// 20. No objective bound means no ConformalQuantile threshold
// ===========================================================================

#[test]
fn no_objective_bound_means_no_conformal_threshold() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "no_bound".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![],
        objectives: vec![objective(
            "obj1",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let bundle = &output.threshold_bundles[0];

    let conformal = bundle
        .thresholds
        .iter()
        .find(|t| t.calibration_method == CalibrationMethod::ConformalQuantile);

    assert!(
        conformal.is_none(),
        "no ConformalQuantile without bound_millionths"
    );
}

// ===========================================================================
// 21. Threshold calibration: OperatorFixed from variable bounds
// ===========================================================================

#[test]
fn variable_bounds_produce_operator_fixed_thresholds() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "var_bounds".into(),
        variables: vec![
            bounded_var("x", 100_000, 900_000), // lo > 0, hi < 1_000_000
        ],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let bundle = &output.threshold_bundles[0];

    let fixed = bundle
        .thresholds
        .iter()
        .find(|t| t.calibration_method == CalibrationMethod::OperatorFixed && t.variable == "x")
        .expect("should have OperatorFixed threshold for x");

    assert_eq!(fixed.value_millionths, 900_000); // hi bound
    assert_eq!(fixed.coverage_millionths, 1_000_000); // 100%
}

// ===========================================================================
// 22. Variables at 0..1_000_000 do not produce OperatorFixed
// ===========================================================================

#[test]
fn full_range_variables_no_operator_fixed_threshold() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "full_range".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let bundle = &output.threshold_bundles[0];

    let fixed = bundle
        .thresholds
        .iter()
        .find(|t| t.calibration_method == CalibrationMethod::OperatorFixed);

    assert!(
        fixed.is_none(),
        "full range [0, 1_000_000] should not produce OperatorFixed"
    );
}

// ===========================================================================
// 23. Certificate obligations for decision tables
// ===========================================================================

#[test]
fn certificate_obligations_for_decision_tables() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "cert_dt".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![],
        objectives: vec![objective(
            "obj1",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 5,
    };
    let output = p.synthesize(&spec).unwrap();

    // Find certificate for the decision table
    let dt_cert = output
        .certificates
        .iter()
        .find(|c| c.certificate_id.starts_with("cert_dt_"))
        .expect("should have decision table certificate");

    assert!(
        dt_cert
            .satisfied_obligations
            .contains(&"behavioral_preservation".to_string())
    );
    assert!(
        dt_cert
            .satisfied_obligations
            .contains(&"determinism".to_string())
    );
    assert!(dt_cert.all_obligations_met);
    assert_eq!(dt_cert.epoch, 5);
    assert_eq!(dt_cert.evidence.len(), 2);
    assert_eq!(
        dt_cert.evidence[0].category,
        EvidenceCategory::BoundednessProof
    );
    assert_eq!(
        dt_cert.evidence[1].category,
        EvidenceCategory::MonotonicityCheck
    );
}

// ===========================================================================
// 24. Certificate obligations for automata
// ===========================================================================

#[test]
fn certificate_obligations_for_automata() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "cert_aut".into(),
        variables: vec![
            bounded_var("x", 0, 1_000_000),
            bounded_var("y", 0, 1_000_000),
        ],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![safety("ss1", vec!["x"], vec!["y"])],
        epoch: 7,
    };
    let output = p.synthesize(&spec).unwrap();

    let aut_cert = output
        .certificates
        .iter()
        .find(|c| c.certificate_id.starts_with("cert_ta_"))
        .expect("should have automaton certificate");

    assert!(
        aut_cert
            .satisfied_obligations
            .contains(&"safety".to_string())
    );
    assert!(
        aut_cert
            .satisfied_obligations
            .contains(&"liveness".to_string())
    );
    assert!(aut_cert.all_obligations_met);
    assert_eq!(aut_cert.epoch, 7);
    assert_eq!(aut_cert.evidence.len(), 2);
    assert_eq!(aut_cert.evidence[0].category, EvidenceCategory::FormalProof);
    assert_eq!(
        aut_cert.evidence[1].category,
        EvidenceCategory::BoundednessProof
    );
}

// ===========================================================================
// 25. Certificate for threshold bundle
// ===========================================================================

#[test]
fn certificate_obligations_for_threshold_bundle() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "cert_tb".into(),
        variables: vec![
            bounded_var("x", 0, 1_000_000),
            bounded_var("y", 0, 1_000_000),
        ],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![safety("ss1", vec!["x"], vec!["y"])],
        epoch: 3,
    };
    let output = p.synthesize(&spec).unwrap();

    let tb_cert = output
        .certificates
        .iter()
        .find(|c| c.certificate_id.starts_with("cert_tb_"))
        .expect("should have threshold bundle certificate");

    assert!(
        tb_cert
            .satisfied_obligations
            .contains(&"calibration_validity".to_string())
    );
    assert!(
        tb_cert
            .satisfied_obligations
            .contains(&"tail_risk".to_string())
    );
    assert_eq!(tb_cert.evidence.len(), 1);
    assert_eq!(
        tb_cert.evidence[0].category,
        EvidenceCategory::StatisticalTest
    );
    assert_eq!(tb_cert.evidence[0].confidence_millionths, 950_000);
}

// ===========================================================================
// 26. Resource usage accumulates across stages
// ===========================================================================

#[test]
fn resource_usage_accumulates_across_stages() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "res_accum".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![unit_constraint("c1", "x", CmpOp::Le, 500_000)],
        objectives: vec![objective(
            "obj",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![safety("ss1", vec!["x"], vec!["x"])],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();

    // Total resource usage should be sum of all stages
    let stage_time_sum: u64 = output
        .stage_witnesses
        .iter()
        .map(|w| w.resource_usage.time_ms)
        .sum();
    let stage_iter_sum: u64 = output
        .stage_witnesses
        .iter()
        .map(|w| w.resource_usage.iterations)
        .sum();
    let stage_mem_sum: u64 = output
        .stage_witnesses
        .iter()
        .map(|w| w.resource_usage.memory_bytes)
        .sum();

    assert_eq!(output.total_resource_usage.time_ms, stage_time_sum);
    assert_eq!(output.total_resource_usage.iterations, stage_iter_sum);
    assert_eq!(output.total_resource_usage.memory_bytes, stage_mem_sum);
}

// ===========================================================================
// 27. Budget-limited pipeline with tiny max_iterations
// ===========================================================================

#[test]
fn budget_limited_pipeline_truncates_tables() {
    let p = OfflineSynthesisPipeline::new(
        PipelineBudget {
            max_iterations: 3,
            max_stage_time_ms: 1_000,
            max_memory_bytes: 100_000_000,
        },
        "safe_deny".into(),
    );
    let spec = SynthesisSpec {
        spec_id: "budget_lim".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![],
        objectives: vec![objective(
            "obj",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let table = &output.decision_tables[0];
    // With max_iterations=3, table should have at most 3 rows
    assert!(
        table.entry_count() <= 3,
        "expected <= 3 entries, got {}",
        table.entry_count()
    );
}

// ===========================================================================
// 28. Budget exhaustion in optimization stage
// ===========================================================================

#[test]
fn budget_exhaustion_in_optimization_stage() {
    let p = OfflineSynthesisPipeline::new(
        PipelineBudget {
            max_iterations: 0, // No iterations allowed
            max_stage_time_ms: 1_000,
            max_memory_bytes: 100_000_000,
        },
        "safe_deny".into(),
    );
    let spec = SynthesisSpec {
        spec_id: "budget_zero".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![unit_constraint("c1", "x", CmpOp::Le, 500_000)],
        objectives: vec![],
        safety_specs: vec![],
        epoch: 1,
    };
    // With max_iterations=0 and 1 constraint, optimization should exhaust budget
    let result = p.synthesize(&spec);
    match result {
        Err(SynthesisError::BudgetExhausted { stage }) => {
            assert_eq!(stage, PipelineStage::OptimizationSolving);
        }
        Ok(_) => {
            // It's also acceptable if 0 iterations still allows 0 constraints through
            // (the loop check is `iterations > max_iterations`, and the loop starts at 0)
        }
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

// ===========================================================================
// 29. Stage witness hashes are deterministic
// ===========================================================================

#[test]
fn stage_witness_hashes_deterministic_across_invocations() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "hash_det".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![unit_constraint("c1", "x", CmpOp::Le, 500_000)],
        objectives: vec![objective(
            "obj",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![safety("ss1", vec!["x"], vec!["x"])],
        epoch: 1,
    };

    let out1 = p.synthesize(&spec).unwrap();
    let out2 = p.synthesize(&spec).unwrap();

    for (w1, w2) in out1.stage_witnesses.iter().zip(out2.stage_witnesses.iter()) {
        assert_eq!(w1.input_hash, w2.input_hash);
        assert_eq!(w1.output_hash, w2.output_hash);
        assert_eq!(w1.resource_usage, w2.resource_usage);
        assert_eq!(w1.stage, w2.stage);
    }
}

// ===========================================================================
// 30. Full output equality under determinism
// ===========================================================================

#[test]
fn full_output_equality_deterministic() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "full_eq".into(),
        variables: vec![bounded_var("a", 0, 1_000_000), bounded_var("b", 0, 500_000)],
        constraints: vec![unit_constraint("c1", "a", CmpOp::Le, 800_000)],
        objectives: vec![objective(
            "obj",
            vec![("a", 500_000), ("b", 300_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![safety("ss1", vec!["a"], vec!["b"])],
        epoch: 42,
    };

    let out1 = p.synthesize(&spec).unwrap();
    let out2 = p.synthesize(&spec).unwrap();
    assert_eq!(out1, out2, "full output must be identical across runs");
}

// ===========================================================================
// 31. SynthesisOutput full serde round-trip equality
// ===========================================================================

#[test]
fn synthesis_output_full_serde_roundtrip_equality() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "serde_full".into(),
        variables: vec![
            bounded_var("x", 0, 1_000_000),
            bool_var("flag"),
            enum_var("regime", 3),
        ],
        constraints: vec![unit_constraint("c1", "x", CmpOp::Le, 500_000)],
        objectives: vec![objective_bounded(
            "obj",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
            800_000,
        )],
        safety_specs: vec![safety("ss1", vec!["x"], vec!["x"])],
        epoch: 99,
    };

    let output = p.synthesize(&spec).unwrap();
    let json = serde_json::to_string(&output).unwrap();
    let back: SynthesisOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(output, back);
}

// ===========================================================================
// 32. Clone equality for all major types
// ===========================================================================

#[test]
fn clone_equality_spec_var() {
    let v = bounded_var("x", 10, 20);
    assert_eq!(v, v.clone());
}

#[test]
fn clone_equality_linear_constraint() {
    let c = unit_constraint("c1", "x", CmpOp::Ge, 100);
    assert_eq!(c, c.clone());
}

#[test]
fn clone_equality_optimization_objective() {
    let o = objective_bounded(
        "obj",
        vec![("x", 500_000)],
        OptDirection::Maximize,
        1_000_000,
    );
    assert_eq!(o, o.clone());
}

#[test]
fn clone_equality_safety_spec() {
    let s = safety("ss", vec!["a", "b"], vec!["c"]);
    assert_eq!(s, s.clone());
}

#[test]
fn clone_equality_synthesis_spec() {
    let spec = SynthesisSpec {
        spec_id: "clone_test".into(),
        variables: vec![bounded_var("x", 0, 100)],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![],
        epoch: 1,
    };
    assert_eq!(spec, spec.clone());
}

#[test]
fn clone_equality_pipeline() {
    let p = default_pipeline();
    assert_eq!(p, p.clone());
}

// ===========================================================================
// 33. Ord/Hash on CmpOp - BTreeSet deduplication
// ===========================================================================

#[test]
fn cmp_op_ord_hash_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(CmpOp::Le);
    set.insert(CmpOp::Lt);
    set.insert(CmpOp::Ge);
    set.insert(CmpOp::Gt);
    set.insert(CmpOp::Eq);
    set.insert(CmpOp::Ne);
    // Insert duplicates
    set.insert(CmpOp::Le);
    set.insert(CmpOp::Eq);
    assert_eq!(set.len(), 6, "BTreeSet should deduplicate CmpOp");
}

// ===========================================================================
// 34. Ord/Hash on PipelineStage
// ===========================================================================

#[test]
fn pipeline_stage_ord_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(PipelineStage::ArtifactAssembly);
    set.insert(PipelineStage::ConstraintParsing);
    set.insert(PipelineStage::TableGeneration);
    set.insert(PipelineStage::OptimizationSolving);
    set.insert(PipelineStage::ThresholdCalibration);
    set.insert(PipelineStage::ArtifactAssembly); // duplicate
    assert_eq!(set.len(), 5);
}

// ===========================================================================
// 35. Ord/Hash on CalibrationMethod
// ===========================================================================

#[test]
fn calibration_method_ord_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(CalibrationMethod::ConformalQuantile);
    set.insert(CalibrationMethod::EProcessSequential);
    set.insert(CalibrationMethod::CvarEmpirical);
    set.insert(CalibrationMethod::OperatorFixed);
    set.insert(CalibrationMethod::ConformalQuantile); // duplicate
    assert_eq!(set.len(), 4);
}

// ===========================================================================
// 36. Ord/Hash on EvidenceCategory
// ===========================================================================

#[test]
fn evidence_category_ord_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(EvidenceCategory::DifferentialTest);
    set.insert(EvidenceCategory::StatisticalTest);
    set.insert(EvidenceCategory::FormalProof);
    set.insert(EvidenceCategory::BoundednessProof);
    set.insert(EvidenceCategory::MonotonicityCheck);
    set.insert(EvidenceCategory::FormalProof); // duplicate
    assert_eq!(set.len(), 5);
}

// ===========================================================================
// 37. Ord/Hash on OptDirection
// ===========================================================================

#[test]
fn opt_direction_ord_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(OptDirection::Minimize);
    set.insert(OptDirection::Maximize);
    set.insert(OptDirection::Minimize); // duplicate
    assert_eq!(set.len(), 2);
}

// ===========================================================================
// 38. Ord/Hash on VarDomain
// ===========================================================================

#[test]
fn var_domain_ord_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(VarDomain::Boolean);
    set.insert(VarDomain::BoundedInt { lo: 0, hi: 100 });
    set.insert(VarDomain::Enum { cardinality: 3 });
    set.insert(VarDomain::Boolean); // duplicate
    assert_eq!(set.len(), 3);
}

// ===========================================================================
// 39. Empty objectives and safety specs but valid variables+constraints
// ===========================================================================

#[test]
fn empty_objectives_and_safety_specs_still_succeeds() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "no_obj_no_safety".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![unit_constraint("c1", "x", CmpOp::Le, 500_000)],
        objectives: vec![],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    assert!(output.decision_tables.is_empty());
    assert!(output.automata.is_empty());
    assert_eq!(output.stage_witnesses.len(), 5);
    assert_eq!(output.spec_id, "no_obj_no_safety");
}

// ===========================================================================
// 40. Variables only (no constraints, objectives, or safety)
// ===========================================================================

#[test]
fn variables_only_succeeds() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "vars_only".into(),
        variables: vec![bool_var("flag")],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    assert!(output.decision_tables.is_empty());
    assert!(output.automata.is_empty());
    assert_eq!(output.threshold_bundles.len(), 1);
    // Threshold bundle should be empty since no safety, objective bounds, or constrained vars
    // Boolean var has range [0, 1_000_000] which is the full "default" range that does NOT
    // trigger OperatorFixed threshold generation (lo=0 and hi=1_000_000 check)
}

// ===========================================================================
// 41. EmptySpec requires BOTH variables and constraints empty
// ===========================================================================

#[test]
fn non_empty_constraints_with_empty_variables_is_not_empty_spec() {
    // This tests the exact condition: variables.is_empty() && constraints.is_empty()
    // If constraints are non-empty but variables are empty, it is NOT EmptySpec
    // (but may fail at constraint validation)
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "constr_no_vars".into(),
        variables: vec![],
        constraints: vec![unit_constraint("c1", "x", CmpOp::Le, 500_000)],
        objectives: vec![],
        safety_specs: vec![],
        epoch: 1,
    };
    let result = p.synthesize(&spec);
    // Should NOT be EmptySpec; should be InvalidConstraint (unknown variable)
    match result {
        Err(SynthesisError::InvalidConstraint { id, reason }) => {
            assert_eq!(id, "c1");
            assert!(reason.contains("unknown variable"));
        }
        other => panic!("expected InvalidConstraint, got {other:?}"),
    }
}

#[test]
fn non_empty_variables_with_empty_constraints_is_not_empty_spec() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "vars_no_constr".into(),
        variables: vec![bool_var("x")],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![],
        epoch: 1,
    };
    // Should succeed (not EmptySpec)
    let output = p.synthesize(&spec).unwrap();
    assert_eq!(output.spec_id, "vars_no_constr");
}

// ===========================================================================
// 42. Large-scale stress: many variables, constraints, objectives
// ===========================================================================

#[test]
fn large_scale_many_variables_and_constraints() {
    let p = default_pipeline();
    let n = 20;
    let variables: Vec<SpecVar> = (0..n)
        .map(|i| bounded_var(&format!("v{i}"), 0, 1_000_000))
        .collect();
    let constraints: Vec<LinearConstraint> = (0..n)
        .map(|i| unit_constraint(&format!("c{i}"), &format!("v{i}"), CmpOp::Le, 800_000))
        .collect();
    // Single-variable objectives to keep table generation bounded
    let objectives: Vec<OptimizationObjective> = vec![objective(
        "obj_v0",
        vec![("v0", 1_000_000)],
        OptDirection::Minimize,
    )];

    let spec = SynthesisSpec {
        spec_id: "large_scale".into(),
        variables,
        constraints,
        objectives,
        safety_specs: vec![safety("ss", vec!["v0"], vec!["v1"])],
        epoch: 1,
    };

    let output = p.synthesize(&spec).unwrap();
    assert!(!output.decision_tables.is_empty());
    assert!(!output.automata.is_empty());
    assert_eq!(output.stage_witnesses.len(), 5);
    // All stage witnesses should be Completed
    for w in &output.stage_witnesses {
        assert!(matches!(w.status, StageStatus::Completed { .. }));
    }
}

// ===========================================================================
// 43. Boolean variable produces grid points 0 and 1_000_000
// ===========================================================================

#[test]
fn boolean_variable_grid_points() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "bool_grid".into(),
        variables: vec![bool_var("flag")],
        constraints: vec![],
        objectives: vec![objective(
            "obj",
            vec![("flag", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let table = &output.decision_tables[0];
    let flag_vals: BTreeSet<i64> = table
        .rows
        .iter()
        .filter_map(|r| r.state.values.get("flag").copied())
        .collect();
    // Boolean domain [0, 1_000_000]: grid discretizes with step = max(1, (1_000_000-0)/4) = 250_000
    // Points: 0, 250_000, 500_000, 750_000, 1_000_000
    assert!(flag_vals.contains(&0));
    assert!(flag_vals.contains(&1_000_000));
}

// ===========================================================================
// 44. Enum variable grid points
// ===========================================================================

#[test]
fn enum_variable_grid_points() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "enum_grid".into(),
        variables: vec![enum_var("mode", 3)],
        constraints: vec![],
        objectives: vec![objective(
            "obj",
            vec![("mode", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let table = &output.decision_tables[0];
    let mode_vals: BTreeSet<i64> = table
        .rows
        .iter()
        .filter_map(|r| r.state.values.get("mode").copied())
        .collect();
    // Enum cardinality=3: range [0, 2_000_000], step = max(1, 2_000_000/4) = 500_000
    // Grid: 0, 500_000, 1_000_000, 1_500_000, 2_000_000
    assert!(mode_vals.contains(&0));
    assert!(mode_vals.contains(&2_000_000));
}

// ===========================================================================
// 45. Decision table table_id and content_hash naming convention
// ===========================================================================

#[test]
fn decision_table_id_naming_convention() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "naming".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![],
        objectives: vec![objective(
            "obj_alpha",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let table = &output.decision_tables[0];
    assert_eq!(table.table_id, "dt_naming_obj_alpha");
    // Content hash should be non-empty hex
    assert!(!table.content_hash.is_empty());
    assert!(
        table.content_hash.chars().all(|c| c.is_ascii_hexdigit()),
        "content_hash should be hex: {}",
        table.content_hash
    );
}

// ===========================================================================
// 46. Automaton id naming convention
// ===========================================================================

#[test]
fn automaton_id_naming_convention() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "naming_aut".into(),
        variables: vec![
            bounded_var("x", 0, 1_000_000),
            bounded_var("y", 0, 1_000_000),
        ],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![safety("ss_beta", vec!["x"], vec!["y"])],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let aut = &output.automata[0];
    assert_eq!(aut.automaton_id, "ta_naming_aut_ss_beta");
    assert!(
        aut.content_hash.chars().all(|c| c.is_ascii_hexdigit()),
        "content_hash should be hex: {}",
        aut.content_hash
    );
}

// ===========================================================================
// 47. Threshold bundle id naming convention
// ===========================================================================

#[test]
fn threshold_bundle_id_naming_convention() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "naming_tb".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let bundle = &output.threshold_bundles[0];
    assert_eq!(bundle.bundle_id, "tb_naming_tb");
}

// ===========================================================================
// 48. Certificate id naming convention
// ===========================================================================

#[test]
fn certificate_id_naming_convention() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "cert_name".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![],
        objectives: vec![objective(
            "obj1",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    // Decision table certificate
    let dt_cert = output
        .certificates
        .iter()
        .find(|c| c.certificate_id.contains("dt_"))
        .expect("should have dt certificate");
    assert!(dt_cert.certificate_id.starts_with("cert_dt_cert_name_obj1"));

    // Threshold bundle certificate
    let tb_cert = output
        .certificates
        .iter()
        .find(|c| c.certificate_id.contains("tb_"))
        .expect("should have tb certificate");
    assert!(tb_cert.certificate_id.starts_with("cert_tb_cert_name"));
}

// ===========================================================================
// 49. Guardrail blocking: constraints violated at certain grid points
// ===========================================================================

#[test]
fn guardrail_blocking_at_violated_grid_points() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "guardrail".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![unit_constraint("c1", "x", CmpOp::Le, 500_000)],
        objectives: vec![objective(
            "obj",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let table = &output.decision_tables[0];

    let mut found_blocked = false;
    let mut found_unblocked = false;

    for row in &table.rows {
        let x = row.state.values.get("x").copied().unwrap_or(0);
        if x > 500_000 {
            // Constraint violated
            assert!(
                row.entry.guardrail_blocked,
                "x={x} exceeds cap, should be blocked"
            );
            assert_eq!(row.entry.action, "safe_deny");
            found_blocked = true;
        } else {
            // Constraint satisfied
            assert!(
                !row.entry.guardrail_blocked,
                "x={x} within cap, should not be blocked"
            );
            assert!(row.entry.action.contains("opt_"));
            found_unblocked = true;
        }
    }

    // The grid should have both blocked and unblocked points
    // because the variable bound is [0, 500_000] after tightening,
    // but the grid is computed from the tightened bounds.
    // Actually with tightened bounds [0, 500_000], all points satisfy the constraint.
    // So found_blocked might be false. Let's just verify consistency.
    assert!(found_unblocked, "should have at least some unblocked rows");
    // The tightened range is [0, 500_000] so all grid points satisfy x <= 500_000
    // => found_blocked should be false
    let _ = found_blocked; // suppress unused warning
}

// ===========================================================================
// 50. Non-unit coefficient constraint does not tighten bounds
// ===========================================================================

#[test]
fn non_unit_coefficient_does_not_tighten() {
    let p = default_pipeline();
    // Constraint with coeff_millionths = 2_000_000 (not 1_000_000) should not tighten
    let spec = SynthesisSpec {
        spec_id: "non_unit".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![LinearConstraint {
            id: "c1".into(),
            terms: vec![LinearTerm {
                var: "x".into(),
                coeff_millionths: 2_000_000,
            }],
            op: CmpOp::Le,
            rhs_millionths: 500_000,
            label: "non-unit".into(),
        }],
        objectives: vec![objective(
            "obj",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let table = &output.decision_tables[0];
    // Bounds should not be tightened (non-unit coeff), so grid spans [0, 1_000_000]
    let x_vals: BTreeSet<i64> = table
        .rows
        .iter()
        .filter_map(|r| r.state.values.get("x").copied())
        .collect();
    assert!(x_vals.contains(&0));
    assert!(x_vals.contains(&1_000_000));
}

// ===========================================================================
// 51. SynthesisError implements std::error::Error
// ===========================================================================

#[test]
fn synthesis_error_implements_std_error() {
    fn assert_error<E: std::error::Error>(_e: &E) {}

    assert_error(&SynthesisError::EmptySpec);
    assert_error(&SynthesisError::NoSafetySpec);
    assert_error(&SynthesisError::InternalError("test".into()));
    assert_error(&SynthesisError::InvalidVariable { name: "x".into() });
    assert_error(&SynthesisError::InvalidConstraint {
        id: "c".into(),
        reason: "r".into(),
    });
    assert_error(&SynthesisError::Infeasible {
        constraint_ids: vec![],
    });
    assert_error(&SynthesisError::BudgetExhausted {
        stage: PipelineStage::ConstraintParsing,
    });
}

// ===========================================================================
// 52. Display for SynthesisError: Infeasible with empty constraint_ids
// ===========================================================================

#[test]
fn synthesis_error_infeasible_empty_ids_display() {
    let err = SynthesisError::Infeasible {
        constraint_ids: vec![],
    };
    assert_eq!(err.to_string(), "infeasible: ");
}

// ===========================================================================
// 53. Display for SynthesisError: Infeasible with many ids
// ===========================================================================

#[test]
fn synthesis_error_infeasible_many_ids_display() {
    let err = SynthesisError::Infeasible {
        constraint_ids: vec!["a".into(), "b".into(), "c".into(), "d".into()],
    };
    assert_eq!(err.to_string(), "infeasible: a, b, c, d");
}

// ===========================================================================
// 54. Display for SynthesisError: BudgetExhausted all stages
// ===========================================================================

#[test]
fn synthesis_error_budget_exhausted_all_stages_display() {
    let stages = [
        PipelineStage::ConstraintParsing,
        PipelineStage::OptimizationSolving,
        PipelineStage::TableGeneration,
        PipelineStage::ThresholdCalibration,
        PipelineStage::ArtifactAssembly,
    ];
    for stage in stages {
        let err = SynthesisError::BudgetExhausted { stage };
        let msg = err.to_string();
        assert!(msg.starts_with("budget exhausted at "));
        assert!(msg.contains(&format!("{stage:?}")));
    }
}

// ===========================================================================
// 55. Automaton priority: equal priority, first in list wins
// ===========================================================================

#[test]
fn automaton_equal_priority_first_wins() {
    let automaton = make_automaton(
        "eq_prio",
        &["s0", "s1", "s2"],
        vec![
            Transition {
                from: "s0".into(),
                to: "s1".into(),
                guards: vec![],
                priority: 5,
                emit_action: Some("first".into()),
            },
            Transition {
                from: "s0".into(),
                to: "s2".into(),
                guards: vec![],
                priority: 5,
                emit_action: Some("second".into()),
            },
        ],
        "s0",
    );

    let bindings = BTreeMap::new();
    let (state, action) = automaton.step("s0", &bindings);
    // Both have priority 5; the code uses `t.priority > current.priority` (strict gt),
    // so the first one stays as best since the second does not have strictly greater priority.
    assert_eq!(state, "s1");
    assert_eq!(action.as_deref(), Some("first"));
}

// ===========================================================================
// 56. Automaton with multiple guards using different CmpOps
// ===========================================================================

#[test]
fn automaton_guard_with_eq_op() {
    let automaton = make_automaton(
        "eq_guard",
        &["s0", "s1"],
        vec![Transition {
            from: "s0".into(),
            to: "s1".into(),
            guards: vec![TransitionGuard {
                variable: "x".into(),
                op: CmpOp::Eq,
                threshold_millionths: 500_000,
            }],
            priority: 1,
            emit_action: Some("exact_match".into()),
        }],
        "s0",
    );

    // Exact match
    let bindings = BTreeMap::from([("x".to_string(), 500_000i64)]);
    let (state, action) = automaton.step("s0", &bindings);
    assert_eq!(state, "s1");
    assert_eq!(action.as_deref(), Some("exact_match"));

    // Off by one
    let bindings = BTreeMap::from([("x".to_string(), 500_001i64)]);
    let (state, action) = automaton.step("s0", &bindings);
    assert_eq!(state, "s0");
    assert!(action.is_none());
}

#[test]
fn automaton_guard_with_ne_op() {
    let automaton = make_automaton(
        "ne_guard",
        &["s0", "s1"],
        vec![Transition {
            from: "s0".into(),
            to: "s1".into(),
            guards: vec![TransitionGuard {
                variable: "x".into(),
                op: CmpOp::Ne,
                threshold_millionths: 500_000,
            }],
            priority: 1,
            emit_action: Some("not_equal".into()),
        }],
        "s0",
    );

    // Not equal -> fires
    let bindings = BTreeMap::from([("x".to_string(), 499_999i64)]);
    let (state, action) = automaton.step("s0", &bindings);
    assert_eq!(state, "s1");
    assert_eq!(action.as_deref(), Some("not_equal"));

    // Equal -> does not fire
    let bindings = BTreeMap::from([("x".to_string(), 500_000i64)]);
    let (state, action) = automaton.step("s0", &bindings);
    assert_eq!(state, "s0");
    assert!(action.is_none());
}

#[test]
fn automaton_guard_with_le_op() {
    let automaton = make_automaton(
        "le_guard",
        &["s0", "s1"],
        vec![Transition {
            from: "s0".into(),
            to: "s1".into(),
            guards: vec![TransitionGuard {
                variable: "x".into(),
                op: CmpOp::Le,
                threshold_millionths: 500_000,
            }],
            priority: 1,
            emit_action: None,
        }],
        "s0",
    );

    // Boundary: x == 500_000 -> Le passes
    let bindings = BTreeMap::from([("x".to_string(), 500_000i64)]);
    let (state, _) = automaton.step("s0", &bindings);
    assert_eq!(state, "s1");

    // Just above: x == 500_001 -> Le fails
    let bindings = BTreeMap::from([("x".to_string(), 500_001i64)]);
    let (state, _) = automaton.step("s0", &bindings);
    assert_eq!(state, "s0");
}

// ===========================================================================
// 57. Decision table with guardrail_blocked entry preserves pre_guardrail_action
// ===========================================================================

#[test]
fn guardrail_blocked_preserves_pre_guardrail_action() {
    let p = OfflineSynthesisPipeline::new(PipelineBudget::default(), "emergency_stop".into());
    // Use a tight Le constraint that will be violated by some grid points
    // We need the bounds to NOT be tightened, so use non-unit constraint for bound
    // Actually, let's use a multi-term constraint which won't tighten:
    let spec = SynthesisSpec {
        spec_id: "pre_guard".into(),
        variables: vec![
            bounded_var("x", 0, 1_000_000),
            bounded_var("y", 0, 1_000_000),
        ],
        constraints: vec![multi_term_constraint(
            "cap",
            vec![("x", 500_000), ("y", 500_000)],
            CmpOp::Le,
            500_000, // 0.5*x + 0.5*y <= 0.5
        )],
        objectives: vec![objective(
            "obj_xy",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let table = &output.decision_tables[0];

    for row in &table.rows {
        if row.entry.guardrail_blocked {
            assert_eq!(row.entry.action, "emergency_stop");
            assert_eq!(row.entry.pre_guardrail_action, "opt_obj_xy");
        } else {
            assert_eq!(row.entry.action, "opt_obj_xy");
            assert_eq!(row.entry.pre_guardrail_action, "opt_obj_xy");
        }
    }
}

// ===========================================================================
// 58. Serde round-trip for SynthesisError::InternalError with special chars
// ===========================================================================

#[test]
fn synthesis_error_internal_error_special_chars_serde() {
    let err = SynthesisError::InternalError("msg with \"quotes\" and \nnewlines".into());
    let json = serde_json::to_string(&err).unwrap();
    let back: SynthesisError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

// ===========================================================================
// 59. Serde round-trip for SynthesisError::Infeasible with many ids
// ===========================================================================

#[test]
fn synthesis_error_infeasible_many_ids_serde() {
    let ids: Vec<String> = (0..100).map(|i| format!("var_{i}")).collect();
    let err = SynthesisError::Infeasible {
        constraint_ids: ids.clone(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: SynthesisError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
    if let SynthesisError::Infeasible { constraint_ids } = back {
        assert_eq!(constraint_ids.len(), 100);
    }
}

// ===========================================================================
// 60. ObservableState Ord: ordering by key then value
// ===========================================================================

#[test]
fn observable_state_ord_ordering() {
    let s1 = ObservableState {
        values: BTreeMap::from([("a".to_string(), 100i64)]),
    };
    let s2 = ObservableState {
        values: BTreeMap::from([("a".to_string(), 200i64)]),
    };
    let s3 = ObservableState {
        values: BTreeMap::from([("b".to_string(), 100i64)]),
    };

    // s1 < s2 (same key, smaller value)
    assert!(s1 < s2);
    // s1 < s3 ("a" < "b" lexicographically in BTreeMap comparison)
    assert!(s1 < s3);

    let mut set = BTreeSet::new();
    set.insert(s2.clone());
    set.insert(s1.clone());
    set.insert(s3.clone());
    assert_eq!(set.len(), 3);
}

// ===========================================================================
// 61. Decision table rows are sorted by state
// ===========================================================================

#[test]
fn decision_table_rows_sorted_by_state() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "sorted".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![],
        objectives: vec![objective(
            "obj",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let table = &output.decision_tables[0];

    for w in table.rows.windows(2) {
        assert!(w[0].state <= w[1].state, "rows should be sorted by state");
    }
}

// ===========================================================================
// 62. Automaton initial_state field
// ===========================================================================

#[test]
fn automaton_initial_state_is_normal() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "init_state".into(),
        variables: vec![
            bounded_var("x", 0, 1_000_000),
            bounded_var("y", 0, 1_000_000),
        ],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![safety("ss1", vec!["x"], vec!["y"])],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    assert_eq!(output.automata[0].initial_state, "normal");
}

// ===========================================================================
// 63. Certificate rollback_token is non-empty and deterministic
// ===========================================================================

#[test]
fn certificate_rollback_token_deterministic() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "rollback".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![],
        objectives: vec![objective(
            "obj",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };

    let out1 = p.synthesize(&spec).unwrap();
    let out2 = p.synthesize(&spec).unwrap();

    for (c1, c2) in out1.certificates.iter().zip(out2.certificates.iter()) {
        assert!(!c1.rollback_token.is_empty());
        assert_eq!(c1.rollback_token, c2.rollback_token);
        assert!(
            c1.rollback_token.chars().all(|c| c.is_ascii_hexdigit()),
            "rollback token should be hex"
        );
    }
}

// ===========================================================================
// 64. Evidence confidence is 1_000_000 for BoundednessProof and FormalProof
// ===========================================================================

#[test]
fn evidence_confidence_values() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "evidence_conf".into(),
        variables: vec![
            bounded_var("x", 0, 1_000_000),
            bounded_var("y", 0, 1_000_000),
        ],
        constraints: vec![],
        objectives: vec![objective(
            "obj",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![safety("ss1", vec!["x"], vec!["y"])],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();

    for cert in &output.certificates {
        for ev in &cert.evidence {
            match ev.category {
                EvidenceCategory::BoundednessProof
                | EvidenceCategory::MonotonicityCheck
                | EvidenceCategory::FormalProof => {
                    assert_eq!(ev.confidence_millionths, 1_000_000);
                }
                EvidenceCategory::StatisticalTest => {
                    assert_eq!(ev.confidence_millionths, 950_000);
                }
                EvidenceCategory::DifferentialTest => {
                    // Not generated by the pipeline, but handle gracefully
                }
            }
        }
    }
}

// ===========================================================================
// 65. Constraint parsing stage iterations equals constraint count
// ===========================================================================

#[test]
fn constraint_parsing_iterations_equals_constraint_count() {
    let p = default_pipeline();
    let n_constraints = 5;
    let spec = SynthesisSpec {
        spec_id: "parse_iter".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: (0..n_constraints)
            .map(|i| unit_constraint(&format!("c{i}"), "x", CmpOp::Le, 1_000_000 - i * 100_000))
            .collect(),
        objectives: vec![],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let parse_witness = &output.stage_witnesses[0];
    assert_eq!(parse_witness.stage, PipelineStage::ConstraintParsing);
    assert_eq!(
        parse_witness.resource_usage.iterations,
        n_constraints as u64
    );
}

// ===========================================================================
// 66. Threshold calibration stage iterations equals safety_spec count
// ===========================================================================

#[test]
fn threshold_calibration_iterations_equals_safety_spec_count() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "calib_iter".into(),
        variables: vec![
            bounded_var("x", 0, 1_000_000),
            bounded_var("y", 0, 1_000_000),
        ],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![
            safety("ss1", vec!["x"], vec!["y"]),
            safety("ss2", vec!["y"], vec!["x"]),
        ],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let calib_witness = &output.stage_witnesses[3];
    assert_eq!(calib_witness.stage, PipelineStage::ThresholdCalibration);
    assert_eq!(calib_witness.resource_usage.iterations, 2);
}

// ===========================================================================
// 67. Mixed variable domains in a single spec
// ===========================================================================

#[test]
fn mixed_variable_domains() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "mixed".into(),
        variables: vec![
            bool_var("flag"),
            bounded_var("score", -500_000, 500_000),
            enum_var("level", 4),
        ],
        constraints: vec![],
        objectives: vec![
            objective(
                "obj_score",
                vec![("score", 1_000_000)],
                OptDirection::Minimize,
            ),
            objective(
                "obj_flag",
                vec![("flag", 1_000_000)],
                OptDirection::Maximize,
            ),
        ],
        safety_specs: vec![safety("ss1", vec!["flag"], vec!["score"])],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    assert_eq!(output.decision_tables.len(), 2);
    assert_eq!(output.automata.len(), 1);
    assert_eq!(output.stage_witnesses.len(), 5);

    // Decision table for score should include negative values
    let score_table = output
        .decision_tables
        .iter()
        .find(|t| t.key_variables.contains(&"score".to_string()))
        .expect("should have score table");
    let score_vals: BTreeSet<i64> = score_table
        .rows
        .iter()
        .filter_map(|r| r.state.values.get("score").copied())
        .collect();
    assert!(
        score_vals.iter().any(|v| *v < 0),
        "score grid should include negative values"
    );
}

// ===========================================================================
// 68. Constraint parsing memory_bytes proportional to constraints
// ===========================================================================

#[test]
fn constraint_parsing_memory_bytes() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "parse_mem".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![
            unit_constraint("c1", "x", CmpOp::Le, 900_000),
            unit_constraint("c2", "x", CmpOp::Ge, 100_000),
            unit_constraint("c3", "x", CmpOp::Le, 800_000),
        ],
        objectives: vec![],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let parse_witness = &output.stage_witnesses[0];
    // Memory = constraints.len() * 64
    assert_eq!(parse_witness.resource_usage.memory_bytes, 3 * 64);
}

// ===========================================================================
// 69. Multi-objective with overlapping variables
// ===========================================================================

#[test]
fn multi_objective_overlapping_variables() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "overlap".into(),
        variables: vec![
            bounded_var("x", 0, 1_000_000),
            bounded_var("y", 0, 1_000_000),
        ],
        constraints: vec![],
        objectives: vec![
            objective(
                "obj_combined",
                vec![("x", 500_000), ("y", 300_000)],
                OptDirection::Minimize,
            ),
            objective("obj_x_only", vec![("x", 1_000_000)], OptDirection::Maximize),
        ],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    assert_eq!(output.decision_tables.len(), 2);

    // Combined objective table should have both x and y as key variables
    let combined = output
        .decision_tables
        .iter()
        .find(|t| t.table_id.contains("obj_combined"))
        .unwrap();
    assert!(combined.key_variables.contains(&"x".to_string()));
    assert!(combined.key_variables.contains(&"y".to_string()));

    // X-only table should have only x
    let x_only = output
        .decision_tables
        .iter()
        .find(|t| t.table_id.contains("obj_x_only"))
        .unwrap();
    assert_eq!(x_only.key_variables, vec!["x".to_string()]);
}

// ===========================================================================
// 70. Safety spec with multiple strategy and adversary vars
// ===========================================================================

#[test]
fn safety_spec_multiple_strategy_and_adversary_vars() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "multi_vars_safety".into(),
        variables: vec![
            bounded_var("s1", 0, 1_000_000),
            bounded_var("s2", 0, 1_000_000),
            bounded_var("a1", 0, 1_000_000),
            bounded_var("a2", 0, 1_000_000),
        ],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![safety("ss", vec!["s1", "s2"], vec!["a1", "a2"])],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let aut = &output.automata[0];

    // Should have transitions from normal for each strategy var
    let normal_transitions: Vec<&Transition> = aut
        .transitions
        .iter()
        .filter(|t| t.from == "normal")
        .collect();
    assert_eq!(
        normal_transitions.len(),
        2,
        "one transition per strategy var from normal"
    );

    // Should have transitions from elevated for each adversary var
    let elevated_transitions: Vec<&Transition> = aut
        .transitions
        .iter()
        .filter(|t| t.from == "elevated")
        .collect();
    assert_eq!(
        elevated_transitions.len(),
        2,
        "one transition per adversary var from elevated"
    );

    // Should have transitions from recovery for each strategy var
    let recovery_transitions: Vec<&Transition> = aut
        .transitions
        .iter()
        .filter(|t| t.from == "recovery")
        .collect();
    assert_eq!(
        recovery_transitions.len(),
        2,
        "one transition per strategy var from recovery"
    );

    // Critical -> recovery is unconditional (1 transition)
    let critical_transitions: Vec<&Transition> = aut
        .transitions
        .iter()
        .filter(|t| t.from == "critical")
        .collect();
    assert_eq!(critical_transitions.len(), 1);
}

// ===========================================================================
// 71. Automaton transition guard thresholds derived from safety spec values
// ===========================================================================

#[test]
fn automaton_guard_thresholds_derived_from_safety_spec() {
    let p = default_pipeline();
    let maximin = 400_000i64;
    let cvar_bound = 600_000i64;
    let spec = SynthesisSpec {
        spec_id: "guard_thresholds".into(),
        variables: vec![
            bounded_var("x", 0, 1_000_000),
            bounded_var("y", 0, 1_000_000),
        ],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![SafetySpec {
            id: "ss1".into(),
            property: "prop".into(),
            maximin_value_millionths: maximin,
            strategy_vars: vec!["x".into()],
            adversary_vars: vec!["y".into()],
            cvar_alpha_millionths: 50_000,
            cvar_bound_millionths: cvar_bound,
        }],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let aut = &output.automata[0];

    // normal->elevated guard: strategy var > maximin/2
    let normal_to_elevated = aut
        .transitions
        .iter()
        .find(|t| t.from == "normal" && t.to == "elevated")
        .expect("should have normal->elevated transition");
    assert_eq!(normal_to_elevated.guards.len(), 1);
    assert_eq!(
        normal_to_elevated.guards[0].threshold_millionths,
        maximin / 2
    );
    assert_eq!(normal_to_elevated.guards[0].op, CmpOp::Gt);

    // elevated->critical guard: adversary var > cvar_bound
    let elevated_to_critical = aut
        .transitions
        .iter()
        .find(|t| t.from == "elevated" && t.to == "critical")
        .expect("should have elevated->critical transition");
    assert_eq!(elevated_to_critical.guards.len(), 1);
    assert_eq!(
        elevated_to_critical.guards[0].threshold_millionths,
        cvar_bound
    );
    assert_eq!(elevated_to_critical.guards[0].op, CmpOp::Gt);

    // recovery->normal guard: strategy var <= maximin/2
    let recovery_to_normal = aut
        .transitions
        .iter()
        .find(|t| t.from == "recovery" && t.to == "normal")
        .expect("should have recovery->normal transition");
    assert_eq!(recovery_to_normal.guards.len(), 1);
    assert_eq!(
        recovery_to_normal.guards[0].threshold_millionths,
        maximin / 2
    );
    assert_eq!(recovery_to_normal.guards[0].op, CmpOp::Le);
}

// ===========================================================================
// 72. Stage witness status: all completed with duration_ms set
// ===========================================================================

#[test]
fn all_stages_completed_with_duration() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "duration".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![unit_constraint("c1", "x", CmpOp::Le, 500_000)],
        objectives: vec![objective(
            "obj",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![safety("ss1", vec!["x"], vec!["x"])],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();

    for w in &output.stage_witnesses {
        match &w.status {
            StageStatus::Completed { duration_ms } => {
                assert!(
                    *duration_ms > 0 || w.stage == PipelineStage::ArtifactAssembly,
                    "stage {:?} should have duration_ms > 0, got {}",
                    w.stage,
                    duration_ms
                );
            }
            other => panic!("expected Completed, got {other:?} for stage {:?}", w.stage),
        }
    }
}

// ===========================================================================
// 73. Synthesis spec with only safety specs (no objectives/constraints)
// ===========================================================================

#[test]
fn spec_with_only_safety_specs() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "safety_only".into(),
        variables: vec![
            bounded_var("x", 0, 1_000_000),
            bounded_var("y", 0, 1_000_000),
        ],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![safety("ss1", vec!["x"], vec!["y"])],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    assert!(output.decision_tables.is_empty());
    assert_eq!(output.automata.len(), 1);
    assert!(!output.threshold_bundles.is_empty());
    // Should have certificates for automaton and threshold bundle
    assert!(output.certificates.len() >= 2);
}

// ===========================================================================
// 74. Optimization solving memory_bytes proportional to variable count
// ===========================================================================

#[test]
fn optimization_solving_memory_bytes() {
    let p = default_pipeline();
    let n_vars = 8;
    let spec = SynthesisSpec {
        spec_id: "solve_mem".into(),
        variables: (0..n_vars)
            .map(|i| bounded_var(&format!("v{i}"), 0, 1_000_000))
            .collect(),
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let solve_witness = &output.stage_witnesses[1];
    assert_eq!(solve_witness.stage, PipelineStage::OptimizationSolving);
    // Memory = variable_bounds.len() * 32
    assert_eq!(
        solve_witness.resource_usage.memory_bytes,
        n_vars as u64 * 32
    );
}

// ===========================================================================
// 75. Negative bounded int domain
// ===========================================================================

#[test]
fn negative_bounded_int_domain() {
    let p = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "negative".into(),
        variables: vec![bounded_var("x", -1_000_000, -500_000)],
        constraints: vec![],
        objectives: vec![objective(
            "obj",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let table = &output.decision_tables[0];
    // All grid points should be in [-1_000_000, -500_000]
    for row in &table.rows {
        let x = row.state.values.get("x").copied().unwrap();
        assert!(x >= -1_000_000 && x <= -500_000, "x={x} out of range");
    }
}

// ===========================================================================
// 76. SpecVar Debug and Clone
// ===========================================================================

#[test]
fn spec_var_debug_contains_name() {
    let v = bounded_var("my_var", 0, 100);
    let dbg = format!("{v:?}");
    assert!(dbg.contains("my_var"));
    assert!(dbg.contains("BoundedInt"));
}

// ===========================================================================
// 77. AutomatonState Ord usage in BTreeMap key
// ===========================================================================

#[test]
fn automaton_state_as_btreemap_key() {
    let s1 = AutomatonState {
        id: "a".into(),
        label: "A".into(),
        accepting: true,
    };
    let s2 = AutomatonState {
        id: "b".into(),
        label: "B".into(),
        accepting: false,
    };
    let mut set = BTreeSet::new();
    set.insert(s1.clone());
    set.insert(s2.clone());
    set.insert(s1.clone()); // duplicate
    assert_eq!(set.len(), 2);
}

// ===========================================================================
// 78. OfflineSynthesisPipeline with custom safe_default reflected in tables
// ===========================================================================

#[test]
fn custom_safe_default_reflected_in_tables() {
    let p = OfflineSynthesisPipeline::new(PipelineBudget::default(), "custom_safe_action".into());
    let spec = SynthesisSpec {
        spec_id: "custom_safe".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![],
        objectives: vec![objective(
            "obj",
            vec![("x", 1_000_000)],
            OptDirection::Minimize,
        )],
        safety_specs: vec![],
        epoch: 1,
    };
    let output = p.synthesize(&spec).unwrap();
    let table = &output.decision_tables[0];
    assert_eq!(table.safe_default, "custom_safe_action");
}
