#![forbid(unsafe_code)]
//! Integration tests for the `offline_synthesis_pipeline` module.
//!
//! Exercises SynthesisSpec construction, validation, OfflineSynthesisPipeline
//! synthesis lifecycle, DecisionTable lookup, TransitionAutomaton stepping,
//! ThresholdBundle, ArtifactCertificate, stage witnesses, error paths,
//! and serde round-trips.

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

use std::collections::BTreeMap;

use frankenengine_engine::offline_synthesis_pipeline::{
    ArtifactCertificate, AutomatonState, CalibratedThreshold, CalibrationMethod, CmpOp,
    DecisionEntry, DecisionTable, DecisionTableRow, EvidenceCategory, EvidenceItem,
    LinearConstraint, LinearTerm, ObservableState, OfflineSynthesisPipeline, OptDirection,
    OptimizationObjective, PipelineBudget, PipelineStage, ResourceUsage, SafetySpec, SpecVar,
    StageStatus, StageWitness, SynthesisError, SynthesisOutput, SynthesisSpec, ThresholdBundle,
    Transition, TransitionAutomaton, TransitionGuard, VarDomain,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bool_var(name: &str) -> SpecVar {
    SpecVar {
        name: name.into(),
        domain: VarDomain::Boolean,
    }
}

fn bounded_var(name: &str, lo: i64, hi: i64) -> SpecVar {
    SpecVar {
        name: name.into(),
        domain: VarDomain::BoundedInt { lo, hi },
    }
}

fn enum_var(name: &str, cardinality: u32) -> SpecVar {
    SpecVar {
        name: name.into(),
        domain: VarDomain::Enum { cardinality },
    }
}

fn simple_constraint(id: &str, var: &str, coeff: i64, op: CmpOp, rhs: i64) -> LinearConstraint {
    LinearConstraint {
        id: id.into(),
        terms: vec![LinearTerm {
            var: var.into(),
            coeff_millionths: coeff,
        }],
        op,
        rhs_millionths: rhs,
        label: format!("constraint-{id}"),
    }
}

fn simple_objective(id: &str, var: &str, coeff: i64, dir: OptDirection) -> OptimizationObjective {
    OptimizationObjective {
        id: id.into(),
        direction: dir,
        terms: vec![LinearTerm {
            var: var.into(),
            coeff_millionths: coeff,
        }],
        bound_millionths: None,
    }
}

fn simple_safety_spec(id: &str, strategy_var: &str, adversary_var: &str) -> SafetySpec {
    SafetySpec {
        id: id.into(),
        property: format!("safety-{id}"),
        maximin_value_millionths: 500_000,
        strategy_vars: vec![strategy_var.into()],
        adversary_vars: vec![adversary_var.into()],
        cvar_alpha_millionths: 950_000,
        cvar_bound_millionths: 200_000,
    }
}

fn minimal_spec() -> SynthesisSpec {
    SynthesisSpec {
        spec_id: "test-spec".into(),
        variables: vec![
            bounded_var("risk", 0, 1_000_000),
            bounded_var("latency", 0, 10_000_000),
        ],
        constraints: vec![simple_constraint(
            "c1",
            "risk",
            1_000_000,
            CmpOp::Le,
            500_000,
        )],
        objectives: vec![simple_objective(
            "obj1",
            "latency",
            1_000_000,
            OptDirection::Minimize,
        )],
        safety_specs: vec![simple_safety_spec("s1", "risk", "latency")],
        epoch: 1,
    }
}

fn default_pipeline() -> OfflineSynthesisPipeline {
    OfflineSynthesisPipeline::new(PipelineBudget::default(), "safe_fallback".into())
}

// ===========================================================================
// 1. VarDomain
// ===========================================================================

#[test]
fn var_domain_boolean_serde() {
    let d = VarDomain::Boolean;
    let json = serde_json::to_string(&d).unwrap();
    let back: VarDomain = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

#[test]
fn var_domain_bounded_int_serde() {
    let d = VarDomain::BoundedInt { lo: -100, hi: 100 };
    let json = serde_json::to_string(&d).unwrap();
    let back: VarDomain = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

#[test]
fn var_domain_enum_serde() {
    let d = VarDomain::Enum { cardinality: 5 };
    let json = serde_json::to_string(&d).unwrap();
    let back: VarDomain = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

// ===========================================================================
// 2. CmpOp
// ===========================================================================

#[test]
fn cmp_op_all_variants_serde() {
    for op in [
        CmpOp::Le,
        CmpOp::Lt,
        CmpOp::Ge,
        CmpOp::Gt,
        CmpOp::Eq,
        CmpOp::Ne,
    ] {
        let json = serde_json::to_string(&op).unwrap();
        let back: CmpOp = serde_json::from_str(&json).unwrap();
        assert_eq!(back, op);
    }
}

// ===========================================================================
// 3. SynthesisSpec
// ===========================================================================

#[test]
fn synthesis_spec_serde_round_trip() {
    let spec = minimal_spec();
    let json = serde_json::to_string(&spec).unwrap();
    let back: SynthesisSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back.spec_id, spec.spec_id);
    assert_eq!(back.variables.len(), spec.variables.len());
    assert_eq!(back.constraints.len(), spec.constraints.len());
}

// ===========================================================================
// 4. DecisionTable
// ===========================================================================

#[test]
fn decision_table_lookup_found() {
    let mut values = BTreeMap::new();
    values.insert("risk".into(), 300_000_i64);

    let table = DecisionTable {
        table_id: "dt-1".into(),
        key_variables: vec!["risk".into()],
        rows: vec![DecisionTableRow {
            state: ObservableState {
                values: values.clone(),
            },
            entry: DecisionEntry {
                action: "use_quickjs".into(),
                expected_loss_millionths: 150_000,
                guardrail_blocked: false,
                pre_guardrail_action: "use_quickjs".into(),
            },
        }],
        safe_default: "safe_fallback".into(),
        content_hash: "hash-1".into(),
    };

    assert_eq!(table.lookup(&ObservableState { values }), "use_quickjs");
    assert_eq!(table.entry_count(), 1);
}

#[test]
fn decision_table_lookup_falls_back_to_safe_default() {
    let table = DecisionTable {
        table_id: "dt-1".into(),
        key_variables: vec!["risk".into()],
        rows: Vec::new(),
        safe_default: "safe_fallback".into(),
        content_hash: "hash-1".into(),
    };

    let mut values = BTreeMap::new();
    values.insert("risk".into(), 999_999_i64);
    assert_eq!(table.lookup(&ObservableState { values }), "safe_fallback");
}

#[test]
fn decision_table_serde() {
    let table = DecisionTable {
        table_id: "dt-1".into(),
        key_variables: vec!["x".into()],
        rows: Vec::new(),
        safe_default: "default".into(),
        content_hash: "h".into(),
    };
    let json = serde_json::to_string(&table).unwrap();
    let back: DecisionTable = serde_json::from_str(&json).unwrap();
    assert_eq!(back.table_id, table.table_id);
}

// ===========================================================================
// 5. TransitionAutomaton
// ===========================================================================

#[test]
fn automaton_step_basic() {
    let mut states = BTreeMap::new();
    states.insert(
        "idle".into(),
        AutomatonState {
            id: "idle".into(),
            label: "Idle".into(),
            accepting: false,
        },
    );
    states.insert(
        "alert".into(),
        AutomatonState {
            id: "alert".into(),
            label: "Alert".into(),
            accepting: true,
        },
    );

    let automaton = TransitionAutomaton {
        automaton_id: "ta-1".into(),
        states,
        transitions: vec![Transition {
            from: "idle".into(),
            to: "alert".into(),
            guards: vec![TransitionGuard {
                variable: "risk".into(),
                op: CmpOp::Gt,
                threshold_millionths: 800_000,
            }],
            priority: 1,
            emit_action: Some("escalate".into()),
        }],
        initial_state: "idle".into(),
        content_hash: "hash-ta".into(),
    };

    let mut bindings = BTreeMap::new();
    bindings.insert("risk".into(), 900_000_i64);

    let (next_state, action) = automaton.step("idle", &bindings);
    assert_eq!(next_state, "alert");
    assert_eq!(action, Some("escalate".to_string()));
}

#[test]
fn automaton_step_no_matching_transition() {
    let mut states = BTreeMap::new();
    states.insert(
        "idle".into(),
        AutomatonState {
            id: "idle".into(),
            label: "Idle".into(),
            accepting: false,
        },
    );

    let automaton = TransitionAutomaton {
        automaton_id: "ta-1".into(),
        states,
        transitions: vec![Transition {
            from: "idle".into(),
            to: "alert".into(),
            guards: vec![TransitionGuard {
                variable: "risk".into(),
                op: CmpOp::Gt,
                threshold_millionths: 800_000,
            }],
            priority: 1,
            emit_action: None,
        }],
        initial_state: "idle".into(),
        content_hash: "hash-ta".into(),
    };

    let mut bindings = BTreeMap::new();
    bindings.insert("risk".into(), 100_000_i64); // Below threshold

    let (next_state, action) = automaton.step("idle", &bindings);
    // No transition fires → stays in current state
    assert_eq!(next_state, "idle");
    assert!(action.is_none());
}

#[test]
fn automaton_counts() {
    let mut states = BTreeMap::new();
    states.insert(
        "s1".into(),
        AutomatonState {
            id: "s1".into(),
            label: "S1".into(),
            accepting: false,
        },
    );
    states.insert(
        "s2".into(),
        AutomatonState {
            id: "s2".into(),
            label: "S2".into(),
            accepting: true,
        },
    );

    let automaton = TransitionAutomaton {
        automaton_id: "ta".into(),
        states,
        transitions: vec![Transition {
            from: "s1".into(),
            to: "s2".into(),
            guards: Vec::new(),
            priority: 1,
            emit_action: None,
        }],
        initial_state: "s1".into(),
        content_hash: "h".into(),
    };
    assert_eq!(automaton.state_count(), 2);
    assert_eq!(automaton.transition_count(), 1);
}

#[test]
fn automaton_serde() {
    let mut states = BTreeMap::new();
    states.insert(
        "s1".into(),
        AutomatonState {
            id: "s1".into(),
            label: "S".into(),
            accepting: false,
        },
    );
    let automaton = TransitionAutomaton {
        automaton_id: "ta".into(),
        states,
        transitions: Vec::new(),
        initial_state: "s1".into(),
        content_hash: "h".into(),
    };
    let json = serde_json::to_string(&automaton).unwrap();
    let back: TransitionAutomaton = serde_json::from_str(&json).unwrap();
    assert_eq!(back.automaton_id, automaton.automaton_id);
}

// ===========================================================================
// 6. ThresholdBundle & CalibratedThreshold
// ===========================================================================

#[test]
fn calibrated_threshold_serde() {
    let t = CalibratedThreshold {
        threshold_id: "t-1".into(),
        variable: "risk".into(),
        value_millionths: 500_000,
        calibration_method: CalibrationMethod::ConformalQuantile,
        sample_count: 1000,
        coverage_millionths: 950_000,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: CalibratedThreshold = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

#[test]
fn calibration_method_all_variants() {
    for method in [
        CalibrationMethod::ConformalQuantile,
        CalibrationMethod::EProcessSequential,
        CalibrationMethod::CvarEmpirical,
        CalibrationMethod::OperatorFixed,
    ] {
        let json = serde_json::to_string(&method).unwrap();
        let back: CalibrationMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(back, method);
    }
}

#[test]
fn threshold_bundle_serde() {
    let bundle = ThresholdBundle {
        bundle_id: "tb-1".into(),
        thresholds: vec![CalibratedThreshold {
            threshold_id: "t-1".into(),
            variable: "risk".into(),
            value_millionths: 500_000,
            calibration_method: CalibrationMethod::ConformalQuantile,
            sample_count: 100,
            coverage_millionths: 950_000,
        }],
        content_hash: "hash-tb".into(),
    };
    let json = serde_json::to_string(&bundle).unwrap();
    let back: ThresholdBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, bundle);
}

// ===========================================================================
// 7. ArtifactCertificate & Evidence
// ===========================================================================

#[test]
fn evidence_category_serde() {
    for cat in [
        EvidenceCategory::DifferentialTest,
        EvidenceCategory::StatisticalTest,
        EvidenceCategory::FormalProof,
        EvidenceCategory::BoundednessProof,
        EvidenceCategory::MonotonicityCheck,
    ] {
        let json = serde_json::to_string(&cat).unwrap();
        let back: EvidenceCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cat);
    }
}

#[test]
fn artifact_certificate_serde() {
    let cert = ArtifactCertificate {
        certificate_id: "cert-1".into(),
        artifact_hash: "hash-a".into(),
        epoch: 1,
        evidence: vec![EvidenceItem {
            category: EvidenceCategory::DifferentialTest,
            description: "test".into(),
            confidence_millionths: 950_000,
            artifact_hash: "hash-e".into(),
        }],
        resource_usage: ResourceUsage {
            time_ms: 100,
            iterations: 50,
            memory_bytes: 1024,
            budget_limited: false,
        },
        satisfied_obligations: vec!["obl-1".into()],
        all_obligations_met: true,
        rollback_token: "rollback-1".into(),
    };
    let json = serde_json::to_string(&cert).unwrap();
    let back: ArtifactCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cert);
}

// ===========================================================================
// 8. StageWitness & StageStatus
// ===========================================================================

#[test]
fn pipeline_stage_serde() {
    for stage in [
        PipelineStage::ConstraintParsing,
        PipelineStage::OptimizationSolving,
        PipelineStage::TableGeneration,
        PipelineStage::ThresholdCalibration,
        PipelineStage::ArtifactAssembly,
    ] {
        let json = serde_json::to_string(&stage).unwrap();
        let back: PipelineStage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, stage);
    }
}

#[test]
fn stage_witness_serde() {
    let w = StageWitness {
        stage: PipelineStage::ConstraintParsing,
        status: StageStatus::Completed { duration_ms: 42 },
        input_hash: "in".into(),
        output_hash: "out".into(),
        resource_usage: ResourceUsage {
            time_ms: 42,
            iterations: 10,
            memory_bytes: 512,
            budget_limited: false,
        },
    };
    let json = serde_json::to_string(&w).unwrap();
    let back: StageWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(back, w);
}

// ===========================================================================
// 9. SynthesisError
// ===========================================================================

#[test]
fn synthesis_error_empty_spec() {
    let err = SynthesisError::EmptySpec;
    assert!(err.to_string().contains("mpty") || !err.to_string().is_empty());
}

#[test]
fn synthesis_error_invalid_constraint() {
    let err = SynthesisError::InvalidConstraint {
        id: "c1".into(),
        reason: "bad variable".into(),
    };
    let s = err.to_string();
    assert!(s.contains("c1") || s.contains("constraint"));
}

#[test]
fn synthesis_error_budget_exhausted() {
    let err = SynthesisError::BudgetExhausted {
        stage: PipelineStage::OptimizationSolving,
    };
    assert!(!err.to_string().is_empty());
}

// ===========================================================================
// 10. PipelineBudget
// ===========================================================================

#[test]
fn pipeline_budget_default() {
    let budget = PipelineBudget::default();
    assert!(budget.max_iterations > 0);
    assert!(budget.max_stage_time_ms > 0);
    assert!(budget.max_memory_bytes > 0);
}

// ===========================================================================
// 11. OfflineSynthesisPipeline — synthesis
// ===========================================================================

#[test]
fn synthesize_minimal_spec() {
    let pipeline = default_pipeline();
    let spec = minimal_spec();

    let output = pipeline.synthesize(&spec).unwrap();
    assert_eq!(output.spec_id, "test-spec");
    assert!(!output.decision_tables.is_empty());
    assert!(!output.stage_witnesses.is_empty());
}

#[test]
fn synthesize_produces_stage_witnesses() {
    let pipeline = default_pipeline();
    let spec = minimal_spec();

    let output = pipeline.synthesize(&spec).unwrap();
    // Should have witnesses for all 5 stages
    assert_eq!(output.stage_witnesses.len(), 5);
}

#[test]
fn synthesize_produces_certificates() {
    let pipeline = default_pipeline();
    let spec = minimal_spec();

    let output = pipeline.synthesize(&spec).unwrap();
    assert!(!output.certificates.is_empty());
}

#[test]
fn synthesize_produces_threshold_bundles() {
    let pipeline = default_pipeline();
    let spec = minimal_spec();

    let output = pipeline.synthesize(&spec).unwrap();
    assert!(!output.threshold_bundles.is_empty());
}

#[test]
fn synthesize_produces_automata() {
    let pipeline = default_pipeline();
    let spec = minimal_spec();

    let output = pipeline.synthesize(&spec).unwrap();
    // Safety specs should produce at least one automaton
    assert!(!output.automata.is_empty());
}

#[test]
fn synthesize_tracks_resource_usage() {
    let pipeline = default_pipeline();
    let spec = minimal_spec();

    let output = pipeline.synthesize(&spec).unwrap();
    assert!(output.total_resource_usage.time_ms > 0 || output.total_resource_usage.iterations > 0);
}

#[test]
fn synthesize_output_serde_round_trip() {
    let pipeline = default_pipeline();
    let spec = minimal_spec();

    let output = pipeline.synthesize(&spec).unwrap();
    let json = serde_json::to_string(&output).unwrap();
    let back: SynthesisOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(back.spec_id, output.spec_id);
    assert_eq!(back.decision_tables.len(), output.decision_tables.len());
}

// ===========================================================================
// 12. Error paths
// ===========================================================================

#[test]
fn synthesize_empty_spec_fails() {
    let pipeline = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "empty".into(),
        variables: Vec::new(),
        constraints: Vec::new(),
        objectives: Vec::new(),
        safety_specs: Vec::new(),
        epoch: 1,
    };

    let result = pipeline.synthesize(&spec);
    assert!(result.is_err());
}

#[test]
fn synthesize_invalid_variable_ref_fails() {
    let pipeline = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "bad-ref".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![simple_constraint(
            "c1",
            "nonexistent_var",
            1_000_000,
            CmpOp::Le,
            500_000,
        )],
        objectives: Vec::new(),
        safety_specs: vec![simple_safety_spec("s1", "x", "x")],
        epoch: 1,
    };

    let result = pipeline.synthesize(&spec);
    assert!(result.is_err());
}

// ===========================================================================
// 13. Multi-variable spec
// ===========================================================================

#[test]
fn synthesize_multi_variable() {
    let pipeline = default_pipeline();
    let spec = SynthesisSpec {
        spec_id: "multi-var".into(),
        variables: vec![
            bounded_var("risk", 0, 1_000_000),
            bounded_var("latency", 0, 10_000_000),
            bool_var("use_cache"),
            enum_var("lane", 3),
        ],
        constraints: vec![
            simple_constraint("c1", "risk", 1_000_000, CmpOp::Le, 500_000),
            simple_constraint("c2", "latency", 1_000_000, CmpOp::Le, 5_000_000),
        ],
        objectives: vec![
            simple_objective("obj1", "latency", 1_000_000, OptDirection::Minimize),
            simple_objective("obj2", "risk", -1_000_000, OptDirection::Minimize),
        ],
        safety_specs: vec![simple_safety_spec("s1", "risk", "latency")],
        epoch: 2,
    };

    let output = pipeline.synthesize(&spec).unwrap();
    assert_eq!(output.spec_id, "multi-var");
    assert!(!output.decision_tables.is_empty());
}

// ===========================================================================
// 14. Decision table from synthesis
// ===========================================================================

#[test]
fn synthesized_decision_table_lookup_works() {
    let pipeline = default_pipeline();
    let spec = minimal_spec();

    let output = pipeline.synthesize(&spec).unwrap();
    let table = &output.decision_tables[0];

    // Should be able to look up any state
    let mut values = BTreeMap::new();
    for key in &table.key_variables {
        values.insert(key.clone(), 500_000_i64);
    }
    let action = table.lookup(&ObservableState { values });
    assert!(!action.is_empty());
}

// ===========================================================================
// 15. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle() {
    let budget = PipelineBudget {
        max_iterations: 1000,
        max_stage_time_ms: 5000,
        max_memory_bytes: 50_000_000,
    };
    let pipeline = OfflineSynthesisPipeline::new(budget, "fallback_safe".into());

    let spec = minimal_spec();
    let output = pipeline.synthesize(&spec).unwrap();

    // Verify all major output components exist
    assert!(!output.decision_tables.is_empty());
    assert!(!output.automata.is_empty());
    assert!(!output.threshold_bundles.is_empty());
    assert!(!output.certificates.is_empty());
    assert_eq!(output.stage_witnesses.len(), 5);

    // Verify decision table works
    let table = &output.decision_tables[0];
    assert!(table.entry_count() > 0);

    // Verify automaton
    let automaton = &output.automata[0];
    assert!(automaton.state_count() > 0);

    // Full serde round-trip
    let json = serde_json::to_string(&output).unwrap();
    let back: SynthesisOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(back.spec_id, output.spec_id);
}
