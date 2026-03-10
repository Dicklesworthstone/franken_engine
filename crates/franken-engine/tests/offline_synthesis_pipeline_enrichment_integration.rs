#![forbid(unsafe_code)]
//! Enrichment integration tests for `offline_synthesis_pipeline`.
//!
//! Adds exact Display messages, Debug distinctness, JSON field-name stability,
//! serde exact enum values, std::error::Error impl, validation edge cases,
//! decision table/automaton behavior, and additional serde roundtrips beyond
//! the existing 35 integration tests.

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
    ArtifactCertificate, AutomatonState, CalibratedThreshold, CalibrationMethod, CmpOp,
    DecisionEntry, DecisionTable, DecisionTableRow, EvidenceCategory, EvidenceItem,
    LinearConstraint, LinearTerm, ObservableState, OfflineSynthesisPipeline, OptDirection,
    OptimizationObjective, PipelineBudget, PipelineStage, ResourceUsage, SafetySpec, SpecVar,
    StageStatus, SynthesisError, SynthesisSpec, Transition, TransitionAutomaton, TransitionGuard,
    VarDomain,
};

// ===========================================================================
// Helpers
// ===========================================================================

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

fn constraint(id: &str, var: &str, op: CmpOp, rhs: i64) -> LinearConstraint {
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

fn safety_spec(id: &str, strat_var: &str, adv_var: &str) -> SafetySpec {
    SafetySpec {
        id: id.into(),
        property: "safety".into(),
        maximin_value_millionths: 500_000,
        strategy_vars: vec![strat_var.into()],
        adversary_vars: vec![adv_var.into()],
        cvar_alpha_millionths: 50_000,
        cvar_bound_millionths: 100_000,
    }
}

fn minimal_spec() -> SynthesisSpec {
    SynthesisSpec {
        spec_id: "spec-1".into(),
        variables: vec![bool_var("x")],
        constraints: vec![constraint("c1", "x", CmpOp::Le, 1_000_000)],
        objectives: vec![],
        safety_specs: vec![],
        epoch: 1,
    }
}

fn pipeline() -> OfflineSynthesisPipeline {
    OfflineSynthesisPipeline::new(PipelineBudget::default(), "safe_deny".into())
}

// ===========================================================================
// 1. SynthesisError — Display exact messages
// ===========================================================================

#[test]
fn error_display_empty_spec() {
    assert_eq!(SynthesisError::EmptySpec.to_string(), "empty specification");
}

#[test]
fn error_display_invalid_constraint() {
    let e = SynthesisError::InvalidConstraint {
        id: "c1".into(),
        reason: "unknown variable: z".into(),
    };
    assert_eq!(e.to_string(), "invalid constraint c1: unknown variable: z");
}

#[test]
fn error_display_infeasible() {
    let e = SynthesisError::Infeasible {
        constraint_ids: vec!["c1".into(), "c2".into()],
    };
    assert_eq!(e.to_string(), "infeasible: c1, c2");
}

#[test]
fn error_display_budget_exhausted() {
    let e = SynthesisError::BudgetExhausted {
        stage: PipelineStage::OptimizationSolving,
    };
    assert_eq!(e.to_string(), "budget exhausted at OptimizationSolving");
}

#[test]
fn error_display_no_safety_spec() {
    assert_eq!(
        SynthesisError::NoSafetySpec.to_string(),
        "no safety specification provided"
    );
}

#[test]
fn error_display_invalid_variable() {
    let e = SynthesisError::InvalidVariable {
        name: "unknown_var".into(),
    };
    assert_eq!(e.to_string(), "invalid variable: unknown_var");
}

#[test]
fn error_display_internal_error() {
    let e = SynthesisError::InternalError("oops".into());
    assert_eq!(e.to_string(), "internal error: oops");
}

#[test]
fn synthesis_error_is_std_error() {
    let e = SynthesisError::EmptySpec;
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 2. SynthesisError — serde all variants
// ===========================================================================

#[test]
fn synthesis_error_serde_all_variants() {
    let errors = [
        SynthesisError::EmptySpec,
        SynthesisError::InvalidConstraint {
            id: "c1".into(),
            reason: "bad".into(),
        },
        SynthesisError::Infeasible {
            constraint_ids: vec!["c1".into()],
        },
        SynthesisError::BudgetExhausted {
            stage: PipelineStage::TableGeneration,
        },
        SynthesisError::NoSafetySpec,
        SynthesisError::InvalidVariable { name: "v".into() },
        SynthesisError::InternalError("err".into()),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: SynthesisError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

// ===========================================================================
// 3. Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_cmp_op() {
    let variants = [
        CmpOp::Le,
        CmpOp::Lt,
        CmpOp::Ge,
        CmpOp::Gt,
        CmpOp::Eq,
        CmpOp::Ne,
    ];
    let strings: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(strings.len(), variants.len());
}

#[test]
fn debug_distinct_opt_direction() {
    let a = format!("{:?}", OptDirection::Minimize);
    let b = format!("{:?}", OptDirection::Maximize);
    assert_ne!(a, b);
}

#[test]
fn debug_distinct_pipeline_stage() {
    let variants = [
        PipelineStage::ConstraintParsing,
        PipelineStage::OptimizationSolving,
        PipelineStage::TableGeneration,
        PipelineStage::ThresholdCalibration,
        PipelineStage::ArtifactAssembly,
    ];
    let strings: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(strings.len(), variants.len());
}

#[test]
fn debug_distinct_calibration_method() {
    let variants = [
        CalibrationMethod::ConformalQuantile,
        CalibrationMethod::EProcessSequential,
        CalibrationMethod::CvarEmpirical,
        CalibrationMethod::OperatorFixed,
    ];
    let strings: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(strings.len(), variants.len());
}

#[test]
fn debug_distinct_evidence_category() {
    let variants = [
        EvidenceCategory::DifferentialTest,
        EvidenceCategory::StatisticalTest,
        EvidenceCategory::FormalProof,
        EvidenceCategory::BoundednessProof,
        EvidenceCategory::MonotonicityCheck,
    ];
    let strings: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(strings.len(), variants.len());
}

#[test]
fn debug_distinct_stage_status() {
    let variants = [
        StageStatus::Pending,
        StageStatus::Running,
        StageStatus::Completed { duration_ms: 0 },
        StageStatus::Failed { reason: "x".into() },
        StageStatus::BudgetExhausted,
    ];
    let strings: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(strings.len(), variants.len());
}

// ===========================================================================
// 4. Serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_cmp_op() {
    assert_eq!(serde_json::to_string(&CmpOp::Le).unwrap(), "\"Le\"");
    assert_eq!(serde_json::to_string(&CmpOp::Lt).unwrap(), "\"Lt\"");
    assert_eq!(serde_json::to_string(&CmpOp::Ge).unwrap(), "\"Ge\"");
    assert_eq!(serde_json::to_string(&CmpOp::Gt).unwrap(), "\"Gt\"");
    assert_eq!(serde_json::to_string(&CmpOp::Eq).unwrap(), "\"Eq\"");
    assert_eq!(serde_json::to_string(&CmpOp::Ne).unwrap(), "\"Ne\"");
}

#[test]
fn serde_exact_opt_direction() {
    assert_eq!(
        serde_json::to_string(&OptDirection::Minimize).unwrap(),
        "\"Minimize\""
    );
    assert_eq!(
        serde_json::to_string(&OptDirection::Maximize).unwrap(),
        "\"Maximize\""
    );
}

#[test]
fn serde_exact_pipeline_stage() {
    assert_eq!(
        serde_json::to_string(&PipelineStage::ConstraintParsing).unwrap(),
        "\"ConstraintParsing\""
    );
    assert_eq!(
        serde_json::to_string(&PipelineStage::OptimizationSolving).unwrap(),
        "\"OptimizationSolving\""
    );
    assert_eq!(
        serde_json::to_string(&PipelineStage::TableGeneration).unwrap(),
        "\"TableGeneration\""
    );
    assert_eq!(
        serde_json::to_string(&PipelineStage::ThresholdCalibration).unwrap(),
        "\"ThresholdCalibration\""
    );
    assert_eq!(
        serde_json::to_string(&PipelineStage::ArtifactAssembly).unwrap(),
        "\"ArtifactAssembly\""
    );
}

#[test]
fn serde_exact_calibration_method() {
    assert_eq!(
        serde_json::to_string(&CalibrationMethod::ConformalQuantile).unwrap(),
        "\"ConformalQuantile\""
    );
    assert_eq!(
        serde_json::to_string(&CalibrationMethod::EProcessSequential).unwrap(),
        "\"EProcessSequential\""
    );
    assert_eq!(
        serde_json::to_string(&CalibrationMethod::CvarEmpirical).unwrap(),
        "\"CvarEmpirical\""
    );
    assert_eq!(
        serde_json::to_string(&CalibrationMethod::OperatorFixed).unwrap(),
        "\"OperatorFixed\""
    );
}

#[test]
fn serde_exact_evidence_category() {
    assert_eq!(
        serde_json::to_string(&EvidenceCategory::DifferentialTest).unwrap(),
        "\"DifferentialTest\""
    );
    assert_eq!(
        serde_json::to_string(&EvidenceCategory::StatisticalTest).unwrap(),
        "\"StatisticalTest\""
    );
    assert_eq!(
        serde_json::to_string(&EvidenceCategory::FormalProof).unwrap(),
        "\"FormalProof\""
    );
    assert_eq!(
        serde_json::to_string(&EvidenceCategory::BoundednessProof).unwrap(),
        "\"BoundednessProof\""
    );
    assert_eq!(
        serde_json::to_string(&EvidenceCategory::MonotonicityCheck).unwrap(),
        "\"MonotonicityCheck\""
    );
}

// ===========================================================================
// 5. JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_spec_var() {
    let v = bool_var("x");
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains("\"name\""), "{json}");
    assert!(json.contains("\"domain\""), "{json}");
}

#[test]
fn json_fields_linear_constraint() {
    let c = constraint("c1", "x", CmpOp::Le, 1_000_000);
    let json = serde_json::to_string(&c).unwrap();
    for field in ["id", "terms", "op", "rhs_millionths", "label"] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_optimization_objective() {
    let o = OptimizationObjective {
        id: "obj-1".into(),
        direction: OptDirection::Minimize,
        terms: vec![],
        bound_millionths: Some(1_000_000),
    };
    let json = serde_json::to_string(&o).unwrap();
    for field in ["id", "direction", "terms", "bound_millionths"] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_safety_spec() {
    let s = safety_spec("ss-1", "x", "y");
    let json = serde_json::to_string(&s).unwrap();
    for field in [
        "id",
        "property",
        "maximin_value_millionths",
        "strategy_vars",
        "adversary_vars",
        "cvar_alpha_millionths",
        "cvar_bound_millionths",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_resource_usage() {
    let r = ResourceUsage {
        time_ms: 10,
        iterations: 100,
        memory_bytes: 1024,
        budget_limited: false,
    };
    let json = serde_json::to_string(&r).unwrap();
    for field in ["time_ms", "iterations", "memory_bytes", "budget_limited"] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_decision_entry() {
    let e = DecisionEntry {
        action: "allow".into(),
        expected_loss_millionths: 100_000,
        guardrail_blocked: false,
        pre_guardrail_action: "allow".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    for field in [
        "action",
        "expected_loss_millionths",
        "guardrail_blocked",
        "pre_guardrail_action",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_decision_table() {
    let t = DecisionTable {
        table_id: "t1".into(),
        key_variables: vec!["x".into()],
        rows: vec![],
        safe_default: "deny".into(),
        content_hash: "hash".into(),
    };
    let json = serde_json::to_string(&t).unwrap();
    for field in [
        "table_id",
        "key_variables",
        "rows",
        "safe_default",
        "content_hash",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_automaton_state() {
    let s = AutomatonState {
        id: "s0".into(),
        label: "initial".into(),
        accepting: false,
    };
    let json = serde_json::to_string(&s).unwrap();
    for field in ["id", "label", "accepting"] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_transition() {
    let t = Transition {
        from: "s0".into(),
        to: "s1".into(),
        guards: vec![],
        priority: 1,
        emit_action: Some("alert".into()),
    };
    let json = serde_json::to_string(&t).unwrap();
    for field in ["from", "to", "guards", "priority", "emit_action"] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_calibrated_threshold() {
    let t = CalibratedThreshold {
        threshold_id: "t1".into(),
        variable: "x".into(),
        value_millionths: 950_000,
        calibration_method: CalibrationMethod::ConformalQuantile,
        sample_count: 1000,
        coverage_millionths: 950_000,
    };
    let json = serde_json::to_string(&t).unwrap();
    for field in [
        "threshold_id",
        "variable",
        "value_millionths",
        "calibration_method",
        "sample_count",
        "coverage_millionths",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_evidence_item() {
    let e = EvidenceItem {
        category: EvidenceCategory::FormalProof,
        description: "proved".into(),
        confidence_millionths: 999_000,
        artifact_hash: "h".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    for field in [
        "category",
        "description",
        "confidence_millionths",
        "artifact_hash",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_artifact_certificate() {
    let c = ArtifactCertificate {
        certificate_id: "cert-1".into(),
        artifact_hash: "ah".into(),
        epoch: 1,
        evidence: vec![],
        resource_usage: ResourceUsage {
            time_ms: 0,
            iterations: 0,
            memory_bytes: 0,
            budget_limited: false,
        },
        satisfied_obligations: vec![],
        all_obligations_met: true,
        rollback_token: "rb".into(),
    };
    let json = serde_json::to_string(&c).unwrap();
    for field in [
        "certificate_id",
        "artifact_hash",
        "epoch",
        "evidence",
        "resource_usage",
        "satisfied_obligations",
        "all_obligations_met",
        "rollback_token",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_pipeline_budget() {
    let b = PipelineBudget::default();
    let json = serde_json::to_string(&b).unwrap();
    for field in ["max_iterations", "max_stage_time_ms", "max_memory_bytes"] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

// ===========================================================================
// 6. PipelineBudget Default exact values
// ===========================================================================

#[test]
fn pipeline_budget_default_exact() {
    let b = PipelineBudget::default();
    assert_eq!(b.max_iterations, 100_000);
    assert_eq!(b.max_stage_time_ms, 10_000);
    assert_eq!(b.max_memory_bytes, 100_000_000);
}

// ===========================================================================
// 7. Serde roundtrips for types not covered
// ===========================================================================

#[test]
fn serde_roundtrip_linear_term() {
    let t = LinearTerm {
        var: "x".into(),
        coeff_millionths: 500_000,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: LinearTerm = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

#[test]
fn serde_roundtrip_observable_state() {
    let mut values = BTreeMap::new();
    values.insert("x".to_string(), 500_000i64);
    values.insert("y".to_string(), 750_000i64);
    let s = ObservableState { values };
    let json = serde_json::to_string(&s).unwrap();
    let back: ObservableState = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

#[test]
fn serde_roundtrip_transition_guard() {
    let g = TransitionGuard {
        variable: "risk".into(),
        op: CmpOp::Gt,
        threshold_millionths: 800_000,
    };
    let json = serde_json::to_string(&g).unwrap();
    let back: TransitionGuard = serde_json::from_str(&json).unwrap();
    assert_eq!(back, g);
}

#[test]
fn serde_roundtrip_stage_status_all() {
    let statuses = [
        StageStatus::Pending,
        StageStatus::Running,
        StageStatus::Completed { duration_ms: 42 },
        StageStatus::Failed {
            reason: "timeout".into(),
        },
        StageStatus::BudgetExhausted,
    ];
    for s in &statuses {
        let json = serde_json::to_string(s).unwrap();
        let back: StageStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, s);
    }
}

#[test]
fn serde_roundtrip_resource_usage() {
    let r = ResourceUsage {
        time_ms: 100,
        iterations: 5000,
        memory_bytes: 1_048_576,
        budget_limited: true,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: ResourceUsage = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[test]
fn serde_roundtrip_decision_table_row() {
    let mut values = BTreeMap::new();
    values.insert("x".to_string(), 1_000_000i64);
    let row = DecisionTableRow {
        state: ObservableState { values },
        entry: DecisionEntry {
            action: "allow".into(),
            expected_loss_millionths: 0,
            guardrail_blocked: false,
            pre_guardrail_action: "allow".into(),
        },
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: DecisionTableRow = serde_json::from_str(&json).unwrap();
    assert_eq!(back, row);
}

// ===========================================================================
// 8. DecisionTable — lookup edge cases
// ===========================================================================

#[test]
fn decision_table_empty_returns_safe_default() {
    let t = DecisionTable {
        table_id: "t1".into(),
        key_variables: vec!["x".into()],
        rows: vec![],
        safe_default: "deny".into(),
        content_hash: "h".into(),
    };
    let state = ObservableState {
        values: BTreeMap::from([("x".to_string(), 500_000)]),
    };
    assert_eq!(t.lookup(&state), "deny");
    assert_eq!(t.entry_count(), 0);
}

#[test]
fn decision_table_lookup_exact_match() {
    let state = ObservableState {
        values: BTreeMap::from([("x".to_string(), 1_000_000)]),
    };
    let t = DecisionTable {
        table_id: "t1".into(),
        key_variables: vec!["x".into()],
        rows: vec![DecisionTableRow {
            state: state.clone(),
            entry: DecisionEntry {
                action: "allow".into(),
                expected_loss_millionths: 50_000,
                guardrail_blocked: false,
                pre_guardrail_action: "allow".into(),
            },
        }],
        safe_default: "deny".into(),
        content_hash: "h".into(),
    };
    assert_eq!(t.lookup(&state), "allow");
    assert_eq!(t.entry_count(), 1);
}

// ===========================================================================
// 9. TransitionAutomaton — step edge cases
// ===========================================================================

#[test]
fn automaton_step_priority_resolution() {
    let mut states = BTreeMap::new();
    states.insert(
        "s0".to_string(),
        AutomatonState {
            id: "s0".into(),
            label: "start".into(),
            accepting: false,
        },
    );
    states.insert(
        "s1".to_string(),
        AutomatonState {
            id: "s1".into(),
            label: "low".into(),
            accepting: false,
        },
    );
    states.insert(
        "s2".to_string(),
        AutomatonState {
            id: "s2".into(),
            label: "high".into(),
            accepting: true,
        },
    );

    let automaton = TransitionAutomaton {
        automaton_id: "a1".into(),
        states,
        transitions: vec![
            Transition {
                from: "s0".into(),
                to: "s1".into(),
                guards: vec![TransitionGuard {
                    variable: "risk".into(),
                    op: CmpOp::Ge,
                    threshold_millionths: 0,
                }],
                priority: 1,
                emit_action: Some("low_alert".into()),
            },
            Transition {
                from: "s0".into(),
                to: "s2".into(),
                guards: vec![TransitionGuard {
                    variable: "risk".into(),
                    op: CmpOp::Ge,
                    threshold_millionths: 0,
                }],
                priority: 10, // higher priority
                emit_action: Some("high_alert".into()),
            },
        ],
        initial_state: "s0".into(),
        content_hash: "h".into(),
    };

    let bindings = BTreeMap::from([("risk".to_string(), 500_000i64)]);
    let (next, action) = automaton.step("s0", &bindings);
    assert_eq!(next, "s2"); // higher priority wins
    assert_eq!(action, Some("high_alert".to_string()));
}

#[test]
fn automaton_step_stays_when_no_guards_pass() {
    let mut states = BTreeMap::new();
    states.insert(
        "s0".to_string(),
        AutomatonState {
            id: "s0".into(),
            label: "start".into(),
            accepting: false,
        },
    );
    let automaton = TransitionAutomaton {
        automaton_id: "a1".into(),
        states,
        transitions: vec![Transition {
            from: "s0".into(),
            to: "s1".into(),
            guards: vec![TransitionGuard {
                variable: "risk".into(),
                op: CmpOp::Gt,
                threshold_millionths: 999_999,
            }],
            priority: 1,
            emit_action: None,
        }],
        initial_state: "s0".into(),
        content_hash: "h".into(),
    };

    let bindings = BTreeMap::from([("risk".to_string(), 500_000i64)]);
    let (next, action) = automaton.step("s0", &bindings);
    assert_eq!(next, "s0"); // stays
    assert_eq!(action, None);
}

#[test]
fn automaton_state_count_and_transition_count() {
    let mut states = BTreeMap::new();
    states.insert(
        "s0".to_string(),
        AutomatonState {
            id: "s0".into(),
            label: "a".into(),
            accepting: false,
        },
    );
    states.insert(
        "s1".to_string(),
        AutomatonState {
            id: "s1".into(),
            label: "b".into(),
            accepting: true,
        },
    );
    let automaton = TransitionAutomaton {
        automaton_id: "a1".into(),
        states,
        transitions: vec![
            Transition {
                from: "s0".into(),
                to: "s1".into(),
                guards: vec![],
                priority: 1,
                emit_action: None,
            },
            Transition {
                from: "s1".into(),
                to: "s0".into(),
                guards: vec![],
                priority: 1,
                emit_action: None,
            },
        ],
        initial_state: "s0".into(),
        content_hash: "h".into(),
    };
    assert_eq!(automaton.state_count(), 2);
    assert_eq!(automaton.transition_count(), 2);
}

// ===========================================================================
// 10. Validation — unknown variable in safety spec
// ===========================================================================

#[test]
fn synthesize_invalid_safety_spec_variable() {
    let spec = SynthesisSpec {
        spec_id: "spec-bad".into(),
        variables: vec![bool_var("x"), bool_var("y")],
        constraints: vec![],
        objectives: vec![],
        safety_specs: vec![safety_spec("ss1", "x", "unknown_var")],
        epoch: 1,
    };
    let p = pipeline();
    match p.synthesize(&spec) {
        Err(SynthesisError::InvalidVariable { name }) => {
            assert_eq!(name, "unknown_var");
        }
        other => panic!("expected InvalidVariable, got {other:?}"),
    }
}

// ===========================================================================
// 11. Validation — unknown variable in objective
// ===========================================================================

#[test]
fn synthesize_invalid_objective_variable() {
    let spec = SynthesisSpec {
        spec_id: "spec-bad".into(),
        variables: vec![bool_var("x")],
        constraints: vec![],
        objectives: vec![OptimizationObjective {
            id: "obj-1".into(),
            direction: OptDirection::Minimize,
            terms: vec![LinearTerm {
                var: "nonexistent".into(),
                coeff_millionths: 1_000_000,
            }],
            bound_millionths: None,
        }],
        safety_specs: vec![],
        epoch: 1,
    };
    let p = pipeline();
    match p.synthesize(&spec) {
        Err(SynthesisError::InvalidVariable { name }) => {
            assert_eq!(name, "nonexistent");
        }
        other => panic!("expected InvalidVariable, got {other:?}"),
    }
}

// ===========================================================================
// 12. Infeasible constraint detection
// ===========================================================================

#[test]
fn synthesize_infeasible_constraints() {
    let spec = SynthesisSpec {
        spec_id: "spec-inf".into(),
        variables: vec![bounded_var("x", 0, 1_000_000)],
        constraints: vec![
            constraint("c1", "x", CmpOp::Ge, 900_000),
            constraint("c2", "x", CmpOp::Le, 100_000),
        ],
        objectives: vec![],
        safety_specs: vec![],
        epoch: 1,
    };
    let p = pipeline();
    match p.synthesize(&spec) {
        Err(SynthesisError::Infeasible { constraint_ids }) => {
            assert!(constraint_ids.contains(&"x".to_string()));
        }
        other => panic!("expected Infeasible, got {other:?}"),
    }
}

// ===========================================================================
// 13. Pipeline output has 5 stage witnesses
// ===========================================================================

#[test]
fn synthesize_output_has_five_stages() {
    let p = pipeline();
    let output = p.synthesize(&minimal_spec()).unwrap();
    assert_eq!(output.stage_witnesses.len(), 5);
    let stages: Vec<PipelineStage> = output.stage_witnesses.iter().map(|w| w.stage).collect();
    assert_eq!(stages[0], PipelineStage::ConstraintParsing);
    assert_eq!(stages[1], PipelineStage::OptimizationSolving);
    assert_eq!(stages[2], PipelineStage::TableGeneration);
    assert_eq!(stages[3], PipelineStage::ThresholdCalibration);
    assert_eq!(stages[4], PipelineStage::ArtifactAssembly);
}

// ===========================================================================
// 14. Pipeline deterministic output
// ===========================================================================

#[test]
fn synthesize_deterministic() {
    let p = pipeline();
    let spec = minimal_spec();
    let o1 = p.synthesize(&spec).unwrap();
    let o2 = p.synthesize(&spec).unwrap();
    assert_eq!(o1, o2);
}

// ===========================================================================
// 15. VarDomain Enum — serde with cardinality
// ===========================================================================

#[test]
fn var_domain_enum_serde_exact() {
    let v = VarDomain::Enum { cardinality: 5 };
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains("\"Enum\""), "{json}");
    assert!(json.contains("\"cardinality\""), "{json}");
    let back: VarDomain = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn var_domain_bounded_int_serde_exact() {
    let v = VarDomain::BoundedInt { lo: -100, hi: 100 };
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains("\"BoundedInt\""), "{json}");
    assert!(json.contains("\"lo\""), "{json}");
    assert!(json.contains("\"hi\""), "{json}");
    let back: VarDomain = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}
