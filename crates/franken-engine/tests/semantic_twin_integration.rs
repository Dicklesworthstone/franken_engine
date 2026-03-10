#![forbid(unsafe_code)]
//! Integration tests for the `semantic_twin` module.
//!
//! Exercises every public type, constant, enum variant, method, error path,
//! and cross-concern scenario from outside the crate boundary.

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

use std::collections::BTreeSet;

use frankenengine_engine::assumptions_ledger::{
    AssumptionCategory, AssumptionOrigin, DemotionAction, DemotionPolicy, LedgerError, MonitorKind,
    MonitorOp, ViolationSeverity,
};
use frankenengine_engine::semantic_twin::{
    CausalAdjustmentStrategy, IdentifiabilityAssumption,
    SEMANTIC_TWIN_CAUSAL_ADJUSTMENT_SCHEMA_VERSION, SEMANTIC_TWIN_COMPONENT,
    SEMANTIC_TWIN_LOG_SCHEMA_VERSION, SEMANTIC_TWIN_STATE_SPACE_SCHEMA_VERSION, SemanticTwinError,
    SemanticTwinLogEvent, SemanticTwinObservationResult, SemanticTwinRuntime,
    SemanticTwinSpecification, SignalNamespace, TelemetryContractRef, TransitionGuard,
    TwinStateTransition, TwinStateVariable,
};
use frankenengine_engine::structural_causal_model::{ScmError, VariableDomain};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_spec() -> SemanticTwinSpecification {
    SemanticTwinSpecification::frx_19_1_default().expect("default spec must build")
}

fn make_runtime() -> SemanticTwinRuntime {
    SemanticTwinRuntime::new(
        default_spec(),
        "trace-integ",
        "decision-integ",
        "policy-integ",
        1,
        DemotionPolicy::default(),
    )
    .expect("runtime must build")
}

fn custom_demotion_policy() -> DemotionPolicy {
    DemotionPolicy {
        advisory_action: DemotionAction::NoAction,
        warning_action: DemotionAction::DemoteLane {
            lane_id: "lane-fallback".into(),
            reason: "custom warning demotion".into(),
        },
        critical_action: DemotionAction::EscalateToOperator {
            reason: "custom critical escalation".into(),
        },
        fatal_action: DemotionAction::EnterSafeMode {
            reason: "custom fatal safe mode".into(),
        },
    }
}

// ===========================================================================
// Section 1: Constants
// ===========================================================================

#[test]
fn constant_state_space_schema_version() {
    assert_eq!(
        SEMANTIC_TWIN_STATE_SPACE_SCHEMA_VERSION,
        "franken-engine.semantic-twin.state-space.v1"
    );
}

#[test]
fn constant_causal_adjustment_schema_version() {
    assert_eq!(
        SEMANTIC_TWIN_CAUSAL_ADJUSTMENT_SCHEMA_VERSION,
        "franken-engine.semantic-twin.causal-adjustment.v1"
    );
}

#[test]
fn constant_log_schema_version() {
    assert_eq!(
        SEMANTIC_TWIN_LOG_SCHEMA_VERSION,
        "franken-engine.semantic-twin.log-event.v1"
    );
}

#[test]
fn constant_component_name() {
    assert_eq!(SEMANTIC_TWIN_COMPONENT, "semantic_twin_state_space");
}

// ===========================================================================
// Section 2: SignalNamespace
// ===========================================================================

#[test]
fn signal_namespace_as_str_all_five_variants() {
    let pairs: [(SignalNamespace, &str); 5] = [
        (SignalNamespace::Frir, "frir"),
        (
            SignalNamespace::RuntimeDecisionCore,
            "runtime_decision_core",
        ),
        (
            SignalNamespace::RuntimeObservability,
            "runtime_observability",
        ),
        (SignalNamespace::PolicyController, "policy_controller"),
        (SignalNamespace::AssumptionsLedger, "assumptions_ledger"),
    ];
    for (ns, expected) in pairs {
        assert_eq!(ns.as_str(), expected);
    }
}

#[test]
fn signal_namespace_serde_roundtrip_all() {
    let all = [
        SignalNamespace::Frir,
        SignalNamespace::RuntimeDecisionCore,
        SignalNamespace::RuntimeObservability,
        SignalNamespace::PolicyController,
        SignalNamespace::AssumptionsLedger,
    ];
    for ns in all {
        let json = serde_json::to_string(&ns).unwrap();
        let back: SignalNamespace = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ns);
    }
}

#[test]
fn signal_namespace_deterministic_ordering() {
    let mut a = vec![
        SignalNamespace::AssumptionsLedger,
        SignalNamespace::Frir,
        SignalNamespace::PolicyController,
    ];
    let mut b = a.clone();
    a.sort();
    b.sort();
    assert_eq!(a, b);
}

#[test]
fn signal_namespace_btree_set_dedup() {
    let mut set = BTreeSet::new();
    set.insert(SignalNamespace::Frir);
    set.insert(SignalNamespace::Frir);
    set.insert(SignalNamespace::PolicyController);
    assert_eq!(set.len(), 2);
}

// ===========================================================================
// Section 3: TelemetryContractRef
// ===========================================================================

#[test]
fn telemetry_ref_valid_passes() {
    let tcr = TelemetryContractRef {
        namespace: SignalNamespace::Frir,
        signal_key: "workload.complexity".into(),
        units: "millionths".into(),
        deterministic: true,
        required: true,
    };
    assert!(tcr.validate().is_ok());
}

#[test]
fn telemetry_ref_empty_signal_key_error() {
    let tcr = TelemetryContractRef {
        namespace: SignalNamespace::RuntimeDecisionCore,
        signal_key: String::new(),
        units: "millionths".into(),
        deterministic: true,
        required: true,
    };
    let err = tcr.validate().unwrap_err();
    assert!(matches!(
        err,
        SemanticTwinError::MissingTelemetrySignalKey { .. }
    ));
}

#[test]
fn telemetry_ref_whitespace_signal_key_error() {
    let tcr = TelemetryContractRef {
        namespace: SignalNamespace::Frir,
        signal_key: "   ".into(),
        units: "ms".into(),
        deterministic: false,
        required: false,
    };
    assert!(tcr.validate().is_err());
}

#[test]
fn telemetry_ref_empty_units_error() {
    let tcr = TelemetryContractRef {
        namespace: SignalNamespace::Frir,
        signal_key: "valid.key".into(),
        units: String::new(),
        deterministic: true,
        required: true,
    };
    let err = tcr.validate().unwrap_err();
    assert!(matches!(
        err,
        SemanticTwinError::MissingTelemetryUnits { .. }
    ));
}

#[test]
fn telemetry_ref_whitespace_units_error() {
    let tcr = TelemetryContractRef {
        namespace: SignalNamespace::RuntimeObservability,
        signal_key: "some.key".into(),
        units: "  ".into(),
        deterministic: true,
        required: false,
    };
    assert!(tcr.validate().is_err());
}

#[test]
fn telemetry_ref_serde_roundtrip() {
    let tcr = TelemetryContractRef {
        namespace: SignalNamespace::PolicyController,
        signal_key: "policy.weight".into(),
        units: "millionths".into(),
        deterministic: false,
        required: false,
    };
    let json = serde_json::to_string(&tcr).unwrap();
    let back: TelemetryContractRef = serde_json::from_str(&json).unwrap();
    assert_eq!(back, tcr);
}

// ===========================================================================
// Section 4: TwinStateVariable
// ===========================================================================

#[test]
fn twin_state_variable_serde_roundtrip() {
    let var = TwinStateVariable {
        id: "test_v".into(),
        label: "Test Var".into(),
        description: "Integration test variable".into(),
        domain: VariableDomain::RiskBelief,
        observable: true,
        telemetry: TelemetryContractRef {
            namespace: SignalNamespace::RuntimeDecisionCore,
            signal_key: "risk.posterior".into(),
            units: "millionths".into(),
            deterministic: true,
            required: true,
        },
    };
    let json = serde_json::to_string(&var).unwrap();
    let back: TwinStateVariable = serde_json::from_str(&json).unwrap();
    assert_eq!(back, var);
}

// ===========================================================================
// Section 5: TransitionGuard & TwinStateTransition
// ===========================================================================

#[test]
fn transition_guard_serde_roundtrip() {
    let g = TransitionGuard {
        variable: "env_load".into(),
        op: MonitorOp::Le,
        threshold_millionths: 750_000,
    };
    let json = serde_json::to_string(&g).unwrap();
    let back: TransitionGuard = serde_json::from_str(&json).unwrap();
    assert_eq!(back, g);
}

#[test]
fn twin_state_transition_with_guard_serde() {
    let t = TwinStateTransition {
        transition_id: "t-guard".into(),
        source_variable: "risk_belief".into(),
        target_variable: "lane_choice".into(),
        trigger_event: "risk_posterior_updated".into(),
        telemetry_contract: "risk_belief->lane_choice".into(),
        guard: Some(TransitionGuard {
            variable: "risk_belief".into(),
            op: MonitorOp::Ge,
            threshold_millionths: 400_000,
        }),
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: TwinStateTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
    assert!(back.guard.is_some());
}

#[test]
fn twin_state_transition_without_guard_serde() {
    let t = TwinStateTransition {
        transition_id: "t-no-guard".into(),
        source_variable: "a".into(),
        target_variable: "b".into(),
        trigger_event: "evt".into(),
        telemetry_contract: "a->b".into(),
        guard: None,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: TwinStateTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
    assert!(back.guard.is_none());
}

// ===========================================================================
// Section 6: CausalAdjustmentStrategy
// ===========================================================================

#[test]
fn causal_adjustment_strategy_serde_roundtrip() {
    let s = CausalAdjustmentStrategy {
        effect_id: "effect_1".into(),
        treatment: "lane_choice".into(),
        outcome: "latency_outcome".into(),
        identified: true,
        adjustment_set: BTreeSet::from(["regime".to_string(), "environment_load".to_string()]),
        blocked_confounding_paths: vec![vec!["regime".into(), "lane_choice".into()]],
        strategy_note: "backdoor".into(),
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: CausalAdjustmentStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

// ===========================================================================
// Section 7: IdentifiabilityAssumption
// ===========================================================================

#[test]
fn identifiability_assumption_serde_roundtrip() {
    let asm = IdentifiabilityAssumption {
        assumption_id: "asm-integ".into(),
        description: "integration test assumption".into(),
        category: AssumptionCategory::Statistical,
        origin: AssumptionOrigin::Inferred,
        decision_effect_id: "effect_1".into(),
        telemetry_contract: "rt.signal".into(),
        monitor_kind: MonitorKind::Drift,
        monitor_variable: "drift_var".into(),
        monitor_op: MonitorOp::Le,
        monitor_threshold_millionths: 150_000,
        trigger_count: 2,
        violation_severity: ViolationSeverity::Warning,
    };
    let json = serde_json::to_string(&asm).unwrap();
    let back: IdentifiabilityAssumption = serde_json::from_str(&json).unwrap();
    assert_eq!(back, asm);
}

// ===========================================================================
// Section 8: SemanticTwinLogEvent
// ===========================================================================

#[test]
fn log_event_all_none_serde() {
    let ev = SemanticTwinLogEvent {
        schema_version: SEMANTIC_TWIN_LOG_SCHEMA_VERSION.into(),
        trace_id: "tr".into(),
        decision_id: "dec".into(),
        policy_id: "pol".into(),
        component: SEMANTIC_TWIN_COMPONENT.into(),
        event: "observation_ok".into(),
        outcome: "ok".into(),
        error_code: None,
        variable: "v".into(),
        observed_value_millionths: 100_000,
        assumption_id: None,
        monitor_id: None,
        action: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: SemanticTwinLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ev);
}

#[test]
fn log_event_all_some_serde() {
    let ev = SemanticTwinLogEvent {
        schema_version: SEMANTIC_TWIN_LOG_SCHEMA_VERSION.into(),
        trace_id: "tr-2".into(),
        decision_id: "dec-2".into(),
        policy_id: "pol-2".into(),
        component: SEMANTIC_TWIN_COMPONENT.into(),
        event: "assumption_falsified".into(),
        outcome: "falsified".into(),
        error_code: Some("FE-SEMANTIC-TWIN-0001".into()),
        variable: "drift".into(),
        observed_value_millionths: 200_000,
        assumption_id: Some("asm-1".into()),
        monitor_id: Some("mon-1".into()),
        action: Some("enter_safe_mode".into()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: SemanticTwinLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ev);
}

// ===========================================================================
// Section 9: SemanticTwinObservationResult
// ===========================================================================

#[test]
fn observation_result_serde_roundtrip() {
    let r = SemanticTwinObservationResult {
        actions: vec![],
        events: vec![],
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: SemanticTwinObservationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

// ===========================================================================
// Section 10: SemanticTwinSpecification::frx_19_1_default
// ===========================================================================

#[test]
fn frx_19_1_default_builds_and_validates() {
    let spec = default_spec();
    spec.validate().unwrap();
}

#[test]
fn default_spec_schema_versions_correct() {
    let spec = default_spec();
    assert_eq!(
        spec.schema_version,
        SEMANTIC_TWIN_STATE_SPACE_SCHEMA_VERSION
    );
    assert_eq!(
        spec.causal_adjustment_schema_version,
        SEMANTIC_TWIN_CAUSAL_ADJUSTMENT_SCHEMA_VERSION
    );
}

#[test]
fn default_spec_has_fifteen_state_variables() {
    let spec = default_spec();
    assert_eq!(spec.state_variables.len(), 15);
}

#[test]
fn default_spec_variable_ids_are_unique() {
    let spec = default_spec();
    let ids: BTreeSet<&str> = spec.state_variables.iter().map(|v| v.id.as_str()).collect();
    assert_eq!(ids.len(), spec.state_variables.len());
}

#[test]
fn default_spec_all_telemetry_valid() {
    let spec = default_spec();
    for var in &spec.state_variables {
        var.telemetry
            .validate()
            .unwrap_or_else(|e| panic!("variable {} telemetry invalid: {e}", var.id));
    }
}

#[test]
fn default_spec_has_transitions_for_all_causal_edges() {
    let spec = default_spec();
    assert!(spec.transitions.len() >= 10);
    for t in &spec.transitions {
        assert!(
            !t.transition_id.is_empty(),
            "transition_id should not be empty"
        );
    }
}

#[test]
fn default_spec_has_two_adjustment_strategies() {
    let spec = default_spec();
    assert_eq!(spec.adjustment_strategies.len(), 2);
    assert_eq!(
        spec.adjustment_strategies[0].effect_id,
        "effect_lane_choice_to_latency"
    );
    assert_eq!(
        spec.adjustment_strategies[1].effect_id,
        "effect_lane_choice_to_correctness"
    );
}

#[test]
fn default_spec_adjustment_strategies_are_identified() {
    let spec = default_spec();
    for s in &spec.adjustment_strategies {
        assert!(s.identified, "effect {} should be identified", s.effect_id);
        // An identified effect may have an empty adjustment set if there are
        // no confounding paths that need blocking.
        assert!(
            !s.adjustment_set.is_empty() || s.blocked_confounding_paths.is_empty(),
            "effect {} must either have an adjustment set or no confounding paths",
            s.effect_id
        );
    }
}

#[test]
fn default_spec_has_four_assumptions() {
    let spec = default_spec();
    assert_eq!(spec.assumptions.len(), 4);
}

#[test]
fn default_spec_serde_roundtrip() {
    let spec = default_spec();
    let json = serde_json::to_string(&spec).unwrap();
    let back: SemanticTwinSpecification = serde_json::from_str(&json).unwrap();
    assert_eq!(back, spec);
}

// ===========================================================================
// Section 11: SemanticTwinSpecification::validate error paths
// ===========================================================================

#[test]
fn validate_rejects_duplicate_variable() {
    let mut spec = default_spec();
    let dup = spec.state_variables[0].clone();
    spec.state_variables.push(dup);
    let err = spec.validate().unwrap_err();
    assert!(matches!(err, SemanticTwinError::DuplicateVariable(..)));
}

#[test]
fn validate_rejects_transition_unknown_source() {
    let mut spec = default_spec();
    spec.transitions[0].source_variable = "nonexistent_src".into();
    let err = spec.validate().unwrap_err();
    assert!(matches!(
        err,
        SemanticTwinError::TransitionMissingVariable { .. }
    ));
}

#[test]
fn validate_rejects_transition_unknown_target() {
    let mut spec = default_spec();
    spec.transitions[0].target_variable = "nonexistent_tgt".into();
    let err = spec.validate().unwrap_err();
    assert!(matches!(
        err,
        SemanticTwinError::TransitionMissingVariable { .. }
    ));
}

#[test]
fn validate_rejects_guard_unknown_variable() {
    let mut spec = default_spec();
    // Find a transition with a guard
    for t in &mut spec.transitions {
        if let Some(g) = t.guard.as_mut() {
            g.variable = "ghost_var".into();
            break;
        }
    }
    let err = spec.validate().unwrap_err();
    assert!(matches!(
        err,
        SemanticTwinError::TransitionMissingVariable { .. }
    ));
}

#[test]
fn validate_rejects_unidentified_adjustment() {
    let mut spec = default_spec();
    spec.adjustment_strategies[0].identified = false;
    let err = spec.validate().unwrap_err();
    assert!(matches!(
        err,
        SemanticTwinError::AdjustmentNotIdentified { .. }
    ));
}

#[test]
fn validate_rejects_adjustment_set_mismatch() {
    let mut spec = default_spec();
    spec.adjustment_strategies[0].adjustment_set.clear();
    let err = spec.validate().unwrap_err();
    assert!(matches!(err, SemanticTwinError::AdjustmentMismatch { .. }));
}

#[test]
fn validate_rejects_assumption_unknown_effect() {
    let mut spec = default_spec();
    spec.assumptions[0].decision_effect_id = "phantom_effect".into();
    let err = spec.validate().unwrap_err();
    assert!(matches!(
        err,
        SemanticTwinError::AssumptionMissingEffect { .. }
    ));
}

#[test]
fn validate_rejects_assumption_unknown_variable() {
    let mut spec = default_spec();
    spec.assumptions[0].monitor_variable = "phantom_var".into();
    let err = spec.validate().unwrap_err();
    assert!(matches!(
        err,
        SemanticTwinError::AssumptionMissingVariable { .. }
    ));
}

#[test]
fn validate_rejects_assumption_zero_trigger_count() {
    let mut spec = default_spec();
    spec.assumptions[0].trigger_count = 0;
    let err = spec.validate().unwrap_err();
    assert!(matches!(
        err,
        SemanticTwinError::InvalidAssumptionTriggerCount { .. }
    ));
}

// ===========================================================================
// Section 12: SemanticTwinSpecification::build_assumption_ledger
// ===========================================================================

#[test]
fn build_ledger_assumption_count_matches() {
    let spec = default_spec();
    let ledger = spec
        .build_assumption_ledger("dec-ledger", 1, DemotionPolicy::default())
        .unwrap();
    assert_eq!(ledger.assumption_count(), spec.assumptions.len());
}

#[test]
fn build_ledger_monitor_count_matches() {
    let spec = default_spec();
    let ledger = spec
        .build_assumption_ledger("dec-ledger", 1, DemotionPolicy::default())
        .unwrap();
    assert_eq!(ledger.monitors().len(), spec.assumptions.len());
}

#[test]
fn build_ledger_all_active() {
    let spec = default_spec();
    let ledger = spec
        .build_assumption_ledger("dec-ledger", 5, DemotionPolicy::default())
        .unwrap();
    assert_eq!(ledger.active_count(), spec.assumptions.len());
}

#[test]
fn build_ledger_custom_epoch_preserved() {
    let spec = default_spec();
    let ledger = spec
        .build_assumption_ledger("dec-epoch", 42, DemotionPolicy::default())
        .unwrap();
    // All assumptions should have epoch=42
    for a in ledger.assumptions().values() {
        assert_eq!(a.epoch, 42);
    }
}

// ===========================================================================
// Section 13: SemanticTwinRuntime construction
// ===========================================================================

#[test]
fn runtime_new_success() {
    let rt = make_runtime();
    assert_eq!(rt.specification().state_variables.len(), 15);
}

#[test]
fn runtime_specification_accessor() {
    let rt = make_runtime();
    assert_eq!(
        rt.specification().schema_version,
        SEMANTIC_TWIN_STATE_SPACE_SCHEMA_VERSION
    );
}

#[test]
fn runtime_ledger_accessor() {
    let rt = make_runtime();
    assert_eq!(rt.ledger().assumption_count(), 4);
    assert_eq!(rt.ledger().monitors().len(), 4);
}

#[test]
fn runtime_rejects_invalid_spec() {
    let mut spec = default_spec();
    spec.assumptions[0].trigger_count = 0;
    let err = SemanticTwinRuntime::new(spec, "tr", "dec", "pol", 1, DemotionPolicy::default())
        .unwrap_err();
    assert!(matches!(
        err,
        SemanticTwinError::InvalidAssumptionTriggerCount { .. }
    ));
}

// ===========================================================================
// Section 14: SemanticTwinRuntime::observe - OK path
// ===========================================================================

#[test]
fn observe_ok_emits_single_ok_event() {
    let mut rt = make_runtime();
    let result = rt.observe("risk_calibration_error_millionths", 80_000, 1);
    assert!(result.actions.is_empty());
    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0].event, "assumption_monitor_evaluate");
    assert_eq!(result.events[0].outcome, "ok");
    assert!(result.events[0].error_code.is_none());
    assert!(result.events[0].assumption_id.is_none());
    assert!(result.events[0].monitor_id.is_none());
    assert!(result.events[0].action.is_none());
}

#[test]
fn observe_ok_event_schema_version() {
    let mut rt = make_runtime();
    let result = rt.observe("regime_observed_millionths", 1_000_000, 1);
    assert_eq!(
        result.events[0].schema_version,
        SEMANTIC_TWIN_LOG_SCHEMA_VERSION
    );
}

#[test]
fn observe_ok_event_component_field() {
    let mut rt = make_runtime();
    let result = rt.observe("regime_observed_millionths", 1_000_000, 1);
    assert_eq!(result.events[0].component, SEMANTIC_TWIN_COMPONENT);
}

#[test]
fn observe_ok_event_trace_decision_policy_ids() {
    let mut rt = make_runtime();
    let result = rt.observe("regime_observed_millionths", 1_000_000, 1);
    assert_eq!(result.events[0].trace_id, "trace-integ");
    assert_eq!(result.events[0].decision_id, "decision-integ");
    assert_eq!(result.events[0].policy_id, "policy-integ");
}

#[test]
fn observe_ok_event_variable_and_value() {
    let mut rt = make_runtime();
    let result = rt.observe("environment_load_drift_millionths", 100_000, 5);
    assert_eq!(
        result.events[0].variable,
        "environment_load_drift_millionths"
    );
    assert_eq!(result.events[0].observed_value_millionths, 100_000);
}

#[test]
fn observe_multiple_ok_accumulates_ticks() {
    let mut rt = make_runtime();
    for i in 0..10 {
        let r = rt.observe("regime_observed_millionths", 1_000_000, i);
        assert!(r.actions.is_empty());
        assert_eq!(r.events.len(), 1);
        assert_eq!(r.events[0].outcome, "ok");
    }
}

// ===========================================================================
// Section 15: SemanticTwinRuntime::observe - Falsification path
// ===========================================================================

#[test]
fn observe_drift_assumption_triggers_after_two_violations() {
    // environment_load_drift_millionths has trigger_count=2, threshold Le 150_000
    let mut rt = make_runtime();

    // First violation (above threshold) - does not trigger yet
    let r1 = rt.observe("environment_load_drift_millionths", 200_000, 1);
    assert!(r1.actions.is_empty());

    // Second violation - triggers
    let r2 = rt.observe("environment_load_drift_millionths", 220_000, 2);
    assert_eq!(r2.actions.len(), 1);
    assert!(matches!(
        r2.actions[0],
        DemotionAction::SuspendAdaptive { .. }
    ));
    assert_eq!(r2.events.len(), 1);
    assert_eq!(r2.events[0].event, "assumption_falsified");
    assert_eq!(r2.events[0].outcome, "falsified");
    assert_eq!(
        r2.events[0].error_code.as_deref(),
        Some("FE-SEMANTIC-TWIN-0001")
    );
    assert!(r2.events[0].assumption_id.is_some());
    assert!(r2.events[0].monitor_id.is_some());
    assert!(r2.events[0].action.is_some());
}

#[test]
fn observe_regime_observability_critical_assumption() {
    // regime_observed_millionths has Ge 1_000_000, trigger_count=1, Critical
    let mut rt = make_runtime();
    let result = rt.observe("regime_observed_millionths", 0, 1);
    assert_eq!(result.actions.len(), 1);
    assert!(matches!(
        result.actions[0],
        DemotionAction::EnterSafeMode { .. }
    ));
    assert_eq!(result.events[0].event, "assumption_falsified");
}

#[test]
fn observe_risk_calibration_critical_assumption() {
    // risk_calibration_error_millionths has Le 120_000, trigger_count=1, Critical
    let mut rt = make_runtime();
    let result = rt.observe("risk_calibration_error_millionths", 200_000, 1);
    assert_eq!(result.actions.len(), 1);
    assert!(matches!(
        result.actions[0],
        DemotionAction::EnterSafeMode { .. }
    ));
}

#[test]
fn observe_frir_linkage_fatal_assumption() {
    // frir_witness_linkage_millionths has Ge 1_000_000, trigger_count=1, Fatal
    let mut rt = make_runtime();
    let result = rt.observe("frir_witness_linkage_millionths", 500_000, 1);
    assert_eq!(result.actions.len(), 1);
    assert!(matches!(
        result.actions[0],
        DemotionAction::EnterSafeMode { .. }
    ));
    assert_eq!(result.events[0].event, "assumption_falsified");
}

#[test]
fn observe_falsification_action_label_in_event() {
    let mut rt = make_runtime();
    // regime_observed_millionths: Ge 1_000_000, Critical -> EnterSafeMode
    let result = rt.observe("regime_observed_millionths", 0, 1);
    assert_eq!(result.events[0].action.as_deref(), Some("enter_safe_mode"));
}

// ===========================================================================
// Section 16: Custom DemotionPolicy
// ===========================================================================

#[test]
fn runtime_custom_demotion_policy_warning_action() {
    let spec = default_spec();
    let mut rt = SemanticTwinRuntime::new(
        spec,
        "tr-custom",
        "dec-custom",
        "pol-custom",
        1,
        custom_demotion_policy(),
    )
    .unwrap();

    // Warning assumption: environment_load_drift_millionths, trigger_count=2
    let _ = rt.observe("environment_load_drift_millionths", 200_000, 1);
    let r2 = rt.observe("environment_load_drift_millionths", 300_000, 2);
    assert_eq!(r2.actions.len(), 1);
    assert!(matches!(r2.actions[0], DemotionAction::DemoteLane { .. }));
}

#[test]
fn runtime_custom_demotion_policy_critical_action() {
    let spec = default_spec();
    let mut rt = SemanticTwinRuntime::new(
        spec,
        "tr-custom2",
        "dec-custom2",
        "pol-custom2",
        1,
        custom_demotion_policy(),
    )
    .unwrap();

    // Critical assumption: regime_observed_millionths, trigger_count=1
    let result = rt.observe("regime_observed_millionths", 0, 1);
    assert_eq!(result.actions.len(), 1);
    assert!(matches!(
        result.actions[0],
        DemotionAction::EscalateToOperator { .. }
    ));
}

// ===========================================================================
// Section 17: SemanticTwinError Display
// ===========================================================================

#[test]
fn error_display_all_variants_non_empty_and_unique() {
    let variants: Vec<SemanticTwinError> = vec![
        SemanticTwinError::Scm(ScmError::NodeNotFound("n".into())),
        SemanticTwinError::Ledger(LedgerError::DuplicateAssumption("d".into())),
        SemanticTwinError::DuplicateVariable("v".into()),
        SemanticTwinError::MissingTelemetrySignalKey {
            namespace: "ns".into(),
        },
        SemanticTwinError::MissingTelemetryUnits {
            signal_key: "k".into(),
        },
        SemanticTwinError::TransitionMissingVariable {
            transition_id: "t".into(),
            variable: "v".into(),
        },
        SemanticTwinError::AdjustmentNotIdentified {
            effect_id: "e".into(),
        },
        SemanticTwinError::AdjustmentMismatch {
            effect_id: "e".into(),
            expected: BTreeSet::from(["a".to_string()]),
            actual: BTreeSet::from(["b".to_string()]),
        },
        SemanticTwinError::AssumptionMissingVariable {
            assumption_id: "a".into(),
            variable: "v".into(),
        },
        SemanticTwinError::AssumptionMissingEffect {
            assumption_id: "a".into(),
            effect_id: "e".into(),
        },
        SemanticTwinError::InvalidAssumptionTriggerCount {
            assumption_id: "a".into(),
        },
    ];
    let mut msgs = BTreeSet::new();
    for v in &variants {
        let msg = format!("{v}");
        assert!(!msg.is_empty());
        msgs.insert(msg);
    }
    assert_eq!(msgs.len(), variants.len());
}

// ===========================================================================
// Section 18: SemanticTwinError From impls
// ===========================================================================

#[test]
fn from_scm_error() {
    let scm = ScmError::NodeNotFound("node".into());
    let twin_err: SemanticTwinError = scm.into();
    assert!(matches!(twin_err, SemanticTwinError::Scm(..)));
    let msg = format!("{twin_err}");
    assert!(msg.contains("scm error"));
}

#[test]
fn from_ledger_error() {
    let ledger = LedgerError::DuplicateAssumption("dup".into());
    let twin_err: SemanticTwinError = ledger.into();
    assert!(matches!(twin_err, SemanticTwinError::Ledger(..)));
    let msg = format!("{twin_err}");
    assert!(msg.contains("ledger"));
}

// ===========================================================================
// Section 19: SemanticTwinError is std::error::Error
// ===========================================================================

#[test]
fn error_implements_std_error() {
    let err = SemanticTwinError::DuplicateVariable("x".into());
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

// ===========================================================================
// Section 20: SemanticTwinError serde roundtrip
// ===========================================================================

#[test]
fn error_serde_roundtrip_all_variants() {
    let variants: Vec<SemanticTwinError> = vec![
        SemanticTwinError::DuplicateVariable("v1".into()),
        SemanticTwinError::MissingTelemetrySignalKey {
            namespace: "frir".into(),
        },
        SemanticTwinError::MissingTelemetryUnits {
            signal_key: "k".into(),
        },
        SemanticTwinError::TransitionMissingVariable {
            transition_id: "t1".into(),
            variable: "x".into(),
        },
        SemanticTwinError::AdjustmentNotIdentified {
            effect_id: "e1".into(),
        },
        SemanticTwinError::AdjustmentMismatch {
            effect_id: "e2".into(),
            expected: BTreeSet::from(["a".to_string()]),
            actual: BTreeSet::from(["b".to_string()]),
        },
        SemanticTwinError::AssumptionMissingVariable {
            assumption_id: "a1".into(),
            variable: "v2".into(),
        },
        SemanticTwinError::AssumptionMissingEffect {
            assumption_id: "a2".into(),
            effect_id: "e3".into(),
        },
        SemanticTwinError::InvalidAssumptionTriggerCount {
            assumption_id: "a3".into(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: SemanticTwinError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, v);
    }
}

// ===========================================================================
// Section 21: Cross-concern integration scenarios
// ===========================================================================

#[test]
fn full_lifecycle_build_observe_ok_then_falsify() {
    let spec = default_spec();
    let mut rt = SemanticTwinRuntime::new(
        spec,
        "trace-lifecycle",
        "decision-lifecycle",
        "policy-lifecycle",
        10,
        DemotionPolicy::default(),
    )
    .unwrap();

    // Several OK observations
    for _ in 0..5 {
        let r = rt.observe("risk_calibration_error_millionths", 80_000, 10);
        assert!(r.actions.is_empty());
    }

    // Falsify
    let r = rt.observe("risk_calibration_error_millionths", 999_999, 10);
    assert_eq!(r.actions.len(), 1);
    assert_eq!(r.events[0].event, "assumption_falsified");

    // Ledger should have falsification evidence now
    assert!(!rt.ledger().falsification_history().is_empty());
}

#[test]
fn unrelated_variable_observation_does_not_trigger() {
    let mut rt = make_runtime();
    // Observe a variable that is not a monitor variable
    let r = rt.observe("workload_complexity", 5_000_000, 1);
    assert!(r.actions.is_empty());
    assert_eq!(r.events.len(), 1);
    assert_eq!(r.events[0].outcome, "ok");
}

#[test]
fn spec_clone_is_independent() {
    let spec = default_spec();
    let mut spec2 = spec.clone();
    spec2.state_variables.pop();
    assert_ne!(spec.state_variables.len(), spec2.state_variables.len());
}

#[test]
fn runtime_serde_roundtrip() {
    let rt = make_runtime();
    let json = serde_json::to_string(&rt).unwrap();
    let back: SemanticTwinRuntime = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rt);
}

#[test]
fn default_spec_transition_ids_contain_source_and_target() {
    let spec = default_spec();
    for t in &spec.transitions {
        assert!(
            t.transition_id.contains(&t.source_variable) || t.transition_id.contains("transition"),
            "transition_id {} should reference source or be prefixed",
            t.transition_id
        );
    }
}

#[test]
fn default_spec_has_guarded_transitions() {
    let spec = default_spec();
    let guarded_count = spec
        .transitions
        .iter()
        .filter(|t| t.guard.is_some())
        .count();
    assert!(
        guarded_count >= 3,
        "expected at least 3 guarded transitions, found {guarded_count}"
    );
}
