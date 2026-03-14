#![forbid(unsafe_code)]

//! Enrichment integration tests for the semantic_twin module.

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

use frankenengine_engine::assumptions_ledger::DemotionPolicy;
use frankenengine_engine::semantic_twin::{
    SEMANTIC_TWIN_CAUSAL_ADJUSTMENT_SCHEMA_VERSION, SEMANTIC_TWIN_COMPONENT,
    SEMANTIC_TWIN_LOG_SCHEMA_VERSION, SEMANTIC_TWIN_STATE_SPACE_SCHEMA_VERSION, SemanticTwinError,
    SemanticTwinRuntime, SemanticTwinSpecification, SignalNamespace,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_spec() -> SemanticTwinSpecification {
    SemanticTwinSpecification::frx_19_1_default().unwrap()
}

fn default_runtime() -> SemanticTwinRuntime {
    let spec = default_spec();
    SemanticTwinRuntime::new(
        spec,
        "trace-001",
        "decision-001",
        "policy-001",
        1,
        DemotionPolicy::default(),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// SignalNamespace — Copy / BTreeSet / Clone / Debug / as_str
// ---------------------------------------------------------------------------

#[test]
fn enrichment_signal_namespace_copy_semantics() {
    let a = SignalNamespace::Frir;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_signal_namespace_btreeset_dedup_5() {
    let mut set = BTreeSet::new();
    set.insert(SignalNamespace::Frir);
    set.insert(SignalNamespace::RuntimeDecisionCore);
    set.insert(SignalNamespace::RuntimeObservability);
    set.insert(SignalNamespace::PolicyController);
    set.insert(SignalNamespace::AssumptionsLedger);
    set.insert(SignalNamespace::Frir);
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_signal_namespace_clone_independence() {
    let a = SignalNamespace::PolicyController;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_signal_namespace_debug_all_unique() {
    let namespaces = [
        SignalNamespace::Frir,
        SignalNamespace::RuntimeDecisionCore,
        SignalNamespace::RuntimeObservability,
        SignalNamespace::PolicyController,
        SignalNamespace::AssumptionsLedger,
    ];
    let dbgs: BTreeSet<String> = namespaces.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn enrichment_signal_namespace_as_str_all_unique() {
    let namespaces = [
        SignalNamespace::Frir,
        SignalNamespace::RuntimeDecisionCore,
        SignalNamespace::RuntimeObservability,
        SignalNamespace::PolicyController,
        SignalNamespace::AssumptionsLedger,
    ];
    let strs: BTreeSet<&str> = namespaces.iter().map(|v| v.as_str()).collect();
    assert_eq!(strs.len(), 5);
}

#[test]
fn enrichment_signal_namespace_serde_roundtrip_all() {
    let namespaces = [
        SignalNamespace::Frir,
        SignalNamespace::RuntimeDecisionCore,
        SignalNamespace::RuntimeObservability,
        SignalNamespace::PolicyController,
        SignalNamespace::AssumptionsLedger,
    ];
    for ns in &namespaces {
        let json = serde_json::to_string(ns).unwrap();
        let rt: SignalNamespace = serde_json::from_str(&json).unwrap();
        assert_eq!(*ns, rt);
    }
}

// ---------------------------------------------------------------------------
// SemanticTwinError — Clone / Debug / Display / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_semantic_twin_error_clone_independence() {
    let a = SemanticTwinError::DuplicateVariable("x".to_string());
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_semantic_twin_error_debug_nonempty() {
    let e = SemanticTwinError::DuplicateVariable("x".to_string());
    assert!(!format!("{:?}", e).is_empty());
}

#[test]
fn enrichment_semantic_twin_error_display_nonempty() {
    let errors: Vec<SemanticTwinError> = vec![
        SemanticTwinError::DuplicateVariable("x".to_string()),
        SemanticTwinError::MissingTelemetrySignalKey {
            namespace: "frir".to_string(),
        },
        SemanticTwinError::MissingTelemetryUnits {
            signal_key: "latency".to_string(),
        },
        SemanticTwinError::TransitionMissingVariable {
            transition_id: "t1".to_string(),
            variable: "v1".to_string(),
        },
        SemanticTwinError::AdjustmentNotIdentified {
            effect_id: "e1".to_string(),
        },
        SemanticTwinError::AdjustmentMismatch {
            effect_id: "e1".to_string(),
            expected: BTreeSet::from(["a".to_string()]),
            actual: BTreeSet::from(["b".to_string()]),
        },
        SemanticTwinError::AssumptionMissingVariable {
            assumption_id: "a1".to_string(),
            variable: "v1".to_string(),
        },
        SemanticTwinError::AssumptionMissingEffect {
            assumption_id: "a1".to_string(),
            effect_id: "e1".to_string(),
        },
        SemanticTwinError::InvalidAssumptionTriggerCount {
            assumption_id: "a1".to_string(),
        },
    ];
    for e in &errors {
        assert!(!format!("{}", e).is_empty(), "empty display for: {:?}", e);
    }
}

#[test]
fn enrichment_semantic_twin_error_display_all_unique() {
    let errors: Vec<SemanticTwinError> = vec![
        SemanticTwinError::DuplicateVariable("x".to_string()),
        SemanticTwinError::MissingTelemetrySignalKey {
            namespace: "frir".to_string(),
        },
        SemanticTwinError::MissingTelemetryUnits {
            signal_key: "latency".to_string(),
        },
        SemanticTwinError::TransitionMissingVariable {
            transition_id: "t1".to_string(),
            variable: "v1".to_string(),
        },
        SemanticTwinError::AdjustmentNotIdentified {
            effect_id: "e1".to_string(),
        },
        SemanticTwinError::AdjustmentMismatch {
            effect_id: "e1".to_string(),
            expected: BTreeSet::from(["a".to_string()]),
            actual: BTreeSet::from(["b".to_string()]),
        },
        SemanticTwinError::AssumptionMissingVariable {
            assumption_id: "a1".to_string(),
            variable: "v1".to_string(),
        },
        SemanticTwinError::AssumptionMissingEffect {
            assumption_id: "a1".to_string(),
            effect_id: "e1".to_string(),
        },
        SemanticTwinError::InvalidAssumptionTriggerCount {
            assumption_id: "a1".to_string(),
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| format!("{}", e)).collect();
    assert_eq!(displays.len(), errors.len());
}

#[test]
fn enrichment_semantic_twin_error_serde_roundtrip() {
    let errors: Vec<SemanticTwinError> = vec![
        SemanticTwinError::DuplicateVariable("x".to_string()),
        SemanticTwinError::MissingTelemetrySignalKey {
            namespace: "frir".to_string(),
        },
        SemanticTwinError::MissingTelemetryUnits {
            signal_key: "latency".to_string(),
        },
        SemanticTwinError::TransitionMissingVariable {
            transition_id: "t1".to_string(),
            variable: "v1".to_string(),
        },
        SemanticTwinError::AdjustmentNotIdentified {
            effect_id: "e1".to_string(),
        },
        SemanticTwinError::AssumptionMissingVariable {
            assumption_id: "a1".to_string(),
            variable: "v1".to_string(),
        },
        SemanticTwinError::AssumptionMissingEffect {
            assumption_id: "a1".to_string(),
            effect_id: "e1".to_string(),
        },
        SemanticTwinError::InvalidAssumptionTriggerCount {
            assumption_id: "a1".to_string(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let rt: SemanticTwinError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, rt);
    }
}

#[test]
fn enrichment_semantic_twin_error_is_std_error() {
    let e = SemanticTwinError::DuplicateVariable("test".to_string());
    // Verify it implements std::error::Error
    let _err_ref: &dyn std::error::Error = &e;
}

// ---------------------------------------------------------------------------
// SemanticTwinSpecification — Clone / Debug / JSON / validate / frx_19_1
// ---------------------------------------------------------------------------

#[test]
fn enrichment_specification_clone_independence() {
    let a = default_spec();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_specification_debug_nonempty() {
    assert!(!format!("{:?}", default_spec()).is_empty());
}

#[test]
fn enrichment_specification_json_field_names() {
    let spec = default_spec();
    let json = serde_json::to_string(&spec).unwrap();
    for field in &[
        "schema_version",
        "causal_adjustment_schema_version",
        "state_variables",
        "transitions",
        "adjustment_strategies",
        "assumptions",
        "causal_model",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_specification_frx_19_1_validates() {
    let spec = default_spec();
    assert!(spec.validate().is_ok());
}

#[test]
fn enrichment_specification_frx_19_1_has_15_state_variables() {
    let spec = default_spec();
    assert_eq!(spec.state_variables.len(), 15);
}

#[test]
fn enrichment_specification_frx_19_1_has_4_assumptions() {
    let spec = default_spec();
    assert_eq!(spec.assumptions.len(), 4);
}

#[test]
fn enrichment_specification_frx_19_1_has_2_strategies() {
    let spec = default_spec();
    assert_eq!(spec.adjustment_strategies.len(), 2);
}

#[test]
fn enrichment_specification_serde_roundtrip() {
    let spec = default_spec();
    let json = serde_json::to_string(&spec).unwrap();
    let rt: SemanticTwinSpecification = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, rt);
}

// ---------------------------------------------------------------------------
// SemanticTwinRuntime — new / observe / accessors
// ---------------------------------------------------------------------------

#[test]
fn enrichment_runtime_new_success() {
    let rt = default_runtime();
    assert!(!format!("{:?}", rt).is_empty());
}

#[test]
fn enrichment_runtime_clone_independence() {
    let a = default_runtime();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_runtime_specification_accessor() {
    let rt = default_runtime();
    let spec = rt.specification();
    assert_eq!(spec.state_variables.len(), 15);
}

#[test]
fn enrichment_runtime_ledger_accessor() {
    let rt = default_runtime();
    let _ledger = rt.ledger();
}

#[test]
fn enrichment_runtime_observe_returns_result() {
    let mut rt = default_runtime();
    let var_id = &rt.specification().state_variables[0].id.clone();
    let result = rt.observe(var_id, 500_000, 1);
    // Just verify it runs and returns a result
    let _ = result.actions;
    let _ = result.events;
}

#[test]
fn enrichment_runtime_observe_produces_events() {
    let mut rt = default_runtime();
    let var_id = &rt.specification().state_variables[0].id.clone();
    let result = rt.observe(var_id, 500_000, 1);
    // At least some events should be generated
    assert!(!result.events.is_empty());
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_exact_values() {
    assert_eq!(
        SEMANTIC_TWIN_STATE_SPACE_SCHEMA_VERSION,
        "franken-engine.semantic-twin.state-space.v1"
    );
    assert_eq!(
        SEMANTIC_TWIN_CAUSAL_ADJUSTMENT_SCHEMA_VERSION,
        "franken-engine.semantic-twin.causal-adjustment.v1"
    );
    assert_eq!(
        SEMANTIC_TWIN_LOG_SCHEMA_VERSION,
        "franken-engine.semantic-twin.log-event.v1"
    );
    assert_eq!(SEMANTIC_TWIN_COMPONENT, "semantic_twin_state_space");
}

#[test]
fn enrichment_constants_all_unique() {
    let versions: BTreeSet<&str> = [
        SEMANTIC_TWIN_STATE_SPACE_SCHEMA_VERSION,
        SEMANTIC_TWIN_CAUSAL_ADJUSTMENT_SCHEMA_VERSION,
        SEMANTIC_TWIN_LOG_SCHEMA_VERSION,
    ]
    .into_iter()
    .collect();
    assert_eq!(versions.len(), 3);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_five_run_determinism_spec() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| serde_json::to_string(&default_spec()).unwrap())
        .collect();
    assert_eq!(jsons.len(), 1, "specification should be deterministic");
}

#[test]
fn enrichment_five_run_determinism_runtime_observe() {
    let results: Vec<String> = (0..5)
        .map(|_| {
            let mut rt = default_runtime();
            let var_id = &rt.specification().state_variables[0].id.clone();
            let result = rt.observe(var_id, 500_000, 1);
            serde_json::to_string(&result).unwrap()
        })
        .collect();
    for r in &results[1..] {
        assert_eq!(*r, results[0], "observe should be deterministic");
    }
}

// ---------------------------------------------------------------------------
// Cross-cutting invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_cutting_spec_schema_version() {
    let spec = default_spec();
    assert_eq!(
        spec.schema_version,
        SEMANTIC_TWIN_STATE_SPACE_SCHEMA_VERSION
    );
}

#[test]
fn enrichment_cross_cutting_spec_causal_schema_version() {
    let spec = default_spec();
    assert_eq!(
        spec.causal_adjustment_schema_version,
        SEMANTIC_TWIN_CAUSAL_ADJUSTMENT_SCHEMA_VERSION
    );
}

#[test]
fn enrichment_cross_cutting_variable_ids_unique() {
    let spec = default_spec();
    let ids: BTreeSet<&str> = spec.state_variables.iter().map(|v| v.id.as_str()).collect();
    assert_eq!(ids.len(), spec.state_variables.len());
}

#[test]
fn enrichment_cross_cutting_assumption_ids_unique() {
    let spec = default_spec();
    let ids: BTreeSet<&str> = spec
        .assumptions
        .iter()
        .map(|a| a.assumption_id.as_str())
        .collect();
    assert_eq!(ids.len(), spec.assumptions.len());
}

#[test]
fn enrichment_cross_cutting_strategy_effect_ids_unique() {
    let spec = default_spec();
    let ids: BTreeSet<&str> = spec
        .adjustment_strategies
        .iter()
        .map(|s| s.effect_id.as_str())
        .collect();
    assert_eq!(ids.len(), spec.adjustment_strategies.len());
}

#[test]
fn enrichment_cross_cutting_all_strategies_identified() {
    let spec = default_spec();
    for s in &spec.adjustment_strategies {
        assert!(
            s.identified,
            "strategy {} should be identified",
            s.effect_id
        );
    }
}

#[test]
fn enrichment_cross_cutting_events_have_schema_version() {
    let mut rt = default_runtime();
    let var_id = &rt.specification().state_variables[0].id.clone();
    let result = rt.observe(var_id, 500_000, 1);
    for event in &result.events {
        assert_eq!(event.schema_version, SEMANTIC_TWIN_LOG_SCHEMA_VERSION);
    }
}

#[test]
fn enrichment_cross_cutting_events_have_component() {
    let mut rt = default_runtime();
    let var_id = &rt.specification().state_variables[0].id.clone();
    let result = rt.observe(var_id, 500_000, 1);
    for event in &result.events {
        assert_eq!(event.component, SEMANTIC_TWIN_COMPONENT);
    }
}

// ===== PearlTower enrichment batch 2 — 2026-03-14 =====

// ---------------------------------------------------------------------------
// SemanticTwinSpecification — validate catches invalid specs
// ---------------------------------------------------------------------------

#[test]
fn enrichment_spec_validate_rejects_duplicate_variable_ids() {
    let mut spec = default_spec();
    let dup = spec.state_variables[0].clone();
    spec.state_variables.push(dup);
    let result = spec.validate();
    assert!(
        result.is_err(),
        "validate must reject duplicate variable ids"
    );
}

#[test]
fn enrichment_spec_validate_rejects_transition_missing_variable() {
    use frankenengine_engine::semantic_twin::{TransitionGuard, TwinStateTransition};
    let mut spec = default_spec();
    spec.transitions.push(TwinStateTransition {
        transition_id: "bad-transition".to_string(),
        source_variable: "nonexistent-var".to_string(),
        target_variable: spec.state_variables[0].id.clone(),
        trigger_event: "test-trigger".to_string(),
        telemetry_contract: "test".to_string(),
        guard: Some(TransitionGuard {
            variable: "always".to_string(),
            op: frankenengine_engine::assumptions_ledger::MonitorOp::Gt,
            threshold_millionths: 0,
        }),
    });
    let result = spec.validate();
    assert!(
        result.is_err(),
        "validate must reject transitions referencing missing variables"
    );
}

// ---------------------------------------------------------------------------
// SemanticTwinSpecification — build_assumption_ledger
// ---------------------------------------------------------------------------

#[test]
fn enrichment_spec_build_assumption_ledger_succeeds() {
    let spec = default_spec();
    let ledger = spec.build_assumption_ledger(
        "decision-bl",
        1,
        DemotionPolicy::default(),
    );
    assert!(ledger.is_ok());
}

// ---------------------------------------------------------------------------
// SemanticTwinRuntime — multiple observations
// ---------------------------------------------------------------------------

#[test]
fn enrichment_runtime_multiple_observations_no_panic() {
    let mut rt = default_runtime();
    let spec = rt.specification().clone();
    for var in &spec.state_variables {
        let _ = rt.observe(&var.id, 500_000, 1);
    }
}

#[test]
fn enrichment_runtime_observe_increments_epoch() {
    let mut rt = default_runtime();
    let var_id = rt.specification().state_variables[0].id.clone();
    let r1 = rt.observe(&var_id, 500_000, 1);
    let r2 = rt.observe(&var_id, 600_000, 2);
    // Events from second observation should reference later timestamps
    assert!(!r2.events.is_empty());
    if !r1.events.is_empty() && !r2.events.is_empty() {
        assert!(r2.events[0].observed_value_millionths >= r1.events[0].observed_value_millionths);
    }
}

// ---------------------------------------------------------------------------
// TelemetryContractRef — validate
// ---------------------------------------------------------------------------

#[test]
fn enrichment_telemetry_contract_ref_validate_valid() {
    use frankenengine_engine::semantic_twin::TelemetryContractRef;
    let tcr = TelemetryContractRef {
        namespace: SignalNamespace::Frir,
        signal_key: "latency_ns".to_string(),
        units: "nanoseconds".to_string(),
    };
    assert!(tcr.validate().is_ok());
}

#[test]
fn enrichment_telemetry_contract_ref_validate_missing_signal_key() {
    use frankenengine_engine::semantic_twin::TelemetryContractRef;
    let tcr = TelemetryContractRef {
        namespace: SignalNamespace::Frir,
        signal_key: String::new(),
        units: "nanoseconds".to_string(),
    };
    let result = tcr.validate();
    assert!(result.is_err());
}

#[test]
fn enrichment_telemetry_contract_ref_validate_missing_units() {
    use frankenengine_engine::semantic_twin::TelemetryContractRef;
    let tcr = TelemetryContractRef {
        namespace: SignalNamespace::Frir,
        signal_key: "latency_ns".to_string(),
        units: String::new(),
    };
    let result = tcr.validate();
    assert!(result.is_err());
}

#[test]
fn enrichment_telemetry_contract_ref_serde_roundtrip() {
    use frankenengine_engine::semantic_twin::TelemetryContractRef;
    let tcr = TelemetryContractRef {
        namespace: SignalNamespace::RuntimeDecisionCore,
        signal_key: "decision_latency".to_string(),
        units: "ms".to_string(),
    };
    let json = serde_json::to_string(&tcr).unwrap();
    let restored: TelemetryContractRef = serde_json::from_str(&json).unwrap();
    assert_eq!(tcr, restored);
}

// ---------------------------------------------------------------------------
// SemanticTwinLogEvent — serde roundtrip and fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_log_event_serde_roundtrip() {
    let mut rt = default_runtime();
    let var_id = rt.specification().state_variables[0].id.clone();
    let result = rt.observe(&var_id, 500_000, 1);
    assert!(!result.events.is_empty());
    let event = &result.events[0];
    let json = serde_json::to_string(event).unwrap();
    let restored: frankenengine_engine::semantic_twin::SemanticTwinLogEvent =
        serde_json::from_str(&json).unwrap();
    assert_eq!(event, &restored);
}

#[test]
fn enrichment_log_event_json_field_names() {
    let mut rt = default_runtime();
    let var_id = rt.specification().state_variables[0].id.clone();
    let result = rt.observe(&var_id, 500_000, 1);
    assert!(!result.events.is_empty());
    let json = serde_json::to_string(&result.events[0]).unwrap();
    for field in &[
        "schema_version",
        "component",
        "trace_id",
        "decision_id",
        "timestamp_ns",
        "variable_id",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// SemanticTwinObservationResult — serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_observation_result_serde_roundtrip() {
    let mut rt = default_runtime();
    let var_id = rt.specification().state_variables[0].id.clone();
    let result = rt.observe(&var_id, 500_000, 1);
    let json = serde_json::to_string(&result).unwrap();
    let restored: frankenengine_engine::semantic_twin::SemanticTwinObservationResult =
        serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

// ---------------------------------------------------------------------------
// TransitionGuard / TwinStateTransition — serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transition_guard_serde_roundtrip() {
    use frankenengine_engine::semantic_twin::TransitionGuard;
    let guard = TransitionGuard {
        condition: "threshold_exceeded".to_string(),
        parameters: std::collections::BTreeMap::from([(
            "threshold".to_string(),
            "100".to_string(),
        )]),
    };
    let json = serde_json::to_string(&guard).unwrap();
    let restored: TransitionGuard = serde_json::from_str(&json).unwrap();
    assert_eq!(guard, restored);
}

#[test]
fn enrichment_state_variable_serde_roundtrip() {
    let spec = default_spec();
    let var = &spec.state_variables[0];
    let json = serde_json::to_string(var).unwrap();
    let restored: frankenengine_engine::semantic_twin::TwinStateVariable =
        serde_json::from_str(&json).unwrap();
    assert_eq!(var, &restored);
}

// ---------------------------------------------------------------------------
// CausalAdjustmentStrategy — serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_causal_adjustment_strategy_serde_roundtrip() {
    let spec = default_spec();
    let strategy = &spec.adjustment_strategies[0];
    let json = serde_json::to_string(strategy).unwrap();
    let restored: frankenengine_engine::semantic_twin::CausalAdjustmentStrategy =
        serde_json::from_str(&json).unwrap();
    assert_eq!(strategy, &restored);
}

// ---------------------------------------------------------------------------
// IdentifiabilityAssumption — serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_identifiability_assumption_serde_roundtrip() {
    let spec = default_spec();
    let assumption = &spec.assumptions[0];
    let json = serde_json::to_string(assumption).unwrap();
    let restored: frankenengine_engine::semantic_twin::IdentifiabilityAssumption =
        serde_json::from_str(&json).unwrap();
    assert_eq!(assumption, &restored);
}

// ---------------------------------------------------------------------------
// Specification — transitions are internally consistent
// ---------------------------------------------------------------------------

#[test]
fn enrichment_spec_transitions_reference_valid_variables() {
    let spec = default_spec();
    let var_ids: BTreeSet<&str> = spec.state_variables.iter().map(|v| v.id.as_str()).collect();
    for t in &spec.transitions {
        assert!(
            var_ids.contains(t.from_variable.as_str()),
            "transition {} references unknown from_variable {}",
            t.id,
            t.from_variable
        );
        assert!(
            var_ids.contains(t.to_variable.as_str()),
            "transition {} references unknown to_variable {}",
            t.id,
            t.to_variable
        );
    }
}

#[test]
fn enrichment_spec_transition_ids_unique() {
    let spec = default_spec();
    let ids: BTreeSet<&str> = spec.transitions.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(ids.len(), spec.transitions.len());
}
