#![forbid(unsafe_code)]
//! Integration tests for the `semantic_twin_state_space` module.
//!
//! Exercises TwinStateDomain, TwinSignalSource, TwinPhase, TwinTransitionTrigger,
//! TwinStateSnapshot, TwinSpecError, SemanticTwinSpecification (lane_decision_default,
//! validate, validate_snapshot, to_assumption_ledger, deterministic_digest), and serde.

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

use frankenengine_engine::semantic_twin_state_space::{
    SEMANTIC_TWIN_COMPONENT, SEMANTIC_TWIN_SCHEMA_VERSION, SemanticTwinSpecification,
    TwinFalsificationHook, TwinMeasurementContract, TwinPhase, TwinSignalSource, TwinSpecError,
    TwinStateDomain, TwinStateSnapshot, TwinStateVariableSpec, TwinTransitionSpec,
    TwinTransitionTrigger,
};

use frankenengine_engine::assumptions_ledger::{MonitorKind, MonitorOp};

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn schema_version_nonempty() {
    assert!(!SEMANTIC_TWIN_SCHEMA_VERSION.is_empty());
    assert!(SEMANTIC_TWIN_SCHEMA_VERSION.contains("semantic-twin"));
}

#[test]
fn component_nonempty() {
    assert!(!SEMANTIC_TWIN_COMPONENT.is_empty());
}

// ===========================================================================
// 2. Enums
// ===========================================================================

#[test]
fn twin_state_domain_serde() {
    for d in [
        TwinStateDomain::Workload,
        TwinStateDomain::Risk,
        TwinStateDomain::Policy,
        TwinStateDomain::Lane,
        TwinStateDomain::Outcome,
        TwinStateDomain::Regime,
        TwinStateDomain::Resource,
        TwinStateDomain::Replay,
        TwinStateDomain::Calibration,
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let back: TwinStateDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }
}

#[test]
fn twin_signal_source_serde() {
    for s in [
        TwinSignalSource::RuntimeDecisionCore,
        TwinSignalSource::RuntimeDecisionTheory,
        TwinSignalSource::CausalReplay,
        TwinSignalSource::FrirIr2,
        TwinSignalSource::FrirIr3,
        TwinSignalSource::ObservabilityChannel,
        TwinSignalSource::EvidenceLedger,
        TwinSignalSource::OperatorInput,
        TwinSignalSource::EnvironmentTelemetry,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: TwinSignalSource = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn twin_phase_serde() {
    for p in [
        TwinPhase::ObserveWorkload,
        TwinPhase::UpdateRiskBelief,
        TwinPhase::SelectLane,
        TwinPhase::ExecuteLane,
        TwinPhase::RecordOutcome,
        TwinPhase::EvaluateFallback,
        TwinPhase::SafeMode,
    ] {
        let json = serde_json::to_string(&p).unwrap();
        let back: TwinPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }
}

#[test]
fn twin_transition_trigger_serde() {
    for t in [
        TwinTransitionTrigger::ObservationCommitted,
        TwinTransitionTrigger::PosteriorUpdated,
        TwinTransitionTrigger::DecisionCommitted,
        TwinTransitionTrigger::ExecutionCompleted,
        TwinTransitionTrigger::OutcomeRecorded,
        TwinTransitionTrigger::GuardrailTriggered,
        TwinTransitionTrigger::OperatorOverride,
        TwinTransitionTrigger::ReplayCounterfactual,
    ] {
        let json = serde_json::to_string(&t).unwrap();
        let back: TwinTransitionTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }
}

// ===========================================================================
// 3. TwinStateSnapshot
// ===========================================================================

#[test]
fn snapshot_new() {
    let snap = TwinStateSnapshot::new("trace-1", "dec-1", "pol-1", 7, 42);
    assert_eq!(snap.trace_id, "trace-1");
    assert_eq!(snap.decision_id, "dec-1");
    assert_eq!(snap.policy_id, "pol-1");
    assert_eq!(snap.epoch, 7);
    assert_eq!(snap.tick, 42);
    assert!(snap.values_millionths.is_empty());
}

#[test]
fn snapshot_upsert_value() {
    let mut snap = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    snap.upsert_value("var_a", 500_000);
    snap.upsert_value("var_b", 1_000_000);
    assert_eq!(snap.values_millionths.len(), 2);
    assert_eq!(*snap.values_millionths.get("var_a").unwrap(), 500_000);
}

#[test]
fn snapshot_upsert_overwrites() {
    let mut snap = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    snap.upsert_value("var_a", 100);
    snap.upsert_value("var_a", 200);
    assert_eq!(*snap.values_millionths.get("var_a").unwrap(), 200);
}

#[test]
fn snapshot_deterministic_digest() {
    let mut s1 = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    s1.upsert_value("x", 42);
    let mut s2 = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    s2.upsert_value("x", 42);
    assert_eq!(s1.deterministic_digest(), s2.deterministic_digest());
}

#[test]
fn snapshot_digest_varies() {
    let mut s1 = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    s1.upsert_value("x", 42);
    let mut s2 = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    s2.upsert_value("x", 43);
    assert_ne!(s1.deterministic_digest(), s2.deterministic_digest());
}

#[test]
fn snapshot_serde() {
    let mut snap = TwinStateSnapshot::new("trace", "dec", "pol", 5, 10);
    snap.upsert_value("workload_complexity", 750_000);
    let json = serde_json::to_string(&snap).unwrap();
    let back: TwinStateSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(back, snap);
}

// ===========================================================================
// 4. TwinSpecError
// ===========================================================================

#[test]
fn spec_error_display_variants() {
    let err = TwinSpecError::DuplicateVariable("x".into());
    assert!(err.to_string().contains("duplicate variable"));

    let err = TwinSpecError::UnknownVariable("y".into());
    assert!(err.to_string().contains("unknown variable"));

    let err = TwinSpecError::InvalidSchemaVersion("bad".into());
    assert!(err.to_string().contains("invalid semantic twin schema"));

    let err = TwinSpecError::DuplicateTransition("t".into());
    assert!(err.to_string().contains("duplicate transition"));

    let err = TwinSpecError::DuplicateAssumption("a".into());
    assert!(err.to_string().contains("duplicate assumption"));

    let err = TwinSpecError::DuplicateMonitor("m".into());
    assert!(err.to_string().contains("duplicate monitor"));

    let err = TwinSpecError::InvalidMonitorTriggerCount {
        monitor_id: "m".into(),
    };
    assert!(err.to_string().contains("invalid trigger_count"));

    let err = TwinSpecError::InvalidMeasurementRange {
        variable_id: "v".into(),
    };
    assert!(err.to_string().contains("invalid measurement range"));

    let err = TwinSpecError::MissingTreatmentVariable("t".into());
    assert!(err.to_string().contains("missing treatment variable"));

    let err = TwinSpecError::MissingOutcomeVariable("o".into());
    assert!(err.to_string().contains("missing outcome variable"));

    let err = TwinSpecError::MissingSnapshotValue {
        variable_id: "v".into(),
    };
    assert!(err.to_string().contains("missing required snapshot"));

    let err = TwinSpecError::OutOfRangeSnapshotValue {
        variable_id: "v".into(),
        value: 999,
        min: Some(0),
        max: Some(100),
    };
    assert!(err.to_string().contains("out of range"));
}

#[test]
fn spec_error_serde() {
    let err = TwinSpecError::DuplicateVariable("x".into());
    let json = serde_json::to_string(&err).unwrap();
    let back: TwinSpecError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

// ===========================================================================
// 5. Struct serde
// ===========================================================================

#[test]
fn variable_spec_serde() {
    let v = TwinStateVariableSpec {
        id: "workload".into(),
        label: "Workload".into(),
        domain: TwinStateDomain::Workload,
        source: TwinSignalSource::RuntimeDecisionTheory,
        observable: true,
        unit: "millionths".into(),
        description: "test".into(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: TwinStateVariableSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn transition_spec_serde() {
    let t = TwinTransitionSpec {
        id: "t-1".into(),
        from_phase: TwinPhase::ObserveWorkload,
        to_phase: TwinPhase::UpdateRiskBelief,
        trigger: TwinTransitionTrigger::ObservationCommitted,
        deterministic_priority: 10,
        guard_assumptions: vec!["a-1".into()],
        description: "test transition".into(),
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: TwinTransitionSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

#[test]
fn measurement_contract_serde() {
    let mc = TwinMeasurementContract {
        variable_id: "risk_belief".into(),
        required: true,
        min_value_millionths: Some(0),
        max_value_millionths: Some(1_000_000),
        max_staleness_ticks: 1,
        evidence_component: "runtime_decision_core".into(),
    };
    let json = serde_json::to_string(&mc).unwrap();
    let back: TwinMeasurementContract = serde_json::from_str(&json).unwrap();
    assert_eq!(back, mc);
}

#[test]
fn falsification_hook_serde() {
    let h = TwinFalsificationHook {
        monitor_id: "mon-1".into(),
        assumption_id: "a-1".into(),
        variable_id: "regime".into(),
        kind: MonitorKind::Invariant,
        op: MonitorOp::Ge,
        threshold_millionths: 0,
        trigger_count: 1,
    };
    let json = serde_json::to_string(&h).unwrap();
    let back: TwinFalsificationHook = serde_json::from_str(&json).unwrap();
    assert_eq!(back, h);
}

// ===========================================================================
// 6. SemanticTwinSpecification — lane_decision_default
// ===========================================================================

#[test]
fn lane_decision_default_constructs() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert_eq!(spec.schema_version, SEMANTIC_TWIN_SCHEMA_VERSION);
    assert_eq!(spec.component, SEMANTIC_TWIN_COMPONENT);
}

#[test]
fn lane_decision_default_validates() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    spec.validate().unwrap();
}

#[test]
fn lane_decision_default_has_states() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert_eq!(spec.states.len(), 7);
    assert!(spec.states.contains(&TwinPhase::ObserveWorkload));
    assert!(spec.states.contains(&TwinPhase::SafeMode));
}

#[test]
fn lane_decision_default_treatment_outcome() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert_eq!(spec.treatment_variable, "lane_choice");
    assert_eq!(spec.outcome_variable, "latency_outcome");
}

#[test]
fn lane_decision_default_has_variables() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert!(!spec.variables.is_empty());
    let ids: Vec<&str> = spec.variables.iter().map(|v| v.id.as_str()).collect();
    assert!(ids.contains(&"workload_complexity"));
    assert!(ids.contains(&"lane_choice"));
    assert!(ids.contains(&"latency_outcome"));
    assert!(ids.contains(&"regime"));
}

#[test]
fn lane_decision_default_has_transitions() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert!(!spec.transitions.is_empty());
    // Transitions cover the full lifecycle
    let from_phases: Vec<TwinPhase> = spec.transitions.iter().map(|t| t.from_phase).collect();
    assert!(from_phases.contains(&TwinPhase::ObserveWorkload));
    assert!(from_phases.contains(&TwinPhase::EvaluateFallback));
}

#[test]
fn lane_decision_default_has_measurement_contracts() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert!(!spec.measurement_contracts.is_empty());
    let required_ids: Vec<&str> = spec
        .measurement_contracts
        .iter()
        .filter(|c| c.required)
        .map(|c| c.variable_id.as_str())
        .collect();
    assert!(required_ids.contains(&"workload_complexity"));
    assert!(required_ids.contains(&"risk_belief"));
}

#[test]
fn lane_decision_default_has_assumptions() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert!(!spec.assumptions.is_empty());
    let ids: Vec<&str> = spec.assumptions.iter().map(|a| a.id.as_str()).collect();
    assert!(ids.contains(&"assumption_regime_observable"));
    assert!(ids.contains(&"assumption_nondeterminism_log_complete"));
}

#[test]
fn lane_decision_default_has_falsification_hooks() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert!(!spec.falsification_hooks.is_empty());
    let monitor_ids: Vec<&str> = spec
        .falsification_hooks
        .iter()
        .map(|h| h.monitor_id.as_str())
        .collect();
    assert!(monitor_ids.contains(&"monitor_replay_completeness"));
}

#[test]
fn lane_decision_default_has_adjustment_set() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert!(!spec.recommended_adjustment_set.is_empty());
    assert!(spec.recommended_adjustment_set.contains("regime"));
}

// ===========================================================================
// 7. SemanticTwinSpecification — deterministic_digest
// ===========================================================================

#[test]
fn deterministic_digest_stable() {
    let a = SemanticTwinSpecification::lane_decision_default().unwrap();
    let b = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert_eq!(a.deterministic_digest(), b.deterministic_digest());
}

#[test]
fn deterministic_digest_starts_with_sha256() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert!(spec.deterministic_digest().starts_with("sha256:"));
}

// ===========================================================================
// 8. SemanticTwinSpecification — validate error paths
// ===========================================================================

#[test]
fn validate_wrong_schema_version() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    spec.schema_version = "wrong".into();
    let err = spec.validate().unwrap_err();
    assert!(matches!(err, TwinSpecError::InvalidSchemaVersion(_)));
}

#[test]
fn validate_duplicate_variable() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let dup = spec.variables[0].clone();
    spec.variables.push(dup);
    let err = spec.validate().unwrap_err();
    assert!(matches!(err, TwinSpecError::DuplicateVariable(_)));
}

#[test]
fn validate_missing_treatment_variable() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    spec.treatment_variable = "nonexistent".into();
    let err = spec.validate().unwrap_err();
    assert!(matches!(err, TwinSpecError::MissingTreatmentVariable(_)));
}

#[test]
fn validate_missing_outcome_variable() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    spec.outcome_variable = "nonexistent".into();
    let err = spec.validate().unwrap_err();
    assert!(matches!(err, TwinSpecError::MissingOutcomeVariable(_)));
}

#[test]
fn validate_duplicate_transition() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let dup = spec.transitions[0].clone();
    spec.transitions.push(dup);
    let err = spec.validate().unwrap_err();
    assert!(matches!(err, TwinSpecError::DuplicateTransition(_)));
}

#[test]
fn validate_invalid_measurement_range() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    spec.measurement_contracts.push(TwinMeasurementContract {
        variable_id: "risk_belief".into(),
        required: false,
        min_value_millionths: Some(100),
        max_value_millionths: Some(50),
        max_staleness_ticks: 1,
        evidence_component: "test".into(),
    });
    let err = spec.validate().unwrap_err();
    assert!(matches!(err, TwinSpecError::InvalidMeasurementRange { .. }));
}

#[test]
fn validate_duplicate_assumption() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let dup = spec.assumptions[0].clone();
    spec.assumptions.push(dup);
    let err = spec.validate().unwrap_err();
    assert!(matches!(err, TwinSpecError::DuplicateAssumption(_)));
}

#[test]
fn validate_duplicate_monitor() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let dup = spec.falsification_hooks[0].clone();
    spec.falsification_hooks.push(dup);
    let err = spec.validate().unwrap_err();
    assert!(matches!(err, TwinSpecError::DuplicateMonitor(_)));
}

// ===========================================================================
// 9. SemanticTwinSpecification — validate_snapshot
// ===========================================================================

fn make_valid_snapshot(spec: &SemanticTwinSpecification) -> TwinStateSnapshot {
    let mut snap = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    // Fill all required measurement contracts
    for contract in &spec.measurement_contracts {
        if contract.required {
            // Use midpoint of range
            let value = match (contract.min_value_millionths, contract.max_value_millionths) {
                (Some(min), Some(max)) => (min + max) / 2,
                (Some(min), None) => min,
                (None, Some(max)) => max / 2,
                (None, None) => 0,
            };
            snap.upsert_value(&contract.variable_id, value);
        }
    }
    snap
}

#[test]
fn validate_snapshot_valid() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let snap = make_valid_snapshot(&spec);
    spec.validate_snapshot(&snap).unwrap();
}

#[test]
fn validate_snapshot_missing_required() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let snap = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    // Empty snapshot → missing required variable
    let err = spec.validate_snapshot(&snap).unwrap_err();
    assert!(matches!(err, TwinSpecError::MissingSnapshotValue { .. }));
}

#[test]
fn validate_snapshot_out_of_range() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let mut snap = make_valid_snapshot(&spec);
    // workload_complexity has max 1_000_000
    snap.upsert_value("workload_complexity", 2_000_000);
    let err = spec.validate_snapshot(&snap).unwrap_err();
    assert!(matches!(err, TwinSpecError::OutOfRangeSnapshotValue { .. }));
}

#[test]
fn validate_snapshot_unknown_variable() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let mut snap = make_valid_snapshot(&spec);
    snap.upsert_value("totally_unknown_variable", 42);
    let err = spec.validate_snapshot(&snap).unwrap_err();
    assert!(matches!(err, TwinSpecError::UnknownVariable(_)));
}

// ===========================================================================
// 10. SemanticTwinSpecification — to_assumption_ledger
// ===========================================================================

#[test]
fn to_assumption_ledger_success() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let ledger = spec.to_assumption_ledger("dec-1", 7).unwrap();
    assert_eq!(ledger.assumption_count(), spec.assumptions.len());
    assert_eq!(ledger.monitors().len(), spec.falsification_hooks.len());
}

#[test]
fn to_assumption_ledger_falsification_trigger() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let mut ledger = spec.to_assumption_ledger("dec-1", 7).unwrap();

    // nondeterminism_log_completeness monitor: requires >= 1_000_000
    // Observing 900_000 should trigger violation
    let actions = ledger.observe("nondeterminism_log_completeness", 900_000, 7, 1);
    assert_eq!(actions.len(), 1);
    assert_eq!(ledger.violated_count(), 1);
}

// ===========================================================================
// 11. SemanticTwinSpecification — serde round-trip
// ===========================================================================

#[test]
fn spec_serde_roundtrip() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let json = serde_json::to_string(&spec).unwrap();
    let back: SemanticTwinSpecification = serde_json::from_str(&json).unwrap();
    assert_eq!(back, spec);
}

// ===========================================================================
// 12. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_build_validate_snapshot_ledger() {
    // 1. Build default spec
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    spec.validate().unwrap();

    // 2. Verify digest is stable
    let d1 = spec.deterministic_digest();
    let d2 = spec.deterministic_digest();
    assert_eq!(d1, d2);
    assert!(d1.starts_with("sha256:"));

    // 3. Create valid snapshot
    let mut snap = TwinStateSnapshot::new("trace-e2e", "dec-e2e", "pol-e2e", 10, 100);
    snap.upsert_value("workload_complexity", 500_000);
    snap.upsert_value("risk_belief", 400_000);
    snap.upsert_value("loss_matrix_weight", 900_000);
    snap.upsert_value("latency_outcome", 200_000);
    snap.upsert_value("nondeterminism_log_completeness", 1_000_000);
    spec.validate_snapshot(&snap).unwrap();

    // 4. Build assumption ledger
    let mut ledger = spec.to_assumption_ledger("dec-e2e", 10).unwrap();
    assert_eq!(ledger.assumption_count(), spec.assumptions.len());

    // 5. Observe nominal value — no violation
    let actions = ledger.observe("nondeterminism_log_completeness", 1_000_000, 10, 100);
    assert!(actions.is_empty());
    assert_eq!(ledger.violated_count(), 0);

    // 6. Observe bad value — triggers violation
    let actions = ledger.observe("nondeterminism_log_completeness", 0, 10, 101);
    assert!(!actions.is_empty());
    assert!(ledger.violated_count() > 0);

    // 7. Serde round-trip of spec
    let json = serde_json::to_string(&spec).unwrap();
    let back: SemanticTwinSpecification = serde_json::from_str(&json).unwrap();
    assert_eq!(back.deterministic_digest(), spec.deterministic_digest());
}
