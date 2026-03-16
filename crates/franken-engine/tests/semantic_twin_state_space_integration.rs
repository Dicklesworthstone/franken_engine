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

// ===========================================================================
// 13. Enum ordering tests
// ===========================================================================

#[test]
fn twin_state_domain_ordering() {
    assert!(TwinStateDomain::Workload < TwinStateDomain::Risk);
    assert!(TwinStateDomain::Risk < TwinStateDomain::Policy);
    assert!(TwinStateDomain::Lane < TwinStateDomain::Outcome);
    assert!(TwinStateDomain::Outcome < TwinStateDomain::Regime);
    assert!(TwinStateDomain::Resource < TwinStateDomain::Replay);
    assert!(TwinStateDomain::Replay < TwinStateDomain::Calibration);
}

#[test]
fn twin_signal_source_ordering() {
    assert!(TwinSignalSource::RuntimeDecisionCore < TwinSignalSource::RuntimeDecisionTheory);
    assert!(TwinSignalSource::RuntimeDecisionTheory < TwinSignalSource::CausalReplay);
    assert!(TwinSignalSource::FrirIr2 < TwinSignalSource::FrirIr3);
    assert!(TwinSignalSource::EvidenceLedger < TwinSignalSource::OperatorInput);
}

#[test]
fn twin_phase_ordering() {
    assert!(TwinPhase::ObserveWorkload < TwinPhase::UpdateRiskBelief);
    assert!(TwinPhase::UpdateRiskBelief < TwinPhase::SelectLane);
    assert!(TwinPhase::SelectLane < TwinPhase::ExecuteLane);
    assert!(TwinPhase::ExecuteLane < TwinPhase::RecordOutcome);
    assert!(TwinPhase::RecordOutcome < TwinPhase::EvaluateFallback);
    assert!(TwinPhase::EvaluateFallback < TwinPhase::SafeMode);
}

#[test]
fn twin_transition_trigger_ordering() {
    assert!(TwinTransitionTrigger::ObservationCommitted < TwinTransitionTrigger::PosteriorUpdated);
    assert!(TwinTransitionTrigger::PosteriorUpdated < TwinTransitionTrigger::DecisionCommitted);
    assert!(TwinTransitionTrigger::GuardrailTriggered < TwinTransitionTrigger::OperatorOverride);
}

// ===========================================================================
// 14. Snapshot deterministic digest varies with metadata fields
// ===========================================================================

#[test]
fn snapshot_digest_varies_with_trace_id() {
    let mut s1 = TwinStateSnapshot::new("trace-a", "d", "p", 1, 1);
    s1.upsert_value("x", 42);
    let mut s2 = TwinStateSnapshot::new("trace-b", "d", "p", 1, 1);
    s2.upsert_value("x", 42);
    assert_ne!(s1.deterministic_digest(), s2.deterministic_digest());
}

#[test]
fn snapshot_digest_varies_with_decision_id() {
    let mut s1 = TwinStateSnapshot::new("t", "dec-a", "p", 1, 1);
    s1.upsert_value("x", 42);
    let mut s2 = TwinStateSnapshot::new("t", "dec-b", "p", 1, 1);
    s2.upsert_value("x", 42);
    assert_ne!(s1.deterministic_digest(), s2.deterministic_digest());
}

#[test]
fn snapshot_digest_varies_with_epoch() {
    let mut s1 = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    s1.upsert_value("x", 42);
    let mut s2 = TwinStateSnapshot::new("t", "d", "p", 2, 1);
    s2.upsert_value("x", 42);
    assert_ne!(s1.deterministic_digest(), s2.deterministic_digest());
}

#[test]
fn snapshot_digest_varies_with_tick() {
    let mut s1 = TwinStateSnapshot::new("t", "d", "p", 1, 10);
    s1.upsert_value("x", 42);
    let mut s2 = TwinStateSnapshot::new("t", "d", "p", 1, 20);
    s2.upsert_value("x", 42);
    assert_ne!(s1.deterministic_digest(), s2.deterministic_digest());
}

// ===========================================================================
// 15. Snapshot clone preserves digest
// ===========================================================================

#[test]
fn snapshot_clone_preserves_digest() {
    let mut snap = TwinStateSnapshot::new("t", "d", "p", 5, 50);
    snap.upsert_value("a", 100);
    snap.upsert_value("b", 200);
    let cloned = snap.clone();
    assert_eq!(snap, cloned);
    assert_eq!(snap.deterministic_digest(), cloned.deterministic_digest());
}

// ===========================================================================
// 16. Snapshot with many variables — determinism
// ===========================================================================

#[test]
fn snapshot_many_variables_deterministic_digest() {
    let build = || {
        let mut snap = TwinStateSnapshot::new("trace", "dec", "pol", 1, 1);
        for i in 0..20 {
            snap.upsert_value(&format!("var_{i:03}"), i * 50_000);
        }
        snap.deterministic_digest()
    };
    assert_eq!(build(), build());
}

// ===========================================================================
// 17. Spec clone preserves digest
// ===========================================================================

#[test]
fn spec_clone_preserves_digest() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let cloned = spec.clone();
    assert_eq!(spec, cloned);
    assert_eq!(spec.deterministic_digest(), cloned.deterministic_digest());
}

// ===========================================================================
// 18. Validate — invalid monitor trigger_count
// ===========================================================================

#[test]
fn validate_invalid_monitor_trigger_count() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    spec.falsification_hooks.push(TwinFalsificationHook {
        monitor_id: "bad_count_monitor".into(),
        assumption_id: spec.assumptions[0].id.clone(),
        variable_id: spec.variables[0].id.clone(),
        kind: MonitorKind::Invariant,
        op: MonitorOp::Ge,
        threshold_millionths: 0,
        trigger_count: 0, // invalid: 0 triggers
    });
    let err = spec.validate().unwrap_err();
    assert!(matches!(
        err,
        TwinSpecError::InvalidMonitorTriggerCount { .. }
    ));
}

// ===========================================================================
// 19. Validate snapshot — value exactly at range boundaries
// ===========================================================================

#[test]
fn validate_snapshot_at_exact_boundaries() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let mut snap = make_valid_snapshot(&spec);
    // workload_complexity: min=0, max=1_000_000
    // Set to exact min.
    snap.upsert_value("workload_complexity", 0);
    spec.validate_snapshot(&snap).unwrap();
    // Set to exact max.
    snap.upsert_value("workload_complexity", 1_000_000);
    spec.validate_snapshot(&snap).unwrap();
}

#[test]
fn validate_snapshot_one_past_max_fails() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let mut snap = make_valid_snapshot(&spec);
    snap.upsert_value("workload_complexity", 1_000_001);
    let err = spec.validate_snapshot(&snap).unwrap_err();
    assert!(matches!(err, TwinSpecError::OutOfRangeSnapshotValue { .. }));
}

#[test]
fn validate_snapshot_negative_value_fails() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let mut snap = make_valid_snapshot(&spec);
    // workload_complexity: min=0, so -1 is out of range.
    snap.upsert_value("workload_complexity", -1);
    let err = spec.validate_snapshot(&snap).unwrap_err();
    assert!(matches!(err, TwinSpecError::OutOfRangeSnapshotValue { .. }));
}

// ===========================================================================
// 20. Ledger — multiple sequential observations
// ===========================================================================

#[test]
fn ledger_multiple_observations_accumulate_violations() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let mut ledger = spec.to_assumption_ledger("dec-1", 7).unwrap();

    // First observation: nominal — no violation.
    let actions = ledger.observe("nondeterminism_log_completeness", 1_000_000, 7, 100);
    assert!(actions.is_empty());
    assert_eq!(ledger.violated_count(), 0);

    // Second observation: bad value — triggers violation.
    let actions = ledger.observe("nondeterminism_log_completeness", 0, 7, 101);
    assert!(!actions.is_empty());
    assert!(ledger.violated_count() > 0);
}

// ===========================================================================
// 21. Spec default — causal model present
// ===========================================================================

#[test]
fn lane_decision_default_has_causal_model_nodes() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    // Causal model should have nodes from the variable set.
    assert!(!spec.causal_model.nodes().is_empty());
}

// ===========================================================================
// 22. Error serde round-trips for all variants
// ===========================================================================

#[test]
fn spec_error_serde_all_variants() {
    let errors: Vec<TwinSpecError> = vec![
        TwinSpecError::DuplicateVariable("v".into()),
        TwinSpecError::UnknownVariable("u".into()),
        TwinSpecError::InvalidSchemaVersion("bad".into()),
        TwinSpecError::DuplicateTransition("t".into()),
        TwinSpecError::DuplicateAssumption("a".into()),
        TwinSpecError::DuplicateMonitor("m".into()),
        TwinSpecError::InvalidMonitorTriggerCount {
            monitor_id: "m".into(),
        },
        TwinSpecError::InvalidMeasurementRange {
            variable_id: "v".into(),
        },
        TwinSpecError::MissingTreatmentVariable("t".into()),
        TwinSpecError::MissingOutcomeVariable("o".into()),
        TwinSpecError::MissingSnapshotValue {
            variable_id: "v".into(),
        },
        TwinSpecError::OutOfRangeSnapshotValue {
            variable_id: "v".into(),
            value: 999,
            min: Some(0),
            max: Some(100),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: TwinSpecError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *err);
    }
}

// ===========================================================================
// 23. Snapshot deterministic_digest format
// ===========================================================================

#[test]
fn snapshot_digest_format_sha256_prefix() {
    let snap = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    let digest = snap.deterministic_digest();
    assert!(
        digest.starts_with("sha256:"),
        "snapshot digest should start with 'sha256:', got: {}",
        digest
    );
    // The hex portion should be 64 chars (SHA-256).
    let hex_part = &digest["sha256:".len()..];
    assert_eq!(
        hex_part.len(),
        64,
        "SHA-256 hex should be 64 chars, got {}",
        hex_part.len()
    );
}

// ===========================================================================
// 24. Spec serde preserves all fields
// ===========================================================================

#[test]
fn spec_serde_preserves_all_fields() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let json = serde_json::to_string(&spec).unwrap();
    let back: SemanticTwinSpecification = serde_json::from_str(&json).unwrap();

    assert_eq!(back.schema_version, spec.schema_version);
    assert_eq!(back.component, spec.component);
    assert_eq!(back.states, spec.states);
    assert_eq!(back.variables.len(), spec.variables.len());
    assert_eq!(back.transitions.len(), spec.transitions.len());
    assert_eq!(
        back.measurement_contracts.len(),
        spec.measurement_contracts.len()
    );
    assert_eq!(back.assumptions.len(), spec.assumptions.len());
    assert_eq!(
        back.falsification_hooks.len(),
        spec.falsification_hooks.len()
    );
    assert_eq!(back.treatment_variable, spec.treatment_variable);
    assert_eq!(back.outcome_variable, spec.outcome_variable);
    assert_eq!(
        back.recommended_adjustment_set,
        spec.recommended_adjustment_set
    );
}

// ===========================================================================
// 25. BTreeMap ordering determinism in snapshot values
// ===========================================================================

#[test]
fn snapshot_values_btreemap_ordered() {
    let mut snap = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    // Insert in reverse alphabetical order.
    snap.upsert_value("z_var", 100);
    snap.upsert_value("a_var", 200);
    snap.upsert_value("m_var", 300);

    let keys: Vec<&String> = snap.values_millionths.keys().collect();
    // BTreeMap should maintain sorted order.
    assert_eq!(keys[0], "a_var");
    assert_eq!(keys[1], "m_var");
    assert_eq!(keys[2], "z_var");
}

// ===========================================================================
// 26. Spec default states are 7 lifecycle phases
// ===========================================================================

#[test]
fn lane_decision_default_all_phases_present() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let phases = [
        TwinPhase::ObserveWorkload,
        TwinPhase::UpdateRiskBelief,
        TwinPhase::SelectLane,
        TwinPhase::ExecuteLane,
        TwinPhase::RecordOutcome,
        TwinPhase::EvaluateFallback,
        TwinPhase::SafeMode,
    ];
    for phase in &phases {
        assert!(
            spec.states.contains(phase),
            "phase {:?} should be in states",
            phase
        );
    }
}
