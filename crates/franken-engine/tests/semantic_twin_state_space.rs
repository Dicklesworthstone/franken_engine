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
    TwinSpecError, TwinStateDomain, TwinStateSnapshot,
};

#[test]
fn lane_decision_default_exposes_expected_contracts() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    assert_eq!(spec.component, SEMANTIC_TWIN_COMPONENT);
    assert_eq!(spec.treatment_variable, "lane_choice");
    assert_eq!(spec.outcome_variable, "latency_outcome");
    assert!(
        spec.assumptions
            .iter()
            .any(|assumption| assumption.id == "assumption_nondeterminism_log_complete")
    );
    assert!(
        spec.transitions
            .iter()
            .any(|transition| transition.id == "transition_fallback_to_safe_mode")
    );
}

#[test]
fn causal_model_backdoor_recommendation_is_consistent() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let backdoor = spec
        .causal_model
        .backdoor_criterion(&spec.treatment_variable, &spec.outcome_variable)
        .expect("backdoor criterion");
    assert!(backdoor.identified);
    assert_eq!(backdoor.adjustment_set, spec.recommended_adjustment_set);
}

#[test]
fn assumption_ledger_from_spec_is_deterministic_and_actionable() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let mut first = spec
        .to_assumption_ledger("decision-semantic-ledger", 11)
        .expect("first ledger");
    let second = spec
        .to_assumption_ledger("decision-semantic-ledger", 11)
        .expect("second ledger");

    assert_eq!(first.assumption_count(), second.assumption_count());
    assert_eq!(first.monitors().len(), second.monitors().len());
    assert_eq!(first.chain_hash(), second.chain_hash());

    // Violate monitor_replay_completeness (requires >= 1_000_000).
    let before = first.chain_hash().to_string();
    let actions = first.observe("nondeterminism_log_completeness", 800_000, 11, 3);
    let after = first.chain_hash().to_string();
    assert_eq!(actions.len(), 1);
    assert_eq!(first.violated_count(), 1);
    assert_ne!(before, after);
}

#[test]
fn snapshot_validation_requires_mandatory_fields() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let mut snapshot = TwinStateSnapshot::new("trace-1", "decision-1", "policy-1", 1, 1);
    snapshot.upsert_value("workload_complexity", 500_000);

    let err = spec
        .validate_snapshot(&snapshot)
        .expect_err("missing required contracts should fail");
    assert!(matches!(err, TwinSpecError::MissingSnapshotValue { .. }));
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde, display, validation, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn twin_spec_error_display_is_non_empty_for_key_variants() {
    let errors: Vec<TwinSpecError> = vec![
        TwinSpecError::Scm("test scm error".to_string()),
        TwinSpecError::InvalidSchemaVersion("bad-version".to_string()),
        TwinSpecError::DuplicateVariable("var-x".to_string()),
        TwinSpecError::UnknownVariable("var-y".to_string()),
        TwinSpecError::DuplicateTransition("trans-z".to_string()),
        TwinSpecError::UnknownAssumption("assumption-q".to_string()),
        TwinSpecError::DuplicateAssumption("assumption-r".to_string()),
        TwinSpecError::DuplicateMonitor("monitor-s".to_string()),
        TwinSpecError::InvalidMonitorTriggerCount {
            monitor_id: "monitor-t".to_string(),
        },
        TwinSpecError::InvalidMeasurementRange {
            variable_id: "var-u".to_string(),
        },
        TwinSpecError::MissingTreatmentVariable("treatment".to_string()),
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "error display must not be empty: {err:?}");
    }
}

#[test]
fn twin_state_snapshot_serde_round_trip() {
    let mut snapshot = TwinStateSnapshot::new("trace-rt", "decision-rt", "policy-rt", 1, 10);
    snapshot.upsert_value("workload_complexity", 500_000);
    snapshot.upsert_value("control_intensity", 800_000);
    let json = serde_json::to_string(&snapshot).expect("serialize");
    let recovered: TwinStateSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(snapshot, recovered);
}

#[test]
fn semantic_twin_specification_serde_round_trip() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let json = serde_json::to_string(&spec).expect("serialize");
    let recovered: SemanticTwinSpecification = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(spec, recovered);
}

#[test]
fn twin_spec_error_serde_round_trip() {
    let err = TwinSpecError::DuplicateVariable("var-dup".to_string());
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: TwinSpecError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

#[test]
fn semantic_twin_component_constant_is_non_empty() {
    assert!(!SEMANTIC_TWIN_COMPONENT.is_empty());
}

#[test]
fn twin_state_domain_serde_round_trip() {
    for domain in [
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
        let json = serde_json::to_string(&domain).expect("serialize");
        let recovered: TwinStateDomain = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(domain, recovered);
    }
}

#[test]
fn default_spec_produces_non_empty_adjustment_set() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    assert!(!spec.recommended_adjustment_set.is_empty());
    assert!(!spec.variables.is_empty());
    assert!(!spec.transitions.is_empty());
    assert!(!spec.measurement_contracts.is_empty());
    assert!(!spec.assumptions.is_empty());
}

#[test]
fn twin_state_snapshot_multiple_upserts_preserved_in_serde() {
    let mut snapshot = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    snapshot.upsert_value("key_a", 100);
    snapshot.upsert_value("key_b", 200);
    let json = serde_json::to_string(&snapshot).expect("serialize");
    let recovered: TwinStateSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(snapshot, recovered);
}

#[test]
fn twin_state_snapshot_new_sets_trace_fields() {
    let snapshot = TwinStateSnapshot::new("trace-1", "decision-1", "policy-1", 5, 42);
    let json = serde_json::to_string(&snapshot).expect("serialize");
    assert!(json.contains("trace-1"));
    assert!(json.contains("decision-1"));
    assert!(json.contains("policy-1"));
}

#[test]
fn default_spec_causal_model_is_identified() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let backdoor = spec
        .causal_model
        .backdoor_criterion(&spec.treatment_variable, &spec.outcome_variable)
        .expect("backdoor criterion");
    assert!(backdoor.identified);
}

#[test]
fn twin_state_domain_serde_round_trip_extended() {
    for domain in [
        TwinStateDomain::Outcome,
        TwinStateDomain::Regime,
        TwinStateDomain::Resource,
        TwinStateDomain::Replay,
        TwinStateDomain::Calibration,
    ] {
        let json = serde_json::to_string(&domain).expect("serialize");
        let recovered: TwinStateDomain = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(domain, recovered);
    }
}

#[test]
fn default_spec_has_nonempty_assumptions() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    assert!(!spec.assumptions.is_empty());
    for assumption in &spec.assumptions {
        assert!(!assumption.id.trim().is_empty());
    }
}

#[test]
fn default_spec_has_nonempty_transitions() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    assert!(!spec.transitions.is_empty());
    for transition in &spec.transitions {
        assert!(!transition.id.trim().is_empty());
    }
}

#[test]
fn default_spec_treatment_and_outcome_variables_are_nonempty() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    assert!(!spec.treatment_variable.trim().is_empty());
    assert!(!spec.outcome_variable.trim().is_empty());
}

#[test]
fn twin_state_domain_all_variants_serialize() {
    for domain in [
        TwinStateDomain::Outcome,
        TwinStateDomain::Regime,
        TwinStateDomain::Resource,
        TwinStateDomain::Replay,
        TwinStateDomain::Calibration,
    ] {
        let json = serde_json::to_string(&domain).expect("serialize");
        assert!(!json.is_empty());
    }
}

#[test]
fn default_spec_serde_roundtrip_preserves_component() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let json = serde_json::to_string(&spec).expect("serialize");
    let recovered: SemanticTwinSpecification = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.component, SEMANTIC_TWIN_COMPONENT);
    assert_eq!(recovered.treatment_variable, spec.treatment_variable);
}

#[test]
fn semantic_twin_component_is_nonempty() {
    assert!(!SEMANTIC_TWIN_COMPONENT.is_empty());
}

#[test]
fn twin_state_domain_all_variants_debug() {
    for domain in [
        TwinStateDomain::Outcome,
        TwinStateDomain::Regime,
        TwinStateDomain::Resource,
        TwinStateDomain::Replay,
        TwinStateDomain::Calibration,
    ] {
        let dbg = format!("{domain:?}");
        assert!(!dbg.is_empty());
    }
}

#[test]
fn default_spec_assumptions_have_nonempty_ids() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    assert!(!spec.assumptions.is_empty());
    for assumption in &spec.assumptions {
        assert!(!assumption.id.trim().is_empty());
    }
}

#[test]
fn snapshot_deterministic_digest_is_stable() {
    let mut snap_a = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    snap_a.upsert_value("key_x", 100);
    snap_a.upsert_value("key_y", 200);

    let mut snap_b = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    snap_b.upsert_value("key_x", 100);
    snap_b.upsert_value("key_y", 200);

    assert_eq!(snap_a.deterministic_digest(), snap_b.deterministic_digest());
    assert!(snap_a.deterministic_digest().starts_with("sha256:"));
}

#[test]
fn snapshot_deterministic_digest_changes_with_value() {
    let mut snap_a = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    snap_a.upsert_value("key_x", 100);

    let mut snap_b = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    snap_b.upsert_value("key_x", 999);

    assert_ne!(snap_a.deterministic_digest(), snap_b.deterministic_digest());
}

#[test]
fn spec_deterministic_digest_is_stable_across_calls() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let d1 = spec.deterministic_digest();
    let d2 = spec.deterministic_digest();
    assert_eq!(d1, d2);
    assert!(d1.starts_with("sha256:"));
}

#[test]
fn validate_snapshot_rejects_unknown_variable() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let mut snapshot = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    // Fill all required variables with valid values
    for contract in &spec.measurement_contracts {
        if contract.required {
            let value = contract.min_value_millionths.unwrap_or(0);
            snapshot.upsert_value(&contract.variable_id, value);
        }
    }
    // Now add an unknown variable
    snapshot.upsert_value("completely_unknown_variable", 42);
    let err = spec
        .validate_snapshot(&snapshot)
        .expect_err("unknown variable should fail");
    assert!(
        matches!(err, TwinSpecError::UnknownVariable(ref id) if id == "completely_unknown_variable")
    );
}

#[test]
fn default_spec_schema_version_matches_constant() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    assert_eq!(spec.schema_version, SEMANTIC_TWIN_SCHEMA_VERSION);
}

#[test]
fn assumption_ledger_observation_with_passing_value_no_violation() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let mut ledger = spec
        .to_assumption_ledger("decision-pass", 11)
        .expect("ledger");
    // Observe with a value that satisfies the monitor (>= 1_000_000)
    let actions = ledger.observe("nondeterminism_log_completeness", 1_000_000, 11, 5);
    assert!(
        actions.is_empty(),
        "passing value should produce no actions"
    );
    assert_eq!(ledger.violated_count(), 0);
}

#[test]
fn default_spec_validate_succeeds() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    spec.validate()
        .expect("default spec should pass validation");
}

#[test]
fn semantic_twin_specification_debug_is_nonempty() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    assert!(!format!("{spec:?}").is_empty());
}

#[test]
fn default_spec_serde_is_deterministic() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let a = serde_json::to_string(&spec).expect("first");
    let b = serde_json::to_string(&spec).expect("second");
    assert_eq!(a, b);
}

#[test]
fn default_spec_serialized_length_exceeds_minimum() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let json = serde_json::to_string(&spec).expect("serialize");
    assert!(
        json.len() > 50,
        "serialized spec should be >50 chars, got {}",
        json.len()
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: PearlTower 2026-03-12 — 70 new tests
// ────────────────────────────────────────────────────────────

use frankenengine_engine::assumptions_ledger::{
    AssumptionCategory, AssumptionOrigin, MonitorKind, MonitorOp, ViolationSeverity,
};
use frankenengine_engine::semantic_twin_state_space::{
    TwinAssumptionSpec, TwinFalsificationHook, TwinMeasurementContract, TwinPhase,
    TwinSignalSource, TwinStateVariableSpec, TwinTransitionSpec, TwinTransitionTrigger,
};
use std::collections::BTreeSet;

// ── TwinSignalSource serde roundtrip ────────────────────────

#[test]
fn twin_signal_source_serde_round_trip_all_variants() {
    for source in [
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
        let json = serde_json::to_string(&source).expect("serialize");
        let recovered: TwinSignalSource = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(source, recovered);
    }
}

// ── TwinPhase serde roundtrip ───────────────────────────────

#[test]
fn twin_phase_serde_round_trip_all_variants() {
    for phase in [
        TwinPhase::ObserveWorkload,
        TwinPhase::UpdateRiskBelief,
        TwinPhase::SelectLane,
        TwinPhase::ExecuteLane,
        TwinPhase::RecordOutcome,
        TwinPhase::EvaluateFallback,
        TwinPhase::SafeMode,
    ] {
        let json = serde_json::to_string(&phase).expect("serialize");
        let recovered: TwinPhase = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(phase, recovered);
    }
}

// ── TwinTransitionTrigger serde roundtrip ───────────────────

#[test]
fn twin_transition_trigger_serde_round_trip_all_variants() {
    for trigger in [
        TwinTransitionTrigger::ObservationCommitted,
        TwinTransitionTrigger::PosteriorUpdated,
        TwinTransitionTrigger::DecisionCommitted,
        TwinTransitionTrigger::ExecutionCompleted,
        TwinTransitionTrigger::OutcomeRecorded,
        TwinTransitionTrigger::GuardrailTriggered,
        TwinTransitionTrigger::OperatorOverride,
        TwinTransitionTrigger::ReplayCounterfactual,
    ] {
        let json = serde_json::to_string(&trigger).expect("serialize");
        let recovered: TwinTransitionTrigger = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(trigger, recovered);
    }
}

// ── Struct serde roundtrips (integration level) ─────────────

#[test]
fn twin_state_variable_spec_serde_round_trip() {
    let spec = TwinStateVariableSpec {
        id: "test_integration_var".to_string(),
        label: "Integration Test Variable".to_string(),
        domain: TwinStateDomain::Calibration,
        source: TwinSignalSource::EnvironmentTelemetry,
        observable: false,
        unit: "count".to_string(),
        description: "An integration-level variable spec test.".to_string(),
    };
    let json = serde_json::to_string(&spec).expect("serialize");
    let recovered: TwinStateVariableSpec = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(spec, recovered);
}

#[test]
fn twin_transition_spec_serde_round_trip() {
    let spec = TwinTransitionSpec {
        id: "transition_integ_test".to_string(),
        from_phase: TwinPhase::SafeMode,
        to_phase: TwinPhase::ObserveWorkload,
        trigger: TwinTransitionTrigger::ReplayCounterfactual,
        deterministic_priority: 999,
        guard_assumptions: vec!["guard_a".to_string(), "guard_b".to_string()],
        description: "Integration transition test".to_string(),
    };
    let json = serde_json::to_string(&spec).expect("serialize");
    let recovered: TwinTransitionSpec = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(spec, recovered);
}

#[test]
fn twin_measurement_contract_serde_round_trip() {
    let contract = TwinMeasurementContract {
        variable_id: "integ_contract_var".to_string(),
        required: false,
        min_value_millionths: None,
        max_value_millionths: Some(5_000_000),
        max_staleness_ticks: 100,
        evidence_component: "integ_test".to_string(),
    };
    let json = serde_json::to_string(&contract).expect("serialize");
    let recovered: TwinMeasurementContract = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(contract, recovered);
}

#[test]
fn twin_assumption_spec_serde_round_trip() {
    let spec = TwinAssumptionSpec {
        id: "assumption_integ".to_string(),
        category: AssumptionCategory::Statistical,
        origin: AssumptionOrigin::PolicyInherited,
        violation_severity: ViolationSeverity::Advisory,
        description: "Integration-level assumption".to_string(),
        dependencies: BTreeSet::from(["dep_a".to_string(), "dep_b".to_string()]),
        predicate_hash: "sha256:deadbeef".to_string(),
    };
    let json = serde_json::to_string(&spec).expect("serialize");
    let recovered: TwinAssumptionSpec = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(spec, recovered);
}

#[test]
fn twin_falsification_hook_serde_round_trip() {
    let hook = TwinFalsificationHook {
        monitor_id: "monitor_integ".to_string(),
        assumption_id: "assumption_integ".to_string(),
        variable_id: "var_integ".to_string(),
        kind: MonitorKind::Coverage,
        op: MonitorOp::Ge,
        threshold_millionths: 750_000,
        trigger_count: 3,
    };
    let json = serde_json::to_string(&hook).expect("serialize");
    let recovered: TwinFalsificationHook = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(hook, recovered);
}

// ── serde rename_all snake_case verification ────────────────

#[test]
fn twin_state_domain_serializes_to_snake_case() {
    let json = serde_json::to_string(&TwinStateDomain::Workload).expect("serialize");
    assert_eq!(json, "\"workload\"");
}

#[test]
fn twin_signal_source_serializes_to_snake_case() {
    let json = serde_json::to_string(&TwinSignalSource::RuntimeDecisionCore).expect("serialize");
    assert_eq!(json, "\"runtime_decision_core\"");
    let json2 = serde_json::to_string(&TwinSignalSource::FrirIr2).expect("serialize");
    assert_eq!(json2, "\"frir_ir2\"");
}

#[test]
fn twin_phase_serializes_to_snake_case() {
    let json = serde_json::to_string(&TwinPhase::ObserveWorkload).expect("serialize");
    assert_eq!(json, "\"observe_workload\"");
    let json2 = serde_json::to_string(&TwinPhase::SafeMode).expect("serialize");
    assert_eq!(json2, "\"safe_mode\"");
}

#[test]
fn twin_transition_trigger_serializes_to_snake_case() {
    let json =
        serde_json::to_string(&TwinTransitionTrigger::GuardrailTriggered).expect("serialize");
    assert_eq!(json, "\"guardrail_triggered\"");
    let json2 =
        serde_json::to_string(&TwinTransitionTrigger::ReplayCounterfactual).expect("serialize");
    assert_eq!(json2, "\"replay_counterfactual\"");
}

// ── Display format verification for error variants ──────────

#[test]
fn twin_spec_error_display_missing_outcome_variable_contains_id() {
    let err = TwinSpecError::MissingOutcomeVariable("outcome_xyz".to_string());
    let msg = err.to_string();
    assert!(
        msg.contains("outcome_xyz"),
        "display should contain variable id"
    );
    assert!(
        msg.contains("missing outcome"),
        "display should describe the error"
    );
}

#[test]
fn twin_spec_error_display_missing_required_variable_contains_id() {
    let err = TwinSpecError::MissingRequiredVariable {
        variable_id: "var_req_xyz".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("var_req_xyz"));
}

#[test]
fn twin_spec_error_display_missing_snapshot_value_contains_id() {
    let err = TwinSpecError::MissingSnapshotValue {
        variable_id: "snap_val_xyz".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("snap_val_xyz"));
    assert!(msg.contains("snapshot"));
}

#[test]
fn twin_spec_error_display_out_of_range_contains_value_and_bounds() {
    let err = TwinSpecError::OutOfRangeSnapshotValue {
        variable_id: "oor_var".to_string(),
        value: 42,
        min: Some(0),
        max: Some(10),
    };
    let msg = err.to_string();
    assert!(msg.contains("42"), "display should contain value");
    assert!(
        msg.contains("oor_var"),
        "display should contain variable_id"
    );
}

#[test]
fn twin_spec_error_display_duplicate_transition_priority_contains_phase_and_trigger() {
    let err = TwinSpecError::DuplicateTransitionPriority {
        from_phase: TwinPhase::ExecuteLane,
        trigger: TwinTransitionTrigger::ExecutionCompleted,
        deterministic_priority: 55,
    };
    let msg = err.to_string();
    assert!(msg.contains("55"), "display should contain priority");
    assert!(
        msg.contains("ExecuteLane"),
        "display should contain phase debug"
    );
}

// ── std::error::Error implementation ────────────────────────

#[test]
fn twin_spec_error_implements_std_error() {
    let err = TwinSpecError::Scm("test error".to_string());
    let std_err: &dyn std::error::Error = &err;
    assert!(!std_err.to_string().is_empty());
    assert!(std_err.source().is_none());
}

// ── TwinSpecError serde roundtrip all variants ──────────────

#[test]
fn twin_spec_error_serde_round_trip_out_of_range_with_none_bounds() {
    let err = TwinSpecError::OutOfRangeSnapshotValue {
        variable_id: "test_oor".to_string(),
        value: -999,
        min: None,
        max: None,
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: TwinSpecError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

#[test]
fn twin_spec_error_serde_round_trip_duplicate_transition_priority() {
    let err = TwinSpecError::DuplicateTransitionPriority {
        from_phase: TwinPhase::EvaluateFallback,
        trigger: TwinTransitionTrigger::GuardrailTriggered,
        deterministic_priority: 100,
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: TwinSpecError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

// ── Snapshot edge cases ─────────────────────────────────────

#[test]
fn snapshot_new_with_zero_epoch_and_tick() {
    let snapshot = TwinStateSnapshot::new("trace", "decision", "policy", 0, 0);
    assert_eq!(snapshot.epoch, 0);
    assert_eq!(snapshot.tick, 0);
    let json = serde_json::to_string(&snapshot).expect("serialize");
    let recovered: TwinStateSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(snapshot, recovered);
}

#[test]
fn snapshot_new_with_empty_string_ids() {
    let snapshot = TwinStateSnapshot::new("", "", "", 1, 1);
    assert_eq!(snapshot.trace_id, "");
    assert_eq!(snapshot.decision_id, "");
    assert_eq!(snapshot.policy_id, "");
    let json = serde_json::to_string(&snapshot).expect("serialize");
    let recovered: TwinStateSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(snapshot, recovered);
}

#[test]
fn snapshot_new_with_max_epoch_and_tick() {
    let snapshot = TwinStateSnapshot::new("t", "d", "p", u64::MAX, u64::MAX);
    assert_eq!(snapshot.epoch, u64::MAX);
    assert_eq!(snapshot.tick, u64::MAX);
    let json = serde_json::to_string(&snapshot).expect("serialize");
    let recovered: TwinStateSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(snapshot, recovered);
}

#[test]
fn snapshot_upsert_value_with_i64_min_boundary() {
    let mut snapshot = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    snapshot.upsert_value("boundary_var", i64::MIN);
    assert_eq!(snapshot.values_millionths["boundary_var"], i64::MIN);
}

#[test]
fn snapshot_upsert_value_with_i64_max_boundary() {
    let mut snapshot = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    snapshot.upsert_value("boundary_var", i64::MAX);
    assert_eq!(snapshot.values_millionths["boundary_var"], i64::MAX);
}

#[test]
fn snapshot_upsert_value_with_zero() {
    let mut snapshot = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    snapshot.upsert_value("zero_var", 0);
    assert_eq!(snapshot.values_millionths["zero_var"], 0);
}

#[test]
fn snapshot_upsert_value_overwrites_preserves_other_keys() {
    let mut snapshot = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    snapshot.upsert_value("key_a", 100);
    snapshot.upsert_value("key_b", 200);
    snapshot.upsert_value("key_a", 300);
    assert_eq!(snapshot.values_millionths["key_a"], 300);
    assert_eq!(snapshot.values_millionths["key_b"], 200);
    assert_eq!(snapshot.values_millionths.len(), 2);
}

#[test]
fn snapshot_deterministic_digest_empty_values() {
    let snapshot = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    let digest = snapshot.deterministic_digest();
    assert!(digest.starts_with("sha256:"));
    assert!(digest.len() > 10);
}

#[test]
fn snapshot_deterministic_digest_differs_by_decision_id() {
    let s1 = TwinStateSnapshot::new("t", "decision-a", "p", 1, 1);
    let s2 = TwinStateSnapshot::new("t", "decision-b", "p", 1, 1);
    assert_ne!(s1.deterministic_digest(), s2.deterministic_digest());
}

#[test]
fn snapshot_deterministic_digest_differs_by_policy_id() {
    let s1 = TwinStateSnapshot::new("t", "d", "policy-a", 1, 1);
    let s2 = TwinStateSnapshot::new("t", "d", "policy-b", 1, 1);
    assert_ne!(s1.deterministic_digest(), s2.deterministic_digest());
}

#[test]
fn snapshot_deterministic_digest_differs_by_epoch() {
    let s1 = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    let s2 = TwinStateSnapshot::new("t", "d", "p", 2, 1);
    assert_ne!(s1.deterministic_digest(), s2.deterministic_digest());
}

#[test]
fn snapshot_deterministic_digest_differs_by_tick() {
    let s1 = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    let s2 = TwinStateSnapshot::new("t", "d", "p", 1, 2);
    assert_ne!(s1.deterministic_digest(), s2.deterministic_digest());
}

#[test]
fn snapshot_deterministic_digest_differs_by_key_name() {
    let mut s1 = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    s1.upsert_value("alpha", 100);
    let mut s2 = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    s2.upsert_value("beta", 100);
    assert_ne!(s1.deterministic_digest(), s2.deterministic_digest());
}

// ── Validate snapshot boundary conditions ───────────────────

#[test]
fn validate_snapshot_accepts_values_at_exact_min_boundary() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let mut snapshot = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    for contract in &spec.measurement_contracts {
        if contract.required {
            let value = contract.min_value_millionths.unwrap_or(0);
            snapshot.upsert_value(&contract.variable_id, value);
        }
    }
    spec.validate_snapshot(&snapshot)
        .expect("values at exact min boundary should pass");
}

#[test]
fn validate_snapshot_accepts_values_at_exact_max_boundary() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let mut snapshot = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    for contract in &spec.measurement_contracts {
        if contract.required {
            let value = contract.max_value_millionths.unwrap_or(0);
            snapshot.upsert_value(&contract.variable_id, value);
        }
    }
    spec.validate_snapshot(&snapshot)
        .expect("values at exact max boundary should pass");
}

#[test]
fn validate_snapshot_rejects_value_above_max() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let mut snapshot = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    for contract in &spec.measurement_contracts {
        if contract.required {
            snapshot.upsert_value(
                &contract.variable_id,
                contract.min_value_millionths.unwrap_or(0),
            );
        }
    }
    // risk_belief has max 1_000_000
    snapshot.upsert_value("risk_belief", 1_000_001);
    let err = spec
        .validate_snapshot(&snapshot)
        .expect_err("above max should fail");
    assert!(matches!(err, TwinSpecError::OutOfRangeSnapshotValue { .. }));
}

#[test]
fn validate_snapshot_with_optional_variable_included() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let mut snapshot = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    for contract in &spec.measurement_contracts {
        if contract.required {
            snapshot.upsert_value(
                &contract.variable_id,
                contract.min_value_millionths.unwrap_or(0),
            );
        }
    }
    // Also add an optional variable (replay_fidelity_margin is not required)
    snapshot.upsert_value("replay_fidelity_margin", 500_000);
    spec.validate_snapshot(&snapshot)
        .expect("optional variable should be accepted");
}

// ── Validation edge cases ───────────────────────────────────

#[test]
fn validate_rejects_transition_referencing_unknown_state() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    // Remove SafeMode from states list but keep the transition that uses it
    spec.states.retain(|s| *s != TwinPhase::SafeMode);
    let err = spec
        .validate()
        .expect_err("unknown state reference should fail");
    assert!(matches!(err, TwinSpecError::Scm(..)));
}

#[test]
fn validate_rejects_measurement_contract_with_inverted_range() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    spec.measurement_contracts.push(TwinMeasurementContract {
        variable_id: "workload_complexity".to_string(),
        required: false,
        min_value_millionths: Some(1_000_000),
        max_value_millionths: Some(0),
        max_staleness_ticks: 1,
        evidence_component: "test".to_string(),
    });
    let err = spec.validate().expect_err("inverted range should fail");
    assert!(matches!(err, TwinSpecError::InvalidMeasurementRange { .. }));
}

#[test]
fn validate_accepts_measurement_contract_with_none_min() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    spec.measurement_contracts.push(TwinMeasurementContract {
        variable_id: "workload_complexity".to_string(),
        required: false,
        min_value_millionths: None,
        max_value_millionths: Some(1_000_000),
        max_staleness_ticks: 1,
        evidence_component: "test".to_string(),
    });
    spec.validate().expect("None min should pass validation");
}

#[test]
fn validate_accepts_measurement_contract_with_none_max() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    spec.measurement_contracts.push(TwinMeasurementContract {
        variable_id: "workload_complexity".to_string(),
        required: false,
        min_value_millionths: Some(0),
        max_value_millionths: None,
        max_staleness_ticks: 1,
        evidence_component: "test".to_string(),
    });
    spec.validate().expect("None max should pass validation");
}

#[test]
fn validate_accepts_measurement_contract_with_both_none() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    spec.measurement_contracts.push(TwinMeasurementContract {
        variable_id: "workload_complexity".to_string(),
        required: false,
        min_value_millionths: None,
        max_value_millionths: None,
        max_staleness_ticks: 1,
        evidence_component: "test".to_string(),
    });
    spec.validate().expect("both None should pass validation");
}

// ── to_assumption_ledger edge cases ─────────────────────────

#[test]
fn to_assumption_ledger_different_decision_ids_produce_different_ledgers() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let ledger_a = spec
        .to_assumption_ledger("decision-a", 1)
        .expect("ledger a");
    let ledger_b = spec
        .to_assumption_ledger("decision-b", 1)
        .expect("ledger b");
    // Both should have same assumption count but different chain hashes
    assert_eq!(ledger_a.assumption_count(), ledger_b.assumption_count());
    assert_ne!(ledger_a.chain_hash(), ledger_b.chain_hash());
}

#[test]
fn to_assumption_ledger_different_epochs_produce_different_chain_hashes() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let ledger_a = spec
        .to_assumption_ledger("decision-x", 1)
        .expect("ledger a");
    let ledger_b = spec
        .to_assumption_ledger("decision-x", 2)
        .expect("ledger b");
    assert_ne!(ledger_a.chain_hash(), ledger_b.chain_hash());
}

#[test]
fn to_assumption_ledger_multiple_monitor_violations() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let mut ledger = spec
        .to_assumption_ledger("decision-multi", 11)
        .expect("ledger");

    // Violate monitor_replay_completeness (requires >= 1_000_000)
    let actions1 = ledger.observe("nondeterminism_log_completeness", 800_000, 11, 1);
    assert_eq!(actions1.len(), 1);

    // Violate monitor_workload_complexity_presence (requires >= 0, but let us check
    // the latency SLO envelope monitor: requires latency_outcome <= 250_000)
    let actions2 = ledger.observe("latency_outcome", 300_000, 11, 2);
    // trigger_count is 2 for this monitor, so first observation does not fire
    assert!(actions2.is_empty());
    let actions3 = ledger.observe("latency_outcome", 300_000, 11, 3);
    assert_eq!(actions3.len(), 1);
    assert_eq!(ledger.violated_count(), 2);
}

#[test]
fn to_assumption_ledger_no_violations_on_passing_values() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let mut ledger = spec
        .to_assumption_ledger("decision-pass-all", 11)
        .expect("ledger");
    let initial_count = ledger.violated_count();

    // Passing values for each monitored variable
    ledger.observe("nondeterminism_log_completeness", 1_000_000, 11, 1);
    ledger.observe("workload_complexity", 500_000, 11, 2);
    ledger.observe("loss_matrix_weight", 500_000, 11, 3);
    ledger.observe("latency_outcome", 100_000, 11, 4);
    ledger.observe("regime", 1_000_000, 11, 5);
    ledger.observe("risk_belief", 500_000, 11, 6);

    assert_eq!(ledger.violated_count(), initial_count);
}

// ── Default spec structural assertions ──────────────────────

#[test]
fn default_spec_all_states_match_twin_phase_enum() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let expected: Vec<TwinPhase> = vec![
        TwinPhase::ObserveWorkload,
        TwinPhase::UpdateRiskBelief,
        TwinPhase::SelectLane,
        TwinPhase::ExecuteLane,
        TwinPhase::RecordOutcome,
        TwinPhase::EvaluateFallback,
        TwinPhase::SafeMode,
    ];
    assert_eq!(spec.states, expected);
}

#[test]
fn default_spec_variable_domains_cover_all_needed_domains() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let domains: BTreeSet<TwinStateDomain> = spec.variables.iter().map(|v| v.domain).collect();
    assert!(domains.contains(&TwinStateDomain::Workload));
    assert!(domains.contains(&TwinStateDomain::Risk));
    assert!(domains.contains(&TwinStateDomain::Policy));
    assert!(domains.contains(&TwinStateDomain::Lane));
    assert!(domains.contains(&TwinStateDomain::Outcome));
    assert!(domains.contains(&TwinStateDomain::Regime));
    assert!(domains.contains(&TwinStateDomain::Resource));
    assert!(domains.contains(&TwinStateDomain::Replay));
    assert!(domains.contains(&TwinStateDomain::Calibration));
}

#[test]
fn default_spec_variable_signal_sources_cover_multiple_sources() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let sources: BTreeSet<TwinSignalSource> = spec.variables.iter().map(|v| v.source).collect();
    assert!(
        sources.len() >= 5,
        "should use at least 5 distinct signal sources"
    );
}

#[test]
fn default_spec_all_variables_are_observable() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    for variable in &spec.variables {
        assert!(
            variable.observable,
            "default spec variable '{}' should be observable",
            variable.id
        );
    }
}

#[test]
fn default_spec_transition_priorities_are_strictly_increasing() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let priorities: Vec<u16> = spec
        .transitions
        .iter()
        .map(|t| t.deterministic_priority)
        .collect();
    for window in priorities.windows(2) {
        assert!(
            window[0] < window[1],
            "priorities should be strictly increasing: {} >= {}",
            window[0],
            window[1]
        );
    }
}

#[test]
fn default_spec_transition_ids_all_start_with_transition_prefix() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    for transition in &spec.transitions {
        assert!(
            transition.id.starts_with("transition_"),
            "transition id '{}' should start with 'transition_'",
            transition.id
        );
    }
}

#[test]
fn default_spec_assumption_ids_all_start_with_assumption_prefix() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    for assumption in &spec.assumptions {
        assert!(
            assumption.id.starts_with("assumption_"),
            "assumption id '{}' should start with 'assumption_'",
            assumption.id
        );
    }
}

#[test]
fn default_spec_falsification_hooks_all_reference_valid_assumptions() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let assumption_ids: BTreeSet<&str> = spec.assumptions.iter().map(|a| a.id.as_str()).collect();
    for hook in &spec.falsification_hooks {
        assert!(
            assumption_ids.contains(hook.assumption_id.as_str()),
            "hook '{}' references unknown assumption '{}'",
            hook.monitor_id,
            hook.assumption_id
        );
    }
}

#[test]
fn default_spec_falsification_hooks_all_reference_valid_variables() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let variable_ids: BTreeSet<&str> = spec.variables.iter().map(|v| v.id.as_str()).collect();
    for hook in &spec.falsification_hooks {
        assert!(
            variable_ids.contains(hook.variable_id.as_str()),
            "hook '{}' references unknown variable '{}'",
            hook.monitor_id,
            hook.variable_id
        );
    }
}

#[test]
fn default_spec_assumption_categories_cover_multiple_categories() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let categories: BTreeSet<String> = spec
        .assumptions
        .iter()
        .map(|a| format!("{:?}", a.category))
        .collect();
    assert!(
        categories.len() >= 3,
        "should have at least 3 distinct assumption categories, got {:?}",
        categories
    );
}

#[test]
fn default_spec_assumption_violation_severities_cover_multiple_levels() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let severities: BTreeSet<String> = spec
        .assumptions
        .iter()
        .map(|a| format!("{:?}", a.violation_severity))
        .collect();
    assert!(
        severities.len() >= 2,
        "should have at least 2 distinct violation severities, got {:?}",
        severities
    );
}

#[test]
fn default_spec_assumptions_have_nonempty_predicate_hashes() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    for assumption in &spec.assumptions {
        assert!(
            assumption.predicate_hash.starts_with("sha256:"),
            "assumption '{}' predicate_hash should start with 'sha256:', got '{}'",
            assumption.id,
            assumption.predicate_hash
        );
    }
}

#[test]
fn default_spec_measurement_contracts_have_nonempty_evidence_components() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    for contract in &spec.measurement_contracts {
        assert!(
            !contract.evidence_component.is_empty(),
            "measurement contract for '{}' should have non-empty evidence_component",
            contract.variable_id
        );
    }
}

#[test]
fn default_spec_recommended_adjustment_set_is_subset_of_variables() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let variable_ids: BTreeSet<&str> = spec.variables.iter().map(|v| v.id.as_str()).collect();
    for adjusted in &spec.recommended_adjustment_set {
        assert!(
            variable_ids.contains(adjusted.as_str()),
            "adjustment variable '{}' should exist in variables list",
            adjusted
        );
    }
}

// ── Clone and Eq behavior ───────────────────────────────────

#[test]
fn twin_state_domain_clone_eq() {
    let domain = TwinStateDomain::Lane;
    let cloned = domain.clone();
    assert_eq!(domain, cloned);
}

#[test]
fn twin_signal_source_clone_eq() {
    let source = TwinSignalSource::CausalReplay;
    let cloned = source.clone();
    assert_eq!(source, cloned);
}

#[test]
fn twin_phase_clone_eq() {
    let phase = TwinPhase::EvaluateFallback;
    let cloned = phase.clone();
    assert_eq!(phase, cloned);
}

#[test]
fn twin_transition_trigger_clone_eq() {
    let trigger = TwinTransitionTrigger::OperatorOverride;
    let cloned = trigger.clone();
    assert_eq!(trigger, cloned);
}

#[test]
fn semantic_twin_specification_clone_eq() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let cloned = spec.clone();
    assert_eq!(spec, cloned);
    assert_eq!(spec.deterministic_digest(), cloned.deterministic_digest());
}

// ── Hash derivation usable in BTreeSet ──────────────────────

#[test]
fn twin_state_domain_usable_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(TwinStateDomain::Workload);
    set.insert(TwinStateDomain::Risk);
    set.insert(TwinStateDomain::Workload); // duplicate
    assert_eq!(set.len(), 2);
}

#[test]
fn twin_phase_usable_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(TwinPhase::SafeMode);
    set.insert(TwinPhase::SelectLane);
    set.insert(TwinPhase::SafeMode); // duplicate
    assert_eq!(set.len(), 2);
}

#[test]
fn twin_transition_trigger_usable_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(TwinTransitionTrigger::GuardrailTriggered);
    set.insert(TwinTransitionTrigger::OperatorOverride);
    set.insert(TwinTransitionTrigger::GuardrailTriggered); // duplicate
    assert_eq!(set.len(), 2);
}

// ── Debug formatting ────────────────────────────────────────

#[test]
fn twin_signal_source_debug_distinct_all_variants() {
    let all = [
        TwinSignalSource::RuntimeDecisionCore,
        TwinSignalSource::RuntimeDecisionTheory,
        TwinSignalSource::CausalReplay,
        TwinSignalSource::FrirIr2,
        TwinSignalSource::FrirIr3,
        TwinSignalSource::ObservabilityChannel,
        TwinSignalSource::EvidenceLedger,
        TwinSignalSource::OperatorInput,
        TwinSignalSource::EnvironmentTelemetry,
    ];
    let set: BTreeSet<String> = all.iter().map(|s| format!("{s:?}")).collect();
    assert_eq!(set.len(), all.len());
}

#[test]
fn twin_transition_trigger_debug_distinct_all_variants() {
    let all = [
        TwinTransitionTrigger::ObservationCommitted,
        TwinTransitionTrigger::PosteriorUpdated,
        TwinTransitionTrigger::DecisionCommitted,
        TwinTransitionTrigger::ExecutionCompleted,
        TwinTransitionTrigger::OutcomeRecorded,
        TwinTransitionTrigger::GuardrailTriggered,
        TwinTransitionTrigger::OperatorOverride,
        TwinTransitionTrigger::ReplayCounterfactual,
    ];
    let set: BTreeSet<String> = all.iter().map(|t| format!("{t:?}")).collect();
    assert_eq!(set.len(), all.len());
}

#[test]
fn twin_spec_error_debug_is_non_empty_for_all_variants() {
    let errors = vec![
        TwinSpecError::Scm("err".to_string()),
        TwinSpecError::InvalidSchemaVersion("v".to_string()),
        TwinSpecError::DuplicateVariable("x".to_string()),
        TwinSpecError::UnknownVariable("x".to_string()),
        TwinSpecError::DuplicateTransition("x".to_string()),
        TwinSpecError::MissingOutcomeVariable("x".to_string()),
        TwinSpecError::MissingRequiredVariable {
            variable_id: "x".to_string(),
        },
        TwinSpecError::MissingSnapshotValue {
            variable_id: "x".to_string(),
        },
    ];
    for err in &errors {
        let dbg = format!("{err:?}");
        assert!(!dbg.is_empty(), "debug should be non-empty for {err:?}");
    }
}

// ── Spec digest behavior ────────────────────────────────────

#[test]
fn spec_deterministic_digest_length_is_consistent() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let digest = spec.deterministic_digest();
    // sha256: prefix (7 chars) + 64 hex chars = 71 total
    assert_eq!(digest.len(), 7 + 64);
}

#[test]
fn snapshot_deterministic_digest_length_is_consistent() {
    let snapshot = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    let digest = snapshot.deterministic_digest();
    assert_eq!(digest.len(), 7 + 64);
}

// ── Measurement contract edge cases ─────────────────────────

#[test]
fn measurement_contract_with_equal_min_max_is_valid() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    spec.measurement_contracts.push(TwinMeasurementContract {
        variable_id: "workload_complexity".to_string(),
        required: false,
        min_value_millionths: Some(500_000),
        max_value_millionths: Some(500_000),
        max_staleness_ticks: 1,
        evidence_component: "test".to_string(),
    });
    spec.validate().expect("equal min/max should be valid");
}

#[test]
fn measurement_contract_serde_with_none_bounds() {
    let contract = TwinMeasurementContract {
        variable_id: "unbounded_var".to_string(),
        required: false,
        min_value_millionths: None,
        max_value_millionths: None,
        max_staleness_ticks: 0,
        evidence_component: "test".to_string(),
    };
    let json = serde_json::to_string(&contract).expect("serialize");
    let recovered: TwinMeasurementContract = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(contract, recovered);
}

// ── Constants stability ─────────────────────────────────────

#[test]
fn schema_version_constant_contains_v1() {
    assert!(
        SEMANTIC_TWIN_SCHEMA_VERSION.contains(".v1"),
        "schema version should contain '.v1'"
    );
}

#[test]
fn schema_version_constant_and_component_are_distinct() {
    assert_ne!(SEMANTIC_TWIN_SCHEMA_VERSION, SEMANTIC_TWIN_COMPONENT);
}

// ── Transition guard assumptions ────────────────────────────

#[test]
fn default_spec_some_transitions_have_guard_assumptions() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let with_guards = spec
        .transitions
        .iter()
        .filter(|t| !t.guard_assumptions.is_empty())
        .count();
    assert!(
        with_guards >= 4,
        "at least 4 transitions should have guard assumptions, got {}",
        with_guards
    );
}

#[test]
fn default_spec_safe_mode_transition_has_no_guard_assumptions() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let fallback_to_safe = spec
        .transitions
        .iter()
        .find(|t| t.id == "transition_fallback_to_safe_mode")
        .expect("should find fallback to safe mode transition");
    assert!(
        fallback_to_safe.guard_assumptions.is_empty(),
        "fallback to safe mode should have no guard assumptions (fail-closed)"
    );
}

// ── Assumption dependency wiring ────────────────────────────

#[test]
fn default_spec_assumptions_have_non_empty_dependencies() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    for assumption in &spec.assumptions {
        assert!(
            !assumption.dependencies.is_empty(),
            "assumption '{}' should have at least one dependency",
            assumption.id
        );
    }
}

#[test]
fn default_spec_assumption_dependencies_reference_valid_variables() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let variable_ids: BTreeSet<&str> = spec.variables.iter().map(|v| v.id.as_str()).collect();
    for assumption in &spec.assumptions {
        for dep in &assumption.dependencies {
            assert!(
                variable_ids.contains(dep.as_str()),
                "assumption '{}' has dependency '{}' not found in variables",
                assumption.id,
                dep
            );
        }
    }
}

// ── Causal model integration ────────────────────────────────

#[test]
fn default_spec_causal_model_has_treatment_and_outcome_nodes() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    assert!(spec.causal_model.node(&spec.treatment_variable).is_some());
    assert!(spec.causal_model.node(&spec.outcome_variable).is_some());
}

#[test]
fn default_spec_causal_model_adjustment_set_nodes_exist_in_model() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    for adj in &spec.recommended_adjustment_set {
        assert!(
            spec.causal_model.node(adj).is_some(),
            "adjustment variable '{}' should exist in causal model",
            adj
        );
    }
}

#[test]
fn default_spec_backdoor_criterion_adjustment_set_matches_recommended() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
    let backdoor = spec
        .causal_model
        .backdoor_criterion(&spec.treatment_variable, &spec.outcome_variable)
        .expect("backdoor criterion");
    assert_eq!(backdoor.adjustment_set, spec.recommended_adjustment_set);
}
