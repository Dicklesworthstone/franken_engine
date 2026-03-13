//! Enrichment integration tests for `semantic_twin_state_space`.
//!
//! Supplements base tests with deeper coverage of: specification validation
//! edges, snapshot validation, digest determinism, to_assumption_ledger
//! conversion, serde roundtrips for compound types, Display formatting,
//! and error edge cases.

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

use frankenengine_engine::semantic_twin_state_space::{
    SEMANTIC_TWIN_COMPONENT, SEMANTIC_TWIN_SCHEMA_VERSION, SemanticTwinSpecification,
    TwinFalsificationHook, TwinMeasurementContract, TwinPhase, TwinSignalSource, TwinSpecError,
    TwinStateDomain, TwinStateSnapshot, TwinStateVariableSpec, TwinTransitionSpec,
    TwinTransitionTrigger,
};

use frankenengine_engine::assumptions_ledger::{MonitorKind, MonitorOp};

// ===========================================================================
// A. Enum Display uniqueness (4 tests)
// ===========================================================================

#[test]
fn enrichment_state_domain_debug_all_distinct() {
    let domains = [
        TwinStateDomain::Workload,
        TwinStateDomain::Risk,
        TwinStateDomain::Policy,
        TwinStateDomain::Lane,
        TwinStateDomain::Outcome,
        TwinStateDomain::Regime,
        TwinStateDomain::Resource,
        TwinStateDomain::Replay,
        TwinStateDomain::Calibration,
    ];
    let mut displays = BTreeSet::new();
    for d in &domains {
        let s = format!("{d:?}");
        assert!(!s.is_empty());
        displays.insert(s);
    }
    assert_eq!(displays.len(), domains.len());
}

#[test]
fn enrichment_signal_source_debug_all_distinct() {
    let sources = [
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
    let mut displays = BTreeSet::new();
    for s in &sources {
        displays.insert(format!("{s:?}"));
    }
    assert_eq!(displays.len(), sources.len());
}

#[test]
fn enrichment_phase_debug_all_distinct() {
    let phases = [
        TwinPhase::ObserveWorkload,
        TwinPhase::UpdateRiskBelief,
        TwinPhase::SelectLane,
        TwinPhase::ExecuteLane,
        TwinPhase::RecordOutcome,
        TwinPhase::EvaluateFallback,
        TwinPhase::SafeMode,
    ];
    let mut displays = BTreeSet::new();
    for p in &phases {
        displays.insert(format!("{p:?}"));
    }
    assert_eq!(displays.len(), phases.len());
}

#[test]
fn enrichment_trigger_debug_all_distinct() {
    let triggers = [
        TwinTransitionTrigger::ObservationCommitted,
        TwinTransitionTrigger::PosteriorUpdated,
        TwinTransitionTrigger::DecisionCommitted,
        TwinTransitionTrigger::ExecutionCompleted,
        TwinTransitionTrigger::OutcomeRecorded,
        TwinTransitionTrigger::GuardrailTriggered,
        TwinTransitionTrigger::OperatorOverride,
        TwinTransitionTrigger::ReplayCounterfactual,
    ];
    let mut displays = BTreeSet::new();
    for t in &triggers {
        displays.insert(format!("{t:?}"));
    }
    assert_eq!(displays.len(), triggers.len());
}

// ===========================================================================
// B. TwinStateSnapshot edges (6 tests)
// ===========================================================================

#[test]
fn enrichment_snapshot_empty_values_digest_deterministic() {
    let s1 = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    let s2 = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    assert_eq!(s1.deterministic_digest(), s2.deterministic_digest());
}

#[test]
fn enrichment_snapshot_digest_varies_by_trace_id() {
    let s1 = TwinStateSnapshot::new("trace-a", "d", "p", 1, 1);
    let s2 = TwinStateSnapshot::new("trace-b", "d", "p", 1, 1);
    assert_ne!(s1.deterministic_digest(), s2.deterministic_digest());
}

#[test]
fn enrichment_snapshot_digest_varies_by_epoch() {
    let s1 = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    let s2 = TwinStateSnapshot::new("t", "d", "p", 2, 1);
    assert_ne!(s1.deterministic_digest(), s2.deterministic_digest());
}

#[test]
fn enrichment_snapshot_digest_varies_by_tick() {
    let s1 = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    let s2 = TwinStateSnapshot::new("t", "d", "p", 1, 2);
    assert_ne!(s1.deterministic_digest(), s2.deterministic_digest());
}

#[test]
fn enrichment_snapshot_multiple_values_order_independent() {
    // BTreeMap is sorted, so insertion order shouldn't matter
    let mut s1 = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    s1.upsert_value("alpha", 100);
    s1.upsert_value("beta", 200);

    let mut s2 = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    s2.upsert_value("beta", 200);
    s2.upsert_value("alpha", 100);

    assert_eq!(s1.deterministic_digest(), s2.deterministic_digest());
}

#[test]
fn enrichment_snapshot_clone_eq() {
    let mut snap = TwinStateSnapshot::new("t", "d", "p", 5, 10);
    snap.upsert_value("var", 42);
    let clone = snap.clone();
    assert_eq!(snap, clone);
}

// ===========================================================================
// C. SemanticTwinSpecification lane_decision_default (5 tests)
// ===========================================================================

#[test]
fn enrichment_lane_decision_default_valid() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert!(spec.validate().is_ok());
}

#[test]
fn enrichment_lane_decision_default_schema_version() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert_eq!(spec.schema_version, SEMANTIC_TWIN_SCHEMA_VERSION);
}

#[test]
fn enrichment_lane_decision_default_component() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert_eq!(spec.component, SEMANTIC_TWIN_COMPONENT);
}

#[test]
fn enrichment_lane_decision_default_has_variables() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert!(!spec.variables.is_empty());
    // Treatment and outcome variables should exist
    assert!(
        spec.variables
            .iter()
            .any(|v| v.id == spec.treatment_variable),
        "treatment variable should exist in variables"
    );
    assert!(
        spec.variables.iter().any(|v| v.id == spec.outcome_variable),
        "outcome variable should exist in variables"
    );
}

#[test]
fn enrichment_lane_decision_default_has_transitions() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert!(!spec.transitions.is_empty());
}

// ===========================================================================
// D. Specification validation (6 tests)
// ===========================================================================

#[test]
fn enrichment_validate_duplicate_variable_detected() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    // Add a duplicate variable
    let dup = spec.variables[0].clone();
    spec.variables.push(dup);
    let err = spec.validate().unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("duplicate variable"),
        "should detect duplicate variable: {msg}"
    );
}

#[test]
fn enrichment_validate_duplicate_transition_detected() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    if !spec.transitions.is_empty() {
        let dup = spec.transitions[0].clone();
        spec.transitions.push(dup);
        let err = spec.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("duplicate transition"),
            "should detect dup transition: {msg}"
        );
    }
}

#[test]
fn enrichment_validate_unknown_treatment_variable() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    spec.treatment_variable = "nonexistent_variable_xyz".to_string();
    let err = spec.validate().unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("unknown variable") || msg.contains("treatment"),
        "{msg}"
    );
}

#[test]
fn enrichment_validate_unknown_outcome_variable() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    spec.outcome_variable = "nonexistent_outcome_xyz".to_string();
    let err = spec.validate().unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("unknown variable") || msg.contains("outcome"),
        "{msg}"
    );
}

#[test]
fn enrichment_validate_invalid_schema_version() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    spec.schema_version = "invalid-schema".to_string();
    let err = spec.validate().unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("schema"), "{msg}");
}

#[test]
fn enrichment_validate_duplicate_assumption_detected() {
    let mut spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    if !spec.assumptions.is_empty() {
        let dup = spec.assumptions[0].clone();
        spec.assumptions.push(dup);
        let err = spec.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("duplicate assumption"),
            "should detect dup assumption: {msg}"
        );
    }
}

// ===========================================================================
// E. Snapshot validation (4 tests)
// ===========================================================================

#[test]
fn enrichment_validate_snapshot_matching_vars_passes() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let mut snap = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    // Add all required variables with valid values
    for mc in &spec.measurement_contracts {
        if mc.required {
            snap.upsert_value(&mc.variable_id, 500_000); // nominal value
        }
    }
    let result = spec.validate_snapshot(&snap);
    assert!(
        result.is_ok(),
        "snapshot with all required vars should pass: {result:?}"
    );
}

#[test]
fn enrichment_validate_snapshot_missing_required_var_fails() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let snap = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    // Empty snapshot should fail if any measurement_contracts are required
    let has_required = spec.measurement_contracts.iter().any(|mc| mc.required);
    if has_required {
        let err = spec.validate_snapshot(&snap);
        assert!(
            err.is_err(),
            "empty snapshot should fail when required vars missing"
        );
    }
}

#[test]
fn enrichment_validate_snapshot_out_of_range_fails() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let mut snap = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    // Find a bounded measurement contract and set value outside range
    for mc in &spec.measurement_contracts {
        if let Some(max_val) = mc.max_value_millionths {
            snap.upsert_value(&mc.variable_id, max_val + 1_000_000);
            break;
        }
    }
    // Add remaining required vars at nominal
    for mc in &spec.measurement_contracts {
        if mc.required && !snap.values_millionths.contains_key(&mc.variable_id) {
            snap.upsert_value(&mc.variable_id, 500_000);
        }
    }
    // If we found a bounded contract, this should fail
    let has_bounded = spec
        .measurement_contracts
        .iter()
        .any(|mc| mc.max_value_millionths.is_some());
    if has_bounded {
        let result = spec.validate_snapshot(&snap);
        assert!(result.is_err(), "out-of-range value should fail validation");
    }
}

#[test]
fn enrichment_validate_snapshot_unknown_var_rejected() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let mut snap = TwinStateSnapshot::new("t", "d", "p", 1, 1);
    // Add all required vars
    for mc in &spec.measurement_contracts {
        if mc.required {
            snap.upsert_value(&mc.variable_id, 500_000);
        }
    }
    // Add an extra variable not in the spec
    snap.upsert_value("totally_unknown_variable", 42);
    // Unknown vars should be rejected
    let result = spec.validate_snapshot(&snap);
    assert!(result.is_err(), "unknown variable should fail validation");
}

// ===========================================================================
// F. Specification deterministic digest (3 tests)
// ===========================================================================

#[test]
fn enrichment_spec_digest_deterministic() {
    let s1 = SemanticTwinSpecification::lane_decision_default().unwrap();
    let s2 = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert_eq!(s1.deterministic_digest(), s2.deterministic_digest());
}

#[test]
fn enrichment_spec_digest_not_empty() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let digest = spec.deterministic_digest();
    assert!(!digest.is_empty());
}

#[test]
fn enrichment_spec_digest_hex_format() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let digest = spec.deterministic_digest();
    assert!(
        digest.starts_with("sha256:"),
        "digest should have sha256 prefix: {digest}"
    );
    let hex_part = &digest["sha256:".len()..];
    assert!(
        hex_part.chars().all(|c| c.is_ascii_hexdigit()),
        "digest hex part should be hex: {hex_part}"
    );
}

// ===========================================================================
// G. to_assumption_ledger conversion (4 tests)
// ===========================================================================

#[test]
fn enrichment_to_assumption_ledger_succeeds() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let ledger = spec.to_assumption_ledger("dec-1", 1);
    assert!(ledger.is_ok(), "conversion should succeed: {ledger:?}");
}

#[test]
fn enrichment_to_assumption_ledger_assumption_count_matches() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let ledger = spec.to_assumption_ledger("my-dec", 42).unwrap();
    assert_eq!(ledger.assumptions().len(), spec.assumptions.len());
}

#[test]
fn enrichment_to_assumption_ledger_has_monitors() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    if !spec.falsification_hooks.is_empty() {
        let ledger = spec.to_assumption_ledger("d", 1).unwrap();
        assert!(
            !ledger.monitors().is_empty(),
            "should have monitors from hooks"
        );
    }
}

#[test]
fn enrichment_to_assumption_ledger_has_assumptions() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    if !spec.assumptions.is_empty() {
        let ledger = spec.to_assumption_ledger("d", 1).unwrap();
        assert!(!ledger.assumptions().is_empty(), "should have assumptions");
    }
}

// ===========================================================================
// H. Serde roundtrips for compound types (5 tests)
// ===========================================================================

#[test]
fn enrichment_variable_spec_serde_roundtrip() {
    let vs = TwinStateVariableSpec {
        id: "workload_complexity".to_string(),
        label: "Workload Complexity".to_string(),
        domain: TwinStateDomain::Workload,
        source: TwinSignalSource::RuntimeDecisionCore,
        observable: true,
        unit: "millionths".to_string(),
        description: "complexity score".to_string(),
    };
    let json = serde_json::to_string(&vs).unwrap();
    let back: TwinStateVariableSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back, vs);
}

#[test]
fn enrichment_transition_spec_serde_roundtrip() {
    let ts = TwinTransitionSpec {
        id: "observe_to_risk".to_string(),
        from_phase: TwinPhase::ObserveWorkload,
        to_phase: TwinPhase::UpdateRiskBelief,
        trigger: TwinTransitionTrigger::ObservationCommitted,
        deterministic_priority: 1,
        guard_assumptions: vec!["assumption_a".to_string()],
        description: "transition desc".to_string(),
    };
    let json = serde_json::to_string(&ts).unwrap();
    let back: TwinTransitionSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ts);
}

#[test]
fn enrichment_measurement_contract_serde_roundtrip() {
    let mc = TwinMeasurementContract {
        variable_id: "risk_score".to_string(),
        required: true,
        min_value_millionths: Some(0),
        max_value_millionths: Some(1_000_000),
        max_staleness_ticks: 100,
        evidence_component: "runtime_decision_core".to_string(),
    };
    let json = serde_json::to_string(&mc).unwrap();
    let back: TwinMeasurementContract = serde_json::from_str(&json).unwrap();
    assert_eq!(back, mc);
}

#[test]
fn enrichment_falsification_hook_serde_roundtrip() {
    let fh = TwinFalsificationHook {
        monitor_id: "mon-1".to_string(),
        assumption_id: "asm-1".to_string(),
        variable_id: "var-1".to_string(),
        kind: MonitorKind::Threshold,
        op: MonitorOp::Ge,
        threshold_millionths: 800_000,
        trigger_count: 3,
    };
    let json = serde_json::to_string(&fh).unwrap();
    let back: TwinFalsificationHook = serde_json::from_str(&json).unwrap();
    assert_eq!(back, fh);
}

#[test]
fn enrichment_full_spec_serde_roundtrip() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let json = serde_json::to_string(&spec).unwrap();
    let back: SemanticTwinSpecification = serde_json::from_str(&json).unwrap();
    assert_eq!(back, spec);
}

// ===========================================================================
// I. Error variants (4 tests)
// ===========================================================================

#[test]
fn enrichment_error_serde_all_variants() {
    let errors = [
        TwinSpecError::DuplicateVariable("x".into()),
        TwinSpecError::UnknownVariable("y".into()),
        TwinSpecError::InvalidSchemaVersion("bad".into()),
        TwinSpecError::DuplicateTransition("t".into()),
        TwinSpecError::DuplicateAssumption("a".into()),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: TwinSpecError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

#[test]
fn enrichment_error_display_all_non_empty() {
    let errors = [
        TwinSpecError::DuplicateVariable("x".into()),
        TwinSpecError::UnknownVariable("y".into()),
        TwinSpecError::InvalidSchemaVersion("bad".into()),
        TwinSpecError::DuplicateTransition("t".into()),
        TwinSpecError::DuplicateAssumption("a".into()),
    ];
    let mut displays = BTreeSet::new();
    for err in &errors {
        let s = format!("{err}");
        assert!(!s.is_empty());
        displays.insert(s);
    }
    assert_eq!(
        displays.len(),
        errors.len(),
        "all error displays should be distinct"
    );
}

#[test]
fn enrichment_error_debug_not_empty() {
    let err = TwinSpecError::DuplicateVariable("x".into());
    let d = format!("{err:?}");
    assert!(d.contains("DuplicateVariable"));
}

#[test]
fn enrichment_error_implements_std_error() {
    let err = TwinSpecError::UnknownVariable("y".into());
    let _: &dyn std::error::Error = &err;
}

// ===========================================================================
// J. Specification structure (3 tests)
// ===========================================================================

#[test]
fn enrichment_spec_states_not_empty() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    assert!(!spec.states.is_empty(), "spec should declare states");
}

#[test]
fn enrichment_spec_variable_ids_unique() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let mut ids = BTreeSet::new();
    for v in &spec.variables {
        assert!(ids.insert(&v.id), "duplicate variable id: {}", v.id);
    }
}

#[test]
fn enrichment_spec_transition_ids_unique() {
    let spec = SemanticTwinSpecification::lane_decision_default().unwrap();
    let mut ids = BTreeSet::new();
    for t in &spec.transitions {
        assert!(ids.insert(&t.id), "duplicate transition id: {}", t.id);
    }
}
