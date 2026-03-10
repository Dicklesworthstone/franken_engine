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
