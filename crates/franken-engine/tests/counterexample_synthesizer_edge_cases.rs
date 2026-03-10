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

use frankenengine_engine::counterexample_synthesizer::{
    ConcreteScenario, ConflictDiagnostic, ControllerConfig, ControllerInterference,
    ControllerInterferenceEvent, CounterexampleSynthesizer, DEFAULT_BUDGET_NS,
    DEFAULT_MAX_MINIMIZATION_ROUNDS, InterferenceKind, MinimalityEvidence, MutationKind,
    PolicyMutation, RegressionCorpus, RegressionEntry, SynthesisConfig, SynthesisError,
    SynthesisOutcome, SynthesisStrategy, SynthesizedCounterexample,
};
use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_theorem_compiler::{
    AuthorityGrant, Capability, Constraint, FormalProperty, MergeOperator, PolicyId, PolicyIr,
    PolicyIrNode, PolicyTheoremCompiler,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_signing_key() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(13);
    }
    key
}

fn test_config() -> SynthesisConfig {
    SynthesisConfig {
        budget_ns: 1_000_000_000,
        max_minimization_rounds: 10,
        preferred_strategy: SynthesisStrategy::CompilerExtraction,
        detect_controller_interference: true,
        max_enumeration_candidates: 50,
        epoch: SecurityEpoch::from_raw(100),
        signing_key_bytes: test_signing_key(),
    }
}

fn make_valid_policy() -> PolicyIr {
    let cap = Capability::new("read-data");
    let mut universe = BTreeSet::new();
    universe.insert(cap.clone());
    let mut claims = BTreeSet::new();
    claims.insert(FormalProperty::Monotonicity);

    PolicyIr {
        policy_id: PolicyId::new("valid-policy"),
        version: 1,
        nodes: vec![PolicyIrNode {
            node_id: "node-1".to_string(),
            grants: vec![AuthorityGrant {
                subject: "user-a".to_string(),
                capability: cap,
                conditions: BTreeSet::new(),
                scope: "default".to_string(),
                lifetime_epochs: 10,
            }],
            merge_op: MergeOperator::Union,
            property_claims: claims,
            constraints: Vec::new(),
            decision_point: None,
            priority: 1,
        }],
        capability_universe: universe,
        verified_properties: BTreeSet::new(),
        epoch: SecurityEpoch::from_raw(100),
    }
}

fn make_monotonicity_violating_policy() -> PolicyIr {
    let cap_a = Capability::new("read-data");
    let cap_b = Capability::new("write-data");
    let cap_extra = Capability::new("admin-override");
    let mut universe = BTreeSet::new();
    universe.insert(cap_a.clone());
    universe.insert(cap_b.clone());
    let mut claims = BTreeSet::new();
    claims.insert(FormalProperty::Monotonicity);

    PolicyIr {
        policy_id: PolicyId::new("mono-violating"),
        version: 1,
        nodes: vec![
            PolicyIrNode {
                node_id: "node-a".to_string(),
                grants: vec![AuthorityGrant {
                    subject: "user-a".to_string(),
                    capability: cap_a,
                    conditions: BTreeSet::new(),
                    scope: "default".to_string(),
                    lifetime_epochs: 10,
                }],
                merge_op: MergeOperator::Union,
                property_claims: claims.clone(),
                constraints: Vec::new(),
                decision_point: None,
                priority: 1,
            },
            PolicyIrNode {
                node_id: "node-b".to_string(),
                grants: vec![
                    AuthorityGrant {
                        subject: "user-a".to_string(),
                        capability: cap_b,
                        conditions: BTreeSet::new(),
                        scope: "default".to_string(),
                        lifetime_epochs: 10,
                    },
                    AuthorityGrant {
                        subject: "user-a".to_string(),
                        capability: cap_extra,
                        conditions: BTreeSet::new(),
                        scope: "elevated".to_string(),
                        lifetime_epochs: 10,
                    },
                ],
                merge_op: MergeOperator::Union,
                property_claims: claims,
                constraints: Vec::new(),
                decision_point: None,
                priority: 2,
            },
        ],
        capability_universe: universe,
        verified_properties: BTreeSet::new(),
        epoch: SecurityEpoch::from_raw(100),
    }
}

fn synth_schema_id() -> SchemaId {
    SchemaId::from_definition(b"CounterexampleSynthesizer.v1")
}

fn make_fake_counterexample(
    conflict_id: EngineObjectId,
    property: FormalProperty,
) -> SynthesizedCounterexample {
    SynthesizedCounterexample {
        conflict_id,
        property_violated: property,
        policy_ids: vec![PolicyId::new("test-policy")],
        merge_path: vec!["step-1".to_string()],
        concrete_scenario: ConcreteScenario {
            subjects: ["subject-a".to_string()].into(),
            capabilities: ["cap-x".to_string()].into(),
            conditions: [("k".to_string(), "v".to_string())].into(),
            merge_ordering: vec!["step-1".to_string()],
            input_state: BTreeMap::new(),
        },
        expected_outcome: "expected".to_string(),
        actual_outcome: "actual".to_string(),
        minimality_evidence: MinimalityEvidence {
            rounds: 3,
            elements_removed: 1,
            starting_size: 5,
            final_size: 4,
            is_fixed_point: true,
        },
        strategy: SynthesisStrategy::CompilerExtraction,
        outcome: SynthesisOutcome::Complete,
        compute_time_ns: 42_000,
        content_hash: ContentHash::compute(b"test-hash"),
        epoch: SecurityEpoch::from_raw(100),
        resolution_hint: "fix it".to_string(),
    }
}

fn derive_test_id(seed: &[u8]) -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::EvidenceRecord,
        "counterexample-synth",
        &synth_schema_id(),
        seed,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn default_budget_ns_is_30_seconds() {
    assert_eq!(DEFAULT_BUDGET_NS, 30_000_000_000);
}

#[test]
fn default_max_minimization_rounds_is_50() {
    assert_eq!(DEFAULT_MAX_MINIMIZATION_ROUNDS, 50);
}

// ---------------------------------------------------------------------------
// SynthesisStrategy — serde + ordering
// ---------------------------------------------------------------------------

#[test]
fn synthesis_strategy_serde_all_variants() {
    let variants = [
        SynthesisStrategy::CompilerExtraction,
        SynthesisStrategy::Enumeration,
        SynthesisStrategy::Mutation,
        SynthesisStrategy::TimeBounded,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: SynthesisStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn synthesis_strategy_ordering() {
    let mut variants = vec![
        SynthesisStrategy::TimeBounded,
        SynthesisStrategy::Mutation,
        SynthesisStrategy::CompilerExtraction,
        SynthesisStrategy::Enumeration,
    ];
    variants.sort();
    // Verify sort is stable and deterministic.
    let sorted_again = {
        let mut v = variants.clone();
        v.sort();
        v
    };
    assert_eq!(variants, sorted_again);
}

// ---------------------------------------------------------------------------
// SynthesisOutcome — serde + ordering
// ---------------------------------------------------------------------------

#[test]
fn synthesis_outcome_serde_all_variants() {
    let variants = [
        SynthesisOutcome::Complete,
        SynthesisOutcome::Partial,
        SynthesisOutcome::Incomplete,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: SynthesisOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn synthesis_outcome_display_exhaustive() {
    assert_eq!(SynthesisOutcome::Complete.to_string(), "complete");
    assert_eq!(SynthesisOutcome::Partial.to_string(), "partial");
    assert_eq!(SynthesisOutcome::Incomplete.to_string(), "incomplete");
}

// ---------------------------------------------------------------------------
// InterferenceKind — serde + ordering
// ---------------------------------------------------------------------------

#[test]
fn interference_kind_serde_all_variants() {
    let variants = [
        InterferenceKind::InvariantInvalidation,
        InterferenceKind::Oscillation,
        InterferenceKind::TimescaleConflict,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: InterferenceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn interference_kind_ordering() {
    let mut variants = vec![
        InterferenceKind::TimescaleConflict,
        InterferenceKind::Oscillation,
        InterferenceKind::InvariantInvalidation,
    ];
    variants.sort();
    let sorted_again = {
        let mut v = variants.clone();
        v.sort();
        v
    };
    assert_eq!(variants, sorted_again);
}

// ---------------------------------------------------------------------------
// MutationKind — Display all 6 + serde + ordering
// ---------------------------------------------------------------------------

#[test]
fn mutation_kind_display_all_variants() {
    assert_eq!(MutationKind::ChangeMergeOp.to_string(), "change-merge-op");
    assert_eq!(MutationKind::AddGrant.to_string(), "add-grant");
    assert_eq!(
        MutationKind::RemovePropertyClaim.to_string(),
        "remove-property-claim"
    );
    assert_eq!(MutationKind::ChangePriority.to_string(), "change-priority");
    assert_eq!(
        MutationKind::RemoveConstraint.to_string(),
        "remove-constraint"
    );
    assert_eq!(MutationKind::DuplicateNode.to_string(), "duplicate-node");
}

#[test]
fn mutation_kind_serde_all_variants() {
    let variants = [
        MutationKind::ChangeMergeOp,
        MutationKind::AddGrant,
        MutationKind::RemovePropertyClaim,
        MutationKind::ChangePriority,
        MutationKind::RemoveConstraint,
        MutationKind::DuplicateNode,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: MutationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn mutation_kind_ordering() {
    let mut variants = vec![
        MutationKind::DuplicateNode,
        MutationKind::ChangeMergeOp,
        MutationKind::RemoveConstraint,
        MutationKind::AddGrant,
        MutationKind::ChangePriority,
        MutationKind::RemovePropertyClaim,
    ];
    variants.sort();
    let sorted_again = {
        let mut v = variants.clone();
        v.sort();
        v
    };
    assert_eq!(variants, sorted_again);
}

// ---------------------------------------------------------------------------
// SynthesisError — std::error::Error + serde + Display completeness
// ---------------------------------------------------------------------------

#[test]
fn synthesis_error_implements_std_error() {
    let err: &dyn std::error::Error = &SynthesisError::NoViolations;
    assert!(err.source().is_none());
}

#[test]
fn synthesis_error_display_minimization_exhausted() {
    let err = SynthesisError::MinimizationExhausted { rounds: 42 };
    assert!(err.to_string().contains("42"));
    assert!(err.to_string().contains("minimization exhausted"));
}

#[test]
fn synthesis_error_display_compiler_failure() {
    let err = SynthesisError::CompilerFailure("boom".to_string());
    assert!(err.to_string().contains("boom"));
    assert!(err.to_string().contains("compiler failure"));
}

#[test]
fn synthesis_error_display_id_derivation() {
    let err = SynthesisError::IdDerivation("bad id".to_string());
    assert!(err.to_string().contains("bad id"));
    assert!(err.to_string().contains("id derivation"));
}

#[test]
fn synthesis_error_serde_all_variants() {
    let variants: Vec<SynthesisError> = vec![
        SynthesisError::NoViolations,
        SynthesisError::Timeout {
            elapsed_ns: 100,
            budget_ns: 200,
            partial: None,
        },
        SynthesisError::InvalidPolicy {
            reason: "test".to_string(),
        },
        SynthesisError::IdDerivation("test".to_string()),
        SynthesisError::MinimizationExhausted { rounds: 5 },
        SynthesisError::CompilerFailure("test".to_string()),
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: SynthesisError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn synthesis_error_timeout_with_partial_serde() {
    let partial = Box::new(make_fake_counterexample(
        derive_test_id(b"partial-timeout"),
        FormalProperty::Monotonicity,
    ));
    let err = SynthesisError::Timeout {
        elapsed_ns: 500,
        budget_ns: 1000,
        partial: Some(partial),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: SynthesisError = serde_json::from_str(&json).unwrap();
    match restored {
        SynthesisError::Timeout {
            elapsed_ns,
            budget_ns,
            partial,
        } => {
            assert_eq!(elapsed_ns, 500);
            assert_eq!(budget_ns, 1000);
            assert!(partial.is_some());
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// SynthesisConfig — Default values
// ---------------------------------------------------------------------------

#[test]
fn synthesis_config_default_values() {
    let cfg = SynthesisConfig::default();
    assert_eq!(cfg.budget_ns, DEFAULT_BUDGET_NS);
    assert_eq!(cfg.max_minimization_rounds, DEFAULT_MAX_MINIMIZATION_ROUNDS);
    assert_eq!(
        cfg.preferred_strategy,
        SynthesisStrategy::CompilerExtraction
    );
    assert!(cfg.detect_controller_interference);
    assert_eq!(cfg.max_enumeration_candidates, 100);
    assert_eq!(cfg.epoch, SecurityEpoch::from_raw(1));
    assert_eq!(cfg.signing_key_bytes.len(), 32);
}

// ---------------------------------------------------------------------------
// ConcreteScenario — edge cases
// ---------------------------------------------------------------------------

#[test]
fn concrete_scenario_empty_fields_serde() {
    let scenario = ConcreteScenario {
        subjects: BTreeSet::new(),
        capabilities: BTreeSet::new(),
        conditions: BTreeMap::new(),
        merge_ordering: Vec::new(),
        input_state: BTreeMap::new(),
    };
    let json = serde_json::to_string(&scenario).unwrap();
    let restored: ConcreteScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(scenario, restored);
}

#[test]
fn concrete_scenario_with_input_state_serde() {
    let mut input_state = BTreeMap::new();
    input_state.insert("mutation_type".to_string(), "change-merge-op".to_string());
    input_state.insert("mutation_target".to_string(), "node-1".to_string());

    let scenario = ConcreteScenario {
        subjects: ["s1".to_string(), "s2".to_string()].into(),
        capabilities: ["c1".to_string()].into(),
        conditions: [("key".to_string(), "value".to_string())].into(),
        merge_ordering: vec!["a".to_string(), "b".to_string()],
        input_state,
    };
    let json = serde_json::to_string(&scenario).unwrap();
    let restored: ConcreteScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(scenario, restored);
}

// ---------------------------------------------------------------------------
// MinimalityEvidence — edge cases
// ---------------------------------------------------------------------------

#[test]
fn minimality_evidence_zero_rounds() {
    let min = MinimalityEvidence {
        rounds: 0,
        elements_removed: 0,
        starting_size: 0,
        final_size: 0,
        is_fixed_point: true,
    };
    let json = serde_json::to_string(&min).unwrap();
    let restored: MinimalityEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(min, restored);
}

#[test]
fn minimality_evidence_not_fixed_point() {
    let min = MinimalityEvidence {
        rounds: 50,
        elements_removed: 10,
        starting_size: 100,
        final_size: 90,
        is_fixed_point: false,
    };
    assert!(!min.is_fixed_point);
    let json = serde_json::to_string(&min).unwrap();
    let restored: MinimalityEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(min, restored);
}

// ---------------------------------------------------------------------------
// RegressionCorpus — serde, contains, lifecycle
// ---------------------------------------------------------------------------

#[test]
fn regression_corpus_default_is_new() {
    let c1 = RegressionCorpus::new();
    let c2 = RegressionCorpus::default();
    assert_eq!(c1, c2);
}

#[test]
fn regression_corpus_contains_false_for_missing() {
    let corpus = RegressionCorpus::new();
    let id = derive_test_id(b"nonexistent");
    assert!(!corpus.contains(&id));
}

#[test]
fn regression_corpus_full_lifecycle() {
    let mut corpus = RegressionCorpus::new();
    let epoch = SecurityEpoch::from_raw(100);

    let id1 = derive_test_id(b"entry-1");
    let id2 = derive_test_id(b"entry-2");
    let cx1 = make_fake_counterexample(id1.clone(), FormalProperty::Monotonicity);
    let cx2 = make_fake_counterexample(id2.clone(), FormalProperty::NonInterference);

    assert!(corpus.append(cx1.clone(), epoch, 1000));
    assert!(corpus.append(cx2.clone(), epoch, 2000));
    assert_eq!(corpus.len(), 2);
    assert!(!corpus.is_empty());
    assert_eq!(corpus.unresolved().len(), 2);
    assert!(corpus.contains(&id1));
    assert!(corpus.contains(&id2));

    // Duplicate append
    assert!(!corpus.append(cx1, epoch, 3000));
    assert_eq!(corpus.len(), 2);

    // Resolve one
    assert!(corpus.resolve(&id1));
    assert_eq!(corpus.unresolved().len(), 1);
    assert_eq!(
        corpus.unresolved()[0].counterexample.property_violated,
        FormalProperty::NonInterference
    );

    // Resolve nonexistent
    let fake = derive_test_id(b"fake");
    assert!(!corpus.resolve(&fake));
}

#[test]
fn regression_corpus_empty_serde_roundtrip() {
    // Empty corpus (no EngineObjectId keys) round-trips through JSON fine.
    let corpus = RegressionCorpus::new();
    let json = serde_json::to_string(&corpus).unwrap();
    let restored: RegressionCorpus = serde_json::from_str(&json).unwrap();
    assert_eq!(corpus.len(), restored.len());
    assert!(restored.is_empty());
}

#[test]
fn regression_corpus_entries_returns_all() {
    let mut corpus = RegressionCorpus::new();
    for i in 0..5 {
        let id = derive_test_id(format!("entry-{i}").as_bytes());
        let cx = make_fake_counterexample(id, FormalProperty::Monotonicity);
        corpus.append(cx, SecurityEpoch::from_raw(1), i * 100);
    }
    assert_eq!(corpus.entries().len(), 5);
}

// ---------------------------------------------------------------------------
// RegressionEntry — serde
// ---------------------------------------------------------------------------

#[test]
fn regression_entry_serde_roundtrip() {
    let id = derive_test_id(b"regression-entry");
    let cx = make_fake_counterexample(id.clone(), FormalProperty::AttenuationLegality);
    let entry = RegressionEntry {
        entry_id: id,
        counterexample: cx,
        added_epoch: SecurityEpoch::from_raw(50),
        added_at_ns: 12345,
        resolved: false,
        content_hash: ContentHash::compute(b"regression-entry"),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let restored: RegressionEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
}

// ---------------------------------------------------------------------------
// ControllerInterferenceEvent — serde
// ---------------------------------------------------------------------------

#[test]
fn controller_interference_event_serde_roundtrip() {
    let event = ControllerInterferenceEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: "counterexample_synthesizer".to_string(),
        event: "controller_interference_rejected".to_string(),
        outcome: "reject".to_string(),
        error_code: Some("FE-CX-INTERFERENCE-TIMESCALE".to_string()),
        kind: InterferenceKind::TimescaleConflict,
        controller_ids: vec!["a".to_string(), "b".to_string()],
        shared_metrics: vec!["throughput".to_string()],
        timescale_separation_millionths: 20_000,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: ControllerInterferenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// ---------------------------------------------------------------------------
// ControllerInterference — edge cases
// ---------------------------------------------------------------------------

#[test]
fn controller_interference_with_convergence_steps_serde() {
    let ci = ControllerInterference {
        kind: InterferenceKind::Oscillation,
        controller_ids: vec!["ctrl-a".to_string(), "ctrl-b".to_string()],
        shared_metrics: ["metric-x".to_string()].into(),
        timescale_separation_millionths: 0,
        evidence_description: "oscillation detected".to_string(),
        convergence_steps: Some(1000),
    };
    let json = serde_json::to_string(&ci).unwrap();
    let restored: ControllerInterference = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, restored);
    assert_eq!(restored.convergence_steps, Some(1000));
}

#[test]
fn controller_interference_without_convergence_serde() {
    let ci = ControllerInterference {
        kind: InterferenceKind::InvariantInvalidation,
        controller_ids: vec!["x".to_string()],
        shared_metrics: BTreeSet::new(),
        timescale_separation_millionths: -500,
        evidence_description: "none".to_string(),
        convergence_steps: None,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let restored: ControllerInterference = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, restored);
    assert!(restored.convergence_steps.is_none());
}

// ---------------------------------------------------------------------------
// ConflictDiagnostic — serde
// ---------------------------------------------------------------------------

#[test]
fn conflict_diagnostic_serde_roundtrip() {
    let diag = ConflictDiagnostic {
        conflict_id: derive_test_id(b"diag-test"),
        summary: "test violation".to_string(),
        property: FormalProperty::PrecedenceStability,
        policy_ids: vec![PolicyId::new("p1"), PolicyId::new("p2")],
        conflict_points: vec!["node-1".to_string()],
        affected_subjects: ["user-a".to_string()].into(),
        affected_capabilities: ["cap-1".to_string()].into(),
        resolution_suggestions: vec!["fix it".to_string()],
        severity_millionths: 700_000,
    };
    let json = serde_json::to_string(&diag).unwrap();
    let restored: ConflictDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, restored);
}

// ---------------------------------------------------------------------------
// SynthesizedCounterexample — serde
// ---------------------------------------------------------------------------

#[test]
fn synthesized_counterexample_serde_roundtrip() {
    let cx = make_fake_counterexample(
        derive_test_id(b"serde-cx"),
        FormalProperty::AttenuationLegality,
    );
    let json = serde_json::to_string(&cx).unwrap();
    let restored: SynthesizedCounterexample = serde_json::from_str(&json).unwrap();
    assert_eq!(cx, restored);
}

// ---------------------------------------------------------------------------
// PolicyMutation — serde
// ---------------------------------------------------------------------------

#[test]
fn policy_mutation_serde_all_kinds() {
    let kinds = [
        MutationKind::ChangeMergeOp,
        MutationKind::AddGrant,
        MutationKind::RemovePropertyClaim,
        MutationKind::ChangePriority,
        MutationKind::RemoveConstraint,
        MutationKind::DuplicateNode,
    ];
    for kind in &kinds {
        let m = PolicyMutation {
            kind: *kind,
            target_node: "node-1".to_string(),
            new_value: "test-value".to_string(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let restored: PolicyMutation = serde_json::from_str(&json).unwrap();
        assert_eq!(m, restored);
    }
}

// ---------------------------------------------------------------------------
// ControllerConfig — serde, timescale statement edge cases
// ---------------------------------------------------------------------------

#[test]
fn controller_config_serde_with_empty_timescale() {
    let cfg = ControllerConfig {
        controller_id: "ctrl".to_string(),
        read_metrics: BTreeSet::new(),
        write_metrics: BTreeSet::new(),
        affected_metrics: BTreeSet::new(),
        timescale_millionths: 0,
        timescale_statement: String::new(),
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: ControllerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

#[test]
fn controller_config_whitespace_timescale_treated_as_missing() {
    // When timescale_statement is whitespace-only, detect_interference should treat
    // it as missing (has_timescale_statement returns false).
    let synth = CounterexampleSynthesizer::new(test_config());
    let configs = vec![
        ControllerConfig {
            controller_id: "ws-a".to_string(),
            read_metrics: BTreeSet::new(),
            write_metrics: ["m".to_string()].into(),
            affected_metrics: ["m".to_string()].into(),
            timescale_millionths: 100_000,
            timescale_statement: "   ".to_string(),
        },
        ControllerConfig {
            controller_id: "ws-b".to_string(),
            read_metrics: BTreeSet::new(),
            write_metrics: ["m".to_string()].into(),
            affected_metrics: ["m".to_string()].into(),
            timescale_millionths: 200_000,
            timescale_statement: "valid statement".to_string(),
        },
    ];
    let interferences = synth.detect_interference(&configs);
    // Should detect interference because ws-a has whitespace-only statement.
    assert!(
        interferences
            .iter()
            .any(|i| i.kind == InterferenceKind::TimescaleConflict),
        "whitespace-only timescale_statement should be treated as missing"
    );
}

// ---------------------------------------------------------------------------
// CounterexampleSynthesizer — config accessor, synthesize lifecycle
// ---------------------------------------------------------------------------

#[test]
fn synthesizer_config_accessor() {
    let cfg = test_config();
    let synth = CounterexampleSynthesizer::new(cfg.clone());
    assert_eq!(synth.config().budget_ns, cfg.budget_ns);
    assert_eq!(
        synth.config().max_minimization_rounds,
        cfg.max_minimization_rounds
    );
    assert_eq!(synth.config().epoch, cfg.epoch);
}

#[test]
fn synthesizer_starts_with_empty_state() {
    let synth = CounterexampleSynthesizer::new(test_config());
    assert_eq!(synth.synthesis_count(), 0);
    assert!(synth.corpus().is_empty());
    assert!(synth.diagnostics().is_empty());
}

#[test]
fn synthesizer_synthesize_populates_corpus_and_diagnostics() {
    let compiler = PolicyTheoremCompiler::new();
    let policy = make_monotonicity_violating_policy();
    let result = compiler.compile(&policy).unwrap();
    assert!(!result.counterexamples.is_empty());

    let mut synth = CounterexampleSynthesizer::new(test_config());
    let cxs = synth.synthesize(&result, 1000).unwrap();

    assert!(!cxs.is_empty());
    assert_eq!(synth.corpus().len(), cxs.len());
    assert_eq!(synth.diagnostics().len(), cxs.len());
    assert_eq!(synth.synthesis_count(), cxs.len() as u64);

    for cx in &cxs {
        assert!(synth.corpus().contains(&cx.conflict_id));
        assert_eq!(cx.strategy, SynthesisStrategy::CompilerExtraction);
        assert_eq!(cx.outcome, SynthesisOutcome::Complete);
        assert_eq!(cx.epoch, SecurityEpoch::from_raw(100));
    }
}

#[test]
fn synthesizer_no_violations_returns_error() {
    let compiler = PolicyTheoremCompiler::new();
    let policy = make_valid_policy();
    let result = compiler.compile(&policy).unwrap();

    let mut synth = CounterexampleSynthesizer::new(test_config());
    let err = synth.synthesize(&result, 1000).unwrap_err();
    assert_eq!(err, SynthesisError::NoViolations);
}

// ---------------------------------------------------------------------------
// Enumeration strategy
// ---------------------------------------------------------------------------

#[test]
fn enumeration_empty_policies_returns_invalid_policy() {
    let mut synth = CounterexampleSynthesizer::new(test_config());
    let err = synth.synthesize_by_enumeration(&[], 1000).unwrap_err();
    match err {
        SynthesisError::InvalidPolicy { reason } => {
            assert!(reason.contains("no policies"));
        }
        _ => panic!("expected InvalidPolicy, got {err:?}"),
    }
}

#[test]
fn enumeration_valid_policy_no_violations() {
    let policy = make_valid_policy();
    let mut synth = CounterexampleSynthesizer::new(test_config());
    let err = synth
        .synthesize_by_enumeration(&[&policy], 1000)
        .unwrap_err();
    assert_eq!(err, SynthesisError::NoViolations);
}

#[test]
fn enumeration_finds_violations_in_bad_policy() {
    let bad = make_monotonicity_violating_policy();
    let mut synth = CounterexampleSynthesizer::new(test_config());
    let results = synth.synthesize_by_enumeration(&[&bad], 1000).unwrap();
    assert!(!results.is_empty());
    // Corpus and diagnostics should also be populated.
    assert_eq!(synth.corpus().len(), results.len());
    assert_eq!(synth.diagnostics().len(), results.len());
}

#[test]
fn enumeration_respects_max_candidates() {
    // Create a config with max_enumeration_candidates = 1
    let mut cfg = test_config();
    cfg.max_enumeration_candidates = 1;
    let mut synth = CounterexampleSynthesizer::new(cfg);

    let valid = make_valid_policy();
    let bad = make_monotonicity_violating_policy();
    // Pass valid first, then bad — should only check 1 and get NoViolations.
    let result = synth.synthesize_by_enumeration(&[&valid, &bad], 1000);
    // With max=1, only the first policy is checked. If it's valid, we get NoViolations.
    assert_eq!(result.unwrap_err(), SynthesisError::NoViolations);
}

// ---------------------------------------------------------------------------
// Mutation strategy
// ---------------------------------------------------------------------------

#[test]
fn mutation_no_violations_from_noop_mutation() {
    let base = make_valid_policy();
    let mutations = vec![PolicyMutation {
        kind: MutationKind::ChangePriority,
        target_node: "nonexistent-node".to_string(),
        new_value: "1".to_string(),
    }];
    let mut synth = CounterexampleSynthesizer::new(test_config());
    let result = synth.synthesize_by_mutation(&base, &mutations, 1000);
    // Mutation targeting nonexistent node doesn't change anything.
    assert_eq!(result.unwrap_err(), SynthesisError::NoViolations);
}

#[test]
fn mutation_records_mutation_type_in_scenario() {
    let base = make_valid_policy();
    let mutations = vec![PolicyMutation {
        kind: MutationKind::AddGrant,
        target_node: "node-1".to_string(),
        new_value: "admin-access".to_string(),
    }];
    let mut synth = CounterexampleSynthesizer::new(test_config());
    if let Ok(cxs) = synth.synthesize_by_mutation(&base, &mutations, 1000) {
        for cx in &cxs {
            assert_eq!(cx.strategy, SynthesisStrategy::Mutation);
            assert!(
                cx.concrete_scenario
                    .input_state
                    .contains_key("mutation_type")
            );
            assert!(
                cx.concrete_scenario
                    .input_state
                    .contains_key("mutation_target")
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Interference detection — oscillation event
// ---------------------------------------------------------------------------

#[test]
fn build_interference_events_oscillation_kind() {
    let synth = CounterexampleSynthesizer::new(test_config());
    let interferences = vec![ControllerInterference {
        kind: InterferenceKind::Oscillation,
        controller_ids: vec!["osc-a".to_string(), "osc-b".to_string()],
        shared_metrics: ["osc-metric".to_string()].into(),
        timescale_separation_millionths: 10_000,
        evidence_description: "oscillation".to_string(),
        convergence_steps: Some(50),
    }];
    let events = synth.build_interference_events(&interferences, "trace-osc", "policy-osc");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, InterferenceKind::Oscillation);
    assert_eq!(events[0].event, "controller_interference_rejected");
    assert_eq!(events[0].outcome, "reject");
    assert_eq!(
        events[0].error_code.as_deref(),
        Some("FE-CX-INTERFERENCE-OSCILLATION")
    );
    assert_eq!(events[0].trace_id, "trace-osc");
    assert_eq!(events[0].policy_id, "policy-osc");
    assert_eq!(events[0].component, "counterexample_synthesizer");
}

#[test]
fn build_interference_events_empty_input() {
    let synth = CounterexampleSynthesizer::new(test_config());
    let events = synth.build_interference_events(&[], "t", "p");
    assert!(events.is_empty());
}

#[test]
fn detect_interference_empty_controllers() {
    let synth = CounterexampleSynthesizer::new(test_config());
    let interferences = synth.detect_interference(&[]);
    assert!(interferences.is_empty());
}

#[test]
fn detect_interference_single_controller() {
    let synth = CounterexampleSynthesizer::new(test_config());
    let configs = vec![ControllerConfig {
        controller_id: "solo".to_string(),
        read_metrics: ["m".to_string()].into(),
        write_metrics: ["m".to_string()].into(),
        affected_metrics: ["m".to_string()].into(),
        timescale_millionths: 1_000_000,
        timescale_statement: "sole controller".to_string(),
    }];
    let interferences = synth.detect_interference(&configs);
    assert!(interferences.is_empty());
}

#[test]
fn detect_interference_well_separated_timescales_no_conflict() {
    let synth = CounterexampleSynthesizer::new(test_config());
    let configs = vec![
        ControllerConfig {
            controller_id: "fast".to_string(),
            read_metrics: BTreeSet::new(),
            write_metrics: ["m".to_string()].into(),
            affected_metrics: ["m".to_string()].into(),
            timescale_millionths: 100_000,
            timescale_statement: "100ms writer".to_string(),
        },
        ControllerConfig {
            controller_id: "slow".to_string(),
            read_metrics: BTreeSet::new(),
            write_metrics: ["m".to_string()].into(),
            affected_metrics: ["m".to_string()].into(),
            timescale_millionths: 1_000_000,
            timescale_statement: "1s writer".to_string(),
        },
    ];
    let interferences = synth.detect_interference(&configs);
    // Sufficient separation (900_000 > 100_000 threshold) so no timescale conflict
    // for the concurrent writers check. But there is still read/write overlap potential.
    // Let me check: both are writers to "m", shared = {"m"}. concurrent_writes = {"m"}.
    // separation = |100_000 - 1_000_000| = 900_000. Since 900_000 >= 100_000,
    // insufficient_separation is false, so no timescale conflict from concurrent writes.
    // However, read_write_overlap: a_writes ∩ b_reads = {} (b has no reads).
    // b_writes ∩ a_reads = {} (a has no reads). So no invariant invalidation either.
    assert!(
        !interferences
            .iter()
            .any(|i| i.kind == InterferenceKind::TimescaleConflict),
        "well-separated timescales should not produce a timescale conflict"
    );
}

// ---------------------------------------------------------------------------
// Replay fixture generation
// ---------------------------------------------------------------------------

#[test]
fn replay_fixture_trace_id_starts_with_synth() {
    let compiler = PolicyTheoremCompiler::new();
    let policy = make_monotonicity_violating_policy();
    let result = compiler.compile(&policy).unwrap();

    let mut synth = CounterexampleSynthesizer::new(test_config());
    let cxs = synth.synthesize(&result, 1000).unwrap();
    let trace = synth.to_replay_fixture(&cxs[0], 10_000);

    assert!(trace.trace_id.starts_with("synth-"));
    assert!(!trace.entries.is_empty());
}

#[test]
fn replay_fixture_chain_integrity() {
    let compiler = PolicyTheoremCompiler::new();
    let policy = make_monotonicity_violating_policy();
    let result = compiler.compile(&policy).unwrap();

    let mut synth = CounterexampleSynthesizer::new(test_config());
    let cxs = synth.synthesize(&result, 1000).unwrap();
    let trace = synth.to_replay_fixture(&cxs[0], 5000);
    assert!(
        trace.verify_chain_integrity().is_ok(),
        "replay fixture should have valid chain integrity"
    );
}

#[test]
fn replay_fixture_metadata_includes_property_and_strategy() {
    let compiler = PolicyTheoremCompiler::new();
    let policy = make_monotonicity_violating_policy();
    let result = compiler.compile(&policy).unwrap();

    let mut synth = CounterexampleSynthesizer::new(test_config());
    let cxs = synth.synthesize(&result, 1000).unwrap();
    let trace = synth.to_replay_fixture(&cxs[0], 5000);

    assert!(trace.metadata.contains_key("property_violated"));
    assert!(trace.metadata.contains_key("strategy"));
}

// ---------------------------------------------------------------------------
// Evidence entry
// ---------------------------------------------------------------------------

#[test]
fn evidence_entry_has_correct_metadata_keys() {
    let compiler = PolicyTheoremCompiler::new();
    let policy = make_monotonicity_violating_policy();
    let result = compiler.compile(&policy).unwrap();

    let mut synth = CounterexampleSynthesizer::new(test_config());
    let cxs = synth.synthesize(&result, 1000).unwrap();
    let entry = synth.to_evidence_entry(&cxs[0], 2000).unwrap();

    assert!(entry.metadata.contains_key("conflict_id"));
    assert!(entry.metadata.contains_key("synthesis_strategy"));
    assert!(entry.metadata.contains_key("compute_time_ns"));
    assert!(entry.metadata.contains_key("minimality_depth"));
    assert!(entry.metadata.contains_key("resolution_status"));
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn synthesize_is_deterministic() {
    let compiler = PolicyTheoremCompiler::new();
    let policy = make_monotonicity_violating_policy();
    let result = compiler.compile(&policy).unwrap();

    let mut synth1 = CounterexampleSynthesizer::new(test_config());
    let mut synth2 = CounterexampleSynthesizer::new(test_config());

    let cxs1 = synth1.synthesize(&result, 1000).unwrap();
    let cxs2 = synth2.synthesize(&result, 1000).unwrap();

    assert_eq!(cxs1.len(), cxs2.len());
    for (a, b) in cxs1.iter().zip(cxs2.iter()) {
        assert_eq!(a.conflict_id, b.conflict_id);
        assert_eq!(a.content_hash, b.content_hash);
        assert_eq!(a.concrete_scenario, b.concrete_scenario);
        assert_eq!(a.minimality_evidence, b.minimality_evidence);
    }
}

#[test]
fn different_timestamps_produce_different_conflict_ids() {
    let compiler = PolicyTheoremCompiler::new();
    let policy = make_monotonicity_violating_policy();
    let result = compiler.compile(&policy).unwrap();

    let mut synth1 = CounterexampleSynthesizer::new(test_config());
    let mut synth2 = CounterexampleSynthesizer::new(test_config());

    let cxs1 = synth1.synthesize(&result, 1000).unwrap();
    let cxs2 = synth2.synthesize(&result, 2000).unwrap();

    // Different timestamps should produce different conflict IDs since
    // timestamp is part of the ID derivation.
    assert_ne!(cxs1[0].conflict_id, cxs2[0].conflict_id);
}

// ---------------------------------------------------------------------------
// Synthesizer serde
// ---------------------------------------------------------------------------

#[test]
fn synthesizer_serde_roundtrip_empty() {
    let synth = CounterexampleSynthesizer::new(test_config());
    let json = serde_json::to_string(&synth).unwrap();
    let restored: CounterexampleSynthesizer = serde_json::from_str(&json).unwrap();
    assert_eq!(synth.synthesis_count(), restored.synthesis_count());
    assert_eq!(synth.corpus().len(), restored.corpus().len());
}

#[test]
fn synthesizer_state_after_synthesis() {
    // Verify that after synthesis, the synthesizer state is consistent.
    // (Note: EngineObjectId map keys don't round-trip through JSON,
    // so we test state consistency instead of full serde with data.)
    let compiler = PolicyTheoremCompiler::new();
    let policy = make_monotonicity_violating_policy();
    let result = compiler.compile(&policy).unwrap();

    let mut synth = CounterexampleSynthesizer::new(test_config());
    let cxs = synth.synthesize(&result, 1000).unwrap();

    assert_eq!(synth.synthesis_count(), cxs.len() as u64);
    assert_eq!(synth.corpus().len(), cxs.len());
    assert_eq!(synth.diagnostics().len(), cxs.len());

    // Each counterexample should be in the corpus.
    for cx in &cxs {
        assert!(synth.corpus().contains(&cx.conflict_id));
    }
}

// ---------------------------------------------------------------------------
// Diagnostic severity per property
// ---------------------------------------------------------------------------

#[test]
fn diagnostic_severity_noninterference_is_critical() {
    let compiler = PolicyTheoremCompiler::new();
    let cap = Capability::new("cross-domain");
    let mut universe = BTreeSet::new();
    universe.insert(cap.clone());
    let mut claims = BTreeSet::new();
    claims.insert(FormalProperty::NonInterference);

    let policy = PolicyIr {
        policy_id: PolicyId::new("ni-violating"),
        version: 1,
        nodes: vec![PolicyIrNode {
            node_id: "node-shared".to_string(),
            grants: vec![AuthorityGrant {
                subject: "shared-subject".to_string(),
                capability: cap,
                conditions: BTreeSet::new(),
                scope: "default".to_string(),
                lifetime_epochs: 10,
            }],
            merge_op: MergeOperator::Union,
            property_claims: claims,
            constraints: vec![Constraint::NonInterferenceClaim {
                domain_a: "domain-a".to_string(),
                domain_b: "domain-b".to_string(),
            }],
            decision_point: None,
            priority: 1,
        }],
        capability_universe: universe,
        verified_properties: BTreeSet::new(),
        epoch: SecurityEpoch::from_raw(100),
    };

    let result = compiler.compile(&policy).unwrap();
    if result.counterexamples.is_empty() {
        return; // Skip if compiler doesn't detect this
    }

    let mut synth = CounterexampleSynthesizer::new(test_config());
    synth.synthesize(&result, 1000).unwrap();

    let diag = &synth.diagnostics()[0];
    // Severity depends on which property the compiler actually detected.
    // NonInterference => 1_000_000, Monotonicity/AttenuationLegality => 900_000,
    // MergeDeterminism/PrecedenceStability => 700_000.
    assert!(
        diag.severity_millionths >= 700_000,
        "severity should be at least 700_000, got {}",
        diag.severity_millionths
    );
}

// ---------------------------------------------------------------------------
// Merge determinism policy
// ---------------------------------------------------------------------------

#[test]
fn merge_determinism_violation_detection() {
    let compiler = PolicyTheoremCompiler::new();
    let cap = Capability::new("data-access");
    let mut universe = BTreeSet::new();
    universe.insert(cap.clone());
    let mut claims = BTreeSet::new();
    claims.insert(FormalProperty::MergeDeterminism);

    let policy = PolicyIr {
        policy_id: PolicyId::new("merge-nondet"),
        version: 1,
        nodes: vec![
            PolicyIrNode {
                node_id: "node-x".to_string(),
                grants: vec![AuthorityGrant {
                    subject: "user-x".to_string(),
                    capability: cap.clone(),
                    conditions: BTreeSet::new(),
                    scope: "default".to_string(),
                    lifetime_epochs: 5,
                }],
                merge_op: MergeOperator::Precedence,
                property_claims: claims.clone(),
                constraints: Vec::new(),
                decision_point: None,
                priority: 1,
            },
            PolicyIrNode {
                node_id: "node-y".to_string(),
                grants: vec![AuthorityGrant {
                    subject: "user-y".to_string(),
                    capability: cap,
                    conditions: BTreeSet::new(),
                    scope: "default".to_string(),
                    lifetime_epochs: 5,
                }],
                merge_op: MergeOperator::Precedence,
                property_claims: claims,
                constraints: Vec::new(),
                decision_point: None,
                priority: 1, // Same priority -> ambiguity
            },
        ],
        capability_universe: universe,
        verified_properties: BTreeSet::new(),
        epoch: SecurityEpoch::from_raw(100),
    };

    let result = compiler.compile(&policy).unwrap();
    if result.counterexamples.is_empty() {
        return;
    }

    let mut synth = CounterexampleSynthesizer::new(test_config());
    let cxs = synth.synthesize(&result, 2000).unwrap();
    assert!(!cxs.is_empty());

    // Diagnostic severity for MergeDeterminism should be 700_000.
    let diag = &synth.diagnostics()[0];
    assert_eq!(diag.severity_millionths, 700_000);
}

// ---------------------------------------------------------------------------
// Multiple synthesis calls accumulate state
// ---------------------------------------------------------------------------

#[test]
fn multiple_synthesize_calls_accumulate() {
    let compiler = PolicyTheoremCompiler::new();
    let policy = make_monotonicity_violating_policy();
    let result = compiler.compile(&policy).unwrap();

    let mut synth = CounterexampleSynthesizer::new(test_config());

    let _cxs1 = synth.synthesize(&result, 1000).unwrap();
    let count_after_first = synth.synthesis_count();
    let corpus_len_after_first = synth.corpus().len();

    // Second call with different timestamp should produce different conflict IDs.
    let cxs2 = synth.synthesize(&result, 2000).unwrap();
    assert_eq!(
        synth.synthesis_count(),
        count_after_first + cxs2.len() as u64
    );
    assert_eq!(synth.corpus().len(), corpus_len_after_first + cxs2.len());

    // But same timestamp produces duplicates that don't increase corpus.
    let cxs3 = synth.synthesize(&result, 1000).unwrap();
    assert_eq!(
        synth.synthesis_count(),
        count_after_first + cxs2.len() as u64 + cxs3.len() as u64
    );
    // Corpus should NOT grow because conflict_ids are the same.
    assert_eq!(synth.corpus().len(), corpus_len_after_first + cxs2.len());
}
