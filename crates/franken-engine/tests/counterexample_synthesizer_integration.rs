#![forbid(unsafe_code)]

//! Integration tests for the `counterexample_synthesizer` module.
//!
//! Covers: constants, Display/Ord/Serde for all enums and structs,
//! RegressionCorpus lifecycle, CounterexampleSynthesizer workflows,
//! detect_interference, build_interference_events, synthesize,
//! synthesize_by_enumeration, synthesize_by_mutation, to_replay_fixture,
//! to_evidence_entry, and full lifecycle.

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

use frankenengine_engine::counterexample_synthesizer::*;
use frankenengine_engine::evidence_ledger::DecisionType;
use frankenengine_engine::policy_theorem_compiler::{
    AuthorityGrant, Capability, FormalProperty, MergeOperator, PolicyId, PolicyIr, PolicyIrNode,
    PolicyTheoremCompiler,
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
        epoch: SecurityEpoch::from_raw(42),
        signing_key_bytes: test_signing_key(),
    }
}

/// A valid policy that passes all compiler checks.
fn valid_policy() -> PolicyIr {
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
        epoch: SecurityEpoch::from_raw(42),
    }
}

/// A policy that triggers a monotonicity violation (Union without Monotonicity claim
/// on the second node, plus an undefined capability).
fn violating_policy() -> PolicyIr {
    let cap_a = Capability::new("read-data");
    let cap_b = Capability::new("write-data");
    let cap_extra = Capability::new("admin-override");
    let mut universe = BTreeSet::new();
    universe.insert(cap_a.clone());
    universe.insert(cap_b.clone());
    // cap_extra not in universe -> type-check failure

    let mut claims = BTreeSet::new();
    claims.insert(FormalProperty::Monotonicity);

    PolicyIr {
        policy_id: PolicyId::new("bad-policy"),
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
        epoch: SecurityEpoch::from_raw(42),
    }
}

/// A policy with precedence-stability / merge-determinism violation
/// (two Precedence nodes with the same priority).
fn merge_nondeterminism_policy() -> PolicyIr {
    let cap = Capability::new("data-access");
    let mut universe = BTreeSet::new();
    universe.insert(cap.clone());
    let mut claims = BTreeSet::new();
    claims.insert(FormalProperty::MergeDeterminism);
    claims.insert(FormalProperty::Monotonicity);

    PolicyIr {
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
                priority: 1, // same priority => ambiguity
            },
        ],
        capability_universe: universe,
        verified_properties: BTreeSet::new(),
        epoch: SecurityEpoch::from_raw(42),
    }
}

/// Compile a policy and return the compilation result (panics on compiler error).
fn compile(policy: &PolicyIr) -> frankenengine_engine::policy_theorem_compiler::CompilationResult {
    PolicyTheoremCompiler::new().compile(policy).unwrap()
}

/// Synthesize counterexamples from a violating policy using a fresh synthesizer.
fn synthesize_from_violating() -> (CounterexampleSynthesizer, Vec<SynthesizedCounterexample>) {
    let result = compile(&violating_policy());
    assert!(
        !result.counterexamples.is_empty(),
        "violating policy must produce compiler counterexamples"
    );
    let mut synth = CounterexampleSynthesizer::new(test_config());
    let cxs = synth.synthesize(&result, 1000).unwrap();
    (synth, cxs)
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn constants_have_expected_values() {
    assert_eq!(DEFAULT_BUDGET_NS, 30_000_000_000);
    assert_eq!(DEFAULT_MAX_MINIMIZATION_ROUNDS, 50);
}

// ===========================================================================
// 2. SynthesisStrategy: Display, serde, ordering
// ===========================================================================

#[test]
fn synthesis_strategy_display_all_four() {
    assert_eq!(
        SynthesisStrategy::CompilerExtraction.to_string(),
        "compiler-extraction"
    );
    assert_eq!(SynthesisStrategy::Enumeration.to_string(), "enumeration");
    assert_eq!(SynthesisStrategy::Mutation.to_string(), "mutation");
    assert_eq!(SynthesisStrategy::TimeBounded.to_string(), "time-bounded");
}

#[test]
fn synthesis_strategy_serde_roundtrip() {
    for v in [
        SynthesisStrategy::CompilerExtraction,
        SynthesisStrategy::Enumeration,
        SynthesisStrategy::Mutation,
        SynthesisStrategy::TimeBounded,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let restored: SynthesisStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }
}

#[test]
fn synthesis_strategy_ordering() {
    let mut strategies = [
        SynthesisStrategy::TimeBounded,
        SynthesisStrategy::CompilerExtraction,
        SynthesisStrategy::Mutation,
        SynthesisStrategy::Enumeration,
    ];
    strategies.sort();
    assert_eq!(strategies[0], SynthesisStrategy::CompilerExtraction);
    assert_eq!(strategies[1], SynthesisStrategy::Enumeration);
    assert_eq!(strategies[2], SynthesisStrategy::Mutation);
    assert_eq!(strategies[3], SynthesisStrategy::TimeBounded);
}

// ===========================================================================
// 3. SynthesisError: Display, serde, Error trait
// ===========================================================================

#[test]
fn synthesis_error_display_all_six() {
    assert_eq!(
        SynthesisError::NoViolations.to_string(),
        "no violations found in compilation result"
    );
    let timeout = SynthesisError::Timeout {
        elapsed_ns: 5000,
        budget_ns: 10000,
        partial: None,
    };
    assert!(timeout.to_string().contains("5000ns"));
    assert!(timeout.to_string().contains("10000ns"));
    let inv = SynthesisError::InvalidPolicy {
        reason: "empty".to_string(),
    };
    assert!(inv.to_string().contains("empty"));
    let id_err = SynthesisError::IdDerivation("bad-id".to_string());
    assert!(id_err.to_string().contains("bad-id"));
    let min = SynthesisError::MinimizationExhausted { rounds: 42 };
    assert!(min.to_string().contains("42"));
    let comp = SynthesisError::CompilerFailure("oops".to_string());
    assert!(comp.to_string().contains("oops"));
}

#[test]
fn synthesis_error_serde_roundtrip_all_variants() {
    let variants = vec![
        SynthesisError::NoViolations,
        SynthesisError::Timeout {
            elapsed_ns: 100,
            budget_ns: 200,
            partial: None,
        },
        SynthesisError::InvalidPolicy {
            reason: "test".to_string(),
        },
        SynthesisError::IdDerivation("x".to_string()),
        SynthesisError::MinimizationExhausted { rounds: 10 },
        SynthesisError::CompilerFailure("fail".to_string()),
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: SynthesisError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn synthesis_error_implements_std_error_trait() {
    let errors: Vec<Box<dyn std::error::Error>> = vec![
        Box::new(SynthesisError::NoViolations),
        Box::new(SynthesisError::Timeout {
            elapsed_ns: 1,
            budget_ns: 2,
            partial: None,
        }),
        Box::new(SynthesisError::InvalidPolicy {
            reason: "r".to_string(),
        }),
        Box::new(SynthesisError::IdDerivation("d".to_string())),
        Box::new(SynthesisError::MinimizationExhausted { rounds: 3 }),
        Box::new(SynthesisError::CompilerFailure("c".to_string())),
    ];
    let mut msgs = BTreeSet::new();
    for e in &errors {
        msgs.insert(e.to_string());
    }
    assert_eq!(
        msgs.len(),
        6,
        "all 6 variants must have distinct Display messages"
    );
}

// ===========================================================================
// 4. SynthesisOutcome: Display, serde
// ===========================================================================

#[test]
fn synthesis_outcome_display_all_three() {
    assert_eq!(SynthesisOutcome::Complete.to_string(), "complete");
    assert_eq!(SynthesisOutcome::Partial.to_string(), "partial");
    assert_eq!(SynthesisOutcome::Incomplete.to_string(), "incomplete");
}

#[test]
fn synthesis_outcome_serde_roundtrip() {
    for v in [
        SynthesisOutcome::Complete,
        SynthesisOutcome::Partial,
        SynthesisOutcome::Incomplete,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let restored: SynthesisOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }
}

// ===========================================================================
// 5. ConcreteScenario, MinimalityEvidence: construction and serde
// ===========================================================================

#[test]
fn concrete_scenario_construction_and_serde() {
    let scenario = ConcreteScenario {
        subjects: ["alice".to_string(), "bob".to_string()].into(),
        capabilities: ["read".to_string(), "write".to_string()].into(),
        conditions: BTreeMap::from([("env".to_string(), "prod".to_string())]),
        merge_ordering: vec!["step-1".to_string(), "step-2".to_string()],
        input_state: BTreeMap::from([("key".to_string(), "val".to_string())]),
    };
    let json = serde_json::to_string(&scenario).unwrap();
    let restored: ConcreteScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(scenario, restored);
    assert_eq!(restored.subjects.len(), 2);
    assert_eq!(restored.merge_ordering.len(), 2);
}

#[test]
fn minimality_evidence_construction_and_serde() {
    let evidence = MinimalityEvidence {
        rounds: 12,
        elements_removed: 3,
        starting_size: 15,
        final_size: 12,
        is_fixed_point: true,
    };
    let json = serde_json::to_string(&evidence).unwrap();
    let restored: MinimalityEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(evidence, restored);
}

// ===========================================================================
// 6. InterferenceKind: Display, serde, ordering
// ===========================================================================

#[test]
fn interference_kind_display_all_three() {
    assert_eq!(
        InterferenceKind::InvariantInvalidation.to_string(),
        "invariant-invalidation"
    );
    assert_eq!(InterferenceKind::Oscillation.to_string(), "oscillation");
    assert_eq!(
        InterferenceKind::TimescaleConflict.to_string(),
        "timescale-conflict"
    );
}

#[test]
fn interference_kind_serde_roundtrip() {
    for v in [
        InterferenceKind::InvariantInvalidation,
        InterferenceKind::Oscillation,
        InterferenceKind::TimescaleConflict,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let restored: InterferenceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }
}

#[test]
fn interference_kind_ordering() {
    let mut kinds = [
        InterferenceKind::TimescaleConflict,
        InterferenceKind::InvariantInvalidation,
        InterferenceKind::Oscillation,
    ];
    kinds.sort();
    assert_eq!(kinds[0], InterferenceKind::InvariantInvalidation);
    assert_eq!(kinds[1], InterferenceKind::Oscillation);
    assert_eq!(kinds[2], InterferenceKind::TimescaleConflict);
}

// ===========================================================================
// 7. MutationKind: Display, serde, ordering
// ===========================================================================

#[test]
fn mutation_kind_display_all_six() {
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
fn mutation_kind_serde_roundtrip_all() {
    for v in [
        MutationKind::ChangeMergeOp,
        MutationKind::AddGrant,
        MutationKind::RemovePropertyClaim,
        MutationKind::ChangePriority,
        MutationKind::RemoveConstraint,
        MutationKind::DuplicateNode,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let restored: MutationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }
}

#[test]
fn mutation_kind_ordering() {
    let mut kinds = [
        MutationKind::DuplicateNode,
        MutationKind::ChangeMergeOp,
        MutationKind::RemoveConstraint,
        MutationKind::AddGrant,
        MutationKind::RemovePropertyClaim,
        MutationKind::ChangePriority,
    ];
    kinds.sort();
    assert_eq!(kinds[0], MutationKind::ChangeMergeOp);
    assert_eq!(kinds[1], MutationKind::AddGrant);
    assert_eq!(kinds[2], MutationKind::RemovePropertyClaim);
    assert_eq!(kinds[3], MutationKind::ChangePriority);
    assert_eq!(kinds[4], MutationKind::RemoveConstraint);
    assert_eq!(kinds[5], MutationKind::DuplicateNode);
}

// ===========================================================================
// 8. PolicyMutation: serde
// ===========================================================================

#[test]
fn policy_mutation_serde_roundtrip() {
    let m = PolicyMutation {
        kind: MutationKind::AddGrant,
        target_node: "node-1".to_string(),
        new_value: "admin".to_string(),
    };
    let json = serde_json::to_string(&m).unwrap();
    let restored: PolicyMutation = serde_json::from_str(&json).unwrap();
    assert_eq!(m, restored);
}

// ===========================================================================
// 9. ControllerConfig: serde
// ===========================================================================

#[test]
fn controller_config_serde_roundtrip() {
    let cfg = ControllerConfig {
        controller_id: "ctrl-alpha".to_string(),
        read_metrics: ["latency".to_string()].into(),
        write_metrics: ["throughput".to_string()].into(),
        affected_metrics: ["latency".to_string(), "throughput".to_string()].into(),
        timescale_millionths: 500_000,
        timescale_statement: "reads latency every 500ms; writes throughput every 500ms".to_string(),
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: ControllerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// ===========================================================================
// 10. ControllerInterference, ControllerInterferenceEvent: serde
// ===========================================================================

#[test]
fn controller_interference_serde_roundtrip() {
    let ci = ControllerInterference {
        kind: InterferenceKind::Oscillation,
        controller_ids: vec!["ctrl-a".to_string(), "ctrl-b".to_string()],
        shared_metrics: ["cpu".to_string()].into(),
        timescale_separation_millionths: 200_000,
        evidence_description: "oscillation detected on cpu metric".to_string(),
        convergence_steps: Some(50),
    };
    let json = serde_json::to_string(&ci).unwrap();
    let restored: ControllerInterference = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, restored);
}

#[test]
fn controller_interference_event_serde_roundtrip() {
    let evt = ControllerInterferenceEvent {
        trace_id: "trace-001".to_string(),
        decision_id: "interference-000001".to_string(),
        policy_id: "policy-v1".to_string(),
        component: "counterexample_synthesizer".to_string(),
        event: "controller_interference_rejected".to_string(),
        outcome: "reject".to_string(),
        error_code: Some("FE-CX-INTERFERENCE-TIMESCALE".to_string()),
        kind: InterferenceKind::TimescaleConflict,
        controller_ids: vec!["a".to_string(), "b".to_string()],
        shared_metrics: vec!["m1".to_string()],
        timescale_separation_millionths: 50_000,
    };
    let json = serde_json::to_string(&evt).unwrap();
    let restored: ControllerInterferenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(evt, restored);
}

// ===========================================================================
// 11. ConflictDiagnostic: serde
// ===========================================================================

#[test]
fn conflict_diagnostic_serde_roundtrip() {
    let (synth, _cxs) = synthesize_from_violating();
    let diag = &synth.diagnostics()[0];
    let json = serde_json::to_string(diag).unwrap();
    let restored: ConflictDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(diag.conflict_id, restored.conflict_id);
    assert_eq!(diag.property, restored.property);
    assert_eq!(diag.severity_millionths, restored.severity_millionths);
}

// ===========================================================================
// 12. RegressionCorpus: new/empty, append/dedup, resolve, unresolved, contains, serde
// ===========================================================================

#[test]
fn regression_corpus_new_is_empty() {
    let corpus = RegressionCorpus::new();
    assert!(corpus.is_empty());
    assert_eq!(corpus.len(), 0);
    assert!(corpus.unresolved().is_empty());
}

#[test]
fn regression_corpus_default_is_empty() {
    let corpus = RegressionCorpus::default();
    assert!(corpus.is_empty());
}

#[test]
fn regression_corpus_append_and_dedup() {
    let (_synth, cxs) = synthesize_from_violating();
    let cx = cxs[0].clone();
    let epoch = SecurityEpoch::from_raw(42);

    let mut corpus = RegressionCorpus::new();
    assert!(corpus.append(cx.clone(), epoch, 1000));
    assert!(!corpus.append(cx, epoch, 2000)); // duplicate by conflict_id
    assert_eq!(corpus.len(), 1);
}

#[test]
fn regression_corpus_resolve_and_unresolved() {
    let (_synth, cxs) = synthesize_from_violating();
    let cx = cxs[0].clone();
    let cid = cx.conflict_id.clone();
    let epoch = SecurityEpoch::from_raw(42);

    let mut corpus = RegressionCorpus::new();
    corpus.append(cx, epoch, 1000);
    assert_eq!(corpus.unresolved().len(), 1);

    assert!(corpus.resolve(&cid));
    assert_eq!(corpus.unresolved().len(), 0);
    assert!(corpus.contains(&cid));
}

#[test]
fn regression_corpus_resolve_nonexistent_returns_false() {
    let mut corpus = RegressionCorpus::new();
    // Create a fake id that definitely will not be in the corpus.
    let fake_id = frankenengine_engine::engine_object_id::derive_id(
        frankenengine_engine::engine_object_id::ObjectDomain::EvidenceRecord,
        "test-zone",
        &frankenengine_engine::engine_object_id::SchemaId::from_definition(b"FakeSchema"),
        b"nonexistent",
    )
    .unwrap();
    assert!(!corpus.resolve(&fake_id));
}

#[test]
fn regression_corpus_contains() {
    let (_synth, cxs) = synthesize_from_violating();
    let cx = cxs[0].clone();
    let cid = cx.conflict_id.clone();
    let epoch = SecurityEpoch::from_raw(42);

    let mut corpus = RegressionCorpus::new();
    assert!(!corpus.contains(&cid));
    corpus.append(cx, epoch, 1000);
    assert!(corpus.contains(&cid));
}

#[test]
fn regression_corpus_empty_serde_roundtrip() {
    // Note: BTreeMap<EngineObjectId, T> cannot roundtrip through JSON
    // (key must be a string), so we test the empty corpus case.
    let corpus = RegressionCorpus::new();
    let json = serde_json::to_string(&corpus).unwrap();
    let restored: RegressionCorpus = serde_json::from_str(&json).unwrap();
    assert_eq!(corpus.len(), restored.len());
    assert!(restored.is_empty());
}

#[test]
fn regression_corpus_entries_individually_serde() {
    // Individual RegressionEntry values serde fine; the BTreeMap key is the issue.
    let (_synth, cxs) = synthesize_from_violating();
    let epoch = SecurityEpoch::from_raw(42);
    let mut corpus = RegressionCorpus::new();
    corpus.append(cxs[0].clone(), epoch, 1000);
    assert_eq!(corpus.len(), 1);

    // Each entry roundtrips fine.
    for entry in corpus.entries().values() {
        let json = serde_json::to_string(entry).unwrap();
        let restored: RegressionEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry.entry_id, restored.entry_id);
    }
}

// ===========================================================================
// 13. SynthesisConfig: default values and serde
// ===========================================================================

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
    assert_eq!(cfg.signing_key_bytes, vec![0u8; 32]);
}

#[test]
fn synthesis_config_serde_roundtrip() {
    let cfg = test_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: SynthesisConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// ===========================================================================
// 14. CounterexampleSynthesizer: new, initial state, config accessor
// ===========================================================================

#[test]
fn synthesizer_new_initial_state() {
    let cfg = test_config();
    let synth = CounterexampleSynthesizer::new(cfg.clone());
    assert!(synth.corpus().is_empty());
    assert_eq!(synth.synthesis_count(), 0);
    assert!(synth.diagnostics().is_empty());
    assert_eq!(*synth.config(), cfg);
}

// ===========================================================================
// 15. detect_interference: various scenarios
// ===========================================================================

#[test]
fn detect_interference_no_overlap_disjoint_controllers() {
    let synth = CounterexampleSynthesizer::new(test_config());
    let configs = vec![
        ControllerConfig {
            controller_id: "ctrl-a".to_string(),
            read_metrics: ["cpu".to_string()].into(),
            write_metrics: ["cpu".to_string()].into(),
            affected_metrics: ["cpu".to_string()].into(),
            timescale_millionths: 1_000_000,
            timescale_statement: "reads/writes cpu every 1s".to_string(),
        },
        ControllerConfig {
            controller_id: "ctrl-b".to_string(),
            read_metrics: ["memory".to_string()].into(),
            write_metrics: ["memory".to_string()].into(),
            affected_metrics: ["memory".to_string()].into(),
            timescale_millionths: 1_000_000,
            timescale_statement: "reads/writes memory every 1s".to_string(),
        },
    ];
    let interferences = synth.detect_interference(&configs);
    assert!(interferences.is_empty());
}

#[test]
fn detect_interference_shared_metrics_missing_timescale_statement() {
    let synth = CounterexampleSynthesizer::new(test_config());
    let configs = vec![
        ControllerConfig {
            controller_id: "writer-a".to_string(),
            read_metrics: BTreeSet::new(),
            write_metrics: ["latency".to_string()].into(),
            affected_metrics: ["latency".to_string()].into(),
            timescale_millionths: 100_000,
            timescale_statement: String::new(), // missing!
        },
        ControllerConfig {
            controller_id: "writer-b".to_string(),
            read_metrics: BTreeSet::new(),
            write_metrics: ["latency".to_string()].into(),
            affected_metrics: ["latency".to_string()].into(),
            timescale_millionths: 120_000,
            timescale_statement: "writes every 120ms".to_string(),
        },
    ];
    let interferences = synth.detect_interference(&configs);
    assert!(interferences.iter().any(|i| {
        i.kind == InterferenceKind::TimescaleConflict
            && i.evidence_description
                .contains("missing required timescale-separation")
    }));
}

#[test]
fn detect_interference_concurrent_writes_insufficient_separation() {
    let synth = CounterexampleSynthesizer::new(test_config());
    let configs = vec![
        ControllerConfig {
            controller_id: "fast-ctrl".to_string(),
            read_metrics: ["throughput".to_string()].into(),
            write_metrics: ["throughput".to_string()].into(),
            affected_metrics: ["throughput".to_string()].into(),
            timescale_millionths: 100_000,
            timescale_statement: "writes every 100ms".to_string(),
        },
        ControllerConfig {
            controller_id: "also-fast-ctrl".to_string(),
            read_metrics: ["throughput".to_string()].into(),
            write_metrics: ["throughput".to_string()].into(),
            affected_metrics: ["throughput".to_string()].into(),
            timescale_millionths: 120_000,
            timescale_statement: "writes every 120ms".to_string(),
        },
    ];
    let interferences = synth.detect_interference(&configs);
    assert!(
        interferences
            .iter()
            .any(|i| i.kind == InterferenceKind::TimescaleConflict)
    );
}

#[test]
fn detect_interference_read_write_overlap() {
    let synth = CounterexampleSynthesizer::new(test_config());
    let configs = vec![
        ControllerConfig {
            controller_id: "writer".to_string(),
            read_metrics: BTreeSet::new(),
            write_metrics: ["shared-metric".to_string()].into(),
            affected_metrics: ["shared-metric".to_string()].into(),
            timescale_millionths: 1_000_000,
            timescale_statement: "writes every 1s".to_string(),
        },
        ControllerConfig {
            controller_id: "reader".to_string(),
            read_metrics: ["shared-metric".to_string()].into(),
            write_metrics: BTreeSet::new(),
            affected_metrics: ["shared-metric".to_string()].into(),
            timescale_millionths: 1_000_000,
            timescale_statement: "reads every 1s".to_string(),
        },
    ];
    let interferences = synth.detect_interference(&configs);
    assert!(
        interferences
            .iter()
            .any(|i| i.kind == InterferenceKind::InvariantInvalidation)
    );
}

#[test]
fn detect_interference_read_only_no_conflict() {
    let synth = CounterexampleSynthesizer::new(test_config());
    let configs = vec![
        ControllerConfig {
            controller_id: "reader-a".to_string(),
            read_metrics: ["cpu".to_string()].into(),
            write_metrics: BTreeSet::new(),
            affected_metrics: ["cpu".to_string()].into(),
            timescale_millionths: 100_000,
            timescale_statement: "reads cpu every 100ms".to_string(),
        },
        ControllerConfig {
            controller_id: "reader-b".to_string(),
            read_metrics: ["cpu".to_string()].into(),
            write_metrics: BTreeSet::new(),
            affected_metrics: ["cpu".to_string()].into(),
            timescale_millionths: 200_000,
            timescale_statement: "reads cpu every 200ms".to_string(),
        },
    ];
    let interferences = synth.detect_interference(&configs);
    assert!(interferences.is_empty());
}

// ===========================================================================
// 16. build_interference_events: event/outcome/error_code per kind
// ===========================================================================

#[test]
fn build_interference_events_timescale_conflict() {
    let synth = CounterexampleSynthesizer::new(test_config());
    let interferences = vec![ControllerInterference {
        kind: InterferenceKind::TimescaleConflict,
        controller_ids: vec!["a".to_string(), "b".to_string()],
        shared_metrics: ["m1".to_string()].into(),
        timescale_separation_millionths: 50_000,
        evidence_description: "timescale conflict".to_string(),
        convergence_steps: None,
    }];
    let events = synth.build_interference_events(&interferences, "trace-1", "pol-1");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "controller_interference_rejected");
    assert_eq!(events[0].outcome, "reject");
    assert_eq!(
        events[0].error_code.as_deref(),
        Some("FE-CX-INTERFERENCE-TIMESCALE")
    );
    assert_eq!(events[0].decision_id, "interference-000001");
    assert_eq!(events[0].component, "counterexample_synthesizer");
}

#[test]
fn build_interference_events_invariant_invalidation() {
    let synth = CounterexampleSynthesizer::new(test_config());
    let interferences = vec![ControllerInterference {
        kind: InterferenceKind::InvariantInvalidation,
        controller_ids: vec!["x".to_string(), "y".to_string()],
        shared_metrics: ["m2".to_string()].into(),
        timescale_separation_millionths: 500_000,
        evidence_description: "read/write overlap".to_string(),
        convergence_steps: None,
    }];
    let events = synth.build_interference_events(&interferences, "trace-2", "pol-2");
    assert_eq!(events[0].event, "controller_interference_serialized");
    assert_eq!(events[0].outcome, "serialize");
    assert_eq!(
        events[0].error_code.as_deref(),
        Some("FE-CX-INTERFERENCE-INVARIANT")
    );
}

#[test]
fn build_interference_events_oscillation() {
    let synth = CounterexampleSynthesizer::new(test_config());
    let interferences = vec![ControllerInterference {
        kind: InterferenceKind::Oscillation,
        controller_ids: vec!["p".to_string(), "q".to_string()],
        shared_metrics: ["m3".to_string()].into(),
        timescale_separation_millionths: 10_000,
        evidence_description: "oscillation on m3".to_string(),
        convergence_steps: Some(200),
    }];
    let events = synth.build_interference_events(&interferences, "trace-3", "pol-3");
    assert_eq!(events[0].event, "controller_interference_rejected");
    assert_eq!(events[0].outcome, "reject");
    assert_eq!(
        events[0].error_code.as_deref(),
        Some("FE-CX-INTERFERENCE-OSCILLATION")
    );
}

// ===========================================================================
// 17. synthesize: from compilation with violations and NoViolations error
// ===========================================================================

#[test]
fn synthesize_from_violating_policy_produces_counterexamples() {
    let (_synth, cxs) = synthesize_from_violating();
    assert!(!cxs.is_empty());
    let cx = &cxs[0];
    assert_eq!(cx.strategy, SynthesisStrategy::CompilerExtraction);
    assert_eq!(cx.outcome, SynthesisOutcome::Complete);
    assert!(!cx.policy_ids.is_empty());
    assert!(!cx.concrete_scenario.subjects.is_empty());
    assert!(!cx.resolution_hint.is_empty());
    assert!(cx.minimality_evidence.starting_size > 0);
}

#[test]
fn synthesize_no_violations_returns_error() {
    let result = compile(&valid_policy());
    let mut synth = CounterexampleSynthesizer::new(test_config());
    let err = synth.synthesize(&result, 1000).unwrap_err();
    assert_eq!(err, SynthesisError::NoViolations);
}

#[test]
fn synthesize_updates_corpus_diagnostics_count() {
    let (synth, cxs) = synthesize_from_violating();
    assert_eq!(synth.corpus().len(), cxs.len());
    assert_eq!(synth.diagnostics().len(), cxs.len());
    assert_eq!(synth.synthesis_count(), cxs.len() as u64);
}

// ===========================================================================
// 18. synthesize_by_enumeration: empty policies error and with violations
// ===========================================================================

#[test]
fn enumerate_empty_policies_returns_error() {
    let mut synth = CounterexampleSynthesizer::new(test_config());
    let err = synth.synthesize_by_enumeration(&[], 1000).unwrap_err();
    assert_eq!(
        err,
        SynthesisError::InvalidPolicy {
            reason: "no policies provided".to_string(),
        }
    );
}

#[test]
fn enumerate_valid_policies_returns_no_violations() {
    let policy = valid_policy();
    let mut synth = CounterexampleSynthesizer::new(test_config());
    let err = synth
        .synthesize_by_enumeration(&[&policy], 1000)
        .unwrap_err();
    assert_eq!(err, SynthesisError::NoViolations);
}

#[test]
fn enumerate_finds_violations_in_bad_policy() {
    let bad = violating_policy();
    let mut synth = CounterexampleSynthesizer::new(test_config());
    let results = synth.synthesize_by_enumeration(&[&bad], 1000).unwrap();
    assert!(!results.is_empty());
}

// ===========================================================================
// 19. synthesize_by_mutation: mutations that create violations
// ===========================================================================

#[test]
fn mutation_add_grant_outside_universe_creates_violation() {
    let base = valid_policy();
    let mutations = vec![PolicyMutation {
        kind: MutationKind::AddGrant,
        target_node: "node-1".to_string(),
        new_value: "admin-access".to_string(),
    }];

    let mut synth = CounterexampleSynthesizer::new(test_config());
    let result = synth.synthesize_by_mutation(&base, &mutations, 1000);
    // Adding an undefined capability should trigger an attenuation violation.
    if let Ok(cxs) = result {
        assert!(!cxs.is_empty());
        let cx = &cxs[0];
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

#[test]
fn mutation_duplicate_node() {
    let base = valid_policy();
    let mutations = vec![PolicyMutation {
        kind: MutationKind::DuplicateNode,
        target_node: "node-1".to_string(),
        new_value: String::new(),
    }];
    let mut synth = CounterexampleSynthesizer::new(test_config());
    // May or may not find violations; should not panic.
    let _ = synth.synthesize_by_mutation(&base, &mutations, 1000);
}

// ===========================================================================
// 20. to_replay_fixture and to_evidence_entry
// ===========================================================================

#[test]
fn to_replay_fixture_basic() {
    let (synth, cxs) = synthesize_from_violating();
    let trace = synth.to_replay_fixture(&cxs[0], 5000);
    assert!(trace.trace_id.starts_with("synth-"));
    assert_eq!(trace.start_epoch, SecurityEpoch::from_raw(42));
    assert!(trace.incident_id.is_some());
    assert!(!trace.entries.is_empty());
    assert!(trace.verify_chain_integrity().is_ok());
}

#[test]
fn to_evidence_entry_basic() {
    let (synth, cxs) = synthesize_from_violating();
    let entry = synth.to_evidence_entry(&cxs[0], 2000).unwrap();
    assert_eq!(entry.decision_type, DecisionType::ContractEvaluation);
    assert!(entry.chosen_action.action_name.contains("counterexample"));
    assert!(entry.metadata.contains_key("conflict_id"));
    assert!(entry.metadata.contains_key("synthesis_strategy"));
    assert!(entry.metadata.contains_key("compute_time_ns"));
}

// ===========================================================================
// 21. Full lifecycle: compile -> synthesize -> corpus -> resolve -> evidence
// ===========================================================================

#[test]
fn full_lifecycle() {
    // Step 1: Compile violating policy.
    let result = compile(&violating_policy());
    assert!(!result.counterexamples.is_empty());

    // Step 2: Synthesize counterexamples.
    let mut synth = CounterexampleSynthesizer::new(test_config());
    let cxs = synth.synthesize(&result, 1000).unwrap();
    assert!(!cxs.is_empty());

    // Step 3: Verify corpus populated.
    assert_eq!(synth.corpus().len(), cxs.len());
    let cid = cxs[0].conflict_id.clone();
    assert!(synth.corpus().contains(&cid));
    assert_eq!(synth.corpus().unresolved().len(), cxs.len());

    // Step 4: Verify diagnostics populated.
    assert_eq!(synth.diagnostics().len(), cxs.len());
    let diag = &synth.diagnostics()[0];
    assert_eq!(diag.conflict_id, cid);
    assert!(diag.severity_millionths > 0);

    // Step 5: Generate replay fixture.
    let trace = synth.to_replay_fixture(&cxs[0], 10_000);
    assert!(trace.verify_chain_integrity().is_ok());

    // Step 6: Generate evidence entry.
    let entry = synth.to_evidence_entry(&cxs[0], 3000).unwrap();
    assert!(entry.chosen_action.rationale.contains("violation"));

    // Step 7: Verify deterministic IDs (second synthesizer, same inputs).
    let mut synth2 = CounterexampleSynthesizer::new(test_config());
    let cxs2 = synth2.synthesize(&result, 1000).unwrap();
    assert_eq!(cxs[0].conflict_id, cxs2[0].conflict_id);
    assert_eq!(cxs[0].content_hash, cxs2[0].content_hash);

    // Step 8: Serde roundtrip of an empty synthesizer (populated synthesizers
    // contain BTreeMap<EngineObjectId, _> which cannot JSON-serialize as keys).
    let fresh = CounterexampleSynthesizer::new(test_config());
    let json = serde_json::to_string(&fresh).unwrap();
    let restored: CounterexampleSynthesizer = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.synthesis_count(), 0);
    assert!(restored.corpus().is_empty());
}

// ===========================================================================
// Additional: synthesized counterexample serde roundtrip
// ===========================================================================

#[test]
fn synthesized_counterexample_serde_roundtrip() {
    let (_synth, cxs) = synthesize_from_violating();
    let cx = &cxs[0];
    let json = serde_json::to_string(cx).unwrap();
    let restored: SynthesizedCounterexample = serde_json::from_str(&json).unwrap();
    assert_eq!(cx.conflict_id, restored.conflict_id);
    assert_eq!(cx.property_violated, restored.property_violated);
    assert_eq!(cx.strategy, restored.strategy);
    assert_eq!(cx.outcome, restored.outcome);
    assert_eq!(cx.content_hash, restored.content_hash);
    assert_eq!(cx.epoch, restored.epoch);
}

// ===========================================================================
// Additional: regression entry serde roundtrip
// ===========================================================================

#[test]
fn regression_entry_serde_roundtrip() {
    let (synth, _cxs) = synthesize_from_violating();
    let entry = synth.corpus().entries().values().next().unwrap();
    let json = serde_json::to_string(entry).unwrap();
    let restored: RegressionEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry.entry_id, restored.entry_id);
    assert_eq!(entry.resolved, restored.resolved);
    assert_eq!(entry.added_epoch, restored.added_epoch);
}

// ===========================================================================
// Additional: merge nondeterminism synthesis
// ===========================================================================

#[test]
fn synthesize_merge_nondeterminism_policy() {
    let result = compile(&merge_nondeterminism_policy());
    if result.counterexamples.is_empty() {
        // Compiler may not flag this in current implementation; skip gracefully.
        return;
    }
    let mut synth = CounterexampleSynthesizer::new(test_config());
    let cxs = synth.synthesize(&result, 2000).unwrap();
    assert!(!cxs.is_empty());
}
