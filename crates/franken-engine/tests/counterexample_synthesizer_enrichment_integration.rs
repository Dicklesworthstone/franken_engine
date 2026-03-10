#![forbid(unsafe_code)]
//! Enrichment integration tests for `counterexample_synthesizer`.
//!
//! Adds Display exactness, Debug distinctness, serde exact tags,
//! JSON field-name stability, serde roundtrips, config defaults,
//! initial-state checks, and constants beyond the existing 51 integration tests.

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
    ConcreteScenario, ControllerInterference, ControllerInterferenceEvent,
    CounterexampleSynthesizer, DEFAULT_BUDGET_NS, DEFAULT_MAX_MINIMIZATION_ROUNDS,
    InterferenceKind, MinimalityEvidence, RegressionCorpus, SynthesisConfig, SynthesisError,
    SynthesisOutcome, SynthesisStrategy,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// 1) Constants — exact values
// ===========================================================================

#[test]
fn default_budget_ns_is_30_seconds() {
    assert_eq!(DEFAULT_BUDGET_NS, 30_000_000_000);
}

#[test]
fn default_max_minimization_rounds_is_50() {
    assert_eq!(DEFAULT_MAX_MINIMIZATION_ROUNDS, 50);
}

// ===========================================================================
// 2) SynthesisStrategy — Display exact values
// ===========================================================================

#[test]
fn synthesis_strategy_display_compiler_extraction() {
    assert_eq!(
        SynthesisStrategy::CompilerExtraction.to_string(),
        "compiler-extraction"
    );
}

#[test]
fn synthesis_strategy_display_enumeration() {
    assert_eq!(SynthesisStrategy::Enumeration.to_string(), "enumeration");
}

#[test]
fn synthesis_strategy_display_mutation() {
    assert_eq!(SynthesisStrategy::Mutation.to_string(), "mutation");
}

#[test]
fn synthesis_strategy_display_time_bounded() {
    assert_eq!(SynthesisStrategy::TimeBounded.to_string(), "time-bounded");
}

// ===========================================================================
// 3) SynthesisStrategy — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_synthesis_strategy() {
    let variants = [
        format!("{:?}", SynthesisStrategy::CompilerExtraction),
        format!("{:?}", SynthesisStrategy::Enumeration),
        format!("{:?}", SynthesisStrategy::Mutation),
        format!("{:?}", SynthesisStrategy::TimeBounded),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 4) SynthesisStrategy — serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_synthesis_strategy_all() {
    for s in [
        SynthesisStrategy::CompilerExtraction,
        SynthesisStrategy::Enumeration,
        SynthesisStrategy::Mutation,
        SynthesisStrategy::TimeBounded,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: SynthesisStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

// ===========================================================================
// 5) SynthesisOutcome — Display exact values
// ===========================================================================

#[test]
fn synthesis_outcome_display_complete() {
    assert_eq!(SynthesisOutcome::Complete.to_string(), "complete");
}

#[test]
fn synthesis_outcome_display_partial() {
    assert_eq!(SynthesisOutcome::Partial.to_string(), "partial");
}

#[test]
fn synthesis_outcome_display_incomplete() {
    assert_eq!(SynthesisOutcome::Incomplete.to_string(), "incomplete");
}

// ===========================================================================
// 6) SynthesisOutcome — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_synthesis_outcome() {
    let variants = [
        format!("{:?}", SynthesisOutcome::Complete),
        format!("{:?}", SynthesisOutcome::Partial),
        format!("{:?}", SynthesisOutcome::Incomplete),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 7) SynthesisOutcome — serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_synthesis_outcome_all() {
    for o in [
        SynthesisOutcome::Complete,
        SynthesisOutcome::Partial,
        SynthesisOutcome::Incomplete,
    ] {
        let json = serde_json::to_string(&o).unwrap();
        let rt: SynthesisOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, rt);
    }
}

// ===========================================================================
// 8) InterferenceKind — Display exact values
// ===========================================================================

#[test]
fn interference_kind_display_invariant_invalidation() {
    assert_eq!(
        InterferenceKind::InvariantInvalidation.to_string(),
        "invariant-invalidation"
    );
}

#[test]
fn interference_kind_display_oscillation() {
    assert_eq!(InterferenceKind::Oscillation.to_string(), "oscillation");
}

#[test]
fn interference_kind_display_timescale_conflict() {
    assert_eq!(
        InterferenceKind::TimescaleConflict.to_string(),
        "timescale-conflict"
    );
}

// ===========================================================================
// 9) InterferenceKind — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_interference_kind() {
    let variants = [
        format!("{:?}", InterferenceKind::InvariantInvalidation),
        format!("{:?}", InterferenceKind::Oscillation),
        format!("{:?}", InterferenceKind::TimescaleConflict),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 10) InterferenceKind — serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_interference_kind_all() {
    for k in [
        InterferenceKind::InvariantInvalidation,
        InterferenceKind::Oscillation,
        InterferenceKind::TimescaleConflict,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let rt: InterferenceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, rt);
    }
}

// ===========================================================================
// 11) SynthesisError — Display exact values
// ===========================================================================

#[test]
fn synthesis_error_display_no_violations() {
    let e = SynthesisError::NoViolations;
    assert_eq!(e.to_string(), "no violations found in compilation result");
}

#[test]
fn synthesis_error_display_timeout() {
    let e = SynthesisError::Timeout {
        elapsed_ns: 100,
        budget_ns: 200,
        partial: None,
    };
    let s = e.to_string();
    assert!(s.contains("100"), "{s}");
    assert!(s.contains("200"), "{s}");
}

#[test]
fn synthesis_error_display_invalid_policy() {
    let e = SynthesisError::InvalidPolicy {
        reason: "empty".into(),
    };
    let s = e.to_string();
    assert!(s.contains("empty"), "{s}");
}

#[test]
fn synthesis_error_display_id_derivation() {
    let e = SynthesisError::IdDerivation("bad id".into());
    let s = e.to_string();
    assert!(s.contains("bad id"), "{s}");
}

#[test]
fn synthesis_error_display_minimization_exhausted() {
    let e = SynthesisError::MinimizationExhausted { rounds: 42 };
    let s = e.to_string();
    assert!(s.contains("42"), "{s}");
}

#[test]
fn synthesis_error_display_compiler_failure() {
    let e = SynthesisError::CompilerFailure("crash".into());
    let s = e.to_string();
    assert!(s.contains("crash"), "{s}");
}

// ===========================================================================
// 12) SynthesisError — is std::error::Error
// ===========================================================================

#[test]
fn synthesis_error_is_std_error() {
    let e = SynthesisError::NoViolations;
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 13) SynthesisError — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_synthesis_error() {
    let variants = [
        format!("{:?}", SynthesisError::NoViolations),
        format!(
            "{:?}",
            SynthesisError::Timeout {
                elapsed_ns: 0,
                budget_ns: 0,
                partial: None
            }
        ),
        format!("{:?}", SynthesisError::InvalidPolicy { reason: "x".into() }),
        format!("{:?}", SynthesisError::IdDerivation("x".into())),
        format!("{:?}", SynthesisError::MinimizationExhausted { rounds: 0 }),
        format!("{:?}", SynthesisError::CompilerFailure("x".into())),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 6);
}

// ===========================================================================
// 14) SynthesisError — serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_synthesis_error_no_violations() {
    let e = SynthesisError::NoViolations;
    let json = serde_json::to_string(&e).unwrap();
    let rt: SynthesisError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, rt);
}

#[test]
fn serde_roundtrip_synthesis_error_invalid_policy() {
    let e = SynthesisError::InvalidPolicy {
        reason: "no rules".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let rt: SynthesisError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, rt);
}

#[test]
fn serde_roundtrip_synthesis_error_minimization_exhausted() {
    let e = SynthesisError::MinimizationExhausted { rounds: 50 };
    let json = serde_json::to_string(&e).unwrap();
    let rt: SynthesisError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, rt);
}

// ===========================================================================
// 15) SynthesisConfig — default exact values
// ===========================================================================

#[test]
fn synthesis_config_default_budget_ns() {
    let c = SynthesisConfig::default();
    assert_eq!(c.budget_ns, DEFAULT_BUDGET_NS);
}

#[test]
fn synthesis_config_default_max_minimization_rounds() {
    let c = SynthesisConfig::default();
    assert_eq!(c.max_minimization_rounds, DEFAULT_MAX_MINIMIZATION_ROUNDS);
}

#[test]
fn synthesis_config_default_preferred_strategy() {
    let c = SynthesisConfig::default();
    assert_eq!(c.preferred_strategy, SynthesisStrategy::CompilerExtraction);
}

#[test]
fn synthesis_config_default_detect_controller_interference() {
    let c = SynthesisConfig::default();
    assert!(c.detect_controller_interference);
}

#[test]
fn synthesis_config_default_max_enumeration_candidates() {
    let c = SynthesisConfig::default();
    assert_eq!(c.max_enumeration_candidates, 100);
}

#[test]
fn synthesis_config_default_epoch() {
    let c = SynthesisConfig::default();
    assert_eq!(c.epoch, SecurityEpoch::from_raw(1));
}

#[test]
fn synthesis_config_default_signing_key_bytes_len() {
    let c = SynthesisConfig::default();
    assert_eq!(c.signing_key_bytes.len(), 32);
}

// ===========================================================================
// 16) SynthesisConfig — serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_synthesis_config() {
    let c = SynthesisConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let rt: SynthesisConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, rt);
}

// ===========================================================================
// 17) JSON field-name stability — SynthesisConfig
// ===========================================================================

#[test]
fn json_fields_synthesis_config() {
    let c = SynthesisConfig::default();
    let v: serde_json::Value = serde_json::to_value(&c).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "budget_ns",
        "max_minimization_rounds",
        "preferred_strategy",
        "detect_controller_interference",
        "max_enumeration_candidates",
        "epoch",
        "signing_key_bytes",
    ] {
        assert!(
            obj.contains_key(key),
            "SynthesisConfig missing field: {key}"
        );
    }
}

// ===========================================================================
// 18) JSON field-name stability — ConcreteScenario
// ===========================================================================

#[test]
fn json_fields_concrete_scenario() {
    let s = ConcreteScenario {
        subjects: BTreeSet::from(["subj".into()]),
        capabilities: BTreeSet::from(["cap".into()]),
        conditions: BTreeMap::from([("k".into(), "v".into())]),
        merge_ordering: vec!["step1".into()],
        input_state: BTreeMap::new(),
    };
    let v: serde_json::Value = serde_json::to_value(&s).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "subjects",
        "capabilities",
        "conditions",
        "merge_ordering",
        "input_state",
    ] {
        assert!(
            obj.contains_key(key),
            "ConcreteScenario missing field: {key}"
        );
    }
}

// ===========================================================================
// 19) JSON field-name stability — MinimalityEvidence
// ===========================================================================

#[test]
fn json_fields_minimality_evidence() {
    let m = MinimalityEvidence {
        rounds: 10,
        elements_removed: 3,
        starting_size: 8,
        final_size: 5,
        is_fixed_point: true,
    };
    let v: serde_json::Value = serde_json::to_value(&m).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "rounds",
        "elements_removed",
        "starting_size",
        "final_size",
        "is_fixed_point",
    ] {
        assert!(
            obj.contains_key(key),
            "MinimalityEvidence missing field: {key}"
        );
    }
}

// ===========================================================================
// 20) JSON field-name stability — ControllerInterference
// ===========================================================================

#[test]
fn json_fields_controller_interference() {
    let ci = ControllerInterference {
        kind: InterferenceKind::Oscillation,
        controller_ids: vec!["c1".into(), "c2".into()],
        shared_metrics: BTreeSet::from(["latency".into()]),
        timescale_separation_millionths: 500_000,
        evidence_description: "cyclic".into(),
        convergence_steps: Some(10),
    };
    let v: serde_json::Value = serde_json::to_value(&ci).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "kind",
        "controller_ids",
        "shared_metrics",
        "timescale_separation_millionths",
        "evidence_description",
        "convergence_steps",
    ] {
        assert!(
            obj.contains_key(key),
            "ControllerInterference missing field: {key}"
        );
    }
}

// ===========================================================================
// 21) JSON field-name stability — ControllerInterferenceEvent
// ===========================================================================

#[test]
fn json_fields_controller_interference_event() {
    let cie = ControllerInterferenceEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "ok".into(),
        error_code: None,
        kind: InterferenceKind::TimescaleConflict,
        controller_ids: vec!["c1".into()],
        shared_metrics: vec!["mem".into()],
        timescale_separation_millionths: 0,
    };
    let v: serde_json::Value = serde_json::to_value(&cie).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "kind",
        "controller_ids",
        "shared_metrics",
        "timescale_separation_millionths",
    ] {
        assert!(
            obj.contains_key(key),
            "ControllerInterferenceEvent missing field: {key}"
        );
    }
}

// ===========================================================================
// 22) Serde roundtrips — structs
// ===========================================================================

#[test]
fn serde_roundtrip_concrete_scenario() {
    let s = ConcreteScenario {
        subjects: BTreeSet::from(["s1".into(), "s2".into()]),
        capabilities: BTreeSet::from(["read".into()]),
        conditions: BTreeMap::from([("pre".into(), "true".into())]),
        merge_ordering: vec!["p1".into(), "p2".into()],
        input_state: BTreeMap::from([("key".into(), "val".into())]),
    };
    let json = serde_json::to_string(&s).unwrap();
    let rt: ConcreteScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(s, rt);
}

#[test]
fn serde_roundtrip_minimality_evidence() {
    let m = MinimalityEvidence {
        rounds: 5,
        elements_removed: 2,
        starting_size: 7,
        final_size: 5,
        is_fixed_point: false,
    };
    let json = serde_json::to_string(&m).unwrap();
    let rt: MinimalityEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(m, rt);
}

#[test]
fn serde_roundtrip_controller_interference() {
    let ci = ControllerInterference {
        kind: InterferenceKind::InvariantInvalidation,
        controller_ids: vec!["c1".into()],
        shared_metrics: BTreeSet::from(["cpu".into()]),
        timescale_separation_millionths: 100_000,
        evidence_description: "test".into(),
        convergence_steps: None,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let rt: ControllerInterference = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, rt);
}

#[test]
fn serde_roundtrip_controller_interference_event() {
    let cie = ControllerInterferenceEvent {
        trace_id: "t1".into(),
        decision_id: "d1".into(),
        policy_id: "p1".into(),
        component: "comp".into(),
        event: "detect".into(),
        outcome: "blocked".into(),
        error_code: Some("interference".into()),
        kind: InterferenceKind::Oscillation,
        controller_ids: vec!["c1".into(), "c2".into()],
        shared_metrics: vec!["latency".into()],
        timescale_separation_millionths: 250_000,
    };
    let json = serde_json::to_string(&cie).unwrap();
    let rt: ControllerInterferenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(cie, rt);
}

// ===========================================================================
// 23) RegressionCorpus — initial state
// ===========================================================================

#[test]
fn regression_corpus_initial_empty() {
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

// ===========================================================================
// 24) CounterexampleSynthesizer — initial state
// ===========================================================================

#[test]
fn synthesizer_initial_state() {
    let synth = CounterexampleSynthesizer::new(SynthesisConfig::default());
    // Just verify it constructs without panic
    let _ = format!("{synth:?}");
}

// ===========================================================================
// 25) SynthesisConfig — JSON field-name stability
// ===========================================================================

#[test]
fn synthesis_config_json_fields_complete() {
    let c = SynthesisConfig::default();
    let v: serde_json::Value = serde_json::to_value(&c).unwrap();
    let obj = v.as_object().unwrap();
    assert_eq!(
        obj.len(),
        7,
        "SynthesisConfig has unexpected number of fields"
    );
}
