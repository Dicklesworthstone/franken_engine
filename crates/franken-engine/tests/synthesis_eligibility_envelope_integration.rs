//! Integration tests for `synthesis_eligibility_envelope` module.
//!
//! Validates public API, serde contracts, determinism, eligibility evaluation,
//! corpus management, and envelope generation.

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

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::synthesis_eligibility_envelope::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(400)
}

fn pure_schema(id: &str) -> KernelSchema {
    let mut ops = BTreeMap::new();
    ops.insert(OperationKind::Arithmetic, 10);
    ops.insert(OperationKind::Load, 5);
    KernelSchema::new(KernelSchemaInput {
        schema_id: id.into(),
        operation_counts: ops,
        branch_depth: 2,
        side_effects: BTreeSet::new(),
        input_shape_stability: 950_000,
        output_shape_stability: 970_000,
        input_shape_count: 1,
        output_shape_count: 1,
    })
}

fn effectful_schema(id: &str) -> KernelSchema {
    let mut ops = BTreeMap::new();
    ops.insert(OperationKind::Arithmetic, 5);
    ops.insert(OperationKind::Store, 3);
    let effects = BTreeSet::from([SideEffectKind::PropertyWrite]);
    KernelSchema::new(KernelSchemaInput {
        schema_id: id.into(),
        operation_counts: ops,
        branch_depth: 1,
        side_effects: effects,
        input_shape_stability: 920_000,
        output_shape_stability: 940_000,
        input_shape_count: 2,
        output_shape_count: 1,
    })
}

fn oversized_schema(id: &str) -> KernelSchema {
    let mut ops = BTreeMap::new();
    ops.insert(OperationKind::Arithmetic, 300);
    KernelSchema::new(KernelSchemaInput {
        schema_id: id.into(),
        operation_counts: ops,
        branch_depth: 10,
        side_effects: BTreeSet::new(),
        input_shape_stability: 500_000,
        output_shape_stability: 500_000,
        input_shape_count: 5,
        output_shape_count: 5,
    })
}

fn global_mutation_schema(id: &str) -> KernelSchema {
    let mut ops = BTreeMap::new();
    ops.insert(OperationKind::Store, 1);
    let effects = BTreeSet::from([SideEffectKind::GlobalMutation]);
    KernelSchema::new(KernelSchemaInput {
        schema_id: id.into(),
        operation_counts: ops,
        branch_depth: 0,
        side_effects: effects,
        input_shape_stability: 950_000,
        output_shape_stability: 950_000,
        input_shape_count: 1,
        output_shape_count: 1,
    })
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("synthesis"));
}

#[test]
fn component_name() {
    assert_eq!(COMPONENT, "synthesis_eligibility_envelope");
}

#[test]
fn bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn policy_id_format() {
    assert!(POLICY_ID.starts_with("RGC-"));
}

#[test]
fn thresholds_positive() {
    const {
        assert!(MAX_SYNTHESIZABLE_BRANCH_DEPTH > 0);
        assert!(MAX_SYNTHESIZABLE_OPS > 0);
        assert!(HOT_SCHEMA_THRESHOLD > 0);
        assert!(MAX_SIDE_EFFECTS > 0);
        assert!(MIN_SHAPE_STABILITY > 0);
    }
}

// ---------------------------------------------------------------------------
// OperationKind
// ---------------------------------------------------------------------------

#[test]
fn op_kind_all_length() {
    assert_eq!(OperationKind::ALL.len(), 11);
}

#[test]
fn op_kind_names_unique() {
    let names: BTreeSet<&str> = OperationKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(names.len(), OperationKind::ALL.len());
}

#[test]
fn op_kind_display_matches_as_str() {
    for k in OperationKind::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

#[test]
fn op_kind_side_effect_semantics() {
    let with_effects: Vec<_> = OperationKind::ALL
        .iter()
        .filter(|k| k.has_side_effects())
        .collect();
    assert!(with_effects.len() >= 3);
    assert!(OperationKind::Store.has_side_effects());
    assert!(!OperationKind::Load.has_side_effects());
}

#[test]
fn op_kind_serde_all() {
    for k in OperationKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: OperationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// SideEffectKind
// ---------------------------------------------------------------------------

#[test]
fn side_effect_all_length() {
    assert_eq!(SideEffectKind::ALL.len(), 6);
}

#[test]
fn side_effect_names_unique() {
    let names: BTreeSet<&str> = SideEffectKind::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(names.len(), SideEffectKind::ALL.len());
}

#[test]
fn side_effect_display_matches_as_str() {
    for s in SideEffectKind::ALL {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn side_effect_proof_requirements() {
    assert!(SideEffectKind::PropertyWrite.requires_equivalence_proof());
    assert!(SideEffectKind::GlobalMutation.requires_equivalence_proof());
    assert!(!SideEffectKind::HeapAllocation.requires_equivalence_proof());
    assert!(!SideEffectKind::ThrowsException.requires_equivalence_proof());
}

#[test]
fn side_effect_serde_all() {
    for s in SideEffectKind::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: SideEffectKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// KernelSchema
// ---------------------------------------------------------------------------

#[test]
fn schema_pure_properties() {
    let s = pure_schema("p1");
    assert!(s.is_pure());
    assert!(s.has_stable_shapes());
    assert_eq!(s.total_ops, 15);
    assert_eq!(s.side_effect_count(), 0);
    assert_eq!(s.op_count(OperationKind::Arithmetic), 10);
    assert_eq!(s.op_count(OperationKind::Branch), 0);
}

#[test]
fn schema_effectful_properties() {
    let s = effectful_schema("e1");
    assert!(!s.is_pure());
    assert!(s.has_stable_shapes());
    assert_eq!(s.side_effect_count(), 1);
}

#[test]
fn schema_unstable_shapes() {
    let s = oversized_schema("os");
    assert!(!s.has_stable_shapes());
}

#[test]
fn schema_hash_deterministic() {
    let s1 = pure_schema("s1");
    let s2 = pure_schema("s1");
    assert_eq!(s1.content_hash, s2.content_hash);
}

#[test]
fn schema_different_ops_different_hash() {
    let s1 = pure_schema("s1");
    let s2 = effectful_schema("s1");
    assert_ne!(s1.content_hash, s2.content_hash);
}

#[test]
fn schema_serde_roundtrip() {
    let s = effectful_schema("test");
    let json = serde_json::to_string(&s).unwrap();
    let back: KernelSchema = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// RejectionReason
// ---------------------------------------------------------------------------

#[test]
fn rejection_tags_unique() {
    let reasons = vec![
        RejectionReason::TooManyOps { count: 1, limit: 1 },
        RejectionReason::ExcessiveBranchDepth { depth: 1, limit: 1 },
        RejectionReason::TooManySideEffects { count: 1, limit: 1 },
        RejectionReason::UnsafeGlobalMutation,
        RejectionReason::UnstableInputShapes {
            stability: 1,
            threshold: 1,
        },
        RejectionReason::UnstableOutputShapes {
            stability: 1,
            threshold: 1,
        },
        RejectionReason::InsufficientFrequency {
            frequency: 1,
            threshold: 1,
        },
        RejectionReason::ForbiddenByPolicy {
            policy_note: "x".into(),
        },
    ];
    let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
    assert_eq!(tags.len(), 8);
}

#[test]
fn rejection_display_contains_values() {
    let r = RejectionReason::TooManyOps {
        count: 300,
        limit: 256,
    };
    let s = r.to_string();
    assert!(s.contains("300"));
    assert!(s.contains("256"));
}

#[test]
fn rejection_serde_roundtrip() {
    let r = RejectionReason::ForbiddenByPolicy {
        policy_note: "test policy".into(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: RejectionReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// EligibilityVerdict
// ---------------------------------------------------------------------------

#[test]
fn verdict_eligible_semantics() {
    let v = EligibilityVerdict::Eligible;
    assert!(v.is_eligible());
    assert!(!v.is_rejected());
    assert_eq!(v.tag(), "eligible");
}

#[test]
fn verdict_caveats_semantics() {
    let v = EligibilityVerdict::EligibleWithCaveats {
        caveats: vec!["needs proof".into()],
    };
    assert!(v.is_eligible());
    assert!(!v.is_rejected());
    assert_eq!(v.tag(), "eligible_with_caveats");
}

#[test]
fn verdict_rejected_semantics() {
    let v = EligibilityVerdict::Rejected {
        reasons: vec![RejectionReason::UnsafeGlobalMutation],
    };
    assert!(!v.is_eligible());
    assert!(v.is_rejected());
    assert_eq!(v.tag(), "rejected");
}

#[test]
fn verdict_display() {
    let v = EligibilityVerdict::Rejected {
        reasons: vec![
            RejectionReason::UnsafeGlobalMutation,
            RejectionReason::TooManyOps {
                count: 300,
                limit: 256,
            },
        ],
    };
    assert!(v.to_string().contains("2 reasons"));
}

#[test]
fn verdict_serde_roundtrip() {
    let v = EligibilityVerdict::EligibleWithCaveats {
        caveats: vec!["caveat1".into(), "caveat2".into()],
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: EligibilityVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// evaluate_eligibility
// ---------------------------------------------------------------------------

#[test]
fn eval_pure_hot_schema_eligible() {
    let s = pure_schema("s1");
    let v = evaluate_eligibility(&s, 50_000);
    assert_eq!(v.tag(), "eligible");
}

#[test]
fn eval_effectful_schema_caveats() {
    let s = effectful_schema("s1");
    let v = evaluate_eligibility(&s, 50_000);
    assert_eq!(v.tag(), "eligible_with_caveats");
}

#[test]
fn eval_low_frequency_rejected() {
    let s = pure_schema("s1");
    let v = evaluate_eligibility(&s, 1_000);
    assert!(v.is_rejected());
}

#[test]
fn eval_oversized_rejected() {
    let s = oversized_schema("s1");
    let v = evaluate_eligibility(&s, 100_000);
    assert!(v.is_rejected());
}

#[test]
fn eval_global_mutation_rejected() {
    let s = global_mutation_schema("gm");
    let v = evaluate_eligibility(&s, 100_000);
    assert!(v.is_rejected());
}

#[test]
fn eval_at_threshold_boundary() {
    let s = pure_schema("s1");
    let v = evaluate_eligibility(&s, HOT_SCHEMA_THRESHOLD);
    assert!(v.is_eligible());
}

#[test]
fn eval_just_below_threshold() {
    let s = pure_schema("s1");
    let v = evaluate_eligibility(&s, HOT_SCHEMA_THRESHOLD - 1);
    assert!(v.is_rejected());
}

// ---------------------------------------------------------------------------
// SynthesisEnvelope
// ---------------------------------------------------------------------------

#[test]
fn envelope_empty() {
    let e = SynthesisEnvelope::compute(epoch(), &[], &BTreeMap::new());
    assert_eq!(e.total_count(), 0);
    assert_eq!(e.eligible_count, 0);
    assert_eq!(e.rejected_count, 0);
    assert_eq!(e.eligibility_rate(), 0);
    assert_eq!(e.schema_version, SCHEMA_VERSION);
}

#[test]
fn envelope_all_eligible() {
    let schemas = vec![pure_schema("s1"), pure_schema("s2")];
    let mut freqs = BTreeMap::new();
    freqs.insert("s1".into(), 100_000);
    freqs.insert("s2".into(), 200_000);
    let e = SynthesisEnvelope::compute(epoch(), &schemas, &freqs);
    assert_eq!(e.eligible_count, 2);
    assert_eq!(e.rejected_count, 0);
    assert_eq!(e.eligibility_rate(), 1_000_000);
}

#[test]
fn envelope_mixed_eligibility() {
    let schemas = vec![pure_schema("good"), oversized_schema("bad")];
    let mut freqs = BTreeMap::new();
    freqs.insert("good".into(), 100_000);
    freqs.insert("bad".into(), 50_000);
    let e = SynthesisEnvelope::compute(epoch(), &schemas, &freqs);
    assert_eq!(e.eligible_count, 1);
    assert_eq!(e.rejected_count, 1);
    assert_eq!(e.eligible_frequency_mass, 100_000);
}

#[test]
fn envelope_verdict_lookup() {
    let schemas = vec![pure_schema("s1"), oversized_schema("s2")];
    let mut freqs = BTreeMap::new();
    freqs.insert("s1".into(), 50_000);
    freqs.insert("s2".into(), 50_000);
    let e = SynthesisEnvelope::compute(epoch(), &schemas, &freqs);
    assert!(e.verdict_for("s1").unwrap().is_eligible());
    assert!(e.verdict_for("s2").unwrap().is_rejected());
    assert!(e.verdict_for("nonexistent").is_none());
}

#[test]
fn envelope_eligible_ids() {
    let schemas = vec![pure_schema("a"), pure_schema("b"), oversized_schema("c")];
    let mut freqs = BTreeMap::new();
    freqs.insert("a".into(), 50_000);
    freqs.insert("b".into(), 50_000);
    freqs.insert("c".into(), 50_000);
    let e = SynthesisEnvelope::compute(epoch(), &schemas, &freqs);
    let ids = e.eligible_ids();
    assert_eq!(ids.len(), 2);
}

#[test]
fn envelope_rejected_ids() {
    let schemas = vec![
        pure_schema("g"),
        oversized_schema("b1"),
        oversized_schema("b2"),
    ];
    let mut freqs = BTreeMap::new();
    freqs.insert("g".into(), 50_000);
    freqs.insert("b1".into(), 50_000);
    freqs.insert("b2".into(), 50_000);
    let e = SynthesisEnvelope::compute(epoch(), &schemas, &freqs);
    assert_eq!(e.rejected_ids().len(), 2);
}

#[test]
fn envelope_hash_deterministic() {
    let schemas = vec![pure_schema("s1")];
    let mut freqs = BTreeMap::new();
    freqs.insert("s1".into(), 50_000);
    let e1 = SynthesisEnvelope::compute(epoch(), &schemas, &freqs);
    let e2 = SynthesisEnvelope::compute(epoch(), &schemas, &freqs);
    assert_eq!(e1.content_hash, e2.content_hash);
}

#[test]
fn envelope_different_input_different_hash() {
    let schemas = vec![pure_schema("s1")];
    let mut f1 = BTreeMap::new();
    f1.insert("s1".into(), 50_000);
    let mut f2 = BTreeMap::new();
    f2.insert("s1".into(), 100_000);
    let e1 = SynthesisEnvelope::compute(epoch(), &schemas, &f1);
    let e2 = SynthesisEnvelope::compute(epoch(), &schemas, &f2);
    assert_ne!(e1.content_hash, e2.content_hash);
}

#[test]
fn envelope_serde_roundtrip() {
    let schemas = vec![pure_schema("s1"), effectful_schema("s2")];
    let mut freqs = BTreeMap::new();
    freqs.insert("s1".into(), 100_000);
    freqs.insert("s2".into(), 80_000);
    let e = SynthesisEnvelope::compute(epoch(), &schemas, &freqs);
    let json = serde_json::to_string(&e).unwrap();
    let back: SynthesisEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// KernelCorpus
// ---------------------------------------------------------------------------

#[test]
fn corpus_empty() {
    let c = KernelCorpus::new();
    assert_eq!(c.schema_count(), 0);
    assert_eq!(c.total_observations, 0);
}

#[test]
fn corpus_default() {
    let c = KernelCorpus::default();
    assert_eq!(c.schema_count(), 0);
}

#[test]
fn corpus_observe_single() {
    let mut c = KernelCorpus::new();
    c.observe(pure_schema("s1"), 100);
    assert_eq!(c.schema_count(), 1);
    assert_eq!(c.total_observations, 100);
}

#[test]
fn corpus_observe_accumulates() {
    let mut c = KernelCorpus::new();
    c.observe(pure_schema("s1"), 50);
    c.observe(pure_schema("s1"), 30);
    assert_eq!(c.schema_count(), 1);
    assert_eq!(c.total_observations, 80);
}

#[test]
fn corpus_multiple_schemas() {
    let mut c = KernelCorpus::new();
    c.observe(pure_schema("s1"), 50);
    c.observe(effectful_schema("s2"), 50);
    assert_eq!(c.schema_count(), 2);
    assert_eq!(c.total_observations, 100);
}

#[test]
fn corpus_frequencies() {
    let mut c = KernelCorpus::new();
    c.observe(pure_schema("s1"), 750);
    c.observe(effectful_schema("s2"), 250);
    let freqs = c.frequencies();
    assert_eq!(freqs.get("s1").copied(), Some(750_000));
    assert_eq!(freqs.get("s2").copied(), Some(250_000));
}

#[test]
fn corpus_hot_schemas() {
    let mut c = KernelCorpus::new();
    c.observe(pure_schema("hot"), 900);
    c.observe(effectful_schema("cold"), 1);
    let hot = c.hot_schemas();
    assert_eq!(hot.len(), 1);
    assert_eq!(hot[0].schema_id, "hot");
}

#[test]
fn corpus_compute_envelope() {
    let mut c = KernelCorpus::new();
    c.observe(pure_schema("good"), 800);
    c.observe(oversized_schema("bad"), 200);
    let e = c.compute_envelope(epoch());
    assert_eq!(e.total_count(), 2);
    assert_eq!(e.eligible_count, 1);
}

#[test]
fn corpus_serde_roundtrip() {
    let mut c = KernelCorpus::new();
    c.observe(pure_schema("s1"), 100);
    c.observe(effectful_schema("s2"), 50);
    let json = serde_json::to_string(&c).unwrap();
    let back: KernelCorpus = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}
