//! Enrichment integration tests for `synthesis_eligibility_envelope`.
//!
//! Covers Copy/Clone semantics, BTreeSet dedup, Debug/Display uniqueness,
//! serde JSON field stability, Clone independence, determinism, boundary
//! conditions, and cross-cutting invariants NOT already tested in the base
//! integration file.

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

fn ep() -> SecurityEpoch {
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
    let effects = BTreeSet::from([SideEffectKind::PropertyWrite, SideEffectKind::ArrayWrite]);
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

// ===========================================================================
// OperationKind enrichment
// ===========================================================================

#[test]
fn enrichment_op_kind_copy_semantics() {
    let a = OperationKind::Arithmetic;
    let b = a;
    assert_eq!(a, b);
    assert_eq!(a.as_str(), "arithmetic");
}

#[test]
fn enrichment_op_kind_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for &k in OperationKind::ALL {
        set.insert(k);
        set.insert(k);
    }
    assert_eq!(set.len(), 11);
}

#[test]
fn enrichment_op_kind_debug_all_unique() {
    let debugs: BTreeSet<String> = OperationKind::ALL
        .iter()
        .map(|k| format!("{k:?}"))
        .collect();
    assert_eq!(debugs.len(), 11);
}

#[test]
fn enrichment_op_kind_display_all_unique() {
    let displays: BTreeSet<String> = OperationKind::ALL.iter().map(|k| format!("{k}")).collect();
    assert_eq!(displays.len(), 11);
}

#[test]
fn enrichment_op_kind_as_str_all_unique() {
    let strs: BTreeSet<&str> = OperationKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(strs.len(), 11);
}

#[test]
fn enrichment_op_kind_side_effects_exactly_three() {
    let with_effects: Vec<_> = OperationKind::ALL
        .iter()
        .filter(|k| k.has_side_effects())
        .collect();
    assert_eq!(with_effects.len(), 3);
    let names: BTreeSet<&str> = with_effects.iter().map(|k| k.as_str()).collect();
    assert!(names.contains("store"));
    assert!(names.contains("call"));
    assert!(names.contains("allocation"));
}

// ===========================================================================
// SideEffectKind enrichment
// ===========================================================================

#[test]
fn enrichment_side_effect_copy_semantics() {
    let a = SideEffectKind::GlobalMutation;
    let b = a;
    assert_eq!(a, b);
    assert_eq!(a.as_str(), "global_mutation");
}

#[test]
fn enrichment_side_effect_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for &s in SideEffectKind::ALL {
        set.insert(s);
        set.insert(s);
    }
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_side_effect_debug_all_unique() {
    let debugs: BTreeSet<String> = SideEffectKind::ALL
        .iter()
        .map(|s| format!("{s:?}"))
        .collect();
    assert_eq!(debugs.len(), 6);
}

#[test]
fn enrichment_side_effect_display_all_unique() {
    let displays: BTreeSet<String> = SideEffectKind::ALL.iter().map(|s| format!("{s}")).collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_side_effect_proof_exactly_four() {
    let proof_needed: Vec<_> = SideEffectKind::ALL
        .iter()
        .filter(|s| s.requires_equivalence_proof())
        .collect();
    assert_eq!(proof_needed.len(), 4);
}

// ===========================================================================
// KernelSchemaInput enrichment
// ===========================================================================

#[test]
fn enrichment_schema_input_clone_independence() {
    let original = KernelSchemaInput {
        schema_id: "s1".into(),
        operation_counts: BTreeMap::new(),
        branch_depth: 2,
        side_effects: BTreeSet::new(),
        input_shape_stability: 950_000,
        output_shape_stability: 970_000,
        input_shape_count: 1,
        output_shape_count: 1,
    };
    let mut cloned = original.clone();
    cloned.schema_id = "s2".to_string();
    assert_eq!(original.schema_id, "s1");
    assert_eq!(cloned.schema_id, "s2");
}

#[test]
fn enrichment_schema_input_json_field_names() {
    let input = KernelSchemaInput {
        schema_id: "s1".into(),
        operation_counts: BTreeMap::new(),
        branch_depth: 2,
        side_effects: BTreeSet::new(),
        input_shape_stability: 950_000,
        output_shape_stability: 970_000,
        input_shape_count: 1,
        output_shape_count: 1,
    };
    let json = serde_json::to_string(&input).unwrap();
    assert!(json.contains("\"schema_id\""));
    assert!(json.contains("\"operation_counts\""));
    assert!(json.contains("\"branch_depth\""));
    assert!(json.contains("\"side_effects\""));
    assert!(json.contains("\"input_shape_stability\""));
    assert!(json.contains("\"output_shape_stability\""));
    assert!(json.contains("\"input_shape_count\""));
    assert!(json.contains("\"output_shape_count\""));
}

#[test]
fn enrichment_schema_input_debug_nonempty() {
    let input = KernelSchemaInput {
        schema_id: "s1".into(),
        operation_counts: BTreeMap::new(),
        branch_depth: 2,
        side_effects: BTreeSet::new(),
        input_shape_stability: 950_000,
        output_shape_stability: 970_000,
        input_shape_count: 1,
        output_shape_count: 1,
    };
    let dbg = format!("{input:?}");
    assert!(dbg.contains("KernelSchemaInput"));
}

// ===========================================================================
// KernelSchema enrichment
// ===========================================================================

#[test]
fn enrichment_schema_clone_independence() {
    let original = pure_schema("s1");
    let mut cloned = original.clone();
    cloned.branch_depth = 99;
    assert_eq!(original.branch_depth, 2);
    assert_eq!(cloned.branch_depth, 99);
}

#[test]
fn enrichment_schema_json_field_names() {
    let s = pure_schema("s1");
    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"schema_id\""));
    assert!(json.contains("\"operation_counts\""));
    assert!(json.contains("\"total_ops\""));
    assert!(json.contains("\"branch_depth\""));
    assert!(json.contains("\"side_effects\""));
    assert!(json.contains("\"input_shape_stability\""));
    assert!(json.contains("\"output_shape_stability\""));
    assert!(json.contains("\"input_shape_count\""));
    assert!(json.contains("\"output_shape_count\""));
    assert!(json.contains("\"content_hash\""));
}

#[test]
fn enrichment_schema_debug_nonempty() {
    let s = pure_schema("s1");
    let dbg = format!("{s:?}");
    assert!(dbg.contains("KernelSchema"));
}

#[test]
fn enrichment_schema_total_ops_sum() {
    let s = effectful_schema("s1");
    let manual_sum: u32 = s.operation_counts.values().sum();
    assert_eq!(s.total_ops, manual_sum);
}

#[test]
fn enrichment_schema_op_count_missing_kind_returns_zero() {
    let s = pure_schema("s1");
    assert_eq!(s.op_count(OperationKind::StringOp), 0);
    assert_eq!(s.op_count(OperationKind::Allocation), 0);
}

// ===========================================================================
// RejectionReason enrichment
// ===========================================================================

#[test]
fn enrichment_rejection_clone_independence() {
    let original = RejectionReason::TooManyOps {
        count: 300,
        limit: 256,
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_rejection_debug_all_unique() {
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
    let debugs: BTreeSet<String> = reasons.iter().map(|r| format!("{r:?}")).collect();
    assert_eq!(debugs.len(), 8);
}

#[test]
fn enrichment_rejection_display_all_unique() {
    let reasons = vec![
        RejectionReason::TooManyOps {
            count: 300,
            limit: 256,
        },
        RejectionReason::ExcessiveBranchDepth {
            depth: 10,
            limit: 8,
        },
        RejectionReason::TooManySideEffects { count: 5, limit: 4 },
        RejectionReason::UnsafeGlobalMutation,
        RejectionReason::UnstableInputShapes {
            stability: 500,
            threshold: 900,
        },
        RejectionReason::UnstableOutputShapes {
            stability: 500,
            threshold: 900,
        },
        RejectionReason::InsufficientFrequency {
            frequency: 1000,
            threshold: 10000,
        },
        RejectionReason::ForbiddenByPolicy {
            policy_note: "test".into(),
        },
    ];
    let displays: BTreeSet<String> = reasons.iter().map(|r| format!("{r}")).collect();
    assert_eq!(displays.len(), 8);
}

#[test]
fn enrichment_rejection_serde_all_variants() {
    let reasons = vec![
        RejectionReason::TooManyOps {
            count: 300,
            limit: 256,
        },
        RejectionReason::ExcessiveBranchDepth {
            depth: 10,
            limit: 8,
        },
        RejectionReason::TooManySideEffects { count: 5, limit: 4 },
        RejectionReason::UnsafeGlobalMutation,
        RejectionReason::UnstableInputShapes {
            stability: 500,
            threshold: 900,
        },
        RejectionReason::UnstableOutputShapes {
            stability: 500,
            threshold: 900,
        },
        RejectionReason::InsufficientFrequency {
            frequency: 1000,
            threshold: 10000,
        },
        RejectionReason::ForbiddenByPolicy {
            policy_note: "test".into(),
        },
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: RejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

#[test]
fn enrichment_rejection_display_contains_values() {
    let r = RejectionReason::ExcessiveBranchDepth {
        depth: 12,
        limit: 8,
    };
    let s = format!("{r}");
    assert!(s.contains("12"));
    assert!(s.contains("8"));
}

#[test]
fn enrichment_rejection_forbidden_display_contains_note() {
    let r = RejectionReason::ForbiddenByPolicy {
        policy_note: "security review".into(),
    };
    assert!(format!("{r}").contains("security review"));
}

// ===========================================================================
// EligibilityVerdict enrichment
// ===========================================================================

#[test]
fn enrichment_verdict_clone_independence() {
    let original = EligibilityVerdict::EligibleWithCaveats {
        caveats: vec!["caveat1".into()],
    };
    let mut cloned = original.clone();
    if let EligibilityVerdict::EligibleWithCaveats { ref mut caveats } = cloned {
        caveats.push("caveat2".into());
    }
    if let EligibilityVerdict::EligibleWithCaveats { caveats } = &original {
        assert_eq!(caveats.len(), 1);
    }
}

#[test]
fn enrichment_verdict_debug_all_unique() {
    let verdicts = vec![
        EligibilityVerdict::Eligible,
        EligibilityVerdict::EligibleWithCaveats {
            caveats: vec!["x".into()],
        },
        EligibilityVerdict::Rejected {
            reasons: vec![RejectionReason::UnsafeGlobalMutation],
        },
    ];
    let debugs: BTreeSet<String> = verdicts.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 3);
}

#[test]
fn enrichment_verdict_display_all_unique() {
    let verdicts = vec![
        EligibilityVerdict::Eligible,
        EligibilityVerdict::EligibleWithCaveats {
            caveats: vec!["x".into()],
        },
        EligibilityVerdict::Rejected {
            reasons: vec![RejectionReason::UnsafeGlobalMutation],
        },
    ];
    let displays: BTreeSet<String> = verdicts.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_verdict_tag_all_unique() {
    let verdicts = vec![
        EligibilityVerdict::Eligible,
        EligibilityVerdict::EligibleWithCaveats { caveats: vec![] },
        EligibilityVerdict::Rejected { reasons: vec![] },
    ];
    let tags: BTreeSet<&str> = verdicts.iter().map(|v| v.tag()).collect();
    assert_eq!(tags.len(), 3);
}

#[test]
fn enrichment_verdict_display_caveats_count() {
    let v = EligibilityVerdict::EligibleWithCaveats {
        caveats: vec!["a".into(), "b".into(), "c".into()],
    };
    assert!(format!("{v}").contains("3 caveats"));
}

// ===========================================================================
// EligibilityEntry enrichment
// ===========================================================================

#[test]
fn enrichment_entry_clone_independence() {
    let original = EligibilityEntry {
        schema_id: "s1".into(),
        frequency_millionths: 50_000,
        verdict: EligibilityVerdict::Eligible,
    };
    let mut cloned = original.clone();
    cloned.schema_id = "s2".to_string();
    assert_eq!(original.schema_id, "s1");
    assert_eq!(cloned.schema_id, "s2");
}

#[test]
fn enrichment_entry_json_field_names() {
    let entry = EligibilityEntry {
        schema_id: "s1".into(),
        frequency_millionths: 50_000,
        verdict: EligibilityVerdict::Eligible,
    };
    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains("\"schema_id\""));
    assert!(json.contains("\"frequency_millionths\""));
    assert!(json.contains("\"verdict\""));
}

#[test]
fn enrichment_entry_debug_nonempty() {
    let entry = EligibilityEntry {
        schema_id: "s1".into(),
        frequency_millionths: 50_000,
        verdict: EligibilityVerdict::Eligible,
    };
    let dbg = format!("{entry:?}");
    assert!(dbg.contains("EligibilityEntry"));
}

#[test]
fn enrichment_entry_serde_roundtrip() {
    let entry = EligibilityEntry {
        schema_id: "s1".into(),
        frequency_millionths: 50_000,
        verdict: EligibilityVerdict::EligibleWithCaveats {
            caveats: vec!["proof needed".into()],
        },
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: EligibilityEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ===========================================================================
// SynthesisEnvelope enrichment
// ===========================================================================

#[test]
fn enrichment_envelope_clone_independence() {
    let schemas = vec![pure_schema("s1")];
    let mut freqs = BTreeMap::new();
    freqs.insert("s1".into(), 100_000u64);
    let original = SynthesisEnvelope::compute(ep(), &schemas, &freqs);
    let mut cloned = original.clone();
    cloned.eligible_count = 99;
    assert_ne!(original.eligible_count, 99);
    assert_eq!(cloned.eligible_count, 99);
}

#[test]
fn enrichment_envelope_json_field_names() {
    let e = SynthesisEnvelope::compute(ep(), &[], &BTreeMap::new());
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"entries\""));
    assert!(json.contains("\"eligible_count\""));
    assert!(json.contains("\"rejected_count\""));
    assert!(json.contains("\"eligible_frequency_mass\""));
    assert!(json.contains("\"content_hash\""));
}

#[test]
fn enrichment_envelope_debug_nonempty() {
    let e = SynthesisEnvelope::compute(ep(), &[], &BTreeMap::new());
    let dbg = format!("{e:?}");
    assert!(dbg.contains("SynthesisEnvelope"));
}

#[test]
fn enrichment_envelope_total_count_eq_eligible_plus_rejected() {
    let schemas = vec![pure_schema("good"), oversized_schema("bad")];
    let mut freqs = BTreeMap::new();
    freqs.insert("good".into(), 100_000u64);
    freqs.insert("bad".into(), 50_000u64);
    let e = SynthesisEnvelope::compute(ep(), &schemas, &freqs);
    assert_eq!(e.total_count(), e.eligible_count + e.rejected_count);
}

#[test]
fn enrichment_envelope_eligibility_rate_boundary() {
    // All eligible → 1_000_000
    let schemas = vec![pure_schema("s1")];
    let mut freqs = BTreeMap::new();
    freqs.insert("s1".into(), 100_000u64);
    let e = SynthesisEnvelope::compute(ep(), &schemas, &freqs);
    assert_eq!(e.eligibility_rate(), 1_000_000);
}

#[test]
fn enrichment_envelope_eligibility_rate_half() {
    let schemas = vec![pure_schema("g"), oversized_schema("b")];
    let mut freqs = BTreeMap::new();
    freqs.insert("g".into(), 100_000u64);
    freqs.insert("b".into(), 100_000u64);
    let e = SynthesisEnvelope::compute(ep(), &schemas, &freqs);
    assert_eq!(e.eligibility_rate(), 500_000);
}

#[test]
fn enrichment_envelope_verdict_for_missing() {
    let e = SynthesisEnvelope::compute(ep(), &[], &BTreeMap::new());
    assert!(e.verdict_for("nonexistent").is_none());
}

// ===========================================================================
// KernelCorpus enrichment
// ===========================================================================

#[test]
fn enrichment_corpus_clone_independence() {
    let mut original = KernelCorpus::new();
    original.observe(pure_schema("s1"), 100);
    let mut cloned = original.clone();
    cloned.observe(pure_schema("s2"), 50);
    assert_eq!(original.schema_count(), 1);
    assert_eq!(cloned.schema_count(), 2);
}

#[test]
fn enrichment_corpus_json_field_names() {
    let c = KernelCorpus::new();
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"schemas\""));
    assert!(json.contains("\"observation_counts\""));
    assert!(json.contains("\"total_observations\""));
}

#[test]
fn enrichment_corpus_debug_nonempty() {
    let c = KernelCorpus::new();
    let dbg = format!("{c:?}");
    assert!(dbg.contains("KernelCorpus"));
}

#[test]
fn enrichment_corpus_default_eq_new() {
    assert_eq!(KernelCorpus::default(), KernelCorpus::new());
}

#[test]
fn enrichment_corpus_frequencies_sum_to_million() {
    let mut c = KernelCorpus::new();
    c.observe(pure_schema("s1"), 500);
    c.observe(pure_schema("s2"), 500);
    let freqs = c.frequencies();
    let sum: u64 = freqs.values().sum();
    assert_eq!(sum, 1_000_000);
}

#[test]
fn enrichment_corpus_hot_schemas_excludes_cold() {
    let mut c = KernelCorpus::new();
    // hot: 99% of observations
    c.observe(pure_schema("hot"), 99_000);
    // cold: far below 1% threshold
    c.observe(pure_schema("cold"), 1);
    let hot = c.hot_schemas();
    assert_eq!(hot.len(), 1);
    assert_eq!(hot[0].schema_id, "hot");
}

// ===========================================================================
// Cross-cutting: evaluate_eligibility boundary conditions
// ===========================================================================

#[test]
fn enrichment_eval_exact_max_ops_eligible() {
    let mut ops = BTreeMap::new();
    ops.insert(OperationKind::Arithmetic, MAX_SYNTHESIZABLE_OPS);
    let s = KernelSchema::new(KernelSchemaInput {
        schema_id: "exact_ops".into(),
        operation_counts: ops,
        branch_depth: 1,
        side_effects: BTreeSet::new(),
        input_shape_stability: 950_000,
        output_shape_stability: 950_000,
        input_shape_count: 1,
        output_shape_count: 1,
    });
    let v = evaluate_eligibility(&s, 100_000);
    assert!(v.is_eligible());
}

#[test]
fn enrichment_eval_one_over_max_ops_rejected() {
    let mut ops = BTreeMap::new();
    ops.insert(OperationKind::Arithmetic, MAX_SYNTHESIZABLE_OPS + 1);
    let s = KernelSchema::new(KernelSchemaInput {
        schema_id: "over_ops".into(),
        operation_counts: ops,
        branch_depth: 1,
        side_effects: BTreeSet::new(),
        input_shape_stability: 950_000,
        output_shape_stability: 950_000,
        input_shape_count: 1,
        output_shape_count: 1,
    });
    let v = evaluate_eligibility(&s, 100_000);
    assert!(v.is_rejected());
}

#[test]
fn enrichment_eval_exact_max_branch_depth_eligible() {
    let mut ops = BTreeMap::new();
    ops.insert(OperationKind::Arithmetic, 10);
    let s = KernelSchema::new(KernelSchemaInput {
        schema_id: "exact_depth".into(),
        operation_counts: ops,
        branch_depth: MAX_SYNTHESIZABLE_BRANCH_DEPTH,
        side_effects: BTreeSet::new(),
        input_shape_stability: 950_000,
        output_shape_stability: 950_000,
        input_shape_count: 1,
        output_shape_count: 1,
    });
    let v = evaluate_eligibility(&s, 100_000);
    assert!(v.is_eligible());
}

#[test]
fn enrichment_eval_one_over_max_branch_depth_rejected() {
    let mut ops = BTreeMap::new();
    ops.insert(OperationKind::Arithmetic, 10);
    let s = KernelSchema::new(KernelSchemaInput {
        schema_id: "over_depth".into(),
        operation_counts: ops,
        branch_depth: MAX_SYNTHESIZABLE_BRANCH_DEPTH + 1,
        side_effects: BTreeSet::new(),
        input_shape_stability: 950_000,
        output_shape_stability: 950_000,
        input_shape_count: 1,
        output_shape_count: 1,
    });
    let v = evaluate_eligibility(&s, 100_000);
    assert!(v.is_rejected());
}

#[test]
fn enrichment_eval_exact_max_side_effects_eligible() {
    let mut ops = BTreeMap::new();
    ops.insert(OperationKind::Store, 4);
    // 4 side effects = MAX_SIDE_EFFECTS, should still be eligible
    // But only if none is GlobalMutation
    let effects = BTreeSet::from([
        SideEffectKind::PropertyWrite,
        SideEffectKind::ArrayWrite,
        SideEffectKind::HeapAllocation,
        SideEffectKind::ThrowsException,
    ]);
    let s = KernelSchema::new(KernelSchemaInput {
        schema_id: "exact_se".into(),
        operation_counts: ops,
        branch_depth: 1,
        side_effects: effects,
        input_shape_stability: 950_000,
        output_shape_stability: 950_000,
        input_shape_count: 1,
        output_shape_count: 1,
    });
    let v = evaluate_eligibility(&s, 100_000);
    assert!(v.is_eligible());
}

#[test]
fn enrichment_eval_exact_min_shape_stability_eligible() {
    let mut ops = BTreeMap::new();
    ops.insert(OperationKind::Arithmetic, 10);
    let s = KernelSchema::new(KernelSchemaInput {
        schema_id: "exact_stability".into(),
        operation_counts: ops,
        branch_depth: 1,
        side_effects: BTreeSet::new(),
        input_shape_stability: MIN_SHAPE_STABILITY,
        output_shape_stability: MIN_SHAPE_STABILITY,
        input_shape_count: 1,
        output_shape_count: 1,
    });
    let v = evaluate_eligibility(&s, 100_000);
    assert!(v.is_eligible());
}

#[test]
fn enrichment_eval_one_below_min_shape_stability_rejected() {
    let mut ops = BTreeMap::new();
    ops.insert(OperationKind::Arithmetic, 10);
    let s = KernelSchema::new(KernelSchemaInput {
        schema_id: "below_stability".into(),
        operation_counts: ops,
        branch_depth: 1,
        side_effects: BTreeSet::new(),
        input_shape_stability: MIN_SHAPE_STABILITY - 1,
        output_shape_stability: 950_000,
        input_shape_count: 1,
        output_shape_count: 1,
    });
    let v = evaluate_eligibility(&s, 100_000);
    assert!(v.is_rejected());
}

// ===========================================================================
// Cross-cutting: determinism
// ===========================================================================

#[test]
fn enrichment_envelope_determinism_five_runs() {
    let schemas = vec![
        pure_schema("s1"),
        effectful_schema("s2"),
        oversized_schema("s3"),
        global_mutation_schema("s4"),
    ];
    let mut freqs = BTreeMap::new();
    freqs.insert("s1".into(), 100_000u64);
    freqs.insert("s2".into(), 80_000u64);
    freqs.insert("s3".into(), 50_000u64);
    freqs.insert("s4".into(), 30_000u64);
    let mut hashes = BTreeSet::new();
    for _ in 0..5 {
        let e = SynthesisEnvelope::compute(ep(), &schemas, &freqs);
        hashes.insert(e.content_hash);
    }
    assert_eq!(hashes.len(), 1);
}

#[test]
fn enrichment_corpus_envelope_determinism_five_runs() {
    let mut c = KernelCorpus::new();
    c.observe(pure_schema("s1"), 500);
    c.observe(oversized_schema("s2"), 300);
    let mut hashes = BTreeSet::new();
    for _ in 0..5 {
        let e = c.compute_envelope(ep());
        hashes.insert(e.content_hash);
    }
    assert_eq!(hashes.len(), 1);
}

// ===========================================================================
// Cross-cutting: constants stability
// ===========================================================================

#[test]
fn enrichment_constants_stable() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.synthesis-eligibility-envelope.v1"
    );
    assert_eq!(COMPONENT, "synthesis_eligibility_envelope");
    assert_eq!(BEAD_ID, "bd-1lsy.7.13.1");
    assert_eq!(POLICY_ID, "RGC-613A");
    assert_eq!(MAX_SYNTHESIZABLE_BRANCH_DEPTH, 8);
    assert_eq!(MAX_SYNTHESIZABLE_OPS, 256);
    assert_eq!(HOT_SCHEMA_THRESHOLD, 10_000);
    assert_eq!(MAX_SIDE_EFFECTS, 4);
    assert_eq!(MIN_SHAPE_STABILITY, 900_000);
}

// ===========================================================================
// Cross-cutting: serde roundtrip preserves evaluation
// ===========================================================================

#[test]
fn enrichment_envelope_serde_preserves_counts() {
    let schemas = vec![pure_schema("g"), oversized_schema("b")];
    let mut freqs = BTreeMap::new();
    freqs.insert("g".into(), 100_000u64);
    freqs.insert("b".into(), 50_000u64);
    let e = SynthesisEnvelope::compute(ep(), &schemas, &freqs);
    let json = serde_json::to_string(&e).unwrap();
    let back: SynthesisEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(e.eligible_count, back.eligible_count);
    assert_eq!(e.rejected_count, back.rejected_count);
    assert_eq!(e.eligible_frequency_mass, back.eligible_frequency_mass);
    assert_eq!(e.content_hash, back.content_hash);
}

// ===========================================================================
// Cross-cutting: global mutation always rejected
// ===========================================================================

#[test]
fn enrichment_global_mutation_rejected_even_hot() {
    let s = global_mutation_schema("gm");
    let v = evaluate_eligibility(&s, 500_000); // very hot
    assert!(v.is_rejected());
}

#[test]
fn enrichment_effectful_schema_caveats_contain_proof_note() {
    let v = evaluate_eligibility(&effectful_schema("e1"), 100_000);
    if let EligibilityVerdict::EligibleWithCaveats { caveats } = &v {
        assert!(caveats.iter().any(|c| c.contains("equivalence proof")));
    } else {
        panic!("expected EligibleWithCaveats, got {v:?}");
    }
}
