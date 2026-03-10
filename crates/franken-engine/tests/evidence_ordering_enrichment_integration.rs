//! Enrichment integration tests for `evidence_ordering`.
//!
//! Covers: JSON field-name stability, serde roundtrips, Display exact values,
//! Debug distinctness, OrderingViolation variants, SizeBounds defaults,
//! TruncationMarker Display, sort/dedup/normalize functions,
//! validate_entry_ordering, and NormalizationResult properties.

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

use frankenengine_engine::evidence_ledger::{
    CandidateAction, ChosenAction, Constraint, DecisionType, EvidenceEntryBuilder, Witness,
};
use frankenengine_engine::evidence_ordering::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── helpers ────────────────────────────────────────────────────────────

fn make_entry(
    candidates: Vec<CandidateAction>,
    witnesses: Vec<Witness>,
    constraints: Vec<Constraint>,
) -> frankenengine_engine::evidence_ledger::EvidenceEntry {
    let mut e = EvidenceEntryBuilder::new(
        "trace",
        "decision",
        "policy",
        SecurityEpoch::from_raw(1),
        DecisionType::SecurityAction,
    )
    .chosen(ChosenAction {
        action_name: "test".to_string(),
        expected_loss_millionths: 0,
        rationale: "test".to_string(),
    })
    .build()
    .unwrap();
    e.candidates = candidates;
    e.witnesses = witnesses;
    e.constraints = constraints;
    e
}

fn w(id: &str) -> Witness {
    Witness {
        witness_id: id.to_string(),
        witness_type: "t".to_string(),
        value: "v".to_string(),
    }
}

fn c(id: &str) -> Constraint {
    Constraint {
        constraint_id: id.to_string(),
        description: "d".to_string(),
        active: true,
    }
}

// ── SizeBounds ─────────────────────────────────────────────────────────

#[test]
fn size_bounds_defaults() {
    let sb = SizeBounds::default();
    assert_eq!(sb.max_candidates, 64);
    assert_eq!(sb.max_witnesses, 256);
    assert_eq!(sb.max_constraints, 32);
}

#[test]
fn size_bounds_json_fields() {
    let sb = SizeBounds::default();
    let v: serde_json::Value = serde_json::to_value(&sb).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("max_candidates"));
    assert!(obj.contains_key("max_witnesses"));
    assert!(obj.contains_key("max_constraints"));
    assert_eq!(obj.len(), 3);
}

#[test]
fn size_bounds_serde_roundtrip() {
    let sb = SizeBounds {
        max_candidates: 10,
        max_witnesses: 20,
        max_constraints: 5,
    };
    let json = serde_json::to_vec(&sb).unwrap();
    let back: SizeBounds = serde_json::from_slice(&json).unwrap();
    assert_eq!(sb, back);
}

#[test]
fn size_bounds_debug_nonempty() {
    let sb = SizeBounds::default();
    let d = format!("{sb:?}");
    assert!(d.contains("SizeBounds"));
}

// ── TruncationMarker ───────────────────────────────────────────────────

#[test]
fn truncation_marker_display_format() {
    let tm = TruncationMarker {
        list_name: "candidates".to_string(),
        original_count: 100,
        retained_count: 64,
        policy: "top-K by action_name".to_string(),
    };
    assert_eq!(
        tm.to_string(),
        "candidates: 100 -> 64 (top-K by action_name)"
    );
}

#[test]
fn truncation_marker_json_fields() {
    let tm = TruncationMarker {
        list_name: "witnesses".to_string(),
        original_count: 300,
        retained_count: 256,
        policy: "top-K by witness_id".to_string(),
    };
    let v: serde_json::Value = serde_json::to_value(&tm).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("list_name"));
    assert!(obj.contains_key("original_count"));
    assert!(obj.contains_key("retained_count"));
    assert!(obj.contains_key("policy"));
    assert_eq!(obj.len(), 4);
}

#[test]
fn truncation_marker_serde_roundtrip() {
    let tm = TruncationMarker {
        list_name: "constraints".to_string(),
        original_count: 50,
        retained_count: 32,
        policy: "top-K by constraint_id".to_string(),
    };
    let json = serde_json::to_vec(&tm).unwrap();
    let back: TruncationMarker = serde_json::from_slice(&json).unwrap();
    assert_eq!(tm, back);
}

// ── OrderingViolation ──────────────────────────────────────────────────

#[test]
fn ordering_violation_display_candidates_not_sorted() {
    let ov = OrderingViolation::CandidatesNotSorted {
        first_unsorted_index: 3,
    };
    assert_eq!(ov.to_string(), "candidates not sorted at index 3");
}

#[test]
fn ordering_violation_display_witnesses_not_sorted() {
    let ov = OrderingViolation::WitnessesNotSorted {
        first_unsorted_index: 7,
    };
    assert_eq!(ov.to_string(), "witnesses not sorted at index 7");
}

#[test]
fn ordering_violation_display_constraints_not_sorted() {
    let ov = OrderingViolation::ConstraintsNotSorted {
        first_unsorted_index: 0,
    };
    assert_eq!(ov.to_string(), "constraints not sorted at index 0");
}

#[test]
fn ordering_violation_display_duplicate_witness() {
    let ov = OrderingViolation::DuplicateWitnessId {
        witness_id: "w-42".to_string(),
    };
    assert_eq!(ov.to_string(), "duplicate witness id: w-42");
}

#[test]
fn ordering_violation_display_candidates_exceed() {
    let ov = OrderingViolation::CandidatesExceedBound {
        count: 100,
        max: 64,
    };
    assert_eq!(ov.to_string(), "candidates exceed bound: 100 > 64");
}

#[test]
fn ordering_violation_display_witnesses_exceed() {
    let ov = OrderingViolation::WitnessesExceedBound {
        count: 300,
        max: 256,
    };
    assert_eq!(ov.to_string(), "witnesses exceed bound: 300 > 256");
}

#[test]
fn ordering_violation_display_constraints_exceed() {
    let ov = OrderingViolation::ConstraintsExceedBound { count: 50, max: 32 };
    assert_eq!(ov.to_string(), "constraints exceed bound: 50 > 32");
}

#[test]
fn ordering_violation_is_std_error() {
    let ov = OrderingViolation::CandidatesNotSorted {
        first_unsorted_index: 0,
    };
    let e: &dyn std::error::Error = &ov;
    assert!(!e.to_string().is_empty());
}

#[test]
fn ordering_violation_debug_all_distinct() {
    let variants: Vec<OrderingViolation> = vec![
        OrderingViolation::CandidatesNotSorted {
            first_unsorted_index: 0,
        },
        OrderingViolation::WitnessesNotSorted {
            first_unsorted_index: 0,
        },
        OrderingViolation::ConstraintsNotSorted {
            first_unsorted_index: 0,
        },
        OrderingViolation::DuplicateWitnessId {
            witness_id: "x".to_string(),
        },
        OrderingViolation::CandidatesExceedBound { count: 1, max: 0 },
        OrderingViolation::WitnessesExceedBound { count: 1, max: 0 },
        OrderingViolation::ConstraintsExceedBound { count: 1, max: 0 },
    ];
    let dbgs: Vec<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    let unique: std::collections::BTreeSet<&str> = dbgs.iter().map(|s| s.as_str()).collect();
    assert_eq!(unique.len(), 7);
}

#[test]
fn ordering_violation_serde_roundtrip_all() {
    let variants = vec![
        OrderingViolation::CandidatesNotSorted {
            first_unsorted_index: 5,
        },
        OrderingViolation::WitnessesNotSorted {
            first_unsorted_index: 2,
        },
        OrderingViolation::ConstraintsNotSorted {
            first_unsorted_index: 1,
        },
        OrderingViolation::DuplicateWitnessId {
            witness_id: "w".to_string(),
        },
        OrderingViolation::CandidatesExceedBound { count: 70, max: 64 },
        OrderingViolation::WitnessesExceedBound {
            count: 300,
            max: 256,
        },
        OrderingViolation::ConstraintsExceedBound { count: 40, max: 32 },
    ];
    for v in &variants {
        let json = serde_json::to_vec(v).unwrap();
        let back: OrderingViolation = serde_json::from_slice(&json).unwrap();
        assert_eq!(v, &back);
    }
}

// ── sort_candidates ────────────────────────────────────────────────────

#[test]
fn sort_candidates_already_sorted() {
    let mut cands = vec![
        CandidateAction::new("a", 100),
        CandidateAction::new("b", 200),
    ];
    sort_candidates(&mut cands);
    assert_eq!(cands[0].action_name, "a");
    assert_eq!(cands[1].action_name, "b");
}

#[test]
fn sort_candidates_reverse() {
    let mut cands = vec![
        CandidateAction::new("z", 100),
        CandidateAction::new("a", 200),
    ];
    sort_candidates(&mut cands);
    assert_eq!(cands[0].action_name, "a");
    assert_eq!(cands[1].action_name, "z");
}

#[test]
fn sort_candidates_same_name_by_loss() {
    let mut cands = vec![
        CandidateAction::new("act", 500),
        CandidateAction::new("act", 100),
        CandidateAction::new("act", 300),
    ];
    sort_candidates(&mut cands);
    assert_eq!(cands[0].expected_loss_millionths, 100);
    assert_eq!(cands[1].expected_loss_millionths, 300);
    assert_eq!(cands[2].expected_loss_millionths, 500);
}

#[test]
fn sort_candidates_empty() {
    let mut cands: Vec<CandidateAction> = vec![];
    sort_candidates(&mut cands);
    assert!(cands.is_empty());
}

// ── sort_witnesses ─────────────────────────────────────────────────────

#[test]
fn sort_witnesses_lexicographic() {
    let mut ws = vec![w("z-obs"), w("a-obs"), w("m-obs")];
    sort_witnesses(&mut ws);
    assert_eq!(ws[0].witness_id, "a-obs");
    assert_eq!(ws[1].witness_id, "m-obs");
    assert_eq!(ws[2].witness_id, "z-obs");
}

#[test]
fn sort_witnesses_single() {
    let mut ws = vec![w("only")];
    sort_witnesses(&mut ws);
    assert_eq!(ws[0].witness_id, "only");
}

// ── sort_constraints ───────────────────────────────────────────────────

#[test]
fn sort_constraints_lexicographic() {
    let mut cs = vec![c("z-rule"), c("a-rule"), c("m-rule")];
    sort_constraints(&mut cs);
    assert_eq!(cs[0].constraint_id, "a-rule");
    assert_eq!(cs[1].constraint_id, "m-rule");
    assert_eq!(cs[2].constraint_id, "z-rule");
}

// ── dedup_witnesses ────────────────────────────────────────────────────

#[test]
fn dedup_witnesses_keeps_first() {
    let mut ws = vec![
        Witness {
            witness_id: "a".to_string(),
            witness_type: "t".to_string(),
            value: "first".to_string(),
        },
        Witness {
            witness_id: "a".to_string(),
            witness_type: "t".to_string(),
            value: "second".to_string(),
        },
    ];
    dedup_witnesses(&mut ws);
    assert_eq!(ws.len(), 1);
    assert_eq!(ws[0].value, "first");
}

#[test]
fn dedup_witnesses_no_duplicates() {
    let mut ws = vec![w("a"), w("b"), w("c")];
    dedup_witnesses(&mut ws);
    assert_eq!(ws.len(), 3);
}

#[test]
fn dedup_witnesses_all_same() {
    let mut ws = vec![w("x"), w("x"), w("x")];
    dedup_witnesses(&mut ws);
    assert_eq!(ws.len(), 1);
}

// ── normalize_entry ────────────────────────────────────────────────────

#[test]
fn normalize_empty_entry() {
    let mut entry = make_entry(vec![], vec![], vec![]);
    let result = normalize_entry(&mut entry, &SizeBounds::default());
    assert_eq!(result.duplicates_removed, 0);
    assert!(result.truncations.is_empty());
}

#[test]
fn normalize_sorts_candidates_and_witnesses() {
    let mut entry = make_entry(
        vec![
            CandidateAction::new("z", 100),
            CandidateAction::new("a", 200),
        ],
        vec![w("z-w"), w("a-w")],
        vec![c("z-c"), c("a-c")],
    );
    let _result = normalize_entry(&mut entry, &SizeBounds::default());
    assert_eq!(entry.candidates[0].action_name, "a");
    assert_eq!(entry.witnesses[0].witness_id, "a-w");
    assert_eq!(entry.constraints[0].constraint_id, "a-c");
}

#[test]
fn normalize_deduplicates_witnesses() {
    let mut entry = make_entry(vec![], vec![w("dup"), w("dup"), w("unique")], vec![]);
    let result = normalize_entry(&mut entry, &SizeBounds::default());
    assert_eq!(result.duplicates_removed, 1);
    assert_eq!(entry.witnesses.len(), 2);
}

#[test]
fn normalize_truncates_candidates() {
    let cands: Vec<CandidateAction> = (0..10)
        .map(|i| CandidateAction::new(format!("act-{i:03}"), i))
        .collect();
    let mut entry = make_entry(cands, vec![], vec![]);
    let bounds = SizeBounds {
        max_candidates: 3,
        max_witnesses: 256,
        max_constraints: 32,
    };
    let result = normalize_entry(&mut entry, &bounds);
    assert_eq!(result.truncations.len(), 1);
    assert_eq!(result.truncations[0].list_name, "candidates");
    assert_eq!(result.truncations[0].original_count, 10);
    assert_eq!(result.truncations[0].retained_count, 3);
    assert_eq!(entry.candidates.len(), 3);
}

#[test]
fn normalize_truncates_witnesses() {
    let ws: Vec<Witness> = (0..10).map(|i| w(&format!("w-{i:03}"))).collect();
    let mut entry = make_entry(vec![], ws, vec![]);
    let bounds = SizeBounds {
        max_candidates: 64,
        max_witnesses: 5,
        max_constraints: 32,
    };
    let result = normalize_entry(&mut entry, &bounds);
    assert_eq!(result.truncations.len(), 1);
    assert_eq!(result.truncations[0].list_name, "witnesses");
    assert_eq!(entry.witnesses.len(), 5);
}

#[test]
fn normalize_truncates_constraints() {
    let cs: Vec<Constraint> = (0..10).map(|i| c(&format!("c-{i:03}"))).collect();
    let mut entry = make_entry(vec![], vec![], cs);
    let bounds = SizeBounds {
        max_candidates: 64,
        max_witnesses: 256,
        max_constraints: 4,
    };
    let result = normalize_entry(&mut entry, &bounds);
    assert_eq!(result.truncations.len(), 1);
    assert_eq!(result.truncations[0].list_name, "constraints");
    assert_eq!(entry.constraints.len(), 4);
}

#[test]
fn normalize_multiple_truncations() {
    let cands: Vec<CandidateAction> = (0..5)
        .map(|i| CandidateAction::new(format!("a-{i}"), i))
        .collect();
    let ws: Vec<Witness> = (0..5).map(|i| w(&format!("w-{i}"))).collect();
    let cs: Vec<Constraint> = (0..5).map(|i| c(&format!("c-{i}"))).collect();
    let mut entry = make_entry(cands, ws, cs);
    let bounds = SizeBounds {
        max_candidates: 2,
        max_witnesses: 2,
        max_constraints: 2,
    };
    let result = normalize_entry(&mut entry, &bounds);
    assert_eq!(result.truncations.len(), 3);
    assert_eq!(entry.candidates.len(), 2);
    assert_eq!(entry.witnesses.len(), 2);
    assert_eq!(entry.constraints.len(), 2);
}

// ── validate_entry_ordering ────────────────────────────────────────────

#[test]
fn validate_ok_for_normalized_entry() {
    let mut entry = make_entry(
        vec![
            CandidateAction::new("a", 100),
            CandidateAction::new("b", 200),
        ],
        vec![w("w-a"), w("w-b")],
        vec![c("c-a"), c("c-b")],
    );
    normalize_entry(&mut entry, &SizeBounds::default());
    assert!(validate_entry_ordering(&entry, &SizeBounds::default()).is_ok());
}

#[test]
fn validate_detects_unsorted_candidates() {
    let entry = make_entry(
        vec![
            CandidateAction::new("z", 100),
            CandidateAction::new("a", 200),
        ],
        vec![],
        vec![],
    );
    let errs = validate_entry_ordering(&entry, &SizeBounds::default()).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e, OrderingViolation::CandidatesNotSorted { .. }))
    );
}

#[test]
fn validate_detects_unsorted_witnesses() {
    let entry = make_entry(vec![], vec![w("z"), w("a")], vec![]);
    let errs = validate_entry_ordering(&entry, &SizeBounds::default()).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e, OrderingViolation::WitnessesNotSorted { .. }))
    );
}

#[test]
fn validate_detects_unsorted_constraints() {
    let entry = make_entry(vec![], vec![], vec![c("z"), c("a")]);
    let errs = validate_entry_ordering(&entry, &SizeBounds::default()).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e, OrderingViolation::ConstraintsNotSorted { .. }))
    );
}

#[test]
fn validate_detects_duplicate_witness_ids() {
    let entry = make_entry(vec![], vec![w("same"), w("same")], vec![]);
    let errs = validate_entry_ordering(&entry, &SizeBounds::default()).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e, OrderingViolation::DuplicateWitnessId { .. }))
    );
}

#[test]
fn validate_detects_candidates_exceed_bound() {
    let cands: Vec<CandidateAction> = (0..5)
        .map(|i| CandidateAction::new(format!("a-{i:03}"), i))
        .collect();
    let entry = make_entry(cands, vec![], vec![]);
    let bounds = SizeBounds {
        max_candidates: 3,
        max_witnesses: 256,
        max_constraints: 32,
    };
    let errs = validate_entry_ordering(&entry, &bounds).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e, OrderingViolation::CandidatesExceedBound { .. }))
    );
}

#[test]
fn validate_detects_witnesses_exceed_bound() {
    let ws: Vec<Witness> = (0..10).map(|i| w(&format!("w-{i:03}"))).collect();
    let entry = make_entry(vec![], ws, vec![]);
    let bounds = SizeBounds {
        max_candidates: 64,
        max_witnesses: 5,
        max_constraints: 32,
    };
    let errs = validate_entry_ordering(&entry, &bounds).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e, OrderingViolation::WitnessesExceedBound { .. }))
    );
}

#[test]
fn validate_detects_constraints_exceed_bound() {
    let cs: Vec<Constraint> = (0..10).map(|i| c(&format!("c-{i:03}"))).collect();
    let entry = make_entry(vec![], vec![], cs);
    let bounds = SizeBounds {
        max_candidates: 64,
        max_witnesses: 256,
        max_constraints: 3,
    };
    let errs = validate_entry_ordering(&entry, &bounds).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e, OrderingViolation::ConstraintsExceedBound { .. }))
    );
}

#[test]
fn validate_empty_entry_passes() {
    let entry = make_entry(vec![], vec![], vec![]);
    assert!(validate_entry_ordering(&entry, &SizeBounds::default()).is_ok());
}

#[test]
fn validate_after_normalize_always_passes() {
    let cands: Vec<CandidateAction> = (0..20)
        .map(|i| CandidateAction::new(format!("act-{}", (20 - i)), i))
        .collect();
    let ws: Vec<Witness> = (0..20).map(|i| w(&format!("w-{}", (20 - i)))).collect();
    let mut entry = make_entry(cands, ws, vec![]);
    let bounds = SizeBounds {
        max_candidates: 10,
        max_witnesses: 10,
        max_constraints: 32,
    };
    normalize_entry(&mut entry, &bounds);
    assert!(validate_entry_ordering(&entry, &bounds).is_ok());
}

// ── Idempotence ────────────────────────────────────────────────────────

#[test]
fn normalize_is_idempotent() {
    let cands: Vec<CandidateAction> = (0..10)
        .map(|i| CandidateAction::new(format!("act-{}", (10 - i)), i))
        .collect();
    let ws: Vec<Witness> = (0..5).map(|i| w(&format!("w-{}", (5 - i)))).collect();
    let mut entry = make_entry(cands, ws, vec![]);
    let bounds = SizeBounds {
        max_candidates: 5,
        max_witnesses: 3,
        max_constraints: 32,
    };

    normalize_entry(&mut entry, &bounds);
    let json_after_first = serde_json::to_vec(&entry).unwrap();

    let result2 = normalize_entry(&mut entry, &bounds);
    let json_after_second = serde_json::to_vec(&entry).unwrap();

    assert_eq!(json_after_first, json_after_second);
    assert_eq!(result2.duplicates_removed, 0);
    assert!(result2.truncations.is_empty());
}

// ── Deterministic serialization ────────────────────────────────────────

#[test]
fn normalized_entry_serialization_deterministic() {
    let build = || {
        let cands = vec![
            CandidateAction::new("z-action", 500),
            CandidateAction::new("a-action", 100),
            CandidateAction::new("m-action", 300),
        ];
        let ws = vec![w("z-w"), w("a-w"), w("m-w")];
        let cs = vec![c("z-c"), c("a-c")];
        let mut entry = make_entry(cands, ws, cs);
        normalize_entry(&mut entry, &SizeBounds::default());
        serde_json::to_vec(&entry).unwrap()
    };
    assert_eq!(build(), build());
}
