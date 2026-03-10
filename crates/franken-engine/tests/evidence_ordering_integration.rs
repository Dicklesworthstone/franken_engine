#![forbid(unsafe_code)]

//! Integration tests for the `evidence_ordering` module.
//!
//! Covers canonical sorting (candidates, witnesses, constraints),
//! deduplication, bounded-size normalization with truncation markers,
//! ordering validation, Display impls, serde roundtrips, deterministic
//! replay, and edge cases (empty lists, boundary sizes).

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
    CandidateAction, ChosenAction, Constraint, DecisionType, EvidenceEntry, EvidenceEntryBuilder,
    Witness,
};
use frankenengine_engine::evidence_ordering::{
    OrderingViolation, SizeBounds, TruncationMarker, dedup_witnesses, normalize_entry,
    sort_candidates, sort_constraints, sort_witnesses, validate_entry_ordering,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_entry(
    candidates: Vec<CandidateAction>,
    witnesses: Vec<Witness>,
    constraints: Vec<Constraint>,
) -> EvidenceEntry {
    EvidenceEntryBuilder::new(
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
    .map(|mut e| {
        e.candidates = candidates;
        e.witnesses = witnesses;
        e.constraints = constraints;
        e
    })
    .expect("build entry")
}

fn make_witness(id: &str) -> Witness {
    Witness {
        witness_id: id.to_string(),
        witness_type: "type".to_string(),
        value: "val".to_string(),
    }
}

fn make_constraint(id: &str) -> Constraint {
    Constraint {
        constraint_id: id.to_string(),
        description: "desc".to_string(),
        active: true,
    }
}

// ---------------------------------------------------------------------------
// SizeBounds
// ---------------------------------------------------------------------------

#[test]
fn size_bounds_default_values() {
    let bounds = SizeBounds::default();
    assert_eq!(bounds.max_candidates, 64);
    assert_eq!(bounds.max_witnesses, 256);
    assert_eq!(bounds.max_constraints, 32);
}

#[test]
fn size_bounds_serde_roundtrip() {
    let bounds = SizeBounds {
        max_candidates: 10,
        max_witnesses: 20,
        max_constraints: 5,
    };
    let json = serde_json::to_string(&bounds).expect("serialize");
    let restored: SizeBounds = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(bounds, restored);
}

#[test]
fn size_bounds_default_serde_roundtrip() {
    let bounds = SizeBounds::default();
    let json = serde_json::to_string(&bounds).expect("serialize");
    let restored: SizeBounds = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(bounds, restored);
}

// ---------------------------------------------------------------------------
// TruncationMarker
// ---------------------------------------------------------------------------

#[test]
fn truncation_marker_display() {
    let marker = TruncationMarker {
        list_name: "witnesses".to_string(),
        original_count: 300,
        retained_count: 256,
        policy: "top-K by witness_id".to_string(),
    };
    assert_eq!(
        marker.to_string(),
        "witnesses: 300 -> 256 (top-K by witness_id)"
    );
}

#[test]
fn truncation_marker_serde_roundtrip() {
    let marker = TruncationMarker {
        list_name: "candidates".to_string(),
        original_count: 100,
        retained_count: 64,
        policy: "top-K by action_name".to_string(),
    };
    let json = serde_json::to_string(&marker).expect("serialize");
    let restored: TruncationMarker = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(marker, restored);
}

// ---------------------------------------------------------------------------
// OrderingViolation — Display
// ---------------------------------------------------------------------------

#[test]
fn ordering_violation_display_candidates_not_sorted() {
    let v = OrderingViolation::CandidatesNotSorted {
        first_unsorted_index: 3,
    };
    assert_eq!(v.to_string(), "candidates not sorted at index 3");
}

#[test]
fn ordering_violation_display_witnesses_not_sorted() {
    let v = OrderingViolation::WitnessesNotSorted {
        first_unsorted_index: 7,
    };
    assert_eq!(v.to_string(), "witnesses not sorted at index 7");
}

#[test]
fn ordering_violation_display_constraints_not_sorted() {
    let v = OrderingViolation::ConstraintsNotSorted {
        first_unsorted_index: 2,
    };
    assert_eq!(v.to_string(), "constraints not sorted at index 2");
}

#[test]
fn ordering_violation_display_duplicate_witness_id() {
    let v = OrderingViolation::DuplicateWitnessId {
        witness_id: "obs-42".to_string(),
    };
    assert_eq!(v.to_string(), "duplicate witness id: obs-42");
}

#[test]
fn ordering_violation_display_candidates_exceed_bound() {
    let v = OrderingViolation::CandidatesExceedBound {
        count: 100,
        max: 64,
    };
    assert_eq!(v.to_string(), "candidates exceed bound: 100 > 64");
}

#[test]
fn ordering_violation_display_witnesses_exceed_bound() {
    let v = OrderingViolation::WitnessesExceedBound {
        count: 500,
        max: 256,
    };
    assert_eq!(v.to_string(), "witnesses exceed bound: 500 > 256");
}

#[test]
fn ordering_violation_display_constraints_exceed_bound() {
    let v = OrderingViolation::ConstraintsExceedBound { count: 50, max: 32 };
    assert_eq!(v.to_string(), "constraints exceed bound: 50 > 32");
}

// ---------------------------------------------------------------------------
// OrderingViolation — serde
// ---------------------------------------------------------------------------

#[test]
fn ordering_violation_serde_all_variants() {
    let violations = vec![
        OrderingViolation::CandidatesNotSorted {
            first_unsorted_index: 1,
        },
        OrderingViolation::WitnessesNotSorted {
            first_unsorted_index: 5,
        },
        OrderingViolation::ConstraintsNotSorted {
            first_unsorted_index: 3,
        },
        OrderingViolation::DuplicateWitnessId {
            witness_id: "w-dup".to_string(),
        },
        OrderingViolation::CandidatesExceedBound { count: 70, max: 64 },
        OrderingViolation::WitnessesExceedBound {
            count: 300,
            max: 256,
        },
        OrderingViolation::ConstraintsExceedBound { count: 40, max: 32 },
    ];
    for v in &violations {
        let json = serde_json::to_string(v).expect("serialize");
        let restored: OrderingViolation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*v, restored);
    }
}

// ---------------------------------------------------------------------------
// sort_candidates
// ---------------------------------------------------------------------------

#[test]
fn sort_candidates_by_name_then_loss() {
    let mut candidates = vec![
        CandidateAction::new("terminate", 500_000),
        CandidateAction::new("allow", 10_000),
        CandidateAction::new("sandbox", 100_000),
        CandidateAction::new("allow", 5_000),
    ];
    sort_candidates(&mut candidates);
    assert_eq!(candidates[0].action_name, "allow");
    assert_eq!(candidates[0].expected_loss_millionths, 5_000);
    assert_eq!(candidates[1].action_name, "allow");
    assert_eq!(candidates[1].expected_loss_millionths, 10_000);
    assert_eq!(candidates[2].action_name, "sandbox");
    assert_eq!(candidates[3].action_name, "terminate");
}

#[test]
fn sort_candidates_empty_is_noop() {
    let mut candidates: Vec<CandidateAction> = vec![];
    sort_candidates(&mut candidates);
    assert!(candidates.is_empty());
}

#[test]
fn sort_candidates_single_element() {
    let mut candidates = vec![CandidateAction::new("only", 42)];
    sort_candidates(&mut candidates);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].action_name, "only");
}

#[test]
fn sort_candidates_negative_loss_values() {
    let mut candidates = vec![
        CandidateAction::new("a", 100),
        CandidateAction::new("a", -200),
        CandidateAction::new("a", 0),
    ];
    sort_candidates(&mut candidates);
    assert_eq!(candidates[0].expected_loss_millionths, -200);
    assert_eq!(candidates[1].expected_loss_millionths, 0);
    assert_eq!(candidates[2].expected_loss_millionths, 100);
}

// ---------------------------------------------------------------------------
// sort_witnesses
// ---------------------------------------------------------------------------

#[test]
fn sort_witnesses_lexicographic_by_id() {
    let mut witnesses = vec![
        make_witness("z-obs"),
        make_witness("a-obs"),
        make_witness("m-obs"),
    ];
    sort_witnesses(&mut witnesses);
    assert_eq!(witnesses[0].witness_id, "a-obs");
    assert_eq!(witnesses[1].witness_id, "m-obs");
    assert_eq!(witnesses[2].witness_id, "z-obs");
}

#[test]
fn sort_witnesses_empty_is_noop() {
    let mut witnesses: Vec<Witness> = vec![];
    sort_witnesses(&mut witnesses);
    assert!(witnesses.is_empty());
}

// ---------------------------------------------------------------------------
// sort_constraints
// ---------------------------------------------------------------------------

#[test]
fn sort_constraints_lexicographic_by_id() {
    let mut constraints = vec![
        make_constraint("z-rule"),
        make_constraint("a-rule"),
        make_constraint("m-rule"),
    ];
    sort_constraints(&mut constraints);
    assert_eq!(constraints[0].constraint_id, "a-rule");
    assert_eq!(constraints[1].constraint_id, "m-rule");
    assert_eq!(constraints[2].constraint_id, "z-rule");
}

#[test]
fn sort_constraints_empty_is_noop() {
    let mut constraints: Vec<Constraint> = vec![];
    sort_constraints(&mut constraints);
    assert!(constraints.is_empty());
}

// ---------------------------------------------------------------------------
// dedup_witnesses
// ---------------------------------------------------------------------------

#[test]
fn dedup_witnesses_removes_duplicates_keeps_first() {
    let mut witnesses = vec![
        Witness {
            witness_id: "obs-1".to_string(),
            witness_type: "t".to_string(),
            value: "first".to_string(),
        },
        Witness {
            witness_id: "obs-1".to_string(),
            witness_type: "t".to_string(),
            value: "second".to_string(),
        },
        make_witness("obs-2"),
    ];
    dedup_witnesses(&mut witnesses);
    assert_eq!(witnesses.len(), 2);
    assert_eq!(witnesses[0].value, "first"); // keeps first occurrence
    assert_eq!(witnesses[1].witness_id, "obs-2");
}

#[test]
fn dedup_witnesses_no_duplicates_unchanged() {
    let mut witnesses = vec![make_witness("a"), make_witness("b"), make_witness("c")];
    dedup_witnesses(&mut witnesses);
    assert_eq!(witnesses.len(), 3);
}

#[test]
fn dedup_witnesses_all_same_id_keeps_one() {
    let mut witnesses = vec![
        Witness {
            witness_id: "same".to_string(),
            witness_type: "t".to_string(),
            value: "v1".to_string(),
        },
        Witness {
            witness_id: "same".to_string(),
            witness_type: "t".to_string(),
            value: "v2".to_string(),
        },
        Witness {
            witness_id: "same".to_string(),
            witness_type: "t".to_string(),
            value: "v3".to_string(),
        },
    ];
    dedup_witnesses(&mut witnesses);
    assert_eq!(witnesses.len(), 1);
    assert_eq!(witnesses[0].value, "v1");
}

#[test]
fn dedup_witnesses_empty_is_noop() {
    let mut witnesses: Vec<Witness> = vec![];
    dedup_witnesses(&mut witnesses);
    assert!(witnesses.is_empty());
}

// ---------------------------------------------------------------------------
// normalize_entry
// ---------------------------------------------------------------------------

#[test]
fn normalize_sorts_deduplicates_and_reports() {
    let mut entry = make_entry(
        vec![
            CandidateAction::new("z-action", 100),
            CandidateAction::new("a-action", 200),
        ],
        vec![
            make_witness("w-b"),
            make_witness("w-a"),
            Witness {
                witness_id: "w-a".to_string(),
                witness_type: "t".to_string(),
                value: "dup".to_string(),
            },
        ],
        vec![make_constraint("z-rule"), make_constraint("a-rule")],
    );

    let result = normalize_entry(&mut entry, &SizeBounds::default());

    // Candidates sorted
    assert_eq!(entry.candidates[0].action_name, "a-action");
    assert_eq!(entry.candidates[1].action_name, "z-action");

    // Witnesses sorted and deduped
    assert_eq!(entry.witnesses.len(), 2);
    assert_eq!(entry.witnesses[0].witness_id, "w-a");
    assert_eq!(entry.witnesses[1].witness_id, "w-b");

    // Constraints sorted
    assert_eq!(entry.constraints[0].constraint_id, "a-rule");
    assert_eq!(entry.constraints[1].constraint_id, "z-rule");

    // Result stats
    assert_eq!(result.duplicates_removed, 1);
    assert!(result.truncations.is_empty());
}

#[test]
fn normalize_truncates_candidates_when_exceeding_bounds() {
    let candidates: Vec<CandidateAction> = (0..10)
        .map(|i| CandidateAction::new(format!("action-{i:03}"), i))
        .collect();
    let mut entry = make_entry(candidates, vec![], vec![]);

    let bounds = SizeBounds {
        max_candidates: 3,
        max_witnesses: 256,
        max_constraints: 32,
    };
    let result = normalize_entry(&mut entry, &bounds);

    assert_eq!(entry.candidates.len(), 3);
    assert_eq!(result.truncations.len(), 1);
    assert_eq!(result.truncations[0].list_name, "candidates");
    assert_eq!(result.truncations[0].original_count, 10);
    assert_eq!(result.truncations[0].retained_count, 3);
}

#[test]
fn normalize_truncates_witnesses_when_exceeding_bounds() {
    let witnesses: Vec<Witness> = (0..20)
        .map(|i| make_witness(&format!("w-{i:03}")))
        .collect();
    let mut entry = make_entry(vec![], witnesses, vec![]);

    let bounds = SizeBounds {
        max_candidates: 64,
        max_witnesses: 5,
        max_constraints: 32,
    };
    let result = normalize_entry(&mut entry, &bounds);

    assert_eq!(entry.witnesses.len(), 5);
    assert_eq!(result.truncations.len(), 1);
    assert_eq!(result.truncations[0].list_name, "witnesses");
}

#[test]
fn normalize_truncates_constraints_when_exceeding_bounds() {
    let constraints: Vec<Constraint> = (0..15)
        .map(|i| make_constraint(&format!("c-{i:03}")))
        .collect();
    let mut entry = make_entry(vec![], vec![], constraints);

    let bounds = SizeBounds {
        max_candidates: 64,
        max_witnesses: 256,
        max_constraints: 4,
    };
    let result = normalize_entry(&mut entry, &bounds);

    assert_eq!(entry.constraints.len(), 4);
    assert_eq!(result.truncations.len(), 1);
    assert_eq!(result.truncations[0].list_name, "constraints");
}

#[test]
fn normalize_multiple_truncations_simultaneous() {
    let candidates: Vec<CandidateAction> = (0..10)
        .map(|i| CandidateAction::new(format!("a-{i:03}"), i))
        .collect();
    let witnesses: Vec<Witness> = (0..10)
        .map(|i| make_witness(&format!("w-{i:03}")))
        .collect();
    let constraints: Vec<Constraint> = (0..10)
        .map(|i| make_constraint(&format!("c-{i:03}")))
        .collect();
    let mut entry = make_entry(candidates, witnesses, constraints);

    let bounds = SizeBounds {
        max_candidates: 2,
        max_witnesses: 3,
        max_constraints: 4,
    };
    let result = normalize_entry(&mut entry, &bounds);

    assert_eq!(entry.candidates.len(), 2);
    assert_eq!(entry.witnesses.len(), 3);
    assert_eq!(entry.constraints.len(), 4);
    assert_eq!(result.truncations.len(), 3);
}

#[test]
fn normalize_empty_entry_no_truncation_no_dedup() {
    let mut entry = make_entry(vec![], vec![], vec![]);
    let result = normalize_entry(&mut entry, &SizeBounds::default());
    assert_eq!(result.duplicates_removed, 0);
    assert!(result.truncations.is_empty());
}

#[test]
fn normalize_within_bounds_no_truncation() {
    let mut entry = make_entry(
        vec![CandidateAction::new("a", 1)],
        vec![make_witness("w-1")],
        vec![make_constraint("c-1")],
    );
    let result = normalize_entry(&mut entry, &SizeBounds::default());
    assert!(result.truncations.is_empty());
    assert_eq!(result.duplicates_removed, 0);
}

// ---------------------------------------------------------------------------
// validate_entry_ordering
// ---------------------------------------------------------------------------

#[test]
fn validate_passes_for_normalized_entry() {
    let mut entry = make_entry(
        vec![
            CandidateAction::new("b", 200),
            CandidateAction::new("a", 100),
        ],
        vec![make_witness("w-2"), make_witness("w-1")],
        vec![make_constraint("c-2"), make_constraint("c-1")],
    );
    normalize_entry(&mut entry, &SizeBounds::default());
    assert!(validate_entry_ordering(&entry, &SizeBounds::default()).is_ok());
}

#[test]
fn validate_catches_unsorted_candidates() {
    let entry = make_entry(
        vec![
            CandidateAction::new("z-action", 100),
            CandidateAction::new("a-action", 200),
        ],
        vec![],
        vec![],
    );
    let errors = validate_entry_ordering(&entry, &SizeBounds::default()).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, OrderingViolation::CandidatesNotSorted { .. }))
    );
}

#[test]
fn validate_catches_unsorted_witnesses() {
    let entry = make_entry(vec![], vec![make_witness("z"), make_witness("a")], vec![]);
    let errors = validate_entry_ordering(&entry, &SizeBounds::default()).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, OrderingViolation::WitnessesNotSorted { .. }))
    );
}

#[test]
fn validate_catches_unsorted_constraints() {
    let entry = make_entry(
        vec![],
        vec![],
        vec![make_constraint("z"), make_constraint("a")],
    );
    let errors = validate_entry_ordering(&entry, &SizeBounds::default()).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, OrderingViolation::ConstraintsNotSorted { .. }))
    );
}

#[test]
fn validate_catches_duplicate_witness_ids() {
    let entry = make_entry(
        vec![],
        vec![make_witness("obs-1"), make_witness("obs-1")],
        vec![],
    );
    let errors = validate_entry_ordering(&entry, &SizeBounds::default()).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, OrderingViolation::DuplicateWitnessId { .. }))
    );
}

#[test]
fn validate_catches_candidates_exceed_bound() {
    let candidates: Vec<CandidateAction> = (0..5)
        .map(|i| CandidateAction::new(format!("a-{i:03}"), i))
        .collect();
    let entry = make_entry(candidates, vec![], vec![]);
    let bounds = SizeBounds {
        max_candidates: 3,
        max_witnesses: 256,
        max_constraints: 32,
    };
    let errors = validate_entry_ordering(&entry, &bounds).unwrap_err();
    assert!(errors.iter().any(|e| matches!(
        e,
        OrderingViolation::CandidatesExceedBound { count: 5, max: 3 }
    )));
}

#[test]
fn validate_catches_witnesses_exceed_bound() {
    let witnesses: Vec<Witness> = (0..10)
        .map(|i| make_witness(&format!("w-{i:03}")))
        .collect();
    let entry = make_entry(vec![], witnesses, vec![]);
    let bounds = SizeBounds {
        max_candidates: 64,
        max_witnesses: 5,
        max_constraints: 32,
    };
    let errors = validate_entry_ordering(&entry, &bounds).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, OrderingViolation::WitnessesExceedBound { .. }))
    );
}

#[test]
fn validate_catches_constraints_exceed_bound() {
    let constraints: Vec<Constraint> = (0..10)
        .map(|i| make_constraint(&format!("c-{i:03}")))
        .collect();
    let entry = make_entry(vec![], vec![], constraints);
    let bounds = SizeBounds {
        max_candidates: 64,
        max_witnesses: 256,
        max_constraints: 5,
    };
    let errors = validate_entry_ordering(&entry, &bounds).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, OrderingViolation::ConstraintsExceedBound { .. }))
    );
}

#[test]
fn validate_collects_multiple_violations() {
    let entry = make_entry(
        vec![CandidateAction::new("z", 1), CandidateAction::new("a", 2)],
        vec![make_witness("z"), make_witness("a")],
        vec![],
    );
    let errors = validate_entry_ordering(&entry, &SizeBounds::default()).unwrap_err();
    assert!(errors.len() >= 2);
}

#[test]
fn validate_passes_empty_entry() {
    let entry = make_entry(vec![], vec![], vec![]);
    assert!(validate_entry_ordering(&entry, &SizeBounds::default()).is_ok());
}

// ---------------------------------------------------------------------------
// normalize then validate always passes
// ---------------------------------------------------------------------------

#[test]
fn normalize_then_validate_always_passes() {
    let candidates: Vec<CandidateAction> = (0..100)
        .rev()
        .map(|i| CandidateAction::new(format!("act-{i:03}"), i * 1000))
        .collect();
    let witnesses: Vec<Witness> = (0..50)
        .rev()
        .map(|i| make_witness(&format!("w-{i:03}")))
        .collect();
    let constraints: Vec<Constraint> = (0..20)
        .rev()
        .map(|i| make_constraint(&format!("c-{i:03}")))
        .collect();
    let mut entry = make_entry(candidates, witnesses, constraints);

    let bounds = SizeBounds {
        max_candidates: 20,
        max_witnesses: 30,
        max_constraints: 10,
    };
    normalize_entry(&mut entry, &bounds);
    assert!(validate_entry_ordering(&entry, &bounds).is_ok());
}

#[test]
fn normalize_then_validate_with_duplicates() {
    let witnesses = vec![
        make_witness("w-c"),
        make_witness("w-a"),
        make_witness("w-b"),
        make_witness("w-a"), // duplicate
        make_witness("w-c"), // duplicate
    ];
    let mut entry = make_entry(vec![], witnesses, vec![]);
    normalize_entry(&mut entry, &SizeBounds::default());
    assert!(validate_entry_ordering(&entry, &SizeBounds::default()).is_ok());
    assert_eq!(entry.witnesses.len(), 3);
}

// ---------------------------------------------------------------------------
// Deterministic replay
// ---------------------------------------------------------------------------

#[test]
fn normalization_is_deterministic() {
    let make_input = || {
        make_entry(
            vec![
                CandidateAction::new("z", 300),
                CandidateAction::new("a", 100),
                CandidateAction::new("m", 200),
            ],
            vec![
                make_witness("w-z"),
                make_witness("w-a"),
                make_witness("w-a"), // dup
            ],
            vec![make_constraint("c-z"), make_constraint("c-a")],
        )
    };

    let bounds = SizeBounds::default();
    let mut entry1 = make_input();
    let mut entry2 = make_input();
    let result1 = normalize_entry(&mut entry1, &bounds);
    let result2 = normalize_entry(&mut entry2, &bounds);

    // Candidates identical
    assert_eq!(entry1.candidates, entry2.candidates);
    // Witnesses identical
    assert_eq!(entry1.witnesses, entry2.witnesses);
    // Constraints identical
    assert_eq!(entry1.constraints, entry2.constraints);
    // Stats identical
    assert_eq!(result1.duplicates_removed, result2.duplicates_removed);
    assert_eq!(result1.truncations.len(), result2.truncations.len());
}

#[test]
fn validation_is_deterministic() {
    let entry = make_entry(
        vec![CandidateAction::new("z", 1), CandidateAction::new("a", 2)],
        vec![make_witness("z"), make_witness("a")],
        vec![],
    );
    let bounds = SizeBounds::default();
    let first_errors = validate_entry_ordering(&entry, &bounds).unwrap_err();
    for _ in 0..10 {
        let errors = validate_entry_ordering(&entry, &bounds).unwrap_err();
        assert_eq!(first_errors, errors, "validation must be deterministic");
    }
}

// ---------------------------------------------------------------------------
// Serialization of entries after normalization
// ---------------------------------------------------------------------------

#[test]
fn normalized_entry_serde_roundtrip() {
    let mut entry = make_entry(
        vec![
            CandidateAction::new("z-action", 200),
            CandidateAction::new("a-action", 100),
        ],
        vec![make_witness("w-b"), make_witness("w-a")],
        vec![make_constraint("c-b"), make_constraint("c-a")],
    );
    normalize_entry(&mut entry, &SizeBounds::default());

    let json = serde_json::to_string(&entry).expect("serialize");
    let restored: EvidenceEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, restored);
}

#[test]
fn normalized_entry_deterministic_serialization() {
    let mut entry = make_entry(
        vec![
            CandidateAction::new("z", 200),
            CandidateAction::new("a", 100),
        ],
        vec![make_witness("w-b"), make_witness("w-a")],
        vec![],
    );
    normalize_entry(&mut entry, &SizeBounds::default());

    let json1 = serde_json::to_string(&entry).expect("serialize");
    let json2 = serde_json::to_string(&entry).expect("serialize");
    assert_eq!(json1, json2, "serialization must be deterministic");
}
