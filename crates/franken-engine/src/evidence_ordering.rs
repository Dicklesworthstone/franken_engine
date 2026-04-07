//! Deterministic ordering and bounded-size policies for evidence entries.
//!
//! Ensures replay determinism: given identical decision inputs, the
//! serialized evidence entry is byte-identical across runs.  Provides
//! canonical sorting of candidates, witnesses, and constraints, plus
//! bounded-size truncation with audit markers.
//!
//! Plan references: Section 10.11 item 12, 9G.5 (policy controller),
//! Top-10 #3 (deterministic evidence graph and replay).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::evidence_ledger::{CandidateAction, Constraint, EvidenceEntry, Witness};

// ---------------------------------------------------------------------------
// SizeBounds — configurable bounded-size policy
// ---------------------------------------------------------------------------

/// Configurable size bounds for evidence entry lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeBounds {
    /// Maximum candidates per entry (default: 64).
    pub max_candidates: usize,
    /// Maximum witnesses per entry (default: 256).
    pub max_witnesses: usize,
    /// Maximum constraints per entry (default: 32).
    pub max_constraints: usize,
}

impl Default for SizeBounds {
    fn default() -> Self {
        Self {
            max_candidates: 64,
            max_witnesses: 256,
            max_constraints: 32,
        }
    }
}

// ---------------------------------------------------------------------------
// TruncationMarker — audit trail for truncation
// ---------------------------------------------------------------------------

/// Marker indicating that a list was truncated to stay within bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruncationMarker {
    /// Which list was truncated.
    pub list_name: String,
    /// Original count before truncation.
    pub original_count: usize,
    /// Retained count after truncation.
    pub retained_count: usize,
    /// Truncation policy applied.
    pub policy: String,
}

impl fmt::Display for TruncationMarker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} -> {} ({})",
            self.list_name, self.original_count, self.retained_count, self.policy
        )
    }
}

// ---------------------------------------------------------------------------
// OrderingViolation — validation error
// ---------------------------------------------------------------------------

/// Violation found during ordering validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderingViolation {
    /// Candidates are not in canonical sort order.
    CandidatesNotSorted { first_unsorted_index: usize },
    /// Witnesses are not in canonical sort order.
    WitnessesNotSorted { first_unsorted_index: usize },
    /// Constraints are not in canonical sort order.
    ConstraintsNotSorted { first_unsorted_index: usize },
    /// Duplicate witness IDs found.
    DuplicateWitnessId { witness_id: String },
    /// Candidates exceed size bound.
    CandidatesExceedBound { count: usize, max: usize },
    /// Witnesses exceed size bound.
    WitnessesExceedBound { count: usize, max: usize },
    /// Constraints exceed size bound.
    ConstraintsExceedBound { count: usize, max: usize },
}

impl fmt::Display for OrderingViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CandidatesNotSorted {
                first_unsorted_index,
            } => write!(f, "candidates not sorted at index {first_unsorted_index}"),
            Self::WitnessesNotSorted {
                first_unsorted_index,
            } => write!(f, "witnesses not sorted at index {first_unsorted_index}"),
            Self::ConstraintsNotSorted {
                first_unsorted_index,
            } => write!(f, "constraints not sorted at index {first_unsorted_index}"),
            Self::DuplicateWitnessId { witness_id } => {
                write!(f, "duplicate witness id: {witness_id}")
            }
            Self::CandidatesExceedBound { count, max } => {
                write!(f, "candidates exceed bound: {count} > {max}")
            }
            Self::WitnessesExceedBound { count, max } => {
                write!(f, "witnesses exceed bound: {count} > {max}")
            }
            Self::ConstraintsExceedBound { count, max } => {
                write!(f, "constraints exceed bound: {count} > {max}")
            }
        }
    }
}

impl std::error::Error for OrderingViolation {}

// ---------------------------------------------------------------------------
// Canonical sort comparators
// ---------------------------------------------------------------------------

/// Canonical sort key for candidates: action_name, then expected_loss ascending.
fn candidate_sort_key(c: &CandidateAction) -> (&str, i64) {
    (&c.action_name, c.expected_loss_millionths)
}

/// Sort candidates canonically.
pub fn sort_candidates(candidates: &mut [CandidateAction]) {
    candidates.sort_by(|a, b| candidate_sort_key(a).cmp(&candidate_sort_key(b)));
}

/// Sort witnesses by witness_id (lexicographic).
pub fn sort_witnesses(witnesses: &mut [Witness]) {
    witnesses.sort_by(|a, b| a.witness_id.cmp(&b.witness_id));
}

/// Sort constraints by constraint_id (lexicographic).
pub fn sort_constraints(constraints: &mut [Constraint]) {
    constraints.sort_by(|a, b| a.constraint_id.cmp(&b.constraint_id));
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

/// Deduplicate witnesses by witness_id, keeping the first occurrence.
pub fn dedup_witnesses(witnesses: &mut Vec<Witness>) {
    let mut seen = std::collections::BTreeSet::new();
    witnesses.retain(|w| seen.insert(w.witness_id.clone()));
}

// ---------------------------------------------------------------------------
// Normalization pipeline
// ---------------------------------------------------------------------------

/// Result of normalizing an evidence entry.
#[derive(Debug, Clone)]
pub struct NormalizationResult {
    /// Truncation markers (empty if no truncation was needed).
    pub truncations: Vec<TruncationMarker>,
    /// Number of duplicate witnesses removed.
    pub duplicates_removed: usize,
}

/// Normalize an evidence entry in place: sort, deduplicate, truncate.
///
/// This is the normalization pass that should be run before emission.
pub fn normalize_entry(entry: &mut EvidenceEntry, bounds: &SizeBounds) -> NormalizationResult {
    let mut truncations = Vec::new();

    // 1. Sort all lists canonically.
    sort_candidates(&mut entry.candidates);
    sort_witnesses(&mut entry.witnesses);
    sort_constraints(&mut entry.constraints);

    // 2. Deduplicate witnesses.
    let pre_dedup = entry.witnesses.len();
    dedup_witnesses(&mut entry.witnesses);
    let duplicates_removed = pre_dedup - entry.witnesses.len();

    // 3. Apply size bounds with truncation markers.
    if entry.candidates.len() > bounds.max_candidates {
        truncations.push(TruncationMarker {
            list_name: "candidates".to_string(),
            original_count: entry.candidates.len(),
            retained_count: bounds.max_candidates,
            policy: "top-K by action_name".to_string(),
        });
        entry.candidates.truncate(bounds.max_candidates);
    }

    if entry.witnesses.len() > bounds.max_witnesses {
        truncations.push(TruncationMarker {
            list_name: "witnesses".to_string(),
            original_count: entry.witnesses.len(),
            retained_count: bounds.max_witnesses,
            policy: "top-K by witness_id".to_string(),
        });
        entry.witnesses.truncate(bounds.max_witnesses);
    }

    if entry.constraints.len() > bounds.max_constraints {
        truncations.push(TruncationMarker {
            list_name: "constraints".to_string(),
            original_count: entry.constraints.len(),
            retained_count: bounds.max_constraints,
            policy: "top-K by constraint_id".to_string(),
        });
        entry.constraints.truncate(bounds.max_constraints);
    }

    NormalizationResult {
        truncations,
        duplicates_removed,
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate that an evidence entry satisfies all ordering, uniqueness,
/// and size invariants.
///
/// Returns all violations found (not fail-fast).
pub fn validate_entry_ordering(
    entry: &EvidenceEntry,
    bounds: &SizeBounds,
) -> Result<(), Vec<OrderingViolation>> {
    let mut violations = Vec::new();

    // Check candidate ordering.
    for i in 1..entry.candidates.len() {
        if candidate_sort_key(&entry.candidates[i]) < candidate_sort_key(&entry.candidates[i - 1]) {
            violations.push(OrderingViolation::CandidatesNotSorted {
                first_unsorted_index: i,
            });
            break;
        }
    }

    // Check witness ordering and uniqueness.
    let mut witness_ids = std::collections::BTreeSet::new();
    for (i, w) in entry.witnesses.iter().enumerate() {
        if !witness_ids.insert(&w.witness_id) {
            violations.push(OrderingViolation::DuplicateWitnessId {
                witness_id: w.witness_id.clone(),
            });
        }
        if i > 0 && w.witness_id < entry.witnesses[i - 1].witness_id {
            violations.push(OrderingViolation::WitnessesNotSorted {
                first_unsorted_index: i,
            });
            break;
        }
    }

    // Check constraint ordering.
    for i in 1..entry.constraints.len() {
        if entry.constraints[i].constraint_id < entry.constraints[i - 1].constraint_id {
            violations.push(OrderingViolation::ConstraintsNotSorted {
                first_unsorted_index: i,
            });
            break;
        }
    }

    // Check size bounds.
    if entry.candidates.len() > bounds.max_candidates {
        violations.push(OrderingViolation::CandidatesExceedBound {
            count: entry.candidates.len(),
            max: bounds.max_candidates,
        });
    }
    if entry.witnesses.len() > bounds.max_witnesses {
        violations.push(OrderingViolation::WitnessesExceedBound {
            count: entry.witnesses.len(),
            max: bounds.max_witnesses,
        });
    }
    if entry.constraints.len() > bounds.max_constraints {
        violations.push(OrderingViolation::ConstraintsExceedBound {
            count: entry.constraints.len(),
            max: bounds.max_constraints,
        });
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence_ledger::*;
    use crate::security_epoch::SecurityEpoch;

    fn make_entry_with(
        candidates: Vec<CandidateAction>,
        witnesses: Vec<Witness>,
        constraints: Vec<Constraint>,
    ) -> EvidenceEntry {
        EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
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
        .expect("build")
    }

    // -- Sorting --

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
    fn sort_witnesses_by_id() {
        let mut witnesses = vec![
            Witness {
                witness_id: "z-obs".to_string(),
                witness_type: "t".to_string(),
                value: "1".to_string(),
            },
            Witness {
                witness_id: "a-obs".to_string(),
                witness_type: "t".to_string(),
                value: "2".to_string(),
            },
            Witness {
                witness_id: "m-obs".to_string(),
                witness_type: "t".to_string(),
                value: "3".to_string(),
            },
        ];
        sort_witnesses(&mut witnesses);
        assert_eq!(witnesses[0].witness_id, "a-obs");
        assert_eq!(witnesses[1].witness_id, "m-obs");
        assert_eq!(witnesses[2].witness_id, "z-obs");
    }

    #[test]
    fn sort_constraints_by_id() {
        let mut constraints = vec![
            Constraint {
                constraint_id: "z-rule".to_string(),
                description: "d".to_string(),
                active: true,
            },
            Constraint {
                constraint_id: "a-rule".to_string(),
                description: "d".to_string(),
                active: false,
            },
        ];
        sort_constraints(&mut constraints);
        assert_eq!(constraints[0].constraint_id, "a-rule");
        assert_eq!(constraints[1].constraint_id, "z-rule");
    }

    // -- Deduplication --

    #[test]
    fn dedup_removes_duplicate_witness_ids() {
        let mut witnesses = vec![
            Witness {
                witness_id: "obs-1".to_string(),
                witness_type: "t".to_string(),
                value: "a".to_string(),
            },
            Witness {
                witness_id: "obs-1".to_string(),
                witness_type: "t".to_string(),
                value: "b".to_string(),
            },
            Witness {
                witness_id: "obs-2".to_string(),
                witness_type: "t".to_string(),
                value: "c".to_string(),
            },
        ];
        dedup_witnesses(&mut witnesses);
        assert_eq!(witnesses.len(), 2);
        assert_eq!(witnesses[0].value, "a"); // keeps first
        assert_eq!(witnesses[1].witness_id, "obs-2");
    }

    // -- Normalization --

    #[test]
    fn normalize_sorts_and_deduplicates() {
        let mut entry = make_entry_with(
            vec![
                CandidateAction::new("z-action", 100),
                CandidateAction::new("a-action", 200),
            ],
            vec![
                Witness {
                    witness_id: "w-b".to_string(),
                    witness_type: "t".to_string(),
                    value: "1".to_string(),
                },
                Witness {
                    witness_id: "w-a".to_string(),
                    witness_type: "t".to_string(),
                    value: "2".to_string(),
                },
                Witness {
                    witness_id: "w-a".to_string(),
                    witness_type: "t".to_string(),
                    value: "3".to_string(),
                },
            ],
            vec![],
        );

        let result = normalize_entry(&mut entry, &SizeBounds::default());
        assert_eq!(result.duplicates_removed, 1);
        assert!(result.truncations.is_empty());

        // Candidates sorted.
        assert_eq!(entry.candidates[0].action_name, "a-action");
        assert_eq!(entry.candidates[1].action_name, "z-action");

        // Witnesses sorted and deduped.
        assert_eq!(entry.witnesses.len(), 2);
        assert_eq!(entry.witnesses[0].witness_id, "w-a");
        assert_eq!(entry.witnesses[1].witness_id, "w-b");
    }

    #[test]
    fn normalize_truncates_when_exceeding_bounds() {
        let candidates: Vec<CandidateAction> = (0..10)
            .map(|i| CandidateAction::new(format!("action-{i:03}"), i))
            .collect();
        let mut entry = make_entry_with(candidates, vec![], vec![]);

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

    // -- Validation --

    #[test]
    fn validate_passes_for_normalized_entry() {
        let mut entry = make_entry_with(
            vec![
                CandidateAction::new("a", 100),
                CandidateAction::new("b", 200),
            ],
            vec![Witness {
                witness_id: "w-1".to_string(),
                witness_type: "t".to_string(),
                value: "v".to_string(),
            }],
            vec![],
        );
        normalize_entry(&mut entry, &SizeBounds::default());
        assert!(validate_entry_ordering(&entry, &SizeBounds::default()).is_ok());
    }

    #[test]
    fn validate_catches_unsorted_candidates() {
        let entry = make_entry_with(
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
        let entry = make_entry_with(
            vec![],
            vec![
                Witness {
                    witness_id: "z".to_string(),
                    witness_type: "t".to_string(),
                    value: "v".to_string(),
                },
                Witness {
                    witness_id: "a".to_string(),
                    witness_type: "t".to_string(),
                    value: "v".to_string(),
                },
            ],
            vec![],
        );
        let errors = validate_entry_ordering(&entry, &SizeBounds::default()).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, OrderingViolation::WitnessesNotSorted { .. }))
        );
    }

    #[test]
    fn validate_catches_duplicate_witness_ids() {
        let entry = make_entry_with(
            vec![],
            vec![
                Witness {
                    witness_id: "obs-1".to_string(),
                    witness_type: "t".to_string(),
                    value: "a".to_string(),
                },
                Witness {
                    witness_id: "obs-1".to_string(),
                    witness_type: "t".to_string(),
                    value: "b".to_string(),
                },
            ],
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
    fn validate_catches_size_bound_violations() {
        let candidates: Vec<CandidateAction> = (0..5)
            .map(|i| CandidateAction::new(format!("a-{i:03}"), i))
            .collect();
        let entry = make_entry_with(candidates, vec![], vec![]);
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
    fn validate_collects_multiple_violations() {
        let entry = make_entry_with(
            vec![CandidateAction::new("z", 1), CandidateAction::new("a", 2)],
            vec![
                Witness {
                    witness_id: "z".to_string(),
                    witness_type: "t".to_string(),
                    value: "v".to_string(),
                },
                Witness {
                    witness_id: "a".to_string(),
                    witness_type: "t".to_string(),
                    value: "v".to_string(),
                },
            ],
            vec![],
        );
        let errors = validate_entry_ordering(&entry, &SizeBounds::default()).unwrap_err();
        assert!(errors.len() >= 2);
    }

    // -- Normalized entry passes validation --

    #[test]
    fn normalize_then_validate_always_passes() {
        let candidates: Vec<CandidateAction> = (0..100)
            .rev()
            .map(|i| CandidateAction::new(format!("act-{i:03}"), i * 1000))
            .collect();
        let witnesses: Vec<Witness> = (0..50)
            .rev()
            .map(|i| Witness {
                witness_id: format!("w-{i:03}"),
                witness_type: "t".to_string(),
                value: format!("{i}"),
            })
            .collect();
        let mut entry = make_entry_with(candidates, witnesses, vec![]);

        let bounds = SizeBounds {
            max_candidates: 20,
            max_witnesses: 30,
            max_constraints: 10,
        };
        normalize_entry(&mut entry, &bounds);
        assert!(validate_entry_ordering(&entry, &bounds).is_ok());
    }

    // -- Display --

    #[test]
    fn truncation_marker_display() {
        let marker = TruncationMarker {
            list_name: "candidates".to_string(),
            original_count: 100,
            retained_count: 64,
            policy: "top-K by action_name".to_string(),
        };
        assert_eq!(
            marker.to_string(),
            "candidates: 100 -> 64 (top-K by action_name)"
        );
    }

    #[test]
    fn ordering_violation_display() {
        let v = OrderingViolation::CandidatesNotSorted {
            first_unsorted_index: 3,
        };
        assert_eq!(v.to_string(), "candidates not sorted at index 3");
    }

    // -- Serialization --

    #[test]
    fn size_bounds_serialization_round_trip() {
        let bounds = SizeBounds::default();
        let json = serde_json::to_string(&bounds).unwrap_or_default();
        let restored: SizeBounds = serde_json::from_str(&json).unwrap_or_default();
        assert_eq!(bounds, restored);
    }

    #[test]
    fn truncation_marker_serialization_round_trip() {
        let marker = TruncationMarker {
            list_name: "witnesses".to_string(),
            original_count: 300,
            retained_count: 256,
            policy: "top-K by witness_id".to_string(),
        };
        let json = serde_json::to_string(&marker).unwrap_or_default();
        let restored: TruncationMarker = serde_json::from_str(&json).unwrap_or_default();
        assert_eq!(marker, restored);
    }

    // -- Enrichment: Display & std::error --

    #[test]
    fn ordering_violation_display_all_variants() {
        let variants: Vec<OrderingViolation> = vec![
            OrderingViolation::CandidatesNotSorted {
                first_unsorted_index: 3,
            },
            OrderingViolation::WitnessesNotSorted {
                first_unsorted_index: 1,
            },
            OrderingViolation::ConstraintsNotSorted {
                first_unsorted_index: 0,
            },
            OrderingViolation::DuplicateWitnessId {
                witness_id: "w-1".to_string(),
            },
            OrderingViolation::CandidatesExceedBound {
                count: 300,
                max: 256,
            },
            OrderingViolation::WitnessesExceedBound {
                count: 300,
                max: 256,
            },
            OrderingViolation::ConstraintsExceedBound {
                count: 300,
                max: 256,
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            7,
            "all 7 variants produce distinct messages"
        );
    }

    #[test]
    fn ordering_violation_implements_std_error() {
        let v = OrderingViolation::CandidatesNotSorted {
            first_unsorted_index: 0,
        };
        let err: &dyn std::error::Error = &v;
        assert!(!format!("{err}").is_empty());
        assert!(err.source().is_none());
    }

    #[test]
    fn ordering_violation_serialization_round_trip() {
        let violations = vec![
            OrderingViolation::CandidatesNotSorted {
                first_unsorted_index: 2,
            },
            OrderingViolation::DuplicateWitnessId {
                witness_id: "obs-1".to_string(),
            },
            OrderingViolation::WitnessesExceedBound {
                count: 300,
                max: 256,
            },
        ];
        for v in &violations {
            let json = serde_json::to_string(v).unwrap_or_default();
            let restored: OrderingViolation = serde_json::from_str(&json).unwrap_or_default();
            assert_eq!(*v, restored);
        }
    }

    // -- Enrichment: edge cases and boundary conditions --

    #[test]
    fn empty_entry_passes_validation() {
        let entry = make_entry_with(vec![], vec![], vec![]);
        assert!(validate_entry_ordering(&entry, &SizeBounds::default()).is_ok());
    }

    #[test]
    fn single_candidate_passes_validation() {
        let entry = make_entry_with(vec![CandidateAction::new("only", 100)], vec![], vec![]);
        assert!(validate_entry_ordering(&entry, &SizeBounds::default()).is_ok());
    }

    #[test]
    fn already_sorted_candidates_unchanged_by_sort() {
        let mut candidates = vec![
            CandidateAction::new("alpha", 100),
            CandidateAction::new("beta", 200),
            CandidateAction::new("gamma", 300),
        ];
        let before: Vec<String> = candidates.iter().map(|c| c.action_name.clone()).collect();
        sort_candidates(&mut candidates);
        let after: Vec<String> = candidates.iter().map(|c| c.action_name.clone()).collect();
        assert_eq!(before, after);
    }

    #[test]
    fn normalize_is_idempotent() {
        let mut entry = make_entry_with(
            vec![
                CandidateAction::new("z", 500),
                CandidateAction::new("a", 100),
            ],
            vec![
                Witness {
                    witness_id: "w-b".to_string(),
                    witness_type: "t".to_string(),
                    value: "1".to_string(),
                },
                Witness {
                    witness_id: "w-a".to_string(),
                    witness_type: "t".to_string(),
                    value: "2".to_string(),
                },
            ],
            vec![],
        );
        let bounds = SizeBounds::default();
        normalize_entry(&mut entry, &bounds);
        let json_first = serde_json::to_string(&entry).unwrap();
        let result2 = normalize_entry(&mut entry, &bounds);
        let json_second = serde_json::to_string(&entry).unwrap();
        assert_eq!(json_first, json_second, "normalize should be idempotent");
        assert_eq!(result2.duplicates_removed, 0);
        assert!(result2.truncations.is_empty());
    }

    #[test]
    fn normalize_constraints_truncation() {
        let constraints: Vec<Constraint> = (0..20)
            .rev()
            .map(|i| Constraint {
                constraint_id: format!("c-{i:03}"),
                description: "d".to_string(),
                active: true,
            })
            .collect();
        let mut entry = make_entry_with(vec![], vec![], constraints);
        let bounds = SizeBounds {
            max_candidates: 64,
            max_witnesses: 256,
            max_constraints: 5,
        };
        let result = normalize_entry(&mut entry, &bounds);
        assert_eq!(result.truncations.len(), 1);
        assert_eq!(result.truncations[0].list_name, "constraints");
        assert_eq!(entry.constraints.len(), 5);
        // Sorted, so first 5 should be c-000 through c-004
        assert_eq!(entry.constraints[0].constraint_id, "c-000");
        assert_eq!(entry.constraints[4].constraint_id, "c-004");
    }

    #[test]
    fn witnesses_truncation() {
        let witnesses: Vec<Witness> = (0..10)
            .map(|i| Witness {
                witness_id: format!("w-{i:03}"),
                witness_type: "t".to_string(),
                value: format!("{i}"),
            })
            .collect();
        let mut entry = make_entry_with(vec![], witnesses, vec![]);
        let bounds = SizeBounds {
            max_candidates: 64,
            max_witnesses: 3,
            max_constraints: 32,
        };
        let result = normalize_entry(&mut entry, &bounds);
        assert_eq!(result.truncations.len(), 1);
        assert_eq!(entry.witnesses.len(), 3);
    }

    #[test]
    fn validate_catches_unsorted_constraints() {
        let entry = make_entry_with(
            vec![],
            vec![],
            vec![
                Constraint {
                    constraint_id: "z-rule".to_string(),
                    description: "d".to_string(),
                    active: true,
                },
                Constraint {
                    constraint_id: "a-rule".to_string(),
                    description: "d".to_string(),
                    active: false,
                },
            ],
        );
        let errors = validate_entry_ordering(&entry, &SizeBounds::default()).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, OrderingViolation::ConstraintsNotSorted { .. }))
        );
    }

    #[test]
    fn validate_catches_witnesses_exceed_bound() {
        let witnesses: Vec<Witness> = (0..5)
            .map(|i| Witness {
                witness_id: format!("w-{i:03}"),
                witness_type: "t".to_string(),
                value: "v".to_string(),
            })
            .collect();
        let entry = make_entry_with(vec![], witnesses, vec![]);
        let bounds = SizeBounds {
            max_candidates: 64,
            max_witnesses: 3,
            max_constraints: 32,
        };
        let errors = validate_entry_ordering(&entry, &bounds).unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            OrderingViolation::WitnessesExceedBound { count: 5, max: 3 }
        )));
    }

    #[test]
    fn validate_catches_constraints_exceed_bound() {
        let constraints: Vec<Constraint> = (0..5)
            .map(|i| Constraint {
                constraint_id: format!("c-{i:03}"),
                description: "d".to_string(),
                active: true,
            })
            .collect();
        let entry = make_entry_with(vec![], vec![], constraints);
        let bounds = SizeBounds {
            max_candidates: 64,
            max_witnesses: 256,
            max_constraints: 2,
        };
        let errors = validate_entry_ordering(&entry, &bounds).unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            OrderingViolation::ConstraintsExceedBound { count: 5, max: 2 }
        )));
    }

    #[test]
    fn sort_candidates_stable_on_equal_names() {
        let mut candidates = vec![
            CandidateAction::new("same", 300),
            CandidateAction::new("same", 100),
            CandidateAction::new("same", 200),
        ];
        sort_candidates(&mut candidates);
        assert_eq!(candidates[0].expected_loss_millionths, 100);
        assert_eq!(candidates[1].expected_loss_millionths, 200);
        assert_eq!(candidates[2].expected_loss_millionths, 300);
    }

    #[test]
    fn dedup_witnesses_no_duplicates_unchanged() {
        let mut witnesses = vec![
            Witness {
                witness_id: "a".to_string(),
                witness_type: "t".to_string(),
                value: "1".to_string(),
            },
            Witness {
                witness_id: "b".to_string(),
                witness_type: "t".to_string(),
                value: "2".to_string(),
            },
        ];
        dedup_witnesses(&mut witnesses);
        assert_eq!(witnesses.len(), 2);
    }

    #[test]
    fn dedup_witnesses_all_duplicates() {
        let mut witnesses = vec![
            Witness {
                witness_id: "same".to_string(),
                witness_type: "t".to_string(),
                value: "1".to_string(),
            },
            Witness {
                witness_id: "same".to_string(),
                witness_type: "t".to_string(),
                value: "2".to_string(),
            },
            Witness {
                witness_id: "same".to_string(),
                witness_type: "t".to_string(),
                value: "3".to_string(),
            },
        ];
        dedup_witnesses(&mut witnesses);
        assert_eq!(witnesses.len(), 1);
        assert_eq!(witnesses[0].value, "1"); // keeps first
    }

    #[test]
    fn size_bounds_default_values() {
        let bounds = SizeBounds::default();
        assert_eq!(bounds.max_candidates, 64);
        assert_eq!(bounds.max_witnesses, 256);
        assert_eq!(bounds.max_constraints, 32);
    }

    #[test]
    fn normalize_large_entry_all_truncations() {
        let candidates: Vec<CandidateAction> = (0..100)
            .map(|i| CandidateAction::new(format!("act-{i:03}"), i * 1000))
            .collect();
        let witnesses: Vec<Witness> = (0..100)
            .map(|i| Witness {
                witness_id: format!("w-{i:03}"),
                witness_type: "t".to_string(),
                value: format!("{i}"),
            })
            .collect();
        let constraints: Vec<Constraint> = (0..100)
            .map(|i| Constraint {
                constraint_id: format!("c-{i:03}"),
                description: "d".to_string(),
                active: true,
            })
            .collect();
        let mut entry = make_entry_with(candidates, witnesses, constraints);
        let bounds = SizeBounds {
            max_candidates: 10,
            max_witnesses: 10,
            max_constraints: 10,
        };
        let result = normalize_entry(&mut entry, &bounds);
        assert_eq!(result.truncations.len(), 3);
        assert_eq!(entry.candidates.len(), 10);
        assert_eq!(entry.witnesses.len(), 10);
        assert_eq!(entry.constraints.len(), 10);
        assert!(validate_entry_ordering(&entry, &bounds).is_ok());
    }

    #[test]
    fn normalization_result_truncation_marker_display() {
        let marker = TruncationMarker {
            list_name: "witnesses".to_string(),
            original_count: 500,
            retained_count: 256,
            policy: "top-K by witness_id".to_string(),
        };
        let display = marker.to_string();
        assert!(display.contains("witnesses"));
        assert!(display.contains("500"));
        assert!(display.contains("256"));
    }

    // -- Enrichment: additional coverage --

    #[test]
    fn size_bounds_custom_values_serde_roundtrip() {
        let bounds = SizeBounds {
            max_candidates: 10,
            max_witnesses: 20,
            max_constraints: 5,
        };
        let json = serde_json::to_string(&bounds).unwrap();
        let restored: SizeBounds = serde_json::from_str(&json).unwrap();
        assert_eq!(bounds, restored);
    }

    #[test]
    fn dedup_witnesses_empty_vec() {
        let mut witnesses: Vec<Witness> = vec![];
        dedup_witnesses(&mut witnesses);
        assert!(witnesses.is_empty());
    }

    #[test]
    fn sort_candidates_empty_slice() {
        let mut candidates: Vec<CandidateAction> = vec![];
        sort_candidates(&mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn sort_witnesses_empty_slice() {
        let mut witnesses: Vec<Witness> = vec![];
        sort_witnesses(&mut witnesses);
        assert!(witnesses.is_empty());
    }

    #[test]
    fn sort_constraints_empty_slice() {
        let mut constraints: Vec<Constraint> = vec![];
        sort_constraints(&mut constraints);
        assert!(constraints.is_empty());
    }

    #[test]
    fn validate_entry_at_exact_bound_passes() {
        let candidates: Vec<CandidateAction> = (0..3)
            .map(|i| CandidateAction::new(format!("act-{i:03}"), i * 1000))
            .collect();
        let mut entry = make_entry_with(candidates, vec![], vec![]);
        normalize_entry(&mut entry, &SizeBounds::default());
        let bounds = SizeBounds {
            max_candidates: 3,
            max_witnesses: 256,
            max_constraints: 32,
        };
        assert!(validate_entry_ordering(&entry, &bounds).is_ok());
    }

    #[test]
    fn ordering_violation_all_variants_serde_roundtrip() {
        let variants = vec![
            OrderingViolation::CandidatesNotSorted {
                first_unsorted_index: 0,
            },
            OrderingViolation::WitnessesNotSorted {
                first_unsorted_index: 1,
            },
            OrderingViolation::ConstraintsNotSorted {
                first_unsorted_index: 2,
            },
            OrderingViolation::DuplicateWitnessId {
                witness_id: "w-dup".to_string(),
            },
            OrderingViolation::CandidatesExceedBound {
                count: 100,
                max: 64,
            },
            OrderingViolation::WitnessesExceedBound {
                count: 300,
                max: 256,
            },
            OrderingViolation::ConstraintsExceedBound { count: 50, max: 32 },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let restored: OrderingViolation = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn normalize_no_truncation_when_within_bounds() {
        let candidates: Vec<CandidateAction> = (0..5)
            .map(|i| CandidateAction::new(format!("act-{i:03}"), i * 1000))
            .collect();
        let mut entry = make_entry_with(candidates, vec![], vec![]);
        let result = normalize_entry(&mut entry, &SizeBounds::default());
        assert!(result.truncations.is_empty());
        assert_eq!(result.duplicates_removed, 0);
    }

    #[test]
    fn truncation_marker_display_contains_policy() {
        let marker = TruncationMarker {
            list_name: "constraints".to_string(),
            original_count: 40,
            retained_count: 32,
            policy: "top-K by constraint_id".to_string(),
        };
        let display = marker.to_string();
        assert!(display.contains("top-K by constraint_id"));
    }

    #[test]
    fn normalize_then_validate_stress_all_lists_oversized() {
        let candidates: Vec<CandidateAction> = (0..200)
            .rev()
            .map(|i| CandidateAction::new(format!("act-{i:04}"), i * 100))
            .collect();
        let witnesses: Vec<Witness> = (0..300)
            .rev()
            .map(|i| Witness {
                witness_id: format!("w-{i:04}"),
                witness_type: "t".to_string(),
                value: format!("{i}"),
            })
            .collect();
        let constraints: Vec<Constraint> = (0..50)
            .rev()
            .map(|i| Constraint {
                constraint_id: format!("c-{i:03}"),
                description: "d".to_string(),
                active: true,
            })
            .collect();
        let mut entry = make_entry_with(candidates, witnesses, constraints);
        let bounds = SizeBounds {
            max_candidates: 64,
            max_witnesses: 256,
            max_constraints: 32,
        };
        normalize_entry(&mut entry, &bounds);
        assert!(validate_entry_ordering(&entry, &bounds).is_ok());
        assert!(entry.candidates.len() <= 64);
        assert!(entry.witnesses.len() <= 256);
        assert!(entry.constraints.len() <= 32);
    }

    #[test]
    fn sort_candidates_negative_loss_values() {
        let mut candidates = vec![
            CandidateAction::new("action", 100),
            CandidateAction::new("action", -500),
            CandidateAction::new("action", 0),
        ];
        sort_candidates(&mut candidates);
        assert_eq!(candidates[0].expected_loss_millionths, -500);
        assert_eq!(candidates[1].expected_loss_millionths, 0);
        assert_eq!(candidates[2].expected_loss_millionths, 100);
    }

    // ── Enrichment batch 2: edge cases & boundary conditions ────

    #[test]
    fn normalize_single_duplicate_witness_removed() {
        let mut entry = make_entry_with(
            vec![],
            vec![
                Witness {
                    witness_id: "w".to_string(),
                    witness_type: "t".to_string(),
                    value: "first".to_string(),
                },
                Witness {
                    witness_id: "w".to_string(),
                    witness_type: "t".to_string(),
                    value: "second".to_string(),
                },
            ],
            vec![],
        );
        let result = normalize_entry(&mut entry, &SizeBounds::default());
        assert_eq!(result.duplicates_removed, 1);
        assert_eq!(entry.witnesses.len(), 1);
        assert_eq!(entry.witnesses[0].value, "first");
    }

    #[test]
    fn validate_single_witness_passes() {
        let entry = make_entry_with(
            vec![],
            vec![Witness {
                witness_id: "only".to_string(),
                witness_type: "t".to_string(),
                value: "v".to_string(),
            }],
            vec![],
        );
        assert!(validate_entry_ordering(&entry, &SizeBounds::default()).is_ok());
    }

    #[test]
    fn validate_single_constraint_passes() {
        let entry = make_entry_with(
            vec![],
            vec![],
            vec![Constraint {
                constraint_id: "only".to_string(),
                description: "d".to_string(),
                active: true,
            }],
        );
        assert!(validate_entry_ordering(&entry, &SizeBounds::default()).is_ok());
    }

    #[test]
    fn truncation_at_exact_bound_no_marker() {
        let witnesses: Vec<Witness> = (0..3)
            .map(|i| Witness {
                witness_id: format!("w-{i:03}"),
                witness_type: "t".to_string(),
                value: format!("{i}"),
            })
            .collect();
        let mut entry = make_entry_with(vec![], witnesses, vec![]);
        let bounds = SizeBounds {
            max_candidates: 64,
            max_witnesses: 3,
            max_constraints: 32,
        };
        let result = normalize_entry(&mut entry, &bounds);
        assert!(result.truncations.is_empty());
        assert_eq!(entry.witnesses.len(), 3);
    }

    #[test]
    fn filtered_candidate_preserves_sort_order() {
        let mut candidates = vec![
            CandidateAction::filtered("z-action", 100, "blocked"),
            CandidateAction::new("a-action", 200),
            CandidateAction::filtered("m-action", 50, "cost cap"),
        ];
        sort_candidates(&mut candidates);
        assert_eq!(candidates[0].action_name, "a-action");
        assert_eq!(candidates[1].action_name, "m-action");
        assert_eq!(candidates[2].action_name, "z-action");
        // Filtered status preserved after sort
        assert!(candidates[1].filtered);
        assert!(!candidates[0].filtered);
    }

    #[test]
    fn normalize_mixed_duplicates_and_truncation() {
        let witnesses: Vec<Witness> = (0..10)
            .flat_map(|i| {
                vec![
                    Witness {
                        witness_id: format!("w-{i:03}"),
                        witness_type: "t".to_string(),
                        value: "a".to_string(),
                    },
                    Witness {
                        witness_id: format!("w-{i:03}"),
                        witness_type: "t".to_string(),
                        value: "b".to_string(),
                    },
                ]
            })
            .collect();
        let mut entry = make_entry_with(vec![], witnesses, vec![]);
        let bounds = SizeBounds {
            max_candidates: 64,
            max_witnesses: 5,
            max_constraints: 32,
        };
        let result = normalize_entry(&mut entry, &bounds);
        assert_eq!(result.duplicates_removed, 10);
        assert_eq!(result.truncations.len(), 1);
        assert_eq!(entry.witnesses.len(), 5);
    }

    #[test]
    fn validate_two_witnesses_sorted_passes() {
        let entry = make_entry_with(
            vec![],
            vec![
                Witness {
                    witness_id: "alpha".to_string(),
                    witness_type: "t".to_string(),
                    value: "v".to_string(),
                },
                Witness {
                    witness_id: "beta".to_string(),
                    witness_type: "t".to_string(),
                    value: "v".to_string(),
                },
            ],
            vec![],
        );
        assert!(validate_entry_ordering(&entry, &SizeBounds::default()).is_ok());
    }

    #[test]
    fn sort_single_candidate_unchanged() {
        let mut candidates = vec![CandidateAction::new("only", 42)];
        sort_candidates(&mut candidates);
        assert_eq!(candidates[0].action_name, "only");
        assert_eq!(candidates[0].expected_loss_millionths, 42);
    }

    #[test]
    fn size_bounds_zero_truncates_everything() {
        let candidates: Vec<CandidateAction> = (0..5)
            .map(|i| CandidateAction::new(format!("a-{i}"), i))
            .collect();
        let mut entry = make_entry_with(candidates, vec![], vec![]);
        let bounds = SizeBounds {
            max_candidates: 0,
            max_witnesses: 0,
            max_constraints: 0,
        };
        let result = normalize_entry(&mut entry, &bounds);
        assert_eq!(result.truncations.len(), 1);
        assert!(entry.candidates.is_empty());
    }

    #[test]
    fn normalization_result_debug_impl() {
        let result = NormalizationResult {
            truncations: vec![],
            duplicates_removed: 0,
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("NormalizationResult"));
    }

    #[test]
    fn truncation_marker_serde_roundtrip() {
        let marker = TruncationMarker {
            list_name: "candidates".to_string(),
            original_count: 100,
            retained_count: 64,
            policy: "top-K".to_string(),
        };
        let json = serde_json::to_string(&marker).unwrap();
        let restored: TruncationMarker = serde_json::from_str(&json).unwrap();
        assert_eq!(marker, restored);
    }

    // ── Enrichment batch 3: Clone independence ────────────────────────

    #[test]
    fn size_bounds_clone_independence() {
        let original = SizeBounds {
            max_candidates: 10,
            max_witnesses: 20,
            max_constraints: 5,
        };
        let mut cloned = original.clone();
        cloned.max_candidates = 999;
        cloned.max_witnesses = 888;
        cloned.max_constraints = 777;
        assert_eq!(cloned.max_candidates, 999);
        assert_eq!(cloned.max_witnesses, 888);
        assert_eq!(cloned.max_constraints, 777);
        assert_eq!(original.max_candidates, 10);
        assert_eq!(original.max_witnesses, 20);
        assert_eq!(original.max_constraints, 5);
    }

    #[test]
    fn truncation_marker_clone_independence() {
        let original = TruncationMarker {
            list_name: "candidates".to_string(),
            original_count: 100,
            retained_count: 64,
            policy: "top-K".to_string(),
        };
        let mut cloned = original.clone();
        cloned.list_name = "witnesses".to_string();
        cloned.original_count = 999;
        assert_eq!(cloned.list_name, "witnesses");
        assert_eq!(cloned.original_count, 999);
        assert_eq!(original.list_name, "candidates");
        assert_eq!(original.original_count, 100);
    }

    #[test]
    fn ordering_violation_clone_independence() {
        let original = OrderingViolation::DuplicateWitnessId {
            witness_id: "obs-1".to_string(),
        };
        let cloned = original.clone();
        // Verify both are equal but independent allocations
        assert_eq!(original, cloned);
        if let OrderingViolation::DuplicateWitnessId { witness_id } = &original {
            assert_eq!(witness_id, "obs-1");
        }
    }

    #[test]
    fn normalization_result_clone_independence() {
        let original = NormalizationResult {
            truncations: vec![TruncationMarker {
                list_name: "witnesses".to_string(),
                original_count: 500,
                retained_count: 256,
                policy: "top-K by witness_id".to_string(),
            }],
            duplicates_removed: 5,
        };
        let mut cloned = original.clone();
        cloned.duplicates_removed = 999;
        cloned.truncations.clear();
        assert_eq!(cloned.duplicates_removed, 999);
        assert!(cloned.truncations.is_empty());
        assert_eq!(original.duplicates_removed, 5);
        assert_eq!(original.truncations.len(), 1);
    }

    // ── Enrichment batch 3: Debug distinctness ────────────────────────

    #[test]
    fn ordering_violation_debug_all_variants_distinct() {
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
                witness_id: "w".to_string(),
            },
            OrderingViolation::CandidatesExceedBound { count: 1, max: 0 },
            OrderingViolation::WitnessesExceedBound { count: 1, max: 0 },
            OrderingViolation::ConstraintsExceedBound { count: 1, max: 0 },
        ];
        let mut debugs = std::collections::BTreeSet::new();
        for v in &variants {
            let d = format!("{v:?}");
            assert!(!d.is_empty());
            debugs.insert(d);
        }
        assert_eq!(
            debugs.len(),
            7,
            "all 7 variants produce distinct Debug output"
        );
    }

    #[test]
    fn size_bounds_debug_contains_field_names() {
        let bounds = SizeBounds::default();
        let d = format!("{bounds:?}");
        assert!(d.contains("max_candidates"));
        assert!(d.contains("max_witnesses"));
        assert!(d.contains("max_constraints"));
    }

    #[test]
    fn truncation_marker_debug_contains_fields() {
        let marker = TruncationMarker {
            list_name: "test".to_string(),
            original_count: 10,
            retained_count: 5,
            policy: "pol".to_string(),
        };
        let d = format!("{marker:?}");
        assert!(d.contains("TruncationMarker"));
        assert!(d.contains("list_name"));
        assert!(d.contains("original_count"));
        assert!(d.contains("retained_count"));
        assert!(d.contains("policy"));
    }

    // ── Enrichment batch 3: Serde variant distinctness ────────────────

    #[test]
    fn ordering_violation_serde_all_variants_distinct_json() {
        let variants: Vec<OrderingViolation> = vec![
            OrderingViolation::CandidatesNotSorted {
                first_unsorted_index: 1,
            },
            OrderingViolation::WitnessesNotSorted {
                first_unsorted_index: 1,
            },
            OrderingViolation::ConstraintsNotSorted {
                first_unsorted_index: 1,
            },
            OrderingViolation::DuplicateWitnessId {
                witness_id: "x".to_string(),
            },
            OrderingViolation::CandidatesExceedBound { count: 5, max: 3 },
            OrderingViolation::WitnessesExceedBound { count: 5, max: 3 },
            OrderingViolation::ConstraintsExceedBound { count: 5, max: 3 },
        ];
        let mut jsons = std::collections::BTreeSet::new();
        for v in &variants {
            let j = serde_json::to_string(v).unwrap();
            jsons.insert(j);
        }
        assert_eq!(jsons.len(), 7, "all 7 variants serialize to distinct JSON");
    }

    // ── Enrichment batch 3: JSON field-name stability ─────────────────

    #[test]
    fn size_bounds_json_field_names_stable() {
        let bounds = SizeBounds {
            max_candidates: 10,
            max_witnesses: 20,
            max_constraints: 5,
        };
        let json = serde_json::to_string(&bounds).unwrap();
        assert!(json.contains("\"max_candidates\""));
        assert!(json.contains("\"max_witnesses\""));
        assert!(json.contains("\"max_constraints\""));
    }

    #[test]
    fn truncation_marker_json_field_names_stable() {
        let marker = TruncationMarker {
            list_name: "candidates".to_string(),
            original_count: 100,
            retained_count: 64,
            policy: "top-K".to_string(),
        };
        let json = serde_json::to_string(&marker).unwrap();
        assert!(json.contains("\"list_name\""));
        assert!(json.contains("\"original_count\""));
        assert!(json.contains("\"retained_count\""));
        assert!(json.contains("\"policy\""));
    }

    #[test]
    fn ordering_violation_candidates_not_sorted_json_field_name() {
        let v = OrderingViolation::CandidatesNotSorted {
            first_unsorted_index: 7,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"CandidatesNotSorted\""));
        assert!(json.contains("\"first_unsorted_index\""));
        assert!(json.contains("7"));
    }

    #[test]
    fn ordering_violation_duplicate_witness_json_field_name() {
        let v = OrderingViolation::DuplicateWitnessId {
            witness_id: "w-dup-42".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"DuplicateWitnessId\""));
        assert!(json.contains("\"witness_id\""));
        assert!(json.contains("w-dup-42"));
    }

    #[test]
    fn ordering_violation_exceed_bound_json_field_names() {
        let v = OrderingViolation::CandidatesExceedBound {
            count: 200,
            max: 64,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"CandidatesExceedBound\""));
        assert!(json.contains("\"count\""));
        assert!(json.contains("\"max\""));
        assert!(json.contains("200"));
        assert!(json.contains("64"));
    }

    // ── Enrichment batch 3: Display format checks ─────────────────────

    #[test]
    fn truncation_marker_display_format_exact() {
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
    fn ordering_violation_display_witnesses_not_sorted() {
        let v = OrderingViolation::WitnessesNotSorted {
            first_unsorted_index: 5,
        };
        assert_eq!(v.to_string(), "witnesses not sorted at index 5");
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
    fn ordering_violation_display_candidates_exceed() {
        let v = OrderingViolation::CandidatesExceedBound {
            count: 100,
            max: 64,
        };
        assert_eq!(v.to_string(), "candidates exceed bound: 100 > 64");
    }

    #[test]
    fn ordering_violation_display_witnesses_exceed() {
        let v = OrderingViolation::WitnessesExceedBound {
            count: 300,
            max: 256,
        };
        assert_eq!(v.to_string(), "witnesses exceed bound: 300 > 256");
    }

    #[test]
    fn ordering_violation_display_constraints_exceed() {
        let v = OrderingViolation::ConstraintsExceedBound { count: 50, max: 32 };
        assert_eq!(v.to_string(), "constraints exceed bound: 50 > 32");
    }

    // ── Enrichment batch 3: Hash consistency ──────────────────────────

    #[test]
    fn size_bounds_hash_not_available_but_eq_consistent() {
        // SizeBounds derives Eq but not Hash. Verify Eq consistency.
        let a = SizeBounds {
            max_candidates: 64,
            max_witnesses: 256,
            max_constraints: 32,
        };
        let b = SizeBounds {
            max_candidates: 64,
            max_witnesses: 256,
            max_constraints: 32,
        };
        assert_eq!(a, b);
        let c = SizeBounds {
            max_candidates: 1,
            max_witnesses: 256,
            max_constraints: 32,
        };
        assert_ne!(a, c);
    }

    #[test]
    fn truncation_marker_eq_consistency() {
        let a = TruncationMarker {
            list_name: "candidates".to_string(),
            original_count: 100,
            retained_count: 64,
            policy: "top-K".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
        let c = TruncationMarker {
            list_name: "witnesses".to_string(),
            original_count: 100,
            retained_count: 64,
            policy: "top-K".to_string(),
        };
        assert_ne!(a, c);
    }

    #[test]
    fn ordering_violation_eq_same_variant_same_data() {
        let a = OrderingViolation::CandidatesNotSorted {
            first_unsorted_index: 3,
        };
        let b = OrderingViolation::CandidatesNotSorted {
            first_unsorted_index: 3,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn ordering_violation_ne_same_variant_different_data() {
        let a = OrderingViolation::CandidatesNotSorted {
            first_unsorted_index: 3,
        };
        let b = OrderingViolation::CandidatesNotSorted {
            first_unsorted_index: 5,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn ordering_violation_ne_different_variants() {
        let a = OrderingViolation::CandidatesNotSorted {
            first_unsorted_index: 1,
        };
        let b = OrderingViolation::WitnessesNotSorted {
            first_unsorted_index: 1,
        };
        assert_ne!(a, b);
    }

    // ── Enrichment batch 3: Boundary / edge cases ─────────────────────

    #[test]
    fn sort_candidates_with_i64_min_and_max_loss() {
        let mut candidates = vec![
            CandidateAction::new("action", i64::MAX),
            CandidateAction::new("action", i64::MIN),
            CandidateAction::new("action", 0),
        ];
        sort_candidates(&mut candidates);
        assert_eq!(candidates[0].expected_loss_millionths, i64::MIN);
        assert_eq!(candidates[1].expected_loss_millionths, 0);
        assert_eq!(candidates[2].expected_loss_millionths, i64::MAX);
    }

    #[test]
    fn normalize_entry_with_all_empty_lists() {
        let mut entry = make_entry_with(vec![], vec![], vec![]);
        let result = normalize_entry(&mut entry, &SizeBounds::default());
        assert!(result.truncations.is_empty());
        assert_eq!(result.duplicates_removed, 0);
        assert!(validate_entry_ordering(&entry, &SizeBounds::default()).is_ok());
    }

    #[test]
    fn size_bounds_max_usize_values() {
        let bounds = SizeBounds {
            max_candidates: usize::MAX,
            max_witnesses: usize::MAX,
            max_constraints: usize::MAX,
        };
        let json = serde_json::to_string(&bounds).unwrap();
        let restored: SizeBounds = serde_json::from_str(&json).unwrap();
        assert_eq!(bounds, restored);
    }

    #[test]
    fn truncation_marker_empty_strings() {
        let marker = TruncationMarker {
            list_name: String::new(),
            original_count: 0,
            retained_count: 0,
            policy: String::new(),
        };
        let json = serde_json::to_string(&marker).unwrap();
        let restored: TruncationMarker = serde_json::from_str(&json).unwrap();
        assert_eq!(marker, restored);
        // Display still works
        let display = marker.to_string();
        assert_eq!(display, ": 0 -> 0 ()");
    }

    #[test]
    fn sort_witnesses_single_element() {
        let mut witnesses = vec![Witness {
            witness_id: "only".to_string(),
            witness_type: "t".to_string(),
            value: "v".to_string(),
        }];
        sort_witnesses(&mut witnesses);
        assert_eq!(witnesses.len(), 1);
        assert_eq!(witnesses[0].witness_id, "only");
    }

    #[test]
    fn sort_constraints_single_element() {
        let mut constraints = vec![Constraint {
            constraint_id: "only".to_string(),
            description: "d".to_string(),
            active: true,
        }];
        sort_constraints(&mut constraints);
        assert_eq!(constraints.len(), 1);
        assert_eq!(constraints[0].constraint_id, "only");
    }

    #[test]
    fn validate_many_violations_simultaneously() {
        // Build entry with: unsorted candidates, unsorted witnesses,
        // unsorted constraints, exceed all bounds, and duplicate witness
        let entry = make_entry_with(
            vec![
                CandidateAction::new("z", 1),
                CandidateAction::new("a", 2),
                CandidateAction::new("m", 3),
                CandidateAction::new("b", 4),
            ],
            vec![
                Witness {
                    witness_id: "z".to_string(),
                    witness_type: "t".to_string(),
                    value: "v".to_string(),
                },
                Witness {
                    witness_id: "a".to_string(),
                    witness_type: "t".to_string(),
                    value: "v".to_string(),
                },
                Witness {
                    witness_id: "a".to_string(),
                    witness_type: "t".to_string(),
                    value: "v2".to_string(),
                },
            ],
            vec![
                Constraint {
                    constraint_id: "z-rule".to_string(),
                    description: "d".to_string(),
                    active: true,
                },
                Constraint {
                    constraint_id: "a-rule".to_string(),
                    description: "d".to_string(),
                    active: false,
                },
            ],
        );
        let bounds = SizeBounds {
            max_candidates: 1,
            max_witnesses: 1,
            max_constraints: 1,
        };
        let errors = validate_entry_ordering(&entry, &bounds).unwrap_err();
        // Should have violations for: candidates unsorted, witnesses unsorted,
        // duplicate witness, constraints unsorted, candidates exceed, witnesses exceed,
        // constraints exceed
        assert!(errors.len() >= 5);
    }

    #[test]
    fn candidates_sort_key_lexicographic_order() {
        let mut candidates = vec![
            CandidateAction::new("aab", 100),
            CandidateAction::new("aaa", 200),
            CandidateAction::new("aac", 50),
        ];
        sort_candidates(&mut candidates);
        assert_eq!(candidates[0].action_name, "aaa");
        assert_eq!(candidates[1].action_name, "aab");
        assert_eq!(candidates[2].action_name, "aac");
    }

    #[test]
    fn dedup_witnesses_preserves_order_of_unique() {
        let mut witnesses = vec![
            Witness {
                witness_id: "c".to_string(),
                witness_type: "t".to_string(),
                value: "1".to_string(),
            },
            Witness {
                witness_id: "a".to_string(),
                witness_type: "t".to_string(),
                value: "2".to_string(),
            },
            Witness {
                witness_id: "c".to_string(),
                witness_type: "t".to_string(),
                value: "3".to_string(),
            },
            Witness {
                witness_id: "b".to_string(),
                witness_type: "t".to_string(),
                value: "4".to_string(),
            },
        ];
        dedup_witnesses(&mut witnesses);
        assert_eq!(witnesses.len(), 3);
        // Order preserved: c, a, b (first occurrence of c kept)
        assert_eq!(witnesses[0].witness_id, "c");
        assert_eq!(witnesses[0].value, "1");
        assert_eq!(witnesses[1].witness_id, "a");
        assert_eq!(witnesses[2].witness_id, "b");
    }

    // ── Enrichment batch 3: Serde roundtrips (complex structs) ────────

    #[test]
    fn size_bounds_serde_roundtrip_minimal_values() {
        let bounds = SizeBounds {
            max_candidates: 0,
            max_witnesses: 0,
            max_constraints: 0,
        };
        let json = serde_json::to_string(&bounds).unwrap();
        let restored: SizeBounds = serde_json::from_str(&json).unwrap();
        assert_eq!(bounds, restored);
    }

    #[test]
    fn truncation_marker_serde_roundtrip_unicode_strings() {
        let marker = TruncationMarker {
            list_name: "candidates\u{1F600}".to_string(),
            original_count: 100,
            retained_count: 64,
            policy: "top-K \u{2603}".to_string(),
        };
        let json = serde_json::to_string(&marker).unwrap();
        let restored: TruncationMarker = serde_json::from_str(&json).unwrap();
        assert_eq!(marker, restored);
    }

    #[test]
    fn ordering_violation_serde_roundtrip_zero_index() {
        let v = OrderingViolation::CandidatesNotSorted {
            first_unsorted_index: 0,
        };
        let json = serde_json::to_string(&v).unwrap();
        let restored: OrderingViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }

    #[test]
    fn ordering_violation_serde_roundtrip_large_index() {
        let v = OrderingViolation::WitnessesNotSorted {
            first_unsorted_index: usize::MAX,
        };
        let json = serde_json::to_string(&v).unwrap();
        let restored: OrderingViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }

    #[test]
    fn ordering_violation_serde_roundtrip_empty_witness_id() {
        let v = OrderingViolation::DuplicateWitnessId {
            witness_id: String::new(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let restored: OrderingViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }

    #[test]
    fn ordering_violation_serde_roundtrip_exceed_bound_equal_count_max() {
        // count == max technically not a violation, but the struct allows it
        let v = OrderingViolation::ConstraintsExceedBound { count: 32, max: 32 };
        let json = serde_json::to_string(&v).unwrap();
        let restored: OrderingViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }

    // ── Enrichment batch 3: Normalize pipeline edge cases ─────────────

    #[test]
    fn normalize_dedup_before_truncation_reduces_below_bound() {
        // 10 witnesses, 5 are duplicates. After dedup = 5, bound = 7 -> no truncation
        let witnesses: Vec<Witness> = (0..5)
            .flat_map(|i| {
                vec![
                    Witness {
                        witness_id: format!("w-{i:03}"),
                        witness_type: "t".to_string(),
                        value: "a".to_string(),
                    },
                    Witness {
                        witness_id: format!("w-{i:03}"),
                        witness_type: "t".to_string(),
                        value: "b".to_string(),
                    },
                ]
            })
            .collect();
        let mut entry = make_entry_with(vec![], witnesses, vec![]);
        let bounds = SizeBounds {
            max_candidates: 64,
            max_witnesses: 7,
            max_constraints: 32,
        };
        let result = normalize_entry(&mut entry, &bounds);
        assert_eq!(result.duplicates_removed, 5);
        assert!(
            result.truncations.is_empty(),
            "dedup brought count below bound, so no truncation"
        );
        assert_eq!(entry.witnesses.len(), 5);
    }

    #[test]
    fn normalize_preserves_filtered_candidates() {
        let mut entry = make_entry_with(
            vec![
                CandidateAction::filtered("z-action", 100, "blocked"),
                CandidateAction::new("a-action", 200),
                CandidateAction::filtered("m-action", 50, "cost cap"),
            ],
            vec![],
            vec![],
        );
        normalize_entry(&mut entry, &SizeBounds::default());
        // All three preserved with correct ordering
        assert_eq!(entry.candidates.len(), 3);
        assert_eq!(entry.candidates[0].action_name, "a-action");
        assert!(!entry.candidates[0].filtered);
        assert_eq!(entry.candidates[1].action_name, "m-action");
        assert!(entry.candidates[1].filtered);
        assert_eq!(
            entry.candidates[1].filter_reason.as_deref(),
            Some("cost cap")
        );
    }

    #[test]
    fn normalize_constraints_sorted_and_active_flag_preserved() {
        let mut entry = make_entry_with(
            vec![],
            vec![],
            vec![
                Constraint {
                    constraint_id: "z-rule".to_string(),
                    description: "desc-z".to_string(),
                    active: false,
                },
                Constraint {
                    constraint_id: "a-rule".to_string(),
                    description: "desc-a".to_string(),
                    active: true,
                },
                Constraint {
                    constraint_id: "m-rule".to_string(),
                    description: "desc-m".to_string(),
                    active: false,
                },
            ],
        );
        normalize_entry(&mut entry, &SizeBounds::default());
        assert_eq!(entry.constraints[0].constraint_id, "a-rule");
        assert!(entry.constraints[0].active);
        assert_eq!(entry.constraints[1].constraint_id, "m-rule");
        assert!(!entry.constraints[1].active);
        assert_eq!(entry.constraints[2].constraint_id, "z-rule");
        assert!(!entry.constraints[2].active);
    }

    #[test]
    fn normalized_entry_serializes_deterministically() {
        // Build two entries with same data in different orders
        let mut entry_a = make_entry_with(
            vec![
                CandidateAction::new("beta", 200),
                CandidateAction::new("alpha", 100),
            ],
            vec![
                Witness {
                    witness_id: "w-2".to_string(),
                    witness_type: "t".to_string(),
                    value: "v2".to_string(),
                },
                Witness {
                    witness_id: "w-1".to_string(),
                    witness_type: "t".to_string(),
                    value: "v1".to_string(),
                },
            ],
            vec![
                Constraint {
                    constraint_id: "c-2".to_string(),
                    description: "d".to_string(),
                    active: true,
                },
                Constraint {
                    constraint_id: "c-1".to_string(),
                    description: "d".to_string(),
                    active: true,
                },
            ],
        );
        let mut entry_b = make_entry_with(
            vec![
                CandidateAction::new("alpha", 100),
                CandidateAction::new("beta", 200),
            ],
            vec![
                Witness {
                    witness_id: "w-1".to_string(),
                    witness_type: "t".to_string(),
                    value: "v1".to_string(),
                },
                Witness {
                    witness_id: "w-2".to_string(),
                    witness_type: "t".to_string(),
                    value: "v2".to_string(),
                },
            ],
            vec![
                Constraint {
                    constraint_id: "c-1".to_string(),
                    description: "d".to_string(),
                    active: true,
                },
                Constraint {
                    constraint_id: "c-2".to_string(),
                    description: "d".to_string(),
                    active: true,
                },
            ],
        );
        let bounds = SizeBounds::default();
        normalize_entry(&mut entry_a, &bounds);
        normalize_entry(&mut entry_b, &bounds);

        // After normalization, candidates/witnesses/constraints are in same order
        let json_a = serde_json::to_string(&entry_a.candidates).unwrap();
        let json_b = serde_json::to_string(&entry_b.candidates).unwrap();
        assert_eq!(json_a, json_b, "candidates should be deterministic");

        let json_a = serde_json::to_string(&entry_a.witnesses).unwrap();
        let json_b = serde_json::to_string(&entry_b.witnesses).unwrap();
        assert_eq!(json_a, json_b, "witnesses should be deterministic");

        let json_a = serde_json::to_string(&entry_a.constraints).unwrap();
        let json_b = serde_json::to_string(&entry_b.constraints).unwrap();
        assert_eq!(json_a, json_b, "constraints should be deterministic");
    }

    // ── Enrichment batch 3: Validation edge cases ─────────────────────

    #[test]
    fn validate_sorted_candidates_different_names_passes() {
        let entry = make_entry_with(
            vec![
                CandidateAction::new("alpha", 9999),
                CandidateAction::new("beta", 1),
                CandidateAction::new("gamma", 5000),
            ],
            vec![],
            vec![],
        );
        // Names are sorted even though loss values are not ascending
        assert!(validate_entry_ordering(&entry, &SizeBounds::default()).is_ok());
    }

    #[test]
    fn validate_sorted_candidates_same_name_ascending_loss() {
        let entry = make_entry_with(
            vec![
                CandidateAction::new("same", 100),
                CandidateAction::new("same", 200),
                CandidateAction::new("same", 300),
            ],
            vec![],
            vec![],
        );
        assert!(validate_entry_ordering(&entry, &SizeBounds::default()).is_ok());
    }

    #[test]
    fn validate_sorted_candidates_same_name_descending_loss_fails() {
        let entry = make_entry_with(
            vec![
                CandidateAction::new("same", 300),
                CandidateAction::new("same", 100),
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
    fn validate_two_constraints_sorted_passes() {
        let entry = make_entry_with(
            vec![],
            vec![],
            vec![
                Constraint {
                    constraint_id: "a-rule".to_string(),
                    description: "d".to_string(),
                    active: true,
                },
                Constraint {
                    constraint_id: "b-rule".to_string(),
                    description: "d".to_string(),
                    active: false,
                },
            ],
        );
        assert!(validate_entry_ordering(&entry, &SizeBounds::default()).is_ok());
    }

    #[test]
    fn validate_bound_one_less_than_count_fails() {
        let entry = make_entry_with(
            vec![CandidateAction::new("a", 1), CandidateAction::new("b", 2)],
            vec![],
            vec![],
        );
        let bounds = SizeBounds {
            max_candidates: 1,
            max_witnesses: 256,
            max_constraints: 32,
        };
        let errors = validate_entry_ordering(&entry, &bounds).unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            OrderingViolation::CandidatesExceedBound { count: 2, max: 1 }
        )));
    }

    // ── Enrichment batch 3: Display/Error interplay ───────────────────

    #[test]
    fn ordering_violation_error_source_is_none_all_variants() {
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
                witness_id: "w".to_string(),
            },
            OrderingViolation::CandidatesExceedBound { count: 1, max: 0 },
            OrderingViolation::WitnessesExceedBound { count: 1, max: 0 },
            OrderingViolation::ConstraintsExceedBound { count: 1, max: 0 },
        ];
        for v in &variants {
            let err: &dyn std::error::Error = v;
            assert!(err.source().is_none());
        }
    }

    #[test]
    fn ordering_violation_display_matches_error_display() {
        let v = OrderingViolation::DuplicateWitnessId {
            witness_id: "obs-99".to_string(),
        };
        let display_str = format!("{v}");
        let err: &dyn std::error::Error = &v;
        let err_str = format!("{err}");
        assert_eq!(display_str, err_str);
    }

    #[test]
    fn truncation_marker_display_zero_counts() {
        let marker = TruncationMarker {
            list_name: "empty".to_string(),
            original_count: 0,
            retained_count: 0,
            policy: "none".to_string(),
        };
        assert_eq!(marker.to_string(), "empty: 0 -> 0 (none)");
    }

    #[test]
    fn truncation_marker_display_large_counts() {
        let marker = TruncationMarker {
            list_name: "witnesses".to_string(),
            original_count: 1_000_000,
            retained_count: 256,
            policy: "top-K by witness_id".to_string(),
        };
        let display = marker.to_string();
        assert!(display.contains("1000000"));
        assert!(display.contains("256"));
    }

    // ── Enrichment batch 3: Candidate filtered edge cases ─────────────

    #[test]
    fn filtered_candidate_serde_roundtrip() {
        let c = CandidateAction::filtered("terminate", 500_000, "policy-block");
        let json = serde_json::to_string(&c).unwrap();
        let restored: CandidateAction = serde_json::from_str(&json).unwrap();
        assert_eq!(c, restored);
        assert!(restored.filtered);
        assert_eq!(restored.filter_reason.as_deref(), Some("policy-block"));
    }

    #[test]
    fn sort_candidates_mixed_filtered_and_unfiltered() {
        let mut candidates = vec![
            CandidateAction::filtered("z-action", 100, "reason"),
            CandidateAction::new("a-action", 200),
            CandidateAction::new("z-action", 50),
        ];
        sort_candidates(&mut candidates);
        // a-action first, then z-action sorted by loss (50, 100)
        assert_eq!(candidates[0].action_name, "a-action");
        assert_eq!(candidates[1].action_name, "z-action");
        assert_eq!(candidates[1].expected_loss_millionths, 50);
        assert!(!candidates[1].filtered);
        assert_eq!(candidates[2].action_name, "z-action");
        assert_eq!(candidates[2].expected_loss_millionths, 100);
        assert!(candidates[2].filtered);
    }

    // ── Enrichment batch 3: Normalization result detail checks ────────

    #[test]
    fn normalize_result_zero_duplicates_when_all_unique() {
        let witnesses: Vec<Witness> = (0..5)
            .map(|i| Witness {
                witness_id: format!("w-{i}"),
                witness_type: "t".to_string(),
                value: format!("{i}"),
            })
            .collect();
        let mut entry = make_entry_with(vec![], witnesses, vec![]);
        let result = normalize_entry(&mut entry, &SizeBounds::default());
        assert_eq!(result.duplicates_removed, 0);
    }

    #[test]
    fn normalize_result_truncation_markers_have_correct_policy_strings() {
        let candidates: Vec<CandidateAction> = (0..10)
            .map(|i| CandidateAction::new(format!("a-{i}"), i))
            .collect();
        let witnesses: Vec<Witness> = (0..10)
            .map(|i| Witness {
                witness_id: format!("w-{i}"),
                witness_type: "t".to_string(),
                value: format!("{i}"),
            })
            .collect();
        let constraints: Vec<Constraint> = (0..10)
            .map(|i| Constraint {
                constraint_id: format!("c-{i}"),
                description: "d".to_string(),
                active: true,
            })
            .collect();
        let mut entry = make_entry_with(candidates, witnesses, constraints);
        let bounds = SizeBounds {
            max_candidates: 2,
            max_witnesses: 2,
            max_constraints: 2,
        };
        let result = normalize_entry(&mut entry, &bounds);
        assert_eq!(result.truncations.len(), 3);
        assert_eq!(result.truncations[0].policy, "top-K by action_name");
        assert_eq!(result.truncations[1].policy, "top-K by witness_id");
        assert_eq!(result.truncations[2].policy, "top-K by constraint_id");
    }

    #[test]
    fn normalization_result_clone_eq() {
        let a = NormalizationResult {
            truncations: vec![TruncationMarker {
                list_name: "x".to_string(),
                original_count: 10,
                retained_count: 5,
                policy: "p".to_string(),
            }],
            duplicates_removed: 3,
        };
        let b = a.clone();
        assert_eq!(a.duplicates_removed, b.duplicates_removed);
        assert_eq!(a.truncations.len(), b.truncations.len());
        assert_eq!(a.truncations[0], b.truncations[0]);
    }

    // ── Enrichment batch 3: Serialize/deserialize error cases ─────────

    #[test]
    fn size_bounds_deserialize_from_partial_json_fails() {
        let json = r#"{"max_candidates": 10}"#;
        let result = serde_json::from_str::<SizeBounds>(json);
        assert!(result.is_err());
    }

    #[test]
    fn truncation_marker_deserialize_from_empty_object_fails() {
        let json = "{}";
        let result = serde_json::from_str::<TruncationMarker>(json);
        assert!(result.is_err());
    }

    #[test]
    fn ordering_violation_deserialize_from_invalid_variant_fails() {
        let json = r#"{"NonExistentVariant": {}}"#;
        let result = serde_json::from_str::<OrderingViolation>(json);
        assert!(result.is_err());
    }

    #[test]
    fn size_bounds_pretty_json_roundtrip() {
        let bounds = SizeBounds {
            max_candidates: 64,
            max_witnesses: 256,
            max_constraints: 32,
        };
        let json = serde_json::to_string_pretty(&bounds).unwrap();
        let restored: SizeBounds = serde_json::from_str(&json).unwrap();
        assert_eq!(bounds, restored);
    }
}
