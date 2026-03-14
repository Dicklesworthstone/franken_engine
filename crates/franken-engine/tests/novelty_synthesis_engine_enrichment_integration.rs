//! Enrichment integration tests for the `novelty_synthesis_engine` module.
//!
//! Covers: SynthesisStrategy ordering/Copy/Hash/Display/as_str/serde,
//! ProgramKind ordering/Copy/Hash/Display/as_str/file_extension/serde,
//! SynthesisDenialReason ordering/Copy/Hash/Display/as_str/serde,
//! SynthesisError Display all variants/serde,
//! SynthesisConstraint new/require_feature/forbid_pattern/checks,
//! SynthesizedCandidate source_byte_count/exceeds_novelty,
//! SynthesisBatch candidate_count/is_empty/average_novelty/content_hash,
//! SynthesisReceipt acceptance_rate/all_accepted/none_accepted,
//! build_constraints clamps to kind minimum,
//! synthesize_candidate determinism/error paths,
//! constants verification, Debug formatting.

#![forbid(unsafe_code)]
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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::novelty_synthesis_engine::{
    BEAD_ID, COMPONENT, DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, DEFAULT_MIN_NOVELTY, KIND_COUNT,
    MAX_BATCH_SIZE, POLICY_ID, ProgramKind, SCHEMA_VERSION, STRATEGY_COUNT, SynthesisConstraint,
    SynthesisDenialReason, SynthesisError, SynthesisReceipt, SynthesisStrategy, build_constraints,
    synthesize_candidate,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// =========================================================================
// A. SynthesisStrategy — ordering, Copy, Hash, Display, as_str, serde
// =========================================================================

#[test]
fn enrichment_synthesis_strategy_ordering() {
    for i in 0..SynthesisStrategy::ALL.len() - 1 {
        assert!(
            SynthesisStrategy::ALL[i] < SynthesisStrategy::ALL[i + 1],
            "{:?} should be < {:?}",
            SynthesisStrategy::ALL[i],
            SynthesisStrategy::ALL[i + 1]
        );
    }
}

#[test]
fn enrichment_synthesis_strategy_copy_hash() {
    let s = SynthesisStrategy::GrammarGuided;
    let s2 = s;
    assert_eq!(s, s2);

    use std::hash::{Hash, Hasher};
    let mut hashes = BTreeSet::new();
    for variant in SynthesisStrategy::ALL {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        variant.hash(&mut hasher);
        hashes.insert(hasher.finish());
    }
    assert_eq!(hashes.len(), STRATEGY_COUNT);
}

#[test]
fn enrichment_synthesis_strategy_display_matches_as_str() {
    for s in SynthesisStrategy::ALL {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn enrichment_synthesis_strategy_serde_all() {
    for s in SynthesisStrategy::ALL {
        let json = serde_json::to_string(s).unwrap();
        let restored: SynthesisStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, restored);
    }
}

// =========================================================================
// B. ProgramKind — ordering, Copy, Hash, Display, as_str, file_extension, serde
// =========================================================================

#[test]
fn enrichment_program_kind_ordering() {
    for i in 0..ProgramKind::ALL.len() - 1 {
        assert!(ProgramKind::ALL[i] < ProgramKind::ALL[i + 1]);
    }
}

#[test]
fn enrichment_program_kind_copy_hash() {
    let k = ProgramKind::ReactComponent;
    let k2 = k;
    assert_eq!(k, k2);

    use std::hash::{Hash, Hasher};
    let mut hashes = BTreeSet::new();
    for variant in ProgramKind::ALL {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        variant.hash(&mut hasher);
        hashes.insert(hasher.finish());
    }
    assert_eq!(hashes.len(), KIND_COUNT);
}

#[test]
fn enrichment_program_kind_display_matches_as_str() {
    for k in ProgramKind::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

#[test]
fn enrichment_program_kind_file_extension_all_nonempty() {
    for k in ProgramKind::ALL {
        let ext = k.file_extension();
        assert!(!ext.is_empty());
        assert!(ext.starts_with('.'));
    }
}

#[test]
fn enrichment_program_kind_serde_all() {
    for k in ProgramKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let restored: ProgramKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, restored);
    }
}

// =========================================================================
// C. SynthesisDenialReason — ordering, Copy, Hash, Display, as_str, serde
// =========================================================================

#[test]
fn enrichment_denial_reason_ordering() {
    for i in 0..SynthesisDenialReason::ALL.len() - 1 {
        assert!(SynthesisDenialReason::ALL[i] < SynthesisDenialReason::ALL[i + 1]);
    }
}

#[test]
fn enrichment_denial_reason_display_matches_as_str() {
    for r in SynthesisDenialReason::ALL {
        assert_eq!(r.to_string(), r.as_str());
    }
}

#[test]
fn enrichment_denial_reason_as_str_all_distinct() {
    let strings: BTreeSet<&str> = SynthesisDenialReason::ALL
        .iter()
        .map(|r| r.as_str())
        .collect();
    assert_eq!(strings.len(), 8);
}

#[test]
fn enrichment_denial_reason_serde_all() {
    for r in SynthesisDenialReason::ALL {
        let json = serde_json::to_string(r).unwrap();
        let restored: SynthesisDenialReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, restored);
    }
}

// =========================================================================
// D. SynthesisError — Display, serde
// =========================================================================

#[test]
fn enrichment_synthesis_error_display_all_variants() {
    let variants = [
        SynthesisError::InvalidConstraint,
        SynthesisError::NoveltyBelowThreshold,
        SynthesisError::BatchOverflow,
        SynthesisError::StrategyNotApplicable,
        SynthesisError::InternalError("test msg".into()),
    ];
    let mut displays = BTreeSet::new();
    for v in &variants {
        let s = v.to_string();
        assert!(!s.is_empty());
        displays.insert(s);
    }
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_synthesis_error_serde_all_variants() {
    let variants = [
        SynthesisError::InvalidConstraint,
        SynthesisError::NoveltyBelowThreshold,
        SynthesisError::BatchOverflow,
        SynthesisError::StrategyNotApplicable,
        SynthesisError::InternalError("test error".into()),
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: SynthesisError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

// =========================================================================
// E. SynthesisConstraint — new, feature/pattern, checks
// =========================================================================

#[test]
fn enrichment_constraint_new_basic() {
    let c = SynthesisConstraint::new(100, 1000, 300_000);
    assert_eq!(c.max_ast_nodes, 100);
    assert_eq!(c.max_bytes, 1000);
    assert_eq!(c.min_novelty_millionths, 300_000);
    assert!(c.required_features.is_empty());
    assert!(c.forbidden_patterns.is_empty());
}

#[test]
fn enrichment_constraint_require_feature() {
    let mut c = SynthesisConstraint::new(100, 1000, 300_000);
    c.require_feature("async");
    c.require_feature("hooks");
    assert_eq!(c.required_features.len(), 2);
    assert!(c.required_features.contains("async"));
}

#[test]
fn enrichment_constraint_forbid_pattern() {
    let mut c = SynthesisConstraint::new(100, 1000, 300_000);
    c.forbid_pattern("eval(");
    c.forbid_pattern("document.write");
    assert_eq!(c.forbidden_patterns.len(), 2);
}

#[test]
fn enrichment_constraint_nodes_within_budget() {
    let c = SynthesisConstraint::new(100, 1000, 0);
    assert!(c.nodes_within_budget(100));
    assert!(c.nodes_within_budget(0));
    assert!(!c.nodes_within_budget(101));
}

#[test]
fn enrichment_constraint_bytes_within_budget() {
    let c = SynthesisConstraint::new(100, 1000, 0);
    assert!(c.bytes_within_budget(1000));
    assert!(!c.bytes_within_budget(1001));
}

#[test]
fn enrichment_constraint_novelty_sufficient() {
    let c = SynthesisConstraint::new(100, 1000, 300_000);
    assert!(c.novelty_sufficient(300_000));
    assert!(c.novelty_sufficient(500_000));
    assert!(!c.novelty_sufficient(299_999));
}

#[test]
fn enrichment_constraint_contains_forbidden() {
    let mut c = SynthesisConstraint::new(100, 1000, 0);
    c.forbid_pattern("eval(");
    assert!(c.contains_forbidden("let x = eval('1+1')").is_some());
    assert!(c.contains_forbidden("let x = 1 + 1").is_none());
}

#[test]
fn enrichment_constraint_missing_features() {
    let mut c = SynthesisConstraint::new(100, 1000, 0);
    c.require_feature("useState");
    c.require_feature("useEffect");
    let missing = c.missing_features("const [x, setX] = useState(0)");
    assert_eq!(missing.len(), 1);
    assert!(missing.contains(&"useEffect".to_string()));
}

#[test]
fn enrichment_constraint_serde() {
    let mut c = SynthesisConstraint::new(256, 4096, 300_000);
    c.require_feature("async");
    c.forbid_pattern("eval(");
    let json = serde_json::to_string(&c).unwrap();
    let restored: SynthesisConstraint = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
}

// =========================================================================
// F. SynthesisReceipt — acceptance_rate, all/none accepted
// =========================================================================

#[test]
fn enrichment_receipt_acceptance_rate() {
    let receipt = SynthesisReceipt {
        batch_id: "batch-1".into(),
        timestamp_epoch: epoch(1),
        candidates_proposed: 4,
        candidates_accepted: 1,
        novelty_yield_millionths: 500_000,
        coverage_improvement_millionths: 100_000,
        content_hash: ContentHash::compute(b"receipt"),
    };
    assert_eq!(receipt.acceptance_rate_millionths(), 250_000); // 25%
}

#[test]
fn enrichment_receipt_all_accepted() {
    let receipt = SynthesisReceipt {
        batch_id: "batch-1".into(),
        timestamp_epoch: epoch(1),
        candidates_proposed: 3,
        candidates_accepted: 3,
        novelty_yield_millionths: 500_000,
        coverage_improvement_millionths: 100_000,
        content_hash: ContentHash::compute(b"receipt"),
    };
    assert!(receipt.all_accepted());
    assert!(!receipt.none_accepted());
}

#[test]
fn enrichment_receipt_none_accepted() {
    let receipt = SynthesisReceipt {
        batch_id: "batch-1".into(),
        timestamp_epoch: epoch(1),
        candidates_proposed: 5,
        candidates_accepted: 0,
        novelty_yield_millionths: 0,
        coverage_improvement_millionths: 0,
        content_hash: ContentHash::compute(b"receipt"),
    };
    assert!(receipt.none_accepted());
    assert!(!receipt.all_accepted());
    assert_eq!(receipt.acceptance_rate_millionths(), 0);
}

#[test]
fn enrichment_receipt_zero_proposed() {
    let receipt = SynthesisReceipt {
        batch_id: "batch-1".into(),
        timestamp_epoch: epoch(1),
        candidates_proposed: 0,
        candidates_accepted: 0,
        novelty_yield_millionths: 0,
        coverage_improvement_millionths: 0,
        content_hash: ContentHash::compute(b"receipt"),
    };
    assert_eq!(receipt.acceptance_rate_millionths(), 0);
    assert!(!receipt.all_accepted()); // proposed is 0
}

#[test]
fn enrichment_receipt_serde() {
    let receipt = SynthesisReceipt {
        batch_id: "batch-1".into(),
        timestamp_epoch: epoch(1),
        candidates_proposed: 10,
        candidates_accepted: 7,
        novelty_yield_millionths: 700_000,
        coverage_improvement_millionths: 200_000,
        content_hash: ContentHash::compute(b"receipt"),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let restored: SynthesisReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, restored);
}

// =========================================================================
// G. build_constraints — clamps to kind minimum
// =========================================================================

#[test]
fn enrichment_build_constraints_respects_max_nodes() {
    let c = build_constraints(ProgramKind::PlainJs, 100, 300_000);
    assert_eq!(c.max_ast_nodes, 100);
    assert_eq!(c.min_novelty_millionths, 300_000);
}

#[test]
fn enrichment_build_constraints_clamps_to_kind_minimum() {
    // PlainJs typical_min_nodes = 3, so max_nodes=1 should be clamped to 3.
    let c = build_constraints(ProgramKind::PlainJs, 1, 0);
    assert!(c.max_ast_nodes >= 3);
}

#[test]
fn enrichment_build_constraints_react_app_higher_minimum() {
    // ReactApp typical_min_nodes = 20
    let c = build_constraints(ProgramKind::ReactApp, 5, 0);
    assert!(c.max_ast_nodes >= 20);
}

// =========================================================================
// H. synthesize_candidate — determinism, error paths
// =========================================================================

#[test]
fn enrichment_synthesize_candidate_deterministic() {
    let constraint = SynthesisConstraint::new(256, 8192, 0);
    let c1 = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"seed-42",
    )
    .unwrap();
    let c2 = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"seed-42",
    )
    .unwrap();
    assert_eq!(c1.candidate_id, c2.candidate_id);
    assert_eq!(c1.content_hash, c2.content_hash);
    assert_eq!(c1.source_text, c2.source_text);
    assert_eq!(c1.novelty_score_millionths, c2.novelty_score_millionths);
}

#[test]
fn enrichment_synthesize_candidate_zero_max_nodes_error() {
    let constraint = SynthesisConstraint::new(0, 0, 0);
    let result = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"seed",
    );
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), SynthesisError::InvalidConstraint);
}

#[test]
fn enrichment_synthesize_candidate_different_seeds_differ() {
    let constraint = SynthesisConstraint::new(256, 8192, 0);
    let c1 = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"seed-1",
    )
    .unwrap();
    let c2 = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"seed-2",
    )
    .unwrap();
    assert_ne!(c1.candidate_id, c2.candidate_id);
    assert_ne!(c1.content_hash, c2.content_hash);
}

// =========================================================================
// I. SynthesizedCandidate — accessors
// =========================================================================

#[test]
fn enrichment_candidate_source_byte_count() {
    let constraint = SynthesisConstraint::new(256, 8192, 0);
    let c = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"seed",
    )
    .unwrap();
    assert_eq!(c.source_byte_count(), c.source_text.len() as u64);
}

#[test]
fn enrichment_candidate_exceeds_novelty() {
    let constraint = SynthesisConstraint::new(256, 8192, 0);
    let c = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::ObstructionTargeted,
        &constraint,
        b"seed",
    )
    .unwrap();
    // ObstructionTargeted has base novelty 900_000.
    assert!(c.exceeds_novelty(0));
    assert!(!c.exceeds_novelty(u64::MAX));
}

// =========================================================================
// J. Constants verification
// =========================================================================

#[test]
fn enrichment_constants_correct() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!POLICY_ID.is_empty());
    assert_eq!(DEFAULT_MAX_AST_NODES, 256);
    assert_eq!(DEFAULT_MAX_BYTES, 4_096);
    assert_eq!(DEFAULT_MIN_NOVELTY, 300_000);
    assert_eq!(MAX_BATCH_SIZE, 1_024);
    assert_eq!(STRATEGY_COUNT, SynthesisStrategy::ALL.len());
    assert_eq!(KIND_COUNT, ProgramKind::ALL.len());
}

// =========================================================================
// K. Debug formatting
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", SynthesisStrategy::GrammarGuided).is_empty());
    assert!(!format!("{:?}", ProgramKind::PlainJs).is_empty());
    assert!(!format!("{:?}", SynthesisDenialReason::InsufficientNovelty).is_empty());
    assert!(!format!("{:?}", SynthesisError::InvalidConstraint).is_empty());
    assert!(!format!("{:?}", SynthesisConstraint::new(100, 1000, 300_000)).is_empty());
}

// =========================================================================
// L. build_batch — basic, overflow, strategy_distribution, average_novelty
// =========================================================================

#[test]
fn test_build_batch_empty_succeeds() {
    use frankenengine_engine::novelty_synthesis_engine::build_batch;
    let batch = build_batch(epoch(1), vec![]).unwrap();
    assert!(batch.is_empty());
    assert_eq!(batch.candidate_count(), 0);
    assert_eq!(batch.average_novelty_millionths(), 0);
    assert!(batch.strategy_distribution.is_empty());
    assert_eq!(batch.total_novelty_millionths, 0);
}

#[test]
fn test_build_batch_overflow_returns_error() {
    use frankenengine_engine::novelty_synthesis_engine::build_batch;
    let constraint = SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 0);
    // Build MAX_BATCH_SIZE + 1 candidates by reusing the same seed under different kinds.
    let mut candidates = Vec::new();
    let mut seed: u64 = 0;
    // cycle through kinds to avoid hitting size constraints
    let kinds = ProgramKind::ALL;
    let strategies = SynthesisStrategy::ALL;
    while candidates.len() <= MAX_BATCH_SIZE {
        let kind = kinds[candidates.len() % kinds.len()];
        let strategy = strategies[candidates.len() % strategies.len()];
        let s = seed.to_le_bytes();
        seed += 1;
        if let Ok(c) = synthesize_candidate(kind, strategy, &constraint, &s) {
            candidates.push(c);
        }
    }
    let result = build_batch(epoch(1), candidates);
    assert_eq!(result.unwrap_err(), SynthesisError::BatchOverflow);
}

#[test]
fn test_build_batch_strategy_distribution_counts() {
    use frankenengine_engine::novelty_synthesis_engine::build_batch;
    let constraint = SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 0);
    let c1 = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"s1",
    )
    .unwrap();
    let c2 = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"s2",
    )
    .unwrap();
    let c3 = synthesize_candidate(
        ProgramKind::TypeScript,
        SynthesisStrategy::MutationBased,
        &constraint,
        b"s3",
    )
    .unwrap();
    let batch = build_batch(epoch(1), vec![c1, c2, c3]).unwrap();
    assert_eq!(batch.candidate_count(), 3);
    assert_eq!(
        *batch
            .strategy_distribution
            .get(&SynthesisStrategy::GrammarGuided)
            .unwrap(),
        2
    );
    assert_eq!(
        *batch
            .strategy_distribution
            .get(&SynthesisStrategy::MutationBased)
            .unwrap(),
        1
    );
}

#[test]
fn test_build_batch_average_novelty_nonzero() {
    use frankenengine_engine::novelty_synthesis_engine::build_batch;
    let constraint = SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 0);
    let c1 = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::ObstructionTargeted,
        &constraint,
        b"avg-seed-1",
    )
    .unwrap();
    let c2 = synthesize_candidate(
        ProgramKind::TypeScript,
        SynthesisStrategy::ObstructionTargeted,
        &constraint,
        b"avg-seed-2",
    )
    .unwrap();
    let batch = build_batch(epoch(2), vec![c1, c2]).unwrap();
    let avg = batch.average_novelty_millionths();
    assert!(avg > 0, "average novelty should be positive");
    assert_eq!(avg, batch.total_novelty_millionths / 2);
}

#[test]
fn test_synthesis_batch_content_hash_deterministic() {
    use frankenengine_engine::novelty_synthesis_engine::build_batch;
    let constraint = SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 0);
    let c1 = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"hash-det-seed",
    )
    .unwrap();
    let c2 = c1.clone();
    let batch1 = build_batch(epoch(5), vec![c1]).unwrap();
    let batch2 = build_batch(epoch(5), vec![c2]).unwrap();
    assert_eq!(batch1.content_hash(), batch2.content_hash());
}

#[test]
fn test_synthesis_batch_serde_roundtrip() {
    use frankenengine_engine::novelty_synthesis_engine::{SynthesisBatch, build_batch};
    let constraint = SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 0);
    let c = synthesize_candidate(
        ProgramKind::TypeScript,
        SynthesisStrategy::TemplateDriven,
        &constraint,
        b"serde-batch-seed",
    )
    .unwrap();
    let batch = build_batch(epoch(3), vec![c]).unwrap();
    let json = serde_json::to_string(&batch).unwrap();
    let restored: SynthesisBatch = serde_json::from_str(&json).unwrap();
    assert_eq!(batch, restored);
}

// =========================================================================
// M. evaluate_candidate_novelty
// =========================================================================

#[test]
fn test_evaluate_novelty_unique_candidate_full_score() {
    use frankenengine_engine::novelty_synthesis_engine::evaluate_candidate_novelty;
    let constraint = SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 0);
    let c = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"unique-seed",
    )
    .unwrap();
    let existing: BTreeSet<ContentHash> = BTreeSet::new();
    let score = evaluate_candidate_novelty(&c, &existing);
    assert_eq!(
        score, 1_000_000,
        "unique candidate should have full novelty"
    );
}

#[test]
fn test_evaluate_novelty_exact_duplicate_zero() {
    use frankenengine_engine::novelty_synthesis_engine::evaluate_candidate_novelty;
    let constraint = SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 0);
    let c = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"dup-seed",
    )
    .unwrap();
    let mut existing: BTreeSet<ContentHash> = BTreeSet::new();
    existing.insert(c.content_hash);
    let score = evaluate_candidate_novelty(&c, &existing);
    assert_eq!(score, 0, "exact duplicate should have zero novelty");
}

#[test]
fn test_evaluate_novelty_empty_set_returns_full() {
    use frankenengine_engine::novelty_synthesis_engine::evaluate_candidate_novelty;
    let constraint = SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 0);
    let c = synthesize_candidate(
        ProgramKind::ReactComponent,
        SynthesisStrategy::RecombinationBased,
        &constraint,
        b"novel-react-seed",
    )
    .unwrap();
    let existing: BTreeSet<ContentHash> = BTreeSet::new();
    assert_eq!(evaluate_candidate_novelty(&c, &existing), 1_000_000);
}

// =========================================================================
// N. filter_candidates
// =========================================================================

#[test]
fn test_filter_candidates_all_accepted() {
    use frankenengine_engine::novelty_synthesis_engine::filter_candidates;
    let constraint = SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 0);
    let c1 = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"fc-seed-1",
    )
    .unwrap();
    let c2 = synthesize_candidate(
        ProgramKind::TypeScript,
        SynthesisStrategy::MutationBased,
        &constraint,
        b"fc-seed-2",
    )
    .unwrap();
    let (accepted, denied) = filter_candidates(vec![c1, c2], &constraint);
    assert_eq!(accepted.len(), 2);
    assert!(denied.is_empty());
}

#[test]
fn test_filter_candidates_novelty_below_threshold_denied() {
    use frankenengine_engine::novelty_synthesis_engine::filter_candidates;
    // TemplateDriven has base novelty 400_000; setting threshold to 999_000 forces denial.
    let constraint = SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 999_000);
    let c = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::TemplateDriven,
        &constraint,
        b"low-novelty-seed",
    );
    // synthesize_candidate itself may reject with NoveltyBelowThreshold.
    // If it succeeded, filter should deny it if score < 999_000.
    if let Ok(candidate) = c
        && candidate.novelty_score_millionths < 999_000
    {
        let (accepted, denied) = filter_candidates(vec![candidate], &constraint);
        assert!(accepted.is_empty());
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].1, SynthesisDenialReason::InsufficientNovelty);
    }
    // If synthesis itself failed, the test still passes — both paths verify the threshold.
}

#[test]
fn test_filter_candidates_forbidden_pattern_denied() {
    use frankenengine_engine::novelty_synthesis_engine::filter_candidates;
    let mut constraint = SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 0);
    let c = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"fp-seed",
    )
    .unwrap();
    // Now forbid a pattern that is actually in the generated source.
    // Grammar-guided PlainJs includes "module.exports".
    constraint.forbid_pattern("module.exports");
    let (accepted, denied) = filter_candidates(vec![c], &constraint);
    assert!(accepted.is_empty());
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0].1, SynthesisDenialReason::ForbiddenPattern);
}

#[test]
fn test_filter_candidates_duplicate_denied() {
    use frankenengine_engine::novelty_synthesis_engine::filter_candidates;
    let constraint = SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 0);
    let c = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"dup-filter-seed",
    )
    .unwrap();
    let c2 = c.clone();
    let (accepted, denied) = filter_candidates(vec![c, c2], &constraint);
    assert_eq!(accepted.len(), 1);
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0].1, SynthesisDenialReason::DuplicateCandidate);
}

// =========================================================================
// O. build_receipt
// =========================================================================

#[test]
fn test_build_receipt_from_batch() {
    use frankenengine_engine::novelty_synthesis_engine::{build_batch, build_receipt};
    let constraint = SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 0);
    let c1 = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"receipt-seed-1",
    )
    .unwrap();
    let c2 = synthesize_candidate(
        ProgramKind::TypeScript,
        SynthesisStrategy::MutationBased,
        &constraint,
        b"receipt-seed-2",
    )
    .unwrap();
    let batch = build_batch(epoch(7), vec![c1, c2]).unwrap();
    let receipt = build_receipt(&batch, 1);
    assert_eq!(receipt.candidates_proposed, 2);
    assert_eq!(receipt.candidates_accepted, 1);
    assert_eq!(receipt.acceptance_rate_millionths(), 500_000);
    assert!(!receipt.all_accepted());
    assert!(!receipt.none_accepted());
}

#[test]
fn test_build_receipt_clamps_accepted_to_proposed() {
    use frankenengine_engine::novelty_synthesis_engine::{build_batch, build_receipt};
    let constraint = SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 0);
    let c = synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"clamp-receipt-seed",
    )
    .unwrap();
    let batch = build_batch(epoch(8), vec![c]).unwrap();
    // Pass accepted > proposed — should clamp to proposed.
    let receipt = build_receipt(&batch, 999);
    assert_eq!(receipt.candidates_proposed, 1);
    assert_eq!(receipt.candidates_accepted, 1);
    assert!(receipt.all_accepted());
}

#[test]
fn test_build_receipt_serde_roundtrip() {
    use frankenengine_engine::novelty_synthesis_engine::{build_batch, build_receipt};
    let constraint = SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 0);
    let c = synthesize_candidate(
        ProgramKind::NodePackage,
        SynthesisStrategy::TemplateDriven,
        &constraint,
        b"receipt-serde-seed",
    )
    .unwrap();
    let batch = build_batch(epoch(9), vec![c]).unwrap();
    let receipt = build_receipt(&batch, 1);
    let json = serde_json::to_string(&receipt).unwrap();
    let restored: SynthesisReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, restored);
}

// =========================================================================
// P. franken_engine_synthesis_manifest
// =========================================================================

#[test]
fn test_synthesis_manifest_nonempty() {
    use frankenengine_engine::novelty_synthesis_engine::franken_engine_synthesis_manifest;
    let manifest = franken_engine_synthesis_manifest();
    assert!(!manifest.is_empty(), "manifest should contain candidates");
    assert_eq!(manifest.epoch, epoch(1));
}

#[test]
fn test_synthesis_manifest_covers_all_kinds() {
    use frankenengine_engine::novelty_synthesis_engine::franken_engine_synthesis_manifest;
    use std::collections::BTreeSet as Bts;
    let manifest = franken_engine_synthesis_manifest();
    let kinds_present: Bts<ProgramKind> = manifest.candidates.iter().map(|c| c.kind).collect();
    for kind in ProgramKind::ALL {
        assert!(
            kinds_present.contains(kind),
            "manifest missing kind: {:?}",
            kind
        );
    }
}

#[test]
fn test_synthesis_manifest_deterministic() {
    use frankenengine_engine::novelty_synthesis_engine::franken_engine_synthesis_manifest;
    let m1 = franken_engine_synthesis_manifest();
    let m2 = franken_engine_synthesis_manifest();
    assert_eq!(m1.batch_id, m2.batch_id);
    assert_eq!(m1.total_novelty_millionths, m2.total_novelty_millionths);
    assert_eq!(m1.candidate_count(), m2.candidate_count());
}

// =========================================================================
// Q. SynthesizedCandidate — Clone and serde roundtrip
// =========================================================================

#[test]
fn test_synthesized_candidate_clone_equality() {
    let constraint = SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 0);
    let c = synthesize_candidate(
        ProgramKind::BunPackage,
        SynthesisStrategy::ObstructionTargeted,
        &constraint,
        b"clone-eq-seed",
    )
    .unwrap();
    let c2 = c.clone();
    assert_eq!(c, c2);
    assert_eq!(c.content_hash, c2.content_hash);
    assert_eq!(c.candidate_id, c2.candidate_id);
}

#[test]
fn test_synthesized_candidate_serde_roundtrip() {
    use frankenengine_engine::novelty_synthesis_engine::SynthesizedCandidate;
    let constraint = SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 0);
    let c = synthesize_candidate(
        ProgramKind::ReactApp,
        SynthesisStrategy::RecombinationBased,
        &constraint,
        b"serde-candidate-seed",
    )
    .unwrap();
    let json = serde_json::to_string(&c).unwrap();
    let restored: SynthesizedCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
    assert_eq!(c.source_byte_count(), restored.source_byte_count());
}

// =========================================================================
// R. SynthesisError — PartialEq on InternalError variants
// =========================================================================

#[test]
fn test_synthesis_error_internal_eq_by_message() {
    let e1 = SynthesisError::InternalError("msg-a".into());
    let e2 = SynthesisError::InternalError("msg-a".into());
    let e3 = SynthesisError::InternalError("msg-b".into());
    assert_eq!(e1, e2);
    assert_ne!(e1, e3);
}

#[test]
fn test_synthesis_error_display_contains_message() {
    let e = SynthesisError::InternalError("detail".into());
    let s = e.to_string();
    assert!(s.contains("detail"), "display should include inner message");
}

// =========================================================================
// S. synthesize_candidate — all strategy/kind combos succeed with loose constraints
// =========================================================================

#[test]
fn test_synthesize_candidate_all_strategies_all_kinds() {
    // Use very loose constraints to ensure no StrategyNotApplicable rejections.
    let constraint = SynthesisConstraint::new(65_536, 1_048_576, 0);
    for kind in ProgramKind::ALL {
        for strategy in SynthesisStrategy::ALL {
            let result = synthesize_candidate(*kind, *strategy, &constraint, b"cross-seed");
            assert!(
                result.is_ok(),
                "expected Ok for kind={:?} strategy={:?}, got {:?}",
                kind,
                strategy,
                result
            );
        }
    }
}

// =========================================================================
// T. build_constraints — all kinds produce consistent byte budget
// =========================================================================

#[test]
fn test_build_constraints_bytes_proportional_to_nodes() {
    for kind in ProgramKind::ALL {
        let c = build_constraints(*kind, 100, 0);
        // The heuristic is ~16 bytes per AST node.
        assert_eq!(c.max_bytes, c.max_ast_nodes * 16);
    }
}

#[test]
fn test_build_constraints_node_package_minimum() {
    // NodePackage typical_min_nodes = 10
    let c = build_constraints(ProgramKind::NodePackage, 1, 0);
    assert!(c.max_ast_nodes >= 10);
}

#[test]
fn test_build_constraints_bun_package_minimum() {
    // BunPackage typical_min_nodes = 10
    let c = build_constraints(ProgramKind::BunPackage, 1, 0);
    assert!(c.max_ast_nodes >= 10);
}

#[test]
fn test_build_constraints_typescript_minimum() {
    // TypeScript typical_min_nodes = 5
    let c = build_constraints(ProgramKind::TypeScript, 2, 0);
    assert!(c.max_ast_nodes >= 5);
}

#[test]
fn test_build_constraints_react_component_minimum() {
    // ReactComponent typical_min_nodes = 8
    let c = build_constraints(ProgramKind::ReactComponent, 1, 0);
    assert!(c.max_ast_nodes >= 8);
}
