//! Integration tests for the novelty synthesis engine (RGC-707B).

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

use frankenengine_engine::novelty_synthesis_engine::{
    self, BEAD_ID, COMPONENT, DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, DEFAULT_MIN_NOVELTY,
    KIND_COUNT, POLICY_ID, ProgramKind, SCHEMA_VERSION, STRATEGY_COUNT, SynthesisConstraint,
    SynthesisDenialReason, SynthesisError, SynthesisStrategy,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn default_constraint() -> SynthesisConstraint {
    SynthesisConstraint::new(DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, 0)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_constant() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.contains("novelty"));
}

#[test]
fn test_bead_id_constant() {
    assert!(!BEAD_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn test_component_constant() {
    assert_eq!(COMPONENT, "novelty_synthesis_engine");
}

#[test]
fn test_policy_id_constant() {
    assert_eq!(POLICY_ID, "RGC-707B");
}

#[test]
fn test_default_max_ast_nodes() {
    assert_eq!(DEFAULT_MAX_AST_NODES, 256);
}

#[test]
fn test_default_max_bytes() {
    assert_eq!(DEFAULT_MAX_BYTES, 4_096);
}

#[test]
fn test_default_min_novelty() {
    assert_eq!(DEFAULT_MIN_NOVELTY, 300_000);
}

#[test]
fn test_strategy_count_matches_all() {
    assert_eq!(STRATEGY_COUNT, SynthesisStrategy::ALL.len());
}

#[test]
fn test_kind_count_matches_all() {
    assert_eq!(KIND_COUNT, ProgramKind::ALL.len());
}

// ---------------------------------------------------------------------------
// SynthesisStrategy
// ---------------------------------------------------------------------------

#[test]
fn test_strategy_all_variants() {
    assert_eq!(SynthesisStrategy::ALL.len(), 5);
}

#[test]
fn test_strategy_as_str_roundtrip() {
    for strategy in SynthesisStrategy::ALL {
        let s = strategy.as_str();
        assert!(!s.is_empty());
        assert_eq!(format!("{strategy}"), s);
    }
}

#[test]
fn test_strategy_serde_roundtrip() {
    for strategy in SynthesisStrategy::ALL {
        let json = serde_json::to_string(strategy).unwrap();
        let back: SynthesisStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*strategy, back);
    }
}

// ---------------------------------------------------------------------------
// ProgramKind
// ---------------------------------------------------------------------------

#[test]
fn test_kind_all_variants() {
    assert_eq!(ProgramKind::ALL.len(), 6);
}

#[test]
fn test_kind_file_extensions() {
    assert_eq!(ProgramKind::PlainJs.file_extension(), ".js");
    assert_eq!(ProgramKind::TypeScript.file_extension(), ".ts");
    assert_eq!(ProgramKind::ReactComponent.file_extension(), ".tsx");
    assert_eq!(ProgramKind::ReactApp.file_extension(), ".tsx");
}

#[test]
fn test_kind_serde_roundtrip() {
    for kind in ProgramKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: ProgramKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ---------------------------------------------------------------------------
// SynthesisConstraint
// ---------------------------------------------------------------------------

#[test]
fn test_constraint_new() {
    let c = SynthesisConstraint::new(100, 200, 300_000);
    assert_eq!(c.max_ast_nodes, 100);
    assert_eq!(c.max_bytes, 200);
    assert_eq!(c.min_novelty_millionths, 300_000);
    assert!(c.required_features.is_empty());
    assert!(c.forbidden_patterns.is_empty());
}

#[test]
fn test_constraint_require_feature() {
    let mut c = SynthesisConstraint::new(100, 200, 0);
    c.require_feature("async");
    assert!(c.required_features.contains("async"));
}

#[test]
fn test_constraint_forbid_pattern() {
    let mut c = SynthesisConstraint::new(100, 200, 0);
    c.forbid_pattern("eval(");
    assert!(c.forbidden_patterns.contains("eval("));
}

#[test]
fn test_constraint_nodes_within_budget() {
    let c = SynthesisConstraint::new(100, 200, 0);
    assert!(c.nodes_within_budget(99));
    assert!(c.nodes_within_budget(100));
    assert!(!c.nodes_within_budget(101));
}

#[test]
fn test_constraint_bytes_within_budget() {
    let c = SynthesisConstraint::new(100, 200, 0);
    assert!(c.bytes_within_budget(200));
    assert!(!c.bytes_within_budget(201));
}

#[test]
fn test_constraint_novelty_sufficient() {
    let c = SynthesisConstraint::new(100, 200, 500_000);
    assert!(!c.novelty_sufficient(499_999));
    assert!(c.novelty_sufficient(500_000));
    assert!(c.novelty_sufficient(1_000_000));
}

#[test]
fn test_constraint_contains_forbidden() {
    let mut c = SynthesisConstraint::new(100, 200, 0);
    c.forbid_pattern("eval(");
    assert!(c.contains_forbidden("some eval( call").is_some());
    assert!(c.contains_forbidden("safe code").is_none());
}

#[test]
fn test_constraint_missing_features() {
    let mut c = SynthesisConstraint::new(100, 200, 0);
    c.require_feature("async");
    c.require_feature("await");
    let missing = c.missing_features("function async() {}");
    assert_eq!(missing, vec!["await".to_string()]);
}

#[test]
fn test_constraint_serde_roundtrip() {
    let c = SynthesisConstraint::new(100, 200, 300_000);
    let json = serde_json::to_string(&c).unwrap();
    let back: SynthesisConstraint = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// build_constraints
// ---------------------------------------------------------------------------

#[test]
fn test_build_constraints_respects_kind() {
    let c = novelty_synthesis_engine::build_constraints(ProgramKind::PlainJs, 100, 0);
    assert!(c.max_ast_nodes >= 3); // PlainJs typical min is 3
}

#[test]
fn test_build_constraints_floor_nodes() {
    // If max_nodes is lower than typical minimum, it should raise to minimum
    let c = novelty_synthesis_engine::build_constraints(ProgramKind::ReactApp, 1, 0);
    assert!(c.max_ast_nodes >= 20); // ReactApp typical min is 20
}

// ---------------------------------------------------------------------------
// synthesize_candidate
// ---------------------------------------------------------------------------

#[test]
fn test_synthesize_candidate_ok() {
    let constraint = default_constraint();
    let result = novelty_synthesis_engine::synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"seed-123",
    );
    assert!(result.is_ok());
    let c = result.unwrap();
    assert!(!c.candidate_id.is_empty());
    assert!(!c.source_text.is_empty());
    assert!(c.ast_node_count > 0);
}

#[test]
fn test_synthesize_candidate_deterministic() {
    let constraint = default_constraint();
    let a = novelty_synthesis_engine::synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"determinism-test",
    )
    .unwrap();
    let b = novelty_synthesis_engine::synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"determinism-test",
    )
    .unwrap();
    assert_eq!(a.candidate_id, b.candidate_id);
    assert_eq!(a.content_hash, b.content_hash);
    assert_eq!(a.source_text, b.source_text);
}

#[test]
fn test_synthesize_candidate_zero_max_nodes_error() {
    let constraint = SynthesisConstraint::new(0, 0, 0);
    let result = novelty_synthesis_engine::synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"seed",
    );
    assert!(matches!(result, Err(SynthesisError::InvalidConstraint)));
}

// ---------------------------------------------------------------------------
// SynthesizedCandidate methods
// ---------------------------------------------------------------------------

#[test]
fn test_candidate_source_byte_count() {
    let constraint = default_constraint();
    let c = novelty_synthesis_engine::synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::MutationBased,
        &constraint,
        b"byte-count-test",
    )
    .unwrap();
    assert_eq!(c.source_byte_count(), c.source_text.len() as u64);
}

#[test]
fn test_candidate_exceeds_novelty() {
    let constraint = default_constraint();
    let c = novelty_synthesis_engine::synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::ObstructionTargeted,
        &constraint,
        b"novelty-test",
    )
    .unwrap();
    // ObstructionTargeted has the highest base multiplier (900k)
    assert!(c.exceeds_novelty(0));
}

// ---------------------------------------------------------------------------
// build_batch
// ---------------------------------------------------------------------------

#[test]
fn test_build_batch_empty() {
    let batch = novelty_synthesis_engine::build_batch(test_epoch(), vec![]).unwrap();
    assert!(batch.is_empty());
    assert_eq!(batch.candidate_count(), 0);
    assert_eq!(batch.average_novelty_millionths(), 0);
}

#[test]
fn test_build_batch_with_candidates() {
    let constraint = default_constraint();
    let c = novelty_synthesis_engine::synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"batch-test",
    )
    .unwrap();
    let batch = novelty_synthesis_engine::build_batch(test_epoch(), vec![c]).unwrap();
    assert_eq!(batch.candidate_count(), 1);
    assert!(!batch.is_empty());
    assert!(batch.total_novelty_millionths > 0);
}

#[test]
fn test_build_batch_content_hash_deterministic() {
    let constraint = default_constraint();
    let c1 = novelty_synthesis_engine::synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"hash-test",
    )
    .unwrap();
    let c2 = c1.clone();
    let b1 = novelty_synthesis_engine::build_batch(test_epoch(), vec![c1]).unwrap();
    let b2 = novelty_synthesis_engine::build_batch(test_epoch(), vec![c2]).unwrap();
    assert_eq!(b1.content_hash(), b2.content_hash());
}

// ---------------------------------------------------------------------------
// evaluate_candidate_novelty
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_novelty_empty_set() {
    let constraint = default_constraint();
    let c = novelty_synthesis_engine::synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"eval-test",
    )
    .unwrap();
    let novelty = novelty_synthesis_engine::evaluate_candidate_novelty(&c, &BTreeSet::new());
    assert_eq!(novelty, 1_000_000); // Full novelty
}

#[test]
fn test_evaluate_novelty_duplicate() {
    let constraint = default_constraint();
    let c = novelty_synthesis_engine::synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"dup-test",
    )
    .unwrap();
    let mut existing = BTreeSet::new();
    existing.insert(c.content_hash.clone());
    let novelty = novelty_synthesis_engine::evaluate_candidate_novelty(&c, &existing);
    assert_eq!(novelty, 0);
}

// ---------------------------------------------------------------------------
// filter_candidates
// ---------------------------------------------------------------------------

#[test]
fn test_filter_candidates_all_accepted() {
    let constraint = default_constraint();
    let c = novelty_synthesis_engine::synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"filter-test",
    )
    .unwrap();
    let (accepted, denied) = novelty_synthesis_engine::filter_candidates(vec![c], &constraint);
    assert_eq!(accepted.len(), 1);
    assert!(denied.is_empty());
}

#[test]
fn test_filter_candidates_duplicate_denied() {
    let constraint = default_constraint();
    let c = novelty_synthesis_engine::synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"dup-filter",
    )
    .unwrap();
    let c2 = c.clone();
    let (accepted, denied) = novelty_synthesis_engine::filter_candidates(vec![c, c2], &constraint);
    assert_eq!(accepted.len(), 1);
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0].1, SynthesisDenialReason::DuplicateCandidate);
}

// ---------------------------------------------------------------------------
// build_receipt
// ---------------------------------------------------------------------------

#[test]
fn test_build_receipt_from_batch() {
    let constraint = default_constraint();
    let c = novelty_synthesis_engine::synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"receipt-test",
    )
    .unwrap();
    let batch = novelty_synthesis_engine::build_batch(test_epoch(), vec![c]).unwrap();
    let receipt = novelty_synthesis_engine::build_receipt(&batch, 1);
    assert_eq!(receipt.candidates_proposed, 1);
    assert_eq!(receipt.candidates_accepted, 1);
    assert!(receipt.all_accepted());
    assert!(!receipt.none_accepted());
}

#[test]
fn test_build_receipt_none_accepted() {
    let constraint = default_constraint();
    let c = novelty_synthesis_engine::synthesize_candidate(
        ProgramKind::PlainJs,
        SynthesisStrategy::GrammarGuided,
        &constraint,
        b"none-accept",
    )
    .unwrap();
    let batch = novelty_synthesis_engine::build_batch(test_epoch(), vec![c]).unwrap();
    let receipt = novelty_synthesis_engine::build_receipt(&batch, 0);
    assert!(receipt.none_accepted());
    assert!(!receipt.all_accepted());
    assert_eq!(receipt.acceptance_rate_millionths(), 0);
}

// ---------------------------------------------------------------------------
// SynthesisDenialReason
// ---------------------------------------------------------------------------

#[test]
fn test_denial_reason_all_variants() {
    assert_eq!(SynthesisDenialReason::ALL.len(), 8);
}

#[test]
fn test_denial_reason_serde_roundtrip() {
    for reason in SynthesisDenialReason::ALL {
        let json = serde_json::to_string(reason).unwrap();
        let back: SynthesisDenialReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_produces_nonempty_batch() {
    let manifest = novelty_synthesis_engine::franken_engine_synthesis_manifest();
    assert!(!manifest.is_empty());
    assert!(!manifest.batch_id.is_empty());
}

#[test]
fn test_manifest_covers_multiple_strategies() {
    let manifest = novelty_synthesis_engine::franken_engine_synthesis_manifest();
    assert!(manifest.strategy_distribution.len() > 1);
}

#[test]
fn test_manifest_deterministic() {
    let a = novelty_synthesis_engine::franken_engine_synthesis_manifest();
    let b = novelty_synthesis_engine::franken_engine_synthesis_manifest();
    assert_eq!(a.batch_id, b.batch_id);
    assert_eq!(a.content_hash(), b.content_hash());
}
